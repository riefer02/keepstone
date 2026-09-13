//! Reference TCP transport for the peer protocol.
//!
//! This is the M2 "pure P2P, no relay" delivery path: a node serves ciphertext
//! envelopes it holds and can fetch drops from a peer by id. It is intentionally
//! simple; libp2p (QUIC + Noise, gossip + Kademlia) slots in behind the same
//! [`crate::protocol`] messages later.

use std::sync::{Arc, Mutex};

use keepstone_core::DropId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::protocol::{self, Message, MAX_FRAME, PROTOCOL_VERSION};
use crate::{MemoryStore, Storage};

fn io_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Send one framed message.
///
/// # Errors
/// Returns an I/O error on write failure or an oversized frame.
pub async fn send(stream: &mut TcpStream, message: &Message) -> std::io::Result<()> {
    let framed = protocol::frame(message).map_err(|_| io_error("frame"))?;
    stream.write_all(&framed).await
}

/// Receive one framed message, or `None` on clean EOF.
///
/// # Errors
/// Returns an I/O error on a partial/oversized/invalid frame.
pub async fn recv(stream: &mut TcpStream) -> std::io::Result<Option<Message>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io_error("frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let message = Message::decode(&buf).map_err(|_| io_error("protocol"))?;
    Ok(Some(message))
}

/// Answer a single client connection.
///
/// # Errors
/// Returns an I/O error on transport failure.
pub async fn respond(
    stream: &mut TcpStream,
    store: &Arc<Mutex<MemoryStore>>,
) -> std::io::Result<()> {
    while let Some(message) = recv(stream).await? {
        match message {
            Message::Hello(version) => send(stream, &Message::Hello(version)).await?,
            Message::Want(id) => {
                let held = {
                    let guard = store
                        .lock()
                        .map_err(|_| std::io::Error::other("store poisoned"))?;
                    guard.get_drop(&id).map(<[u8]>::to_vec)
                };
                match held {
                    Some(raw) => send(stream, &Message::Drop(raw)).await?,
                    None => send(stream, &Message::Missing(id)).await?,
                }
            }
            Message::WantChunk(id, index) => {
                let held = {
                    let guard = store
                        .lock()
                        .map_err(|_| std::io::Error::other("store poisoned"))?;
                    guard.get_chunk(&id, index).map(<[u8]>::to_vec)
                };
                match held {
                    Some(data) => send(stream, &Message::Chunk(id, index, data)).await?,
                    None => send(stream, &Message::Missing(id)).await?,
                }
            }
            Message::Bye | Message::Drop(_) | Message::Missing(_) | Message::Chunk(..) => {
                send(stream, &Message::Bye).await?;
                break;
            }
        }
    }
    Ok(())
}

/// Serve connections until the task is aborted.
pub async fn serve(listener: TcpListener, store: Arc<Mutex<MemoryStore>>) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let _ = respond(&mut stream, &store).await;
        });
    }
}

/// Fetch a drop by id from a peer, returning the raw envelope if held.
///
/// # Errors
/// Returns an I/O error on transport failure or an unexpected reply.
pub async fn fetch(addr: &str, id: DropId) -> std::io::Result<Option<Vec<u8>>> {
    let mut stream = TcpStream::connect(addr).await?;
    send(&mut stream, &Message::Hello(PROTOCOL_VERSION)).await?;
    let _ = recv(&mut stream).await?;
    send(&mut stream, &Message::Want(id)).await?;
    match recv(&mut stream).await? {
        Some(Message::Drop(raw)) => Ok(Some(raw)),
        Some(Message::Missing(_)) => Ok(None),
        _ => Err(io_error("unexpected reply")),
    }
}

/// Fetch one ciphertext chunk by id and index from a peer.
///
/// # Errors
/// Returns an I/O error on transport failure or an unexpected reply.
pub async fn fetch_chunk(addr: &str, id: DropId, index: u32) -> std::io::Result<Option<Vec<u8>>> {
    let mut stream = TcpStream::connect(addr).await?;
    send(&mut stream, &Message::Hello(PROTOCOL_VERSION)).await?;
    let _ = recv(&mut stream).await?;
    send(&mut stream, &Message::WantChunk(id, index)).await?;
    match recv(&mut stream).await? {
        Some(Message::Chunk(_, _, data)) => Ok(Some(data)),
        Some(Message::Missing(_)) => Ok(None),
        _ => Err(io_error("unexpected reply")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_nodes_exchange_a_drop() {
        let mut store = MemoryStore::new();
        let raw = vec![9u8; 128];
        let id = DropId::of(&raw);
        store.put_drop(id, raw.clone());
        store.put_chunk(id, 0, vec![1u8; 64]);
        store.put_chunk(id, 1, vec![2u8; 64]);
        let store = Arc::new(Mutex::new(store));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(serve(listener, Arc::clone(&store)));

        // Envelope + chunks.
        assert_eq!(fetch(&addr, id).await.unwrap(), Some(raw));
        assert_eq!(
            fetch_chunk(&addr, id, 0).await.unwrap(),
            Some(vec![1u8; 64])
        );
        assert_eq!(
            fetch_chunk(&addr, id, 1).await.unwrap(),
            Some(vec![2u8; 64])
        );

        // Absent data returns None rather than an error.
        assert_eq!(fetch(&addr, DropId::of(b"absent")).await.unwrap(), None);
        assert_eq!(fetch_chunk(&addr, id, 9).await.unwrap(), None);

        handle.abort();
    }
}
