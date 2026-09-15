//! Reference TCP transport for the peer protocol.
//!
//! This is the M2 "pure P2P, no relay" delivery path: a node serves ciphertext
//! envelopes it holds and can fetch drops from a peer by id. It is intentionally
//! simple; libp2p (QUIC + Noise, gossip + Kademlia) slots in behind the same
//! [`crate::protocol`] messages later.

use std::sync::{Arc, Mutex};

use keepstone_core::presence::{PresenceAttestation, PresenceRequest};
use keepstone_core::{DropId, SignedDrop};
use keepstone_crypto::Identity;
use keepstone_log::sth::STH_ENCODED_LEN;
use keepstone_log::SignedTreeHead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::protocol::{self, Message, MAX_FRAME, PROTOCOL_VERSION};
use crate::{Clock, MemoryStore, Storage, SystemClock};

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
            Message::Put(raw) => {
                // Store only signature-valid envelopes; a relay holds ciphertext.
                match SignedDrop::decode(&raw) {
                    Ok(signed) if signed.verify().is_ok() => {
                        let id = signed.id();
                        if let Ok(mut guard) = store.lock() {
                            guard.put_drop(id, raw);
                        }
                        send(stream, &Message::Stored(id)).await?;
                    }
                    _ => {
                        send(stream, &Message::Bye).await?;
                    }
                }
            }
            Message::PutChunk(id, index, data) => {
                if let Ok(mut guard) = store.lock() {
                    guard.put_chunk(id, index, data);
                }
                send(stream, &Message::Stored(id)).await?;
            }
            Message::Bye
            | Message::Drop(_)
            | Message::Missing(_)
            | Message::Chunk(..)
            | Message::Presence(_)
            | Message::Attestation(_)
            | Message::Stored(_)
            | Message::GetSth
            | Message::Sth(_) => {
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

/// Push a signed envelope to a peer for storage (federated relay).
///
/// Returns `true` if the peer confirmed storage.
///
/// # Errors
/// Returns an I/O error on transport failure.
pub async fn push_drop(addr: &str, raw: Vec<u8>) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(addr).await?;
    send(&mut stream, &Message::Hello(PROTOCOL_VERSION)).await?;
    let _ = recv(&mut stream).await?;
    send(&mut stream, &Message::Put(raw)).await?;
    match recv(&mut stream).await? {
        Some(Message::Stored(_)) => Ok(true),
        _ => Ok(false),
    }
}

/// Push one ciphertext chunk to a peer for storage.
///
/// # Errors
/// Returns an I/O error on transport failure.
pub async fn push_chunk(
    addr: &str,
    id: DropId,
    index: u32,
    data: Vec<u8>,
) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(addr).await?;
    send(&mut stream, &Message::Hello(PROTOCOL_VERSION)).await?;
    let _ = recv(&mut stream).await?;
    send(&mut stream, &Message::PutChunk(id, index, data)).await?;
    match recv(&mut stream).await? {
        Some(Message::Stored(_)) => Ok(true),
        _ => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// Signed tree head gossip (multi-log verifiability)
// ---------------------------------------------------------------------------

async fn sth_respond(stream: &mut TcpStream, sth: &SignedTreeHead) -> std::io::Result<()> {
    while let Some(message) = recv(stream).await? {
        match message {
            Message::Hello(version) => send(stream, &Message::Hello(version)).await?,
            Message::GetSth => send(stream, &Message::Sth(sth.to_bytes().to_vec())).await?,
            Message::Bye => {
                send(stream, &Message::Bye).await?;
                break;
            }
            _ => {
                send(stream, &Message::Bye).await?;
                break;
            }
        }
    }
    Ok(())
}

/// Serve a signed tree head until the task is aborted.
pub async fn serve_sth(listener: TcpListener, sth: SignedTreeHead) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let sth = sth.clone();
        tokio::spawn(async move {
            let _ = sth_respond(&mut stream, &sth).await;
        });
    }
}

/// Fetch a signed tree head from a log node.
///
/// The caller MUST verify the returned STH's signature.
///
/// # Errors
/// Returns an I/O error on transport failure or a malformed STH.
pub async fn fetch_sth(addr: &str) -> std::io::Result<Option<SignedTreeHead>> {
    let mut stream = TcpStream::connect(addr).await?;
    send(&mut stream, &Message::Hello(PROTOCOL_VERSION)).await?;
    let _ = recv(&mut stream).await?;
    send(&mut stream, &Message::GetSth).await?;
    match recv(&mut stream).await? {
        Some(Message::Sth(bytes)) => {
            let encoded: [u8; STH_ENCODED_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| io_error("bad sth length"))?;
            Ok(Some(SignedTreeHead::from_bytes(&encoded)))
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Witness presence (M3b)
// ---------------------------------------------------------------------------

async fn witness_respond(
    stream: &mut TcpStream,
    witness: &Identity,
    cell: &str,
) -> std::io::Result<()> {
    while let Some(message) = recv(stream).await? {
        match message {
            Message::Hello(version) => send(stream, &Message::Hello(version)).await?,
            Message::Presence(bytes) => {
                let Ok(request) = PresenceRequest::from_canonical(&bytes) else {
                    send(stream, &Message::Bye).await?;
                    break;
                };
                // Best-effort: only attest requests addressed to our cell.
                if request.cell != cell {
                    send(stream, &Message::Missing(DropId::of(b"cell"))).await?;
                    continue;
                }
                let attestation =
                    PresenceAttestation::sign(witness, &request, 0, SystemClock.now_unix());
                send(stream, &Message::Attestation(attestation.to_canonical())).await?;
            }
            Message::Bye => {
                send(stream, &Message::Bye).await?;
                break;
            }
            _ => {
                send(stream, &Message::Bye).await?;
                break;
            }
        }
    }
    Ok(())
}

/// Serve presence attestations for a cell until the task is aborted.
pub async fn serve_witness(listener: TcpListener, witness: Arc<Identity>, cell: String) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let witness = Arc::clone(&witness);
        let cell = cell.clone();
        tokio::spawn(async move {
            let _ = witness_respond(&mut stream, &witness, &cell).await;
        });
    }
}

/// Request a presence attestation from a witness peer.
///
/// # Errors
/// Returns an I/O error on transport failure.
pub async fn request_presence(
    addr: &str,
    request: &PresenceRequest,
) -> std::io::Result<Option<PresenceAttestation>> {
    let mut stream = TcpStream::connect(addr).await?;
    send(&mut stream, &Message::Hello(PROTOCOL_VERSION)).await?;
    let _ = recv(&mut stream).await?;
    send(&mut stream, &Message::Presence(request.to_canonical())).await?;
    match recv(&mut stream).await? {
        Some(Message::Attestation(bytes)) => Ok(PresenceAttestation::from_canonical(&bytes).ok()),
        _ => Ok(None),
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

    #[tokio::test]
    async fn relay_stores_pushed_drops_and_serves_them() {
        let store = Arc::new(Mutex::new(MemoryStore::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(serve(listener, Arc::clone(&store)));

        let identity = keepstone_crypto::Identity::generate();
        let body = keepstone_core::DropBody {
            version: keepstone_core::PROTOCOL_VERSION,
            suite: keepstone_crypto::CryptoSuite::Classical25519.id(),
            cell: "8928308280fffff".to_owned(),
            ring: 2,
            created_at: 1_700_000_000,
            expiry: 0,
            mode: keepstone_core::Mode::Capability.id(),
            chunk_size: 65536,
            chunk_count: 1,
            content_root: [1u8; 32],
            prefix: [2u8; 20],
            drop_nonce: [3u8; 16],
            pow_nonce: 0,
            wrapped_keys: vec![],
        };
        let signed = keepstone_core::SignedDrop::sign(&identity, &body);
        let id = signed.id();

        // The relay starts empty.
        assert_eq!(fetch(&addr, id).await.unwrap(), None);

        // After a push it serves the envelope to anyone.
        assert!(push_drop(&addr, signed.raw.clone()).await.unwrap());
        assert_eq!(fetch(&addr, id).await.unwrap(), Some(signed.raw.clone()));

        // Chunks can be pushed and fetched too.
        assert!(push_chunk(&addr, id, 0, vec![7u8; 32]).await.unwrap());
        assert_eq!(
            fetch_chunk(&addr, id, 0).await.unwrap(),
            Some(vec![7u8; 32])
        );

        // Garbage is rejected and does not evict the valid drop.
        assert!(!push_drop(&addr, vec![0xAA; 64]).await.unwrap());
        assert_eq!(fetch(&addr, id).await.unwrap(), Some(signed.raw));

        handle.abort();
    }

    #[tokio::test]
    async fn fetches_and_verifies_a_signed_tree_head() {
        let log = keepstone_crypto::Identity::generate();
        let root = keepstone_log::merkle::mth(&[keepstone_log::merkle::leaf_hash(b"a")]);
        let sth = SignedTreeHead::sign(&log, 1, root, 1_234);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(serve_sth(listener, sth.clone()));

        let fetched = fetch_sth(&addr).await.unwrap().unwrap();
        assert_eq!(fetched, sth);
        fetched.verify().unwrap();

        handle.abort();
    }
}
