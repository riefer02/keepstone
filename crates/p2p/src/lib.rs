//! libp2p transport (M2b): QUIC + TCP with Noise, exchanging drops through a
//! request/response protocol.
//!
//! This is the production transport the reference TCP implementation in
//! `keepstone-node` stands in for. It speaks the **same** [`keepstone_node::protocol`]
//! messages: a peer answers "do you have this drop / chunk?" with ciphertext or
//! a miss. There is no relay dependency and no plaintext on the wire beyond
//! content already end-to-end encrypted.
//!
//! libp2p is used here only as transport, discovery, and framing. All
//! confidentiality and authenticity guarantees come from `keepstone-crypto`
//! and `keepstone-core`.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{
    gossipsub, identify, kad, noise, request_response as rr, tcp, yamux, StreamProtocol, Swarm,
    SwarmBuilder,
};
use thiserror::Error;

use keepstone_core::{DropId, SignedDrop};
use keepstone_node::protocol::{Message, MAX_FRAME};
use keepstone_node::{MemoryStore, Storage};

/// The request/response protocol identifier.
pub const DROP_PROTOCOL: &str = "/keepstone/drop/1";

/// The gossipsub topic for a cell.
#[must_use]
pub fn cell_topic(cell: &str) -> String {
    format!("keepstone/drops/v1/cell/{cell}")
}

pub use libp2p::Multiaddr;

/// Errors from the p2p transport.
#[derive(Debug, Error)]
pub enum P2pError {
    /// libp2p transport construction failed.
    #[error("transport: {0}")]
    Transport(String),
    /// The peer could not be reached.
    #[error("connection failed")]
    Connection,
    /// The peer sent something malformed.
    #[error("protocol")]
    Protocol,
    /// No reply arrived before the deadline.
    #[error("timed out")]
    Timeout,
}

/// A codec that frames [`Message`] values using Keepstone's canonical encoding.
#[derive(Debug, Default, Clone, Copy)]
pub struct MessageCodec;

async fn read_message<T>(io: &mut T) -> std::io::Result<Message>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
    }
    Message::decode(&buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "protocol"))
}

async fn write_message<T>(io: &mut T, message: &Message) -> std::io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    io.write_all(&message.encode()).await?;
    io.close().await
}

impl request_response::Codec for MessageCodec {
    type Protocol = StreamProtocol;
    type Request = Message;
    type Response = Message;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Message>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_message(io).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Message>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_message(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Message,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_message(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Message,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_message(io, &response).await
    }
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    drop: request_response::Behaviour<MessageCodec>,
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
}

/// Error type used while constructing the composed behaviour.
#[derive(Debug)]
struct BehaviourError(String);

impl std::fmt::Display for BehaviourError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BehaviourError {}

fn build_swarm() -> Result<Swarm<Behaviour>, P2pError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| P2pError::Transport(e.to_string()))?
        .with_quic()
        .with_behaviour(|key| {
            let identify = identify::Behaviour::new(identify::Config::new(
                "/keepstone/1.0.0".to_owned(),
                key.public(),
            ));
            let drop = request_response::Behaviour::with_codec(
                MessageCodec,
                [(StreamProtocol::new(DROP_PROTOCOL), ProtocolSupport::Full)].into_iter(),
                request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
            );
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .max_transmit_size(MAX_FRAME)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .map_err(|e| BehaviourError(e.to_string()))?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| BehaviourError(e.to_string()))?;

            let peer_id = key.public().to_peer_id();
            let mut kad = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
            kad.set_mode(Some(kad::Mode::Server));

            Ok(Behaviour {
                identify,
                drop,
                gossipsub,
                kad,
            })
        })
        .map_err(|e| P2pError::Transport(e.to_string()))?
        .build();
    Ok(swarm)
}

fn respond(store: &Arc<Mutex<MemoryStore>>, request: Message) -> Message {
    match request {
        Message::Want(id) => match store.lock() {
            Ok(guard) => match guard.get_drop(&id) {
                Some(bytes) => Message::Drop(bytes.to_vec()),
                None => Message::Missing(id),
            },
            Err(_) => Message::Missing(id),
        },
        Message::WantChunk(id, index) => match store.lock() {
            Ok(guard) => match guard.get_chunk(&id, index) {
                Some(bytes) => Message::Chunk(id, index, bytes.to_vec()),
                None => Message::Missing(id),
            },
            Err(_) => Message::Missing(id),
        },
        other => other,
    }
}

/// Serve drops to peers until the task is aborted.
///
/// # Errors
/// Returns [`P2pError`] if the listener cannot be started.
pub async fn serve(listen: Multiaddr, store: Arc<Mutex<MemoryStore>>) -> Result<(), P2pError> {
    serve_with_ready(listen, store, None).await
}

/// Like [`serve`], but reports the first bound listen address on `ready`.
///
/// # Errors
/// Returns [`P2pError`] if the listener cannot be started.
pub async fn serve_with_ready(
    listen: Multiaddr,
    store: Arc<Mutex<MemoryStore>>,
    ready: Option<tokio::sync::oneshot::Sender<Multiaddr>>,
) -> Result<(), P2pError> {
    let mut swarm = build_swarm()?;
    swarm
        .listen_on(listen)
        .map_err(|e| P2pError::Transport(e.to_string()))?;

    let mut ready = ready;
    loop {
        let event = swarm.select_next_some().await;
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if let Some(sender) = ready.take() {
                    let _ = sender.send(address);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Drop(request_response::Event::Message {
                message:
                    rr::Message::Request {
                        request, channel, ..
                    },
                ..
            })) => {
                let response = respond(&store, request);
                let _ = swarm.behaviour_mut().drop.send_response(channel, response);
            }
            _ => {}
        }
    }
}

/// Dial a peer by multiaddr and send one request, awaiting the response.
///
/// # Errors
/// Returns [`P2pError`] on connection failure or timeout.
pub async fn request(addr: Multiaddr, request: Message) -> Result<Message, P2pError> {
    let mut swarm = build_swarm()?;
    swarm
        .dial(addr)
        .map_err(|e| P2pError::Transport(e.to_string()))?;

    let outer = async {
        let mut sent: Option<request_response::OutboundRequestId> = None;
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    sent = Some(
                        swarm
                            .behaviour_mut()
                            .drop
                            .send_request(&peer_id, request.clone()),
                    );
                }
                SwarmEvent::Behaviour(BehaviourEvent::Drop(request_response::Event::Message {
                    message:
                        rr::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                })) => {
                    if Some(request_id) == sent {
                        return Ok(response);
                    }
                }
                SwarmEvent::OutgoingConnectionError { .. } => {
                    return Err(P2pError::Connection);
                }
                _ => {}
            }
        }
    };

    tokio::time::timeout(Duration::from_secs(20), outer)
        .await
        .map_err(|_| P2pError::Timeout)?
}

/// Fetch a drop envelope from a peer.
///
/// # Errors
/// Returns [`P2pError`] on transport failure.
pub async fn fetch_drop(addr: Multiaddr, id: DropId) -> Result<Option<Vec<u8>>, P2pError> {
    match request(addr, Message::Want(id)).await? {
        Message::Drop(bytes) => Ok(Some(bytes)),
        Message::Missing(_) => Ok(None),
        _ => Err(P2pError::Protocol),
    }
}

/// Fetch one ciphertext chunk from a peer.
///
/// # Errors
/// Returns [`P2pError`] on transport failure.
pub async fn fetch_chunk(
    addr: Multiaddr,
    id: DropId,
    index: u32,
) -> Result<Option<Vec<u8>>, P2pError> {
    match request(addr, Message::WantChunk(id, index)).await? {
        Message::Chunk(_, _, bytes) => Ok(Some(bytes)),
        Message::Missing(_) => Ok(None),
        _ => Err(P2pError::Protocol),
    }
}

// ---------------------------------------------------------------------------
// Gossipsub: dense-cell push delivery of "unknown" drops
// ---------------------------------------------------------------------------

/// Serve request/response **and** subscribe to cell topics, storing any valid
/// drop that arrives over gossip.
///
/// This is the dense-cell path: a subscriber receives drops from authors it has
/// never met, as long as both are in the same cell topic's mesh. Each received
/// drop is signature-verified before it is stored.
///
/// # Errors
/// Returns [`P2pError`] if the listener cannot be started.
pub async fn serve_cells(
    listen: Multiaddr,
    store: Arc<Mutex<MemoryStore>>,
    cells: Vec<String>,
    ready: Option<tokio::sync::oneshot::Sender<Multiaddr>>,
) -> Result<(), P2pError> {
    let mut swarm = build_swarm()?;
    for cell in &cells {
        let topic = gossipsub::IdentTopic::new(cell_topic(cell));
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| P2pError::Transport(e.to_string()))?;
        // Advertise to the DHT that this node serves the cell (sparse-cell path).
        let _ = swarm
            .behaviour_mut()
            .kad
            .start_providing(kad::RecordKey::new(&cell.as_bytes()));
    }
    swarm
        .listen_on(listen)
        .map_err(|e| P2pError::Transport(e.to_string()))?;

    let mut ready = ready;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                if let Some(sender) = ready.take() {
                    let _ = sender.send(address);
                }
            }
            SwarmEvent::ConnectionEstablished { .. } => {
                let _ = swarm.behaviour_mut().kad.bootstrap();
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                }
                let _ = swarm.behaviour_mut().kad.bootstrap();
            }
            SwarmEvent::Behaviour(BehaviourEvent::Drop(request_response::Event::Message {
                message:
                    rr::Message::Request {
                        request, channel, ..
                    },
                ..
            })) => {
                let response = respond(&store, request);
                let _ = swarm.behaviour_mut().drop.send_response(channel, response);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                // Store only drops that verify; gossip is untrusted transport.
                if let Ok(signed) = SignedDrop::decode(&message.data) {
                    if signed.verify().is_ok() {
                        let id = signed.id();
                        if let Ok(mut guard) = store.lock() {
                            guard.put_drop(id, message.data.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Find peers advertising that they serve a cell, via the Kademlia DHT.
///
/// This is the sparse-cell path: when no gossip mesh exists, a node asks the
/// DHT who holds the cell and fetches from the returned peers directly.
///
/// # Errors
/// Returns [`P2pError`] on dial failure. A timeout yields an empty list.
pub async fn find_providers(peer: Multiaddr, cell: &str) -> Result<Vec<libp2p::PeerId>, P2pError> {
    let mut swarm = build_swarm()?;
    swarm
        .dial(peer)
        .map_err(|e| P2pError::Transport(e.to_string()))?;

    let key = kad::RecordKey::new(&cell.as_bytes());
    let mut queried = false;

    let outer =
        async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { .. } => {
                        let _ = swarm.behaviour_mut().kad.bootstrap();
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }
                        let _ = swarm.behaviour_mut().kad.bootstrap();
                        if !queried {
                            queried = true;
                            let _ = swarm.behaviour_mut().kad.get_providers(key.clone());
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(
                        kad::Event::OutboundQueryProgressed {
                            result:
                                kad::QueryResult::GetProviders(Ok(
                                    kad::GetProvidersOk::FoundProviders { providers, .. },
                                )),
                            ..
                        },
                    )) => {
                        if !providers.is_empty() {
                            return Ok(providers.into_iter().collect());
                        }
                    }
                    _ => {}
                }
            }
        };

    match tokio::time::timeout(Duration::from_secs(15), outer).await {
        Ok(result) => result,
        Err(_) => Ok(Vec::new()),
    }
}

async fn settle(swarm: &mut Swarm<Behaviour>, duration: Duration) {
    let _ = tokio::time::timeout(duration, async {
        loop {
            swarm.select_next_some().await;
        }
    })
    .await;
}

/// Publish a signed drop envelope to a cell topic ("unknown drop" delivery).
///
/// # Errors
/// Returns [`P2pError`] on dial or publish failure.
pub async fn gossip_publish(peer: Multiaddr, cell: &str, payload: Vec<u8>) -> Result<(), P2pError> {
    let mut swarm = build_swarm()?;
    let topic = gossipsub::IdentTopic::new(cell_topic(cell));
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(|e| P2pError::Transport(e.to_string()))?;
    swarm
        .dial(peer)
        .map_err(|e| P2pError::Transport(e.to_string()))?;

    loop {
        if let SwarmEvent::ConnectionEstablished { .. } = swarm.select_next_some().await {
            break;
        }
    }
    settle(&mut swarm, Duration::from_millis(500)).await;
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, payload)
        .map_err(|e| P2pError::Transport(format!("publish: {e:?}")))?;
    settle(&mut swarm, Duration::from_millis(750)).await;
    Ok(())
}
