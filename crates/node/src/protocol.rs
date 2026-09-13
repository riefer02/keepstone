//! Peer-to-peer wire protocol for drop exchange.
//!
//! The protocol is deliberately transport-agnostic: messages are encoded with
//! Keepstone's canonical CBOR and framed with a length prefix, so the same
//! framing works over the reference TCP transport today and libp2p streams
//! later. A peer answers "do you have this drop?" with either the raw signed
//! envelope or a miss.
//!
//! Only ciphertext envelopes ever cross the wire.

use keepstone_core::cbor::{Decoder, Encoder};
use keepstone_core::DropId;

use crate::NodeError;

/// Maximum accepted frame size (8 MiB) to bound memory use.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

const TAG_HELLO: u64 = 0;
const TAG_WANT: u64 = 1;
const TAG_DROP: u64 = 2;
const TAG_MISSING: u64 = 3;
const TAG_BYE: u64 = 4;
const TAG_WANT_CHUNK: u64 = 5;
const TAG_CHUNK: u64 = 6;
const TAG_PRESENCE: u64 = 7;
const TAG_ATTESTATION: u64 = 8;

/// A peer protocol message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Greeting carrying the sender's protocol version.
    Hello(u8),
    /// Ask a peer for a drop by id.
    Want(DropId),
    /// Reply containing the raw signed envelope.
    Drop(Vec<u8>),
    /// Reply indicating the drop is not held.
    Missing(DropId),
    /// Ask a peer for one ciphertext chunk.
    WantChunk(DropId, u32),
    /// Reply containing one ciphertext chunk.
    Chunk(DropId, u32, Vec<u8>),
    /// A presence request (encoded `PresenceRequest`).
    Presence(Vec<u8>),
    /// A witness attestation (encoded `PresenceAttestation`).
    Attestation(Vec<u8>),
    /// Polite close.
    Bye,
}

impl Message {
    /// Encode the message as canonical CBOR (without framing).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.array(2);
        match self {
            Self::Hello(version) => {
                enc.uint(TAG_HELLO);
                enc.bytes(&[*version]);
            }
            Self::Want(id) => {
                enc.uint(TAG_WANT);
                enc.bytes(id.as_bytes());
            }
            Self::Drop(raw) => {
                enc.uint(TAG_DROP);
                enc.bytes(raw);
            }
            Self::Missing(id) => {
                enc.uint(TAG_MISSING);
                enc.bytes(id.as_bytes());
            }
            Self::WantChunk(id, index) => {
                enc.uint(TAG_WANT_CHUNK);
                let mut payload = Vec::with_capacity(36);
                payload.extend_from_slice(id.as_bytes());
                payload.extend_from_slice(&index.to_be_bytes());
                enc.bytes(&payload);
            }
            Self::Chunk(id, index, data) => {
                enc.uint(TAG_CHUNK);
                let mut payload = Vec::with_capacity(36 + data.len());
                payload.extend_from_slice(id.as_bytes());
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(data);
                enc.bytes(&payload);
            }
            Self::Presence(bytes) | Self::Attestation(bytes) => {
                enc.uint(if matches!(self, Self::Presence(_)) {
                    TAG_PRESENCE
                } else {
                    TAG_ATTESTATION
                });
                enc.bytes(bytes);
            }
            Self::Bye => {
                enc.uint(TAG_BYE);
                enc.bytes(&[]);
            }
        }
        enc.into_bytes()
    }

    /// Decode a message from canonical CBOR.
    ///
    /// # Errors
    /// Returns [`NodeError::Protocol`] on malformed input.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeError> {
        let mut dec = Decoder::new(bytes);
        if dec.array().map_err(|_| NodeError::Protocol("arity"))? != 2 {
            return Err(NodeError::Protocol("arity"));
        }
        let tag = dec.uint().map_err(|_| NodeError::Protocol("tag"))?;
        let payload = dec.bytes().map_err(|_| NodeError::Protocol("payload"))?;
        dec.finish().map_err(|_| NodeError::Protocol("trailing"))?;

        match tag {
            TAG_HELLO => {
                let version = *payload.first().ok_or(NodeError::Protocol("hello"))?;
                Ok(Self::Hello(version))
            }
            TAG_WANT => Ok(Self::Want(id_from(payload)?)),
            TAG_DROP => Ok(Self::Drop(payload.to_vec())),
            TAG_MISSING => Ok(Self::Missing(id_from(payload)?)),
            TAG_WANT_CHUNK => {
                let (id, index) = id_index_from(payload)?;
                Ok(Self::WantChunk(id, index))
            }
            TAG_CHUNK => {
                let (id, index) = id_index_from(payload)?;
                Ok(Self::Chunk(id, index, payload[36..].to_vec()))
            }
            TAG_PRESENCE => Ok(Self::Presence(payload.to_vec())),
            TAG_ATTESTATION => Ok(Self::Attestation(payload.to_vec())),
            TAG_BYE => Ok(Self::Bye),
            _ => Err(NodeError::Protocol("unknown tag")),
        }
    }
}

fn id_from(payload: &[u8]) -> Result<DropId, NodeError> {
    let bytes: [u8; 32] = payload
        .try_into()
        .map_err(|_| NodeError::Protocol("id length"))?;
    Ok(DropId::from_bytes(bytes))
}

fn id_index_from(payload: &[u8]) -> Result<(DropId, u32), NodeError> {
    if payload.len() < 36 {
        return Err(NodeError::Protocol("chunk header"));
    }
    let id = id_from(&payload[..32])?;
    let index = u32::from_be_bytes(
        payload[32..36]
            .try_into()
            .map_err(|_| NodeError::Protocol("chunk index"))?,
    );
    Ok((id, index))
}

/// Prefix a message with its big-endian length, enforcing [`MAX_FRAME`].
///
/// # Errors
/// Returns [`NodeError::Protocol`] if the encoded message is too large.
pub fn frame(message: &Message) -> Result<Vec<u8>, NodeError> {
    let body = message.encode();
    if body.len() > MAX_FRAME {
        return Err(NodeError::Protocol("frame too large"));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| NodeError::Protocol("frame too large"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(message: Message) {
        let encoded = message.encode();
        assert_eq!(Message::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn messages_round_trip() {
        round_trip(Message::Hello(1));
        round_trip(Message::Want(DropId::of(b"a")));
        round_trip(Message::Drop(vec![1, 2, 3]));
        round_trip(Message::Missing(DropId::of(b"b")));
        round_trip(Message::WantChunk(DropId::of(b"c"), 7));
        round_trip(Message::Chunk(DropId::of(b"d"), 2, vec![9, 8, 7]));
        round_trip(Message::Presence(vec![1, 2, 3]));
        round_trip(Message::Attestation(vec![4, 5, 6]));
        round_trip(Message::Bye);
    }

    #[test]
    fn framing_prefixes_length() {
        let framed = frame(&Message::Bye).unwrap();
        let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(len, framed.len() - 4);
        assert_eq!(Message::decode(&framed[4..]).unwrap(), Message::Bye);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Message::decode(&[0xFF, 0xFF]).is_err());
    }
}
