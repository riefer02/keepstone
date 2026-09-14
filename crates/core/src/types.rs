//! Wire types: drops, chunks, wrapped keys, and signed envelopes.

use core::fmt;

use keepstone_crypto::{verify, HybridSealed, Identity, SealedKey};
use sha2::{Digest, Sha256};

use crate::cbor::{Decoder, Encoder};
use crate::error::CoreError;
use crate::pow;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Signing context (domain separation) for drop envelopes.
pub const DROP_CONTEXT: &[u8] = b"keepstone/v1/drop";

/// Minimum number of recipient tag slots per drop (real + decoys).
///
/// Padding to a fixed count hides the true number of recipients and creates
/// false positives for anyone trying to match tags.
pub const MIN_TAGS: usize = 16;

/// Compute SHA-256 over `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// A content-addressed identifier: `SHA-256(exact transmitted bytes)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DropId([u8; 32]);

impl DropId {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hash `bytes` into an identifier.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(sha256(bytes))
    }

    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex.
    ///
    /// # Errors
    /// Returns [`CoreError::Invalid`] on bad hex or length.
    pub fn from_hex(text: &str) -> Result<Self, CoreError> {
        let bytes = hex::decode(text).map_err(|_| CoreError::Invalid("bad hex"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CoreError::Invalid("bad id length"))?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for DropId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DropId({})", self.to_hex())
    }
}

impl fmt::Display for DropId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// The root commitment over a drop's chunk ciphertexts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContentRoot([u8; 32]);

impl ContentRoot {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ContentRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentRoot({})", self.to_hex())
    }
}

/// How a drop's content key is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The recipient key is the only lock (pure capability).
    Capability = 0,
    /// Additionally gated by a witness presence certificate.
    PlaceLocked = 1,
}

impl Mode {
    /// Wire identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parse a wire identifier.
    ///
    /// # Errors
    /// Returns [`CoreError::Invalid`] for unknown modes.
    pub const fn from_id(id: u8) -> Result<Self, CoreError> {
        match id {
            0 => Ok(Self::Capability),
            1 => Ok(Self::PlaceLocked),
            _ => Err(CoreError::Invalid("unknown mode")),
        }
    }
}

/// A content key sealed under the classical or hybrid suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedContentKey {
    /// X25519 sealed box (suite 1).
    Classical(SealedKey),
    /// X25519 + ML-KEM-768 hybrid seal (suite 2).
    Hybrid(HybridSealed),
}

impl SealedContentKey {
    /// The crypto-suite id that produced this sealed key.
    #[must_use]
    pub fn suite_id(&self) -> u8 {
        match self {
            Self::Classical(_) => 1,
            Self::Hybrid(_) => 2,
        }
    }
}

/// A content key sealed to one recipient, located by a short tag.
///
/// The drop does **not** name the recipient in the clear. The recipient derives
/// the tag from their own public key and the drop's `drop_nonce`, and attempts
/// to open any matching entry. Decoy entries create false positives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    /// `HKDF(recipient_x25519_public, drop_nonce)` truncated to 8 bytes.
    pub tag: [u8; 8],
    /// The sealed content key (classical or hybrid).
    pub sealed: SealedContentKey,
}

/// The signed body of a drop (everything except the signature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropBody {
    /// Protocol version.
    pub version: u8,
    /// Crypto suite identifier.
    pub suite: u8,
    /// H3 cell (hex).
    pub cell: String,
    /// k-ring radius for delivery.
    pub ring: u32,
    /// Creation time (Unix seconds).
    pub created_at: u64,
    /// Expiry (Unix seconds; 0 = never).
    pub expiry: u64,
    /// Access mode.
    pub mode: u8,
    /// Chunk size used.
    pub chunk_size: u32,
    /// Number of chunks.
    pub chunk_count: u32,
    /// Commitment over chunk ciphertexts.
    pub content_root: [u8; 32],
    /// Nonce prefix for chunk encryption.
    pub prefix: [u8; 20],
    /// Per-drop nonce used to derive recipient tags.
    pub drop_nonce: [u8; 16],
    /// Proof-of-work nonce.
    pub pow_nonce: u64,
    /// Tagged, sealed content keys (real + decoys).
    pub wrapped_keys: Vec<WrappedKey>,
}

impl DropBody {
    /// Encode this body as canonical CBOR.
    #[must_use]
    pub fn to_canonical(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.array(14);
        enc.uint(u64::from(self.version));
        enc.uint(u64::from(self.suite));
        enc.text(&self.cell);
        enc.uint(u64::from(self.ring));
        enc.uint(self.created_at);
        enc.uint(self.expiry);
        enc.uint(u64::from(self.mode));
        enc.uint(u64::from(self.chunk_size));
        enc.uint(u64::from(self.chunk_count));
        enc.bytes(&self.content_root);
        enc.bytes(&self.prefix);
        enc.bytes(&self.drop_nonce);
        enc.uint(self.pow_nonce);
        enc.array(self.wrapped_keys.len());
        for wrapped in &self.wrapped_keys {
            enc.array(3);
            enc.bytes(&wrapped.tag);
            match &wrapped.sealed {
                SealedContentKey::Classical(sealed) => {
                    enc.uint(1);
                    enc.array(3);
                    enc.bytes(&sealed.ephemeral_public);
                    enc.bytes(&sealed.nonce);
                    enc.bytes(&sealed.ciphertext);
                }
                SealedContentKey::Hybrid(sealed) => {
                    enc.uint(2);
                    enc.array(4);
                    enc.bytes(&sealed.ephemeral_x25519);
                    enc.bytes(&sealed.kem_ciphertext);
                    enc.bytes(&sealed.nonce);
                    enc.bytes(&sealed.ciphertext);
                }
            }
        }
        enc.into_bytes()
    }

    /// Decode a body from canonical CBOR.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed or non-canonical input.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut dec = Decoder::new(bytes);
        if dec.array()? != 14 {
            return Err(CoreError::Cbor("drop body arity"));
        }
        let version = u8::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("version"))?;
        let suite = u8::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("suite"))?;
        let cell = dec.text()?.to_owned();
        let ring = u32::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("ring"))?;
        let created_at = dec.uint()?;
        let expiry = dec.uint()?;
        let mode = u8::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("mode"))?;
        let chunk_size = u32::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("chunk_size"))?;
        let chunk_count = u32::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("chunk_count"))?;
        let content_root = dec.bytes_fixed::<32>()?;
        let prefix = dec.bytes_fixed::<20>()?;
        let drop_nonce = dec.bytes_fixed::<16>()?;
        let pow_nonce = dec.uint()?;
        let wrapped_count = dec.array()?;
        let mut wrapped_keys = Vec::with_capacity(wrapped_count);
        for _ in 0..wrapped_count {
            if dec.array()? != 3 {
                return Err(CoreError::Cbor("wrapped key arity"));
            }
            let tag = dec.bytes_fixed::<8>()?;
            let kind = dec.uint()?;
            let sealed = match kind {
                1 => {
                    if dec.array()? != 3 {
                        return Err(CoreError::Cbor("classical sealed arity"));
                    }
                    let ephemeral_public = dec.bytes_fixed::<32>()?;
                    let nonce = dec.bytes_fixed::<24>()?;
                    let ciphertext = dec.bytes()?.to_vec();
                    SealedContentKey::Classical(SealedKey {
                        ephemeral_public,
                        nonce,
                        ciphertext,
                    })
                }
                2 => {
                    if dec.array()? != 4 {
                        return Err(CoreError::Cbor("hybrid sealed arity"));
                    }
                    let ephemeral_x25519 = dec.bytes_fixed::<32>()?;
                    let kem_ciphertext = dec.bytes()?.to_vec();
                    let nonce = dec.bytes_fixed::<24>()?;
                    let ciphertext = dec.bytes()?.to_vec();
                    SealedContentKey::Hybrid(HybridSealed {
                        ephemeral_x25519,
                        kem_ciphertext,
                        nonce,
                        ciphertext,
                    })
                }
                _ => return Err(CoreError::Cbor("unknown sealed key kind")),
            };
            wrapped_keys.push(WrappedKey { tag, sealed });
        }
        dec.finish()?;
        Ok(Self {
            version,
            suite,
            cell,
            ring,
            created_at,
            expiry,
            mode,
            chunk_size,
            chunk_count,
            content_root,
            prefix,
            drop_nonce,
            pow_nonce,
            wrapped_keys,
        })
    }

    /// Check the proof-of-work bound to `signer`.
    #[must_use]
    pub fn pow_ok(&self, signer: &[u8; 32]) -> bool {
        pow::is_valid(signer, &self.content_root, &self.drop_nonce, self.pow_nonce)
    }
}

/// The exact bytes hashed/signed for a drop payload (domain separated).
#[must_use]
pub fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DROP_CONTEXT.len() + 4 + payload.len());
    out.extend_from_slice(DROP_CONTEXT);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// Encode the signed envelope for a payload + signature.
fn encode_envelope(suite: u8, signer: &[u8; 32], payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.array(4);
    enc.uint(u64::from(suite));
    enc.bytes(signer);
    enc.bytes(payload);
    enc.bytes(signature);
    enc.into_bytes()
}

/// A signed drop envelope.
///
/// The `raw` field holds the **exact transmitted bytes**; [`SignedDrop::id`] is
/// the hash of those bytes and signature verification is performed over the
/// preserved payload bytes — never a re-encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDrop {
    /// Crypto suite identifier.
    pub suite: u8,
    /// Author's Ed25519 public key.
    pub signer: [u8; 32],
    /// Canonical body bytes exactly as received.
    pub payload: Vec<u8>,
    /// Author's Ed25519 signature over [`signing_input`].
    pub signature: [u8; 64],
    /// Exact transmitted bytes of the whole envelope.
    pub raw: Vec<u8>,
}

impl SignedDrop {
    /// Sign a drop body with `identity`, producing a canonical envelope.
    #[must_use]
    pub fn sign(identity: &Identity, body: &DropBody) -> Self {
        let payload = body.to_canonical();
        let signature = identity.sign(&signing_input(&payload));
        let signer = identity.signing_public();
        let raw = encode_envelope(body.suite, &signer, &payload, &signature);
        Self {
            suite: body.suite,
            signer,
            payload,
            signature,
            raw,
        }
    }

    /// Decode an envelope from its exact transmitted bytes.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut dec = Decoder::new(bytes);
        if dec.array()? != 4 {
            return Err(CoreError::Cbor("envelope arity"));
        }
        let suite = u8::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("suite"))?;
        let signer = dec.bytes_fixed::<32>()?;
        let payload = dec.bytes()?.to_vec();
        let signature = dec.bytes_fixed::<64>()?;
        dec.finish()?;
        Ok(Self {
            suite,
            signer,
            payload,
            signature,
            raw: bytes.to_vec(),
        })
    }

    /// The identifier: hash of the exact transmitted bytes.
    #[must_use]
    pub fn id(&self) -> DropId {
        DropId::of(&self.raw)
    }

    /// Verify the author's signature over the preserved payload bytes.
    ///
    /// # Errors
    /// Returns [`CoreError::Verify`] on failure.
    pub fn verify(&self) -> Result<(), CoreError> {
        verify(&self.signer, &signing_input(&self.payload), &self.signature)
            .map_err(|_| CoreError::Verify)
    }

    /// Decode the preserved payload as a [`DropBody`].
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed payload.
    pub fn body(&self) -> Result<DropBody, CoreError> {
        DropBody::from_canonical(&self.payload)
    }
}

/// Compute the content root over chunk ciphertexts.
///
/// `SHA-256( SHA-256(chunk_0) || SHA-256(chunk_1) || ... )`.
#[must_use]
pub fn content_root(chunks: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(sha256(chunk));
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepstone_crypto::CryptoSuite;

    fn sample_body() -> DropBody {
        DropBody {
            version: PROTOCOL_VERSION,
            suite: CryptoSuite::Classical25519.id(),
            cell: "8928308280fffff".to_owned(),
            ring: 2,
            created_at: 1_700_000_000,
            expiry: 0,
            mode: Mode::Capability.id(),
            chunk_size: 65536,
            chunk_count: 1,
            content_root: [9u8; 32],
            prefix: [7u8; 20],
            drop_nonce: [5u8; 16],
            pow_nonce: 0,
            wrapped_keys: vec![],
        }
    }

    #[test]
    fn body_round_trips_canonically() {
        let body = sample_body();
        let bytes = body.to_canonical();
        assert_eq!(DropBody::from_canonical(&bytes).unwrap(), body);
    }

    #[test]
    fn signed_drop_verifies_and_hashes_exact_bytes() {
        let identity = Identity::generate();
        let drop = SignedDrop::sign(&identity, &sample_body());
        drop.verify().unwrap();
        assert_eq!(drop.id(), DropId::of(&drop.raw));

        let decoded = SignedDrop::decode(&drop.raw).unwrap();
        assert_eq!(decoded, drop);
        decoded.verify().unwrap();
        assert_eq!(decoded.id(), drop.id());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let identity = Identity::generate();
        let mut drop = SignedDrop::sign(&identity, &sample_body());
        drop.payload.push(0x00);
        assert!(drop.verify().is_err());
    }

    #[test]
    fn content_root_is_order_sensitive() {
        let a = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        let b = vec![vec![4u8, 5], vec![1u8, 2, 3]];
        assert_ne!(content_root(&a), content_root(&b));
    }

    #[test]
    fn pow_binds_to_signer() {
        let signer = [3u8; 32];
        let body = sample_body();
        let nonce = pow::mine(&signer, &body.content_root, &body.drop_nonce);
        let mut mined = body;
        mined.pow_nonce = nonce;
        assert!(mined.pow_ok(&signer));
        assert!(!mined.pow_ok(&[4u8; 32]));
    }
}
