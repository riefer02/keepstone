//! Chunked (streaming) authenticated encryption.
//!
//! Arbitrary-size payloads are split into chunks. Each chunk gets:
//!
//! - a **fresh key**: `HKDF(content_key, "chunk-key" || index)`
//! - a **unique nonce**: `random_prefix (20 bytes) || index (4 bytes, BE)`
//! - **AAD binding** the drop identity, chunk index, and total count
//!
//! Binding the total count in the AAD prevents truncation and reordering. This
//! is a STREAM-style construction over XChaCha20-Poly1305; we implement the
//! framing ourselves so the exact wire layout is under our control.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::aead;
use crate::error::CryptoError;
use crate::kdf::{self, KEY_LEN};

/// Default chunk size (64 KiB) — the degenerate case for small messages.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Length of the per-drop random nonce prefix.
pub const PREFIX_LEN: usize = 20;

const AAD_DOMAIN: &[u8] = b"keepstone/v1/chunk";

/// The framing material needed to decrypt a chunked payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Framing {
    /// Random nonce prefix shared by all chunks of this drop.
    pub prefix: [u8; PREFIX_LEN],
    /// Total number of chunks.
    pub total: u32,
}

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], index: u32) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(index: u32, total: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 8);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&total.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Encrypt a payload into chunks, returning the framing and ciphertexts.
///
/// # Errors
/// Propagates key-derivation and encryption failures.
pub fn encrypt(
    content_key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<(Framing, Vec<Vec<u8>>), CryptoError> {
    let mut prefix = [0u8; PREFIX_LEN];
    OsRng.fill_bytes(&mut prefix);

    let total = plaintext.len().div_ceil(DEFAULT_CHUNK_SIZE).max(1);
    let total_u32 = u32::try_from(total).map_err(|_| CryptoError::InvalidKeyLength)?;

    let mut chunks = Vec::with_capacity(total);
    for index in 0..total {
        let start = index * DEFAULT_CHUNK_SIZE;
        let end = usize::min(start + DEFAULT_CHUNK_SIZE, plaintext.len());
        let data = plaintext.get(start..end).unwrap_or(&[]);
        let key = kdf::derive_chunk_key(
            content_key,
            u32::try_from(index).map_err(|_| CryptoError::InvalidKeyLength)?,
        )?;
        let nonce = chunk_nonce(
            &prefix,
            u32::try_from(index).map_err(|_| CryptoError::InvalidKeyLength)?,
        );
        let aad = chunk_aad(
            u32::try_from(index).map_err(|_| CryptoError::InvalidKeyLength)?,
            total_u32,
        );
        chunks.push(aead::seal(&key, &nonce, &aad, data)?);
    }

    Ok((
        Framing {
            prefix,
            total: total_u32,
        },
        chunks,
    ))
}

/// Decrypt a single chunk in place (used for resumable fetch).
///
/// # Errors
/// Returns [`CryptoError::Decrypt`] if the index is out of range or the chunk
/// fails authentication.
pub fn decrypt_chunk(
    content_key: &[u8; KEY_LEN],
    framing: &Framing,
    index: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if index >= framing.total {
        return Err(CryptoError::Decrypt);
    }
    let key = kdf::derive_chunk_key(content_key, index)?;
    let nonce = chunk_nonce(&framing.prefix, index);
    let aad = chunk_aad(index, framing.total);
    aead::open(&key, &nonce, &aad, ciphertext)
}

/// Decrypt all chunks and concatenate them.
///
/// # Errors
/// Returns [`CryptoError::Decrypt`] if the chunk count does not match the
/// framing, or any chunk fails authentication.
pub fn decrypt(
    content_key: &[u8; KEY_LEN],
    framing: &Framing,
    chunks: &[Vec<u8>],
) -> Result<Vec<u8>, CryptoError> {
    if chunks.len() != framing.total as usize {
        return Err(CryptoError::Decrypt);
    }
    let mut out = Vec::new();
    for (index, ciphertext) in chunks.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| CryptoError::Decrypt)?;
        out.extend_from_slice(&decrypt_chunk(content_key, framing, index, ciphertext)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_message_is_one_chunk() {
        let key = [1u8; KEY_LEN];
        let (framing, chunks) = encrypt(&key, b"hello").unwrap();
        assert_eq!(framing.total, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(decrypt(&key, &framing, &chunks).unwrap(), b"hello");
    }

    #[test]
    fn large_message_round_trips() {
        let key = [1u8; KEY_LEN];
        let plaintext = vec![0x5Au8; DEFAULT_CHUNK_SIZE * 3 + 17];
        let (framing, chunks) = encrypt(&key, &plaintext).unwrap();
        assert_eq!(framing.total, 4);
        assert_eq!(decrypt(&key, &framing, &chunks).unwrap(), plaintext);
    }

    #[test]
    fn empty_message_round_trips() {
        let key = [1u8; KEY_LEN];
        let (framing, chunks) = encrypt(&key, b"").unwrap();
        assert_eq!(framing.total, 1);
        assert!(decrypt(&key, &framing, &chunks).unwrap().is_empty());
    }

    #[test]
    fn tampered_chunk_fails() {
        let key = [1u8; KEY_LEN];
        let (framing, mut chunks) = encrypt(&key, b"hello world").unwrap();
        chunks[0][0] ^= 0x01;
        assert_eq!(decrypt(&key, &framing, &chunks), Err(CryptoError::Decrypt));
    }

    #[test]
    fn truncated_chunk_list_fails() {
        let key = [1u8; KEY_LEN];
        let plaintext = vec![7u8; DEFAULT_CHUNK_SIZE * 2];
        let (framing, mut chunks) = encrypt(&key, &plaintext).unwrap();
        chunks.pop();
        assert_eq!(decrypt(&key, &framing, &chunks), Err(CryptoError::Decrypt));
    }
}
