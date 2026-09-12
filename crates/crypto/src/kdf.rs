//! Domain-separated key derivation (HKDF-SHA256).
//!
//! Every key purpose has its own `info` string. Reusing a key across purposes is
//! a category error we make impossible by centralizing the labels here.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;

/// Default HKDF salt for Keepstone derivations.
pub const DEFAULT_SALT: &[u8] = b"keepstone/v1";

/// `info` label for deriving the per-drop content key.
pub const INFO_DROP_KEY: &[u8] = b"keepstone/v1/drop-key";
/// `info` label for deriving per-chunk keys.
pub const INFO_CHUNK_KEY: &[u8] = b"keepstone/v1/chunk-key";
/// `info` label for deriving sealed-box keys.
pub const INFO_SEAL_KEY: &[u8] = b"keepstone/v1/seal-key";
/// `info` label for deriving recipient tags.
pub const INFO_TAG: &[u8] = b"keepstone/v1/tag";

/// Length of all symmetric keys used by the classical suite.
pub const KEY_LEN: usize = 32;

/// Expand key material into `out` using HKDF-SHA256.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] if `out` is too long.
pub fn expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    hkdf.expand(info, out)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// Derive a 32-byte key.
///
/// # Errors
/// Propagates [`CryptoError::InvalidKeyLength`].
pub fn derive_key32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut out = [0u8; KEY_LEN];
    expand(ikm, salt, info, &mut out)?;
    Ok(out)
}

/// Derive the symmetric key for a specific chunk of a drop.
///
/// The chunk index is bound into the derivation, so two chunks under the same
/// content key can never share a key (and therefore never share a nonce space).
///
/// # Errors
/// Propagates [`CryptoError::InvalidKeyLength`].
pub fn derive_chunk_key(
    content_key: &[u8; KEY_LEN],
    index: u32,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut info = Vec::with_capacity(INFO_CHUNK_KEY.len() + 4);
    info.extend_from_slice(INFO_CHUNK_KEY);
    info.extend_from_slice(&index.to_be_bytes());
    derive_key32(content_key, DEFAULT_SALT, &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_domain_separated() {
        let ikm = b"input key material";
        let a = derive_key32(ikm, DEFAULT_SALT, INFO_DROP_KEY).unwrap();
        let b = derive_key32(ikm, DEFAULT_SALT, INFO_DROP_KEY).unwrap();
        let c = derive_key32(ikm, DEFAULT_SALT, INFO_TAG).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn chunk_keys_differ_per_index() {
        let content = [7u8; KEY_LEN];
        let k0 = derive_chunk_key(&content, 0).unwrap();
        let k1 = derive_chunk_key(&content, 1).unwrap();
        assert_ne!(k0, k1);
    }
}
