//! Authenticated encryption (XChaCha20-Poly1305).
//!
//! We use the 192-bit nonce variant so that *random* nonces are safe. This
//! removes the classic 96-bit-nonce reuse footgun for long-lived keys.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::CryptoError;

/// Length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Length of an XChaCha20-Poly1305 key.
pub const KEY_LEN: usize = 32;

/// Encrypt `plaintext` with `key` and `nonce`, authenticating `aad`.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] or [`CryptoError::Encrypt`].
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)
}

/// Decrypt `ciphertext`, verifying the tag and `aad`.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] or [`CryptoError::Decrypt`].
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"aad", b"hello world").unwrap();
        let pt = open(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"aad", b"secret").unwrap();
        assert_eq!(
            open(&key, &nonce, b"different", &ct),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let mut ct = seal(&key, &nonce, b"", b"secret").unwrap();
        ct[0] ^= 0x01;
        assert_eq!(open(&key, &nonce, b"", &ct), Err(CryptoError::Decrypt));
    }
}
