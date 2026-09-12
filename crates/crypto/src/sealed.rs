//! Sealed boxes: ephemeral-static X25519 to wrap a content key for a recipient.
//!
//! The sender generates an ephemeral X25519 keypair, performs ECDH with the
//! recipient's static public key, derives a wrapping key, and encrypts the
//! per-drop content key. Only the recipient's secret key can open it. The
//! ephemeral key provides forward secrecy for the wrap.

use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::kdf;
use crate::{aead, kdf::KEY_LEN};

const SEAL_AAD: &[u8] = b"keepstone/v1/sealed";

/// A content key sealed to one recipient device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKey {
    /// Sender's ephemeral X25519 public key.
    pub ephemeral_public: [u8; 32],
    /// Random nonce for the wrapping AEAD.
    pub nonce: [u8; aead::NONCE_LEN],
    /// AEAD ciphertext of the 32-byte content key.
    pub ciphertext: Vec<u8>,
}

impl SealedKey {
    /// Encoded length of a sealed key: 32 + 24 + 48.
    pub const ENCODED_LEN: usize = 32 + aead::NONCE_LEN + (KEY_LEN + 16);

    /// Seal `content_key` to `recipient` (an X25519 public key).
    ///
    /// # Errors
    /// Returns [`CryptoError`] on RNG or key-derivation failure.
    pub fn seal(content_key: &[u8; KEY_LEN], recipient: &[u8; 32]) -> Result<Self, CryptoError> {
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral).to_bytes();
        let recipient_public = X25519Public::from(*recipient);
        let shared = ephemeral.diffie_hellman(&recipient_public);

        let mut wrap_key =
            kdf::derive_key32(shared.as_bytes(), kdf::DEFAULT_SALT, kdf::INFO_SEAL_KEY)?;

        let mut nonce = [0u8; aead::NONCE_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

        let ciphertext = aead::seal(&wrap_key, &nonce, SEAL_AAD, content_key)?;
        wrap_key.zeroize();

        Ok(Self {
            ephemeral_public,
            nonce,
            ciphertext,
        })
    }

    /// Open the sealed key using the recipient's X25519 secret.
    ///
    /// # Errors
    /// Returns [`CryptoError::Decrypt`] on failure, or
    /// [`CryptoError::InvalidPublicKey`] for a degenerate sender key.
    pub fn open(&self, recipient_secret: &[u8; 32]) -> Result<[u8; KEY_LEN], CryptoError> {
        let recipient = StaticSecret::from(*recipient_secret);
        let ephemeral_public = X25519Public::from(self.ephemeral_public);
        let shared = recipient.diffie_hellman(&ephemeral_public);

        if shared.as_bytes().iter().all(|b| *b == 0) {
            return Err(CryptoError::InvalidPublicKey);
        }

        let mut wrap_key =
            kdf::derive_key32(shared.as_bytes(), kdf::DEFAULT_SALT, kdf::INFO_SEAL_KEY)?;
        let plaintext = aead::open(&wrap_key, &self.nonce, SEAL_AAD, &self.ciphertext);
        wrap_key.zeroize();

        let plaintext = plaintext?;
        if plaintext.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&plaintext);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn only_the_recipient_can_open() {
        let recipient = Identity::generate();
        let other = Identity::generate();
        let content_key = [42u8; KEY_LEN];

        let sealed = SealedKey::seal(&content_key, &recipient.ecdh_public()).unwrap();
        assert_eq!(
            sealed.open(&recipient.ecdh_secret_bytes()).unwrap(),
            content_key
        );
        assert_eq!(
            sealed.open(&other.ecdh_secret_bytes()),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn encoded_length_is_stable() {
        let recipient = Identity::generate();
        let sealed = SealedKey::seal(&[0u8; KEY_LEN], &recipient.ecdh_public()).unwrap();
        assert_eq!(sealed.ciphertext.len(), KEY_LEN + 16);
        assert_eq!(SealedKey::ENCODED_LEN, 104);
    }
}
