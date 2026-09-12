//! Identity keys: Ed25519 for signing, X25519 for key agreement.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::error::CryptoError;

/// A device identity: a long-term signing key plus a key-agreement key.
///
/// In the default (single-device) configuration this is the user's device
/// identity. In multi-device mode, each device holds its own `Identity`, and an
/// account root authorizes the device public keys.
pub struct Identity {
    signing: SigningKey,
    ecdh: StaticSecret,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity([REDACTED])")
    }
}

impl Identity {
    /// Generate a fresh identity from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        let ecdh = StaticSecret::random_from_rng(rng);
        Self { signing, ecdh }
    }

    /// Reconstruct an identity from raw secret bytes.
    #[must_use]
    pub fn from_secret_bytes(signing: &[u8; 32], ecdh: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(signing),
            ecdh: StaticSecret::from(*ecdh),
        }
    }

    /// The Ed25519 public (verifying) key.
    #[must_use]
    pub fn signing_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The X25519 public key.
    #[must_use]
    pub fn ecdh_public(&self) -> [u8; 32] {
        X25519Public::from(&self.ecdh).to_bytes()
    }

    /// Export the Ed25519 secret bytes (handle with care).
    #[must_use]
    pub fn signing_secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Export the X25519 secret bytes (handle with care).
    #[must_use]
    pub fn ecdh_secret_bytes(&self) -> [u8; 32] {
        self.ecdh.to_bytes()
    }

    /// Sign a message with the device signing key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Verify an Ed25519 signature over `message` by `public`.
///
/// # Errors
/// Returns [`CryptoError::Verify`] on any failure.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::Verify)?;
    let sig = Signature::from_bytes(signature);
    key.verify(message, &sig).map_err(|_| CryptoError::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let id = Identity::generate();
        let sig = id.sign(b"drop body");
        assert!(verify(&id.signing_public(), b"drop body", &sig).is_ok());
        assert_eq!(
            verify(&id.signing_public(), b"tampered", &sig),
            Err(CryptoError::Verify)
        );
    }

    #[test]
    fn secret_round_trip_reproduces_public_keys() {
        let id = Identity::generate();
        let restored =
            Identity::from_secret_bytes(&id.signing_secret_bytes(), &id.ecdh_secret_bytes());
        assert_eq!(restored.signing_public(), id.signing_public());
        assert_eq!(restored.ecdh_public(), id.ecdh_public());
    }

    #[test]
    fn debug_is_redacted() {
        let id = Identity::generate();
        assert_eq!(format!("{id:?}"), "Identity([REDACTED])");
    }
}
