//! Hybrid post-quantum signatures: Ed25519 + ML-DSA-65.
//!
//! Complements [`crate::hybrid`] (the KEM side). A hybrid signature is valid
//! only if **both** the classical Ed25519 signature and the ML-DSA-65 signature
//! verify, so it remains sound as long as either scheme is unbroken. The cost
//! is size: ML-DSA-65 signatures are 3309 bytes.
//!
//! This is the signature half of [`crate::CryptoSuite::Hybrid25519MlKem768`];
//! wiring it into the drop envelope is a follow-up.

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, Signature, Signer,
    SigningKey as MlDsaSigningKey, Verifier, VerifyingKey as MlDsaVerifyingKey,
};
use rand::rngs::OsRng;

use crate::error::CryptoError;
use crate::keys::verify as verify_ed25519;

/// Length of an ML-DSA-65 verifying key.
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature.
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// A hybrid signing key (secret).
pub struct HybridSigningKey {
    ed25519: SigningKey,
    ml_dsa: MlDsaSigningKey<MlDsa65>,
}

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSigningKey([REDACTED])")
    }
}

/// A hybrid verifying key (public).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    /// Ed25519 public key.
    pub ed25519: [u8; 32],
    /// ML-DSA-65 verifying key bytes.
    pub ml_dsa: Vec<u8>,
}

/// A hybrid signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature.
    pub ed25519: [u8; 64],
    /// ML-DSA-65 signature bytes.
    pub ml_dsa: Vec<u8>,
}

impl HybridSigningKey {
    /// Generate a fresh hybrid signing key.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            ed25519: SigningKey::generate(&mut OsRng),
            ml_dsa: MlDsaSigningKey::<MlDsa65>::generate(),
        }
    }

    /// The public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed25519: self.ed25519.verifying_key().to_bytes(),
            ml_dsa: self.ml_dsa.verifying_key().to_bytes().as_slice().to_vec(),
        }
    }

    /// Sign a message with both schemes.
    ///
    /// # Errors
    /// Returns [`CryptoError::Encrypt`] if ML-DSA signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature, CryptoError> {
        let ed25519 = self.ed25519.sign(message).to_bytes();
        let ml_dsa = self
            .ml_dsa
            .try_sign(message)
            .map_err(|_| CryptoError::Encrypt)?;
        Ok(HybridSignature {
            ed25519,
            ml_dsa: ml_dsa.encode().as_slice().to_vec(),
        })
    }
}

/// Verify a hybrid signature; both halves must verify.
///
/// # Errors
/// Returns [`CryptoError::Verify`] if either signature fails.
pub fn verify(
    key: &HybridVerifyingKey,
    message: &[u8],
    signature: &HybridSignature,
) -> Result<(), CryptoError> {
    verify_ed25519(&key.ed25519, message, &signature.ed25519)?;

    let verifying_key = MlDsaVerifyingKey::<MlDsa65>::new_from_slice(&key.ml_dsa)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let ml_dsa_signature = Signature::<MlDsa65>::try_from(signature.ml_dsa.as_slice())
        .map_err(|_| CryptoError::Verify)?;
    verifying_key
        .verify(message, &ml_dsa_signature)
        .map_err(|_| CryptoError::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_signatures_round_trip() {
        let key = HybridSigningKey::generate();
        let signature = key.sign(b"the eagle lands at midnight").unwrap();
        verify(
            &key.verifying_key(),
            b"the eagle lands at midnight",
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn tampering_or_wrong_key_fails() {
        let key = HybridSigningKey::generate();
        let other = HybridSigningKey::generate();
        let signature = key.sign(b"message").unwrap();

        assert!(verify(&key.verifying_key(), b"tampered", &signature).is_err());
        assert!(verify(&other.verifying_key(), b"message", &signature).is_err());

        let mut broken = signature;
        broken.ed25519[0] ^= 0x01;
        assert!(verify(&key.verifying_key(), b"message", &broken).is_err());
    }

    #[test]
    fn sizes_are_as_expected() {
        let key = HybridSigningKey::generate();
        let public = key.verifying_key();
        assert_eq!(public.ml_dsa.len(), ML_DSA_65_VK_LEN);
        let signature = key.sign(b"x").unwrap();
        assert_eq!(signature.ml_dsa.len(), ML_DSA_65_SIG_LEN);
    }
}
