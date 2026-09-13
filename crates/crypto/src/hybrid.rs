//! Hybrid post-quantum sealing: X25519 + ML-KEM-768.
//!
//! Dead drops are long-lived, so "harvest now, decrypt later" is a real threat.
//! This module combines a classical X25519 ECDH with an ML-KEM-768
//! encapsulation and mixes both shared secrets through HKDF, so the wrap is
//! secure as long as **either** primitive holds. It powers
//! [`crate::CryptoSuite::Hybrid25519MlKem768`].
//!
//! Only the key-encapsulation (confidentiality) side is hybridised here;
//! signatures remain Ed25519 for now.

use core::fmt;

use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::aead;
use crate::error::CryptoError;
use crate::kdf::{self, KEY_LEN};

const HYBRID_CONTEXT: &[u8] = b"keepstone/v1/hybrid-seal";

type Encapsulation = EncapsulationKey<MlKem768>;
type Decapsulation = DecapsulationKey<MlKem768>;

/// A hybrid keypair: an X25519 secret and an ML-KEM-768 decapsulation key.
pub struct HybridKeypair {
    x25519: StaticSecret,
    kem: Decapsulation,
    kem_public: Vec<u8>,
}

impl fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridKeypair([REDACTED])")
    }
}

/// The public half of a hybrid keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublic {
    /// X25519 public key.
    pub x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key bytes.
    pub kem: Vec<u8>,
}

/// A content key sealed under a hybrid public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSealed {
    /// Ephemeral X25519 public key.
    pub ephemeral_x25519: [u8; 32],
    /// ML-KEM-768 ciphertext bytes.
    pub kem_ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; aead::NONCE_LEN],
    /// AEAD ciphertext of the content key.
    pub ciphertext: Vec<u8>,
}

fn mix(shared: &[u8], kem_shared: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut ikm = Vec::with_capacity(shared.len() + kem_shared.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(kem_shared);
    let mut key = kdf::derive_key32(&ikm, HYBRID_CONTEXT, kdf::INFO_SEAL_KEY)?;
    let out = key;
    key.zeroize();
    Ok(out)
}

impl HybridKeypair {
    /// Generate a fresh hybrid keypair.
    #[must_use]
    pub fn generate() -> Self {
        let (kem, encapsulation) = MlKem768::generate_keypair();
        let kem_public = encapsulation.to_bytes().as_slice().to_vec();
        let x25519 = StaticSecret::random_from_rng(OsRng);
        Self {
            x25519,
            kem,
            kem_public,
        }
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> HybridPublic {
        HybridPublic {
            x25519: X25519Public::from(&self.x25519).to_bytes(),
            kem: self.kem_public.clone(),
        }
    }

    /// Open a value sealed to this keypair's public half.
    ///
    /// # Errors
    /// Returns [`CryptoError::Decrypt`] on any failure.
    pub fn open(&self, sealed: &HybridSealed) -> Result<[u8; KEY_LEN], CryptoError> {
        let shared = self
            .x25519
            .diffie_hellman(&X25519Public::from(sealed.ephemeral_x25519));
        let kem_shared = self
            .kem
            .decapsulate_slice(&sealed.kem_ciphertext)
            .map_err(|_| CryptoError::Decrypt)?;

        let mut key = mix(shared.as_bytes(), kem_shared.as_slice())?;
        let plaintext = aead::open(&key, &sealed.nonce, HYBRID_CONTEXT, &sealed.ciphertext);
        key.zeroize();

        let plaintext = plaintext?;
        if plaintext.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&plaintext);
        Ok(out)
    }
}

/// Seal `content_key` to a hybrid public key.
///
/// # Errors
/// Returns [`CryptoError`] on invalid keys, RNG, or KEM failure.
pub fn seal(
    content_key: &[u8; KEY_LEN],
    recipient: &HybridPublic,
) -> Result<HybridSealed, CryptoError> {
    let mut rng = OsRng;
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&X25519Public::from(recipient.x25519));

    let encapsulation = <Encapsulation as TryKeyInit>::new_from_slice(&recipient.kem)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let (kem_ciphertext, kem_shared) = encapsulation.encapsulate();

    let mut key = mix(shared.as_bytes(), kem_shared.as_slice())?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ciphertext = aead::seal(&key, &nonce, HYBRID_CONTEXT, content_key)?;
    key.zeroize();

    Ok(HybridSealed {
        ephemeral_x25519: ephemeral_public,
        kem_ciphertext: kem_ciphertext.as_slice().to_vec(),
        nonce,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_seal_opens_with_the_right_keypair() {
        let recipient = HybridKeypair::generate();
        let content_key = [42u8; KEY_LEN];
        let sealed = seal(&content_key, &recipient.public()).unwrap();
        assert_eq!(recipient.open(&sealed).unwrap(), content_key);
    }

    #[test]
    fn hybrid_seal_rejects_the_wrong_keypair() {
        let recipient = HybridKeypair::generate();
        let other = HybridKeypair::generate();
        let sealed = seal(&[1u8; KEY_LEN], &recipient.public()).unwrap();
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn public_bytes_have_expected_sizes() {
        let recipient = HybridKeypair::generate();
        let public = recipient.public();
        // ML-KEM-768 encapsulation key is 1184 bytes.
        assert_eq!(public.kem.len(), 1184);
        let sealed = seal(&[0u8; KEY_LEN], &public).unwrap();
        // ML-KEM-768 ciphertext is 1088 bytes.
        assert_eq!(sealed.kem_ciphertext.len(), 1088);
    }
}
