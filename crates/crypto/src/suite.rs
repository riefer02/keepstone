//! Versioned cryptographic suites (algorithm agility).

use crate::error::CryptoError;

/// Identifies a concrete, versioned set of cryptographic algorithms.
///
/// Every signed or encrypted object in Keepstone carries a suite identifier so
/// the protocol can migrate (e.g. to post-quantum hybrids) without a flag day.
/// Unknown suites must **fail closed**.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CryptoSuite {
    /// X25519 + Ed25519 + XChaCha20-Poly1305 + HKDF-SHA256 + SHA-256.
    Classical25519 = 1,
    /// X25519 + ML-KEM-768 (hybrid KEM) + Ed25519 + XChaCha20-Poly1305.
    Hybrid25519MlKem768 = 2,
}

impl CryptoSuite {
    /// The wire identifier for this suite.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parse a suite identifier, rejecting anything unsupported.
    ///
    /// # Errors
    /// Returns [`CryptoError::UnsupportedSuite`] for unknown identifiers.
    pub const fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Self::Classical25519),
            2 => Ok(Self::Hybrid25519MlKem768),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }

    /// The suite that this build uses by default.
    #[must_use]
    pub const fn default_suite() -> Self {
        Self::Classical25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_id() {
        for suite in [
            CryptoSuite::Classical25519,
            CryptoSuite::Hybrid25519MlKem768,
        ] {
            assert_eq!(CryptoSuite::from_id(suite.id()), Ok(suite));
        }
    }

    #[test]
    fn rejects_unknown_id() {
        assert_eq!(CryptoSuite::from_id(0), Err(CryptoError::UnsupportedSuite));
        assert_eq!(
            CryptoSuite::from_id(255),
            Err(CryptoError::UnsupportedSuite)
        );
    }
}
