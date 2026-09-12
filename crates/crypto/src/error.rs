//! Error types for the cryptographic core.

use thiserror::Error;

/// Errors produced by the cryptographic core.
///
/// These are intentionally coarse: callers must not be able to distinguish
/// failure modes in a way that leaks information (no decryption oracle).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A key or nonce had the wrong length.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// Decryption or authentication failed.
    #[error("decryption failed")]
    Decrypt,
    /// Signature verification failed.
    #[error("signature verification failed")]
    Verify,
    /// A low-order / degenerate public key was supplied.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The crypto suite identifier is not supported.
    #[error("unsupported crypto suite")]
    UnsupportedSuite,
}
