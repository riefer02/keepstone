//! Error types for the core crate.

use thiserror::Error;

/// Errors produced by core types and encoding.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Canonical CBOR encoding or decoding failed.
    #[error("cbor: {0}")]
    Cbor(&'static str),
    /// A cryptographic operation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] keepstone_crypto::CryptoError),
    /// A cell identifier could not be parsed or computed.
    #[error("cell: {0}")]
    Cell(String),
    /// A length or count did not match expectations.
    #[error("length mismatch")]
    Length,
    /// A signature did not verify.
    #[error("signature verification failed")]
    Verify,
    /// A structurally valid object failed a semantic check.
    #[error("invalid: {0}")]
    Invalid(&'static str),
}
