//! An RFC 6962-style append-only Merkle transparency log.
//!
//! The log gives *tamper-evidence without consensus*: an inclusion proof shows
//! a leaf is in the tree, and a consistency proof shows a newer tree is a
//! superset of an older one. A log that equivocates is detectable.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod merkle;
pub mod sth;

pub use merkle::{mth, Hash};
pub use sth::SignedTreeHead;

use thiserror::Error;

/// Errors from the log.
#[derive(Debug, Error)]
pub enum LogError {
    /// The requested index was out of range.
    #[error("index out of range")]
    IndexOutOfRange,
    /// A proof failed to verify.
    #[error("proof verification failed")]
    ProofInvalid,
    /// A signed tree head failed to verify.
    #[error("tree head verification failed")]
    TreeHeadInvalid,
}
