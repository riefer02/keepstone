//! An untrusted relay for federated store-and-forward.
//!
//! A relay is **ciphertext-only by construction**: it has no key material and
//! exposes no decryption capability. It can affect availability and metadata,
//! but never confidentiality.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::collections::HashMap;

use keepstone_core::DropId;
use thiserror::Error;

/// Errors from relay operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayError {
    /// The requested chunk is not held.
    #[error("chunk not found")]
    NotFound,
}

/// A minimal in-memory relay.
#[derive(Debug, Default)]
pub struct Relay {
    chunks: HashMap<(DropId, u32), Vec<u8>>,
}

impl Relay {
    /// Create an empty relay.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a ciphertext chunk.
    pub fn store(&mut self, id: DropId, index: u32, ciphertext: Vec<u8>) {
        self.chunks.insert((id, index), ciphertext);
    }

    /// Fetch a ciphertext chunk.
    ///
    /// # Errors
    /// Returns [`RelayError::NotFound`] when the chunk is absent.
    pub fn fetch(&self, id: &DropId, index: u32) -> Result<&[u8], RelayError> {
        self.chunks
            .get(&(*id, index))
            .map(Vec::as_slice)
            .ok_or(RelayError::NotFound)
    }

    /// Number of stored chunks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the relay holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_returns_opaque_bytes() {
        let mut relay = Relay::new();
        let id = DropId::of(b"drop");
        relay.store(id, 0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(relay.fetch(&id, 0).unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(relay.fetch(&id, 1), Err(RelayError::NotFound));
    }
}
