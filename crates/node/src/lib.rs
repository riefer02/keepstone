//! Node abstractions: clock, storage, and delivery traits.
//!
//! This crate is where I/O is allowed. `core`, `crypto`, and `log` stay pure so
//! they remain deterministic and easy to test. Concrete transports (libp2p) and
//! persistent storage arrive in M2; here we define the seams and provide
//! in-memory implementations for tests.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::collections::HashMap;

use keepstone_core::DropId;
use thiserror::Error;

/// Errors from node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    /// The requested item was not found.
    #[error("not found")]
    NotFound,
}

/// A source of wall-clock time. Injected so tests are deterministic.
pub trait Clock: Send + Sync {
    /// Current Unix time in seconds.
    fn now_unix(&self) -> u64;
}

/// The real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A fixed clock for tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// Storage for drops and their ciphertext chunks.
pub trait Storage {
    /// Store a signed drop envelope.
    fn put_drop(&mut self, id: DropId, bytes: Vec<u8>);
    /// Fetch a signed drop envelope.
    fn get_drop(&self, id: &DropId) -> Option<&[u8]>;
    /// Store one ciphertext chunk.
    fn put_chunk(&mut self, id: DropId, index: u32, bytes: Vec<u8>);
    /// Fetch one ciphertext chunk.
    fn get_chunk(&self, id: &DropId, index: u32) -> Option<&[u8]>;
    /// List chunk indices held for a drop, ascending.
    fn chunk_indices(&self, id: &DropId) -> Vec<u32>;
}

/// An in-memory [`Storage`] implementation.
#[derive(Debug, Default)]
pub struct MemoryStore {
    drops: HashMap<DropId, Vec<u8>>,
    chunks: HashMap<(DropId, u32), Vec<u8>>,
}

impl MemoryStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStore {
    fn put_drop(&mut self, id: DropId, bytes: Vec<u8>) {
        self.drops.insert(id, bytes);
    }

    fn get_drop(&self, id: &DropId) -> Option<&[u8]> {
        self.drops.get(id).map(Vec::as_slice)
    }

    fn put_chunk(&mut self, id: DropId, index: u32, bytes: Vec<u8>) {
        self.chunks.insert((id, index), bytes);
    }

    fn get_chunk(&self, id: &DropId, index: u32) -> Option<&[u8]> {
        self.chunks.get(&(*id, index)).map(Vec::as_slice)
    }

    fn chunk_indices(&self, id: &DropId) -> Vec<u32> {
        let mut indices: Vec<u32> = self
            .chunks
            .keys()
            .filter(|(d, _)| d == id)
            .map(|(_, i)| *i)
            .collect();
        indices.sort_unstable();
        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trips() {
        let mut store = MemoryStore::new();
        let id = DropId::of(b"drop");
        store.put_drop(id, b"envelope".to_vec());
        store.put_chunk(id, 1, b"one".to_vec());
        store.put_chunk(id, 0, b"zero".to_vec());
        assert_eq!(store.get_drop(&id), Some(&b"envelope"[..]));
        assert_eq!(store.get_chunk(&id, 0), Some(&b"zero"[..]));
        assert_eq!(store.chunk_indices(&id), vec![0, 1]);
    }

    #[test]
    fn fixed_clock_is_stable() {
        assert_eq!(FixedClock(42).now_unix(), 42);
    }
}
