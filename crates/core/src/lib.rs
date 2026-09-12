//! Core types, addressing, canonical encoding, and signed drop envelopes.
//!
//! This crate is **pure**: it performs no I/O, reads no clock, and forbids
//! `unsafe`. It defines the wire types and the rules that make them safe to
//! sign.
//!
//! # Byte preservation (decision D2)
//!
//! The identity of a received object is `SHA-256` of the **exact bytes as
//! transmitted**. We never recompute a signature or an ID from a re-encoding;
//! the canonical encoding is used only for *locally constructed* objects.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod cbor;
pub mod error;
pub mod types;

pub use address::CellId;
pub use error::CoreError;
pub use types::{
    content_root, sha256, signing_input, DropBody, DropId, Mode, SignedDrop, WrappedKey,
    PROTOCOL_VERSION,
};
