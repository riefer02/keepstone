//! Cryptographic core for Keepstone.
//!
//! This crate is a *pure leaf*: it performs no I/O, reads no clock, and forbids
//! `unsafe`. It composes vetted primitives (RustCrypto + dalek) under a single,
//! versioned [`CryptoSuite`] and enforces the project's key-handling rules:
//! every secret is zeroized on drop and never rendered in `Debug` output.
//!
//! # The lock
//!
//! The recipient key is the lock. Content is encrypted under a per-drop
//! **content key**, which is sealed to each recipient device's X25519 key using
//! ephemeral-static ECDH (a "sealed box"). Location is an access gate, never the
//! confidentiality guarantee.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod aead;
pub mod error;
pub mod hybrid;
pub mod hybrid_sig;
pub mod kdf;
pub mod keys;
pub mod sealed;
pub mod secret;
pub mod shamir;
pub mod stream;
pub mod suite;

pub use error::CryptoError;
pub use hybrid::{HybridKeypair, HybridPublic, HybridSealed};
pub use hybrid_sig::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
pub use keys::{verify, Identity};
pub use sealed::SealedKey;
pub use secret::SecretBytes;
pub use shamir::Share;
pub use suite::CryptoSuite;
