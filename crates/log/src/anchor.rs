//! External anchoring of signed tree heads.
//!
//! A transparency log is only as trustworthy as the evidence that its history
//! was not rewritten. Anchoring commits a tree head to an **external**,
//! append-only medium so that a later equivocation is provable to third
//! parties.
//!
//! The [`Anchor`] trait is deliberately backend-agnostic. This crate ships a
//! dependency-free [`HashChainAnchor`] (a locally verifiable, append-only hash
//! chain). OpenTimestamps (Bitcoin calendar servers) plugs in behind the same
//! trait; see ADR-0010. Because the OTS Rust ecosystem is thin and 0.2.0 does
//! not submit to calendars, the trait boundary is the important artifact.

use sha2::{Digest, Sha256};

use crate::merkle::Hash;

/// Domain-separation context for anchor links.
pub const ANCHOR_CONTEXT: &[u8] = b"keepstone/v1/anchor";

/// The all-zero hash used as the predecessor of the first link.
pub const GENESIS: Hash = [0u8; 32];

/// A receipt proving a tree head was anchored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Backend name (e.g. `"local-hashchain"`).
    pub anchor: String,
    /// Number of leaves at anchoring time.
    pub tree_size: u64,
    /// Merkle root that was anchored.
    pub root: Hash,
    /// Unix seconds at anchoring time.
    pub anchored_at: u64,
    /// The previous link in the chain ([`GENESIS`] for the first).
    pub previous: Hash,
    /// This link.
    pub link: Hash,
}

/// An external anchoring backend.
pub trait Anchor {
    /// Human-readable backend name.
    fn name(&self) -> &'static str;
    /// Commit a tree head, returning a receipt.
    fn submit(&mut self, tree_size: u64, root: &Hash, now: u64) -> AnchorReceipt;
    /// Verify a receipt against this anchor's state.
    fn verify(&self, receipt: &AnchorReceipt) -> bool;
}

/// Compute a chain link binding the predecessor, tree head, and time.
#[must_use]
pub fn link_hash(previous: &Hash, tree_size: u64, root: &Hash, now: u64) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_CONTEXT);
    hasher.update(previous);
    hasher.update(tree_size.to_be_bytes());
    hasher.update(root);
    hasher.update(now.to_be_bytes());
    hasher.finalize().into()
}

/// Verify a receipt's link is internally consistent (independent of chain
/// position). Chain membership is checked by [`verify_receipts`].
#[must_use]
pub fn verify_link(receipt: &AnchorReceipt) -> bool {
    link_hash(
        &receipt.previous,
        receipt.tree_size,
        &receipt.root,
        receipt.anchored_at,
    ) == receipt.link
}

/// Verify a sequence of receipts forms an unbroken chain.
#[must_use]
pub fn verify_receipts(receipts: &[AnchorReceipt]) -> bool {
    let mut previous = GENESIS;
    for receipt in receipts {
        if receipt.previous != previous || !verify_link(receipt) {
            return false;
        }
        previous = receipt.link;
    }
    true
}

/// A local, append-only hash-chain anchor.
#[derive(Clone, Debug, Default)]
pub struct HashChainAnchor {
    links: Vec<Hash>,
    latest: Hash,
}

impl HashChainAnchor {
    /// Create an empty anchor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            links: Vec::new(),
            latest: GENESIS,
        }
    }

    /// Rebuild an anchor from previously persisted links.
    #[must_use]
    pub fn from_links(links: Vec<Hash>) -> Self {
        let latest = links.last().copied().unwrap_or(GENESIS);
        Self { links, latest }
    }

    /// Number of committed links.
    #[must_use]
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Whether no anchors have been committed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// All committed links.
    #[must_use]
    pub fn links(&self) -> &[Hash] {
        &self.links
    }
}

impl Anchor for HashChainAnchor {
    fn name(&self) -> &'static str {
        "local-hashchain"
    }

    fn submit(&mut self, tree_size: u64, root: &Hash, now: u64) -> AnchorReceipt {
        let previous = self.latest;
        let link = link_hash(&previous, tree_size, root, now);
        self.links.push(link);
        self.latest = link;
        AnchorReceipt {
            anchor: self.name().to_owned(),
            tree_size,
            root: *root,
            anchored_at: now,
            previous,
            link,
        }
    }

    fn verify(&self, receipt: &AnchorReceipt) -> bool {
        receipt.anchor == self.name() && verify_link(receipt) && self.links.contains(&receipt.link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_records_and_verifies() {
        let mut anchor = HashChainAnchor::new();
        let r0 = anchor.submit(1, &[1u8; 32], 100);
        let r1 = anchor.submit(2, &[2u8; 32], 200);
        let r2 = anchor.submit(3, &[3u8; 32], 300);

        assert_eq!(anchor.len(), 3);
        assert!(anchor.verify(&r0));
        assert!(anchor.verify(&r1));
        assert!(anchor.verify(&r2));
        assert!(verify_receipts(&[r0.clone(), r1.clone(), r2.clone()]));

        // Links chain together.
        assert_eq!(r0.previous, GENESIS);
        assert_eq!(r1.previous, r0.link);
        assert_eq!(r2.previous, r1.link);
    }

    #[test]
    fn tampering_is_detected() {
        let mut anchor = HashChainAnchor::new();
        let receipt = anchor.submit(1, &[1u8; 32], 100);
        let mut bad = receipt.clone();
        bad.root = [9u8; 32];
        assert!(!verify_link(&bad));
        assert!(!anchor.verify(&bad));
        // A receipt not in the chain is rejected.
        assert!(!anchor.verify(&AnchorReceipt {
            link: [7u8; 32],
            ..receipt
        }));
    }

    #[test]
    fn rebuilt_chain_preserves_membership() {
        let mut anchor = HashChainAnchor::new();
        let r0 = anchor.submit(1, &[1u8; 32], 100);
        let r1 = anchor.submit(2, &[2u8; 32], 200);
        let rebuilt = HashChainAnchor::from_links(anchor.links().to_vec());
        assert!(rebuilt.verify(&r0));
        assert!(rebuilt.verify(&r1));
    }

    #[test]
    fn broken_chain_is_rejected() {
        let mut anchor = HashChainAnchor::new();
        let r0 = anchor.submit(1, &[1u8; 32], 100);
        let r1 = anchor.submit(2, &[2u8; 32], 200);
        // Drop the first receipt: the second no longer chains from genesis.
        assert!(!verify_receipts(&[r1.clone()]));
        assert!(verify_receipts(&[r0, r1]));
    }
}
