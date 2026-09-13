//! Signed tree heads (STHs) for the transparency log.

use keepstone_crypto::{verify, Identity};

use crate::merkle::Hash;
use crate::LogError;

/// Domain-separation context for STH signatures.
pub const STH_CONTEXT: &[u8] = b"keepstone/v1/sth";

/// A log's signed commitment to its current tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Number of leaves in the tree.
    pub tree_size: u64,
    /// Merkle Tree Hash of the tree.
    pub root: Hash,
    /// Unix seconds at signing time.
    pub timestamp: u64,
    /// Log's Ed25519 public key.
    pub log_public: [u8; 32],
    /// Log's signature.
    pub signature: [u8; 64],
}

/// The exact bytes signed by a log for an STH.
#[must_use]
pub fn sth_input(tree_size: u64, root: &Hash, timestamp: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(STH_CONTEXT.len() + 8 + 32 + 8);
    out.extend_from_slice(STH_CONTEXT);
    out.extend_from_slice(&tree_size.to_be_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

impl SignedTreeHead {
    /// Sign a tree head with the log's identity.
    #[must_use]
    pub fn sign(signer: &Identity, tree_size: u64, root: Hash, timestamp: u64) -> Self {
        let signature = signer.sign(&sth_input(tree_size, &root, timestamp));
        Self {
            tree_size,
            root,
            timestamp,
            log_public: signer.signing_public(),
            signature,
        }
    }

    /// Verify the log's signature.
    ///
    /// # Errors
    /// Returns [`LogError::TreeHeadInvalid`] on failure.
    pub fn verify(&self) -> Result<(), LogError> {
        verify(
            &self.log_public,
            &sth_input(self.tree_size, &self.root, self.timestamp),
            &self.signature,
        )
        .map_err(|_| LogError::TreeHeadInvalid)
    }
}

/// Whether two signed tree heads from the same log equivocate.
///
/// Equivocation is two different roots at the **same tree size**. Detecting it
/// is how clients catch a log that shows different histories to different
/// people. Returns `false` for consistent STHs (including one being a proper
/// prefix of the other, which is covered by consistency proofs).
#[must_use]
pub fn detect_equivocation(a: &SignedTreeHead, b: &SignedTreeHead) -> bool {
    a.tree_size == b.tree_size && a.root != b.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{leaf_hash, mth};

    #[test]
    fn sth_signs_and_verifies() {
        let log = Identity::generate();
        let root = mth(&[leaf_hash(b"a"), leaf_hash(b"b")]);
        let sth = SignedTreeHead::sign(&log, 2, root, 1_700_000_000);
        sth.verify().unwrap();
    }

    #[test]
    fn tampered_sth_fails() {
        let log = Identity::generate();
        let sth = SignedTreeHead::sign(&log, 1, [1u8; 32], 1);
        let mut bad = sth;
        bad.tree_size = 2;
        assert!(bad.verify().is_err());
    }

    #[test]
    fn equivocation_is_detected() {
        let log = Identity::generate();
        let a = SignedTreeHead::sign(&log, 3, [1u8; 32], 1);
        let b = SignedTreeHead::sign(&log, 3, [2u8; 32], 2);
        assert!(detect_equivocation(&a, &b));
        // Same root at the same size is not equivocation.
        let c = SignedTreeHead::sign(&log, 3, [1u8; 32], 3);
        assert!(!detect_equivocation(&a, &c));
        // Different sizes are not equivocation (consistency applies instead).
        let d = SignedTreeHead::sign(&log, 4, [1u8; 32], 4);
        assert!(!detect_equivocation(&a, &d));
    }
}
