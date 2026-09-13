//! Property-based tests for the RFC 6962 Merkle log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use keepstone_log::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, mth, verify_consistency, verify_inclusion, Hash,
};

use proptest::prelude::*;

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| leaf_hash(format!("entry-{i}").as_bytes()))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn inclusion_holds_for_random_shapes(n in 1usize..=300, index in 0usize..300) {
        prop_assume!(index < n);
        let leaves = leaves(n);
        let root = mth(&leaves);
        let proof = inclusion_proof(&leaves, index).unwrap();
        prop_assert!(verify_inclusion(&leaves[index], index, n, &proof, &root));
        // A wrong leaf never verifies.
        prop_assert!(!verify_inclusion(&leaf_hash(b"nope"), index, n, &proof, &root));
    }

    #[test]
    fn consistency_holds_for_random_shapes(n in 1usize..=300, m in 0usize..300) {
        prop_assume!(m <= n);
        let leaves = leaves(n);
        let new_root = mth(&leaves);
        let old_root = mth(&leaves[..m]);
        let proof = consistency_proof(&leaves, m).unwrap();
        prop_assert!(verify_consistency(m, n, &old_root, &new_root, &proof));
        prop_assert!(!verify_consistency(m, n, &leaf_hash(b"wrong"), &new_root, &proof));
    }
}
