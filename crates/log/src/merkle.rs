//! RFC 6962 Merkle tree hashing, inclusion proofs, and consistency proofs.

use sha2::{Digest, Sha256};

use crate::LogError;

/// A 32-byte SHA-256 hash.
pub type Hash = [u8; 32];

/// Hash of a data entry: `SHA-256(0x00 || data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash of an internal node: `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The Merkle Tree Hash of `leaves` (already leaf-hashed), per RFC 6962.
#[must_use]
pub fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_less(n);
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

/// The largest power of two strictly less than `n` (for `n > 1`).
fn largest_power_of_two_less(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The Merkle Tree Hash over raw data entries.
#[must_use]
pub fn mth_data(entries: &[Vec<u8>]) -> Hash {
    let leaves: Vec<Hash> = entries.iter().map(|e| leaf_hash(e)).collect();
    mth(&leaves)
}

/// Generate an inclusion proof for leaf `index` in a tree of `leaves`.
///
/// # Errors
/// Returns [`LogError::IndexOutOfRange`] if `index` is not a leaf.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Result<Vec<Hash>, LogError> {
    if index >= leaves.len() {
        return Err(LogError::IndexOutOfRange);
    }
    Ok(path(leaves, index))
}

fn path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_less(n);
    let mut proof = if index < k {
        path(&leaves[..k], index)
    } else {
        path(&leaves[k..], index - k)
    };
    if index < k {
        proof.push(mth(&leaves[k..]));
    } else {
        proof.push(mth(&leaves[..k]));
    }
    proof
}

/// Verify an inclusion proof.
#[must_use]
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    if index >= tree_size || tree_size == 0 {
        return false;
    }
    match compute_root(leaf, index, tree_size, proof, 0) {
        Some((computed, used)) => used == proof.len() && &computed == root,
        None => false,
    }
}

fn compute_root(
    leaf: &Hash,
    index: usize,
    n: usize,
    proof: &[Hash],
    pos: usize,
) -> Option<(Hash, usize)> {
    if n == 0 {
        return None;
    }
    if n == 1 {
        return Some((*leaf, pos));
    }
    let k = largest_power_of_two_less(n);
    if index < k {
        let (left, next) = compute_root(leaf, index, k, proof, pos)?;
        let right = *proof.get(next)?;
        Some((node_hash(&left, &right), next + 1))
    } else {
        let (right, next) = compute_root(leaf, index - k, n - k, proof, pos)?;
        let left = *proof.get(next)?;
        Some((node_hash(&left, &right), next + 1))
    }
}

/// Generate a consistency proof that the first `m` leaves are a prefix of the
/// tree of `leaves`.
///
/// # Errors
/// Returns [`LogError::IndexOutOfRange`] if `m > leaves.len()`.
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Result<Vec<Hash>, LogError> {
    if m > leaves.len() {
        return Err(LogError::IndexOutOfRange);
    }
    if m == 0 || m == leaves.len() {
        return Ok(Vec::new());
    }
    Ok(subproof(m, leaves, true))
}

fn subproof(m: usize, leaves: &[Hash], old_known: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if old_known {
            Vec::new()
        } else {
            vec![mth(leaves)]
        };
    }
    let k = largest_power_of_two_less(n);
    let mut proof = if m <= k {
        subproof(m, &leaves[..k], old_known)
    } else {
        subproof(m - k, &leaves[k..], false)
    };
    if m <= k {
        proof.push(mth(&leaves[k..]));
    } else {
        proof.push(mth(&leaves[..k]));
    }
    proof
}

/// Verify a consistency proof between `old_root` (size `m`) and `new_root`
/// (size `n`).
#[must_use]
pub fn verify_consistency(
    m: usize,
    n: usize,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if m > n {
        return false;
    }
    if m == 0 {
        let empty = mth(&[]);
        return proof.is_empty() && old_root == &empty;
    }
    if m == n {
        return proof.is_empty() && old_root == new_root;
    }
    match verify_subproof(m, n, old_root, proof, 0, true) {
        Some((old, new, used)) => used == proof.len() && &old == old_root && &new == new_root,
        None => false,
    }
}

fn verify_subproof(
    m: usize,
    n: usize,
    old_root: &Hash,
    proof: &[Hash],
    pos: usize,
    old_known: bool,
) -> Option<(Hash, Hash, usize)> {
    if m == n {
        if old_known {
            return Some((*old_root, *old_root, pos));
        }
        let h = *proof.get(pos)?;
        return Some((h, h, pos + 1));
    }
    let k = largest_power_of_two_less(n);
    if m <= k {
        let (old, new_left, next) = verify_subproof(m, k, old_root, proof, pos, old_known)?;
        let right = *proof.get(next)?;
        Some((old, node_hash(&new_left, &right), next + 1))
    } else {
        let (old_right, new_right, next) =
            verify_subproof(m - k, n - k, old_root, proof, pos, false)?;
        let left = *proof.get(next)?;
        Some((
            node_hash(&left, &old_right),
            node_hash(&left, &new_right),
            next + 1,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(format!("entry-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn empty_tree_hash_matches_empty_sha256() {
        let digest = Sha256::digest([]);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&digest);
        assert_eq!(mth(&[]), expected);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let l = leaves(1);
        assert_eq!(mth(&l), l[0]);
    }

    #[test]
    fn inclusion_verifies_for_all_sizes_and_indices() {
        for n in 1..=64usize {
            let l = leaves(n);
            let root = mth(&l);
            for index in 0..n {
                let proof = inclusion_proof(&l, index).unwrap();
                assert!(
                    verify_inclusion(&l[index], index, n, &proof, &root),
                    "n={n} index={index}"
                );
                // A wrong leaf must not verify.
                let wrong = leaf_hash(b"nope");
                assert!(!verify_inclusion(&wrong, index, n, &proof, &root));
            }
        }
    }

    #[test]
    fn consistency_verifies_for_all_prefixes() {
        for n in 1..=48usize {
            let l = leaves(n);
            let new_root = mth(&l);
            for m in 0..=n {
                let old_root = mth(&l[..m]);
                let proof = consistency_proof(&l, m).unwrap();
                assert!(
                    verify_consistency(m, n, &old_root, &new_root, &proof),
                    "m={m} n={n}"
                );
                // Wrong old root must fail.
                let wrong = leaf_hash(b"wrong");
                assert!(!verify_consistency(m, n, &wrong, &new_root, &proof));
            }
        }
    }
}
