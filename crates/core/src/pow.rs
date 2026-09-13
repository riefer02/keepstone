//! Hashcash-style proof-of-work for drop creation (anti-spam).
//!
//! PoW makes flooding a location expensive without requiring a token or a
//! central rate limiter. The work is bound to the signer and the drop's content
//! commitment, so it cannot be reused across drops.

use crate::types::sha256;

/// Required leading zero bits. Tuned to be cheap for a client, costly at scale.
pub const POW_DIFFICULTY_BITS: u32 = 12;

/// Domain-separation context for PoW.
pub const POW_CONTEXT: &[u8] = b"keepstone/v1/pow";

/// Count leading zero bits of a 32-byte digest.
#[must_use]
pub fn leading_zero_bits(bytes: &[u8; 32]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// The PoW digest for a candidate nonce.
#[must_use]
pub fn digest(
    signer: &[u8; 32],
    content_root: &[u8; 32],
    drop_nonce: &[u8; 16],
    nonce: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(POW_CONTEXT.len() + 32 + 32 + 16 + 8);
    buf.extend_from_slice(POW_CONTEXT);
    buf.extend_from_slice(signer);
    buf.extend_from_slice(content_root);
    buf.extend_from_slice(drop_nonce);
    buf.extend_from_slice(&nonce.to_be_bytes());
    sha256(&buf)
}

/// Whether `nonce` satisfies the difficulty target.
#[must_use]
pub fn is_valid(
    signer: &[u8; 32],
    content_root: &[u8; 32],
    drop_nonce: &[u8; 16],
    nonce: u64,
) -> bool {
    leading_zero_bits(&digest(signer, content_root, drop_nonce, nonce)) >= POW_DIFFICULTY_BITS
}

/// Find a nonce satisfying the difficulty target.
#[must_use]
pub fn mine(signer: &[u8; 32], content_root: &[u8; 32], drop_nonce: &[u8; 16]) -> u64 {
    let mut nonce = 0u64;
    loop {
        if is_valid(signer, content_root, drop_nonce, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_are_counted() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        assert_eq!(
            leading_zero_bits(&[
                0x00, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ]),
            12
        );
        assert_eq!(
            leading_zero_bits(&[
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            0
        );
    }

    #[test]
    fn mined_nonce_verifies() {
        let signer = [1u8; 32];
        let root = [2u8; 32];
        let nonce_field = [3u8; 16];
        let nonce = mine(&signer, &root, &nonce_field);
        assert!(is_valid(&signer, &root, &nonce_field, nonce));
        // A different signer's work does not transfer.
        assert!(!is_valid(&[9u8; 32], &root, &nonce_field, nonce));
    }
}
