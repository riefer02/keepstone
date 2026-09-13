//! Shamir secret sharing over GF(256).
//!
//! Used by place-locked drops: the per-drop content key is split `t`-of-`n`
//! across cell custodians, so the key can only be reconstructed by collecting a
//! threshold of shares (released to a claimant who presents a valid presence
//! certificate).
//!
//! Arithmetic is over GF(2^8) with the AES polynomial `x^8 + x^4 + x^3 + x + 1`.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::CryptoError;

/// One share of a split secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// Evaluation point (`1..=n`, never zero).
    pub x: u8,
    /// Share bytes, one per secret byte.
    pub y: Vec<u8>,
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(mut base: u8, mut exp: u32) -> u8 {
    let mut result = 1u8;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

fn gf_inv(a: u8) -> u8 {
    // a^(2^8 - 2) = a^254 is the multiplicative inverse for a != 0.
    gf_pow(a, 254)
}

fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method.
    let mut acc = 0u8;
    for coeff in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ coeff;
    }
    acc
}

/// Split `secret` into `shares` shares, any `threshold` of which reconstruct it.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] for invalid thresholds or an empty
/// secret, or if randomness fails.
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, CryptoError> {
    if secret.is_empty() || threshold < 2 || shares < threshold {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut out: Vec<Share> = (1..=shares)
        .map(|x| Share {
            x,
            y: vec![0u8; secret.len()],
        })
        .collect();

    let mut rng = OsRng;
    for (byte_index, secret_byte) in secret.iter().enumerate() {
        let mut coeffs = vec![0u8; threshold as usize];
        coeffs[0] = *secret_byte;
        rng.fill_bytes(&mut coeffs[1..]);
        for share in &mut out {
            share.y[byte_index] = eval_poly(&coeffs, share.x);
        }
    }
    Ok(out)
}

/// Reconstruct a secret from at least `threshold` shares.
///
/// Returns an error if the shares are empty, have inconsistent lengths, or
/// contain a zero evaluation point.
///
/// # Errors
/// Returns [`CryptoError::InvalidKeyLength`] on malformed input.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, CryptoError> {
    if shares.len() < 2 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let len = shares[0].y.len();
    if len == 0 || shares.iter().any(|s| s.y.len() != len || s.x == 0) {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut secret = vec![0u8; len];
    for (i, share_i) in shares.iter().enumerate() {
        // Lagrange basis at x = 0: prod_{j != i} x_j / (x_j - x_i).
        let mut coefficient = 1u8;
        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let numerator = share_j.x;
            let denominator = share_j.x ^ share_i.x;
            coefficient = gf_mul(coefficient, gf_mul(numerator, gf_inv(denominator)));
        }
        for (byte_index, value) in share_i.y.iter().enumerate() {
            secret[byte_index] ^= gf_mul(*value, coefficient);
        }
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_consistent() {
        assert_eq!(gf_mul(0, 123), 0);
        assert_eq!(gf_mul(1, 123), 123);
        assert_eq!(gf_mul(2, 3), 6);
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
        }
    }

    #[test]
    fn any_threshold_subset_reconstructs() {
        let secret = [42u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Every 3-of-5 subset reconstructs the secret.
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let subset = vec![shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(combine(&subset).unwrap(), secret, "{a},{b},{c}");
                }
            }
        }
    }

    #[test]
    fn too_few_shares_do_not_reconstruct() {
        let secret = [7u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        assert_ne!(combine(&subset).unwrap(), secret);
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert!(split(&[], 2, 3).is_err());
        assert!(split(&[1, 2], 1, 3).is_err());
        assert!(split(&[1, 2], 4, 3).is_err());
        assert!(combine(&[]).is_err());
    }
}
