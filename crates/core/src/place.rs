//! Place-locked key release.
//!
//! A content key can be Shamir-split across cell **custodians**, each holding a
//! share sealed to their device key. Custodians release shares only to a
//! claimant who presents a valid [`crate::presence::PresenceCert`] (the release
//! protocol lives above this crate; this module provides the sealing and
//! reconstruction).
//!
//! Location is best-effort defense in depth. A colluding or Sybil custodian set
//! can defeat it; that limitation is documented, not hidden.

use keepstone_crypto::{shamir, SealedKey};

use crate::error::CoreError;

/// One custodian's sealed share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodianShare {
    /// Custodian's X25519 public key.
    pub custodian: [u8; 32],
    /// Shamir evaluation point (not secret).
    pub x: u8,
    /// The share value, sealed to the custodian.
    pub sealed_y: SealedKey,
}

/// Split `content_key` `threshold`-of-`custodians` and seal each share.
///
/// # Errors
/// Returns [`CoreError`] on invalid parameters or sealing failure.
pub fn seal(
    content_key: &[u8; 32],
    custodians: &[[u8; 32]],
    threshold: u8,
) -> Result<Vec<CustodianShare>, CoreError> {
    if custodians.is_empty() {
        return Err(CoreError::Invalid("no custodians"));
    }
    let count =
        u8::try_from(custodians.len()).map_err(|_| CoreError::Invalid("too many custodians"))?;
    let shares = shamir::split(content_key, threshold, count)?;

    let mut out = Vec::with_capacity(custodians.len());
    for (custodian, share) in custodians.iter().zip(shares.iter()) {
        let y: [u8; 32] = share
            .y
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Invalid("share length"))?;
        let sealed_y = SealedKey::seal(&y, custodian)?;
        out.push(CustodianShare {
            custodian: *custodian,
            x: share.x,
            sealed_y,
        });
    }
    Ok(out)
}

/// Reconstruct the content key from at least `threshold` released shares.
///
/// Each entry is `(custodian_ecdh_secret, x, sealed_share)`.
///
/// # Errors
/// Returns [`CoreError`] on insufficient shares or any crypto failure.
pub fn open(
    available: &[([u8; 32], u8, SealedKey)],
    threshold: usize,
) -> Result<[u8; 32], CoreError> {
    if available.len() < threshold || threshold < 2 {
        return Err(CoreError::Invalid("insufficient shares"));
    }
    let mut shares = Vec::with_capacity(available.len());
    for (secret, x, sealed) in available {
        let y = sealed.open(secret)?;
        shares.push(shamir::Share {
            x: *x,
            y: y.to_vec(),
        });
    }
    let key = shamir::combine(&shares)?;
    key.try_into()
        .map_err(|_| CoreError::Invalid("reconstructed key length"))
}

/// Convenience re-export for callers working with custodians.
pub use keepstone_crypto::Identity as CustodianIdentity;

#[cfg(test)]
mod tests {
    use super::*;
    use keepstone_crypto::Identity;

    #[test]
    fn threshold_of_custodians_reconstructs() {
        let content_key = [42u8; 32];
        let custodians: Vec<Identity> = (0..5).map(|_| Identity::generate()).collect();
        let pubs: Vec<[u8; 32]> = custodians.iter().map(Identity::ecdh_public).collect();

        let shares = seal(&content_key, &pubs, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Any three custodians can reconstruct.
        let available: Vec<([u8; 32], u8, SealedKey)> = [0usize, 2, 4]
            .iter()
            .map(|&i| {
                (
                    custodians[i].ecdh_secret_bytes(),
                    shares[i].x,
                    shares[i].sealed_y.clone(),
                )
            })
            .collect();
        assert_eq!(open(&available, 3).unwrap(), content_key);
    }

    #[test]
    fn too_few_shares_are_refused_or_wrong() {
        let content_key = [7u8; 32];
        let custodians: Vec<Identity> = (0..5).map(|_| Identity::generate()).collect();
        let pubs: Vec<[u8; 32]> = custodians.iter().map(Identity::ecdh_public).collect();
        let shares = seal(&content_key, &pubs, 3).unwrap();

        let two: Vec<([u8; 32], u8, SealedKey)> = [0usize, 1]
            .iter()
            .map(|&i| {
                (
                    custodians[i].ecdh_secret_bytes(),
                    shares[i].x,
                    shares[i].sealed_y.clone(),
                )
            })
            .collect();
        // Below threshold: refused.
        assert!(open(&two, 3).is_err());
        // At a lower threshold: reconstructs something, but not the real key.
        assert_ne!(open(&two, 2).unwrap(), content_key);
    }

    #[test]
    fn a_wrong_custodian_cannot_open_a_share() {
        let content_key = [1u8; 32];
        let custodian = Identity::generate();
        let other = Identity::generate();
        let shares = seal(&content_key, &[custodian.ecdh_public()], 2);
        // threshold 2 with a single custodian is invalid.
        assert!(shares.is_err());

        let shares = seal(
            &content_key,
            &[custodian.ecdh_public(), other.ecdh_public()],
            2,
        )
        .unwrap();
        let opened = shares[0].sealed_y.open(&other.ecdh_secret_bytes());
        assert!(opened.is_err());
    }
}
