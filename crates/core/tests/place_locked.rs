//! End-to-end M3 flow: place-locked drop released only with a witness cert.
//!
//! This exercises the pieces together without a network:
//! content encryption, Shamir split to custodians, witness presence
//! attestations and threshold verification, custodian share release, key
//! reconstruction, and decryption by the claimant.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use keepstone_core::place::{open, seal};
use keepstone_core::presence::{PresenceAttestation, PresenceCert, PresenceRequest};
use keepstone_crypto::{stream, Identity, SealedKey};

#[test]
fn place_locked_drop_requires_a_presence_certificate() {
    let _author = Identity::generate();
    let claimant = Identity::generate();

    // The secret payload and its per-drop content key.
    let content_key = [9u8; 32];
    let plaintext = b"the drop is under the third bench";
    let (framing, chunks) = stream::encrypt(&content_key, plaintext).unwrap();

    // Split the content key 3-of-5 across cell custodians.
    let custodians: Vec<Identity> = (0..5).map(|_| Identity::generate()).collect();
    let custodian_pubs: Vec<[u8; 32]> = custodians.iter().map(Identity::ecdh_public).collect();
    let shares = seal(&content_key, &custodian_pubs, 3).unwrap();
    assert_eq!(shares.len(), 5);

    // The claimant proves presence with a k-of-n certificate.
    let request = PresenceRequest {
        cell: "8928308280fffff".to_owned(),
        nonce: [7u8; 16],
        claimant: claimant.signing_public(),
        expiry: 0,
    };
    let cert = PresenceCert {
        request: request.clone(),
        attestations: (0..3)
            .map(|i| {
                let witness = Identity::generate();
                PresenceAttestation::sign(
                    &witness,
                    &request,
                    u8::try_from(i).unwrap(),
                    1_700_000_000,
                )
            })
            .collect(),
    };
    cert.verify(3).unwrap();

    // Custodians would only release shares for a valid cert; model the release.
    let chosen = [0usize, 2, 4];
    let available: Vec<([u8; 32], u8, SealedKey)> = chosen
        .iter()
        .map(|&i| {
            (
                custodians[i].ecdh_secret_bytes(),
                shares[i].x,
                shares[i].sealed_y.clone(),
            )
        })
        .collect();

    // With the certificate, the claimant reconstructs the content key.
    let recovered = open(&available, 3).unwrap();
    assert_eq!(recovered, content_key);

    // And can decrypt the drop.
    let decrypted = stream::decrypt(&recovered, &framing, &chunks).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn without_enough_shares_the_drop_stays_locked() {
    let content_key = [3u8; 32];
    let (framing, chunks) = stream::encrypt(&content_key, b"locked").unwrap();

    let custodians: Vec<Identity> = (0..5).map(|_| Identity::generate()).collect();
    let custodian_pubs: Vec<[u8; 32]> = custodians.iter().map(Identity::ecdh_public).collect();
    let shares = seal(&content_key, &custodian_pubs, 3).unwrap();

    // Two shares are below threshold: release is refused.
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
    assert!(open(&two, 3).is_err());

    // Even if someone lowers the threshold, the wrong key cannot decrypt.
    let wrong = open(&two, 2).unwrap();
    assert!(stream::decrypt(&wrong, &framing, &chunks).is_err());
}
