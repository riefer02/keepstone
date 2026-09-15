//! Witness presence collection over libp2p.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use keepstone_core::presence::{PresenceCert, PresenceRequest};
use keepstone_crypto::Identity;
use keepstone_p2p::{request_presence, serve_witness_cell, Multiaddr};

const CELL: &str = "8928308280fffff";

#[tokio::test]
async fn collects_a_presence_certificate_over_libp2p() {
    let mut addrs = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let witness = Arc::new(Identity::generate());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let cell = CELL.to_owned();
        handles.push(tokio::spawn(async move {
            let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
            let _ = serve_witness_cell(listen, witness, cell, Some(ready_tx)).await;
        }));
        addrs.push(ready_rx.await.unwrap());
    }

    let claimant = Identity::generate();
    let request = PresenceRequest {
        cell: CELL.to_owned(),
        nonce: [9u8; 16],
        claimant: claimant.signing_public(),
        expiry: 0,
    };

    let mut attestations = Vec::new();
    for addr in addrs {
        if let Some(attestation) = request_presence(addr, &request).await.unwrap() {
            attestations.push(attestation);
        }
    }
    assert_eq!(
        attestations.len(),
        3,
        "expected one attestation per witness"
    );

    let cert = PresenceCert {
        request,
        attestations,
    };
    cert.verify(3).unwrap();

    for handle in handles {
        handle.abort();
    }
}
