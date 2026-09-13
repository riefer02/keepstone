//! Networked presence: collect a threshold of witness attestations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use keepstone_core::presence::{PresenceCert, PresenceRequest};
use keepstone_crypto::Identity;
use keepstone_node::net::{request_presence, serve_witness};
use tokio::net::TcpListener;

const CELL: &str = "8928308280fffff";

#[tokio::test]
async fn collects_a_presence_certificate_from_witnesses() {
    // Three independent witnesses listen for presence requests.
    let mut addrs = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addrs.push(listener.local_addr().unwrap().to_string());
        let witness = Arc::new(Identity::generate());
        let cell = CELL.to_owned();
        handles.push(tokio::spawn(async move {
            serve_witness(listener, witness, cell).await;
        }));
    }

    let claimant = Identity::generate();
    let request = PresenceRequest {
        cell: CELL.to_owned(),
        nonce: [9u8; 16],
        claimant: claimant.signing_public(),
        expiry: 0,
    };

    let mut attestations = Vec::new();
    for addr in &addrs {
        if let Some(attestation) = request_presence(addr, &request).await.unwrap() {
            attestations.push(attestation);
        }
    }
    assert_eq!(attestations.len(), 3, "expected an attestation per witness");

    let cert = PresenceCert {
        request,
        attestations,
    };
    cert.verify(3).unwrap();

    for handle in handles {
        handle.abort();
    }
}
