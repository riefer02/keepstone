//! Gossipsub delivers drops to peers that never explicitly asked for them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use keepstone_core::{DropBody, Mode, SignedDrop, PROTOCOL_VERSION};
use keepstone_crypto::{CryptoSuite, Identity};
use keepstone_node::{MemoryStore, Storage};
use keepstone_p2p::{gossip_publish, serve_cells, Multiaddr};

const CELL: &str = "8928308280fffff";

fn sample_drop() -> SignedDrop {
    let identity = Identity::generate();
    let body = DropBody {
        version: PROTOCOL_VERSION,
        suite: CryptoSuite::Classical25519.id(),
        cell: CELL.to_owned(),
        ring: 2,
        created_at: 1_700_000_000,
        expiry: 0,
        mode: Mode::Capability.id(),
        chunk_size: 65536,
        chunk_count: 1,
        content_root: [3u8; 32],
        prefix: [4u8; 20],
        drop_nonce: [5u8; 16],
        pow_nonce: 0,
        wrapped_keys: vec![],
    };
    SignedDrop::sign(&identity, &body)
}

#[tokio::test]
async fn gossip_delivers_an_unknown_drop() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server_store = Arc::clone(&store);
    let handle = tokio::spawn(async move {
        let _ = serve_cells(listen, server_store, vec![CELL.to_owned()], Some(ready_tx)).await;
    });
    let addr = ready_rx.await.unwrap();

    let drop = sample_drop();
    let id = drop.id();
    gossip_publish(addr, CELL, drop.raw.clone()).await.unwrap();

    for _ in 0..50 {
        if store.lock().unwrap().get_drop(&id).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        store.lock().unwrap().get_drop(&id).is_some(),
        "gossip drop was not delivered"
    );
    handle.abort();
}
