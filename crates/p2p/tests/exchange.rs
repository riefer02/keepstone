//! Two-node libp2p exchange over a live TCP listener.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use keepstone_core::DropId;
use keepstone_node::{MemoryStore, Storage};
use keepstone_p2p::{fetch_chunk, fetch_drop, serve_with_ready, Multiaddr};

#[tokio::test]
async fn two_nodes_exchange_a_drop_over_libp2p() {
    let mut store = MemoryStore::new();
    let raw = vec![7u8; 256];
    let id = DropId::of(&raw);
    store.put_drop(id, raw.clone());
    store.put_chunk(id, 0, vec![1u8; 32]);
    store.put_chunk(id, 1, vec![2u8; 32]);
    let store = Arc::new(Mutex::new(store));

    let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server_store = Arc::clone(&store);
    let handle = tokio::spawn(async move {
        let _ = serve_with_ready(listen, server_store, Some(ready_tx)).await;
    });

    let addr = ready_rx.await.unwrap();

    // Envelope, then chunks, by id.
    assert_eq!(fetch_drop(addr.clone(), id).await.unwrap(), Some(raw));
    assert_eq!(
        fetch_chunk(addr.clone(), id, 0).await.unwrap(),
        Some(vec![1u8; 32])
    );
    assert_eq!(
        fetch_chunk(addr.clone(), id, 1).await.unwrap(),
        Some(vec![2u8; 32])
    );

    // Absent data returns None, not an error.
    assert_eq!(
        fetch_drop(addr.clone(), DropId::of(b"absent"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(fetch_chunk(addr.clone(), id, 9).await.unwrap(), None);

    handle.abort();
}
