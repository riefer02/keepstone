//! Kademlia provider discovery, including the k-anonymous private lookup.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use keepstone_node::MemoryStore;
use keepstone_p2p::{find_providers, find_providers_private, nearby_cells, serve_cells, Multiaddr};

const CELL: &str = "8928308280fffff";

async fn provider_node(
    tag: &str,
) -> (
    Multiaddr,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<MemoryStore>>,
) {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server_store = Arc::clone(&store);
    let cell = tag.to_owned();
    let handle = tokio::spawn(async move {
        let _ = serve_cells(listen, server_store, vec![cell], Some(ready_tx)).await;
    });
    let addr = ready_rx.await.unwrap();
    (addr, handle, store)
}

#[tokio::test]
async fn finds_a_cell_provider() {
    let (addr, handle, _store) = provider_node(CELL).await;
    let providers = find_providers(addr, CELL).await.unwrap();
    assert!(!providers.is_empty(), "DHT returned no providers");
    handle.abort();
}

#[tokio::test]
async fn private_lookup_still_finds_the_target_provider() {
    let (addr, handle, _store) = provider_node(CELL).await;

    // A private lookup queries the target and its ring but must still return the
    // target's providers.
    let providers = find_providers_private(addr, CELL, 1).await.unwrap();
    assert!(!providers.is_empty(), "private lookup lost the provider");

    // A ring of 1 is the cell plus its six neighbours.
    let cells = nearby_cells(CELL, 1).unwrap();
    assert_eq!(cells.len(), 7);
    assert!(cells.contains(&CELL.to_owned()));

    handle.abort();
}
