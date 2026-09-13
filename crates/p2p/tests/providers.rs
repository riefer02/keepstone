//! Kademlia provider discovery for the sparse-cell path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use keepstone_node::MemoryStore;
use keepstone_p2p::{find_providers, serve_cells, Multiaddr};

const CELL: &str = "8928308280fffff";

#[tokio::test]
async fn kademlia_finds_a_cell_provider() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _ = serve_cells(listen, store, vec![CELL.to_owned()], Some(ready_tx)).await;
    });
    let addr = ready_rx.await.unwrap();

    let providers = find_providers(addr, CELL).await.unwrap();
    assert!(
        !providers.is_empty(),
        "DHT returned no providers for a served cell"
    );
    handle.abort();
}
