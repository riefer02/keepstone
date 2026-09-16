# 20. Networking

Networking has one job: move **ciphertext** between nodes. Content is already
end-to-end encrypted, so the transport is untrusted and carries no keys. There
are two transports over one protocol.

## One protocol

Defined in [`protocol.rs`](../../crates/node/src/protocol.rs). Messages are
canonical CBOR arrays:

```
Message = [ tag:uint, payload:bytes ]
```

| tag | message | tag | message |
|---|---|---|---|
| 0 | Hello | 7 | Presence |
| 1 | Want | 8 | Attestation |
| 2 | Drop | 9 | Put |
| 3 | Missing | 10 | Stored |
| 4 | Bye | 11 | PutChunk |
| 5 | WantChunk | 12 | GetSth |
| 6 | Chunk | 13 | Sth |

**Reference TCP framing:** `u32_be length || message`, max frame **8 MiB**
(`MAX_FRAME`). **libp2p** uses the same encoded `Message` as the body of
protocol `/keepstone/drop/1`.

This split is [ADR-0007](../DECISIONS.md) + [ADR-0009](../DECISIONS.md): prove
the protocol on a tiny transport, then put libp2p behind the same messages.

## Reference TCP transport

[`net.rs`](../../crates/node/src/net.rs). Minimal length-prefixed client/server
for fast tests and two-node demos. Implements `Want`/`Drop`, `WantChunk`/`Chunk`,
`Put`/`Stored`, `GetSth`/`Sth`.

```bash
keepstone --data-dir ./alice serve --listen 127.0.0.1:7777
keepstone --data-dir ./bob fetch 127.0.0.1:7777 <id>
```

## libp2p transport

[`p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) uses **libp2p 0.57**:

- **QUIC** and **TCP** transports (QUIC-first),
- **Noise** for transport encryption and peer authentication,
- **Yamux** multiplexing (TCP),
- **identify** for address learning,
- a **request/response** codec speaking the same `Message`
  (`DROP_PROTOCOL = "/keepstone/drop/1"`).

```bash
keepstone --data-dir ./alice p2p-serve --listen /ip4/127.0.0.1/tcp/7778
keepstone --data-dir ./bob   p2p-fetch /ip4/127.0.0.1/tcp/7778 <id>
```

API: `serve`, `serve_with_ready`, `request`, `fetch_drop`, `fetch_chunk`,
`serve_cells`, `gossip_publish`, `serve_witness_cell`, `request_presence`,
`find_providers`, `find_providers_private`, `nearby_cells`, `cell_topic`.

## Discovery: dense vs. sparse

Transport moves bytes once you **know** a peer; discovery is split by density:

- **Dense cells** — gossipsub topic `keepstone/drops/v1/cell/{h3_index}`. A
  subscriber receives a drop published by a peer it never requested from.
  `gossip_publish` sends; `serve_cells` receives.
- **Sparse cells** — Kademlia **provider records** (`/keepstone/kad`). A node
  advertises a cell; a seeker queries the DHT with `find_providers`, then asks
  the returned peers directly with `Want`.

```
dense:   publisher ──gossipsub topic──▶ every subscriber in the cell
sparse:  seeker ──kad get_providers──▶ [peers] ──Want/Drop──▶ envelope
```

Both paths verify the author signature before storing — a gossiped drop from an
unknown author isn't trusted just because it arrived.

## Trust boundary

Relays and log nodes hold **ciphertext only** and no keys. Transport encryption
(Noise) is defense in depth, not the guarantee. A malicious peer can withhold or
corrupt data but cannot read or forge a drop. Availability is best-effort
([Chapter 22](22-federated-relays-and-gossip.md)).

## Go look at this

- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — messages + framing
- [`crates/node/src/net.rs`](../../crates/node/src/net.rs) — reference TCP
- [`crates/p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) — libp2p behaviours
- Tests: `crates/node/tests` (TCP), `crates/p2p/tests` (libp2p, gossip, providers)

Next: [Place-locked release](21-place-locked-release.md)
