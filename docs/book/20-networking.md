# 20. Networking

Networking has one job in Keepstone: move **ciphertext** between nodes. The
content is already end-to-end encrypted, so the transport is untrusted by design
and carries no key material. There are two transports over one protocol.

## One protocol, two transports

The peer protocol is defined **transport-agnostically** in
`crates/node/src/protocol.rs`. Messages are canonical CBOR arrays:

```
Message = [ tag:uint, payload:bytes ]
```

| tag | message | payload |
|---|---|---|
| 0 | Hello | protocol version |
| 1 | Want(drop_id) | 32 bytes |
| 2 | Drop | raw envelope bytes |
| 3 | Missing(drop_id) | 32 bytes |
| 4 | Bye | empty |
| 5 | WantChunk(drop_id, index) | `id(32) || index_be32` |
| 6 | Chunk(drop_id, index, data) | `id(32) || index_be32 || data` |
| 7 | Presence | canonical `PresenceRequest` |
| 8 | Attestation | canonical `PresenceAttestation` |
| 9 | Put | raw signed envelope (offer for storage) |
| 10 | Stored(drop_id) | 32 bytes |
| 11 | PutChunk(drop_id, index, data) | `id(32) || index_be32 || data` |
| 12 | GetSth | empty |
| 13 | Sth | 144-byte signed tree head |

**Reference TCP framing:** `u32_be length || message`, max frame **8 MiB**
(`MAX_FRAME`). **libp2p** uses the same encoded `Message` as the
request/response body of protocol `/keepstone/drop/1`.

This split is [ADR-0007](../DECISIONS.md) + [ADR-0009](../DECISIONS.md): prove
the protocol over a tiny transport first, then put libp2p behind the same
messages.

## The reference TCP transport

`crates/node/src/net.rs`. A minimal length-prefixed client/server used for fast,
dependency-light tests and two-node demos. It implements the `Want`/`Drop` and
`WantChunk`/`Chunk` exchanges (and the newer `Put`/`Stored`, `GetSth`/`Sth`).

```bash
keepstone --data-dir ./alice serve --listen 127.0.0.1:7777
keepstone --data-dir ./bob fetch 127.0.0.1:7777 <id>
```

## The libp2p transport

`crates/p2p/src/lib.rs` uses **libp2p 0.57** with:

- **QUIC** and **TCP** transports (QUIC-first, TCP fallback),
- **Noise** for transport encryption and peer authentication,
- **Yamux** multiplexing (for TCP),
- **identify** so peers learn each other's addresses,
- a **request/response** protocol whose codec speaks the existing `Message`
  type (`DROP_PROTOCOL = "/keepstone/drop/1"`).

```bash
keepstone --data-dir ./alice p2p-serve --listen /ip4/127.0.0.1/tcp/7778
keepstone --data-dir ./bob   p2p-fetch /ip4/127.0.0.1/tcp/7778 <id>
```

The public API: `serve`, `serve_with_ready`, `request`, `fetch_drop`,
`fetch_chunk`, `serve_cells`, `gossip_publish`, `serve_witness_cell`,
`request_presence`, `find_providers`, `find_providers_private`, `nearby_cells`,
`cell_topic`.

## Discovery: dense vs. sparse cells

Transport gets bytes to a peer once you **know** the peer. Discovery is split by
density:

- **Dense cells** — many peers interested in the same place. `gossipsub` topic
  `keepstone/drops/v1/cell/{h3_index}` (`cell_topic`): a subscriber receives a
  drop published by a peer it never requested from. `gossip_publish` is the send
  side; `serve_cells` is the receive side.
- **Sparse cells** — few or no peers around. Kademlia **provider records**
  (`/keepstone/kad`): a node advertises that it serves a cell, and a seeker
  queries the DHT. `find_providers` returns the peers advertising a cell; they
  are then asked directly with `Want`.

```
dense:   publisher ──gossipsub topic──▶ every subscriber in the cell
sparse:  seeker ──kad get_providers──▶ [peers] ──Want/Drop──▶ envelope
```

Both paths verify the author signature before storing anything — a gossiped drop
from an unknown author is not trusted just because it arrived.

## The trust boundary

Everything above is deliberately dumb about confidentiality:

- relays and log nodes hold **ciphertext only** and have no key material,
- transport encryption (Noise) is defense in depth, not the guarantee,
- a malicious peer can withhold or corrupt data but cannot read or forge a drop.

Availability is therefore best-effort; see
[Chapter 22](22-federated-relays-and-gossip.md).

## Go look at this

- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — messages + framing
- [`crates/node/src/net.rs`](../../crates/node/src/net.rs) — reference TCP
- [`crates/p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) — libp2p behaviours
- Tests: `crates/node/tests` (TCP), `crates/p2p/tests` (libp2p, gossip, providers)

Next: [Place-locked release](21-place-locked-release.md)
