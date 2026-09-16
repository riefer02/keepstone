# 12. The workspace map

This is the map you'll come back to. Nine crates, layered so the tricky code is
isolated and testable.

```
                          ┌───────────┐   ┌──────────┐
                          │    cli    │   │  daemon  │
                          └─────┬─────┘   └────┬─────┘
                                │              │
                          ┌─────┴──────┐  ┌────┴─────┐
                          │   store    │◀─┤  store   │
                          └─────┬──────┘  └──────────┘
                                │
              ┌─────────────────┼───────────────────┐
              │                 │                   │
        ┌─────▼─────┐     ┌─────▼─────┐       ┌─────▼─────┐
        │   node    │     │    p2p    │       │   relay   │
        │ (traits,  │     │ (libp2p)  │       │(ciphertext│
        │ ref TCP)  │     │           │       │   only)   │
        └─────┬─────┘     └─────┬─────┘       └─────┬─────┘
              └───────────┬─────┴───────────────────┘
                          │
                    ┌─────▼─────┐
                    │   core    │
                    │ (types,   │
                    │  H3, CBOR,│
                    │  presence)│
                    └─────┬─────┘
                          │
              ┌───────────┼───────────┐
              │                       │
        ┌─────▼─────┐           ┌─────▼─────┐
        │  crypto   │           │    log    │
        │ (leaf)    │           │  (leaf)   │
        └───────────┘           └───────────┘
```

## The crates

| Crate | Role | Purity |
|---|---|---|
| **`keepstone-crypto`** | Primitives: AEAD, KDF, sealed boxes, chunked stream encryption, hybrid KEM/signatures, Shamir, identity keys, zeroizing secrets | Pure leaf; `#![forbid(unsafe_code)]`, no I/O |
| **`keepstone-log`** | RFC 6962 Merkle tree, inclusion/consistency proofs, signed tree heads, equivocation detection, the `Anchor` trait + `HashChainAnchor` | Pure leaf; `sha2` only |
| **`keepstone-core`** | Wire types (`DropBody`, `SignedDrop`, …), canonical CBOR, H3 addressing, proof-of-work, presence certificates, custodian shares | Pure; builds on `crypto` |
| **`keepstone-node`** | Clock/storage/transport traits, the peer protocol messages + framing, the reference TCP transport, an in-memory store | I/O allowed |
| **`keepstone-relay`** | An untrusted, ciphertext-only relay | I/O allowed |
| **`keepstone-p2p`** | libp2p transport: QUIC + TCP, Noise, identify, request/response, gossipsub cell topics, Kademlia provider records, k-anonymous lookups | I/O allowed |
| **`keepstone-store`** | Shared data-directory operations used by both clients (identity, contacts, drops, log) | I/O; synchronous |
| **`keepstone-cli`** | The `keepstone` reference client | Binary |
| **`keepstone-daemon`** | Local HTTP/JSON API + browser UI | Binary |

`xtask` is a tenth, non-library crate that runs the developer tasks.

## Why the layering matters

- The **pure leaves** (`crypto`, `log`) are where correctness is hardest and
  testing is easiest, because they have no clock, no network, and no filesystem.
  They are where the property tests and fuzzing concentrate.
- **`core`** owns the wire format. If you want to understand a drop, this is the
  crate to read.
- **`node`** and **`p2p`** provide the *same* protocol messages over two
  transports. The reference TCP transport is for fast tests; libp2p is the
  production one. Keeping the protocol transport-agnostic is
  [ADR-0007](../DECISIONS.md).
- **`store`** exists so the CLI and the daemon cannot drift apart
  ([ADR-0013](../DECISIONS.md)).

## Dependency direction

Nothing points "up". `crypto` and `log` depend on nothing internal. `core`
depends on `crypto`. `node`/`relay`/`p2p` depend on `core` (+ `log`, `crypto`).
`store` depends on `core`/`crypto`/`log`. The binaries depend on everything
below them. No cycles.

## Go look at this

- [`Cargo.toml`](../../Cargo.toml) — the member list and shared dependencies
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — the one-page version
- Each crate's `src/lib.rs` crate-level docs

Next: [The cryptographic core](13-crypto-core.md)
