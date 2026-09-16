# 12. The workspace map

Nine library/binary crates, layered so the tricky code is isolated and
testable.

```
                          ┌───────────┐   ┌──────────┐
                          │    cli    │   │  daemon  │
                          └─────┬─────┘   └────┬─────┘
                                │              │
                          ┌─────┴──────────────┴─────┐
                          │          store           │
                          └─────────────┬────────────┘
                                        │
              ┌─────────────────┬───────┴─────────┐
        ┌─────▼─────┐     ┌─────▼─────┐     ┌─────▼─────┐
        │   node    │     │    p2p    │     │   relay   │
        │ (traits,  │     │ (libp2p)  │     │(ciphertext│
        │ ref TCP)  │     │           │     │   only)   │
        └─────┬─────┘     └─────┬─────┘     └─────┬─────┘
              └───────────┬─────┴─────────────────┘
                    ┌─────▼─────┐
                    │   core    │
                    │ (types,   │
                    │  H3, CBOR,│
                    │  presence)│
                    └─────┬─────┘
              ┌───────────┴───────────┐
        ┌─────▼─────┐           ┌─────▼─────┐
        │  crypto   │           │    log    │
        │  (leaf)   │           │  (leaf)   │
        └───────────┘           └───────────┘
```

## The crates

| Crate | Role | Purity |
|---|---|---|
| **`keepstone-crypto`** | AEAD, KDF, sealed boxes, chunked streaming, hybrid KEM/signatures, Shamir, identity keys, zeroizing secrets | Pure leaf; `forbid(unsafe_code)`, no I/O |
| **`keepstone-log`** | RFC 6962 Merkle tree, inclusion/consistency proofs, STHs, equivocation, `Anchor` + `HashChainAnchor` | Pure leaf; `sha2` only |
| **`keepstone-core`** | Wire types (`DropBody`, `SignedDrop`, …), canonical CBOR, H3 addressing, PoW, presence certs, custodian shares | Pure; builds on `crypto` |
| **`keepstone-node`** | Clock/storage/transport traits, protocol messages + framing, reference TCP, in-memory store | I/O |
| **`keepstone-relay`** | Untrusted, ciphertext-only relay | I/O |
| **`keepstone-p2p`** | libp2p: QUIC + TCP, Noise, identify, request/response, gossipsub cell topics, Kademlia providers, k-anonymous lookups | I/O |
| **`keepstone-store`** | Shared data-directory operations (identity, contacts, drops, log) | I/O, synchronous |
| **`keepstone-cli`** | The `keepstone` reference client | Binary |
| **`keepstone-daemon`** | Local HTTP/JSON API + browser UI | Binary |

`xtask` is a tenth, non-library crate for developer tasks.

## Why the layering matters

- **Pure leaves** (`crypto`, `log`) have the hardest correctness and the easiest
  testing (no clock, network, or filesystem). Property tests and fuzzing
  concentrate there.
- **`core`** owns the wire format; read it to understand a drop.
- **`node`** and **`p2p`** carry the *same* protocol messages over two
  transports: reference TCP for fast tests, libp2p for production
  ([ADR-0007](../DECISIONS.md)).
- **`store`** stops the CLI and daemon drifting apart
  ([ADR-0013](../DECISIONS.md)).

## Dependency direction

No cycles. `crypto` and `log` depend on nothing internal. `core` → `crypto`.
`node`/`relay`/`p2p` → `core` (+ `log`, `crypto`). `store` → `core`/`crypto`/
`log`. Binaries depend on everything below.

## Go look at this

- [`Cargo.toml`](../../Cargo.toml) — members and shared deps
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — one-page version
- Each crate's `src/lib.rs` crate docs

Next: [The cryptographic core](13-crypto-core.md)
