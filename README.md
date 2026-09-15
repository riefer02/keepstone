# Keepstone

> Leave an encrypted message at a place. Only the person you choose can read it,
> only when they're there. No server can read it, no company can delete it, and
> anyone can verify it existed.

Keepstone is a decentralized, end-to-end encrypted geospatial dead-drop engine.
It is built in Rust as both a serious learning project and a genuine
privacy tool: **the recipient key is the lock; location is an access gate, never
the confidentiality guarantee.**

## Status

- **M0 (foundations):** complete — crypto core, canonical encoding, RFC 6962 log, workspace lints + CI.
- **M1 (local capability drops):** complete — keygen, contacts, chunked encryption, sealed content keys, signed envelopes, transparency log, open/verify.
- **M2 (networking):** reference TCP peer protocol (`serve` / `fetch`); **libp2p transport** (QUIC + TCP, Noise, identify) with request/response for envelope + chunk exchange (`p2p-serve` / `p2p-fetch`); **gossipsub cell topics** so peers receive drops from unknown authors in dense cells; **Kademlia provider records** for sparse-cell discovery (`/keepstone/kad`); recipient tags with decoy padding; hashcash-style proof-of-work; log equivocation detection.
- **M3 (place-locked, in progress):** Shamir secret sharing over GF(256); witness presence requests/attestations and k-of-n certificates (distinct-witness + expiry checks); **networked witness collection** over the peer protocol (`serve_witness` / `request_presence`); custodian share sealing and place-locked reconstruction.
- **M4 (verifiability & hardening):** property-based tests; **fuzzing** (`cargo-fuzz` harnesses for drop, protocol, and presence decoders — ~30M executions, no crashes); **external anchoring** of signed tree heads behind an `Anchor` trait (`log-anchor` / `log-anchors`); **criterion benchmarks** (`docs/BENCHMARKS.md`).
- **M5 (in progress):** post-quantum **hybrid key encapsulation** *and* **hybrid signatures** (X25519 + ML-KEM-768; Ed25519 + ML-DSA-65), **wired end-to-end** into drops (`drop-create --suite hybrid`); **multi-recipient and multi-device** drops; federation remains.

The test suite currently passes **94 tests** covering AEAD, sealed boxes,
chunked streaming encryption, canonical CBOR, signing/verification, H3
addressing, Merkle inclusion + consistency proofs, the peer protocol,
two-node TCP exchange, **two-node libp2p (QUIC + TCP) exchange**, **gossipsub
delivery of drops from unknown authors**, **Kademlia cell-provider discovery**,
**networked presence-certificate collection**, **hybrid post-quantum
encapsulation and signatures**, Shamir sharing, the place-locked end-to-end
flow, and property-based invariants.

## The two locks

| Lock | Mechanism | Strength | Protects |
|---|---|---|---|
| Cryptographic | X25519 + XChaCha20-Poly1305; per-drop content key sealed to each recipient device | Strong, works anywhere | Confidentiality — the real guarantee |
| Spatial | H3 cell dissemination + (later) k-of-n presence certificate | Best-effort, defense in depth | Access gating + friction |

## Repository layout

```
crates/
├── crypto/   # X25519/Ed25519/XChaCha20/HKDF, sealed boxes, chunked AEAD
├── core/     # types, H3 addressing, canonical CBOR, signed drop envelopes
├── log/      # RFC 6962 Merkle tree, inclusion + consistency proofs, STHs
├── node/     # clock/storage/transport traits + in-memory impls
├── relay/    # untrusted ciphertext-only relay
└── cli/      # the `keepstone` reference client
```

`crypto`, `core`, and `log` are pure (no I/O, no async) and `#![forbid(unsafe_code)]`.

## Quickstart

Run the whole stack with one command (identities → post-quantum drop → relay → fetch → open → verify):

```bash
cargo xtask demo
```

Or step through it manually:

```bash
cargo build --workspace

# Alice and Bob each generate a device identity.
keepstone --data-dir ./demo/alice keygen
keepstone --data-dir ./demo/bob   keygen

# Alice adds Bob (public keys exchanged out of band; hybrid key optional).
BOB_SIGN=$(keepstone --data-dir ./demo/bob id | awk '/signing/{print $2}')
BOB_ECDH=$(keepstone --data-dir ./demo/bob id | awk '/ecdh/{print $2}')
BOB_HYBRID=$(keepstone --data-dir ./demo/bob id | awk '/hybrid/{print $2}')
keepstone --data-dir ./demo/alice contact-add bob "$BOB_SIGN" "$BOB_ECDH" "$BOB_HYBRID"

# Alice leaves a drop at a location (repeat --to for multiple recipients).
keepstone --data-dir ./demo/alice drop-create \
  --to bob --lat 51.5007 --lng -0.1246 --ring 2 \
  --message "meet at the old oak at dusk"

# Or a post-quantum hybrid drop (X25519 + ML-KEM-768) with `--suite hybrid`.

# Anyone can verify the drop's signature and its place in the log.
keepstone --data-dir ./demo/alice log-verify <id>

# Bob opens it (once he has the ciphertext).
keepstone --data-dir ./demo/bob drop-open <id>
```

### Two-node exchange over TCP (M2 reference transport)

```bash
# Alice serves the drops she holds (ciphertext only).
keepstone --data-dir ./demo/alice serve --listen 127.0.0.1:7777

# Bob fetches the envelope and its chunks, then opens it.
keepstone --data-dir ./demo/bob fetch 127.0.0.1:7777 <id>
keepstone --data-dir ./demo/bob drop-open <id>
keepstone --data-dir ./demo/bob log-verify <id>
```

### Federated store-and-forward (author can be offline)

```bash
# A relay holds no keys and starts empty.
keepstone --data-dir ./demo/relay serve --listen 127.0.0.1:7790
# Alice pushes ciphertext to the relay.
keepstone --data-dir ./demo/alice push 127.0.0.1:7790 <id>
# Bob fetches from the relay later, even if Alice is offline.
keepstone --data-dir ./demo/bob fetch 127.0.0.1:7790 <id>
keepstone --data-dir ./demo/bob drop-open <id>
```

### Signed tree head gossip

```bash
keepstone --data-dir ./demo/alice sth-serve --listen 127.0.0.1:7791
keepstone --data-dir ./demo/bob sth-fetch 127.0.0.1:7791   # verifies the log signature
```

### Two-node exchange over libp2p (QUIC + TCP, Noise)

```bash
keepstone --data-dir ./demo/alice p2p-serve --listen /ip4/127.0.0.1/tcp/7778
keepstone --data-dir ./demo/bob p2p-fetch /ip4/127.0.0.1/tcp/7778 <id>
keepstone --data-dir ./demo/bob drop-open <id>
```

Run the full local quality gate with `cargo xtask ci`.

## Security summary

**Covered:** content confidentiality and integrity — no one but the author and
intended recipient devices can read or forge a drop, including relays, log
nodes, network observers, and the operator.

**Not covered:** metadata (who is near which cell), endpoint compromise,
availability, and — for place-locked mode — proof of physical location.

This code is **not yet independently audited**. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/CLAIMS.md](docs/CLAIMS.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md)
for the contributor license agreement.
