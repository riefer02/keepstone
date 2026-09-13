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
- **M2 (networking, in progress):** reference TCP peer protocol (`serve` / `fetch`) for envelope + chunk exchange; recipient tags with decoy padding (recipients are no longer named in cleartext); hashcash-style proof-of-work anti-spam; log equivocation detection. libp2p (QUIC + Noise, gossip + Kademlia) is the next step.
- **M3 (place-locked, in progress):** Shamir secret sharing over GF(256); witness presence requests/attestations and k-of-n certificates (distinct-witness + expiry checks); custodian share sealing and place-locked reconstruction. Network witness discovery is next.
- **M4+:** OpenTimestamps anchoring, benchmarks/fuzzing, federation, clients — see [the plan](docs/ARCHITECTURE.md).

The test suite currently passes **64 tests** covering AEAD, sealed boxes,
chunked streaming encryption, canonical CBOR, signing/verification, H3
addressing, Merkle inclusion + consistency proofs, the peer protocol,
two-node TCP exchange, Shamir sharing, presence certificates, and the
place-locked end-to-end flow.

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

```bash
cargo build --workspace

# Alice and Bob each generate a device identity.
keepstone --data-dir ./demo/alice keygen
keepstone --data-dir ./demo/bob   keygen

# Alice adds Bob (public keys exchanged out of band).
BOB_SIGN=$(keepstone --data-dir ./demo/bob id | awk '/signing/{print $2}')
BOB_ECDH=$(keepstone --data-dir ./demo/bob id | awk '/ecdh/{print $2}')
keepstone --data-dir ./demo/alice contact-add bob "$BOB_SIGN" "$BOB_ECDH"

# Alice leaves a drop at a location.
keepstone --data-dir ./demo/alice drop-create \
  --to bob --lat 51.5007 --lng -0.1246 --ring 2 \
  --message "meet at the old oak at dusk"

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
