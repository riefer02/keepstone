# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Keepstone is pre-release (`0.0.x`). Until `1.0.0`, the wire format may change
without notice (see [docs/DECISIONS.md](docs/DECISIONS.md) for the rationale
behind each breaking change).

## [Unreleased]

## [0.0.1] - 2026-09-22

Initial development. Everything below landed between 2026-09-12 and 2026-09-22.

### Added

- **M0 — Foundations.** Cryptographic core (X25519/Ed25519, XChaCha20-Poly1305,
  HKDF), canonical CBOR encoding, RFC 6962 Merkle log, workspace lints and CI.
- **M1 — Local capability drops.** Keygen, contacts, chunked encryption, sealed
  content keys, signed drop envelopes, transparency log, open/verify.
- **M2 — Networking.** Reference TCP peer protocol; libp2p transport (QUIC +
  TCP, Noise, identify) with request/response; gossipsub cell topics for
  unknown-author delivery; Kademlia provider records for sparse-cell discovery;
  recipient tags with decoy padding; hashcash-style proof-of-work; log
  equivocation detection.
- **M3 — Place-locked release.** Shamir secret sharing over GF(256); witness
  presence requests and k-of-n certificates; networked witness collection over
  TCP and libp2p; custodian share sealing and place-locked reconstruction.
- **M4 — Verifiability & hardening.** Property-based tests; `cargo-fuzz`
  harnesses for the drop, protocol, and presence decoders; external anchoring of
  signed tree heads behind an `Anchor` trait (local hash chain + OpenTimestamps
  via the reference `ots` client); criterion benchmarks.
- **M5 — Scale & clients.** Hybrid post-quantum key encapsulation
  (X25519 + ML-KEM-768) and signatures (Ed25519 + ML-DSA-65) wired end-to-end;
  multi-recipient and multi-device drops; federated relays; signed tree head
  gossip; k-anonymous cell lookups; a local JSON daemon + browser UI; a
  standalone drop verifier; and a Docker deployment kit.
- **M-Pilot — Event hunt kit.** `hunt create / add-participant / add-drop / seed
  / map` organizer workflow plus a participant guide ([docs/PILOT.md](docs/PILOT.md)).
- The Keepstone Book ([docs/book/](docs/book/README.md)) — a 31-chapter guide.
- Wire specification ([docs/SPEC.md](docs/SPEC.md)), threat model
  ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)), claims-to-evidence matrix
  ([docs/CLAIMS.md](docs/CLAIMS.md)), and architecture decision records
  ([docs/DECISIONS.md](docs/DECISIONS.md)).

### Security

- Content confidentiality and integrity, author authenticity, and tamper-evident
  logging are implemented and tested. **Not independently audited.** See
  [SECURITY.md](SECURITY.md).

[Unreleased]: https://github.com/riefer02/keepstone/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/riefer02/keepstone/releases/tag/v0.0.1
