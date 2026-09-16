# 29. Design decisions, digest

Significant choices are recorded as **ADRs** in
[`docs/DECISIONS.md`](../DECISIONS.md), append-only: a later ADR supersedes an
earlier one rather than editing it. One-line digest below.

| ADR | Decision | Why |
|---|---|---|
| **0001** | AGPL-3.0-or-later + CLA | Prevents proprietary hosted forks; CLA keeps relicensing possible |
| **0002** | Hand-rolled canonical CBOR subset | Deterministic bytes for signed objects; small audit surface |
| **0003** | XChaCha20-Poly1305 for content | 192-bit nonces make random nonces safe |
| **0004** | SHA-256 + RFC 6962 Merkle log | Standard, consensus-free tamper-evidence |
| **0005** | **Location is access, not discovery** | No global spatial index; removes metadata/abuse classes |
| **0006** | `pedantic`/`nursery` clippy off | Keep the always-green gate meaningful |
| **0007** | Reference TCP transport before libp2p | Prove the protocol cheaply, transport-agnostically |
| **0008** | Recipient tags + decoy padding | Recipients unnamed in cleartext; count hidden |
| **0009** | libp2p as the production transport | QUIC + Noise, path to gossip/DHT |
| **0010** | Anchoring behind a trait; hash chain first | Real, offline anchoring with no dependencies |
| **0011** | Namespaced envelope v2 (sig kinds) | Carries Ed25519 or hybrid signatures; self-verifying |
| **0012** | Hand-written HTTP daemon | No web framework for a few localhost routes |
| **0013** | Shared `keepstone-store` library | CLI and daemon can't drift apart |
| **0014** | k-anonymous cell lookups | Hide the target cell among neighbours (not PIR) |
| **0015** | OpenTimestamps via the reference `ots` client | Real Bitcoin timestamps without fragile reimplementation |

## Highest-leverage decisions

- **ADR-0005 (location is access)** shapes the product: remove the global index
  and many problems disappear; the cost is out-of-band coordination.
- **ADR-0008 (tags + decoys)** keeps recipients off the wire and every drop the
  same size regardless of audience.
- **ADR-0011 (envelope v2)** makes hybrid drops self-verifying.
- **ADR-0013 (store)** is the code-health counterpart: one format, one test set.

## Reading the ADRs

Each is *Context → Decision → Consequences*, and the **Consequences** section is
where the honesty lives — costs, undone work, future work. When this book and an
ADR disagree, the ADR (and the code) win.

## Go look at this

- [`docs/DECISIONS.md`](../DECISIONS.md) — all 15 records
- [`docs/CLAIMS.md`](../CLAIMS.md) — claims → evidence

Next: [Glossary and appendices](30-glossary-and-appendices.md)
