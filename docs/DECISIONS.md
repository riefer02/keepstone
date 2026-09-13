# Architecture Decision Records

Decisions are append-only. Each records the context, the decision, and the
consequences.

## ADR-0001 — License: AGPL-3.0-or-later + CLA

**Context.** Keepstone's mission is to prevent enclosure of privacy
infrastructure by large platforms.

**Decision.** License the whole project AGPL-3.0-or-later. Require a CLA from
contributors so the project retains the option to relicense/dual-license.

**Consequences.** Prevents proprietary hosted forks. Some enterprises ban AGPL,
which may limit SDK adoption; a permissive `core`/`crypto` split or commercial
license remains possible because of the CLA.

## ADR-0002 — Hand-rolled canonical CBOR subset for M0

**Context.** The plan selected `cbor2`/`cose2`. In M0 we need deterministic
encoding for signed objects and strict rejection of non-canonical input, with a
minimal dependency surface.

**Decision.** Implement a small canonical CBOR subset (`crates/core/src/cbor.rs`)
supporting unsigned ints, byte/text strings, arrays, maps, and booleans, with
shortest-form heads and no indefinite lengths. Signing verifies over **preserved
payload bytes**, not a re-encoding.

**Consequences.** Full control of the wire layout and a small audit surface.
Must be revisited if richer CBOR (tags, floats, extensions) is needed; a COSE
layer can be added on top later.

## ADR-0003 — XChaCha20-Poly1305 for content encryption

**Context.** Random nonces are the safest nonce strategy, but 96-bit random
nonces risk reuse over long-lived keys.

**Decision.** Use XChaCha20-Poly1305 (192-bit nonces). For chunked payloads,
derive a per-chunk key via HKDF and use a `prefix || counter` nonce, with the
drop id, chunk index, and total bound in the AAD.

**Consequences.** Safe random nonces and no nonce reuse across chunks; binds
ordering and total count to prevent truncation/reordering.

## ADR-0004 — SHA-256 and an RFC 6962 Merkle log

**Context.** We need tamper-evident, consensus-free verifiability.

**Decision.** Use SHA-256 with the RFC 6962 construction (domain-separated leaf
`0x00` / node `0x01` hashes), inclusion proofs, and consistency proofs. Signed
tree heads provide non-equivocation when gossiped.

**Consequences.** Standard, well-reviewed proof algorithms and tooling interop;
no consensus overhead. Anchoring to OpenTimestamps is planned for M4.

## ADR-0005 — Location is access, not discovery

**Context.** Location could be a discovery mechanism (find drops nearby) or an
access gate (open a drop you already know about).

**Decision.** Location is an **access gate**. There is no global spatial index;
the author communicates the place out of band.

**Consequences.** Removes a large class of metadata leakage and opportunistic
abuse, and simplifies the protocol. Requires out-of-band coordination.

## ADR-0006 — `pedantic`/`nursery` clippy lints advisory-off

**Context.** We want a strict, always-green `-D warnings` gate.

**Decision.** Enforce `clippy::all` plus explicit correctness denies
(`unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`,
`unsafe`), and leave `pedantic`/`nursery` off to avoid noise.

**Consequences.** CI stays meaningful and green; style-level suggestions are not
enforced. Revisit if the codebase stabilizes and we want stricter style lints.

## ADR-0007 — Reference TCP transport before libp2p

**Context.** M2 needs two-node delivery, sparse-cell request/response, and
chunk transfer. The plan specifies libp2p (QUIC + TCP, gossipsub + Kademlia),
which carries significant API surface and build weight.

**Decision.** Implement the peer protocol transport-agnostically
(`keepstone-node::protocol`) and ship a small reference TCP transport
(`keepstone-node::net`) first. libp2p slots in behind the same messages.

**Consequences.** Faster, testable delivery today with no new cryptographic
assumptions (content is already end-to-end encrypted). Transport-level
encryption, gossipsub, Kademlia, and NAT traversal still require libp2p and
remain M2 work.

## ADR-0008 — Recipient tags with decoy padding

**Context.** Naming recipient X25519 keys in the drop body leaks who a drop is
for to anyone who fetches the ciphertext.

**Decision.** Replace recipient keys with an 8-byte tag
`HKDF(recipient_public, drop_nonce)` and pad every drop to `MIN_TAGS` (16)
entries with random decoys. Recipients match their tag and attempt to unseal;
decoys fail authentication.

**Consequences.** Recipient count and identity are no longer in the clear, and
tags are unlinkable across drops. False positives cost a failed AEAD open.
Larger drops (16 sealed keys) regardless of recipient count.

## ADR-0009 — libp2p as the production transport

**Context.** The plan specifies libp2p/QUIC with Noise. The reference TCP
transport proved the protocol but lacks transport encryption, QUIC, and future
gossip/DHT support.

**Decision.** Add a `keepstone-p2p` crate using `libp2p` 0.57 (requires Rust
1.88) with TCP + QUIC, Noise, Yamux, identify, and a request/response protocol
whose codec speaks the existing `keepstone-node::protocol` messages. The
reference TCP transport remains for fast, dependency-light tests.

**Consequences.** Real QUIC + Noise transport and a path to gossipsub/Kademlia.
Heavier build and a higher MSRV (1.88). Confidentiality is unchanged: the
transport carries only end-to-end-encrypted ciphertext.
