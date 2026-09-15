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

## ADR-0010 — Anchoring behind a trait; local hash chain first

**Context.** The plan commits to OpenTimestamps (D6) but notes the Rust OTS
ecosystem is thin. On crates.io, `opentimestamps` is 0.2.0 and supports parsing
and verifying `.ots` files — it does not submit to calendar servers, and
verification needs Bitcoin block headers.

**Decision.** Introduce an `Anchor` trait in `keepstone-log` and ship a
dependency-free `HashChainAnchor` that commits signed tree heads into a locally
verifiable append-only chain. The CLI persists and verifies this chain
(`log-anchor`, `log-anchors`). OpenTimestamps plugs in behind the same trait
once a suitable crate exists.

**Consequences.** Real, testable, offline anchoring today with no new
dependencies. It provides tamper-evidence but not a third-party timestamp until
an external backend is added; the trait boundary keeps that a drop-in change.

## ADR-0011 — Namespaced file layout over the wire (drop envelope v2)

**Context.** The envelope needed to carry either an Ed25519 signature or a
hybrid Ed25519 + ML-DSA-65 signature.

**Decision.** `Envelope = [suite, sig_kind, signer, ml_dsa_key, payload, signature]`.
`sig_kind` 1 has an empty `ml_dsa_key` and a 64-byte signature; kind 2 carries a
1952-byte verifying key and a `64 || 3309` signature. Verification dispatches on
`sig_kind` and, for hybrid, requires both halves.

**Consequences.** Post-quantum drops are self-verifying (the verifying key
travels with the drop). Envelopes grew from `array(4)` to `array(6)`; this is a
pre-release wire break.

## ADR-0012 — Hand-written HTTP daemon instead of a web framework

**Context.** The plan calls for a browser client as a thin client to a local
node. A framework (axum/hyper) would add a large dependency tree for a handful
of JSON routes on localhost.

**Decision.** Implement a minimal HTTP/1.1 server (Content-Length bodies,
`Connection: close`) in `keepstone-daemon`, serving an embedded single-page UI.
The daemon reuses the same crates and data-directory format as the CLI.

**Consequences.** No new heavy dependencies and full control of the surface. It
is not a general-purpose HTTP server (no keep-alive, chunked encoding, or TLS);
it is intended for `127.0.0.1` only. The daemon duplicates a little data-dir
logic from the CLI; extracting a shared `keepstone-store` crate is a follow-up.

## ADR-0013 — Shared `keepstone-store` library

**Context.** The CLI and the browser-client daemon both implemented the same
data-directory operations (identity, contacts, drops, log). The duplication had
already caused drift and made both clients harder to maintain.

**Decision.** Extract those operations into `keepstone-store`. Both clients open
a `Store` over their data directory and call it; the on-disk format is defined
in exactly one place. Path helpers stay where they are cheap.

**Consequences.** One implementation of create/open/list/verify, shared tests,
and easier future clients (desktop, mobile). The daemon shrank substantially.
The store is synchronous; async callers just call it directly (operations are
short and local).

## ADR-0014 — k-anonymous cell lookups (query privacy)

**Context.** The sparse-cell path queries the Kademlia DHT with the literal H3
cell, so a network observer learns which cell a node is interested in — a
location leak that undercuts the metadata story.

**Decision.** Add `find_providers_private`: it issues provider lookups for the
target cell **and its `ring` neighbours** concurrently, shuffled, and returns
only the target's providers. `nearby_cells` exposes the ring. The CLI surfaces
this as `find-providers --ring`.

**Consequences.** A passive observer sees a set of plausible nearby-cell queries
instead of the one that identifies the node. This is k-anonymity, **not**
cryptographic PIR: it raises the cost of linkage without eliminating it, and it
costs `ring`-many lookups. Proper PIR remains future work; the interface is
shaped so it can be swapped in.
