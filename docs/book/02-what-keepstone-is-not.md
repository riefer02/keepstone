# 2. What Keepstone is *not*

Naming the non-goals is the fastest way to understand a system. Keepstone is
**not** any of these, and each "not" is a deliberate decision.

## Not a messenger

There is no real-time channel, no online presence, no typing indicator, no
"delivered" receipt. A drop is created and then sits still until someone with
the key opens it. If you want a conversation, this is the wrong tool — and that
is on purpose. Conversations are chat apps; *place-anchored, asynchronous,
no-live-channel disclosure* is the gap Keepstone fills.

## Not an anonymity network

Keepstone does **not** route your traffic through onion layers, and it does not
pretend to hide that a node is talking to the network. It mitigates *some*
metadata (recipients are unnamed on the wire; cell lookups are k-anonymous), but
a global observer can still learn a lot. See
[Chapter 4](04-adversaries-and-threat-model.md) and
[Chapter 23](23-query-privacy.md). If you need strong anonymity, layer Keepstone
over Tor; it does not claim to be Tor.

## Not a blockchain

There is no global consensus, no mining, no shared ledger every node agrees on.
Each node keeps its **own** append-only transparency log, and logs can be
compared via **signed tree heads** and **consistency proofs** (Chapter 19).
Optional external anchoring (a local hash chain, or Bitcoin via OpenTimestamps)
gives tamper-evidence against rewrite. Trust is *verifiable*, not *consensual*.

## Not a global search engine

You cannot ask "show me all drops near me." That query does not exist because
the index that would answer it is exactly the metadata and abuse vector the
design refuses to create ([ADR-0005](../DECISIONS.md)). You find a drop by
already knowing roughly where it is.

## Not a durable storage service

There is no guarantee a drop survives. Relays and peers hold ciphertext
best-effort; federation (`push` / `fetch`) improves the odds but is not a
durability contract. Availability is an explicit non-guarantee for now.

## Not audited

The code is **not independently audited**. It is research-grade. Treat the
claims in [`docs/CLAIMS.md`](../CLAIMS.md) as the honest boundary: each one maps
to a test or artefact, and the last row says "not audited."

## Who it's for

- Someone who wants to **leave something for a person**, where the something
  shouldn't pass through a server that can read it, and without a live channel.
- An **organizer** running a location game or event (the "hunt" kit).
- A **builder** who wants a real, honest example of applied cryptography, a
  transparency log, and a peer-to-peer protocol in Rust.

## Go look at this

- [`docs/ABUSE.md`](../ABUSE.md) — the mitigations and their limits
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — explicit non-guarantees
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0005 (no spatial index)

Next: [The two locks](03-the-two-locks.md)
