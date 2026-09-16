# 2. What Keepstone is *not*

The non-goals are the fastest way to understand the system.

## Not a messenger

No real-time channel, no presence, no delivery receipt. A drop is created and
sits still until someone with the key opens it. Conversations are chat apps;
this is place-anchored, asynchronous, no-live-channel disclosure.

## Not an anonymity network

No onion routing, and no pretense of hiding that a node talks to the network.
Some metadata is mitigated (recipients unnamed on the wire; k-anonymous cell
lookups), but a global observer still learns a lot. See
[Chapter 4](04-adversaries-and-threat-model.md) and
[Chapter 23](23-query-privacy.md). Layer it over Tor if you need Tor.

## Not a blockchain

No global consensus, mining, or shared ledger. Each node keeps its **own**
append-only transparency log; logs are compared via **signed tree heads** and
**consistency proofs** (Chapter 19). Optional anchoring (hash chain, or Bitcoin
via OpenTimestamps) gives tamper-evidence. Trust is verifiable, not consensual.

## Not a global search engine

You cannot ask "show me drops near me." That index is exactly the metadata and
abuse vector the design refuses to create ([ADR-0005](../DECISIONS.md)). You
find a drop by already knowing roughly where it is.

## Not durable storage

No guarantee a drop survives. Relays and peers hold ciphertext best-effort;
federation improves the odds but is not a durability contract. Availability is
an explicit non-guarantee.

## Not audited

The code is **not independently audited**. It is research-grade. See
[`docs/CLAIMS.md`](../CLAIMS.md): each claim maps to a test or artefact, and the
last row says "not audited."

## Who it's for

- Someone leaving something for a person, without a server that can read it and
  without a live channel.
- An organizer running a location game (the "hunt" kit).
- A builder wanting a real example of applied crypto, a transparency log, and a
  peer protocol in Rust.

## Go look at this

- [`docs/ABUSE.md`](../ABUSE.md) — mitigations and limits
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — non-guarantees
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0005

Next: [The two locks](03-the-two-locks.md)
