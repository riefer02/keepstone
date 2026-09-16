# The Keepstone Book

A guided tour of **what Keepstone is, what it does, and how it works** — written
for a developer who has never seen the repo, and for the author six months from
now who has forgotten every detail.

It assumes you can read code and know roughly what a public key is. It does
**not** assume any cryptography background: every idea is introduced in plain
language before the real types and fields show up.

---

## The one-sentence version

> Leave an encrypted message at a place. Only the person you choose can read it,
> only when they're there.

Keepstone is a decentralized, end-to-end-encrypted **geospatial dead-drop
engine**. The **recipient's key is the lock**. The **location is an access
gate**, never the confidentiality guarantee.

---

## How to read this book

Each chapter is short and self-contained, and ends with a **Go look at this**
block pointing at the exact source file(s) and the test that proves the
behaviour. Read in order the first time; after that, jump around.

Three reading paths:

| If you want… | Read |
|---|---|
| **The idea, fast** (~20 min) | 01 → 02 → 03 → 12 → 25 |
| **How to use it** (~40 min) | 05 → 06 → 07 → 08 → 09 → 10 → 11 |
| **How it actually works** (the whole thing) | everything, in order |

## Conventions

- `H(x)` means `SHA-256(x)`.
- `||` means byte concatenation. All multi-byte integers on the wire are
  **big-endian**.
- A **drop** is one encrypted message at one place. Its **id** is
  `H(exact transmitted bytes)`.
- Diagrams are ASCII so they render anywhere.
- "Go look at this" paths are relative to the repository root.

## Accuracy

Everything here is written against the code at the time of writing — 106 tests
passing, all quality gates green. Where the code and this book could drift, the
code wins. The authoritative documents are:

- [`docs/SPEC.md`](../SPEC.md) — the wire format
- [`docs/DECISIONS.md`](../DECISIONS.md) — 15 architecture decision records
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — what is and isn't guaranteed
- [`docs/CLAIMS.md`](../CLAIMS.md) — every claim mapped to evidence

## Contents

**Part I — Why this exists**

1. [The dead-drop idea](01-the-dead-drop-idea.md)
2. [What Keepstone is *not*](02-what-keepstone-is-not.md)
3. [The two locks](03-the-two-locks.md)
4. [Adversaries and the threat model](04-adversaries-and-threat-model.md)

**Part II — What it does (you, using it)**

5. [Build, run, and the quality gate](05-build-run-gate.md)
6. [Identities and contacts](06-identities-and-contacts.md)
7. [Making a drop](07-making-a-drop.md)
8. [Getting a drop](08-getting-a-drop.md)
9. [Verifying and anchoring](09-verifying.md)
10. [The browser client and the daemon API](10-browser-client-and-api.md)
11. [Running a hunt](11-running-a-hunt.md)

**Part III — How it works (the engine room)**

12. [The workspace map](12-workspace-map.md)
13. [The cryptographic core](13-crypto-core.md)
14. [Post-quantum, hybrid](14-post-quantum-hybrid.md)
15. [Canonical CBOR and byte-preservation identity](15-canonical-cbor-and-identity.md)
16. [Anatomy of a drop](16-anatomy-of-a-drop.md)
17. [Geospatial addressing](17-geospatial-addressing.md)
18. [Many recipients, many devices, Shamir](18-multi-recipient-and-shamir.md)
19. [The transparency log](19-transparency-log.md)
20. [Networking](20-networking.md)
21. [Place-locked release](21-place-locked-release.md)
22. [Federated relays and STH gossip](22-federated-relays-and-gossip.md)
23. [Query privacy](23-query-privacy.md)
24. [The store and the data directory](24-the-store-and-data-dir.md)

**Part IV — Trust, operations, and the future**

25. [Security summary](25-security-summary.md)
26. [Anchoring trust](26-anchoring-trust.md)
27. [Deployment](27-deployment.md)
28. [How it's tested](28-how-its-tested.md)
29. [Design decisions, digest](29-design-decisions.md)
30. [Glossary and appendices](30-glossary-and-appendices.md)
