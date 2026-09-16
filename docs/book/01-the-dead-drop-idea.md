# 1. The dead-drop idea

## The old idea

In espionage, a **dead drop** is a hiding place where one person leaves
something and another picks it up later. The two never meet. The hiding place —
a loose brick, a hollow tree, a mark on a bench — is chosen in advance and
communicated out of band.

The beauty of a dead drop is that it decouples the two parties in **time and
space**. The sender doesn't have to be present when the receiver arrives. There
is no direct channel to intercept. If the spot is compromised, you lose that
drop, not your whole network.

## The digital version, done badly

Most digital "leave a message for later" systems are a server with a mailbox:

```
   sender ─────▶ [ server mailbox ] ─────▶ recipient
                        ▲
                        │  reads everything,
                        │  can delete it,
                        │  logs who/when/where
```

The server is a single point of:
- **confidentiality failure** (it sees plaintext, or holds the keys),
- **availability failure** (it can be shut down or delete your message),
- **metadata failure** (it knows who talks to whom, and when).

Encrypting the message end-to-end fixes the first, but the second two remain.
And the mailbox still needs addressing, which leaks.

## Keepstone's twist: the hiding place is a real place

Keepstone replaces the mailbox with a **geographic cell** — a small patch of the
real world, addressed with an [H3](17-geospatial-addressing.md) index. A drop is
encrypted content plus the cell it belongs to.

```
   author ──▶ [ encrypted drop addressed to cell 8928308280fffff ]
                        │
                        │  relayed by anyone; readable by no one but the key
                        ▼
              anyone near that cell can carry it
              only the recipient's key can open it
```

Two things follow, and they are the whole design:

1. **Only the intended key can read it.** The content is encrypted to the
   recipient's public key. Relays, log nodes, and network observers hold
   ciphertext they cannot open.
2. **Being near the place is how you find it — and how you're *allowed* to
   find it.** There is no global "search all drops" index. The author tells the
   recipient where to look. Location is an **access gate**, not a map you can
   browse.

That second point is a deliberate choice with a name:
[ADR-0005 — location is access, not discovery](../DECISIONS.md). It removes an
entire class of abuse (no opportunistic scanning for drops near you) and a large
amount of metadata leakage, at the cost of requiring out-of-band coordination —
which is exactly what a dead drop always required anyway.

## Why build this

- **It's a genuinely useful primitive.** "Leave something at a place for a
  specific person, that no intermediary can read or erase" is not well served by
  chat apps or file sync.
- **It forces real engineering.** You cannot hand-wave storage/retrieval, so you
  end up building a real transparency log, a real peer protocol, a real crypto
  core — the things that make a portfolio project more than a CRUD app.
- **The threat model is honest.** The crypto is the guarantee; the location is
  friction and defense in depth. That distinction is stated everywhere, and
  never oversold.

## The shape of the system

By the end of this book you'll recognize this picture:

```
   ┌──────────── identity ────────────┐
   │  Ed25519 signing + X25519 ecdh   │   (the author's keys)
   └───────────────┬──────────────────┘
                   │  create
                   ▼
   ┌──────────── a drop ──────────────────────────────┐
   │  content ──encrypt──▶ chunks (AEAD)              │
   │  content key ──seal to each recipient──▶ wrapped │
   │  body = { cell, ring, tags+decoys, proof-of-work }│
   │  body ──sign──▶ envelope ──hash──▶ drop id        │
   └───────────────┬───────────────────────────────────┘
                   │  publish / relay / gossip
                   ▼
   ┌──────── transport: TCP / libp2p(QUIC+TCP) ────────┐
   │  anyone carries ciphertext; nobody can read it     │
   └───────────────┬───────────────────────────────────┘
                   │  fetch by id (or receive via cell topic)
                   ▼
   ┌──────── recipient ────────────────────────────────┐
   │  verify signature → match own tag → unseal key     │
   │  → decrypt chunks → reassemble → verify log entry  │
   └────────────────────────────────────────────────────┘
```

Keep that picture in mind. The rest of Part I explains the *why* around it; Part
III opens up each box.

## Go look at this

- [`README.md`](../../README.md) — the one-paragraph pitch
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — the layered picture
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0005, "location is access, not discovery"

Next: [What Keepstone is *not*](02-what-keepstone-is-not.md)
