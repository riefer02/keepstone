# 1. The dead-drop idea

## The old idea

A **dead drop** is a hiding place where one person leaves something and another
picks it up later. The two never meet. The spot — a loose brick, a hollow tree —
is agreed in advance and communicated out of band.

Its value is decoupling the parties in **time and space**: the sender needn't be
present when the receiver arrives, there's no direct channel to intercept, and
compromising one drop doesn't compromise the network.

## The digital version, done badly

Most "leave a message for later" systems are a server with a mailbox:

```
   sender ─────▶ [ server mailbox ] ─────▶ recipient
                        ▲
                        │  reads everything, can delete it,
                        │  logs who/when/where
```

The server is a single point of confidentiality, availability, and metadata
failure. End-to-end encryption fixes the first; the other two remain. The
mailbox also still needs addressing, which leaks.

## Keepstone's twist: the hiding place is a real place

Keepstone replaces the mailbox with a **geographic cell** — a small patch of the
world addressed by an [H3](17-geospatial-addressing.md) index.

```
   author ──▶ [ encrypted drop addressed to cell 8928308280fffff ]
                        │  relayed by anyone, readable by no one but the key
                        ▼
              anyone near the cell can carry it
              only the recipient's key can open it
```

Two consequences are the whole design:

1. **Only the intended key can read it.** Content is encrypted to the
   recipient's public key; relays, logs, and observers hold ciphertext.
2. **Proximity is how you find it — and how you're allowed to.** There is no
   global "search all drops" index. The author tells the recipient where to
   look.

The second is [ADR-0005 — location is access, not discovery](../DECISIONS.md).
It removes opportunistic abuse and a class of metadata leakage, at the cost of
out-of-band coordination — which a dead drop always required.

## Why build it

- **Useful primitive:** "leave something at a place for a specific person, that
  no intermediary can read or erase" is poorly served by chat or file sync.
- **Real engineering:** it forces a crypto core, a transparency log, and a peer
  protocol rather than CRUD.
- **Honest threat model:** the crypto is the guarantee; location is friction and
  defense in depth. Stated everywhere, never oversold.

## The shape of the system

```
   ┌──────────── identity ────────────┐
   │  Ed25519 signing + X25519 ecdh   │
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
                   │  fetch by id, or receive via cell topic
                   ▼
   ┌──────── recipient ────────────────────────────────┐
   │  verify signature → match own tag → unseal key     │
   │  → decrypt chunks → reassemble → verify log entry  │
   └────────────────────────────────────────────────────┘
```

Part I explains the *why*; Part III opens each box.

## Go look at this

- [`README.md`](../../README.md) — the pitch
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — the layered picture
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0005

Next: [What Keepstone is *not*](02-what-keepstone-is-not.md)
