# 3. The two locks

A Keepstone drop is protected by two independent mechanisms. Keeping them
mentally separate is the single most important thing in this book.

## Lock 1 — the cryptographic lock (the real guarantee)

The content is encrypted under a random **per-drop content key**. That key is
then sealed — separately — to each recipient device's public key.

```
   plaintext
      │  encrypt with content key K
      ▼
   ciphertext chunks  ──▶  anyone can carry these; they are useless without K
      ▲
      │  K is sealed to each recipient's public key
      │
   K ─┴─▶ sealed-to-Alice, sealed-to-Bob, ... (+ decoys)
```

- Nobody but a holder of a recipient secret key can recover `K`.
- Therefore nobody but a recipient can read the content. Not relays, not log
  nodes, not network observers, not the operator.
- This holds **anywhere on Earth**. It does not depend on location at all.

This is the lock that keeps the promise. Everything else is convenience or
defense in depth.

## Lock 2 — the spatial lock (access gating, best-effort)

A drop is addressed to an [H3 cell](17-geospatial-addressing.md). There is no
global index, so *finding* a drop means already knowing its place. In
**place-locked mode** (Chapter 21) the content key is additionally split across
custodians and only released when the claimant presents a
**presence certificate** — evidence that they were near the place.

- This is the "only when they're there" part.
- It is **best-effort**. GPS can be spoofed and witnesses can be Sybil. The
  design says this out loud rather than pretending otherwise.

## Why two locks, and why the order matters

It is tempting to think location makes the crypto stronger. It does not. The
crypto must stand on its own, because the spatial lock is exactly the kind of
thing that fails in the real world (spoofed coordinates, colluding witnesses,
a recipient who simply carries the ciphertext away and opens it later).

So the design rule, repeated throughout the repo, is:

> **The recipient key is the lock. Location is an access gate. Location is
> never the confidentiality guarantee.**

| Lock | Mechanism | Strength | Protects |
|---|---|---|---|
| Cryptographic | Per-drop content key; X25519 + XChaCha20-Poly1305 seal to each recipient device; post-quantum hybrid available | Strong, works anywhere | **Confidentiality** — the real guarantee |
| Spatial | H3 cell addressing + k-of-n presence certificate (place-locked mode) | Best-effort, defense in depth | **Access gating** and friction |

## A worked intuition

Imagine a locked box buried at a marked spot.

- The box is the crypto: even if someone digs it up, they can't open it.
- The spot is the location: you have to know where to dig, and being there is
  part of the ritual.

If someone finds the box and carries it home, the lock still holds — it just
wasn't "there" anymore. That is exactly the tradeoff Keepstone embraces: the
location is a gate you walk through, not a property of the key.

## Go look at this

- [`crates/crypto/src/lib.rs`](../../crates/crypto/src/lib.rs) — the crate-level doc states the rule
- [`crates/crypto/src/sealed.rs`](../../crates/crypto/src/sealed.rs) — the sealed box (Lock 1)
- [`crates/core/src/place.rs`](../../crates/core/src/place.rs) — custodian shares (Lock 2, place-locked)
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — "the recipient key is the lock"

Next: [Adversaries and the threat model](04-adversaries-and-threat-model.md)
