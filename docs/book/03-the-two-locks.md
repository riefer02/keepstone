# 3. The two locks

A drop is protected by two independent mechanisms. Keeping them separate is the
most important idea in this book.

## Lock 1 — cryptographic (the real guarantee)

Content is encrypted under a random **per-drop content key**, which is sealed
separately to each recipient device's public key.

```
   plaintext
      │  encrypt with content key K
      ▼
   ciphertext chunks  ──▶  anyone can carry these; useless without K
      ▲
      │  K is sealed to each recipient's public key
      │
   K ─┴─▶ sealed-to-Alice, sealed-to-Bob, ... (+ decoys)
```

- Only a holder of a recipient secret key can recover `K`.
- So only a recipient can read the content — not relays, log nodes, observers,
  or the operator.
- This holds **anywhere**. It does not depend on location.

## Lock 2 — spatial (access gating, best-effort)

A drop is addressed to an [H3 cell](17-geospatial-addressing.md). With no global
index, finding a drop means already knowing its place. In **place-locked mode**
(Chapter 21) the content key is also split across custodians and released only
for a valid **presence certificate**.

- This is the "only when they're there" part.
- It is **best-effort**: GPS can be spoofed, witnesses can be Sybil.

## Why the order matters

Location does **not** strengthen the crypto. The crypto must stand alone,
because the spatial lock is what fails in practice: spoofed coordinates,
colluding witnesses, or a recipient who simply carries the ciphertext home and
opens it later.

> **The recipient key is the lock. Location is an access gate. Location is never
> the confidentiality guarantee.**

| Lock | Mechanism | Strength | Protects |
|---|---|---|---|
| Cryptographic | Per-drop content key; X25519 + XChaCha20-Poly1305 seal per recipient device; PQ hybrid available | Strong, works anywhere | **Confidentiality** — the real guarantee |
| Spatial | H3 cell + k-of-n presence certificate (place-locked) | Best-effort | **Access gating** and friction |

## The intuition

A locked box buried at a marked spot. The box is the crypto: digging it up
doesn't open it. The spot is the location: you must know where to dig. If someone
carries the box home, the lock still holds — it just isn't "there" anymore.

## Go look at this

- [`crates/crypto/src/lib.rs`](../../crates/crypto/src/lib.rs) — states the rule
- [`crates/crypto/src/sealed.rs`](../../crates/crypto/src/sealed.rs) — the sealed box (Lock 1)
- [`crates/core/src/place.rs`](../../crates/core/src/place.rs) — custodian shares (Lock 2)
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — "the recipient key is the lock"

Next: [Adversaries and the threat model](04-adversaries-and-threat-model.md)
