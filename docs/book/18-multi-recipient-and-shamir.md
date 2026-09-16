# 18. Many recipients, many devices, Shamir

A drop's content is encrypted once under a random content key, and that key is
sealed **separately** to every device that should be able to read it. Scaling
that in two directions — more people, more devices per person — is nearly free.

## Multi-recipient

Pass `--to` more than once:

```bash
keepstone --data-dir ./alice drop-create \
  --to bob --to carol --to dave \
  --lat 51.5007 --lng -0.1246 --message "for the three of you"
```

`create_drop` resolves every named contact to its devices and produces one
wrapped-key slot per device. Any of them opens the drop; a non-recipient matches
no slot and is refused.

## Multi-device

A contact name can hold several devices ([Chapter 6](06-identities-and-contacts.md)).
Addressing `--to bob` seals to **all** of bob's devices, so the same drop opens
on his laptop and his phone. Keys stay per-device, so losing one device doesn't
mean rotating the others.

```
                          content key K
                               │
        ┌──────────┬──────────┬┴─────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼
     bob-laptop  bob-phone  carol      dave      (decoys)
        │          │          │          │          │
        └──────────┴──────────┴──────────┴──────────┘
                    all slots padded to ≥ MIN_TAGS = 16
```

Because every drop is padded to at least 16 slots with random decoys, an observer
can't tell whether this drop has 2 recipients or 12, or which slots are real.

## Where the scaling breaks down (and the fix)

Sealing to `n` devices is linear in `n`: fine for tens, silly for thousands.
Beyond that you would use a group key, which is out of scope today. The current
design optimizes for *small, personal* drops — the common case for a dead drop.

## Shamir secret sharing: sharing one key among many custodians

There's a different scaling problem in **place-locked** mode: you want the
content key to be released only when someone is *there*, and no single custodian
should be able to release it alone. The tool is **Shamir secret sharing**
(`crates/crypto/src/shamir.rs`).

```
split(content_key, t, n)  ──▶  n shares, any t reconstruct
combine([t shares])        ──▶  content_key   (fewer than t: nothing)
```

- Arithmetic is over **GF(2^8)** with the AES polynomial `x^8 + x^4 + x^3 + x + 1`
  (`0x11B`).
- Shares are `(x, y)` pairs; `combine` does Lagrange interpolation at `x = 0`.
- With fewer than `t` shares, the secret is information-theoretically hidden —
  no amount of compute helps.

In place-locked drops the content key is split across **cell custodians**. Each
custodian stores only its own share, sealed to the custodian's key
(`crates/core/src/place.rs`, `seal`/`open`). A share is released only when the
claimant presents a valid presence certificate
([Chapter 21](21-place-locked-release.md)).

```
   content key K
        │  split(3-of-5)
        ▼
   ┌────┬────┬────┬────┬────┐
   │ s1 │ s2 │ s3 │ s4 │ s5 │   each sealed to a different custodian
   └────┴────┴────┴────┴────┘
        │
        │  claimant presents a presence cert
        ▼
   custodian i releases s_i  ──▶  any 3 of 5 reconstruct K
```

`DEFAULT_THRESHOLD` for presence is **3**. Shamir combine is sub-microsecond, so
the threshold adds essentially no cost beyond the network round-trips to collect
shares.

## Why both mechanisms exist

They solve different problems and it's worth not conflating them:

| Mechanism | Scales | Purpose |
|---|---|---|
| Sealed keys (multi-recipient/devices) | `n` devices | **Who** can read (the lock) |
| Shamir sharing (place-locked) | `t`-of-`n` custodians | **When/where** the key is released (the gate) |

## Go look at this

- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — recipient resolution in `create_drop`
- [`crates/crypto/src/shamir.rs`](../../crates/crypto/src/shamir.rs) — `split` / `combine`
- [`crates/core/src/place.rs`](../../crates/core/src/place.rs) — custodian share sealing
- [`docs/SPEC.md`](../SPEC.md) §13 — place-locked release

Next: [The transparency log](19-transparency-log.md)
