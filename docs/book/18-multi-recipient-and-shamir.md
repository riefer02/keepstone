# 18. Many recipients, many devices, Shamir

Content is encrypted once under a random content key, then that key is sealed
**separately** to every device that should read it. Scaling in two directions is
nearly free.

## Multi-recipient

```bash
keepstone --data-dir ./alice drop-create \
  --to bob --to carol --to dave \
  --lat 51.5007 --lng -0.1246 --message "for the three of you"
```

`create_drop` resolves every named contact to its devices and produces one
wrapped-key slot per device. Any can open it; a non-recipient matches no slot.

## Multi-device

A contact name can hold several devices ([Chapter 6](06-identities-and-contacts.md)).
`--to bob` seals to **all** of bob's devices, so the same drop opens on laptop
and phone. Keys stay per-device, so a lost device doesn't force rotating the
others.

```
                          content key K
        ┌──────────┬──────────┬┴─────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼
     bob-laptop  bob-phone  carol      dave      (decoys)
                    all slots padded to ≥ MIN_TAGS = 16
```

Every drop is padded to ≥16 slots with random decoys, so an observer can't tell
whether there are 2 recipients or 12, or which slots are real.

## Where it breaks down

Sealing to `n` devices is linear in `n` — fine for tens, not thousands (that
would need a group key, out of scope). The design targets small, personal drops.

## Shamir secret sharing

Place-locked mode wants the key released only when someone is *there*, with no
single custodian able to release alone. The tool is **Shamir secret sharing**
([`shamir.rs`](../../crates/crypto/src/shamir.rs)):

```
split(content_key, t, n)  ──▶  n shares, any t reconstruct
combine([t shares])        ──▶  content_key   (fewer than t: nothing)
```

- Arithmetic over **GF(2^8)**, AES polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
- Shares are `(x, y)` pairs; `combine` does Lagrange interpolation at `x = 0`.
- Fewer than `t` shares leave the secret information-theoretically hidden.

In place-locked drops the key is split across **cell custodians**; each share is
sealed to its custodian ([`place.rs`](../../crates/core/src/place.rs),
`seal`/`open`) and released only for a valid presence certificate
([Chapter 21](21-place-locked-release.md)).

```
   content key K
        │  split(3-of-5)
   ┌────┬────┬────┬────┬────┐
   │ s1 │ s2 │ s3 │ s4 │ s5 │   each sealed to a different custodian
   └────┴────┴────┴────┴────┘
        │  claimant presents a presence cert
   custodian i releases s_i  ──▶  any 3 of 5 reconstruct K
```

`DEFAULT_THRESHOLD` for presence is **3**. Combine is sub-microsecond, so the
threshold costs only the network round-trips.

## Why both

| Mechanism | Scales | Purpose |
|---|---|---|
| Sealed keys (multi-recipient/devices) | `n` devices | **Who** can read (the lock) |
| Shamir sharing (place-locked) | `t`-of-`n` custodians | **When/where** the key is released (the gate) |

## Go look at this

- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — recipient resolution in `create_drop`
- [`crates/crypto/src/shamir.rs`](../../crates/crypto/src/shamir.rs) — `split` / `combine`
- [`crates/core/src/place.rs`](../../crates/core/src/place.rs) — custodian share sealing
- [`docs/SPEC.md`](../SPEC.md) §13

Next: [The transparency log](19-transparency-log.md)
