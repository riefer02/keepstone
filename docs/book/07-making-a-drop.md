# 7. Making a drop

```bash
keepstone --data-dir ./alice drop-create \
  --to bob \
  --lat 51.5007 --lng -0.1246 \
  --ring 2 \
  --message "meet at the old oak at dusk"
```

Output:

```
drop created
  id:      c682441a71867429725455f0014a4fc07ae00010d913c033356a8bde591fccb1
  cell:    8928308280fffff
  chunks:  1
  bytes:   26
```

## Options

| Flag | Meaning | Default |
|---|---|---|
| `--to <name>` | Recipient contact. **Repeatable**. | required |
| `--lat` / `--lng` | The place. | required |
| `--res` | H3 resolution 0–15 (cell size). | `9` |
| `--ring` | Delivery k-ring radius. | `2` |
| `--message "<text>"` | Inline payload. | — |
| `--file <path>` | File payload (conflicts with `--message`). | — |
| `--ttl <seconds>` | Lifetime; `0` = never. | `0` |
| `--suite <name>` | `classical` or `hybrid`. | `classical` |

Provide exactly one of `--message` / `--file`.

## Recipients

- **Multi-recipient:** repeat `--to`. Each recipient device gets its own sealed
  content key.
- **Unknown recipient:** fails before anything is written.
- **Hybrid + contact with no hybrid key:** fails with a clear message.
- Non-recipients match no slot and are refused.

## Suites

- **`classical`** (1): X25519 + Ed25519 + XChaCha20-Poly1305, HKDF-SHA256. Small
  and fast.
- **`hybrid`** (2): X25519 **+ ML-KEM-768** encryption; envelope signed
  **Ed25519 + ML-DSA-65**. Secure if either primitive holds — survives "harvest
  now, decrypt later." Much larger (the ML-DSA-65 signature alone is 3309 bytes).

## What `--ring` means

It does **not** gate reading (the key does). It's the neighbourhood around the
cell used for delivery and discovery: ring 1 is the cell plus six neighbours,
ring 2 the next layer out ([Chapter 17](17-geospatial-addressing.md)).

## What just happened

`drop-create` calls `Store::create_drop`, which:

1. generates a random content key,
2. stream-encrypts the payload into chunks,
3. seals the content key to each recipient device and pads the slots with decoys,
4. mines a small proof-of-work,
5. builds and signs the envelope,
6. writes chunks + envelope and appends the envelope to the local log.

Chapter 16 takes the envelope apart.

## Go look at this

- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `DropCreate`
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `create_drop`
- Tests: `create_open_verify_round_trip`, the CLI demo

Next: [Getting a drop](08-getting-a-drop.md)
