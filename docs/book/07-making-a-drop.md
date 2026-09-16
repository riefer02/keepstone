# 7. Making a drop

Creating a drop means: pick the recipients, pick the place, choose a payload,
and (optionally) set a lifetime and a crypto suite.

```bash
keepstone --data-dir ./alice drop-create \
  --to bob \
  --lat 51.5007 --lng -0.1246 \
  --ring 2 \
  --message "meet at the old oak at dusk"
```

The command prints the drop's id and a short summary:

```
drop created
  id:      c682441a71867429725455f0014a4fc07ae00010d913c033356a8bde591fccb1
  cell:    8928308280fffff
  chunks:  1
  bytes:   26
```

## The options

| Flag | Meaning | Default |
|---|---|---|
| `--to <name>` | Recipient contact. **Repeatable** for multiple recipients. | required |
| `--lat` / `--lng` | The place. | required |
| `--res` | H3 resolution 0–15 (how big the cell is). | `9` |
| `--ring` | Delivery k-ring radius (how far around the cell is "near"). | `2` |
| `--message "<text>"` | Inline payload. | — |
| `--file <path>` | File payload (conflicts with `--message`). | — |
| `--ttl <seconds>` | Lifetime; `0` means never expires. | `0` |
| `--suite <name>` | `classical` or `hybrid` (post-quantum). | `classical` |

You must provide exactly one of `--message` or `--file`; anything else is
rejected.

## Recipients

- **Multi-recipient:** pass `--to` more than once. Each recipient (and each of
  their devices) gets their own sealed copy of the content key.
- **Unknown recipient:** trying to send to a name you haven't added fails before
  anything is written.
- **Hybrid + contact without a hybrid key:** fails with a clear message, since
  there's nothing to encapsulate to.

Non-recipients are simply unable to open the drop — they match no key slot and
decryption is refused.

## Choosing a suite

- **`classical`** (suite 1): X25519 + Ed25519 + XChaCha20-Poly1305, HKDF-SHA256.
  Small and fast.
- **`hybrid`** (suite 2): X25519 **+ ML-KEM-768** for encryption, and the
  envelope is signed **Ed25519 + ML-DSA-65**. Secure as long as *either*
  primitive holds — the point being to survive "harvest now, decrypt later."

Hybrid drops are much larger (the ML-DSA-65 signature alone is 3309 bytes), so
use it when longevity or quantum resistance matters.

## What "ring" means here

`--ring` doesn't restrict who can *read* the drop (the key does that). It
describes the neighbourhood around the cell that counts as "near" for delivery
and discovery — the 1-ring is the cell plus its six neighbours, the 2-ring is
that plus the next layer out, and so on. See
[Chapter 17](17-geospatial-addressing.md).

## What just happened

Under the hood, `drop-create` is one call into the shared store library
(`Store::create_drop`), which:

1. generates a random content key,
2. streams-encrypts the payload into chunks,
3. seals the content key to each recipient device and pads the slot list with
   decoys,
4. mines a small proof-of-work,
5. builds and signs the envelope, and
6. writes the chunks + envelope and appends the envelope to the local log.

Chapter 16 takes the envelope apart field by field.

## Go look at this

- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — the `DropCreate` command
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `create_drop`
- Tests: `crates/store/src/lib.rs` (`create_open_verify_round_trip`), the CLI demo

Next: [Getting a drop](08-getting-a-drop.md)
