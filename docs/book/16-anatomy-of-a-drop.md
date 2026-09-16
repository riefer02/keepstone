# 16. Anatomy of a drop

Two layers: an **envelope** (signature + author) wrapping a **body** (what the
drop is).

## Envelope

```
Envelope = [ suite:uint, sig_kind:uint, signer:bytes(32),
             ml_dsa_key:bytes, payload:bytes, signature:bytes ]
```

| Field | Meaning |
|---|---|
| `suite` | crypto suite id (1 classical, 2 hybrid) |
| `sig_kind` | 1 = Ed25519, 2 = Ed25519 + ML-DSA-65 |
| `signer` | author's Ed25519 public key (always present) |
| `ml_dsa_key` | ML-DSA-65 verifying key (empty for `sig_kind = 1`) |
| `payload` | canonical-encoded `DropBody`, stored verbatim |
| `signature` | 64 bytes, or `64 || 3309` for hybrid |

The drop's **id** is `SHA-256` of the whole envelope's exact bytes. The envelope
is also what goes into the transparency log, byte for byte.

## Body — 14 fields

`DropBody` is a canonical CBOR array of 14 entries:

| # | Field | Purpose |
|---|---|---|
| 1 | `version` | protocol version (`1`) |
| 2 | `suite` | crypto suite |
| 3 | `cell` | H3 cell (hex text) — the place |
| 4 | `ring` | delivery k-ring radius |
| 5 | `created_at` | Unix seconds |
| 6 | `expiry` | Unix seconds, `0` = never |
| 7 | `mode` | `0` capability, `1` place-locked |
| 8 | `chunk_size` | chunk size used |
| 9 | `chunk_count` | number of chunks |
| 10 | `content_root` | commitment over chunk ciphertexts |
| 11 | `prefix` | 20-byte nonce prefix |
| 12 | `drop_nonce` | 16 bytes; binds recipient tags to this drop |
| 13 | `pow_nonce` | proof-of-work nonce |
| 14 | `wrapped_keys` | tagged, sealed content keys (real + decoys) |

Not present: recipient public keys, author name, plaintext, content key.

## Wrapped keys — recipients without naming them

```
WrappedKey = [ tag:bytes(8), kind:uint, inner ]

kind = 1 (classical):
    inner = [ ephemeral_public(32), nonce(24), ciphertext(48) ]
kind = 2 (hybrid):
    inner = [ ephemeral_x25519(32), kem_ciphertext(1088), nonce(24), ciphertext(48) ]
```

The `tag` locates a recipient's slot without naming their key:

```
tag = HKDF(ikm = recipient_x25519_public,
           salt = "keepstone/v1",
           info = "keepstone/v1/tag" || drop_nonce)[0..8]
```

Because it depends on the drop's random `drop_nonce`, tags are **unlinkable
across drops**.

### Decoys

Every drop has at least `MIN_TAGS = 16` slots, padded with random decoys (random
tag, key, nonce, ciphertext). So recipient **count** and **identity** are hidden.
A tag that matches a decoy fails AEAD authentication
([ADR-0008](../DECISIONS.md)).

## Content root

`content_root = SHA-256( SHA-256(chunk_0) || SHA-256(chunk_1) || ... )`.

Order-sensitive (a test proves swapping chunks changes it) and commits the
author to the exact ciphertext. With the per-chunk AAD binding `(total, index)`,
truncation, duplication, and reordering are detectable.

## Proof-of-work

```
digest = SHA-256("keepstone/v1/pow" || signer(32) || content_root(32)
                 || drop_nonce(16) || pow_nonce_be64)
```

`digest` needs `POW_DIFFICULTY_BITS = 12` leading zero bits. A spam/rate limit
that costs the author CPU and the verifier one hash.

## Putting it together

```
┌────────────────── envelope (id = H(these bytes)) ──────────────────────────┐
│ suite │ sig_kind │ signer │ ml_dsa_key │      payload      │   signature    │
└───────────────────────────────────────────┬───────────────────────────────┘
        ┌───────────────────────────────────┴───────────────────────┐
        │ DropBody: version suite cell ring created_at expiry mode   │
        │ chunk_size chunk_count content_root prefix drop_nonce      │
        │ pow_nonce  wrapped_keys:[ tag │ sealed, ... , decoys ]     │
        └───────────────────────────┬───────────────────────────────┘
                     content key (sealed in each slot)
        ┌───────────────────────────┴───────────────────────────────┐
        │ chunk_0 … chunk_{n-1}  (AEAD, keyed by HKDF(content_key,i))│
        └────────────────────────────────────────────────────────────┘
```

## Go look at this

- [`crates/core/src/types.rs`](../../crates/core/src/types.rs) — `DropBody`, `SignedDrop`, `WrappedKey`, `content_root`
- [`crates/core/src/pow.rs`](../../crates/core/src/pow.rs) — mine + verify
- [`docs/SPEC.md`](../SPEC.md) §3–§8 — authoritative field list
- Tests: `content_root_is_order_sensitive`, `pow_binds_to_signer`, `tampered_payload_fails_verification`

Next: [Geospatial addressing](17-geospatial-addressing.md)
