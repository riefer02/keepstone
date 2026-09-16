# 16. Anatomy of a drop

A drop is two layers: an **envelope** (signature + author) wrapping a **body**
(what the drop is). We'll peel them apart.

## Layer 1 — the envelope

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
| `payload` | the canonical-encoded `DropBody` — stored verbatim |
| `signature` | 64 bytes, or `64 || 3309` for hybrid |

The drop's **id** is `SHA-256` of the whole envelope's exact bytes. The envelope
is also what gets copied into the transparency log, byte for byte.

## Layer 2 — the body (14 fields)

`DropBody` is a canonical CBOR array of 14 entries:

| # | Field | What it's for |
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
| 11 | `prefix` | 20-byte nonce prefix for chunk encryption |
| 12 | `drop_nonce` | 16 bytes; binds recipient tags to this drop |
| 13 | `pow_nonce` | proof-of-work nonce |
| 14 | `wrapped_keys` | tagged, sealed content keys (real + decoys) |

Notice what is **not** here: no recipient public keys, no author name, no
plaintext, no content key. All of that is either sealed or absent.

## The wrapped keys — recipients without naming them

```
WrappedKey = [ tag:bytes(8), kind:uint, inner ]

kind = 1 (classical):
    inner = [ ephemeral_public(32), nonce(24), ciphertext(48) ]
kind = 2 (hybrid):
    inner = [ ephemeral_x25519(32), kem_ciphertext(1088), nonce(24), ciphertext(48) ]
```

The `tag` is how a recipient finds *their* slot without their public key being
named:

```
tag = HKDF(ikm = recipient_x25519_public,
           salt = "keepstone/v1",
           info = "keepstone/v1/tag" || drop_nonce)[0..8]
```

The recipient recomputes this for their own key and tries every matching slot.
Because it depends on the drop's random `drop_nonce`, tags are **unlinkable
across drops** — the same recipient has a different tag in every drop.

### Decoys

Every drop has at least `MIN_TAGS = 16` slots, padded with **random decoys**
(random tag, random ephemeral key, random nonce, random ciphertext). So:

- the **number** of recipients is hidden (always ≥16 slots), and
- the **identity** of recipients is hidden (no keys in the clear).

An observer who guesses a tag and tries to open a decoy simply gets an AEAD
authentication failure. False positives cost one failed decryption. This is
[ADR-0008](../DECISIONS.md).

## The content root and chunk binding

`content_root = SHA-256( SHA-256(chunk_0) || SHA-256(chunk_1) || ... )`.

It is **order-sensitive** (a test proves swapping chunks changes it) and it
commits the author to the exact ciphertext. Combined with the per-chunk AAD
binding `(total, index)`, this makes truncation, duplication, and reordering
detectable.

## Proof-of-work

Creating a drop costs a little work, bound to the author and the content so it
can't be copied across drops:

```
digest = SHA-256("keepstone/v1/pow" || signer(32) || content_root(32)
                 || drop_nonce(16) || pow_nonce_be64)
```

`digest` must have at least `POW_DIFFICULTY_BITS = 12` leading zero bits. This
is not a security boundary — it's a spam/rate limit that costs the author CPU
and not the verifier (verification is a single hash).

## Putting it together

```
┌──────────────────────── envelope (id = H(these bytes)) ────────────────────────┐
│ suite │ sig_kind │ signer │ ml_dsa_key │        payload        │   signature     │
└──────────────────────────────────────────────┬─────────────────────────────────┘
                                               │
        ┌──────────────────────────────────────┴───────────────────────────┐
        │ DropBody                                                          │
        │  version suite cell ring created_at expiry mode                   │
        │  chunk_size chunk_count content_root prefix drop_nonce pow_nonce  │
        │  wrapped_keys: [ tag │ sealed-to-recipient, ... , decoys ]        │
        └───────────────────────────────────────────────────────────────────┘
                                               │
                                    content key (sealed inside each slot)
                                               │
        ┌──────────────────────────────────────┴───────────────────────────┐
        │ chunk_0 … chunk_{n-1}   (AEAD, keyed by HKDF(content_key, index)) │
        └───────────────────────────────────────────────────────────────────┘
```

## Go look at this

- [`crates/core/src/types.rs`](../../crates/core/src/types.rs) — `DropBody`, `SignedDrop`, `WrappedKey`, `content_root`
- [`crates/core/src/pow.rs`](../../crates/core/src/pow.rs) — mining and verification
- [`docs/SPEC.md`](../SPEC.md) §3–§8 — the authoritative field list
- Tests: `content_root_is_order_sensitive`, `pow_binds_to_signer`, `tampered_payload_fails_verification`

Next: [Geospatial addressing](17-geospatial-addressing.md)
