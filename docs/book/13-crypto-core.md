# 13. The cryptographic core

`keepstone-crypto` is a **pure leaf**: no I/O, no clock, no async, and
`#![forbid(unsafe_code)]`. It composes vetted primitives under one versioned
suite and enforces the project's key-handling rules.

## The rules the crate enforces

1. **Every secret is zeroized on drop** and never appears in `Debug` output
   (`crates/crypto/src/secret.rs`).
2. **Every key purpose has its own HKDF label.** Reusing a key across purposes
   is a category error the code makes hard to commit (the labels live in
   `kdf.rs`).
3. **Random nonces are safe** because we use the 192-bit-nonce AEAD
   (XChaCha20-Poly1305), not the 96-bit variant.
4. **Nothing re-encodes what it receives.** Crypto operates on exact bytes; the
   byte-preservation rule lives above in `core` ([Chapter 15](15-canonical-cbor-and-identity.md)).

## The primitives

| Purpose | Algorithm | Crate |
|---|---|---|
| Authenticated encryption | XChaCha20-Poly1305 (24-byte nonce, 32-byte key) | `chacha20poly1305` |
| Key derivation | HKDF-SHA256 | `hkdf`, `sha2` |
| Signing | Ed25519 | `ed25519-dalek` |
| Key agreement | X25519 (ephemeral-static) | `x25519-dalek` |
| Post-quantum KEM | ML-KEM-768 | (hybrid module) |
| Post-quantum signatures | ML-DSA-65 | (hybrid_sig module) |
| Secret sharing | Shamir over GF(256), AES polynomial `0x11B` | hand-rolled |

## AEAD (`aead.rs`)

A thin wrapper over XChaCha20-Poly1305. The important choice is the **192-bit
nonce**: it makes *random* nonces safe, removing the classic 96-bit-nonce reuse
footgun for long-lived keys.

## Key derivation (`kdf.rs`)

Everything is HKDF-SHA256 with domain separation. One salt, distinct `info`
labels per purpose:

```
DEFAULT_SALT   = "keepstone/v1"
INFO_DROP_KEY  = "keepstone/v1/drop-key"
INFO_CHUNK_KEY = "keepstone/v1/chunk-key"
INFO_SEAL_KEY  = "keepstone/v1/seal-key"
INFO_TAG       = "keepstone/v1/tag"
```

The helpers you'll see referenced:

- `derive_key32(ikm, salt, info) -> [u8; 32]`
- `derive_chunk_key(content_key, index) -> [u8; 32]`
- `derive_tag(recipient_x25519_public, drop_nonce) -> [u8; 8]`

## Sealed boxes (`sealed.rs`) — the lock itself

A sealed box wraps the per-drop content key for one recipient using
**ephemeral-static ECDH**:

```
   sender                                    recipient
   ──────                                    ─────────
   ephemeral sk_E  ──┐
                     ├─ ECDH ──▶ shared ──▶ HKDF("seal-key") ──▶ wrapping key
   recipient pk   ──┘                                             │
                                                                 ▼
   ciphertext = AEAD(wrapping_key, nonce, aad="keepstone/v1/sealed", content_key)
   sealed = { ephemeral_public(32), nonce(24), ciphertext(48) }   ── ENCODED_LEN = 104
```

- Only the recipient's secret can reproduce `shared`, so only they can unwrap.
- The ephemeral key gives the wrap forward secrecy.
- A wrong key fails **authentication**, not just produces garbage — that's how
  decoys are rejected cleanly.

## Chunked stream encryption (`stream.rs`)

Large payloads are split into chunks, each independently authenticated. This is
a STREAM-style construction implemented by hand so the wire layout is under our
control.

For chunk `i` of `total`:

```
chunk_key_i = HKDF(content_key, salt "keepstone/v1",
                   info "keepstone/v1/chunk-key" || i_be32)
nonce_i     = prefix(20 random bytes) || i_be32
aad_i       = "keepstone/v1/chunk" || total_be32 || i_be32
chunk_i     = AEAD(chunk_key_i, nonce_i, aad_i, plaintext_chunk_i)
```

Three properties fall out of this:

- **Fresh key per chunk** (derived from the index) — no key/nonce reuse even
  across a long message.
- **Unique nonce per chunk** — the counter in the last 4 bytes.
- **Order and length are bound** in the AAD — an attacker who drops, duplicates,
  or reorders chunks makes authentication fail. Truncation is impossible without
  detection.

`DEFAULT_CHUNK_SIZE` is 64 KiB and `PREFIX_LEN` is 20. An empty plaintext yields
one empty chunk (so "no content" is still authenticated).

## Identity keys (`keys.rs`)

`Identity` holds the Ed25519 signing secret and the X25519 agreement secret. It
can produce the public keys, sign messages, and hand out secret bytes for
sealing to storage. A free `verify(public, message, signature)` handles the
public side.

## Shamir secret sharing (`shamir.rs`)

`split(secret, t, n)` and `combine(shares)` implement `t`-of-`n` sharing over
GF(256). This is what makes place-locked release possible
([Chapter 21](21-place-locked-release.md)): the content key is split across
custodians and only reconstructed from a threshold.

## Size and performance notes

- A sealed classical key is 104 bytes on the wire; the AEAD plaintext is only
  32 bytes, so the overhead is the ephemeral key + nonce + tag.
- Chunked AEAD runs at roughly 650 MiB/s on Apple Silicon (see
  [`docs/BENCHMARKS.md`](../BENCHMARKS.md)); Shamir combine is sub-microsecond.

## Go look at this

- [`crates/crypto/src/lib.rs`](../../crates/crypto/src/lib.rs) — crate docs and re-exports
- [`crates/crypto/src/sealed.rs`](../../crates/crypto/src/sealed.rs) — the lock
- [`crates/crypto/src/stream.rs`](../../crates/crypto/src/stream.rs) — chunked AEAD
- [`crates/crypto/src/kdf.rs`](../../crates/crypto/src/kdf.rs) — the label registry
- [`crates/crypto/src/secret.rs`](../../crates/crypto/src/secret.rs) — zeroizing buffers

Next: [Post-quantum, hybrid](14-post-quantum-hybrid.md)
