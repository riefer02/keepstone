# 13. The cryptographic core

`keepstone-crypto` is a **pure leaf**: no I/O, no clock, no async,
`#![forbid(unsafe_code)]`. It composes vetted primitives under one versioned
suite and enforces the key-handling rules.

## Rules the crate enforces

1. **Secrets zeroize on drop** and never print in `Debug`
   ([`secret.rs`](../../crates/crypto/src/secret.rs)).
2. **Every key purpose has its own HKDF label** (labels live in
   [`kdf.rs`](../../crates/crypto/src/kdf.rs)).
3. **Random nonces are safe** — 192-bit-nonce AEAD, not 96-bit.
4. **Nothing re-encodes what it receives** (byte preservation lives above, in
   `core` — [Chapter 15](15-canonical-cbor-and-identity.md)).

## Primitives

| Purpose | Algorithm | Crate |
|---|---|---|
| Authenticated encryption | XChaCha20-Poly1305 (24-byte nonce, 32-byte key) | `chacha20poly1305` |
| Key derivation | HKDF-SHA256 | `hkdf`, `sha2` |
| Signing | Ed25519 | `ed25519-dalek` |
| Key agreement | X25519 (ephemeral-static) | `x25519-dalek` |
| Post-quantum KEM | ML-KEM-768 | hybrid module |
| Post-quantum signatures | ML-DSA-65 | hybrid_sig module |
| Secret sharing | Shamir over GF(256), AES poly `0x11B` | hand-rolled |

## AEAD (`aead.rs`)

A wrapper over XChaCha20-Poly1305. The key choice is the **192-bit nonce**, which
makes random nonces safe and removes the 96-bit reuse footgun.

## Key derivation (`kdf.rs`)

HKDF-SHA256 with domain separation — one salt, one `info` per purpose:

```
DEFAULT_SALT   = "keepstone/v1"
INFO_DROP_KEY  = "keepstone/v1/drop-key"
INFO_CHUNK_KEY = "keepstone/v1/chunk-key"
INFO_SEAL_KEY  = "keepstone/v1/seal-key"
INFO_TAG       = "keepstone/v1/tag"
```

Helpers: `derive_key32`, `derive_chunk_key(content_key, index)`,
`derive_tag(recipient_x25519_public, drop_nonce) -> [u8; 8]`.

## Sealed boxes (`sealed.rs`) — the lock

Wraps the per-drop content key for one recipient via **ephemeral-static ECDH**:

```
   sender                                    recipient
   ephemeral sk_E ──┐
                    ├─ ECDH ──▶ shared ──▶ HKDF("seal-key") ──▶ wrapping key
   recipient pk  ──┘                                             │
                                                                 ▼
   ciphertext = AEAD(wrapping_key, nonce, aad="keepstone/v1/sealed", content_key)
   sealed = { ephemeral_public(32), nonce(24), ciphertext(48) }  = 104 bytes
```

Only the recipient's secret reproduces `shared`; the ephemeral key gives the
wrap forward secrecy; a wrong key fails **authentication** (how decoys are
rejected).

## Chunked stream encryption (`stream.rs`)

For chunk `i` of `total`:

```
chunk_key_i = HKDF(content_key, salt "keepstone/v1",
                   info "keepstone/v1/chunk-key" || i_be32)
nonce_i     = prefix(20 bytes) || i_be32
aad_i       = "keepstone/v1/chunk" || total_be32 || i_be32
chunk_i     = AEAD(chunk_key_i, nonce_i, aad_i, plaintext_chunk_i)
```

Three properties: fresh key per chunk, unique nonce per chunk, and order/length
bound in the AAD — so dropping, duplicating, reordering, or truncating chunks
fails authentication. `DEFAULT_CHUNK_SIZE` = 64 KiB, `PREFIX_LEN` = 20. Empty
plaintext yields one empty (still authenticated) chunk.

## Identity keys (`keys.rs`)

`Identity` holds the Ed25519 signing secret and X25519 agreement secret; it
produces public keys, signs, and exposes secret bytes for sealing to storage. A
free `verify(public, message, signature)` handles the public side.

## Shamir (`shamir.rs`)

`split(secret, t, n)` / `combine(shares)` over GF(256) — the basis of
place-locked release ([Chapter 21](21-place-locked-release.md)).

## Cost

A classical sealed key is 104 wire bytes (32-byte plaintext). Chunked AEAD runs
~650 MiB/s on Apple Silicon; Shamir combine is sub-microsecond
([`docs/BENCHMARKS.md`](../BENCHMARKS.md)).

## Go look at this

- [`crates/crypto/src/lib.rs`](../../crates/crypto/src/lib.rs) — crate docs + re-exports
- [`crates/crypto/src/sealed.rs`](../../crates/crypto/src/sealed.rs) — the lock
- [`crates/crypto/src/stream.rs`](../../crates/crypto/src/stream.rs) — chunked AEAD
- [`crates/crypto/src/kdf.rs`](../../crates/crypto/src/kdf.rs) — label registry
- [`crates/crypto/src/secret.rs`](../../crates/crypto/src/secret.rs) — zeroizing buffers

Next: [Post-quantum, hybrid](14-post-quantum-hybrid.md)
