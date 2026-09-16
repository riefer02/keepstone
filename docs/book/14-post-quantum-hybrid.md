# 14. Post-quantum, hybrid

Dead drops are long-lived by nature. A message left today might be read in ten
years, which makes **"harvest now, decrypt later"** a real threat: an adversary
records ciphertext today and decrypts it once a quantum computer exists. The
answer is not to bet everything on a new algorithm, but to run a classical and a
post-quantum primitive **together** so the result is safe if *either* holds.

This is the **hybrid** approach, and Keepstone applies it to both halves of the
problem: encryption and signatures.

## Hybrid encryption: X25519 + ML-KEM-768

`crates/crypto/src/hybrid.rs`. The recipient publishes a hybrid public key
`X25519 || ML-KEM-768 encapsulation key`. To seal the content key:

```
1. shared1     = ECDH(ephemeral_x25519, recipient_x25519)          (classical)
2. (ct, shared2) = ML-KEM-768.Encapsulate(recipient_kem_pk)         (post-quantum)
3. key   = HKDF(shared1 || shared2, salt "keepstone/v1", info "seal-key")
4. ctext = AEAD(key, nonce, aad="keepstone/v1/hybrid-seal", content_key)
```

Both secrets are **mixed** into the KDF, so an attacker must break **both**
X25519 and ML-KEM-768 to recover the key. If ML-KEM is later broken by a new
attack, X25519 still stands; if quantum computers break X25519, ML-KEM still
stands.

`HybridKeypair` is 96 secret bytes (32 X25519 + 64 ML-KEM), persisted to
`hybrid.txt`. The public encaps key is 1184 bytes, which is why hybrid contacts
and drops are noticeably larger.

## Hybrid signatures: Ed25519 + ML-DSA-65

`crates/crypto/src/hybrid_sig.rs`. A hybrid signature is valid only if **both**
halves verify:

```
signing_input = "keepstone/v1/drop" || len_be32(payload) || payload
signature      = Ed25519(signing_input) || ML-DSA-65(signing_input)
```

Sizes (these drive the envelope layout):

| Item | Bytes |
|---|---|
| ML-DSA-65 verifying key | 1952 |
| ML-DSA-65 signature | 3309 |
| Ed25519 signature | 64 |
| Hybrid signature total | 64 + 3309 |

Hybrid drops are therefore **self-verifying**: the ML-DSA-65 verifying key
travels inside the envelope, so anyone can check the post-quantum half without a
key directory.

`MlDsaKeypair` is generated from a 32-byte seed, persisted to `mldsa.txt` (so a
32-byte secret file reconstructs the full keypair).

## How the envelope carries it

The envelope ([Chapter 16](16-anatomy-of-a-drop.md)) has a `sig_kind` field:

```
sig_kind = 1  (Ed25519):
    ml_dsa_key = empty
    signature  = 64 bytes

sig_kind = 2  (hybrid):
    ml_dsa_key = 1952-byte ML-DSA-65 verifying key
    signature  = 64 bytes Ed25519 || 3309 bytes ML-DSA-65
```

Verification dispatches on `sig_kind`; for hybrid, it requires **both** halves
to verify ([ADR-0011](../DECISIONS.md)).

## The suite table

| id | name | KEM | signatures | AEAD | KDF |
|---|---|---|---|---|---|
| 1 | `Classical25519` | X25519 | Ed25519 | XChaCha20-Poly1305 | HKDF-SHA256 |
| 2 | `Hybrid25519MlKem768` | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 | XChaCha20-Poly1305 | HKDF-SHA256 |

Unknown suite ids **fail closed** ([`suite.rs`](../../crates/crypto/src/suite.rs)).

## Why not post-quantum everything?

Because hybrid is strictly safer than either alone, and the classical half costs
almost nothing to keep. The only real cost is **size** (ML-DSA-65 alone makes a
hybrid envelope ~5 KB larger), which is why `classical` remains the default and
`hybrid` is opt-in per drop.

## Go look at this

- [`crates/crypto/src/hybrid.rs`](../../crates/crypto/src/hybrid.rs) — KEM half
- [`crates/crypto/src/hybrid_sig.rs`](../../crates/crypto/src/hybrid_sig.rs) — signature half
- [`crates/crypto/src/suite.rs`](../../crates/crypto/src/suite.rs) — the versioned suites
- Tests: `crates/core/src/types.rs` (`hybrid_signed_drop_verifies`), crypto hybrid tests

Next: [Canonical CBOR and byte-preservation identity](15-canonical-cbor-and-identity.md)
