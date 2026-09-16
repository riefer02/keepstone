# 14. Post-quantum, hybrid

Dead drops are long-lived, so **"harvest now, decrypt later"** is real: an
adversary records ciphertext today, decrypts it once a quantum computer exists.
The answer is not to bet on one new algorithm but to run a classical and a
post-quantum primitive **together** — safe if *either* holds. Keepstone does
this for both encryption and signatures.

## Hybrid encryption: X25519 + ML-KEM-768

`crates/crypto/src/hybrid.rs`. The recipient publishes
`X25519 || ML-KEM-768 encapsulation key`. To seal the content key:

```
1. shared1       = ECDH(ephemeral_x25519, recipient_x25519)     (classical)
2. (ct, shared2) = ML-KEM-768.Encapsulate(recipient_kem_pk)      (post-quantum)
3. key   = HKDF(shared1 || shared2, salt "keepstone/v1", info "seal-key")
4. ctext = AEAD(key, nonce, aad="keepstone/v1/hybrid-seal", content_key)
```

Both secrets are mixed into the KDF: breaking the wrap requires breaking **both**
primitives.

- `HybridKeypair` = 96 secret bytes (32 X25519 + 64 ML-KEM), in `hybrid.txt`.
- Public encaps key = 1184 bytes — why hybrid contacts and drops are larger.

## Hybrid signatures: Ed25519 + ML-DSA-65

`crates/crypto/src/hybrid_sig.rs`. Valid only if **both** halves verify:

```
signing_input = "keepstone/v1/drop" || len_be32(payload) || payload
signature      = Ed25519(signing_input) || ML-DSA-65(signing_input)
```

| Item | Bytes |
|---|---|
| ML-DSA-65 verifying key | 1952 |
| ML-DSA-65 signature | 3309 |
| Ed25519 signature | 64 |
| Hybrid signature total | 64 + 3309 |

Hybrid drops are **self-verifying**: the ML-DSA-65 verifying key travels in the
envelope, so no key directory is needed. `MlDsaKeypair` is generated from a
32-byte seed (`mldsa.txt`).

## How the envelope carries it

```
sig_kind = 1 (Ed25519):  ml_dsa_key = empty,             signature = 64 bytes
sig_kind = 2 (hybrid):   ml_dsa_key = 1952-byte vk,      signature = 64 || 3309
```

Verification dispatches on `sig_kind`; hybrid requires both halves
([ADR-0011](../DECISIONS.md)).

## Suites

| id | name | KEM | signatures | AEAD | KDF |
|---|---|---|---|---|---|
| 1 | `Classical25519` | X25519 | Ed25519 | XChaCha20-Poly1305 | HKDF-SHA256 |
| 2 | `Hybrid25519MlKem768` | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 | XChaCha20-Poly1305 | HKDF-SHA256 |

Unknown suite ids **fail closed**
([`suite.rs`](../../crates/crypto/src/suite.rs)).

## Why not PQ everything

Hybrid is strictly safer than either alone, and the classical half is nearly
free. The only real cost is **size** (ML-DSA-65 adds ~5 KB per envelope), so
`classical` stays the default and `hybrid` is opt-in per drop.

## Go look at this

- [`crates/crypto/src/hybrid.rs`](../../crates/crypto/src/hybrid.rs) — KEM half
- [`crates/crypto/src/hybrid_sig.rs`](../../crates/crypto/src/hybrid_sig.rs) — signature half
- [`crates/crypto/src/suite.rs`](../../crates/crypto/src/suite.rs) — versioned suites
- Tests: `hybrid_signed_drop_verifies`, crypto hybrid tests

Next: [Canonical CBOR and byte-preservation identity](15-canonical-cbor-and-identity.md)
