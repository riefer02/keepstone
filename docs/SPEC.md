# Keepstone Wire Specification (v1)

Status: **draft**. An independent implementation should be possible from this
document. Numeric constants are authoritative in code; see
`crates/core` and `crates/crypto`.

## 1. Conventions

- **Canonical CBOR** (RFC 8949 §4.2.1 subset): shortest-form integer heads,
  definite lengths only, no trailing bytes. Decoders MUST reject non-canonical
  input.
- All multi-byte integers are **big-endian**.
- `SHA-256` is written `H`.
- A **drop's identity** is `H(exact transmitted envelope bytes)`. Signatures and
  identifiers are computed over received bytes, never a re-encoding.
- Strings are UTF-8. Byte strings are raw.

## 2. Crypto suites

| id | name | KEM | signatures | AEAD | KDF |
|---|---|---|---|---|---|
| 1 | `Classical25519` | X25519 (ephemeral-static) | Ed25519 | XChaCha20-Poly1305 | HKDF-SHA256 |
| 2 | `Hybrid25519MlKem768` | X25519 + ML-KEM-768 | Ed25519 (ML-DSA-65 available) | XChaCha20-Poly1305 | HKDF-SHA256 |

Unknown suite ids MUST fail closed.

## 3. Drop envelope

```
Envelope = [ suite:uint, sig_kind:uint, signer:bytes(32),
             ml_dsa_key:bytes, payload:bytes, signature:bytes ]

sig_kind = 1 (Ed25519):
  ml_dsa_key = empty, signature = 64 bytes
sig_kind = 2 (hybrid Ed25519 + ML-DSA-65):
  ml_dsa_key = 1952-byte ML-DSA-65 verifying key,
  signature  = 64-byte Ed25519 || 3309-byte ML-DSA-65 signature
```

- `payload` is the canonical encoding of `DropBody`.
- `signing_input = "keepstone/v1/drop" || len_be32(payload) || payload`.
- Ed25519 signs `signing_input`; ML-DSA-65 signs the same `signing_input`.
- A hybrid envelope verifies only if **both** signatures verify.
- `signer` is always the Ed25519 public key and is what the proof-of-work binds to.
- `id = SHA-256(envelope_bytes)`.

## 4. Drop body

```
DropBody = [
  version:uint(=1), suite:uint,
  cell:text, ring:uint,
  created_at:uint, expiry:uint(0=never),
  mode:uint(0=capability, 1=place-locked),
  chunk_size:uint, chunk_count:uint,
  content_root:bytes(32),
  prefix:bytes(20),
  drop_nonce:bytes(16),
  pow_nonce:uint,
  wrapped_keys:[WrappedKey, ...]
]
```

`content_root = SHA-256( concat_i SHA-256(chunk_ciphertext_i) )`.

### 4.1 Wrapped keys

```
WrappedKey = [ tag:bytes(8), kind:uint, inner ]

kind = 1 (Classical):
  inner = [ ephemeral_public:bytes(32), nonce:bytes(24), ciphertext:bytes(48) ]
kind = 2 (Hybrid):
  inner = [ ephemeral_x25519:bytes(32),
            kem_ciphertext:bytes(1088),
            nonce:bytes(24),
            ciphertext:bytes(48) ]
```

A drop MUST contain at least `MIN_TAGS = 16` wrapped key slots. Slots beyond the
true recipients are random **decoys**, making the recipient count and identity
ambiguous.

## 5. Recipient tags

```
tag = HKDF-SHA256(
        ikm  = recipient_x25519_public (32 bytes),
        salt = "keepstone/v1",
        info = "keepstone/v1/tag" || drop_nonce
      )[0..8]
```

The recipient recomputes `tag` for each candidate slot; decoys produce false
positives that fail AEAD authentication.

## 6. Content sealing

### 6.1 Classical (suite 1)

1. generate ephemeral X25519 keypair; `shared = ECDH(ephemeral_sk, recipient_pk)`
2. `key = HKDF(shared, salt "keepstone/v1", info "keepstone/v1/seal-key")`
3. `nonce` = 24 random bytes
4. `ciphertext = AEAD(key, nonce, aad = "keepstone/v1/sealed", content_key)`

### 6.2 Hybrid (suite 2)

1. `shared1 = ECDH(ephemeral_x25519, recipient_x25519)`
2. `(kem_ct, shared2) = ML-KEM-768.Encapsulate(recipient_kem_pk)`
3. `key = HKDF(shared1 || shared2, salt "keepstone/v1", info "keepstone/v1/seal-key")`
4. `ciphertext = AEAD(key, nonce, aad = "keepstone/v1/hybrid-seal", content_key)`

The wrap is secure if **either** primitive holds.

## 7. Chunked content encryption

Chunks are produced by a STREAM-style construction:

```
chunk_key_i = HKDF(content_key, salt "keepstone/v1",
                   info "keepstone/v1/chunk-key" || i_be32)
nonce_i     = prefix(20) || i_be32
aad_i       = "keepstone/v1/chunk" || total_be32 || i_be32
chunk_i     = AEAD(chunk_key_i, nonce_i, aad_i, plaintext_chunk_i)
```

The AAD binds the chunk index and total count, preventing truncation and
reordering. An empty plaintext yields one empty chunk.

## 8. Proof-of-work

```
digest = SHA-256("keepstone/v1/pow" || signer(32) || content_root(32)
                 || drop_nonce(16) || pow_nonce_be64)
```

`digest` MUST have at least `POW_DIFFICULTY_BITS = 12` leading zero bits.

## 9. Transparency log (RFC 6962)

- `leaf_hash(d) = SHA-256(0x00 || d)`
- `node_hash(l, r) = SHA-256(0x01 || l || r)`
- `MTH` per RFC 6962 §2.1; inclusion and consistency proofs per §2.1.1–2.1.2.
- Leaves are drop envelope bytes.

### 9.1 Signed tree head

```
sth_input = "keepstone/v1/sth" || tree_size_be64 || root(32) || timestamp_be64
```

`SignedTreeHead = { tree_size, root, timestamp, log_public(32), signature(64) }`.
Equivocation = two valid STHs with equal `tree_size` and different `root`.

### 9.2 Anchoring

```
link = SHA-256("keepstone/v1/anchor" || previous(32) || tree_size_be64
               || root(32) || timestamp_be64)
```

`previous` is all-zero for the first link. The `Anchor` trait allows swapping in
OpenTimestamps as an external backend.

## 10. Peer protocol

Messages are canonical CBOR arrays:

```
Message = [ tag:uint, payload:bytes ]
```

| tag | message | payload |
|---|---|---|
| 0 | Hello | `[protocol_version:u8]` |
| 1 | Want(drop_id) | `drop_id` (32 bytes) |
| 2 | Drop | raw envelope bytes |
| 3 | Missing(drop_id) | `drop_id` (32 bytes) |
| 4 | Bye | empty |
| 5 | WantChunk(drop_id, index) | `drop_id(32) || index_be32` |
| 6 | Chunk(drop_id, index, data) | `drop_id(32) || index_be32 || data` |
| 7 | Presence | canonical `PresenceRequest` |
| 8 | Attestation | canonical `PresenceAttestation` |
| 9 | Put | raw signed envelope (offer for storage) |
| 10 | Stored(drop_id) | `drop_id` (32 bytes) |
| 11 | PutChunk(drop_id, index, data) | `drop_id(32) || index_be32 || data` |

**Framing (reference TCP):** `u32_be length || message`; max frame `8 MiB`.
**libp2p:** the same encoded `Message` is the request/response body, protocol
`/keepstone/drop/1`. Only ciphertext crosses the wire.

## 11. Discovery

- **Dense cells:** gossipsub topic `keepstone/drops/v1/cell/{h3_index}`; payload
  is a raw envelope. Subscribers MUST verify the signature before storing.
- **Sparse cells:** Kademlia provider records keyed by the cell string; query
  returns peers, which are then asked directly via `Want`.

## 12. Presence (place-locked, best-effort)

```
PresenceRequest     = [ cell:text, nonce:bytes(16), claimant:bytes(32), expiry:uint ]
attestation_input   = "keepstone/v1/presence" || len_be32(cell) || cell
                      || nonce || claimant || rtt_bucket:u8 || timestamp_be64
PresenceAttestation = [ cell:text, nonce:bytes(16), claimant:bytes(32),
                        rtt_bucket:uint, timestamp:uint, witness:bytes(32),
                        signature:bytes(64) ]
```

A `PresenceCert` is a request plus attestations; it verifies if every
attestation matches the request, has a valid witness signature, witnesses are
distinct, and the count meets the threshold.

## 13. Place-locked release

The content key is Shamir-split `t`-of-`n` over GF(256) (AES polynomial
`0x11B`). Each share's value is sealed to a custodian with §6. Custodians release
shares only for a valid `PresenceCert`. Any `t` shares reconstruct the key.

> **Limitation:** location is best-effort defense in depth, not proof. GPS can be
> spoofed and witnesses can be Sybil; this is documented, not hidden.
