# 30. Glossary and appendices

## Glossary

| Term | Meaning |
|---|---|
| **Drop** | One encrypted message/file addressed to a place; the unit of the system |
| **Drop id** | `SHA-256` of the exact transmitted envelope bytes |
| **Envelope** | The signed container: `[suite, sig_kind, signer, ml_dsa_key, payload, signature]` |
| **Body** | The canonical CBOR `DropBody` inside the payload (14 fields) |
| **Content key** | Random per-drop key that encrypts the content; the actual lock |
| **Sealed box** | The content key encrypted to one recipient via ephemeral-static X25519 |
| **Wrapped key** | A `tag` + a sealed content key (real or decoy) |
| **Tag** | 8 bytes from `HKDF(recipient_public, drop_nonce)` locating a recipient's slot |
| **Decoy** | A random wrapped-key slot padding every drop to ≥16 slots |
| **Cell** | An H3 hexagonal address (hex), e.g. `8928308280fffff` |
| **Ring** | The k-ring around a cell (`grid_disk`): the centre plus k layers of neighbours |
| **H3** | The hierarchical hexagonal geospatial index used for addressing |
| **Suite** | A versioned set of algorithms (1 classical, 2 hybrid) |
| **Hybrid** | Classical + post-quantum run together, sound if either holds |
| **PoW** | Hashcash-style proof-of-work bound to signer + content (12 leading zero bits) |
| **Log** | This node's append-only RFC 6962 Merkle log of envelope bytes |
| **Leaf / node hash** | `H(0x00 || d)` / `H(0x01 || l || r)` (RFC 6962 domain separation) |
| **MTH** | Merkle Tree Hash — the root over the log's leaves |
| **Inclusion proof** | Evidence a leaf is in the tree (≈`log₂ n` hashes) |
| **Consistency proof** | Evidence a smaller tree is a prefix of a larger one |
| **STH** | Signed Tree Head: a log's signed `{size, root, time}`, 144 bytes encoded |
| **Equivocation** | Two valid STHs with the same size but different roots — proof of misbehaviour |
| **Anchor** | A commitment to an STH outside the log (hash chain or OpenTimestamps) |
| **OTS** | OpenTimestamps — Bitcoin-backed timestamps |
| **Presence cert** | A request plus witness attestations proving (best-effort) presence |
| **Custodian** | A holder of one Shamir share for a place-locked drop |
| **Shamir** | `t`-of-`n` secret sharing over GF(256) |
| **Gossipsub** | libp2p pub/sub; used for cell topics (dense cells) |
| **Kademlia** | libp2p DHT; used for provider records (sparse cells) |
| **k-anonymity** | Hiding your target among k plausible ones (here: a cell's ring) |
| **PIR** | Private Information Retrieval — the stronger goal we do **not** claim |
| **Store** | `keepstone-store`, the shared data-directory library |

## Appendix A — CLI reference

The binary is `keepstone`. Global option: `--data-dir <path>` (default
`./.keepstone-data`).

```bash
# identity & contacts
keepstone keygen
keepstone id
keepstone contact-add <name> <signing> <ecdh> [hybrid]
keepstone contact-list

# drops
keepstone drop-create --to <name>... --lat <f> --lng <f> \
    [--res 9] [--ring 2] [--message "..." | --file <path>] \
    [--ttl 0] [--suite classical|hybrid]
keepstone drop-open <id> [--out <path>]
keepstone drop-list [--lat <f> --lng <f> --ring 2]

# verification & anchoring
keepstone log-verify <id>
keepstone verify <file.signed>
keepstone log-anchor <id>
keepstone log-anchors
keepstone log-anchor-ots <id>
keepstone log-ots-verify <file.ots>

# reference TCP transport
keepstone serve --listen 127.0.0.1:7777
keepstone fetch <peer> <id>
keepstone push <peer> <id>
keepstone sth-serve --listen 127.0.0.1:7791
keepstone sth-fetch <peer>

# libp2p transport
keepstone p2p-serve --listen /ip4/127.0.0.1/tcp/7778
keepstone p2p-fetch <multiaddr> <id>
keepstone find-providers <multiaddr> <cell> [--ring 2]

# events
keepstone hunt create|add-participant|add-drop|seed|show|map ...
```

## Appendix B — Peer protocol messages

```
Message = [ tag:uint, payload:bytes ]        (canonical CBOR)
Framing (TCP): u32_be length || message,        max frame 8 MiB
libp2p:        same bytes, protocol "/keepstone/drop/1"
```

| tag | message | tag | message |
|---|---|---|---|
| 0 | Hello | 7 | Presence |
| 1 | Want | 8 | Attestation |
| 2 | Drop | 9 | Put |
| 3 | Missing | 10 | Stored |
| 4 | Bye | 11 | PutChunk |
| 5 | WantChunk | 12 | GetSth |
| 6 | Chunk | 13 | Sth |

## Appendix C — Data directory

```
<data-dir>/
├── identity.txt      # Ed25519 signing + X25519 secrets (hex)
├── hybrid.txt        # X25519 || ML-KEM-768 secret (hex)
├── mldsa.txt         # ML-DSA-65 seed (hex)
├── contacts.txt      # name signing ecdh [hybrid]
├── drops/<id>.signed # exact envelope bytes
├── chunks/<id>/<n>.bin
├── anchors/<root>.digest [.ots]
└── log/
    ├── entries.bin   # [len:u32_be][envelope bytes]...
    ├── key.txt       # local log identity
    └── anchors.txt   # anchor receipts
```

## Appendix D — Constants worth knowing

| Constant | Value | Where |
|---|---|---|
| Protocol version | 1 | `core::types::PROTOCOL_VERSION` |
| `MIN_TAGS` | 16 | `core::types` |
| Tag length | 8 bytes | `crypto::kdf::derive_tag` |
| Chunk size | 64 KiB | `crypto::stream::DEFAULT_CHUNK_SIZE` |
| Nonce prefix | 20 bytes | `crypto::stream::PREFIX_LEN` |
| AEAD nonce | 24 bytes | `crypto::aead::NONCE_LEN` |
| PoW difficulty | 12 leading zero bits | `core::pow::POW_DIFFICULTY_BITS` |
| STH encoded length | 144 bytes | `log::sth::STH_ENCODED_LEN` |
| Presence threshold | 3 | `core::presence::DEFAULT_THRESHOLD` |
| ML-KEM-768 ciphertext | 1088 bytes | hybrid seal |
| ML-DSA-65 vk / sig | 1952 / 3309 bytes | `crypto::hybrid_sig` |
| Max protocol frame | 8 MiB | `node::protocol::MAX_FRAME` |

## Where to go next

- **The wire format:** [`docs/SPEC.md`](../SPEC.md)
- **The decisions:** [`docs/DECISIONS.md`](../DECISIONS.md)
- **The guarantees:** [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md)
- **The evidence:** [`docs/CLAIMS.md`](../CLAIMS.md)
- **Running it:** [`docs/OPERATIONS.md`](../OPERATIONS.md)
- **The event pilot:** [`docs/PILOT.md`](../PILOT.md)
- **Performance:** [`docs/BENCHMARKS.md`](../BENCHMARKS.md)
- **Abuse posture:** [`docs/ABUSE.md`](../ABUSE.md)

Back to [the contents](README.md).
