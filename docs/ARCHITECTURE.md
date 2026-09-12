# Architecture

## Layering

```
cli  ──▶ node ──▶ core
        relay ──▶ core
                   core ──▶ crypto
                   log   (pure; sha2 only)
                   node  ──▶ core, log, crypto
```

`crypto`, `core`, and `log` are pure: no I/O, no async, no clock reads, and
`#![forbid(unsafe_code)]`. `node` and `relay` may do I/O. `cli` is a thin
binary over the libraries.

## Data flow (create)

1. Generate a random 256-bit **content key** (the actual lock).
2. Chunk the plaintext; encrypt each chunk with a key derived from the content
   key and the chunk index, using a `prefix || counter` nonce and AAD binding
   `(drop id, index, total)`.
3. Seal the content key to each recipient device's X25519 key
   (ephemeral-static ECDH → HKDF → XChaCha20-Poly1305).
4. Build a canonical CBOR `DropBody`, sign it (Ed25519), and wrap it in a
   `SignedDrop` envelope.
5. Append the exact envelope bytes to the local RFC 6962 log.

## Data flow (open)

1. Decode the envelope; verify the author signature over the **preserved**
   payload bytes.
2. Find the wrapped key addressed to this device; unseal the content key.
3. Fetch and decrypt chunks; verify chunk authentication.
4. Reassemble the plaintext.

## Identity and byte preservation

- Identity = Ed25519 signing key + X25519 key-agreement key.
- A drop's identifier is `SHA-256` of the **exact transmitted bytes**. Decoding
  never changes an identifier or invalidates a signature.

## Milestones

- **M0/M1 (done):** pure crypto/core/log, local capability drops, CLI.
- **M2:** libp2p transport (QUIC + TCP), gossipsub for dense cells, Kademlia
  request/response for sparse cells, log nodes + STH gossip.
- **M3:** witness presence certificates and place-locked drops.
- **M4:** OpenTimestamps anchoring, map UI, benchmarks, fuzzing, docs.
- **M5:** federated relays, multi-device, post-quantum hybrid suite.
