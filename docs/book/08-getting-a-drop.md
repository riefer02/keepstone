# 8. Getting a drop

You have ciphertext somewhere and you know the drop's id. Or you don't have the
ciphertext yet and you know a peer that does. Either way, this chapter is about
moving bytes and then opening the lock.

## Local drops

```bash
keepstone --data-dir ./alice drop-list
keepstone --data-dir ./alice drop-list --lat 51.5007 --lng -0.1246 --ring 2
```

`drop-list` prints the drops in this data directory, optionally filtered to
those near a point. The filter computes the H3 cell of your coordinates at each
drop's own resolution and checks whether the drop's cell is inside the k-ring —
it never displays your exact coordinates to anyone else.

## Fetch from a peer (reference TCP transport)

The reference transport is a tiny length-prefixed protocol designed for fast,
dependency-light tests and for two-node demos.

```bash
# Alice serves the ciphertext she holds (no keys involved).
keepstone --data-dir ./alice serve --listen 127.0.0.1:7777

# Bob fetches the envelope and all its chunks.
keepstone --data-dir ./bob fetch 127.0.0.1:7777 <id>
```

`fetch` asks the peer for the envelope (`Want` → `Drop`), then for each chunk
(`WantChunk` → `Chunk`), and stores them under bob's data directory. Only
ciphertext crosses the wire.

## Fetch over libp2p (QUIC + TCP, Noise)

The production transport speaks the same messages over libp2p, so you get QUIC,
transport encryption, and the platform for gossipsub and Kademlia.

```bash
keepstone --data-dir ./alice p2p-serve --listen /ip4/127.0.0.1/tcp/7778
keepstone --data-dir ./bob   p2p-fetch /ip4/127.0.0.1/tcp/7778 <id>
```

See [Chapter 20](20-networking.md) for what's actually happening on the wire.

## Open it

```bash
keepstone --data-dir ./bob drop-open <id>
```

O printing writes the plaintext to stdout; `--out <path>` writes a file instead.

```bash
keepstone --data-dir ./bob drop-open <id> --out secret.txt
```

What `drop-open` does, in order:

```
  read envelope bytes
        │
        ▼
  decode envelope, verify author signature over the preserved payload
        │
        ▼
  check proof-of-work
        │
        ▼
  derive MY tag = HKDF(my_ecdh_public, drop_nonce)[0..8]
        │
        ▼
  scan the wrapped-key slots for my tag(s), try to unseal the content key
        │  (decoys may match but fail authentication)
        ▼
  decrypt each chunk (AEAD), verify chunk index/count via AAD
        │
        ▼
  reassemble and return plaintext
```

If the drop isn't addressed to this device, every candidate fails to unseal and
you get a clear "not addressed to this device" error. If it *is* your drop but a
chunk is missing or corrupted, authentication fails and you get a decryption
error rather than silent garbage.

## Getting a drop without the author online

Federation is covered in [Chapter 22](22-federated-relays-and-gossip.md), but
the shape is: a relay holds ciphertext and nothing else.

```bash
keepstone --data-dir ./relay serve --listen 127.0.0.1:7790   # untrusted, keyless
keepstone --data-dir ./alice push 127.0.0.1:7790 <id>          # author pushes
keepstone --data-dir ./bob   fetch 127.0.0.1:7790 <id>         # bob fetches later
```

## Go look at this

- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `DropOpen`, `Fetch`, `P2pFetch`
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `open_drop`
- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — `Want`/`Drop`/`WantChunk`/`Chunk`
- Tests: `crates/node/tests` (two-node TCP), `crates/p2p/tests` (two-node libp2p)

Next: [Verifying and anchoring](09-verifying.md)
