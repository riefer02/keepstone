# 8. Getting a drop

## Local drops

```bash
keepstone --data-dir ./alice drop-list
keepstone --data-dir ./alice drop-list --lat 51.5007 --lng -0.1246 --ring 2
```

`drop-list` prints this data directory's drops, optionally filtered to those
near a point. The filter computes your cell at each drop's resolution and checks
the k-ring; it never displays your exact coordinates.

## Fetch over the reference TCP transport

```bash
keepstone --data-dir ./alice serve --listen 127.0.0.1:7777   # ciphertext only
keepstone --data-dir ./bob   fetch 127.0.0.1:7777 <id>
```

`fetch` asks for the envelope (`Want` → `Drop`), then each chunk (`WantChunk` →
`Chunk`), stores them in bob's data dir, and appends the envelope to **bob's own
log**. Only ciphertext crosses the wire.

## Fetch over libp2p (QUIC + TCP, Noise)

```bash
keepstone --data-dir ./alice p2p-serve --listen /ip4/127.0.0.1/tcp/7778
keepstone --data-dir ./bob   p2p-fetch /ip4/127.0.0.1/tcp/7778 <id>
```

Same messages; see [Chapter 20](20-networking.md).

## Open

```bash
keepstone --data-dir ./bob drop-open <id>
keepstone --data-dir ./bob drop-open <id> --out secret.txt
```

`drop-open`:

```
  read envelope bytes
        ▼
  decode, verify author signature over the preserved payload
        ▼
  check proof-of-work
        ▼
  derive MY tag = HKDF(my_ecdh_public, drop_nonce)[0..8]
        ▼
  scan slots for my tag(s), unseal the content key (decoys fail auth)
        ▼
  decrypt each chunk (AEAD), verify index/count via AAD
        ▼
  reassemble plaintext
```

A drop not addressed to this device returns "not addressed to this device". A
missing/corrupt chunk returns a decryption error, never silent garbage.

## Author offline

A relay holds ciphertext and nothing else; the author can leave.

```bash
keepstone --data-dir ./relay serve --listen 127.0.0.1:7790
keepstone --data-dir ./alice push  127.0.0.1:7790 <id>
keepstone --data-dir ./bob   fetch 127.0.0.1:7790 <id>
```

## Go look at this

- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `DropOpen`, `Fetch`, `P2pFetch`
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `open_drop`
- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — `Want`/`Drop`/`WantChunk`/`Chunk`
- Tests: `crates/node/tests`, `crates/p2p/tests`

Next: [Verifying and anchoring](09-verifying.md)
