# 28. How it's tested

Four layers, cheap-and-broad to slow-and-thorough.

## Unit and integration tests — 106 passing

```bash
cargo xtask test          # cargo test --workspace
cargo test -p keepstone-crypto
cargo test --workspace merkle    # filter by name
```

Coverage: AEAD, sealed boxes, chunked streaming, canonical CBOR, sign/verify, H3,
Merkle inclusion + consistency, the peer protocol, two-node TCP and libp2p
exchange, gossipsub delivery, Kademlia provider discovery, networked presence
(TCP and libp2p), hybrid encapsulation and signatures, Shamir, the place-locked
flow, and the CLI hunt flow.

Integration tests in `crates/*/tests/`:

```
crates/cli/tests/hunt.rs            # multi-participant hunt
crates/core/tests/place_locked.rs   # place-locked release
crates/core/tests/properties.rs     # CBOR property tests
crates/crypto/tests/properties.rs   # crypto property tests
crates/log/tests/properties.rs      # Merkle property tests
crates/node/tests/presence_net.rs   # presence over the network
crates/p2p/tests/{exchange,gossip,presence,providers}.rs
```

## Property-based tests

`proptest` in `crypto`, `core`, and `log` checks invariants over generated
inputs:

- canonical CBOR encode → decode round-trips,
- chunked encrypt → decrypt round-trips,
- inclusion proofs verify for random sizes and indices,
- consistency proofs hold between random prefix/suffix sizes,
- tag derivation is stable and decoys fail authentication.

Catches the "off by one at an unusual size" bugs example tests miss.

## Fuzzing

A detached `cargo-fuzz` project (`fuzz/`) hammers three decoders with arbitrary
bytes:

```
fuzz/fuzz_targets/drop_decode.rs       # envelope + body
fuzz/fuzz_targets/protocol_decode.rs   # peer protocol messages
fuzz/fuzz_targets/presence_decode.rs   # presence certificates
```

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run drop       # or protocol / presence
```

Invariant: **untrusted input must never crash or panic** — it must return an
error. ~30M executions, no crashes. Corpus and artifacts under `fuzz/corpus/`
and `fuzz/artifacts/`. This pairs with the canonical-CBOR rule: the decoder is
where hostile bytes arrive.

## Benchmarks

```bash
cargo bench -p keepstone-crypto --bench crypto
cargo bench -p keepstone-log --bench merkle
```

Headline numbers in [`docs/BENCHMARKS.md`](../BENCHMARKS.md): ~656 MiB/s chunked
AEAD, sub-µs inclusion *verification*, ~2 ms inclusion *generation* at 10k leaves
(a tracked `O(n)` generation limitation).

## The gate

```bash
cargo xtask ci      # fmt-check + clippy -D warnings + test
cargo xtask deny    # cargo-deny: licenses, advisories, bans
cargo xtask demo    # end-to-end smoke test, prints PASS
```

CI requires all three; `deny.toml` encodes the license policy and blocks
vulnerable or duplicate-banned dependencies.

## Why this shape

- **Pure leaves** (`crypto`, `log`) get property tests and fuzzing — hardest
  correctness, easiest testing.
- **The protocol parser** gets a fuzzer because it consumes hostile bytes.
- **End-to-end flows** get integration tests plus one scripted demo.

## Go look at this

- [`xtask/src/main.rs`](../../xtask/src/main.rs) — gate + demo
- [`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/) — fuzzers
- [`docs/BENCHMARKS.md`](../BENCHMARKS.md)
- [`deny.toml`](../../deny.toml)

Next: [Design decisions, digest](29-design-decisions.md)
