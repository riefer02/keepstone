# 28. How it's tested

Testing is layered from cheap-and-broad (unit tests) to slow-and-thorough
(property tests, fuzzing, benchmarks). Every layer earns its keep.

## Unit and integration tests — 106 passing

```bash
cargo xtask test          # cargo test --workspace
cargo test -p keepstone-crypto
cargo test --workspace merkle    # filter by name
```

They cover: AEAD, sealed boxes, chunked streaming, canonical CBOR, sign/verify,
H3 addressing, Merkle inclusion + consistency, the peer protocol, two-node TCP
and two-node libp2p exchange, gossipsub delivery, Kademlia provider discovery,
networked presence certificates (TCP and libp2p), hybrid encapsulation and
signatures, Shamir, the place-locked flow, and the CLI hunt flow.

Integration tests live in `crates/*/tests/`:

```
crates/cli/tests/hunt.rs            # multi-participant hunt end to end
crates/core/tests/place_locked.rs   # place-locked release
crates/core/tests/properties.rs     # property tests (CBOR, etc.)
crates/crypto/tests/properties.rs   # property tests (crypto)
crates/log/tests/properties.rs      # property tests (Merkle)
crates/node/tests/presence_net.rs   # presence over the network
crates/p2p/tests/{exchange,gossip,presence,providers}.rs
```

## Property-based tests

`proptest` (in `crypto`, `core`, `log`) checks invariants over generated inputs
rather than hand-picked cases:

- encode → decode round-trips for canonical CBOR,
- encrypt → decrypt round-trips for chunked streams,
- Merkle inclusion proofs verify for random tree sizes and indices,
- consistency proofs hold between random prefix/suffix sizes,
- tag derivation is stable and decoys fail authentication.

These catch the "off by one at an unusual size" bugs that example tests miss.

## Fuzzing

A detached `cargo-fuzz` project (`fuzz/`) hammer three decoders with arbitrary
bytes:

```
fuzz/fuzz_targets/drop_decode.rs       # envelope + body decoding
fuzz/fuzz_targets/protocol_decode.rs   # peer protocol messages
fuzz/fuzz_targets/presence_decode.rs   # presence certificates
```

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run drop       # or protocol / presence
```

The goal is the parser invariant: **untrusted input must never crash or panic** —
it must return an error. Roughly 30M executions have been run with no crashes.
Corpus and any artifacts live under `fuzz/corpus/` and `fuzz/artifacts/`.

This pairs with the canonical-CBOR rule: the decoder is where hostile bytes
arrive, so it's where the fuzzer spends its time.

## Benchmarks

`criterion` benchmarks quantify cost and catch regressions:

```bash
cargo bench -p keepstone-crypto --bench crypto
cargo bench -p keepstone-log --bench merkle
```

Headline numbers (Apple Silicon, Rust 1.88) are in
[`docs/BENCHMARKS.md`](../BENCHMARKS.md): ~656 MiB/s chunked AEAD, sub-µs
inclusion *verification*, ~2 ms inclusion *generation* at 10k leaves (a known
`O(n)` generation limitation, tracked as an optimization).

## The gate

```bash
cargo xtask ci      # fmt-check + clippy -D warnings + test
cargo xtask deny    # cargo-deny: licenses, advisories, bans
cargo xtask demo    # end-to-end smoke test, prints PASS
```

CI requires all three. `cargo-deny` (`deny.toml`) enforces the license policy
and blocks known-vulnerable or duplicate-banned dependencies.

## Why this shape

- **Pure leaves** (`crypto`, `log`) get the heaviest scrutiny — property tests
  and fuzzing — because that's where correctness is hardest and the code is
  easiest to test (no I/O).
- **The protocol parser** gets a fuzzer because it consumes hostile bytes.
- **End-to-end flows** get integration tests and one scripted demo so the whole
  stack is exercised, not just its parts.

## Go look at this

- [`xtask/src/main.rs`](../../xtask/src/main.rs) — the gate and demo
- [`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/) — the fuzzers
- [`docs/BENCHMARKS.md`](../BENCHMARKS.md) — numbers and methodology
- [`deny.toml`](../../deny.toml) — the dependency policy

Next: [Design decisions, digest](29-design-decisions.md)
