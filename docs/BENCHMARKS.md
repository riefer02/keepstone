# Benchmarks

Measured with `criterion` on Apple Silicon (arm64), Rust 1.88, optimized bench
profile. Reproduce with:

```bash
cargo bench -p keepstone-crypto --bench crypto
cargo bench -p keepstone-log --bench merkle
```

## Cryptographic core

| Benchmark | Time |
|---|---|
| XChaCha20-Poly1305 seal (4 KiB) | ~5.96 µs |
| XChaCha20-Poly1305 open (4 KiB) | ~7.75 µs |
| Chunked stream encrypt (1 MiB) | ~1.52 ms (~656 MiB/s) |
| Chunked stream decrypt (1 MiB) | ~1.52 ms (~660 MiB/s) |
| Sealed box seal (X25519 + AEAD) | ~38.1 µs |
| Sealed box open | ~23.4 µs |
| Shamir split (3-of-5, 32 bytes) | ~28.6 µs |
| Shamir combine (3-of-5, 32 bytes) | ~486 ns |

## RFC 6962 Merkle log (10,000 leaves)

| Benchmark | Time |
|---|---|
| `mth` (root over 10k leaves) | ~2.24 ms |
| Inclusion proof generation | ~2.25 ms |
| Inclusion proof verification | ~3.23 µs |
| Consistency proof generation | ~2.25 ms |
| Consistency proof verification | ~3.44 µs |

## Observations

- **Verification is cheap; proof generation is not.** Verifying an inclusion or
  consistency proof is microseconds, while generating one recomputes subtree
  hashes in `O(n)` (milliseconds at 10k leaves). A log with cached internal
  nodes or a persistent tree would make generation `O(log n)`. This is a known,
  tracked optimization, not a correctness issue.
- **Throughput ~656 MiB/s** for chunked AEAD is dominated by XChaCha20 on this
  hardware; acceptable for drop-sized payloads.
- **Shamir combine is sub-microsecond**, so place-locked release adds negligible
  cost over the network round-trips it already requires.
