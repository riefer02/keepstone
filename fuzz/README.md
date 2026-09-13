# Fuzzing

`cargo-fuzz` (libFuzzer) harnesses for untrusted input parsing. This is a
separate Cargo project so it does not affect normal workspace builds.

```bash
cargo +nightly fuzz build
cargo +nightly fuzz run drop_decode      -- -max_total_time=60
cargo +nightly fuzz run protocol_decode  -- -max_total_time=60
cargo +nightly fuzz run presence_decode  -- -max_total_time=60
```

## Targets

| Target | Surfaces |
|---|---|
| `drop_decode` | `SignedDrop::decode` → `verify` → `body` → canonical re-encode invariant |
| `protocol_decode` | peer `Message::decode` |
| `presence_decode` | `PresenceRequest` / `PresenceAttestation` decoders |

## Baseline

A 15-second run of each target executes ~10M inputs with no crashes and growing
coverage. Crash reproducers, if any, land in `fuzz/artifacts/<target>/`.

Corpus and artifacts are intentionally git-ignored.
