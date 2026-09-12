# Contributing to Keepstone

Thanks for wanting to help build privacy infrastructure.

## License and CLA

Keepstone is licensed **AGPL-3.0-or-later**. By submitting a contribution you
agree to the Contributor License Agreement (CLA) below. The CLA is required so
the project can remain able to relicense or dual-license commercially in the
future; without it, that option is permanently lost.

### Contributor License Agreement (summary)

By contributing, you certify that:

1. You created the contribution, or have the right to submit it.
2. You grant the project a perpetual, worldwide, non-exclusive, royalty-free,
   irrevocable license to use, reproduce, modify, distribute, and relicense your
   contribution under the AGPL-3.0-or-later and under other licenses.
3. Your contribution is provided "as is", without warranty.

(Replace this summary with a full CLA text before accepting external PRs.)

## Development

```bash
cargo xtask ci      # fmt check + clippy (-D warnings) + tests
cargo xtask test    # tests only
cargo xtask clippy
cargo xtask fmt
```

### Ground rules

- `crypto`, `core`, and `log` are **pure**: no I/O, no async, no clock reads.
- `#![forbid(unsafe_code)]` everywhere unless reviewed and justified.
- No `unwrap`/`expect`/`panic` in library code (tests are exempt).
- Secrets are zeroized on drop and never rendered in `Debug`.
- Received objects are identified by their **exact transmitted bytes**; never
  re-encode before hashing or verifying.
- New cryptographic choices require an ADR in `docs/DECISIONS.md`.

### Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
