# Pull Request

## What does this change?

<!-- A short description, and the motivation. Link the issue it closes, if any. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactor / internal
- [ ] Test / tooling / CI

## Checklist

- [ ] `cargo xtask ci` passes locally (fmt + clippy `-D warnings` + tests).
- [ ] I followed the [ground rules](../CONTRIBUTING.md): `crypto`/`core`/`log`
      stay pure; no `unwrap`/`expect`/`panic` in library code; secrets are
      zeroized; received bytes are never re-encoded before hashing/verifying.
- [ ] New cryptographic choices include an ADR in `docs/DECISIONS.md`.
- [ ] User-facing changes update the relevant docs (README, `docs/book/`, `docs/SPEC.md`).
- [ ] I agree to the [CLA](../CONTRIBUTING.md) and license my contribution under AGPL-3.0-or-later.

## Security impact

<!-- Does this change the threat model or any guarantee in docs/THREAT_MODEL.md?
     Write "none" if not. -->
