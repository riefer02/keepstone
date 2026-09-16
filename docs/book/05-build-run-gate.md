# 5. Build, run, and the quality gate

## Toolchain

Rust **1.88.0**, pinned in `rust-toolchain.toml` (fetched by `rustup`). Required
by `libp2p` 0.57.

## Build

```bash
cargo build --workspace
```

Builds the libraries, the `keepstone` CLI, and `keepstone-daemon`.

## Task runner: `cargo xtask`

No `make`. Common tasks live in the `xtask` crate:

| Command | Does |
|---|---|
| `cargo xtask fmt` / `fmt-check` | format / verify |
| `cargo xtask clippy` | lint with `-D warnings` |
| `cargo xtask test` | all workspace tests |
| `cargo xtask ci` | `fmt-check` + `clippy` + `test` — **the gate** |
| `cargo xtask deny` | `cargo-deny` license/advisory check |
| `cargo xtask demo` | end-to-end smoke test, prints `result: PASS` |

Every commit keeps `ci`, `deny`, and `demo` green.

## See it work

```bash
cargo xtask demo
```

Drives the whole stack in a temp dir: identities for **alice**, **bob**, a
**relay**; alice adds bob; alice creates a post-quantum drop; pushes ciphertext
to the relay; bob fetches and opens it. Ends with:

```
[6/6] bob opened the drop: meet at the old oak at dusk
      signature:   ok (hybrid (Ed25519 + ML-DSA-65))
      inclusion:   ok

result: PASS
```

## Running the CLI

The binary is `./target/debug/keepstone`. Every command takes `--data-dir`
(default `./.keepstone-data`) — that node's identity, contacts, drops, and log.

```bash
B=./target/debug/keepstone
$B --data-dir ./demo/alice id
```

## Lints and safety

- `unsafe_code = "forbid"` workspace-wide; `crypto`, `core`, and `log` are pure
  (no I/O, no clock, no async).
- Clippy `all` denied; `unwrap_used`, `expect_used`, `panic`, `todo`,
  `unimplemented`, `dbg_macro` denied in library code (relaxed in binaries/tests).
- `missing_docs` warns, so public items are documented.

See [`Cargo.toml`](../../Cargo.toml).

## Go look at this

- [`xtask/src/main.rs`](../../xtask/src/main.rs) — tasks + demo
- [`rust-toolchain.toml`](../../rust-toolchain.toml)
- [`Cargo.toml`](../../Cargo.toml) — lints and dependencies

Next: [Identities and contacts](06-identities-and-contacts.md)
