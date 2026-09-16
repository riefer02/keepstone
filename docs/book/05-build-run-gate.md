# 5. Build, run, and the quality gate

## Toolchain

The repository pins Rust **1.88.0** in `rust-toolchain.toml`. `rustup` will
fetch it automatically. (1.88 is required by `libp2p` 0.57.)

```bash
rustc --version   # rustc 1.88.0
```

## Build

```bash
cargo build --workspace
```

This builds the libraries, the `keepstone` CLI binary (from the `keepstone-cli`
crate), and the `keepstone-daemon` binary. The CLI binary is named `keepstone`
so the command you type is short.

## The task runner: `cargo xtask`

There is no `make`; instead there is a small `xtask` crate that runs the common
tasks. Anything you'd otherwise copy-paste from CI lives here.

| Command | What it does |
|---|---|
| `cargo xtask fmt` | format the workspace |
| `cargo xtask fmt-check` | verify formatting (CI) |
| `cargo xtask clippy` | lint with `-D warnings` |
| `cargo xtask test` | run all workspace tests |
| `cargo xtask ci` | `fmt-check` + `clippy` + `test` — **the gate** |
| `cargo xtask deny` | `cargo-deny` license/security/advisory check |
| `cargo xtask demo` | end-to-end smoke test, prints `result: PASS` |

Every commit is expected to keep `cargo xtask ci`, `cargo xtask deny`, and
`cargo xtask demo` green.

## See it work right now

```bash
cargo xtask demo
```

This builds the CLI and then, in a temp directory, drives the whole stack:
generates identities for **alice**, **bob**, and a **relay**; alice adds bob;
alice creates a post-quantum drop; alice pushes the ciphertext to the relay;
bob fetches it; bob opens it and verifies it. Expected output ends:

```
[1/6] generated identities for alice, bob, and a relay
[2/6] alice added bob (out-of-band key exchange)
[3/6] alice created a post-quantum drop c682441a...
[4/6] alice pushed ciphertext to the relay (relay holds no keys)
[5/6] bob fetched the envelope and chunks from the relay
[6/6] bob opened the drop: meet at the old oak at dusk
      signature:   ok (hybrid (Ed25519 + ML-DSA-65))
      inclusion:   ok

result: PASS
```

## Running the CLI

The binary in this walkthrough is `./target/debug/keepstone`. Every command
takes `--data-dir` (default `./.keepstone-data`) which is where that node's
identity, contacts, drops, and log live:

```bash
B=./target/debug/keepstone
$B --data-dir ./demo/alice id
```

## Lints and the safety posture

The workspace lint configuration is deliberately strict:

- `unsafe_code = "forbid"` across the workspace; `crypto`, `core`, and `log`
  also forbid it at the crate root and are pure (no I/O, no clock, no async).
- Clippy `all` is `deny`, and `unwrap_used`, `expect_used`, `panic`, `todo`,
  `unimplemented`, and `dbg_macro` are denied in library code. Binaries and
  tests relax the `unwrap`/`panic` ones where it aids clarity.
- `missing_docs` is a warning, so public items are documented.

See [`Cargo.toml`](../../Cargo.toml) for the exact set.

## Go look at this

- [`xtask/src/main.rs`](../../xtask/src/main.rs) — the task definitions and the demo
- [`rust-toolchain.toml`](../../rust-toolchain.toml) — the pinned toolchain
- [`Cargo.toml`](../../Cargo.toml) — workspace lints and dependencies

Next: [Identities and contacts](06-identities-and-contacts.md)
