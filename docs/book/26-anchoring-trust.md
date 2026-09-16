# 26. Anchoring trust

A signed tree head proves *a log said* a history existed. It doesn't prove the
log can't later rewrite that history and sign a different one. **Anchoring**
commits a tree head somewhere the operator can't reach, making a rewrite
detectable. Two backends, one trait.

## The `Anchor` trait

[`anchor.rs`](../../crates/log/src/anchor.rs) defines an `Anchor`: commit a
signed tree head; later, prove it's still there. Two implementations; a third
can swap in behind the trait without touching callers.

## Backend 1 — local hash chain (dependency-free)

`HashChainAnchor` commits tree heads into an append-only chain:

```
link_i = SHA-256( "keepstone/v1/anchor"
                  || previous_link(32)          // all-zero for the first link
                  || tree_size_be64
                  || root(32)
                  || timestamp_be64 )
```

- `link_hash(previous, tree_size, root, now)` — one link
- `verify_link(receipt)` — one receipt
- `verify_receipts(receipts)` — whole-chain continuity
- Receipts persist to `<data-dir>/log/anchors.txt`

```bash
keepstone --data-dir ./node log-anchor <id>   # commit the current tree head
keepstone --data-dir ./node log-anchors       # verify chain continuity
```

**Gives:** tamper-evidence against rewriting. **Doesn't:** a third-party
timestamp — you trust your own chain. That's OTS's job.

## Backend 2 — OpenTimestamps (Bitcoin), via the reference client

```bash
keepstone --data-dir ./node log-anchor-ots <id>
keepstone log-ots-verify ./anchors/<root>.digest.ots
```

1. Compute the current STH; write its 32-byte Merkle root to
   `<data-dir>/anchors/<root-hex>.digest`.
2. If `ots` is on `PATH`, run `ots stamp <digest>` (submits to calendar servers,
   eventually a Bitcoin-anchored `.ots` proof).
3. If not, print install instructions and exit non-zero — **the digest file is
   still written**.

Verification is `ots verify` on a `.ots` proof.

### Why delegate instead of reimplement

The Rust `opentimestamps` crate (0.2.0) parses/serializes/verifies `.ots` but
**cannot submit to calendars**, and Bitcoin verification needs block headers.
Reimplementing the calendar protocol risks a subtly-wrong version we can't
validate here. Delegating gives real Bitcoin timestamps with no fragile code and
no new dependencies ([ADR-0015](../DECISIONS.md)). Caveat: it needs the external
`ots` client; a native Rust client is future work behind the same trait.

## Layered picture

```
   drop envelope ──▶ local log (RFC 6962) ──▶ signed tree head
                                                     │
                              ┌──────────────────────┴──────────────────────┐
                              ▼                                             ▼
                   hash chain (self-trusted)               OpenTimestamps (Bitcoin)
                   log-anchor / log-anchors                 log-anchor-ots / log-ots-verify
```

Use the hash chain as the always-available default; add OTS for an externally
verifiable proof.

## Go look at this

- [`crates/log/src/anchor.rs`](../../crates/log/src/anchor.rs) — `Anchor`, `HashChainAnchor`, `link_hash`, `verify_receipts`
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `log-anchor-ots`, `log-ots-verify`, `write_ots_digest`
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0010, ADR-0015

Next: [Deployment](27-deployment.md)
