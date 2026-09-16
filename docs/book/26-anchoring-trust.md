# 26. Anchoring trust

A signed tree head proves *a log said* a history existed. It does not prove the
log can't rewrite that history later and sign a different one. **Anchoring**
commits a tree head somewhere the log operator can't reach, so a rewrite becomes
detectable. Keepstone has two backends behind one trait.

## The `Anchor` trait

`crates/log/src/anchor.rs` defines an `Anchor` abstraction: "commit this signed
tree head; later, prove it's still there." Two implementations exist, and the
trait boundary means a third can be added without touching callers.

## Backend 1 — the local hash chain (dependency-free)

`HashChainAnchor` commits tree heads into an **append-only hash chain**:

```
link_i = SHA-256( "keepstone/v1/anchor"
                  || previous_link(32)          // all-zero for the first link
                  || tree_size_be64
                  || root(32)
                  || timestamp_be64 )
```

- `link_hash(previous, tree_size, root, now)` computes one link.
- `verify_link(receipt)` checks a single receipt.
- `verify_receipts(receipts)` checks the whole chain's continuity.
- Receipts are persisted to `<data-dir>/log/anchors.txt`.

```bash
keepstone --data-dir ./node log-anchor <id>   # commit the current tree head
keepstone --data-dir ./node log-anchors       # verify chain continuity
```

**What it gives you:** tamper-evidence against *rewriting* — a later head can
prove it extends the earlier one, and any break is visible.

**What it doesn't:** a third-party timestamp. You're trusting your own chain.
That's the gap OTS fills.

## Backend 2 — OpenTimestamps (Bitcoin), via the reference client

For a timestamp you don't have to trust yourself for, the CLI produces a digest
of the tree-head root and delegates to the official `ots` client:

```bash
keepstone --data-dir ./node log-anchor-ots <id>
keepstone log-ots-verify ./anchors/<root>.digest.ots
```

Mechanically:

1. Compute the current signed tree head and write its 32-byte Merkle root to
   `<data-dir>/anchors/<root-hex>.digest`.
2. If the `ots` client is on `PATH`, run `ots stamp <digest>` (which submits to
   calendar servers and eventually produces a Bitcoin-anchored `.ots` proof).
3. If it isn't, print install instructions and exit non-zero — **the digest file
   is still written**, so nothing is lost.

Verification is `ots verify` on a `.ots` proof.

### Why delegate instead of reimplement

The Rust `opentimestamps` crate (0.2.0) can parse/serialize/verify `.ots` files
but **cannot submit to calendar servers**, and Bitcoin verification needs block
headers. Reimplementing the calendar wire protocol ourselves would risk a
subtly-wrong version we can't validate against the live service. Delegating to
the reference client gives *real* Bitcoin timestamps with no fragile code and no
new dependencies. This is [ADR-0015](../DECISIONS.md).

The honest caveat: it requires the external `ots` client. A native Rust calendar
client remains future work behind the same `Anchor` trait.

## The layered picture

```
   drop envelope ──▶ local log (RFC 6962) ──▶ signed tree head
                                                     │
                              ┌──────────────────────┴──────────────────────┐
                              ▼                                             ▼
                   hash chain (self-trusted)               OpenTimestamps (Bitcoin)
                   log-anchor / log-anchors                 log-anchor-ots / log-ots-verify
```

Use the hash chain as the always-available default; add OTS when you want an
externally verifiable proof.

## Go look at this

- [`crates/log/src/anchor.rs`](../../crates/log/src/anchor.rs) — `Anchor`, `HashChainAnchor`, `link_hash`, `verify_receipts`
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `log-anchor-ots`, `log-ots-verify`, `write_ots_digest`
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0010, ADR-0015

Next: [Deployment](27-deployment.md)
