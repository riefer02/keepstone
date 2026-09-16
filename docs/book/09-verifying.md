# 9. Verifying and anchoring

Decrypting proves you can read a drop. **Verifying** proves *who wrote it* and
*that it existed in a tamper-evident log*. These are different questions and
Keepstone answers them separately.

## Verify against your local log

```bash
keepstone --data-dir ./bob log-verify <id>
```

This checks three things and prints them:

```
signature:   ok (hybrid (Ed25519 + ML-DSA-65))
inclusion:   ok
tree size:   3
leaf index:  2
merkle root: 9f2c... 
sth:         ok
```

- **signature** — the author's signature over the canonical payload verifies.
- **inclusion** — an RFC 6962 inclusion proof shows this drop's exact bytes are
  a leaf of the log at the current tree size.
- **sth** — the freshly re-signed tree head verifies.

If any of the three fail, the command exits non-zero.

## Verify a file with no data directory

Any `.signed` envelope is self-contained enough to check its signature and
proof-of-work **offline**:

```bash
keepstone verify ./drops/<id>.signed
```

This needs no keys, no network, and no data directory — useful for handing a
drop to an auditor.

## Where the log lives

```
<data-dir>/log/
├── entries.bin   # length-prefixed copies of exact envelope bytes
├── key.txt       # this log's signing identity
└── anchors.txt   # anchor receipts (see below)
```

The log is the list of the exact envelope bytes this node has committed to.
Because a drop's id is `H(exact bytes)`, the log entry and the drop are bound
together with no re-encoding anywhere.

## Anchor the tree head (dependency-free)

Anchoring commits the current signed tree head into an append-only **hash
chain**, so a later tree head can prove it extends an earlier one. It needs no
external service.

```bash
keepstone --data-dir ./bob log-anchor <id>   # commit the current tree head
keepstone --data-dir ./bob log-anchors       # verify chain continuity
```

Each link is
`H("keepstone/v1/anchor" || previous || tree_size || root || timestamp)` with an
all-zero `previous` for the first link. See
[Chapter 26](26-anchoring-trust.md).

## Anchor to Bitcoin via OpenTimestamps

For a **third-party** timestamp (one you don't have to trust yourself for), the
CLI can produce a digest of the tree-head root and delegate to the reference
`ots` client:

```bash
keepstone --data-dir ./bob log-anchor-ots <id>
keepstone log-ots-verify ./anchors/<root>.digest.ots
```

The digest file (`<root>.digest`, 32 raw bytes) is **always** written, even if
the `ots` client isn't installed — in that case the command prints how to
install it and exits non-zero. This is a deliberate choice over reimplementing
the calendar protocol unsafely; see
[ADR-0015](../DECISIONS.md) and [Chapter 26](26-anchoring-trust.md).

## Auditing someone else's log head

A node can serve its **signed tree head** so others can verify it and compare:

```bash
keepstone --data-dir ./alice sth-serve --listen 127.0.0.1:7791
keepstone --data-dir ./bob   sth-fetch 127.0.0.1:7791   # verifies the signature
```

If two valid tree heads have the **same tree size but different roots**, that is
**equivocation** — proof the log tried to show different histories. See
[Chapter 19](19-transparency-log.md).

## The three verification questions

| Question | Answered by | Command |
|---|---|---|
| Who wrote this? | Ed25519 (+ ML-DSA-65) signature | `verify`, `log-verify` |
| Is it in your log? | RFC 6962 inclusion proof | `log-verify` |
| Has history been rewritten? | Consistency proofs, STH gossip, anchoring | `log-anchors`, `sth-fetch`, OTS |

## Go look at this

- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `verify`, `signed_tree_head`
- [`crates/log/src/merkle.rs`](../../crates/log/src/merkle.rs) — inclusion + consistency proofs
- [`crates/log/src/sth.rs`](../../crates/log/src/sth.rs) — `detect_equivocation`
- [`crates/log/src/anchor.rs`](../../crates/log/src/anchor.rs) — `HashChainAnchor`
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — the operator's view

Next: [The browser client and the daemon API](10-browser-client-and-api.md)
