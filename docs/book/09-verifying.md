# 9. Verifying and anchoring

Decrypting proves you can read a drop. **Verifying** proves *who wrote it* and
*that it existed in a tamper-evident log*. Different questions, answered
separately.

## Verify against your local log

```bash
keepstone --data-dir ./bob log-verify <id>
```

```
signature:   ok (hybrid (Ed25519 + ML-DSA-65))
inclusion:   ok
tree size:   3
leaf index:  2
merkle root: 9f2c...
sth:         ok
```

- **signature** — the author's signature over the canonical payload verifies.
- **inclusion** — an RFC 6962 inclusion proof shows this drop's bytes are a leaf
  of the current tree.
- **sth** — the re-signed tree head verifies.

Any failure exits non-zero.

## Verify a file, no data directory

```bash
keepstone verify ./drops/<id>.signed
```

Checks signature and proof-of-work offline — no keys, no network, no data dir.

## The log on disk

```
<data-dir>/log/
├── entries.bin   # length-prefixed copies of exact envelope bytes
├── key.txt       # this log's signing identity
└── anchors.txt   # anchor receipts
```

Because a drop's id is `H(exact bytes)`, the log entry and the drop are bound
with no re-encoding.

## Anchor the tree head (dependency-free)

```bash
keepstone --data-dir ./bob log-anchor <id>   # commit the current tree head
keepstone --data-dir ./bob log-anchors       # verify chain continuity
```

Each link is
`H("keepstone/v1/anchor" || previous || tree_size || root || timestamp)`, with
an all-zero `previous` for the first. See
[Chapter 26](26-anchoring-trust.md).

## Anchor to Bitcoin (OpenTimestamps)

```bash
keepstone --data-dir ./bob log-anchor-ots <id>
keepstone log-ots-verify ./anchors/<root>.digest.ots
```

The digest file (`<root>.digest`, 32 raw bytes) is **always** written; if the
`ots` client is absent the command prints install instructions and exits
non-zero. Delegation over unsafe reimplementation —
[ADR-0015](../DECISIONS.md).

## Audit someone else's log head

```bash
keepstone --data-dir ./alice sth-serve --listen 127.0.0.1:7791
keepstone --data-dir ./bob   sth-fetch 127.0.0.1:7791   # verifies the signature
```

Two valid tree heads with the **same size but different roots** is
**equivocation**. See [Chapter 19](19-transparency-log.md).

## The three questions

| Question | Answered by | Command |
|---|---|---|
| Who wrote this? | Ed25519 (+ ML-DSA-65) signature | `verify`, `log-verify` |
| Is it in your log? | RFC 6962 inclusion proof | `log-verify` |
| Has history been rewritten? | Consistency proofs, STH gossip, anchoring | `log-anchors`, `sth-fetch`, OTS |

## Go look at this

- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `verify`, `signed_tree_head`
- [`crates/log/src/merkle.rs`](../../crates/log/src/merkle.rs) — inclusion + consistency
- [`crates/log/src/sth.rs`](../../crates/log/src/sth.rs) — `detect_equivocation`
- [`crates/log/src/anchor.rs`](../../crates/log/src/anchor.rs) — `HashChainAnchor`
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — operator's view

Next: [The browser client and the daemon API](10-browser-client-and-api.md)
