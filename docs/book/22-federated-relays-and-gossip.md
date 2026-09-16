# 22. Federated relays and STH gossip

A dead drop's whole point is that the sender doesn't have to be present when the
recipient arrives. That requires somewhere for the ciphertext to live in the
meantime — and somewhere untrusted, because the operator must not be able to
read it.

## Store-and-forward

A **relay** is any node willing to hold ciphertext. It holds no keys and can
read nothing.

```bash
# A relay starts empty and keyless (ciphertext only).
keepstone --data-dir ./relay serve --listen 127.0.0.1:7790

# The author pushes ciphertext to it.
keepstone --data-dir ./alice push 127.0.0.1:7790 <id>

# The recipient fetches later, even if the author is offline.
keepstone --data-dir ./bob fetch 127.0.0.1:7790 <id>
keepstone --data-dir ./bob drop-open <id>
```

The protocol messages are `Put` (offer a raw envelope for storage) →
`Stored(drop_id)`, and `PutChunk` for each chunk. Fetch reuses `Want`/`Drop` and
`WantChunk`/`Chunk`.

```
   author ──Put / PutChunk──▶ relay (ciphertext, no keys) ◀──Want / WantChunk── recipient
                                   │
                                   └── can never read, only hold or drop
```

Because the relay holds only ciphertext, the trust model is simple: it can
withhold availability, but it cannot break confidentiality or forge content.

## STH gossip: auditing a log's head

Logs shouldn't be islands. A node can serve its **signed tree head** so others
can verify it and compare against the heads they've seen — the mechanism that
catches a log trying to show different histories to different people.

```bash
keepstone --data-dir ./alice sth-serve --listen 127.0.0.1:7791
keepstone --data-dir ./bob   sth-fetch 127.0.0.1:7791   # verifies the signature
```

Over the protocol this is `GetSth` → `Sth` (144-byte signed tree head). If two
valid STHs have the **same tree size but different roots**, that's
**equivocation** (`detect_equivocation`) — proof the log is inconsistent. See
[Chapter 19](19-transparency-log.md).

## Availability, honestly

Federation improves availability but does **not** guarantee it:

- no replication factor, no erasure coding, no durability contract,
- a relay can go away, and if it held the only copy, the drop is gone,
- the fix (replication across independent nodes/logs) is tracked but not
  claimed.

This is listed as an explicit non-guarantee in the threat model. The right way to
run it today: run a relay, and for anything important, keep the data directory
itself backed up.

## Why this design

- **No hosted service required.** Relays are self-hostable and untrusted by
  design, so there's no central operator to subpoena or shut down.
- **The author can leave.** Push once, walk away; the recipient fetches whenever.
- **Nothing new is trusted.** All the confidentiality comes from the lock; the
  relay is just a shelf.

## Go look at this

- [`crates/relay/src/lib.rs`](../../crates/relay/src/lib.rs) — the ciphertext-only relay
- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — `Put`, `Stored`, `PutChunk`, `GetSth`, `Sth`
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `push`, `fetch`, `sth-serve`, `sth-fetch`
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — running relays and log nodes

Next: [Query privacy](23-query-privacy.md)
