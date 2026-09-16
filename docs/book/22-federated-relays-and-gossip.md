# 22. Federated relays and STH gossip

A dead drop needs somewhere for the ciphertext to live until the recipient
arrives — and it must be somewhere untrusted, because the operator must not be
able to read it.

## Store-and-forward

A **relay** is any node willing to hold ciphertext. It holds no keys.

```bash
keepstone --data-dir ./relay serve --listen 127.0.0.1:7790   # keyless, ciphertext
keepstone --data-dir ./alice push  127.0.0.1:7790 <id>        # author pushes
keepstone --data-dir ./bob   fetch 127.0.0.1:7790 <id>        # recipient fetches later
keepstone --data-dir ./bob   drop-open <id>
```

Messages: `Put` (offer a raw envelope) → `Stored(drop_id)`, plus `PutChunk` per
chunk. Fetch reuses `Want`/`Drop` and `WantChunk`/`Chunk`.

```
   author ──Put / PutChunk──▶ relay (ciphertext, no keys) ◀──Want / WantChunk── recipient
                                   │
                                   └── can withhold, but cannot read or forge
```

## STH gossip

A node can serve its **signed tree head** so others verify and compare — the
mechanism that catches a log showing different histories to different people.

```bash
keepstone --data-dir ./alice sth-serve --listen 127.0.0.1:7791
keepstone --data-dir ./bob   sth-fetch 127.0.0.1:7791   # verifies the signature
```

Over the protocol: `GetSth` → `Sth` (144-byte signed tree head). Two valid STHs
with the same tree size but different roots is **equivocation**
([Chapter 19](19-transparency-log.md)).

## Availability, honestly

Federation improves availability but does **not** guarantee it:

- no replication factor, erasure coding, or durability contract;
- if a relay holding the only copy goes away, the drop is gone;
- replication across independent nodes/logs is tracked, not claimed.

An explicit non-guarantee. Run a relay; back up the data directory for anything
important.

## Why this design

- **No hosted service required** — relays are self-hostable and untrusted, so
  there's no central operator to subpoena or shut down.
- **The author can leave** — push once, walk away.
- **Nothing new is trusted** — all confidentiality comes from the lock; the relay
  is a shelf.

## Go look at this

- [`crates/relay/src/lib.rs`](../../crates/relay/src/lib.rs) — ciphertext-only relay
- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — `Put`, `Stored`, `PutChunk`, `GetSth`, `Sth`
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `push`, `fetch`, `sth-serve`, `sth-fetch`
- [`docs/OPERATIONS.md`](../OPERATIONS.md)

Next: [Query privacy](23-query-privacy.md)
