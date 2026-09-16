# 23. Query privacy

The sparse-cell path ([Chapter 20](20-networking.md)) asks a DHT "who serves
cell X?" That query, sent literally, tells a network observer exactly which cell
you care about — a location leak that would undercut the metadata story. Query
privacy is the mitigation, and it is deliberately modest in what it claims.

## The problem

```
  you ──"who serves 8928308280fffff?"──▶ DHT
                    │
                    └── an observer learns: you are interested in this exact place
```

## The mitigation: ask about a neighbourhood, not a point

`find_providers_private` issues provider lookups for the **target cell and its
`ring` neighbours**, in a shuffled order, and returns only the target's
providers. To an observer, the queries look like a set of plausible nearby
cells — not one identifying query.

```
  target: 8928308280fffff        ring = 1 → query all of:

        ⬡ ⬡ ⬡
        ⬡ C ⬡     (one of these is the real target; the observer can't tell which)
        ⬡ ⬡ ⬡
```

`nearby_cells(cell, ring)` exposes the ring; `find_providers_private(peer, cell,
ring)` performs the private lookup. The CLI surfaces it:

```bash
keepstone find-providers /ip4/127.0.0.1/tcp/7778 8928308280fffff --ring 2
```

## How it's implemented (and why it's fast)

The naive version — query the target and every decoy, then wait — costs `ring` ×
the per-query timeout (90 seconds for a ring of 1 in early testing). Instead the
implementation fires all lookups **concurrently** and returns as soon as the
target answers; the decoy queries are still sent, but their timeouts aren't
waited on.

```rust
let mut cells = nearby_cells(cell, ring)?;
cells.shuffle(&mut rand::thread_rng());

let mut pending = FuturesUnordered::new();
for candidate in cells {
    pending.push(async move { (candidate == cell, find_providers(peer, &candidate).await) });
}
while let Some((is_target, providers)) = pending.next().await {
    if is_target { return Ok(providers.unwrap_or_default()); }
}
```

Wall-clock cost is roughly one lookup, not `ring` of them.

## What this is, and is not

**Is:** k-anonymity. A passive observer sees a set of plausible nearby-cell
queries instead of the one that identifies you. It raises the cost of linkage.

**Is not:** cryptographic PIR (private information retrieval). It does not hide
*that* you are querying, only *which* of several cells you want. A global active
observer, or an adversary who controls the decoy-answering peers, can still
learn a lot.

```
   k-anonymity:  you are one of these 7 cells   (this is what we have)
   true PIR:     the server learns nothing about which item you fetched
                 (this is future work)
```

The interface (`find_providers_private`) is shaped so a real PIR backend can be
swapped in behind it without changing callers. This tradeoff is recorded in
[ADR-0014](../DECISIONS.md).

## Cost

- Privacy costs `ring`-many lookups of network traffic (though not `ring`-many
  timeouts).
- Larger rings mean stronger anonymity among more cells, and more noise.

## Go look at this

- [`crates/p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) — `nearby_cells`, `find_providers_private`
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — the `find-providers` command
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0014
- Tests: `crates/p2p/tests/providers.rs`

Next: [The store and the data directory](24-the-store-and-data-dir.md)
