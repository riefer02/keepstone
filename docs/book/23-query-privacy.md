# 23. Query privacy

The sparse-cell path ([Chapter 20](20-networking.md)) asks a DHT "who serves
cell X?". Sent literally, that query tells an observer exactly which cell you
care about — a location leak. Query privacy mitigates it, and is modest about
what it claims.

## The problem

```
  you ──"who serves 8928308280fffff?"──▶ DHT
                    │
                    └── observer learns: you want this exact place
```

## The mitigation: ask about a neighbourhood

`find_providers_private` issues provider lookups for the **target cell and its
`ring` neighbours**, shuffled, and returns only the target's providers. The
observer sees a set of plausible nearby cells, not one identifying query.

```
  target: 8928308280fffff        ring = 1 → query all of:

        ⬡ ⬡ ⬡
        ⬡ C ⬡     (one is the real target; the observer can't tell which)
        ⬡ ⬡ ⬡
```

`nearby_cells(cell, ring)` exposes the ring; the CLI surfaces the lookup:

```bash
keepstone find-providers /ip4/127.0.0.1/tcp/7778 8928308280fffff --ring 2
```

## Why it's fast

A naive version — query the target and every decoy, then wait — costs `ring` ×
the per-query timeout (90 s for a ring of 1 in early testing). Instead all
lookups run **concurrently** and the function returns as soon as the target
answers; decoy queries are still sent, but their timeouts aren't waited on.

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

Wall-clock cost is roughly one lookup, not `ring`.

## What this is, and is not

**Is:** k-anonymity. A passive observer sees plausible nearby queries instead of
the identifying one. It raises linkage cost.

**Is not:** cryptographic PIR. It hides which of several cells you want, not
*that* you are querying. A global active observer, or one controlling the
decoy-answering peers, can still learn a lot.

```
   k-anonymity:  you are one of these 7 cells        (what we have)
   true PIR:     the server learns nothing about which item you fetched (future)
```

`find_providers_private` is shaped so a real PIR backend can swap in behind it
([ADR-0014](../DECISIONS.md)).

## Cost

Privacy costs `ring`-many lookups of traffic (not `ring`-many timeouts). Larger
rings mean stronger anonymity and more noise.

## Go look at this

- [`crates/p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) — `nearby_cells`, `find_providers_private`
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — `find-providers`
- [`docs/DECISIONS.md`](../DECISIONS.md) — ADR-0014
- Tests: `crates/p2p/tests/providers.rs`

Next: [The store and the data directory](24-the-store-and-data-dir.md)
