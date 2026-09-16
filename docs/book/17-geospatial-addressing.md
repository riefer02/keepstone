# 17. Geospatial addressing

Keepstone doesn't use raw latitude/longitude. It uses **H3**, a hierarchical
hexagonal grid that tiles the whole planet. An address is a **cell index**, a
64-bit integer shown as hex (e.g. `8928308280fffff`).

## Why hexagons

Hexagons tile a sphere with fewer distortion artefacts than lat/lng rectangles,
have a uniform neighbour relationship (every hexagon has 6 edge-neighbours), and
nest cleanly: a coarse cell contains exactly seven finer ones. That makes
"nearby" and "resolution" natural operations instead of awkward ones.

## Resolution: how big is a cell

Resolution runs **0–15**. Coarser means bigger. Approximate average areas:

| Resolution | Average cell area | Feels like |
|---|---|---|
| 5 | ~253 km² | a city district |
| 7 | ~5.16 km² | a neighbourhood |
| 9 | ~0.105 km² | a park / city block |
| 11 | ~0.00215 km² | a building / plaza |

Keepstone's default is **9** — in the low-hundreds-of-metres range, small enough
that "being there" is meaningful, large enough to be forgiving of GPS noise.

## The operations (`crates/core/src/address.rs`)

```
CellId::from_lat_lng(lat, lng, resolution)   // which cell contains this point
CellId::parse_hex("8928308280fffff")         // parse an address
cell.to_hex()                                // render it
cell.resolution()                            // 0..=15
cell.ring(k)                                 // all cells within grid distance k
```

`ring(k)` is H3's **grid disk**: every cell within `k` steps of the centre,
including the centre itself. For `k = 1` that's 7 cells.

```
        k = 0            k = 1                     k = 2
         ┌─┐          ⬡ ⬡ ⬡                    ⬡ ⬡ ⬡ ⬡ ⬡
         │C│         ⬡ ⬡ C ⬡                  ⬡ ⬡ ⬡ ⬡ ⬡ ⬡ ⬡
         └─┘          ⬡ ⬡ ⬡                    ⬡ ⬡ ⬡ ⬡ ⬡ ⬡ ⬡
        (1 cell)      (7 cells)                ⬡ ⬡ ⬡ ⬡ ⬡ ⬡ ⬡
                                               (19 cells)
```

## Ring as a *delivery* concept, not an access concept

A drop stores `cell` (the exact place) and `ring` (how wide the "near" halo is).
The ring is used for **delivery and discovery**:

- dense cells: peers subscribe to gossipsub topics per cell, so a drop reaches
  whoever is listening in that neighbourhood;
- sparse cells: a provider advertises the cell, and a would-be recipient queries
  the k-ring (k-anonymously — [Chapter 23](23-query-privacy.md));
- listing: `drop-list --lat --lng --ring` filters to drops whose cell is inside
  your k-ring.

The ring does **not** gate reading. The recipient key does that, always.

## Location is access, not discovery

There is deliberately **no global spatial index**. You cannot enumerate all
drops in a region. The author must communicate the place out of band
([ADR-0005](../DECISIONS.md)). Consequences:

- no opportunistic scanning of "what's near me",
- a large class of metadata leakage simply doesn't exist,
- at the cost of out-of-band coordination (which a dead drop always required).

## Resolution is a privacy knob

Coarser cells mean more plausible deniability (you're "somewhere in the city")
but vaguer placement; finer cells mean precise placement but more location
leakage if the cell is observed. Resolution is chosen per drop, so an organizer
can be loose and a private sender can be vague.

## Go look at this

- [`crates/core/src/address.rs`](../../crates/core/src/address.rs) — `CellId`
- Tests: `cell_round_trips_through_hex`, `ring_contains_center_and_neighbors`, `invalid_resolution_is_rejected`
- H3 background: <https://h3geo.org>

Next: [Many recipients, many devices, Shamir](18-multi-recipient-and-shamir.md)
