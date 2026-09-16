# 17. Geospatial addressing

Keepstone addresses places with **H3**, a hierarchical hexagonal grid. An
address is a **cell index**, a 64-bit integer shown as hex (e.g.
`8928308280fffff`).

## Why hexagons

They tile a sphere with fewer distortion artefacts than lat/lng rectangles, have
a uniform neighbour relationship (6 edge-neighbours), and nest cleanly (a coarse
cell contains exactly seven finer ones). "Nearby" and "resolution" become
natural operations.

## Resolution — cell size

Resolution runs **0–15**; coarser is bigger.

| Resolution | Average cell area | Feels like |
|---|---|---|
| 5 | ~253 km² | a city district |
| 7 | ~5.16 km² | a neighbourhood |
| 9 | ~0.105 km² | a park / city block |
| 11 | ~0.00215 km² | a building / plaza |

Default is **9** — hundreds of metres, small enough that "being there" means
something, large enough to tolerate GPS noise.

## Operations

```
CellId::from_lat_lng(lat, lng, resolution)   // cell containing a point
CellId::parse_hex("8928308280fffff")         // parse
cell.to_hex()                                // render
cell.resolution()                            // 0..=15
cell.ring(k)                                 // all cells within grid distance k
```

`ring(k)` is H3's **grid disk**: every cell within `k` steps, including the
centre. `k = 1` is 7 cells.

```
        k = 0            k = 1                 k = 2
         ┌─┐          ⬡ ⬡ ⬡                ⬡ ⬡ ⬡ ⬡ ⬡
         │C│         ⬡ ⬡ C ⬡              ⬡ ⬡ ⬡ ⬡ ⬡ ⬡ ⬡
         └─┘          ⬡ ⬡ ⬡                ⬡ ⬡ ⬡ ⬡ ⬡ ⬡ ⬡
        (1 cell)      (7 cells)            ⬡ ⬡ ⬡ ⬡ ⬡ ⬡ ⬡
                                            (19 cells)
```

## Ring is delivery, not access

A drop stores `cell` (the place) and `ring` (the "near" halo). The ring is used
for **delivery and discovery**:

- dense cells: peers subscribe to gossipsub topics per cell;
- sparse cells: a provider advertises the cell; a seeker queries the k-ring
  k-anonymously ([Chapter 23](23-query-privacy.md));
- listing: `drop-list --lat --lng --ring` filters to drops inside your k-ring.

The ring does **not** gate reading. The recipient key does.

## Location is access, not discovery

There is **no global spatial index** — you cannot enumerate drops in a region.
The author communicates the place out of band ([ADR-0005](../DECISIONS.md)).
That removes "what's near me" scanning and a class of metadata leakage, at the
cost of out-of-band coordination.

## Resolution is a privacy knob

Coarser cells mean more plausible deniability and vaguer placement; finer cells
mean precise placement and more leakage if observed. It's chosen per drop.

## Go look at this

- [`crates/core/src/address.rs`](../../crates/core/src/address.rs) — `CellId`
- Tests: `cell_round_trips_through_hex`, `ring_contains_center_and_neighbors`, `invalid_resolution_is_rejected`
- H3 background: <https://h3geo.org>

Next: [Many recipients, many devices, Shamir](18-multi-recipient-and-shamir.md)
