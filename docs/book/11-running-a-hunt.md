# 11. Running a hunt

The event-pilot kit: a small location game where participants walk to places
and open drops addressed to them. It answers a product question cheaply — *do
people want this?* Full guide:
[`docs/PILOT.md`](../PILOT.md).

## The shape

An organizer defines locations, writes a clue at each, and creates one drop per
location addressed to **all** participants. Participants add the organizer as a
contact, fetch the drops (via a relay or a copied data dir), and walk the area.

## Organizer

```bash
BIN="keepstone --data-dir ./org"
$BIN keygen
$BIN id                                   # share with participants

$BIN contact-add alice <signing> <ecdh> <hybrid>
$BIN contact-add bob   <signing> <ecdh> <hybrid>

$BIN hunt create demo
$BIN hunt add-participant demo alice
$BIN hunt add-participant demo bob
$BIN hunt add-drop demo --lat 51.5007 --lng -0.1246 --suite hybrid "Find the lion statue"
$BIN hunt add-drop demo --lat 51.5010 --lng -0.1250 "Count the benches"

$BIN hunt seed demo                 # create the drops
$BIN hunt show demo                 # ids + clues
$BIN hunt map demo --out map.html   # printable organizer map
```

`hunt seed` creates one drop per location addressed to every participant.
`hunt map` renders an HTML map for the organizer; participants get the clues.

## Participants

```bash
BIN="keepstone --data-dir ./me"
$BIN keygen
$BIN id                          # send to the organizer
$BIN contact-add organizer <signing> <ecdh> <hybrid>

$BIN fetch <relay-host>:7777 <id>
$BIN drop-open <id>
```

Or use the daemon UI (`keepstone-daemon --data-dir ./me`).

## One-command deployment

```bash
docker compose -f deploy/docker-compose.yml up --build
# relay on :7777, browser UI on http://127.0.0.1:8787
```

Run a relay so drops survive participants arriving at different times
([Chapter 22](22-federated-relays-and-gossip.md)).

## What to measure

- **Activation:** did each participant open at least one drop?
- **Completion:** did groups finish?
- **Friction:** where did onboarding stall (key exchange, fetching, opening)?
- **Qualitative:** would they do it again? What was missing?

## Honest limits

- Location is best-effort defense in depth, not proof; GPS can be spoofed.
- Not independently audited.
- Delivery is best-effort; run a relay.

## Go look at this

- [`docs/PILOT.md`](../PILOT.md) — full guide
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — the `Hunt` command tree
- The CLI integration test exercises a multi-participant hunt

Next: [Workspace map](12-workspace-map.md)
