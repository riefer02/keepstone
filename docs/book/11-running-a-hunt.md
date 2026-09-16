# 11. Running a hunt

The "hunt" is the project's event-pilot kit: a way to run a small
location-based game where participants walk to places and open the drops
addressed to them. It exists to answer a product question cheaply — *do people
want this?* — before building more.

The full guide is [`docs/PILOT.md`](../PILOT.md). This chapter is the shape of
it.

## The idea

An organizer defines a set of locations, writes a clue at each, and creates one
drop per location addressed to **all** participants. Participants add the
organizer as a contact, fetch the drops (via a relay or a copied data dir), and
walk the area opening clues.

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

$BIN hunt seed demo            # actually create the drops
$BIN hunt show demo            # ids + clues
$BIN hunt map demo --out map.html   # a printable organizer map
```

`hunt seed` creates one drop per location, addressed to every participant, and
records the resulting ids. `hunt map` renders an HTML map for the organizer
(not for participants — they get the clues and walk).

## Participants

```bash
BIN="keepstone --data-dir ./me"
$BIN keygen
$BIN id                          # send to the organizer
$BIN contact-add organizer <signing> <ecdh> <hybrid>

$BIN fetch <relay-host>:7777 <id>
$BIN drop-open <id>
```

Or point a browser at the daemon (`keepstone-daemon --data-dir ./me`) and use
the UI.

## One-command deployment

```bash
docker compose -f deploy/docker-compose.yml up --build
# relay on :7777, browser UI on http://127.0.0.1:8787
```

Run a relay so drops survive participants arriving at different times — the
author doesn't have to stay online (Chapter 22).

## What the pilot measures

- **Activation:** did each participant open at least one drop?
- **Completion:** did groups finish?
- **Friction:** where did onboarding stall (key exchange, fetching, opening)?
- **Qualitative:** would they do it again? What did they expect that's missing?

## Honest limits

- Location is **best-effort defense in depth**, not proof. GPS can be spoofed.
- The code is **not independently audited**.
- Delivery is best-effort; run a relay.

## Go look at this

- [`docs/PILOT.md`](../PILOT.md) — the full guide
- [`crates/cli/src/main.rs`](../../crates/cli/src/main.rs) — the `Hunt` command tree
- The CLI integration test exercises a multi-participant hunt end to end

Next: [The workspace map](12-workspace-map.md)
