# Running an Event Pilot (M-Pilot)

A 10–20 person, one-afternoon hunt using the Docker deployment. This is the
cheap go/no-go for whether people want the product, before building more.

## What you need

- A laptop or small server to run the organizer node (Docker).
- Each participant runs a node once to generate an identity, then sends the
  organizer their public keys (out of band — a group chat is fine).
- A chosen area (park, campus, festival) with 3–6 locations.

## Organizer

```bash
BIN="keepstone --data-dir ./org"
$BIN keygen
$BIN id                      # share these keys with participants so they can add you

# For each participant, add them as a contact with the keys they sent you:
$BIN contact-add alice <signing> <ecdh> <hybrid>
$BIN contact-add bob   <signing> <ecdh> <hybrid>

# Define the hunt:
$BIN hunt create demo
$BIN hunt add-participant demo alice
$BIN hunt add-participant demo bob
$BIN hunt add-drop demo --lat 51.5007 --lng -0.1246 --suite hybrid "Find the lion statue"
$BIN hunt add-drop demo --lat 51.5010 --lng -0.1250 "Count the benches"

# Create the drops (one per location, addressed to every participant):
$BIN hunt seed demo
$BIN hunt show demo          # ids + clues
$BIN hunt map demo --out map.html   # printable map for the organizer
```

Distribute the drop locations/ids to participants (the `map.html` is for you;
send participants the clues and let them walk).

## Participants

```bash
BIN="keepstone --data-dir ./me"
$BIN keygen
$BIN id                      # send to the organizer

# Add the organizer as a contact (from their `id` output):
$BIN contact-add organizer <signing> <ecdh> <hybrid>

# Once drops are reachable (relay fetch, or a copied data dir):
$BIN fetch <relay-host>:7777 <id>
$BIN drop-open <id>
```

Or point a browser at the daemon (`keepstone-daemon --data-dir ./me`) and use
the UI.

## One-command deployment

```bash
docker compose -f deploy/docker-compose.yml up --build
# relay on :7777, browser client on http://127.0.0.1:8787
```

## What to measure

- **Activation:** did each participant open at least one drop?
- **Completion:** did groups finish the hunt?
- **Friction:** where did onboarding stall (key exchange, fetching, opening)?
- **Qualitative:** would they do it again? What did they expect that was missing?

## Honest limits

- Location is **best-effort defense in depth**, not proof: GPS can be spoofed.
- The code is **not independently audited**.
- Delivery is best-effort; run a relay so drops survive participants arriving
  later.
