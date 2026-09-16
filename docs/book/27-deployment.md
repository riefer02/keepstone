# 27. Deployment

The `deploy/` directory has everything needed to run a relay and a browser
client with one command. It's a small, honest deployment kit, not a
production-grade orchestration story.

## One command

```bash
docker compose -f deploy/docker-compose.yml up --build
# relay on 127.0.0.1:7777, browser UI on http://127.0.0.1:8787
```

The compose file has two services, both built from the same image:

- **`relay`** runs `keepstone serve --listen 0.0.0.0:7777` — holds ciphertext
  only, no keys.
- **`daemon`** runs `keepstone-daemon --listen 0.0.0.0:8787` — the browser
  client, holding only the local identity's keys.

Each gets its own named volume (`relay-data`, `daemon-data`) for its data
directory, so state survives rebuilds.

## The image

`deploy/Dockerfile` is a two-stage build:

- **Builder:** `rust:1.88-bookworm`, `cargo build --release --locked` for the CLI
  and daemon.
- **Runtime:** `debian:bookworm-slim`, a **non-root** user (`uid 10001`), the two
  binaries, the entrypoint, and a `/data` volume owned by that user.

```
FROM rust:1.88-bookworm AS builder       # compile
        │
        ▼
FROM debian:bookworm-slim                # run
  useradd --uid 10001 keepstone
  COPY keepstone, keepstone-daemon, entrypoint.sh
  USER keepstone
  VOLUME /data
  ENTRYPOINT ["entrypoint.sh"]
```

Running as non-root matters: a compromised daemon shouldn't be root in the
container.

## First-run identity

`deploy/entrypoint.sh` ensures the data directory has an identity before running
the requested command:

```sh
DATA="${KEEPSTONE_DATA:-/data}"
mkdir -p "$DATA"
if [ ! -f "$DATA/identity.txt" ]; then
    keepstone --data-dir "$DATA" keygen >/dev/null
    echo "keepstone: generated identity in $DATA"
fi
exec "$@"
```

So the first `up` generates a device identity automatically; subsequent runs
reuse it. The image holds no keys beyond those generated locally.

## What this is not

- No TLS termination, no reverse proxy, no secret management — put it behind
  your own proxy and set `--token` if you expose the daemon beyond localhost.
- No replication or backup policy — the relay's volume is the only copy unless
  you add one.
- Not hardened for hostile multi-tenant use.

## Beyond compose

Every component is a normal binary you can run directly (see
[`docs/OPERATIONS.md`](../OPERATIONS.md)): the CLI for scripts, the daemon for a
UI, `serve` for a relay, `sth-serve` for a log node. Docker just wires two of
them together with a first-run identity.

## Go look at this

- [`deploy/docker-compose.yml`](../../deploy/docker-compose.yml)
- [`deploy/Dockerfile`](../../deploy/Dockerfile)
- [`deploy/entrypoint.sh`](../../deploy/entrypoint.sh)
- [`deploy/README.md`](../../deploy/README.md)

Next: [How it's tested](28-how-its-tested.md)
