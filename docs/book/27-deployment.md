# 27. Deployment

`deploy/` runs a relay and a browser client with one command. A small, honest
kit — not a production orchestration story.

## One command

```bash
docker compose -f deploy/docker-compose.yml up --build
# relay on 127.0.0.1:7777, browser UI on http://127.0.0.1:8787
```

Two services, one image:

- **`relay`** — `keepstone serve --listen 0.0.0.0:7777`, ciphertext only, no keys.
- **`daemon`** — `keepstone-daemon --listen 0.0.0.0:8787`, browser client holding
  only the local identity's keys.

Each gets its own named volume (`relay-data`, `daemon-data`).

## The image

Two-stage build (`deploy/Dockerfile`):

- **Builder:** `rust:1.88-bookworm`, `cargo build --release --locked` for the CLI
  and daemon.
- **Runtime:** `debian:bookworm-slim`, **non-root** user (`uid 10001`), the two
  binaries, the entrypoint, a `/data` volume.

```
FROM rust:1.88-bookworm AS builder       # compile
        ▼
FROM debian:bookworm-slim                # run
  useradd --uid 10001 keepstone
  COPY binaries + entrypoint.sh
  USER keepstone
  VOLUME /data
  ENTRYPOINT ["entrypoint.sh"]
```

Non-root matters: a compromised daemon shouldn't be root in the container.

## First-run identity

`deploy/entrypoint.sh` ensures the data directory has an identity:

```sh
DATA="${KEEPSTONE_DATA:-/data}"
mkdir -p "$DATA"
if [ ! -f "$DATA/identity.txt" ]; then
    keepstone --data-dir "$DATA" keygen >/dev/null
    echo "keepstone: generated identity in $DATA"
fi
exec "$@"
```

The first `up` generates an identity; later runs reuse it. The image holds no
keys beyond those generated locally.

## What this is not

- No TLS, reverse proxy, or secret management — add your own and set `--token`
  if you expose the daemon beyond localhost.
- No replication or backup policy.
- Not hardened for hostile multi-tenant use.

## Beyond compose

Every component is a normal binary (see [`docs/OPERATIONS.md`](../OPERATIONS.md)):
CLI for scripts, daemon for a UI, `serve` for a relay, `sth-serve` for a log
node. Docker just wires two together with a first-run identity.

## Go look at this

- [`deploy/docker-compose.yml`](../../deploy/docker-compose.yml)
- [`deploy/Dockerfile`](../../deploy/Dockerfile)
- [`deploy/entrypoint.sh`](../../deploy/entrypoint.sh)
- [`deploy/README.md`](../../deploy/README.md)

Next: [How it's tested](28-how-its-tested.md)
