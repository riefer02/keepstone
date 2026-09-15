# Deploying Keepstone

A self-contained relay + browser client, useful for running a local event hunt
or a small federated deployment.

## Quickstart

```bash
docker compose -f deploy/docker-compose.yml up --build
# open http://127.0.0.1:8787
```

The relay listens on `127.0.0.1:7777` (ciphertext only). The browser UI talks to
the local daemon on `8787` and can create, list, open, and verify drops.

## What runs

| Service | Command | Holds |
|---|---|---|
| `relay` | `keepstone serve --listen 0.0.0.0:7777` | ciphertext only, no keys |
| `daemon` | `keepstone-daemon --listen 0.0.0.0:8787` | the local identity's keys |

Both share one image built from the repository root (`deploy/Dockerfile`). The
`entrypoint.sh` generates an identity on first run if the data volume is empty.

## Pushing and fetching

```bash
# From a node with a drop and the relay reachable:
docker compose -f deploy/docker-compose.yml exec daemon \
  keepstone --data-dir /data push relay:7777 <id>
```

## Notes

- Bind to `127.0.0.1` for local use; expose to a LAN only deliberately.
- The image runs as a non-root user (uid 10001).
- Not independently audited. Treat as research-grade.
