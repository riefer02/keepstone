# 10. The browser client and the daemon API

Not everyone wants a terminal. `keepstone-daemon` is a tiny local HTTP/JSON
server that turns the same data directory into a browser UI. It is a **thin
client to the local node** — it holds only the local device's keys and never
exposes plaintext without them.

## Run it

```bash
cargo build -p keepstone-daemon
./target/debug/keepstone-daemon --data-dir ./demo/alice --listen 127.0.0.1:8787
# open http://127.0.0.1:8787
```

The UI lists nearby drops, creates drops (classical or post-quantum), opens
them, and verifies log inclusion — all by calling the JSON API below.

## The API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | the embedded single-page UI |
| `GET` | `/api/id` | this node's public keys |
| `GET` | `/api/contacts` | contacts (with devices) |
| `POST` | `/api/contacts` | add a contact device |
| `GET` | `/api/drops?lat&lng&ring` | list drops (optionally near a point) |
| `POST` | `/api/drops` | create a drop |
| `GET` | `/api/drops/{id}` | drop metadata |
| `POST` | `/api/drops/{id}/open` | decrypt a drop |
| `GET` | `/api/log/{id}/verify` | signature + inclusion + STH checks |

Example:

```bash
curl -s localhost:8787/api/id
curl -s -X POST localhost:8787/api/drops \
  -H 'content-type: application/json' \
  -d '{"to":["bob"],"lat":51.5,"lng":-0.12,"suite":"hybrid","message":"hi"}'
```

## Token auth

By default the daemon is for `127.0.0.1` only. If you bind it more widely, set a
bearer token:

```bash
keepstone-daemon --data-dir ./alice --listen 0.0.0.0:8787 --token "$(openssl rand -hex 16)"
# then open http://<host>:8787/?token=<the-token>
```

When a token is configured, **every** `/api/*` route requires
`Authorization: Bearer <token>`; the UI reads it from the `?token=` query
parameter. `--token` or the `KEEPSTONE_TOKEN` environment variable both work.

## How it's built (and why it looks unusual)

The daemon does **not** use a web framework. It is a hand-written HTTP/1.1
server: parses the request line, headers, and a `Content-Length` body, routes on
`(method, path)`, and replies with `Connection: close`. It serves one embedded
HTML file and a handful of JSON routes. The reasoning is in
[ADR-0012](../DECISIONS.md): a framework would drag in a large dependency tree
for a few localhost routes.

Two consequences worth knowing:

- It is **not** a general-purpose server: no keep-alive, no chunked encoding, no
  TLS. Put it behind a proxy if you need those.
- All the real work is delegated to the shared `keepstone-store` library, so the
  daemon and the CLI can never disagree about the on-disk format
  ([Chapter 24](24-the-store-and-data-dir.md)).

## Go look at this

- [`crates/daemon/src/main.rs`](../../crates/daemon/src/main.rs) — server + handlers + tests
- [`crates/daemon/web/index.html`](../../crates/daemon/web/index.html) — the UI
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — token auth and deployment notes

Next: [Running a hunt](11-running-a-hunt.md)
