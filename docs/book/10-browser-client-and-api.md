# 10. The browser client and the daemon API

`keepstone-daemon` is a local HTTP/JSON server that turns the same data
directory into a browser UI. It is a thin client to the local node: it holds
only the local device's keys and never exposes plaintext without them.

## Run it

```bash
cargo build -p keepstone-daemon
./target/debug/keepstone-daemon --data-dir ./demo/alice --listen 127.0.0.1:8787
# open http://127.0.0.1:8787
```

The UI lists nearby drops, creates drops (classical or PQ), opens them, and
verifies log inclusion.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | embedded UI |
| `GET` | `/api/id` | this node's public keys |
| `GET` | `/api/contacts` | contacts (with devices) |
| `POST` | `/api/contacts` | add a contact device |
| `GET` | `/api/drops?lat&lng&ring` | list drops (optionally near a point) |
| `POST` | `/api/drops` | create a drop |
| `GET` | `/api/drops/{id}` | drop metadata |
| `POST` | `/api/drops/{id}/open` | decrypt a drop |
| `GET` | `/api/log/{id}/verify` | signature + inclusion + STH checks |

```bash
curl -s localhost:8787/api/id
curl -s -X POST localhost:8787/api/drops \
  -H 'content-type: application/json' \
  -d '{"to":["bob"],"lat":51.5,"lng":-0.12,"suite":"hybrid","message":"hi"}'
```

## Token auth

Default is `127.0.0.1` only. To bind wider, set a bearer token:

```bash
keepstone-daemon --data-dir ./alice --listen 0.0.0.0:8787 --token "$(openssl rand -hex 16)"
# open http://<host>:8787/?token=<the-token>
```

With a token set, every `/api/*` route requires
`Authorization: Bearer <token>`; the UI reads it from `?token=`. `--token` or
`KEEPSTONE_TOKEN` both work.

## How it's built

No web framework. A hand-written HTTP/1.1 server (request line, headers,
`Content-Length` body, `(method, path)` routing, `Connection: close`), one
embedded HTML file, a few JSON routes ([ADR-0012](../DECISIONS.md)). Two
consequences:

- Not general-purpose: no keep-alive, no chunked encoding, no TLS. Put it behind
  a proxy if you need those.
- All real work is delegated to `keepstone-store`, so CLI and daemon can't
  disagree about the on-disk format ([Chapter 24](24-the-store-and-data-dir.md)).

## Go look at this

- [`crates/daemon/src/main.rs`](../../crates/daemon/src/main.rs) — server + handlers + tests
- [`crates/daemon/web/index.html`](../../crates/daemon/web/index.html) — the UI
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — token auth, deployment

Next: [Running a hunt](11-running-a-hunt.md)
