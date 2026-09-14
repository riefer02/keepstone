# Operations Guide

How to run Keepstone components. All nodes hold **ciphertext only**; they never
see plaintext and hold no recipient keys.

## Data directory

```
<data-dir>/
├── identity.txt     # Ed25519 signing secret + X25519 secret (hex)
├── hybrid.txt       # X25519 || ML-KEM-768 secret (hex)
├── contacts.txt     # name signing ecdh [hybrid] (hex)
├── drops/<id>.signed
├── chunks/<id>/<index>.bin
└── log/
    ├── entries.bin  # length-prefixed drop envelopes
    ├── key.txt      # local log identity
    └── anchors.txt  # anchor receipts
```

## Reference TCP transport

```bash
# Serve drops held locally (ciphertext only).
keepstone --data-dir ./node serve --listen 127.0.0.1:7777

# Fetch a drop and its chunks from a peer, then open it.
keepstone --data-dir ./client fetch 127.0.0.1:7777 <id>
keepstone --data-dir ./client drop-open <id>
```

## libp2p transport (QUIC + TCP, Noise)

```bash
keepstone --data-dir ./node p2p-serve --listen /ip4/0.0.0.0/tcp/7778
keepstone --data-dir ./client p2p-fetch /ip4/<host>/tcp/7778 <id>
```

The libp2p node also subscribes to cell topics (gossipsub) and advertises cell
provider records (Kademlia). `p2p-serve` currently subscribes to no cells; wire
cell subscription to the `keepstone-p2p` library API for discovery.

## Verification and anchoring

```bash
keepstone --data-dir ./node log-verify <id>   # signature + inclusion + STH
keepstone --data-dir ./node log-anchor <id>   # commit the tree head to the chain
keepstone --data-dir ./node log-anchors       # verify chain continuity
```

## Security posture

- No hosted service is required. Relays and log nodes are self-hostable and
  untrusted by design.
- **Not independently audited.** Treat as research-grade until it is.
- Federated relays, multi-device, and post-quantum signatures are planned; see
  `docs/DECISIONS.md`.

## Upgrades

- The wire format is versioned (`DropBody.version`, `CryptoSuite`). Unknown
  suites fail closed.
- Reproducible, signed releases and SBOM generation are planned (cargo-dist).
