# 21. Place-locked release

Everything so far protects *who* can read a drop. Place-locked mode adds a
gate on *when and where* the content key is released: the key is split across
cell custodians and only reassembled when a claimant proves presence. It is
best-effort defense in depth, and the design says so out loud.

## The two pieces

1. **Presence certificates** — evidence, signed by independent witnesses, that
   a claimant was near a cell at a time.
2. **Shamir custodians** — the content key is `t`-of-`n` split; each custodian
   releases its share only for a valid presence certificate.

Together: no single party can unlock the drop, and the key material only becomes
available to someone who showed up.

## Presence: request and attestation

```
PresenceRequest     = [ cell:text, nonce:bytes(16), claimant:bytes(32), expiry:uint ]

attestation_input   = "keepstone/v1/presence"
                      || len_be32(cell) || cell
                      || nonce || claimant || rtt_bucket:u8 || timestamp_be64

PresenceAttestation = [ cell, nonce, claimant, rtt_bucket, timestamp,
                        witness:bytes(32), signature:bytes(64) ]
```

A claimant broadcasts a request with a fresh `nonce`. Each nearby **witness**
signs an attestation over `attestation_input`, including their measured
`rtt_bucket` (a coarse round-trip-time bucket) and a timestamp. The claimant
collects attestations into a `PresenceCert`.

Networked collection is available over both transports:

- reference TCP: `serve_witness` (server side) and `request_presence` (client),
- libp2p: `serve_witness_cell` / `request_presence`.

## What makes a certificate valid

`PresenceCert::verify(threshold)` — or `verify_at(threshold, now)` to also check
expiry against a supplied clock — checks all of:

1. **Every attestation matches the request** (same cell, nonce, claimant) — you
   can't replay an attestation from a different request.
2. **Each witness signature verifies** against that witness's key.
3. **Witnesses are distinct** — one witness can't count three times.
4. **The count meets the threshold** (`DEFAULT_THRESHOLD = 3`).
5. **The certificate hasn't expired.**

Fail any one and the certificate is rejected.

## Release via custodians

The content key `K` is split `t`-of-`n` (Shamir over GF(256),
[Chapter 18](18-multi-recipient-and-shamir.md)). Each share is sealed to a
different custodian (`crates/core/src/place.rs`, `seal`/`open`). A custodian
releases its share only when presented a valid `PresenceCert`.

```
   claimant ──PresenceRequest──▶ witnesses ──attestations──▶ PresenceCert
                                                                  │
                                                                  ▼
                                             custodian 1..n: verify cert, release share
                                                                  │
                                                                  ▼
                                                     any t shares reconstruct K
```

## The honest limitation

This is **defense in depth, not proof of location**:

- **GPS can be spoofed.** A determined attacker can fake coordinates.
- **Witnesses can be Sybil.** A well-resourced attacker can run many witnesses
  and manufacture a certificate.
- `rtt_bucket` is a coarse signal, not a cryptographic distance bound.

The design treats place-locking as **friction and a second lock**, never as the
confidentiality guarantee. That guarantee remains the recipient's key. This is
stated in the threat model and repeated here on purpose — it's the kind of claim
that projects oversell, and Keepstone refuses to.

## Go look at this

- [`crates/core/src/presence.rs`](../../crates/core/src/presence.rs) — request, attestation, `PresenceCert::verify`
- [`crates/core/src/place.rs`](../../crates/core/src/place.rs) — custodian share seal/open
- [`crates/node/src/lib.rs`](../../crates/node/src/lib.rs) — `serve_witness`, `request_presence`
- [`crates/p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) — `serve_witness_cell`, `request_presence`
- [`docs/SPEC.md`](../SPEC.md) §12–§13

Next: [Federated relays and STH gossip](22-federated-relays-and-gossip.md)
