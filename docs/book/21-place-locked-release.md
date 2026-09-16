# 21. Place-locked release

Earlier chapters protect *who* can read a drop. Place-locked mode gates *when and
where* the content key is released: the key is split across cell custodians and
reassembled only for a claimant who proves presence. Best-effort defense in
depth, stated as such.

## The two pieces

1. **Presence certificates** — signed evidence, from independent witnesses, that
   a claimant was near a cell at a time.
2. **Shamir custodians** — the key is `t`-of-`n` split; each custodian releases
   its share only for a valid certificate.

## Presence

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
`rtt_bucket` and a timestamp. The claimant collects them into a `PresenceCert`.

Networked collection: reference TCP (`serve_witness` / `request_presence`) and
libp2p (`serve_witness_cell` / `request_presence`).

## What makes a certificate valid

`PresenceCert::verify(threshold)`, or `verify_at(threshold, now)` to also check
expiry, checks all of:

1. every attestation matches the request (cell, nonce, claimant) — no replay
   across requests,
2. each witness signature verifies,
3. witnesses are **distinct** — one witness can't count thrice,
4. the count meets the threshold (`DEFAULT_THRESHOLD = 3`),
5. the certificate hasn't expired.

Fail any one and it's rejected.

## Release via custodians

The content key is split `t`-of-`n` ([Chapter 18](18-multi-recipient-and-shamir.md));
each share is sealed to a custodian ([`place.rs`](../../crates/core/src/place.rs),
`seal`/`open`). A custodian releases its share only for a valid `PresenceCert`.

```
   claimant ──PresenceRequest──▶ witnesses ──attestations──▶ PresenceCert
                                                                  │
                                             custodian 1..n: verify cert, release share
                                                                  │
                                                     any t shares reconstruct K
```

## The honest limitation

This is **defense in depth, not proof of location**:

- **GPS can be spoofed.**
- **Witnesses can be Sybil** — a resourced attacker can manufacture a
  certificate.
- `rtt_bucket` is a coarse signal, not a cryptographic distance bound.

Place-locking is friction and a second lock, never the confidentiality
guarantee. That guarantee remains the recipient's key. The threat model says so;
so does this book, on purpose.

## Go look at this

- [`crates/core/src/presence.rs`](../../crates/core/src/presence.rs) — request, attestation, `PresenceCert::verify`
- [`crates/core/src/place.rs`](../../crates/core/src/place.rs) — custodian share seal/open
- [`crates/node/src/lib.rs`](../../crates/node/src/lib.rs) — `serve_witness`, `request_presence`
- [`crates/p2p/src/lib.rs`](../../crates/p2p/src/lib.rs) — `serve_witness_cell`, `request_presence`
- [`docs/SPEC.md`](../SPEC.md) §12–§13

Next: [Federated relays and STH gossip](22-federated-relays-and-gossip.md)
