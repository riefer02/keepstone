# 25. Security summary

The shortest honest summary. The canonical version, every claim mapped to
evidence, is [`docs/CLAIMS.md`](../CLAIMS.md).

## Covered

| Property | Mechanism |
|---|---|
| Only the intended recipient can read | Per-drop content key sealed to recipient devices (X25519 / hybrid) |
| Recipients aren't named in cleartext | 8-byte tags from recipient key + drop nonce; padded with decoys to ≥16 slots |
| No server can read it | Relays/log nodes hold ciphertext only, no keys |
| The author can't be impersonated | Ed25519 (or + ML-DSA-65) signature over canonical payload |
| Content can't be truncated/reordered | Chunk count and index bound in the AEAD AAD |
| Anyone can verify a drop existed | RFC 6962 inclusion proof + STH; offline `verify` |
| History can't be silently rewritten | Consistency proofs, equivocation detection, anchoring (hash chain / Bitcoin) |
| Flooding costs work | PoW bound to signer + content |
| Resistant to a quantum adversary | Hybrid X25519 + ML-KEM-768 sealing and Ed25519 + ML-DSA-65 signatures; sound if either holds |
| Only when they're there (best-effort) | k-of-n presence certificates, distinct witnesses, Shamir custodians |

## Not covered

| Non-guarantee | Reality |
|---|---|
| **Metadata** | Who is near which cell, fetch patterns. Partially mitigated by k-anonymous lookups — **not** PIR |
| **Endpoint compromise** | If your device is owned, your keys are the attacker's |
| **Availability** | No durability guarantee; federation is best-effort |
| **Proof of physical location** | GPS spoofable, witnesses Sybil-able — defense in depth |
| **Anonymity** | Not an anonymity network; layer over Tor if needed |
| **Audit** | Not independently audited |

## Three invariants

1. **The recipient key is the lock.** Location is an access gate, never the
   confidentiality guarantee.
2. **Identity is `H(exact transmitted bytes)`.** A decode/re-encode changes
   neither a signature nor an id.
3. **Secrets zeroize on drop and are redacted from `Debug`.**

## The posture

Keepstone is a tool for *confidentiality and verifiability*, not anonymity or
availability. It keeps its promise — no one but your recipient can read a drop,
and anyone can check it existed — by leaning entirely on well-understood
cryptography and a transparent log. Everything location-related is friction and
defense in depth, labelled as such. It has not been audited; treat it as
research-grade.

## Go look at this

- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md)
- [`docs/CLAIMS.md`](../CLAIMS.md) — claim → evidence
- [`docs/ABUSE.md`](../ABUSE.md)

Next: [Anchoring trust](26-anchoring-trust.md)
