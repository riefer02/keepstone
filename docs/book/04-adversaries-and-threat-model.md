# 4. Adversaries and the threat model

Plain-language version of [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md).

## Assets

- **Content** — messages and files in drops.
- **Key material** — per-drop content keys and long-term identity keys.
- **Metadata** — which device is near which cell; who fetches what, when.

## Adversaries and answers

| Adversary | Can do | Keepstone's answer |
|---|---|---|
| Users without keys | Fetch ciphertext | Can't read it (Lock 1) |
| Untrusted relays / log nodes | Store, drop, reorder, inspect | Ciphertext only; no keys, no plaintext |
| Network observers | Watch traffic | Ciphertext only; recipients unnamed on the wire |
| Forgers | Fabricate or alter a drop | Ed25519 (+ ML-DSA-65) over canonical bytes; tamper fails |
| Rewriters | Rewrite log history | Inclusion + consistency proofs, STHs, equivocation detection, anchoring |
| Spammers | Flood drops | Per-drop proof-of-work bound to signer + content |
| Sybil witnesses / GPS spoofers | Fake presence | k-of-n distinct witnesses — but best-effort only |
| Abusers | Target by location | Location is access, not discovery; no global index; allowlist |
| Legal process | Demand server data | No hosted server required; relays can't read |

## Guaranteed

- **Confidentiality** — content encrypted under a per-drop key, sealed to
  recipient device keys; relays and logs hold ciphertext only.
- **Integrity / authenticity** — author signature covers the canonical payload;
  each chunk is AEAD-authenticated; count and order bound into the AAD, so
  truncation and reordering fail.
- **Tamper-evidence** — drops commit to an RFC 6962 Merkle log with signed tree
  heads.

## Explicitly not guaranteed

- **Metadata** — who is near which cell, fetch patterns. Partially mitigated by
  k-anonymous lookups (k-anonymity, **not** PIR). Raises linkage cost; doesn't
  eliminate it.
- **Endpoint compromise** — if your device is owned, the keys are the attacker's.
- **Availability** — no durability guarantee; federation is best-effort.
- **Proof of physical location** — place-locked mode is best-effort.
- **Audit** — none yet.

## Three invariants

1. **The recipient key is the lock.** Location is an access gate and delivery
   hint, never the confidentiality guarantee.
2. **Identity is `H(exact transmitted bytes)`.** A decode/re-encode changes
   neither a signature nor an id ([Chapter 15](15-canonical-cbor-and-identity.md)).
3. **Secrets are zeroized on drop and redacted from `Debug`.**

## Go look at this

- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — canonical statement
- [`docs/ABUSE.md`](../ABUSE.md) — mitigations and limits
- [`crates/crypto/src/secret.rs`](../../crates/crypto/src/secret.rs) — zeroizing buffers

Next: [Build, run, and the quality gate](05-build-run-gate.md)
