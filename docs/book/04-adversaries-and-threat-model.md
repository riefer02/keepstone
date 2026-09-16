# 4. Adversaries and the threat model

Security claims are meaningless without naming who you're defending against.
This chapter is the plain-language version of
[`docs/THREAT_MODEL.md`](../THREAT_MODEL.md).

## What we're protecting

- **Content** — the messages and files inside drops.
- **Key material** — the per-drop content keys and long-term identity keys.
- **Metadata** — which device is near which cell, and the patterns of who
  fetches what, when.

## Who we're defending against

| Adversary | Can do | Keepstone's answer |
|---|---|---|
| Other users without keys | Fetch ciphertext | Cannot read it (Lock 1) |
| Untrusted relays / log nodes | Store, drop, reorder, inspect | Hold ciphertext only; no keys, no plaintext |
| Network observers | Watch traffic, see bytes | Ciphertext only; recipients unnamed on the wire |
| Forgers | Fabricate or alter a drop | Ed25519 (+ ML-DSA-65) signature over canonical bytes; tamper fails |
| Rewriters | Rewrite log history | Inclusion + consistency proofs, signed tree heads, equivocation detection, external anchoring |
| Spammers / flooders | Create drops cheaply | Per-drop proof-of-work bound to signer + content |
| Sybil witnesses / GPS spoofers | Fake presence (place-locked) | k-of-n with distinct witnesses — but explicitly best-effort |
| Abusers and harassers | Target people by location | Location is access, not discovery; no global index; recipient allowlist |
| Legal process | Demand data from a server | No hosted server required; relays hold ciphertext they cannot read |

## What is guaranteed

- **Confidentiality** — content is encrypted under a per-drop content key,
  sealed to recipient device keys. Relays and logs hold ciphertext only.
- **Integrity / authenticity** — the author's signature covers the canonical
  payload; each chunk is AEAD-authenticated; the chunk count and order are bound
  into the AAD (encryption associated data), so truncation and reordering fail.
- **Tamper-evidence** — drops commit to an RFC 6962 Merkle log with signed tree
  heads; history can't be silently rewritten without detection.

## What is explicitly **not** guaranteed

- **Metadata.** Who is near which cell, and fetch/subscription patterns. This is
  *partially* mitigated by k-anonymous cell lookups — a query for a cell is
  hidden among its neighbours — but that is k-anonymity, **not** cryptographic
  PIR. It raises the cost of linkage; it does not eliminate it.
- **Endpoint compromise.** If your device is owned, the keys are the attacker's.
- **Availability.** No durability guarantee yet; federation improves the odds.
- **Proof of physical location.** Place-locked mode is best-effort defense in
  depth. GPS can be spoofed and witnesses can be Sybil.
- **Audit.** No independent audit yet.

## Three invariants worth memorising

These show up again and again in the code and tests:

1. **The recipient key is the lock.** Location is an access gate and delivery
   hint — never the confidentiality guarantee.
2. **Identity is `H(exact transmitted bytes)`.** A decode/re-encode must never
   change a signature or an id. This is the *byte-preservation* rule
   ([Chapter 15](15-canonical-cbor-and-identity.md)).
3. **Secrets are zeroized on drop and redacted from `Debug`.** Key material must
   not linger in memory or leak into logs.

## Go look at this

- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — the canonical statement
- [`docs/ABUSE.md`](../ABUSE.md) — abuse mitigations and what can't be done
- [`crates/crypto/src/secret.rs`](../../crates/crypto/src/secret.rs) — zeroizing buffers

Next: [Build, run, and the quality gate](05-build-run-gate.md)
