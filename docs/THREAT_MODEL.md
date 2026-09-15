# Threat Model (v0.1 — M0/M1)

## Assets

- **Content** of drops (messages and files).
- **Content keys** and long-term identity keys.
- **Metadata**: which device is near which cell, and delivery patterns.

## Adversaries

- Other users without keys.
- Untrusted relays, log nodes, and (later) push operators.
- Network observers.
- Sybil witnesses and GPS spoofers (relevant from M3).
- Abusers and harassers, and legal process.

## Guarantees (M0/M1)

- **Confidentiality:** content is encrypted under a per-drop content key, sealed
  to recipient device X25519 keys. Relays and logs hold ciphertext only.
- **Integrity / authenticity:** author signatures over the canonical payload
  bytes; AEAD authentication per chunk; chunk count and order bound in the AAD.
- **Tamper-evidence:** drops are committed to an RFC 6962 Merkle log with signed
  tree heads.

## Explicit non-guarantees

- **Metadata** (who is near which cell; subscription/fetch patterns).
  Partially mitigated by k-anonymous cell lookups (`find_providers_private`):
  a query for a cell is hidden among its neighbours. This raises the cost of
  linkage but is **not** cryptographic PIR.
- **Endpoint compromise.**
- **Availability** (no durability guarantee yet; M5 federation will address it).
- **Proof of physical location** (place-locked mode is best-effort, from M3).
- The implementation is **not yet independently audited**.

## Notes

- The recipient key is the lock. Location is an access gate and delivery hint;
  it is never the confidentiality guarantee.
- Received objects are identified by `SHA-256(exact transmitted bytes)`; a
  decode/re-encode must never change a signature or an identifier.
- Secrets are zeroized on drop and redacted from `Debug`.
