# Security Policy

Keepstone is privacy infrastructure, so we take vulnerability reports seriously.
Thank you for helping keep users safe.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.**

Preferred: use GitHub's private vulnerability reporting —
[**Report a vulnerability**](https://github.com/riefer02/keepstone/security/advisories/new).
This keeps the report private and lets us coordinate a fix and an advisory.

If you cannot use GitHub advisories, email **andrew.riefenstahl@gmail.com** with
`[keepstone security]` in the subject. Encrypt if you can; ask for a key first.

Please include, where possible:

- A description of the issue and its impact.
- Affected component (crate, file, or CLI command) and version/commit.
- Reproduction steps or a proof of concept.
- Any suggested mitigation.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment (severity, affected scope) within 7 business days.
- Coordinated disclosure: we aim to ship a fix and publish an advisory within
  **90 days** of a confirmed report, sooner for high-severity issues.
- Credit in the advisory unless you ask to remain anonymous.

This is an unfunded, pre-release project maintained on a best-effort basis. We
will be honest if we cannot meet these timelines.

## Scope

**In scope** — anything that breaks the guarantees in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/CLAIMS.md](docs/CLAIMS.md):

- Content confidentiality or integrity: reading or forging a drop without the
  intended recipient/author keys.
- Cryptographic misuse: nonce/key reuse, weak randomness, broken sealed boxes,
  chunked-AEAD truncation/reordering, Shamir or presence-certificate flaws.
- Signature or log flaws: bypassing author signatures, forging or equivocating
  signed tree heads, invalid Merkle inclusion/consistency proofs.
- Parser/serialization flaws on untrusted input (envelope, protocol, presence)
  that cause memory-safety issues, panics, or acceptance of non-canonical data.
- Authentication/authorization flaws in the daemon API.

**Out of scope** (documented non-guarantees — see the threat model):

- Metadata leakage (who is near which cell; subscription/fetch patterns).
- Endpoint compromise (a device whose keys are stolen).
- Availability / denial of service.
- Proof of physical location in place-locked mode.
- Anything requiring an already-compromised trusted device.

## Supported versions

Keepstone is **pre-release (0.0.x)** and has **not been independently audited**.
There are no supported release branches yet; fixes land on `main`. Do not rely on
this code for high-stakes confidentiality until it has been audited.

## Safe harbor

We will not pursue or support legal action against researchers who:

- Act in good faith and follow this policy.
- Only test against their own devices, data, and deployments — never other
  people's data or infrastructure.
- Avoid privacy violations, data destruction, and service disruption.
- Give us reasonable time to fix the issue before public disclosure.
