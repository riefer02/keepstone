# Abuse & Harm Mitigation

Anonymous, location-addressed messaging can be abused. This document records the
mitigations we build and the ones we cannot.

## Strongest structural mitigation

Location is **access, not discovery** (ADR-0005). There is no way to browse or
search for drops by location; the author must tell the recipient where to look.
This removes opportunistic abuse and a large class of metadata leakage.

## Controls

- **Recipient opt-in / allowlist** — by default, no drops from unknown
  identities. (M1: contacts are explicitly added by public key exchange.)
- **Rate limits / proof-of-work** on drop creation and presence requests. (M2+)
- **No exact coordinates** are displayed to recipients; cell + approximate only.
- **Blocking** — refuse future drops from an identity. (M1: remove the contact.)
- **Expiry enforced** — drops carry a TTL; expired drops must not be served.
- **Per-cell creation limits** to blunt brigading. (M2+)

## What we cannot do

- We cannot scan end-to-end encrypted content. There is no server-side content
  moderation by design.
- We cannot prevent an authorized recipient from misusing content they can read.

## Reporting

Because payloads are end-to-end encrypted, reports are necessarily
metadata-level (identity, timing, location context). A reporting channel and
policy are required before any hosted infrastructure exists (see the legal
posture in the project plan).
