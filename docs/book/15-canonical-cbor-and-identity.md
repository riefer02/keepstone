# 15. Canonical CBOR and byte-preservation identity

Two rules govern every byte on the wire, and explain why the format is
hand-rolled.

## Rule 1 — canonical encoding

When you **sign** structured data, you sign *bytes*. If the same structure can
encode to different bytes, a signature over one encoding fails against a
re-encoding of the "same" object — forgery and interop pain.

Canonical CBOR gives exactly **one** valid encoding per value. Keepstone's strict
subset ([`cbor.rs`](../../crates/core/src/cbor.rs)) supports unsigned integers
(shortest-form heads), byte strings, UTF-8 text strings, arrays and maps
(definite lengths only), and booleans. Decoders **must reject non-canonical
input**: over-long heads, trailing bytes, unknown structures
([ADR-0002](../DECISIONS.md)).

```
   value           canonical bytes
   0               0x00
   23              0x17
   24              0x18 0x18
   1000            0x19 0x03 0xE8
   [1, 2, 3]       0x83 0x01 0x02 0x03
   "hi"            0x62 0x68 0x69
```

The decoder tracks bytes consumed and calls `finish()` to assert nothing is left.

## Rule 2 — byte-preservation identity

> **A drop's id is `SHA-256` of the exact transmitted envelope bytes, and
> signature verification runs over the preserved payload bytes — never a
> re-encoding.**

`SignedDrop` carries a `raw: Vec<u8>` field of the exact received bytes,
alongside the decoded `payload`. Every operation uses the preserved bytes:

```
   received bytes ──▶ decode ──▶ SignedDrop { payload, raw, ... }
                                      │        │
                        id() = H(raw)─┘        │
                        verify() over signing_input(payload) ─┘
```

Why it matters:

- A decode/re-encode can never change an **id** (content addressing stays stable
  across encoder changes).
- A decode/re-encode can never invalidate a **signature** (you verify the
  author's bytes, not your encoder's idea of them).
- It kills malleability: if a decoder normalized anything, two byte strings
  would map to one object with one id.

Test: `signed_drop_verifies_and_hashes_exact_bytes`.

## How the envelope uses both

The envelope's `payload` field **contains** the canonical `DropBody` bytes.
Verification signs over those stored bytes:

```
signing_input = "keepstone/v1/drop" || len_be32(payload) || payload
```

The domain prefix prevents cross-context replay; the length prefix removes
ambiguity about where the payload ends.

## For an implementer

1. Encode canonically; reject anything non-canonical.
2. Hash and verify over received bytes, never a re-encoding.
3. Domain-separate every signed context with `"keepstone/v1/..."`.

Break any of these and you either fail interop or open a malleability hole.

## Go look at this

- [`crates/core/src/cbor.rs`](../../crates/core/src/cbor.rs) — encoder/decoder
- [`crates/core/src/types.rs`](../../crates/core/src/types.rs) — `SignedDrop`, `signing_input`, `id`
- [`docs/SPEC.md`](../SPEC.md) §1 — conventions
- Tests: `body_round_trips_canonically`, `signed_drop_verifies_and_hashes_exact_bytes`

Next: [Anatomy of a drop](16-anatomy-of-a-drop.md)
