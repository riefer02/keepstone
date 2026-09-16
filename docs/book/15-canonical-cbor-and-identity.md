# 15. Canonical CBOR and byte-preservation identity

Two ideas govern every byte Keepstone puts on the wire, and they are the reason
the format is hand-rolled rather than pulled from a library.

## Idea 1 — canonical encoding

When you **sign** structured data, you sign *bytes*. If two programs can encode
the same structure into different bytes, a signature over one encoding won't
verify against a re-encoding of the "same" object — a recipe for forgery and
interoperability pain.

Canonical CBOR removes the ambiguity: for any given value there is exactly
**one** valid encoding. Keepstone implements a small, strict subset in
`crates/core/src/cbor.rs`:

- unsigned integers (shortest-form heads),
- byte strings,
- text strings (UTF-8),
- arrays and maps (definite lengths only — **no indefinite lengths**),
- booleans.

Decoders **must reject non-canonical input**: over-long integer heads, trailing
bytes after the top-level value, unknown structures. This is
[ADR-0002](../DECISIONS.md).

```
   value           canonical bytes
   ─────           ───────────────
   0              0x00
   23             0x17
   24             0x18 0x18
   1000           0x19 0x03 0xE8
   [1, 2, 3]      0x83 0x01 0x02 0x03
   "hi"           0x62 0x68 0x69
```

The decoder tracks exactly how many bytes it consumed and calls `finish()` to
assert there is nothing left over.

## Idea 2 — byte-preservation identity

This is the more important one, and it is a single rule:

> **A drop's id is `SHA-256` of the exact transmitted envelope bytes, and
> signature verification runs over the preserved payload bytes — never over a
> re-encoding.**

Concretely, `SignedDrop` carries a `raw: Vec<u8>` field holding the exact bytes
it was received as, alongside the decoded `payload`. Every operation uses those
preserved bytes:

```
   received bytes ──▶ decode ──▶ SignedDrop { payload, raw, ... }
                                      │        │
                        id() = H(raw)─┘        │
                        verify() signs over signing_input(payload) ─┘
```

Why this matters:

- **A decode/re-encode can never change an id.** Content addressing stays stable
  even if the encoder changes in a future version.
- **A decode/re-encode can never invalidate a signature.** You verify the bytes
  the author actually signed, not what your encoder thinks they should be.
- **It kills a class of malleability bugs.** If a decoder normalized anything,
  two different byte strings would map to the same object with the same id —
  exactly what an attacker wants.

The test `signed_drop_verifies_and_hashes_exact_bytes` pins this down: decode a
signed drop, and assert the decoded copy has the same id and still verifies.

## How the envelope uses both

The envelope's `payload` field literally **contains** the canonical `DropBody`
bytes. Verification does not rebuild the body and re-encode it; it signs
`signing_input(payload)` over the stored bytes:

```
signing_input = "keepstone/v1/drop" || len_be32(payload) || payload
```

Domain separation (`"keepstone/v1/drop"`) ensures a signature can't be replayed
in another context. The length prefix prevents ambiguity about where the payload
ends.

## The rules, stated for an implementer

1. Encode canonically; reject anything non-canonical.
2. Hash and verify over received bytes, never a re-encoding.
3. Domain-separate every signed context with a `"keepstone/v1/..."` prefix.

Break any of these and you either fail interoperability or open a
malleability hole.

## Go look at this

- [`crates/core/src/cbor.rs`](../../crates/core/src/cbor.rs) — the encoder/decoder
- [`crates/core/src/types.rs`](../../crates/core/src/types.rs) — `SignedDrop`, `signing_input`, `id`
- [`docs/SPEC.md`](../SPEC.md) §1 — the conventions
- Tests: `body_round_trips_canonically`, `signed_drop_verifies_and_hashes_exact_bytes`

Next: [Anatomy of a drop](16-anatomy-of-a-drop.md)
