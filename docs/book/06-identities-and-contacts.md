# 6. Identities and contacts

## A device identity is two keypairs

When you run `keygen`, Keepstone generates **four** keys, but conceptually an
identity is **two**:

- an **Ed25519** key for **signing** (proves you authored a drop), and
- an **X25519** key for **key agreement** (the "lock" that content keys are
  sealed to).

On top of those, it also generates the **post-quantum** halves so hybrid drops
work out of the box:

- an **X25519 + ML-KEM-768** keypair (hybrid *encryption*), and
- an **ML-DSA-65** keypair (hybrid *signatures*).

```bash
keepstone --data-dir ./alice keygen
keepstone --data-dir ./alice id
```

`id` prints the **public** keys. The hybrid public key is
`32-byte X25519 || ML-KEM-768 encapsulation key` (1184 bytes), so it's long:

```
signing: <64 hex chars>
ecdh:    <64 hex chars>
hybrid:  <~2400 hex chars>
```

`keygen` refuses to overwrite an existing identity: an identity is a long-lived
device secret, not something you regenerate casually.

## Contacts are public keys with a petname

To send a drop to someone, you need their **public** keys, exchanged **out of
band** (a group chat, a business card, a QR code — anything but the network).
There is no key directory and no discovery of keys.

```bash
keepstone --data-dir ./alice contact-add bob <bob-signing> <bob-ecdh> <bob-hybrid>
keepstone --data-dir ./alice contact-list
```

The hybrid key is optional; a contact without one can still receive *classical*
drops but not *hybrid* ones.

## Multiple devices, one person

A contact name can have **several devices** under it. Add the same name again
with a different key pair:

```bash
keepstone --data-dir ./alice contact-add bob <bob-laptop-signing> <bob-laptop-ecdh> <bob-laptop-hybrid>
keepstone --data-dir ./alice contact-add bob <bob-phone-signing>  <bob-phone-ecdh>  <bob-phone-hybrid>
```

You still address the drop with `--to bob`; Keepstone seals the content key to
**every** device under that name, so it opens on each. Adding the exact same
device twice is rejected as a duplicate.

This is the multi-device story: keys stay per-device (so a lost phone doesn't
require rotating your laptop), but addressing stays per-person.

## Where it lives on disk

```
<data-dir>/
├── identity.txt   # Ed25519 signing secret + X25519 secret (hex)
├── hybrid.txt     # X25519 || ML-KEM-768 secret (hex)
├── mldsa.txt      # ML-DSA-65 seed (hex)
└── contacts.txt   # name signing ecdh [hybrid] — one device per line
```

All secrets are hex-encoded text files with owner-only expectations. The
`contacts.txt` format is whitespace-separated, one device per line, with `-` for
a missing hybrid key:

```
bob <signing-hex> <ecdh-hex> <hybrid-hex-or-dash>
```

## The trust model in one line

Adding a contact *is* the opt-in. There is no global directory to be listed in,
and by default a drop from an unknown identity is not something you would fetch
or open. Blocking someone is removing (or never adding) the contact.

## Go look at this

- [`crates/crypto/src/keys.rs`](../../crates/crypto/src/keys.rs) — `Identity::generate`, sign/verify
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `keygen`, `identity`, `add_contact`, `contacts`
- [`crates/crypto/src/hybrid.rs`](../../crates/crypto/src/hybrid.rs) and [`hybrid_sig.rs`](../../crates/crypto/src/hybrid_sig.rs) — the PQ halves
- Tests: `crates/store/src/lib.rs` (`duplicate_device_is_rejected`), CLI integration test

Next: [Making a drop](07-making-a-drop.md)
