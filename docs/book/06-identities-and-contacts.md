# 6. Identities and contacts

## An identity is two keypairs (plus their PQ halves)

`keygen` generates four keys; conceptually an identity is two:

- **Ed25519** — signing (proves you authored a drop).
- **X25519** — key agreement (the lock content keys are sealed to).

Plus the post-quantum halves so hybrid drops work out of the box:

- **X25519 + ML-KEM-768** — hybrid encryption.
- **ML-DSA-65** — hybrid signatures.

```bash
keepstone --data-dir ./alice keygen
keepstone --data-dir ./alice id
```

`id` prints the **public** keys. The hybrid key is `32-byte X25519 || ML-KEM-768`
(1184 bytes):

```
signing: <64 hex chars>
ecdh:    <64 hex chars>
hybrid:  <~2400 hex chars>
```

`keygen` refuses to overwrite an existing identity.

## Contacts: public keys with a petname

Public keys are exchanged **out of band**. There is no key directory and no key
discovery.

```bash
keepstone --data-dir ./alice contact-add bob <bob-signing> <bob-ecdh> <bob-hybrid>
keepstone --data-dir ./alice contact-list
```

The hybrid key is optional: without it a contact can receive *classical* drops
but not *hybrid* ones.

## Multi-device

Add the same name again with a different keypair:

```bash
keepstone --data-dir ./alice contact-add bob <bob-laptop-signing> <bob-laptop-ecdh> <bob-laptop-hybrid>
keepstone --data-dir ./alice contact-add bob <bob-phone-signing>  <bob-phone-ecdh>  <bob-phone-hybrid>
```

You still address `--to bob`; Keepstone seals to **every** device under that
name, so it opens on each. Adding the same device twice is rejected. Keys stay
per-device (a lost phone doesn't force rotating the laptop); addressing stays
per-person.

## On disk

```
<data-dir>/
├── identity.txt   # Ed25519 signing + X25519 secrets (hex)
├── hybrid.txt     # X25519 || ML-KEM-768 secret (hex)
├── mldsa.txt      # ML-DSA-65 seed (hex)
└── contacts.txt   # name signing ecdh [hybrid] — one device per line
```

`contacts.txt` is whitespace-separated, `-` for a missing hybrid key:

```
bob <signing-hex> <ecdh-hex> <hybrid-hex-or-dash>
```

## Trust model

Adding a contact **is** the opt-in. There is no directory to be listed in, and by
default you don't fetch or open drops from unknown identities. Blocking is
removing the contact.

## Go look at this

- [`crates/crypto/src/keys.rs`](../../crates/crypto/src/keys.rs) — `Identity`, sign/verify
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `keygen`, `identity`, `add_contact`, `contacts`
- [`crates/crypto/src/hybrid.rs`](../../crates/crypto/src/hybrid.rs) / [`hybrid_sig.rs`](../../crates/crypto/src/hybrid_sig.rs) — PQ halves
- Tests: `duplicate_device_is_rejected`, CLI integration test

Next: [Making a drop](07-making-a-drop.md)
