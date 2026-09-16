# 24. The store and the data directory

Every client talks to disk through one library: **`keepstone-store`**. The
on-disk format is defined there, exactly once.

## Why it exists

The CLI and the daemon once each implemented the same data-directory operations,
and the duplication caused drift ([ADR-0013](../DECISIONS.md)). Extracting it
means one implementation of create/open/list/verify, with one set of tests. The
store is **synchronous**; operations are short and local, so async callers call
it directly.

## The data directory

```
<data-dir>/
├── identity.txt      # Ed25519 signing + X25519 secrets (hex)
├── hybrid.txt        # X25519 || ML-KEM-768 secret (hex)
├── mldsa.txt         # ML-DSA-65 seed (hex)
├── contacts.txt      # name signing ecdh [hybrid], one device per line
├── drops/
│   └── <id>.signed    # exact envelope bytes
├── chunks/
│   └── <id>/<n>.bin
├── anchors/<root>.digest [.ots]
└── log/
    ├── entries.bin    # [len:u32_be][envelope bytes]...
    ├── key.txt        # local log identity
    └── anchors.txt    # anchor receipts
```

## `Store` API

```rust
pub struct Store { root: PathBuf }

Store::open(root) -> Result<Store>        // creates the directory
store.root() -> &Path

// identity
store.keygen() -> Result<Identity>
store.has_identity() -> bool
store.identity() -> Result<Identity>
store.hybrid() / hybrid_or_create() / hybrid_public_bytes()
store.mldsa() / mldsa_or_create()
store.save_identity / save_hybrid / save_mldsa

// contacts
store.contacts() -> Result<Vec<Contact>>
store.add_contact(name, signing, ecdh, hybrid) -> Result<()>

// drops
store.create_drop(to, lat, lng, res, ring, ttl, suite, plaintext) -> Result<CreatedDrop>
store.open_drop(id) -> Result<Vec<u8>>
store.list_drops(near, ring) -> Result<Vec<DropSummary>>
store.read_drop(id) -> Result<(SignedDrop, DropBody)>
store.drop_path(id) / chunk_dir(id)

// log
store.append_log_entry(raw)
store.log_entries() -> Result<Vec<Vec<u8>>>
store.log_identity() -> Result<Identity>
store.signed_tree_head() -> Result<SignedTreeHead>
store.verify(id) -> Result<Verification>
```

Return types are presentation-friendly structs (`CreatedDrop`, `DropSummary`,
`Verification`, `Contact`) so clients needn't know the wire types.

## What create/open encapsulate

- **`create_drop`** — resolve recipients to devices, generate the content key,
  stream-encrypt, seal per device, pad with decoys, mine PoW, build and sign the
  envelope, write chunks + envelope, append to the log.
- **`open_drop`** — read and verify the envelope, check PoW, derive the local
  tag, unseal the key (classical then hybrid), read and decrypt chunks,
  reassemble.

Both clients call these, so a change can't apply to only one of them.

## Boring formats on purpose

- Secrets are hex text, one value per line — easy to inspect and back up.
- `entries.bin` is `[len:u32_be][bytes]...`.
- Drops are stored as their exact `.signed` bytes, so stored and decoded drops
  share an id by construction.

No database, no binary container to reverse-engineer.

## Errors

`StoreError` distinguishes what clients care about: `NoIdentity`, `NoHybrid`,
`NoMlDsa`, `NotFound`, `Invalid`, and wrapped crypto/core/log/io errors. That's
what makes "not addressed to this device" a clean error instead of a generic
failure.

## Go look at this

- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — the whole crate
- Tests: `create_open_verify_round_trip`, `list_filters_by_proximity`, `duplicate_device_is_rejected`
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — the data directory as an operator sees it

Next: [Security summary](25-security-summary.md)
