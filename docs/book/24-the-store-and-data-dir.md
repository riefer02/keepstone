# 24. The store and the data directory

Every client — the CLI, the daemon, and anything future — talks to the disk
through one library: **`keepstone-store`**. This is where the on-disk format is
defined, exactly once.

## Why it exists

Before the extraction, the CLI and the daemon each implemented the same
data-directory operations (identity, contacts, drops, log). The duplication had
already caused drift and made both clients harder to maintain. Extracting it
([ADR-0013](../DECISIONS.md)) means the format and the create/open/verify logic
live in one place, with one set of tests.

The store is **synchronous**; operations are short and local, so async callers
(the daemon) just call it directly.

## The data directory

```
<data-dir>/
├── identity.txt      # Ed25519 signing secret + X25519 secret (hex)
├── hybrid.txt        # X25519 || ML-KEM-768 secret (hex)
├── mldsa.txt         # ML-DSA-65 seed (hex)
├── contacts.txt      # name signing ecdh [hybrid], one device per line
├── drops/
│   └── <id>.signed    # the exact envelope bytes
├── chunks/
│   └── <id>/
│       ├── 0.bin
│       ├── 1.bin
│       └── ...
└── log/
    ├── entries.bin    # length-prefixed envelope bytes (the transparency log)
    ├── key.txt        # this log's signing identity
    └── anchors.txt    # anchor receipts
```

`anchors/` (created by OpenTimestamps anchoring) lives alongside, holding
`<root>.digest` files.

## The `Store` API

```rust
pub struct Store { root: PathBuf }

Store::open(root) -> Result<Store>     // creates the directory
store.root() -> &Path

// identity
store.keygen() -> Result<Identity>     // generate + persist everything
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

The return types are small, presentation-friendly structs (`CreatedDrop`,
`DropSummary`, `Verification`, `Contact`) so clients don't have to know the wire
types to render a result.

## What `create_drop` and `open_drop` encapsulate

These two are the heart of the store and they keep the CLI and daemon honest:

- **`create_drop`** — resolve recipients to devices, generate the content key,
  stream-encrypt, seal per device, pad with decoys, mine proof-of-work, build and
  sign the envelope, write chunks + envelope, append to the log.
- **`open_drop`** — read and verify the envelope, check proof-of-work, derive the
  local tag, unseal the content key (trying classical then hybrid), read and
  decrypt chunks, reassemble.

Because both clients call these, a change to any of these steps can't
accidentally apply to only one client.

## On-disk formats are boring on purpose

- Secrets are hex text, one value per line — easy to inspect, easy to back up.
- `entries.bin` is `[len:u32_be][bytes]...` — trivially readable.
- Drops are stored as their exact `.signed` bytes, so a decoded drop and a stored
  drop have the same id by construction.

There is no database and no binary container to reverse-engineer. Everything is
either a hex text file or a length-prefixed blob.

## Errors

`StoreError` distinguishes the cases clients care about: `NoIdentity`,
`NoHybrid`, `NoMlDsa`, `NotFound`, `Invalid`, and wrapped crypto/core/log/io
errors. That's what lets `drop-open` on a stranger's drop return a clean "not
addressed to this device" instead of a generic failure.

## Go look at this

- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — the whole crate
- Tests: `create_open_verify_round_trip`, `list_filters_by_proximity`, `duplicate_device_is_rejected`
- [`docs/OPERATIONS.md`](../OPERATIONS.md) — the data directory as an operator sees it

Next: [Security summary](25-security-summary.md)
