# 19. The transparency log

Encryption hides *what* a drop says. It says nothing about *whether the record
of it has been tampered with*. For that, each node keeps an append-only
**transparency log** built on the RFC 6962 Merkle tree, so anyone can prove a
drop is in the log and that the log hasn't been rewritten behind their back.

## What goes in the log

The **exact envelope bytes** of every drop this node knows about. Because a
drop's id is `H(envelope bytes)`, the log leaf and the drop are bound together
with no re-encoding anywhere.

```
<data-dir>/log/entries.bin

  [ len:u32_be ][ envelope bytes ][ len:u32_be ][ envelope bytes ] ...
```

`entries.bin` is a simple length-prefixed concatenation. Reading it back yields
the list of envelope byte strings; hashing each gives the leaves.

## The tree (RFC 6962)

Domain separation stops a leaf from being confused with an internal node:

```
leaf_hash(d)     = SHA-256( 0x00 || d )
node_hash(l, r)  = SHA-256( 0x01 || l || r )
```

`MTH` (Merkle Tree Hash) is defined recursively: one leaf is its own root; two
leaves hash together; larger trees split at the largest power of two smaller
than the size.

```
                 root = node_hash(A, B)
                /                      \
       A = node_hash(L0, L1)         B = node_hash(L2, L3)
        /          \                 /          \
   leaf(L0)    leaf(L1)        leaf(L2)      leaf(L3)
```

## Inclusion proofs

To prove leaf `i` is in a tree of size `n`, you provide the **sibling hashes**
along the path from that leaf to the root — about `log2(n)` of them.

```
   leaf(L2) ──sibling──▶ L3
        └──▶ A            (the sibling of L2's parent)
             └──▶ root

   proof = [ L3, A ]   — two hashes, regardless of how many leaves the tree has
```

`verify_inclusion(leaf, index, tree_size, proof, root)` recomputes the path and
checks it lands on `root`. This is what `log-verify` prints as `inclusion: ok`.
Verification is microseconds even for large trees.

## Consistency proofs

An inclusion proof says "this leaf is in *this* tree." A **consistency proof**
says "the tree I showed you before is a prefix of the tree I'm showing you now"
— i.e. nothing was removed or rewritten, only appended. This is the antidote to
a log silently rewriting history.

```
   root_n  ──────────────▶  root_{n+m}
      │                          ▲
      └── consistency proof ─────┘
         (proves root_n is a prefix of root_{n+m})
```

## Signed tree heads (STHs)

A **signed tree head** is a log operator's signed statement: "as of this tree
size, the root is this." It's what gets gossiped and anchored.

```
sth_input = "keepstone/v1/sth" || tree_size_be64 || root(32) || timestamp_be64

SignedTreeHead = { tree_size, root, timestamp, log_public(32), signature(64) }
encoded length = 8 + 32 + 8 + 32 + 64 = 144 bytes
```

Verification checks the signature against `log_public`; `detect_equivocation`
fires when two valid STHs share a `tree_size` but differ in `root` — proof the
log tried to show two histories.

## The three log primitives

| Question | Primitive | Cost |
|---|---|---|
| Is this drop in the log? | inclusion proof | verify ~µs; generate ~O(n) |
| Has anything been removed? | consistency proof | verify ~µs; generate ~O(n) |
| Is the operator being consistent? | compare/gossip STHs | O(1) per comparison |

## A known, honest limitation

Generating a proof currently recomputes subtree hashes in **O(n)** — about 2 ms
at 10,000 leaves on Apple Silicon. Verifying is microseconds. This is a tracked
performance issue, not a correctness one: a cached internal-node tree or a
persistent Merkle tree would make generation `O(log n)`. See
[`docs/BENCHMARKS.md`](../BENCHMARKS.md). For a local node's log sizes this is
fine; it would matter for a busy public log.

## Go look at this

- [`crates/log/src/merkle.rs`](../../crates/log/src/merkle.rs) — leaf/node hashes, `mth`, proofs
- [`crates/log/src/sth.rs`](../../crates/log/src/sth.rs) — STH encode/sign/verify, `detect_equivocation`
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `append_log_entry`, `log_entries`, `verify`
- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — `GetSth`/`Sth` messages
- Tests: Merkle inclusion/consistency tests in `crates/log`

Next: [Networking](20-networking.md)
