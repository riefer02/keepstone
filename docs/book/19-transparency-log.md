# 19. The transparency log

Encryption hides *what* a drop says; it says nothing about whether the record of
it was tampered with. Each node keeps an append-only **transparency log** on the
RFC 6962 Merkle tree, so anyone can prove a drop is in the log and that history
wasn't rewritten.

## Leaves

The **exact envelope bytes** of every drop this node knows. Since a drop's id is
`H(envelope bytes)`, leaf and drop are bound with no re-encoding.

```
<data-dir>/log/entries.bin

  [ len:u32_be ][ envelope bytes ][ len:u32_be ][ envelope bytes ] ...
```

## The tree

Domain separation stops a leaf being confused with an internal node:

```
leaf_hash(d)    = SHA-256( 0x00 || d )
node_hash(l, r) = SHA-256( 0x01 || l || r )
```

`MTH` is recursive: one leaf is its own root; two hash together; larger trees
split at the largest power of two below the size.

```
                 root = node_hash(A, B)
                /                      \
       A = node_hash(L0, L1)         B = node_hash(L2, L3)
        /          \                 /          \
   leaf(L0)    leaf(L1)        leaf(L2)      leaf(L3)
```

## Inclusion proofs

Prove leaf `i` is in a tree of size `n` by giving the **sibling hashes** along
the path to the root — about `log2(n)` of them.

```
   leaf(L2) ──sibling──▶ L3
        └──▶ A            (sibling of L2's parent)
             └──▶ root

   proof = [ L3, A ]   — two hashes, regardless of tree size
```

`verify_inclusion(leaf, index, tree_size, proof, root)` recomputes the path. This
is `log-verify`'s `inclusion: ok`; verification is microseconds.

## Consistency proofs

Inclusion says "this leaf is in *this* tree." **Consistency** says "the tree I
showed before is a prefix of the tree now" — nothing removed or rewritten, only
appended. This is the antidote to silent history rewriting.

```
   root_n  ──────────────▶  root_{n+m}
      │                          ▲
      └── consistency proof ─────┘
```

## Signed tree heads

```
sth_input = "keepstone/v1/sth" || tree_size_be64 || root(32) || timestamp_be64

SignedTreeHead = { tree_size, root, timestamp, log_public(32), signature(64) }
encoded length = 8 + 32 + 8 + 32 + 64 = 144 bytes
```

`detect_equivocation` fires when two valid STHs share a `tree_size` but differ
in `root`.

## The primitives

| Question | Primitive | Cost |
|---|---|---|
| Is this drop in the log? | inclusion proof | verify ~µs; generate ~O(n) |
| Has anything been removed? | consistency proof | verify ~µs; generate ~O(n) |
| Is the operator consistent? | compare/gossip STHs | O(1) |

## Known limitation

Proof **generation** recomputes subtree hashes in **O(n)** (~2 ms at 10k leaves);
verification is microseconds. Tracked performance issue, not correctness — a
cached or persistent Merkle tree would make generation `O(log n)`
([`docs/BENCHMARKS.md`](../BENCHMARKS.md)). Fine for local log sizes.

## Go look at this

- [`crates/log/src/merkle.rs`](../../crates/log/src/merkle.rs) — hashes, `mth`, proofs
- [`crates/log/src/sth.rs`](../../crates/log/src/sth.rs) — STH encode/sign/verify, `detect_equivocation`
- [`crates/store/src/lib.rs`](../../crates/store/src/lib.rs) — `append_log_entry`, `log_entries`, `verify`
- [`crates/node/src/protocol.rs`](../../crates/node/src/protocol.rs) — `GetSth`/`Sth`
- Tests: Merkle tests in `crates/log`

Next: [Networking](20-networking.md)
