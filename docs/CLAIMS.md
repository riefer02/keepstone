# Claims → Evidence

Every public claim in the README maps to a verifiable artifact. Status is
updated as milestones land.

| Claim | Evidence | Status |
|---|---|---|
| Only the intended recipient can read a drop | `crypto::sealed` + `stream` tests; CLI demo (a third party is refused) | ✅ M1 |
| Recipients are not named in cleartext | Recipient tags + decoy padding (`MIN_TAGS`); no recipient keys in the body | ✅ M2 |
| No server can read it | relay + TCP serve hold **ciphertext only**; no key material in the node API | ✅ M2 |
| The author cannot be impersonated | Ed25519 signature over the canonical payload; tamper tests fail verification | ✅ M1 |
| Anyone can verify a drop existed | RFC 6962 inclusion proof + signed tree head; `log verify` CLI | ✅ M1 |
| History cannot be silently rewritten | Consistency proofs between tree sizes; **equivocation detection**; **external anchoring** of signed tree heads via an append-only hash chain | ✅ M4 |
| Content cannot be truncated or reordered | Chunk count + index bound in the AEAD AAD | ✅ M1 |
| Flooding costs work | Hashcash-style proof-of-work bound to signer + content | ✅ M2 |
| Peers can exchange drops | Reference TCP protocol and **libp2p** (QUIC + TCP, Noise) request/response; in-process test + two-node CLI demo | ✅ M2 |
| Drops from unknown authors reach nearby peers | **gossipsub cell topics**: a subscriber stores a valid drop published by a peer it never requested from | ✅ M2 |
| Peers can find who serves a quiet cell | **Kademlia provider records**: `find_providers` returns the peer advertising a cell | ✅ M2 |
| It actually works | Multi-chunk (200 KB) round-trip; **99 tests** incl. property tests; `cargo xtask demo` end-to-end | ✅ M4 |
| Untrusted input cannot crash the parser | `cargo-fuzz` targets for drop/protocol/presence decoders: ~30M executions, no crashes | ✅ M4 |
| Only when they're there | k-of-n presence certificates with distinct-witness + expiry checks; **networked witness collection over TCP and libp2p**; place-locked release via Shamir custodians | ✅ M3 |
| Secret is unreadable without a threshold of custodians | Shamir 3-of-5 split/combine tests; fewer shares cannot decrypt | ✅ M3 |
| No company can delete it | Replication across independent nodes/logs | ⏳ M5 |
| Resistant to a quantum adversary | Hybrid X25519 + ML-KEM-768 sealing **and** Ed25519 + ML-DSA-65 signatures, both wired into the drop envelope; sound if **either** primitive holds | ✅ M5 |
| Drops can target a group | Repeat `--to`; each recipient gets its own sealed content key + tag, padded with decoys; non-recipients are refused | ✅ M5 |
| Multi-device recipients | Add several devices under one contact name; a single drop seals to every device and opens on each | ✅ M5 |
| Delivery does not require the author online | Federated store-and-forward: `push` ciphertext to a relay, `fetch` later; the relay holds no keys | ✅ M5 |
| Anyone can audit a log's head | `sth-serve` / `sth-fetch`: a peer retrieves and verifies a log's signed tree head; equivocation detection applies | ✅ M5 |
| A normal person can use it | Local JSON API + browser UI (`keepstone-daemon`): create, list, open, verify against the local node | ✅ M5 |
| Not audited | — | ⚠️ No independent audit yet |
