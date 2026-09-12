# Claims → Evidence

Every public claim in the README maps to a verifiable artifact. Status is
updated as milestones land.

| Claim | Evidence | Status |
|---|---|---|
| Only the intended recipient can read a drop | `crypto::sealed` + `stream` tests; CLI demo (third party is refused) | ✅ M1 |
| No server can read it | `relay` stores ciphertext only; no key material in the relay API | ✅ M1 (unit) |
| The author cannot be impersonated | Ed25519 signature over the canonical payload; tamper tests fail verification | ✅ M1 |
| Anyone can verify a drop existed | RFC 6962 inclusion proof + signed tree head; `log verify` CLI | ✅ M1 (local log) |
| History cannot be silently rewritten | Consistency proofs between tree sizes | ✅ M1 (unit); cross-log gossip is M2 |
| Content cannot be truncated or reordered | Chunk count + index bound in the AEAD AAD | ✅ M1 |
| It actually works | Multi-chunk (200 KB) round-trip; 40 passing tests | ✅ M1 |
| Only when they're there | Presence certificate (k-of-n witnesses) | ⏳ M3 |
| No company can delete it | Replication + independent log nodes | ⏳ M2/M5 |
| Not audited | — | ⚠️ No independent audit yet |
