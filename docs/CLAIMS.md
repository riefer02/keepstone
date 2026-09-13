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
| History cannot be silently rewritten | Consistency proofs between tree sizes; **equivocation detection** for same-size differing roots | ✅ M2 |
| Content cannot be truncated or reordered | Chunk count + index bound in the AEAD AAD | ✅ M1 |
| Flooding costs work | Hashcash-style proof-of-work bound to signer + content | ✅ M2 |
| Peers can exchange drops | Reference TCP protocol: `serve` / `fetch` envelope + chunks; two-node test + CLI demo | ✅ M2 |
| It actually works | Multi-chunk (200 KB) round-trip; 49 passing tests | ✅ M2 |
| Only when they're there | Presence certificate (k-of-n witnesses) | ⏳ M3 |
| No company can delete it | Replication across independent nodes/logs | ⏳ M5 |
| Resistant to a quantum adversary | Hybrid X25519+ML-KEM / Ed25519+ML-DSA suite | ⏳ M5 |
| Not audited | — | ⚠️ No independent audit yet |
