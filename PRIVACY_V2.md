# Privacy V2 — Solvent-Set Membership & Deterministic Nullifiers

**Status**: Design + initial implementation (Phase 10)
**Depends on**: ARCHITECTURE.md (V1 batch model), Phase 9 (ZK privacy mode)

---

## 1. Why V2

Phase 9 moved the agent from "watch enrolled addresses" to "verify user-submitted
EIP-1186 proofs, never persist addresses." That was the right instinct, but it has
three structural problems:

1. **Privacy is a retention policy, not a cryptographic property.** The
   `/submit_proof` endpoint receives `wallet_address` in plaintext (it is required
   to compute the MPT trie key). Even without it, the account-proof path *is*
   `keccak256(address)` — anyone holding the submitted proof nodes can recover the
   address by dictionary-matching against the public set of active accounts. The
   agent must be trusted not to look.

2. **It silently gave up the flagship UX property.** If the agent cannot see
   addresses, it cannot monitor them. Solvency freshness now depends on users
   re-submitting proofs each epoch — "enroll once, never interact again" no longer
   holds, and nothing enforces it.

3. **`memberId = SHA256(signature)` is not a sound identifier.** ECDSA signatures
   are not adversarially deterministic:
   - The key owner can vary the nonce `k` to mint unlimited distinct signatures →
     unlimited memberIds backed by the same funds within one scope.
   - Standard malleability: given any valid `(r, s, v)`, the pair
     `(r, n − s, v ⊕ 1)` is also valid for the same message and key — so even a
     *third party* who observes one signature can derive a second distinct
     memberId that recovers to the same address.
   "One address, one member" is therefore unenforceable, which breaks sybil
   resistance for any relying protocol that assumes members are distinct actors
   (governance, airdrops, one-account-per-person gating).

V2 fixes all three with two constructions:

- **Construction A — deterministic nullifiers (PLUME-style)**: replace the
  signature hash with a verifiably deterministic nullifier. Exactly one identity
  per (key, policy), enforced by cryptography rather than convention.
- **Construction B — the solvent-set model**: split the proof at the
  public/private boundary. The agent proves the *public* part (which addresses are
  solvent) once per epoch for everyone; the user proves the *private* part (I
  control one of them) client-side. The agent never learns any member's address —
  not transiently, not at all — and there is no enrollment.

---

## 2. Threat-model comparison

| Property | V1 (watch model) | Phase 9 (submit-proof) | **V2 (solvent-set)** |
|---|---|---|---|
| Agent learns address | Yes (stored) | Yes (transient, deniable) | **No (never sent)** |
| Verifier learns address | No | No | No |
| Anonymity set | Enrolled members | Enrolled members | **All solvent addresses on chain** |
| User work per epoch | None | Submit fresh MPT proof | **None** (set updates without user) |
| User work at use time | None | None | One small client-side proof (~seconds) |
| One identity per address | Not enforced (malleable memberId) | Not enforced | **Enforced (nullifier)** |
| Correctness of status bits | SP1 batch proof | Host-side MPT verify (trusted) | SP1 membership proof (per use) + published set root |

The one cost V2 pays: a small ZK proof is generated on the user's device at use
time. This was listed as an anti-pattern in ARCHITECTURE.md §19, but that
assessment priced the *original* design — ECDSA + MPT + state verification all
inside the user's circuit. In V2 the user's statement is only:

```
key derivation + one SHA-256 Merkle path + one nullifier
```

The expensive, state-scale work (deriving the solvent set from chain data) stays
on the agent side, proven once per epoch and amortized over every user. The
anti-pattern was about the wrong axis: what must stay free is *maintenance*
(per-epoch chores), and V2 keeps maintenance at zero.

---

## 3. Construction A — Deterministic nullifiers

### 3.1 Definitions (byte-level, normative)

All points are secp256k1, SEC1-encoded. Compressed points are 33 bytes.
`H` is SHA-256. `‖` is byte concatenation.

```
DST_H2C   = "zkpof-v1:secp256k1_XMD:SHA-256_SSWU_RO_"          (ASCII, RFC 9380 XMD:SHA-256 SSWU RO)
msg_pol   = "zkpof-nullifier-v2:" ‖ lowercase_hex(policy_id)    (ASCII; 19 + 64 chars)

pk        = g · sk                                              (secp256k1 generator g)
h         = hash_to_curve(msg_pol ‖ pk_compressed, DST_H2C)     (RFC 9380 hash-to-curve)
N         = h · sk                                              (the nullifier, a curve point)
nullifier_hash = H(N_compressed)                                (32 bytes)

member_id = nullifier_hash
```

Properties:

- **Deterministic**: one and only one `N` exists per `(sk, policy_id)`. No nonce,
  no signer discretion, no malleability. The multiplicity attacks in §1(3) are
  structurally impossible.
- **Unlinkable across policies**: different `policy_id` → different `h` →
  unrelated nullifiers. (V1's string `scope` gave scope-level linkage; V2 binds to
  `policy_id` because `policy_id` is what the chain can verify. If two policies
  intentionally want shared identities, a committed `scope_hash` can be added to
  the public values later — noted in §7.)
- **Non-invertible**: recovering `pk` or the address from `N` requires breaking
  DDH-style assumptions on secp256k1; `nullifier_hash` additionally hides `N`.
- `pk` is folded into the hash-to-curve input (as in PLUME) so each key gets a
  distinct base point `h`.

This is the PLUME construction ("Verifiably Deterministic Signatures on ECDSA",
2022) with project-specific domain separation. We do not claim wire-format
compatibility with the PLUME spec's test vectors; parameters above are normative
for this project.

### 3.2 Proving the nullifier is well-formed

Two contexts, two mechanisms:

**(a) Outside a ZK circuit (V2 enrollment for the monitored flow):** the user
reveals `pk` to the agent (the agent in this flow knows the address anyway — that
is the point of monitored mode) plus a **Chaum–Pedersen DLEQ proof** that
`log_g(pk) = log_h(N)`:

```
r  = reduce(H("zkpof-dleq-nonce-v1" ‖ sk_be32 ‖ pk ‖ N ‖ msg_pol))   (deterministic nonce; reject r = 0)
A  = g · r
B  = h · r
c  = reduce(H("zkpof-dleq-chal-v1" ‖ pk ‖ N ‖ A ‖ B ‖ msg_pol))
s  = r + c · sk  (mod n)

proof = (A, B, s)      — 33 + 33 + 32 = 98 bytes
verify: g·s == A + pk·c   AND   h·s == B + N·c
        (verifier recomputes h from msg_pol and pk; rejects identity/invalid points)
```

`reduce` maps 32 bytes to a scalar mod `n`; the modulo bias is ≤ 2⁻¹²⁷ for
secp256k1 and is not exploitable here.

**(b) Inside the SP1 membership program (Construction B):** no DLEQ is needed —
the zkVM computes `N = hash_to_curve(msg_pol ‖ pk) · sk` directly from the private
`sk` and commits `nullifier_hash` as a public output. The proof of the whole
program subsumes well-formedness.

### 3.3 Wallet-support caveat (honest limits)

Computing `N` requires raw access to `sk`. Browser wallets (MetaMask et al.) do
not expose it; PLUME requires wallet cooperation (`eth_getPlumeSignature`
proposals, MetaMask snaps, or embedded/local signers). Consequences:

- The Rust implementation is the reference; a CLI or local signer can enroll
  today. The React app keeps the legacy signature flow until wallet support
  exists.
- The legacy `SHA256(signature)` path is **retained but hardened**: low-`s`
  signatures are now enforced (EIP-2 half-order check), which closes the
  third-party malleability attack. The owner-multiplicity attack is inherent to
  ECDSA and is documented as a known limitation of the legacy path.

---

## 4. Construction B — The solvent-set model

### 4.1 Key insight

On a transparent chain, *solvency is public data*. The set

```
S(T, B) = { addr : balance(addr, block B) ≥ T }
```

is derivable by anyone from chain state. Nothing about any individual member is
needed to compute it. So instead of enrolling members and watching their
addresses, the agent commits to `S` itself, once per epoch:

```
Per epoch:
  1. Derive S(threshold, B) for the policy's asset at reference block B
  2. leaf_i = SHA256("zkpof-solvent-leaf-v1" ‖ addr_i)       (addresses sorted ascending, deduped)
  3. solvent_set_root = SHA256-Merkle-root(leaves)            (same tree rules as V1: odd level duplicates last)
  4. Publish (policy_id, solvent_set_root, epoch, B, |S|) on-chain (SolventSetOracle)
  5. Serve the full leaf list via API (it is public data)
```

A user proves membership entirely client-side:

```
1. Download the leaf list (or the policy-relevant chunk) — downloading everything
   is what makes the lookup oblivious; the agent sees only "someone fetched the set"
2. Locate own address locally, build the Merkle path locally
3. Generate the SP1 membership proof (statement below)
4. Hand (proofBytes, publicValues) to the relying dApp, which calls
   SolventSetOracle.verifyMembership / verifyAndConsume on-chain
```

No enrollment. No watchlist. The agent cannot distinguish members from curious
downloaders. The anonymity set is every solvent address on the chain.

### 4.2 The membership statement (SP1 program `program-membership/`)

```
Private inputs:  sk (32B), merkle_siblings (Vec<[u8;32]>), leaf_index (u64)
Public inputs:   solvent_set_root (32B), policy_id (32B), epoch (u64), chain_id (u64)

1. assert sk is a valid nonzero scalar; pk = g · sk
2. address = keccak256(pk_uncompressed[1..65])[12..32]
3. leaf = SHA256("zkpof-solvent-leaf-v1" ‖ address)
4. assert MerkleVerify(leaf, leaf_index, merkle_siblings, solvent_set_root)
5. N = hash_to_curve("zkpof-nullifier-v2:" ‖ hex(policy_id) ‖ pk_compressed, DST_H2C) · sk
6. nullifier_hash = SHA256(N_compressed)
7. commit abi.encode(solvent_set_root, policy_id, epoch, nullifier_hash, chain_id)
```

**Public values ABI (normative):** `abi.encode(bytes32 solventSetRoot,
bytes32 policyId, uint64 epoch, bytes32 nullifierHash, uint64 chainId)` — five
32-byte words, 160 bytes, committed as a single `commit_slice` blob so Solidity
`abi.decode` consumes it directly.

Note the unification: `nullifier_hash` here equals `member_id` from Construction
A. A member enrolled in monitored mode and the same key proving client-side in V2
present the *same* identity to relying protocols, so the two modes are
interchangeable per policy without integration changes.

### 4.3 On-chain: `SolventSetOracle.sol`

- `publishRoot(policyId, root, epoch, blockNumber, memberCount)` — operator-only,
  epoch strictly increasing, policy active. (Publication is operator-trusted in
  Stage A; Stage B replaces this with an SP1-proven derivation — §4.4.)
- `verifyMembership(policyId, rootIndex, publicValues, proofBytes) → nullifierHash`
  — view; checks TTL, verifies the SP1 proof against `membershipVKey`, decodes and
  cross-checks the public values against the stored entry, returns the nullifier.
- `verifyAndConsume(...)` — same, then marks `usedNullifiers[policyId][nullifierHash]`,
  reverting on reuse. For one-per-address semantics (votes, mints). Protocols that
  want their own consumption namespace use the view function and track nullifiers
  themselves.

Gas: one SP1 Groth16 verification (~270k) per membership use. That is the cost of
maximal privacy; policies that prefer the ~10k-gas V1 Merkle check keep the
monitored flow — both modes coexist per policy.

### 4.4 Deriving the solvent set (staged)

The derivation is the only part of V2 where trust is staged rather than immediate:

- **Stage A (this implementation)**: the agent computes `S` and publishes the root
  under operator trust — same trust level as Phase 9's host-side verification, but
  with strictly less knowledge (no member identities at all). Sources:
  - *ERC-20 / WETH*: candidate discovery from `Transfer` event logs (both
    `from`/`to` participants), balances checked per candidate at block B via RPC.
  - *Native ETH*: candidate lists (config or discovery heuristics) checked via
    `eth_getBalance` at block B. Full-state enumeration needs node-level access
    (`debug_accountRange`/snapshots) and is out of scope here.
- **Stage B (future)**: prove the derivation in SP1. For ERC-20s the set is
  maintainable purely from Transfer logs verified against per-block receipt roots
  and the header chain — a rolling proof, far cheaper than state-trie iteration.
  Caveats: nonstandard tokens (rebasing, fee-on-transfer) break log accounting and
  must be flagged per policy. Native ETH requires proving state reads (RSP-style
  block execution or EIP-1186 sampling) and stays on the watch/monitored path
  until that is economical.
- **Stage C (research)**: multi-party or light-client-verified publication so even
  root publication needs no single trusted operator.

An honest framing of Stage A: the operator can omit an address from the set
(censorship → liveness failure for that user, visible to them immediately) or
include an insolvent address (safety failure — requires operator misbehavior
exactly as trusted-mode V1 does). Stage B removes the safety failure; the TTL and
epoch-increasing rules already bound the damage window on-chain.

### 4.5 What V2 deliberately does not solve

- **The trilemma**: continuous automation + middleware-blind privacy + no new
  trust — a fresh proof about a secret requires *someone* to hold the secret. V2
  resolves it by making the per-epoch work witness-free and the witness-dependent
  proof a use-time, user-held step. TEEs/MPC could move that back to a service at
  the cost of new trust; out of scope.
- **Non-encumbrance**: proving funds aren't borrowed, key-shared, or pledged
  elsewhere is not possible on a transparent account chain. Mitigation is
  economic: streak/time-weighted solvency (consecutive epochs in the set, with
  blockhash-randomized reference blocks) is a planned leaf extension — idea 3 from
  the design discussion, not part of this change.

---

## 5. Implementation map (this change)

| Piece | Location | Notes |
|---|---|---|
| Nullifier + DLEQ | `crates/common/src/plume.rs` | k256 `hash2curve`, deterministic nonce, 98-byte proof |
| Solvent-set tree | `crates/common/src/solvent_set.rs` | Domain-separated leaves, sorted/deduped, path building |
| Membership statement (host mirror) | `crates/common/src/membership.rs` | Native execution + ABI encoding; must match the guest byte-for-byte |
| SP1 guest program | `program-membership/` | Excluded from workspace, `cargo prove build`, sp1-zkvm 6 |
| Low-s hardening | `crates/agent/src/enrollment.rs` | EIP-2 half-order check; malleated signatures rejected |
| Nullifier enrollment | `crates/agent/src/enrollment.rs` | `enroll_with_nullifier`; `member_id = nullifier_hash` |
| Solvent-set service | `crates/agent/src/solvent_set_service.rs` | Build from candidates, Transfer-log discovery, DB persistence |
| DB | `crates/agent/src/db.rs` | `nullifiers`, `solvent_sets` tables |
| API | `crates/backend/src/main.rs` | `POST /v2/enroll`, `GET /v2/solvent_set/:policy_id`, `GET /v2/solvent_set/:policy_id/leaves`, `POST /v2/admin/build_solvent_set/:policy_id` |
| Oracle | `contracts/src/SolventSetOracle.sol` | publish + verifyMembership + verifyAndConsume; Foundry tests with MockSP1Verifier |
| SDK | `sdk/src/` | Solvent-set fetch + local tree/path computation (still zero-dep) |

**No server-side path endpoint exists by design** — asking the agent for "the path
for address X" would reveal X. Paths are computed client-side from the public leaf
list (SDK and `crates/common` both implement it).

## 6. Rollout

1. Land V2 alongside V1 (this change): additive routes, tables, contracts. Nothing
   existing breaks; legacy enrollment is hardened but keeps its API shape.
2. Wire real SP1 proving for `program-membership` (needs `cargo prove build` ELF +
   prover infra; same operational gate as the existing batch program).
3. Wallet-side PLUME (snap or local signer) → surface V2 enrollment and
   client-side proving in the React app.
4. Stage B proven set derivation for ERC-20 policies.

## 7. Open items

- Committed `scope_hash` if cross-policy shared identity is wanted.
- Browser proving target: SP1 is not browser-feasible today; either delegate
  proving with TEE privacy, or compile the membership statement to a small
  dedicated circuit (circom/noir) with the same public-values ABI.
- Streak/time-weighted solvency leaf extension (anti-flash-loan).
- Purge `wallet_address` from the legacy `/submit_proof` request path once V2
  covers its use cases.
