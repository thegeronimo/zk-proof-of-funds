# Privacy V2 — Solvent-Set Membership & Deterministic Nullifiers

**Status**: Implemented (Phase 10 + Phase 11 — see EXECUTION_PLAN.md)
**Depends on**: ARCHITECTURE.md (V1 batch model), Phase 9 (ZK privacy mode)

> **Phase 11 amendments** (normative): solvent-set leaves are streak-aware
> (`"zkpof-solvent-leaf-v2"`, §4.1), membership public values carry
> `minStreak` (192 bytes, §4.2), and Stage B — SP1-proven set derivation with
> permissionless publication — is implemented (§4.4).
>
> **Phase 12 amendments** (normative): derivation public values are 416 bytes
> (adds `token`, `balanceSlot`, `candidatesRoot`); proven builds support
> ERC-20 policies via storage proofs; the Stage B.2 completeness statement
> (receipt_scan, 160-byte public values) is implemented; wallet-side nullifier
> crypto ships as `@zk-proof-of-funds/sdk/plume`; production vkeys live in
> `config/vkeys.env`.
>
> **Phase 13 amendments** (normative): the nullifier is now computed **exactly
> as ERC-7524 specifies** — `N = hash_to_curve(scope_hash ‖ sec1(pk))^sk` over
> a 32-byte message with the standard `secp256k1_XMD:SHA-256_SSWU_RO_` suite —
> so a wallet implementing `eth_getPlumeSignature` derives the same member
> identity (§3.1, §3.3). Identity separation moves from `policy_id` to a
> **scope hash** (default `SHA256("zkpof-scope-v1:" ‖ policy_id)`), making
> cross-policy shared identity an opt-in configuration. Membership public
> values are 224 bytes (adds `scopeHash`). Stage B.2 composition is enforced
> on-chain by `publishRootProvenComplete` (§4.3-§4.4).
>
> **Phase 15 amendments** (normative, supersede the sizes above — external
> review remediation, see EXECUTION_PLAN.md "External Review (2026-07)"):
>
> - **Membership public values are 448 bytes.** They add a *presentation
>   context* — `policyConfigHash`, `verifier`, `verifierChainId`, `actionId`,
>   `beneficiary`, `nonce`, `deadline`. Without it a proof is a bearer token:
>   replayable at another verifier and front-runnable out of the mempool.
>   `verifyAndConsume` requires `beneficiary == msg.sender`, and nullifier
>   consumption is namespaced by `(consumer, policyConfigHash, actionId)`
>   rather than shared across every caller of a policy.
> - **Derivation public values are 448 bytes**, adding `prevBlockNumber`. The
>   statement requires `blockNumber > prevBlockNumber`, and the contract binds
>   `prevBlockNumber` to the stored previous entry — so a streak can no longer
>   be manufactured by re-proving one snapshot across many epochs. Epochs must
>   be sequential and each reference block must fall inside its own window,
>   derived from the new `Policy.startBlock`.
> - **Scan public values are 224 bytes**, adding `startBlock`/`endBlock`. The
>   range is *proven* from header item 8 (block number), not asserted, and is
>   stored on-chain. `endBlockHash` is bound through EIP-2935 (8191 blocks)
>   instead of `blockhash(block.number - 1)`.
> - **`proven: bool` is replaced by an immutable `Provenance` enum**
>   (`OperatorAsserted` / `BalancesProven` / `RangeScanProven`). Completeness
>   is always *relative to a recorded block range*; no surface may call a root
>   simply "complete".
> - **Roots pin their own semantics**: each `SetEntry` stores
>   `policyConfigHash`, both vkey hashes, and an immutable `validUntil`
>   computed from the source block. Policies freeze on first publication.
> - **An empty set has a root**: `SHA256("zkpof-empty-solvent-set-v1")`, so an
>   epoch where nobody qualified is publishable. `bytes32(0)` still means "no
>   root at all", and `prevBlockNumber == 0` is the first-epoch discriminator.
> - **The MPT verifier no longer treats an empty proof as proof of absence**
>   against an arbitrary root — the flaw that allowed silent censorship from a
>   root advertised as complete.

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
DST_H2C    = "secp256k1_XMD:SHA-256_SSWU_RO_"        (RFC 9380 / ERC-7524 standard suite)
scope_hash = H("zkpof-scope-v1:" ‖ policy_id)        (32 bytes; default — may be shared)

pk         = g · sk                                  (secp256k1 generator g)
h          = hash_to_curve(scope_hash ‖ sec1(pk), DST_H2C)   (65-byte input, per ERC-7524)
N          = h · sk                                  (the nullifier, a curve point)
nullifier_hash = H(sec1(N))                          (32 bytes)

member_id  = nullifier_hash
```

**This is the ERC-7524 nullifier**, with `scope_hash` as the ERC's 32-byte
message `m`. Matching it exactly is deliberate: it is what allows a wallet to
produce this identity natively (§3.3), and it costs nothing, since the scope
already had to be a 32-byte domain separator.

Properties:

- **Deterministic**: one and only one `N` exists per `(sk, policy_id)`. No nonce,
  no signer discretion, no malleability. The multiplicity attacks in §1(3) are
  structurally impossible.
- **Unlinkable across scopes**: different `scope_hash` → different `h` →
  unrelated nullifiers. Each policy gets its own scope by default, so policies
  are mutually unlinkable. Two policies that *want* one sybil-resistance
  namespace configure the same explicit scope
  (`SolventSetOracle.setScopeHash`); the membership proof commits `scope_hash`
  publicly so the contract pins it to the policy's configured value.
- **Non-invertible**: recovering `pk` or the address from `N` requires breaking
  DDH-style assumptions on secp256k1; `nullifier_hash` additionally hides `N`.
- `pk` is folded into the hash-to-curve input (as in PLUME) so each key gets a
  distinct base point `h`.

The *nullifier* above is wire-compatible with ERC-7524 (PLUME Signature in
Wallets, Draft). The *DLEQ proof encoding* below is project-specific: the ERC
defines its own challenge layout (V1/V2 variants), which we do not claim to
match. Only the nullifier — the identity-defining value, and the one baked
into on-chain nullifier sets — needs to agree for wallet interoperability.

### 3.2 Proving the nullifier is well-formed

Two contexts, two mechanisms:

**(a) Outside a ZK circuit (V2 enrollment for the monitored flow):** the user
reveals `pk` to the agent (the agent in this flow knows the address anyway — that
is the point of monitored mode) plus a **Chaum–Pedersen DLEQ proof** that
`log_g(pk) = log_h(N)`:

```
r  = reduce(H("zkpof-dleq-nonce-v1" ‖ sk_be32 ‖ pk ‖ N ‖ scope_hash))   (deterministic nonce; reject r = 0)
A  = g · r
B  = h · r
c  = reduce(H("zkpof-dleq-chal-v1" ‖ pk ‖ N ‖ A ‖ B ‖ scope_hash))
s  = r + c · sk  (mod n)

proof = (A, B, s)      — 33 + 33 + 32 = 98 bytes
verify: g·s == A + pk·c   AND   h·s == B + N·c
        (verifier recomputes h from scope_hash and pk; rejects identity/invalid points)
```

`reduce` maps 32 bytes to a scalar mod `n`; the modulo bias is ≤ 2⁻¹²⁷ for
secp256k1 and is not exploitable here.

**(b) Inside the SP1 membership program (Construction B):** no DLEQ is needed —
the zkVM computes `N = hash_to_curve(msg_pol ‖ pk) · sk` directly from the private
`sk` and commits `nullifier_hash` as a public output. The proof of the whole
program subsumes well-formedness.

### 3.3 Wallet support: why a snap cannot do this, and what can

Computing `N` requires the raw `sk`, which a browser wallet never exposes.

**A MetaMask snap cannot close this gap.** Snaps derive keys through
`snap_getBip32Entropy` / `snap_getBip44Entropy`, and **coin type 60 — the
Ethereum path — is reserved for MetaMask's own accounts and blocked for
snaps**; the documented way for a snap to touch an EOA is
`endowment:ethereum-provider`, which *requests signatures* rather than
exposing keys. So a snap can only ever produce nullifiers for keys it
generates itself, whose addresses are not the user's and therefore are not in
the solvent set. Snap packaging is not a missing sprint of work here; it is
the wrong shape of solution.

**The right shape is wallet-native PLUME**: ERC-7524 (Draft) specifies
`eth_getPlumeSignature`, where the wallet computes `nullifier = htc(m ‖
sec1(pk))^sk` internally and returns it — no key exposure. Since Phase 13 our
nullifier *is* that construction (§3.1) with `m = scope_hash`, so a wallet
shipping ERC-7524 produces exactly the member identity this system uses. The
remaining work is adapting the ERC's proof encoding, not the identity.

Consequences today:

- The Rust implementation is the reference, and `zkpof-client` (Phase 11) is
  the supported local-signer path: `nullifier`/`enroll`/`witness`/`prove`
  subcommands compute everything key-touching on the user's machine. The React
  app keeps the legacy signature flow for enrollment (plus a read-only
  solvent-set panel with local membership checks) until wallet support exists.
- `@zk-proof-of-funds/sdk/plume` is the JavaScript port (@noble/curves +
  @noble/hashes, locked byte-for-byte to the Rust reference by shared test
  vectors). `buildEnrollV2Request(sk, policyId, scope?)` gives any raw-key JS
  context — an embedded wallet, a key-holding service, a Node script —
  everything `POST /v2/enroll` needs.
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
     (B is blockhash-derived and unpredictable — see the streak note below)
  2. streak_i = prev_streak(addr_i) + 1 if addr_i was in the previous set, else 1
  3. leaf_i = SHA256("zkpof-solvent-leaf-v2" ‖ addr_i ‖ streak_i_be4)
     (entries sorted ascending by address, deduped)
  4. solvent_set_root = SHA256-Merkle-root(leaves)            (same tree rules as V1: odd level duplicates last)
  5. Publish (policy_id, solvent_set_root, epoch, B, |S|) on-chain (SolventSetOracle)
  6. Serve the full entry list via API (it is public data)
```

**Streaks (the time dimension, Phase 11).** A single balance snapshot is
gameable — borrow funds for the sampled block, prove, return them. Each leaf
therefore carries the number of consecutive epochs the address has qualified,
and the reference block is sampled unpredictably (blockhash-derived offset
within the freshness window; `select_reference_block`). A policy demanding
"solvent for ≥ k epochs" then makes rented solvency cost roughly as much as
real solvency.

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
Private inputs:  sk (32B), streak (u32), merkle_siblings (Vec<[u8;32]>), leaf_index (u64)
Public inputs:   solvent_set_root (32B), policy_id (32B), epoch (u64), chain_id (u64),
                 min_streak (u64), scope_hash (32B)

1. assert sk is a valid nonzero scalar; pk = g · sk
2. address = keccak256(pk_uncompressed[1..65])[12..32]
3. assert streak >= min_streak                       (time-dimension gate)
4. leaf = SHA256("zkpof-solvent-leaf-v2" ‖ address ‖ streak_be4)
5. assert MerkleVerify(leaf, leaf_index, merkle_siblings, solvent_set_root)
6. N = hash_to_curve(scope_hash ‖ sec1(pk), DST_H2C) · sk        (ERC-7524 form)
7. nullifier_hash = SHA256(sec1(N))
8. commit abi.encode(solvent_set_root, policy_id, epoch, nullifier_hash, chain_id,
                     min_streak, scope_hash)
```

The exact streak stays private — the proof reveals only that it meets the
policy minimum, not how long the member has actually held funds.

**Public values ABI (normative):** `abi.encode(bytes32 solventSetRoot,
bytes32 policyId, uint64 epoch, bytes32 nullifierHash, uint64 chainId,
uint64 minStreak, bytes32 scopeHash)` — seven 32-byte words, 224 bytes,
committed as a single `commit_slice` blob so Solidity `abi.decode` consumes it
directly. The contract checks `scopeHash == effectiveScopeHash(policyId)`, so
a proof scoped to another policy cannot be replayed under this one.

Note the unification: `nullifier_hash` here equals `member_id` from Construction
A. A member enrolled in monitored mode and the same key proving client-side in V2
present the *same* identity to relying protocols, so the two modes are
interchangeable per policy without integration changes.

### 4.3 On-chain: `SolventSetOracle.sol`

- `publishRoot(policyId, root, epoch, blockNumber, memberCount)` — operator-only,
  epoch strictly increasing, policy active (Stage A, operator-trusted).
- `publishRootProven(policyId, headerRlp, publicValues, proofBytes)` — **anyone**
  may call (Stage B): verifies the SP1 derivation proof against `derivationVKey`,
  binds `stateRoot` to the chain via `keccak256(headerRlp) == blockhash(blockNumber)`
  (state root extracted from the header by a fixed-shape RLP walk), checks
  `prevRoot` against the stored history (streak continuity), and cross-checks
  the policy's threshold/chain. Entries record a `proven` flag.
- `publishRootProvenComplete(policyId, headerRlp, publicValues, proofBytes,
  scanPublicValues, scanProofBytes)` — **anyone** may call: additionally
  verifies a receipt-scan proof (§4.4 Stage B.2) and enforces the composition
  `scan.participantsRoot == derivation.candidatesRoot`, plus that the scan
  covers the policy's token and ends at the current chain tip
  (`blockhash(block.number - 1)`), so a stale scan cannot be replayed.
  Policies with `requiresCompleteness` set accept *only* this path.
- `verifyMembership(policyId, rootIndex, publicValues, proofBytes) →
  (nullifierHash, minStreak)` — view; checks TTL, verifies the SP1 proof
  against `membershipVKey`, decodes and cross-checks the public values against
  the stored entry, and pins `scopeHash` to the policy's configured scope.
  Relying protocols requiring "solvent ≥ k epochs" check `minStreak >= k`.
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
- **Stage B (implemented, Phase 11; ERC-20 in Phase 12)**: prove the
  derivation in SP1 (`program-solvent-set/`, mirror in
  `crates/common/src/solvent_derivation.rs`). The proof shows every entry's
  balance was verified against the block's state root — native ETH via
  EIP-1186 account proofs, ERC-20 via the token account's storage root plus a
  storage proof of `balanceOf[candidate]` at the policy-pinned mapping slot —
  and every streak chains from the previously published set (`prevRoot`
  recommitted inside the proof and matched against on-chain history).
  `SolventSetOracle.publishRootProven` binds the state root to the chain
  through the block header, cross-checks the policy's token and pinned
  `balanceSlot`, and accepts the root from **anyone** — publication itself is
  permissionless. This removes the operator *safety* failure (smuggling an
  insolvent address or inflated streak is impossible).
- **Stage B.2 (statement implemented, Phase 12)**: candidate *completeness*
  for ERC-20s (`crates/common/src/receipt_scan.rs`, `program-receipt-scan/`):
  verify a contiguous header chain, exhaustively enumerate **every receipt of
  every block** (a withheld trie node aborts — no Transfer can be hidden),
  and commit the participant set as `participants_root` — the same
  construction the derivation proof commits as `candidates_root`. Equality of
  the two roots shows the derivation missed no holder active in the scanned
  window — and that composition is **enforced on-chain** by
  `publishRootProvenComplete`. Witness building ships as
  `zkpof-client scan-witness` / `agent::scan_witness`: it re-encodes receipts
  per EIP-2718, rebuilds each block's receipts trie, and accepts the result
  only when `keccak256(header) == block.hash` and the rebuilt root equals the
  header's `receiptsRoot` — so a bad reconstruction fails at build time rather
  than producing an unprovable witness, and the witness *producer* is never
  trusted. Caveats: nonstandard tokens (rebasing, fee-on-transfer) break log
  accounting and must be flagged per policy; the scan must start from the
  token's deployment (or a checkpointed set) to be a true superset.
- **Stage C (research)**: multi-party or light-client-verified candidate
  sourcing so even the candidate list needs no single operator.

An honest framing of the residual trust: with Stage B nobody can fake balances
or streaks, and with Stage B.2 enforced (`requiresCompleteness`) nobody can
silently omit a holder either — the published root must cover every address the
scan saw. What remains is the scan's own starting point: a range that begins
after the token's first Transfer proves completeness only relative to that
window, so policies must pin a range (deployment block, or a checkpoint whose
set is itself proven). For native-ETH policies completeness is still
unproven — there is no log trail for plain balance changes, which is why
Stage C (light-client-verified state enumeration) remains open.

### 4.5 What V2 deliberately does not solve

- **The trilemma**: continuous automation + middleware-blind privacy + no new
  trust — a fresh proof about a secret requires *someone* to hold the secret. V2
  resolves it by making the per-epoch work witness-free and the witness-dependent
  proof a use-time, user-held step. TEEs/MPC could move that back to a service at
  the cost of new trust; out of scope.
- **Non-encumbrance**: proving funds aren't borrowed, key-shared, or pledged
  elsewhere is not possible on a transparent account chain. The economic
  mitigation — streak solvency with randomized reference blocks (§4.1) —
  landed in Phase 11 and was made temporally sound in Phase 15, but it is a
  price, not a proof.

  **What a streak of N actually means.** The address met the threshold at
  **N sampled blocks, one per epoch** — not continuously, and not at any
  block in between. Phase 15 guarantees those N observations are genuinely
  distinct and ordered (sequential epochs, strictly advancing reference
  blocks inside their own windows, each bound to the previous entry on-chain),
  which is what stops one funded snapshot being replayed into an arbitrarily
  long streak. It does **not** turn N samples into continuous holding: funds
  can leave and return between samples. Because the sample points are drawn
  from entropy the holder cannot predict in advance, evading them means
  holding the balance most of the time anyway — that is the deterrent, and it
  is economic, not cryptographic.

  Interfaces must not describe a streak as "held for N epochs". The accurate
  phrasing is "met the threshold at N sampled observations".

---

## 5. Implementation map (this change)

| Piece | Location | Notes |
|---|---|---|
| Nullifier + DLEQ | `crates/common/src/plume.rs` | k256 `hash2curve`, deterministic nonce, 98-byte proof |
| Solvent-set tree (streaks) | `crates/common/src/solvent_set.rs` | Leaf v2 with streak, sorted/deduped entries, path building |
| Membership statement (host mirror) | `crates/common/src/membership.rs` | Native execution + 192-byte ABI; same code as the guest |
| Derivation statement (host mirror) | `crates/common/src/solvent_derivation.rs` | EIP-1186 per candidate, streak continuity, 320-byte ABI; synthetic-trie fixtures |
| Shared MPT verification | `crates/common/src/mpt.rs` | Used by host and guests (agent re-exports as `mpt_verifier`) |
| SP1 membership guest | `program-membership/` | Imports the shared statement; `cargo prove build`, sp1-zkvm 6 |
| SP1 derivation guest | `program-solvent-set/` | Imports the shared statement; `cargo prove build`, sp1-zkvm 6 |
| Low-s hardening | `crates/agent/src/enrollment.rs` | EIP-2 half-order check; malleated signatures rejected |
| Nullifier enrollment | `crates/agent/src/enrollment.rs` | `register_nullifier_member`; `member_id = nullifier_hash` |
| Solvent-set service | `crates/agent/src/solvent_set_service.rs` | Streak persistence, Stage A + Stage B builds, Transfer-log discovery, `select_reference_block` |
| Provers (host drivers) | `crates/agent/src/{membership,derivation}_prover.rs` | Runtime-loaded ELFs, execute + Groth16 prove |
| Client tooling | `crates/agent/src/bin/{zkpof-client,print-vkeys}.rs` | Local signer/prover CLI; vkey generation for deployment |
| DB | `crates/agent/src/db.rs` | `nullifiers`, `solvent_sets` (entries + streaks) tables |
| API | `crates/backend/src/main.rs` | `POST /v2/enroll`, `GET /v2/solvent_set/:policy_id[/leaves]`, `POST /v2/admin/build_solvent_set/:policy_id` (`proven` flag) |
| Oracle | `contracts/src/SolventSetOracle.sol` | publishRoot + publishRootProven (header binding, token/slot pinning) + verifyMembership/verifyAndConsume |
| Storage proofs | `crates/common/src/mpt.rs` | Account-state + storage-slot verification, `erc20_balance_slot`, trie-key API |
| Completeness (B.2) | `crates/common/src/receipt_scan.rs` + `program-receipt-scan/` | Header chain, exhaustive receipts-trie enumeration, Transfer extraction |
| SDK | `sdk/src/` | Streak-aware set fetch + local tree/path computation (core still zero-dep) |
| Wallet crypto | `sdk/src/plume.ts` (`@zk-proof-of-funds/sdk/plume`) | JS nullifier + DLEQ on @noble, cross-language vectors in `plume.test.ts` |
| Vkeys | `config/vkeys.env` | Generated by `print-vkeys`; consumed by Deploy.s.sol |
| Web | `web/src/components/` | `ProveFlow` (guided 4-step flow + CLI handoff), `SolventSetPanel` (explorer + on-chain provenance), `IdentityPanel` (nullifier + V2 enrollment), `ProofViewer` (relying-party inspector), `OperatorPanel` (Stage A/B builds) |
| Public-values decoding | `sdk/src/utils/membership.ts` | Zero-dep 224-byte decode + field cross-check; cross-language vector in `membership.test.ts` |
| Dev seeding | `crates/agent/src/bin/zkpof-devseed.rs` | Populates a solvent set from synthetic balances so the client flow runs without an RPC |

**No server-side path endpoint exists by design** — asking the agent for "the path
for address X" would reveal X. Paths are computed client-side from the public
entry list (SDK, `crates/common`, and `zkpof-client` all implement it).

## 6. Rollout

1. ✅ Land V2 alongside V1 (Phase 10): additive routes, tables, contracts.
2. ✅ Streak solvency + unpredictable reference blocks (Phase 11).
3. ✅ Stage B proven derivation + permissionless publication (Phase 11, native ETH).
4. ✅ Local-signer client path (`zkpof-client`) + vkey deployment wiring (Phase 11).
5. Generate + set the production vkeys (`print-vkeys`, `setMembershipVKey` /
   `setDerivationVKey`) and run Groth16 proving on real infrastructure.
6. ✅ V2 surfaced in the React app beyond the read-only panel (Phase 14): the
   guided prove flow, nullifier derivation + V2 enrollment, on-chain
   provenance, and a proof inspector for relying parties. Proof *generation*
   remains `zkpof-client` — the app generates the exact command and verifies
   the output it returns — until browser-native proving lands (§7). Wallet-side
   PLUME (`eth_getPlumeSignature`) is feature-detected but cannot yet be
   consumed: that needs the ERC-7524 proof-format adapter (§7).

## 7. Open items

Closed since the last revision: on-chain completeness composition, receipt-scan
witness tooling, `scope_hash`, and the plaintext-address fallback (see §4.3,
§4.4, §3.1, and the note below). What genuinely remains:

- **Native-ETH completeness.** Stage B.2 proves candidate completeness from
  Transfer logs, which only exist for tokens. Plain ETH balance changes leave
  no log trail, so a native-ETH policy's candidate list is still
  operator-assembled. Closing this needs proven state enumeration
  (RSP-style block execution, or a light-client-verified state snapshot) —
  Stage C.
- **Scan range provenance.** A completeness proof is relative to the block
  range it scanned. Policies must pin a range that starts at the token's
  deployment or at a checkpoint whose participant set is itself proven;
  the contract currently checks only that the scan *ends* at the chain tip.
- **ERC-7524 proof-format adapter.** Our nullifier already matches the ERC
  exactly, so a wallet's `eth_getPlumeSignature` yields the right identity;
  consuming a wallet-produced *proof* additionally needs a verifier for the
  ERC's own challenge encoding (V1/V2), which should be written against the
  reference implementation's test vectors rather than from the prose spec.
- **Browser-native proving.** SP1 cannot prove in a browser. The two viable
  paths are (a) a small dedicated circuit (circom/noir) for the membership
  statement with the same 224-byte public-values ABI — which needs a trusted
  setup ceremony, not just code — or (b) delegated proving with a TEE
  privacy boundary. `zkpof-client` remains the supported client prover.
- **Ops hardening for proving**: real Groth16 runs on prover infrastructure,
  vkey rotation procedure, and monitoring — tracked under Phase 9.

Explicitly *not* planned:

- **MetaMask snap packaging.** Blocked by design, not by effort: snaps cannot
  derive coin type 60, so they cannot produce a nullifier for the user's own
  EOA (§3.3). ERC-7524 is the path that actually works.
- **Removing the `wallet_address` field entirely.** It is already rejected by
  default (`ZKPOF_ALLOW_PLAINTEXT_ADDRESS=1` re-enables it for un-migrated
  integrators); deleting the field outright is a breaking API change to
  schedule with integrators rather than a code gap.
