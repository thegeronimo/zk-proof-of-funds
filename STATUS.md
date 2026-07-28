# Project status

Short, honest answer to "what works, what doesn't, what's next". Detail lives
in [EXECUTION_PLAN.md](EXECUTION_PLAN.md); this page exists so nobody has to
read 1,500 lines to find out whether something is safe to rely on.

**Last updated**: 2026-07-27, end of Phase 16.

---

## The one-line version

> The protocol is implemented and its soundness bugs are fixed, but **no proof
> has ever been verified by a Solidity contract**. Until that happens, every
> user-facing surface says "protocol simulation", and that wording is correct.

---

## What this system actually proves

Precision matters here, because the marketing-shaped version of this sentence
is false:

> The prover controls the signing key of an **externally-owned account** whose
> address was in a committed set of addresses classified as meeting a balance
> threshold at one or more **historical sampled blocks**.

It does **not** establish beneficial ownership, exclusive key control, absence
of liabilities or encumbrances, that the funds were not borrowed, that the
balance still exists now, or anything about smart-contract accounts (Safe,
ERC-4337, passkeys — all unsupported).

"Solvency" would be the wrong word: solvency is assets minus liabilities, and
this measures a historical on-chain asset predicate. Interfaces say
"threshold-balance attestation".

A **streak of N** means the threshold was met at N *sampled observations*, one
per epoch — not held continuously. Funds can leave and return between samples.
Because the sample points are drawn from entropy nobody can predict while the
window is open, evading them means holding the balance most of the time — that
is an economic deterrent, not a proof.

---

## Verified vs. not

| Claim | Status | How it is established |
|---|---|---|
| Contract logic binds every public value | ✅ Verified | `contracts/test/E2EMutation.t.sol` — one-field-at-a-time mutation matrix, validated with negative controls |
| MPT verifier agrees with a production client | ✅ Verified | `crates/common/tests/mpt_differential.rs` — differential fuzz vs `alloy-trie` (reth's implementation) |
| Guest circuits match their host mirrors | ✅ Verified | `cargo test --test privacy_v2_integration -- --ignored` — real ELFs in the SP1 emulator |
| A real proof exists and verifies | ✅ Verified | `zkpof-e2e derivation-compressed` — real recursive STARK, checked by SP1's verifier |
| **A proof verifies on-chain (EVM)** | ❌ **NOT verified** | Needs the Groth16 wrap; see below |
| MPT verifier reviewed by a cryptographer | ❌ **NOT done** | Third-party task |

### Why the EVM leg is outstanding

SP1 wraps proofs to Groth16 by shelling out to Succinct's `sp1-gnark` Docker
image, which is published for **amd64 only**. On Apple Silicon it cannot run
at all — with or without Docker, at any amount of RAM.

The fix is not local: `.github/workflows/real-proof-e2e.yml` runs it on
GitHub's amd64 runners. That workflow is **written but has never executed**
(no remote is configured). So the EVM claim is *plumbed*, not *demonstrated*.

**Do not remove the "protocol simulation" labelling until that workflow is
green on a commit.**

---

## Phase status

| Phase | What | Status |
|---|---|---|
| 0–14 | Foundation → Privacy V2 → front-end parity | ✅ Complete |
| 15 | Protocol soundness (external-review blockers) | ✅ Complete except external `mpt.rs` review |
| 16 | Ops hardening + honest presentation | ✅ Complete |
| 17 | Mode A/B split, browser prover (**gate G1**) | 🟡 Next |
| 18 | Direct EIP-1186 state proof (**gate G2**), deferred capabilities | 🟢 After 17 |

Phases 17 and 18 are **decision-gated spikes**, not more remediation. The
external review's own framing was that measurements — not architectural
preference — should choose the default proving mode. G1 asks whether a
Noir/Barretenberg circuit can prove membership fast enough on a phone; G2 asks
whether proving one EIP-1186 path directly beats maintaining a global solvent
set. Build and benchmark before committing to either.

---

## What the 2026-07 external review changed

An external protocol review found six critical/high issues. All were verified
against the code before any work started, and all were confirmed. Full
assessment table in [EXECUTION_PLAN.md](EXECUTION_PLAN.md#external-review-2026-07--findings-assessment).
The headline fixes:

- **MPT** — the verifier accepted an empty proof as proof-of-absence against
  *any* root, which let an operator censor qualifying accounts from a root
  advertised as complete. Now absence must be proven.
- **Streaks** — one funded snapshot could be replayed into an arbitrarily long
  streak. Epochs must now be sequential with strictly advancing reference
  blocks, and the reference block is *sampled* from post-window entropy rather
  than chosen by the publisher.
- **Scan ranges** — `numBlocks` was decoded and discarded. The range is now
  proven from block headers and stored on-chain, and `proven: bool` became a
  three-valued `Provenance` enum, because "balances proven" and "list complete"
  are different claims.
- **Policy mutability** — a published root's meaning could be rewritten under
  it. Roots now pin their own config hash, vkeys, and expiry; policies freeze
  on first publication.
- **Proof binding** — membership proofs were bearer tokens, replayable at any
  verifier and front-runnable out of the mempool. They now carry a presentation
  context (verifier, action, beneficiary, nonce, deadline).

### Breaking changes

Nothing was ever deployed, so there is no migration path and none is needed:

| Blob | Before | After |
|---|---|---|
| Membership public values | 224 B | **448 B** |
| Derivation public values | 416 B | **448 B** |
| Scan public values | 160 B | **224 B** |

`SetEntry.proven: bool` → `Provenance` enum; `Policy` gains `startBlock` and
`version`.

---

## Conventions that are easy to get wrong

- **Empty set vs. no set.** An empty solvent set hashes to
  `SHA256("zkpof-empty-solvent-set-v1")`, so "nobody qualified this epoch" is
  publishable. `bytes32(0)` still means "no root at all". The discriminator for
  the first epoch is `prevBlockNumber == 0`, *not* an empty previous entry list.
- **`maxBlockAge` changed meaning.** It now bounds how long *after the epoch
  window closes* a publication may land — not the age of the reference block,
  which the publisher no longer chooses.
- **A wrong ERC-20 balance slot is a liveness failure, not a safety one.** With
  correct non-inclusion handling, a proof against the wrong slot proves the slot
  absent, so the balance reads zero and the candidate is excluded. It can never
  credit a balance, and `balanceSlot` is committed publicly so the
  misconfiguration is visible.
- **Test discipline: use negative controls.** Every safety test added in Phase
  15/16 was validated by reintroducing the bug and confirming the test fails.
  A passing test that *cannot* fail is worthless, and this codebase has already
  shipped one (the original MPT fixtures reproduced the very bug they should
  have caught).

---

## Running things

```bash
cargo test --workspace                 # Rust: common, agent, differential fuzz
cd contracts && forge test             # Solidity: 195 tests incl. mutation matrix
cd sdk && npx vitest run               # SDK, incl. cross-language vectors
cd web && npx tsc --noEmit && npm run build

bash scripts/real-proof-e2e.sh         # full proof pipeline (see below)
```

`real-proof-e2e.sh` degrades by platform: it always runs the compressed-proof
tier, the mutation matrix, and an anvil deployment, and skips the Groth16 legs
with an explicit message on arm64. `SKIP_VKEYS=1` skips SP1 setup (minutes per
program); `--skip-build` reuses already-built guest ELFs.

### Environment notes

- Git worktrees do **not** inherit `contracts/lib` (Foundry submodules),
  `node_modules`, or `target/` — install or copy them.
- The Groth16 circuit artifact is ~8 GB and caches at `~/.sp1/circuits`. It is
  useless on arm64; delete it if you are not on x86_64.
