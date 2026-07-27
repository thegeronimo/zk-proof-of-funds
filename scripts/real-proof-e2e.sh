#!/usr/bin/env bash
#
# Real end-to-end proof verification (EXECUTION_PLAN.md Phase 15.6).
#
# Everything the test suite covers today stops short of the one thing that
# matters most: that an actual Groth16 proof, produced by the actual guest
# ELF, is accepted by the actual deployed SP1 verifier through our oracle.
# Until this script passes on a given commit, no surface may describe the
# system as producing verified proofs — the demo is a protocol simulation.
#
# The chain is deliberately unbroken:
#
#   guest source -> ELF -> vkey -> Groth16 proof -> public values
#     -> deployed SP1 verifier -> SolventSetOracle -> accepted tx
#
# and then every field is mutated one at a time to confirm rejection. A test
# that only ever feeds *valid* input cannot tell a real verifier from a stub.
#
# Requirements: SP1 toolchain (`cargo prove`), Docker (Groth16 wrapping needs
# it and ~16 GB RAM), Foundry, and an anvil instance. Set SP1_PROVER=network
# with NETWORK_PRIVATE_KEY to prove remotely instead of locally.
#
# Usage:
#   scripts/real-proof-e2e.sh [--skip-build]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/target/e2e"
MANIFEST="${OUT}/artifact-manifest.json"
SKIP_BUILD="${1:-}"

mkdir -p "${OUT}"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

# ── Preflight ───────────────────────────────────────────────────────────────

step "Checking toolchain"
command -v cargo >/dev/null || fail "cargo not found"
command -v forge >/dev/null || fail "forge not found (Foundry)"
if ! cargo prove --version >/dev/null 2>&1; then
  fail "SP1 toolchain not found. Install: curl -L https://sp1up.succinct.xyz | bash && sp1up"
fi
if [ "${SP1_PROVER:-cpu}" = "cpu" ] && ! docker info >/dev/null 2>&1; then
  fail "Docker is required for local Groth16 wrapping. Start Docker, or set SP1_PROVER=network."
fi

# ── 1. Build every guest, recording exactly what was built ──────────────────

GUESTS=(program program-membership program-solvent-set program-receipt-scan)

if [ "${SKIP_BUILD}" != "--skip-build" ]; then
  for guest in "${GUESTS[@]}"; do
    step "Building guest: ${guest}"
    (cd "${ROOT}/${guest}" && cargo prove build) || fail "cargo prove build failed for ${guest}"
  done
fi

step "Recording artifact manifest"
# The manifest is the reproducibility contract: a proof is only meaningful
# relative to the exact ELF and vkey it was produced under, so a release
# records both alongside the verifier it was checked against.
GIT_COMMIT="$(git -C "${ROOT}" rev-parse HEAD)"
GIT_DIRTY="$(git -C "${ROOT}" status --porcelain | head -c1)"
RUST_VERSION="$(rustc --version)"
SP1_VERSION="$(cargo prove --version 2>&1 | head -1)"

{
  printf '{\n'
  printf '  "git_commit": "%s",\n' "${GIT_COMMIT}"
  printf '  "git_dirty": %s,\n' "$([ -n "${GIT_DIRTY}" ] && echo true || echo false)"
  printf '  "rust_version": "%s",\n' "${RUST_VERSION}"
  printf '  "sp1_version": "%s",\n' "${SP1_VERSION}"
  printf '  "public_values_schema": {\n'
  printf '    "membership_bytes": 448,\n'
  printf '    "derivation_bytes": 448,\n'
  printf '    "scan_bytes": 224\n'
  printf '  },\n'
  printf '  "guests": {\n'
  first=1
  for guest in "${GUESTS[@]}"; do
    elf=$(find "${ROOT}/${guest}/target/elf-compilation" -type f -name 'zk-pof-*' ! -name '*.d' 2>/dev/null | head -1)
    [ -n "${elf}" ] || fail "No ELF found for ${guest} — run without --skip-build"
    sha=$(shasum -a 256 "${elf}" | cut -d' ' -f1)
    size=$(wc -c < "${elf}" | tr -d ' ')
    [ ${first} -eq 1 ] || printf ',\n'
    first=0
    printf '    "%s": { "elf_sha256": "%s", "elf_bytes": %s }' "${guest}" "${sha}" "${size}"
  done
  printf '\n  }\n}\n'
} > "${MANIFEST}"

cat "${MANIFEST}"

# ── 2. Verification keys ────────────────────────────────────────────────────

step "Deriving verification keys"
# print-vkeys reads the built ELFs and prints the vkeys the oracle must be
# configured with. A vkey mismatch is the single most common cause of a
# "valid" proof being rejected on-chain, so it is derived here, never assumed.
cargo run --quiet --bin print-vkeys > "${OUT}/vkeys.env" || fail "print-vkeys failed"
cat "${OUT}/vkeys.env"

# ── 3. Real proofs ──────────────────────────────────────────────────────────
#
# Each of these must produce a Groth16 proof and have it accepted by the
# deployed verifier. They are ordered cheapest-first so a broken toolchain
# fails fast.

step "TODO: generate + verify real proofs"
cat <<'NOTES'
Remaining work to finish Phase 15.6 (tracked in EXECUTION_PLAN.md):

  a. Start anvil and deploy SP1VerifierGroth16 + PolicyRegistry +
     SolventSetOracle, configured with the vkeys printed above.
  b. Generate a real derivation proof against a forked mainnet block and
     submit publishRootProven; assert the tx succeeds and the stored entry
     matches the committed public values field for field.
  c. Generate a real membership proof against that root, with a full
     presentation context, and call verifyMembership; assert it returns the
     expected nullifier and minStreak.
  d. Generate a real receipt-scan proof and submit publishRootProvenComplete;
     assert the stored scan range matches the proven headers.
  e. Mutation pass — for each of the following, flip one value and assert the
     call REVERTS:
       proof byte, root, epoch, prevBlockNumber, blockNumber, stateRoot,
       chainId, threshold, token, balanceSlot, candidatesRoot, scanStartBlock,
       scanEndBlock, vkey, scopeHash, policyConfigHash, verifier, beneficiary,
       deadline, nonce
     A mutation that still succeeds means that field is not actually bound.

This script currently establishes the reproducible build + vkey derivation
half. Until (a)-(e) run green in CI, the demo must be labelled a protocol
simulation, not a working ZK proof-of-funds deployment.
NOTES

step "Artifact manifest written to ${MANIFEST}"
