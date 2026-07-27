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
# Docker gates only the Groth16 legs. Everything else — builds, manifest,
# vkeys, the mutation matrix, deployment — runs without it, and those are the
# parts that catch unbound fields. Degrade rather than refuse.
CAN_PROVE=1
if [ "${SP1_PROVER:-cpu}" = "cpu" ] && ! docker info >/dev/null 2>&1; then
  CAN_PROVE=0
  printf '\033[33mNOTE: Docker is not running, so real Groth16 proofs cannot be\n'
  printf '      generated locally. Running every other leg. Start Docker, or set\n'
  printf '      SP1_PROVER=network with NETWORK_PRIVATE_KEY, for the full run.\033[0m\n'
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

# print-vkeys reads the built ELFs and prints the vkeys the oracle must be
# configured with. A vkey mismatch is the single most common cause of a
# "valid" proof being rejected on-chain, so it is derived here, never assumed.
#
# SP1 setup is minutes per program, so this is skippable when you only want
# the fast legs (mutation matrix, deployment).
if [ "${SKIP_VKEYS:-0}" = "1" ]; then
  step "Skipping vkey derivation (SKIP_VKEYS=1)"
else
  step "Deriving verification keys (SP1 setup — minutes per program)"
  cargo run --quiet --bin print-vkeys > "${OUT}/vkeys.env" || fail "print-vkeys failed"
  cat "${OUT}/vkeys.env"
fi

# ── 3. Real Groth16 proofs (requires Docker or the prover network) ──────────

if [ "${CAN_PROVE}" = "1" ]; then
  step "Generating a real Groth16 derivation proof"
  # Release build: a debug-built prover is unusably slow.
  cargo run --release --quiet --bin zkpof-e2e -- derivation \
    || fail "Groth16 proof generation failed"

  step "Verifying the real proof against the real deployed SP1 verifier"
  # This is the link nothing else in the repo covers: actual guest ELF ->
  # actual Groth16 wrap -> actual on-chain verifier. It also asserts that
  # tampered public values and a wrong vkey are rejected, without which
  # "it verified" would prove nothing.
  if ! command -v anvil >/dev/null; then
    fail "anvil is required for the on-chain verification leg"
  fi
  anvil --silent --port 8546 &
  PROVE_ANVIL_PID=$!
  trap 'kill ${PROVE_ANVIL_PID} 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do
    cast block-number --rpc-url http://127.0.0.1:8546 >/dev/null 2>&1 && break
    sleep 0.2
  done

  export DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  (cd "${ROOT}/contracts" && forge script script/RealProofE2E.s.sol \
      --rpc-url http://127.0.0.1:8546 --broadcast) \
    || fail "the real proof was NOT accepted by the deployed SP1 verifier"

  kill ${PROVE_ANVIL_PID} 2>/dev/null || true
  REAL_PROOF_VERIFIED=1
else
  step "Skipping real Groth16 proofs (no Docker / prover network)"
  REAL_PROOF_VERIFIED=0
fi

# ── 4. Contract-level end-to-end + mutation matrix ──────────────────────────
#
# Runs without Docker: every binding the contract performs is exercised, with
# only the SNARK itself mocked. The mutation matrix is the part that matters —
# it walks the public-values blob one field at a time and requires each
# mutation to be rejected, which is what distinguishes a real verifier from a
# stub. Validated with negative controls: removing a single binding in the
# contract makes exactly the corresponding mutation test fail.

step "Contract-level E2E + mutation matrix"
(cd "${ROOT}/contracts" && forge test --match-contract E2EMutationTest -vv) \
  || fail "mutation matrix failed — a public value is not actually bound"

step "Full contract suite"
(cd "${ROOT}/contracts" && forge test) || fail "contract suite failed"

# ── 5. Live deployment smoke test on anvil ──────────────────────────────────

step "Deploying to a throwaway anvil"
if ! command -v anvil >/dev/null; then
  echo "anvil not found — skipping the live deployment leg"
else
  anvil --silent --port 8545 &
  ANVIL_PID=$!
  trap 'kill ${ANVIL_PID} 2>/dev/null || true' EXIT
  # Wait for readiness rather than sleeping a fixed amount.
  for _ in $(seq 1 50); do
    cast block-number --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1 && break
    sleep 0.2
  done

  # anvil's first well-known dev key. Safe to hard-code: it is a published
  # test key on a throwaway local chain, never a real account.
  export DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  (cd "${ROOT}/contracts" && forge script script/Deploy.s.sol \
      --rpc-url http://127.0.0.1:8545 \
      --broadcast) \
    || fail "deployment to anvil failed"
  echo "Deployment succeeded (registry + oracle wired, freezer authorized)."
fi

# ── 6. What is still missing ────────────────────────────────────────────────

step "Remaining work for a full real-proof E2E"
cat <<'NOTES'
DONE here:
  - reproducible guest builds + artifact manifest (ELF hashes, toolchain)
  - verification keys derived from the built ELFs (unless SKIP_VKEYS=1)
  - contract-level publish/verify with a one-field-at-a-time mutation matrix
  - live deployment to anvil

NOTES

if [ "${REAL_PROOF_VERIFIED:-0}" = "1" ]; then
  cat <<'NOTES'
  - a REAL Groth16 derivation proof, verified by the REAL deployed
    SP1VerifierGroth16 v6.0.0, with tampered-publics and wrong-vkey both
    rejected

Still outstanding: the same round trip for the membership and receipt-scan
programs, and driving it through publishRootProven end to end rather than
verifying the proof directly.
NOTES
else
  cat <<'NOTES'

STILL REQUIRED for the real-Groth16 claim (needs Docker + ~16 GB RAM, or
SP1_PROVER=network with a NETWORK_PRIVATE_KEY):
  - generate real Groth16 proofs for membership / derivation / receipt scan
  - deploy SP1VerifierGroth16 and verify them against it
  - drive publishRootProven + verifyMembership through that real verifier

Until that passes, the demo is a PROTOCOL SIMULATION: the contract logic is
verified, the proof system integration is not.
NOTES
fi

step "Artifact manifest written to ${MANIFEST}"
