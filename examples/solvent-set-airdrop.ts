/**
 * Example: claiming a Privacy V2 solvent-set airdrop.
 *
 * The V2 counterpart to `lending-pool-integration.ts`. The two flows differ in
 * a way worth seeing side by side:
 *
 *   Monitored mode (V1)          Solvent-set mode (V2)
 *   ────────────────────         ─────────────────────
 *   enroll with the agent        no enrollment at all
 *   agent watches your address   agent never learns your address
 *   fetch your proof from agent  build your own proof locally
 *   identity = SHA256(signature) identity = nullifier hash
 *
 * The steps here are:
 *   1. Download the whole public solvent set and rebuild its root locally.
 *   2. Locate your own address in it — client-side, so no query reveals it.
 *   3. Generate the SP1 membership proof with `zkpof-client` (native; see the
 *      note in step 3 for why this is not JavaScript).
 *   4. Decode the proof's public values and check them before spending gas.
 *   5. Submit to SolventSetGatedAirdrop.claim().
 *
 * Requires: @zk-proof-of-funds/sdk, ethers, and the `zkpof-client` binary.
 */

import {
  SolvencyClient,
  computeSolventSetRoot,
  computeSolventSetPath,
  decodeMembershipPublicValues,
  checkMembershipPublicValues,
  type SolventSetEntryTuple,
} from "@zk-proof-of-funds/sdk";

// ─── Configuration ──────────────────────────────────────────────────────────

const AGENT_URL = "http://localhost:3000";
const POLICY_ID =
  "0x0000000000000000000000000000000000000000000000000000000000000001";
const CHAIN_ID = 1;

/** The streak SolventSetGatedAirdrop was deployed with. */
const REQUIRED_STREAK = 3;

const client = new SolvencyClient({ agentUrl: AGENT_URL });

// ─── Step 1: Download the set and verify it yourself ────────────────────────

async function downloadAndVerifySet() {
  // Fetch *everything*. Downloading the whole set is what makes the lookup
  // oblivious — asking "is address X in the set?" would reveal X.
  const { info, entries } = await client.fetchAllSolventSetEntries(POLICY_ID);

  // Never trust the served root. Rebuild it from the entries you were given;
  // if they disagree, the agent is serving inconsistent data and any proof
  // built against it would fail on-chain anyway.
  const rebuilt = await computeSolventSetRoot(entries as SolventSetEntryTuple[]);
  const served = info.root.replace(/^0x/, "").toLowerCase();
  if (rebuilt.toLowerCase() !== served) {
    throw new Error(
      `Root mismatch: rebuilt ${rebuilt} but agent served ${served}. Do not use this set.`
    );
  }

  console.log(`Set verified: epoch ${info.epoch}, ${entries.length} members`);
  return { info, entries: entries as SolventSetEntryTuple[] };
}

// ─── Step 2: Find yourself, locally ─────────────────────────────────────────

async function findMyself(entries: SolventSetEntryTuple[], myAddress: string) {
  const path = await computeSolventSetPath(entries, myAddress);
  if (!path) {
    throw new Error(
      "Your address is not in this epoch's set — it was below the threshold at the reference block."
    );
  }

  console.log(`Found at leaf ${path.leafIndex}, streak ${path.streak}`);

  // Your streak is the ceiling on what you can prove. Catch this here rather
  // than after paying for a proof.
  if (path.streak < REQUIRED_STREAK) {
    throw new Error(
      `Streak ${path.streak} is below the airdrop's required ${REQUIRED_STREAK}.`
    );
  }
  return path;
}

// ─── Step 3: Generate the proof (native, not JavaScript) ────────────────────

/**
 * SP1 cannot prove in a browser or in Node, and the nullifier needs raw key
 * access that wallets do not grant — so this step is a local CLI invocation.
 * Run it yourself and feed the JSON back in:
 *
 * ```bash
 * zkpof-client prove \
 *   --sk <YOUR_32_BYTE_HEX_KEY> \
 *   --policy 0x00...01 \
 *   --agent http://localhost:3000 \
 *   --min-streak 3 \
 *   --chain-id 1
 * ```
 *
 * It prints `{ mode, proof_bytes, public_values_abi, ... }`. The secret key
 * never leaves your machine; the agent only ever saw you download the set.
 */
interface ProveOutput {
  mode: "execute" | "groth16";
  proof_bytes?: string;
  public_values_abi: string;
}

// ─── Step 4: Check the proof before spending gas ────────────────────────────

function inspectProof(output: ProveOutput, expectedRoot: string, epoch: number) {
  if (output.mode !== "groth16" || !output.proof_bytes) {
    throw new Error(
      "This output was emulated (--execute-only) and has no proof bytes to submit."
    );
  }

  const values = decodeMembershipPublicValues(output.public_values_abi);

  // Cross-check against what you independently established above. The oracle
  // performs equivalent checks on-chain; doing them here turns an opaque
  // revert into a specific, readable failure.
  const result = checkMembershipPublicValues(values, {
    solventSetRoot: expectedRoot,
    policyId: POLICY_ID,
    epoch,
    chainId: CHAIN_ID,
    requiredMinStreak: REQUIRED_STREAK,
  });

  if (!result.ok) {
    const detail = result.failures
      .map((f) => `${f.field}: expected ${f.expected}, got ${f.actual}`)
      .join("; ");
    throw new Error(`Proof does not match expectations — ${detail}`);
  }

  console.log(`Proof valid for identity ${values.nullifierHash}`);
  console.log(`Attests to a streak of >= ${values.minStreak} epochs`);
  return values;
}

// ─── Step 5: Claim on-chain ─────────────────────────────────────────────────

const AIRDROP_ABI = [
  "function claim(uint256 setIndex, bytes publicValues, bytes proofBytes, address recipient)",
  "function checkEligible(uint256 setIndex, bytes publicValues, bytes proofBytes) view returns (bool eligible, bytes32 nullifierHash, uint64 minStreak)",
];

async function claim(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  airdrop: any,
  setIndex: number,
  output: ProveOutput,
  recipient: string
) {
  // Preflight against the view path so a bad claim doesn't burn the nullifier.
  const [eligible, nullifierHash] = await airdrop.checkEligible(
    setIndex,
    output.public_values_abi,
    output.proof_bytes
  );
  if (!eligible) {
    throw new Error(`Not eligible (identity ${nullifierHash} may have already claimed).`);
  }

  // `recipient` is deliberately unrelated to the address that proved. You
  // proved *a* solvent wallet is claiming; sending the payout to the proving
  // address would undo the unlinkability the proof just bought you.
  const tx = await airdrop.claim(
    setIndex,
    output.public_values_abi,
    output.proof_bytes,
    recipient
  );
  const receipt = await tx.wait();
  console.log(`Claimed in ${receipt.hash}`);
  return receipt;
}

// ─── Putting it together ────────────────────────────────────────────────────

export async function runAirdropClaim(
  myAddress: string,
  proveOutput: ProveOutput,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  airdropContract: any,
  recipient: string
) {
  const { info, entries } = await downloadAndVerifySet();
  await findMyself(entries, myAddress);

  inspectProof(proveOutput, info.root, info.epoch);

  // The on-chain set index, not the epoch — read it from the oracle
  // (`latestSetIndex(policyId)`) or track it as sets are published.
  const setIndex = 0;
  return claim(airdropContract, setIndex, proveOutput, recipient);
}
