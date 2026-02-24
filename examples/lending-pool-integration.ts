/**
 * Example: Integrating solvency-gated deposits with a DeFi lending pool.
 *
 * This script demonstrates the full flow:
 * 1. User enrolls in a solvency policy
 * 2. Agent monitors balance and produces Merkle proofs
 * 3. User fetches proof from the agent
 * 4. User deposits into the pool, providing the proof on-chain
 *
 * Requires: @zk-proof-of-funds/sdk, ethers
 */

import {
  SolvencyClient,
  buildEnrollmentMessage,
  computeMemberId,
} from "@zk-proof-of-funds/sdk";

// ─── Configuration ──────────────────────────────────────────────────────────

const AGENT_URL = "http://localhost:3000";
const POLICY_ID =
  "0x0101010101010101010101010101010101010101010101010101010101010101";

// ─── Step 1: Initialize the SDK ─────────────────────────────────────────────

const client = new SolvencyClient({ agentUrl: AGENT_URL });

// ─── Step 2: Enrollment (one-time) ──────────────────────────────────────────

async function enrollUser(
  signMessage: (msg: string) => Promise<string>
) {
  // Build the enrollment message
  const nonce = Math.floor(Math.random() * 1_000_000).toString();
  const message = buildEnrollmentMessage("lending-pool", nonce);

  // User signs with their wallet (e.g., MetaMask, wagmi, ethers.js)
  const signature = await signMessage(message);

  // Compute memberId client-side (for UI display)
  const memberId = await computeMemberId(signature);
  console.log("Computed memberId:", memberId);

  // Submit enrollment to the agent (no wallet address sent — full privacy)
  const result = await client.enroll({
    policy_id: POLICY_ID,
    signature,
    signed_message: message,
  });

  console.log("Enrolled! Member ID:", result.member_id);
  console.log("Effective epoch:", result.effective_epoch);
  return result.member_id;
}

// ─── Step 3: Fetch proof and deposit ────────────────────────────────────────

async function depositWithProof(memberId: string) {
  // Fetch the latest Merkle proof from the agent
  const proof = await client.getMemberProof(POLICY_ID, memberId);

  if (proof.status !== 1) {
    console.error("Member is not solvent! Cannot deposit.");
    return;
  }

  console.log("Proof fetched:");
  console.log("  Epoch:", proof.epoch);
  console.log("  Leaf index:", proof.leaf_index);
  console.log("  Proof depth:", proof.merkle_proof.length);
  console.log("  Root:", proof.root);

  // Build the on-chain transaction
  // In a real app, you'd use ethers.js or viem to send this:
  //
  // const pool = new ethers.Contract(POOL_ADDRESS, SolvencyGatedPoolABI, signer);
  // const tx = await pool.deposit(
  //   memberId,                        // bytes32
  //   proof.epoch,                     // uint64
  //   proof.merkle_proof,              // bytes32[]
  //   proof.leaf_index,                // uint256
  //   0,                               // rootIndex (latest)
  //   { value: ethers.parseEther("1") }
  // );
  // await tx.wait();

  console.log("Transaction calldata ready for SolvencyGatedPool.deposit()");
}

// ─── Step 4: Check status ───────────────────────────────────────────────────

async function checkStatus(memberId: string) {
  const status = await client.getMemberStatus(POLICY_ID, memberId);

  console.log("Member status:", status.status);
  console.log("Last balance:", status.last_balance_wei, "wei");
  console.log("Last checked block:", status.last_checked_block);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== Lending Pool Solvency Integration ===\n");

  // In production, signMessage comes from the user's wallet:
  //   const signer = await provider.getSigner();
  //   const signMessage = (msg: string) => signer.signMessage(msg);
  const mockSignMessage = async (_msg: string) =>
    "0x" + "ab".repeat(65); // placeholder

  const memberId = await enrollUser(mockSignMessage);

  await checkStatus(memberId);
  await depositWithProof(memberId);
}

main().catch(console.error);
