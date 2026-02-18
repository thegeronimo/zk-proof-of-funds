/**
 * Example: Solvency-gated NFT minting.
 *
 * This script demonstrates how an NFT project can use solvency proofs as
 * an allowlist mechanism, replacing traditional whitelists with financial
 * proof of stake.
 *
 * Flow:
 * 1. User enrolls in the solvency policy
 * 2. User fetches solvency proof from agent
 * 3. User mints NFT by providing the proof + payment
 * 4. Contract verifies solvency before minting
 *
 * Requires: @zk-proof-of-funds/sdk
 */

import {
  SolvencyClient,
  buildEnrollmentMessage,
} from "@zk-proof-of-funds/sdk";

const AGENT_URL = "http://localhost:3000";
const POLICY_ID =
  "0x0303030303030303030303030303030303030303030303030303030303030303";

const client = new SolvencyClient({ agentUrl: AGENT_URL });

// ─── Mint Flow ──────────────────────────────────────────────────────────────

async function mintWithSolvencyProof(memberId: string) {
  // 1. Verify the member is solvent
  const status = await client.getMemberStatus(POLICY_ID, memberId);
  if (status.status !== "solvent") {
    console.error("Not eligible to mint: must be solvent.");
    return;
  }

  // 2. Fetch Merkle proof
  const proof = await client.getMemberProof(POLICY_ID, memberId);

  console.log("Minting NFT with solvency proof:");
  console.log("  Member:", memberId.slice(0, 16) + "...");
  console.log("  Status: SOLVENT");
  console.log("  Epoch:", proof.epoch);
  console.log("  Proof depth:", proof.merkle_proof.length, "levels");

  // 3. Build the on-chain transaction
  // In a real app:
  //
  // const nft = new ethers.Contract(NFT_ADDRESS, SolvencyGatedNFTABI, signer);
  // const tx = await nft.mint(
  //   memberId,                        // bytes32
  //   proof.epoch,                     // uint64
  //   proof.merkle_proof,              // bytes32[]
  //   proof.leaf_index,                // uint256
  //   0,                               // rootIndex (latest)
  //   { value: MINT_PRICE }
  // );
  // const receipt = await tx.wait();
  // const tokenId = receipt.logs[0].args.tokenId;

  console.log("Mint transaction calldata ready.");
}

// ─── Eligibility Check ──────────────────────────────────────────────────────

async function checkEligibility(memberId: string) {
  try {
    const status = await client.getMemberStatus(POLICY_ID, memberId);
    const eligible = status.status === "solvent";

    console.log("\nEligibility check:");
    console.log("  Status:", status.status);
    console.log("  Balance:", status.last_balance_wei, "wei");
    console.log("  Eligible to mint:", eligible ? "YES" : "NO");

    return eligible;
  } catch {
    console.log("  Member not found. Please enroll first.");
    return false;
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== Solvency-Gated NFT Mint ===\n");

  const memberId =
    "1122334455667788112233445566778811223344556677881122334455667788";

  const eligible = await checkEligibility(memberId);
  if (eligible) {
    await mintWithSolvencyProof(memberId);
  }
}

main().catch(console.error);
