/**
 * Example: Solvency-gated DAO governance voting.
 *
 * This script demonstrates how a DAO can require voters to prove solvency
 * before casting votes, ensuring "skin in the game" for governance decisions.
 *
 * Flow:
 * 1. Proposal is created on-chain
 * 2. Voter fetches their solvency proof from the agent
 * 3. Voter submits vote + proof to the governance contract
 * 4. Contract verifies solvency before counting the vote
 *
 * Requires: @zk-proof-of-funds/sdk, ethers
 */

import { SolvencyClient } from "@zk-proof-of-funds/sdk";

const AGENT_URL = "http://localhost:3000";
const POLICY_ID =
  "0x0202020202020202020202020202020202020202020202020202020202020202";

const client = new SolvencyClient({ agentUrl: AGENT_URL });

// ─── Voting Flow ────────────────────────────────────────────────────────────

async function voteOnProposal(
  memberId: string,
  proposalId: number,
  support: boolean
) {
  // 1. Check member is currently solvent
  const status = await client.getMemberStatus(POLICY_ID, memberId);

  if (status.status !== "solvent") {
    console.error(
      `Cannot vote: member status is "${status.status}".`,
      "Only solvent members can vote."
    );
    return;
  }

  // 2. Fetch the Merkle proof
  const proof = await client.getMemberProof(POLICY_ID, memberId);

  console.log(`Voting ${support ? "FOR" : "AGAINST"} proposal #${proposalId}`);
  console.log("  Member ID:", memberId.slice(0, 16) + "...");
  console.log("  Epoch:", proof.epoch);
  console.log("  Proof depth:", proof.merkle_proof.length);

  // 3. Build the on-chain transaction
  // In a real app:
  //
  // const governor = new ethers.Contract(GOV_ADDRESS, SolvencyGatedGovernorABI, signer);
  // const tx = await governor.vote(
  //   proposalId,                      // uint256
  //   support,                         // bool
  //   memberId,                        // bytes32
  //   proof.epoch,                     // uint64
  //   proof.merkle_proof,              // bytes32[]
  //   proof.leaf_index,                // uint256
  //   0,                               // rootIndex (latest)
  // );
  // await tx.wait();

  console.log("Vote transaction calldata ready.");
}

// ─── Admin: List all members and their status ───────────────────────────────

async function listVoters() {
  const result = await client.listMembers(POLICY_ID);

  console.log(`\nPolicy members: ${result.member_count}`);
  for (const member of result.members) {
    const eligible = member.status === "solvent" ? "ELIGIBLE" : "INELIGIBLE";
    console.log(
      `  ${member.member_id.slice(0, 16)}... [${eligible}] balance=${member.last_balance_wei} wei`
    );
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== Solvency-Gated Governance Voting ===\n");

  const memberId =
    "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

  await listVoters();
  await voteOnProposal(memberId, 1, true);
}

main().catch(console.error);
