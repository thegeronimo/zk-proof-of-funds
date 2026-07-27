// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ISolventSetOracle
/// @notice Interface for relying protocols verifying Privacy V2 membership proofs.
/// @dev The V2 counterpart to {ISolvencyOracle}. The two differ in what the
///      caller supplies and what they learn:
///
///      - {ISolvencyOracle} (monitored mode) takes a `memberId` the caller
///        already knows, plus a Merkle path. The member enrolled with the
///        agent, so the agent knows which address is being watched.
///      - This interface takes an SP1 proof and *returns* the prover's
///        identity. The prover never enrolled and never revealed an address;
///        they proved membership of the public solvent set in zero knowledge.
///
///      Both surface the same stable, unlinkable identity for a given key and
///      policy — a nullifier hash — so a protocol can accept either mode
///      without changing how it keys its own storage.
interface ISolventSetOracle {
    /// @notice Verify a client-generated SP1 membership proof against a stored
    ///         solvent-set root.
    /// @dev Reverts if the proof is invalid, the public values do not match the
    ///      stored set entry, the scope is not this policy's, or the root has
    ///      passed its TTL. Being a `view`, this does *not* consume the
    ///      nullifier — the same proof can be presented repeatedly. Use
    ///      {verifyAndConsume} for one-shot actions.
    /// @param policyId      The policy the proof is scoped to.
    /// @param setIndex      Index into the policy's published set history.
    /// @param publicValues  224-byte ABI-encoded public outputs of the
    ///                      membership program.
    /// @param proofBytes    SP1 Groth16 proof bytes.
    /// @return nullifierHash The prover's stable, unlinkable identity for this
    ///                       policy. Key your own storage by this value.
    /// @return minStreak     The minimum consecutive-epoch streak the proof
    ///                       attests to. A protocol requiring "solvent for
    ///                       >= k epochs" MUST check `minStreak >= k` itself;
    ///                       the oracle does not know your k.
    function verifyMembership(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view returns (bytes32 nullifierHash, uint64 minStreak);

    /// @notice Verify a membership proof and consume its nullifier.
    /// @dev Enforces one use per (key, policy) across *all* callers of this
    ///      oracle — consumption is global, not per-protocol. Suitable for
    ///      airdrops, one-per-person mints, and single-vote governance. If two
    ///      protocols each want their own independent one-shot budget, they
    ///      should use {verifyMembership} and track spending themselves.
    /// @return nullifierHash The prover's identity, now marked consumed.
    /// @return minStreak     The proven minimum streak.
    function verifyAndConsume(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external returns (bytes32 nullifierHash, uint64 minStreak);

    /// @notice Whether a nullifier has already been consumed for a policy.
    function isNullifierUsed(bytes32 policyId, bytes32 nullifierHash)
        external
        view
        returns (bool);

    /// @notice Number of published sets for a policy.
    function getSetCount(bytes32 policyId) external view returns (uint256);

    /// @notice Index of the most recent set for a policy. Reverts if none.
    function latestSetIndex(bytes32 policyId) external view returns (uint256);
}
