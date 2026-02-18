// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ISolvencyOracle
/// @notice Interface for relying protocols to verify solvency membership.
/// @dev Import this interface in your dApp contracts to check solvency status.
interface ISolvencyOracle {
    /// @notice Verify that a member is included in a solvency Merkle tree with a given status.
    /// @param policyId    The policy identifier.
    /// @param memberId    The member's unique identifier.
    /// @param status      The claimed status (1 = solvent, 0 = insolvent).
    /// @param epoch       The epoch number the proof was generated for.
    /// @param merkleProof Array of sibling hashes from leaf to root.
    /// @param leafIndex   The leaf's position in the tree (0-based).
    /// @param rootIndex   Index into the rootHistory array for this policy.
    /// @return valid      True if the member is included with the given status.
    function verifyMember(
        bytes32 policyId,
        bytes32 memberId,
        uint8 status,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool);

    /// @notice Convenience function: verify that a member is solvent (status = 1).
    /// @param policyId    The policy identifier.
    /// @param memberId    The member's unique identifier.
    /// @param epoch       The epoch number the proof was generated for.
    /// @param merkleProof Array of sibling hashes from leaf to root.
    /// @param leafIndex   The leaf's position in the tree (0-based).
    /// @param rootIndex   Index into the rootHistory array for this policy.
    /// @return solvent    True if the member is proven solvent.
    function isMemberSolvent(
        bytes32 policyId,
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool);

    /// @notice Get the number of root entries for a policy (latest index = count - 1).
    /// @param policyId The policy identifier.
    /// @return count   The number of root entries stored.
    function getRootCount(bytes32 policyId) external view returns (uint256);
}
