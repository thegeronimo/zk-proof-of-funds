// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolvencyOracle} from "./interfaces/ISolvencyOracle.sol";

/// @title RelyingProtocol
/// @notice Example dApp that gates actions behind solvency proof verification.
/// @dev Demonstrates how a relying protocol integrates with the SolvencyRootOracle
///      via the ISolvencyOracle interface. Any dApp can deploy this pattern to
///      require users to prove solvency before executing privileged operations.
contract RelyingProtocol {
    // --- State ---

    /// @notice The solvency oracle contract.
    ISolvencyOracle public immutable oracle;

    /// @notice The policy this protocol is gating behind.
    bytes32 public immutable policyId;

    // --- Events ---

    /// @notice Emitted when a gated action is successfully performed.
    event ActionPerformed(bytes32 indexed memberId, uint64 epoch, address caller);

    // --- Custom Errors ---

    /// @notice The member is not proven solvent for this policy.
    error NotSolvent(bytes32 memberId);

    // --- Constructor ---

    /// @param _oracle   Address of the SolvencyRootOracle (or any ISolvencyOracle).
    /// @param _policyId The policy ID this protocol gates behind.
    constructor(address _oracle, bytes32 _policyId) {
        oracle = ISolvencyOracle(_oracle);
        policyId = _policyId;
    }

    // --- External ---

    /// @notice Perform a gated action that requires the caller to prove solvency.
    /// @dev Calls oracle.isMemberSolvent() and reverts with NotSolvent if false.
    /// @param memberId    The member's unique identifier.
    /// @param epoch       The epoch of the solvency proof.
    /// @param merkleProof Array of sibling hashes from leaf to root.
    /// @param leafIndex   The leaf's position in the tree (0-based).
    /// @param rootIndex   Index into the rootHistory array for this policy.
    function performGatedAction(
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external {
        bool solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch, merkleProof, leafIndex, rootIndex
        );
        if (!solvent) revert NotSolvent(memberId);

        emit ActionPerformed(memberId, epoch, msg.sender);
    }

    /// @notice Read-only solvency check (does not emit events or modify state).
    /// @param memberId    The member's unique identifier.
    /// @param epoch       The epoch of the solvency proof.
    /// @param merkleProof Array of sibling hashes from leaf to root.
    /// @param leafIndex   The leaf's position in the tree (0-based).
    /// @param rootIndex   Index into the rootHistory array for this policy.
    /// @return solvent    True if the member is proven solvent.
    function checkSolvency(
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool solvent) {
        solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch, merkleProof, leafIndex, rootIndex
        );
    }
}
