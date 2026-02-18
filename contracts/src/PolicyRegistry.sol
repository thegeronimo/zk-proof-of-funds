// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title PolicyRegistry
/// @notice Stores solvency policy definitions. Policies define the parameters
///         for a group of members being monitored by the Solvency Agent.
/// @dev Maps bytes32 policyId to Policy structs. The policyId is supplied by the
///      caller (not auto-generated) and matches the Rust PolicyId type ([u8; 32]).
contract PolicyRegistry is Ownable {
    /// @notice Policy configuration. Matches the Rust Policy struct in crates/common/src/types.rs.
    /// @dev `description` is intentionally omitted (off-chain metadata, saves gas).
    struct Policy {
        uint256 thresholdWei;      // Minimum balance required for solvency
        address tokenAddress;      // address(0) = native ETH, else ERC-20 contract
        uint64 chainId;            // Target chain for balance monitoring
        uint64 epochLengthBlocks;  // Blocks between epoch updates
        uint64 maxBlockAge;        // Max staleness of referenced block (must be <= 256)
        uint64 rootTTLBlocks;      // How long a published root remains valid
        address operator;          // Authorized address for root submissions
        string scope;              // Scope string for memberId computation
        bool trustedMode;          // If true, uses EIP-712 signatures instead of ZK proofs
        bool active;               // If false, no new roots can be published
    }

    /// @notice Mapping from policyId to policy configuration.
    mapping(bytes32 => Policy) internal _policies;

    /// @notice Track whether a policy has been created (needed because a zeroed Policy is the default).
    mapping(bytes32 => bool) public policyExists;

    // --- Events ---

    event PolicyCreated(bytes32 indexed policyId, address indexed operator);
    event PolicyUpdated(bytes32 indexed policyId);
    event PolicyDeactivated(bytes32 indexed policyId);

    // --- Custom Errors ---

    error PolicyAlreadyExists(bytes32 policyId);
    error PolicyNotFound(bytes32 policyId);
    error InvalidOperator();
    error MaxBlockAgeTooHigh(uint64 maxBlockAge);
    error ZeroEpochLength();
    error ZeroRootTTL();
    error NotAuthorized();

    // --- Constructor ---

    constructor() Ownable(msg.sender) {}

    // --- External Functions ---

    /// @notice Create a new policy. Only the contract owner can create policies.
    /// @param policyId Unique identifier for the policy.
    /// @param policy   The policy configuration. `active` is forced to true regardless of input.
    function createPolicy(bytes32 policyId, Policy calldata policy) external onlyOwner {
        if (policyExists[policyId]) revert PolicyAlreadyExists(policyId);
        if (policy.operator == address(0)) revert InvalidOperator();
        if (policy.maxBlockAge > 256) revert MaxBlockAgeTooHigh(policy.maxBlockAge);
        if (policy.epochLengthBlocks == 0) revert ZeroEpochLength();
        if (policy.rootTTLBlocks == 0) revert ZeroRootTTL();

        _policies[policyId] = policy;
        _policies[policyId].active = true; // Force active on creation
        policyExists[policyId] = true;

        emit PolicyCreated(policyId, policy.operator);
    }

    /// @notice Update an existing policy. Can be called by the owner or the current operator.
    /// @param policyId The policy to update.
    /// @param policy   The new policy configuration.
    function updatePolicy(bytes32 policyId, Policy calldata policy) external {
        if (!policyExists[policyId]) revert PolicyNotFound(policyId);
        if (msg.sender != owner() && msg.sender != _policies[policyId].operator) {
            revert NotAuthorized();
        }
        if (policy.maxBlockAge > 256) revert MaxBlockAgeTooHigh(policy.maxBlockAge);

        _policies[policyId] = policy;

        emit PolicyUpdated(policyId);
    }

    /// @notice Deactivate a policy. Only the contract owner can deactivate.
    /// @param policyId The policy to deactivate.
    function deactivatePolicy(bytes32 policyId) external onlyOwner {
        if (!policyExists[policyId]) revert PolicyNotFound(policyId);

        _policies[policyId].active = false;

        emit PolicyDeactivated(policyId);
    }

    /// @notice Get the full policy configuration.
    /// @param policyId The policy to retrieve.
    /// @return policy  The policy struct.
    function getPolicy(bytes32 policyId) external view returns (Policy memory) {
        if (!policyExists[policyId]) revert PolicyNotFound(policyId);
        return _policies[policyId];
    }
}
