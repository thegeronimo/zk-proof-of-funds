// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title PolicyRegistry
/// @notice Stores solvency policy definitions. Policies define the parameters
///         for a group of members being monitored by the Solvency Agent.
/// @dev Maps bytes32 policyId to Policy structs. The policyId is supplied by the
///      caller (not auto-generated) and matches the Rust PolicyId type ([u8; 32]).
///
///      **Semantic immutability (external review finding R4).** A published
///      root is an attestation under a *specific* set of policy semantics. If
///      the threshold, token, or scope could later be rewritten under the same
///      policyId, every historical root would silently change meaning. So:
///
///      - `configHash` commits to every semantic field.
///      - Once a policy is *frozen* (the oracle freezes it at first
///        publication), the semantic fields can never change again. Changing
///        them requires a new `version`, which changes `configHash`, which
///        relying contracts pin.
///      - `updatePolicy` is owner-only and, post-freeze, restricted to
///        operator rotation. The operator can no longer rewrite the policy or
///        flip `active` — previously it could reactivate a policy the owner
///        had deactivated.
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
        uint64 startBlock;         // Epoch 0 anchor: epoch = (refBlock - startBlock) / epochLengthBlocks
        uint32 version;            // Bumped when semantics change; part of configHash
    }

    /// @notice Mapping from policyId to policy configuration.
    mapping(bytes32 => Policy) internal _policies;

    /// @notice Track whether a policy has been created (needed because a zeroed Policy is the default).
    mapping(bytes32 => bool) public policyExists;

    /// @notice Once frozen, a policy's semantic fields are immutable. Set by
    ///         the authorized freezer (the oracle) at first publication.
    mapping(bytes32 => bool) public policyFrozen;

    /// @notice Address permitted to freeze policies — the SolventSetOracle.
    address public freezer;

    // --- Events ---

    event PolicyCreated(bytes32 indexed policyId, address indexed operator);
    event PolicyUpdated(bytes32 indexed policyId);
    event PolicyDeactivated(bytes32 indexed policyId);
    event PolicyFrozen(bytes32 indexed policyId, bytes32 configHash);
    event FreezerSet(address indexed freezer);

    // --- Custom Errors ---

    error PolicyAlreadyExists(bytes32 policyId);
    error PolicyNotFound(bytes32 policyId);
    error InvalidOperator();
    error MaxBlockAgeTooHigh(uint64 maxBlockAge);
    error ZeroEpochLength();
    error ZeroRootTTL();
    error NotAuthorized();
    error PolicyIsFrozen(bytes32 policyId);
    error SemanticsChangeRequiresVersionBump(bytes32 policyId);

    // --- Constructor ---

    constructor() Ownable(msg.sender) {}

    // --- External Functions ---

    /// @notice Authorize the contract allowed to freeze policies (the oracle).
    function setFreezer(address _freezer) external onlyOwner {
        freezer = _freezer;
        emit FreezerSet(_freezer);
    }

    /// @notice Create a new policy. Only the contract owner can create policies.
    /// @param policyId Unique identifier for the policy.
    /// @param policy   The policy configuration. `active` is forced to true regardless of input.
    function createPolicy(bytes32 policyId, Policy calldata policy) external onlyOwner {
        if (policyExists[policyId]) revert PolicyAlreadyExists(policyId);
        _validate(policy);

        _policies[policyId] = policy;
        _policies[policyId].active = true; // Force active on creation
        policyExists[policyId] = true;

        emit PolicyCreated(policyId, policy.operator);
    }

    /// @notice Update an existing policy. Owner-only.
    /// @dev Before the first publication a policy is still malleable, so the
    ///      owner may correct it freely. After freezing, only the operator may
    ///      be rotated — the semantic fields are what historical roots mean,
    ///      and rewriting them would retroactively redefine every attestation
    ///      already published (review finding R4). Deliberate semantic changes
    ///      go through a `version` bump on a fresh policyId.
    /// @param policyId The policy to update.
    /// @param policy   The new policy configuration.
    function updatePolicy(bytes32 policyId, Policy calldata policy) external onlyOwner {
        if (!policyExists[policyId]) revert PolicyNotFound(policyId);
        _validate(policy);

        if (policyFrozen[policyId]) {
            // Only the operator field may move post-freeze. Everything else —
            // including `active`, which the owner controls via
            // deactivatePolicy — must be identical.
            Policy memory current = _policies[policyId];
            Policy memory candidate = policy;
            candidate.operator = current.operator;
            if (configHashOf(candidate) != configHashOf(current)) {
                revert SemanticsChangeRequiresVersionBump(policyId);
            }
            if (policy.active != current.active) revert PolicyIsFrozen(policyId);
            _policies[policyId].operator = policy.operator;
        } else {
            _policies[policyId] = policy;
        }

        emit PolicyUpdated(policyId);
    }

    /// @notice Freeze a policy's semantics. Callable by the owner or the
    ///         authorized freezer (the oracle, at first publication).
    function freezePolicy(bytes32 policyId) external {
        if (msg.sender != owner() && msg.sender != freezer) revert NotAuthorized();
        if (!policyExists[policyId]) revert PolicyNotFound(policyId);
        if (policyFrozen[policyId]) return; // idempotent
        policyFrozen[policyId] = true;
        emit PolicyFrozen(policyId, configHash(policyId));
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

    /// @notice Content hash of a policy's semantics. Pinned into every
    ///         published root so an attestation carries the meaning it was
    ///         created under, and relying contracts can require an exact
    ///         configuration rather than trusting the current registry state.
    /// @dev Deliberately excludes `operator` (rotatable without changing what
    ///      a root *means*) and `active` (a lifecycle flag, not semantics).
    function configHash(bytes32 policyId) public view returns (bytes32) {
        if (!policyExists[policyId]) revert PolicyNotFound(policyId);
        return configHashOf(_policies[policyId]);
    }

    /// @notice `configHash` over an arbitrary policy struct (pure helper).
    function configHashOf(Policy memory policy) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                policy.thresholdWei,
                policy.tokenAddress,
                policy.chainId,
                policy.epochLengthBlocks,
                policy.maxBlockAge,
                policy.rootTTLBlocks,
                keccak256(bytes(policy.scope)),
                policy.trustedMode,
                policy.startBlock,
                policy.version
            )
        );
    }

    /// @dev Creation-time validation, re-run on every update — previously
    ///      `updatePolicy` skipped the operator/epoch/TTL checks entirely and
    ///      could install a zero operator or a zero TTL.
    function _validate(Policy calldata policy) internal pure {
        if (policy.operator == address(0)) revert InvalidOperator();
        if (policy.maxBlockAge > 256) revert MaxBlockAgeTooHigh(policy.maxBlockAge);
        if (policy.epochLengthBlocks == 0) revert ZeroEpochLength();
        if (policy.rootTTLBlocks == 0) revert ZeroRootTTL();
    }
}
