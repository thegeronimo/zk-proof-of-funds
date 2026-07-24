// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";

/// @title SolventSetOracle
/// @notice Privacy V2 (PRIVACY_V2.md): stores per-policy *solvent-set* Merkle
///         roots — commitments to every address meeting the policy threshold
///         at a reference block — and verifies client-generated SP1 membership
///         proofs against them.
/// @dev A membership proof shows "I control a key whose address is in the set"
///      without revealing the address; its public output is a deterministic
///      nullifier hash, unique per (key, policy), which relying protocols use
///      for sybil resistance. Root publication is operator-trusted in Stage A;
///      Stage B replaces it with an SP1-proven derivation from receipt logs.
contract SolventSetOracle is Ownable {
    // --- Types ---

    /// @notice A stored solvent-set root for a policy epoch.
    /// @dev Packed into 2 storage slots:
    ///      Slot 0: root (bytes32)
    ///      Slot 1: epoch (64) + blockNumber (64) + publishedAt (64) + memberCount (32) = 224 bits
    struct SetEntry {
        bytes32 root;
        uint64 epoch;
        uint64 blockNumber;
        uint64 publishedAt;
        uint32 memberCount;
    }

    // --- State ---

    /// @notice The policy registry contract.
    PolicyRegistry public immutable policyRegistry;

    /// @notice The SP1 verifier contract.
    ISP1Verifier public immutable sp1Verifier;

    /// @notice Verification key of the membership program (program-membership/).
    bytes32 public membershipVKey;

    /// @notice Per-policy array of solvent-set entries, append-only.
    mapping(bytes32 => SetEntry[]) internal _setHistory;

    /// @notice Consumed nullifiers per policy (for one-per-address gating).
    /// @dev Namespace is shared across all callers of verifyAndConsume for a
    ///      policy; protocols wanting an isolated namespace should call the
    ///      view verifyMembership() and track nullifiers themselves.
    mapping(bytes32 => mapping(bytes32 => bool)) public usedNullifiers;

    // --- Events ---

    event SolventSetRootPublished(
        bytes32 indexed policyId,
        bytes32 root,
        uint256 epoch,
        uint256 blockNumber,
        uint256 memberCount
    );

    event NullifierConsumed(bytes32 indexed policyId, bytes32 indexed nullifierHash, address consumer);

    event MembershipVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);

    // --- Custom Errors ---

    error PolicyNotActive(bytes32 policyId);
    error NotOperator(address caller, address operator);
    error ZeroRoot();
    error EpochNotIncreasing(uint64 newEpoch, uint64 lastEpoch);
    error NoSetPublished(bytes32 policyId);
    error SetIndexOutOfBounds(bytes32 policyId, uint256 setIndex, uint256 setCount);
    error SetExpired(uint256 currentBlock, uint64 publishedAt, uint64 rootTTL);
    error InvalidPublicValuesLength(uint256 length);
    error PublicValuesMismatch();
    error NullifierAlreadyUsed(bytes32 policyId, bytes32 nullifierHash);

    // --- Constructor ---

    /// @param _policyRegistry Address of the PolicyRegistry contract.
    /// @param _sp1Verifier    Address of the SP1 verifier contract.
    /// @param _membershipVKey Verification key of the membership program
    ///                        (or bytes32(0) until `cargo prove vkey` output is set).
    constructor(
        address _policyRegistry,
        address _sp1Verifier,
        bytes32 _membershipVKey
    ) Ownable(msg.sender) {
        policyRegistry = PolicyRegistry(_policyRegistry);
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        membershipVKey = _membershipVKey;
    }

    // --- Admin ---

    /// @notice Update the membership program verification key.
    function setMembershipVKey(bytes32 _vkey) external onlyOwner {
        bytes32 oldVKey = membershipVKey;
        membershipVKey = _vkey;
        emit MembershipVKeyUpdated(oldVKey, _vkey);
    }

    // --- Root Publication ---

    /// @notice Publish a solvent-set root for a policy epoch.
    /// @dev Operator-only. The set is public data (all addresses meeting the
    ///      threshold), so publication reveals nothing about members.
    /// @param policyId    The policy this set is for.
    /// @param root        The solvent-set Merkle root.
    /// @param epoch       The epoch number (strictly increasing per policy).
    /// @param blockNumber The reference block balances were sampled at.
    /// @param memberCount Number of addresses in the set.
    function publishRoot(
        bytes32 policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) external {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (!policy.active) revert PolicyNotActive(policyId);
        if (msg.sender != policy.operator) revert NotOperator(msg.sender, policy.operator);
        if (root == bytes32(0)) revert ZeroRoot();

        uint256 setCount = _setHistory[policyId].length;
        if (setCount > 0) {
            uint64 lastEpoch = _setHistory[policyId][setCount - 1].epoch;
            if (epoch <= lastEpoch) revert EpochNotIncreasing(epoch, lastEpoch);
        }

        _setHistory[policyId].push(
            SetEntry({
                root: root,
                epoch: epoch,
                blockNumber: blockNumber,
                publishedAt: uint64(block.number),
                memberCount: memberCount
            })
        );

        emit SolventSetRootPublished(policyId, root, epoch, blockNumber, memberCount);
    }

    // --- Membership Verification ---

    /// @notice Verify a client-generated SP1 membership proof against a stored
    ///         solvent-set root.
    /// @dev Public values layout (program-membership/, crates/common/src/membership.rs):
    ///      abi.encode(bytes32 solventSetRoot, bytes32 policyId, uint64 epoch,
    ///                 bytes32 nullifierHash, uint64 chainId) — 160 bytes.
    /// @param policyId     The policy to verify against.
    /// @param setIndex     Index into the policy's set history.
    /// @param publicValues ABI-encoded public outputs of the membership program.
    /// @param proofBytes   SP1 Groth16 proof bytes.
    /// @return nullifierHash The prover's deterministic nullifier hash — the
    ///         member's stable, unlinkable identity for this policy.
    function verifyMembership(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) public view returns (bytes32 nullifierHash) {
        uint256 setCount = _setHistory[policyId].length;
        if (setIndex >= setCount) {
            revert SetIndexOutOfBounds(policyId, setIndex, setCount);
        }
        SetEntry storage entry = _setHistory[policyId][setIndex];

        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (block.number > uint256(entry.publishedAt) + policy.rootTTLBlocks) {
            revert SetExpired(block.number, entry.publishedAt, policy.rootTTLBlocks);
        }

        // Verify the SP1 proof (reverts on invalid proof).
        sp1Verifier.verifyProof(membershipVKey, publicValues, proofBytes);

        if (publicValues.length != 160) revert InvalidPublicValuesLength(publicValues.length);
        (
            bytes32 provenRoot,
            bytes32 provenPolicyId,
            uint64 provenEpoch,
            bytes32 provenNullifierHash,
            uint64 provenChainId
        ) = abi.decode(publicValues, (bytes32, bytes32, uint64, bytes32, uint64));

        if (
            provenRoot != entry.root ||
            provenPolicyId != policyId ||
            provenEpoch != entry.epoch ||
            provenChainId != uint64(block.chainid)
        ) {
            revert PublicValuesMismatch();
        }

        return provenNullifierHash;
    }

    /// @notice Verify a membership proof and consume its nullifier — enforces
    ///         one use per (key, policy) across all callers.
    function verifyAndConsume(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external returns (bytes32 nullifierHash) {
        nullifierHash = verifyMembership(policyId, setIndex, publicValues, proofBytes);
        if (usedNullifiers[policyId][nullifierHash]) {
            revert NullifierAlreadyUsed(policyId, nullifierHash);
        }
        usedNullifiers[policyId][nullifierHash] = true;
        emit NullifierConsumed(policyId, nullifierHash, msg.sender);
    }

    // --- Views ---

    /// @notice Whether a nullifier has been consumed for a policy.
    function isNullifierUsed(bytes32 policyId, bytes32 nullifierHash) external view returns (bool) {
        return usedNullifiers[policyId][nullifierHash];
    }

    /// @notice Number of published sets for a policy.
    function getSetCount(bytes32 policyId) external view returns (uint256) {
        return _setHistory[policyId].length;
    }

    /// @notice Index of the most recent set for a policy.
    function latestSetIndex(bytes32 policyId) external view returns (uint256) {
        uint256 setCount = _setHistory[policyId].length;
        if (setCount == 0) revert NoSetPublished(policyId);
        return setCount - 1;
    }

    /// @notice Get a specific set entry for a policy.
    function getSetEntry(bytes32 policyId, uint256 setIndex) external view returns (SetEntry memory) {
        uint256 setCount = _setHistory[policyId].length;
        if (setIndex >= setCount) {
            revert SetIndexOutOfBounds(policyId, setIndex, setCount);
        }
        return _setHistory[policyId][setIndex];
    }
}
