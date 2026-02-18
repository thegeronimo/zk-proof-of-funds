// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {MerkleVerifier} from "./MerkleVerifier.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";
import {ISolvencyOracle} from "./interfaces/ISolvencyOracle.sol";

/// @title SolvencyRootOracle
/// @notice Stores per-policy solvency Merkle roots and verifies membership proofs.
/// @dev Supports two modes of root submission:
///      - Trusted mode: EIP-712 signed assertion from the policy operator.
///      - ZK mode: SP1 Groth16-wrapped proof verified via ISP1Verifier.
///      Relying protocols call verifyMember() to check membership (~5-10k gas).
contract SolvencyRootOracle is ISolvencyOracle, Ownable, EIP712 {
    using MerkleVerifier for *;

    // --- Types ---

    /// @notice A stored Merkle root entry for a policy epoch.
    /// @dev Packed into 2 storage slots:
    ///      Slot 0: root (bytes32)
    ///      Slot 1: epoch (64) + blockNumber (64) + publishedAt (64) + memberCount (32) = 224 bits
    struct RootEntry {
        bytes32 root;
        uint64 epoch;
        uint64 blockNumber;
        uint64 publishedAt;
        uint32 memberCount;
    }

    // --- EIP-712 ---

    /// @dev Must match the Rust struct in crates/agent/src/proof_worker.rs lines 15-25.
    ///      Field order and types must be identical for digest compatibility.
    bytes32 private constant SOLVENCY_ROOT_UPDATE_TYPEHASH = keccak256(
        "SolvencyRootUpdate(bytes32 policyId,bytes32 root,uint64 epoch,uint64 blockNumber,uint32 memberCount,uint64 chainId)"
    );

    // --- State ---

    /// @notice The policy registry contract.
    PolicyRegistry public immutable policyRegistry;

    /// @notice The SP1 verifier contract (for ZK mode).
    ISP1Verifier public immutable sp1Verifier;

    /// @notice The SP1 program verification key (updatable until Phase 2 finalizes).
    bytes32 public programVKey;

    /// @notice Per-policy array of root entries, append-only.
    mapping(bytes32 => RootEntry[]) internal _rootHistory;

    // --- Events ---

    event RootUpdated(
        bytes32 indexed policyId,
        bytes32 root,
        uint256 epoch,
        uint256 blockNumber,
        uint256 memberCount,
        bool trusted
    );

    event ProgramVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);

    // --- Custom Errors ---

    error PolicyNotActive(bytes32 policyId);
    error PolicyNotTrustedMode(bytes32 policyId);
    error PolicyIsTrustedMode(bytes32 policyId);
    error InvalidSignature();
    error SignerNotOperator(address signer, address operator);
    error BlockTooOld(uint256 currentBlock, uint64 blockNumber, uint64 maxBlockAge);
    error EpochNotIncreasing(uint64 newEpoch, uint64 lastEpoch);
    error RootIndexOutOfBounds(bytes32 policyId, uint256 rootIndex, uint256 rootCount);
    error RootExpired(uint256 currentBlock, uint64 publishedAt, uint64 rootTTL);
    error EpochMismatch(uint64 proofEpoch, uint64 rootEpoch);
    error InvalidPublicValues();
    error ZeroRoot();

    // --- Constructor ---

    /// @param _policyRegistry Address of the PolicyRegistry contract.
    /// @param _sp1Verifier    Address of the SP1 verifier contract (or address(0) if ZK not ready).
    /// @param _programVKey    The SP1 program verification key (or bytes32(0) as placeholder).
    constructor(
        address _policyRegistry,
        address _sp1Verifier,
        bytes32 _programVKey
    ) Ownable(msg.sender) EIP712("SolvencyRootOracle", "1") {
        policyRegistry = PolicyRegistry(_policyRegistry);
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        programVKey = _programVKey;
    }

    // --- Admin ---

    /// @notice Update the SP1 program verification key.
    /// @param _vkey The new verification key.
    function setProgramVKey(bytes32 _vkey) external onlyOwner {
        bytes32 oldVKey = programVKey;
        programVKey = _vkey;
        emit ProgramVKeyUpdated(oldVKey, _vkey);
    }

    // --- Root Submission: Trusted Mode ---

    /// @notice Submit a new solvency root using an EIP-712 operator signature (trusted mode).
    /// @dev The operator signs a SolvencyRootUpdate struct. Any address can submit the
    ///      transaction (allowing relayers), but the signature must come from the operator.
    /// @param policyId    The policy this root is for.
    /// @param newRoot     The solvency Merkle root.
    /// @param epoch       The epoch number (must be strictly increasing).
    /// @param blockNumber The Ethereum block the balances were checked at.
    /// @param memberCount Number of members included in this root.
    /// @param signature   65-byte EIP-712 signature (r || s || v).
    function updateRootTrusted(
        bytes32 policyId,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount,
        bytes calldata signature
    ) external {
        if (newRoot == bytes32(0)) revert ZeroRoot();

        // Load and validate policy
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (!policy.active) revert PolicyNotActive(policyId);
        if (!policy.trustedMode) revert PolicyNotTrustedMode(policyId);

        // Validate block freshness
        if (block.number - uint256(blockNumber) > uint256(policy.maxBlockAge)) {
            revert BlockTooOld(block.number, blockNumber, policy.maxBlockAge);
        }

        // Validate epoch is strictly increasing
        _validateEpochIncreasing(policyId, epoch);

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(abi.encode(
            SOLVENCY_ROOT_UPDATE_TYPEHASH,
            policyId,
            newRoot,
            uint256(epoch),
            uint256(blockNumber),
            uint256(memberCount),
            uint256(block.chainid)
        ));

        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        if (signer == address(0)) revert InvalidSignature();
        if (signer != policy.operator) revert SignerNotOperator(signer, policy.operator);

        // Store the new root
        _storeRoot(policyId, newRoot, epoch, blockNumber, memberCount);

        emit RootUpdated(policyId, newRoot, epoch, blockNumber, memberCount, true);
    }

    // --- Root Submission: ZK Mode ---

    /// @notice Submit a new solvency root with an SP1 ZK proof.
    /// @dev Only the policy operator can submit ZK roots. The SP1 proof is verified
    ///      on-chain, and the public values are cross-checked against the arguments.
    /// @param policyId     The policy this root is for.
    /// @param newRoot      The solvency Merkle root.
    /// @param epoch        The epoch number (must be strictly increasing).
    /// @param blockNumber  The Ethereum block the state proofs reference.
    /// @param memberCount  Number of members included in this root.
    /// @param proofBytes   The SP1 Groth16 proof bytes.
    /// @param publicValues ABI-encoded public outputs from the SP1 program.
    function updateRoot(
        bytes32 policyId,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount,
        bytes calldata proofBytes,
        bytes calldata publicValues
    ) external {
        if (newRoot == bytes32(0)) revert ZeroRoot();

        // Load and validate policy
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (!policy.active) revert PolicyNotActive(policyId);
        if (policy.trustedMode) revert PolicyIsTrustedMode(policyId);

        // Validate block freshness
        if (block.number - uint256(blockNumber) > uint256(policy.maxBlockAge)) {
            revert BlockTooOld(block.number, blockNumber, policy.maxBlockAge);
        }

        // Validate epoch is strictly increasing
        _validateEpochIncreasing(policyId, epoch);

        // Verify SP1 proof
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);

        // Decode and validate public values match submitted arguments
        _validatePublicValues(publicValues, policyId, newRoot, epoch, blockNumber, memberCount);

        // Store the new root
        _storeRoot(policyId, newRoot, epoch, blockNumber, memberCount);

        emit RootUpdated(policyId, newRoot, epoch, blockNumber, memberCount, false);
    }

    // --- Verification ---

    /// @inheritdoc ISolvencyOracle
    function verifyMember(
        bytes32 policyId,
        bytes32 memberId,
        uint8 status,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool) {
        // Bounds check
        uint256 rootCount = _rootHistory[policyId].length;
        if (rootIndex >= rootCount) {
            revert RootIndexOutOfBounds(policyId, rootIndex, rootCount);
        }

        RootEntry storage entry = _rootHistory[policyId][rootIndex];

        // Check root TTL
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (block.number - uint256(entry.publishedAt) > uint256(policy.rootTTLBlocks)) {
            revert RootExpired(block.number, entry.publishedAt, policy.rootTTLBlocks);
        }

        // Check epoch matches the root entry
        if (epoch != entry.epoch) {
            revert EpochMismatch(epoch, entry.epoch);
        }

        // Compute the expected leaf
        bytes32 leaf = MerkleVerifier.computeLeaf(memberId, status, epoch, policyId);

        // Verify the Merkle proof
        return MerkleVerifier.verifyProof(merkleProof, entry.root, leaf, leafIndex);
    }

    /// @inheritdoc ISolvencyOracle
    function isMemberSolvent(
        bytes32 policyId,
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool) {
        return this.verifyMember(policyId, memberId, 1, epoch, merkleProof, leafIndex, rootIndex);
    }

    /// @inheritdoc ISolvencyOracle
    function getRootCount(bytes32 policyId) external view returns (uint256) {
        return _rootHistory[policyId].length;
    }

    /// @notice Get a specific root entry for a policy.
    /// @param policyId  The policy identifier.
    /// @param rootIndex The index in the root history array.
    /// @return entry    The root entry.
    function getRootEntry(bytes32 policyId, uint256 rootIndex) external view returns (RootEntry memory) {
        uint256 rootCount = _rootHistory[policyId].length;
        if (rootIndex >= rootCount) {
            revert RootIndexOutOfBounds(policyId, rootIndex, rootCount);
        }
        return _rootHistory[policyId][rootIndex];
    }

    // --- Internal ---

    /// @dev Decode SP1 public values and cross-check against submitted arguments.
    ///      Matches BatchProofPublicOutputs from crates/common/src/types.rs:
    ///      (state_root, policy_id, epoch, solvency_root, threshold_wei, member_count, block_number, chain_id)
    function _validatePublicValues(
        bytes calldata publicValues,
        bytes32 policyId,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) internal view {
        (
            /* bytes32 stateRoot */,
            bytes32 proofPolicyId,
            uint64 proofEpoch,
            bytes32 proofRoot,
            /* uint64 thresholdWei */,
            uint32 proofMemberCount,
            uint64 proofBlockNumber,
            uint64 proofChainId
        ) = abi.decode(publicValues, (bytes32, bytes32, uint64, bytes32, uint64, uint32, uint64, uint64));

        if (proofPolicyId != policyId ||
            proofEpoch != epoch ||
            proofRoot != newRoot ||
            proofMemberCount != memberCount ||
            proofBlockNumber != blockNumber ||
            proofChainId != uint64(block.chainid)) {
            revert InvalidPublicValues();
        }
    }

    /// @dev Validate that the new epoch is strictly greater than the last one.
    function _validateEpochIncreasing(bytes32 policyId, uint64 epoch) internal view {
        uint256 rootCount = _rootHistory[policyId].length;
        if (rootCount > 0) {
            uint64 lastEpoch = _rootHistory[policyId][rootCount - 1].epoch;
            if (epoch <= lastEpoch) {
                revert EpochNotIncreasing(epoch, lastEpoch);
            }
        }
    }

    /// @dev Append a new root entry to the policy's history.
    function _storeRoot(
        bytes32 policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) internal {
        _rootHistory[policyId].push(RootEntry({
            root: root,
            epoch: epoch,
            blockNumber: blockNumber,
            publishedAt: uint64(block.number),
            memberCount: memberCount
        }));
    }
}
