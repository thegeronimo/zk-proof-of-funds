// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";

/// @title SolventSetOracle
/// @notice Privacy V2 (PRIVACY_V2.md): stores per-policy *solvent-set* Merkle
///         roots — commitments to every (address, streak) pair meeting the
///         policy threshold at a reference block — and verifies
///         client-generated SP1 membership proofs against them.
/// @dev A membership proof shows "I control a key whose address is in the set
///      with streak >= minStreak" without revealing the address or the exact
///      streak; its public output is a deterministic nullifier hash, unique
///      per (key, policy), which relying protocols use for sybil resistance.
///
///      Two publication paths:
///      - `publishRoot` (Stage A): operator-trusted.
///      - `publishRootProven` (Stage B): **permissionless** — an SP1 proof of
///        the derivation program shows every entry's balance was proven via
///        EIP-1186 against the block's state root and every streak chains
///        from the previous set. The state root is bound to the chain by
///        `keccak256(headerRlp) == blockhash(blockNumber)`.
contract SolventSetOracle is Ownable {
    // --- Types ---

    /// @notice A stored solvent-set root for a policy epoch.
    /// @dev Packed into 2 storage slots:
    ///      Slot 0: root (bytes32)
    ///      Slot 1: epoch (64) + blockNumber (64) + publishedAt (64)
    ///              + memberCount (32) + proven (8) = 232 bits
    struct SetEntry {
        bytes32 root;
        uint64 epoch;
        uint64 blockNumber;
        uint64 publishedAt;
        uint32 memberCount;
        bool proven;
    }

    // --- Constants ---

    /// @dev abi.encode(bytes32 root, bytes32 policyId, uint64 epoch,
    ///      bytes32 nullifierHash, uint64 chainId, uint64 minStreak).
    uint256 private constant MEMBERSHIP_PUBLIC_VALUES_LEN = 192;

    /// @dev abi.encode(bytes32 stateRoot, bytes32 prevRoot, bytes32 newRoot,
    ///      bytes32 policyId, uint64 epoch, uint64 blockNumber, uint64 chainId,
    ///      uint256 thresholdWei, uint32 memberCount, uint32 candidateCount,
    ///      address token, uint64 balanceSlot, bytes32 candidatesRoot).
    uint256 private constant DERIVATION_PUBLIC_VALUES_LEN = 416;

    // --- State ---

    /// @notice The policy registry contract.
    PolicyRegistry public immutable policyRegistry;

    /// @notice The SP1 verifier contract.
    ISP1Verifier public immutable sp1Verifier;

    /// @notice Verification key of the membership program (program-membership/).
    bytes32 public membershipVKey;

    /// @notice Verification key of the derivation program (program-solvent-set/).
    bytes32 public derivationVKey;

    /// @notice Per-policy array of solvent-set entries, append-only.
    mapping(bytes32 => SetEntry[]) internal _setHistory;

    /// @notice Consumed nullifiers per policy (for one-per-address gating).
    /// @dev Namespace is shared across all callers of verifyAndConsume for a
    ///      policy; protocols wanting an isolated namespace should call the
    ///      view verifyMembership() and track nullifiers themselves.
    mapping(bytes32 => mapping(bytes32 => bool)) public usedNullifiers;

    /// @notice ERC-20 policies: the pinned Solidity mapping slot of
    ///         `balanceOf` for the policy's token. A proven publication must
    ///         match it — a proof against the wrong slot proves nothing.
    mapping(bytes32 => uint64) public balanceSlotOf;

    // --- Events ---

    event SolventSetRootPublished(
        bytes32 indexed policyId,
        bytes32 root,
        uint256 epoch,
        uint256 blockNumber,
        uint256 memberCount,
        bool proven,
        address publisher
    );

    event NullifierConsumed(bytes32 indexed policyId, bytes32 indexed nullifierHash, address consumer);

    event MembershipVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);
    event DerivationVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);
    event BalanceSlotSet(bytes32 indexed policyId, uint64 balanceSlot);

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
    error PrevRootMismatch(bytes32 expected, bytes32 actual);
    error ThresholdMismatch(uint256 policyThreshold, uint256 provenThreshold);
    error ChainIdMismatch(uint64 expected, uint64 actual);
    error TokenMismatch(address policyToken, address provenToken);
    error BalanceSlotMismatch(uint64 pinnedSlot, uint64 provenSlot);
    error StaleReferenceBlock(uint256 currentBlock, uint64 blockNumber, uint64 maxBlockAge);
    error BlockhashUnavailable(uint64 blockNumber);
    error HeaderHashMismatch(bytes32 expected, bytes32 actual);
    error MalformedHeader();
    error StateRootMismatch(bytes32 headerStateRoot, bytes32 provenStateRoot);

    // --- Constructor ---

    /// @param _policyRegistry Address of the PolicyRegistry contract.
    /// @param _sp1Verifier    Address of the SP1 verifier contract.
    /// @param _membershipVKey Verification key of the membership program
    ///                        (or bytes32(0) until `print-vkeys` output is set).
    /// @param _derivationVKey Verification key of the derivation program
    ///                        (or bytes32(0) until `print-vkeys` output is set).
    constructor(
        address _policyRegistry,
        address _sp1Verifier,
        bytes32 _membershipVKey,
        bytes32 _derivationVKey
    ) Ownable(msg.sender) {
        policyRegistry = PolicyRegistry(_policyRegistry);
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        membershipVKey = _membershipVKey;
        derivationVKey = _derivationVKey;
    }

    // --- Admin ---

    /// @notice Update the membership program verification key.
    function setMembershipVKey(bytes32 _vkey) external onlyOwner {
        bytes32 oldVKey = membershipVKey;
        membershipVKey = _vkey;
        emit MembershipVKeyUpdated(oldVKey, _vkey);
    }

    /// @notice Update the derivation program verification key.
    function setDerivationVKey(bytes32 _vkey) external onlyOwner {
        bytes32 oldVKey = derivationVKey;
        derivationVKey = _vkey;
        emit DerivationVKeyUpdated(oldVKey, _vkey);
    }

    /// @notice Pin the `balanceOf` mapping slot for an ERC-20 policy's token.
    /// @dev Policy-operator only — the slot is part of what makes a proven
    ///      publication sound for the token.
    function setBalanceSlot(bytes32 policyId, uint64 slot) external {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (msg.sender != policy.operator) revert NotOperator(msg.sender, policy.operator);
        balanceSlotOf[policyId] = slot;
        emit BalanceSlotSet(policyId, slot);
    }

    // --- Root Publication: Stage A (operator-trusted) ---

    /// @notice Publish a solvent-set root for a policy epoch.
    /// @dev Operator-only. The set is public data (all addresses meeting the
    ///      threshold), so publication reveals nothing about members.
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

        _validateEpochIncreasing(policyId, epoch);
        _storeEntry(policyId, root, epoch, blockNumber, memberCount, false);
    }

    // --- Root Publication: Stage B (proven, permissionless) ---

    /// @notice Publish a solvent-set root backed by an SP1 derivation proof.
    ///         Callable by **anyone**: the proof (not the caller) is trusted.
    /// @dev The proof attests (program-solvent-set/, PRIVACY_V2.md §4.4):
    ///      every entry's balance was proven via EIP-1186 against `stateRoot`
    ///      and every streak chains from the set committed by `prevRoot`.
    ///      On-chain we bind: `prevRoot` to our stored history, `stateRoot` to
    ///      the chain via the block header, and the policy's threshold/chain.
    /// @param policyId     The policy this set is for.
    /// @param headerRlp    The full RLP-encoded header of the reference block.
    /// @param publicValues ABI-encoded public outputs of the derivation program.
    /// @param proofBytes   SP1 Groth16 proof bytes.
    function publishRootProven(
        bytes32 policyId,
        bytes calldata headerRlp,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (!policy.active) revert PolicyNotActive(policyId);

        if (publicValues.length != DERIVATION_PUBLIC_VALUES_LEN) {
            revert InvalidPublicValuesLength(publicValues.length);
        }
        (
            bytes32 stateRoot,
            bytes32 prevRoot,
            bytes32 newRoot,
            bytes32 provenPolicyId,
            uint64 epoch,
            uint64 blockNumber,
            uint64 chainId,
            uint256 thresholdWei,
            uint32 memberCount,
            , // candidateCount
            address provenToken,
            uint64 provenBalanceSlot,
            // bytes32 candidatesRoot — the Stage B.2 completeness binding
            // surface; unchecked on-chain until composition lands.
        ) = abi.decode(
            publicValues,
            (
                bytes32, bytes32, bytes32, bytes32, uint64, uint64, uint64, uint256,
                uint32, uint32, address, uint64, bytes32
            )
        );

        if (provenPolicyId != policyId) revert PublicValuesMismatch();
        if (newRoot == bytes32(0)) revert ZeroRoot();
        if (chainId != uint64(block.chainid)) revert ChainIdMismatch(uint64(block.chainid), chainId);
        if (thresholdWei != policy.thresholdWei) {
            revert ThresholdMismatch(policy.thresholdWei, thresholdWei);
        }
        // Asset binding: the proof's token/slot must match the policy's.
        if (provenToken != policy.tokenAddress) {
            revert TokenMismatch(policy.tokenAddress, provenToken);
        }
        uint64 pinnedSlot = provenToken == address(0) ? 0 : balanceSlotOf[policyId];
        if (provenBalanceSlot != pinnedSlot) {
            revert BalanceSlotMismatch(pinnedSlot, provenBalanceSlot);
        }

        // Epoch strictly increasing; streak continuity binds to our history.
        _validateEpochIncreasing(policyId, epoch);
        bytes32 expectedPrevRoot = bytes32(0);
        uint256 setCount = _setHistory[policyId].length;
        if (setCount > 0) {
            expectedPrevRoot = _setHistory[policyId][setCount - 1].root;
        }
        if (prevRoot != expectedPrevRoot) revert PrevRootMismatch(expectedPrevRoot, prevRoot);

        // Reference-block freshness + state-root binding via the header.
        if (blockNumber >= block.number || block.number - blockNumber > policy.maxBlockAge) {
            revert StaleReferenceBlock(block.number, blockNumber, policy.maxBlockAge);
        }
        bytes32 expectedHash = _blockhash(blockNumber);
        if (expectedHash == bytes32(0)) revert BlockhashUnavailable(blockNumber);
        bytes32 headerHash = keccak256(headerRlp);
        if (headerHash != expectedHash) revert HeaderHashMismatch(expectedHash, headerHash);
        bytes32 headerStateRoot = _extractStateRoot(headerRlp);
        if (headerStateRoot != stateRoot) revert StateRootMismatch(headerStateRoot, stateRoot);

        // Verify the derivation proof (reverts on invalid proof).
        sp1Verifier.verifyProof(derivationVKey, publicValues, proofBytes);

        _storeEntry(policyId, newRoot, epoch, blockNumber, memberCount, true);
    }

    // --- Membership Verification ---

    /// @notice Verify a client-generated SP1 membership proof against a stored
    ///         solvent-set root.
    /// @dev Public values layout (program-membership/, crates/common/src/membership.rs):
    ///      abi.encode(bytes32 solventSetRoot, bytes32 policyId, uint64 epoch,
    ///                 bytes32 nullifierHash, uint64 chainId, uint64 minStreak).
    /// @return nullifierHash The prover's deterministic nullifier hash — the
    ///         member's stable, unlinkable identity for this policy.
    /// @return minStreak The minimum consecutive-epoch streak the proof
    ///         attests to; relying protocols requiring "solvent >= k epochs"
    ///         must check `minStreak >= k`.
    function verifyMembership(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) public view returns (bytes32 nullifierHash, uint64 minStreak) {
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

        if (publicValues.length != MEMBERSHIP_PUBLIC_VALUES_LEN) {
            revert InvalidPublicValuesLength(publicValues.length);
        }
        (
            bytes32 provenRoot,
            bytes32 provenPolicyId,
            uint64 provenEpoch,
            bytes32 provenNullifierHash,
            uint64 provenChainId,
            uint64 provenMinStreak
        ) = abi.decode(publicValues, (bytes32, bytes32, uint64, bytes32, uint64, uint64));

        if (
            provenRoot != entry.root ||
            provenPolicyId != policyId ||
            provenEpoch != entry.epoch ||
            provenChainId != uint64(block.chainid)
        ) {
            revert PublicValuesMismatch();
        }

        return (provenNullifierHash, provenMinStreak);
    }

    /// @notice Verify a membership proof and consume its nullifier — enforces
    ///         one use per (key, policy) across all callers.
    function verifyAndConsume(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external returns (bytes32 nullifierHash, uint64 minStreak) {
        (nullifierHash, minStreak) = verifyMembership(policyId, setIndex, publicValues, proofBytes);
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

    // --- Internal ---

    /// @dev Blockhash access behind a virtual hook: overridable in tests and
    ///      swappable for EIP-2935 / L2 blockhash oracles later.
    function _blockhash(uint64 blockNumber) internal view virtual returns (bytes32) {
        return blockhash(blockNumber);
    }

    /// @dev Extract the state root (4th item) from an RLP block header via a
    ///      fixed-shape walk. Ethereum headers invariantly encode:
    ///        item 0: parentHash  — 32-byte string (0xa0 prefix)
    ///        item 1: unclesHash  — 32-byte string (0xa0 prefix)
    ///        item 2: coinbase    — 20-byte string (0x94 prefix)
    ///        item 3: stateRoot   — 32-byte string (0xa0 prefix)
    ///      Lenient about anything after item 3: the full header bytes are
    ///      already bound by `keccak256(headerRlp) == blockhash`.
    function _extractStateRoot(bytes calldata headerRlp) internal pure returns (bytes32) {
        if (headerRlp.length < 4) revert MalformedHeader();

        uint256 offset;
        uint8 listPrefix = uint8(headerRlp[0]);
        if (listPrefix >= 0xC0 && listPrefix <= 0xF7) {
            offset = 1;
        } else if (listPrefix > 0xF7) {
            offset = 1 + (listPrefix - 0xF7);
        } else {
            revert MalformedHeader();
        }

        // parentHash, unclesHash: 32-byte strings.
        for (uint256 i = 0; i < 2; i++) {
            if (headerRlp.length <= offset || uint8(headerRlp[offset]) != 0xA0) {
                revert MalformedHeader();
            }
            offset += 33;
        }
        // coinbase: 20-byte string.
        if (headerRlp.length <= offset || uint8(headerRlp[offset]) != 0x94) {
            revert MalformedHeader();
        }
        offset += 21;
        // stateRoot: 32-byte string.
        if (headerRlp.length < offset + 33 || uint8(headerRlp[offset]) != 0xA0) {
            revert MalformedHeader();
        }
        return bytes32(headerRlp[offset + 1:offset + 33]);
    }

    /// @dev Validate that the new epoch is strictly greater than the last one.
    function _validateEpochIncreasing(bytes32 policyId, uint64 epoch) internal view {
        uint256 setCount = _setHistory[policyId].length;
        if (setCount > 0) {
            uint64 lastEpoch = _setHistory[policyId][setCount - 1].epoch;
            if (epoch <= lastEpoch) revert EpochNotIncreasing(epoch, lastEpoch);
        }
    }

    /// @dev Append a set entry and emit the publication event.
    function _storeEntry(
        bytes32 policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount,
        bool proven
    ) internal {
        _setHistory[policyId].push(
            SetEntry({
                root: root,
                epoch: epoch,
                blockNumber: blockNumber,
                publishedAt: uint64(block.number),
                memberCount: memberCount,
                proven: proven
            })
        );

        emit SolventSetRootPublished(policyId, root, epoch, blockNumber, memberCount, proven, msg.sender);
    }
}
