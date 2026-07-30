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

    /// @notice How a root's contents were established. Immutable per entry.
    /// @dev Replaces the old `proven` bool, which conflated "candidate
    ///      balances were proven" with "the candidate list was complete" and
    ///      so let the UI show a blanket green badge for both (review R3/§4.1).
    enum Provenance {
        /// The operator asserted the set. No cryptographic backing.
        OperatorAsserted,
        /// Every listed candidate's balance was proven against the block's
        /// state root. Says NOTHING about who was left out of the list.
        BalancesProven,
        /// BalancesProven, plus a receipt scan proving the candidate list
        /// covers every address seen in the token's Transfer events over the
        /// recorded block range. Complete *relative to that range only*.
        RangeScanProven
    }

    /// @notice A stored solvent-set root for a policy epoch.
    /// @dev Every field a verifier needs is pinned here at publication time —
    ///      the entry must never depend on mutable current state (review R4).
    struct SetEntry {
        bytes32 root;
        /// Policy semantics in force when this root was published.
        bytes32 policyConfigHash;
        /// Verification keys this root was accepted under. Rotating a vkey
        /// must not retroactively change what an old root means.
        bytes32 membershipVKey;
        bytes32 derivationVKey;
        uint64 epoch;
        uint64 blockNumber;
        uint64 publishedAt;
        /// Absolute expiry, computed at publication from the *source* block
        /// and the TTL then in force. Previously freshness was measured from
        /// publication against the current TTL, so a delayed publication got a
        /// full fresh TTL and a TTL change retroactively moved expiry.
        uint64 validUntil;
        uint32 memberCount;
        Provenance provenance;
        /// Inclusive scan range backing a RangeScanProven entry (0 otherwise).
        uint64 scanStartBlock;
        uint64 scanEndBlock;
        /// Owner-revoked roots fail verification regardless of TTL.
        bool revoked;
    }

    // --- Constants ---

    /// @dev abi.encode(bytes32 root, bytes32 policyId, uint64 epoch,
    ///      bytes32 nullifierHash, uint64 chainId, uint64 minStreak,
    ///      bytes32 scopeHash, bytes32 policyConfigHash, address verifier,
    ///      uint64 verifierChainId, bytes32 actionId, address beneficiary,
    ///      uint64 nonce, uint64 deadline).
    uint256 private constant MEMBERSHIP_PUBLIC_VALUES_LEN = 448;

    /// @dev abi.encode(bytes32 endBlockHash, uint64 startBlock, uint64 endBlock,
    ///      uint64 numBlocks, address token, bytes32 participantsRoot,
    ///      uint32 participantCount).
    uint256 private constant SCAN_PUBLIC_VALUES_LEN = 224;

    /// @dev abi.encode(bytes32 stateRoot, bytes32 prevRoot, bytes32 newRoot,
    ///      bytes32 policyId, uint64 epoch, uint64 blockNumber,
    ///      uint64 prevBlockNumber, uint64 chainId, uint256 thresholdWei,
    ///      uint32 memberCount, uint32 candidateCount, address token,
    ///      uint64 balanceSlot, bytes32 candidatesRoot).
    uint256 private constant DERIVATION_PUBLIC_VALUES_LEN = 448;

    /// @dev EIP-2935 history contract (live on mainnet since Pectra, May 2025).
    ///      Serves the last 8191 ancestor block hashes, vs 256 for the
    ///      BLOCKHASH opcode — the headroom a multi-block proving job needs.
    address internal constant HISTORY_STORAGE_ADDRESS =
        0x0000F90827F1C53a10cb7A02335B175320002935;

    /// @dev Window served by EIP-2935.
    uint256 internal constant HISTORY_SERVE_WINDOW = 8191;

    /// @dev Domain tag for reference-block sampling.
    bytes32 internal constant REFERENCE_BLOCK_SAMPLE_DOMAIN =
        keccak256("zkpof-refblock-sample-v2");

    /// @dev `sha256("zkpof-empty-solvent-set-v1")` — the root of a set in
    ///      which nobody qualified. A real, publishable outcome, kept
    ///      distinct from `bytes32(0)` which means "no root at all"
    ///      (mirrors `zk_pof_common::solvent_set::EMPTY_SET_ROOT`).
    bytes32 public constant EMPTY_SET_ROOT =
        0xd8bf5d04d144b2f516e9e385272948b54f534876047251f87a3aaa171b83784d;

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

    /// @notice Consumed nullifiers, namespaced by
    ///         `keccak256(consumer, policyConfigHash, actionId)`.
    /// @dev Previously a single `[policyId][nullifier]` namespace shared by
    ///      every caller, so one dApp consuming a nullifier made it
    ///      permanently unavailable to every other dApp on the same policy
    ///      (review R5). Each consumer/action now gets its own namespace.
    mapping(bytes32 => mapping(bytes32 => bool)) public usedNullifiers;

    /// @notice Paused policies reject new publications (owner-controlled).
    mapping(bytes32 => bool) public publicationPaused;

    /// @notice ERC-20 policies: the pinned Solidity mapping slot of
    ///         `balanceOf` for the policy's token. A proven publication must
    ///         match it — a proof against the wrong slot proves nothing.
    mapping(bytes32 => uint64) public balanceSlotOf;

    /// @notice Optional explicit nullifier scope. Zero means "use the policy's
    ///         default scope" (`sha256("zkpof-scope-v1:" || policyId)`).
    ///         Policies configured with the *same* scope deliberately share one
    ///         member-identity namespace (PRIVACY_V2.md §3.1).
    mapping(bytes32 => bytes32) public scopeHashOf;

    /// @notice Policies that require a completeness-proven publication
    ///         (Stage B.2): `publishRootProven` alone is rejected, only
    ///         `publishRootProvenComplete` is accepted.
    mapping(bytes32 => bool) public requiresCompleteness;

    /// @notice Verification key of the receipt-scan program (program-receipt-scan/).
    bytes32 public scanVKey;

    // --- Events ---

    event SolventSetRootPublished(
        bytes32 indexed policyId,
        bytes32 root,
        uint256 epoch,
        uint256 blockNumber,
        uint256 memberCount,
        Provenance provenance,
        bytes32 policyConfigHash,
        uint64 validUntil,
        address publisher
    );

    event NullifierConsumed(
        bytes32 indexed policyId,
        bytes32 indexed nullifierHash,
        address indexed consumer,
        bytes32 actionId
    );

    event RootRevoked(bytes32 indexed policyId, uint256 setIndex, bytes32 root);
    event PublicationPauseSet(bytes32 indexed policyId, bool paused);

    event MembershipVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);
    event DerivationVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);
    event BalanceSlotSet(bytes32 indexed policyId, uint64 balanceSlot);
    event ScopeHashSet(bytes32 indexed policyId, bytes32 scopeHash);
    event CompletenessRequirementSet(bytes32 indexed policyId, bool required);
    event ScanVKeyUpdated(bytes32 oldVKey, bytes32 newVKey);

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
    error ScopeMismatch(bytes32 expected, bytes32 actual);
    error CompletenessRequired(bytes32 policyId);
    error CandidatesNotCovered(bytes32 participantsRoot, bytes32 candidatesRoot);
    error ScanBlockNotCurrent(bytes32 expectedHash, bytes32 scanEndHash);
    error StaleReferenceBlock(uint256 currentBlock, uint64 blockNumber, uint64 maxBlockAge);
    error BlockhashUnavailable(uint64 blockNumber);
    error HeaderHashMismatch(bytes32 expected, bytes32 actual);
    error MalformedHeader();
    error StateRootMismatch(bytes32 headerStateRoot, bytes32 provenStateRoot);
    error EpochNotSequential(uint64 newEpoch, uint64 expectedEpoch);
    error ReferenceBlockNotAdvancing(uint64 newBlock, uint64 lastBlock);
    error ReferenceBlockOutsideEpoch(uint64 blockNumber, uint64 epoch);
    error PrevBlockMismatch(uint64 expected, uint64 actual);
    error ConfigAlreadyPinned(bytes32 policyId);
    error PolicyConfigChanged(bytes32 expected, bytes32 actual);
    error RootRevokedError(bytes32 policyId, uint256 setIndex);
    error PublicationPausedError(bytes32 policyId);
    error VerifierMismatch(address expected, address actual);
    error ProofExpired(uint256 currentBlock, uint64 deadline);
    error BeneficiaryMismatch(address expected, address actual);
    error InvalidScanRange(uint64 startBlock, uint64 endBlock, uint64 numBlocks);
    error ScanRangeNotContiguous(uint64 expectedStart, uint64 actualStart);
    error ScanEndBlockUnavailable(uint64 endBlock);
    error EpochWindowStillOpen(uint64 windowEnd);
    error SamplingEntropyUnavailable(uint64 windowEnd);
    error ReferenceBlockNotSampled(uint64 expected, uint64 actual);

    // --- Constructor ---

    /// @param _policyRegistry Address of the PolicyRegistry contract.
    /// @param _sp1Verifier    Address of the SP1 verifier contract.
    /// @param _membershipVKey Verification key of the membership program
    ///                        (or bytes32(0) until `print-vkeys` output is set).
    /// @param _derivationVKey Verification key of the derivation program
    ///                        (or bytes32(0) until `print-vkeys` output is set).
    /// @param _scanVKey       Verification key of the receipt-scan program
    ///                        (or bytes32(0); only needed for completeness).
    constructor(
        address _policyRegistry,
        address _sp1Verifier,
        bytes32 _membershipVKey,
        bytes32 _derivationVKey,
        bytes32 _scanVKey
    ) Ownable(msg.sender) {
        policyRegistry = PolicyRegistry(_policyRegistry);
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        membershipVKey = _membershipVKey;
        derivationVKey = _derivationVKey;
        scanVKey = _scanVKey;
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

    /// @notice Update the receipt-scan program verification key.
    function setScanVKey(bytes32 _vkey) external onlyOwner {
        bytes32 oldVKey = scanVKey;
        scanVKey = _vkey;
        emit ScanVKeyUpdated(oldVKey, _vkey);
    }

    /// @notice The nullifier scope a policy's membership proofs must use.
    /// @dev Defaults to `sha256("zkpof-scope-v1:" || policyId)`, mirroring
    ///      `zk_pof_common::plume::default_scope_hash`.
    function effectiveScopeHash(bytes32 policyId) public view returns (bytes32) {
        bytes32 configured = scopeHashOf[policyId];
        if (configured != bytes32(0)) return configured;
        return sha256(abi.encodePacked("zkpof-scope-v1:", policyId));
    }

    /// @notice Configure an explicit nullifier scope. Operator-only, and only
    ///         **before the policy's first publication**.
    /// @dev Setting the same scope on two policies makes them share one member
    ///      identity namespace — deliberate linkage, opt-in only. Changing the
    ///      scope after roots exist would invalidate every existing member
    ///      identity and silently change linkability (review R4), so it is
    ///      rejected once history is non-empty; the value is folded into the
    ///      per-root config hash from then on.
    function setScopeHash(bytes32 policyId, bytes32 scope) external {
        _onlyOperatorBeforeFirstPublication(policyId);
        scopeHashOf[policyId] = scope;
        emit ScopeHashSet(policyId, scope);
    }

    /// @notice Require completeness-proven publication. Operator-only, and
    ///         only before the policy's first publication.
    function setRequiresCompleteness(bytes32 policyId, bool required) external {
        _onlyOperatorBeforeFirstPublication(policyId);
        requiresCompleteness[policyId] = required;
        emit CompletenessRequirementSet(policyId, required);
    }

    /// @notice Pin the `balanceOf` mapping slot for an ERC-20 policy's token.
    ///         Operator-only, and only before the policy's first publication.
    /// @dev The slot is part of what makes a proven publication sound for the
    ///      token, so it is pinned into the config hash rather than left
    ///      mutable under published roots.
    function setBalanceSlot(bytes32 policyId, uint64 slot) external {
        _onlyOperatorBeforeFirstPublication(policyId);
        balanceSlotOf[policyId] = slot;
        emit BalanceSlotSet(policyId, slot);
    }

    /// @notice Pause/unpause new publications for a policy (owner-only).
    function setPublicationPaused(bytes32 policyId, bool paused) external onlyOwner {
        publicationPaused[policyId] = paused;
        emit PublicationPauseSet(policyId, paused);
    }

    /// @notice Revoke a specific published root (owner-only). Revocation is
    ///         per-root and does not touch any other entry — the narrow
    ///         emergency control that replaces "rewrite the policy".
    function revokeRoot(bytes32 policyId, uint256 setIndex) external onlyOwner {
        uint256 setCount = _setHistory[policyId].length;
        if (setIndex >= setCount) revert SetIndexOutOfBounds(policyId, setIndex, setCount);
        _setHistory[policyId][setIndex].revoked = true;
        emit RootRevoked(policyId, setIndex, _setHistory[policyId][setIndex].root);
    }

    /// @dev Operator-gated, and only while the policy has no published roots.
    function _onlyOperatorBeforeFirstPublication(bytes32 policyId) internal view {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (msg.sender != policy.operator) revert NotOperator(msg.sender, policy.operator);
        if (_setHistory[policyId].length > 0) revert ConfigAlreadyPinned(policyId);
    }

    /// @notice The full semantic fingerprint a root is published under: the
    ///         registry's policy config plus the oracle-side settings that
    ///         change what a proof means.
    function policyConfigHash(bytes32 policyId) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                policyRegistry.configHash(policyId),
                effectiveScopeHash(policyId),
                balanceSlotOf[policyId],
                requiresCompleteness[policyId]
            )
        );
    }

    // --- Root Publication: Stage A (operator-trusted) ---

    /// @notice Publish a solvent-set root for a policy epoch.
    /// @dev Operator-only. The set contains only public on-chain facts, but
    ///      "reveals nothing" would overstate it: publishing a curated,
    ///      threshold-filtered, streak-labelled list of wealthy accounts is a
    ///      cheaper targeting artefact than reconstructing the same list from
    ///      raw chain history. Publish deliberately (review §4.3).
    function publishRoot(
        bytes32 policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) external {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (!policy.active) revert PolicyNotActive(policyId);
        if (publicationPaused[policyId]) revert PublicationPausedError(policyId);
        if (msg.sender != policy.operator) revert NotOperator(msg.sender, policy.operator);
        if (root == bytes32(0)) revert ZeroRoot();

        // Even the trusted path must respect the epoch schedule — previously
        // it stored an arbitrary operator-supplied block with no relation to
        // the epoch, freshness, or the previous entry (review R2).
        _validateEpochSchedule(policyId, epoch, blockNumber, policy);
        _storeEntry(
            policyId, root, epoch, blockNumber, memberCount,
            Provenance.OperatorAsserted, policy, 0, 0
        );
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
        if (requiresCompleteness[policyId]) revert CompletenessRequired(policyId);
        _publishRootProven(policyId, headerRlp, publicValues, proofBytes, bytes32(0), false, 0, 0);
    }

    /// @notice Publish a proven root that is ALSO proven *complete*: a second
    ///         SP1 proof (program-receipt-scan/) shows the candidate list the
    ///         derivation checked covers every address that appeared in any
    ///         `Transfer` of the policy's token over a contiguous block range
    ///         ending at the current chain tip. Callable by anyone.
    /// @dev The composition is `participantsRoot == candidatesRoot`: both
    ///      proofs commit the same address-set commitment, so equality means
    ///      the derivation omitted nobody the scan saw. This closes the
    ///      censorship/liveness gap left by Stage B (PRIVACY_V2.md §4.4).
    /// @param scanPublicValues ABI-encoded public outputs of the scan program.
    /// @param scanProofBytes   SP1 Groth16 proof of the scan program.
    function publishRootProvenComplete(
        bytes32 policyId,
        bytes calldata headerRlp,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        bytes calldata scanPublicValues,
        bytes calldata scanProofBytes
    ) external {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);

        if (scanPublicValues.length != SCAN_PUBLIC_VALUES_LEN) {
            revert InvalidPublicValuesLength(scanPublicValues.length);
        }
        (
            bytes32 endBlockHash,
            uint64 scanStartBlock,
            uint64 scanEndBlock,
            uint64 numBlocks,
            address scanToken,
            bytes32 participantsRoot,
            // uint32 participantCount
        ) = abi.decode(
            scanPublicValues,
            (bytes32, uint64, uint64, uint64, address, bytes32, uint32)
        );

        // The scan must cover the policy's asset...
        if (scanToken != policy.tokenAddress) {
            revert TokenMismatch(policy.tokenAddress, scanToken);
        }

        // ...and its range must actually be pinned. Previously `numBlocks` was
        // decoded and discarded and no start block was supplied at all, so a
        // one-block scan satisfied the same interface as a
        // deployment-to-tip scan (review R3).
        if (scanEndBlock < scanStartBlock || numBlocks != scanEndBlock - scanStartBlock + 1) {
            revert InvalidScanRange(scanStartBlock, scanEndBlock, numBlocks);
        }
        // Contiguity: the first scan for a policy must start at or before the
        // policy's start block; later scans must continue from the previous
        // range without leaving a gap.
        uint256 setCount = _setHistory[policyId].length;
        if (setCount > 0 && _setHistory[policyId][setCount - 1].provenance == Provenance.RangeScanProven) {
            uint64 prevEnd = _setHistory[policyId][setCount - 1].scanEndBlock;
            if (scanStartBlock > prevEnd + 1) {
                revert ScanRangeNotContiguous(prevEnd + 1, scanStartBlock);
            }
        } else if (scanStartBlock > policy.startBlock) {
            revert ScanRangeNotContiguous(policy.startBlock, scanStartBlock);
        }

        // The scan's end block must be one this chain actually produced and
        // still serves a hash for. Using EIP-2935 rather than
        // `blockhash(block.number - 1)` gives ~8191 blocks of headroom, so a
        // multi-minute proving job can still land — the old rule required the
        // proof to be generated and included within a single block interval,
        // which no realistic historical scan can meet (review R3).
        bytes32 expectedEndHash = _blockhash(scanEndBlock);
        if (expectedEndHash == bytes32(0)) revert ScanEndBlockUnavailable(scanEndBlock);
        if (endBlockHash != expectedEndHash) {
            revert ScanBlockNotCurrent(expectedEndHash, endBlockHash);
        }

        sp1Verifier.verifyProof(scanVKey, scanPublicValues, scanProofBytes);

        _publishRootProven(
            policyId, headerRlp, publicValues, proofBytes,
            participantsRoot, true, scanStartBlock, scanEndBlock
        );
    }

    /// @dev Shared publication core. When `checkCompleteness` is set, the
    ///      derivation's `candidatesRoot` must equal `participantsRoot`.
    function _publishRootProven(
        bytes32 policyId,
        bytes calldata headerRlp,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        bytes32 participantsRoot,
        bool checkCompleteness,
        uint64 scanStartBlock,
        uint64 scanEndBlock
    ) internal {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        if (!policy.active) revert PolicyNotActive(policyId);
        if (publicationPaused[policyId]) revert PublicationPausedError(policyId);

        if (publicValues.length != DERIVATION_PUBLIC_VALUES_LEN) {
            revert InvalidPublicValuesLength(publicValues.length);
        }
        DerivationValues memory d = _decodeDerivation(publicValues);

        if (d.policyId != policyId) revert PublicValuesMismatch();
        if (d.newRoot == bytes32(0)) revert ZeroRoot();
        if (d.chainId != uint64(block.chainid)) {
            revert ChainIdMismatch(uint64(block.chainid), d.chainId);
        }
        // The source chain and the verifier chain are the same chain: the
        // state root is bound through this chain's own block hashes. The
        // policy's chainId field is therefore not a cross-chain selector, and
        // letting it disagree would be a lie about what was proven (review
        // §4.7). Real cross-chain verification needs a light client or
        // checkpoint oracle; until then this is enforced, not implied.
        if (policy.chainId != uint64(block.chainid)) {
            revert ChainIdMismatch(uint64(block.chainid), policy.chainId);
        }
        if (d.thresholdWei != policy.thresholdWei) {
            revert ThresholdMismatch(policy.thresholdWei, d.thresholdWei);
        }
        // Asset binding: the proof's token/slot must match the policy's.
        if (d.token != policy.tokenAddress) {
            revert TokenMismatch(policy.tokenAddress, d.token);
        }
        uint64 pinnedSlot = d.token == address(0) ? 0 : balanceSlotOf[policyId];
        if (d.balanceSlot != pinnedSlot) {
            revert BalanceSlotMismatch(pinnedSlot, d.balanceSlot);
        }
        // Stage B.2 composition: the checked candidate list must be exactly
        // the participant list the scan proved complete.
        if (checkCompleteness && participantsRoot != d.candidatesRoot) {
            revert CandidatesNotCovered(participantsRoot, d.candidatesRoot);
        }

        // Epoch schedule + streak continuity bound to our stored history.
        _validateEpochSchedule(policyId, d.epoch, d.blockNumber, policy);
        // ...and, on the permissionless path, the reference block must be the
        // one the sampling rule names — not one the publisher preferred.
        _validateSampledReferenceBlock(policyId, d.epoch, d.blockNumber, policy);
        bytes32 expectedPrevRoot = bytes32(0);
        uint64 expectedPrevBlock = 0;
        uint256 setCount = _setHistory[policyId].length;
        if (setCount > 0) {
            expectedPrevRoot = _setHistory[policyId][setCount - 1].root;
            expectedPrevBlock = _setHistory[policyId][setCount - 1].blockNumber;
        }
        if (d.prevRoot != expectedPrevRoot) revert PrevRootMismatch(expectedPrevRoot, d.prevRoot);
        // The circuit asserts blockNumber > prevBlockNumber; binding
        // prevBlockNumber to *our* stored entry is what stops a publisher
        // supplying an invented older block to satisfy that inequality while
        // re-proving the same snapshot (review R2).
        if (d.prevBlockNumber != expectedPrevBlock) {
            revert PrevBlockMismatch(expectedPrevBlock, d.prevBlockNumber);
        }

        // Reference-block freshness + state-root binding via the header.
        if (d.blockNumber >= block.number || block.number - d.blockNumber > policy.maxBlockAge) {
            revert StaleReferenceBlock(block.number, d.blockNumber, policy.maxBlockAge);
        }
        bytes32 expectedHash = _blockhash(d.blockNumber);
        if (expectedHash == bytes32(0)) revert BlockhashUnavailable(d.blockNumber);
        bytes32 headerHash = keccak256(headerRlp);
        if (headerHash != expectedHash) revert HeaderHashMismatch(expectedHash, headerHash);
        bytes32 headerStateRoot = _extractStateRoot(headerRlp);
        if (headerStateRoot != d.stateRoot) {
            revert StateRootMismatch(headerStateRoot, d.stateRoot);
        }

        // Verify the derivation proof (reverts on invalid proof).
        sp1Verifier.verifyProof(derivationVKey, publicValues, proofBytes);

        _storeEntry(
            policyId, d.newRoot, d.epoch, d.blockNumber, d.memberCount,
            checkCompleteness ? Provenance.RangeScanProven : Provenance.BalancesProven,
            policy, scanStartBlock, scanEndBlock
        );
    }

    /// @dev Decoded derivation public values (a struct keeps the publication
    ///      core under the stack-depth limit).
    struct DerivationValues {
        bytes32 stateRoot;
        bytes32 prevRoot;
        bytes32 newRoot;
        bytes32 policyId;
        uint64 epoch;
        uint64 blockNumber;
        uint64 prevBlockNumber;
        uint64 chainId;
        uint256 thresholdWei;
        uint32 memberCount;
        address token;
        uint64 balanceSlot;
        bytes32 candidatesRoot;
    }

    function _decodeDerivation(bytes calldata publicValues)
        internal
        pure
        returns (DerivationValues memory d)
    {
        (
            d.stateRoot,
            d.prevRoot,
            d.newRoot,
            d.policyId,
            d.epoch,
            d.blockNumber,
            d.prevBlockNumber,
            d.chainId,
            d.thresholdWei,
            d.memberCount,
            , // candidateCount
            d.token,
            d.balanceSlot,
            d.candidatesRoot
        ) = abi.decode(
            publicValues,
            (
                bytes32, bytes32, bytes32, bytes32, uint64, uint64, uint64, uint64,
                uint256, uint32, uint32, address, uint64, bytes32
            )
        );
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
        if (entry.revoked) revert RootRevokedError(policyId, setIndex);

        // Expiry from the entry's own pinned `validUntil` — never from the
        // policy's *current* TTL, which the owner can change (review §4.6).
        if (block.number > entry.validUntil) {
            revert SetExpired(block.number, entry.blockNumber, entry.validUntil);
        }

        // Verify the SP1 proof under the vkey this root was published with,
        // so rotating the key cannot retroactively change which program is
        // accepted for an already-published root.
        sp1Verifier.verifyProof(entry.membershipVKey, publicValues, proofBytes);

        if (publicValues.length != MEMBERSHIP_PUBLIC_VALUES_LEN) {
            revert InvalidPublicValuesLength(publicValues.length);
        }
        MembershipValues memory m = _decodeMembership(publicValues);

        if (
            m.root != entry.root ||
            m.policyId != policyId ||
            m.epoch != entry.epoch ||
            m.chainId != uint64(block.chainid)
        ) {
            revert PublicValuesMismatch();
        }
        // The nullifier must be bound to this policy's configured scope —
        // otherwise a proof from a differently-scoped policy could be replayed
        // here under a different identity.
        bytes32 expectedScope = effectiveScopeHash(policyId);
        if (m.scopeHash != expectedScope) {
            revert ScopeMismatch(expectedScope, m.scopeHash);
        }
        // The proof must have been made under the same policy semantics this
        // root was published under.
        if (m.policyConfigHash != entry.policyConfigHash) {
            revert PolicyConfigChanged(entry.policyConfigHash, m.policyConfigHash);
        }

        // --- Presentation context (review finding R5) ---
        // Without these, a valid proof is a bearer token: anyone who sees it
        // can present it to another dApp, and a mempool watcher can front-run
        // the owner's own transaction and burn the nullifier.
        if (m.verifier != address(this)) {
            revert VerifierMismatch(address(this), m.verifier);
        }
        if (m.verifierChainId != uint64(block.chainid)) {
            revert ChainIdMismatch(uint64(block.chainid), m.verifierChainId);
        }
        if (block.number > m.deadline) revert ProofExpired(block.number, m.deadline);

        return (m.nullifierHash, m.minStreak);
    }

    /// @notice Verify a membership proof and consume its nullifier within the
    ///         caller's own namespace.
    /// @dev The proof must name `msg.sender` as the intended beneficiary, so
    ///      copying it out of the mempool and front-running the owner no
    ///      longer works: the attacker's call reverts rather than burning the
    ///      nullifier. Consumption is keyed by
    ///      (consumer, policyConfigHash, actionId), so one dApp can never
    ///      exhaust another's namespace (review R5).
    function verifyAndConsume(
        bytes32 policyId,
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external returns (bytes32 nullifierHash, uint64 minStreak) {
        (nullifierHash, minStreak) = verifyMembership(policyId, setIndex, publicValues, proofBytes);
        MembershipValues memory m = _decodeMembership(publicValues);

        if (m.beneficiary != msg.sender) {
            revert BeneficiaryMismatch(m.beneficiary, msg.sender);
        }

        bytes32 ns = nullifierNamespace(msg.sender, m.policyConfigHash, m.actionId);
        if (usedNullifiers[ns][nullifierHash]) {
            revert NullifierAlreadyUsed(policyId, nullifierHash);
        }
        usedNullifiers[ns][nullifierHash] = true;
        emit NullifierConsumed(policyId, nullifierHash, msg.sender, m.actionId);
    }

    /// @dev Decoded membership public values.
    struct MembershipValues {
        bytes32 root;
        bytes32 policyId;
        uint64 epoch;
        bytes32 nullifierHash;
        uint64 chainId;
        uint64 minStreak;
        bytes32 scopeHash;
        bytes32 policyConfigHash;
        address verifier;
        uint64 verifierChainId;
        bytes32 actionId;
        address beneficiary;
        uint64 nonce;
        uint64 deadline;
    }

    function _decodeMembership(bytes calldata publicValues)
        internal
        pure
        returns (MembershipValues memory m)
    {
        (
            m.root,
            m.policyId,
            m.epoch,
            m.nullifierHash,
            m.chainId,
            m.minStreak,
            m.scopeHash,
            m.policyConfigHash,
            m.verifier,
            m.verifierChainId,
            m.actionId,
            m.beneficiary,
            m.nonce,
            m.deadline
        ) = abi.decode(
            publicValues,
            (
                bytes32, bytes32, uint64, bytes32, uint64, uint64, bytes32, bytes32,
                address, uint64, bytes32, address, uint64, uint64
            )
        );
    }

    // --- Views ---

    /// @notice The consumption namespace for a (consumer, config, action).
    function nullifierNamespace(address consumer, bytes32 configHash, bytes32 actionId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(consumer, configHash, actionId));
    }

    /// @notice Whether a nullifier has been consumed in a specific namespace.
    function isNullifierUsed(
        address consumer,
        bytes32 configHash,
        bytes32 actionId,
        bytes32 nullifierHash
    ) external view returns (bool) {
        return usedNullifiers[nullifierNamespace(consumer, configHash, actionId)][nullifierHash];
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
    ///      swappable for L2 blockhash oracles.
    ///
    ///      Reads through the EIP-2935 history contract, which has served the
    ///      previous 8191 ancestor hashes from state since the Pectra upgrade
    ///      (mainnet, May 2025), and falls back to the 256-block BLOCKHASH
    ///      opcode on chains where the system contract is absent. The wider
    ///      window is what makes a multi-block proving job publishable at all.
    function _blockhash(uint64 blockNumber) internal view virtual returns (bytes32) {
        if (blockNumber >= block.number) return bytes32(0);
        uint256 age = block.number - blockNumber;

        if (age <= 256) {
            bytes32 fromOpcode = blockhash(blockNumber);
            if (fromOpcode != bytes32(0)) return fromOpcode;
        }
        if (age > HISTORY_SERVE_WINDOW) return bytes32(0);

        (bool ok, bytes memory out) =
            HISTORY_STORAGE_ADDRESS.staticcall(abi.encode(uint256(blockNumber)));
        if (!ok || out.length != 32) return bytes32(0);
        return abi.decode(out, (bytes32));
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

    /// @dev Enforce the epoch schedule for a new publication.
    ///
    ///      A "streak" only means "solvent across N separate observations" if
    ///      the epochs are consecutive and each one samples a strictly later
    ///      block inside its own window. The old rule was `epoch > lastEpoch`
    ///      and nothing else, so a publisher could re-prove one funded block
    ///      into an arbitrarily long streak by submitting epochs 1..N in
    ///      order (review finding R2). We now require:
    ///        - epoch == lastEpoch + 1 (no skipping)
    ///        - referenceBlock strictly newer than the previous entry's
    ///        - referenceBlock inside epoch's window, derived from the
    ///          policy's startBlock and epochLengthBlocks
    function _validateEpochSchedule(
        bytes32 policyId,
        uint64 epoch,
        uint64 blockNumber,
        PolicyRegistry.Policy memory policy
    ) internal view {
        uint256 setCount = _setHistory[policyId].length;
        if (setCount > 0) {
            SetEntry storage last = _setHistory[policyId][setCount - 1];
            if (epoch <= last.epoch) revert EpochNotIncreasing(epoch, last.epoch);
            if (epoch != last.epoch + 1) revert EpochNotSequential(epoch, last.epoch + 1);
            if (blockNumber <= last.blockNumber) {
                revert ReferenceBlockNotAdvancing(blockNumber, last.blockNumber);
            }
        }

        // The reference block must fall in the window this epoch names, so
        // the epoch number is a fact about *when* the observation happened
        // rather than a free-running counter.
        if (blockNumber < policy.startBlock) {
            revert ReferenceBlockOutsideEpoch(blockNumber, epoch);
        }
        // Widened to uint256 so an absurd first-publication epoch reverts with
        // this specific error rather than an opaque arithmetic panic.
        uint256 windowStart =
            uint256(policy.startBlock) + uint256(epoch) * uint256(policy.epochLengthBlocks);
        uint256 windowEnd = windowStart + policy.epochLengthBlocks;
        if (blockNumber < windowStart || blockNumber >= windowEnd) {
            revert ReferenceBlockOutsideEpoch(blockNumber, epoch);
        }
    }

    /// @notice The reference block epoch `epoch` must be proven against.
    ///
    /// @dev A streak is only an anti-rental deterrent if the holder cannot
    ///      know, while deciding whether to hold funds, which block will be
    ///      sampled. So the sample is derived from the hash of the first block
    ///      **after** the epoch's window — entropy that does not exist until
    ///      the window has closed and every balance in it is already settled:
    ///
    ///        windowStart = startBlock + epoch * epochLengthBlocks
    ///        windowEnd   = windowStart + epochLengthBlocks   (exclusive)
    ///        entropy     = blockhash(windowEnd)
    ///        reference   = windowStart
    ///                    + keccak(DOMAIN, configHash, epoch, entropy)
    ///                      % epochLengthBlocks
    ///
    ///      The previous scheme derived the sample from the *current* block,
    ///      which an operator could watch and re-roll by simply waiting — the
    ///      randomness was real but the choice of when to consume it was not
    ///      constrained (review finding R2). Here the answer is fixed the
    ///      moment the window closes, and identical for every publisher.
    ///
    ///      Reverts if the window has not closed yet, or if the entropy block
    ///      is outside the served hash window.
    function sampledReferenceBlock(bytes32 policyId, uint64 epoch)
        public
        view
        returns (uint64)
    {
        PolicyRegistry.Policy memory policy = policyRegistry.getPolicy(policyId);
        return _sampledReferenceBlock(policyId, epoch, policy);
    }

    function _sampledReferenceBlock(
        bytes32 policyId,
        uint64 epoch,
        PolicyRegistry.Policy memory policy
    ) internal view returns (uint64) {
        uint256 windowStart =
            uint256(policy.startBlock) + uint256(epoch) * uint256(policy.epochLengthBlocks);
        uint256 windowEnd = windowStart + policy.epochLengthBlocks;

        // The window must be closed: sampling from an open window would let a
        // holder see the draw while they can still move funds.
        if (block.number <= windowEnd) revert EpochWindowStillOpen(uint64(windowEnd));

        bytes32 entropy = _blockhash(uint64(windowEnd));
        if (entropy == bytes32(0)) revert SamplingEntropyUnavailable(uint64(windowEnd));

        uint256 offset = uint256(
            keccak256(
                abi.encode(REFERENCE_BLOCK_SAMPLE_DOMAIN, policyConfigHash(policyId), epoch, entropy)
            )
        ) % policy.epochLengthBlocks;

        return uint64(windowStart + offset);
    }

    /// @dev Require the proven reference block to equal the sampled one, and
    ///      the publication to land within `maxBlockAge` of the window closing.
    function _validateSampledReferenceBlock(
        bytes32 policyId,
        uint64 epoch,
        uint64 blockNumber,
        PolicyRegistry.Policy memory policy
    ) internal view {
        uint64 expected = _sampledReferenceBlock(policyId, epoch, policy);
        if (blockNumber != expected) {
            revert ReferenceBlockNotSampled(expected, blockNumber);
        }
        uint256 windowEnd = uint256(policy.startBlock)
            + uint256(epoch + 1) * uint256(policy.epochLengthBlocks);
        // `maxBlockAge` now means "how long after the window closes you may
        // still publish", which is the only freshness notion that survives a
        // sampled reference block: the block itself is whatever the draw said.
        if (block.number - windowEnd > policy.maxBlockAge) {
            revert StaleReferenceBlock(block.number, blockNumber, policy.maxBlockAge);
        }
    }

    /// @dev Append a set entry and emit the publication event. Every semantic
    ///      input is pinned into the entry here; nothing about verifying this
    ///      root later may depend on mutable current state.
    function _storeEntry(
        bytes32 policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount,
        Provenance provenance,
        PolicyRegistry.Policy memory policy,
        uint64 scanStartBlock,
        uint64 scanEndBlock
    ) internal {
        // Freeze the policy at first publication: from here on its semantics
        // are what this root (and every later one) attests under.
        policyRegistry.freezePolicy(policyId);

        bytes32 configHash = policyConfigHash(policyId);
        // Expiry runs from the *source* block, not from publication — a root
        // built on old state must not get a full fresh TTL just because it was
        // published late (review §4.6).
        uint64 validUntil = blockNumber + policy.rootTTLBlocks;

        _setHistory[policyId].push(
            SetEntry({
                root: root,
                policyConfigHash: configHash,
                membershipVKey: membershipVKey,
                derivationVKey: derivationVKey,
                epoch: epoch,
                blockNumber: blockNumber,
                publishedAt: uint64(block.number),
                validUntil: validUntil,
                memberCount: memberCount,
                provenance: provenance,
                scanStartBlock: scanStartBlock,
                scanEndBlock: scanEndBlock,
                revoked: false
            })
        );

        emit SolventSetRootPublished(
            policyId, root, epoch, blockNumber, memberCount,
            provenance, configHash, validUntil, msg.sender
        );
    }
}
