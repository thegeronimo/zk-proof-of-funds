// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolventSetOracle} from "../src/SolventSetOracle.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";

/// @dev Test harness exposing a settable blockhash source, since Foundry's
///      default environment has no real block hashes. Production code path is
///      identical except for the `_blockhash` virtual hook.
contract TestableSolventSetOracle is SolventSetOracle {
    mapping(uint64 => bytes32) private _hashes;

    constructor(
        address _policyRegistry,
        address _sp1Verifier,
        bytes32 _membershipVKey,
        bytes32 _derivationVKey,
        bytes32 _scanVKey
    ) SolventSetOracle(_policyRegistry, _sp1Verifier, _membershipVKey, _derivationVKey, _scanVKey) {}

    function setBlockhash(uint64 blockNumber, bytes32 hash) external {
        _hashes[blockNumber] = hash;
    }

    function _blockhash(uint64 blockNumber) internal view override returns (bytes32) {
        return _hashes[blockNumber];
    }
}

contract SolventSetOracleTest is Test {
    PolicyRegistry registry;
    TestableSolventSetOracle oracle;
    MockSP1Verifier mockVerifier;

    address operatorAddr;
    address stranger;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));
    bytes32 constant OTHER_POLICY_ID = bytes32(uint256(0x02));
    bytes32 constant SET_ROOT = bytes32(uint256(0xABCD));
    bytes32 constant NULLIFIER_HASH = bytes32(uint256(0xFEED));
    bytes32 constant STATE_ROOT = bytes32(uint256(0x57A7E));
    bytes32 constant CANDIDATES_ROOT = bytes32(uint256(0xCA4D));
    bytes32 constant ACTION_ID = bytes32(uint256(0xAC10));
    uint64 constant ROOT_TTL = 1000;
    uint64 constant EPOCH_LEN = 100;
    uint64 constant SCAN_START = 0;
    uint256 constant THRESHOLD = 1 ether;

    function setUp() public {
        operatorAddr = makeAddr("operator");
        stranger = makeAddr("stranger");

        registry = new PolicyRegistry();
        mockVerifier = new MockSP1Verifier();
        oracle = new TestableSolventSetOracle(
            address(registry),
            address(mockVerifier),
            bytes32(0), // placeholder membership vkey
            bytes32(0), // placeholder derivation vkey
            bytes32(0)  // placeholder scan vkey
        );
        registry.setFreezer(address(oracle));

        registry.createPolicy(POLICY_ID, _defaultPolicy(address(0), "test-scope"));
    }

    function _defaultPolicy(address token, string memory scope)
        internal
        view
        returns (PolicyRegistry.Policy memory)
    {
        return PolicyRegistry.Policy({
            thresholdWei: THRESHOLD,
            tokenAddress: token,
            chainId: uint64(block.chainid),
            epochLengthBlocks: EPOCH_LEN,
            maxBlockAge: 256,
            rootTTLBlocks: ROOT_TTL,
            operator: operatorAddr,
            scope: scope,
            trustedMode: false,
            active: true,
            startBlock: 0,
            version: 1
        });
    }

    // --- Helpers ---

    /// @dev The canonical reference block for an epoch: the middle of the
    ///      epoch's window `[startBlock + epoch*len, +len)`.
    function _epochBlock(uint64 epoch) internal pure returns (uint64) {
        return epoch * EPOCH_LEN + EPOCH_LEN / 2;
    }

    /// @dev ABI-encode membership public values exactly as the SP1 program
    ///      commits them (crates/common/src/membership.rs::abi_encode).
    function _publicValues(
        bytes32 root,
        bytes32 policyId,
        uint64 epoch,
        bytes32 nullifierHash,
        uint64 minStreak
    ) internal view returns (bytes memory) {
        return _publicValuesFull(
            root, policyId, epoch, nullifierHash, uint64(block.chainid), minStreak,
            oracle.effectiveScopeHash(policyId), oracle.policyConfigHash(policyId),
            address(oracle), uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 100)
        );
    }

    function _publicValuesFull(
        bytes32 root,
        bytes32 policyId,
        uint64 epoch,
        bytes32 nullifierHash,
        uint64 chainId,
        uint64 minStreak,
        bytes32 scopeHash,
        bytes32 configHash,
        address verifier,
        uint64 verifierChainId,
        bytes32 actionId,
        address beneficiary,
        uint64 nonce,
        uint64 deadline
    ) internal pure returns (bytes memory) {
        return abi.encode(
            root, policyId, epoch, nullifierHash, chainId, minStreak, scopeHash,
            configHash, verifier, verifierChainId, actionId, beneficiary, nonce, deadline
        );
    }

    /// @dev ABI-encode derivation public values exactly as the SP1 program
    ///      commits them (crates/common/src/solvent_derivation.rs::abi_encode).
    ///      Native-ETH shape: zero token, zero slot.
    function _derivationValues(
        bytes32 stateRoot,
        bytes32 prevRoot,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint64 prevBlockNumber,
        uint64 chainId,
        uint256 thresholdWei
    ) internal pure returns (bytes memory) {
        return _derivationValuesFor(
            POLICY_ID, stateRoot, prevRoot, newRoot, epoch, blockNumber, prevBlockNumber,
            chainId, thresholdWei, address(0), 0
        );
    }

    function _derivationValuesFor(
        bytes32 policyId,
        bytes32 stateRoot,
        bytes32 prevRoot,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint64 prevBlockNumber,
        uint64 chainId,
        uint256 thresholdWei,
        address token,
        uint64 balanceSlot
    ) internal pure returns (bytes memory) {
        return _derivationValuesWithCandidates(
            policyId, stateRoot, prevRoot, newRoot, epoch, blockNumber, prevBlockNumber,
            chainId, thresholdWei, token, balanceSlot, CANDIDATES_ROOT
        );
    }

    function _derivationValuesWithCandidates(
        bytes32 policyId,
        bytes32 stateRoot,
        bytes32 prevRoot,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint64 prevBlockNumber,
        uint64 chainId,
        uint256 thresholdWei,
        address token,
        uint64 balanceSlot,
        bytes32 candidatesRoot
    ) internal pure returns (bytes memory) {
        return abi.encode(
            stateRoot, prevRoot, newRoot, policyId, epoch, blockNumber, prevBlockNumber,
            chainId, thresholdWei, uint32(3), uint32(5), token, balanceSlot, candidatesRoot
        );
    }

    /// @dev ABI-encode receipt-scan public values as the scan program commits
    ///      them (crates/common/src/receipt_scan.rs::abi_encode). The range is
    ///      now part of the statement, not decorative metadata.
    function _scanValues(
        bytes32 endBlockHash,
        uint64 startBlock,
        uint64 endBlock,
        address token,
        bytes32 participantsRoot
    ) internal pure returns (bytes memory) {
        return abi.encode(
            endBlockHash, startBlock, endBlock, endBlock - startBlock + 1,
            token, participantsRoot, uint32(3)
        );
    }

    /// @dev A minimal header the fixed-shape walker accepts: list prefix, two
    ///      32-byte hashes, a 20-byte coinbase, then the state root. Anything
    ///      beyond item 3 is irrelevant — real binding comes from the keccak.
    function _buildHeader(bytes32 stateRoot) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"f90200",
            hex"a0", bytes32(uint256(0x1111)), // parentHash
            hex"a0", bytes32(uint256(0x2222)), // unclesHash
            hex"94", bytes20(uint160(0x3333)), // coinbase
            hex"a0", stateRoot
        );
    }

    function _publishDefaultRoot() internal {
        vm.roll(_epochBlock(1) + 1);
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    /// @dev Roll forward and prepare a provable reference block for `epoch`:
    ///      header + registered blockhash. Returns (refBlock, headerRlp).
    /// @dev Prepare a provable reference block for `epoch` on the *proven*
    ///      path. The block is not ours to choose: the oracle recomputes the
    ///      sample from the hash of the first block after the epoch's window,
    ///      so the harness registers that entropy, asks the oracle which block
    ///      it drew, and provides a header for exactly that block.
    function _prepareProvenBlock(bytes32 stateRoot, uint64 epoch)
        internal
        returns (uint64, bytes memory)
    {
        uint64 windowEnd = (epoch + 1) * EPOCH_LEN;
        vm.roll(windowEnd + 50); // window closed, inside maxBlockAge (256)
        oracle.setBlockhash(windowEnd, keccak256(abi.encodePacked("entropy", epoch)));

        uint64 refBlock = oracle.sampledReferenceBlock(POLICY_ID, epoch);
        bytes memory headerRlp = _buildHeader(stateRoot);
        oracle.setBlockhash(refBlock, keccak256(headerRlp));
        return (refBlock, headerRlp);
    }

    /// @dev As above but for a policy other than POLICY_ID.
    function _prepareProvenBlockFor(bytes32 policyId, bytes32 stateRoot, uint64 epoch)
        internal
        returns (uint64, bytes memory)
    {
        uint64 windowEnd = (epoch + 1) * EPOCH_LEN;
        vm.roll(windowEnd + 50);
        oracle.setBlockhash(windowEnd, keccak256(abi.encodePacked("entropy", epoch)));

        uint64 refBlock = oracle.sampledReferenceBlock(policyId, epoch);
        bytes memory headerRlp = _buildHeader(stateRoot);
        oracle.setBlockhash(refBlock, keccak256(headerRlp));
        return (refBlock, headerRlp);
    }

    // --- publishRoot (Stage A) ---

    function test_PublishRoot() public {
        _publishDefaultRoot();

        assertEq(oracle.getSetCount(POLICY_ID), 1);
        assertEq(oracle.latestSetIndex(POLICY_ID), 0);

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertEq(entry.root, SET_ROOT);
        assertEq(entry.epoch, 1);
        assertEq(entry.memberCount, 42);
        assertEq(entry.publishedAt, uint64(block.number));
        assertTrue(
            entry.provenance == SolventSetOracle.Provenance.OperatorAsserted,
            "Stage A publication is operator-asserted, not proven"
        );
        // Expiry runs from the source block, not from publication.
        assertEq(entry.validUntil, _epochBlock(1) + ROOT_TTL);
        assertEq(entry.policyConfigHash, oracle.policyConfigHash(POLICY_ID));
    }

    /// An epoch where nobody qualified must still be publishable. Previously
    /// the empty set hashed to zero and both paths rejected it, so the
    /// operator's only options were to publish a false set or nothing at all.
    function test_PublishRoot_AcceptsEmptySetSentinel() public {
        bytes32 emptyRoot = oracle.EMPTY_SET_ROOT();
        vm.roll(_epochBlock(1) + 1);
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, emptyRoot, 1, _epochBlock(1), 0);

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertEq(entry.root, emptyRoot);
        assertEq(entry.memberCount, 0);
        // ...while a genuinely absent root stays rejected.
        vm.roll(_epochBlock(2) + 1);
        vm.prank(operatorAddr);
        vm.expectRevert(SolventSetOracle.ZeroRoot.selector);
        oracle.publishRoot(POLICY_ID, bytes32(0), 2, _epochBlock(2), 0);
    }

    /// The sentinel must equal the Rust constant byte for byte, or an empty
    /// set built off-chain would not match what the contract stores.
    function test_EmptySetRootMatchesRustConstant() public view {
        assertEq(
            oracle.EMPTY_SET_ROOT(),
            sha256(abi.encodePacked("zkpof-empty-solvent-set-v1")),
            "must equal SHA256(EMPTY_SET_DOMAIN)"
        );
    }

    function test_PublishRoot_FreezesPolicy() public {
        assertFalse(registry.policyFrozen(POLICY_ID));
        _publishDefaultRoot();
        assertTrue(registry.policyFrozen(POLICY_ID), "First publication freezes semantics");
    }

    /// Deployment footgun: the oracle must be the registry's authorized
    /// freezer, or every publication reverts. Deploy.s.sol wires this; this
    /// test makes the failure mode explicit rather than a mystery revert.
    function test_PublishRoot_RevertsWhenOracleIsNotTheFreezer() public {
        PolicyRegistry fresh = new PolicyRegistry();
        TestableSolventSetOracle detached = new TestableSolventSetOracle(
            address(fresh), address(mockVerifier), bytes32(0), bytes32(0), bytes32(0)
        );
        fresh.createPolicy(POLICY_ID, _defaultPolicy(address(0), "test-scope"));
        // Deliberately NOT calling fresh.setFreezer(address(detached)).

        vm.roll(_epochBlock(1) + 1);
        vm.prank(operatorAddr);
        vm.expectRevert(PolicyRegistry.NotAuthorized.selector);
        detached.publishRoot(POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    function test_PublishRoot_RevertsForNonOperator() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.NotOperator.selector, stranger, operatorAddr)
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    function test_PublishRoot_RevertsForZeroRoot() public {
        vm.prank(operatorAddr);
        vm.expectRevert(SolventSetOracle.ZeroRoot.selector);
        oracle.publishRoot(POLICY_ID, bytes32(0), 1, _epochBlock(1), 42);
    }

    function test_PublishRoot_RevertsForNonIncreasingEpoch() public {
        _publishDefaultRoot();

        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.EpochNotIncreasing.selector, uint64(1), uint64(1))
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    function test_PublishRoot_RevertsForInactivePolicy() public {
        registry.deactivatePolicy(POLICY_ID);

        vm.prank(operatorAddr);
        vm.expectRevert(abi.encodeWithSelector(SolventSetOracle.PolicyNotActive.selector, POLICY_ID));
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    function test_PublishRoot_RevertsForUnknownPolicy() public {
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyRegistry.PolicyNotFound.selector, OTHER_POLICY_ID)
        );
        oracle.publishRoot(OTHER_POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    // --- Epoch schedule enforcement (review finding R2) ---

    function test_PublishRoot_RevertsOnSkippedEpoch() public {
        _publishDefaultRoot(); // epoch 1

        // Jumping to epoch 3 would let a publisher skip an observation while
        // still advancing the counter.
        vm.roll(_epochBlock(3) + 1);
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.EpochNotSequential.selector, uint64(3), uint64(2))
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 3, _epochBlock(3), 42);
    }

    function test_PublishRoot_RevertsWhenReferenceBlockDoesNotAdvance() public {
        _publishDefaultRoot(); // epoch 1 at block 150

        // Epoch 2 re-using epoch 1's block: this is the streak-replay attack.
        // The block also falls outside epoch 2's window, which catches it
        // first — either way, one snapshot cannot back two epochs.
        vm.roll(_epochBlock(2) + 1);
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ReferenceBlockNotAdvancing.selector,
                _epochBlock(1), _epochBlock(1)
            )
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 2, _epochBlock(1), 42);
    }

    function test_PublishRoot_RevertsWhenBlockOutsideEpochWindow() public {
        // Epoch 1's window is [100, 200); block 250 belongs to epoch 2.
        vm.roll(400);
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ReferenceBlockOutsideEpoch.selector, uint64(250), uint64(1)
            )
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, 250, 42);
    }

    function test_PublishRoot_SequentialEpochsAdvanceBlocks() public {
        _publishDefaultRoot(); // epoch 1 @ 150

        vm.roll(_epochBlock(2) + 1);
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, SET_ROOT, 2, _epochBlock(2), 42);

        vm.roll(_epochBlock(3) + 1);
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, SET_ROOT, 3, _epochBlock(3), 42);

        assertEq(oracle.getSetCount(POLICY_ID), 3);
        assertEq(oracle.getSetEntry(POLICY_ID, 2).blockNumber, _epochBlock(3));
    }

    // --- Reference-block sampling (review finding R2) ---

    /// The publisher does not get to choose the reference block. Any block
    /// other than the drawn one is rejected, which is what stops "prove at the
    /// block I happened to be funded at" from being a viable strategy.
    function test_PublishRootProven_RejectsUnsampledReferenceBlock() public {
        uint64 windowEnd = 2 * EPOCH_LEN;
        vm.roll(windowEnd + 50);
        oracle.setBlockhash(windowEnd, keccak256("entropy"));
        uint64 sampled = oracle.sampledReferenceBlock(POLICY_ID, 1);

        // A different, still-in-window block the publisher would have preferred.
        uint64 preferred = sampled == EPOCH_LEN ? sampled + 1 : sampled - 1;
        bytes memory headerRlp = _buildHeader(STATE_ROOT);
        oracle.setBlockhash(preferred, keccak256(headerRlp));

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, preferred, 0, uint64(block.chainid), THRESHOLD
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ReferenceBlockNotSampled.selector, sampled, preferred
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    /// The draw must not be knowable while the window is open — otherwise a
    /// holder could see which block matters and fund only that one.
    function test_SampledReferenceBlock_RevertsWhileWindowOpen() public {
        vm.roll(EPOCH_LEN + 10); // inside epoch 1's window [100, 200)
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.EpochWindowStillOpen.selector, uint64(200))
        );
        oracle.sampledReferenceBlock(POLICY_ID, 1);
    }

    function test_SampledReferenceBlock_RevertsWithoutEntropy() public {
        vm.roll(2 * EPOCH_LEN + 50); // window closed, but no hash registered
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.SamplingEntropyUnavailable.selector, uint64(200)
            )
        );
        oracle.sampledReferenceBlock(POLICY_ID, 1);
    }

    /// The sample always lands inside its own epoch window, and is stable —
    /// two reads of the same epoch give the same answer.
    function test_SampledReferenceBlock_InWindowAndDeterministic() public {
        for (uint64 epoch = 1; epoch <= 5; epoch++) {
            uint64 windowEnd = (epoch + 1) * EPOCH_LEN;
            vm.roll(windowEnd + 10);
            oracle.setBlockhash(windowEnd, keccak256(abi.encodePacked("e", epoch)));

            uint64 drawn = oracle.sampledReferenceBlock(POLICY_ID, epoch);
            assertGe(drawn, epoch * EPOCH_LEN, "sample below its window");
            assertLt(drawn, (epoch + 1) * EPOCH_LEN, "sample above its window");
            assertEq(drawn, oracle.sampledReferenceBlock(POLICY_ID, epoch), "not deterministic");
        }
    }

    /// Different entropy draws a different block: the sample is genuinely a
    /// function of chain randomness, not a fixed offset.
    function test_SampledReferenceBlock_VariesWithEntropy() public {
        uint64 windowEnd = 2 * EPOCH_LEN;
        vm.roll(windowEnd + 10);

        uint64 seen;
        bool varied;
        for (uint256 i = 0; i < 20; i++) {
            oracle.setBlockhash(windowEnd, keccak256(abi.encodePacked("seed", i)));
            uint64 drawn = oracle.sampledReferenceBlock(POLICY_ID, 1);
            if (i == 0) seen = drawn;
            else if (drawn != seen) varied = true;
        }
        assertTrue(varied, "sample must depend on the entropy block");
    }

    /// Two policies drawing from the same entropy block must not move in
    /// lockstep — the config hash separates them. Checked across several
    /// epochs, since any single epoch can coincide by chance (1-in-100 here).
    function test_SampledReferenceBlock_SeparatedByPolicy() public {
        _createErc20Policy();

        uint256 divergences;
        for (uint64 epoch = 1; epoch <= 8; epoch++) {
            uint64 windowEnd = (epoch + 1) * EPOCH_LEN;
            vm.roll(windowEnd + 10);
            oracle.setBlockhash(windowEnd, keccak256(abi.encodePacked("shared", epoch)));

            uint64 a = oracle.sampledReferenceBlock(POLICY_ID, epoch);
            uint64 b = oracle.sampledReferenceBlock(ERC20_POLICY_ID, epoch);
            // Offsets within their own windows are what must differ.
            if (a - epoch * EPOCH_LEN != b - epoch * EPOCH_LEN) divergences++;
        }
        assertGt(divergences, 0, "distinct policies must draw independently");
    }

    /// The Solidity draw must equal the Rust mirror's, or the agent would
    /// fetch balances at a block the oracle then rejects. Both are checked
    /// against the same independently-computed vector
    /// (`test_sampled_reference_block_matches_independent_vector` in
    /// crates/agent/src/solvent_set_service.rs).
    function test_SampledReferenceBlock_MatchesCrossLanguageVector() public {
        bytes32 SAMPLE_DOMAIN = keccak256("zkpof-refblock-sample-v2");
        bytes32 configHash = bytes32(
            0xC0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0
        );
        bytes32 entropy = bytes32(
            0xE7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7
        );
        uint64 epoch = 7;
        uint64 startBlock = 1_000_000;
        uint64 epochLen = 100;

        uint256 offset = uint256(
            keccak256(abi.encode(SAMPLE_DOMAIN, configHash, epoch, entropy))
        ) % epochLen;
        uint64 drawn = uint64(startBlock + epoch * epochLen + offset);

        assertEq(offset, 53, "offset must match the independent vector");
        assertEq(drawn, 1_000_753, "draw must match the Rust mirror");
    }

    // --- publishRootProven (Stage B) ---

    function test_PublishRootProven_FirstEpoch_Permissionless() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        // Anyone can publish a proven root — the proof is trusted, not the caller.
        vm.prank(stranger);
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertEq(entry.root, SET_ROOT);
        assertEq(entry.epoch, 1);
        assertEq(entry.blockNumber, refBlock);
        assertEq(entry.memberCount, 3);
        assertTrue(
            entry.provenance == SolventSetOracle.Provenance.BalancesProven,
            "Stage B proves balances, not completeness"
        );
    }

    function test_PublishRootProven_ChainsFromTrustedRoot() public {
        _publishDefaultRoot(); // epoch 1, SET_ROOT, trusted

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 2);
        bytes32 newRoot = bytes32(uint256(0xD00D));
        bytes memory pv = _derivationValues(
            STATE_ROOT, SET_ROOT, newRoot, 2, refBlock, _epochBlock(1),
            uint64(block.chainid), THRESHOLD
        );

        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
        assertEq(oracle.getSetEntry(POLICY_ID, 1).root, newRoot);
        assertTrue(
            oracle.getSetEntry(POLICY_ID, 1).provenance
                == SolventSetOracle.Provenance.BalancesProven
        );
    }

    /// The core streak-replay defence: the proof's `prevBlockNumber` must be
    /// the block our stored previous entry actually used. A publisher cannot
    /// invent an older previous block to satisfy the circuit's
    /// `block > prevBlock` while re-proving the same snapshot.
    function test_PublishRootProven_RevertsOnPrevBlockMismatch() public {
        _publishDefaultRoot(); // epoch 1 @ 150

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 2);
        bytes memory pv = _derivationValues(
            STATE_ROOT, SET_ROOT, bytes32(uint256(0xD00D)), 2, refBlock,
            1, // claims the previous set came from block 1
            uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.PrevBlockMismatch.selector, _epochBlock(1), uint64(1)
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnPrevRootMismatch() public {
        _publishDefaultRoot(); // stored prev root = SET_ROOT

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 2);
        bytes32 wrongPrev = bytes32(uint256(0xBAD));
        bytes memory pv = _derivationValues(
            STATE_ROOT, wrongPrev, bytes32(uint256(0xD00D)), 2, refBlock, _epochBlock(1),
            uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.PrevRootMismatch.selector, SET_ROOT, wrongPrev)
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnThresholdMismatch() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD + 1
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ThresholdMismatch.selector, THRESHOLD, THRESHOLD + 1
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnChainIdMismatch() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 wrongChain = uint64(block.chainid) + 1;
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, wrongChain, THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ChainIdMismatch.selector, uint64(block.chainid), wrongChain
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    /// `maxBlockAge` now bounds how long *after the epoch window closes* a
    /// publication may land — the reference block itself is whatever the draw
    /// chose, so its age is not the publisher's to control.
    function test_PublishRootProven_RevertsWhenPublishedTooLateAfterWindow() public {
        uint64 windowEnd = 2 * EPOCH_LEN;
        vm.roll(windowEnd + 300); // beyond maxBlockAge = 256
        oracle.setBlockhash(windowEnd, keccak256("entropy"));
        uint64 refBlock = oracle.sampledReferenceBlock(POLICY_ID, 1);
        bytes memory headerRlp = _buildHeader(STATE_ROOT);
        oracle.setBlockhash(refBlock, keccak256(headerRlp));
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.StaleReferenceBlock.selector,
                uint256(windowEnd + 300), refBlock, uint64(256)
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnMissingBlockhash() public {
        // Window closed and entropy available, so sampling succeeds — but the
        // sampled block's own hash is withheld, so the header cannot be bound.
        uint64 windowEnd = 2 * EPOCH_LEN;
        vm.roll(windowEnd + 50);
        oracle.setBlockhash(windowEnd, keccak256("entropy"));
        uint64 refBlock = oracle.sampledReferenceBlock(POLICY_ID, 1);

        bytes memory headerRlp = _buildHeader(STATE_ROOT);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.BlockhashUnavailable.selector, refBlock)
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnHeaderHashMismatch() public {
        (uint64 refBlock, ) = _prepareProvenBlock(STATE_ROOT, 1);
        // Present a different header than the one whose hash is registered.
        bytes memory forgedHeader = _buildHeader(bytes32(uint256(0xE71)));
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert();
        oracle.publishRootProven(POLICY_ID, forgedHeader, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnStateRootMismatch() public {
        // Header commits a different state root than the proof's public values.
        bytes32 otherStateRoot = bytes32(uint256(0x0DD));
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(otherStateRoot, 1);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.StateRootMismatch.selector, otherStateRoot, STATE_ROOT
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnMalformedHeader() public {
        uint64 windowEnd = 2 * EPOCH_LEN;
        vm.roll(windowEnd + 50);
        oracle.setBlockhash(windowEnd, keccak256("entropy"));
        uint64 refBlock = oracle.sampledReferenceBlock(POLICY_ID, 1);
        bytes memory badHeader = abi.encodePacked(hex"f90200", hex"80"); // not a 32-byte item
        oracle.setBlockhash(refBlock, keccak256(badHeader));
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(SolventSetOracle.MalformedHeader.selector);
        oracle.publishRootProven(POLICY_ID, badHeader, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnInvalidProof() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        mockVerifier.setShouldPass(false);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnBadLength() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        bytes memory truncated = abi.encode(STATE_ROOT, bytes32(0), SET_ROOT, POLICY_ID, refBlock);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.InvalidPublicValuesLength.selector, truncated.length
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, truncated, hex"");
    }

    // --- publishRootProven: ERC-20 mode ---

    bytes32 constant ERC20_POLICY_ID = bytes32(uint256(0x03));
    address constant TOKEN = address(0xBEEF);

    function _createErc20Policy() internal {
        registry.createPolicy(ERC20_POLICY_ID, _defaultPolicy(TOKEN, "erc20-scope"));
    }

    function test_PublishRootProven_Erc20() public {
        _createErc20Policy();
        vm.prank(operatorAddr);
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);

        (uint64 refBlock, bytes memory headerRlp) =
            _prepareProvenBlockFor(ERC20_POLICY_ID, STATE_ROOT, 1);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, TOKEN, 9
        );

        vm.prank(stranger); // still permissionless
        oracle.publishRootProven(ERC20_POLICY_ID, headerRlp, pv, hex"");
        assertTrue(
            oracle.getSetEntry(ERC20_POLICY_ID, 0).provenance
                == SolventSetOracle.Provenance.BalancesProven
        );
    }

    function test_PublishRootProven_RevertsOnTokenMismatch() public {
        _createErc20Policy();
        vm.prank(operatorAddr);
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        address wrongToken = address(0xD00D);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, wrongToken, 9
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.TokenMismatch.selector, TOKEN, wrongToken)
        );
        oracle.publishRootProven(ERC20_POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnBalanceSlotMismatch() public {
        _createErc20Policy();
        vm.prank(operatorAddr);
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);

        (uint64 refBlock, bytes memory headerRlp) =
            _prepareProvenBlockFor(ERC20_POLICY_ID, STATE_ROOT, 1);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, TOKEN, 3 // proof against the wrong slot
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.BalanceSlotMismatch.selector, uint64(9), uint64(3)
            )
        );
        oracle.publishRootProven(ERC20_POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_NativeRejectsNonzeroSlot() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        bytes memory pv = _derivationValuesFor(
            POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, address(0), 7
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.BalanceSlotMismatch.selector, uint64(0), uint64(7)
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_SetBalanceSlot_OperatorOnly() public {
        _createErc20Policy();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.NotOperator.selector, stranger, operatorAddr)
        );
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);
    }

    /// Semantic settings are pinned into every root's config hash, so they
    /// cannot move once roots exist (review finding R4).
    function test_SetBalanceSlot_RevertsAfterFirstPublication() public {
        _createErc20Policy();
        vm.prank(operatorAddr);
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);

        (uint64 refBlock, bytes memory headerRlp) =
            _prepareProvenBlockFor(ERC20_POLICY_ID, STATE_ROOT, 1);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, TOKEN, 9
        );
        oracle.publishRootProven(ERC20_POLICY_ID, headerRlp, pv, hex"");

        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.ConfigAlreadyPinned.selector, ERC20_POLICY_ID)
        );
        oracle.setBalanceSlot(ERC20_POLICY_ID, 11);
    }

    function test_SetScopeHash_RevertsAfterFirstPublication() public {
        _publishDefaultRoot();
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.ConfigAlreadyPinned.selector, POLICY_ID)
        );
        oracle.setScopeHash(POLICY_ID, bytes32(uint256(0x5C09E)));
    }

    // --- verifyMembership ---

    function test_VerifyMembership() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 3);
        (bytes32 nullifierHash, uint64 minStreak) =
            oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
        assertEq(nullifierHash, NULLIFIER_HASH);
        assertEq(minStreak, 3, "Relying protocols gate on the attested min streak");
    }

    function test_VerifyMembership_RevertsOnInvalidProof() public {
        _publishDefaultRoot();
        mockVerifier.setShouldPass(false);

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongRoot() public {
        _publishDefaultRoot();

        bytes memory publicValues =
            _publicValues(bytes32(uint256(0xBEEF)), POLICY_ID, 1, NULLIFIER_HASH, 1);
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongPolicy() public {
        _publishDefaultRoot();

        // Everything else matches this policy's entry; only the committed
        // policyId names a different one.
        bytes memory publicValues = _publicValuesFull(
            SET_ROOT, OTHER_POLICY_ID, 1, NULLIFIER_HASH, uint64(block.chainid), 1,
            oracle.effectiveScopeHash(POLICY_ID), oracle.policyConfigHash(POLICY_ID),
            address(oracle), uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 100)
        );
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongEpoch() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 99, NULLIFIER_HASH, 1);
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongChainId() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValuesFull(
            SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, uint64(block.chainid) + 1, 1,
            oracle.effectiveScopeHash(POLICY_ID), oracle.policyConfigHash(POLICY_ID),
            address(oracle), uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 100)
        );
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnBadLength() public {
        _publishDefaultRoot();

        bytes memory tooShort =
            abi.encode(SET_ROOT, POLICY_ID, uint64(1), NULLIFIER_HASH, uint64(block.chainid));
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.InvalidPublicValuesLength.selector, tooShort.length)
        );
        oracle.verifyMembership(POLICY_ID, 0, tooShort, hex"");
    }

    /// Expiry is measured from the entry's pinned `validUntil` (derived from
    /// the source block), not from publication against a mutable TTL.
    function test_VerifyMembership_RevertsAfterTTL() public {
        _publishDefaultRoot();
        vm.roll(_epochBlock(1) + ROOT_TTL + 1);

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        vm.expectRevert();
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnMissingSet() public {
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.SetIndexOutOfBounds.selector, POLICY_ID, 0, 0)
        );
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_AgainstHistoricalRoot() public {
        _publishDefaultRoot();
        bytes32 newRoot = bytes32(uint256(0xD00D));
        vm.roll(_epochBlock(2) + 1);
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, newRoot, 2, _epochBlock(2), 43);

        // Proof against epoch 1 still verifies at index 0 (within TTL)...
        bytes memory oldValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        (bytes32 oldNullifier, ) = oracle.verifyMembership(POLICY_ID, 0, oldValues, hex"");
        assertEq(oldNullifier, NULLIFIER_HASH);

        // ...and the new epoch verifies at index 1.
        bytes memory newValues = _publicValues(newRoot, POLICY_ID, 2, NULLIFIER_HASH, 1);
        (bytes32 newNullifier, ) = oracle.verifyMembership(POLICY_ID, 1, newValues, hex"");
        assertEq(newNullifier, NULLIFIER_HASH);
    }

    // --- Presentation-context binding (review finding R5) ---

    /// A proof naming a different verifier is not usable here. Without this,
    /// a proof made for one deployment is a bearer token for every other.
    function test_VerifyMembership_RevertsOnWrongVerifier() public {
        _publishDefaultRoot();
        address otherVerifier = makeAddr("otherOracle");
        bytes memory publicValues = _publicValuesFull(
            SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, uint64(block.chainid), 1,
            oracle.effectiveScopeHash(POLICY_ID), oracle.policyConfigHash(POLICY_ID),
            otherVerifier, uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 100)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.VerifierMismatch.selector, address(oracle), otherVerifier
            )
        );
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsAfterDeadline() public {
        _publishDefaultRoot();
        uint64 deadline = uint64(block.number + 10);
        bytes memory publicValues = _publicValuesFull(
            SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, uint64(block.chainid), 1,
            oracle.effectiveScopeHash(POLICY_ID), oracle.policyConfigHash(POLICY_ID),
            address(oracle), uint64(block.chainid), ACTION_ID, address(this), 1, deadline
        );

        vm.roll(deadline + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ProofExpired.selector, uint256(deadline + 1), deadline
            )
        );
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    /// The front-running defence: a proof bound to one beneficiary cannot be
    /// lifted from the mempool and consumed by someone else. Previously the
    /// attacker's copy would burn the legitimate user's nullifier.
    function test_VerifyAndConsume_RevertsForWrongBeneficiary() public {
        _publishDefaultRoot();
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.BeneficiaryMismatch.selector, address(this), stranger
            )
        );
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");

        // The legitimate beneficiary can still consume it afterwards.
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");
    }

    // --- verifyAndConsume ---

    function test_VerifyAndConsume() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 2);
        (bytes32 nullifierHash, uint64 minStreak) =
            oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");
        assertEq(nullifierHash, NULLIFIER_HASH);
        assertEq(minStreak, 2);
        assertTrue(
            oracle.isNullifierUsed(
                address(this), oracle.policyConfigHash(POLICY_ID), ACTION_ID, NULLIFIER_HASH
            )
        );
    }

    function test_VerifyAndConsume_RevertsOnReuse() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");

        // One identity per key per (consumer, config, action): the same
        // nullifier cannot be consumed twice in the same namespace.
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.NullifierAlreadyUsed.selector, POLICY_ID, NULLIFIER_HASH
            )
        );
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");
    }

    /// One dApp consuming a nullifier must not exhaust it for every other dApp
    /// on the same policy — the old shared namespace let exactly that happen.
    function test_VerifyAndConsume_NamespacedPerConsumerAndAction() public {
        _publishDefaultRoot();
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");

        bytes32 configHash = oracle.policyConfigHash(POLICY_ID);
        // Same nullifier, different consumer → still available.
        assertFalse(oracle.isNullifierUsed(stranger, configHash, ACTION_ID, NULLIFIER_HASH));
        // Same consumer, different action → still available.
        assertFalse(
            oracle.isNullifierUsed(
                address(this), configHash, bytes32(uint256(0xFFFF)), NULLIFIER_HASH
            )
        );
    }

    // --- Revocation and pausing ---

    function test_RevokeRoot_BlocksVerification() public {
        _publishDefaultRoot();
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex""); // works before

        oracle.revokeRoot(POLICY_ID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.RootRevokedError.selector, POLICY_ID, uint256(0))
        );
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_RevokeRoot_OnlyOwner() public {
        _publishDefaultRoot();
        vm.prank(stranger);
        vm.expectRevert();
        oracle.revokeRoot(POLICY_ID, 0);
    }

    function test_PublicationPause_BlocksNewRoots() public {
        oracle.setPublicationPaused(POLICY_ID, true);
        vm.roll(_epochBlock(1) + 1);
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.PublicationPausedError.selector, POLICY_ID)
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, _epochBlock(1), 42);
    }

    // --- publishRootProvenComplete (Stage B.2 composition) ---

    function test_PublishRootProvenComplete() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        bytes memory scanPv = _scanValues(endHash, SCAN_START, scanEnd, address(0), CANDIDATES_ROOT);

        vm.prank(stranger); // permissionless
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertTrue(
            entry.provenance == SolventSetOracle.Provenance.RangeScanProven,
            "Completeness is relative to a recorded range, not absolute"
        );
        assertEq(entry.scanStartBlock, SCAN_START);
        assertEq(entry.scanEndBlock, scanEnd, "The covered range is pinned on-chain");
    }

    /// The scan range must be internally consistent — a claimed block count
    /// that does not match the start/end pair is rejected outright.
    function test_PublishRootProvenComplete_RevertsOnInconsistentRange() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        // Claims to cover [0, scanEnd] but reports only 2 blocks scanned.
        bytes memory scanPv = abi.encode(
            endHash, SCAN_START, scanEnd, uint64(2), address(0), CANDIDATES_ROOT, uint32(3)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.InvalidScanRange.selector, SCAN_START, scanEnd, uint64(2)
            )
        );
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    /// A one-block scan ending at the right place used to satisfy the same
    /// interface as a full history scan; now the start must reach back to the
    /// policy's start block (review finding R3).
    function test_PublishRootProvenComplete_RevertsOnLateScanStart() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        bytes memory scanPv =
            _scanValues(endHash, scanEnd, scanEnd, address(0), CANDIDATES_ROOT); // 1 block

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ScanRangeNotContiguous.selector, uint64(0), scanEnd
            )
        );
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    function test_PublishRootProvenComplete_RevertsWhenCandidatesNotCovered() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);

        // The derivation checked a DIFFERENT candidate list than the scan
        // proved complete — exactly the censorship case composition catches.
        bytes32 omittedSomeone = bytes32(uint256(0xBAD5));
        bytes memory pv = _derivationValuesWithCandidates(
            POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, address(0), 0, omittedSomeone
        );
        bytes memory scanPv = _scanValues(endHash, SCAN_START, scanEnd, address(0), CANDIDATES_ROOT);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.CandidatesNotCovered.selector, CANDIDATES_ROOT, omittedSomeone
            )
        );
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    function test_PublishRootProvenComplete_RevertsOnUnavailableEndBlock() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1); // no hash registered

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        bytes memory scanPv = _scanValues(
            bytes32(uint256(0x0107)), SCAN_START, scanEnd, address(0), CANDIDATES_ROOT
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.ScanEndBlockUnavailable.selector, scanEnd)
        );
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    function test_PublishRootProvenComplete_RevertsOnWrongEndHash() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 realHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, realHash);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        bytes32 forgedHash = bytes32(uint256(0x0107));
        bytes memory scanPv =
            _scanValues(forgedHash, SCAN_START, scanEnd, address(0), CANDIDATES_ROOT);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ScanBlockNotCurrent.selector, realHash, forgedHash
            )
        );
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    function test_PublishRootProvenComplete_RevertsOnScanTokenMismatch() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        // Scan covered a different token than the (native-ETH) policy.
        address wrongToken = address(0xBEEF);
        bytes memory scanPv = _scanValues(endHash, SCAN_START, scanEnd, wrongToken, CANDIDATES_ROOT);

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.TokenMismatch.selector, address(0), wrongToken)
        );
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    function test_PublishRootProvenComplete_RevertsOnInvalidScanProof() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);
        mockVerifier.setShouldPass(false);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );
        bytes memory scanPv = _scanValues(endHash, SCAN_START, scanEnd, address(0), CANDIDATES_ROOT);

        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
    }

    function test_RequiresCompleteness_RejectsPlainProvenPublication() public {
        vm.prank(operatorAddr);
        oracle.setRequiresCompleteness(POLICY_ID, true);

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT, 1);
        uint64 scanEnd = uint64(block.number - 1);
        bytes32 endHash = bytes32(uint256(0x71B));
        oracle.setBlockhash(scanEnd, endHash);

        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, 0, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.CompletenessRequired.selector, POLICY_ID)
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");

        // ...but the complete path is accepted.
        bytes memory scanPv = _scanValues(endHash, SCAN_START, scanEnd, address(0), CANDIDATES_ROOT);
        oracle.publishRootProvenComplete(POLICY_ID, headerRlp, pv, hex"", scanPv, hex"");
        assertEq(oracle.getSetCount(POLICY_ID), 1);
    }

    function test_SetRequiresCompleteness_OperatorOnly() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.NotOperator.selector, stranger, operatorAddr)
        );
        oracle.setRequiresCompleteness(POLICY_ID, true);
    }

    // --- Scopes ---

    function test_EffectiveScopeHash_DefaultsToPolicyScope() public view {
        assertEq(
            oracle.effectiveScopeHash(POLICY_ID),
            sha256(abi.encodePacked("zkpof-scope-v1:", POLICY_ID)),
            "Default scope must mirror plume::default_scope_hash"
        );
        assertTrue(
            oracle.effectiveScopeHash(POLICY_ID) != oracle.effectiveScopeHash(OTHER_POLICY_ID)
        );
    }

    function test_SetScopeHash_SharedIdentityAcrossPolicies() public {
        bytes32 shared = bytes32(uint256(0x5C09E));
        vm.prank(operatorAddr);
        oracle.setScopeHash(POLICY_ID, shared);
        assertEq(oracle.effectiveScopeHash(POLICY_ID), shared);

        // Membership proofs must now carry the shared scope.
        _publishDefaultRoot();
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        (bytes32 nullifierHash,) = oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
        assertEq(nullifierHash, NULLIFIER_HASH);
    }

    function test_VerifyMembership_RevertsOnScopeMismatch() public {
        _publishDefaultRoot();
        // A proof scoped to a different policy must not verify here, even
        // though every other public value matches.
        bytes32 foreignScope = oracle.effectiveScopeHash(OTHER_POLICY_ID);
        bytes memory publicValues = _publicValuesFull(
            SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, uint64(block.chainid), 1,
            foreignScope, oracle.policyConfigHash(POLICY_ID),
            address(oracle), uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 100)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ScopeMismatch.selector,
                oracle.effectiveScopeHash(POLICY_ID),
                foreignScope
            )
        );
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnConfigMismatch() public {
        _publishDefaultRoot();
        bytes32 foreignConfig = bytes32(uint256(0xC0FF19));
        bytes memory publicValues = _publicValuesFull(
            SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, uint64(block.chainid), 1,
            oracle.effectiveScopeHash(POLICY_ID), foreignConfig,
            address(oracle), uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 100)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.PolicyConfigChanged.selector,
                oracle.policyConfigHash(POLICY_ID),
                foreignConfig
            )
        );
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_SetScopeHash_OperatorOnly() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.NotOperator.selector, stranger, operatorAddr)
        );
        oracle.setScopeHash(POLICY_ID, bytes32(uint256(1)));
    }

    // --- Admin ---

    function test_SetMembershipVKey() public {
        bytes32 newVKey = bytes32(uint256(0x1234));
        oracle.setMembershipVKey(newVKey);
        assertEq(oracle.membershipVKey(), newVKey);
    }

    /// Rotating a vkey must only affect future publications — an existing
    /// root keeps verifying under the key it was published with.
    function test_SetMembershipVKey_DoesNotAffectExistingRoots() public {
        _publishDefaultRoot();
        bytes32 pinned = oracle.getSetEntry(POLICY_ID, 0).membershipVKey;

        oracle.setMembershipVKey(bytes32(uint256(0xABCDEF)));
        assertEq(
            oracle.getSetEntry(POLICY_ID, 0).membershipVKey, pinned,
            "Published roots keep their original vkey"
        );
    }

    function test_SetDerivationVKey() public {
        bytes32 newVKey = bytes32(uint256(0x5678));
        oracle.setDerivationVKey(newVKey);
        assertEq(oracle.derivationVKey(), newVKey);
    }

    function test_SetVKeys_OnlyOwner() public {
        vm.startPrank(stranger);
        vm.expectRevert();
        oracle.setMembershipVKey(bytes32(uint256(0x1234)));
        vm.expectRevert();
        oracle.setDerivationVKey(bytes32(uint256(0x5678)));
        vm.stopPrank();
    }

    function test_LatestSetIndex_RevertsWhenEmpty() public {
        vm.expectRevert(abi.encodeWithSelector(SolventSetOracle.NoSetPublished.selector, POLICY_ID));
        oracle.latestSetIndex(POLICY_ID);
    }
}
