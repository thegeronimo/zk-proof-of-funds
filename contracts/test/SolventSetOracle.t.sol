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
        bytes32 _derivationVKey
    ) SolventSetOracle(_policyRegistry, _sp1Verifier, _membershipVKey, _derivationVKey) {}

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
    uint64 constant ROOT_TTL = 1000;
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
            bytes32(0)  // placeholder derivation vkey
        );

        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: THRESHOLD,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: ROOT_TTL,
            operator: operatorAddr,
            scope: "test-scope",
            trustedMode: false,
            active: true
        });
        registry.createPolicy(POLICY_ID, policy);
    }

    // --- Helpers ---

    /// @dev ABI-encode membership public values exactly as the SP1 program
    ///      commits them (crates/common/src/membership.rs::abi_encode).
    function _publicValues(
        bytes32 root,
        bytes32 policyId,
        uint64 epoch,
        bytes32 nullifierHash,
        uint64 minStreak
    ) internal view returns (bytes memory) {
        return abi.encode(root, policyId, epoch, nullifierHash, uint64(block.chainid), minStreak);
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
        uint64 chainId,
        uint256 thresholdWei
    ) internal pure returns (bytes memory) {
        return _derivationValuesFor(
            POLICY_ID, stateRoot, prevRoot, newRoot, epoch, blockNumber, chainId,
            thresholdWei, address(0), 0
        );
    }

    function _derivationValuesFor(
        bytes32 policyId,
        bytes32 stateRoot,
        bytes32 prevRoot,
        bytes32 newRoot,
        uint64 epoch,
        uint64 blockNumber,
        uint64 chainId,
        uint256 thresholdWei,
        address token,
        uint64 balanceSlot
    ) internal pure returns (bytes memory) {
        return abi.encode(
            stateRoot, prevRoot, newRoot, policyId, epoch, blockNumber, chainId,
            thresholdWei, uint32(3), uint32(5), token, balanceSlot,
            bytes32(uint256(0xCA4D)) // candidatesRoot (unchecked on-chain)
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
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, uint64(block.number), 42);
    }

    /// @dev Roll forward and prepare a provable reference block: header +
    ///      registered blockhash. Returns (refBlock, headerRlp).
    function _prepareProvenBlock(bytes32 stateRoot) internal returns (uint64, bytes memory) {
        vm.roll(1000);
        uint64 refBlock = 900;
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
        assertFalse(entry.proven, "Stage A publication is operator-trusted");
    }

    function test_PublishRoot_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit SolventSetOracle.SolventSetRootPublished(
            POLICY_ID, SET_ROOT, 1, block.number, 42, false, operatorAddr
        );
        _publishDefaultRoot();
    }

    function test_PublishRoot_RevertsForNonOperator() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.NotOperator.selector, stranger, operatorAddr)
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, uint64(block.number), 42);
    }

    function test_PublishRoot_RevertsForZeroRoot() public {
        vm.prank(operatorAddr);
        vm.expectRevert(SolventSetOracle.ZeroRoot.selector);
        oracle.publishRoot(POLICY_ID, bytes32(0), 1, uint64(block.number), 42);
    }

    function test_PublishRoot_RevertsForNonIncreasingEpoch() public {
        _publishDefaultRoot();

        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.EpochNotIncreasing.selector, uint64(1), uint64(1))
        );
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, uint64(block.number), 42);
    }

    function test_PublishRoot_RevertsForInactivePolicy() public {
        registry.deactivatePolicy(POLICY_ID);

        vm.prank(operatorAddr);
        vm.expectRevert(abi.encodeWithSelector(SolventSetOracle.PolicyNotActive.selector, POLICY_ID));
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, uint64(block.number), 42);
    }

    function test_PublishRoot_RevertsForUnknownPolicy() public {
        vm.prank(operatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyRegistry.PolicyNotFound.selector, OTHER_POLICY_ID)
        );
        oracle.publishRoot(OTHER_POLICY_ID, SET_ROOT, 1, uint64(block.number), 42);
    }

    // --- publishRootProven (Stage B) ---

    function test_PublishRootProven_FirstEpoch_Permissionless() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD
        );

        // Anyone can publish a proven root — the proof is trusted, not the caller.
        vm.prank(stranger);
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertEq(entry.root, SET_ROOT);
        assertEq(entry.epoch, 1);
        assertEq(entry.blockNumber, refBlock);
        assertEq(entry.memberCount, 3);
        assertTrue(entry.proven, "Stage B publication is proof-backed");
    }

    function test_PublishRootProven_ChainsFromTrustedRoot() public {
        _publishDefaultRoot(); // epoch 1, SET_ROOT, trusted

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes32 newRoot = bytes32(uint256(0xD00D));
        bytes memory pv = _derivationValues(
            STATE_ROOT, SET_ROOT, newRoot, 2, refBlock, uint64(block.chainid), THRESHOLD
        );

        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
        assertEq(oracle.getSetEntry(POLICY_ID, 1).root, newRoot);
        assertTrue(oracle.getSetEntry(POLICY_ID, 1).proven);
    }

    function test_PublishRootProven_RevertsOnPrevRootMismatch() public {
        _publishDefaultRoot(); // stored prev root = SET_ROOT

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes32 wrongPrev = bytes32(uint256(0xBAD));
        bytes memory pv = _derivationValues(
            STATE_ROOT, wrongPrev, bytes32(uint256(0xD00D)), 2, refBlock,
            uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.PrevRootMismatch.selector, SET_ROOT, wrongPrev)
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnThresholdMismatch() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD + 1
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ThresholdMismatch.selector, THRESHOLD, THRESHOLD + 1
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnChainIdMismatch() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        uint64 wrongChain = uint64(block.chainid) + 1;
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, wrongChain, THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.ChainIdMismatch.selector, uint64(block.chainid), wrongChain
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnStaleReferenceBlock() public {
        vm.roll(1000);
        uint64 staleBlock = 1000 - 257; // beyond maxBlockAge = 256
        bytes memory headerRlp = _buildHeader(STATE_ROOT);
        oracle.setBlockhash(staleBlock, keccak256(headerRlp));
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, staleBlock, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.StaleReferenceBlock.selector, uint256(1000), staleBlock, uint64(256)
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnMissingBlockhash() public {
        vm.roll(1000);
        uint64 refBlock = 900; // no blockhash registered in the harness
        bytes memory headerRlp = _buildHeader(STATE_ROOT);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.BlockhashUnavailable.selector, refBlock)
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnHeaderHashMismatch() public {
        (uint64 refBlock, ) = _prepareProvenBlock(STATE_ROOT);
        // Present a different header than the one whose hash is registered.
        bytes memory forgedHeader = _buildHeader(bytes32(uint256(0xE71)));
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert();
        oracle.publishRootProven(POLICY_ID, forgedHeader, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnStateRootMismatch() public {
        // Header commits a different state root than the proof's public values.
        bytes32 otherStateRoot = bytes32(uint256(0x0DD));
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(otherStateRoot);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.StateRootMismatch.selector, otherStateRoot, STATE_ROOT
            )
        );
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnMalformedHeader() public {
        vm.roll(1000);
        uint64 refBlock = 900;
        bytes memory badHeader = abi.encodePacked(hex"f90200", hex"80"); // not a 32-byte item
        oracle.setBlockhash(refBlock, keccak256(badHeader));
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(SolventSetOracle.MalformedHeader.selector);
        oracle.publishRootProven(POLICY_ID, badHeader, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnInvalidProof() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        mockVerifier.setShouldPass(false);
        bytes memory pv = _derivationValues(
            STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock, uint64(block.chainid), THRESHOLD
        );

        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.publishRootProven(POLICY_ID, headerRlp, pv, hex"");
    }

    function test_PublishRootProven_RevertsOnBadLength() public {
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
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
        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: THRESHOLD,
            tokenAddress: TOKEN,
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: ROOT_TTL,
            operator: operatorAddr,
            scope: "erc20-scope",
            trustedMode: false,
            active: true
        });
        registry.createPolicy(ERC20_POLICY_ID, policy);
    }

    function test_PublishRootProven_Erc20() public {
        _createErc20Policy();
        vm.prank(operatorAddr);
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock,
            uint64(block.chainid), THRESHOLD, TOKEN, 9
        );

        vm.prank(stranger); // still permissionless
        oracle.publishRootProven(ERC20_POLICY_ID, headerRlp, pv, hex"");
        assertTrue(oracle.getSetEntry(ERC20_POLICY_ID, 0).proven);
    }

    function test_PublishRootProven_RevertsOnTokenMismatch() public {
        _createErc20Policy();
        vm.prank(operatorAddr);
        oracle.setBalanceSlot(ERC20_POLICY_ID, 9);

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        address wrongToken = address(0xD00D);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock,
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

        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes memory pv = _derivationValuesFor(
            ERC20_POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock,
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
        (uint64 refBlock, bytes memory headerRlp) = _prepareProvenBlock(STATE_ROOT);
        bytes memory pv = _derivationValuesFor(
            POLICY_ID, STATE_ROOT, bytes32(0), SET_ROOT, 1, refBlock,
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

        bytes memory publicValues =
            _publicValues(SET_ROOT, OTHER_POLICY_ID, 1, NULLIFIER_HASH, 1);
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

        bytes memory publicValues = abi.encode(
            SET_ROOT, POLICY_ID, uint64(1), NULLIFIER_HASH, uint64(block.chainid + 1), uint64(1)
        );
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnBadLength() public {
        _publishDefaultRoot();

        bytes memory tooShort = abi.encode(SET_ROOT, POLICY_ID, uint64(1), NULLIFIER_HASH);
        vm.expectRevert(
            abi.encodeWithSelector(SolventSetOracle.InvalidPublicValuesLength.selector, tooShort.length)
        );
        oracle.verifyMembership(POLICY_ID, 0, tooShort, hex"");
    }

    function test_VerifyMembership_RevertsAfterTTL() public {
        _publishDefaultRoot();
        vm.roll(block.number + ROOT_TTL + 1);

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
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, newRoot, 2, uint64(block.number), 43);

        // Proof against epoch 1 still verifies at index 0 (within TTL)...
        bytes memory oldValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        (bytes32 oldNullifier, ) = oracle.verifyMembership(POLICY_ID, 0, oldValues, hex"");
        assertEq(oldNullifier, NULLIFIER_HASH);

        // ...and the new epoch verifies at index 1.
        bytes memory newValues = _publicValues(newRoot, POLICY_ID, 2, NULLIFIER_HASH, 1);
        (bytes32 newNullifier, ) = oracle.verifyMembership(POLICY_ID, 1, newValues, hex"");
        assertEq(newNullifier, NULLIFIER_HASH);
    }

    // --- verifyAndConsume ---

    function test_VerifyAndConsume() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 2);
        (bytes32 nullifierHash, uint64 minStreak) =
            oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");
        assertEq(nullifierHash, NULLIFIER_HASH);
        assertEq(minStreak, 2);
        assertTrue(oracle.isNullifierUsed(POLICY_ID, NULLIFIER_HASH));
    }

    function test_VerifyAndConsume_RevertsOnReuse() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");

        // One identity per key per policy: the same nullifier cannot be
        // consumed twice, even via a fresh (valid) proof.
        vm.expectRevert(
            abi.encodeWithSelector(
                SolventSetOracle.NullifierAlreadyUsed.selector, POLICY_ID, NULLIFIER_HASH
            )
        );
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyAndConsume_NamespacedPerPolicy() public {
        _publishDefaultRoot();
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH, 1);
        oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");

        // Consumption under one policy does not mark other policies.
        assertFalse(oracle.isNullifierUsed(OTHER_POLICY_ID, NULLIFIER_HASH));
    }

    // --- Admin ---

    function test_SetMembershipVKey() public {
        bytes32 newVKey = bytes32(uint256(0x1234));
        oracle.setMembershipVKey(newVKey);
        assertEq(oracle.membershipVKey(), newVKey);
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
