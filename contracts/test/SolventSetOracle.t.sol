// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolventSetOracle} from "../src/SolventSetOracle.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";

contract SolventSetOracleTest is Test {
    PolicyRegistry registry;
    SolventSetOracle oracle;
    MockSP1Verifier mockVerifier;

    address operatorAddr;
    address stranger;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));
    bytes32 constant OTHER_POLICY_ID = bytes32(uint256(0x02));
    bytes32 constant SET_ROOT = bytes32(uint256(0xABCD));
    bytes32 constant NULLIFIER_HASH = bytes32(uint256(0xFEED));
    uint64 constant ROOT_TTL = 1000;

    function setUp() public {
        operatorAddr = makeAddr("operator");
        stranger = makeAddr("stranger");

        registry = new PolicyRegistry();
        mockVerifier = new MockSP1Verifier();
        oracle = new SolventSetOracle(
            address(registry),
            address(mockVerifier),
            bytes32(0) // placeholder membership vkey
        );

        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
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
        bytes32 nullifierHash
    ) internal view returns (bytes memory) {
        return abi.encode(root, policyId, epoch, nullifierHash, uint64(block.chainid));
    }

    function _publishDefaultRoot() internal {
        vm.prank(operatorAddr);
        oracle.publishRoot(POLICY_ID, SET_ROOT, 1, uint64(block.number), 42);
    }

    // --- publishRoot ---

    function test_PublishRoot() public {
        _publishDefaultRoot();

        assertEq(oracle.getSetCount(POLICY_ID), 1);
        assertEq(oracle.latestSetIndex(POLICY_ID), 0);

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertEq(entry.root, SET_ROOT);
        assertEq(entry.epoch, 1);
        assertEq(entry.memberCount, 42);
        assertEq(entry.publishedAt, uint64(block.number));
    }

    function test_PublishRoot_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit SolventSetOracle.SolventSetRootPublished(POLICY_ID, SET_ROOT, 1, block.number, 42);
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

    // --- verifyMembership ---

    function test_VerifyMembership() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
        bytes32 nullifierHash = oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
        assertEq(nullifierHash, NULLIFIER_HASH);
    }

    function test_VerifyMembership_RevertsOnInvalidProof() public {
        _publishDefaultRoot();
        mockVerifier.setShouldPass(false);

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongRoot() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(bytes32(uint256(0xBEEF)), POLICY_ID, 1, NULLIFIER_HASH);
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongPolicy() public {
        _publishDefaultRoot();

        // Proof generated for a different policy id must not verify here,
        // even against the same root.
        bytes memory publicValues = _publicValues(SET_ROOT, OTHER_POLICY_ID, 1, NULLIFIER_HASH);
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongEpoch() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 99, NULLIFIER_HASH);
        vm.expectRevert(SolventSetOracle.PublicValuesMismatch.selector);
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnWrongChainId() public {
        _publishDefaultRoot();

        bytes memory publicValues =
            abi.encode(SET_ROOT, POLICY_ID, uint64(1), NULLIFIER_HASH, uint64(block.chainid + 1));
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

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
        vm.expectRevert();
        oracle.verifyMembership(POLICY_ID, 0, publicValues, hex"");
    }

    function test_VerifyMembership_RevertsOnMissingSet() public {
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
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
        bytes memory oldValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
        assertEq(oracle.verifyMembership(POLICY_ID, 0, oldValues, hex""), NULLIFIER_HASH);

        // ...and the new epoch verifies at index 1.
        bytes memory newValues = _publicValues(newRoot, POLICY_ID, 2, NULLIFIER_HASH);
        assertEq(oracle.verifyMembership(POLICY_ID, 1, newValues, hex""), NULLIFIER_HASH);
    }

    // --- verifyAndConsume ---

    function test_VerifyAndConsume() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
        bytes32 nullifierHash = oracle.verifyAndConsume(POLICY_ID, 0, publicValues, hex"");
        assertEq(nullifierHash, NULLIFIER_HASH);
        assertTrue(oracle.isNullifierUsed(POLICY_ID, NULLIFIER_HASH));
    }

    function test_VerifyAndConsume_RevertsOnReuse() public {
        _publishDefaultRoot();

        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
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
        bytes memory publicValues = _publicValues(SET_ROOT, POLICY_ID, 1, NULLIFIER_HASH);
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

    function test_SetMembershipVKey_OnlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert();
        oracle.setMembershipVKey(bytes32(uint256(0x1234)));
    }

    function test_LatestSetIndex_RevertsWhenEmpty() public {
        vm.expectRevert(abi.encodeWithSelector(SolventSetOracle.NoSetPublished.selector, POLICY_ID));
        oracle.latestSetIndex(POLICY_ID);
    }
}
