// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract PolicyRegistryTest is Test {
    PolicyRegistry registry;
    address owner;
    address operator;
    address unauthorized;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));

    function setUp() public {
        owner = address(this);
        operator = makeAddr("operator");
        unauthorized = makeAddr("unauthorized");

        registry = new PolicyRegistry();
    }

    // --- Helper ---

    function _defaultPolicy() internal view returns (PolicyRegistry.Policy memory) {
        return PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: 1,
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operator,
            scope: "test-scope",
            trustedMode: true,
            active: true,
            startBlock: 0,
            version: 1
        });
    }

    // --- Create Policy Tests ---

    function test_createPolicy() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        assertTrue(registry.policyExists(POLICY_ID), "Policy should exist");

        PolicyRegistry.Policy memory stored = registry.getPolicy(POLICY_ID);
        assertEq(stored.thresholdWei, 1 ether);
        assertEq(stored.tokenAddress, address(0));
        assertEq(stored.chainId, 1);
        assertEq(stored.epochLengthBlocks, 100);
        assertEq(stored.maxBlockAge, 256);
        assertEq(stored.rootTTLBlocks, 1000);
        assertEq(stored.operator, operator);
        assertEq(stored.scope, "test-scope");
        assertTrue(stored.trustedMode);
        assertTrue(stored.active, "Policy should be active on creation");
    }

    function test_createPolicy_forcesActive() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        policy.active = false; // Try to create inactive
        registry.createPolicy(POLICY_ID, policy);

        PolicyRegistry.Policy memory stored = registry.getPolicy(POLICY_ID);
        assertTrue(stored.active, "Policy should be forced active on creation");
    }

    function test_createPolicy_emitsEvent() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();

        vm.expectEmit(true, true, false, false);
        emit PolicyRegistry.PolicyCreated(POLICY_ID, operator);
        registry.createPolicy(POLICY_ID, policy);
    }

    function test_createPolicy_reverts_duplicate() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyAlreadyExists.selector, POLICY_ID));
        registry.createPolicy(POLICY_ID, policy);
    }

    function test_createPolicy_reverts_zeroOperator() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        policy.operator = address(0);

        vm.expectRevert(PolicyRegistry.InvalidOperator.selector);
        registry.createPolicy(POLICY_ID, policy);
    }

    function test_createPolicy_reverts_maxBlockAgeTooHigh() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        policy.maxBlockAge = 257;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.MaxBlockAgeTooHigh.selector, uint64(257)));
        registry.createPolicy(POLICY_ID, policy);
    }

    function test_createPolicy_reverts_zeroEpochLength() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        policy.epochLengthBlocks = 0;

        vm.expectRevert(PolicyRegistry.ZeroEpochLength.selector);
        registry.createPolicy(POLICY_ID, policy);
    }

    function test_createPolicy_reverts_zeroRootTTL() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        policy.rootTTLBlocks = 0;

        vm.expectRevert(PolicyRegistry.ZeroRootTTL.selector);
        registry.createPolicy(POLICY_ID, policy);
    }

    function test_createPolicy_reverts_nonOwner() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();

        vm.prank(unauthorized);
        vm.expectRevert();
        registry.createPolicy(POLICY_ID, policy);
    }

    // --- Update Policy Tests ---

    function test_updatePolicy_byOwner() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        policy.thresholdWei = 2 ether;
        policy.trustedMode = false;
        registry.updatePolicy(POLICY_ID, policy);

        PolicyRegistry.Policy memory stored = registry.getPolicy(POLICY_ID);
        assertEq(stored.thresholdWei, 2 ether);
        assertFalse(stored.trustedMode);
    }

    /// The operator used to be able to rewrite the entire policy — including
    /// the threshold every published root attests to, and `active`, which let
    /// it reactivate a policy the owner had deactivated. Owner-only now
    /// (external review finding R4).
    function test_updatePolicy_operatorCannotRewritePolicy() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        policy.thresholdWei = 3 ether;
        vm.prank(operator);
        vm.expectRevert();
        registry.updatePolicy(POLICY_ID, policy);

        assertEq(registry.getPolicy(POLICY_ID).thresholdWei, 1 ether, "unchanged");
    }

    function test_updatePolicy_byOwnerBeforeFreeze() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        // Before any root exists the policy is still malleable.
        policy.thresholdWei = 3 ether;
        registry.updatePolicy(POLICY_ID, policy);

        PolicyRegistry.Policy memory stored = registry.getPolicy(POLICY_ID);
        assertEq(stored.thresholdWei, 3 ether);
    }

    function test_updatePolicy_revertsOnSemanticChangeAfterFreeze() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);
        registry.freezePolicy(POLICY_ID);

        policy.thresholdWei = 3 ether;
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyRegistry.SemanticsChangeRequiresVersionBump.selector, POLICY_ID
            )
        );
        registry.updatePolicy(POLICY_ID, policy);
    }

    function test_updatePolicy_allowsOperatorRotationAfterFreeze() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);
        registry.freezePolicy(POLICY_ID);

        address newOperator = makeAddr("newOperator");
        policy.operator = newOperator;
        registry.updatePolicy(POLICY_ID, policy);

        assertEq(registry.getPolicy(POLICY_ID).operator, newOperator);
    }

    function test_configHash_changesWithSemanticsAndVersion() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);
        bytes32 before = registry.configHash(POLICY_ID);

        // Rotating the operator does not change what a root *means*.
        policy.operator = makeAddr("rotated");
        assertEq(registry.configHashOf(policy), before, "operator is not semantics");

        // A threshold change does, and so does a version bump.
        policy.thresholdWei = 5 ether;
        assertTrue(registry.configHashOf(policy) != before);
        policy.thresholdWei = 1 ether;
        policy.version = 2;
        assertTrue(registry.configHashOf(policy) != before, "version is part of identity");
    }

    function test_updatePolicy_revalidatesFields() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        // updatePolicy used to skip these checks entirely, so a zero operator
        // or zero TTL could be installed after creation.
        policy.operator = address(0);
        vm.expectRevert(PolicyRegistry.InvalidOperator.selector);
        registry.updatePolicy(POLICY_ID, policy);

        policy = _defaultPolicy();
        policy.rootTTLBlocks = 0;
        vm.expectRevert(PolicyRegistry.ZeroRootTTL.selector);
        registry.updatePolicy(POLICY_ID, policy);
    }

    function test_updatePolicy_emitsEvent() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        vm.expectEmit(true, false, false, false);
        emit PolicyRegistry.PolicyUpdated(POLICY_ID);
        registry.updatePolicy(POLICY_ID, policy);
    }

    function test_updatePolicy_reverts_unauthorized() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        vm.prank(unauthorized);
        vm.expectRevert(); // OwnableUnauthorizedAccount — updates are owner-only
        registry.updatePolicy(POLICY_ID, policy);
    }

    function test_updatePolicy_reverts_nonexistent() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyNotFound.selector, POLICY_ID));
        registry.updatePolicy(POLICY_ID, policy);
    }

    function test_updatePolicy_reverts_maxBlockAgeTooHigh() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        policy.maxBlockAge = 300;
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.MaxBlockAgeTooHigh.selector, uint64(300)));
        registry.updatePolicy(POLICY_ID, policy);
    }

    // --- Deactivate Policy Tests ---

    function test_deactivatePolicy() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        registry.deactivatePolicy(POLICY_ID);

        PolicyRegistry.Policy memory stored = registry.getPolicy(POLICY_ID);
        assertFalse(stored.active, "Policy should be inactive after deactivation");
    }

    function test_deactivatePolicy_emitsEvent() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        vm.expectEmit(true, false, false, false);
        emit PolicyRegistry.PolicyDeactivated(POLICY_ID);
        registry.deactivatePolicy(POLICY_ID);
    }

    function test_deactivatePolicy_reverts_nonOwner() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        registry.createPolicy(POLICY_ID, policy);

        vm.prank(operator);
        vm.expectRevert();
        registry.deactivatePolicy(POLICY_ID);
    }

    function test_deactivatePolicy_reverts_nonexistent() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyNotFound.selector, POLICY_ID));
        registry.deactivatePolicy(POLICY_ID);
    }

    // --- Get Policy Tests ---

    function test_getPolicy_reverts_nonexistent() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyNotFound.selector, POLICY_ID));
        registry.getPolicy(POLICY_ID);
    }

    // --- ERC-20 Policy ---

    function test_createPolicy_erc20() public {
        PolicyRegistry.Policy memory policy = _defaultPolicy();
        policy.tokenAddress = makeAddr("usdc");
        registry.createPolicy(POLICY_ID, policy);

        PolicyRegistry.Policy memory stored = registry.getPolicy(POLICY_ID);
        assertEq(stored.tokenAddress, makeAddr("usdc"));
    }
}
