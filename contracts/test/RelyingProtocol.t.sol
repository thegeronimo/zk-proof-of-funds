// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolvencyRootOracle} from "../src/SolvencyRootOracle.sol";
import {MerkleVerifier} from "../src/MerkleVerifier.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";
import {RelyingProtocol} from "../src/RelyingProtocol.sol";

/// @title RelyingProtocolTest
/// @notice Tests for the RelyingProtocol example dApp that gates behind isMemberSolvent().
contract RelyingProtocolTest is Test {
    PolicyRegistry registry;
    SolvencyRootOracle oracle;
    MockSP1Verifier mockVerifier;
    RelyingProtocol dapp;

    uint256 operatorKey;
    address operatorAddr;
    address user;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));
    bytes32 constant MEMBER_ID_0 = bytes32(uint256(0xA0));
    bytes32 constant MEMBER_ID_1 = bytes32(uint256(0xB0));
    bytes32 constant MEMBER_ID_2 = bytes32(uint256(0xC0));

    // EIP-712 type hash (must match SolvencyRootOracle)
    bytes32 private constant TYPEHASH = keccak256(
        "SolvencyRootUpdate(bytes32 policyId,bytes32 root,uint64 epoch,uint64 blockNumber,uint32 memberCount,uint64 chainId)"
    );

    function setUp() public {
        operatorKey = 0xA11CE;
        operatorAddr = vm.addr(operatorKey);
        user = makeAddr("user");

        // Deploy contracts
        registry = new PolicyRegistry();
        mockVerifier = new MockSP1Verifier();
        oracle = new SolvencyRootOracle(
            address(registry),
            address(mockVerifier),
            bytes32(0)
        );

        // Create a trusted mode policy
        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "test-scope",
            trustedMode: true,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(POLICY_ID, policy);

        // Deploy the relying protocol
        dapp = new RelyingProtocol(address(oracle), POLICY_ID);
    }

    // --- Helpers ---

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 domainTypeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        return keccak256(abi.encode(
            domainTypeHash,
            keccak256("SolvencyRootOracle"),
            keccak256("1"),
            block.chainid,
            address(oracle)
        ));
    }

    function _signUpdate(
        bytes32 _policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) internal view returns (bytes memory signature) {
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH,
            _policyId,
            root,
            uint256(epoch),
            uint256(blockNumber),
            uint256(memberCount),
            uint256(block.chainid)
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _buildTwoLeafTree(uint64 epoch)
        internal
        pure
        returns (bytes32 root, bytes32 leaf0, bytes32 leaf1, bytes32[] memory proof0)
    {
        leaf0 = MerkleVerifier.computeLeaf(MEMBER_ID_0, 1, epoch, POLICY_ID);
        leaf1 = MerkleVerifier.computeLeaf(MEMBER_ID_1, 1, epoch, POLICY_ID);
        root = sha256(abi.encodePacked(leaf0, leaf1));

        proof0 = new bytes32[](1);
        proof0[0] = leaf1;
    }

    /// @dev Build a 3-member tree (all solvent) and submit the root.
    ///      Tree structure:
    ///        Level 0: [leaf0, leaf1, leaf2, leaf2]  (leaf2 duplicated for even count)
    ///        Level 1: [H(leaf0,leaf1), H(leaf2,leaf2)]
    ///        Level 2: root = H(level1[0], level1[1])
    function _buildThreeLeafTree(uint64 epoch)
        internal
        pure
        returns (
            bytes32 root,
            bytes32 leaf0,
            bytes32 leaf1,
            bytes32 leaf2
        )
    {
        leaf0 = MerkleVerifier.computeLeaf(MEMBER_ID_0, 1, epoch, POLICY_ID);
        leaf1 = MerkleVerifier.computeLeaf(MEMBER_ID_1, 1, epoch, POLICY_ID);
        leaf2 = MerkleVerifier.computeLeaf(MEMBER_ID_2, 1, epoch, POLICY_ID);

        bytes32 h01 = sha256(abi.encodePacked(leaf0, leaf1));
        bytes32 h22 = sha256(abi.encodePacked(leaf2, leaf2)); // odd-level duplication
        root = sha256(abi.encodePacked(h01, h22));
    }

    /// @dev Submit a root via updateRootTrusted.
    function _submitRoot(bytes32 root, uint64 epoch, uint64 blockNumber, uint32 memberCount) internal {
        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, memberCount);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, memberCount, sig);
    }

    // ========================================
    // Test Cases
    // ========================================

    function test_gatedAction_happyPath() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // User performs gated action with valid proof
        vm.prank(user);
        vm.expectEmit(true, false, false, true);
        emit RelyingProtocol.ActionPerformed(MEMBER_ID_0, epoch, user);

        dapp.performGatedAction(MEMBER_ID_0, epoch, proof0, 0, 0);
    }

    function test_gatedAction_reverts_invalidProof() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Wrong sibling hash
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = bytes32(uint256(0xDEADBEEF));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(RelyingProtocol.NotSolvent.selector, MEMBER_ID_0));
        dapp.performGatedAction(MEMBER_ID_0, epoch, badProof, 0, 0);
    }

    function test_gatedAction_reverts_expiredRoot() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Advance past rootTTLBlocks (1000)
        vm.roll(block.number + 1001);

        // The oracle will revert with RootExpired, which propagates through
        vm.prank(user);
        vm.expectRevert(); // RootExpired propagates from oracle
        dapp.performGatedAction(MEMBER_ID_0, epoch, proof0, 0, 0);
    }

    function test_gatedAction_reverts_insolventMember() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);

        // Build tree where member 0 is insolvent
        bytes32 leaf0 = MerkleVerifier.computeLeaf(MEMBER_ID_0, 0, epoch, POLICY_ID);
        bytes32 leaf1 = MerkleVerifier.computeLeaf(MEMBER_ID_1, 1, epoch, POLICY_ID);
        bytes32 root = sha256(abi.encodePacked(leaf0, leaf1));

        _submitRoot(root, epoch, blockNumber, 2);

        // Proof for member 0 (insolvent) at index 0
        bytes32[] memory proof0 = new bytes32[](1);
        proof0[0] = leaf1;

        // isMemberSolvent checks status=1, but the tree has status=0 → returns false → NotSolvent
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(RelyingProtocol.NotSolvent.selector, MEMBER_ID_0));
        dapp.performGatedAction(MEMBER_ID_0, epoch, proof0, 0, 0);
    }

    function test_checkSolvency_readOnly() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Valid proof → true
        bool solvent = dapp.checkSolvency(MEMBER_ID_0, epoch, proof0, 0, 0);
        assertTrue(solvent, "Valid proof should return true");

        // Invalid proof → false
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = bytes32(uint256(0xBAD));
        bool invalid = dapp.checkSolvency(MEMBER_ID_0, epoch, badProof, 0, 0);
        assertFalse(invalid, "Invalid proof should return false");
    }

    function test_gatedAction_multipleMembers() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root, bytes32 leaf0, bytes32 leaf1, bytes32 leaf2) = _buildThreeLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 3);

        // Proofs for each member in a 3-leaf (padded to 4) tree:
        // Level 0: [leaf0, leaf1, leaf2, leaf2]
        // Level 1: [H(leaf0,leaf1), H(leaf2,leaf2)]
        bytes32 h01 = sha256(abi.encodePacked(leaf0, leaf1));
        bytes32 h22 = sha256(abi.encodePacked(leaf2, leaf2));

        // Member 0 (index 0): siblings = [leaf1, h22]
        bytes32[] memory proof0 = new bytes32[](2);
        proof0[0] = leaf1;
        proof0[1] = h22;
        vm.prank(user);
        dapp.performGatedAction(MEMBER_ID_0, epoch, proof0, 0, 0);

        // Member 1 (index 1): siblings = [leaf0, h22]
        bytes32[] memory proof1 = new bytes32[](2);
        proof1[0] = leaf0;
        proof1[1] = h22;
        vm.prank(user);
        dapp.performGatedAction(MEMBER_ID_1, epoch, proof1, 1, 0);

        // Member 2 (index 2): siblings = [leaf2 (dup), h01]
        bytes32[] memory proof2 = new bytes32[](2);
        proof2[0] = leaf2;  // sibling at level 0 is itself (odd duplication)
        proof2[1] = h01;
        vm.prank(user);
        dapp.performGatedAction(MEMBER_ID_2, epoch, proof2, 2, 0);
    }

    function test_gatedAction_wrongPolicy() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Deploy a second dApp gating behind a different policy
        bytes32 otherPolicyId = bytes32(uint256(0x99));
        PolicyRegistry.Policy memory otherPolicy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "other-scope",
            trustedMode: true,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(otherPolicyId, otherPolicy);
        RelyingProtocol otherDapp = new RelyingProtocol(address(oracle), otherPolicyId);

        // The proof was for POLICY_ID, not otherPolicyId → no roots exist → RootIndexOutOfBounds
        vm.prank(user);
        vm.expectRevert(); // RootIndexOutOfBounds for otherPolicyId
        otherDapp.performGatedAction(MEMBER_ID_0, epoch, proof0, 0, 0);
    }
}
