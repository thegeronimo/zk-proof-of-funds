// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolvencyRootOracle} from "../src/SolvencyRootOracle.sol";
import {MerkleVerifier} from "../src/MerkleVerifier.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";

contract SolvencyRootOracleTest is Test {
    PolicyRegistry registry;
    SolvencyRootOracle oracle;
    MockSP1Verifier mockVerifier;

    uint256 operatorKey;
    address operatorAddr;
    address relayer;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));
    bytes32 constant MEMBER_ID_0 = bytes32(uint256(0xA0));
    bytes32 constant MEMBER_ID_1 = bytes32(uint256(0xB0));

    // EIP-712 type hash (must match SolvencyRootOracle)
    bytes32 private constant TYPEHASH = keccak256(
        "SolvencyRootUpdate(bytes32 policyId,bytes32 root,uint64 epoch,uint64 blockNumber,uint32 memberCount,uint64 chainId)"
    );

    function setUp() public {
        // Generate operator key pair
        operatorKey = 0xA11CE;
        operatorAddr = vm.addr(operatorKey);
        relayer = makeAddr("relayer");

        // Deploy contracts
        registry = new PolicyRegistry();
        mockVerifier = new MockSP1Verifier();
        oracle = new SolvencyRootOracle(
            address(registry),
            address(mockVerifier),
            bytes32(0) // placeholder vkey
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
    }

    // --- Helpers ---

    /// @dev Build a 2-leaf solvency tree and return (root, leaves, proof for leaf0)
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

    /// @dev Compute the EIP-712 domain separator matching the oracle's domain.
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

    /// @dev Sign a SolvencyRootUpdate using EIP-712
    function _signUpdate(
        bytes32 policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) internal view returns (bytes memory signature) {
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH,
            policyId,
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

    // ========================================
    // updateRootTrusted Tests
    // ========================================

    function test_updateRootTrusted_happyPath() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        uint32 memberCount = 2;
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, memberCount);

        vm.expectEmit(true, false, false, true);
        emit SolvencyRootOracle.RootUpdated(POLICY_ID, root, epoch, blockNumber, memberCount, true);

        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, memberCount, sig);

        // Verify root was stored
        assertEq(oracle.getRootCount(POLICY_ID), 1);
        SolvencyRootOracle.RootEntry memory entry = oracle.getRootEntry(POLICY_ID, 0);
        assertEq(entry.root, root);
        assertEq(entry.epoch, epoch);
        assertEq(entry.blockNumber, blockNumber);
        assertEq(entry.memberCount, memberCount);
        assertEq(entry.publishedAt, uint64(block.number));
    }

    function test_updateRootTrusted_relayerCanSubmit() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        uint32 memberCount = 2;
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, memberCount);

        // Relayer (not operator) submits the transaction
        vm.prank(relayer);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, memberCount, sig);

        assertEq(oracle.getRootCount(POLICY_ID), 1);
    }

    function test_updateRootTrusted_multipleEpochs() public {
        uint64 blockNumber = uint64(block.number);

        for (uint64 epoch = 1; epoch <= 3; epoch++) {
            (bytes32 root,,,) = _buildTwoLeafTree(epoch);
            bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
            oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);
        }

        assertEq(oracle.getRootCount(POLICY_ID), 3);
    }

    function test_updateRootTrusted_reverts_wrongSigner() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);

        // Sign with wrong key
        uint256 wrongKey = 0xBAD;
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, POLICY_ID, root, uint256(epoch), uint256(blockNumber), uint256(2), uint256(block.chainid)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvencyRootOracle.SignerNotOperator.selector,
                vm.addr(wrongKey),
                operatorAddr
            )
        );
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, badSig);
    }

    function test_updateRootTrusted_reverts_nonTrustedPolicy() public {
        // Create a non-trusted policy
        bytes32 zkPolicyId = bytes32(uint256(0x02));
        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "zk-scope",
            trustedMode: false,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(zkPolicyId, policy);

        bytes32 root = bytes32(uint256(0xFF));
        bytes memory sig = _signUpdate(zkPolicyId, root, 1, uint64(block.number), 2);

        vm.expectRevert(abi.encodeWithSelector(SolvencyRootOracle.PolicyNotTrustedMode.selector, zkPolicyId));
        oracle.updateRootTrusted(zkPolicyId, root, 1, uint64(block.number), 2, sig);
    }

    function test_updateRootTrusted_reverts_inactivePolicy() public {
        registry.deactivatePolicy(POLICY_ID);

        bytes32 root = bytes32(uint256(0xFF));
        bytes memory sig = _signUpdate(POLICY_ID, root, 1, uint64(block.number), 2);

        vm.expectRevert(abi.encodeWithSelector(SolvencyRootOracle.PolicyNotActive.selector, POLICY_ID));
        oracle.updateRootTrusted(POLICY_ID, root, 1, uint64(block.number), 2, sig);
    }

    function test_updateRootTrusted_reverts_staleBlock() public {
        bytes32 root = bytes32(uint256(0xFF));

        // Set blockNumber far in the past
        uint64 staleBlock = 1;
        vm.roll(1000);
        bytes memory sig = _signUpdate(POLICY_ID, root, 1, staleBlock, 2);

        vm.expectRevert(
            abi.encodeWithSelector(SolvencyRootOracle.BlockTooOld.selector, block.number, staleBlock, uint64(256))
        );
        oracle.updateRootTrusted(POLICY_ID, root, 1, staleBlock, 2, sig);
    }

    function test_updateRootTrusted_reverts_epochNotIncreasing() public {
        uint64 blockNumber = uint64(block.number);
        bytes32 root = bytes32(uint256(0xFF));

        // Submit epoch 5
        bytes memory sig = _signUpdate(POLICY_ID, root, 5, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, 5, blockNumber, 2, sig);

        // Try to submit epoch 5 again (same)
        bytes32 root2 = bytes32(uint256(0xEE));
        sig = _signUpdate(POLICY_ID, root2, 5, blockNumber, 2);
        vm.expectRevert(abi.encodeWithSelector(SolvencyRootOracle.EpochNotIncreasing.selector, uint64(5), uint64(5)));
        oracle.updateRootTrusted(POLICY_ID, root2, 5, blockNumber, 2, sig);

        // Try epoch 3 (going backwards)
        sig = _signUpdate(POLICY_ID, root2, 3, blockNumber, 2);
        vm.expectRevert(abi.encodeWithSelector(SolvencyRootOracle.EpochNotIncreasing.selector, uint64(3), uint64(5)));
        oracle.updateRootTrusted(POLICY_ID, root2, 3, blockNumber, 2, sig);

        // Epoch 6 should work (non-consecutive is fine)
        sig = _signUpdate(POLICY_ID, root2, 6, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root2, 6, blockNumber, 2, sig);
        assertEq(oracle.getRootCount(POLICY_ID), 2);
    }

    function test_updateRootTrusted_reverts_zeroRoot() public {
        bytes memory sig = _signUpdate(POLICY_ID, bytes32(0), 1, uint64(block.number), 2);
        vm.expectRevert(SolvencyRootOracle.ZeroRoot.selector);
        oracle.updateRootTrusted(POLICY_ID, bytes32(0), 1, uint64(block.number), 2, sig);
    }

    // ========================================
    // verifyMember Tests
    // ========================================

    function test_verifyMember_happyPath() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,, , bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        // Submit root
        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        // Verify member 0 is solvent
        bool valid = oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, proof0, 0, 0);
        assertTrue(valid, "Member should be verified as solvent");
    }

    function test_verifyMember_secondMember() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root, bytes32 leaf0,,) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        // Proof for member 1 (index 1): sibling is leaf0
        bytes32[] memory proof1 = new bytes32[](1);
        proof1[0] = leaf0;
        bool valid = oracle.verifyMember(POLICY_ID, MEMBER_ID_1, 1, epoch, proof1, 1, 0);
        assertTrue(valid, "Member 1 should be verified as solvent");
    }

    function test_verifyMember_insolventStatus() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);

        // Build tree where member 0 is insolvent (status=0)
        bytes32 leaf0 = MerkleVerifier.computeLeaf(MEMBER_ID_0, 0, epoch, POLICY_ID);
        bytes32 leaf1 = MerkleVerifier.computeLeaf(MEMBER_ID_1, 1, epoch, POLICY_ID);
        bytes32 root = sha256(abi.encodePacked(leaf0, leaf1));

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        // Verify member 0 is insolvent
        bytes32[] memory proof0 = new bytes32[](1);
        proof0[0] = leaf1;
        assertTrue(oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 0, epoch, proof0, 0, 0), "Insolvent member should verify");

        // Trying to verify member 0 as solvent should fail
        assertFalse(oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, proof0, 0, 0), "Wrong status should fail");
    }

    function test_verifyMember_reverts_rootExpired() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        // Advance past root TTL (1000 blocks)
        vm.roll(block.number + 1001);

        vm.expectRevert(); // RootExpired
        oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, proof0, 0, 0);
    }

    function test_verifyMember_reverts_rootIndexOutOfBounds() public {
        bytes32[] memory emptyProof = new bytes32[](0);

        vm.expectRevert(
            abi.encodeWithSelector(SolvencyRootOracle.RootIndexOutOfBounds.selector, POLICY_ID, 0, 0)
        );
        oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, 1, emptyProof, 0, 0);
    }

    function test_verifyMember_reverts_epochMismatch() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        // Try to verify with wrong epoch
        vm.expectRevert(abi.encodeWithSelector(SolvencyRootOracle.EpochMismatch.selector, uint64(99), epoch));
        oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, 99, proof0, 0, 0);
    }

    function test_verifyMember_invalidProof() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        // Wrong sibling
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = bytes32(uint256(0xDEAD));
        assertFalse(oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, badProof, 0, 0), "Invalid proof should fail");
    }

    // ========================================
    // isMemberSolvent Tests
    // ========================================

    function test_isMemberSolvent() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        assertTrue(oracle.isMemberSolvent(POLICY_ID, MEMBER_ID_0, epoch, proof0, 0, 0));
    }

    // ========================================
    // ZK Mode Tests (with mock verifier)
    // ========================================

    function test_updateRoot_zkMode() public {
        // Create a ZK (non-trusted) policy
        bytes32 zkPolicyId = bytes32(uint256(0x02));
        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "zk-scope",
            trustedMode: false,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(zkPolicyId, policy);

        bytes32 root = bytes32(uint256(0xFF));
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        uint32 memberCount = 5;

        // Encode public values matching BatchProofPublicOutputs
        bytes memory publicValues = abi.encode(
            bytes32(uint256(0xAA)),  // stateRoot
            zkPolicyId,              // policyId
            epoch,                   // epoch
            root,                    // solvencyRoot
            uint64(1 ether),         // thresholdWei
            memberCount,             // memberCount
            blockNumber,             // blockNumber
            uint64(block.chainid)    // chainId
        );

        vm.prank(operatorAddr);
        oracle.updateRoot(zkPolicyId, root, epoch, blockNumber, memberCount, hex"", publicValues);

        assertEq(oracle.getRootCount(zkPolicyId), 1);
        SolvencyRootOracle.RootEntry memory entry = oracle.getRootEntry(zkPolicyId, 0);
        assertEq(entry.root, root);
    }

    function test_updateRoot_zkMode_reverts_invalidPublicValues() public {
        bytes32 zkPolicyId = bytes32(uint256(0x02));
        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "zk-scope",
            trustedMode: false,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(zkPolicyId, policy);

        bytes32 root = bytes32(uint256(0xFF));

        // Public values with wrong policyId
        bytes memory publicValues = abi.encode(
            bytes32(uint256(0xAA)),
            bytes32(uint256(0x99)),       // wrong policyId
            uint64(1),
            root,
            uint64(1 ether),
            uint32(5),
            uint64(block.number),
            uint64(block.chainid)
        );

        vm.prank(operatorAddr);
        vm.expectRevert(SolvencyRootOracle.InvalidPublicValues.selector);
        oracle.updateRoot(zkPolicyId, root, 1, uint64(block.number), 5, hex"", publicValues);
    }

    function test_updateRoot_zkMode_reverts_mockVerifierFails() public {
        bytes32 zkPolicyId = bytes32(uint256(0x02));
        PolicyRegistry.Policy memory policy = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 100,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "zk-scope",
            trustedMode: false,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(zkPolicyId, policy);

        mockVerifier.setShouldPass(false);

        bytes32 root = bytes32(uint256(0xFF));
        bytes memory publicValues = abi.encode(
            bytes32(0), zkPolicyId, uint64(1), root, uint64(1 ether),
            uint32(5), uint64(block.number), uint64(block.chainid)
        );

        vm.prank(operatorAddr);
        vm.expectRevert(); // MockVerifierRejected
        oracle.updateRoot(zkPolicyId, root, 1, uint64(block.number), 5, hex"", publicValues);
    }

    function test_updateRoot_zkMode_reverts_trustedPolicy() public {
        bytes32 root = bytes32(uint256(0xFF));
        bytes memory publicValues = abi.encode(
            bytes32(0), POLICY_ID, uint64(1), root, uint64(1 ether),
            uint32(2), uint64(block.number), uint64(block.chainid)
        );

        vm.expectRevert(abi.encodeWithSelector(SolvencyRootOracle.PolicyIsTrustedMode.selector, POLICY_ID));
        oracle.updateRoot(POLICY_ID, root, 1, uint64(block.number), 2, hex"", publicValues);
    }

    // ========================================
    // Admin Tests
    // ========================================

    function test_setProgramVKey() public {
        bytes32 newVKey = bytes32(uint256(0xCAFE));

        vm.expectEmit(false, false, false, true);
        emit SolvencyRootOracle.ProgramVKeyUpdated(bytes32(0), newVKey);

        oracle.setProgramVKey(newVKey);
        assertEq(oracle.programVKey(), newVKey);
    }

    function test_setProgramVKey_reverts_nonOwner() public {
        vm.prank(relayer);
        vm.expectRevert();
        oracle.setProgramVKey(bytes32(uint256(0xCAFE)));
    }

    // ========================================
    // Gas Benchmarks
    // ========================================

    function test_gas_updateRootTrusted() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);
        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);

        uint256 gasBefore = gasleft();
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("updateRootTrusted gas:", gasUsed);
    }

    function test_gas_verifyMember() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, 2, sig);

        uint256 gasBefore = gasleft();
        oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, proof0, 0, 0);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("verifyMember gas:", gasUsed);
    }
}
