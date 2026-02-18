// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolvencyRootOracle} from "../src/SolvencyRootOracle.sol";
import {MerkleVerifier} from "../src/MerkleVerifier.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";

/// @title SecurityEdgeCasesTest
/// @notice Security-focused edge case tests for the SolvencyRootOracle.
/// @dev Covers replay attacks, forged proofs, boundary conditions, and access control.
contract SecurityEdgeCasesTest is Test {
    PolicyRegistry registry;
    SolvencyRootOracle oracle;
    MockSP1Verifier mockVerifier;

    uint256 operatorKey;
    address operatorAddr;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));
    bytes32 constant MEMBER_ID_0 = bytes32(uint256(0xA0));
    bytes32 constant MEMBER_ID_1 = bytes32(uint256(0xB0));

    bytes32 private constant TYPEHASH = keccak256(
        "SolvencyRootUpdate(bytes32 policyId,bytes32 root,uint64 epoch,uint64 blockNumber,uint32 memberCount,uint64 chainId)"
    );

    function setUp() public {
        operatorKey = 0xA11CE;
        operatorAddr = vm.addr(operatorKey);

        registry = new PolicyRegistry();
        mockVerifier = new MockSP1Verifier();
        oracle = new SolvencyRootOracle(
            address(registry),
            address(mockVerifier),
            bytes32(0)
        );

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
            active: true
        });
        registry.createPolicy(POLICY_ID, policy);
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

    function _signUpdateWithKey(
        uint256 signerKey,
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

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
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

    function _submitRoot(bytes32 root, uint64 epoch, uint64 blockNumber, uint32 memberCount) internal {
        bytes memory sig = _signUpdate(POLICY_ID, root, epoch, blockNumber, memberCount);
        oracle.updateRootTrusted(POLICY_ID, root, epoch, blockNumber, memberCount, sig);
    }

    // ========================================
    // Replay Attack Tests
    // ========================================

    function test_replayAttack_sameEpoch() public {
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(1);

        _submitRoot(root, 1, blockNumber, 2);

        // Re-submit same epoch → should revert
        bytes32 root2 = bytes32(uint256(0xEE));
        bytes memory sig2 = _signUpdate(POLICY_ID, root2, 1, blockNumber, 2);

        vm.expectRevert(
            abi.encodeWithSelector(SolvencyRootOracle.EpochNotIncreasing.selector, uint64(1), uint64(1))
        );
        oracle.updateRootTrusted(POLICY_ID, root2, 1, blockNumber, 2, sig2);
    }

    function test_replayAttack_previousEpoch() public {
        uint64 blockNumber = uint64(block.number);

        // Submit epochs 1, 2, 3
        for (uint64 ep = 1; ep <= 3; ep++) {
            bytes32 root = bytes32(uint256(ep));
            bytes memory sig = _signUpdate(POLICY_ID, root, ep, blockNumber, 2);
            oracle.updateRootTrusted(POLICY_ID, root, ep, blockNumber, 2, sig);
        }

        assertEq(oracle.getRootCount(POLICY_ID), 3);

        // Try to submit epoch 2 again → revert
        bytes32 replayRoot = bytes32(uint256(0xFF));
        bytes memory replaySig = _signUpdate(POLICY_ID, replayRoot, 2, blockNumber, 2);

        vm.expectRevert(
            abi.encodeWithSelector(SolvencyRootOracle.EpochNotIncreasing.selector, uint64(2), uint64(3))
        );
        oracle.updateRootTrusted(POLICY_ID, replayRoot, 2, blockNumber, 2, replaySig);
    }

    // ========================================
    // Wrong Signer Tests
    // ========================================

    function test_wrongSigner_nonOperatorKey() public {
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(1);

        uint256 randomKey = 0xBEEF;
        address randomAddr = vm.addr(randomKey);
        bytes memory badSig = _signUpdateWithKey(randomKey, POLICY_ID, root, 1, blockNumber, 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvencyRootOracle.SignerNotOperator.selector,
                randomAddr,
                operatorAddr
            )
        );
        oracle.updateRootTrusted(POLICY_ID, root, 1, blockNumber, 2, badSig);
    }

    // ========================================
    // Forged Proof Tests
    // ========================================

    function test_forgedProof_wrongSibling() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Random proof bytes → verification should return false
        bytes32[] memory forgedProof = new bytes32[](1);
        forgedProof[0] = bytes32(uint256(0xCAFEBABE));

        bool valid = oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, forgedProof, 0, 0);
        assertFalse(valid, "Forged sibling should not verify");
    }

    function test_forgedProof_wrongLeafIndex() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Correct proof, wrong index (should be 0, claim 1)
        bool valid = oracle.verifyMember(POLICY_ID, MEMBER_ID_0, 1, epoch, proof0, 1, 0);
        assertFalse(valid, "Wrong leaf index should not verify");
    }

    function test_forgedProof_wrongMemberId() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,, bytes32[] memory proof0) = _buildTwoLeafTree(epoch);

        _submitRoot(root, epoch, blockNumber, 2);

        // Proof is for MEMBER_ID_0, but claim MEMBER_ID_1
        bool valid = oracle.verifyMember(POLICY_ID, MEMBER_ID_1, 1, epoch, proof0, 0, 0);
        assertFalse(valid, "Proof for wrong memberId should not verify");
    }

    // ========================================
    // Block Age Boundary Tests
    // ========================================

    function test_blockTooOld_boundary() public {
        // Policy maxBlockAge = 256
        // Start at block 1000
        vm.roll(1000);
        uint64 blockNumber = uint64(block.number);
        (bytes32 root,,,) = _buildTwoLeafTree(1);

        // At exactly maxBlockAge: block.number - blockNumber == 256 should still succeed
        // (the check is: block.number - blockNumber > maxBlockAge)
        vm.roll(1000 + 256);
        bytes memory sig = _signUpdate(POLICY_ID, root, 1, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, 1, blockNumber, 2, sig);

        assertEq(oracle.getRootCount(POLICY_ID), 1, "At boundary should succeed");

        // One more block → blockTooOld
        vm.roll(1000 + 257);
        bytes32 root2 = bytes32(uint256(0xCC));
        bytes memory sig2 = _signUpdate(POLICY_ID, root2, 2, blockNumber, 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolvencyRootOracle.BlockTooOld.selector,
                block.number,
                blockNumber,
                uint64(256)
            )
        );
        oracle.updateRootTrusted(POLICY_ID, root2, 2, blockNumber, 2, sig2);
    }

    // ========================================
    // Zero Root Test
    // ========================================

    function test_zeroRoot_rejected() public {
        uint64 blockNumber = uint64(block.number);
        bytes memory sig = _signUpdate(POLICY_ID, bytes32(0), 1, blockNumber, 2);

        vm.expectRevert(SolvencyRootOracle.ZeroRoot.selector);
        oracle.updateRootTrusted(POLICY_ID, bytes32(0), 1, blockNumber, 2, sig);
    }
}
