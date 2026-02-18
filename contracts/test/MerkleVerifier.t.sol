// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {MerkleVerifier} from "../src/MerkleVerifier.sol";

/// @notice Wrapper contract to expose the MerkleVerifier library functions for testing.
contract MerkleVerifierHarness {
    function computeLeaf(
        bytes32 memberId,
        uint8 status,
        uint64 epoch,
        bytes32 policyId
    ) external pure returns (bytes32) {
        return MerkleVerifier.computeLeaf(memberId, status, epoch, policyId);
    }

    function verifyProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) external pure returns (bool) {
        return MerkleVerifier.verifyProof(proof, root, leaf, index);
    }
}

contract MerkleVerifierTest is Test {
    MerkleVerifierHarness harness;

    function setUp() public {
        harness = new MerkleVerifierHarness();
    }

    // --- Helper: SHA-256 hash pair (matching Rust hash_pair) ---
    function _hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
    }

    // --- Leaf Computation Tests ---

    function test_computeLeaf_deterministic() public view {
        bytes32 memberId = bytes32(uint256(0xAA));
        bytes32 policyId = bytes32(uint256(0xBB));

        bytes32 leaf1 = harness.computeLeaf(memberId, 1, 42, policyId);
        bytes32 leaf2 = harness.computeLeaf(memberId, 1, 42, policyId);
        assertEq(leaf1, leaf2, "Leaf computation should be deterministic");
    }

    function test_computeLeaf_differentStatus() public view {
        bytes32 memberId = bytes32(uint256(0xAA));
        bytes32 policyId = bytes32(uint256(0xBB));

        bytes32 leafSolvent = harness.computeLeaf(memberId, 1, 42, policyId);
        bytes32 leafInsolvent = harness.computeLeaf(memberId, 0, 42, policyId);
        assertTrue(leafSolvent != leafInsolvent, "Different status should produce different leaf");
    }

    function test_computeLeaf_differentEpoch() public view {
        bytes32 memberId = bytes32(uint256(0xAA));
        bytes32 policyId = bytes32(uint256(0xBB));

        bytes32 leaf1 = harness.computeLeaf(memberId, 1, 42, policyId);
        bytes32 leaf2 = harness.computeLeaf(memberId, 1, 43, policyId);
        assertTrue(leaf1 != leaf2, "Different epoch should produce different leaf");
    }

    function test_computeLeaf_matchesManualSha256() public view {
        // Manually compute: sha256(memberId || status || epoch_be || policyId)
        bytes32 memberId = bytes32(uint256(1));
        uint8 status = 1;
        uint64 epoch = 100;
        bytes32 policyId = bytes32(uint256(2));

        bytes32 expected = sha256(abi.encodePacked(memberId, status, epoch, policyId));
        bytes32 actual = harness.computeLeaf(memberId, status, epoch, policyId);
        assertEq(actual, expected, "computeLeaf should match manual sha256");
    }

    // --- Two-Leaf Tree ---

    function test_twoLeafTree() public view {
        bytes32 leaf0 = bytes32(uint256(0x01));
        bytes32 leaf1 = bytes32(uint256(0x02));

        // Root = sha256(leaf0 || leaf1)
        bytes32 root = _hashPair(leaf0, leaf1);

        // Proof for leaf0: sibling is leaf1
        bytes32[] memory proof0 = new bytes32[](1);
        proof0[0] = leaf1;
        assertTrue(harness.verifyProof(proof0, root, leaf0, 0), "leaf0 proof should verify");

        // Proof for leaf1: sibling is leaf0
        bytes32[] memory proof1 = new bytes32[](1);
        proof1[0] = leaf0;
        assertTrue(harness.verifyProof(proof1, root, leaf1, 1), "leaf1 proof should verify");
    }

    // --- Three-Leaf Tree (odd padding) ---

    function test_threeLeafTree() public view {
        bytes32 leafA = bytes32(uint256(0x01));
        bytes32 leafB = bytes32(uint256(0x02));
        bytes32 leafC = bytes32(uint256(0x03));

        // With 3 leaves, leafC is duplicated:
        // Level 1: H(A,B), H(C,C)
        // Root: H(H(A,B), H(C,C))
        bytes32 hAB = _hashPair(leafA, leafB);
        bytes32 hCC = _hashPair(leafC, leafC);
        bytes32 root = _hashPair(hAB, hCC);

        // Proof for leafA (index 0): [leafB, H(C,C)]
        bytes32[] memory proof0 = new bytes32[](2);
        proof0[0] = leafB;
        proof0[1] = hCC;
        assertTrue(harness.verifyProof(proof0, root, leafA, 0), "leafA proof should verify");

        // Proof for leafB (index 1): [leafA, H(C,C)]
        bytes32[] memory proof1 = new bytes32[](2);
        proof1[0] = leafA;
        proof1[1] = hCC;
        assertTrue(harness.verifyProof(proof1, root, leafB, 1), "leafB proof should verify");

        // Proof for leafC (index 2): [leafC (dup), H(A,B)]
        bytes32[] memory proof2 = new bytes32[](2);
        proof2[0] = leafC; // duplicate sibling
        proof2[1] = hAB;
        assertTrue(harness.verifyProof(proof2, root, leafC, 2), "leafC proof should verify");
    }

    // --- Four-Leaf Tree ---

    function test_fourLeafTree() public view {
        bytes32[4] memory leaves;
        for (uint256 i = 0; i < 4; i++) {
            leaves[i] = bytes32(i);
        }

        bytes32 h01 = _hashPair(leaves[0], leaves[1]);
        bytes32 h23 = _hashPair(leaves[2], leaves[3]);
        bytes32 root = _hashPair(h01, h23);

        // Proof for leaf 0 (index 0): [leaf1, H(2,3)]
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaves[1];
        proof[1] = h23;
        assertTrue(harness.verifyProof(proof, root, leaves[0], 0), "leaf0 proof should verify");

        // Proof for leaf 3 (index 3): [leaf2, H(0,1)]
        proof[0] = leaves[2];
        proof[1] = h01;
        assertTrue(harness.verifyProof(proof, root, leaves[3], 3), "leaf3 proof should verify");
    }

    // --- Eight-Leaf Tree ---

    function test_eightLeafTree() public view {
        bytes32[8] memory leaves;
        for (uint256 i = 0; i < 8; i++) {
            leaves[i] = bytes32(i + 10);
        }

        // Level 1
        bytes32 h01 = _hashPair(leaves[0], leaves[1]);
        bytes32 h23 = _hashPair(leaves[2], leaves[3]);
        bytes32 h45 = _hashPair(leaves[4], leaves[5]);
        bytes32 h67 = _hashPair(leaves[6], leaves[7]);

        // Level 2
        bytes32 h0123 = _hashPair(h01, h23);
        bytes32 h4567 = _hashPair(h45, h67);

        // Root
        bytes32 root = _hashPair(h0123, h4567);

        // Proof for leaf 5 (index 5): [leaf4, H(6,7), H(0,1,2,3)]
        bytes32[] memory proof = new bytes32[](3);
        proof[0] = leaves[4]; // sibling at level 0
        proof[1] = h67;       // sibling at level 1
        proof[2] = h0123;     // sibling at level 2
        assertTrue(harness.verifyProof(proof, root, leaves[5], 5), "leaf5 proof should verify");
    }

    // --- Invalid Proof ---

    function test_invalidProofRejected() public view {
        bytes32 leaf0 = bytes32(uint256(0x01));
        bytes32 leaf1 = bytes32(uint256(0x02));
        bytes32 root = _hashPair(leaf0, leaf1);

        // Try to verify leaf0 with wrong sibling
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = bytes32(uint256(0xFF)); // wrong sibling
        assertFalse(harness.verifyProof(badProof, root, leaf0, 0), "Invalid proof should be rejected");
    }

    function test_wrongLeafRejected() public view {
        bytes32 leaf0 = bytes32(uint256(0x01));
        bytes32 leaf1 = bytes32(uint256(0x02));
        bytes32 root = _hashPair(leaf0, leaf1);

        // Try to verify wrong leaf with correct proof for leaf0
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;
        bytes32 wrongLeaf = bytes32(uint256(0xFF));
        assertFalse(harness.verifyProof(proof, root, wrongLeaf, 0), "Wrong leaf should be rejected");
    }

    function test_wrongIndexRejected() public view {
        bytes32 leaf0 = bytes32(uint256(0x01));
        bytes32 leaf1 = bytes32(uint256(0x02));
        bytes32 root = _hashPair(leaf0, leaf1);

        // Correct proof for leaf0 at index 0, but try with index 1
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;
        assertFalse(harness.verifyProof(proof, root, leaf0, 1), "Wrong index should be rejected");
    }

    // --- Full Solvency Leaf Tree Test ---

    function test_fullSolvencyLeafTree() public view {
        // Build a tree with real solvency leaves
        bytes32 memberId0 = bytes32(uint256(0xA0));
        bytes32 memberId1 = bytes32(uint256(0xB0));
        bytes32 policyId = bytes32(uint256(0xCC));
        uint64 epoch = 5;

        bytes32 leaf0 = harness.computeLeaf(memberId0, 1, epoch, policyId);
        bytes32 leaf1 = harness.computeLeaf(memberId1, 1, epoch, policyId);

        bytes32 root = _hashPair(leaf0, leaf1);

        // Verify leaf0
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;
        assertTrue(harness.verifyProof(proof, root, leaf0, 0), "Solvency leaf proof should verify");
    }
}
