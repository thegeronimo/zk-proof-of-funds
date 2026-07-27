// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolvencyRootOracle} from "../src/SolvencyRootOracle.sol";
import {MerkleVerifier} from "../src/MerkleVerifier.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";

/// @title LargeBatchAndEdgeCasesTest
/// @notice Tests for large Merkle trees, TTL boundaries, multi-policy, and gas benchmarks.
/// @dev Includes Solidity-side Merkle tree construction helpers matching crates/common/src/merkle.rs.
contract LargeBatchAndEdgeCasesTest is Test {
    PolicyRegistry registry;
    SolvencyRootOracle oracle;
    MockSP1Verifier mockVerifier;

    uint256 operatorKey;
    address operatorAddr;

    bytes32 constant POLICY_ID = bytes32(uint256(0x01));

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
            active: true,
            startBlock: 0,
            version: 1
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

    function _submitRoot(
        bytes32 _policyId,
        bytes32 root,
        uint64 epoch,
        uint64 blockNumber,
        uint32 memberCount
    ) internal {
        bytes memory sig = _signUpdate(_policyId, root, epoch, blockNumber, memberCount);
        oracle.updateRootTrusted(_policyId, root, epoch, blockNumber, memberCount, sig);
    }

    /// @dev Generate a deterministic memberId from a seed (matches Rust SHA-256 pattern).
    function _makeMemberId(uint256 seed) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(seed));
    }

    /// @dev Build an N-leaf Merkle tree in Solidity, matching the binary SHA-256 tree
    ///      from crates/common/src/merkle.rs with odd-level last-node duplication.
    ///      Returns the root and the array of leaves.
    function _buildTree(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "Empty tree");
        if (leaves.length == 1) return leaves[0];

        bytes32[] memory current = leaves;

        while (current.length > 1) {
            uint256 len = current.length;
            uint256 nextLen = (len + 1) / 2;
            bytes32[] memory next = new bytes32[](nextLen);

            for (uint256 i = 0; i < nextLen; i++) {
                bytes32 left = current[i * 2];
                bytes32 right;
                if (i * 2 + 1 < len) {
                    right = current[i * 2 + 1];
                } else {
                    // Odd-level duplication: duplicate the last node
                    right = left;
                }
                next[i] = sha256(abi.encodePacked(left, right));
            }

            current = next;
        }

        return current[0];
    }

    /// @dev Compute a Merkle proof for a specific leaf index in a tree.
    function _computeProof(bytes32[] memory leaves, uint256 index)
        internal
        pure
        returns (bytes32[] memory proof)
    {
        require(leaves.length > 0, "Empty tree");
        if (leaves.length == 1) {
            proof = new bytes32[](0);
            return proof;
        }

        // Calculate tree depth
        uint256 depth = 0;
        {
            uint256 n = leaves.length;
            while (n > 1) {
                n = (n + 1) / 2;
                depth++;
            }
        }

        proof = new bytes32[](depth);
        bytes32[] memory current = leaves;
        uint256 idx = index;
        uint256 proofIdx = 0;

        while (current.length > 1) {
            uint256 len = current.length;
            uint256 nextLen = (len + 1) / 2;
            bytes32[] memory next = new bytes32[](nextLen);

            // Record sibling for current index
            uint256 siblingIdx = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (siblingIdx >= len) {
                // Odd node: sibling is itself (duplication)
                proof[proofIdx] = current[idx];
            } else {
                proof[proofIdx] = current[siblingIdx];
            }
            proofIdx++;

            // Build next level
            for (uint256 i = 0; i < nextLen; i++) {
                bytes32 left = current[i * 2];
                bytes32 right;
                if (i * 2 + 1 < len) {
                    right = current[i * 2 + 1];
                } else {
                    right = left;
                }
                next[i] = sha256(abi.encodePacked(left, right));
            }

            current = next;
            idx = idx / 2;
        }

        return proof;
    }

    /// @dev Build an array of N leaves (all solvent) for a given epoch and policy.
    function _buildLeaves(uint256 count, uint64 epoch, bytes32 _policyId)
        internal
        pure
        returns (bytes32[] memory leaves)
    {
        leaves = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            bytes32 memberId = _makeMemberId(i);
            leaves[i] = MerkleVerifier.computeLeaf(memberId, 1, epoch, _policyId);
        }
    }

    // ========================================
    // Large Batch Tests
    // ========================================

    function test_largeBatch_50members() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);

        bytes32[] memory leaves = _buildLeaves(50, epoch, POLICY_ID);
        bytes32 root = _buildTree(leaves);

        _submitRoot(POLICY_ID, root, epoch, blockNumber, 50);

        // Verify member at index 0
        bytes32[] memory proof0 = _computeProof(leaves, 0);
        bool valid0 = oracle.verifyMember(POLICY_ID, _makeMemberId(0), 1, epoch, proof0, 0, 0);
        assertTrue(valid0, "Member 0 should verify in 50-leaf tree");

        // Verify member at index 25 (middle)
        bytes32[] memory proof25 = _computeProof(leaves, 25);
        bool valid25 = oracle.verifyMember(POLICY_ID, _makeMemberId(25), 1, epoch, proof25, 25, 0);
        assertTrue(valid25, "Member 25 should verify in 50-leaf tree");

        // Verify member at index 49 (last)
        bytes32[] memory proof49 = _computeProof(leaves, 49);
        bool valid49 = oracle.verifyMember(POLICY_ID, _makeMemberId(49), 1, epoch, proof49, 49, 0);
        assertTrue(valid49, "Member 49 should verify in 50-leaf tree");
    }

    function test_largeBatch_100members() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);

        bytes32[] memory leaves = _buildLeaves(100, epoch, POLICY_ID);
        bytes32 root = _buildTree(leaves);

        _submitRoot(POLICY_ID, root, epoch, blockNumber, 100);

        // Verify a few members: 0, 42, 99
        bytes32[] memory proof0 = _computeProof(leaves, 0);
        assertTrue(oracle.verifyMember(POLICY_ID, _makeMemberId(0), 1, epoch, proof0, 0, 0));

        bytes32[] memory proof42 = _computeProof(leaves, 42);
        assertTrue(oracle.verifyMember(POLICY_ID, _makeMemberId(42), 1, epoch, proof42, 42, 0));

        bytes32[] memory proof99 = _computeProof(leaves, 99);
        assertTrue(oracle.verifyMember(POLICY_ID, _makeMemberId(99), 1, epoch, proof99, 99, 0));
    }

    // ========================================
    // Sequential Epoch Tests
    // ========================================

    function test_sequentialEpochs_10() public {
        uint64 blockNumber = uint64(block.number);

        for (uint64 ep = 1; ep <= 10; ep++) {
            bytes32[] memory leaves = _buildLeaves(5, ep, POLICY_ID);
            bytes32 root = _buildTree(leaves);
            _submitRoot(POLICY_ID, root, ep, blockNumber, 5);
        }

        assertEq(oracle.getRootCount(POLICY_ID), 10, "Should have 10 root entries");

        // Verify each epoch has correct monotonic epoch number
        for (uint256 i = 0; i < 10; i++) {
            SolvencyRootOracle.RootEntry memory entry = oracle.getRootEntry(POLICY_ID, i);
            assertEq(entry.epoch, uint64(i + 1), "Epoch should be monotonic");
            assertEq(entry.memberCount, 5, "Member count should be 5");
        }
    }

    // ========================================
    // Root TTL Boundary Tests
    // ========================================

    function test_rootTTL_exactBoundary() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        bytes32[] memory leaves = _buildLeaves(2, epoch, POLICY_ID);
        bytes32 root = _buildTree(leaves);

        _submitRoot(POLICY_ID, root, epoch, blockNumber, 2);

        uint64 publishedAt = uint64(block.number);
        bytes32[] memory proof0 = _computeProof(leaves, 0);

        // At publishedAt + rootTTL (1000): block.number - publishedAt == 1000
        // The check is: block.number - publishedAt > rootTTLBlocks
        vm.roll(publishedAt + 1000);
        bool valid = oracle.verifyMember(POLICY_ID, _makeMemberId(0), 1, epoch, proof0, 0, 0);
        assertTrue(valid, "At TTL boundary should still be valid");

        // One more block → expired
        // Note: isMemberSolvent uses this.verifyMember() (external call), so we use
        // try/catch instead of vm.expectRevert to handle the call depth issue.
        vm.roll(publishedAt + 1001);
        try oracle.verifyMember(POLICY_ID, _makeMemberId(0), 1, epoch, proof0, 0, 0) returns (bool) {
            fail("Should have reverted with RootExpired");
        } catch {
            // Expected: RootExpired revert
        }
    }

    // ========================================
    // Max Block Age Boundary Tests
    // ========================================

    function test_maxBlockAge_exactBoundary() public {
        // maxBlockAge = 256
        vm.roll(1000);
        uint64 blockNumber = uint64(block.number); // block 1000
        bytes32[] memory leaves = _buildLeaves(2, 1, POLICY_ID);
        bytes32 root = _buildTree(leaves);

        // At boundary: block.number - blockNumber == 256
        vm.roll(1000 + 256);
        bytes memory sig = _signUpdate(POLICY_ID, root, 1, blockNumber, 2);
        oracle.updateRootTrusted(POLICY_ID, root, 1, blockNumber, 2, sig);
        assertEq(oracle.getRootCount(POLICY_ID), 1, "At maxBlockAge boundary should succeed");

        // One past: block.number - blockNumber == 257 > 256
        vm.roll(1000 + 257);
        bytes32 root2 = bytes32(uint256(0xBB));
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
    // Multiple Policies Tests
    // ========================================

    function test_multiplePolicies_independentRoots() public {
        uint64 blockNumber = uint64(block.number);

        // Create 3 policies
        bytes32 policyA = bytes32(uint256(0x0A));
        bytes32 policyB = bytes32(uint256(0x0B));
        bytes32 policyC = bytes32(uint256(0x0C));

        for (uint256 i = 0; i < 3; i++) {
            bytes32 pid = i == 0 ? policyA : (i == 1 ? policyB : policyC);
            PolicyRegistry.Policy memory pol = PolicyRegistry.Policy({
                thresholdWei: 1 ether,
                tokenAddress: address(0),
                chainId: uint64(block.chainid),
                epochLengthBlocks: 100,
                maxBlockAge: 256,
                rootTTLBlocks: 1000,
                operator: operatorAddr,
                scope: string(abi.encodePacked("scope-", i)),
                trustedMode: true,
                active: true,
                startBlock: 0,
                version: 1
            });
            registry.createPolicy(pid, pol);
        }

        // Submit different roots for each policy
        bytes32[] memory leavesA = _buildLeaves(3, 1, policyA);
        bytes32 rootA = _buildTree(leavesA);
        _submitRoot(policyA, rootA, 1, blockNumber, 3);

        bytes32[] memory leavesB = _buildLeaves(5, 1, policyB);
        bytes32 rootB = _buildTree(leavesB);
        _submitRoot(policyB, rootB, 1, blockNumber, 5);

        bytes32[] memory leavesC = _buildLeaves(2, 1, policyC);
        bytes32 rootC = _buildTree(leavesC);
        _submitRoot(policyC, rootC, 1, blockNumber, 2);

        // Verify independent roots
        assertEq(oracle.getRootCount(policyA), 1);
        assertEq(oracle.getRootCount(policyB), 1);
        assertEq(oracle.getRootCount(policyC), 1);

        SolvencyRootOracle.RootEntry memory entryA = oracle.getRootEntry(policyA, 0);
        SolvencyRootOracle.RootEntry memory entryB = oracle.getRootEntry(policyB, 0);
        SolvencyRootOracle.RootEntry memory entryC = oracle.getRootEntry(policyC, 0);

        // Roots should all be different (different policy IDs → different leaves)
        assertTrue(entryA.root != entryB.root, "A and B roots should differ");
        assertTrue(entryB.root != entryC.root, "B and C roots should differ");
        assertTrue(entryA.root != entryC.root, "A and C roots should differ");

        // Member counts correct
        assertEq(entryA.memberCount, 3);
        assertEq(entryB.memberCount, 5);
        assertEq(entryC.memberCount, 2);

        // Verify a member in policy A
        bytes32[] memory proofA0 = _computeProof(leavesA, 0);
        assertTrue(oracle.verifyMember(policyA, _makeMemberId(0), 1, 1, proofA0, 0, 0));

        // Same memberId with policy A proof should NOT verify against policy B
        assertFalse(oracle.verifyMember(policyB, _makeMemberId(0), 1, 1, proofA0, 0, 0));
    }

    function test_multiplePolicies_differentEpochLengths() public {
        uint64 blockNumber = uint64(block.number);

        bytes32 policyShort = bytes32(uint256(0x0D));
        bytes32 policyLong = bytes32(uint256(0x0E));

        PolicyRegistry.Policy memory shortPol = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 10,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "short-epoch",
            trustedMode: true,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(policyShort, shortPol);

        PolicyRegistry.Policy memory longPol = PolicyRegistry.Policy({
            thresholdWei: 1 ether,
            tokenAddress: address(0),
            chainId: uint64(block.chainid),
            epochLengthBlocks: 1000,
            maxBlockAge: 256,
            rootTTLBlocks: 1000,
            operator: operatorAddr,
            scope: "long-epoch",
            trustedMode: true,
            active: true,
            startBlock: 0,
            version: 1
        });
        registry.createPolicy(policyLong, longPol);

        // Short policy: 10 epochs
        for (uint64 ep = 1; ep <= 10; ep++) {
            bytes32[] memory leaves = _buildLeaves(2, ep, policyShort);
            bytes32 root = _buildTree(leaves);
            _submitRoot(policyShort, root, ep, blockNumber, 2);
        }

        // Long policy: 1 epoch at epoch 50
        bytes32[] memory leavesL = _buildLeaves(2, 50, policyLong);
        bytes32 rootL = _buildTree(leavesL);
        _submitRoot(policyLong, rootL, 50, blockNumber, 2);

        assertEq(oracle.getRootCount(policyShort), 10, "Short policy: 10 epochs");
        assertEq(oracle.getRootCount(policyLong), 1, "Long policy: 1 epoch");

        SolvencyRootOracle.RootEntry memory lastShort = oracle.getRootEntry(policyShort, 9);
        assertEq(lastShort.epoch, 10);

        SolvencyRootOracle.RootEntry memory onlyLong = oracle.getRootEntry(policyLong, 0);
        assertEq(onlyLong.epoch, 50);
    }

    // ========================================
    // Gas Benchmarks
    // ========================================

    function test_gas_updateRootTrusted_cost() public {
        uint64 blockNumber = uint64(block.number);
        bytes32[] memory leaves = _buildLeaves(10, 1, POLICY_ID);
        bytes32 root = _buildTree(leaves);
        bytes memory sig = _signUpdate(POLICY_ID, root, 1, blockNumber, 10);

        uint256 gasBefore = gasleft();
        oracle.updateRootTrusted(POLICY_ID, root, 1, blockNumber, 10, sig);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("updateRootTrusted gas (10 members):", gasUsed);
        assertLt(gasUsed, 150_000, "updateRootTrusted should cost < 150k gas");
    }

    function test_gas_verifyMember_varyingDepth() public {
        uint64 blockNumber = uint64(block.number);

        // Depth 1 (2 leaves)
        {
            bytes32[] memory leaves = _buildLeaves(2, 1, POLICY_ID);
            bytes32 root = _buildTree(leaves);
            _submitRoot(POLICY_ID, root, 1, blockNumber, 2);
            bytes32[] memory proof = _computeProof(leaves, 0);

            uint256 gasBefore = gasleft();
            oracle.verifyMember(POLICY_ID, _makeMemberId(0), 1, 1, proof, 0, 0);
            uint256 gasUsed = gasBefore - gasleft();
            console.log("verifyMember depth=1 gas:", gasUsed);
        }

        // Depth 4 (16 leaves) - submit as epoch 2
        {
            bytes32[] memory leaves = _buildLeaves(16, 2, POLICY_ID);
            bytes32 root = _buildTree(leaves);
            _submitRoot(POLICY_ID, root, 2, blockNumber, 16);
            bytes32[] memory proof = _computeProof(leaves, 7);

            uint256 gasBefore = gasleft();
            oracle.verifyMember(POLICY_ID, _makeMemberId(7), 1, 2, proof, 7, 1);
            uint256 gasUsed = gasBefore - gasleft();
            console.log("verifyMember depth=4 gas:", gasUsed);
        }

        // Depth 6 (50 leaves) - submit as epoch 3
        {
            bytes32[] memory leaves = _buildLeaves(50, 3, POLICY_ID);
            bytes32 root = _buildTree(leaves);
            _submitRoot(POLICY_ID, root, 3, blockNumber, 50);
            bytes32[] memory proof = _computeProof(leaves, 25);

            uint256 gasBefore = gasleft();
            oracle.verifyMember(POLICY_ID, _makeMemberId(25), 1, 3, proof, 25, 2);
            uint256 gasUsed = gasBefore - gasleft();
            console.log("verifyMember depth=6 gas:", gasUsed);
        }

        // Depth 7 (100 leaves) - submit as epoch 4
        {
            bytes32[] memory leaves = _buildLeaves(100, 4, POLICY_ID);
            bytes32 root = _buildTree(leaves);
            _submitRoot(POLICY_ID, root, 4, blockNumber, 100);
            bytes32[] memory proof = _computeProof(leaves, 50);

            uint256 gasBefore = gasleft();
            oracle.verifyMember(POLICY_ID, _makeMemberId(50), 1, 4, proof, 50, 3);
            uint256 gasUsed = gasBefore - gasleft();
            console.log("verifyMember depth=7 gas:", gasUsed);
        }
    }

    function test_gas_verifyMember_vs_isMemberSolvent() public {
        uint64 epoch = 1;
        uint64 blockNumber = uint64(block.number);
        bytes32[] memory leaves = _buildLeaves(10, epoch, POLICY_ID);
        bytes32 root = _buildTree(leaves);
        _submitRoot(POLICY_ID, root, epoch, blockNumber, 10);

        bytes32[] memory proof = _computeProof(leaves, 5);
        bytes32 memberId = _makeMemberId(5);

        // Gas for verifyMember
        uint256 gas1 = gasleft();
        oracle.verifyMember(POLICY_ID, memberId, 1, epoch, proof, 5, 0);
        uint256 verifyGas = gas1 - gasleft();

        // Gas for isMemberSolvent
        uint256 gas2 = gasleft();
        oracle.isMemberSolvent(POLICY_ID, memberId, epoch, proof, 5, 0);
        uint256 solventGas = gas2 - gasleft();

        console.log("verifyMember gas:", verifyGas);
        console.log("isMemberSolvent gas:", solventGas);

        // They should be very close (isMemberSolvent is a thin wrapper)
        // Allow up to 1500 gas difference for the external call overhead
        // (isMemberSolvent calls this.verifyMember() which adds ~1000 gas for the external call)
        uint256 diff = solventGas > verifyGas ? solventGas - verifyGas : verifyGas - solventGas;
        assertLt(diff, 1500, "Gas difference should be < 1500");
    }
}
