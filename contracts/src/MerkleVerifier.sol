// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MerkleVerifier
/// @notice SHA-256 based Merkle proof verification library for the Solvency Agent.
/// @dev This must produce byte-identical results to crates/common/src/merkle.rs.
///      Leaf = SHA256(memberId || status || epoch_be_bytes || policyId)
///      Tree uses standard binary construction with last-node duplication for odd levels.
library MerkleVerifier {
    /// @notice Compute a solvency tree leaf.
    /// @param memberId   The member's unique identifier (SHA256 of enrollment signature).
    /// @param status     Solvency status: 1 = solvent, 0 = insolvent.
    /// @param epoch      The epoch number (encoded as 8-byte big-endian uint64).
    /// @param policyId   The policy identifier.
    /// @return leaf      The SHA-256 hash of the concatenated inputs (73 bytes preimage).
    function computeLeaf(
        bytes32 memberId,
        uint8 status,
        uint64 epoch,
        bytes32 policyId
    ) internal pure returns (bytes32) {
        // abi.encodePacked: bytes32 (32) + uint8 (1) + uint64 (8) + bytes32 (32) = 73 bytes
        // uint64 is encoded as 8 bytes big-endian, matching Rust's epoch.to_be_bytes()
        return sha256(abi.encodePacked(memberId, status, epoch, policyId));
    }

    /// @notice Verify a Merkle inclusion proof against a root.
    /// @dev Matches the verify_proof function in crates/common/src/merkle.rs.
    ///      At each level, if index is even the current node is on the left,
    ///      if odd it is on the right. Index is halved at each step.
    /// @param proof  Array of sibling hashes from leaf to root.
    /// @param root   The expected Merkle root.
    /// @param leaf   The leaf to verify inclusion of.
    /// @param index  The leaf's position in the tree (0-based).
    /// @return valid True if the proof is valid.
    function verifyProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 current = leaf;
        uint256 idx = index;

        for (uint256 i = 0; i < proof.length; i++) {
            if (idx % 2 == 0) {
                // Current node is a left child
                current = sha256(abi.encodePacked(current, proof[i]));
            } else {
                // Current node is a right child
                current = sha256(abi.encodePacked(proof[i], current));
            }
            idx = idx / 2;
        }

        return current == root;
    }
}
