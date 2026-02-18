// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolvencyOracle} from "../../contracts/src/interfaces/ISolvencyOracle.sol";

/// @title SolvencyGatedNFT
/// @notice Example: An NFT collection that requires solvency proof to mint.
/// @dev Demonstrates how NFT projects can use solvency proofs as an allowlist
///      mechanism. Instead of traditional whitelists, only users who prove they
///      hold >= threshold balance can mint.
///
///      Use case: A premium NFT drop where only high-balance holders can participate,
///      reducing bot activity and ensuring genuine collector interest.
contract SolvencyGatedNFT {
    ISolvencyOracle public immutable oracle;
    bytes32 public immutable policyId;

    uint256 public totalMinted;
    uint256 public immutable maxSupply;
    uint256 public immutable mintPrice;

    mapping(uint256 => bytes32) public tokenOwner;
    mapping(bytes32 => bool) public hasMinted;

    event Minted(bytes32 indexed memberId, uint256 indexed tokenId);

    error NotSolvent(bytes32 memberId);
    error AlreadyMinted(bytes32 memberId);
    error MaxSupplyReached();
    error InsufficientPayment();

    constructor(
        address _oracle,
        bytes32 _policyId,
        uint256 _maxSupply,
        uint256 _mintPrice
    ) {
        oracle = ISolvencyOracle(_oracle);
        policyId = _policyId;
        maxSupply = _maxSupply;
        mintPrice = _mintPrice;
    }

    /// @notice Mint an NFT. Requires a solvency proof and payment.
    /// @param memberId    Member's privacy-preserving ID.
    /// @param epoch       Epoch of the solvency proof.
    /// @param merkleProof Sibling hashes from leaf to root.
    /// @param leafIndex   Position in the Merkle tree.
    /// @param rootIndex   Index in the oracle's root history.
    function mint(
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external payable {
        if (totalMinted >= maxSupply) revert MaxSupplyReached();
        if (msg.value < mintPrice) revert InsufficientPayment();
        if (hasMinted[memberId]) revert AlreadyMinted(memberId);

        bool solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch, merkleProof, leafIndex, rootIndex
        );
        if (!solvent) revert NotSolvent(memberId);

        uint256 tokenId = totalMinted++;
        tokenOwner[tokenId] = memberId;
        hasMinted[memberId] = true;

        emit Minted(memberId, tokenId);
    }
}
