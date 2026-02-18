// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolvencyOracle} from "../../contracts/src/interfaces/ISolvencyOracle.sol";

/// @title SolvencyGatedGovernor
/// @notice Example: A DAO governance contract that requires solvency for voting.
/// @dev Demonstrates how governance protocols can use solvency proofs to ensure
///      only financially backed members can vote, preventing governance attacks
///      from underfunded wallets.
///
///      Use case: A DAO only allows voting from members who can prove they hold
///      >= threshold balance, ensuring "skin in the game" for governance decisions.
contract SolvencyGatedGovernor {
    ISolvencyOracle public immutable oracle;
    bytes32 public immutable policyId;

    struct Proposal {
        string description;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 deadline;
        bool executed;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(bytes32 => bool)) public hasVoted;

    event ProposalCreated(uint256 indexed proposalId, string description, uint256 deadline);
    event Voted(uint256 indexed proposalId, bytes32 indexed memberId, bool support);
    event ProposalExecuted(uint256 indexed proposalId);

    error NotSolvent(bytes32 memberId);
    error AlreadyVoted(uint256 proposalId, bytes32 memberId);
    error ProposalExpired(uint256 proposalId);
    error ProposalNotExpired(uint256 proposalId);

    constructor(address _oracle, bytes32 _policyId) {
        oracle = ISolvencyOracle(_oracle);
        policyId = _policyId;
    }

    /// @notice Create a new governance proposal.
    /// @param description Human-readable proposal description.
    /// @param durationBlocks Voting period in blocks.
    /// @return proposalId The ID of the created proposal.
    function createProposal(
        string calldata description,
        uint256 durationBlocks
    ) external returns (uint256 proposalId) {
        proposalId = proposalCount++;
        proposals[proposalId] = Proposal({
            description: description,
            votesFor: 0,
            votesAgainst: 0,
            deadline: block.number + durationBlocks,
            executed: false
        });
        emit ProposalCreated(proposalId, description, block.number + durationBlocks);
    }

    /// @notice Vote on a proposal. Requires a solvency proof.
    /// @param proposalId  ID of the proposal to vote on.
    /// @param support     True = vote for, false = vote against.
    /// @param memberId    Member's privacy-preserving ID.
    /// @param epoch       Epoch of the solvency proof.
    /// @param merkleProof Sibling hashes from leaf to root.
    /// @param leafIndex   Position in the Merkle tree.
    /// @param rootIndex   Index in the oracle's root history.
    function vote(
        uint256 proposalId,
        bool support,
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external {
        Proposal storage prop = proposals[proposalId];
        if (block.number > prop.deadline) revert ProposalExpired(proposalId);
        if (hasVoted[proposalId][memberId]) revert AlreadyVoted(proposalId, memberId);

        bool solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch, merkleProof, leafIndex, rootIndex
        );
        if (!solvent) revert NotSolvent(memberId);

        hasVoted[proposalId][memberId] = true;

        if (support) {
            prop.votesFor++;
        } else {
            prop.votesAgainst++;
        }

        emit Voted(proposalId, memberId, support);
    }

    /// @notice Get the current result of a proposal.
    function getProposalResult(uint256 proposalId)
        external
        view
        returns (uint256 votesFor, uint256 votesAgainst, bool passed)
    {
        Proposal storage prop = proposals[proposalId];
        return (prop.votesFor, prop.votesAgainst, prop.votesFor > prop.votesAgainst);
    }
}
