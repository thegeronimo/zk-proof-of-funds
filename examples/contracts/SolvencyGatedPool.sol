// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolvencyOracle} from "../../contracts/src/interfaces/ISolvencyOracle.sol";

/// @title SolvencyGatedPool
/// @notice Example: A DeFi liquidity pool that requires solvency proof for deposits.
/// @dev Demonstrates how a lending/LP protocol can use the ISolvencyOracle interface
///      to gate deposits behind solvency verification.
///
///      Use case: A lending protocol only accepts deposits from users who can prove
///      they hold >= threshold balance, reducing counterparty risk.
contract SolvencyGatedPool {
    ISolvencyOracle public immutable oracle;
    bytes32 public immutable policyId;

    mapping(bytes32 => uint256) public deposits;
    uint256 public totalDeposits;

    event Deposited(bytes32 indexed memberId, uint256 amount);
    event Withdrawn(bytes32 indexed memberId, uint256 amount);

    error NotSolvent(bytes32 memberId);
    error InsufficientBalance(bytes32 memberId, uint256 requested, uint256 available);

    constructor(address _oracle, bytes32 _policyId) {
        oracle = ISolvencyOracle(_oracle);
        policyId = _policyId;
    }

    /// @notice Deposit ETH into the pool. Requires a solvency proof.
    /// @param memberId    Member's privacy-preserving ID.
    /// @param epoch       Epoch of the solvency proof.
    /// @param merkleProof Sibling hashes from leaf to root.
    /// @param leafIndex   Position in the Merkle tree.
    /// @param rootIndex   Index in the oracle's root history.
    function deposit(
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external payable {
        bool solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch, merkleProof, leafIndex, rootIndex
        );
        if (!solvent) revert NotSolvent(memberId);

        deposits[memberId] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(memberId, msg.value);
    }

    /// @notice Withdraw deposited ETH. No solvency proof needed for withdrawals.
    /// @param memberId Member's privacy-preserving ID.
    /// @param amount   Amount in wei to withdraw.
    function withdraw(bytes32 memberId, uint256 amount) external {
        uint256 balance = deposits[memberId];
        if (amount > balance) {
            revert InsufficientBalance(memberId, amount, balance);
        }

        deposits[memberId] -= amount;
        totalDeposits -= amount;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
        emit Withdrawn(memberId, amount);
    }
}
