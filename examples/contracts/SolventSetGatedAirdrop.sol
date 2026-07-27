// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolventSetOracle} from "../../contracts/src/interfaces/ISolventSetOracle.sol";

/// @title SolventSetGatedAirdrop
/// @notice Example: a one-claim-per-person airdrop gated on proven solvency,
///         using Privacy V2 membership proofs.
/// @dev This is the V2 counterpart to the {SolvencyGatedPool} example. The
///      difference is worth stating plainly, because it is the whole point of
///      V2:
///
///      In monitored mode the claimant enrolled with the agent, so the agent
///      knows which address it watches, and this contract is handed a
///      `memberId` that the caller already knew. Here the claimant never
///      enrolled and never told anyone their address. They downloaded the
///      public solvent set, found themselves in it locally, and produced a
///      zero-knowledge proof that *some* member of that set is claiming. This
///      contract learns only a nullifier hash.
///
///      Two properties make that nullifier usable as an identity:
///
///      1. **Deterministic** — one key yields exactly one nullifier per
///         policy, so a claimant cannot mint several identities to farm the
///         airdrop.
///      2. **Unlinkable across policies** — the same key produces an unrelated
///         nullifier under a different policy's scope, so participating here
///         does not deanonymize the claimant elsewhere.
///
///      Use case: "airdrop to wallets that have continuously held >= 10 ETH
///      for at least 3 epochs, one claim each, without anyone learning which
///      wallets claimed."
contract SolventSetGatedAirdrop {
    ISolventSetOracle public immutable oracle;
    bytes32 public immutable policyId;

    /// @notice Consecutive solvent epochs a claimant must prove.
    /// @dev The oracle enforces that the proof attests to *some* minimum; it
    ///      cannot know ours. Checking `minStreak >= requiredStreak` here is
    ///      what actually binds the claim to this protocol's rule — omitting
    ///      it would accept a proof attesting to a streak of 1.
    uint64 public immutable requiredStreak;

    uint256 public immutable amountPerClaim;

    /// @dev Nullifier consumption in the oracle is global across every
    ///      protocol using it. This contract additionally tracks its own
    ///      claims so its accounting does not depend on that shared state.
    mapping(bytes32 => bool) public claimed;
    uint256 public totalClaimed;

    event Claimed(bytes32 indexed nullifierHash, address indexed recipient, uint256 amount);

    error AlreadyClaimed(bytes32 nullifierHash);
    error StreakTooShort(uint64 proven, uint64 required);
    error AirdropExhausted();

    constructor(
        address _oracle,
        bytes32 _policyId,
        uint64 _requiredStreak,
        uint256 _amountPerClaim
    ) payable {
        oracle = ISolventSetOracle(_oracle);
        policyId = _policyId;
        requiredStreak = _requiredStreak;
        amountPerClaim = _amountPerClaim;
    }

    /// @notice Claim the airdrop by proving solvent-set membership.
    /// @dev `recipient` is an ordinary argument, deliberately unrelated to the
    ///      proven identity: the claimant proves that *a* solvent wallet is
    ///      claiming, then directs the payout wherever they like. Tying the
    ///      payout to the proving address would undo the unlinkability the
    ///      proof just bought.
    ///
    ///      `verifyAndConsume` reverts on an invalid proof, a root that is not
    ///      this policy's, a proof scoped to another policy, an expired root,
    ///      or a nullifier already spent — so no separate validity check is
    ///      needed here.
    /// @param setIndex     Index of the published set the proof targets.
    /// @param publicValues 224-byte ABI-encoded membership public values.
    /// @param proofBytes   SP1 Groth16 proof bytes.
    /// @param recipient    Where to send the claim.
    function claim(
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        address payable recipient
    ) external {
        if (address(this).balance < amountPerClaim) revert AirdropExhausted();

        (bytes32 nullifierHash, uint64 minStreak) =
            oracle.verifyAndConsume(policyId, setIndex, publicValues, proofBytes);

        if (minStreak < requiredStreak) {
            revert StreakTooShort(minStreak, requiredStreak);
        }
        if (claimed[nullifierHash]) revert AlreadyClaimed(nullifierHash);

        claimed[nullifierHash] = true;
        totalClaimed += amountPerClaim;

        emit Claimed(nullifierHash, recipient, amountPerClaim);

        (bool ok,) = recipient.call{value: amountPerClaim}("");
        require(ok, "transfer failed");
    }

    /// @notice Check eligibility without consuming the nullifier.
    /// @dev Uses the `view` path, so a front-end can preflight a claim without
    ///      spending the claimant's one shot. Reverts exactly as {claim} would
    ///      on an invalid proof.
    function checkEligible(
        uint256 setIndex,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view returns (bool eligible, bytes32 nullifierHash, uint64 minStreak) {
        (nullifierHash, minStreak) =
            oracle.verifyMembership(policyId, setIndex, publicValues, proofBytes);
        eligible = minStreak >= requiredStreak
            && !claimed[nullifierHash]
            && !oracle.isNullifierUsed(policyId, nullifierHash);
    }

    /// @notice Top up the airdrop pot.
    receive() external payable {}
}
