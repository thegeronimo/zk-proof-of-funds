// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolventSetOracle} from "../src/SolventSetOracle.sol";
import {MockSP1Verifier} from "./mocks/MockSP1Verifier.sol";

/// @dev Same blockhash-injecting harness the unit suite uses.
contract E2EOracle is SolventSetOracle {
    mapping(uint64 => bytes32) private _hashes;

    constructor(address r, address v, bytes32 m, bytes32 d, bytes32 s)
        SolventSetOracle(r, v, m, d, s)
    {}

    function setBlockhash(uint64 blockNumber, bytes32 hash) external {
        _hashes[blockNumber] = hash;
    }

    function _blockhash(uint64 blockNumber) internal view override returns (bytes32) {
        return _hashes[blockNumber];
    }
}

/// @title End-to-end mutation matrix
/// @notice Phase 15.6's central question: **is every field actually bound?**
///
/// A test suite that only ever feeds valid input cannot distinguish a real
/// verifier from a stub. So this establishes one known-good publication and
/// one known-good membership verification, then walks the public-values blob
/// mutating exactly one field at a time and asserts each mutation is
/// rejected. A mutation that still succeeds means that field is decorative —
/// committed by the circuit but unchecked by the contract, which is precisely
/// the class of bug the external review found (`numBlocks` was decoded and
/// discarded; the presentation context did not exist at all).
///
/// The SNARK itself is mocked here: local Groth16 wrapping needs Docker and
/// ~16 GB of RAM, so `scripts/real-proof-e2e.sh` covers that leg separately.
/// Everything *around* the SNARK — decode, bind, compare, store — is the same
/// code a real proof travels through, and that is what these mutations probe.
contract E2EMutationTest is Test {
    PolicyRegistry registry;
    E2EOracle oracle;
    MockSP1Verifier verifier;

    address operatorAddr;
    bytes32 constant POLICY_ID = bytes32(uint256(0xE2E));
    bytes32 constant STATE_ROOT = bytes32(uint256(0x57A7E));
    bytes32 constant SET_ROOT = bytes32(uint256(0xABCD));
    bytes32 constant CANDIDATES_ROOT = bytes32(uint256(0xCA4D));
    bytes32 constant NULLIFIER = bytes32(uint256(0xFEED));
    bytes32 constant ACTION_ID = bytes32(uint256(0xAC10));
    uint64 constant EPOCH_LEN = 100;
    uint64 constant ROOT_TTL = 5000;
    uint256 constant THRESHOLD = 1 ether;

    // The known-good publication, established in setUp.
    uint64 refBlock;
    bytes headerRlp;
    bytes goodDerivation;
    bytes goodMembership;

    function setUp() public {
        operatorAddr = makeAddr("operator");
        registry = new PolicyRegistry();
        verifier = new MockSP1Verifier();
        oracle = new E2EOracle(
            address(registry), address(verifier), bytes32(0), bytes32(0), bytes32(0)
        );
        registry.setFreezer(address(oracle));
        registry.createPolicy(
            POLICY_ID,
            PolicyRegistry.Policy({
                thresholdWei: THRESHOLD,
                tokenAddress: address(0),
                chainId: uint64(block.chainid),
                epochLengthBlocks: EPOCH_LEN,
                maxBlockAge: 256,
                rootTTLBlocks: ROOT_TTL,
                operator: operatorAddr,
                scope: "e2e-scope",
                trustedMode: false,
                active: true,
                startBlock: 0,
                version: 1
            })
        );

        // Close epoch 1's window and register the sampling entropy.
        uint64 windowEnd = 2 * EPOCH_LEN;
        vm.roll(windowEnd + 20);
        oracle.setBlockhash(windowEnd, keccak256("e2e-entropy"));

        refBlock = oracle.sampledReferenceBlock(POLICY_ID, 1);
        headerRlp = _header(STATE_ROOT);
        oracle.setBlockhash(refBlock, keccak256(headerRlp));

        goodDerivation = _derivation(
            STATE_ROOT, bytes32(0), SET_ROOT, POLICY_ID, 1, refBlock, 0,
            uint64(block.chainid), THRESHOLD, address(0), 0, CANDIDATES_ROOT
        );
        goodMembership = _membership(
            SET_ROOT, POLICY_ID, 1, NULLIFIER, uint64(block.chainid), 2,
            oracle.effectiveScopeHash(POLICY_ID), oracle.policyConfigHash(POLICY_ID),
            address(oracle), uint64(block.chainid), ACTION_ID, address(this),
            1, uint64(block.number + 500)
        );
    }

    // ── Encoders ────────────────────────────────────────────────────────

    function _header(bytes32 stateRoot) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"f90200",
            hex"a0", bytes32(uint256(0x1111)),
            hex"a0", bytes32(uint256(0x2222)),
            hex"94", bytes20(uint160(0x3333)),
            hex"a0", stateRoot
        );
    }

    struct Derivation {
        bytes32 stateRoot;
        bytes32 prevRoot;
        bytes32 newRoot;
        bytes32 policyId;
        uint64 epoch;
        uint64 blockNumber;
        uint64 prevBlockNumber;
        uint64 chainId;
        uint256 thresholdWei;
        address token;
        uint64 balanceSlot;
        bytes32 candidatesRoot;
    }

    function _derivation(
        bytes32 stateRoot,
        bytes32 prevRoot,
        bytes32 newRoot,
        bytes32 policyId,
        uint64 epoch,
        uint64 blockNumber,
        uint64 prevBlockNumber,
        uint64 chainId,
        uint256 thresholdWei,
        address token,
        uint64 balanceSlot,
        bytes32 candidatesRoot
    ) internal pure returns (bytes memory) {
        return abi.encode(
            stateRoot, prevRoot, newRoot, policyId, epoch, blockNumber, prevBlockNumber,
            chainId, thresholdWei, uint32(3), uint32(5), token, balanceSlot, candidatesRoot
        );
    }

    function _membership(
        bytes32 root,
        bytes32 policyId,
        uint64 epoch,
        bytes32 nullifierHash,
        uint64 chainId,
        uint64 minStreak,
        bytes32 scopeHash,
        bytes32 configHash,
        address verifierAddr,
        uint64 verifierChainId,
        bytes32 actionId,
        address beneficiary,
        uint64 nonce,
        uint64 deadline
    ) internal pure returns (bytes memory) {
        return abi.encode(
            root, policyId, epoch, nullifierHash, chainId, minStreak, scopeHash,
            configHash, verifierAddr, verifierChainId, actionId, beneficiary, nonce, deadline
        );
    }

    /// Replace the 32-byte word at `wordIndex` — the mutation primitive. Every
    /// public value is exactly one word, so this reaches all of them.
    function _mutateWord(bytes memory blob, uint256 wordIndex, bytes32 value)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory out = bytes.concat(blob);
        uint256 offset = 32 + wordIndex * 32; // skip the memory length slot
        assembly {
            mstore(add(out, offset), value)
        }
        return out;
    }

    // ── The known-good baseline ─────────────────────────────────────────

    /// Everything below is only meaningful if the unmutated path succeeds —
    /// otherwise the mutations would "pass" for the wrong reason.
    function test_Baseline_PublishAndVerifySucceed() public {
        oracle.publishRootProven(POLICY_ID, headerRlp, goodDerivation, hex"");
        assertEq(oracle.getSetCount(POLICY_ID), 1, "publication must succeed");

        (bytes32 nullifier, uint64 minStreak) =
            oracle.verifyMembership(POLICY_ID, 0, goodMembership, hex"");
        assertEq(nullifier, NULLIFIER);
        assertEq(minStreak, 2);

        SolventSetOracle.SetEntry memory entry = oracle.getSetEntry(POLICY_ID, 0);
        assertEq(entry.root, SET_ROOT);
        assertEq(entry.blockNumber, refBlock);
        assertTrue(entry.provenance == SolventSetOracle.Provenance.BalancesProven);
        assertEq(entry.policyConfigHash, oracle.policyConfigHash(POLICY_ID));
    }

    // ── Mutation matrix: derivation public values ───────────────────────

    /// Word indices of the derivation blob, for readability.
    uint256 constant D_STATE_ROOT = 0;
    uint256 constant D_PREV_ROOT = 1;
    uint256 constant D_NEW_ROOT = 2;
    uint256 constant D_POLICY_ID = 3;
    uint256 constant D_EPOCH = 4;
    uint256 constant D_BLOCK = 5;
    uint256 constant D_PREV_BLOCK = 6;
    uint256 constant D_CHAIN_ID = 7;
    uint256 constant D_THRESHOLD = 8;
    uint256 constant D_TOKEN = 11;
    uint256 constant D_BALANCE_SLOT = 12;
    uint256 constant D_CANDIDATES_ROOT = 13;

    function _assertPublishReverts(bytes memory mutated, string memory field) internal {
        vm.expectRevert();
        oracle.publishRootProven(POLICY_ID, headerRlp, mutated, hex"");
        // A revert with no reason would also satisfy expectRevert, so confirm
        // nothing was written either way.
        assertEq(oracle.getSetCount(POLICY_ID), 0, field);
    }

    function test_Mutate_Derivation_StateRoot() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_STATE_ROOT, bytes32(uint256(0xBAD))), "stateRoot"
        );
    }

    function test_Mutate_Derivation_PrevRoot() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_PREV_ROOT, bytes32(uint256(0xBAD))), "prevRoot"
        );
    }

    function test_Mutate_Derivation_NewRootToZero() public {
        _assertPublishReverts(_mutateWord(goodDerivation, D_NEW_ROOT, bytes32(0)), "newRoot=0");
    }

    function test_Mutate_Derivation_PolicyId() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_POLICY_ID, bytes32(uint256(0xDEAD))), "policyId"
        );
    }

    function test_Mutate_Derivation_Epoch() public {
        _assertPublishReverts(_mutateWord(goodDerivation, D_EPOCH, bytes32(uint256(7))), "epoch");
    }

    /// The sampled-block binding: any other reference block must fail.
    function test_Mutate_Derivation_BlockNumber() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_BLOCK, bytes32(uint256(refBlock + 1))), "blockNumber"
        );
    }

    /// The streak-replay defence: prevBlockNumber must match the stored entry.
    function test_Mutate_Derivation_PrevBlockNumber() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_PREV_BLOCK, bytes32(uint256(1))), "prevBlockNumber"
        );
    }

    function test_Mutate_Derivation_ChainId() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_CHAIN_ID, bytes32(uint256(block.chainid + 1))), "chainId"
        );
    }

    function test_Mutate_Derivation_Threshold() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_THRESHOLD, bytes32(THRESHOLD + 1)), "thresholdWei"
        );
    }

    function test_Mutate_Derivation_Token() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_TOKEN, bytes32(uint256(uint160(0xBEEF)))), "token"
        );
    }

    function test_Mutate_Derivation_BalanceSlot() public {
        _assertPublishReverts(
            _mutateWord(goodDerivation, D_BALANCE_SLOT, bytes32(uint256(9))), "balanceSlot"
        );
    }

    /// candidatesRoot is only bound on the completeness path; on the plain
    /// proven path it is carried but not compared. Asserting the *actual*
    /// behaviour keeps the matrix honest rather than implying coverage that
    /// does not exist — the completeness case is covered separately in
    /// SolventSetOracle.t.sol's CandidatesNotCovered test.
    function test_Mutate_Derivation_CandidatesRoot_UnboundOnPlainPath() public {
        bytes memory mutated =
            _mutateWord(goodDerivation, D_CANDIDATES_ROOT, bytes32(uint256(0xF00D)));
        oracle.publishRootProven(POLICY_ID, headerRlp, mutated, hex"");
        assertEq(
            oracle.getSetCount(POLICY_ID), 1,
            "documented: candidatesRoot binds only via publishRootProvenComplete"
        );
    }

    /// The header must hash to the sampled block's hash.
    function test_Mutate_Header() public {
        bytes memory forged = _header(bytes32(uint256(0xE711)));
        vm.expectRevert();
        oracle.publishRootProven(POLICY_ID, forged, goodDerivation, hex"");
        assertEq(oracle.getSetCount(POLICY_ID), 0);
    }

    /// And the proof itself must verify.
    function test_Mutate_ProofRejectedByVerifier() public {
        verifier.setShouldPass(false);
        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.publishRootProven(POLICY_ID, headerRlp, goodDerivation, hex"");
        assertEq(oracle.getSetCount(POLICY_ID), 0);
    }

    // ── Mutation matrix: membership public values ───────────────────────

    uint256 constant M_ROOT = 0;
    uint256 constant M_POLICY_ID = 1;
    uint256 constant M_EPOCH = 2;
    uint256 constant M_CHAIN_ID = 4;
    uint256 constant M_SCOPE = 6;
    uint256 constant M_CONFIG_HASH = 7;
    uint256 constant M_VERIFIER = 8;
    uint256 constant M_VERIFIER_CHAIN = 9;
    uint256 constant M_BENEFICIARY = 11;
    uint256 constant M_DEADLINE = 13;

    function _publishBaseline() internal {
        oracle.publishRootProven(POLICY_ID, headerRlp, goodDerivation, hex"");
    }

    function _assertVerifyReverts(bytes memory mutated) internal {
        _publishBaseline();
        vm.expectRevert();
        oracle.verifyMembership(POLICY_ID, 0, mutated, hex"");
    }

    function test_Mutate_Membership_Root() public {
        _assertVerifyReverts(_mutateWord(goodMembership, M_ROOT, bytes32(uint256(0xBAD))));
    }

    function test_Mutate_Membership_PolicyId() public {
        _assertVerifyReverts(_mutateWord(goodMembership, M_POLICY_ID, bytes32(uint256(0xBAD))));
    }

    function test_Mutate_Membership_Epoch() public {
        _assertVerifyReverts(_mutateWord(goodMembership, M_EPOCH, bytes32(uint256(99))));
    }

    function test_Mutate_Membership_ChainId() public {
        _assertVerifyReverts(
            _mutateWord(goodMembership, M_CHAIN_ID, bytes32(uint256(block.chainid + 1)))
        );
    }

    function test_Mutate_Membership_Scope() public {
        _assertVerifyReverts(_mutateWord(goodMembership, M_SCOPE, bytes32(uint256(0x5C0BAD))));
    }

    function test_Mutate_Membership_ConfigHash() public {
        _assertVerifyReverts(_mutateWord(goodMembership, M_CONFIG_HASH, bytes32(uint256(0xC0BAD))));
    }

    function test_Mutate_Membership_Verifier() public {
        _assertVerifyReverts(
            _mutateWord(goodMembership, M_VERIFIER, bytes32(uint256(uint160(0xBEEF))))
        );
    }

    function test_Mutate_Membership_VerifierChainId() public {
        _assertVerifyReverts(
            _mutateWord(goodMembership, M_VERIFIER_CHAIN, bytes32(uint256(block.chainid + 1)))
        );
    }

    function test_Mutate_Membership_DeadlinePassed() public {
        _publishBaseline();
        bytes memory mutated =
            _mutateWord(goodMembership, M_DEADLINE, bytes32(uint256(block.number - 1)));
        vm.expectRevert();
        oracle.verifyMembership(POLICY_ID, 0, mutated, hex"");
    }

    /// The front-running defence: consuming requires being the named
    /// beneficiary. verifyMembership itself does not check it (a view caller
    /// may inspect any proof), so this asserts the consume path specifically.
    function test_Mutate_Membership_BeneficiaryBlocksConsume() public {
        _publishBaseline();
        bytes memory mutated = _mutateWord(
            goodMembership, M_BENEFICIARY, bytes32(uint256(uint160(makeAddr("attacker"))))
        );
        vm.expectRevert();
        oracle.verifyAndConsume(POLICY_ID, 0, mutated, hex"");
    }

    function test_Mutate_Membership_ProofRejectedByVerifier() public {
        _publishBaseline();
        verifier.setShouldPass(false);
        vm.expectRevert(MockSP1Verifier.MockVerifierRejected.selector);
        oracle.verifyMembership(POLICY_ID, 0, goodMembership, hex"");
    }

    /// Rotating the oracle's live vkey must not change how an already-stored
    /// root verifies — the entry pins the key it was published under.
    function test_VKeyRotationDoesNotAffectStoredRoot() public {
        _publishBaseline();
        bytes32 pinned = oracle.getSetEntry(POLICY_ID, 0).membershipVKey;
        oracle.setMembershipVKey(bytes32(uint256(0xABCDEF)));
        assertEq(oracle.getSetEntry(POLICY_ID, 0).membershipVKey, pinned);
        // ...and the proof still verifies against the pinned key.
        oracle.verifyMembership(POLICY_ID, 0, goodMembership, hex"");
    }
}
