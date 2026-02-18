// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title MockSP1Verifier
/// @notice Mock SP1 verifier for testing. Can be configured to pass or fail.
contract MockSP1Verifier is ISP1Verifier {
    bool public shouldPass = true;

    error MockVerifierRejected();

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verifyProof(
        bytes32, /* programVKey */
        bytes calldata, /* publicValues */
        bytes calldata  /* proofBytes */
    ) external view override {
        if (!shouldPass) revert MockVerifierRejected();
    }
}
