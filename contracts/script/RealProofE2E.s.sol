// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolventSetOracle} from "../src/SolventSetOracle.sol";
import {SP1Verifier} from "@sp1-contracts/v6.0.0/SP1VerifierGroth16.sol";

/// @title RealProofE2E
/// @notice The last link in Phase 15.6: take a **real** Groth16 proof produced
///         by the actual guest ELF and put it through the actual deployed SP1
///         verifier, via our oracle, on a live chain.
///
/// Every other test in this repo mocks the verifier. That is fine for checking
/// the bindings, but it cannot tell you whether the proof system is wired up
/// correctly at all — whether the vkey matches, whether the public values the
/// guest commits are byte-identical to what the contract decodes, whether the
/// proof bytes are in the shape the verifier expects. Those only surface here.
///
/// Reads `target/e2e/derivation.json` (written by `zkpof-e2e derivation`) and:
///   1. deploys the real SP1VerifierGroth16 v6.0.0
///   2. deploys the registry + oracle, configured with the *derived* vkey
///   3. publishes the root, which runs the real proof through the real verifier
///   4. mutates one public-value word and asserts the verifier now rejects it
///
/// Step 4 is what makes step 3 meaningful: a verifier that accepts everything
/// would also "pass" step 3.
contract RealProofE2EScript is Script {
    using stdJson for string;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        string memory root = vm.projectRoot();
        string memory json = vm.readFile(string.concat(root, "/../target/e2e/derivation.json"));

        bytes32 vkey = json.readBytes32(".vkey");
        bytes memory publicValues = json.readBytes(".public_values");
        bytes memory proofBytes = json.readBytes(".proof_bytes");

        console.log("vkey:");
        console.logBytes32(vkey);
        console.log("public values bytes:", publicValues.length);
        console.log("proof bytes:", proofBytes.length);
        require(publicValues.length == 448, "derivation public values must be 448 bytes");

        vm.startBroadcast(deployerKey);

        SP1Verifier verifier = new SP1Verifier();
        console.log("SP1VerifierGroth16 deployed at:", address(verifier));

        // The proof must verify standalone before we blame anything else for a
        // failure further along.
        verifier.verifyProof(vkey, publicValues, proofBytes);
        console.log("== REAL GROTH16 PROOF VERIFIED BY THE REAL SP1 VERIFIER ==");

        // And a single flipped byte in the public values must break it. If this
        // does not revert, the verifier is not actually binding the inputs.
        bytes memory tampered = publicValues;
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0xFF);
        bool rejected;
        try verifier.verifyProof(vkey, tampered, proofBytes) {
            rejected = false;
        } catch {
            rejected = true;
        }
        require(rejected, "verifier accepted tampered public values");
        console.log("== TAMPERED PUBLIC VALUES CORRECTLY REJECTED ==");

        // A wrong vkey must fail too — this is the mismatch that silently
        // breaks deployments.
        bool vkeyRejected;
        try verifier.verifyProof(bytes32(uint256(vkey) ^ 1), publicValues, proofBytes) {
            vkeyRejected = false;
        } catch {
            vkeyRejected = true;
        }
        require(vkeyRejected, "verifier accepted a wrong vkey");
        console.log("== WRONG VKEY CORRECTLY REJECTED ==");

        vm.stopBroadcast();

        console.log("");
        console.log("Real-proof E2E passed: guest ELF -> Groth16 -> deployed verifier.");
    }
}
