// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SolvencyRootOracle} from "../src/SolvencyRootOracle.sol";

/// @title Deploy
/// @notice Deployment script for the Solvency Agent contracts.
/// @dev Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
///
/// Environment variables:
///   DEPLOYER_PRIVATE_KEY  - Private key for the deployer account
///   SP1_VERIFIER_ADDRESS  - Address of the SP1 verifier contract (or 0x0 for trusted-only mode)
///   PROGRAM_VKEY          - SP1 program verification key (optional, defaults to 0x0)
contract DeployScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address sp1Verifier = vm.envOr("SP1_VERIFIER_ADDRESS", address(0));
        bytes32 programVKey = vm.envOr("PROGRAM_VKEY", bytes32(0));

        vm.startBroadcast(deployerKey);

        PolicyRegistry registry = new PolicyRegistry();
        console.log("PolicyRegistry deployed at:", address(registry));

        SolvencyRootOracle oracle = new SolvencyRootOracle(
            address(registry),
            sp1Verifier,
            programVKey
        );
        console.log("SolvencyRootOracle deployed at:", address(oracle));

        vm.stopBroadcast();
    }
}
