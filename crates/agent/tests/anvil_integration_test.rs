//! Integration tests against a live Anvil local Ethereum node.
//!
//! These tests deploy contracts to Anvil, run the full Rust pipeline,
//! and verify cross-validated EIP-712 signatures and Merkle proofs
//! between Rust and Solidity.
//!
//! All tests are `#[ignore]` so `cargo test` skips them by default.
//! Run explicitly with:
//! ```bash
//! cargo test --test anvil_integration_test -- --ignored
//! ```
//!
//! Requirements: `anvil` and `forge` must be installed and on PATH.

use std::process::Command;
use std::sync::{Arc, Mutex};

use alloy::node_bindings::Anvil;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;

use sha2::{Sha256, Digest};

use zk_pof_agent::chain_publisher::OnChainPublisher;
use zk_pof_agent::db::Database;
use zk_pof_agent::epoch_processor::EpochProcessor;
use zk_pof_agent::proof_worker::ProofWorker;
use zk_pof_agent::rpc_fetcher::RpcFetcher;
use zk_pof_agent::scheduler::EpochTrigger;
use zk_pof_agent::webhook::WebhookService;

// ─── Contract ABI Bindings ──────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    contract PolicyRegistry {
        struct Policy {
            uint256 thresholdWei;
            address tokenAddress;
            uint64 chainId;
            uint64 epochLengthBlocks;
            uint64 maxBlockAge;
            uint64 rootTTLBlocks;
            address operator;
            string scope;
            bool trustedMode;
            bool active;
        }

        function createPolicy(bytes32 policyId, Policy memory policy) external;
        function getPolicy(bytes32 policyId) external view returns (Policy memory);
        function policyExists(bytes32 policyId) external view returns (bool);
    }

    #[sol(rpc)]
    contract SolvencyRootOracle {
        struct RootEntry {
            bytes32 root;
            uint64 epoch;
            uint64 blockNumber;
            uint64 publishedAt;
            uint32 memberCount;
        }

        function getRootCount(bytes32 policyId) external view returns (uint256);
        function getRootEntry(bytes32 policyId, uint256 rootIndex) external view returns (RootEntry memory);
        function verifyMember(
            bytes32 policyId,
            bytes32 memberId,
            uint8 status,
            uint64 epoch,
            bytes32[] calldata merkleProof,
            uint256 leafIndex,
            uint256 rootIndex
        ) external view returns (bool);
        function isMemberSolvent(
            bytes32 policyId,
            bytes32 memberId,
            uint64 epoch,
            bytes32[] calldata merkleProof,
            uint256 leafIndex,
            uint256 rootIndex
        ) external view returns (bool);
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Parse deployed contract addresses from forge broadcast JSON.
fn parse_deployed_addresses(project_root: &str) -> (Address, Address) {
    let broadcast_path = format!(
        "{}/contracts/broadcast/Deploy.s.sol/31337/run-latest.json",
        project_root
    );

    let content = std::fs::read_to_string(&broadcast_path)
        .unwrap_or_else(|e| panic!("Failed to read broadcast JSON at {}: {}", broadcast_path, e));

    let json: serde_json::Value = serde_json::from_str(&content)
        .expect("Failed to parse broadcast JSON");

    let transactions = json["transactions"]
        .as_array()
        .expect("No transactions in broadcast JSON");

    let mut registry_addr: Option<Address> = None;
    let mut oracle_addr: Option<Address> = None;

    for tx in transactions {
        let contract_name = tx["contractName"].as_str().unwrap_or("");
        let contract_address = tx["contractAddress"].as_str().unwrap_or("");
        let tx_type = tx["transactionType"].as_str().unwrap_or("");

        if tx_type == "CREATE" {
            let addr: Address = contract_address.parse().unwrap();
            match contract_name {
                "PolicyRegistry" => registry_addr = Some(addr),
                "SolvencyRootOracle" => oracle_addr = Some(addr),
                _ => {}
            }
        }
    }

    (
        registry_addr.expect("PolicyRegistry not found in broadcast"),
        oracle_addr.expect("SolvencyRootOracle not found in broadcast"),
    )
}

/// Deploy contracts to Anvil using forge script.
fn deploy_contracts(rpc_url: &str, deployer_key_hex: &str, project_root: &str) -> (Address, Address) {
    // Deploy.s.sol uses vm.envUint which expects "0x" prefix
    let key_with_prefix = if deployer_key_hex.starts_with("0x") {
        deployer_key_hex.to_string()
    } else {
        format!("0x{}", deployer_key_hex)
    };

    let output = Command::new("forge")
        .current_dir(format!("{}/contracts", project_root))
        .args([
            "script",
            "script/Deploy.s.sol",
            "--rpc-url", rpc_url,
            "--broadcast",
            "--skip-simulation",
        ])
        .env("DEPLOYER_PRIVATE_KEY", &key_with_prefix)
        .env("SP1_VERIFIER_ADDRESS", "0x0000000000000000000000000000000000000000")
        .env("PROGRAM_VKEY", "0x0000000000000000000000000000000000000000000000000000000000000000")
        .output()
        .expect("Failed to run forge script");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "forge script failed:\nstdout: {}\nstderr: {}",
            stdout, stderr
        );
    }

    parse_deployed_addresses(project_root)
}

/// Compute a deterministic member ID from a seed (matches test helpers).
fn make_member_id(seed: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([seed]);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Get the project root directory.
fn project_root() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // crates/agent -> project root
    std::path::Path::new(manifest_dir)
        .parent().unwrap()
        .parent().unwrap()
        .to_str().unwrap()
        .to_string()
}

// ─── Test Cases ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_anvil_deploy_and_create_policy() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, _oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    // Connect to Anvil
    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    let registry = PolicyRegistry::new(registry_addr, &provider);

    // Create a policy
    let policy_id = FixedBytes::from([0x01u8; 32]);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "test-scope".to_string(),
        trustedMode: true,
        active: true,
    };

    let tx = registry.createPolicy(policy_id, policy).send().await.unwrap();
    let receipt = tx.get_receipt().await.unwrap();
    assert!(receipt.status());

    // Verify policy exists
    let exists = registry.policyExists(policy_id).call().await.unwrap();
    assert!(exists, "Policy should exist after creation");

    // Verify getPolicy returns correct values
    let stored = registry.getPolicy(policy_id).call().await.unwrap();
    assert_eq!(stored.operator, signer.address());
    assert!(stored.trustedMode);
    assert!(stored.active);
}

#[tokio::test]
#[ignore]
async fn test_anvil_full_epoch_pipeline() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    // Create operator signer (same as deployer for tests)
    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Create policy
    let policy_id = [0x01u8; 32];
    let policy_id_hex = hex::encode(policy_id);
    let policy_id_fb = FixedBytes::from(policy_id);
    let threshold = 1_000_000_000_000_000_000u128; // 1 ETH

    let registry = PolicyRegistry::new(registry_addr, &provider);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(threshold),
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "test-scope".to_string(),
        trustedMode: true,
        active: true,
    };
    registry.createPolicy(policy_id_fb, policy).send().await.unwrap().get_receipt().await.unwrap();

    // Set up agent components
    let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));
    let oracle_addr_hex = format!("{:?}", oracle_addr);
    let proof_worker = Arc::new(
        ProofWorker::new(&deployer_key, 31337, &oracle_addr_hex).unwrap()
    );
    let publisher = Arc::new(
        OnChainPublisher::new(
            db.clone(),
            &rpc_url,
            &deployer_key,
            &oracle_addr_hex,
            31337,
        ).unwrap()
    );
    let webhook_svc = Arc::new(WebhookService::new(db.clone()));

    // Enroll 3 members using Anvil pre-funded accounts as watch targets
    let member_a = make_member_id(0xAA);
    let member_b = make_member_id(0xBB);
    let member_c = make_member_id(0xCC);

    // Use Anvil accounts 1, 2, 3 as watch targets (each has 10000 ETH)
    let watch_a = format!("{:?}", anvil.addresses()[1]);
    let watch_b = format!("{:?}", anvil.addresses()[2]);
    let watch_c = format!("{:?}", anvil.addresses()[3]);

    // Fetch real balances from Anvil
    let rpc_fetcher = RpcFetcher::new(&rpc_url).unwrap();
    let balance_a = rpc_fetcher.get_balance(&watch_a).await.unwrap();
    let balance_b = rpc_fetcher.get_balance(&watch_b).await.unwrap();

    // For member C, we'll set a low balance by not using a funded account
    // Actually all Anvil accounts are funded with 10000 ETH.
    // We'll just set member C's stored balance low in the DB to simulate insolvency.

    let block_number = rpc_fetcher.get_block_number().await.unwrap();

    {
        let db = db.lock().unwrap();
        db.insert_member(&hex::encode(member_a), &watch_a, &policy_id_hex, 1700000000, 1).unwrap();
        db.insert_member(&hex::encode(member_b), &watch_b, &policy_id_hex, 1700000000, 1).unwrap();
        db.insert_member(&hex::encode(member_c), &watch_c, &policy_id_hex, 1700000000, 1).unwrap();

        // Store real balance for A & B (solvent), low balance for C (insolvent)
        db.update_member_status(&hex::encode(member_a), "pending", &balance_a.to_string(), block_number).unwrap();
        db.update_member_status(&hex::encode(member_b), "pending", &balance_b.to_string(), block_number).unwrap();
        db.update_member_status(&hex::encode(member_c), "pending", "500000000000000000", block_number).unwrap(); // 0.5 ETH
    }

    // Process epoch with skip_on_chain = false (real on-chain submission!)
    let processor = EpochProcessor::new(
        db.clone(), proof_worker, publisher, webhook_svc, false,
    );

    let trigger = EpochTrigger {
        policy_id_hex: policy_id_hex.clone(),
        policy_id,
        epoch: 1,
        block_number,
        threshold_wei: threshold,
        trusted_mode: true,
    };

    let result = processor.process_epoch(&trigger).await.unwrap();

    assert_eq!(result.epoch, 1);
    assert_eq!(result.member_count, 3);
    assert!(result.tx_hash.is_some(), "Should have a real tx hash");

    // Verify on-chain
    let oracle = SolvencyRootOracle::new(oracle_addr, &provider);
    let root_count = oracle.getRootCount(policy_id_fb).call().await.unwrap();
    assert_eq!(root_count, U256::from(1u64));

    let entry = oracle.getRootEntry(policy_id_fb, U256::from(0u64)).call().await.unwrap();
    assert_eq!(entry.epoch, 1);
    assert_eq!(entry.memberCount, 3);
}

#[tokio::test]
#[ignore]
async fn test_anvil_eip712_cross_validation() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Create trusted mode policy
    let policy_id = [0x02u8; 32];
    let policy_id_fb = FixedBytes::from(policy_id);
    let registry = PolicyRegistry::new(registry_addr, &provider);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(1_000_000_000_000_000_000u128),
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "cross-val".to_string(),
        trustedMode: true,
        active: true,
    };
    registry.createPolicy(policy_id_fb, policy).send().await.unwrap().get_receipt().await.unwrap();

    // Sign via Rust ProofWorker
    let oracle_addr_hex = format!("{:?}", oracle_addr);
    let proof_worker = ProofWorker::new(&deployer_key, 31337, &oracle_addr_hex).unwrap();

    let test_root = [0xAB; 32];
    let block_number = provider.get_block_number().await.unwrap();
    let epoch = 1u64;
    let member_count = 5u32;

    let sig_result = proof_worker.sign_trusted_assertion(
        &policy_id,
        &test_root,
        epoch,
        block_number,
        member_count,
    ).await.unwrap();

    // Submit to Solidity updateRootTrusted — if Rust and Solidity EIP-712 match, this succeeds
    // We need to call updateRootTrusted directly
    sol! {
        #[sol(rpc)]
        contract OracleWriter {
            function updateRootTrusted(
                bytes32 policyId,
                bytes32 newRoot,
                uint64 epoch,
                uint64 blockNumber,
                uint32 memberCount,
                bytes calldata signature
            ) external;
        }
    }

    let oracle_writer = OracleWriter::new(oracle_addr, &provider);
    let tx = oracle_writer.updateRootTrusted(
        policy_id_fb,
        FixedBytes::from(test_root),
        epoch,
        block_number,
        member_count,
        alloy::primitives::Bytes::from(sig_result.signature),
    ).send().await.unwrap();

    let receipt = tx.get_receipt().await.unwrap();
    assert!(receipt.status(), "updateRootTrusted should succeed — proves EIP-712 cross-validation");

    // Verify root was stored
    let oracle = SolvencyRootOracle::new(oracle_addr, &provider);
    let count = oracle.getRootCount(policy_id_fb).call().await.unwrap();
    assert_eq!(count, U256::from(1u64));
}

#[tokio::test]
#[ignore]
async fn test_anvil_merkle_proof_onchain() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Create policy
    let policy_id = [0x03u8; 32];
    let policy_id_fb = FixedBytes::from(policy_id);
    let registry = PolicyRegistry::new(registry_addr, &provider);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(1_000_000_000_000_000_000u128),
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "merkle-test".to_string(),
        trustedMode: true,
        active: true,
    };
    registry.createPolicy(policy_id_fb, policy).send().await.unwrap().get_receipt().await.unwrap();

    // Build a 5-member Merkle tree in Rust
    let epoch = 1u64;
    let members: Vec<[u8; 32]> = (0..5).map(|i| make_member_id(i)).collect();
    let leaves: Vec<[u8; 32]> = members.iter()
        .map(|m| zk_pof_common::merkle::compute_leaf(m, 1, epoch, &policy_id))
        .collect();
    let merkle_root = zk_pof_common::merkle::compute_root(&leaves);

    // Sign and submit the root
    let oracle_addr_hex = format!("{:?}", oracle_addr);
    let proof_worker = ProofWorker::new(&deployer_key, 31337, &oracle_addr_hex).unwrap();
    let block_number = provider.get_block_number().await.unwrap();

    let sig = proof_worker.sign_trusted_assertion(
        &policy_id, &merkle_root, epoch, block_number, 5,
    ).await.unwrap();

    sol! {
        #[sol(rpc)]
        contract OracleWriter2 {
            function updateRootTrusted(
                bytes32 policyId,
                bytes32 newRoot,
                uint64 epoch,
                uint64 blockNumber,
                uint32 memberCount,
                bytes calldata signature
            ) external;
        }
    }

    let oracle_writer = OracleWriter2::new(oracle_addr, &provider);
    let tx = oracle_writer.updateRootTrusted(
        policy_id_fb,
        FixedBytes::from(merkle_root),
        epoch,
        block_number,
        5,
        alloy::primitives::Bytes::from(sig.signature),
    ).send().await.unwrap();
    tx.get_receipt().await.unwrap();

    // Verify each member's proof on-chain
    let oracle = SolvencyRootOracle::new(oracle_addr, &provider);

    for (i, member_id) in members.iter().enumerate() {
        let proof = zk_pof_common::merkle::compute_proof(&leaves, i);
        let proof_fb: Vec<FixedBytes<32>> = proof.iter()
            .map(|h| FixedBytes::from(*h))
            .collect();

        let valid = oracle.verifyMember(
            policy_id_fb,
            FixedBytes::from(*member_id),
            1, // status = solvent
            epoch,
            proof_fb,
            U256::from(i),
            U256::from(0u64),
        ).call().await.unwrap();

        assert!(valid, "Member {} proof should verify on-chain", i);
    }
}

#[tokio::test]
#[ignore]
async fn test_anvil_status_change_balance_drop() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Create policy
    let policy_id = [0x04u8; 32];
    let policy_id_hex = hex::encode(policy_id);
    let policy_id_fb = FixedBytes::from(policy_id);
    let threshold = 1_000_000_000_000_000_000u128; // 1 ETH

    let registry = PolicyRegistry::new(registry_addr, &provider);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(threshold),
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "status-change".to_string(),
        trustedMode: true,
        active: true,
    };
    registry.createPolicy(policy_id_fb, policy).send().await.unwrap().get_receipt().await.unwrap();

    // Set up agent
    let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));
    let oracle_addr_hex = format!("{:?}", oracle_addr);
    let proof_worker = Arc::new(ProofWorker::new(&deployer_key, 31337, &oracle_addr_hex).unwrap());
    let publisher = Arc::new(OnChainPublisher::new(db.clone(), &rpc_url, &deployer_key, &oracle_addr_hex, 31337).unwrap());
    let webhook_svc = Arc::new(WebhookService::new(db.clone()));

    let member = make_member_id(0xDD);
    let member_hex = hex::encode(member);
    let watch_target = format!("{:?}", anvil.addresses()[1]); // 10000 ETH

    // Epoch 1: member is solvent (10000 ETH >> 1 ETH threshold)
    let rpc_fetcher = RpcFetcher::new(&rpc_url).unwrap();
    let balance = rpc_fetcher.get_balance(&watch_target).await.unwrap();
    let block_number = rpc_fetcher.get_block_number().await.unwrap();

    {
        let db = db.lock().unwrap();
        db.insert_member(&member_hex, &watch_target, &policy_id_hex, 1700000000, 1).unwrap();
        db.update_member_status(&member_hex, "pending", &balance.to_string(), block_number).unwrap();
    }

    let processor = EpochProcessor::new(db.clone(), proof_worker, publisher, webhook_svc, false);

    let trigger1 = EpochTrigger {
        policy_id_hex: policy_id_hex.clone(),
        policy_id,
        epoch: 1,
        block_number,
        threshold_wei: threshold,
        trusted_mode: true,
    };
    let result1 = processor.process_epoch(&trigger1).await.unwrap();
    assert_eq!(result1.status_changes.len(), 0, "pending → solvent is not a status change");

    // Now simulate balance drop by updating DB
    let new_block = block_number + 1;
    {
        let db = db.lock().unwrap();
        db.update_member_status(&member_hex, "solvent", "100000000000000000", new_block).unwrap(); // 0.1 ETH
    }

    // Epoch 2: member becomes insolvent
    let trigger2 = EpochTrigger {
        policy_id_hex: policy_id_hex.clone(),
        policy_id,
        epoch: 2,
        block_number: new_block,
        threshold_wei: threshold,
        trusted_mode: true,
    };
    let result2 = processor.process_epoch(&trigger2).await.unwrap();

    assert_eq!(result2.status_changes.len(), 1);
    assert_eq!(result2.status_changes[0].old_status, "solvent");
    assert_eq!(result2.status_changes[0].new_status, "insolvent");

    // Verify on-chain: 2 roots stored
    let oracle = SolvencyRootOracle::new(oracle_addr, &provider);
    let root_count = oracle.getRootCount(policy_id_fb).call().await.unwrap();
    assert_eq!(root_count, U256::from(2u64));
}

#[tokio::test]
#[ignore]
async fn test_anvil_sequential_epochs() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Create policy
    let policy_id = [0x05u8; 32];
    let policy_id_hex = hex::encode(policy_id);
    let policy_id_fb = FixedBytes::from(policy_id);

    let registry = PolicyRegistry::new(registry_addr, &provider);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(1_000_000_000_000_000_000u128),
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "seq-epoch".to_string(),
        trustedMode: true,
        active: true,
    };
    registry.createPolicy(policy_id_fb, policy).send().await.unwrap().get_receipt().await.unwrap();

    let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));
    let oracle_addr_hex = format!("{:?}", oracle_addr);
    let proof_worker = Arc::new(ProofWorker::new(&deployer_key, 31337, &oracle_addr_hex).unwrap());
    let publisher = Arc::new(OnChainPublisher::new(db.clone(), &rpc_url, &deployer_key, &oracle_addr_hex, 31337).unwrap());
    let webhook_svc = Arc::new(WebhookService::new(db.clone()));

    // Enroll 2 members
    let member_a = make_member_id(0x01);
    let member_b = make_member_id(0x02);
    let block_number = provider.get_block_number().await.unwrap();

    {
        let db = db.lock().unwrap();
        db.insert_member(&hex::encode(member_a), &format!("{:?}", anvil.addresses()[1]), &policy_id_hex, 1700000000, 1).unwrap();
        db.insert_member(&hex::encode(member_b), &format!("{:?}", anvil.addresses()[2]), &policy_id_hex, 1700000000, 1).unwrap();
        db.update_member_status(&hex::encode(member_a), "pending", "5000000000000000000", block_number).unwrap();
        db.update_member_status(&hex::encode(member_b), "pending", "3000000000000000000", block_number).unwrap();
    }

    let processor = EpochProcessor::new(db.clone(), proof_worker, publisher, webhook_svc, false);

    // Process 5 sequential epochs
    for ep in 1..=5u64 {
        let trigger = EpochTrigger {
            policy_id_hex: policy_id_hex.clone(),
            policy_id,
            epoch: ep,
            block_number,
            threshold_wei: 1_000_000_000_000_000_000,
            trusted_mode: true,
        };
        let result = processor.process_epoch(&trigger).await.unwrap();
        assert_eq!(result.epoch, ep);
        assert_eq!(result.member_count, 2);
    }

    // Verify on-chain
    let oracle = SolvencyRootOracle::new(oracle_addr, &provider);
    let root_count = oracle.getRootCount(policy_id_fb).call().await.unwrap();
    assert_eq!(root_count, U256::from(5u64));

    // Verify monotonic epoch numbers
    for i in 0..5u64 {
        let entry = oracle.getRootEntry(policy_id_fb, U256::from(i)).call().await.unwrap();
        assert_eq!(entry.epoch, i + 1, "Epoch {} should have epoch number {}", i, i + 1);
    }
}

#[tokio::test]
#[ignore]
async fn test_anvil_real_balance_fetch() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();

    let rpc_fetcher = RpcFetcher::new(&rpc_url).unwrap();

    // Anvil pre-funds 10 accounts with 10000 ETH each
    let account = format!("{:?}", anvil.addresses()[0]);
    let balance = rpc_fetcher.get_balance(&account).await.unwrap();

    let expected_balance = 10_000_000_000_000_000_000_000u128; // 10000 ETH in wei
    assert_eq!(balance, expected_balance, "Anvil account should have 10000 ETH");

    // Also test block number
    let block = rpc_fetcher.get_block_number().await.unwrap();
    // Block number should be reasonable (at least 0, typically 0 or 1 on fresh Anvil)
    assert!(block < 1000, "Block number should be reasonable for a fresh Anvil instance");
}

#[tokio::test]
#[ignore]
async fn test_anvil_insolvent_member_proof() {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let deployer_key = hex::encode(anvil.keys()[0].to_bytes());

    let root = project_root();
    let (registry_addr, oracle_addr) = deploy_contracts(&rpc_url, &deployer_key, &root);

    let signer: PrivateKeySigner = deployer_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Create policy
    let policy_id = [0x06u8; 32];
    let policy_id_hex = hex::encode(policy_id);
    let policy_id_fb = FixedBytes::from(policy_id);
    let threshold = 1_000_000_000_000_000_000u128; // 1 ETH

    let registry = PolicyRegistry::new(registry_addr, &provider);
    let policy = PolicyRegistry::Policy {
        thresholdWei: U256::from(threshold),
        tokenAddress: Address::ZERO,
        chainId: 31337,
        epochLengthBlocks: 100,
        maxBlockAge: 256,
        rootTTLBlocks: 1000,
        operator: signer.address(),
        scope: "insolvent-test".to_string(),
        trustedMode: true,
        active: true,
    };
    registry.createPolicy(policy_id_fb, policy).send().await.unwrap().get_receipt().await.unwrap();

    // Set up agent
    let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));
    let oracle_addr_hex = format!("{:?}", oracle_addr);
    let proof_worker = Arc::new(ProofWorker::new(&deployer_key, 31337, &oracle_addr_hex).unwrap());
    let publisher = Arc::new(OnChainPublisher::new(db.clone(), &rpc_url, &deployer_key, &oracle_addr_hex, 31337).unwrap());
    let webhook_svc = Arc::new(WebhookService::new(db.clone()));

    // 2 members: one solvent, one insolvent
    let member_solvent = make_member_id(0xE1);
    let member_insolvent = make_member_id(0xE2);
    let block_number = provider.get_block_number().await.unwrap();

    {
        let db = db.lock().unwrap();
        db.insert_member(&hex::encode(member_solvent), &format!("{:?}", anvil.addresses()[1]), &policy_id_hex, 1700000000, 1).unwrap();
        db.insert_member(&hex::encode(member_insolvent), &format!("{:?}", anvil.addresses()[2]), &policy_id_hex, 1700000000, 1).unwrap();

        db.update_member_status(&hex::encode(member_solvent), "pending", "5000000000000000000", block_number).unwrap(); // 5 ETH
        db.update_member_status(&hex::encode(member_insolvent), "pending", "100000000000000000", block_number).unwrap(); // 0.1 ETH
    }

    let processor = EpochProcessor::new(db.clone(), proof_worker, publisher, webhook_svc, false);

    let trigger = EpochTrigger {
        policy_id_hex: policy_id_hex.clone(),
        policy_id,
        epoch: 1,
        block_number,
        threshold_wei: threshold,
        trusted_mode: true,
    };

    let result = processor.process_epoch(&trigger).await.unwrap();
    assert_eq!(result.member_count, 2);

    // Build proofs from the stored Merkle tree
    let oracle = SolvencyRootOracle::new(oracle_addr, &provider);

    // Get the tree from DB
    let (solvent_status, insolvent_status) = {
        let db = db.lock().unwrap();
        let s = db.get_member(&hex::encode(member_solvent)).unwrap().unwrap();
        let i = db.get_member(&hex::encode(member_insolvent)).unwrap().unwrap();
        (s.status, i.status)
    };

    assert_eq!(solvent_status, "solvent");
    assert_eq!(insolvent_status, "insolvent");

    // Use the MerkleService to get proofs from the stored tree.
    // This ensures we use the exact same leaf ordering as the epoch processor.
    let member_solvent_hex = hex::encode(member_solvent);
    let member_insolvent_hex = hex::encode(member_insolvent);

    let (solvent_proof_data, insolvent_proof_data) = {
        let db = db.lock().unwrap();
        let merkle_svc = zk_pof_agent::merkle_service::MerkleService::new(&db);

        let sp = merkle_svc.get_member_proof(
            &policy_id_hex, 1, &member_solvent_hex,
            &member_solvent, 1, &policy_id,
        ).unwrap();

        let ip = merkle_svc.get_member_proof(
            &policy_id_hex, 1, &member_insolvent_hex,
            &member_insolvent, 0, &policy_id,
        ).unwrap();

        (sp, ip)
    };

    // Verify solvent member (status=1) verifies as solvent on-chain via isMemberSolvent
    let proof_fb: Vec<FixedBytes<32>> = solvent_proof_data.merkle_proof.iter()
        .map(|h| FixedBytes::from(*h)).collect();

    let is_solvent = oracle.isMemberSolvent(
        policy_id_fb,
        FixedBytes::from(member_solvent),
        1,
        proof_fb,
        U256::from(solvent_proof_data.leaf_index as u64),
        U256::from(0u64),
    ).call().await.unwrap();
    assert!(is_solvent, "Solvent member should be verified as solvent");

    // Verify insolvent member (status=0) does NOT verify as solvent.
    // isMemberSolvent checks status=1, but this member's leaf has status=0.
    let proof_fb2: Vec<FixedBytes<32>> = insolvent_proof_data.merkle_proof.iter()
        .map(|h| FixedBytes::from(*h)).collect();

    let is_solvent2 = oracle.isMemberSolvent(
        policy_id_fb,
        FixedBytes::from(member_insolvent),
        1,
        proof_fb2,
        U256::from(insolvent_proof_data.leaf_index as u64),
        U256::from(0u64),
    ).call().await.unwrap();
    assert!(!is_solvent2, "Insolvent member should NOT verify as solvent");
}
