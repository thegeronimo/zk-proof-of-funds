//! Integration test for the trusted mode MVP (Phase 1).
//!
//! Tests the full flow without a real Ethereum node:
//! 1. Open in-memory database
//! 2. Enroll members (insert directly into DB, simulating enrollment)
//! 3. Simulate an epoch update: fetch balances → determine status → build Merkle tree
//! 4. Store the epoch and tree
//! 5. Retrieve per-member Merkle proofs
//! 6. Verify proofs locally
//! 7. Test status changes (balance drop → insolvent → next epoch reflects new status)
//! 8. Sign a trusted mode EIP-712 assertion

use zk_pof_agent::db::Database;
use zk_pof_agent::merkle_service::{MerkleService, LeafInput};
use zk_pof_agent::chain_publisher::ChainPublisher;
use zk_pof_agent::proof_worker::ProofWorker;
use zk_pof_agent::scheduler::{Scheduler, PolicySchedule};
use zk_pof_agent::enrollment::compute_member_id;
use zk_pof_common::merkle;

/// Helper: create a member_id from a seed byte.
fn make_member_id(seed: u8) -> [u8; 32] {
    compute_member_id(&[seed; 65])
}

/// Full trusted mode flow: enroll → epoch → proof → verify.
#[test]
fn test_full_trusted_mode_flow() {
    let db = Database::open_in_memory().unwrap();
    let policy_id = [0x01; 32];
    let policy_id_hex = hex::encode(policy_id);

    // ─── Step 1: Enroll members ──────────────────────────────────────────
    // Simulating enrollment by inserting directly into DB
    // (real enrollment involves RPC + signature verification)
    let members = vec![
        ("member_a", make_member_id(0xAA), "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("member_b", make_member_id(0xBB), "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        ("member_c", make_member_id(0xCC), "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
    ];

    for (_, member_id, watch_target) in &members {
        let member_id_hex = hex::encode(member_id);
        db.insert_member(
            &member_id_hex,
            watch_target,
            &policy_id_hex,
            1700000000, // enrolled_at
            1,          // effective_epoch
        ).unwrap();
    }

    // Verify members were stored
    let stored_members = db.get_members_for_policy(&policy_id_hex).unwrap();
    assert_eq!(stored_members.len(), 3);

    // ─── Step 2: Simulate balance fetch + status determination ───────────
    // In real flow, RPC fetcher would check balances. Here we just set statuses.
    let _threshold_wei: u128 = 1_000_000_000_000_000_000; // 1 ETH

    // Member A: 10 ETH (solvent), Member B: 5 ETH (solvent), Member C: 0.5 ETH (insolvent)
    let balances: Vec<(&str, u128, bool)> = vec![
        ("member_a", 10_000_000_000_000_000_000, true),   // 10 ETH
        ("member_b", 5_000_000_000_000_000_000, true),    // 5 ETH
        ("member_c", 500_000_000_000_000_000, false),     // 0.5 ETH
    ];

    // Update member statuses in DB
    for (i, (_, balance, solvent)) in balances.iter().enumerate() {
        let member_id_hex = hex::encode(members[i].1);
        let status = if *solvent { "solvent" } else { "insolvent" };
        db.update_member_status(
            &member_id_hex,
            status,
            &balance.to_string(),
            19_000_000, // checked_block
        ).unwrap();
    }

    // ─── Step 3: Build Merkle tree for epoch 1 ──────────────────────────
    let merkle_svc = MerkleService::new(&db);

    let leaf_inputs: Vec<LeafInput> = members.iter().enumerate().map(|(i, (_, member_id, _))| {
        let status = if balances[i].2 { 1u8 } else { 0u8 };
        LeafInput {
            member_id: *member_id,
            status,
            member_id_hex: hex::encode(member_id),
        }
    }).collect();

    let tree_result = merkle_svc.build_epoch_tree(&policy_id, 1, &leaf_inputs, &policy_id_hex).unwrap();

    assert_eq!(tree_result.member_count, 3);
    assert_ne!(tree_result.root, [0u8; 32]);
    assert_eq!(tree_result.leaves.len(), 3);

    // ─── Step 4: Record epoch in database ────────────────────────────────
    let publisher = ChainPublisher::new(&db);
    let publish_result = publisher.record_epoch(
        &policy_id_hex,
        1,              // epoch
        19_000_000,     // block_number
        &tree_result.root,
        tree_result.member_count,
        19_000_010,     // published_at_block
        None,           // no proof bytes (trusted mode)
    ).unwrap();

    assert_eq!(publish_result.epoch, 1);
    assert!(publish_result.trusted_mode);

    // ─── Step 5: Retrieve per-member Merkle proofs ──────────────────────
    for (i, (_, member_id, _)) in members.iter().enumerate() {
        let member_id_hex = hex::encode(member_id);
        let status = if balances[i].2 { 1u8 } else { 0u8 };

        let proof = merkle_svc.get_member_proof(
            &policy_id_hex,
            1,
            &member_id_hex,
            member_id,
            status,
            &policy_id,
        ).unwrap();

        assert_eq!(proof.epoch, 1);
        assert_eq!(proof.status, status);
        assert_eq!(proof.root, tree_result.root);

        // ─── Step 6: Verify proof locally ────────────────────────────
        let leaf = merkle::compute_leaf(member_id, status, 1, &policy_id);
        assert!(
            merkle::verify_proof(&leaf, proof.leaf_index as usize, &proof.merkle_proof, &proof.root),
            "Proof verification failed for member {}",
            member_id_hex
        );
    }

    // ─── Step 7: Verify latest epoch is stored correctly ─────────────────
    let latest = db.get_latest_epoch(&policy_id_hex).unwrap().unwrap();
    assert_eq!(latest.epoch, 1);
    assert_eq!(latest.member_count, 3);
    assert_eq!(latest.root, hex::encode(tree_result.root));
}

/// Test balance drop → status change → new epoch reflects new status.
#[test]
fn test_status_change_across_epochs() {
    let db = Database::open_in_memory().unwrap();
    let policy_id = [0x01; 32];
    let policy_id_hex = hex::encode(policy_id);

    let member_id = make_member_id(0xAA);
    let member_id_hex = hex::encode(member_id);

    // Enroll member
    db.insert_member(&member_id_hex, "0xAAAA", &policy_id_hex, 1700000000, 1).unwrap();

    // ─── Epoch 1: Member is solvent ──────────────────────────────────────
    db.update_member_status(&member_id_hex, "solvent", "10000000000000000000", 19_000_000).unwrap();

    let merkle_svc = MerkleService::new(&db);
    let inputs_epoch1 = vec![LeafInput {
        member_id,
        status: 1, // solvent
        member_id_hex: member_id_hex.clone(),
    }];

    let tree1 = merkle_svc.build_epoch_tree(&policy_id, 1, &inputs_epoch1, &policy_id_hex).unwrap();

    let publisher = ChainPublisher::new(&db);
    publisher.record_epoch(&policy_id_hex, 1, 19_000_000, &tree1.root, 1, 19_000_010, None).unwrap();

    // Verify solvent proof
    let proof1 = merkle_svc.get_member_proof(
        &policy_id_hex, 1, &member_id_hex, &member_id, 1, &policy_id,
    ).unwrap();
    assert_eq!(proof1.status, 1);

    // ─── Epoch 2: Balance drops → insolvent ─────────────────────────────
    db.update_member_status(&member_id_hex, "insolvent", "500000000000000000", 19_000_100).unwrap();

    let inputs_epoch2 = vec![LeafInput {
        member_id,
        status: 0, // insolvent
        member_id_hex: member_id_hex.clone(),
    }];

    let tree2 = merkle_svc.build_epoch_tree(&policy_id, 2, &inputs_epoch2, &policy_id_hex).unwrap();
    publisher.record_epoch(&policy_id_hex, 2, 19_000_100, &tree2.root, 1, 19_000_110, None).unwrap();

    // Verify insolvent proof
    let proof2 = merkle_svc.get_member_proof(
        &policy_id_hex, 2, &member_id_hex, &member_id, 0, &policy_id,
    ).unwrap();
    assert_eq!(proof2.status, 0);

    // The roots should be different since status changed
    assert_ne!(tree1.root, tree2.root);

    // ─── Epoch 3: Balance recovers → solvent again ──────────────────────
    db.update_member_status(&member_id_hex, "solvent", "2000000000000000000", 19_000_200).unwrap();

    let inputs_epoch3 = vec![LeafInput {
        member_id,
        status: 1, // solvent again
        member_id_hex: member_id_hex.clone(),
    }];

    let tree3 = merkle_svc.build_epoch_tree(&policy_id, 3, &inputs_epoch3, &policy_id_hex).unwrap();
    publisher.record_epoch(&policy_id_hex, 3, 19_000_200, &tree3.root, 1, 19_000_210, None).unwrap();

    let proof3 = merkle_svc.get_member_proof(
        &policy_id_hex, 3, &member_id_hex, &member_id, 1, &policy_id,
    ).unwrap();
    assert_eq!(proof3.status, 1);

    // Epoch 1 and 3 have DIFFERENT roots even though same status, because
    // epoch number is part of the leaf: SHA256(memberId || status || epoch || policyId)
    assert_ne!(tree1.root, tree3.root);

    // Latest epoch should be 3
    let latest = db.get_latest_epoch(&policy_id_hex).unwrap().unwrap();
    assert_eq!(latest.epoch, 3);
}

/// Test multiple members across policies.
#[test]
fn test_multiple_policies() {
    let db = Database::open_in_memory().unwrap();

    let policy_a = [0x01; 32];
    let policy_b = [0x02; 32];
    let policy_a_hex = hex::encode(policy_a);
    let policy_b_hex = hex::encode(policy_b);

    // Enroll 2 members in policy A
    let member_1 = make_member_id(0x01);
    let member_2 = make_member_id(0x02);
    db.insert_member(&hex::encode(member_1), "0xAAAA", &policy_a_hex, 1700000000, 1).unwrap();
    db.insert_member(&hex::encode(member_2), "0xBBBB", &policy_a_hex, 1700000000, 1).unwrap();

    // Enroll 1 member in policy B
    let member_3 = make_member_id(0x03);
    db.insert_member(&hex::encode(member_3), "0xCCCC", &policy_b_hex, 1700000000, 1).unwrap();

    // Build trees for each policy
    let merkle_svc = MerkleService::new(&db);

    let tree_a = merkle_svc.build_epoch_tree(
        &policy_a, 1,
        &[
            LeafInput { member_id: member_1, status: 1, member_id_hex: hex::encode(member_1) },
            LeafInput { member_id: member_2, status: 1, member_id_hex: hex::encode(member_2) },
        ],
        &policy_a_hex,
    ).unwrap();

    let tree_b = merkle_svc.build_epoch_tree(
        &policy_b, 1,
        &[
            LeafInput { member_id: member_3, status: 1, member_id_hex: hex::encode(member_3) },
        ],
        &policy_b_hex,
    ).unwrap();

    // Different policies → different roots (even if same statuses)
    assert_ne!(tree_a.root, tree_b.root);
    assert_eq!(tree_a.member_count, 2);
    assert_eq!(tree_b.member_count, 1);

    // Proofs should verify for each respective policy
    let proof_1 = merkle_svc.get_member_proof(
        &policy_a_hex, 1, &hex::encode(member_1), &member_1, 1, &policy_a,
    ).unwrap();

    let leaf_1 = merkle::compute_leaf(&member_1, 1, 1, &policy_a);
    assert!(merkle::verify_proof(&leaf_1, proof_1.leaf_index as usize, &proof_1.merkle_proof, &proof_1.root));

    let proof_3 = merkle_svc.get_member_proof(
        &policy_b_hex, 1, &hex::encode(member_3), &member_3, 1, &policy_b,
    ).unwrap();

    let leaf_3 = merkle::compute_leaf(&member_3, 1, 1, &policy_b);
    assert!(merkle::verify_proof(&leaf_3, proof_3.leaf_index as usize, &proof_3.merkle_proof, &proof_3.root));
}

/// Test EIP-712 signing for trusted mode assertions.
#[tokio::test]
async fn test_trusted_mode_eip712_signing() {
    use alloy::signers::local::PrivateKeySigner;

    let db = Database::open_in_memory().unwrap();
    let policy_id = [0x01; 32];
    let policy_id_hex = hex::encode(policy_id);

    // Create a random operator key
    let signer = PrivateKeySigner::random();
    let key_hex = hex::encode(signer.credential().to_bytes());

    let worker = ProofWorker::new(
        &key_hex,
        1, // mainnet
        "0x0000000000000000000000000000000000000001",
    ).unwrap();

    // Enroll a member and build a tree
    let member_id = make_member_id(0xAA);
    db.insert_member(&hex::encode(member_id), "0xAAAA", &policy_id_hex, 1700000000, 1).unwrap();

    let merkle_svc = MerkleService::new(&db);
    let tree = merkle_svc.build_epoch_tree(
        &policy_id, 1,
        &[LeafInput { member_id, status: 1, member_id_hex: hex::encode(member_id) }],
        &policy_id_hex,
    ).unwrap();

    // Sign the trusted assertion
    let sig = worker.sign_trusted_assertion(
        &policy_id,
        &tree.root,
        1,          // epoch
        19_000_000, // block_number
        tree.member_count,
    ).await.unwrap();

    assert_eq!(sig.signature.len(), 65);

    // Signer should match the operator
    let expected_addr = {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(signer.address().as_slice());
        addr
    };
    assert_eq!(sig.signer, expected_addr);
}

/// Test scheduler epoch trigger logic.
#[test]
fn test_scheduler_epoch_scheduling() {
    let policy = PolicySchedule {
        policy_id_hex: hex::encode([0x01; 32]),
        policy_id: [0x01; 32],
        epoch_length_blocks: 100,
        threshold_wei: 1_000_000_000_000_000_000,
        trusted_mode: true,
        active: true,
    };

    let scheduler = Scheduler::new(vec![policy.clone()], 12);

    // First epoch triggers immediately
    let trigger = scheduler.check_epoch_due(&policy, 19_000_000, None, None);
    assert!(trigger.is_some());
    assert_eq!(trigger.unwrap().epoch, 1);

    // After epoch 1 at block 19_000_000, epoch 2 not due until 19_000_100
    let trigger = scheduler.check_epoch_due(&policy, 19_000_050, Some(19_000_000), Some(1));
    assert!(trigger.is_none());

    // At block 19_000_100, epoch 2 is due
    let trigger = scheduler.check_epoch_due(&policy, 19_000_100, Some(19_000_000), Some(1));
    assert!(trigger.is_some());
    assert_eq!(trigger.unwrap().epoch, 2);
}

/// Test the member_id computation is deterministic and unique.
#[test]
fn test_member_id_uniqueness() {
    // Same signature → same member_id
    let sig1 = vec![0xAA; 65];
    let id1 = compute_member_id(&sig1);
    let id2 = compute_member_id(&sig1);
    assert_eq!(id1, id2);

    // Different signatures → different member_ids
    let sig2 = vec![0xBB; 65];
    let id3 = compute_member_id(&sig2);
    assert_ne!(id1, id3);

    // Slight difference → completely different member_id (avalanche effect)
    let mut sig3 = sig1.clone();
    sig3[0] = 0xAB;
    let id4 = compute_member_id(&sig3);
    assert_ne!(id1, id4);
}
