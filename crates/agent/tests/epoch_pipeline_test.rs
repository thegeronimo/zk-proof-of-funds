//! Integration tests for the full epoch pipeline (Phase 4).
//!
//! These tests exercise the complete trusted-mode pipeline:
//!   Enroll members → set balances → process epoch → verify results
//!
//! All tests use `skip_on_chain = true` with in-memory DB.

use std::sync::{Arc, Mutex};

use zk_pof_agent::chain_publisher::OnChainPublisher;
use zk_pof_agent::db::Database;
use zk_pof_agent::epoch_processor::EpochProcessor;
use zk_pof_agent::proof_worker::ProofWorker;
use zk_pof_agent::scheduler::EpochTrigger;
use zk_pof_agent::webhook::WebhookService;

use alloy::signers::local::PrivateKeySigner;

/// Helper: set up all components for pipeline testing.
fn setup() -> (
    Arc<Mutex<Database>>,
    EpochProcessor,
) {
    let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));

    let signer = PrivateKeySigner::random();
    let key_hex = hex::encode(signer.credential().to_bytes());

    let proof_worker = Arc::new(
        ProofWorker::new(&key_hex, 1, "0x0000000000000000000000000000000000000001").unwrap()
    );

    let publisher = Arc::new(
        OnChainPublisher::new(
            db.clone(),
            "http://localhost:8545",
            &key_hex,
            "0x0000000000000000000000000000000000000001",
            1,
        ).unwrap()
    );

    let webhook_svc = Arc::new(WebhookService::new(db.clone()));

    let processor = EpochProcessor::new(
        db.clone(),
        proof_worker,
        publisher,
        webhook_svc,
        true, // skip_on_chain
    );

    (db, processor)
}

/// Helper: compute a deterministic 32-byte member ID from a seed.
fn make_member_id(seed: u8) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update([seed]);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Helper: create a trigger for testing.
fn make_trigger(policy_id: [u8; 32], epoch: u64, block: u64, threshold_wei: u128) -> EpochTrigger {
    EpochTrigger {
        policy_id_hex: hex::encode(policy_id),
        policy_id,
        epoch,
        block_number: block,
        threshold_wei,
        trusted_mode: true,
    }
}

// ─── Test Cases ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_full_epoch_pipeline_trusted_mode() {
    let (db, processor) = setup();
    let policy_id = [0x01; 32];
    let policy_id_hex = hex::encode(policy_id);
    let threshold = 1_000_000_000_000_000_000u128; // 1 ETH

    let member_a = make_member_id(0xAA);
    let member_b = make_member_id(0xBB);
    let member_c = make_member_id(0xCC);

    // Enroll 3 members
    {
        let db = db.lock().unwrap();
        db.insert_member(
            &hex::encode(member_a),
            &policy_id_hex,
            1700000000,
            1,
        ).unwrap();
        db.insert_member(
            &hex::encode(member_b),
            &policy_id_hex,
            1700000000,
            1,
        ).unwrap();
        db.insert_member(
            &hex::encode(member_c),
            &policy_id_hex,
            1700000000,
            1,
        ).unwrap();

        // Set balances: A=5 ETH (solvent), B=2 ETH (solvent), C=0.5 ETH (insolvent)
        db.update_member_status(&hex::encode(member_a), "pending", "5000000000000000000", 19_000_000).unwrap();
        db.update_member_status(&hex::encode(member_b), "pending", "2000000000000000000", 19_000_000).unwrap();
        db.update_member_status(&hex::encode(member_c), "pending", "500000000000000000", 19_000_000).unwrap();
    }

    // Process epoch 1
    let trigger = make_trigger(policy_id, 1, 19_000_100, threshold);
    let result = processor.process_epoch(&trigger).await.unwrap();

    // Verify results
    assert_eq!(result.epoch, 1);
    assert_eq!(result.member_count, 3);
    assert_ne!(result.root, [0u8; 32]);
    assert!(result.tx_hash.is_none()); // skip_on_chain

    // No status changes because all were "pending" → first check
    assert_eq!(result.status_changes.len(), 0);

    // Verify DB state
    {
        let db = db.lock().unwrap();

        // Members should have updated statuses
        let a = db.get_member(&hex::encode(member_a)).unwrap().unwrap();
        assert_eq!(a.status, "solvent");
        assert_eq!(a.last_checked_block, 19_000_100);

        let b = db.get_member(&hex::encode(member_b)).unwrap().unwrap();
        assert_eq!(b.status, "solvent");

        let c = db.get_member(&hex::encode(member_c)).unwrap().unwrap();
        assert_eq!(c.status, "insolvent");

        // Epoch should be recorded
        let epoch = db.get_latest_epoch(&policy_id_hex).unwrap().unwrap();
        assert_eq!(epoch.epoch, 1);
        assert_eq!(epoch.member_count, 3);

        // Merkle tree should be stored
        let tree = db.get_merkle_tree(&policy_id_hex, 1).unwrap();
        assert!(tree.is_some());
    }
}

#[tokio::test]
async fn test_status_change_detection_across_epochs() {
    let (db, processor) = setup();
    let policy_id = [0x10; 32];
    let policy_id_hex = hex::encode(policy_id);
    let threshold = 1_000_000_000_000_000_000u128; // 1 ETH

    let member = make_member_id(0xDD);
    let member_hex = hex::encode(member);

    // Enroll with 5 ETH (solvent)
    {
        let db = db.lock().unwrap();
        db.insert_member(&member_hex, &policy_id_hex, 1700000000, 1).unwrap();
        db.update_member_status(&member_hex, "pending", "5000000000000000000", 19_000_000).unwrap();
    }

    // Epoch 1: initial check (pending → solvent, no status change reported)
    let trigger1 = make_trigger(policy_id, 1, 19_000_100, threshold);
    let result1 = processor.process_epoch(&trigger1).await.unwrap();
    assert_eq!(result1.status_changes.len(), 0); // pending → solvent is not a "change"
    assert_eq!(result1.member_count, 1);

    // Verify member is now solvent
    {
        let db = db.lock().unwrap();
        let m = db.get_member(&member_hex).unwrap().unwrap();
        assert_eq!(m.status, "solvent");
    }

    // Drop balance to 0.1 ETH
    {
        let db = db.lock().unwrap();
        db.update_member_status(&member_hex, "solvent", "100000000000000000", 19_000_200).unwrap();
    }

    // Epoch 2: balance dropped → should detect solvent → insolvent
    let trigger2 = make_trigger(policy_id, 2, 19_000_200, threshold);
    let result2 = processor.process_epoch(&trigger2).await.unwrap();

    assert_eq!(result2.status_changes.len(), 1);
    assert_eq!(result2.status_changes[0].old_status, "solvent");
    assert_eq!(result2.status_changes[0].new_status, "insolvent");

    // Verify member is now insolvent
    {
        let db = db.lock().unwrap();
        let m = db.get_member(&member_hex).unwrap().unwrap();
        assert_eq!(m.status, "insolvent");
    }

    // Restore balance to 3 ETH
    {
        let db = db.lock().unwrap();
        db.update_member_status(&member_hex, "insolvent", "3000000000000000000", 19_000_300).unwrap();
    }

    // Epoch 3: balance restored → should detect insolvent → solvent
    let trigger3 = make_trigger(policy_id, 3, 19_000_300, threshold);
    let result3 = processor.process_epoch(&trigger3).await.unwrap();

    assert_eq!(result3.status_changes.len(), 1);
    assert_eq!(result3.status_changes[0].old_status, "insolvent");
    assert_eq!(result3.status_changes[0].new_status, "solvent");
}

#[tokio::test]
async fn test_epoch_with_no_eligible_members() {
    let (db, processor) = setup();
    let policy_id = [0x20; 32];
    let policy_id_hex = hex::encode(policy_id);

    // Enroll a member with effective_epoch = 10
    {
        let db = db.lock().unwrap();
        db.insert_member(
            &hex::encode(make_member_id(0xEE)),
            &policy_id_hex,
            1700000000,
            10, // Not eligible until epoch 10
        ).unwrap();
        db.update_member_status(
            &hex::encode(make_member_id(0xEE)),
            "pending",
            "5000000000000000000",
            19_000_000,
        ).unwrap();
    }

    // Epoch 3 — member not yet eligible
    let trigger = make_trigger(policy_id, 3, 19_000_300, 1_000_000_000_000_000_000);
    let result = processor.process_epoch(&trigger).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No eligible members"));

    // Epoch 10 — member becomes eligible
    let trigger10 = make_trigger(policy_id, 10, 19_001_000, 1_000_000_000_000_000_000);
    let result10 = processor.process_epoch(&trigger10).await.unwrap();

    assert_eq!(result10.member_count, 1);
    assert_eq!(result10.epoch, 10);
}

#[tokio::test]
async fn test_multiple_policies_independent() {
    let (db, processor) = setup();

    let policy_a = [0x0A; 32];
    let policy_b = [0x0B; 32];
    let policy_a_hex = hex::encode(policy_a);
    let policy_b_hex = hex::encode(policy_b);
    let threshold = 1_000_000_000_000_000_000u128;

    let member_1 = make_member_id(0x01);
    let member_2 = make_member_id(0x02);
    let member_3 = make_member_id(0x03);

    // Policy A: members 1 and 2
    // Policy B: member 3
    {
        let db = db.lock().unwrap();
        db.insert_member(&hex::encode(member_1), &policy_a_hex, 1700000000, 1).unwrap();
        db.insert_member(&hex::encode(member_2), &policy_a_hex, 1700000000, 1).unwrap();
        db.insert_member(&hex::encode(member_3), &policy_b_hex, 1700000000, 1).unwrap();

        // Set balances
        db.update_member_status(&hex::encode(member_1), "pending", "5000000000000000000", 19_000_000).unwrap(); // 5 ETH
        db.update_member_status(&hex::encode(member_2), "pending", "3000000000000000000", 19_000_000).unwrap(); // 3 ETH
        db.update_member_status(&hex::encode(member_3), "pending", "500000000000000000", 19_000_000).unwrap(); // 0.5 ETH
    }

    // Process Policy A epoch 1
    let trigger_a = make_trigger(policy_a, 1, 19_000_100, threshold);
    let result_a = processor.process_epoch(&trigger_a).await.unwrap();

    // Process Policy B epoch 1
    let trigger_b = make_trigger(policy_b, 1, 19_000_100, threshold);
    let result_b = processor.process_epoch(&trigger_b).await.unwrap();

    // Verify independent results
    assert_eq!(result_a.member_count, 2);
    assert_eq!(result_b.member_count, 1);

    // Roots must be different (different members + statuses)
    assert_ne!(result_a.root, result_b.root);

    // Policy A: both solvent
    {
        let db = db.lock().unwrap();
        let m1 = db.get_member(&hex::encode(member_1)).unwrap().unwrap();
        assert_eq!(m1.status, "solvent");
        let m2 = db.get_member(&hex::encode(member_2)).unwrap().unwrap();
        assert_eq!(m2.status, "solvent");

        // Policy B: member 3 insolvent
        let m3 = db.get_member(&hex::encode(member_3)).unwrap().unwrap();
        assert_eq!(m3.status, "insolvent");

        // Both policies should have epoch records
        let epoch_a = db.get_latest_epoch(&policy_a_hex).unwrap().unwrap();
        assert_eq!(epoch_a.epoch, 1);
        assert_eq!(epoch_a.member_count, 2);

        let epoch_b = db.get_latest_epoch(&policy_b_hex).unwrap().unwrap();
        assert_eq!(epoch_b.epoch, 1);
        assert_eq!(epoch_b.member_count, 1);
    }
}

#[tokio::test]
async fn test_epoch_roots_differ_across_epochs() {
    let (db, processor) = setup();
    let policy_id = [0x30; 32];
    let policy_id_hex = hex::encode(policy_id);
    let threshold = 1_000_000_000_000_000_000u128;

    let member = make_member_id(0xFF);
    let member_hex = hex::encode(member);

    {
        let db = db.lock().unwrap();
        db.insert_member(&member_hex, &policy_id_hex, 1700000000, 1).unwrap();
        db.update_member_status(&member_hex, "pending", "5000000000000000000", 19_000_000).unwrap();
    }

    // Epoch 1
    let trigger1 = make_trigger(policy_id, 1, 19_000_100, threshold);
    let result1 = processor.process_epoch(&trigger1).await.unwrap();

    // Epoch 2 (same balance, different epoch → different leaves → different root)
    let trigger2 = make_trigger(policy_id, 2, 19_000_200, threshold);
    let result2 = processor.process_epoch(&trigger2).await.unwrap();

    // Roots should differ because epoch is part of the leaf hash
    assert_ne!(result1.root, result2.root);
}

#[tokio::test]
async fn test_merkle_proofs_available_after_epoch() {
    let (db, processor) = setup();
    let policy_id = [0x40; 32];
    let policy_id_hex = hex::encode(policy_id);
    let threshold = 1_000_000_000_000_000_000u128;

    let member = make_member_id(0x42);
    let member_hex = hex::encode(member);

    {
        let db = db.lock().unwrap();
        db.insert_member(&member_hex, &policy_id_hex, 1700000000, 1).unwrap();
        db.update_member_status(&member_hex, "pending", "5000000000000000000", 19_000_000).unwrap();
    }

    // Process epoch
    let trigger = make_trigger(policy_id, 1, 19_000_100, threshold);
    let result = processor.process_epoch(&trigger).await.unwrap();

    // Retrieve Merkle proof for the member
    {
        let db = db.lock().unwrap();
        let merkle_svc = zk_pof_agent::merkle_service::MerkleService::new(&db);

        let proof = merkle_svc.get_member_proof(
            &policy_id_hex,
            1,
            &member_hex,
            &member,
            1, // solvent
            &policy_id,
        ).unwrap();

        assert_eq!(proof.epoch, 1);
        assert_eq!(proof.status, 1);
        assert_eq!(proof.root, result.root);

        // Verify the proof
        let leaf = zk_pof_common::merkle::compute_leaf(&member, 1, 1, &policy_id);
        assert!(zk_pof_common::merkle::verify_proof(
            &leaf,
            proof.leaf_index as usize,
            &proof.merkle_proof,
            &proof.root,
        ));
    }
}
