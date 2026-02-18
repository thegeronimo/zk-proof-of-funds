//! SP1 execution tests for the batch solvency program (Phase 2).
//!
//! These tests run the SP1 program in execute-only mode (no proof generation).
//! They verify that:
//! 1. The program correctly verifies MPT proofs and extracts balances
//! 2. The solvency root matches the off-chain Merkle computation
//! 3. The ABI-encoded public values match expected Solidity encoding
//!
//! To create valid test vectors, we build minimal synthetic Ethereum state tries
//! using the same keccak256 + RLP encoding the MPT verifier expects.

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use zk_pof_agent::proof_worker::{
    execute_sp1_program, BatchProofInputs, MemberProofInput,
};
use zk_pof_common::merkle;

// ─── Helpers: Build synthetic MPT proofs ──────────────────────────────────────

/// Compute keccak256 hash (same as program/src/mpt.rs).
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// RLP-encode a single bytes item.
/// For len < 56: if single byte 0x00..0x7f → just the byte, else 0x80+len || data.
/// For len >= 56: 0xb7+lenlen || len || data.
fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] <= 0x7f {
        return vec![data[0]];
    }
    if data.len() < 56 {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = encode_length(data.len());
        let mut out = vec![0xb7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

/// RLP-encode a list from pre-encoded items.
fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    if payload.len() < 56 {
        let mut out = vec![0xc0 + payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    } else {
        let len_bytes = encode_length(payload.len());
        let mut out = vec![0xf7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(&payload);
        out
    }
}

/// Encode a length as big-endian bytes (minimal encoding).
fn encode_length(len: usize) -> Vec<u8> {
    if len == 0 {
        return vec![0];
    }
    let bytes = len.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// RLP-encode a uint (big-endian, no leading zeros).
fn rlp_encode_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // RLP empty bytes for zero
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    rlp_encode_bytes(&bytes[start..])
}

/// RLP-encode a u128 balance (big-endian, no leading zeros).
fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // RLP empty bytes for zero
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    rlp_encode_bytes(&bytes[start..])
}

/// HP (Hex-Prefix) encode nibbles.
/// is_leaf: true for leaf, false for extension.
/// nibbles: the path nibbles to encode.
fn hp_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 2 } else { 0 };
    let is_odd = nibbles.len() % 2 == 1;

    let mut encoded = Vec::new();
    if is_odd {
        // Odd: first byte = (flag+1) << 4 | first_nibble
        encoded.push(((flag + 1) << 4) | nibbles[0]);
        for chunk in nibbles[1..].chunks(2) {
            encoded.push((chunk[0] << 4) | chunk[1]);
        }
    } else {
        // Even: first byte = flag << 4 | 0 (padding nibble)
        encoded.push(flag << 4);
        for chunk in nibbles.chunks(2) {
            encoded.push((chunk[0] << 4) | chunk[1]);
        }
    }
    encoded
}

/// Convert a 32-byte key to 64 nibbles.
fn to_nibbles(key: &[u8; 32]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(64);
    for byte in key {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Build a synthetic single-account state trie.
///
/// Creates a minimal trie consisting of just one leaf node where:
/// - The key is keccak256(address)
/// - The value is an RLP-encoded account [nonce, balance, storage_root, code_hash]
/// - The state root is keccak256(leaf_node_rlp)
///
/// Returns (state_root, proof_nodes) suitable for the SP1 program.
fn build_single_account_proof(
    address: &[u8; 20],
    nonce: u64,
    balance_wei: u128,
) -> ([u8; 32], Vec<Vec<u8>>) {
    // Compute the trie key
    let account_key = keccak256(address);
    let nibbles = to_nibbles(&account_key);

    // Build the account RLP: [nonce, balance, storageRoot, codeHash]
    let empty_root_hash: [u8; 32] = [
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
        0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
        0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
        0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
    ];
    let empty_code_hash: [u8; 32] = keccak256(&[]);

    let account_rlp = rlp_encode_list(&[
        rlp_encode_uint(nonce),
        rlp_encode_u128(balance_wei),
        rlp_encode_bytes(&empty_root_hash),
        rlp_encode_bytes(&empty_code_hash),
    ]);

    // Build the leaf node: [HP(nibbles, is_leaf=true), account_rlp]
    let hp_path = hp_encode(&nibbles, true);
    let leaf_node = rlp_encode_list(&[
        rlp_encode_bytes(&hp_path),
        rlp_encode_bytes(&account_rlp),
    ]);

    // State root = keccak256(leaf_node)
    let state_root = keccak256(&leaf_node);

    (state_root, vec![leaf_node])
}

/// Build a two-account state trie where both accounts share the same state root.
///
/// Creates a trie with a branch node at the root. This handles the case where
/// two account keys diverge at the first nibble.
///
/// Strategy:
/// - For two addresses whose keccak256 keys differ at the first nibble,
///   create: root (branch) → leaf1, leaf2
/// - All 16 branch children are empty except two.
///
/// Returns (state_root, Vec<(address, proof_nodes)>) for each account.
fn build_two_account_proofs(
    addr1: &[u8; 20],
    balance1: u128,
    addr2: &[u8; 20],
    balance2: u128,
) -> ([u8; 32], Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let key1 = keccak256(addr1);
    let key2 = keccak256(addr2);
    let nibbles1 = to_nibbles(&key1);
    let nibbles2 = to_nibbles(&key2);

    // Find the first nibble where they differ
    let diverge_idx = nibbles1.iter().zip(nibbles2.iter())
        .position(|(a, b)| a != b)
        .expect("Two different addresses should have different keccak256 keys");

    // Helper to build an account RLP
    let build_account_rlp = |balance: u128| {
        let empty_root: [u8; 32] = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
            0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
            0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
            0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
        ];
        let empty_code = keccak256(&[]);
        rlp_encode_list(&[
            rlp_encode_uint(0),   // nonce = 0
            rlp_encode_u128(balance),
            rlp_encode_bytes(&empty_root),
            rlp_encode_bytes(&empty_code),
        ])
    };

    // Build leaf nodes (path is remaining nibbles after diverge_idx + 1)
    let remaining1 = &nibbles1[diverge_idx + 1..];
    let remaining2 = &nibbles2[diverge_idx + 1..];

    let leaf1_rlp = rlp_encode_list(&[
        rlp_encode_bytes(&hp_encode(remaining1, true)),
        rlp_encode_bytes(&build_account_rlp(balance1)),
    ]);
    let leaf2_rlp = rlp_encode_list(&[
        rlp_encode_bytes(&hp_encode(remaining2, true)),
        rlp_encode_bytes(&build_account_rlp(balance2)),
    ]);

    let leaf1_hash = keccak256(&leaf1_rlp);
    let leaf2_hash = keccak256(&leaf2_rlp);

    // Build the branch node: 16 children + 1 value
    // Children at nibbles1[diverge_idx] and nibbles2[diverge_idx] are hash refs;
    // all others are empty (0x80 = RLP empty bytes)
    let n1 = nibbles1[diverge_idx] as usize;
    let n2 = nibbles2[diverge_idx] as usize;

    let mut children: Vec<Vec<u8>> = Vec::with_capacity(17);
    for i in 0..16 {
        if i == n1 {
            children.push(rlp_encode_bytes(&leaf1_hash));
        } else if i == n2 {
            children.push(rlp_encode_bytes(&leaf2_hash));
        } else {
            children.push(vec![0x80]); // empty
        }
    }
    children.push(vec![0x80]); // branch value (empty for state trie)

    // If diverge_idx > 0, we need an extension node before the branch
    let branch_rlp = rlp_encode_list(&children);

    if diverge_idx == 0 {
        // Branch is the root
        let state_root = keccak256(&branch_rlp);
        let proof1 = vec![branch_rlp.clone(), leaf1_rlp];
        let proof2 = vec![branch_rlp, leaf2_rlp];
        (state_root, proof1, proof2)
    } else {
        // Extension → Branch → Leaf
        let branch_hash = keccak256(&branch_rlp);
        let shared_nibbles = &nibbles1[..diverge_idx];
        let extension_rlp = rlp_encode_list(&[
            rlp_encode_bytes(&hp_encode(shared_nibbles, false)),
            rlp_encode_bytes(&branch_hash),
        ]);
        let state_root = keccak256(&extension_rlp);
        let proof1 = vec![extension_rlp.clone(), branch_rlp.clone(), leaf1_rlp];
        let proof2 = vec![extension_rlp, branch_rlp, leaf2_rlp];
        (state_root, proof1, proof2)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Compute leaf hash identically to the SP1 program and off-chain Merkle lib.
fn compute_leaf_hash(member_id: &[u8; 32], status: u8, epoch: u64, policy_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(member_id);
    hasher.update([status]);
    hasher.update(epoch.to_be_bytes());
    hasher.update(policy_id);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Test: Single solvent member with balance above threshold.
#[test]
fn test_sp1_single_member_solvent() {
    let address: [u8; 20] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
    ];
    let balance: u128 = 2_000_000_000_000_000_000; // 2 ETH
    let threshold: u64 = 1_000_000_000_000_000_000; // 1 ETH

    let (state_root, proof_nodes) = build_single_account_proof(&address, 0, balance);

    let member_id = [0x01; 32];
    let policy_id = [0xAA; 32];
    let epoch = 1u64;
    let block_number = 19_000_000u64;
    let chain_id = 1u64;

    let inputs = BatchProofInputs {
        state_root,
        policy_id,
        epoch,
        threshold_wei: threshold,
        block_number,
        chain_id,
        members: vec![MemberProofInput {
            member_id,
            watch_target: address,
            proof_nodes,
        }],
    };

    let result = execute_sp1_program(&inputs).expect("SP1 execution failed");

    // Verify public values match inputs
    assert_eq!(result.state_root, state_root);
    assert_eq!(result.policy_id, policy_id);
    assert_eq!(result.epoch, epoch);
    assert_eq!(result.threshold_wei, threshold);
    assert_eq!(result.member_count, 1);
    assert_eq!(result.block_number, block_number);
    assert_eq!(result.chain_id, chain_id);

    // Verify solvency root matches off-chain computation
    // Balance (2 ETH) >= threshold (1 ETH) → status = 1 (solvent)
    let expected_leaf = compute_leaf_hash(&member_id, 1, epoch, &policy_id);
    let expected_root = merkle::compute_root(&[expected_leaf]);
    assert_eq!(
        result.solvency_root, expected_root,
        "Solvency root from SP1 should match off-chain Merkle computation"
    );
}

/// Test: Single insolvent member with balance below threshold.
#[test]
fn test_sp1_single_member_insolvent() {
    let address: [u8; 20] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44,
    ];
    let balance: u128 = 500_000_000_000_000_000; // 0.5 ETH
    let threshold: u64 = 1_000_000_000_000_000_000; // 1 ETH

    let (state_root, proof_nodes) = build_single_account_proof(&address, 0, balance);

    let member_id = [0x02; 32];
    let policy_id = [0xBB; 32];
    let epoch = 5u64;
    let block_number = 20_000_000u64;
    let chain_id = 1u64;

    let inputs = BatchProofInputs {
        state_root,
        policy_id,
        epoch,
        threshold_wei: threshold,
        block_number,
        chain_id,
        members: vec![MemberProofInput {
            member_id,
            watch_target: address,
            proof_nodes,
        }],
    };

    let result = execute_sp1_program(&inputs).expect("SP1 execution failed");

    // Balance (0.5 ETH) < threshold (1 ETH) → status = 0 (insolvent)
    let expected_leaf = compute_leaf_hash(&member_id, 0, epoch, &policy_id);
    let expected_root = merkle::compute_root(&[expected_leaf]);
    assert_eq!(
        result.solvency_root, expected_root,
        "Insolvent member should produce status=0 leaf"
    );
}

/// Test: Two members with different solvency statuses sharing the same state root.
#[test]
fn test_sp1_two_members_mixed_solvency() {
    // Use addresses whose keccak256 keys differ early
    let addr1: [u8; 20] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
    ];
    let addr2: [u8; 20] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44,
    ];

    let balance1: u128 = 5_000_000_000_000_000_000; // 5 ETH (solvent)
    let balance2: u128 = 100_000_000_000_000_000;   // 0.1 ETH (insolvent)
    let threshold: u64 = 1_000_000_000_000_000_000; // 1 ETH

    let (state_root, proof1, proof2) = build_two_account_proofs(
        &addr1, balance1,
        &addr2, balance2,
    );

    let member_id1 = [0x01; 32];
    let member_id2 = [0x02; 32];
    let policy_id = [0xCC; 32];
    let epoch = 10u64;
    let block_number = 19_500_000u64;
    let chain_id = 1u64;

    let inputs = BatchProofInputs {
        state_root,
        policy_id,
        epoch,
        threshold_wei: threshold,
        block_number,
        chain_id,
        members: vec![
            MemberProofInput {
                member_id: member_id1,
                watch_target: addr1,
                proof_nodes: proof1,
            },
            MemberProofInput {
                member_id: member_id2,
                watch_target: addr2,
                proof_nodes: proof2,
            },
        ],
    };

    let result = execute_sp1_program(&inputs).expect("SP1 execution failed");

    // Member 1: 5 ETH >= 1 ETH → status = 1
    // Member 2: 0.1 ETH < 1 ETH → status = 0
    let leaf1 = compute_leaf_hash(&member_id1, 1, epoch, &policy_id);
    let leaf2 = compute_leaf_hash(&member_id2, 0, epoch, &policy_id);
    let expected_root = merkle::compute_root(&[leaf1, leaf2]);

    assert_eq!(result.member_count, 2);
    assert_eq!(
        result.solvency_root, expected_root,
        "Mixed solvency: SP1 root should match off-chain Merkle computation"
    );
}

/// Test: Zero balance account (empty account in the trie).
#[test]
fn test_sp1_zero_balance() {
    let address: [u8; 20] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    let (state_root, proof_nodes) = build_single_account_proof(&address, 0, 0);

    let member_id = [0x03; 32];
    let policy_id = [0xDD; 32];
    let epoch = 1u64;
    let threshold: u64 = 1_000_000_000_000_000_000; // 1 ETH

    let inputs = BatchProofInputs {
        state_root,
        policy_id,
        epoch,
        threshold_wei: threshold,
        block_number: 19_000_000,
        chain_id: 1,
        members: vec![MemberProofInput {
            member_id,
            watch_target: address,
            proof_nodes,
        }],
    };

    let result = execute_sp1_program(&inputs).expect("SP1 execution failed");

    // Zero balance < threshold → status = 0
    let expected_leaf = compute_leaf_hash(&member_id, 0, epoch, &policy_id);
    let expected_root = merkle::compute_root(&[expected_leaf]);
    assert_eq!(result.solvency_root, expected_root);
}

/// Test: Exact threshold balance (should be solvent — balance >= threshold).
#[test]
fn test_sp1_exact_threshold() {
    let address: [u8; 20] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66,
        0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC,
    ];
    let threshold: u64 = 1_000_000_000_000_000_000; // 1 ETH
    let balance: u128 = threshold as u128; // Exactly 1 ETH

    let (state_root, proof_nodes) = build_single_account_proof(&address, 0, balance);

    let member_id = [0x04; 32];
    let policy_id = [0xEE; 32];
    let epoch = 3u64;

    let inputs = BatchProofInputs {
        state_root,
        policy_id,
        epoch,
        threshold_wei: threshold,
        block_number: 19_000_000,
        chain_id: 1,
        members: vec![MemberProofInput {
            member_id,
            watch_target: address,
            proof_nodes,
        }],
    };

    let result = execute_sp1_program(&inputs).expect("SP1 execution failed");

    // Exact threshold → status = 1 (solvent)
    let expected_leaf = compute_leaf_hash(&member_id, 1, epoch, &policy_id);
    let expected_root = merkle::compute_root(&[expected_leaf]);
    assert_eq!(
        result.solvency_root, expected_root,
        "Balance equal to threshold should be solvent"
    );
}

/// Test: ABI encoding of public values matches expected Solidity format.
#[test]
fn test_abi_encoding_format() {
    let address: [u8; 20] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
    ];
    let balance: u128 = 2_000_000_000_000_000_000;
    let threshold: u64 = 1_000_000_000_000_000_000;

    let (state_root, proof_nodes) = build_single_account_proof(&address, 0, balance);

    let policy_id = [0xAA; 32];
    let epoch = 42u64;
    let block_number = 19_000_000u64;
    let chain_id = 1u64;
    let member_id = [0x01; 32];

    let inputs = BatchProofInputs {
        state_root,
        policy_id,
        epoch,
        threshold_wei: threshold,
        block_number,
        chain_id,
        members: vec![MemberProofInput {
            member_id,
            watch_target: address,
            proof_nodes,
        }],
    };

    let result = execute_sp1_program(&inputs).expect("SP1 execution failed");

    // ABI encoding should be 8 * 32 = 256 bytes
    // (bytes32, bytes32, uint64, bytes32, uint64, uint32, uint64, uint64)
    // Each ABI slot is 32 bytes (values are right-padded/left-padded as per ABI spec)
    assert_eq!(
        result.public_values_abi.len(), 256,
        "ABI-encoded public values should be 256 bytes (8 slots × 32 bytes)"
    );

    // Verify individual fields in the ABI encoding
    // Slot 0: state_root (bytes32 — left-aligned)
    assert_eq!(&result.public_values_abi[0..32], &state_root);

    // Slot 1: policy_id (bytes32 — left-aligned)
    assert_eq!(&result.public_values_abi[32..64], &policy_id);

    // Slot 2: epoch (uint64 — right-aligned in 32-byte slot)
    let epoch_slot = &result.public_values_abi[64..96];
    assert_eq!(&epoch_slot[..24], &[0u8; 24]); // Leading zeros
    assert_eq!(&epoch_slot[24..32], &epoch.to_be_bytes());

    // Slot 3: solvency_root (bytes32)
    assert_eq!(&result.public_values_abi[96..128], &result.solvency_root);

    // Slot 4: threshold_wei (uint64 — right-aligned)
    let threshold_slot = &result.public_values_abi[128..160];
    assert_eq!(&threshold_slot[..24], &[0u8; 24]);
    assert_eq!(&threshold_slot[24..32], &threshold.to_be_bytes());

    // Slot 5: member_count (uint32 — right-aligned)
    let mc_slot = &result.public_values_abi[160..192];
    assert_eq!(&mc_slot[..28], &[0u8; 28]);
    assert_eq!(&mc_slot[28..32], &1u32.to_be_bytes());

    // Slot 6: block_number (uint64 — right-aligned)
    let bn_slot = &result.public_values_abi[192..224];
    assert_eq!(&bn_slot[..24], &[0u8; 24]);
    assert_eq!(&bn_slot[24..32], &block_number.to_be_bytes());

    // Slot 7: chain_id (uint64 — right-aligned)
    let ci_slot = &result.public_values_abi[224..256];
    assert_eq!(&ci_slot[..24], &[0u8; 24]);
    assert_eq!(&ci_slot[24..32], &chain_id.to_be_bytes());
}
