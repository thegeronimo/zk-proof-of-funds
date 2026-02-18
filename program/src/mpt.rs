//! Ethereum Merkle Patricia Trie (MPT) verification for EIP-1186 account proofs.
//!
//! This module implements a minimal MPT verifier that:
//! 1. Takes an Ethereum state root, an account address, and proof nodes from `eth_getProof`
//! 2. Verifies the proof path from the state root to the account leaf
//! 3. RLP-decodes the account to extract the balance
//!
//! Uses keccak256 for node hashing and alloy-rlp for RLP decoding.
//! Designed to compile to RISC-V for execution inside SP1 zkVM.

use alloy_rlp::Header;
use tiny_keccak::{Hasher, Keccak};

/// Compute keccak256 hash of the input data.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Convert a 32-byte key into a 64-nibble path.
fn to_nibbles(key: &[u8; 32]) -> [u8; 64] {
    let mut nibbles = [0u8; 64];
    for (i, byte) in key.iter().enumerate() {
        nibbles[i * 2] = byte >> 4;
        nibbles[i * 2 + 1] = byte & 0x0F;
    }
    nibbles
}

/// Decode HP (Hex-Prefix) encoded path into nibbles.
/// Returns (nibbles, is_leaf).
///
/// HP encoding: first nibble encodes flags:
///   0 → extension, even length (next nibble is padding 0)
///   1 → extension, odd length (next nibble is first path nibble)
///   2 → leaf, even length (next nibble is padding 0)
///   3 → leaf, odd length (next nibble is first path nibble)
fn decode_hp(encoded: &[u8]) -> (Vec<u8>, bool) {
    assert!(!encoded.is_empty(), "Empty HP-encoded path");
    let first_nibble = encoded[0] >> 4;
    let is_leaf = first_nibble >= 2;
    let is_odd = first_nibble & 1 == 1;

    let mut nibbles = Vec::new();
    if is_odd {
        // Odd length: second nibble of first byte is the first path nibble
        nibbles.push(encoded[0] & 0x0F);
    }
    // Remaining bytes: each contributes two nibbles
    for &byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }

    (nibbles, is_leaf)
}

/// Decode an RLP list, returning the payload slice (after the list header).
fn decode_rlp_list(data: &[u8]) -> &[u8] {
    let mut buf = data;
    let header = Header::decode(&mut buf).expect("Invalid RLP list header");
    assert!(header.list, "Expected RLP list");
    &buf[..header.payload_length]
}

/// Decode a single RLP string/bytes item from `buf`, advancing the reference.
/// Returns the payload bytes.
fn decode_rlp_bytes<'a>(buf: &mut &'a [u8]) -> &'a [u8] {
    let header = Header::decode(buf).expect("Invalid RLP item header");
    assert!(!header.list, "Expected RLP string, got list");
    let payload = &buf[..header.payload_length];
    *buf = &buf[header.payload_length..];
    payload
}

/// Skip one RLP item (string or list) in `buf`, advancing the reference.
fn skip_rlp_item(buf: &mut &[u8]) {
    let header = Header::decode(buf).expect("Invalid RLP header in skip");
    *buf = &buf[header.payload_length..];
}

/// Count the number of items in an RLP list payload.
fn count_rlp_items(mut payload: &[u8]) -> usize {
    let mut count = 0;
    while !payload.is_empty() {
        let header = Header::decode(&mut payload).expect("Invalid RLP in count");
        payload = &payload[header.payload_length..];
        count += 1;
    }
    count
}

/// Read one RLP item (full encoded bytes including header) from `buf`, advancing the reference.
fn read_rlp_item_raw<'a>(buf: &mut &'a [u8]) -> &'a [u8] {
    let start = *buf;
    let header = Header::decode(buf).expect("Invalid RLP header");
    let header_len = start.len() - buf.len();
    *buf = &buf[header.payload_length..];
    &start[..header_len + header.payload_length]
}

/// Verify an EIP-1186 account proof against the state root and extract the balance.
///
/// # Arguments
/// * `state_root` - The 32-byte Ethereum state root from the block header
/// * `address` - The 20-byte account address to verify
/// * `proof_nodes` - The RLP-encoded MPT proof nodes from `eth_getProof`
///
/// # Returns
/// The account balance as a 32-byte big-endian U256.
/// Returns `[0u8; 32]` if the account does not exist (empty proof for non-existent account).
///
/// # Panics
/// Panics if the proof is invalid (wrong hash chain, malformed RLP, etc.).
/// Inside SP1, panics abort the program and invalidate the proof.
pub fn verify_account_balance(
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof_nodes: &[Vec<u8>],
) -> [u8; 32] {
    // Handle empty proof (account does not exist)
    if proof_nodes.is_empty() {
        return [0u8; 32];
    }

    // 1. Compute the trie key: keccak256(address)
    let account_key = keccak256(address);
    let nibbles = to_nibbles(&account_key);

    // 2. Walk the proof nodes
    let mut expected_hash = *state_root;
    let mut key_offset: usize = 0;
    let mut account_rlp: Option<Vec<u8>> = None;

    for (i, node_rlp) in proof_nodes.iter().enumerate() {
        // Verify this node's hash matches what we expect.
        // The first expected hash is the state root.
        // For inline nodes (< 32 bytes), comparison is direct — but in practice,
        // state trie proof nodes from eth_getProof are always >= 32 bytes.
        let node_hash = keccak256(node_rlp);
        assert!(
            node_hash == expected_hash,
            "MPT proof node hash mismatch at index {}",
            i
        );

        // Decode the node
        let payload = decode_rlp_list(node_rlp);
        let item_count = count_rlp_items(payload);

        if item_count == 17 {
            // Branch node: 16 children + 1 value
            // Follow the child at nibbles[key_offset]
            assert!(
                key_offset < nibbles.len(),
                "Key exhausted at branch node"
            );
            let child_index = nibbles[key_offset] as usize;
            key_offset += 1;

            // Read the child reference at child_index
            let mut buf = payload;
            for _ in 0..child_index {
                skip_rlp_item(&mut buf);
            }
            let child_raw = read_rlp_item_raw(&mut buf);

            // Decode the child reference
            let mut child_buf = child_raw;
            let child_header = Header::decode(&mut child_buf).expect("Invalid child header");

            if child_header.list {
                // Inline node — this is the last node and it's a leaf/extension encoded inline.
                // For account proofs, this shouldn't normally happen (nodes are > 32 bytes).
                // But handle it by treating the child_raw as the next node to process.
                panic!("Inline branch child not expected in state trie account proof");
            } else if child_header.payload_length == 32 {
                // 32-byte hash reference to next node
                expected_hash.copy_from_slice(child_buf);
            } else if child_header.payload_length == 0 {
                // Empty child — account does not exist at this path
                assert!(
                    i == proof_nodes.len() - 1,
                    "Empty branch child not at end of proof"
                );
                return [0u8; 32];
            } else {
                panic!("Unexpected branch child length: {}", child_header.payload_length);
            }
        } else if item_count == 2 {
            // Extension or Leaf node
            let mut buf = payload;
            let path_bytes = decode_rlp_bytes(&mut buf);
            let (path_nibbles, is_leaf) = decode_hp(path_bytes);

            // Verify the path matches our key
            for (j, &nibble) in path_nibbles.iter().enumerate() {
                assert!(
                    key_offset + j < nibbles.len(),
                    "Key exhausted in extension/leaf path"
                );
                assert!(
                    nibbles[key_offset + j] == nibble,
                    "Path mismatch at nibble offset {}",
                    key_offset + j
                );
            }
            key_offset += path_nibbles.len();

            if is_leaf {
                // Leaf node: second item is the RLP-encoded account value
                let value_raw = read_rlp_item_raw(&mut buf);
                // The value is RLP-encoded bytes containing the account RLP
                let mut val_buf = value_raw;
                let val_header = Header::decode(&mut val_buf).expect("Invalid leaf value header");
                if val_header.list {
                    // Value is a list (the account RLP itself)
                    account_rlp = Some(value_raw.to_vec());
                } else {
                    // Value is a string (the raw account RLP bytes)
                    account_rlp = Some(val_buf[..val_header.payload_length].to_vec());
                }
            } else {
                // Extension node: second item is the child reference (hash or inline)
                let child_raw = read_rlp_item_raw(&mut buf);
                let mut child_buf = child_raw;
                let child_header = Header::decode(&mut child_buf).expect("Invalid extension child header");

                if child_header.list {
                    panic!("Inline extension child not expected in state trie account proof");
                } else if child_header.payload_length == 32 {
                    expected_hash.copy_from_slice(child_buf);
                } else {
                    panic!("Unexpected extension child length: {}", child_header.payload_length);
                }
            }
        } else {
            panic!("Unexpected RLP item count: {}", item_count);
        }
    }

    // 3. Decode the account RLP to extract balance
    match account_rlp {
        Some(rlp) => decode_account_balance(&rlp),
        None => [0u8; 32], // Account not found
    }
}

/// Decode an Ethereum account from RLP and extract the balance.
///
/// Account encoding: RLP([nonce, balance, storageRoot, codeHash])
/// Returns the balance as a 32-byte big-endian U256.
fn decode_account_balance(account_rlp: &[u8]) -> [u8; 32] {
    let payload = decode_rlp_list(account_rlp);
    let mut buf = payload;

    // Skip nonce (first item)
    skip_rlp_item(&mut buf);

    // Read balance (second item) — RLP-encoded integer (big-endian, no leading zeros)
    let balance_bytes = decode_rlp_bytes(&mut buf);

    // Left-pad to 32 bytes (big-endian U256)
    let mut result = [0u8; 32];
    if !balance_bytes.is_empty() {
        let offset = 32 - balance_bytes.len();
        result[offset..].copy_from_slice(balance_bytes);
    }

    result
}

// Note: Unit tests for MPT verification cannot run natively because the program crate
// depends on sp1_zkvm (RISC-V target). Tests are in crates/agent/tests/sp1_execution_test.rs
// using the SP1 execute path with real/mock MPT proof test vectors.
