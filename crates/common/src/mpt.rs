//! Merkle Patricia Trie (MPT) verification for EIP-1186 account proofs.
//!
//! Shared between the host (agent, which re-exports this as `mpt_verifier`)
//! and the SP1 guests (`program-solvent-set/` imports it directly), so the
//! circuit and the native code are the same bytes. Uses `anyhow::Result`
//! error handling; guests `.expect()` to abort the proof on invalid input.
//!
//! ## Privacy Note
//!
//! The `address` parameter is used *transiently* during MPT verification to compute
//! the trie key (keccak256(address)). It is **never stored** — after verification
//! completes, the address is discarded.

use anyhow::{bail, ensure, Result};
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
fn decode_hp(encoded: &[u8]) -> Result<(Vec<u8>, bool)> {
    ensure!(!encoded.is_empty(), "Empty HP-encoded path");
    let first_nibble = encoded[0] >> 4;
    let is_leaf = first_nibble >= 2;
    let is_odd = first_nibble & 1 == 1;

    let mut nibbles = Vec::new();
    if is_odd {
        nibbles.push(encoded[0] & 0x0F);
    }
    for &byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }

    Ok((nibbles, is_leaf))
}

/// Decode an RLP list, returning the payload slice (after the list header).
fn decode_rlp_list(data: &[u8]) -> Result<&[u8]> {
    let mut buf = data;
    let header = Header::decode(&mut buf).map_err(|e| anyhow::anyhow!("Invalid RLP list header: {}", e))?;
    ensure!(header.list, "Expected RLP list");
    Ok(&buf[..header.payload_length])
}

/// Decode a single RLP string/bytes item from `buf`, advancing the reference.
fn decode_rlp_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let header = Header::decode(buf).map_err(|e| anyhow::anyhow!("Invalid RLP item header: {}", e))?;
    ensure!(!header.list, "Expected RLP string, got list");
    let payload = &buf[..header.payload_length];
    *buf = &buf[header.payload_length..];
    Ok(payload)
}

/// Skip one RLP item (string or list) in `buf`, advancing the reference.
fn skip_rlp_item(buf: &mut &[u8]) -> Result<()> {
    let header = Header::decode(buf).map_err(|e| anyhow::anyhow!("Invalid RLP header in skip: {}", e))?;
    *buf = &buf[header.payload_length..];
    Ok(())
}

/// Count the number of items in an RLP list payload.
fn count_rlp_items(mut payload: &[u8]) -> Result<usize> {
    let mut count = 0;
    while !payload.is_empty() {
        let header = Header::decode(&mut payload).map_err(|e| anyhow::anyhow!("Invalid RLP in count: {}", e))?;
        payload = &payload[header.payload_length..];
        count += 1;
    }
    Ok(count)
}

/// Read one RLP item (full encoded bytes including header) from `buf`, advancing the reference.
fn read_rlp_item_raw<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let start = *buf;
    let header = Header::decode(buf).map_err(|e| anyhow::anyhow!("Invalid RLP header: {}", e))?;
    let header_len = start.len() - buf.len();
    *buf = &buf[header.payload_length..];
    Ok(&start[..header_len + header.payload_length])
}

/// Verify an EIP-1186 account proof against the state root and extract the balance.
///
/// # Arguments
/// * `state_root` - The 32-byte Ethereum state root from the block header
/// * `address` - The 20-byte account address to verify (used transiently, NOT stored)
/// * `proof_nodes` - The RLP-encoded MPT proof nodes from `eth_getProof`
///
/// # Returns
/// The account balance as a 32-byte big-endian U256.
/// Returns `[0u8; 32]` if the account does not exist (empty proof).
///
/// # Errors
/// Returns an error if the proof is invalid (wrong hash chain, malformed RLP, etc.).
pub fn verify_account_balance(
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof_nodes: &[Vec<u8>],
) -> Result<[u8; 32]> {
    // Handle empty proof (account does not exist)
    if proof_nodes.is_empty() {
        return Ok([0u8; 32]);
    }

    // 1. Compute the trie key: keccak256(address)
    let account_key = keccak256(address);
    let nibbles = to_nibbles(&account_key);

    // 2. Walk the proof nodes
    let mut expected_hash = *state_root;
    let mut key_offset: usize = 0;
    let mut account_rlp: Option<Vec<u8>> = None;

    for (i, node_rlp) in proof_nodes.iter().enumerate() {
        // Verify this node's hash matches what we expect
        let node_hash = keccak256(node_rlp);
        ensure!(
            node_hash == expected_hash,
            "MPT proof node hash mismatch at index {} (expected {}, got {})",
            i,
            hex::encode(expected_hash),
            hex::encode(node_hash),
        );

        // Decode the node
        let payload = decode_rlp_list(node_rlp)?;
        let item_count = count_rlp_items(payload)?;

        if item_count == 17 {
            // Branch node: 16 children + 1 value
            ensure!(key_offset < nibbles.len(), "Key exhausted at branch node");
            let child_index = nibbles[key_offset] as usize;
            key_offset += 1;

            // Read the child reference at child_index
            let mut buf = payload;
            for _ in 0..child_index {
                skip_rlp_item(&mut buf)?;
            }
            let child_raw = read_rlp_item_raw(&mut buf)?;

            // Decode the child reference
            let mut child_buf = child_raw;
            let child_header = Header::decode(&mut child_buf)
                .map_err(|e| anyhow::anyhow!("Invalid child header: {}", e))?;

            if child_header.list {
                bail!("Inline branch child not expected in state trie account proof");
            } else if child_header.payload_length == 32 {
                expected_hash.copy_from_slice(child_buf);
            } else if child_header.payload_length == 0 {
                ensure!(
                    i == proof_nodes.len() - 1,
                    "Empty branch child not at end of proof"
                );
                return Ok([0u8; 32]);
            } else {
                bail!("Unexpected branch child length: {}", child_header.payload_length);
            }
        } else if item_count == 2 {
            // Extension or Leaf node
            let mut buf = payload;
            let path_bytes = decode_rlp_bytes(&mut buf)?;
            let (path_nibbles, is_leaf) = decode_hp(path_bytes)?;

            // Verify the path matches our key
            for (j, &nibble) in path_nibbles.iter().enumerate() {
                ensure!(
                    key_offset + j < nibbles.len(),
                    "Key exhausted in extension/leaf path"
                );
                ensure!(
                    nibbles[key_offset + j] == nibble,
                    "Path mismatch at nibble offset {}",
                    key_offset + j,
                );
            }
            key_offset += path_nibbles.len();

            if is_leaf {
                // Leaf node: second item is the RLP-encoded account value
                let value_raw = read_rlp_item_raw(&mut buf)?;
                let mut val_buf = value_raw;
                let val_header = Header::decode(&mut val_buf)
                    .map_err(|e| anyhow::anyhow!("Invalid leaf value header: {}", e))?;
                if val_header.list {
                    account_rlp = Some(value_raw.to_vec());
                } else {
                    account_rlp = Some(val_buf[..val_header.payload_length].to_vec());
                }
            } else {
                // Extension node: second item is the child reference
                let child_raw = read_rlp_item_raw(&mut buf)?;
                let mut child_buf = child_raw;
                let child_header = Header::decode(&mut child_buf)
                    .map_err(|e| anyhow::anyhow!("Invalid extension child header: {}", e))?;

                if child_header.list {
                    bail!("Inline extension child not expected in state trie account proof");
                } else if child_header.payload_length == 32 {
                    expected_hash.copy_from_slice(child_buf);
                } else {
                    bail!("Unexpected extension child length: {}", child_header.payload_length);
                }
            }
        } else {
            bail!("Unexpected RLP item count: {}", item_count);
        }
    }

    // 3. Decode the account RLP to extract balance
    match account_rlp {
        Some(rlp) => decode_account_balance(&rlp),
        None => Ok([0u8; 32]),
    }
}

/// Decode an Ethereum account from RLP and extract the balance.
///
/// Account encoding: RLP([nonce, balance, storageRoot, codeHash])
/// Returns the balance as a 32-byte big-endian U256.
fn decode_account_balance(account_rlp: &[u8]) -> Result<[u8; 32]> {
    let payload = decode_rlp_list(account_rlp)?;
    let mut buf = payload;

    // Skip nonce (first item)
    skip_rlp_item(&mut buf)?;

    // Read balance (second item) — RLP-encoded integer (big-endian, no leading zeros)
    let balance_bytes = decode_rlp_bytes(&mut buf)?;

    // Left-pad to 32 bytes (big-endian U256)
    let mut result = [0u8; 32];
    if !balance_bytes.is_empty() {
        ensure!(
            balance_bytes.len() <= 32,
            "Balance too large: {} bytes",
            balance_bytes.len()
        );
        let offset = 32 - balance_bytes.len();
        result[offset..].copy_from_slice(balance_bytes);
    }

    Ok(result)
}

/// Compare a 32-byte big-endian balance against a u128 threshold.
/// Returns true if balance >= threshold.
pub fn balance_meets_threshold(balance: &[u8; 32], threshold_wei: u128) -> bool {
    let mut threshold_bytes = [0u8; 32];
    threshold_bytes[16..].copy_from_slice(&threshold_wei.to_be_bytes());
    balance >= &threshold_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = keccak256(&[]);
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_to_nibbles() {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        key[1] = 0xCD;
        let nibbles = to_nibbles(&key);
        assert_eq!(nibbles[0], 0x0A);
        assert_eq!(nibbles[1], 0x0B);
        assert_eq!(nibbles[2], 0x0C);
        assert_eq!(nibbles[3], 0x0D);
    }

    #[test]
    fn test_balance_meets_threshold() {
        // 2 ETH = 2_000_000_000_000_000_000
        let mut balance = [0u8; 32];
        let two_eth: u128 = 2_000_000_000_000_000_000;
        balance[16..].copy_from_slice(&two_eth.to_be_bytes());

        // Threshold 1 ETH
        let one_eth: u128 = 1_000_000_000_000_000_000;
        assert!(balance_meets_threshold(&balance, one_eth));

        // Threshold 3 ETH
        let three_eth: u128 = 3_000_000_000_000_000_000;
        assert!(!balance_meets_threshold(&balance, three_eth));
    }

    #[test]
    fn test_empty_proof_returns_zero() {
        let state_root = [0xAA; 32];
        let address = [0xBB; 20];
        let result = verify_account_balance(&state_root, &address, &[]).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_invalid_proof_node_hash() {
        let state_root = [0xAA; 32];
        let address = [0xBB; 20];
        // A proof node whose hash won't match the state root
        let bad_node = vec![0xC0]; // minimal RLP empty list
        let result = verify_account_balance(&state_root, &address, &[bad_node]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }
}
