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
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Convert a 32-byte key into a 64-nibble path.
pub(crate) fn to_nibbles(key: &[u8; 32]) -> [u8; 64] {
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
///
/// Enforces canonical encoding: the flag nibble must be 0-3 and the padding
/// nibble in the even case must be zero.
pub(crate) fn decode_hp(encoded: &[u8]) -> Result<(Vec<u8>, bool)> {
    ensure!(!encoded.is_empty(), "Empty HP-encoded path");
    let first_nibble = encoded[0] >> 4;
    ensure!(first_nibble <= 3, "Invalid HP flag nibble: {}", first_nibble);
    let is_leaf = first_nibble >= 2;
    let is_odd = first_nibble & 1 == 1;

    let mut nibbles = Vec::new();
    if is_odd {
        nibbles.push(encoded[0] & 0x0F);
    } else {
        ensure!(
            encoded[0] & 0x0F == 0,
            "Non-canonical HP padding nibble: {}",
            encoded[0] & 0x0F
        );
    }
    for &byte in &encoded[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }

    Ok((nibbles, is_leaf))
}

/// Decode an RLP list, returning the payload slice (after the list header).
pub(crate) fn decode_rlp_list(data: &[u8]) -> Result<&[u8]> {
    let mut buf = data;
    let header = Header::decode(&mut buf).map_err(|e| anyhow::anyhow!("Invalid RLP list header: {}", e))?;
    ensure!(header.list, "Expected RLP list");
    Ok(&buf[..header.payload_length])
}

/// Decode a single RLP string/bytes item from `buf`, advancing the reference.
pub(crate) fn decode_rlp_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let header = Header::decode(buf).map_err(|e| anyhow::anyhow!("Invalid RLP item header: {}", e))?;
    ensure!(!header.list, "Expected RLP string, got list");
    let payload = &buf[..header.payload_length];
    *buf = &buf[header.payload_length..];
    Ok(payload)
}

/// Skip one RLP item (string or list) in `buf`, advancing the reference.
pub(crate) fn skip_rlp_item(buf: &mut &[u8]) -> Result<()> {
    let header = Header::decode(buf).map_err(|e| anyhow::anyhow!("Invalid RLP header in skip: {}", e))?;
    *buf = &buf[header.payload_length..];
    Ok(())
}

/// Count the number of items in an RLP list payload.
pub(crate) fn count_rlp_items(mut payload: &[u8]) -> Result<usize> {
    let mut count = 0;
    while !payload.is_empty() {
        let header = Header::decode(&mut payload).map_err(|e| anyhow::anyhow!("Invalid RLP in count: {}", e))?;
        payload = &payload[header.payload_length..];
        count += 1;
    }
    Ok(count)
}

/// Read one RLP item (full encoded bytes including header) from `buf`, advancing the reference.
pub(crate) fn read_rlp_item_raw<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let start = *buf;
    let header = Header::decode(buf).map_err(|e| anyhow::anyhow!("Invalid RLP header: {}", e))?;
    let header_len = start.len() - buf.len();
    *buf = &buf[header.payload_length..];
    Ok(&start[..header_len + header.payload_length])
}

/// Root hash of the empty trie: `keccak256(rlp(""))`.
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
    0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
    0xb4, 0x21,
];

/// Verified state of an Ethereum account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    /// Balance as a 32-byte big-endian U256.
    pub balance: [u8; 32],
    /// Root of the account's storage trie ([`EMPTY_TRIE_ROOT`] when absent).
    pub storage_root: [u8; 32],
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
/// Returns `[0u8; 32]` only when the account is **proven absent**: either the
/// state root is the empty-trie root (with an empty proof), or the proof is a
/// valid non-inclusion path (empty branch child or diverging leaf/extension).
/// An empty proof against any other root is an error, never absence.
///
/// # Errors
/// Returns an error if the proof is invalid (wrong hash chain, malformed RLP,
/// empty proof against a nonempty root, etc.).
pub fn verify_account_balance(
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof_nodes: &[Vec<u8>],
) -> Result<[u8; 32]> {
    Ok(verify_account_state(state_root, address, proof_nodes)?.balance)
}

/// Verify an account proof with a precomputed trie key (`keccak256(address)`).
///
/// Lets clients avoid sending their plaintext address: the key suffices for
/// verification. (Note this is linkability-equivalent — anyone can dictionary
/// the keccak of known addresses — but the address itself never transits.)
pub fn verify_account_balance_with_key(
    state_root: &[u8; 32],
    account_key: &[u8; 32],
    proof_nodes: &[Vec<u8>],
) -> Result<[u8; 32]> {
    let account_rlp = walk_trie(state_root, account_key, proof_nodes)?;
    match account_rlp {
        Some(rlp) => Ok(decode_account_state(&rlp)?.balance),
        None => Ok([0u8; 32]),
    }
}

/// Verify an account proof and return balance **and** storage root — needed
/// for ERC-20 balance verification (the token's storage trie hangs off its
/// account's storage root).
pub fn verify_account_state(
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof_nodes: &[Vec<u8>],
) -> Result<AccountState> {
    let account_key = keccak256(address);
    match walk_trie(state_root, &account_key, proof_nodes)? {
        Some(rlp) => decode_account_state(&rlp),
        None => Ok(AccountState {
            balance: [0u8; 32],
            storage_root: EMPTY_TRIE_ROOT,
        }),
    }
}

/// The state-trie key of an account: `keccak256(address)`.
///
/// Clients can compute this locally and submit it instead of the plaintext
/// address (see `verify_account_balance_with_key`).
pub fn account_trie_key(address: &[u8; 20]) -> [u8; 32] {
    keccak256(address)
}

/// Compute the storage slot of `balanceOf[holder]` for a Solidity mapping at
/// `slot_index`: `keccak256(pad32(holder) || pad32(slot_index))`.
pub fn erc20_balance_slot(holder: &[u8; 20], slot_index: u64) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(holder);
    input[56..64].copy_from_slice(&slot_index.to_be_bytes());
    keccak256(&input)
}

/// Verify a storage proof against an account's storage root and extract the
/// slot value as a 32-byte big-endian U256.
///
/// `slot` is the storage slot (e.g. from [`erc20_balance_slot`]); the trie
/// key is `keccak256(slot)`. An absent slot is zero — but absence must be
/// **proven**: either the storage root is the empty-trie root (with an empty
/// proof), or the proof is a valid non-inclusion path. An empty proof against
/// a nonempty storage root is an error.
pub fn verify_storage_value(
    storage_root: &[u8; 32],
    slot: &[u8; 32],
    proof_nodes: &[Vec<u8>],
) -> Result<[u8; 32]> {
    let storage_key = keccak256(slot);
    match walk_trie(storage_root, &storage_key, proof_nodes)? {
        Some(value_rlp) => decode_storage_word(&value_rlp),
        None => Ok([0u8; 32]),
    }
}

/// One step of the trie walk: what the current node resolved to.
enum Step {
    /// Reached the value for our key (the leaf value's inner payload).
    Value(Vec<u8>),
    /// The key is **proven absent**: empty branch child at our nibble, or a
    /// leaf/extension path that diverges from our key.
    Absent,
    /// Descend into a hash-referenced child (the next supplied proof node).
    Hash([u8; 32]),
    /// Descend into an embedded child node (< 32 bytes encoded, carried
    /// inline in its parent — no separate proof node, no hash check).
    Inline(Vec<u8>),
}

/// Walk an MPT proof for `trie_key` from `root`, returning the leaf value's
/// inner payload, or `None` when the path is **proven** absent.
///
/// Soundness invariants enforced here:
/// - An empty node list is accepted only against [`EMPTY_TRIE_ROOT`]. For any
///   other root, absence requires a valid non-inclusion path: a walk that
///   terminates at an empty branch child or at a leaf/extension whose path
///   diverges from the key. (An empty list proves nothing about a nonempty
///   trie — see the 2026-07 external review, finding R1.)
/// - Embedded (< 32-byte) child nodes are descended into inline, as Ethereum
///   tries embed them; a supposed inline child ≥ 32 bytes encoded is rejected.
/// - A leaf only yields a value if it consumes the entire remaining key.
/// - The terminal node (value or absence) must be the last supplied node —
///   trailing proof nodes are rejected.
/// - Node encodings must be canonical: exactly one RLP list with no trailing
///   bytes, canonical hex-prefix paths, and 0- or 32-byte hash references.
fn walk_trie(
    root: &[u8; 32],
    trie_key: &[u8; 32],
    proof_nodes: &[Vec<u8>],
) -> Result<Option<Vec<u8>>> {
    if *root == EMPTY_TRIE_ROOT {
        ensure!(
            proof_nodes.is_empty(),
            "Nonempty proof against the empty trie root"
        );
        return Ok(None);
    }
    ensure!(
        !proof_nodes.is_empty(),
        "Empty proof against nonempty trie root {}",
        hex::encode(root),
    );

    let nibbles = to_nibbles(trie_key);
    let mut key_offset: usize = 0;
    let mut node_index: usize = 0;
    let mut expected_hash = *root;

    loop {
        // Fetch the next hash-referenced node and check it against the chain.
        ensure!(
            node_index < proof_nodes.len(),
            "Proof ended before reaching a terminal node"
        );
        let node_rlp = &proof_nodes[node_index];
        node_index += 1;
        let node_hash = keccak256(node_rlp);
        ensure!(
            node_hash == expected_hash,
            "MPT proof node hash mismatch at index {} (expected {}, got {})",
            node_index - 1,
            hex::encode(expected_hash),
            hex::encode(node_hash),
        );

        // Process this node, descending through any embedded children without
        // consuming further proof nodes (they are part of this node's bytes).
        let mut current: Vec<u8> = node_rlp.clone();
        loop {
            match process_node(&current, &nibbles, &mut key_offset)? {
                Step::Value(value) => {
                    ensure!(
                        node_index == proof_nodes.len(),
                        "Trailing proof nodes after the terminal node"
                    );
                    return Ok(Some(value));
                }
                Step::Absent => {
                    ensure!(
                        node_index == proof_nodes.len(),
                        "Trailing proof nodes after a non-inclusion terminal"
                    );
                    return Ok(None);
                }
                Step::Hash(h) => {
                    expected_hash = h;
                    break; // outer loop consumes the next proof node
                }
                Step::Inline(bytes) => {
                    current = bytes; // keep walking inside this proof node
                }
            }
        }
    }
}

/// Decode and process a single trie node, advancing `key_offset`.
fn process_node(node_rlp: &[u8], nibbles: &[u8; 64], key_offset: &mut usize) -> Result<Step> {
    // The node must be exactly one RLP list — no trailing bytes.
    let payload = decode_rlp_list_exact(node_rlp)?;
    let item_count = count_rlp_items(payload)?;

    if item_count == 17 {
        // Branch node: 16 children + 1 value slot.
        // Keys here are fixed-length (64 nibbles, keccak-derived), so a value
        // can never legitimately terminate at a branch's value slot.
        ensure!(*key_offset < nibbles.len(), "Key exhausted at branch node");
        let child_index = nibbles[*key_offset] as usize;
        *key_offset += 1;

        let mut buf = payload;
        for _ in 0..child_index {
            skip_rlp_item(&mut buf)?;
        }
        let child_raw = read_rlp_item_raw(&mut buf)?;
        decode_child_ref(child_raw)
    } else if item_count == 2 {
        // Extension or Leaf node.
        let mut buf = payload;
        let path_bytes = decode_rlp_bytes(&mut buf)?;
        let (path_nibbles, is_leaf) = decode_hp(path_bytes)?;

        // A path that diverges from our key (or overshoots it) proves the key
        // is not in this subtree — valid non-inclusion.
        let remaining = &nibbles[*key_offset..];
        if path_nibbles.len() > remaining.len()
            || path_nibbles[..] != remaining[..path_nibbles.len()]
        {
            return Ok(Step::Absent);
        }
        *key_offset += path_nibbles.len();

        if is_leaf {
            // A leaf yields our value only if it consumed the entire key.
            ensure!(
                *key_offset == nibbles.len(),
                "Leaf does not consume the full key ({} of {} nibbles)",
                *key_offset,
                nibbles.len(),
            );
            // The leaf value is an RLP string whose payload is the value
            // (for accounts, that payload is itself the RLP account list).
            let value_bytes = decode_rlp_bytes(&mut buf)?;
            Ok(Step::Value(value_bytes.to_vec()))
        } else {
            ensure!(!path_nibbles.is_empty(), "Empty extension path");
            let child_raw = read_rlp_item_raw(&mut buf)?;
            match decode_child_ref(child_raw)? {
                Step::Absent => bail!("Extension child reference is empty"),
                step => Ok(step),
            }
        }
    } else {
        bail!("Unexpected RLP item count in trie node: {}", item_count);
    }
}

/// Decode a child reference inside a branch or extension node: a 32-byte hash
/// string, an empty string (absent child), or an embedded node (an RLP list
/// whose full encoding is shorter than 32 bytes).
fn decode_child_ref(child_raw: &[u8]) -> Result<Step> {
    let mut child_buf = child_raw;
    let child_header = Header::decode(&mut child_buf)
        .map_err(|e| anyhow::anyhow!("Invalid child reference header: {}", e))?;

    if child_header.list {
        // Embedded node: the standard MPT rule embeds children whose encoding
        // is < 32 bytes directly in the parent, so no hash check applies —
        // its bytes are already authenticated as part of the parent.
        ensure!(
            child_raw.len() < 32,
            "Embedded child node must be shorter than 32 bytes (got {})",
            child_raw.len(),
        );
        Ok(Step::Inline(child_raw.to_vec()))
    } else if child_header.payload_length == 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&child_buf[..32]);
        Ok(Step::Hash(hash))
    } else if child_header.payload_length == 0 {
        Ok(Step::Absent)
    } else {
        bail!(
            "Unexpected child reference length: {}",
            child_header.payload_length
        );
    }
}

/// Decode an RLP list that must span `data` exactly (no trailing bytes).
fn decode_rlp_list_exact(data: &[u8]) -> Result<&[u8]> {
    let mut buf = data;
    let header =
        Header::decode(&mut buf).map_err(|e| anyhow::anyhow!("Invalid RLP list header: {}", e))?;
    ensure!(header.list, "Expected RLP list");
    ensure!(
        buf.len() == header.payload_length,
        "Trailing bytes after trie node ({} extra)",
        buf.len() - header.payload_length,
    );
    Ok(&buf[..header.payload_length])
}

/// Decode an Ethereum account from RLP: RLP([nonce, balance, storageRoot, codeHash]).
fn decode_account_state(account_rlp: &[u8]) -> Result<AccountState> {
    let payload = decode_rlp_list(account_rlp)?;
    let mut buf = payload;

    // Skip nonce (first item)
    skip_rlp_item(&mut buf)?;

    // Read balance (second item) — RLP-encoded integer (big-endian, no leading zeros)
    let balance_bytes = decode_rlp_bytes(&mut buf)?;
    let balance = left_pad_u256(balance_bytes)?;

    // Read storageRoot (third item) — 32-byte hash
    let storage_root_bytes = decode_rlp_bytes(&mut buf)?;
    ensure!(
        storage_root_bytes.len() == 32,
        "Invalid storageRoot length: {}",
        storage_root_bytes.len()
    );
    let mut storage_root = [0u8; 32];
    storage_root.copy_from_slice(storage_root_bytes);

    Ok(AccountState { balance, storage_root })
}

/// Decode a storage leaf value: the leaf payload is itself an RLP-encoded
/// integer (big-endian, no leading zeros).
fn decode_storage_word(value_rlp: &[u8]) -> Result<[u8; 32]> {
    let mut buf = value_rlp;
    let value_bytes = decode_rlp_bytes(&mut buf)?;
    left_pad_u256(value_bytes)
}

/// Left-pad big-endian integer bytes into a 32-byte U256 word.
///
/// Enforces canonical RLP integer encoding (no leading zero bytes) so two
/// different encodings can never decode to the same value.
fn left_pad_u256(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut result = [0u8; 32];
    if !bytes.is_empty() {
        ensure!(bytes.len() <= 32, "Integer too large: {} bytes", bytes.len());
        ensure!(bytes[0] != 0, "Non-canonical integer: leading zero byte");
        let offset = 32 - bytes.len();
        result[offset..].copy_from_slice(bytes);
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

    // ── Empty-proof soundness (external review finding R1) ──────────────

    #[test]
    fn test_empty_proof_against_nonempty_root_is_rejected() {
        // The R1 vulnerability: an empty proof must NOT be accepted as proof
        // of absence against an arbitrary nonempty root.
        let state_root = [0xAA; 32];
        let address = [0xBB; 20];
        let err = verify_account_balance(&state_root, &address, &[]).unwrap_err();
        assert!(err.to_string().contains("Empty proof against nonempty"));

        let state_err = verify_account_state(&state_root, &address, &[]).unwrap_err();
        assert!(state_err.to_string().contains("Empty proof against nonempty"));

        let slot = erc20_balance_slot(&address, 0);
        let storage_err = verify_storage_value(&state_root, &slot, &[]).unwrap_err();
        assert!(storage_err.to_string().contains("Empty proof against nonempty"));
    }

    #[test]
    fn test_empty_proof_against_empty_root_is_absent() {
        // The ONLY root an empty proof is valid against.
        let address = [0xBB; 20];
        let state = verify_account_state(&EMPTY_TRIE_ROOT, &address, &[]).unwrap();
        assert_eq!(state.balance, [0u8; 32]);
        assert_eq!(state.storage_root, EMPTY_TRIE_ROOT);

        let slot = erc20_balance_slot(&address, 0);
        let value = verify_storage_value(&EMPTY_TRIE_ROOT, &slot, &[]).unwrap();
        assert_eq!(value, [0u8; 32]);
        // A nonempty proof against the empty root is malformed.
        assert!(verify_storage_value(&EMPTY_TRIE_ROOT, &slot, &[vec![0xC0]]).is_err());
    }

    #[test]
    fn test_erc20_balance_slot_derivation() {
        // keccak256(pad32(holder) || pad32(slot)) — spot-check structure by
        // asserting distinctness across holders and slots.
        let a = erc20_balance_slot(&[0x01; 20], 0);
        let b = erc20_balance_slot(&[0x02; 20], 0);
        let c = erc20_balance_slot(&[0x01; 20], 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, erc20_balance_slot(&[0x01; 20], 0), "deterministic");
    }

    #[test]
    fn test_build_trie_roundtrips_with_enumeration() {
        use super::{build_trie, receipt_trie_key};
        use crate::receipt_scan::enumerate_trie_values;

        // Values large enough to be hashed nodes, plus a tiny one that ends up
        // inline — both paths must survive the round trip.
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..5u64)
            .map(|i| (receipt_trie_key(i), vec![i as u8; 40 + i as usize]))
            .chain(std::iter::once((receipt_trie_key(9), vec![0xAB])))
            .collect();

        let (root, nodes) = build_trie(&entries);
        assert_ne!(root, EMPTY_TRIE_ROOT);

        let mut values = enumerate_trie_values(&root, &nodes).unwrap();
        let mut expected: Vec<Vec<u8>> = entries.iter().map(|(_, v)| v.clone()).collect();
        values.sort();
        expected.sort();
        assert_eq!(values, expected, "Every stored value must be enumerable");
    }

    #[test]
    fn test_build_trie_matches_independent_fixtures() {
        use super::build_trie;
        use crate::solvent_derivation::fixtures::{single_leaf_trie, two_leaf_trie};

        // The builder must agree byte-for-byte with the hand-written fixture
        // constructions (which the receipt-scan and derivation suites already
        // verify against the real walker).
        let key = keccak256(&[0x11; 20]);
        let value = vec![0xAB; 40];
        let (fixture_root, fixture_nodes) = single_leaf_trie(key, value.clone());
        let (built_root, built_nodes) = build_trie(&[(key.to_vec(), value)]);
        assert_eq!(built_root, fixture_root, "single-leaf root must match");
        assert_eq!(built_nodes, fixture_nodes);

        // Two keys splitting at the first nibble → branch + two leaves.
        let key_a = keccak256(&[0x01; 20]);
        let key_b = {
            let mut candidate = keccak256(&[0x02; 20]);
            let mut filler = 2u8;
            while (candidate[0] >> 4) == (key_a[0] >> 4) {
                filler += 1;
                candidate = keccak256(&[filler; 20]);
            }
            candidate
        };
        let value_a = vec![0xAA; 40];
        let value_b = vec![0xBB; 40];
        let (fixture_root2, _, _) =
            two_leaf_trie(key_a, value_a.clone(), key_b, value_b.clone());
        let (built_root2, _) =
            build_trie(&[(key_a.to_vec(), value_a), (key_b.to_vec(), value_b)]);
        assert_eq!(built_root2, fixture_root2, "branch-node root must match");
    }

    #[test]
    fn test_build_trie_empty_is_empty_root() {
        use super::build_trie;
        let (root, nodes) = build_trie(&[]);
        assert_eq!(root, EMPTY_TRIE_ROOT);
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_receipt_trie_key_encoding() {
        use super::receipt_trie_key;
        assert_eq!(receipt_trie_key(0), vec![0x80]);
        assert_eq!(receipt_trie_key(1), vec![0x01]);
        assert_eq!(receipt_trie_key(127), vec![0x7F]);
        assert_eq!(receipt_trie_key(128), vec![0x81, 0x80]);
        assert_eq!(receipt_trie_key(256), vec![0x82, 0x01, 0x00]);
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

    // ── Inclusion / non-inclusion over constructed tries ────────────────

    use crate::solvent_derivation::fixtures::{rlp_bytes, rlp_list, single_leaf_trie, two_leaf_trie};

    /// RLP-encode an account: [nonce, balance, storageRoot, codeHash].
    fn account_rlp(nonce: u64, balance: u128, storage_root: &[u8; 32]) -> Vec<u8> {
        let int_bytes = |v: u128| -> Vec<u8> {
            v.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect()
        };
        rlp_list(&[
            rlp_bytes(&int_bytes(nonce as u128)),
            rlp_bytes(&int_bytes(balance)),
            rlp_bytes(storage_root),
            rlp_bytes(&keccak256(&[])), // empty code hash
        ])
    }

    #[test]
    fn test_account_inclusion_single_leaf() {
        let address = [0x11; 20];
        let key = keccak256(&address);
        let balance: u128 = 5_000_000_000_000_000_000;
        let acct = account_rlp(7, balance, &EMPTY_TRIE_ROOT);
        let (root, proof) = single_leaf_trie(key, acct);

        let state = verify_account_state(&root, &address, &proof).unwrap();
        assert!(balance_meets_threshold(&state.balance, balance));
        assert!(!balance_meets_threshold(&state.balance, balance + 1));
        assert_eq!(state.storage_root, EMPTY_TRIE_ROOT);

        // The precomputed-key path must agree byte for byte.
        assert_eq!(
            verify_account_balance(&root, &address, &proof).unwrap(),
            verify_account_balance_with_key(&root, &key, &proof).unwrap(),
        );
    }

    #[test]
    fn test_non_inclusion_via_diverging_leaf() {
        // A single-leaf trie holding key A proves any other key absent: the
        // walk hits the leaf, the path diverges, and that IS the proof.
        let addr_a = [0x11; 20];
        let key_a = keccak256(&addr_a);
        let (root, proof) = single_leaf_trie(key_a, account_rlp(0, 42, &EMPTY_TRIE_ROOT));

        // Find an address whose trie key diverges from A's (first nibble).
        let mut addr_b = [0x22; 20];
        let mut filler = 0x22u8;
        while keccak256(&addr_b)[0] >> 4 == key_a[0] >> 4 {
            filler += 1;
            addr_b = [filler; 20];
        }

        let state = verify_account_state(&root, &addr_b, &proof).unwrap();
        assert_eq!(state.balance, [0u8; 32], "diverging leaf proves absence");
        assert_eq!(state.storage_root, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_non_inclusion_via_empty_branch_child() {
        // Two-leaf trie: querying a key whose first nibble hits an empty
        // branch slot is proven absent by the branch node alone.
        let addr_a = [0x01; 20];
        let key_a = keccak256(&addr_a);
        let (_addr_b, key_b) = {
            let mut filler = 2u8;
            loop {
                let a = [filler; 20];
                let k = keccak256(&a);
                if k[0] >> 4 != key_a[0] >> 4 {
                    break (a, k);
                }
                filler += 1;
            }
        };
        let (root, proof_a, _proof_b) = two_leaf_trie(
            key_a,
            account_rlp(0, 100, &EMPTY_TRIE_ROOT),
            key_b,
            account_rlp(0, 200, &EMPTY_TRIE_ROOT),
        );

        // A third address hitting an unoccupied first nibble: absent with
        // just the branch node as proof.
        let (addr_c, _key_c) = {
            let mut filler = 100u8;
            loop {
                let a = [filler; 20];
                let k = keccak256(&a);
                if k[0] >> 4 != key_a[0] >> 4 && k[0] >> 4 != key_b[0] >> 4 {
                    break (a, k);
                }
                filler += 1;
            }
        };
        let branch_only = vec![proof_a[0].clone()];
        let state = verify_account_state(&root, &addr_c, &branch_only).unwrap();
        assert_eq!(state.balance, [0u8; 32], "empty branch child proves absence");

        // But the branch node alone must NOT prove absence of key A, whose
        // slot is occupied — the proof just ends early.
        let err = verify_account_state(&root, &addr_a, &branch_only).unwrap_err();
        assert!(err.to_string().contains("Proof ended before reaching a terminal node"));
    }

    #[test]
    fn test_embedded_child_nodes_are_walked() {
        // Two keys sharing 63 nibbles → extension → branch with two INLINE
        // leaves (each < 32 bytes encoded). Real Ethereum storage tries embed
        // such nodes; the walker must descend into them.
        let mut key_a = [0x55u8; 32];
        let mut key_b = [0x55u8; 32];
        key_a[31] = 0x51; // last nibble 1
        key_b[31] = 0x52; // last nibble 2
        let (root, nodes) = build_trie(&[
            (key_a.to_vec(), vec![0x2A]), // storage word 42
            (key_b.to_vec(), vec![0x37]),
        ]);
        // Everything inline except the root extension node.
        assert_eq!(nodes.len(), 1, "fixture must exercise inline children");

        let value = walk_trie(&root, &key_a, &nodes).unwrap().unwrap();
        assert_eq!(decode_storage_word(&rlp_bytes(&value)).unwrap()[31], 0x2A);
        let value_b = walk_trie(&root, &key_b, &nodes).unwrap().unwrap();
        assert_eq!(decode_storage_word(&rlp_bytes(&value_b)).unwrap()[31], 0x37);

        // A key hitting an empty slot of the embedded branch: proven absent.
        let mut key_c = [0x55u8; 32];
        key_c[31] = 0x53;
        assert!(walk_trie(&root, &key_c, &nodes).unwrap().is_none());
    }

    #[test]
    fn test_trailing_proof_nodes_rejected() {
        let address = [0x11; 20];
        let key = keccak256(&address);
        let (root, mut proof) = single_leaf_trie(key, account_rlp(0, 42, &EMPTY_TRIE_ROOT));
        proof.push(vec![0xC0]); // garbage after the terminal node
        let err = verify_account_state(&root, &address, &proof).unwrap_err();
        assert!(err.to_string().contains("Trailing proof nodes"));
    }

    #[test]
    fn test_leaf_must_consume_full_key() {
        // A leaf whose path is a strict prefix of the key must not yield a
        // value — hand-build one with only the first 10 nibbles.
        let address = [0x11; 20];
        let key = keccak256(&address);
        let mut hp = vec![0x20]; // leaf, even
        hp.extend_from_slice(&key[..5]); // 10 nibbles only
        let leaf = rlp_list(&[rlp_bytes(&hp), rlp_bytes(&account_rlp(0, 42, &EMPTY_TRIE_ROOT))]);
        let root = keccak256(&leaf);
        let err = verify_account_state(&root, &address, &[leaf]).unwrap_err();
        assert!(err.to_string().contains("Leaf does not consume the full key"));
    }

    #[test]
    fn test_non_canonical_encodings_rejected() {
        let address = [0x11; 20];
        let key = keccak256(&address);

        // Leading-zero balance is a non-canonical RLP integer.
        let bad_acct = rlp_list(&[
            rlp_bytes(&[]),
            rlp_bytes(&[0x00, 0x2A]), // 42 with a leading zero
            rlp_bytes(&EMPTY_TRIE_ROOT),
            rlp_bytes(&keccak256(&[])),
        ]);
        let (root, proof) = single_leaf_trie(key, bad_acct);
        let err = verify_account_state(&root, &address, &proof).unwrap_err();
        assert!(err.to_string().contains("leading zero"));

        // Invalid HP flag nibble (>= 4).
        let mut bad_hp = vec![0x40];
        bad_hp.extend_from_slice(&key);
        let bad_leaf = rlp_list(&[rlp_bytes(&bad_hp), rlp_bytes(&account_rlp(0, 1, &EMPTY_TRIE_ROOT))]);
        let bad_root = keccak256(&bad_leaf);
        let err = verify_account_state(&bad_root, &address, &[bad_leaf]).unwrap_err();
        assert!(err.to_string().contains("Invalid HP flag"));

        // Non-zero padding nibble in an even-length HP path.
        let mut pad_hp = vec![0x21];
        pad_hp.extend_from_slice(&key);
        let pad_leaf = rlp_list(&[rlp_bytes(&pad_hp), rlp_bytes(&account_rlp(0, 1, &EMPTY_TRIE_ROOT))]);
        let pad_root = keccak256(&pad_leaf);
        let err = verify_account_state(&pad_root, &address, &[pad_leaf]).unwrap_err();
        assert!(err.to_string().contains("padding nibble"));

        // Trailing bytes after the node's RLP list.
        let mut hp = vec![0x20];
        hp.extend_from_slice(&key);
        let mut padded_leaf = rlp_list(&[rlp_bytes(&hp), rlp_bytes(&account_rlp(0, 1, &EMPTY_TRIE_ROOT))]);
        padded_leaf.push(0x00);
        let padded_root = keccak256(&padded_leaf);
        let err = verify_account_state(&padded_root, &address, &[padded_leaf]).unwrap_err();
        assert!(err.to_string().contains("Trailing bytes"));
    }

    #[test]
    fn test_oversized_embedded_child_rejected() {
        // A branch child that is an RLP list but >= 32 bytes encoded must be
        // hash-referenced, never embedded.
        let address = [0x11; 20];
        let key = keccak256(&address);
        let first_nibble = (key[0] >> 4) as usize;

        let big_inline = rlp_list(&[rlp_bytes(&[0xAB; 20]), rlp_bytes(&[0xCD; 10])]);
        assert!(big_inline.len() >= 32);
        let mut branch_items: Vec<Vec<u8>> = (0..17).map(|_| rlp_bytes(&[])).collect();
        branch_items[first_nibble] = big_inline;
        let branch = rlp_list(&branch_items);
        let root = keccak256(&branch);

        let err = verify_account_state(&root, &address, &[branch]).unwrap_err();
        assert!(err.to_string().contains("Embedded child node must be shorter"));
    }

    // ── Randomized round-trip: build_trie ↔ walk_trie ───────────────────

    /// Extract the ordered proof path for `trie_key` from an unordered node
    /// set (as returned by `build_trie`), using the same node decoder.
    fn extract_proof(
        root: &[u8; 32],
        trie_key: &[u8; 32],
        nodes: &[Vec<u8>],
    ) -> Vec<Vec<u8>> {
        use std::collections::HashMap;
        let by_hash: HashMap<[u8; 32], &Vec<u8>> =
            nodes.iter().map(|n| (keccak256(n), n)).collect();
        let nibbles = to_nibbles(trie_key);
        let mut key_offset = 0usize;
        let mut proof = Vec::new();
        let mut hash = *root;
        loop {
            let node = by_hash.get(&hash).expect("node on path must exist");
            proof.push((*node).clone());
            let mut current: Vec<u8> = (*node).clone();
            loop {
                match process_node(&current, &nibbles, &mut key_offset).expect("valid node") {
                    Step::Value(_) | Step::Absent => return proof,
                    Step::Hash(h) => {
                        hash = h;
                        break;
                    }
                    Step::Inline(bytes) => current = bytes,
                }
            }
        }
    }

    #[test]
    fn test_randomized_inclusion_and_absence() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x5eed_2026_07_27);

        for round in 0..10 {
            let n = 1 + (round * 37) % 200;
            let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
                .map(|_| {
                    let key: [u8; 32] = rng.gen();
                    let value_len = 1 + rng.gen_range(0..60usize);
                    let value: Vec<u8> = (0..value_len).map(|_| rng.gen::<u8>().max(1)).collect();
                    (key.to_vec(), value)
                })
                .collect();
            let mut deduped = entries.clone();
            deduped.sort();
            deduped.dedup_by(|a, b| a.0 == b.0);

            let (root, nodes) = build_trie(&deduped);

            // Every stored key must verify with its extracted proof.
            for (key_bytes, value) in &deduped {
                let key: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
                let proof = extract_proof(&root, &key, &nodes);
                let got = walk_trie(&root, &key, &proof).unwrap().expect("stored key present");
                assert_eq!(&got, value);
            }

            // Random absent keys must be provably absent (never an error, and
            // never a value).
            for _ in 0..20 {
                let key: [u8; 32] = rng.gen();
                if deduped.iter().any(|(k, _)| k.as_slice() == key) {
                    continue;
                }
                let proof = extract_proof(&root, &key, &nodes);
                assert!(walk_trie(&root, &key, &proof).unwrap().is_none());
                // And with the proof truncated, absence must NOT be accepted.
                if proof.len() > 1 {
                    let truncated = proof[..proof.len() - 1].to_vec();
                    assert!(walk_trie(&root, &key, &truncated).is_err());
                }
            }
        }
    }
}

// ─── Trie construction (witness building) ───────────────────────────────────

/// Build a Merkle-Patricia trie from `(key, value)` pairs and return
/// `(root, nodes)` — every node of the finished trie, which is exactly the
/// witness `enumerate_trie_values` needs.
///
/// Used to reconstruct a block's receipts trie from raw receipts
/// (`key = rlp(index)`), so a Stage B.2 scan witness can be produced from any
/// full node. The caller checks the returned root against the block header's
/// `receiptsRoot`; a mismatch means the inputs were wrong, which is why this
/// helper needs no trust.
///
/// Keys must be unique. Values are stored verbatim (already-encoded receipts).
pub fn build_trie(entries: &[(Vec<u8>, Vec<u8>)]) -> ([u8; 32], Vec<Vec<u8>>) {
    if entries.is_empty() {
        return (EMPTY_TRIE_ROOT, Vec::new());
    }

    // Work in nibble space; the builder is a straightforward recursive
    // construction over the sorted key set.
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .map(|(k, v)| (bytes_to_nibbles(k), v.clone()))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut nodes = Vec::new();
    let reference = build_node(&items, 0, &mut nodes);

    // The root reference is either a 32-byte hash (node already collected) or
    // an inline node small enough to embed — in which case it is the root
    // node itself and must be hashed.
    let root = match reference {
        NodeRef::Hash(h) => h,
        NodeRef::Inline(encoded) => {
            let h = keccak256(&encoded);
            nodes.push(encoded);
            h
        }
    };
    (root, nodes)
}

/// A child reference inside the trie builder.
enum NodeRef {
    Hash([u8; 32]),
    Inline(Vec<u8>),
}

impl NodeRef {
    /// The RLP item a parent embeds for this child: a 32-byte string for
    /// hashed nodes, or the node's own encoding inline.
    fn to_rlp_item(&self) -> Vec<u8> {
        match self {
            NodeRef::Hash(h) => rlp_encode_bytes(h),
            NodeRef::Inline(encoded) => encoded.clone(),
        }
    }
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [b >> 4, b & 0x0F]).collect()
}

/// Hex-prefix encode a nibble path.
fn hp_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 2u8 } else { 0u8 };
    let mut out = Vec::with_capacity(nibbles.len() / 2 + 1);
    if nibbles.len() % 2 == 1 {
        out.push(((flag + 1) << 4) | nibbles[0]);
        for pair in nibbles[1..].chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    } else {
        out.push(flag << 4);
        for pair in nibbles.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    }
    out
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len() + 5);
    if data.len() < 56 {
        out.push(0x80 + data.len() as u8);
    } else {
        let len_bytes: Vec<u8> = data
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0xB7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(data);
    out
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = Vec::with_capacity(payload.len() + 9);
    if payload.len() < 56 {
        out.push(0xC0 + payload.len() as u8);
    } else {
        let len_bytes: Vec<u8> = payload
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0xF7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(&payload);
    out
}

/// Finish a node: nodes ≥ 32 bytes encoded are hashed and collected; shorter
/// ones are embedded inline in their parent (standard MPT rule).
fn finish_node(encoded: Vec<u8>, nodes: &mut Vec<Vec<u8>>) -> NodeRef {
    if encoded.len() >= 32 {
        let hash = keccak256(&encoded);
        nodes.push(encoded);
        NodeRef::Hash(hash)
    } else {
        NodeRef::Inline(encoded)
    }
}

/// Recursively build the subtrie covering `items` (sorted, sharing the first
/// `depth` nibbles).
fn build_node(items: &[(Vec<u8>, Vec<u8>)], depth: usize, nodes: &mut Vec<Vec<u8>>) -> NodeRef {
    debug_assert!(!items.is_empty());

    if items.len() == 1 {
        let (key, value) = &items[0];
        let encoded = rlp_encode_list(&[
            rlp_encode_bytes(&hp_encode(&key[depth..], true)),
            rlp_encode_bytes(value),
        ]);
        return finish_node(encoded, nodes);
    }

    // Longest common prefix beyond `depth` → extension node.
    let first = &items[0].0;
    let last = &items[items.len() - 1].0;
    let mut common = depth;
    while common < first.len() && common < last.len() && first[common] == last[common] {
        common += 1;
    }
    if common > depth {
        let child = build_node(items, common, nodes);
        let encoded = rlp_encode_list(&[
            rlp_encode_bytes(&hp_encode(&first[depth..common], false)),
            child.to_rlp_item(),
        ]);
        return finish_node(encoded, nodes);
    }

    // Branch node: split by the nibble at `depth`.
    let mut branch_items: Vec<Vec<u8>> = Vec::with_capacity(17);
    for nibble in 0..16u8 {
        let group: Vec<(Vec<u8>, Vec<u8>)> = items
            .iter()
            .filter(|(k, _)| k.len() > depth && k[depth] == nibble)
            .cloned()
            .collect();
        if group.is_empty() {
            branch_items.push(rlp_encode_bytes(&[]));
        } else {
            branch_items.push(build_node(&group, depth + 1, nodes).to_rlp_item());
        }
    }
    // Value slot: a key that ends exactly here.
    match items.iter().find(|(k, _)| k.len() == depth) {
        Some((_, value)) => branch_items.push(rlp_encode_bytes(value)),
        None => branch_items.push(rlp_encode_bytes(&[])),
    }
    finish_node(rlp_encode_list(&branch_items), nodes)
}

/// The receipts-trie key for transaction `index`: `rlp(index)`.
pub fn receipt_trie_key(index: u64) -> Vec<u8> {
    if index == 0 {
        return rlp_encode_bytes(&[]);
    }
    let be: Vec<u8> = index.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    rlp_encode_bytes(&be)
}
