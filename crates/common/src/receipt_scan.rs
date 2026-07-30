//! Stage B.2 — receipt-scan candidate completeness (host mirror of
//! `program-receipt-scan/`).
//!
//! The derivation proof (solvent_derivation.rs) shows every *checked*
//! candidate's balance honestly; what it cannot show is that no qualifying
//! holder was *omitted*. For ERC-20s, completeness is provable: any address
//! with a nonzero balance must have appeared in a `Transfer` event, so
//! exhaustively enumerating **every receipt of every block** in the token's
//! history (or since a trusted checkpoint) yields a superset of all holders.
//!
//! ```text
//! Private:  headers[0..n], per-block receipt-trie nodes
//! Public:   end_block_hash, start_block, end_block, num_blocks, token,
//!           participants_root, participant_count
//!
//! 1. for i in 1..n: parse(headers[i]).parent_hash == keccak(headers[i-1])
//!    AND parse(headers[i]).number == start_block + i
//!    (a contiguous, unbroken header chain whose *range* is proven, not
//!    asserted — external review finding R3)
//! 2. per block: enumerate the ENTIRE receipts trie from the header's
//!    receiptsRoot — every branch child must resolve (missing node aborts),
//!    so no receipt can be hidden
//! 3. parse each receipt (legacy or EIP-2718 typed), collect the from/to of
//!    every Transfer event of `token`
//! 4. participants_root = CandidatesRoot(participants)   (same commitment the
//!    derivation proof exposes as candidates_root — equality of the two roots
//!    is the composition check)
//! 5. commit abi.encode(end_block_hash, start_block, end_block, num_blocks,
//!                      token, participants_root, participant_count)
//! ```
//!
//! An on-chain verifier binds `end_block_hash` to the chain (via EIP-2935,
//! which serves ~8191 ancestor hashes and so leaves room for a real proving
//! job), records the covered range, and checks
//! `participants_root == derivation.candidates_root`.
//!
//! **Completeness is relative to the scanned range**, never absolute: a root
//! published this way is `Provenance.RangeScanProven`, and no surface may
//! describe it as simply "complete".
//!
//! Witness building (fetching raw receipts and reconstructing the tries) is
//! operator-side tooling, out of scope here — any full node can produce it
//! and the proof does not trust the producer.

use crate::mpt::{
    count_rlp_items, decode_hp, decode_rlp_bytes, decode_rlp_list, keccak256, read_rlp_item_raw,
    skip_rlp_item, EMPTY_TRIE_ROOT,
};
use crate::solvent_derivation::candidates_root;
use anyhow::{bail, ensure, Context, Result};
use std::collections::BTreeSet;

/// `keccak256("Transfer(address,address,uint256)")` — topic0 of ERC-20 transfers.
pub const TRANSFER_EVENT_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
    0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
    0xb3, 0xef,
];

/// Fields extracted from a block header by the fixed-shape walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    /// Header item 8. Read from the header itself so the scan's block range
    /// is *proven* rather than asserted by the operator (review finding R3).
    pub number: u64,
}

/// Private inputs to the scan statement.
#[derive(Debug, Clone)]
pub struct ScanWitness {
    /// Full RLP block headers, oldest first, forming a contiguous chain.
    pub headers: Vec<Vec<u8>>,
    /// Per-header: every node of that block's receipts trie.
    pub receipt_nodes: Vec<Vec<Vec<u8>>>,
}

/// Public values committed by the receipt-scan program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPublicValues {
    /// `keccak256` of the last (newest) header — bind via `blockhash` on-chain.
    pub end_block_hash: [u8; 32],
    /// First block of the scanned range (inclusive). Without this the range
    /// is unpinned and a one-block scan is indistinguishable from a full
    /// history scan (external review finding R3).
    pub start_block: u64,
    /// Last block of the scanned range (inclusive).
    pub end_block: u64,
    /// Number of contiguous blocks scanned; must equal
    /// `end_block - start_block + 1`.
    pub num_blocks: u64,
    /// The token whose Transfer participants were collected.
    pub token: [u8; 20],
    /// Commitment to the participant set — same construction as the
    /// derivation proof's `candidates_root`.
    pub participants_root: [u8; 32],
    pub participant_count: u32,
}

/// ABI-encoded size: seven 32-byte words.
pub const SCAN_PUBLIC_VALUES_LEN: usize = 224;

impl ScanPublicValues {
    /// `abi.encode(bytes32, uint64, uint64, uint64, address, bytes32, uint32)`
    /// — 224 bytes.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SCAN_PUBLIC_VALUES_LEN);
        out.extend_from_slice(&self.end_block_hash);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.start_block.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.end_block.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.num_blocks.to_be_bytes());
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.participants_root);
        out.extend_from_slice(&[0u8; 28]);
        out.extend_from_slice(&self.participant_count.to_be_bytes());
        out
    }

    /// Decode and validate a 224-byte public-values blob.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SCAN_PUBLIC_VALUES_LEN {
            bail!(
                "Invalid scan public values length: expected {}, got {}",
                SCAN_PUBLIC_VALUES_LEN,
                bytes.len()
            );
        }
        if bytes[32..56] != [0u8; 24]
            || bytes[64..88] != [0u8; 24]
            || bytes[96..120] != [0u8; 24]
            || bytes[128..140] != [0u8; 12]
            || bytes[192..220] != [0u8; 28]
        {
            bail!("Invalid scan public values: nonzero padding");
        }
        let mut end_block_hash = [0u8; 32];
        end_block_hash.copy_from_slice(&bytes[0..32]);
        let mut token = [0u8; 20];
        token.copy_from_slice(&bytes[140..160]);
        let mut participants_root = [0u8; 32];
        participants_root.copy_from_slice(&bytes[160..192]);
        let start_block = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
        let end_block = u64::from_be_bytes(bytes[88..96].try_into().unwrap());
        let num_blocks = u64::from_be_bytes(bytes[120..128].try_into().unwrap());
        // The range must be internally consistent; the contract enforces the
        // same rule, but rejecting here keeps the host mirror honest too.
        if end_block < start_block || num_blocks != end_block - start_block + 1 {
            bail!(
                "Inconsistent scan range: [{}, {}] does not span {} blocks",
                start_block,
                end_block,
                num_blocks
            );
        }
        Ok(Self {
            end_block_hash,
            start_block,
            end_block,
            num_blocks,
            token,
            participants_root,
            participant_count: u32::from_be_bytes(bytes[220..224].try_into().unwrap()),
        })
    }
}

/// Parse the fields we need from an RLP block header via a fixed-shape walk.
///
/// Ethereum headers invariantly encode:
///   item 0: parentHash   — 32-byte string
///   item 1: unclesHash   — 32-byte string
///   item 2: coinbase     — 20-byte string
///   item 3: stateRoot    — 32-byte string
///   item 4: txRoot       — 32-byte string
///   item 5: receiptsRoot — 32-byte string
pub fn parse_header(header: &[u8]) -> Result<HeaderInfo> {
    ensure!(header.len() >= 4, "Header too short");

    let mut offset: usize;
    let list_prefix = header[0];
    if (0xC0..=0xF7).contains(&list_prefix) {
        offset = 1;
    } else if list_prefix > 0xF7 {
        offset = 1 + (list_prefix - 0xF7) as usize;
    } else {
        bail!("Header is not an RLP list");
    }

    let read32 = |offset: &mut usize| -> Result<[u8; 32]> {
        ensure!(
            header.len() >= *offset + 33 && header[*offset] == 0xA0,
            "Malformed header: expected 32-byte item at offset {offset}"
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&header[*offset + 1..*offset + 33]);
        *offset += 33;
        Ok(out)
    };

    let parent_hash = read32(&mut offset)?; // item 0
    let _uncles = read32(&mut offset)?; // item 1
    // item 2: coinbase (20-byte string)
    ensure!(
        header.len() >= offset + 21 && header[offset] == 0x94,
        "Malformed header: expected coinbase at offset {offset}"
    );
    offset += 21;
    let state_root = read32(&mut offset)?; // item 3
    let _tx_root = read32(&mut offset)?; // item 4
    let receipts_root = read32(&mut offset)?; // item 5

    // items 6-7: logsBloom (256 bytes) and difficulty — skipped; item 8 is
    // the block number, encoded as a canonical big-endian integer.
    skip_header_item(header, &mut offset)?; // logsBloom
    skip_header_item(header, &mut offset)?; // difficulty
    let number_bytes = read_header_item(header, &mut offset)?; // number
    ensure!(
        number_bytes.len() <= 8,
        "Malformed header: block number too large ({} bytes)",
        number_bytes.len()
    );
    ensure!(
        number_bytes.first() != Some(&0),
        "Malformed header: non-canonical block number"
    );
    let mut number = 0u64;
    for byte in number_bytes {
        number = (number << 8) | *byte as u64;
    }

    Ok(HeaderInfo { parent_hash, state_root, receipts_root, number })
}

/// Read one RLP *string* item from a header, advancing `offset`.
fn read_header_item<'a>(header: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    ensure!(*offset < header.len(), "Malformed header: truncated at {offset}");
    let prefix = header[*offset];
    let (start, len) = if prefix < 0x80 {
        (*offset, 1usize) // single byte, encodes itself
    } else if prefix <= 0xB7 {
        (*offset + 1, (prefix - 0x80) as usize)
    } else if prefix <= 0xBF {
        let len_of_len = (prefix - 0xB7) as usize;
        ensure!(
            len_of_len <= 8 && *offset + 1 + len_of_len <= header.len(),
            "Malformed header: bad long-string length"
        );
        let mut len = 0usize;
        for i in 0..len_of_len {
            len = (len << 8) | header[*offset + 1 + i] as usize;
        }
        (*offset + 1 + len_of_len, len)
    } else {
        bail!("Malformed header: expected a string item at offset {offset}");
    };
    ensure!(
        start + len <= header.len(),
        "Malformed header: item overruns the header"
    );
    *offset = start + len;
    Ok(&header[start..start + len])
}

fn skip_header_item(header: &[u8], offset: &mut usize) -> Result<()> {
    read_header_item(header, offset).map(|_| ())
}

/// Exhaustively enumerate every value stored in a trie.
///
/// Every hashed child reference must resolve in the supplied node set — a
/// missing node aborts, so a prover cannot hide a subtree (and with it a
/// receipt). Inline (< 32-byte) children are recursed directly.
pub fn enumerate_trie_values(root: &[u8; 32], nodes: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    if *root == EMPTY_TRIE_ROOT {
        ensure!(nodes.is_empty(), "Nonempty node set for the empty trie");
        return Ok(Vec::new());
    }

    let mut by_hash = std::collections::HashMap::with_capacity(nodes.len());
    for node in nodes {
        by_hash.insert(keccak256(node), node.as_slice());
    }

    let mut values = Vec::new();
    let root_node = *by_hash
        .get(root)
        .context("Missing trie root node — incomplete witness")?;
    enumerate_node(root_node, &by_hash, &mut values, 0)?;
    Ok(values)
}

fn enumerate_node(
    node: &[u8],
    by_hash: &std::collections::HashMap<[u8; 32], &[u8]>,
    values: &mut Vec<Vec<u8>>,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 64, "Trie deeper than the maximum key length");

    let payload = decode_rlp_list(node)?;
    let item_count = count_rlp_items(payload)?;

    if item_count == 17 {
        // Branch: 16 children + a value slot.
        let mut buf = payload;
        for _ in 0..16 {
            let child_raw = read_rlp_item_raw(&mut buf)?;
            enumerate_child(child_raw, by_hash, values, depth + 1)?;
        }
        // The 17th item is a value (nonempty only for short keys).
        let value = decode_rlp_bytes(&mut buf)?;
        if !value.is_empty() {
            values.push(value.to_vec());
        }
    } else if item_count == 2 {
        // Extension or leaf.
        let mut buf = payload;
        let path_bytes = decode_rlp_bytes(&mut buf)?;
        let (_, is_leaf) = decode_hp(path_bytes)?;
        if is_leaf {
            values.push(unwrap_value_item(&mut buf)?);
        } else {
            let child_raw = read_rlp_item_raw(&mut buf)?;
            enumerate_child(child_raw, by_hash, values, depth + 1)?;
        }
    } else {
        bail!("Unexpected RLP item count in trie node: {item_count}");
    }
    Ok(())
}

fn enumerate_child(
    child_raw: &[u8],
    by_hash: &std::collections::HashMap<[u8; 32], &[u8]>,
    values: &mut Vec<Vec<u8>>,
    depth: usize,
) -> Result<()> {
    let mut child_buf = child_raw;
    let header = alloy_rlp::Header::decode(&mut child_buf)
        .map_err(|e| anyhow::anyhow!("Invalid child header: {e}"))?;

    if header.list {
        // Inline node (< 32 bytes encoded) — recurse on the raw bytes.
        enumerate_node(child_raw, by_hash, values, depth)
    } else if header.payload_length == 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&child_buf[..32]);
        let child = *by_hash
            .get(&hash)
            .context("Missing trie node — incomplete witness")?;
        enumerate_node(child, by_hash, values, depth)
    } else if header.payload_length == 0 {
        Ok(()) // empty slot
    } else {
        bail!("Unexpected child reference length: {}", header.payload_length);
    }
}

/// Unwrap a leaf/branch value item into the stored value bytes.
fn unwrap_value_item(buf: &mut &[u8]) -> Result<Vec<u8>> {
    let value_raw = read_rlp_item_raw(buf)?;
    let mut val_buf = value_raw;
    let header = alloy_rlp::Header::decode(&mut val_buf)
        .map_err(|e| anyhow::anyhow!("Invalid value header: {e}"))?;
    if header.list {
        Ok(value_raw.to_vec())
    } else {
        Ok(val_buf[..header.payload_length].to_vec())
    }
}

/// Extract the `from`/`to` participants of every `Transfer` event of `token`
/// in one receipt (legacy or EIP-2718 typed envelope).
pub fn transfer_participants_in_receipt(
    receipt: &[u8],
    token: &[u8; 20],
) -> Result<Vec<[u8; 20]>> {
    ensure!(!receipt.is_empty(), "Empty receipt");
    // EIP-2718: a leading byte in [0x01, 0x7f] is the transaction type.
    let body = if receipt[0] <= 0x7F { &receipt[1..] } else { &receipt[..] };

    // Receipt = RLP([status/root, cumulativeGas, bloom, logs]).
    let payload = decode_rlp_list(body).context("Receipt is not an RLP list")?;
    let mut buf = payload;
    skip_rlp_item(&mut buf)?; // status / post-state root
    skip_rlp_item(&mut buf)?; // cumulative gas
    skip_rlp_item(&mut buf)?; // bloom
    let logs_raw = read_rlp_item_raw(&mut buf)?;
    let mut logs_buf = decode_rlp_list(logs_raw).context("Receipt logs are not a list")?;

    let mut participants = Vec::new();
    while !logs_buf.is_empty() {
        // Log = RLP([address, topics, data]).
        let log_raw = read_rlp_item_raw(&mut logs_buf)?;
        let mut log_buf = decode_rlp_list(log_raw).context("Log is not a list")?;

        let address = decode_rlp_bytes(&mut log_buf)?;
        ensure!(address.len() == 20, "Malformed log address");

        let topics_raw = read_rlp_item_raw(&mut log_buf)?;
        let mut topics_buf = decode_rlp_list(topics_raw).context("Topics is not a list")?;
        let mut topics: Vec<[u8; 32]> = Vec::new();
        while !topics_buf.is_empty() {
            let topic = decode_rlp_bytes(&mut topics_buf)?;
            ensure!(topic.len() == 32, "Malformed topic");
            let mut out = [0u8; 32];
            out.copy_from_slice(topic);
            topics.push(out);
        }

        if address == token && topics.len() >= 3 && topics[0] == TRANSFER_EVENT_TOPIC {
            for topic in &topics[1..3] {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&topic[12..]);
                participants.push(addr);
            }
        }
    }
    Ok(participants)
}

/// Execute the receipt-scan completeness statement natively.
pub fn execute_scan_statement(witness: &ScanWitness, token: &[u8; 20]) -> Result<ScanPublicValues> {
    ensure!(!witness.headers.is_empty(), "At least one header is required");
    ensure!(
        witness.headers.len() == witness.receipt_nodes.len(),
        "headers and receipt_nodes must align"
    );

    // 1. Contiguous header chain — by parent hash *and* by block number, so
    // the committed range provably describes the blocks actually scanned.
    let start_block = parse_header(&witness.headers[0])?.number;
    for i in 1..witness.headers.len() {
        let info = parse_header(&witness.headers[i])?;
        let prev_hash = keccak256(&witness.headers[i - 1]);
        ensure!(
            info.parent_hash == prev_hash,
            "Broken header chain at index {i}"
        );
        ensure!(
            info.number == start_block + i as u64,
            "Header {i} has block number {}, expected {}",
            info.number,
            start_block + i as u64
        );
    }
    let end_block = start_block + witness.headers.len() as u64 - 1;

    // 2-3. Exhaustive receipt enumeration per block.
    let mut participants: BTreeSet<[u8; 20]> = BTreeSet::new();
    for (header, nodes) in witness.headers.iter().zip(&witness.receipt_nodes) {
        let info = parse_header(header)?;
        for receipt in enumerate_trie_values(&info.receipts_root, nodes)? {
            participants.extend(transfer_participants_in_receipt(&receipt, token)?);
        }
    }

    // 4. Commit — same construction as the derivation proof's candidates_root.
    let participant_list: Vec<[u8; 20]> = participants.into_iter().collect();
    Ok(ScanPublicValues {
        end_block_hash: keccak256(witness.headers.last().unwrap()),
        start_block,
        end_block,
        num_blocks: witness.headers.len() as u64,
        token: *token,
        participants_root: candidates_root(&participant_list),
        participant_count: participant_list.len() as u32,
    })
}

/// Synthetic header/receipt fixtures for testing the scan statement.
#[doc(hidden)]
pub mod fixtures {
    use crate::solvent_derivation::fixtures::{rlp_bytes, rlp_list};
    use super::{keccak256, TRANSFER_EVENT_TOPIC};

    /// A minimal header the fixed-shape walker accepts, extended through the
    /// receiptsRoot (item 5). Anything beyond is irrelevant to parsing; the
    /// full bytes are what get hashed for chain linkage.
    pub fn build_header(
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        receipts_root: [u8; 32],
    ) -> Vec<u8> {
        build_header_at(parent_hash, state_root, receipts_root, 1)
    }

    /// As [`build_header`], but with an explicit block number (item 8) so the
    /// scan statement's proven range can be exercised.
    pub fn build_header_at(
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        receipts_root: [u8; 32],
        number: u64,
    ) -> Vec<u8> {
        let mut out = vec![0xF9, 0x02, 0x00]; // list prefix (length bytes unchecked)
        out.push(0xA0);
        out.extend_from_slice(&parent_hash); // item 0
        out.push(0xA0);
        out.extend_from_slice(&[0x22; 32]); // item 1: unclesHash
        out.push(0x94);
        out.extend_from_slice(&[0x33; 20]); // item 2: coinbase
        out.push(0xA0);
        out.extend_from_slice(&state_root); // item 3
        out.push(0xA0);
        out.extend_from_slice(&[0x44; 32]); // item 4: txRoot
        out.push(0xA0);
        out.extend_from_slice(&receipts_root); // item 5
        // item 6: logsBloom — 256 bytes (long string: 0xB9 0x0100).
        out.extend_from_slice(&[0xB9, 0x01, 0x00]);
        out.extend_from_slice(&[0u8; 256]);
        // item 7: difficulty (post-merge: 0 → empty string).
        out.push(0x80);
        // item 8: number, canonical big-endian.
        out.extend_from_slice(&rlp_bytes(&be_bytes(number)));
        out
    }

    /// Minimal big-endian encoding (no leading zeros); empty for zero.
    fn be_bytes(value: u64) -> Vec<u8> {
        value.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect()
    }

    /// An RLP log entry: [address, topics, data].
    pub fn log_entry(address: [u8; 20], topics: &[[u8; 32]], data: &[u8]) -> Vec<u8> {
        let topic_items: Vec<Vec<u8>> = topics.iter().map(|t| rlp_bytes(t)).collect();
        rlp_list(&[rlp_bytes(&address), rlp_list(&topic_items), rlp_bytes(data)])
    }

    /// A Transfer(from, to, value) log for `token`.
    pub fn transfer_log(token: [u8; 20], from: [u8; 20], to: [u8; 20]) -> Vec<u8> {
        let pad = |addr: [u8; 20]| {
            let mut t = [0u8; 32];
            t[12..].copy_from_slice(&addr);
            t
        };
        log_entry(token, &[TRANSFER_EVENT_TOPIC, pad(from), pad(to)], &[0x01])
    }

    /// A legacy receipt: RLP([status, cumulativeGas, bloom, logs]).
    pub fn legacy_receipt(logs: &[Vec<u8>]) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&[0x01]),        // status
            rlp_bytes(&[0x52, 0x08]),  // cumulative gas
            rlp_bytes(&[0u8; 256]),    // bloom
            rlp_list(logs),
        ])
    }

    /// An EIP-2718 typed receipt: type byte || RLP body.
    pub fn typed_receipt(tx_type: u8, logs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![tx_type];
        out.extend_from_slice(&legacy_receipt(logs));
        out
    }

    /// Receipts trie holding one receipt at index 0 (key rlp(0) = 0x80).
    pub fn single_receipt_trie(receipt: &[u8]) -> ([u8; 32], Vec<Vec<u8>>) {
        // Key nibbles [8, 0] — even-length leaf: hp = 0x20 || 0x80.
        let leaf = rlp_list(&[rlp_bytes(&[0x20, 0x80]), rlp_bytes(receipt)]);
        (keccak256(&leaf), vec![leaf])
    }

    /// Receipts trie holding receipts at indices 0, 1, 2
    /// (keys 0x80 → nibbles [8,0]; 0x01 → [0,1]; 0x02 → [0,2]).
    pub fn three_receipt_trie(
        r0: &[u8],
        r1: &[u8],
        r2: &[u8],
    ) -> ([u8; 32], Vec<Vec<u8>>) {
        // Leaf for index 0 under root slot 8, remaining path [0] (odd leaf).
        let leaf0 = rlp_list(&[rlp_bytes(&[0x30]), rlp_bytes(r0)]);
        // Leaves for indices 1/2 under the inner branch, empty remaining path.
        let leaf1 = rlp_list(&[rlp_bytes(&[0x20]), rlp_bytes(r1)]);
        let leaf2 = rlp_list(&[rlp_bytes(&[0x20]), rlp_bytes(r2)]);

        // Inner branch (second nibble of keys 0x01/0x02): children at 1 and 2.
        let mut inner_items: Vec<Vec<u8>> = Vec::with_capacity(17);
        for idx in 0..16u8 {
            match idx {
                1 => inner_items.push(rlp_bytes(&keccak256(&leaf1))),
                2 => inner_items.push(rlp_bytes(&keccak256(&leaf2))),
                _ => inner_items.push(rlp_bytes(&[])),
            }
        }
        inner_items.push(rlp_bytes(&[]));
        let inner = rlp_list(&inner_items);

        // Root branch (first nibble): slot 0 → inner branch, slot 8 → leaf0.
        let mut root_items: Vec<Vec<u8>> = Vec::with_capacity(17);
        for idx in 0..16u8 {
            match idx {
                0 => root_items.push(rlp_bytes(&keccak256(&inner))),
                8 => root_items.push(rlp_bytes(&keccak256(&leaf0))),
                _ => root_items.push(rlp_bytes(&[])),
            }
        }
        root_items.push(rlp_bytes(&[]));
        let root_node = rlp_list(&root_items);
        let root = keccak256(&root_node);

        (root, vec![root_node, inner, leaf0, leaf1, leaf2])
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::mpt::keccak256;

    const TOKEN: [u8; 20] = [0xEE; 20];
    const OTHER_TOKEN: [u8; 20] = [0xDD; 20];
    const ALICE: [u8; 20] = [0xA1; 20];
    const BOB: [u8; 20] = [0xB2; 20];
    const CAROL: [u8; 20] = [0xC3; 20];

    #[test]
    fn test_parse_header_roundtrip() {
        let header = build_header([0x01; 32], [0x02; 32], [0x03; 32]);
        let info = parse_header(&header).unwrap();
        assert_eq!(info.parent_hash, [0x01; 32]);
        assert_eq!(info.state_root, [0x02; 32]);
        assert_eq!(info.receipts_root, [0x03; 32]);

        assert!(parse_header(&[0x80]).is_err(), "Non-list header rejected");
    }

    #[test]
    fn test_scan_single_block_collects_transfer_participants() {
        // r0: our token's transfer; r1 (typed): other token + noise log;
        // r2: no logs at all.
        let r0 = legacy_receipt(&[transfer_log(TOKEN, ALICE, BOB)]);
        let r1 = typed_receipt(
            0x02,
            &[
                transfer_log(OTHER_TOKEN, CAROL, ALICE),
                log_entry(TOKEN, &[[0x77; 32]], &[]), // wrong topic0 — ignored
            ],
        );
        let r2 = legacy_receipt(&[]);
        let (receipts_root, nodes) = three_receipt_trie(&r0, &r1, &r2);
        let header = build_header([0x00; 32], [0x02; 32], receipts_root);

        let witness = ScanWitness {
            headers: vec![header.clone()],
            receipt_nodes: vec![nodes],
        };
        let public = execute_scan_statement(&witness, &TOKEN).unwrap();

        assert_eq!(public.num_blocks, 1);
        assert_eq!(public.token, TOKEN);
        assert_eq!(public.end_block_hash, keccak256(&header));
        assert_eq!(public.participant_count, 2, "Only our token's from/to count");
        assert_eq!(
            public.participants_root,
            crate::solvent_derivation::candidates_root(&[ALICE, BOB]),
            "Commitment matches the derivation proof's candidates_root construction"
        );
    }

    #[test]
    fn test_scan_multi_block_chain() {
        let r0 = legacy_receipt(&[transfer_log(TOKEN, ALICE, BOB)]);
        let (root0, nodes0) = single_receipt_trie(&r0);
        let header0 = build_header_at([0x00; 32], [0x02; 32], root0, 19_000_000);

        // Block 1: no receipts at all (empty trie), chained to block 0.
        let header1 = build_header_at(
            keccak256(&header0), [0x03; 32], crate::mpt::EMPTY_TRIE_ROOT, 19_000_001,
        );

        let witness = ScanWitness {
            headers: vec![header0, header1.clone()],
            receipt_nodes: vec![nodes0, vec![]],
        };
        let public = execute_scan_statement(&witness, &TOKEN).unwrap();

        assert_eq!(public.num_blocks, 2);
        assert_eq!(public.start_block, 19_000_000);
        assert_eq!(public.end_block, 19_000_001, "range comes from the headers");
        assert_eq!(public.end_block_hash, keccak256(&header1));
        assert_eq!(public.participant_count, 2);
    }

    #[test]
    fn test_scan_broken_chain_aborts() {
        let (root, nodes) = single_receipt_trie(&legacy_receipt(&[]));
        let header0 = build_header_at([0x00; 32], [0x02; 32], root, 19_000_000);
        let header1 = build_header_at(
            [0xBA; 32], [0x03; 32], crate::mpt::EMPTY_TRIE_ROOT, 19_000_001,
        );

        let witness = ScanWitness {
            headers: vec![header0, header1],
            receipt_nodes: vec![nodes, vec![]],
        };
        let err = execute_scan_statement(&witness, &TOKEN).unwrap_err();
        assert!(err.to_string().contains("Broken header chain"), "got: {err}");
    }

    #[test]
    fn test_scan_missing_node_aborts() {
        // Completeness: withholding any trie node must abort — a prover
        // cannot hide a subtree of receipts.
        let r0 = legacy_receipt(&[transfer_log(TOKEN, ALICE, BOB)]);
        let r1 = legacy_receipt(&[transfer_log(TOKEN, CAROL, BOB)]);
        let r2 = legacy_receipt(&[]);
        let (receipts_root, mut nodes) = three_receipt_trie(&r0, &r1, &r2);
        let header = build_header([0x00; 32], [0x02; 32], receipts_root);

        nodes.remove(3); // drop leaf1 (Carol's transfer)
        let witness = ScanWitness {
            headers: vec![header],
            receipt_nodes: vec![nodes],
        };
        let err = execute_scan_statement(&witness, &TOKEN).unwrap_err();
        assert!(err.to_string().contains("Missing trie"), "got: {err}");
    }

    #[test]
    fn test_scan_tampered_receipt_aborts() {
        let r0 = legacy_receipt(&[transfer_log(TOKEN, ALICE, BOB)]);
        let (receipts_root, mut nodes) = single_receipt_trie(&r0);
        let header = build_header([0x00; 32], [0x02; 32], receipts_root);

        // Flip a byte inside the leaf — its hash no longer matches the root.
        let last = nodes[0].len() - 1;
        nodes[0][last] ^= 0x01;
        let witness = ScanWitness {
            headers: vec![header],
            receipt_nodes: vec![nodes],
        };
        assert!(execute_scan_statement(&witness, &TOKEN).is_err());
    }

    #[test]
    fn test_enumerate_handles_inline_children() {
        use crate::solvent_derivation::fixtures::{rlp_bytes, rlp_list};

        // A tiny leaf (< 32 bytes encoded) embedded inline in a branch.
        let tiny_leaf = rlp_list(&[rlp_bytes(&[0x20]), rlp_bytes(&[0x42])]);
        assert!(tiny_leaf.len() < 32, "fixture must be inline-sized");

        let mut items: Vec<Vec<u8>> = Vec::with_capacity(17);
        for idx in 0..16u8 {
            if idx == 3 {
                items.push(tiny_leaf.clone()); // inline: raw list as the item
            } else {
                items.push(rlp_bytes(&[]));
            }
        }
        items.push(rlp_bytes(&[]));
        let branch = rlp_list(&items);
        let root = keccak256(&branch);

        let values = enumerate_trie_values(&root, &[branch]).unwrap();
        assert_eq!(values, vec![vec![0x42]]);
    }

    #[test]
    fn test_scan_abi_roundtrip() {
        let public = ScanPublicValues {
            end_block_hash: [0x01; 32],
            start_block: 19_000_000,
            end_block: 19_000_127,
            num_blocks: 128,
            token: TOKEN,
            participants_root: [0x02; 32],
            participant_count: 77,
        };
        let encoded = public.abi_encode();
        assert_eq!(encoded.len(), SCAN_PUBLIC_VALUES_LEN);
        assert_eq!(ScanPublicValues::abi_decode(&encoded).unwrap(), public);

        let mut bad = encoded.clone();
        bad[33] = 0xFF; // dirty padding
        assert!(ScanPublicValues::abi_decode(&bad).is_err());
        assert!(ScanPublicValues::abi_decode(&encoded[..223]).is_err());
    }
}
