//! Stage B.2 witness building — turn a block range into a `ScanWitness`.
//!
//! The receipt-scan proof needs, per block: the **RLP block header** and
//! **every node of that block's receipts trie**. Neither is exposed directly
//! by standard JSON-RPC, so this module reconstructs both and *self-verifies*
//! the reconstruction:
//!
//! - the header is re-encoded from `eth_getBlockByNumber` fields and accepted
//!   only if `keccak256(header) == block.hash`;
//! - receipts are re-encoded per EIP-2718 from `eth_getTransactionReceipt`
//!   and the rebuilt trie is accepted only if its root equals the header's
//!   `receiptsRoot`.
//!
//! Both checks mean a wrong reconstruction fails loudly here rather than
//! producing an unprovable witness — and because the SP1 program re-derives
//! everything from the same bytes, the witness *producer* is never trusted.

use anyhow::{bail, ensure, Context, Result};
use tracing::{debug, info};

use zk_pof_common::mpt::{build_trie, receipt_trie_key};
use zk_pof_common::receipt_scan::{parse_header, ScanWitness};

use crate::rpc_fetcher::RpcFetcher;

/// RLP-encode a byte string.
fn rlp_bytes(data: &[u8]) -> Vec<u8> {
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

/// RLP-encode a list from already-encoded items.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
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

/// RLP-encode an integer (big-endian, minimal, empty for zero).
fn rlp_uint(value: u128) -> Vec<u8> {
    let trimmed: Vec<u8> = value.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    rlp_bytes(&trimmed)
}

/// Encode one receipt per EIP-2718: `type || rlp([status, cumulativeGas,
/// bloom, logs])` for typed transactions, bare RLP for legacy (type 0).
fn encode_receipt(
    tx_type: u8,
    status: u64,
    cumulative_gas: u128,
    logs_bloom: &[u8],
    logs: &[(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)],
) -> Vec<u8> {
    let encoded_logs: Vec<Vec<u8>> = logs
        .iter()
        .map(|(address, topics, data)| {
            let topic_items: Vec<Vec<u8>> = topics.iter().map(|t| rlp_bytes(t)).collect();
            rlp_list(&[rlp_bytes(address), rlp_list(&topic_items), rlp_bytes(data)])
        })
        .collect();

    let body = rlp_list(&[
        rlp_uint(status as u128),
        rlp_uint(cumulative_gas),
        rlp_bytes(logs_bloom),
        rlp_list(&encoded_logs),
    ]);

    if tx_type == 0 {
        body
    } else {
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(tx_type);
        out.extend_from_slice(&body);
        out
    }
}

/// Build the scan witness for the inclusive block range `[from_block, to_block]`.
///
/// Returns a witness whose headers form a contiguous chain (the scan program
/// re-checks this) and whose per-block node sets reconstruct each
/// `receiptsRoot` exactly.
pub async fn build_scan_witness(
    rpc: &RpcFetcher,
    from_block: u64,
    to_block: u64,
) -> Result<ScanWitness> {
    ensure!(from_block <= to_block, "from_block must not exceed to_block");

    let mut headers = Vec::with_capacity((to_block - from_block + 1) as usize);
    let mut receipt_nodes = Vec::with_capacity((to_block - from_block + 1) as usize);

    for block_number in from_block..=to_block {
        let (header_rlp, block_hash) = rpc
            .get_raw_header(block_number)
            .await
            .with_context(|| format!("Failed to reconstruct header for block {block_number}"))?;

        // Self-check 1: the reconstruction must hash to the canonical block hash.
        let computed = keccak(&header_rlp);
        ensure!(
            computed == block_hash,
            "Rebuilt header for block {block_number} hashes to {} but the chain says {} \
             (header encoding is missing or misordering a field)",
            hex::encode(computed),
            hex::encode(block_hash),
        );

        let receipts = rpc
            .get_block_receipts_encoded(block_number)
            .await
            .with_context(|| format!("Failed to fetch receipts for block {block_number}"))?;

        let entries: Vec<(Vec<u8>, Vec<u8>)> = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| (receipt_trie_key(index as u64), receipt.clone()))
            .collect();
        let (root, nodes) = build_trie(&entries);

        // Self-check 2: the rebuilt trie must reproduce the header's root.
        let info = parse_header(&header_rlp)?;
        if root != info.receipts_root {
            bail!(
                "Rebuilt receipts trie for block {block_number} has root {} but the header says {} \
                 ({} receipts)",
                hex::encode(root),
                hex::encode(info.receipts_root),
                receipts.len()
            );
        }

        debug!(
            block_number,
            receipts = receipts.len(),
            nodes = nodes.len(),
            "Reconstructed receipts trie"
        );

        headers.push(header_rlp);
        receipt_nodes.push(nodes);
    }

    info!(
        from_block,
        to_block,
        blocks = headers.len(),
        "Scan witness built and self-verified"
    );

    Ok(ScanWitness { headers, receipt_nodes })
}

fn keccak(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pof_common::receipt_scan::{transfer_participants_in_receipt, TRANSFER_EVENT_TOPIC};

    const TOKEN: [u8; 20] = [0xEE; 20];

    fn topic_for(addr: [u8; 20]) -> Vec<u8> {
        let mut t = vec![0u8; 32];
        t[12..].copy_from_slice(&addr);
        t
    }

    /// Our encoder must produce receipts the scan statement can parse — the
    /// round trip that keeps witness building and proving in agreement.
    #[test]
    fn test_encoded_receipt_parses_back() {
        let alice = [0xA1; 20];
        let bob = [0xB2; 20];
        let logs = vec![(
            TOKEN.to_vec(),
            vec![TRANSFER_EVENT_TOPIC.to_vec(), topic_for(alice), topic_for(bob)],
            vec![0x01],
        )];

        for tx_type in [0u8, 2u8] {
            let receipt = encode_receipt(tx_type, 1, 21_000, &[0u8; 256], &logs);
            let participants = transfer_participants_in_receipt(&receipt, &TOKEN).unwrap();
            assert_eq!(participants, vec![alice, bob], "tx_type {tx_type}");
        }
    }

    #[test]
    fn test_encoded_receipt_ignores_other_tokens() {
        let logs = vec![(
            vec![0xDD; 20], // different token
            vec![TRANSFER_EVENT_TOPIC.to_vec(), topic_for([0xA1; 20]), topic_for([0xB2; 20])],
            vec![],
        )];
        let receipt = encode_receipt(0, 1, 21_000, &[0u8; 256], &logs);
        assert!(transfer_participants_in_receipt(&receipt, &TOKEN).unwrap().is_empty());
    }

    /// A rebuilt receipts trie must be fully enumerable — the property the
    /// completeness proof depends on.
    #[test]
    fn test_rebuilt_trie_enumerates_all_receipts() {
        use zk_pof_common::receipt_scan::enumerate_trie_values;

        let receipts: Vec<Vec<u8>> = (0..6u8)
            .map(|i| {
                encode_receipt(
                    if i % 2 == 0 { 0 } else { 2 },
                    1,
                    21_000 * (i as u128 + 1),
                    &[0u8; 256],
                    &[(
                        TOKEN.to_vec(),
                        vec![
                            TRANSFER_EVENT_TOPIC.to_vec(),
                            topic_for([i; 20]),
                            topic_for([i + 100; 20]),
                        ],
                        vec![],
                    )],
                )
            })
            .collect();

        let entries: Vec<(Vec<u8>, Vec<u8>)> = receipts
            .iter()
            .enumerate()
            .map(|(i, r)| (receipt_trie_key(i as u64), r.clone()))
            .collect();
        let (root, nodes) = build_trie(&entries);

        let mut values = enumerate_trie_values(&root, &nodes).unwrap();
        let mut expected = receipts.clone();
        values.sort();
        expected.sort();
        assert_eq!(values, expected);

        // And every participant is recoverable from the enumerated receipts.
        let mut found = 0;
        for value in &values {
            found += transfer_participants_in_receipt(value, &TOKEN).unwrap().len();
        }
        assert_eq!(found, 12, "6 receipts x (from, to)");
    }
}
