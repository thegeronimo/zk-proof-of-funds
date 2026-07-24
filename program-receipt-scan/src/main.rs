//! ZK Proof of Funds — SP1 Receipt-Scan Program (Stage B.2)
//!
//! Proves candidate **completeness** for an ERC-20 solvent set:
//!
//!   "Over this contiguous chain of blocks (ending at `end_block_hash`),
//!    the complete set of addresses that appeared in any Transfer event of
//!    `token` is committed by `participants_root`."
//!
//! Every receipt of every block is enumerated by walking the ENTIRE receipts
//! trie — a withheld node aborts the proof, so no Transfer can be hidden.
//! Composed with the derivation proof (which commits `candidates_root` over
//! the candidate list it checked), equality of the two roots shows the
//! derivation missed no holder active in the scanned window.
//!
//! Public values committed as one ABI blob (160 bytes):
//!   abi.encode(bytes32 endBlockHash, uint64 numBlocks, address token,
//!              bytes32 participantsRoot, uint32 participantCount)
//!
//! The statement is implemented once, in `zk_pof_common::receipt_scan`,
//! shared byte-for-byte with the host-side mirror.
//!
//! Build: cd program-receipt-scan && cargo prove build

#![no_main]
sp1_zkvm::entrypoint!(main);

use zk_pof_common::receipt_scan::{execute_scan_statement, ScanWitness};

pub fn main() {
    // ── 1. Read inputs ─────────────────────────────────────────────────
    let token: [u8; 20] = sp1_zkvm::io::read();
    let headers: Vec<Vec<u8>> = sp1_zkvm::io::read();
    let receipt_nodes: Vec<Vec<Vec<u8>>> = sp1_zkvm::io::read();

    // ── 2. Execute the statement (panics abort the proof) ──────────────
    let witness = ScanWitness { headers, receipt_nodes };
    let public_values =
        execute_scan_statement(&witness, &token).expect("scan statement not satisfied");

    // ── 3. Commit ABI-encoded public values ────────────────────────────
    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
