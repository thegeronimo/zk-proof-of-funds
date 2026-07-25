//! ZK Proof of Funds — SP1 Membership Program (Privacy V2)
//!
//! Proves, without revealing the address or key:
//!
//!   "I control a secret key whose Ethereum address is in the solvent set
//!    committed by `solvent_set_root`, and my deterministic nullifier for
//!    `policy_id` is `nullifier_hash`."
//!
//! Statement (PRIVACY_V2.md §4.2, streak-extended in Phase 11):
//!   1. pk = g * sk                            (sk valid, nonzero)
//!   2. address = keccak256(pk_uncompressed[1..65])[12..32]
//!   3. assert streak >= min_streak            (time-dimension gate)
//!   4. leaf = SHA256("zkpof-solvent-leaf-v2" || address || streak_be)
//!   5. MerkleVerify(leaf, index, siblings, solvent_set_root)
//!   6. N = hash_to_curve(scope_hash || sec1(pk), DST) * sk   (ERC-7524 form)
//!   7. nullifier_hash = SHA256(N_compressed)
//!
//! The exact streak stays private; the proof reveals only that it meets the
//! policy minimum. Public values committed as one ABI blob (224 bytes) so
//! Solidity decodes it directly: abi.encode(bytes32 solventSetRoot,
//! bytes32 policyId, uint64 epoch, bytes32 nullifierHash, uint64 chainId,
//! uint64 minStreak, bytes32 scopeHash).
//!
//! The statement is implemented once, in `zk_pof_common::membership`, shared
//! byte-for-byte with the host-side mirror used for witness generation and
//! testing.
//!
//! Build: cd program-membership && cargo prove build
//! The output ELF is used by the client-side prover (or a delegated prover)
//! to generate membership proofs.

#![no_main]
sp1_zkvm::entrypoint!(main);

use zk_pof_common::membership::{execute_membership_statement, MembershipWitness};

pub fn main() {
    // ── 1. Read private inputs ─────────────────────────────────────────
    let sk: [u8; 32] = sp1_zkvm::io::read();
    let streak: u32 = sp1_zkvm::io::read();
    let leaf_index: u64 = sp1_zkvm::io::read();
    let siblings: Vec<[u8; 32]> = sp1_zkvm::io::read();

    // ── 2. Read public inputs ──────────────────────────────────────────
    let solvent_set_root: [u8; 32] = sp1_zkvm::io::read();
    let policy_id: [u8; 32] = sp1_zkvm::io::read();
    let epoch: u64 = sp1_zkvm::io::read();
    let chain_id: u64 = sp1_zkvm::io::read();
    let min_streak: u64 = sp1_zkvm::io::read();
    let scope_hash: [u8; 32] = sp1_zkvm::io::read();

    // ── 3. Execute the statement (panics abort the proof) ──────────────
    let witness = MembershipWitness {
        sk,
        streak,
        leaf_index,
        siblings,
    };
    let public_values = execute_membership_statement(
        &witness,
        &solvent_set_root,
        &policy_id,
        epoch,
        chain_id,
        min_streak,
        &scope_hash,
    )
    .expect("membership statement not satisfied");

    // ── 4. Commit ABI-encoded public values ────────────────────────────
    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
