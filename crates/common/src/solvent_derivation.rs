//! The Stage B solvent-set derivation statement — host-side mirror of
//! `program-solvent-set/`.
//!
//! Proves that a published solvent set was *correctly derived*: every entry's
//! balance is proven against the block's state root via EIP-1186, and every
//! streak is continuous with the previously published set. This removes the
//! operator **safety** failure (including an insolvent address, inflating a
//! streak). Candidate **completeness** (censorship) remains operator-side —
//! see PRIVACY_V2.md §4.4.
//!
//! ```text
//! Private:  candidates [(address, mpt_proof)], prev_entries [(address, streak)]
//! Public:   state_root, prev_root, new_root, policy_id, epoch, block_number,
//!           chain_id, threshold_wei, member_count, candidate_count
//!
//! 1. prev_root = SolventSetRoot(prev_entries)        (zero when empty)
//! 2. for each candidate:
//!      balance = VerifyAccountProof(state_root, address, mpt_proof)   (abort on invalid)
//!      if balance >= threshold:
//!        streak = prev_entries[address].streak + 1, or 1 if absent
//!        include (address, streak)
//! 3. new_root = SolventSetRoot(included entries)     (canonical sort/dedup)
//! 4. commit abi.encode(state_root, prev_root, new_root, policy_id, epoch,
//!                      block_number, chain_id, threshold_wei,
//!                      member_count, candidate_count)
//! ```
//!
//! `SolventSetOracle.publishRootProven` verifies this proof, binds
//! `state_root` to the chain via the block header (`keccak256(header) ==
//! blockhash`), and checks `prev_root` against its stored history — making
//! proven publication permissionless.

use crate::mpt;
use crate::solvent_set::{SolventEntry, SolventSet};
use anyhow::{bail, Context, Result};

/// One candidate address with its EIP-1186 account proof.
#[derive(Debug, Clone)]
pub struct CandidateProof {
    /// The candidate address (public data — the whole set is public).
    pub address: [u8; 20],
    /// RLP-encoded MPT proof nodes from `eth_getProof`.
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Private inputs to the derivation statement.
#[derive(Debug, Clone)]
pub struct DerivationWitness {
    /// Candidates to check at the reference block.
    pub candidates: Vec<CandidateProof>,
    /// The previously published set's entries (empty for the first epoch).
    pub prev_entries: Vec<SolventEntry>,
}

/// Public values committed by the derivation program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPublicValues {
    pub state_root: [u8; 32],
    /// Root of the previously published set (zero for the first epoch).
    pub prev_root: [u8; 32],
    /// Root of the newly derived set.
    pub solvent_set_root: [u8; 32],
    pub policy_id: [u8; 32],
    pub epoch: u64,
    pub block_number: u64,
    pub chain_id: u64,
    pub threshold_wei: u128,
    pub member_count: u32,
    pub candidate_count: u32,
}

/// ABI-encoded size: ten 32-byte words.
pub const DERIVATION_PUBLIC_VALUES_LEN: usize = 320;

impl DerivationPublicValues {
    /// `abi.encode(bytes32, bytes32, bytes32, bytes32, uint64, uint64, uint64,
    /// uint256, uint32, uint32)` — 320 bytes.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DERIVATION_PUBLIC_VALUES_LEN);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.prev_root);
        out.extend_from_slice(&self.solvent_set_root);
        out.extend_from_slice(&self.policy_id);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.block_number.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&self.threshold_wei.to_be_bytes());
        out.extend_from_slice(&[0u8; 28]);
        out.extend_from_slice(&self.member_count.to_be_bytes());
        out.extend_from_slice(&[0u8; 28]);
        out.extend_from_slice(&self.candidate_count.to_be_bytes());
        out
    }

    /// Decode and validate a 320-byte public-values blob.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DERIVATION_PUBLIC_VALUES_LEN {
            bail!(
                "Invalid derivation public values length: expected {}, got {}",
                DERIVATION_PUBLIC_VALUES_LEN,
                bytes.len()
            );
        }
        let pad_ok = bytes[128..152] == [0u8; 24]
            && bytes[160..184] == [0u8; 24]
            && bytes[192..216] == [0u8; 24]
            && bytes[224..240] == [0u8; 16]
            && bytes[256..284] == [0u8; 28]
            && bytes[288..316] == [0u8; 28];
        if !pad_ok {
            bail!("Invalid derivation public values: nonzero padding");
        }

        let word32 = |offset: usize| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[offset..offset + 32]);
            out
        };
        Ok(Self {
            state_root: word32(0),
            prev_root: word32(32),
            solvent_set_root: word32(64),
            policy_id: word32(96),
            epoch: u64::from_be_bytes(bytes[152..160].try_into().unwrap()),
            block_number: u64::from_be_bytes(bytes[184..192].try_into().unwrap()),
            chain_id: u64::from_be_bytes(bytes[216..224].try_into().unwrap()),
            threshold_wei: u128::from_be_bytes(bytes[240..256].try_into().unwrap()),
            member_count: u32::from_be_bytes(bytes[284..288].try_into().unwrap()),
            candidate_count: u32::from_be_bytes(bytes[316..320].try_into().unwrap()),
        })
    }
}

/// Verify every candidate's balance against the state root and derive the
/// new entries with continuous streaks.
///
/// Any invalid MPT proof aborts (an operator cannot smuggle an unproven
/// balance); a *valid* proof of an insufficient balance simply excludes the
/// candidate. Shared by the statement below and by the agent's proven-build
/// flow, so the served set and the proven set can never drift.
pub fn derive_entries(
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    threshold_wei: u128,
) -> Result<Vec<SolventEntry>> {
    let prev_set = SolventSet::from_entries(witness.prev_entries.clone());

    let mut entries: Vec<SolventEntry> = Vec::with_capacity(witness.candidates.len());
    for candidate in &witness.candidates {
        let balance =
            mpt::verify_account_balance(state_root, &candidate.address, &candidate.proof_nodes)
                .with_context(|| {
                    format!(
                        "Invalid account proof for candidate 0x{}",
                        hex::encode(candidate.address)
                    )
                })?;

        if mpt::balance_meets_threshold(&balance, threshold_wei) {
            let streak = match prev_set.entry_for(&candidate.address) {
                Some((_, prev_entry)) => prev_entry.streak + 1,
                None => 1,
            };
            entries.push(SolventEntry {
                address: candidate.address,
                streak,
            });
        }
    }
    Ok(entries)
}

/// Execute the derivation statement natively.
pub fn execute_derivation_statement(
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    block_number: u64,
    chain_id: u64,
    threshold_wei: u128,
) -> Result<DerivationPublicValues> {
    // 1. Recommit the previous set — binds streak continuity to prev_root.
    let prev_root = SolventSet::from_entries(witness.prev_entries.clone()).root();

    // 2-3. Derive and canonicalize the new set.
    let new_set = SolventSet::from_entries(derive_entries(witness, state_root, threshold_wei)?);

    Ok(DerivationPublicValues {
        state_root: *state_root,
        prev_root,
        solvent_set_root: new_set.root(),
        policy_id: *policy_id,
        epoch,
        block_number,
        chain_id,
        threshold_wei,
        member_count: new_set.len() as u32,
        candidate_count: witness.candidates.len() as u32,
    })
}

/// Synthetic account-trie fixtures for testing the derivation statement —
/// shared by unit tests, integration tests, and the SP1 emulator tests.
/// Not part of the public API surface.
#[doc(hidden)]
pub mod fixtures {
    use tiny_keccak::{Hasher, Keccak};

    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data);
        hasher.finalize(&mut out);
        out
    }

    // ── Minimal RLP encoding for trie fixtures ──────────────────────────

    fn rlp_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        let mut out = Vec::with_capacity(2 + data.len());
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

    /// List encoding over already-encoded items.
    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.iter().flatten().copied().collect();
        let mut out = Vec::new();
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

    /// RLP([nonce=0, balance, storageRoot, codeHash]).
    fn account_rlp(balance: u128) -> Vec<u8> {
        let balance_trimmed: Vec<u8> = balance
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        rlp_list(&[
            rlp_bytes(&[]),                // nonce 0
            rlp_bytes(&balance_trimmed),   // balance
            rlp_bytes(&[0x55; 32]),        // storageRoot (arbitrary)
            rlp_bytes(&[0x66; 32]),        // codeHash (arbitrary)
        ])
    }

    fn nibbles_of(key: &[u8; 32]) -> Vec<u8> {
        key.iter().flat_map(|b| [b >> 4, b & 0x0F]).collect()
    }

    /// Single-account trie: one leaf node covering the whole 64-nibble path.
    pub fn single_leaf_proof(address: [u8; 20], balance: u128) -> ([u8; 32], Vec<Vec<u8>>) {
        let key = keccak256(&address);
        // HP leaf, even length: 0x20 || packed nibbles (= the key bytes).
        let mut hp = vec![0x20];
        hp.extend_from_slice(&key);
        let leaf = rlp_list(&[rlp_bytes(&hp), rlp_bytes(&account_rlp(balance))]);
        (keccak256(&leaf), vec![leaf])
    }

    /// Two-account trie under one branch node — exercises branch traversal.
    /// Returns (state_root, proof_a, proof_b). Panics if the two addresses'
    /// trie keys share a first nibble (use [`split_addresses`]).
    pub fn two_account_trie(
        addr_a: [u8; 20],
        balance_a: u128,
        addr_b: [u8; 20],
        balance_b: u128,
    ) -> ([u8; 32], Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let key_a = keccak256(&addr_a);
        let key_b = keccak256(&addr_b);
        let nib_a = nibbles_of(&key_a);
        let nib_b = nibbles_of(&key_b);
        assert_ne!(nib_a[0], nib_b[0], "fixture addresses must split at the root branch");

        // Leaf with the remaining 63 nibbles (odd): 0x3X || packed rest.
        let leaf_for = |nibs: &[u8], balance: u128| -> Vec<u8> {
            let rest = &nibs[1..]; // 63 nibbles
            let mut hp = vec![0x30 | rest[0]];
            for pair in rest[1..].chunks(2) {
                hp.push((pair[0] << 4) | pair[1]);
            }
            rlp_list(&[rlp_bytes(&hp), rlp_bytes(&account_rlp(balance))])
        };
        let leaf_a = leaf_for(&nib_a, balance_a);
        let leaf_b = leaf_for(&nib_b, balance_b);

        let mut branch_items: Vec<Vec<u8>> = Vec::with_capacity(17);
        for idx in 0..16u8 {
            if idx == nib_a[0] {
                branch_items.push(rlp_bytes(&keccak256(&leaf_a)));
            } else if idx == nib_b[0] {
                branch_items.push(rlp_bytes(&keccak256(&leaf_b)));
            } else {
                branch_items.push(rlp_bytes(&[]));
            }
        }
        branch_items.push(rlp_bytes(&[])); // branch value slot
        let branch = rlp_list(&branch_items);
        let state_root = keccak256(&branch);

        (
            state_root,
            vec![branch.clone(), leaf_a],
            vec![branch, leaf_b],
        )
    }

    /// Fixture addresses whose keccak keys split at the first nibble.
    pub fn split_addresses() -> ([u8; 20], [u8; 20]) {
        let a = [0x01; 20];
        let key_a_nib = nibbles_of(&keccak256(&a))[0];
        for filler in 2u8..=255 {
            let b = [filler; 20];
            if nibbles_of(&keccak256(&b))[0] != key_a_nib {
                return (a, b);
            }
        }
        unreachable!("some filler must differ in the first nibble");
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{single_leaf_proof, split_addresses, two_account_trie};
    use super::*;

    const POLICY: [u8; 32] = [0xAB; 32];
    const ONE_ETH: u128 = 1_000_000_000_000_000_000;

    #[test]
    fn test_first_epoch_derivation() {
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        let witness = DerivationWitness {
            candidates: vec![CandidateProof { address: addr, proof_nodes: proof }],
            prev_entries: vec![],
        };

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 1, ONE_ETH,
        )
        .unwrap();

        assert_eq!(public.prev_root, [0u8; 32], "First epoch has zero prev root");
        assert_eq!(public.member_count, 1);
        assert_eq!(public.candidate_count, 1);
        let expected = SolventSet::from_entries(vec![SolventEntry { address: addr, streak: 1 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_insufficient_balance_excluded() {
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, ONE_ETH - 1);
        let witness = DerivationWitness {
            candidates: vec![CandidateProof { address: addr, proof_nodes: proof }],
            prev_entries: vec![],
        };

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 1, ONE_ETH,
        )
        .unwrap();

        assert_eq!(public.member_count, 0);
        assert_eq!(public.candidate_count, 1);
        assert_eq!(public.solvent_set_root, [0u8; 32]);
    }

    #[test]
    fn test_invalid_proof_aborts() {
        let addr = [0x42; 20];
        let (state_root, mut proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        proof[0][5] ^= 0x01; // corrupt the node → hash mismatch
        let witness = DerivationWitness {
            candidates: vec![CandidateProof { address: addr, proof_nodes: proof }],
            prev_entries: vec![],
        };

        let result = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 1, ONE_ETH,
        );
        assert!(result.is_err(), "A forged proof must abort the derivation");
    }

    #[test]
    fn test_streak_continuity() {
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);

        // The address was in the previous set with streak 2 → now 3.
        let prev = vec![
            SolventEntry { address: addr, streak: 2 },
            SolventEntry { address: [0x99; 20], streak: 7 }, // dropped out this epoch
        ];
        let witness = DerivationWitness {
            candidates: vec![CandidateProof { address: addr, proof_nodes: proof }],
            prev_entries: prev.clone(),
        };

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_100, 1, ONE_ETH,
        )
        .unwrap();

        assert_eq!(public.prev_root, SolventSet::from_entries(prev).root());
        let expected = SolventSet::from_entries(vec![SolventEntry { address: addr, streak: 3 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_branch_trie_two_candidates() {
        let (addr_a, addr_b) = split_addresses();
        let (state_root, proof_a, proof_b) =
            two_account_trie(addr_a, 10 * ONE_ETH, addr_b, ONE_ETH / 2);

        let witness = DerivationWitness {
            candidates: vec![
                CandidateProof { address: addr_a, proof_nodes: proof_a },
                CandidateProof { address: addr_b, proof_nodes: proof_b },
            ],
            prev_entries: vec![SolventEntry { address: addr_a, streak: 1 }],
        };

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_100, 1, ONE_ETH,
        )
        .unwrap();

        // A qualifies (streak 1 → 2); B is proven but below threshold.
        assert_eq!(public.member_count, 1);
        assert_eq!(public.candidate_count, 2);
        let expected =
            SolventSet::from_entries(vec![SolventEntry { address: addr_a, streak: 2 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_derivation_abi_roundtrip() {
        let public = DerivationPublicValues {
            state_root: [0x01; 32],
            prev_root: [0x02; 32],
            solvent_set_root: [0x03; 32],
            policy_id: [0x04; 32],
            epoch: 7,
            block_number: 19_500_000,
            chain_id: 11155111,
            threshold_wei: 123 * ONE_ETH,
            member_count: 42,
            candidate_count: 99,
        };
        let encoded = public.abi_encode();
        assert_eq!(encoded.len(), DERIVATION_PUBLIC_VALUES_LEN);
        assert_eq!(DerivationPublicValues::abi_decode(&encoded).unwrap(), public);

        // Spot-check Solidity word alignment: uint256 threshold word.
        assert_eq!(&encoded[224..240], &[0u8; 16]);
        assert_eq!(
            u128::from_be_bytes(encoded[240..256].try_into().unwrap()),
            123 * ONE_ETH
        );
    }

    #[test]
    fn test_derivation_abi_rejects_bad_input() {
        let public = DerivationPublicValues {
            state_root: [0x01; 32],
            prev_root: [0; 32],
            solvent_set_root: [0x03; 32],
            policy_id: [0x04; 32],
            epoch: 1,
            block_number: 1,
            chain_id: 1,
            threshold_wei: 1,
            member_count: 1,
            candidate_count: 1,
        };
        let mut encoded = public.abi_encode();
        assert!(DerivationPublicValues::abi_decode(&encoded[..319]).is_err());
        encoded[130] = 0xFF; // dirty padding
        assert!(DerivationPublicValues::abi_decode(&encoded).is_err());
    }
}
