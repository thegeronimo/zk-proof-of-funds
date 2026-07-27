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
//! Private:  candidates [(address, proof)], prev_entries [(address, streak)],
//!           token_account_proof (ERC-20 mode)
//! Public:   state_root, prev_root, new_root, policy_id, epoch, block_number,
//!           prev_block_number, chain_id, threshold_wei, member_count,
//!           candidate_count, token, balance_slot, candidates_root
//!
//! 0. first_epoch = (prev_block_number == 0)
//!    if !first_epoch: require block_number > prev_block_number
//!    (a streak must be built from *distinct, advancing* observations —
//!    external review finding R2)
//! 1. prev_root = 0 when first_epoch (no previous publication), else
//!    SolventSetRoot(prev_entries) — which is EMPTY_SET_ROOT if the previous
//!    epoch existed but nobody qualified
//! 2. ERC-20 mode: storage_root = VerifyAccountProof(state_root, token,
//!    token_account_proof).storageRoot
//! 3. for each candidate:
//!      native: balance = VerifyAccountProof(state_root, address, proof)
//!      ERC-20: balance = VerifyStorageProof(storage_root,
//!              keccak(pad(address) || pad(balance_slot)), proof)
//!      (either aborts on an invalid proof)
//!      if balance >= threshold:
//!        streak = prev_entries[address].streak + 1, or 1 if absent
//!        include (address, streak)
//! 4. new_root = SolventSetRoot(included entries)     (canonical sort/dedup)
//! 5. candidates_root = CandidatesRoot(candidate addresses)   (Stage B.2 binding)
//! 6. commit abi.encode(... 14 words, 448 bytes ...)
//! ```
//!
//! `SolventSetOracle.publishRootProven` verifies this proof, binds
//! `state_root` to the chain via the block header (`keccak256(header) ==
//! blockhash`), and checks `prev_root` against its stored history — making
//! proven publication permissionless.

use crate::mpt;
use crate::solvent_set::{SolventEntry, SolventSet};
use anyhow::{bail, Context, Result};

/// One candidate address with its proof nodes: an EIP-1186 **account** proof
/// in native-ETH mode, or a **storage** proof of the candidate's balance slot
/// in ERC-20 mode.
#[derive(Debug, Clone)]
pub struct CandidateProof {
    /// The candidate address (public data — the whole set is public).
    pub address: [u8; 20],
    /// RLP-encoded MPT proof nodes from `eth_getProof`.
    pub proof_nodes: Vec<Vec<u8>>,
}

/// ERC-20 mode configuration: which token, and which mapping slot holds
/// `balanceOf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenConfig {
    /// The token contract address.
    pub address: [u8; 20],
    /// Solidity mapping slot index of `balanceOf` (e.g. 0 for typical OZ
    /// ERC-20s; must be pinned per policy on-chain).
    pub balance_slot: u64,
}

/// Private inputs to the derivation statement.
#[derive(Debug, Clone)]
pub struct DerivationWitness {
    /// Candidates to check at the reference block.
    pub candidates: Vec<CandidateProof>,
    /// The previously published set's entries (empty for the first epoch).
    pub prev_entries: Vec<SolventEntry>,
    /// ERC-20 mode: account proof of the **token contract** (yields the
    /// storage root all candidate slots are verified against). Must be empty
    /// in native-ETH mode.
    pub token_account_proof: Vec<Vec<u8>>,
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
    /// Source block of the previous set (zero for the first epoch). The
    /// statement requires `block_number > prev_block_number`, so a streak
    /// cannot be inflated by re-proving the same snapshot (review finding R2).
    pub prev_block_number: u64,
    pub chain_id: u64,
    pub threshold_wei: u128,
    pub member_count: u32,
    pub candidate_count: u32,
    /// The token whose balances were proven (all zeros for native ETH).
    pub token: [u8; 20],
    /// The `balanceOf` mapping slot proven against (0 for native ETH).
    pub balance_slot: u64,
    /// Merkle root over the (sorted, deduped) candidate addresses — lets a
    /// Stage B.2 completeness proof (receipt_scan) bind to the same list.
    pub candidates_root: [u8; 32],
}

/// ABI-encoded size: fourteen 32-byte words.
pub const DERIVATION_PUBLIC_VALUES_LEN: usize = 448;

/// Domain separation tag for candidate-list leaves (shared with receipt_scan).
pub const CANDIDATE_LEAF_DOMAIN: &[u8] = b"zkpof-candidate-leaf-v1";

/// Merkle root over a candidate/participant address list: addresses sorted
/// ascending and deduplicated, leaf = SHA256(domain || addr). This is the
/// binding surface between the derivation proof and the Stage B.2
/// completeness proof — both commit the same root for the same list.
pub fn candidates_root(addresses: &[[u8; 20]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<[u8; 20]> = addresses.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let leaves: Vec<[u8; 32]> = sorted
        .iter()
        .map(|addr| {
            let mut hasher = Sha256::new();
            hasher.update(CANDIDATE_LEAF_DOMAIN);
            hasher.update(addr);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hasher.finalize());
            out
        })
        .collect();
    crate::merkle::compute_root(&leaves)
}

impl DerivationPublicValues {
    /// `abi.encode(bytes32, bytes32, bytes32, bytes32, uint64, uint64, uint64,
    /// uint64, uint256, uint32, uint32, address, uint64, bytes32)` — 448 bytes.
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
        out.extend_from_slice(&self.prev_block_number.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&self.threshold_wei.to_be_bytes());
        out.extend_from_slice(&[0u8; 28]);
        out.extend_from_slice(&self.member_count.to_be_bytes());
        out.extend_from_slice(&[0u8; 28]);
        out.extend_from_slice(&self.candidate_count.to_be_bytes());
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.balance_slot.to_be_bytes());
        out.extend_from_slice(&self.candidates_root);
        out
    }

    /// Decode and validate a 448-byte public-values blob.
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
            && bytes[224..248] == [0u8; 24]
            && bytes[256..272] == [0u8; 16]
            && bytes[288..316] == [0u8; 28]
            && bytes[320..348] == [0u8; 28]
            && bytes[352..364] == [0u8; 12]
            && bytes[384..408] == [0u8; 24];
        if !pad_ok {
            bail!("Invalid derivation public values: nonzero padding");
        }

        let word32 = |offset: usize| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[offset..offset + 32]);
            out
        };
        let mut token = [0u8; 20];
        token.copy_from_slice(&bytes[364..384]);
        Ok(Self {
            state_root: word32(0),
            prev_root: word32(32),
            solvent_set_root: word32(64),
            policy_id: word32(96),
            epoch: u64::from_be_bytes(bytes[152..160].try_into().unwrap()),
            block_number: u64::from_be_bytes(bytes[184..192].try_into().unwrap()),
            prev_block_number: u64::from_be_bytes(bytes[216..224].try_into().unwrap()),
            chain_id: u64::from_be_bytes(bytes[248..256].try_into().unwrap()),
            threshold_wei: u128::from_be_bytes(bytes[272..288].try_into().unwrap()),
            member_count: u32::from_be_bytes(bytes[316..320].try_into().unwrap()),
            candidate_count: u32::from_be_bytes(bytes[348..352].try_into().unwrap()),
            token,
            balance_slot: u64::from_be_bytes(bytes[408..416].try_into().unwrap()),
            candidates_root: word32(416),
        })
    }
}

/// Verify every candidate's balance against the state root and derive the
/// new entries with continuous streaks.
///
/// Native mode (`token = None`): each candidate's proof is an account proof.
/// ERC-20 mode: the token contract's account proof yields its storage root,
/// and each candidate's proof is a storage proof of `balanceOf[candidate]`
/// at the pinned mapping slot.
///
/// Any invalid MPT proof aborts (an operator cannot smuggle an unproven
/// balance); a *valid* proof of an insufficient balance simply excludes the
/// candidate. Shared by the statement below and by the agent's proven-build
/// flow, so the served set and the proven set can never drift.
pub fn derive_entries(
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    threshold_wei: u128,
    token: Option<&TokenConfig>,
) -> Result<Vec<SolventEntry>> {
    let prev_set = SolventSet::from_entries(witness.prev_entries.clone());

    // ERC-20 mode: resolve the token's storage root once, proven against the
    // state root. An absent token account has the empty storage root — every
    // balance then proves to zero.
    let storage_root = match token {
        Some(config) => {
            let token_state = mpt::verify_account_state(
                state_root,
                &config.address,
                &witness.token_account_proof,
            )
            .context("Invalid token account proof")?;
            Some(token_state.storage_root)
        }
        None => {
            if !witness.token_account_proof.is_empty() {
                bail!("token_account_proof must be empty in native-ETH mode");
            }
            None
        }
    };

    let mut entries: Vec<SolventEntry> = Vec::with_capacity(witness.candidates.len());
    for candidate in &witness.candidates {
        let balance = match (&storage_root, token) {
            (Some(root), Some(config)) => {
                let slot = mpt::erc20_balance_slot(&candidate.address, config.balance_slot);
                mpt::verify_storage_value(root, &slot, &candidate.proof_nodes).with_context(
                    || {
                        format!(
                            "Invalid storage proof for candidate 0x{}",
                            hex::encode(candidate.address)
                        )
                    },
                )?
            }
            _ => mpt::verify_account_balance(state_root, &candidate.address, &candidate.proof_nodes)
                .with_context(|| {
                    format!(
                        "Invalid account proof for candidate 0x{}",
                        hex::encode(candidate.address)
                    )
                })?,
        };

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
#[allow(clippy::too_many_arguments)]
pub fn execute_derivation_statement(
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    block_number: u64,
    prev_block_number: u64,
    chain_id: u64,
    threshold_wei: u128,
    token: Option<&TokenConfig>,
) -> Result<DerivationPublicValues> {
    // 1. Recommit the previous set — binds streak continuity to prev_root.
    //
    // `prev_block_number == 0` is the discriminator for "there is no previous
    // publication", and commits `prev_root = 0` to match what the contract
    // stores for a policy with empty history. It is deliberately distinct
    // from "the previous set existed but was empty", which recommits to
    // `EMPTY_SET_ROOT` — that case is a real epoch in which nobody qualified
    // and must remain provable (review §4.5).
    let first_epoch = prev_block_number == 0;
    if first_epoch && !witness.prev_entries.is_empty() {
        bail!("prev_block_number is zero (no previous set) but prev_entries is non-empty");
    }
    let prev_root = if first_epoch {
        [0u8; 32]
    } else {
        SolventSet::from_entries(witness.prev_entries.clone()).root()
    };

    // 0. A streak is only meaningful if each epoch observes a *later* block.
    // Without this, the same snapshot can be re-proven epoch after epoch and
    // every streak inflates for free (external review finding R2). The chain
    // separately checks prev_block_number against the stored previous entry,
    // so the two must agree.
    if !first_epoch && block_number <= prev_block_number {
        bail!(
            "Derivation block {} must be newer than the previous set's block {}",
            block_number,
            prev_block_number
        );
    }

    // 2-3. Derive and canonicalize the new set.
    let new_set =
        SolventSet::from_entries(derive_entries(witness, state_root, threshold_wei, token)?);

    // 4. Commit the candidate list root (Stage B.2 composition surface).
    let candidate_addresses: Vec<[u8; 20]> =
        witness.candidates.iter().map(|c| c.address).collect();

    Ok(DerivationPublicValues {
        state_root: *state_root,
        prev_root,
        solvent_set_root: new_set.root(),
        policy_id: *policy_id,
        epoch,
        block_number,
        prev_block_number,
        chain_id,
        threshold_wei,
        member_count: new_set.len() as u32,
        candidate_count: witness.candidates.len() as u32,
        token: token.map(|c| c.address).unwrap_or([0u8; 20]),
        balance_slot: token.map(|c| c.balance_slot).unwrap_or(0),
        candidates_root: candidates_root(&candidate_addresses),
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

    pub fn rlp_bytes(data: &[u8]) -> Vec<u8> {
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
    pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
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

    fn trim_be(value: u128) -> Vec<u8> {
        value.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect()
    }

    /// RLP([nonce=0, balance, storageRoot, codeHash]).
    pub fn account_rlp(balance: u128, storage_root: [u8; 32]) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&[]),                // nonce 0
            rlp_bytes(&trim_be(balance)),  // balance
            rlp_bytes(&storage_root),      // storageRoot
            rlp_bytes(&[0x66; 32]),        // codeHash (arbitrary)
        ])
    }

    fn nibbles_of(key: &[u8; 32]) -> Vec<u8> {
        key.iter().flat_map(|b| [b >> 4, b & 0x0F]).collect()
    }

    /// Single-leaf trie for `trie_key` with the given leaf value payload.
    pub fn single_leaf_trie(trie_key: [u8; 32], value: Vec<u8>) -> ([u8; 32], Vec<Vec<u8>>) {
        // HP leaf, even length: 0x20 || packed nibbles (= the key bytes).
        let mut hp = vec![0x20];
        hp.extend_from_slice(&trie_key);
        let leaf = rlp_list(&[rlp_bytes(&hp), rlp_bytes(&value)]);
        (keccak256(&leaf), vec![leaf])
    }

    /// Two-leaf trie under one branch node — exercises branch traversal.
    /// Returns (root, proof_a, proof_b). Panics if the two trie keys share a
    /// first nibble.
    pub fn two_leaf_trie(
        key_a: [u8; 32],
        value_a: Vec<u8>,
        key_b: [u8; 32],
        value_b: Vec<u8>,
    ) -> ([u8; 32], Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let nib_a = nibbles_of(&key_a);
        let nib_b = nibbles_of(&key_b);
        assert_ne!(nib_a[0], nib_b[0], "fixture keys must split at the root branch");

        // Leaf with the remaining 63 nibbles (odd): 0x3X || packed rest.
        let leaf_for = |nibs: &[u8], value: &[u8]| -> Vec<u8> {
            let rest = &nibs[1..]; // 63 nibbles
            let mut hp = vec![0x30 | rest[0]];
            for pair in rest[1..].chunks(2) {
                hp.push((pair[0] << 4) | pair[1]);
            }
            rlp_list(&[rlp_bytes(&hp), rlp_bytes(value)])
        };
        let leaf_a = leaf_for(&nib_a, &value_a);
        let leaf_b = leaf_for(&nib_b, &value_b);

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
        let root = keccak256(&branch);

        (root, vec![branch.clone(), leaf_a], vec![branch, leaf_b])
    }

    /// Single-account state trie with a configurable storage root.
    pub fn single_leaf_proof_with_storage(
        address: [u8; 20],
        balance: u128,
        storage_root: [u8; 32],
    ) -> ([u8; 32], Vec<Vec<u8>>) {
        single_leaf_trie(keccak256(&address), account_rlp(balance, storage_root))
    }

    /// Single-account state trie (arbitrary storage root).
    pub fn single_leaf_proof(address: [u8; 20], balance: u128) -> ([u8; 32], Vec<Vec<u8>>) {
        single_leaf_proof_with_storage(address, balance, [0x55; 32])
    }

    /// Two-account state trie — exercises branch traversal.
    pub fn two_account_trie(
        addr_a: [u8; 20],
        balance_a: u128,
        addr_b: [u8; 20],
        balance_b: u128,
    ) -> ([u8; 32], Vec<Vec<u8>>, Vec<Vec<u8>>) {
        two_leaf_trie(
            keccak256(&addr_a),
            account_rlp(balance_a, [0x55; 32]),
            keccak256(&addr_b),
            account_rlp(balance_b, [0x55; 32]),
        )
    }

    /// Single-slot storage trie: `slot` (the storage key, e.g. from
    /// `erc20_balance_slot`) mapped to an integer value.
    pub fn storage_leaf_proof(slot: [u8; 32], value: u128) -> ([u8; 32], Vec<Vec<u8>>) {
        single_leaf_trie(keccak256(&slot), rlp_bytes(&trim_be(value)))
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

    /// Fixture holder addresses whose ERC-20 balance-slot *trie keys* split at
    /// the first nibble (for two-holder storage tries).
    pub fn split_storage_holders(slot_index: u64) -> ([u8; 20], [u8; 20]) {
        let storage_key = |holder: &[u8; 20]| -> [u8; 32] {
            keccak256(&crate::mpt::erc20_balance_slot(holder, slot_index))
        };
        let a = [0x01; 20];
        let nib_a = nibbles_of(&storage_key(&a))[0];
        for filler in 2u8..=255 {
            let b = [filler; 20];
            if nibbles_of(&storage_key(&b))[0] != nib_a {
                return (a, b);
            }
        }
        unreachable!("some filler must differ in the first nibble");
    }

    /// Composed ERC-20 fixture: a state trie holding the token contract's
    /// account whose storage trie holds the holders' balance slots.
    /// Returns (state_root, token_account_proof, storage_proofs aligned with
    /// `holders`). Supports one or two holders.
    pub fn erc20_state_fixture(
        token: [u8; 20],
        slot_index: u64,
        holders: &[([u8; 20], u128)],
    ) -> ([u8; 32], Vec<Vec<u8>>, Vec<Vec<Vec<u8>>>) {
        let (storage_root, storage_proofs) = match holders {
            [(holder, balance)] => {
                let slot = crate::mpt::erc20_balance_slot(holder, slot_index);
                let (root, proof) = storage_leaf_proof(slot, *balance);
                (root, vec![proof])
            }
            [(holder_a, balance_a), (holder_b, balance_b)] => {
                let slot_a = crate::mpt::erc20_balance_slot(holder_a, slot_index);
                let slot_b = crate::mpt::erc20_balance_slot(holder_b, slot_index);
                let (root, proof_a, proof_b) = two_leaf_trie(
                    keccak256(&slot_a),
                    rlp_bytes(&trim_be(*balance_a)),
                    keccak256(&slot_b),
                    rlp_bytes(&trim_be(*balance_b)),
                );
                (root, vec![proof_a, proof_b])
            }
            _ => panic!("erc20_state_fixture supports 1 or 2 holders"),
        };

        let (state_root, token_account_proof) =
            single_leaf_proof_with_storage(token, 0, storage_root);
        (state_root, token_account_proof, storage_proofs)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{
        erc20_state_fixture, single_leaf_proof, split_addresses, split_storage_holders,
        two_account_trie,
    };
    use super::*;

    const POLICY: [u8; 32] = [0xAB; 32];
    const ONE_ETH: u128 = 1_000_000_000_000_000_000;

    fn native_witness(candidates: Vec<CandidateProof>, prev: Vec<SolventEntry>) -> DerivationWitness {
        DerivationWitness {
            candidates,
            prev_entries: prev,
            token_account_proof: vec![],
        }
    }

    #[test]
    fn test_first_epoch_derivation() {
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        let witness = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof }],
            vec![],
        );

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, None,
        )
        .unwrap();

        assert_eq!(public.prev_root, [0u8; 32], "First epoch has zero prev root");
        assert_eq!(public.member_count, 1);
        assert_eq!(public.candidate_count, 1);
        assert_eq!(public.token, [0u8; 20], "Native mode commits a zero token");
        assert_eq!(public.balance_slot, 0);
        assert_eq!(public.candidates_root, candidates_root(&[addr]));
        let expected = SolventSet::from_entries(vec![SolventEntry { address: addr, streak: 1 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_insufficient_balance_excluded() {
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, ONE_ETH - 1);
        let witness = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof }],
            vec![],
        );

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, None,
        )
        .unwrap();

        assert_eq!(public.member_count, 0);
        assert_eq!(public.candidate_count, 1);
        // "Nobody qualified" is a real, publishable outcome: it commits to the
        // empty-set sentinel, not zero (which means "no root at all").
        assert_eq!(public.solvent_set_root, crate::solvent_set::EMPTY_SET_ROOT);
    }

    #[test]
    fn test_invalid_proof_aborts() {
        let addr = [0x42; 20];
        let (state_root, mut proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        proof[0][5] ^= 0x01; // corrupt the node → hash mismatch
        let witness = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof }],
            vec![],
        );

        let result = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, None,
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
        let witness = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof }],
            prev.clone(),
        );

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_100, 19_000_000, 1, ONE_ETH, None,
        )
        .unwrap();

        assert_eq!(public.prev_root, SolventSet::from_entries(prev).root());
        let expected = SolventSet::from_entries(vec![SolventEntry { address: addr, streak: 3 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_streak_cannot_replay_the_same_block() {
        // Review finding R2: re-proving one snapshot must not inflate streaks.
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        let prev = vec![SolventEntry { address: addr, streak: 2 }];
        let witness = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof }],
            prev,
        );

        // Same block as the previous set → rejected.
        let err = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_000, 19_000_000, 1, ONE_ETH, None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be newer"));

        // An *older* block is likewise rejected.
        assert!(execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 18_999_999, 19_000_000, 1, ONE_ETH, None,
        )
        .is_err());

        // Advancing by a single block is enough to satisfy the statement.
        assert!(execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_001, 19_000_000, 1, ONE_ETH, None,
        )
        .is_ok());
    }

    #[test]
    fn test_first_epoch_discriminator_is_prev_block_number() {
        // prev_block_number == 0 means "no previous publication" and commits
        // prev_root = 0, matching what the contract stores for empty history.
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        let first = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof.clone() }],
            vec![],
        );
        let public = execute_derivation_statement(
            &first, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, None,
        )
        .unwrap();
        assert_eq!(public.prev_root, [0u8; 32], "no previous set → zero prev root");

        // Claiming "first epoch" while supplying previous entries is
        // incoherent: it would fabricate streak continuity out of nothing.
        let contradictory = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof.clone() }],
            vec![SolventEntry { address: addr, streak: 9 }],
        );
        let err = execute_derivation_statement(
            &contradictory, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("prev_entries is non-empty"));
    }

    #[test]
    fn test_previous_empty_set_recommits_to_sentinel() {
        // An epoch in which nobody qualified is still a real epoch: the next
        // epoch must chain from the sentinel, not from zero.
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        let witness = native_witness(
            vec![CandidateProof { address: addr, proof_nodes: proof }],
            vec![],
        );
        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_100, 19_000_000, 1, ONE_ETH, None,
        )
        .unwrap();
        assert_eq!(
            public.prev_root,
            crate::solvent_set::EMPTY_SET_ROOT,
            "previous set existed and was empty"
        );
    }

    #[test]
    fn test_branch_trie_two_candidates() {
        let (addr_a, addr_b) = split_addresses();
        let (state_root, proof_a, proof_b) =
            two_account_trie(addr_a, 10 * ONE_ETH, addr_b, ONE_ETH / 2);

        let witness = native_witness(
            vec![
                CandidateProof { address: addr_a, proof_nodes: proof_a },
                CandidateProof { address: addr_b, proof_nodes: proof_b },
            ],
            vec![SolventEntry { address: addr_a, streak: 1 }],
        );

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_100, 19_000_000, 1, ONE_ETH, None,
        )
        .unwrap();

        // A qualifies (streak 1 → 2); B is proven but below threshold.
        assert_eq!(public.member_count, 1);
        assert_eq!(public.candidate_count, 2);
        assert_eq!(public.candidates_root, candidates_root(&[addr_a, addr_b]));
        let expected =
            SolventSet::from_entries(vec![SolventEntry { address: addr_a, streak: 2 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_native_mode_rejects_stray_token_proof() {
        let addr = [0x42; 20];
        let (state_root, proof) = single_leaf_proof(addr, 5 * ONE_ETH);
        let witness = DerivationWitness {
            candidates: vec![CandidateProof { address: addr, proof_nodes: proof.clone() }],
            prev_entries: vec![],
            token_account_proof: proof, // must be empty in native mode
        };
        assert!(execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, None,
        )
        .is_err());
    }

    // ── ERC-20 mode (storage proofs) ────────────────────────────────────

    #[test]
    fn test_erc20_two_holders() {
        let token = [0xEE; 20];
        let config = TokenConfig { address: token, balance_slot: 0 };
        let (holder_a, holder_b) = split_storage_holders(0);
        let (state_root, token_account_proof, storage_proofs) = erc20_state_fixture(
            token,
            0,
            &[(holder_a, 10 * ONE_ETH), (holder_b, ONE_ETH / 2)],
        );

        let witness = DerivationWitness {
            candidates: vec![
                CandidateProof { address: holder_a, proof_nodes: storage_proofs[0].clone() },
                CandidateProof { address: holder_b, proof_nodes: storage_proofs[1].clone() },
            ],
            prev_entries: vec![SolventEntry { address: holder_a, streak: 4 }],
            token_account_proof,
        };

        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 2, 19_000_100, 19_000_000, 1, ONE_ETH, Some(&config),
        )
        .unwrap();

        // A qualifies (streak 4 → 5); B's proven balance is below threshold.
        assert_eq!(public.member_count, 1);
        assert_eq!(public.candidate_count, 2);
        assert_eq!(public.token, token);
        assert_eq!(public.balance_slot, 0);
        let expected =
            SolventSet::from_entries(vec![SolventEntry { address: holder_a, streak: 5 }]);
        assert_eq!(public.solvent_set_root, expected.root());
    }

    #[test]
    fn test_erc20_forged_storage_proof_aborts() {
        let token = [0xEE; 20];
        let config = TokenConfig { address: token, balance_slot: 0 };
        let holder = [0x42; 20];
        let (state_root, token_account_proof, mut storage_proofs) =
            erc20_state_fixture(token, 0, &[(holder, 10 * ONE_ETH)]);
        storage_proofs[0][0][3] ^= 0x01; // corrupt the storage node

        let witness = DerivationWitness {
            candidates: vec![CandidateProof {
                address: holder,
                proof_nodes: storage_proofs[0].clone(),
            }],
            prev_entries: vec![],
            token_account_proof,
        };
        assert!(execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, Some(&config),
        )
        .is_err());
    }

    #[test]
    fn test_erc20_wrong_slot_yields_zero_balance() {
        // A storage proof for slot 0 cannot credit a balance under a slot-1
        // policy. The single-leaf storage trie genuinely *proves* the slot-1
        // key absent (the leaf path diverges), so the balance reads as zero
        // and the holder is excluded — never credited. A misconfigured slot is
        // therefore a liveness failure (empty set), not a safety one, and
        // `balance_slot` is committed publicly so the mismatch is detectable.
        let token = [0xEE; 20];
        let holder = [0x42; 20];
        let (state_root, token_account_proof, storage_proofs) =
            erc20_state_fixture(token, 0, &[(holder, 10 * ONE_ETH)]);

        let wrong_slot = TokenConfig { address: token, balance_slot: 1 };
        let witness = DerivationWitness {
            candidates: vec![CandidateProof {
                address: holder,
                proof_nodes: storage_proofs[0].clone(),
            }],
            prev_entries: vec![],
            token_account_proof,
        };
        let public = execute_derivation_statement(
            &witness, &state_root, &POLICY, 1, 19_000_000, 0, 1, ONE_ETH, Some(&wrong_slot),
        )
        .unwrap();
        assert_eq!(public.member_count, 0, "Mismatched slot must not credit a balance");
        assert_eq!(public.balance_slot, 1, "The proven slot is committed publicly");
        assert_eq!(
            public.solvent_set_root,
            SolventSet::from_entries(vec![]).root(),
            "Set must be empty, not silently populated"
        );
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
            prev_block_number: 19_400_000,
            chain_id: 11155111,
            threshold_wei: 123 * ONE_ETH,
            member_count: 42,
            candidate_count: 99,
            token: [0x05; 20],
            balance_slot: 3,
            candidates_root: [0x06; 32],
        };
        let encoded = public.abi_encode();
        assert_eq!(encoded.len(), DERIVATION_PUBLIC_VALUES_LEN);
        assert_eq!(DerivationPublicValues::abi_decode(&encoded).unwrap(), public);

        // Spot-check Solidity word alignment: prev block and token words.
        assert_eq!(u64::from_be_bytes(encoded[216..224].try_into().unwrap()), 19_400_000);
        assert_eq!(&encoded[352..364], &[0u8; 12]);
        assert_eq!(&encoded[364..384], &[0x05; 20]);
        assert_eq!(encoded[415], 3);
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
            prev_block_number: 0,
            chain_id: 1,
            threshold_wei: 1,
            member_count: 1,
            candidate_count: 1,
            token: [0u8; 20],
            balance_slot: 0,
            candidates_root: [0u8; 32],
        };
        let mut encoded = public.abi_encode();
        assert!(DerivationPublicValues::abi_decode(&encoded[..447]).is_err());
        encoded[130] = 0xFF; // dirty padding
        assert!(DerivationPublicValues::abi_decode(&encoded).is_err());
    }

    #[test]
    fn test_candidates_root_is_order_invariant() {
        let a = [0x01; 20];
        let b = [0x02; 20];
        assert_eq!(candidates_root(&[a, b]), candidates_root(&[b, a, a]));
        assert_ne!(candidates_root(&[a]), candidates_root(&[a, b]));
    }
}
