//! Solvent-Set Service — builds and persists per-epoch solvent-set trees.
//!
//! The solvent set is the full list of addresses meeting a policy threshold at
//! a reference block (PRIVACY_V2.md §4), each carrying a **streak** — the
//! number of consecutive epochs it has qualified. It is *public data*: serving
//! it to anyone reveals nothing about who the members are, and clients compute
//! their own membership paths locally.
//!
//! Two build paths:
//! - **Stage A** ([`SolventSetService::build_from_balances`] /
//!   [`SolventSetService::build_from_candidates`]): balances via plain RPC,
//!   root published under operator trust.
//! - **Stage B** ([`SolventSetService::build_proven_from_candidates`]):
//!   per-candidate EIP-1186 proofs verified against the block's state root by
//!   the shared derivation statement; the returned witness feeds
//!   `derivation_prover::prove_derivation` for permissionless on-chain
//!   publication via `SolventSetOracle.publishRootProven`.
//!
//! **Privacy invariant**: this service never learns which addresses belong to
//! members — it enumerates *all* qualifying addresses indiscriminately.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use zk_pof_common::solvent_derivation::{
    derive_entries, execute_derivation_statement, CandidateProof, DerivationPublicValues,
    DerivationWitness, TokenConfig,
};
use zk_pof_common::solvent_set::{SolventEntry, SolventSet};

use crate::db::{Database, SolventSetRow};
use crate::rpc_fetcher::RpcFetcher;

/// Result of building a solvent set for a policy epoch.
#[derive(Debug, Clone)]
pub struct SolventSetBuildResult {
    pub policy_id: String,
    pub epoch: u64,
    pub block_number: u64,
    pub root: [u8; 32],
    pub member_count: u32,
}

/// Result of a Stage B (proven) build: the stored set plus everything needed
/// to generate the on-chain derivation proof out-of-band.
#[derive(Debug, Clone)]
pub struct ProvenBuildResult {
    pub result: SolventSetBuildResult,
    /// Witness for `derivation_prover::prove_derivation` (public data).
    pub witness: DerivationWitness,
    /// The public values a valid proof will commit (native pre-check).
    pub public_values: DerivationPublicValues,
}

/// Service for building and serving solvent sets.
pub struct SolventSetService<'a> {
    db: &'a Database,
}

impl<'a> SolventSetService<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// The next epoch number for a policy's solvent-set series.
    pub fn next_epoch(&self, policy_id: &str) -> Result<u64> {
        Ok(self
            .db
            .get_latest_solvent_set(policy_id)?
            .map(|row| row.epoch + 1)
            .unwrap_or(1))
    }

    /// Load the previous epoch's entries for streak continuity (empty for the
    /// first epoch).
    fn previous_entries(&self, policy_id: &str, epoch: u64) -> Result<Vec<SolventEntry>> {
        match self.db.get_latest_solvent_set_before(policy_id, epoch)? {
            Some(row) => decode_entries_json(&row.addresses_json),
            None => Ok(Vec::new()),
        }
    }

    /// Build a solvent set from already-fetched `(address_hex, balance_wei)`
    /// pairs, chaining streaks from the previous epoch. Pure with respect to
    /// the network — used by tests and by [`Self::build_from_candidates`].
    pub fn build_from_balances(
        &self,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        threshold_wei: u128,
        balances: &[(String, u128)],
    ) -> Result<SolventSetBuildResult> {
        let prev_set = SolventSet::from_entries(self.previous_entries(policy_id, epoch)?);

        let mut entries: Vec<SolventEntry> = Vec::new();
        for (address_hex, balance) in balances {
            if *balance >= threshold_wei {
                let address = parse_address_hex(address_hex)?;
                let streak = match prev_set.entry_for(&address) {
                    Some((_, prev_entry)) => prev_entry.streak + 1,
                    None => 1,
                };
                entries.push(SolventEntry { address, streak });
            }
        }

        self.store_set(policy_id, epoch, block_number, SolventSet::from_entries(entries))
    }

    /// Build a solvent set by checking each candidate's balance at the
    /// reference block (Stage A — operator-trusted). `token_address = None`
    /// checks native ETH; `Some(token)` checks the ERC-20 balance via
    /// `eth_call`.
    ///
    /// Candidates whose balance fetch fails are excluded from this epoch (same
    /// policy as `fetch_member_balances`) — they re-qualify next epoch.
    pub async fn build_from_candidates(
        &self,
        rpc: &RpcFetcher,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        threshold_wei: u128,
        candidates: &[String],
        token_address: Option<&str>,
    ) -> Result<SolventSetBuildResult> {
        let mut balances: Vec<(String, u128)> = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let fetched = match token_address {
                Some(token) => {
                    rpc.get_erc20_balance_at_block(token, candidate, block_number).await
                }
                None => rpc.get_balance_at_block(candidate, block_number).await,
            };
            match fetched {
                Ok(balance) => balances.push((candidate.clone(), balance)),
                Err(e) => {
                    warn!(
                        address = %candidate,
                        error = %e,
                        "Balance fetch failed — excluding candidate from this epoch"
                    );
                }
            }
        }
        self.build_from_balances(policy_id, epoch, block_number, threshold_wei, &balances)
    }

    /// Stage B: build a solvent set from already-fetched EIP-1186 proofs,
    /// validated by the shared derivation statement (native execution).
    /// Sync — safe to call under the backend's DB mutex after all RPC awaits
    /// are done.
    ///
    /// Native mode: `token = None`, candidate proofs are account proofs, and
    /// `token_account_proof` must be empty. ERC-20 mode: candidate proofs are
    /// storage proofs of the balance slot, verified under the token account's
    /// storage root.
    ///
    /// Unlike the Stage A path, an *invalid* proof aborts the build: the same
    /// witness must satisfy the SP1 program, which panics on any bad proof.
    #[allow(clippy::too_many_arguments)]
    pub fn build_proven_from_proofs(
        &self,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        chain_id: u64,
        threshold_wei: u128,
        state_root: &[u8; 32],
        proofs: Vec<CandidateProof>,
        token: Option<&TokenConfig>,
        token_account_proof: Vec<Vec<u8>>,
    ) -> Result<ProvenBuildResult> {
        let witness = DerivationWitness {
            candidates: proofs,
            prev_entries: self.previous_entries(policy_id, epoch)?,
            token_account_proof,
        };

        // Native pre-check: exactly what the SP1 program will prove.
        let public_values = execute_derivation_statement(
            &witness, state_root, &parse_policy_bytes(policy_id)?, epoch, block_number,
            chain_id, threshold_wei, token,
        )?;

        let entries = derive_entries(&witness, state_root, threshold_wei, token)?;
        let result = self.store_set(
            policy_id,
            epoch,
            block_number,
            SolventSet::from_entries(entries),
        )?;

        if result.root != public_values.solvent_set_root {
            bail!("Stored set root diverged from the derivation statement (bug)");
        }

        Ok(ProvenBuildResult { result, witness, public_values })
    }

    /// Stage B convenience: fetch proofs then build. For contexts free to hold
    /// `&Database` across awaits (CLI, tests); the backend uses the fetch
    /// helpers + [`Self::build_proven_from_proofs`] instead.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_proven_from_candidates(
        &self,
        rpc: &RpcFetcher,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        chain_id: u64,
        threshold_wei: u128,
        candidates: &[String],
        token: Option<&TokenConfig>,
    ) -> Result<ProvenBuildResult> {
        match token {
            None => {
                let (state_root, proofs) =
                    fetch_candidate_proofs(rpc, candidates, block_number).await?;
                self.build_proven_from_proofs(
                    policy_id, epoch, block_number, chain_id, threshold_wei, &state_root, proofs,
                    None, vec![],
                )
            }
            Some(config) => {
                let (state_root, token_account_proof, proofs) =
                    fetch_erc20_candidate_proofs(rpc, config, candidates, block_number).await?;
                self.build_proven_from_proofs(
                    policy_id, epoch, block_number, chain_id, threshold_wei, &state_root, proofs,
                    Some(config), token_account_proof,
                )
            }
        }
    }

    /// Persist a built set and return the build result.
    fn store_set(
        &self,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        set: SolventSet,
    ) -> Result<SolventSetBuildResult> {
        let root = set.root();
        let member_count = set.len() as u32;
        let entries_json = encode_entries_json(set.entries())?;

        self.db.store_solvent_set(
            policy_id,
            epoch,
            block_number,
            &hex::encode(root),
            member_count,
            &entries_json,
        )?;

        info!(
            policy_id = %policy_id,
            epoch = epoch,
            block_number = block_number,
            member_count = member_count,
            root = %hex::encode(root),
            "Solvent set built"
        );

        Ok(SolventSetBuildResult {
            policy_id: policy_id.to_string(),
            epoch,
            block_number,
            root,
            member_count,
        })
    }

    /// Fetch a stored solvent set (specific epoch, or latest when `None`).
    pub fn get(&self, policy_id: &str, epoch: Option<u64>) -> Result<Option<SolventSetRow>> {
        match epoch {
            Some(e) => self.db.get_solvent_set(policy_id, e),
            None => self.db.get_latest_solvent_set(policy_id),
        }
    }

    /// Decode the stored entries of a solvent set row.
    pub fn decode_entries(row: &SolventSetRow) -> Result<Vec<SolventEntry>> {
        decode_entries_json(&row.addresses_json)
    }

    /// Decode just the address list of a solvent set row (legacy helper).
    pub fn decode_addresses(row: &SolventSetRow) -> Result<Vec<String>> {
        Ok(Self::decode_entries(row)?
            .iter()
            .map(|e| hex::encode(e.address))
            .collect())
    }
}

/// Fetch everything an ERC-20 Stage B build needs: the state root, the token
/// contract's account proof, and one balance-slot storage proof per candidate
/// — all from a single `eth_getProof` call against the token.
pub async fn fetch_erc20_candidate_proofs(
    rpc: &RpcFetcher,
    token: &TokenConfig,
    candidates: &[String],
    block_number: u64,
) -> Result<([u8; 32], Vec<Vec<u8>>, Vec<CandidateProof>)> {
    let state_root = rpc
        .get_state_root(block_number)
        .await
        .context("Failed to fetch state root for reference block")?;

    let addresses: Vec<[u8; 20]> = candidates
        .iter()
        .map(|c| parse_address_hex(c))
        .collect::<Result<_>>()?;
    let slots: Vec<[u8; 32]> = addresses
        .iter()
        .map(|a| zk_pof_common::mpt::erc20_balance_slot(a, token.balance_slot))
        .collect();

    let token_hex = format!("0x{}", hex::encode(token.address));
    let (token_account_proof, storage_proofs) = rpc
        .get_proof_with_storage(&token_hex, &slots, block_number)
        .await
        .context("Failed to fetch token storage proofs")?;

    let proofs = addresses
        .into_iter()
        .zip(storage_proofs)
        .map(|(address, proof_nodes)| CandidateProof { address, proof_nodes })
        .collect();

    Ok((state_root, token_account_proof, proofs))
}

/// Fetch the state root and per-candidate EIP-1186 proofs for a Stage B
/// build. Fetch failures exclude the candidate (it re-qualifies next epoch);
/// the returned proofs are the derivation witness's candidate list.
pub async fn fetch_candidate_proofs(
    rpc: &RpcFetcher,
    candidates: &[String],
    block_number: u64,
) -> Result<([u8; 32], Vec<CandidateProof>)> {
    let state_root = rpc
        .get_state_root(block_number)
        .await
        .context("Failed to fetch state root for reference block")?;

    let mut proofs: Vec<CandidateProof> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        match rpc.get_account_proof(candidate, block_number).await {
            Ok((_balance, proof_nodes)) => {
                proofs.push(CandidateProof {
                    address: parse_address_hex(candidate)?,
                    proof_nodes,
                });
            }
            Err(e) => {
                warn!(
                    address = %candidate,
                    error = %e,
                    "Account proof fetch failed — excluding candidate from this epoch"
                );
            }
        }
    }
    Ok((state_root, proofs))
}

/// Pick an unpredictable reference block for balance sampling.
///
/// A fixed "latest block" sample lets a borrower rent funds for exactly the
/// block they know will be sampled. Deriving the offset from a recent
/// blockhash makes the sampled block unknowable until the entropy block
/// exists — by which time the funds must already be in place.
///
/// The offset stays within the *first half* of `max_block_age`, leaving the
/// second half as proving/publication headroom before `blockhash()` expires
/// on-chain (same budget split as ARCHITECTURE.md §10.1).
pub fn select_reference_block(
    current_block: u64,
    entropy: &[u8; 32],
    max_block_age: u64,
) -> u64 {
    let window = (max_block_age / 2).max(1);
    let mut hasher = Sha256::new();
    hasher.update(b"zkpof-refblock-v1");
    hasher.update(entropy);
    let digest = hasher.finalize();
    let offset = u64::from_be_bytes(digest[..8].try_into().unwrap()) % window;
    current_block.saturating_sub(1 + offset)
}

/// Serialize entries as `[["<hex addr>", streak], ...]`.
fn encode_entries_json(entries: &[SolventEntry]) -> Result<String> {
    let raw: Vec<(String, u32)> = entries
        .iter()
        .map(|e| (hex::encode(e.address), e.streak))
        .collect();
    serde_json::to_string(&raw).context("Failed to serialize solvent-set entries")
}

/// Decode entries from either the streak format `[["addr", streak], ...]` or
/// the legacy Phase 10 format `["addr", ...]` (treated as streak 1).
fn decode_entries_json(json: &str) -> Result<Vec<SolventEntry>> {
    if let Ok(raw) = serde_json::from_str::<Vec<(String, u32)>>(json) {
        return raw
            .into_iter()
            .map(|(address_hex, streak)| {
                Ok(SolventEntry { address: parse_address_hex(&address_hex)?, streak })
            })
            .collect();
    }
    let legacy: Vec<String> =
        serde_json::from_str(json).context("Corrupt addresses_json in solvent_sets row")?;
    legacy
        .into_iter()
        .map(|address_hex| {
            Ok(SolventEntry { address: parse_address_hex(&address_hex)?, streak: 1 })
        })
        .collect()
}

/// Parse a 20-byte hex address (0x prefix optional).
fn parse_address_hex(address_hex: &str) -> Result<[u8; 20]> {
    let clean = address_hex.strip_prefix("0x").unwrap_or(address_hex);
    let bytes = hex::decode(clean).context("Invalid hex in address")?;
    if bytes.len() != 20 {
        bail!("Invalid address length: expected 20 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a 32-byte policy id from hex.
fn parse_policy_bytes(policy_id_hex: &str) -> Result<[u8; 32]> {
    crate::enrollment::parse_policy_id(policy_id_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pof_common::solvent_set::verify_solvent_membership;

    const POLICY: &str = "abababababababababababababababababababababababababababababababab";
    const ONE_ETH: u128 = 1_000_000_000_000_000_000;

    fn addr_hex(n: u8) -> String {
        hex::encode([n; 20])
    }

    #[test]
    fn test_build_filters_by_threshold() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);

        let balances = vec![
            (addr_hex(1), 5 * ONE_ETH),          // solvent
            (addr_hex(2), ONE_ETH),              // exactly at threshold — solvent
            (addr_hex(3), ONE_ETH - 1),          // below — excluded
            (format!("0x{}", addr_hex(4)), 2 * ONE_ETH), // 0x prefix accepted
        ];
        let result = service
            .build_from_balances(POLICY, 1, 19_000_000, ONE_ETH, &balances)
            .unwrap();

        assert_eq!(result.member_count, 3);
        assert_ne!(result.root, [0u8; 32]);

        let row = service.get(POLICY, None).unwrap().unwrap();
        assert_eq!(row.epoch, 1);
        let addresses = SolventSetService::decode_addresses(&row).unwrap();
        assert_eq!(addresses, vec![addr_hex(1), addr_hex(2), addr_hex(4)]);
    }

    #[test]
    fn test_streaks_chain_across_epochs() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);

        // Epoch 1: addresses 1 and 2 qualify.
        service
            .build_from_balances(
                POLICY, 1, 19_000_000, ONE_ETH,
                &[(addr_hex(1), 2 * ONE_ETH), (addr_hex(2), 2 * ONE_ETH)],
            )
            .unwrap();

        // Epoch 2: address 1 stays, address 2 drops out, address 3 is new.
        service
            .build_from_balances(
                POLICY, 2, 19_000_100, ONE_ETH,
                &[
                    (addr_hex(1), 2 * ONE_ETH),
                    (addr_hex(2), ONE_ETH / 2),
                    (addr_hex(3), 3 * ONE_ETH),
                ],
            )
            .unwrap();

        let row = service.get(POLICY, Some(2)).unwrap().unwrap();
        let entries = SolventSetService::decode_entries(&row).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].address, [0x01; 20]);
        assert_eq!(entries[0].streak, 2, "Continuing member's streak increments");
        assert_eq!(entries[1].address, [0x03; 20]);
        assert_eq!(entries[1].streak, 1, "New member starts at streak 1");

        // Epoch 3: address 2 returns — its streak restarts at 1.
        service
            .build_from_balances(
                POLICY, 3, 19_000_200, ONE_ETH,
                &[(addr_hex(1), 2 * ONE_ETH), (addr_hex(2), 2 * ONE_ETH)],
            )
            .unwrap();
        let row = service.get(POLICY, Some(3)).unwrap().unwrap();
        let entries = SolventSetService::decode_entries(&row).unwrap();
        assert_eq!(entries[0].streak, 3, "Address 1: three consecutive epochs");
        assert_eq!(entries[1].streak, 1, "Address 2: streak reset after dropping out");
    }

    #[test]
    fn test_rebuild_same_epoch_chains_from_prior_epoch() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);

        service
            .build_from_balances(POLICY, 1, 19_000_000, ONE_ETH, &[(addr_hex(1), 2 * ONE_ETH)])
            .unwrap();
        service
            .build_from_balances(POLICY, 2, 19_000_100, ONE_ETH, &[(addr_hex(1), 2 * ONE_ETH)])
            .unwrap();
        // Rebuild epoch 2 — streaks must still chain from epoch 1, not from
        // the earlier build of epoch 2 itself.
        service
            .build_from_balances(POLICY, 2, 19_000_101, ONE_ETH, &[(addr_hex(1), 2 * ONE_ETH)])
            .unwrap();

        let row = service.get(POLICY, Some(2)).unwrap().unwrap();
        let entries = SolventSetService::decode_entries(&row).unwrap();
        assert_eq!(entries[0].streak, 2);
    }

    #[test]
    fn test_legacy_addresses_json_decodes_as_streak_one() {
        let db = Database::open_in_memory().unwrap();
        db.store_solvent_set(POLICY, 1, 19_000_000, "00", 2, r#"["1111111111111111111111111111111111111111","2222222222222222222222222222222222222222"]"#)
            .unwrap();
        let service = SolventSetService::new(&db);
        let row = service.get(POLICY, Some(1)).unwrap().unwrap();
        let entries = SolventSetService::decode_entries(&row).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.streak == 1));
    }

    #[test]
    fn test_built_root_supports_membership_paths() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);

        let balances: Vec<(String, u128)> =
            (1..=5u8).map(|n| (addr_hex(n), 10 * ONE_ETH)).collect();
        let result = service
            .build_from_balances(POLICY, 1, 19_000_000, ONE_ETH, &balances)
            .unwrap();

        // A client rebuilds the set from the served entries and proves
        // membership locally against the stored root.
        let row = service.get(POLICY, Some(1)).unwrap().unwrap();
        let entries = SolventSetService::decode_entries(&row).unwrap();
        let set = SolventSet::from_entries(entries);
        assert_eq!(set.root(), result.root);

        let target = [0x03; 20];
        let (index, streak, siblings) = set.path_for(&target).unwrap();
        assert!(verify_solvent_membership(&target, streak, index, &siblings, &result.root));
    }

    #[test]
    fn test_next_epoch_progression() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);

        assert_eq!(service.next_epoch(POLICY).unwrap(), 1);
        service
            .build_from_balances(POLICY, 1, 19_000_000, ONE_ETH, &[(addr_hex(1), 2 * ONE_ETH)])
            .unwrap();
        assert_eq!(service.next_epoch(POLICY).unwrap(), 2);
    }

    #[test]
    fn test_empty_set_has_zero_root() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);
        let result = service
            .build_from_balances(POLICY, 1, 19_000_000, ONE_ETH, &[(addr_hex(1), 1)])
            .unwrap();
        assert_eq!(result.member_count, 0);
        assert_eq!(result.root, [0u8; 32]);
    }

    #[test]
    fn test_rejects_malformed_address() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);
        let result = service.build_from_balances(
            POLICY,
            1,
            19_000_000,
            ONE_ETH,
            &[("nothex".to_string(), 2 * ONE_ETH)],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_select_reference_block_bounds_and_variance() {
        let current = 20_000_000u64;
        let max_age = 256u64;

        let a = select_reference_block(current, &[0x11; 32], max_age);
        let b = select_reference_block(current, &[0x22; 32], max_age);

        for block in [a, b] {
            assert!(block < current, "Reference block must be in the past");
            assert!(
                current - block <= max_age / 2 + 1,
                "Reference block must leave proving headroom (got {})",
                current - block
            );
        }
        // Deterministic per entropy, varying across entropies.
        assert_eq!(a, select_reference_block(current, &[0x11; 32], max_age));
        assert_ne!(a, b, "Different entropy should (overwhelmingly) shift the sample");
    }
}
