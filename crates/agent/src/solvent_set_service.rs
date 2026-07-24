//! Solvent-Set Service — builds and persists per-epoch solvent-set trees.
//!
//! The solvent set is the full list of addresses meeting a policy threshold at
//! a reference block (PRIVACY_V2.md §4). It is *public data*: serving it to
//! anyone reveals nothing about who the members are, and clients compute their
//! own membership paths locally.
//!
//! Stage A derivation (this module): candidates come from Transfer-log
//! discovery (ERC-20) or configured lists, and balances are checked per
//! candidate at the reference block via RPC. Stage B (future) proves the
//! derivation in SP1 from receipt logs.
//!
//! **Privacy invariant**: this service never learns which addresses belong to
//! members — it enumerates *all* qualifying addresses indiscriminately.

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use zk_pof_common::solvent_set::SolventSet;

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

    /// Build a solvent set from already-fetched `(address_hex, balance_wei)`
    /// pairs. Pure with respect to the network — used by tests and by
    /// [`Self::build_from_candidates`] after balance fetching.
    pub fn build_from_balances(
        &self,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        threshold_wei: u128,
        balances: &[(String, u128)],
    ) -> Result<SolventSetBuildResult> {
        let mut solvent_addresses: Vec<[u8; 20]> = Vec::new();
        for (address_hex, balance) in balances {
            if *balance >= threshold_wei {
                solvent_addresses.push(parse_address_hex(address_hex)?);
            }
        }

        let set = SolventSet::new(solvent_addresses);
        let root = set.root();
        let member_count = set.len() as u32;

        let addresses_hex: Vec<String> = set.addresses().iter().map(hex::encode).collect();
        let addresses_json = serde_json::to_string(&addresses_hex)
            .context("Failed to serialize solvent-set addresses")?;

        self.db.store_solvent_set(
            policy_id,
            epoch,
            block_number,
            &hex::encode(root),
            member_count,
            &addresses_json,
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

    /// Build a solvent set by checking each candidate's balance at the
    /// reference block. `token_address = None` checks native ETH; `Some(token)`
    /// checks the ERC-20 balance via `eth_call`.
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

    /// Fetch a stored solvent set (specific epoch, or latest when `None`).
    pub fn get(&self, policy_id: &str, epoch: Option<u64>) -> Result<Option<SolventSetRow>> {
        match epoch {
            Some(e) => self.db.get_solvent_set(policy_id, e),
            None => self.db.get_latest_solvent_set(policy_id),
        }
    }

    /// Decode the stored address list of a solvent set row.
    pub fn decode_addresses(row: &SolventSetRow) -> Result<Vec<String>> {
        serde_json::from_str(&row.addresses_json)
            .context("Corrupt addresses_json in solvent_sets row")
    }
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
    fn test_built_root_supports_membership_paths() {
        let db = Database::open_in_memory().unwrap();
        let service = SolventSetService::new(&db);

        let balances: Vec<(String, u128)> =
            (1..=5u8).map(|n| (addr_hex(n), 10 * ONE_ETH)).collect();
        let result = service
            .build_from_balances(POLICY, 1, 19_000_000, ONE_ETH, &balances)
            .unwrap();

        // A client rebuilds the set from the served address list and proves
        // membership locally against the stored root.
        let row = service.get(POLICY, Some(1)).unwrap().unwrap();
        let addresses = SolventSetService::decode_addresses(&row).unwrap();
        let parsed: Vec<[u8; 20]> = addresses
            .iter()
            .map(|a| parse_address_hex(a).unwrap())
            .collect();
        let set = SolventSet::new(parsed);
        assert_eq!(set.root(), result.root);

        let target = parse_address_hex(&addr_hex(3)).unwrap();
        let (index, siblings) = set.path_for(&target).unwrap();
        assert!(verify_solvent_membership(&target, index, &siblings, &result.root));
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
}
