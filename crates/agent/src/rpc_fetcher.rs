//! RPC Fetcher — fetches balances for all members in a batch.
//!
//! In trusted mode, uses simple `eth_getBalance` calls.
//! In ZK mode (Phase 4), will use `eth_getProof` for EIP-1186 state proofs.

use anyhow::{Context, Result};
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use std::str::FromStr;
use tracing::{debug, warn};

/// Balance check result for a single member.
#[derive(Debug, Clone)]
pub struct BalanceResult {
    pub member_id_hex: String,
    pub watch_target: String,
    pub balance_wei: u128,
    pub is_solvent: bool,
}

/// RPC fetcher for querying Ethereum node.
///
/// Uses a type-erased provider to avoid leaking transport generics.
pub struct RpcFetcher {
    provider: Box<dyn Provider + Send + Sync>,
    rpc_url: String,
}

impl RpcFetcher {
    /// Create a new RPC fetcher connected to the given Ethereum RPC URL.
    pub fn new(rpc_url: &str) -> Result<Self> {
        let url: url::Url = rpc_url.parse()
            .context("Invalid RPC URL")?;
        let provider = ProviderBuilder::new().connect_http(url);
        Ok(Self {
            provider: Box::new(provider),
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Get the balance of an address in wei (trusted mode — simple eth_getBalance).
    pub async fn get_balance(&self, address_hex: &str) -> Result<u128> {
        let addr = Address::from_str(address_hex)
            .context("Invalid address")?;

        let balance = self.provider
            .get_balance(addr)
            .await
            .context("eth_getBalance RPC call failed")?;

        // Convert U256 to u128 (safe for balances up to ~340 undecillion wei)
        let balance_u128: u128 = balance.try_into()
            .unwrap_or(u128::MAX); // Cap at u128::MAX for enormous balances

        Ok(balance_u128)
    }

    /// Get the balance of an address at a specific block number.
    pub async fn get_balance_at_block(
        &self,
        address_hex: &str,
        block_number: u64,
    ) -> Result<u128> {
        let addr = Address::from_str(address_hex)
            .context("Invalid address")?;

        let balance = self.provider
            .get_balance(addr)
            .block_id(alloy::eips::BlockNumberOrTag::Number(block_number).into())
            .await
            .context("eth_getBalance RPC call failed")?;

        let balance_u128: u128 = balance.try_into()
            .unwrap_or(u128::MAX);

        Ok(balance_u128)
    }

    /// Get the latest block number.
    pub async fn get_block_number(&self) -> Result<u64> {
        let block_number = self.provider
            .get_block_number()
            .await
            .context("eth_blockNumber RPC call failed")?;

        Ok(block_number)
    }

    /// Fetch balances for all members in a policy, comparing against threshold.
    ///
    /// Returns a list of balance results with solvency status.
    /// Members whose balance fetch fails are marked with balance=0 and is_solvent=false.
    pub async fn fetch_member_balances(
        &self,
        members: &[(String, String)], // (member_id_hex, watch_target_hex)
        threshold_wei: u128,
        block_number: Option<u64>,
    ) -> Vec<BalanceResult> {
        let mut results = Vec::with_capacity(members.len());

        for (member_id_hex, watch_target) in members {
            let balance_result = if let Some(block) = block_number {
                self.get_balance_at_block(watch_target, block).await
            } else {
                self.get_balance(watch_target).await
            };

            match balance_result {
                Ok(balance) => {
                    let is_solvent = balance >= threshold_wei;
                    debug!(
                        member_id = %member_id_hex,
                        balance = balance,
                        threshold = threshold_wei,
                        solvent = is_solvent,
                        "Balance fetched"
                    );
                    results.push(BalanceResult {
                        member_id_hex: member_id_hex.clone(),
                        watch_target: watch_target.clone(),
                        balance_wei: balance,
                        is_solvent,
                    });
                }
                Err(e) => {
                    warn!(
                        member_id = %member_id_hex,
                        error = %e,
                        "Failed to fetch balance, marking as insolvent"
                    );
                    results.push(BalanceResult {
                        member_id_hex: member_id_hex.clone(),
                        watch_target: watch_target.clone(),
                        balance_wei: 0,
                        is_solvent: false,
                    });
                }
            }
        }

        results
    }

    /// Get the RPC URL this fetcher is connected to.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

/// A mock RPC fetcher for testing that doesn't require an actual Ethereum node.
#[cfg(test)]
pub mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock RPC fetcher with configurable balances.
    pub struct MockRpcFetcher {
        balances: Mutex<HashMap<String, u128>>,
        block_number: Mutex<u64>,
    }

    impl MockRpcFetcher {
        pub fn new() -> Self {
            Self {
                balances: Mutex::new(HashMap::new()),
                block_number: Mutex::new(19_000_000),
            }
        }

        pub fn set_balance(&self, address: &str, balance: u128) {
            let addr = address.to_lowercase();
            self.balances.lock().unwrap().insert(addr, balance);
        }

        pub fn set_block_number(&self, block: u64) {
            *self.block_number.lock().unwrap() = block;
        }

        pub fn get_balance_sync(&self, address: &str) -> u128 {
            let addr = address.strip_prefix("0x").unwrap_or(address).to_lowercase();
            *self.balances.lock().unwrap().get(&addr).unwrap_or(&0)
        }

        pub fn get_block_number_sync(&self) -> u64 {
            *self.block_number.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockRpcFetcher;

    #[test]
    fn test_mock_rpc_fetcher() {
        let mock = MockRpcFetcher::new();
        mock.set_balance("abcdef1234567890abcdef1234567890abcdef12", 10_000_000_000_000_000_000);
        assert_eq!(
            mock.get_balance_sync("abcdef1234567890abcdef1234567890abcdef12"),
            10_000_000_000_000_000_000
        );
    }

    #[test]
    fn test_mock_rpc_fetcher_default_zero() {
        let mock = MockRpcFetcher::new();
        assert_eq!(
            mock.get_balance_sync("0000000000000000000000000000000000000000"),
            0
        );
    }

    #[test]
    fn test_mock_block_number() {
        let mock = MockRpcFetcher::new();
        assert_eq!(mock.get_block_number_sync(), 19_000_000);
        mock.set_block_number(19_500_000);
        assert_eq!(mock.get_block_number_sync(), 19_500_000);
    }
}
