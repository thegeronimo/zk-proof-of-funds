//! RPC Fetcher — fetches balances and state proofs for all members in a batch.
//!
//! In trusted mode, uses simple `eth_getBalance` calls.
//! In ZK mode, uses `eth_getProof` for EIP-1186 account state proofs.

use anyhow::{Context, Result};
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use std::str::FromStr;
use tracing::{debug, warn};

/// Balance check result for a single member.
#[derive(Debug, Clone)]
pub struct BalanceResult {
    pub member_id_hex: String,
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
                        balance_wei: 0,
                        is_solvent: false,
                    });
                }
            }
        }

        results
    }

    // --- ZK Mode: EIP-1186 Account Proofs ---

    /// Fetch an EIP-1186 account proof for an address at a specific block.
    ///
    /// Returns `(balance_wei, proof_nodes)` where `proof_nodes` are the raw RLP-encoded
    /// MPT proof nodes suitable for feeding into the SP1 program.
    pub async fn get_account_proof(
        &self,
        address_hex: &str,
        block_number: u64,
    ) -> Result<(u128, Vec<Vec<u8>>)> {
        let addr = Address::from_str(address_hex)
            .context("Invalid address")?;

        let proof_response = self.provider
            .get_proof(addr, vec![])
            .block_id(alloy::eips::BlockNumberOrTag::Number(block_number).into())
            .await
            .context("eth_getProof RPC call failed")?;

        // Convert U256 balance to u128 (safe for balances up to ~340 undecillion wei)
        let balance_u128: u128 = proof_response.balance.try_into()
            .unwrap_or(u128::MAX);

        // Extract the RLP-encoded proof nodes as raw bytes
        let proof_nodes: Vec<Vec<u8>> = proof_response
            .account_proof
            .iter()
            .map(|node| node.to_vec())
            .collect();

        debug!(
            address = %addr,
            block_number = block_number,
            balance = balance_u128,
            proof_node_count = proof_nodes.len(),
            "Fetched account proof"
        );

        Ok((balance_u128, proof_nodes))
    }

    /// Get the state root for a specific block.
    ///
    /// The state root is needed as input to the SP1 program for MPT verification.
    pub async fn get_state_root(&self, block_number: u64) -> Result<[u8; 32]> {
        let block = self.provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block_number))
            .hashes()
            .await
            .context("Failed to fetch block")?
            .context("Block not found")?;

        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(block.header.state_root.as_slice());
        Ok(state_root)
    }

    /// Get the RPC URL this fetcher is connected to.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    // --- Privacy V2: solvent-set derivation helpers ---

    /// Get an ERC-20 balance at a specific block via `eth_call` of
    /// `balanceOf(address)` (selector `0x70a08231`).
    pub async fn get_erc20_balance_at_block(
        &self,
        token_hex: &str,
        holder_hex: &str,
        block_number: u64,
    ) -> Result<u128> {
        use alloy::primitives::{Bytes, TxKind, U256};
        use alloy::rpc::types::{TransactionInput, TransactionRequest};

        let token = Address::from_str(token_hex).context("Invalid token address")?;
        let holder = Address::from_str(holder_hex).context("Invalid holder address")?;

        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]); // balanceOf(address)
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(holder.as_slice());

        let tx = TransactionRequest {
            to: Some(TxKind::Call(token)),
            input: TransactionInput::new(Bytes::from(calldata)),
            ..Default::default()
        };

        let output = self.provider
            .call(tx)
            .block(alloy::eips::BlockNumberOrTag::Number(block_number).into())
            .await
            .context("eth_call balanceOf failed")?;

        if output.len() < 32 {
            anyhow::bail!("balanceOf returned {} bytes, expected 32", output.len());
        }
        let balance = U256::from_be_slice(&output[..32]);
        Ok(balance.try_into().unwrap_or(u128::MAX))
    }

    /// Fetch ERC-20 `Transfer` event logs for a token over a block range.
    ///
    /// Used for solvent-set candidate discovery: every address that has sent
    /// or received the token in the range is a candidate whose balance is then
    /// checked at the reference block.
    pub async fn get_transfer_logs(
        &self,
        token_hex: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<alloy::rpc::types::Log>> {
        use alloy::primitives::B256;
        use alloy::rpc::types::Filter;

        let token = Address::from_str(token_hex).context("Invalid token address")?;
        let filter = Filter::new()
            .address(token)
            .event_signature(B256::from(TRANSFER_EVENT_TOPIC))
            .from_block(from_block)
            .to_block(to_block);

        self.provider
            .get_logs(&filter)
            .await
            .context("eth_getLogs RPC call failed")
    }
}

/// `keccak256("Transfer(address,address,uint256)")` — topic0 of ERC-20 transfers.
pub const TRANSFER_EVENT_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
    0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
    0xb3, 0xef,
];

/// Extract the unique `from`/`to` participants from ERC-20 Transfer logs.
///
/// Returns lowercase hex addresses (no 0x prefix), sorted and deduplicated.
/// Logs that are not standard indexed Transfers (fewer than 3 topics) are
/// skipped.
pub fn parse_transfer_participants(logs: &[alloy::rpc::types::Log]) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut participants = BTreeSet::new();
    for log in logs {
        let topics = log.topics();
        if topics.len() >= 3 && topics[0].as_slice() == TRANSFER_EVENT_TOPIC {
            for topic in &topics[1..3] {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&topic.as_slice()[12..]);
                participants.insert(hex::encode(addr));
            }
        }
    }
    participants.into_iter().collect()
}

// ─── Mock RPC Fetcher ────────────────────────────────────────────────────────

/// A mock RPC fetcher for testing that doesn't require an actual Ethereum node.
///
/// Available outside `#[cfg(test)]` so that integration tests in `tests/` can use it.
pub mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use super::BalanceResult;

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

        // ── Async methods (matching RpcFetcher API for epoch_processor) ──

        /// Async version of get_block_number (reads from mock state).
        pub async fn get_block_number_async(&self) -> u64 {
            self.get_block_number_sync()
        }

        /// Fetch balances for members using mock data.
        ///
        /// Mirrors `RpcFetcher::fetch_member_balances()` but reads from the
        /// in-memory HashMap instead of making RPC calls.
        pub async fn fetch_member_balances(
            &self,
            members: &[(String, String)], // (member_id_hex, watch_target_hex)
            threshold_wei: u128,
            _block_number: Option<u64>,
        ) -> Vec<BalanceResult> {
            let mut results = Vec::with_capacity(members.len());

            for (member_id_hex, watch_target) in members {
                let balance = self.get_balance_sync(watch_target);
                let is_solvent = balance >= threshold_wei;

                results.push(BalanceResult {
                    member_id_hex: member_id_hex.clone(),
                    balance_wei: balance,
                    is_solvent,
                });
            }

            results
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

    #[tokio::test]
    async fn test_mock_fetch_member_balances() {
        let mock = MockRpcFetcher::new();
        mock.set_balance("aaaa1234567890abcdef1234567890abcdef1234", 5_000_000_000_000_000_000);
        mock.set_balance("bbbb1234567890abcdef1234567890abcdef1234", 500_000_000_000_000_000);

        let members = vec![
            ("member_a".to_string(), "aaaa1234567890abcdef1234567890abcdef1234".to_string()),
            ("member_b".to_string(), "bbbb1234567890abcdef1234567890abcdef1234".to_string()),
        ];

        let results = mock.fetch_member_balances(
            &members,
            1_000_000_000_000_000_000, // 1 ETH threshold
            Some(19_000_000),
        ).await;

        assert_eq!(results.len(), 2);
        assert!(results[0].is_solvent);   // 5 ETH >= 1 ETH
        assert!(!results[1].is_solvent);  // 0.5 ETH < 1 ETH
    }

    #[tokio::test]
    async fn test_mock_get_block_number_async() {
        let mock = MockRpcFetcher::new();
        mock.set_block_number(20_000_000);
        assert_eq!(mock.get_block_number_async().await, 20_000_000);
    }

    #[test]
    fn test_parse_transfer_participants() {
        use super::{parse_transfer_participants, TRANSFER_EVENT_TOPIC};
        use alloy::primitives::{Address, B256, Log as PrimitiveLog, LogData};

        fn topic_for(addr_byte: u8) -> B256 {
            let mut bytes = [0u8; 32];
            bytes[12..].copy_from_slice(&[addr_byte; 20]);
            B256::from(bytes)
        }

        fn transfer_log(from: u8, to: u8) -> alloy::rpc::types::Log {
            let inner = PrimitiveLog {
                address: Address::ZERO,
                data: LogData::new_unchecked(
                    vec![B256::from(TRANSFER_EVENT_TOPIC), topic_for(from), topic_for(to)],
                    Default::default(),
                ),
            };
            alloy::rpc::types::Log { inner, ..Default::default() }
        }

        // Two transfers sharing a participant, plus a non-Transfer log (2 topics).
        let mut logs = vec![transfer_log(0x01, 0x02), transfer_log(0x02, 0x03)];
        let unrelated = alloy::rpc::types::Log {
            inner: PrimitiveLog {
                address: Address::ZERO,
                data: LogData::new_unchecked(
                    vec![B256::ZERO, topic_for(0x09)],
                    Default::default(),
                ),
            },
            ..Default::default()
        };
        logs.push(unrelated);

        let participants = parse_transfer_participants(&logs);
        assert_eq!(
            participants,
            vec![
                hex::encode([0x01; 20]),
                hex::encode([0x02; 20]),
                hex::encode([0x03; 20]),
            ],
            "Participants must be deduped, sorted, and skip non-Transfer logs"
        );
    }
}
