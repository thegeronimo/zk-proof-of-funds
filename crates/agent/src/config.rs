//! Configuration — reads agent settings from environment variables.
//!
//! All settings have sensible defaults for local development.
//! In production, set env vars to override.

use anyhow::{Context, Result};

/// Agent configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Ethereum JSON-RPC URL.
    pub rpc_url: String,
    /// EVM chain ID (e.g. 1 for mainnet, 11155111 for Sepolia).
    pub chain_id: u64,
    /// Hex-encoded operator private key (with or without 0x prefix).
    pub operator_private_key: String,
    /// Address of the deployed SolvencyRootOracle contract.
    pub oracle_address: String,
    /// Path to the SQLite database file.
    pub database_path: String,
    /// Block polling interval in seconds.
    pub poll_interval_secs: u64,
    /// HTTP bind address for the API server.
    pub bind_addr: String,
    /// Whether to skip on-chain transaction submission (DB-only mode for testing).
    pub skip_on_chain: bool,
}

impl AgentConfig {
    /// Load configuration from environment variables.
    ///
    /// Required: `RPC_URL`, `OPERATOR_PRIVATE_KEY`, `ORACLE_ADDRESS`.
    /// Optional (with defaults): `CHAIN_ID`, `DATABASE_PATH`, `POLL_INTERVAL_SECS`, `BIND_ADDR`, `SKIP_ON_CHAIN`.
    pub fn from_env() -> Result<Self> {
        let rpc_url = std::env::var("RPC_URL")
            .context("RPC_URL environment variable is required")?;

        let operator_private_key = std::env::var("OPERATOR_PRIVATE_KEY")
            .context("OPERATOR_PRIVATE_KEY environment variable is required")?;

        let oracle_address = std::env::var("ORACLE_ADDRESS")
            .context("ORACLE_ADDRESS environment variable is required")?;

        let chain_id = std::env::var("CHAIN_ID")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<u64>()
            .context("CHAIN_ID must be a valid u64")?;

        let database_path = std::env::var("DATABASE_PATH")
            .unwrap_or_else(|_| "solvency_agent.db".to_string());

        let poll_interval_secs = std::env::var("POLL_INTERVAL_SECS")
            .unwrap_or_else(|_| "12".to_string())
            .parse::<u64>()
            .context("POLL_INTERVAL_SECS must be a valid u64")?;

        let bind_addr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string());

        let skip_on_chain = std::env::var("SKIP_ON_CHAIN")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        Ok(Self {
            rpc_url,
            chain_id,
            operator_private_key,
            oracle_address,
            database_path,
            poll_interval_secs,
            bind_addr,
            skip_on_chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the config struct can be constructed directly with default-like values.
    /// We avoid `from_env()` in unit tests because env vars are shared across parallel
    /// test threads and can interfere with each other.
    #[test]
    fn test_config_fields() {
        let config = AgentConfig {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 1,
            operator_private_key: "0xdeadbeef".to_string(),
            oracle_address: "0x0000000000000000000000000000000000000001".to_string(),
            database_path: "solvency_agent.db".to_string(),
            poll_interval_secs: 12,
            bind_addr: "0.0.0.0:3000".to_string(),
            skip_on_chain: false,
        };

        assert_eq!(config.chain_id, 1);
        assert_eq!(config.database_path, "solvency_agent.db");
        assert_eq!(config.poll_interval_secs, 12);
        assert_eq!(config.bind_addr, "0.0.0.0:3000");
        assert!(!config.skip_on_chain);
    }

    #[test]
    fn test_config_custom_values() {
        let config = AgentConfig {
            rpc_url: "https://eth-sepolia.example.com".to_string(),
            chain_id: 11155111,
            operator_private_key: "0xaabbccdd".to_string(),
            oracle_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            database_path: "/tmp/test.db".to_string(),
            poll_interval_secs: 6,
            bind_addr: "127.0.0.1:8080".to_string(),
            skip_on_chain: true,
        };

        assert_eq!(config.chain_id, 11155111);
        assert_eq!(config.database_path, "/tmp/test.db");
        assert_eq!(config.poll_interval_secs, 6);
        assert_eq!(config.bind_addr, "127.0.0.1:8080");
        assert!(config.skip_on_chain);
    }
}
