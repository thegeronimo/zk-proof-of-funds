//! Reading policy parameters from the authoritative on-chain registry.
//!
//! Build parameters used to come from the operator's request body, with a
//! hard-coded 1 ETH default when omitted (external review finding R8). That
//! means the set an operator publishes could be built against a threshold,
//! token, or balance slot that has nothing to do with what the relying
//! contract will check — and the mismatch only surfaces as a revert at
//! publication, or worse, as a root that verifies under semantics nobody
//! intended.
//!
//! The registry is the single source of truth, so the agent reads it. The
//! `configHash` is fetched alongside the fields so a build can be pinned to
//! the exact policy version it was derived under.

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use anyhow::{bail, Context, Result};

sol! {
    #[sol(rpc)]
    contract PolicyRegistry {
        struct Policy {
            uint256 thresholdWei;
            address tokenAddress;
            uint64 chainId;
            uint64 epochLengthBlocks;
            uint64 maxBlockAge;
            uint64 rootTTLBlocks;
            address operator;
            string scope;
            bool trustedMode;
            bool active;
            uint64 startBlock;
            uint32 version;
        }

        function getPolicy(bytes32 policyId) external view returns (Policy memory);
        function configHash(bytes32 policyId) external view returns (bytes32);
        function policyFrozen(bytes32 policyId) external view returns (bool);
    }
}

sol! {
    #[sol(rpc)]
    contract SolventSetOracle {
        function balanceSlotOf(bytes32 policyId) external view returns (uint64);
        function requiresCompleteness(bytes32 policyId) external view returns (bool);
        function policyConfigHash(bytes32 policyId) external view returns (bytes32);
        function getSetCount(bytes32 policyId) external view returns (uint256);
    }
}

/// Policy parameters as the chain defines them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainPolicy {
    pub threshold_wei: u128,
    /// `None` for native ETH.
    pub token_address: Option<[u8; 20]>,
    pub chain_id: u64,
    pub epoch_length_blocks: u64,
    pub max_block_age: u64,
    pub root_ttl_blocks: u64,
    pub start_block: u64,
    pub version: u32,
    pub active: bool,
    /// `balanceOf` mapping slot pinned on the oracle (0 for native ETH).
    pub balance_slot: u64,
    pub requires_completeness: bool,
    /// The oracle's full semantic fingerprint — what a published root pins.
    pub policy_config_hash: [u8; 32],
    /// Whether the registry has frozen this policy's semantics.
    pub frozen: bool,
}

/// Reads policy configuration from the registry + oracle.
pub struct PolicyReader {
    rpc_url: String,
    registry: Address,
    oracle: Address,
}

impl PolicyReader {
    /// Construct from hex addresses. Both contracts are needed: the registry
    /// holds the economic terms, the oracle holds the balance slot, the
    /// completeness requirement, and the combined config hash.
    pub fn new(rpc_url: &str, registry_address: &str, oracle_address: &str) -> Result<Self> {
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            registry: registry_address
                .parse()
                .context("Invalid PolicyRegistry address")?,
            oracle: oracle_address
                .parse()
                .context("Invalid SolventSetOracle address")?,
        })
    }

    /// Build from environment: `ETH_RPC_URL`, `POLICY_REGISTRY_ADDRESS`,
    /// `SOLVENT_SET_ORACLE_ADDRESS`. Returns `None` when any is unset, so a
    /// dev deployment without contracts still starts.
    pub fn from_env() -> Option<Self> {
        let rpc = std::env::var("ETH_RPC_URL").ok()?;
        let registry = std::env::var("POLICY_REGISTRY_ADDRESS").ok()?;
        let oracle = std::env::var("SOLVENT_SET_ORACLE_ADDRESS").ok()?;
        Self::new(&rpc, &registry, &oracle).ok()
    }

    /// Fetch a policy's authoritative parameters.
    pub async fn fetch(&self, policy_id: &[u8; 32]) -> Result<OnChainPolicy> {
        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .context("Failed to connect to the RPC for policy reads")?;

        let registry = PolicyRegistry::new(self.registry, &provider);
        let oracle = SolventSetOracle::new(self.oracle, &provider);
        let id = FixedBytes::<32>::from(*policy_id);

        let policy = registry
            .getPolicy(id)
            .call()
            .await
            .context("PolicyRegistry.getPolicy failed — is the policy registered?")?;

        let threshold_wei: u128 = policy
            .thresholdWei
            .try_into()
            .map_err(|_| anyhow::anyhow!("Policy threshold exceeds u128"))?;

        let token_address = if policy.tokenAddress.is_zero() {
            None
        } else {
            Some(policy.tokenAddress.into_array())
        };

        let balance_slot = oracle.balanceSlotOf(id).call().await.unwrap_or(0);
        let requires_completeness =
            oracle.requiresCompleteness(id).call().await.unwrap_or(false);
        let policy_config_hash = oracle
            .policyConfigHash(id)
            .call()
            .await
            .context("SolventSetOracle.policyConfigHash failed")?
            .into();
        let frozen = registry.policyFrozen(id).call().await.unwrap_or(false);

        Ok(OnChainPolicy {
            threshold_wei,
            token_address,
            chain_id: policy.chainId,
            epoch_length_blocks: policy.epochLengthBlocks,
            max_block_age: policy.maxBlockAge,
            root_ttl_blocks: policy.rootTTLBlocks,
            start_block: policy.startBlock,
            version: policy.version,
            active: policy.active,
            balance_slot,
            requires_completeness,
            policy_config_hash,
            frozen,
        })
    }
}

/// Reject a build request whose parameters contradict the chain.
///
/// The request may still *carry* these values — integrators send them, and
/// silently ignoring a mismatch would be its own trap. They are checked, not
/// trusted: a disagreement means the operator is about to build a set that
/// cannot be published under this policy, and failing here gives a readable
/// error instead of a revert.
pub fn reject_param_drift(
    on_chain: &OnChainPolicy,
    requested_threshold: Option<u128>,
    requested_token: Option<&[u8; 20]>,
    requested_slot: Option<u64>,
) -> Result<()> {
    if let Some(threshold) = requested_threshold {
        if threshold != on_chain.threshold_wei {
            bail!(
                "threshold_wei {} contradicts the on-chain policy ({}). Omit it to \
                 use the registry value.",
                threshold,
                on_chain.threshold_wei
            );
        }
    }
    let requested_token_opt = requested_token.copied();
    if requested_token_opt.is_some() && requested_token_opt != on_chain.token_address {
        bail!(
            "token_address contradicts the on-chain policy (expected {}). Omit it \
             to use the registry value.",
            on_chain
                .token_address
                .map(|t| format!("0x{}", hex::encode(t)))
                .unwrap_or_else(|| "native ETH".to_string())
        );
    }
    if let Some(slot) = requested_slot {
        if slot != on_chain.balance_slot {
            bail!(
                "balance_slot {} contradicts the slot pinned on the oracle ({}). \
                 Omit it to use the pinned value.",
                slot,
                on_chain.balance_slot
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OnChainPolicy {
        OnChainPolicy {
            threshold_wei: 1_000_000_000_000_000_000,
            token_address: None,
            chain_id: 1,
            epoch_length_blocks: 100,
            max_block_age: 256,
            root_ttl_blocks: 1000,
            start_block: 0,
            version: 1,
            active: true,
            balance_slot: 0,
            requires_completeness: false,
            policy_config_hash: [0xC0; 32],
            frozen: true,
        }
    }

    #[test]
    fn test_matching_params_accepted() {
        assert!(reject_param_drift(&policy(), Some(1_000_000_000_000_000_000), None, Some(0)).is_ok());
        // Omitting everything is the normal path: the chain decides.
        assert!(reject_param_drift(&policy(), None, None, None).is_ok());
    }

    #[test]
    fn test_threshold_drift_rejected() {
        let err = reject_param_drift(&policy(), Some(5), None, None).unwrap_err();
        assert!(err.to_string().contains("contradicts the on-chain policy"));
    }

    #[test]
    fn test_token_drift_rejected() {
        // A native-ETH policy must not accept an ERC-20 build request.
        let err = reject_param_drift(&policy(), None, Some(&[0xEE; 20]), None).unwrap_err();
        assert!(err.to_string().contains("native ETH"));

        // ...and vice versa.
        let mut erc20 = policy();
        erc20.token_address = Some([0xEE; 20]);
        assert!(reject_param_drift(&erc20, None, Some(&[0xEE; 20]), None).is_ok());
        assert!(reject_param_drift(&erc20, None, Some(&[0xAA; 20]), None).is_err());
    }

    #[test]
    fn test_slot_drift_rejected() {
        let mut erc20 = policy();
        erc20.token_address = Some([0xEE; 20]);
        erc20.balance_slot = 9;
        let err = reject_param_drift(&erc20, None, None, Some(3)).unwrap_err();
        assert!(err.to_string().contains("pinned on the oracle"));
    }
}
