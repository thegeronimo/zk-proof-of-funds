//! Enrollment — handles member enrollment and signature verification.
//!
//! A member enrolls by signing a deterministic message with their wallet:
//!   Sign("zkpof-holder-v1:{scope}:{nonce}")
//!
//! The agent verifies the signature, checks the initial balance, computes
//! memberId = SHA256(signature), and stores the member for monitoring.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::db::Database;
use crate::rpc_fetcher::RpcFetcher;

/// Enrollment service responsible for processing new member enrollments.
pub struct EnrollmentService<'a> {
    db: &'a Database,
    rpc: &'a RpcFetcher,
}

/// Result of a successful enrollment.
#[derive(Debug, Clone)]
pub struct EnrollmentResult {
    pub member_id: [u8; 32],
    pub effective_epoch: u64,
}

impl<'a> EnrollmentService<'a> {
    /// Create a new enrollment service.
    pub fn new(db: &'a Database, rpc: &'a RpcFetcher) -> Self {
        Self { db, rpc }
    }

    /// Process an enrollment request.
    ///
    /// Steps:
    /// 1. Verify ECDSA signature recovers to the claimed wallet address
    /// 2. Check that the wallet has sufficient balance for the policy threshold
    /// 3. Compute memberId = SHA256(signature)
    /// 4. Determine the effective epoch (next epoch after enrollment)
    /// 5. Store the member in the database
    pub async fn enroll(
        &self,
        policy_id_hex: &str,
        wallet_address_hex: &str,
        signature: &[u8],
        signed_message: &str,
        threshold_wei: &str,
        current_epoch: u64,
    ) -> Result<EnrollmentResult> {
        // 1. Verify signature recovers to the claimed address
        let recovered_address = recover_address(signed_message, signature)
            .context("Failed to recover signer address from signature")?;

        let claimed_address = parse_address(wallet_address_hex)
            .context("Invalid wallet address")?;

        if recovered_address != claimed_address {
            bail!(
                "Signature verification failed: recovered 0x{} but claimed 0x{}",
                hex::encode(recovered_address),
                hex::encode(claimed_address)
            );
        }

        // 2. Verify the signed message format: "zkpof-holder-v1:{scope}:{nonce}"
        if !signed_message.starts_with("zkpof-holder-v1:") {
            bail!("Invalid signed message format: must start with 'zkpof-holder-v1:'");
        }

        // 3. Check balance via RPC (trusted mode — simple eth_getBalance)
        let balance_wei = self.rpc
            .get_balance(wallet_address_hex)
            .await
            .context("Failed to fetch wallet balance")?;

        let threshold = threshold_wei.parse::<u128>()
            .context("Invalid threshold_wei")?;

        if balance_wei < threshold {
            bail!(
                "Insufficient balance: {} < threshold {}",
                balance_wei,
                threshold
            );
        }

        // 4. Compute memberId = SHA256(signature)
        let member_id = compute_member_id(signature);
        let member_id_hex = hex::encode(member_id);

        // 5. Check if already enrolled
        if let Some(existing) = self.db.get_member(&member_id_hex)? {
            if existing.policy_id == policy_id_hex {
                bail!("Member {} is already enrolled in policy {}", member_id_hex, policy_id_hex);
            }
        }

        // 6. Determine effective epoch (next epoch after enrollment)
        let effective_epoch = current_epoch + 1;

        // 7. Get current timestamp
        let enrolled_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 8. Store in database
        self.db.insert_member(
            &member_id_hex,
            wallet_address_hex,
            policy_id_hex,
            enrolled_at,
            effective_epoch,
        )?;

        info!(
            member_id = %member_id_hex,
            policy_id = %policy_id_hex,
            effective_epoch = effective_epoch,
            "Member enrolled successfully"
        );

        Ok(EnrollmentResult {
            member_id,
            effective_epoch,
        })
    }
}

/// Compute memberId = SHA256(signature).
///
/// This is the privacy-preserving identifier used in the Merkle tree.
/// Deterministic — the same signature always produces the same memberId.
pub fn compute_member_id(signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signature);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Recover the Ethereum address from a signed message using EIP-191 personal_sign.
///
/// The message is hashed as:
///   keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
///
/// Then ecrecover is used to get the public key, and the address is the last 20
/// bytes of keccak256(public_key).
pub fn recover_address(message: &str, signature: &[u8]) -> Result<[u8; 20]> {
    use alloy::primitives::{Signature, U256, eip191_hash_message};

    if signature.len() != 65 {
        bail!("Invalid signature length: expected 65, got {}", signature.len());
    }

    // Parse signature: r (32) + s (32) + v (1)
    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    let v = signature[64];

    // v should be 27 or 28, or 0/1 (some signers use 0/1)
    let y_parity = match v {
        27 | 1 => true,
        28 | 0 => false,
        _ => bail!("Invalid v value in signature: {}", v),
    };

    let sig = Signature::new(r, s, y_parity);

    // EIP-191 hash the message
    let message_hash = eip191_hash_message(message.as_bytes());

    // Recover the address
    let recovered = sig.recover_address_from_prehash(&message_hash)
        .context("ecrecover failed")?;

    let mut addr = [0u8; 20];
    addr.copy_from_slice(recovered.as_slice());
    Ok(addr)
}

/// Parse a hex-encoded Ethereum address (with or without 0x prefix).
pub fn parse_address(hex_str: &str) -> Result<[u8; 20]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .context("Invalid hex in address")?;
    if bytes.len() != 20 {
        bail!("Invalid address length: expected 20, got {}", bytes.len());
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_member_id_deterministic() {
        let sig = vec![0xAA; 65];
        let id1 = compute_member_id(&sig);
        let id2 = compute_member_id(&sig);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_member_id_different_sigs() {
        let sig1 = vec![0xAA; 65];
        let sig2 = vec![0xBB; 65];
        let id1 = compute_member_id(&sig1);
        let id2 = compute_member_id(&sig2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_parse_address_with_prefix() {
        let addr = parse_address("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(hex::encode(addr), "1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_parse_address_without_prefix() {
        let addr = parse_address("1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(hex::encode(addr), "1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_parse_address_invalid_length() {
        assert!(parse_address("1234").is_err());
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        assert!(parse_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }
}
