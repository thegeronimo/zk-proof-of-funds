use serde::{Deserialize, Serialize};

// ─── Core Identifiers ───────────────────────────────────────────────────────

/// A 32-byte privacy-preserving member identifier.
/// Computed as SHA256(wallet_signature) where the signature is over
/// "zkpof-holder-v1:{scope}:{nonce}".
pub type MemberId = [u8; 32];

/// A 32-byte policy identifier.
pub type PolicyId = [u8; 32];

// ─── Member ─────────────────────────────────────────────────────────────────

/// Status of an enrolled member for a given policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemberStatus {
    /// Balance >= threshold at last check.
    Solvent,
    /// Balance < threshold at last check.
    Insolvent,
    /// Enrolled but not yet included in an epoch (awaiting first check).
    Pending,
    /// RPC fetch failed for this member in the last epoch.
    FetchFailed,
}

impl MemberStatus {
    /// Returns the on-chain status byte: 1 = solvent, 0 = not solvent.
    pub fn to_status_byte(&self) -> u8 {
        match self {
            MemberStatus::Solvent => 1,
            _ => 0,
        }
    }
}

/// An enrolled member in the solvency system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Privacy-preserving identifier: SHA256(wallet_signature).
    pub member_id: MemberId,
    /// The Ethereum address the agent monitors (private — never exposed via API).
    pub watch_target: [u8; 20],
    /// Which policy this member is enrolled in.
    pub policy_id: PolicyId,
    /// Current solvency status.
    pub status: MemberStatus,
    /// Timestamp when the member enrolled (Unix seconds).
    pub enrolled_at: u64,
    /// The first epoch in which this member will be included.
    pub effective_epoch: u64,
    /// Last balance observed (in wei). Private to the agent.
    pub last_balance_wei: u64,
    /// Last block at which balance was checked.
    pub last_checked_block: u64,
}

// ─── Policy ─────────────────────────────────────────────────────────────────

/// A verification policy defining what the verifier wants proven.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy identifier (32 bytes).
    pub id: PolicyId,
    /// Minimum balance in wei.
    pub threshold_wei: u64,
    /// Token to prove. `None` means native ETH.
    pub token_address: Option<[u8; 20]>,
    /// EVM chain ID.
    pub chain_id: u64,
    /// Blocks between epoch updates.
    pub epoch_length_blocks: u64,
    /// Maximum age of state proof in blocks (must be ≤ 256 for blockhash).
    pub max_block_age: u64,
    /// How long a published root stays valid (in blocks).
    pub root_ttl_blocks: u64,
    /// Authorized Solvency Agent operator address.
    pub operator: [u8; 20],
    /// Scope for memberId scoping / unlinkability across verifiers.
    pub scope: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this policy uses trusted mode (EIP-712) or ZK mode (SP1).
    pub trusted_mode: bool,
    /// Whether the policy is currently active.
    pub active: bool,
}

// ─── Epoch ──────────────────────────────────────────────────────────────────

/// Record of a completed epoch for a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRecord {
    /// Which policy this epoch belongs to.
    pub policy_id: PolicyId,
    /// Epoch number (monotonically increasing per policy).
    pub epoch: u64,
    /// Ethereum block number the state proofs reference.
    pub block_number: u64,
    /// Merkle root of the solvency tree for this epoch.
    pub root: [u8; 32],
    /// Number of members in the tree.
    pub member_count: u32,
    /// Block at which the root was published on-chain.
    pub published_at_block: u64,
    /// Raw proof bytes (SP1 Groth16 proof or empty for trusted mode).
    pub proof_bytes: Vec<u8>,
}

// ─── Merkle Proof ───────────────────────────────────────────────────────────

/// A Merkle membership proof for a single member, served by the agent.
/// This is what relying protocols use to verify membership on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofData {
    /// The member's privacy-preserving ID.
    pub member_id: MemberId,
    /// The policy this proof is for.
    pub policy_id: PolicyId,
    /// Member's status in this epoch (1 = solvent, 0 = insolvent).
    pub status: u8,
    /// Epoch number.
    pub epoch: u64,
    /// Index into the oracle's rootHistory array.
    pub root_index: u64,
    /// The Merkle proof path (sibling hashes from leaf to root).
    pub merkle_proof: Vec<[u8; 32]>,
    /// Index of this member's leaf in the tree.
    pub leaf_index: u32,
    /// The Merkle root (for verification convenience).
    pub root: [u8; 32],
    /// Block number the state proofs reference.
    pub block_number: u64,
}

// ─── Enrollment ─────────────────────────────────────────────────────────────

/// Request to enroll a new member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// Which policy to enroll in.
    pub policy_id: PolicyId,
    /// The wallet address (watchTarget) — revealed to the agent.
    pub wallet_address: [u8; 20],
    /// ECDSA signature proving wallet control.
    pub signature: Vec<u8>,
    /// The message that was signed: "zkpof-holder-v1:{scope}:{nonce}".
    pub signed_message: String,
}

/// Response after successful enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    /// The computed memberId: SHA256(signature).
    pub member_id: MemberId,
    /// Enrollment status.
    pub status: String,
    /// First epoch in which this member will appear in the tree.
    pub effective_epoch: u64,
}

// ─── Trusted Mode (EIP-712) ────────────────────────────────────────────────

/// EIP-712 typed data for trusted mode root assertions.
/// The operator signs this to attest to a solvency root without ZK proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolvencyAssertion {
    /// Which policy this assertion covers.
    pub policy_id: PolicyId,
    /// Merkle root of the solvency tree.
    pub root: [u8; 32],
    /// Epoch number.
    pub epoch: u64,
    /// Block number the state was sampled at.
    pub block_number: u64,
    /// Number of members in the tree.
    pub member_count: u32,
    /// EVM chain ID.
    pub chain_id: u64,
    /// Ethereum state root (for reference, not verified on-chain in trusted mode).
    pub state_root: [u8; 32],
}

// ─── SP1 Public Outputs ─────────────────────────────────────────────────────

/// Public outputs committed by the SP1 batch solvency root program.
/// These are verified on-chain during updateRoot().
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofPublicOutputs {
    /// Ethereum state root all proofs are anchored to.
    pub state_root: [u8; 32],
    /// Which policy this batch covers.
    pub policy_id: PolicyId,
    /// Epoch number.
    pub epoch: u64,
    /// Computed Merkle root of the solvency tree.
    pub solvency_root: [u8; 32],
    /// Balance threshold for this policy (wei).
    pub threshold_wei: u64,
    /// Number of members in the tree.
    pub member_count: u32,
    /// Block number for the state proofs.
    pub block_number: u64,
    /// EVM chain ID.
    pub chain_id: u64,
}

// ─── Webhook ────────────────────────────────────────────────────────────────

/// Webhook event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebhookEvent {
    /// A new member was enrolled.
    MemberEnrolled,
    /// A member's solvency status changed.
    MemberStatusChanged,
    /// A new epoch was completed and root published.
    EpochCompleted,
    /// An epoch update failed.
    EpochFailed,
}

/// A webhook notification payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Type of event.
    pub event: WebhookEvent,
    /// Which policy this event relates to.
    pub policy_id: PolicyId,
    /// Which member (if applicable).
    pub member_id: Option<MemberId>,
    /// Previous status (for status changes).
    pub old_status: Option<u8>,
    /// New status (for status changes).
    pub new_status: Option<u8>,
    /// Epoch number.
    pub epoch: Option<u64>,
    /// Block number.
    pub block_number: Option<u64>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_member_serialization_roundtrip() {
        let member = Member {
            member_id: [0xAA; 32],
            watch_target: [0xBB; 20],
            policy_id: [0xCC; 32],
            status: MemberStatus::Solvent,
            enrolled_at: 1700000000,
            effective_epoch: 42,
            last_balance_wei: 10_000_000_000_000_000_000, // 10 ETH
            last_checked_block: 19_000_000,
        };

        let json = serde_json::to_string(&member).unwrap();
        let deserialized: Member = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.member_id, member.member_id);
        assert_eq!(deserialized.watch_target, member.watch_target);
        assert_eq!(deserialized.status, MemberStatus::Solvent);
        assert_eq!(deserialized.last_balance_wei, 10_000_000_000_000_000_000);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy {
            id: [0xAB; 32],
            threshold_wei: 10_000_000_000_000_000_000, // 10 ETH
            token_address: None,
            chain_id: 1,
            epoch_length_blocks: 100,
            max_block_age: 256,
            root_ttl_blocks: 50_400, // ~7 days at 12s blocks
            operator: [0x01; 20],
            scope: "defi-protocol-xyz".to_string(),
            description: "Prove >= 10 ETH for premium access".to_string(),
            trusted_mode: false,
            active: true,
        };

        let json = serde_json::to_string_pretty(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.threshold_wei, policy.threshold_wei);
        assert_eq!(deserialized.scope, policy.scope);
        assert_eq!(deserialized.root_ttl_blocks, 50_400);
        assert_eq!(deserialized.epoch_length_blocks, 100);
        assert!(!deserialized.trusted_mode);
        assert!(deserialized.active);
    }

    #[test]
    fn test_merkle_proof_data_serialization() {
        let proof = MerkleProofData {
            member_id: [0x11; 32],
            policy_id: [0x22; 32],
            status: 1,
            epoch: 42,
            root_index: 5,
            merkle_proof: vec![[0x33; 32], [0x44; 32], [0x55; 32]],
            leaf_index: 17,
            root: [0x66; 32],
            block_number: 19_500_000,
        };

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: MerkleProofData = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.member_id, proof.member_id);
        assert_eq!(deserialized.status, 1);
        assert_eq!(deserialized.epoch, 42);
        assert_eq!(deserialized.merkle_proof.len(), 3);
        assert_eq!(deserialized.leaf_index, 17);
    }

    #[test]
    fn test_epoch_record_serialization() {
        let epoch = EpochRecord {
            policy_id: [0xAA; 32],
            epoch: 42,
            block_number: 19_500_000,
            root: [0xBB; 32],
            member_count: 100,
            published_at_block: 19_500_050,
            proof_bytes: vec![1, 2, 3, 4],
        };

        let json = serde_json::to_string(&epoch).unwrap();
        let deserialized: EpochRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.epoch, 42);
        assert_eq!(deserialized.member_count, 100);
        assert_eq!(deserialized.proof_bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_member_status_byte() {
        assert_eq!(MemberStatus::Solvent.to_status_byte(), 1);
        assert_eq!(MemberStatus::Insolvent.to_status_byte(), 0);
        assert_eq!(MemberStatus::Pending.to_status_byte(), 0);
        assert_eq!(MemberStatus::FetchFailed.to_status_byte(), 0);
    }

    #[test]
    fn test_enrollment_roundtrip() {
        let request = EnrollmentRequest {
            policy_id: [0xCC; 32],
            wallet_address: [0xDD; 20],
            signature: vec![1, 2, 3, 4, 5],
            signed_message: "zkpof-holder-v1:defi-xyz:42".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: EnrollmentRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.policy_id, request.policy_id);
        assert_eq!(deserialized.wallet_address, request.wallet_address);
        assert_eq!(deserialized.signed_message, "zkpof-holder-v1:defi-xyz:42");
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            event: WebhookEvent::MemberStatusChanged,
            policy_id: [0xAA; 32],
            member_id: Some([0xBB; 32]),
            old_status: Some(1),
            new_status: Some(0),
            epoch: Some(43),
            block_number: Some(19_500_100),
            timestamp: "2025-07-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: WebhookPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.event, WebhookEvent::MemberStatusChanged);
        assert_eq!(deserialized.old_status, Some(1));
        assert_eq!(deserialized.new_status, Some(0));
    }
}
