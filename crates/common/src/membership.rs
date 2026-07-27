//! The V2 membership statement — host-side mirror of `program-membership/`.
//!
//! Statement (PRIVACY_V2.md §4.2; streaks in Phase 11, scopes in Phase 13):
//!
//! ```text
//! Private:  sk, streak, merkle siblings, leaf index
//! Public:   solvent_set_root, policy_id, epoch, chain_id, min_streak,
//!           scope_hash, + presentation context (see below)
//!
//! 1. pk = g * sk                       (sk valid, nonzero)
//! 2. address = keccak256(pk_uncompressed[1..65])[12..32]
//! 3. assert streak >= min_streak       (time-dimension gate)
//! 4. leaf = SHA256("zkpof-solvent-leaf-v2" || address || streak_be)
//! 5. MerkleVerify(leaf, index, siblings, solvent_set_root)
//! 6. N = hash_to_curve(scope_hash || sec1(pk), DST) * sk    (ERC-7524 form)
//! 7. nullifier_hash = SHA256(sec1(N))
//! 8. commit abi.encode(root, policy_id, epoch, nullifier_hash, chain_id,
//!                      min_streak, scope_hash, policy_config_hash,
//!                      verifier, verifier_chain_id, action_id, beneficiary,
//!                      nonce, deadline)
//! ```
//!
//! `scope_hash` is a public input so the verifying contract can pin it to the
//! policy's configured scope (default: `SHA256("zkpof-scope-v1:" || policy_id)`).
//! Policies sharing a scope share member identities by design.
//!
//! The exact streak is a *private* input: the proof reveals only that the
//! streak meets the policy's minimum, not how long the member has actually
//! held funds.
//!
//! ## Presentation context (external review finding R5)
//!
//! Without it a valid proof is a **bearer token**: anyone who observes it can
//! replay it at another verifier, and a mempool watcher can front-run the
//! owner's transaction and burn their nullifier. The proof therefore commits
//! to *where and for whom* it may be used — verifier contract and chain,
//! action, beneficiary, nonce, deadline — plus the policy config hash, so it
//! cannot be carried across a semantic change. This is the same reasoning
//! that makes EIP-4361 sign-in messages carry domain, chain, nonce, and
//! expiry rather than being context-free signatures.
//!
//! This module executes the statement natively (witness generation + testing)
//! and defines the ABI encoding of the public values. The SP1 guest program
//! must match this byte-for-byte; `SolventSetOracle.sol` decodes the same
//! 448-byte blob.

use crate::{plume, solvent_set};
use anyhow::{bail, Result};

/// Private inputs to the membership statement.
#[derive(Debug, Clone)]
pub struct MembershipWitness {
    /// The member's secret key (never leaves the client).
    pub sk: [u8; 32],
    /// The member's committed streak (consecutive epochs in the set).
    /// Private — the proof reveals only `streak >= min_streak`.
    pub streak: u32,
    /// Position of the member's leaf in the solvent-set tree.
    pub leaf_index: u64,
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<[u8; 32]>,
}

/// Where and for whom a proof may be presented. Committed publicly so the
/// verifier can reject anything made for a different destination — see the
/// module docs (review finding R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PresentationContext {
    /// Semantic fingerprint of the policy the proof was made under.
    pub policy_config_hash: [u8; 32],
    /// The verifier contract this proof may be submitted to.
    pub verifier: [u8; 20],
    /// The chain that verifier lives on (may differ from the source chain
    /// once cross-chain verification exists).
    pub verifier_chain_id: u64,
    /// Application-defined action/campaign this proof authorizes.
    pub action_id: [u8; 32],
    /// The only address permitted to consume this proof.
    pub beneficiary: [u8; 20],
    /// Caller-chosen uniqueness value.
    pub nonce: u64,
    /// Last block at which the proof may be presented.
    pub deadline: u64,
}

/// Public values committed by the membership program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipPublicValues {
    pub solvent_set_root: [u8; 32],
    pub policy_id: [u8; 32],
    pub epoch: u64,
    pub nullifier_hash: [u8; 32],
    pub chain_id: u64,
    /// The minimum streak this proof attests to (`witness.streak >= min_streak`).
    pub min_streak: u64,
    /// The scope the nullifier is bound to (policy default, or a shared scope).
    pub scope_hash: [u8; 32],
    /// Where and for whom this proof may be presented.
    pub context: PresentationContext,
}

/// ABI-encoded size: fourteen 32-byte words.
pub const PUBLIC_VALUES_LEN: usize = 448;

impl MembershipPublicValues {
    /// `abi.encode(bytes32, bytes32, uint64, bytes32, uint64, uint64, bytes32,
    /// bytes32, address, uint64, bytes32, address, uint64, uint64)` — 448 bytes.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_VALUES_LEN);
        out.extend_from_slice(&self.solvent_set_root);
        out.extend_from_slice(&self.policy_id);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.nullifier_hash);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.min_streak.to_be_bytes());
        out.extend_from_slice(&self.scope_hash);
        out.extend_from_slice(&self.context.policy_config_hash);
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&self.context.verifier);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.context.verifier_chain_id.to_be_bytes());
        out.extend_from_slice(&self.context.action_id);
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&self.context.beneficiary);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.context.nonce.to_be_bytes());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.context.deadline.to_be_bytes());
        out
    }

    /// Decode and validate a 448-byte public-values blob.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_VALUES_LEN {
            bail!(
                "Invalid public values length: expected {}, got {}",
                PUBLIC_VALUES_LEN,
                bytes.len()
            );
        }
        // uint64/address words must be left-padded with zeros.
        if bytes[64..88] != [0u8; 24]
            || bytes[128..152] != [0u8; 24]
            || bytes[160..184] != [0u8; 24]
            || bytes[256..268] != [0u8; 12]
            || bytes[288..312] != [0u8; 24]
            || bytes[352..364] != [0u8; 12]
            || bytes[384..408] != [0u8; 24]
            || bytes[416..440] != [0u8; 24]
        {
            bail!("Invalid public values: nonzero padding in uint64/address words");
        }
        let word32 = |offset: usize| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[offset..offset + 32]);
            out
        };
        let addr = |offset: usize| {
            let mut out = [0u8; 20];
            out.copy_from_slice(&bytes[offset..offset + 20]);
            out
        };
        Ok(Self {
            solvent_set_root: word32(0),
            policy_id: word32(32),
            epoch: u64::from_be_bytes(bytes[88..96].try_into().unwrap()),
            nullifier_hash: word32(96),
            chain_id: u64::from_be_bytes(bytes[152..160].try_into().unwrap()),
            min_streak: u64::from_be_bytes(bytes[184..192].try_into().unwrap()),
            scope_hash: word32(192),
            context: PresentationContext {
                policy_config_hash: word32(224),
                verifier: addr(268),
                verifier_chain_id: u64::from_be_bytes(bytes[312..320].try_into().unwrap()),
                action_id: word32(320),
                beneficiary: addr(364),
                nonce: u64::from_be_bytes(bytes[408..416].try_into().unwrap()),
                deadline: u64::from_be_bytes(bytes[440..448].try_into().unwrap()),
            },
        })
    }
}

/// Execute the membership statement natively.
///
/// Returns the public values a valid SP1 proof would commit, or an error if
/// the witness does not satisfy the statement (invalid key, bad path,
/// insufficient streak).
#[allow(clippy::too_many_arguments)]
pub fn execute_membership_statement(
    witness: &MembershipWitness,
    solvent_set_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    chain_id: u64,
    min_streak: u64,
    scope_hash: &[u8; 32],
    context: &PresentationContext,
) -> Result<MembershipPublicValues> {
    // 1-2. Key and address derivation (rejects zero/non-canonical sk).
    let pk = plume::derive_public_key(&witness.sk)?;
    let address = plume::derive_address(&pk)?;

    // 3. Time-dimension gate: the committed streak must meet the minimum.
    if (witness.streak as u64) < min_streak {
        bail!(
            "Streak {} does not meet the required minimum {}",
            witness.streak,
            min_streak
        );
    }

    // 4-5. Membership of (address, streak) in the solvent set.
    if !solvent_set::verify_solvent_membership(
        &address,
        witness.streak,
        witness.leaf_index as usize,
        &witness.siblings,
        solvent_set_root,
    ) {
        bail!("Membership path does not verify against the solvent-set root");
    }

    // 6-7. Deterministic nullifier bound to this scope.
    let nullifier = plume::compute_nullifier(&witness.sk, scope_hash)?;
    let nullifier_hash = plume::nullifier_hash(&nullifier);

    Ok(MembershipPublicValues {
        solvent_set_root: *solvent_set_root,
        policy_id: *policy_id,
        epoch,
        nullifier_hash,
        chain_id,
        min_streak,
        scope_hash: *scope_hash,
        context: *context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solvent_set::{SolventEntry, SolventSet};

    const POLICY: [u8; 32] = [0xCD; 32];

    fn scope() -> [u8; 32] {
        plume::default_scope_hash(&POLICY)
    }

    fn sk(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = n;
        out
    }

    fn address_of(key: &[u8; 32]) -> [u8; 20] {
        let pk = plume::derive_public_key(key).unwrap();
        plume::derive_address(&pk).unwrap()
    }

    /// Build a set containing the addresses of the given (key, streak) pairs
    /// plus some fillers.
    fn set_with_keys(keys: &[([u8; 32], u32)]) -> SolventSet {
        let mut entries: Vec<SolventEntry> = keys
            .iter()
            .map(|(k, streak)| SolventEntry { address: address_of(k), streak: *streak })
            .collect();
        entries.push(SolventEntry { address: [0x11; 20], streak: 1 });
        entries.push(SolventEntry { address: [0x22; 20], streak: 4 });
        entries.push(SolventEntry { address: [0x33; 20], streak: 2 });
        SolventSet::from_entries(entries)
    }

    fn witness_for(set: &SolventSet, secret: [u8; 32]) -> MembershipWitness {
        let (index, streak, siblings) = set.path_for(&address_of(&secret)).unwrap();
        MembershipWitness {
            sk: secret,
            streak,
            leaf_index: index as u64,
            siblings,
        }
    }

    fn ctx() -> PresentationContext {
        PresentationContext {
            policy_config_hash: [0xC0; 32],
            verifier: [0xEE; 20],
            verifier_chain_id: 1,
            action_id: [0xAC; 32],
            beneficiary: [0xBE; 20],
            nonce: 7,
            deadline: 19_500_000,
        }
    }

    #[test]
    fn test_statement_happy_path() {
        let secret = sk(5);
        let set = set_with_keys(&[(secret, 3), (sk(6), 1)]);
        let root = set.root();
        let witness = witness_for(&set, secret);

        let public =
            execute_membership_statement(&witness, &root, &POLICY, 42, 1, 2, &scope(), &ctx()).unwrap();

        assert_eq!(public.solvent_set_root, root);
        assert_eq!(public.epoch, 42);
        assert_eq!(public.chain_id, 1);
        assert_eq!(public.min_streak, 2);
        // Identity unification: nullifier_hash == memberId from the enrollment path.
        let expected_nullifier = plume::compute_nullifier(&secret, &scope()).unwrap();
        assert_eq!(public.nullifier_hash, plume::nullifier_hash(&expected_nullifier));
    }

    #[test]
    fn test_statement_rejects_insufficient_streak() {
        // Streak 3 satisfies min_streak 3 but not 4 — rented solvency can't
        // fake holding duration.
        let secret = sk(5);
        let set = set_with_keys(&[(secret, 3)]);
        let root = set.root();
        let witness = witness_for(&set, secret);

        assert!(execute_membership_statement(&witness, &root, &POLICY, 42, 1, 3, &scope(), &ctx()).is_ok());
        let err =
            execute_membership_statement(&witness, &root, &POLICY, 42, 1, 4, &scope(), &ctx()).unwrap_err();
        assert!(err.to_string().contains("Streak"), "got: {err}");
    }

    #[test]
    fn test_statement_rejects_inflated_streak() {
        // Claiming a longer streak than committed breaks the Merkle path.
        let secret = sk(5);
        let set = set_with_keys(&[(secret, 2)]);
        let root = set.root();
        let mut witness = witness_for(&set, secret);
        witness.streak = 5;

        assert!(execute_membership_statement(&witness, &root, &POLICY, 42, 1, 5, &scope(), &ctx()).is_err());
    }

    #[test]
    fn test_statement_rejects_non_member_key() {
        let member = sk(5);
        let outsider = sk(9);
        let set = set_with_keys(&[(member, 2)]);
        let root = set.root();

        // The outsider steals the member's path — the derived address won't match.
        let member_witness = witness_for(&set, member);
        let stolen = MembershipWitness {
            sk: outsider,
            streak: member_witness.streak,
            leaf_index: member_witness.leaf_index,
            siblings: member_witness.siblings,
        };
        assert!(execute_membership_statement(&stolen, &root, &POLICY, 42, 1, 1, &scope(), &ctx()).is_err());
    }

    #[test]
    fn test_statement_rejects_wrong_root() {
        let secret = sk(5);
        let set = set_with_keys(&[(secret, 1)]);
        let witness = witness_for(&set, secret);
        let wrong_root = [0xEE; 32];
        assert!(execute_membership_statement(&witness, &wrong_root, &POLICY, 42, 1, 1, &scope(), &ctx()).is_err());
    }

    #[test]
    fn test_abi_roundtrip() {
        let public = MembershipPublicValues {
            solvent_set_root: [0x01; 32],
            policy_id: [0x02; 32],
            epoch: 0xDEADBEEF,
            nullifier_hash: [0x03; 32],
            chain_id: 11155111,
            min_streak: 12,
            scope_hash: [0x07; 32],
            context: ctx(),
        };
        let encoded = public.abi_encode();
        assert_eq!(encoded.len(), PUBLIC_VALUES_LEN);
        let decoded = MembershipPublicValues::abi_decode(&encoded).unwrap();
        assert_eq!(decoded, public);
    }

    #[test]
    fn test_abi_layout_is_solidity_compatible() {
        // Word layout: [root][policyId][epoch][nullifierHash][chainId][minStreak],
        // uint64s right-aligned in their words.
        let public = MembershipPublicValues {
            solvent_set_root: [0xAA; 32],
            policy_id: [0xBB; 32],
            epoch: 1,
            nullifier_hash: [0xCC; 32],
            chain_id: 5,
            min_streak: 9,
            scope_hash: [0xDD; 32],
            context: ctx(),
        };
        let encoded = public.abi_encode();
        assert_eq!(&encoded[0..32], &[0xAA; 32]);
        assert_eq!(&encoded[32..64], &[0xBB; 32]);
        assert_eq!(&encoded[64..95], &[0u8; 31]);
        assert_eq!(encoded[95], 1);
        assert_eq!(&encoded[96..128], &[0xCC; 32]);
        assert_eq!(encoded[159], 5);
        assert_eq!(&encoded[160..191], &[0u8; 31]);
        assert_eq!(encoded[191], 9);
        assert_eq!(&encoded[192..224], &[0xDD; 32]);
        // Presentation context words.
        assert_eq!(&encoded[224..256], &[0xC0; 32], "policyConfigHash");
        assert_eq!(&encoded[256..268], &[0u8; 12]);
        assert_eq!(&encoded[268..288], &[0xEE; 20], "verifier is address-aligned");
        assert_eq!(encoded[319], 1, "verifierChainId");
        assert_eq!(&encoded[320..352], &[0xAC; 32], "actionId");
        assert_eq!(&encoded[364..384], &[0xBE; 20], "beneficiary");
        assert_eq!(encoded[415], 7, "nonce");
        assert_eq!(
            u64::from_be_bytes(encoded[440..448].try_into().unwrap()),
            19_500_000,
            "deadline"
        );
    }

    #[test]
    fn test_abi_decode_rejects_bad_padding_and_length() {
        let public = MembershipPublicValues {
            solvent_set_root: [0x01; 32],
            policy_id: [0x02; 32],
            epoch: 7,
            nullifier_hash: [0x03; 32],
            chain_id: 1,
            min_streak: 1,
            scope_hash: [0x02; 32],
            context: ctx(),
        };
        let mut encoded = public.abi_encode();
        assert!(MembershipPublicValues::abi_decode(&encoded[..447]).is_err());
        encoded[64] = 0xFF; // dirty padding
        assert!(MembershipPublicValues::abi_decode(&encoded).is_err());
    }
}
