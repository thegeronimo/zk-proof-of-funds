//! The V2 membership statement — host-side mirror of `program-membership/`.
//!
//! Statement (PRIVACY_V2.md §4.2):
//!
//! ```text
//! Private:  sk, merkle siblings, leaf index
//! Public:   solvent_set_root, policy_id, epoch, chain_id
//!
//! 1. pk = g * sk                       (sk valid, nonzero)
//! 2. address = keccak256(pk_uncompressed[1..65])[12..32]
//! 3. leaf = SHA256("zkpof-solvent-leaf-v1" || address)
//! 4. MerkleVerify(leaf, index, siblings, solvent_set_root)
//! 5. N = hash_to_curve(msg_pol || pk, DST) * sk
//! 6. nullifier_hash = SHA256(N_compressed)
//! 7. commit abi.encode(root, policy_id, epoch, nullifier_hash, chain_id)
//! ```
//!
//! This module executes the statement natively (witness generation + testing)
//! and defines the ABI encoding of the public values. The SP1 guest program
//! must match this byte-for-byte; `SolventSetOracle.sol` decodes the same
//! 160-byte blob with `abi.decode(..., (bytes32, bytes32, uint64, bytes32, uint64))`.

use crate::{plume, solvent_set};
use anyhow::{bail, Result};

/// Private inputs to the membership statement.
#[derive(Debug, Clone)]
pub struct MembershipWitness {
    /// The member's secret key (never leaves the client).
    pub sk: [u8; 32],
    /// Position of the member's leaf in the solvent-set tree.
    pub leaf_index: u64,
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<[u8; 32]>,
}

/// Public values committed by the membership program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipPublicValues {
    pub solvent_set_root: [u8; 32],
    pub policy_id: [u8; 32],
    pub epoch: u64,
    pub nullifier_hash: [u8; 32],
    pub chain_id: u64,
}

/// ABI-encoded size: five 32-byte words.
pub const PUBLIC_VALUES_LEN: usize = 160;

impl MembershipPublicValues {
    /// `abi.encode(bytes32, bytes32, uint64, bytes32, uint64)` — 160 bytes.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_VALUES_LEN);
        out.extend_from_slice(&self.solvent_set_root);
        out.extend_from_slice(&self.policy_id);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.nullifier_hash);
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out
    }

    /// Decode and validate a 160-byte public-values blob.
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_VALUES_LEN {
            bail!(
                "Invalid public values length: expected {}, got {}",
                PUBLIC_VALUES_LEN,
                bytes.len()
            );
        }
        // uint64 words must be left-padded with zeros.
        if bytes[64..88] != [0u8; 24] || bytes[128..152] != [0u8; 24] {
            bail!("Invalid public values: nonzero padding in uint64 words");
        }
        let mut solvent_set_root = [0u8; 32];
        solvent_set_root.copy_from_slice(&bytes[0..32]);
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&bytes[32..64]);
        let epoch = u64::from_be_bytes(bytes[88..96].try_into().unwrap());
        let mut nullifier_hash = [0u8; 32];
        nullifier_hash.copy_from_slice(&bytes[96..128]);
        let chain_id = u64::from_be_bytes(bytes[152..160].try_into().unwrap());
        Ok(Self {
            solvent_set_root,
            policy_id,
            epoch,
            nullifier_hash,
            chain_id,
        })
    }
}

/// Execute the membership statement natively.
///
/// Returns the public values a valid SP1 proof would commit, or an error if
/// the witness does not satisfy the statement (invalid key, bad path).
pub fn execute_membership_statement(
    witness: &MembershipWitness,
    solvent_set_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    chain_id: u64,
) -> Result<MembershipPublicValues> {
    // 1-2. Key and address derivation (rejects zero/non-canonical sk).
    let pk = plume::derive_public_key(&witness.sk)?;
    let address = plume::derive_address(&pk)?;

    // 3-4. Membership of the derived address in the solvent set.
    if !solvent_set::verify_solvent_membership(
        &address,
        witness.leaf_index as usize,
        &witness.siblings,
        solvent_set_root,
    ) {
        bail!("Membership path does not verify against the solvent-set root");
    }

    // 5-6. Deterministic nullifier bound to this policy.
    let nullifier = plume::compute_nullifier(&witness.sk, policy_id)?;
    let nullifier_hash = plume::nullifier_hash(&nullifier);

    Ok(MembershipPublicValues {
        solvent_set_root: *solvent_set_root,
        policy_id: *policy_id,
        epoch,
        nullifier_hash,
        chain_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solvent_set::SolventSet;

    const POLICY: [u8; 32] = [0xCD; 32];

    fn sk(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = n;
        out
    }

    /// Build a set containing the addresses of sk(1..=n) plus some fillers.
    fn set_with_keys(keys: &[[u8; 32]]) -> SolventSet {
        let mut addrs: Vec<[u8; 20]> = keys
            .iter()
            .map(|k| {
                let pk = plume::derive_public_key(k).unwrap();
                plume::derive_address(&pk).unwrap()
            })
            .collect();
        addrs.push([0x11; 20]);
        addrs.push([0x22; 20]);
        addrs.push([0x33; 20]);
        SolventSet::new(addrs)
    }

    #[test]
    fn test_statement_happy_path() {
        let secret = sk(5);
        let set = set_with_keys(&[secret, sk(6)]);
        let root = set.root();

        let pk = plume::derive_public_key(&secret).unwrap();
        let address = plume::derive_address(&pk).unwrap();
        let (index, siblings) = set.path_for(&address).unwrap();

        let witness = MembershipWitness {
            sk: secret,
            leaf_index: index as u64,
            siblings,
        };
        let public = execute_membership_statement(&witness, &root, &POLICY, 42, 1).unwrap();

        assert_eq!(public.solvent_set_root, root);
        assert_eq!(public.epoch, 42);
        assert_eq!(public.chain_id, 1);
        // Identity unification: nullifier_hash == memberId from the enrollment path.
        let expected_nullifier = plume::compute_nullifier(&secret, &POLICY).unwrap();
        assert_eq!(public.nullifier_hash, plume::nullifier_hash(&expected_nullifier));
    }

    #[test]
    fn test_statement_rejects_non_member_key() {
        let member = sk(5);
        let outsider = sk(9);
        let set = set_with_keys(&[member]);
        let root = set.root();

        // The outsider steals the member's path — the derived address won't match.
        let pk = plume::derive_public_key(&member).unwrap();
        let address = plume::derive_address(&pk).unwrap();
        let (index, siblings) = set.path_for(&address).unwrap();

        let witness = MembershipWitness {
            sk: outsider,
            leaf_index: index as u64,
            siblings,
        };
        assert!(execute_membership_statement(&witness, &root, &POLICY, 42, 1).is_err());
    }

    #[test]
    fn test_statement_rejects_wrong_root() {
        let secret = sk(5);
        let set = set_with_keys(&[secret]);
        let pk = plume::derive_public_key(&secret).unwrap();
        let address = plume::derive_address(&pk).unwrap();
        let (index, siblings) = set.path_for(&address).unwrap();

        let witness = MembershipWitness {
            sk: secret,
            leaf_index: index as u64,
            siblings,
        };
        let wrong_root = [0xEE; 32];
        assert!(execute_membership_statement(&witness, &wrong_root, &POLICY, 42, 1).is_err());
    }

    #[test]
    fn test_abi_roundtrip() {
        let public = MembershipPublicValues {
            solvent_set_root: [0x01; 32],
            policy_id: [0x02; 32],
            epoch: 0xDEADBEEF,
            nullifier_hash: [0x03; 32],
            chain_id: 11155111,
        };
        let encoded = public.abi_encode();
        assert_eq!(encoded.len(), PUBLIC_VALUES_LEN);
        let decoded = MembershipPublicValues::abi_decode(&encoded).unwrap();
        assert_eq!(decoded, public);
    }

    #[test]
    fn test_abi_layout_is_solidity_compatible() {
        // Word layout: [root][policyId][epoch][nullifierHash][chainId],
        // uint64s right-aligned in their words.
        let public = MembershipPublicValues {
            solvent_set_root: [0xAA; 32],
            policy_id: [0xBB; 32],
            epoch: 1,
            nullifier_hash: [0xCC; 32],
            chain_id: 5,
        };
        let encoded = public.abi_encode();
        assert_eq!(&encoded[0..32], &[0xAA; 32]);
        assert_eq!(&encoded[32..64], &[0xBB; 32]);
        assert_eq!(&encoded[64..95], &[0u8; 31]);
        assert_eq!(encoded[95], 1);
        assert_eq!(&encoded[96..128], &[0xCC; 32]);
        assert_eq!(encoded[159], 5);
    }

    #[test]
    fn test_abi_decode_rejects_bad_padding_and_length() {
        let public = MembershipPublicValues {
            solvent_set_root: [0x01; 32],
            policy_id: [0x02; 32],
            epoch: 7,
            nullifier_hash: [0x03; 32],
            chain_id: 1,
        };
        let mut encoded = public.abi_encode();
        assert!(MembershipPublicValues::abi_decode(&encoded[..159]).is_err());
        encoded[64] = 0xFF; // dirty padding
        assert!(MembershipPublicValues::abi_decode(&encoded).is_err());
    }
}
