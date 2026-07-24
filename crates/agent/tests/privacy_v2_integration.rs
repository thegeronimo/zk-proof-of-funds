//! Privacy V2 end-to-end integration tests (PRIVACY_V2.md).
//!
//! Covers the full solvent-set flow with no chain required:
//!
//! ```text
//! agent:  balances → solvent set → root (published)
//! client: download set → local path → membership statement → public values
//! chain:  (SolventSetOracle.t.sol covers the on-chain half against the same ABI)
//! ```
//!
//! Plus the identity unification property: the nullifier hash from a
//! client-side membership proof equals the memberId from nullifier enrollment,
//! so the monitored (V1) and solvent-set (V2) modes are interchangeable.

use zk_pof_agent::db::Database;
use zk_pof_agent::enrollment::{parse_policy_id, register_nullifier_member, NullifierEnrollment};
use zk_pof_agent::solvent_set_service::SolventSetService;
use zk_pof_common::membership::{
    execute_membership_statement, MembershipPublicValues, MembershipWitness, PUBLIC_VALUES_LEN,
};
use zk_pof_common::plume;
use zk_pof_common::solvent_set::SolventSet;

const POLICY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ONE_ETH: u128 = 1_000_000_000_000_000_000;
const CHAIN_ID: u64 = 31337;

fn test_sk(n: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = n;
    out
}

fn address_hex_for(sk: &[u8; 32]) -> String {
    let pk = plume::derive_public_key(sk).unwrap();
    hex::encode(plume::derive_address(&pk).unwrap())
}

/// The full V2 flow: set building (agent side), path + statement (client side),
/// and the resulting public values a valid SP1 proof would commit.
#[test]
fn test_full_solvent_set_membership_flow() {
    let db = Database::open_in_memory().unwrap();
    let service = SolventSetService::new(&db);
    let policy_id = parse_policy_id(POLICY_HEX).unwrap();

    // ── Agent side: build the epoch's solvent set from public balance data.
    // The user's address is just one qualifying address among others — the
    // agent has no idea which addresses belong to members.
    let user_sk = test_sk(42);
    let user_address = address_hex_for(&user_sk);
    let balances = vec![
        (user_address.clone(), 5 * ONE_ETH),
        (address_hex_for(&test_sk(7)), 100 * ONE_ETH), // some whale
        (hex::encode([0x55u8; 20]), 3 * ONE_ETH),      // unrelated holder
        (hex::encode([0x66u8; 20]), ONE_ETH / 2),      // below threshold — excluded
    ];
    let build = service
        .build_from_balances(POLICY_HEX, 1, 19_000_000, ONE_ETH, &balances)
        .unwrap();
    assert_eq!(build.member_count, 3);

    // ── Client side: download the public address list, rebuild the tree
    // locally, and compute own membership path. No query reveals the address.
    let row = service.get(POLICY_HEX, Some(1)).unwrap().unwrap();
    let served: Vec<String> = SolventSetService::decode_addresses(&row).unwrap();
    let parsed: Vec<[u8; 20]> = served
        .iter()
        .map(|a| {
            let bytes = hex::decode(a).unwrap();
            let mut out = [0u8; 20];
            out.copy_from_slice(&bytes);
            out
        })
        .collect();
    let set = SolventSet::new(parsed);
    assert_eq!(set.root(), build.root, "Client-rebuilt root must match the published root");

    let mut user_addr_bytes = [0u8; 20];
    user_addr_bytes.copy_from_slice(&hex::decode(&user_address).unwrap());
    let (leaf_index, siblings) = set.path_for(&user_addr_bytes).unwrap();

    // ── Client side: execute the membership statement (what the SP1 guest
    // proves) and check the committed public values.
    let witness = MembershipWitness {
        sk: user_sk,
        leaf_index: leaf_index as u64,
        siblings,
    };
    let public_values =
        execute_membership_statement(&witness, &build.root, &policy_id, 1, CHAIN_ID).unwrap();

    assert_eq!(public_values.solvent_set_root, build.root);
    assert_eq!(public_values.policy_id, policy_id);
    assert_eq!(public_values.epoch, 1);
    assert_eq!(public_values.chain_id, CHAIN_ID);

    // The ABI blob is exactly what SolventSetOracle.verifyMembership decodes.
    let encoded = public_values.abi_encode();
    assert_eq!(encoded.len(), PUBLIC_VALUES_LEN);
    assert_eq!(MembershipPublicValues::abi_decode(&encoded).unwrap(), public_values);

    // ── Identity unification: the membership proof's nullifier hash equals
    // the memberId from nullifier enrollment for the same (key, policy).
    let (nullifier, proof) = plume::prove_nullifier(&user_sk, &policy_id).unwrap();
    let enrollment = NullifierEnrollment {
        policy_id_hex: POLICY_HEX,
        public_key: plume::derive_public_key(&user_sk).unwrap(),
        nullifier,
        proof,
    };
    let enrolled = register_nullifier_member(&db, &enrollment, 0).unwrap();
    assert_eq!(
        enrolled.member_id, public_values.nullifier_hash,
        "V1 (enrollment) and V2 (membership proof) must present the same identity"
    );

    // And that identity is one-per-key-per-policy: re-enrollment is rejected.
    assert!(register_nullifier_member(&db, &enrollment, 1).is_err());
}

/// A key whose address is below the threshold cannot satisfy the statement,
/// even with a stolen path from a member.
#[test]
fn test_non_member_cannot_prove_membership() {
    let db = Database::open_in_memory().unwrap();
    let service = SolventSetService::new(&db);
    let policy_id = parse_policy_id(POLICY_HEX).unwrap();

    let member_sk = test_sk(1);
    let outsider_sk = test_sk(2);
    let balances = vec![
        (address_hex_for(&member_sk), 10 * ONE_ETH),
        (address_hex_for(&outsider_sk), ONE_ETH / 10), // insolvent
    ];
    let build = service
        .build_from_balances(POLICY_HEX, 1, 19_000_000, ONE_ETH, &balances)
        .unwrap();
    assert_eq!(build.member_count, 1);

    let row = service.get(POLICY_HEX, Some(1)).unwrap().unwrap();
    let served: Vec<String> = SolventSetService::decode_addresses(&row).unwrap();
    let parsed: Vec<[u8; 20]> = served
        .iter()
        .map(|a| {
            let bytes = hex::decode(a).unwrap();
            let mut out = [0u8; 20];
            out.copy_from_slice(&bytes);
            out
        })
        .collect();
    let set = SolventSet::new(parsed);

    // The outsider's address is not in the set at all...
    let mut outsider_addr = [0u8; 20];
    outsider_addr.copy_from_slice(&hex::decode(address_hex_for(&outsider_sk)).unwrap());
    assert!(set.path_for(&outsider_addr).is_none());

    // ...and stealing the member's path fails: the statement derives the
    // address from the outsider's own sk, which doesn't match the leaf.
    let mut member_addr = [0u8; 20];
    member_addr.copy_from_slice(&hex::decode(address_hex_for(&member_sk)).unwrap());
    let (leaf_index, siblings) = set.path_for(&member_addr).unwrap();
    let stolen = MembershipWitness {
        sk: outsider_sk,
        leaf_index: leaf_index as u64,
        siblings,
    };
    assert!(execute_membership_statement(&stolen, &build.root, &policy_id, 1, CHAIN_ID).is_err());
}

/// Run the *actual* SP1 guest program (program-membership/) in the emulator
/// and check it commits byte-identical public values to the native mirror.
///
/// Requires the built ELF (`cd program-membership && cargo prove build`) and
/// several minutes of emulation in debug builds, so it is `#[ignore]` — run
/// with `cargo test --test privacy_v2_integration -- --ignored`.
#[test]
#[ignore]
fn test_sp1_guest_matches_native_mirror() {
    let elf = match zk_pof_agent::membership_prover::load_membership_elf() {
        Ok(elf) => elf,
        Err(e) => {
            eprintln!("Skipping guest-vs-mirror test: {e}");
            return;
        }
    };

    let policy_id = parse_policy_id(POLICY_HEX).unwrap();
    let user_sk = test_sk(42);
    let pk = plume::derive_public_key(&user_sk).unwrap();
    let user_address = plume::derive_address(&pk).unwrap();

    let set = SolventSet::new(vec![user_address, [0x55; 20], [0x66; 20]]);
    let root = set.root();
    let (leaf_index, siblings) = set.path_for(&user_address).unwrap();
    let witness = MembershipWitness {
        sk: user_sk,
        leaf_index: leaf_index as u64,
        siblings,
    };

    let native =
        execute_membership_statement(&witness, &root, &policy_id, 1, CHAIN_ID).unwrap();
    let guest = zk_pof_agent::membership_prover::execute_membership_program(
        elf, &witness, &root, &policy_id, 1, CHAIN_ID,
    )
    .unwrap();

    assert_eq!(
        guest, native,
        "SP1 guest and native mirror must commit identical public values"
    );
    assert_eq!(guest.abi_encode(), native.abi_encode());
}
