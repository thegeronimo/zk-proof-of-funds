//! Privacy V2 end-to-end integration tests (PRIVACY_V2.md + Phase 11).
//!
//! Covers the full solvent-set flow with no chain required:
//!
//! ```text
//! agent:  balances → streak-aware solvent set → root (published)
//! client: download entries → local path → membership statement → public values
//! proven: EIP-1186 witness → derivation statement → permissionless publication values
//! chain:  (SolventSetOracle.t.sol covers the on-chain half against the same ABIs)
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
use zk_pof_common::solvent_derivation::{
    execute_derivation_statement, fixtures, CandidateProof, DerivationWitness,
};
use zk_pof_common::solvent_set::{SolventEntry, SolventSet};

const POLICY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ONE_ETH: u128 = 1_000_000_000_000_000_000;
const CHAIN_ID: u64 = 31337;

fn test_sk(n: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = n;
    out
}

fn address_of(sk: &[u8; 32]) -> [u8; 20] {
    let pk = plume::derive_public_key(sk).unwrap();
    plume::derive_address(&pk).unwrap()
}

fn address_hex_for(sk: &[u8; 32]) -> String {
    hex::encode(address_of(sk))
}

fn client_rebuild_set(service: &SolventSetService<'_>, epoch: u64) -> SolventSet {
    let row = service.get(POLICY_HEX, Some(epoch)).unwrap().unwrap();
    let entries = SolventSetService::decode_entries(&row).unwrap();
    SolventSet::from_entries(entries)
}

/// The full V2 flow across two epochs: streak-aware set building (agent
/// side), path + statement (client side), and the min-streak gate.
#[test]
fn test_full_solvent_set_membership_flow_with_streaks() {
    let db = Database::open_in_memory().unwrap();
    let service = SolventSetService::new(&db);
    let policy_id = parse_policy_id(POLICY_HEX).unwrap();

    // ── Agent side: two epochs. The user qualifies in both; one whale joins
    // late; one holder drops below threshold in epoch 2.
    let user_sk = test_sk(42);
    let user_address = address_hex_for(&user_sk);
    service
        .build_from_balances(
            POLICY_HEX, 1, 19_000_000, ONE_ETH,
            &[
                (user_address.clone(), 5 * ONE_ETH),
                (hex::encode([0x55u8; 20]), 3 * ONE_ETH),
            ],
        )
        .unwrap();
    let build2 = service
        .build_from_balances(
            POLICY_HEX, 2, 19_000_100, ONE_ETH,
            &[
                (user_address.clone(), 5 * ONE_ETH),
                (address_hex_for(&test_sk(7)), 100 * ONE_ETH), // whale joins at epoch 2
                (hex::encode([0x55u8; 20]), ONE_ETH / 2),      // drops out
            ],
        )
        .unwrap();
    assert_eq!(build2.member_count, 2);

    // ── Client side: download the public entries, rebuild the tree locally,
    // compute own membership path. No query reveals the address.
    let set = client_rebuild_set(&service, 2);
    assert_eq!(set.root(), build2.root, "Client-rebuilt root must match the published root");

    let (leaf_index, streak, siblings) = set.path_for(&address_of(&user_sk)).unwrap();
    assert_eq!(streak, 2, "User has been solvent for two consecutive epochs");

    // ── Client side: execute the membership statement (what the SP1 guest
    // proves) with a min-streak requirement the user meets.
    let witness = MembershipWitness {
        sk: user_sk,
        streak,
        leaf_index: leaf_index as u64,
        siblings: siblings.clone(),
    };
    let public_values =
        execute_membership_statement(&witness, &build2.root, &policy_id, 2, CHAIN_ID, 2).unwrap();

    assert_eq!(public_values.solvent_set_root, build2.root);
    assert_eq!(public_values.epoch, 2);
    assert_eq!(public_values.chain_id, CHAIN_ID);
    assert_eq!(public_values.min_streak, 2);

    // A stricter policy (min streak 3) rejects the same witness — rented
    // solvency cannot fake holding duration.
    assert!(
        execute_membership_statement(&witness, &build2.root, &policy_id, 2, CHAIN_ID, 3).is_err()
    );

    // The whale that joined this epoch has streak 1 and fails min-streak 2.
    let whale_sk = test_sk(7);
    let (w_index, w_streak, w_siblings) = set.path_for(&address_of(&whale_sk)).unwrap();
    assert_eq!(w_streak, 1);
    let whale_witness = MembershipWitness {
        sk: whale_sk,
        streak: w_streak,
        leaf_index: w_index as u64,
        siblings: w_siblings,
    };
    assert!(
        execute_membership_statement(&whale_witness, &build2.root, &policy_id, 2, CHAIN_ID, 2)
            .is_err()
    );

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
    let build = service
        .build_from_balances(
            POLICY_HEX, 1, 19_000_000, ONE_ETH,
            &[
                (address_hex_for(&member_sk), 10 * ONE_ETH),
                (address_hex_for(&outsider_sk), ONE_ETH / 10), // insolvent
            ],
        )
        .unwrap();
    assert_eq!(build.member_count, 1);

    let set = client_rebuild_set(&service, 1);

    // The outsider's address is not in the set at all...
    assert!(set.path_for(&address_of(&outsider_sk)).is_none());

    // ...and stealing the member's path fails: the statement derives the
    // address from the outsider's own sk, which doesn't match the leaf.
    let (leaf_index, streak, siblings) = set.path_for(&address_of(&member_sk)).unwrap();
    let stolen = MembershipWitness {
        sk: outsider_sk,
        streak,
        leaf_index: leaf_index as u64,
        siblings,
    };
    assert!(execute_membership_statement(&stolen, &build.root, &policy_id, 1, CHAIN_ID, 1).is_err());
}

/// Stage B: the proven build path — synthetic EIP-1186 proofs through the
/// derivation statement, with streak continuity chained from the stored set.
#[test]
fn test_proven_build_from_account_proofs() {
    let db = Database::open_in_memory().unwrap();
    let service = SolventSetService::new(&db);

    let (addr_a, addr_b) = fixtures::split_addresses();

    // Epoch 1 (Stage A build): only A qualifies.
    service
        .build_from_balances(
            POLICY_HEX, 1, 19_000_000, ONE_ETH,
            &[(hex::encode(addr_a), 5 * ONE_ETH)],
        )
        .unwrap();

    // Epoch 2 (Stage B): both proven via MPT; B is below threshold.
    let (state_root, proof_a, proof_b) =
        fixtures::two_account_trie(addr_a, 5 * ONE_ETH, addr_b, ONE_ETH / 2);
    let proofs = vec![
        CandidateProof { address: addr_a, proof_nodes: proof_a },
        CandidateProof { address: addr_b, proof_nodes: proof_b },
    ];
    let proven = service
        .build_proven_from_proofs(POLICY_HEX, 2, 19_000_100, CHAIN_ID, ONE_ETH, &state_root, proofs, None, vec![])
        .unwrap();

    assert_eq!(proven.result.member_count, 1);
    assert_eq!(proven.public_values.candidate_count, 2);
    assert_eq!(proven.public_values.state_root, state_root);
    assert_eq!(proven.public_values.chain_id, CHAIN_ID);

    // prev_root binds streak continuity to the epoch-1 set.
    let epoch1 = client_rebuild_set(&service, 1);
    assert_eq!(proven.public_values.prev_root, epoch1.root());

    // A's streak chained: 1 → 2, committed in the proven root.
    let expected =
        SolventSet::from_entries(vec![SolventEntry { address: addr_a, streak: 2 }]);
    assert_eq!(proven.public_values.solvent_set_root, expected.root());
    assert_eq!(proven.result.root, expected.root());

    // The stored witness re-executes to identical public values (what the SP1
    // program will commit for permissionless publication).
    let policy_id = parse_policy_id(POLICY_HEX).unwrap();
    let reexecuted = execute_derivation_statement(
        &proven.witness, &state_root, &policy_id, 2, 19_000_100, CHAIN_ID, ONE_ETH, None,
    )
    .unwrap();
    assert_eq!(reexecuted, proven.public_values);
}

/// Run the *actual* SP1 membership guest (program-membership/) in the
/// emulator and check it commits byte-identical public values to the native
/// mirror. `#[ignore]`: needs the built ELF and minutes of emulation — run
/// with `cargo test --test privacy_v2_integration -- --ignored`.
#[test]
#[ignore]
fn test_sp1_membership_guest_matches_native_mirror() {
    let elf = match zk_pof_agent::membership_prover::load_membership_elf() {
        Ok(elf) => elf,
        Err(e) => {
            eprintln!("Skipping membership guest-vs-mirror test: {e}");
            return;
        }
    };

    let policy_id = parse_policy_id(POLICY_HEX).unwrap();
    let user_sk = test_sk(42);
    let user_address = address_of(&user_sk);

    let set = SolventSet::from_entries(vec![
        SolventEntry { address: user_address, streak: 3 },
        SolventEntry { address: [0x55; 20], streak: 1 },
        SolventEntry { address: [0x66; 20], streak: 7 },
    ]);
    let root = set.root();
    let (leaf_index, streak, siblings) = set.path_for(&user_address).unwrap();
    let witness = MembershipWitness {
        sk: user_sk,
        streak,
        leaf_index: leaf_index as u64,
        siblings,
    };

    let native =
        execute_membership_statement(&witness, &root, &policy_id, 1, CHAIN_ID, 2).unwrap();
    let guest = zk_pof_agent::membership_prover::execute_membership_program(
        elf, &witness, &root, &policy_id, 1, CHAIN_ID, 2,
    )
    .unwrap();

    assert_eq!(
        guest, native,
        "SP1 membership guest and native mirror must commit identical public values"
    );
    assert_eq!(guest.abi_encode(), native.abi_encode());
}

/// Run the *actual* SP1 derivation guest (program-solvent-set/) in the
/// emulator and check it commits byte-identical public values to the native
/// mirror. `#[ignore]`: needs the built ELF and minutes of emulation.
#[test]
#[ignore]
fn test_sp1_derivation_guest_matches_native_mirror() {
    let elf = match zk_pof_agent::derivation_prover::load_derivation_elf() {
        Ok(elf) => elf,
        Err(e) => {
            eprintln!("Skipping derivation guest-vs-mirror test: {e}");
            return;
        }
    };

    let policy_id = parse_policy_id(POLICY_HEX).unwrap();
    let (addr_a, addr_b) = fixtures::split_addresses();
    let (state_root, proof_a, proof_b) =
        fixtures::two_account_trie(addr_a, 5 * ONE_ETH, addr_b, ONE_ETH / 2);

    let witness = DerivationWitness {
        candidates: vec![
            CandidateProof { address: addr_a, proof_nodes: proof_a },
            CandidateProof { address: addr_b, proof_nodes: proof_b },
        ],
        prev_entries: vec![SolventEntry { address: addr_a, streak: 4 }],
        token_account_proof: vec![],
    };

    let native = execute_derivation_statement(
        &witness, &state_root, &policy_id, 5, 19_000_100, CHAIN_ID, ONE_ETH, None,
    )
    .unwrap();
    let guest = zk_pof_agent::derivation_prover::execute_derivation_program(
        elf, &witness, &state_root, &policy_id, 5, 19_000_100, CHAIN_ID, ONE_ETH, None,
    )
    .unwrap();

    assert_eq!(
        guest, native,
        "SP1 derivation guest and native mirror must commit identical public values"
    );
    assert_eq!(guest.abi_encode(), native.abi_encode());
}

/// ERC-20 mode of the derivation guest: token account + storage proofs.
/// `#[ignore]`: needs the built ELF and minutes of emulation.
#[test]
#[ignore]
fn test_sp1_derivation_guest_erc20_matches_native_mirror() {
    use zk_pof_common::solvent_derivation::TokenConfig;

    let elf = match zk_pof_agent::derivation_prover::load_derivation_elf() {
        Ok(elf) => elf,
        Err(e) => {
            eprintln!("Skipping ERC-20 derivation guest test: {e}");
            return;
        }
    };

    let policy_id = parse_policy_id(POLICY_HEX).unwrap();
    let token = [0xEE; 20];
    let config = TokenConfig { address: token, balance_slot: 0 };
    let holder = [0x42; 20];
    let (state_root, token_account_proof, storage_proofs) =
        fixtures::erc20_state_fixture(token, 0, &[(holder, 5 * ONE_ETH)]);

    let witness = DerivationWitness {
        candidates: vec![CandidateProof {
            address: holder,
            proof_nodes: storage_proofs[0].clone(),
        }],
        prev_entries: vec![SolventEntry { address: holder, streak: 1 }],
        token_account_proof,
    };

    let native = execute_derivation_statement(
        &witness, &state_root, &policy_id, 2, 19_000_100, CHAIN_ID, ONE_ETH, Some(&config),
    )
    .unwrap();
    let guest = zk_pof_agent::derivation_prover::execute_derivation_program(
        elf, &witness, &state_root, &policy_id, 2, 19_000_100, CHAIN_ID, ONE_ETH, Some(&config),
    )
    .unwrap();

    assert_eq!(guest, native);
    assert_eq!(guest.abi_encode(), native.abi_encode());
    assert_eq!(guest.token, token);
}

/// Run the *actual* SP1 receipt-scan guest (program-receipt-scan/) in the
/// emulator and check it commits byte-identical public values to the native
/// mirror. `#[ignore]`: needs the built ELF and minutes of emulation.
#[test]
#[ignore]
fn test_sp1_scan_guest_matches_native_mirror() {
    use zk_pof_common::receipt_scan::{
        execute_scan_statement, fixtures as scan_fixtures, ScanWitness,
    };

    let elf = match zk_pof_agent::scan_prover::load_scan_elf() {
        Ok(elf) => elf,
        Err(e) => {
            eprintln!("Skipping scan guest-vs-mirror test: {e}");
            return;
        }
    };

    let token = [0xEE; 20];
    let r0 = scan_fixtures::legacy_receipt(&[scan_fixtures::transfer_log(
        token, [0xA1; 20], [0xB2; 20],
    )]);
    let r1 = scan_fixtures::typed_receipt(
        0x02,
        &[scan_fixtures::transfer_log([0xDD; 20], [0xC3; 20], [0xA1; 20])],
    );
    let r2 = scan_fixtures::legacy_receipt(&[]);
    let (receipts_root, nodes) = scan_fixtures::three_receipt_trie(&r0, &r1, &r2);
    let header0 = scan_fixtures::build_header([0x00; 32], [0x02; 32], receipts_root);
    let header1 = scan_fixtures::build_header(
        zk_pof_common::solvent_derivation::fixtures::keccak256(&header0),
        [0x03; 32],
        zk_pof_common::mpt::EMPTY_TRIE_ROOT,
    );

    let witness = ScanWitness {
        headers: vec![header0, header1],
        receipt_nodes: vec![nodes, vec![]],
    };

    let native = execute_scan_statement(&witness, &token).unwrap();
    let guest =
        zk_pof_agent::scan_prover::execute_scan_program(elf, &witness, &token).unwrap();

    assert_eq!(
        guest, native,
        "SP1 scan guest and native mirror must commit identical public values"
    );
    assert_eq!(guest.abi_encode(), native.abi_encode());
    assert_eq!(guest.participant_count, 2);
}
