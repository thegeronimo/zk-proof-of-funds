//! zkpof-e2e — generate **real** proofs and emit the artifacts an on-chain
//! E2E needs (EXECUTION_PLAN.md Phase 15.6).
//!
//! Everything else in the test suite verifies the code *around* the proof
//! system: ABI encoding, contract bindings, host/guest mirror equivalence.
//! None of it demonstrates the one claim that matters most — that a proof
//! produced by the actual guest ELF, wrapped to Groth16, is accepted by the
//! actual deployed SP1 verifier through our oracle. That chain has to be
//! walked unbroken at least once, or "verified proof" is an assumption.
//!
//! This binary walks the prover half and writes a JSON bundle
//! (`target/e2e/<program>.json`) containing the vkey, the ABI-encoded public
//! values, and the proof bytes. `scripts/real-proof-e2e.sh` then deploys the
//! real `SP1VerifierGroth16` and submits them.
//!
//! Usage:
//!   zkpof-e2e derivation-compressed  # real proof, no gnark/Docker needed
//!   zkpof-e2e derivation             # + Groth16 wrap (EVM-verifiable)
//!   zkpof-e2e membership             # secp256k1 + hash-to-curve; expensive
//!
//! ## Two tiers, and why the cheap one is worth running
//!
//! `*-compressed` produces a **real** STARK proof — the guest genuinely
//! executed, and SP1's verifier checks it against the vkey. It needs nothing
//! but CPU: no Docker, no gnark, and none of the ~8 GB Groth16 circuit
//! artifact. That is enough to establish that the guest, the witness, and the
//! committed public values all agree cryptographically.
//!
//! The Groth16 wrap is a *separate* claim: that the proof is verifiable by a
//! Solidity contract. It requires Succinct's `sp1-gnark` Docker image, which
//! is published for **amd64 only** — so on Apple Silicon this tier cannot run
//! locally at all, with or without Docker. Use SP1_PROVER=network, or an
//! x86_64 machine/CI runner.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use zk_pof_agent::{derivation_prover, membership_prover};
use zk_pof_common::membership::{MembershipWitness, PresentationContext};
use zk_pof_common::solvent_derivation::{fixtures, CandidateProof, DerivationWitness};
use zk_pof_common::solvent_set::{SolventEntry, SolventSet};

const POLICY_ID: [u8; 32] = [0xE2; 32];
const CHAIN_ID: u64 = 31337; // anvil
const ONE_ETH: u128 = 1_000_000_000_000_000_000;

fn out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/e2e")
}

fn write_bundle(name: &str, value: serde_json::Value) -> Result<()> {
    let dir = out_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&value)?)?;
    println!("\nWrote {}", path.display());
    Ok(())
}

/// Prove the derivation statement without the Groth16 wrap.
///
/// The cheap tier: a real recursive STARK proof, verified by SP1's own
/// verifier. Establishes that the guest ran and committed exactly these
/// public values — no mock, no emulator. What it deliberately does not
/// establish is EVM verifiability, which is the Groth16 wrap's job.
fn prove_derivation_compressed() -> Result<()> {
    use sp1_sdk::blocking::{Elf, Prover, ProveRequest, ProverClient};
    use sp1_sdk::{HashableKey, ProvingKey};

    let address = [0x42u8; 20];
    let (state_root, proof_nodes) = fixtures::single_leaf_proof(address, 5 * ONE_ETH);
    let witness = DerivationWitness {
        candidates: vec![CandidateProof { address, proof_nodes }],
        prev_entries: vec![],
        token_account_proof: vec![],
    };

    let elf_bytes = derivation_prover::load_derivation_elf()
        .context("build it first: cd program-solvent-set && cargo prove build")?;
    let stdin = derivation_prover::build_derivation_stdin(
        &witness, &state_root, &POLICY_ID, 1, 19_000_000, 0, CHAIN_ID, ONE_ETH, None,
    );

    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));

    println!("SP1 setup (key generation)...");
    let pk = client.setup(elf).context("SP1 setup failed")?;
    let vkey = pk.verifying_key().bytes32();

    println!("Generating a real compressed (recursive STARK) proof...");
    let proof = client
        .prove(&pk, stdin)
        .compressed()
        .run()
        .context("compressed proof generation failed")?;

    // The point of the exercise: an independent check that the proof is valid
    // for this vkey. Without this the run would only show that proving did not
    // crash.
    client
        .verify(&proof, pk.verifying_key(), None)
        .context("SP1 REJECTED the proof it had just generated")?;
    println!("== REAL COMPRESSED PROOF GENERATED AND VERIFIED ==");

    let public_values =
        zk_pof_common::solvent_derivation::DerivationPublicValues::abi_decode(
            proof.public_values.as_slice(),
        )?;
    println!("  vkey        : {vkey}");
    println!("  set root    : 0x{}", hex::encode(public_values.solvent_set_root));
    println!("  member count: {}", public_values.member_count);

    write_bundle(
        "derivation-compressed",
        serde_json::json!({
            "program": "program-solvent-set",
            "proof_kind": "compressed",
            "evm_verifiable": false,
            "vkey": vkey,
            "public_values": format!("0x{}", hex::encode(public_values.abi_encode())),
            "note": "Real recursive STARK proof, verified by the SP1 verifier. \
                     NOT EVM-verifiable — that needs the Groth16 wrap, whose \
                     gnark image is amd64-only.",
        }),
    )
}

/// Prove the Stage B derivation statement and wrap it to Groth16.
///
/// Same single-candidate witness as the compressed tier — the wrap is what
/// differs, and it is the only part that makes the proof EVM-verifiable.
fn prove_derivation() -> Result<()> {
    let address = [0x42u8; 20];
    let (state_root, proof_nodes) = fixtures::single_leaf_proof(address, 5 * ONE_ETH);

    let witness = DerivationWitness {
        candidates: vec![CandidateProof { address, proof_nodes }],
        prev_entries: vec![],
        token_account_proof: vec![],
    };

    let elf = derivation_prover::load_derivation_elf()
        .context("build it first: cd program-solvent-set && cargo prove build")?;

    println!("Generating a real Groth16 derivation proof — this takes a while.");
    let (proof_bytes, public_values, vkey) = derivation_prover::prove_derivation(
        elf,
        &witness,
        &state_root,
        &POLICY_ID,
        1,          // epoch
        19_000_000, // block number
        0,          // prev block (first epoch)
        CHAIN_ID,
        ONE_ETH,
        None,
    )?;

    println!("  proof bytes : {}", proof_bytes.len());
    println!("  set root    : 0x{}", hex::encode(public_values.solvent_set_root));
    println!("  member count: {}", public_values.member_count);

    write_bundle(
        "derivation",
        serde_json::json!({
            "program": "program-solvent-set",
            "vkey": vkey,
            "public_values": format!("0x{}", hex::encode(public_values.abi_encode())),
            "proof_bytes": format!("0x{}", hex::encode(&proof_bytes)),
            "decoded": {
                "state_root": format!("0x{}", hex::encode(public_values.state_root)),
                "prev_root": format!("0x{}", hex::encode(public_values.prev_root)),
                "solvent_set_root": format!("0x{}", hex::encode(public_values.solvent_set_root)),
                "policy_id": format!("0x{}", hex::encode(public_values.policy_id)),
                "epoch": public_values.epoch,
                "block_number": public_values.block_number,
                "prev_block_number": public_values.prev_block_number,
                "chain_id": public_values.chain_id,
                "threshold_wei": public_values.threshold_wei.to_string(),
                "member_count": public_values.member_count,
                "candidates_root": format!("0x{}", hex::encode(public_values.candidates_root)),
            },
        }),
    )
}

/// Prove the membership statement. Expensive — secp256k1 scalar mult and
/// hash-to-curve inside the zkVM — so it is deliberately second.
fn prove_membership() -> Result<()> {
    let sk = {
        let mut out = [0u8; 32];
        out[31] = 5;
        out
    };
    let pk = zk_pof_common::plume::derive_public_key(&sk)?;
    let address = zk_pof_common::plume::derive_address(&pk)?;

    let set = SolventSet::from_entries(vec![
        SolventEntry { address, streak: 3 },
        SolventEntry { address: [0x11; 20], streak: 1 },
    ]);
    let root = set.root();
    let (leaf_index, streak, siblings) = set
        .path_for(&address)
        .context("the key's address must be in the fixture set")?;

    let witness = MembershipWitness {
        sk,
        streak,
        leaf_index: leaf_index as u64,
        siblings,
    };

    let scope = zk_pof_common::plume::default_scope_hash(&POLICY_ID);
    let context = PresentationContext {
        policy_config_hash: [0xC0; 32],
        verifier: [0x0A; 20],
        verifier_chain_id: CHAIN_ID,
        action_id: [0xAC; 32],
        beneficiary: [0xBE; 20],
        nonce: 1,
        deadline: 99_999_999,
    };

    let elf = membership_prover::load_membership_elf()
        .context("build it first: cd program-membership && cargo prove build")?;

    println!("Generating a real Groth16 membership proof — this takes a while.");
    let (proof_bytes, public_values, vkey) = membership_prover::prove_membership(
        elf, &witness, &root, &POLICY_ID, 1, CHAIN_ID, 2, &scope, &context,
    )?;

    println!("  proof bytes   : {}", proof_bytes.len());
    println!("  nullifier hash: 0x{}", hex::encode(public_values.nullifier_hash));

    write_bundle(
        "membership",
        serde_json::json!({
            "program": "program-membership",
            "vkey": vkey,
            "public_values": format!("0x{}", hex::encode(public_values.abi_encode())),
            "proof_bytes": format!("0x{}", hex::encode(&proof_bytes)),
            "decoded": {
                "solvent_set_root": format!("0x{}", hex::encode(public_values.solvent_set_root)),
                "policy_id": format!("0x{}", hex::encode(public_values.policy_id)),
                "epoch": public_values.epoch,
                "nullifier_hash": format!("0x{}", hex::encode(public_values.nullifier_hash)),
                "chain_id": public_values.chain_id,
                "min_streak": public_values.min_streak,
            },
        }),
    )
}

fn main() -> Result<()> {
    let which = std::env::args().nth(1).unwrap_or_default();
    match which.as_str() {
        "derivation-compressed" => prove_derivation_compressed(),
        "derivation" => prove_derivation(),
        "membership" => prove_membership(),
        other => bail!(
            "unknown target {other:?}. Usage: zkpof-e2e \
             <derivation-compressed|derivation|membership>"
        ),
    }
}
