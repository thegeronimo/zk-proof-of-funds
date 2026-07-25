//! Host-side driver for the V2 membership program (`program-membership/`).
//!
//! In production this runs on the *client's* machine (or a delegated prover
//! the client trusts with their witness) — never on the agent: the witness
//! contains the secret key and the membership path, both of which identify
//! the member's address (PRIVACY_V2.md §4).
//!
//! Unlike `proof_worker.rs` (which embeds its ELF at compile time), the
//! membership ELF is loaded at runtime so the agent builds without the SP1
//! toolchain. Build the ELF with: `cd program-membership && cargo prove build`.

use anyhow::{Context, Result};
use sp1_sdk::blocking::{Elf, Prover, ProveRequest, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing::info;

use zk_pof_common::membership::{MembershipPublicValues, MembershipWitness};

/// Location of the built membership ELF, relative to this crate.
pub const MEMBERSHIP_ELF_RELATIVE_PATH: &str =
    "../../program-membership/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-pof-membership-program";

/// Absolute path to the membership ELF for this checkout.
pub fn membership_elf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MEMBERSHIP_ELF_RELATIVE_PATH)
}

/// Load the membership ELF from disk.
pub fn load_membership_elf() -> Result<Vec<u8>> {
    let path = membership_elf_path();
    std::fs::read(&path).with_context(|| {
        format!(
            "Membership ELF not found at {} — build it with `cd program-membership && cargo prove build`",
            path.display()
        )
    })
}

/// Build the SP1 stdin for the membership program.
///
/// Write order is normative and must match the read order in
/// `program-membership/src/main.rs`.
pub fn build_membership_stdin(
    witness: &MembershipWitness,
    solvent_set_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    chain_id: u64,
    min_streak: u64,
    scope_hash: &[u8; 32],
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    // Private inputs
    stdin.write(&witness.sk);
    stdin.write(&witness.streak);
    stdin.write(&witness.leaf_index);
    stdin.write(&witness.siblings);
    // Public inputs
    stdin.write(solvent_set_root);
    stdin.write(policy_id);
    stdin.write(&epoch);
    stdin.write(&chain_id);
    stdin.write(&min_streak);
    stdin.write(scope_hash);
    stdin
}

/// Execute the membership program in the SP1 emulator (no proof — fast path
/// for testing) and decode the committed public values.
pub fn execute_membership_program(
    elf_bytes: Vec<u8>,
    witness: &MembershipWitness,
    solvent_set_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    chain_id: u64,
    min_streak: u64,
    scope_hash: &[u8; 32],
) -> Result<MembershipPublicValues> {
    let client = ProverClient::builder().cpu().build();
    // Elf::Static needs 'static; leaking once per invocation is fine for the
    // CLI/test contexts this runs in.
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let stdin =
        build_membership_stdin(witness, solvent_set_root, policy_id, epoch, chain_id, min_streak, scope_hash);

    let (public_values, report) = client
        .execute(elf, stdin)
        .run()
        .context("SP1 membership program execution failed")?;

    info!(
        total_cycles = report.total_instruction_count(),
        "Membership program execution complete"
    );

    MembershipPublicValues::abi_decode(public_values.as_slice())
}

/// Generate a Groth16-wrapped membership proof for on-chain verification via
/// `SolventSetOracle.verifyMembership`.
///
/// **Warning**: computationally expensive; requires the SP1 proving stack.
/// Use [`execute_membership_program`] for testing.
pub fn prove_membership(
    elf_bytes: Vec<u8>,
    witness: &MembershipWitness,
    solvent_set_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    chain_id: u64,
    min_streak: u64,
    scope_hash: &[u8; 32],
) -> Result<(Vec<u8>, MembershipPublicValues)> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let stdin =
        build_membership_stdin(witness, solvent_set_root, policy_id, epoch, chain_id, min_streak, scope_hash);

    let pk = client
        .setup(elf)
        .context("SP1 setup (key generation) failed")?;

    info!("Generating SP1 Groth16 membership proof (this will take a while)");

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .context("SP1 membership proof generation failed")?;

    let public_values = MembershipPublicValues::abi_decode(proof.public_values.as_slice())?;
    Ok((proof.bytes(), public_values))
}
