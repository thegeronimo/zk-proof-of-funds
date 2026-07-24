//! Host-side driver for the Stage B derivation program (`program-solvent-set/`).
//!
//! Unlike the membership prover (which runs on the *client's* machine), the
//! derivation prover runs on the agent/operator side — but its output is
//! verifiable by anyone, and `SolventSetOracle.publishRootProven` accepts a
//! valid proof from any submitter. The witness (candidate account proofs and
//! the previous set) is entirely public data.
//!
//! The ELF is loaded at runtime so the agent builds without the SP1 toolchain.
//! Build the ELF with: `cd program-solvent-set && cargo prove build`.

use anyhow::{Context, Result};
use sp1_sdk::blocking::{Elf, Prover, ProveRequest, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing::info;

use zk_pof_common::solvent_derivation::{DerivationPublicValues, DerivationWitness};

/// Location of the built derivation ELF, relative to this crate.
pub const DERIVATION_ELF_RELATIVE_PATH: &str =
    "../../program-solvent-set/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-pof-solvent-set-program";

/// Absolute path to the derivation ELF for this checkout.
pub fn derivation_elf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DERIVATION_ELF_RELATIVE_PATH)
}

/// Load the derivation ELF from disk.
pub fn load_derivation_elf() -> Result<Vec<u8>> {
    let path = derivation_elf_path();
    std::fs::read(&path).with_context(|| {
        format!(
            "Derivation ELF not found at {} — build it with `cd program-solvent-set && cargo prove build`",
            path.display()
        )
    })
}

/// Build the SP1 stdin for the derivation program.
///
/// Write order is normative and must match the read order in
/// `program-solvent-set/src/main.rs`.
pub fn build_derivation_stdin(
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    block_number: u64,
    chain_id: u64,
    threshold_wei: u128,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    // Public inputs
    stdin.write(state_root);
    stdin.write(policy_id);
    stdin.write(&epoch);
    stdin.write(&block_number);
    stdin.write(&chain_id);
    stdin.write(&threshold_wei);
    // Witness
    let prev_raw: Vec<([u8; 20], u32)> = witness
        .prev_entries
        .iter()
        .map(|e| (e.address, e.streak))
        .collect();
    stdin.write(&prev_raw);
    stdin.write(&(witness.candidates.len() as u32));
    for candidate in &witness.candidates {
        stdin.write(&candidate.address);
        stdin.write(&candidate.proof_nodes);
    }
    stdin
}

/// Execute the derivation program in the SP1 emulator (no proof — fast path
/// for testing) and decode the committed public values.
pub fn execute_derivation_program(
    elf_bytes: Vec<u8>,
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    block_number: u64,
    chain_id: u64,
    threshold_wei: u128,
) -> Result<DerivationPublicValues> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let stdin = build_derivation_stdin(
        witness, state_root, policy_id, epoch, block_number, chain_id, threshold_wei,
    );

    let (public_values, report) = client
        .execute(elf, stdin)
        .run()
        .context("SP1 derivation program execution failed")?;

    info!(
        total_cycles = report.total_instruction_count(),
        "Derivation program execution complete"
    );

    DerivationPublicValues::abi_decode(public_values.as_slice())
}

/// Generate a Groth16-wrapped derivation proof for permissionless publication
/// via `SolventSetOracle.publishRootProven`.
///
/// **Warning**: computationally expensive; requires the SP1 proving stack.
/// Use [`execute_derivation_program`] for testing.
pub fn prove_derivation(
    elf_bytes: Vec<u8>,
    witness: &DerivationWitness,
    state_root: &[u8; 32],
    policy_id: &[u8; 32],
    epoch: u64,
    block_number: u64,
    chain_id: u64,
    threshold_wei: u128,
) -> Result<(Vec<u8>, DerivationPublicValues)> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let stdin = build_derivation_stdin(
        witness, state_root, policy_id, epoch, block_number, chain_id, threshold_wei,
    );

    let pk = client
        .setup(elf)
        .context("SP1 setup (key generation) failed")?;

    info!("Generating SP1 Groth16 derivation proof (this will take a while)");

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .context("SP1 derivation proof generation failed")?;

    let public_values = DerivationPublicValues::abi_decode(proof.public_values.as_slice())?;
    Ok((proof.bytes(), public_values))
}
