//! Host-side driver for the Stage B.2 receipt-scan program
//! (`program-receipt-scan/`).
//!
//! The witness (block headers + full receipts tries) is public data any full
//! node can produce; the proof does not trust the producer. Witness *building*
//! (fetching raw receipts and reconstructing the tries) is operator tooling —
//! see PRIVACY_V2.md §7.
//!
//! The ELF is loaded at runtime so the agent builds without the SP1 toolchain.
//! Build the ELF with: `cd program-receipt-scan && cargo prove build`.

use anyhow::{Context, Result};
use sp1_sdk::blocking::{Elf, Prover, ProveRequest, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing::info;

use zk_pof_common::receipt_scan::{ScanPublicValues, ScanWitness};

/// Location of the built receipt-scan ELF, relative to this crate.
pub const SCAN_ELF_RELATIVE_PATH: &str =
    "../../program-receipt-scan/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-pof-receipt-scan-program";

/// Absolute path to the receipt-scan ELF for this checkout.
pub fn scan_elf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SCAN_ELF_RELATIVE_PATH)
}

/// Load the receipt-scan ELF from disk.
pub fn load_scan_elf() -> Result<Vec<u8>> {
    let path = scan_elf_path();
    std::fs::read(&path).with_context(|| {
        format!(
            "Receipt-scan ELF not found at {} — build it with `cd program-receipt-scan && cargo prove build`",
            path.display()
        )
    })
}

/// Build the SP1 stdin for the receipt-scan program.
///
/// Write order is normative and must match the read order in
/// `program-receipt-scan/src/main.rs`.
pub fn build_scan_stdin(witness: &ScanWitness, token: &[u8; 20]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(token);
    stdin.write(&witness.headers);
    stdin.write(&witness.receipt_nodes);
    stdin
}

/// Execute the receipt-scan program in the SP1 emulator (no proof — fast
/// path for testing) and decode the committed public values.
pub fn execute_scan_program(
    elf_bytes: Vec<u8>,
    witness: &ScanWitness,
    token: &[u8; 20],
) -> Result<ScanPublicValues> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let stdin = build_scan_stdin(witness, token);

    let (public_values, report) = client
        .execute(elf, stdin)
        .run()
        .context("SP1 receipt-scan program execution failed")?;

    info!(
        total_cycles = report.total_instruction_count(),
        "Receipt-scan program execution complete"
    );

    ScanPublicValues::abi_decode(public_values.as_slice())
}

/// Generate a Groth16-wrapped completeness proof.
///
/// **Warning**: computationally expensive; requires the SP1 proving stack.
/// Use [`execute_scan_program`] for testing.
pub fn prove_scan(
    elf_bytes: Vec<u8>,
    witness: &ScanWitness,
    token: &[u8; 20],
) -> Result<(Vec<u8>, ScanPublicValues)> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let stdin = build_scan_stdin(witness, token);

    let pk = client
        .setup(elf)
        .context("SP1 setup (key generation) failed")?;

    info!("Generating SP1 Groth16 receipt-scan proof (this will take a while)");

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .context("SP1 receipt-scan proof generation failed")?;

    let public_values = ScanPublicValues::abi_decode(proof.public_values.as_slice())?;
    Ok((proof.bytes(), public_values))
}
