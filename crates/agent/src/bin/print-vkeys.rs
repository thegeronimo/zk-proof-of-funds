//! Print the SP1 verification keys for deployment.
//!
//! The bytes32 outputs are what `SolventSetOracle` expects as
//! `membershipVKey` / `derivationVKey` (settable at deploy time or via
//! `setMembershipVKey` / `setDerivationVKey`).
//!
//! Usage:
//!   cargo run -p zk-pof-agent --bin print-vkeys [membership|derivation|batch]
//!
//! With no argument, prints every program whose ELF is built. Key generation
//! runs a full SP1 setup per program — expect minutes and significant RAM.

use anyhow::{Context, Result};
use sp1_sdk::blocking::{Elf, Prover, ProverClient};
use sp1_sdk::{HashableKey, ProvingKey};

fn vkey_for(name: &str, elf_bytes: Vec<u8>) -> Result<()> {
    eprintln!("[{name}] running SP1 setup (this takes a while)...");
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(elf_bytes.into_boxed_slice()));
    let pk = client
        .setup(elf)
        .with_context(|| format!("SP1 setup failed for {name}"))?;
    println!("{name}: {}", pk.verifying_key().bytes32());
    Ok(())
}

fn main() -> Result<()> {
    let which = std::env::args().nth(1);
    let want = |name: &str| which.as_deref().map_or(true, |w| w == name);
    let mut printed = false;

    if want("membership") {
        match zk_pof_agent::membership_prover::load_membership_elf() {
            Ok(elf) => {
                vkey_for("membership", elf)?;
                printed = true;
            }
            Err(e) => eprintln!("[membership] skipped: {e}"),
        }
    }
    if want("derivation") {
        match zk_pof_agent::derivation_prover::load_derivation_elf() {
            Ok(elf) => {
                vkey_for("derivation", elf)?;
                printed = true;
            }
            Err(e) => eprintln!("[derivation] skipped: {e}"),
        }
    }
    if want("receipt-scan") {
        match zk_pof_agent::scan_prover::load_scan_elf() {
            Ok(elf) => {
                vkey_for("receipt-scan", elf)?;
                printed = true;
            }
            Err(e) => eprintln!("[receipt-scan] skipped: {e}"),
        }
    }

    if !printed {
        anyhow::bail!(
            "No ELFs found (or unknown program name). Build them first:\n  \
             cd program-membership && cargo prove build\n  \
             cd program-solvent-set && cargo prove build"
        );
    }
    Ok(())
}
