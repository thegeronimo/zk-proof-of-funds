//! zkpof-client — the Privacy V2 local signer / client prover.
//!
//! Browser wallets cannot compute PLUME-style nullifiers (raw key access is
//! required — PRIVACY_V2.md §3.3), so this CLI is the supported client path
//! until wallet support lands. The secret key never leaves this process; the
//! agent sees only public data (nullifier + DLEQ, or nothing at all in the
//! solvent-set flow).
//!
//! Subcommands:
//!   nullifier --sk <hex32> --policy <hex32>
//!       Compute the deterministic nullifier + DLEQ proof; prints the JSON
//!       body for POST /v2/enroll.
//!   enroll    --sk <hex32> --policy <hex32> --agent <url>
//!       Compute and submit a V2 enrollment.
//!   witness   --sk <hex32> --policy <hex32> --agent <url>
//!       Download the public solvent set, locate the caller's address
//!       locally, and print the membership witness (leaf index, streak,
//!       siblings) plus the set metadata.
//!   prove     --sk <hex32> --policy <hex32> --agent <url>
//!             [--min-streak <n>] [--chain-id <n>] [--execute-only]
//!       Build the witness and run the SP1 membership program: with
//!       --execute-only (default when no proving stack) emulate and print the
//!       public values; otherwise generate a Groth16 proof for
//!       SolventSetOracle.verifyMembership.

use anyhow::{bail, Context, Result};
use zk_pof_agent::enrollment::parse_policy_id;
use zk_pof_agent::membership_prover;
use zk_pof_common::membership::MembershipWitness;
use zk_pof_common::plume;
use zk_pof_common::solvent_set::{SolventEntry, SolventSet};

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn parse_hex32(value: &str, what: &str) -> Result<[u8; 32]> {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(clean).with_context(|| format!("Invalid hex in {what}"))?;
    if bytes.len() != 32 {
        bail!("Invalid {what} length: expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

struct Common {
    sk: [u8; 32],
    policy_id: [u8; 32],
    policy_hex: String,
}

fn common_args(args: &[String]) -> Result<Common> {
    let sk = parse_hex32(
        &arg_value(args, "--sk").context("--sk <hex32> is required")?,
        "--sk",
    )?;
    let policy_arg = arg_value(args, "--policy").context("--policy <hex32> is required")?;
    let policy_id = parse_policy_id(&policy_arg)?;
    Ok(Common {
        sk,
        policy_id,
        policy_hex: hex::encode(policy_id),
    })
}

/// The JSON body for POST /v2/enroll.
fn enrollment_body(common: &Common) -> Result<serde_json::Value> {
    let public_key = plume::derive_public_key(&common.sk)?;
    let (nullifier, proof) = plume::prove_nullifier(&common.sk, &common.policy_id)?;
    let member_id = plume::nullifier_hash(&nullifier);
    Ok(serde_json::json!({
        "policy_id": common.policy_hex,
        "public_key": hex::encode(public_key),
        "nullifier": hex::encode(nullifier),
        "dleq_a": hex::encode(proof.a),
        "dleq_b": hex::encode(proof.b),
        "dleq_s": hex::encode(proof.s),
        // Derived locally for convenience; the agent recomputes it.
        "member_id": hex::encode(member_id),
    }))
}

/// Download the full solvent set and build this key's membership witness.
async fn build_witness(
    agent: &str,
    common: &Common,
) -> Result<(MembershipWitness, serde_json::Value)> {
    let client = reqwest::Client::new();
    let base = agent.trim_end_matches('/');

    let meta: serde_json::Value = client
        .get(format!("{base}/v2/solvent_set/{}", common.policy_hex))
        .send()
        .await?
        .error_for_status()
        .context("No solvent set found for this policy")?
        .json()
        .await?;
    let epoch = meta["epoch"].as_u64().context("Missing epoch in solvent set metadata")?;
    let total = meta["member_count"].as_u64().unwrap_or(0) as usize;

    // Download the whole public set — the oblivious lookup.
    let mut entries: Vec<SolventEntry> = Vec::with_capacity(total);
    while entries.len() < total {
        let page: serde_json::Value = client
            .get(format!(
                "{base}/v2/solvent_set/{}/leaves?epoch={epoch}&offset={}&limit=10000",
                common.policy_hex,
                entries.len()
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let chunk = page["entries"]
            .as_array()
            .context("Agent did not return entries")?;
        if chunk.is_empty() {
            break;
        }
        for entry in chunk {
            let address_hex = entry[0].as_str().context("Malformed entry address")?;
            let streak = entry[1].as_u64().context("Malformed entry streak")? as u32;
            let bytes = hex::decode(address_hex.strip_prefix("0x").unwrap_or(address_hex))?;
            if bytes.len() != 20 {
                bail!("Malformed entry address length");
            }
            let mut address = [0u8; 20];
            address.copy_from_slice(&bytes);
            entries.push(SolventEntry { address, streak });
        }
    }

    let set = SolventSet::from_entries(entries);
    let served_root = meta["root"].as_str().unwrap_or_default().to_string();
    let local_root = format!("0x{}", hex::encode(set.root()));
    if !served_root.eq_ignore_ascii_case(&local_root) {
        bail!(
            "Rebuilt set root {local_root} does not match the served root {served_root} — refusing to build a witness"
        );
    }

    let public_key = plume::derive_public_key(&common.sk)?;
    let address = plume::derive_address(&public_key)?;
    let Some((leaf_index, streak, siblings)) = set.path_for(&address) else {
        bail!(
            "This key's address is not in the solvent set for epoch {epoch} (not solvent at the reference block)"
        );
    };

    let witness = MembershipWitness {
        sk: common.sk,
        streak,
        leaf_index: leaf_index as u64,
        siblings,
    };
    Ok((witness, meta))
}

fn witness_json(witness: &MembershipWitness, meta: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "epoch": meta["epoch"],
        "root": meta["root"],
        "block_number": meta["block_number"],
        "leaf_index": witness.leaf_index,
        "streak": witness.streak,
        "siblings": witness.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().cloned() else {
        bail!("Usage: zkpof-client <nullifier|enroll|witness|prove> [flags] (see module docs)");
    };

    match command.as_str() {
        "nullifier" => {
            let common = common_args(&args)?;
            println!("{}", serde_json::to_string_pretty(&enrollment_body(&common)?)?);
        }
        "enroll" => {
            let common = common_args(&args)?;
            let agent = arg_value(&args, "--agent").context("--agent <url> is required")?;
            let body = enrollment_body(&common)?;
            let response = reqwest::Client::new()
                .post(format!("{}/v2/enroll", agent.trim_end_matches('/')))
                .json(&body)
                .send()
                .await?;
            let status = response.status();
            let text: serde_json::Value = response.json().await?;
            println!("{}", serde_json::to_string_pretty(&text)?);
            if !status.is_success() {
                bail!("Enrollment failed with HTTP {status}");
            }
        }
        "witness" => {
            let common = common_args(&args)?;
            let agent = arg_value(&args, "--agent").context("--agent <url> is required")?;
            let (witness, meta) = build_witness(&agent, &common).await?;
            println!("{}", serde_json::to_string_pretty(&witness_json(&witness, &meta))?);
        }
        "prove" => {
            let common = common_args(&args)?;
            let agent = arg_value(&args, "--agent").context("--agent <url> is required")?;
            let min_streak: u64 = arg_value(&args, "--min-streak")
                .map(|v| v.parse())
                .transpose()
                .context("Invalid --min-streak")?
                .unwrap_or(1);
            let chain_id: u64 = arg_value(&args, "--chain-id")
                .map(|v| v.parse())
                .transpose()
                .context("Invalid --chain-id")?
                .unwrap_or(1);

            let (witness, meta) = build_witness(&agent, &common).await?;
            let epoch = meta["epoch"].as_u64().unwrap();
            let root_hex = meta["root"].as_str().unwrap_or_default();
            let root = parse_hex32(root_hex, "solvent set root")?;

            let elf = membership_prover::load_membership_elf()?;
            if has_flag(&args, "--execute-only") {
                let public_values = membership_prover::execute_membership_program(
                    elf, &witness, &root, &common.policy_id, epoch, chain_id, min_streak,
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "mode": "execute",
                        "public_values_abi": hex::encode(public_values.abi_encode()),
                        "nullifier_hash": hex::encode(public_values.nullifier_hash),
                        "min_streak": public_values.min_streak,
                        "epoch": public_values.epoch,
                    }))?
                );
            } else {
                let (proof_bytes, public_values) = membership_prover::prove_membership(
                    elf, &witness, &root, &common.policy_id, epoch, chain_id, min_streak,
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "mode": "groth16",
                        "proof_bytes": hex::encode(proof_bytes),
                        "public_values_abi": hex::encode(public_values.abi_encode()),
                        "nullifier_hash": hex::encode(public_values.nullifier_hash),
                        "min_streak": public_values.min_streak,
                        "epoch": public_values.epoch,
                    }))?
                );
            }
        }
        other => bail!("Unknown command: {other} (expected nullifier|enroll|witness|prove)"),
    }
    Ok(())
}
