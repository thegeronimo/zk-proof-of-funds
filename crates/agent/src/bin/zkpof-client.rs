//! zkpof-client — the Privacy V2 local signer / client prover.
//!
//! Browser wallets cannot compute PLUME-style nullifiers (raw key access is
//! required — PRIVACY_V2.md §3.3), so this CLI is the supported client path
//! until wallet support lands. The secret key never leaves this process; the
//! agent sees only public data (nullifier + DLEQ, or nothing at all in the
//! solvent-set flow).
//!
//! ## Secret-key handling
//!
//! The key is **never** accepted as a command-line argument — argv leaks into
//! shell history, `ps`, scrollback, and crash reports. Supply it via the
//! hidden prompt (default), `--sk-stdin`, or `--sk-env <VAR>`; it is held in
//! zeroizing buffers. Passing `--sk` is a hard error with instructions.
//!
//! Subcommands:
//!   (every subcommand accepts an optional --scope <hex32> to bind the
//!    nullifier to a shared scope instead of the policy's default)
//!
//!   nullifier --policy <hex32>
//!       Compute the deterministic nullifier + DLEQ proof; prints the JSON
//!       body for POST /v2/enroll.
//!   enroll    --policy <hex32> --agent <url>
//!       Compute and submit a V2 enrollment.
//!   witness   --policy <hex32> --agent <url>
//!       Download the public solvent set, locate the caller's address
//!       locally, and print the membership witness (leaf index, streak,
//!       siblings) plus the set metadata.
//!   scan-witness --rpc <url> --token <hex20> --from <block> --to <block>
//!             [--execute-only]
//!       Stage B.2: rebuild the receipts tries for a block range (self-
//!       verified against each header's receiptsRoot), then run the
//!       receipt-scan program to produce the completeness commitment.
//!   prove     --policy <hex32> --agent <url>
//!             --verifier <hex20> --beneficiary <hex20> --deadline <block>
//!             --config-hash <hex32> [--action <hex32>] [--nonce <n>]
//!             [--verifier-chain-id <n>]
//!             [--min-streak <n>] [--chain-id <n>] [--execute-only]
//!       Build the witness and run the SP1 membership program: with
//!       --execute-only (default when no proving stack) emulate and print the
//!       public values; otherwise generate a Groth16 proof for
//!       SolventSetOracle.verifyMembership.
//!
//!       The verifier/beneficiary/deadline/config-hash group is the
//!       *presentation context* and is mandatory: without it the resulting
//!       proof is a bearer token that anyone can replay or front-run.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;
use zk_pof_agent::enrollment::parse_policy_id;
use zk_pof_agent::membership_prover;
use zk_pof_common::membership::{MembershipWitness, PresentationContext};
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

fn parse_hex20(value: &str, what: &str) -> Result<[u8; 20]> {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(clean).with_context(|| format!("Invalid hex in {what}"))?;
    if bytes.len() != 20 {
        bail!("Invalid {what} length: expected 20 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Read the secret key without ever accepting it on the command line.
///
/// A key passed as `--sk <hex>` leaks into shell history, `ps` output,
/// terminal scrollback, screen shares, and crash reports — the external
/// review flagged this, and ERC-7524 itself says pasting a private key into
/// a prover should not be normal user behaviour. So argv is refused outright
/// and the key comes from a hidden TTY prompt, stdin, or an env var, held in
/// a `Zeroizing` buffer that is wiped on drop.
fn read_secret_key(args: &[String]) -> Result<Zeroizing<[u8; 32]>> {
    if has_flag(args, "--sk") {
        bail!(
            "Refusing to read a secret key from the command line: it would leak \
             into shell history and process listings.\n\
             Use one of:\n  \
             --sk-stdin           (pipe or type the hex key on stdin)\n  \
             --sk-env ZKPOF_SK    (read from the named environment variable)\n  \
             (no flag)            (interactive hidden prompt)"
        );
    }

    let raw: Zeroizing<String> = if has_flag(args, "--sk-stdin") {
        let mut buf = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)
            .context("Failed to read the secret key from stdin")?;
        Zeroizing::new(buf)
    } else if let Some(var) = arg_value(args, "--sk-env") {
        Zeroizing::new(
            std::env::var(&var)
                .with_context(|| format!("Environment variable {var} is not set"))?,
        )
    } else {
        Zeroizing::new(
            rpassword::prompt_password("Secret key (hex, input hidden): ")
                .context("Failed to read the secret key from the terminal")?,
        )
    };

    Ok(Zeroizing::new(parse_hex32(raw.trim(), "secret key")?))
}

struct Common {
    sk: Zeroizing<[u8; 32]>,
    policy_id: [u8; 32],
    policy_hex: String,
    /// Scope the nullifier binds to — the policy default unless `--scope`
    /// selects a shared one.
    scope_hash: [u8; 32],
}

fn common_args(args: &[String]) -> Result<Common> {
    let sk = read_secret_key(args)?;
    let policy_arg = arg_value(args, "--policy").context("--policy <hex32> is required")?;
    let policy_id = parse_policy_id(&policy_arg)?;
    let scope_hash = match arg_value(args, "--scope") {
        Some(scope) => parse_hex32(&scope, "--scope")?,
        None => plume::default_scope_hash(&policy_id),
    };
    Ok(Common {
        sk,
        policy_id,
        policy_hex: hex::encode(policy_id),
        scope_hash,
    })
}

/// Parse the presentation context a membership proof is bound to.
///
/// These are not optional in production: a proof without them is a bearer
/// token any observer can replay or front-run (review finding R5). The
/// relying application supplies these values in its proof request.
fn presentation_context(args: &[String]) -> Result<PresentationContext> {
    let verifier = match arg_value(args, "--verifier") {
        Some(v) => parse_hex20(&v, "--verifier")?,
        None => bail!(
            "--verifier <hex20> is required: a proof must name the contract it \
             may be submitted to, or it can be replayed elsewhere"
        ),
    };
    let beneficiary = match arg_value(args, "--beneficiary") {
        Some(v) => parse_hex20(&v, "--beneficiary")?,
        None => bail!(
            "--beneficiary <hex20> is required: a proof must name who may \
             consume it, or it can be front-run out of the mempool"
        ),
    };
    let deadline: u64 = match arg_value(args, "--deadline") {
        Some(v) => v.parse().context("--deadline must be a block number")?,
        None => bail!("--deadline <block> is required: proofs must expire"),
    };
    Ok(PresentationContext {
        policy_config_hash: match arg_value(args, "--config-hash") {
            Some(v) => parse_hex32(&v, "--config-hash")?,
            None => bail!("--config-hash <hex32> is required (read it from the oracle)"),
        },
        verifier,
        verifier_chain_id: arg_value(args, "--verifier-chain-id")
            .map(|v| v.parse())
            .transpose()
            .context("--verifier-chain-id must be a number")?
            .unwrap_or(1),
        action_id: match arg_value(args, "--action") {
            Some(v) => parse_hex32(&v, "--action")?,
            None => [0u8; 32],
        },
        beneficiary,
        nonce: arg_value(args, "--nonce")
            .map(|v| v.parse())
            .transpose()
            .context("--nonce must be a number")?
            .unwrap_or(0),
        deadline,
    })
}

/// The JSON body for POST /v2/enroll.
fn enrollment_body(common: &Common) -> Result<serde_json::Value> {
    let public_key = plume::derive_public_key(&common.sk)?;
    let (nullifier, proof) = plume::prove_nullifier(&common.sk, &common.scope_hash)?;
    let member_id = plume::nullifier_hash(&nullifier);
    Ok(serde_json::json!({
        "policy_id": common.policy_hex,
        "scope_hash": hex::encode(common.scope_hash),
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
        sk: *common.sk,
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

            let context = presentation_context(&args)?;
            let (witness, meta) = build_witness(&agent, &common).await?;
            let epoch = meta["epoch"].as_u64().unwrap();
            let root_hex = meta["root"].as_str().unwrap_or_default();
            let root = parse_hex32(root_hex, "solvent set root")?;

            let elf = membership_prover::load_membership_elf()?;
            if has_flag(&args, "--execute-only") {
                let public_values = membership_prover::execute_membership_program(
                    elf, &witness, &root, &common.policy_id, epoch, chain_id, min_streak,
                    &common.scope_hash, &context,
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
                    &common.scope_hash, &context,
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
        "scan-witness" => {
            let rpc_url = arg_value(&args, "--rpc").context("--rpc <url> is required")?;
            let token_hex = arg_value(&args, "--token").context("--token <hex20> is required")?;
            let from_block: u64 = arg_value(&args, "--from")
                .context("--from <block> is required")?
                .parse()
                .context("Invalid --from")?;
            let to_block: u64 = arg_value(&args, "--to")
                .context("--to <block> is required")?
                .parse()
                .context("Invalid --to")?;

            let clean = token_hex.strip_prefix("0x").unwrap_or(&token_hex);
            let token_bytes = hex::decode(clean).context("Invalid --token hex")?;
            if token_bytes.len() != 20 {
                bail!("--token must be 20 bytes");
            }
            let mut token = [0u8; 20];
            token.copy_from_slice(&token_bytes);

            let rpc = zk_pof_agent::rpc_fetcher::RpcFetcher::new(&rpc_url)?;
            // Each block is self-verified: header hash and receipts root must
            // reproduce, so a bad reconstruction fails here, not in the prover.
            let witness =
                zk_pof_agent::scan_witness::build_scan_witness(&rpc, from_block, to_block).await?;

            let elf = zk_pof_agent::scan_prover::load_scan_elf()?;
            let public_values = if has_flag(&args, "--execute-only") {
                zk_pof_agent::scan_prover::execute_scan_program(elf, &witness, &token)?
            } else {
                let (proof_bytes, pv) =
                    zk_pof_agent::scan_prover::prove_scan(elf, &witness, &token)?;
                println!("proof_bytes: {}", hex::encode(proof_bytes));
                pv
            };

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "blocks": witness.headers.len(),
                    "token": hex::encode(public_values.token),
                    "end_block_hash": hex::encode(public_values.end_block_hash),
                    "participants_root": hex::encode(public_values.participants_root),
                    "participant_count": public_values.participant_count,
                    "public_values_abi": hex::encode(public_values.abi_encode()),
                }))?
            );
        }
        other => bail!(
            "Unknown command: {other} (expected nullifier|enroll|witness|prove|scan-witness)"
        ),
    }
    Ok(())
}
