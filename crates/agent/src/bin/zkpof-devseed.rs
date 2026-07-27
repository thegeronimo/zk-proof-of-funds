//! zkpof-devseed — populate a development database with a solvent set.
//!
//! Building a set normally needs an RPC endpoint to read balances. That makes
//! the client-side flow (download → rebuild → locate → prove) impossible to
//! exercise offline, so this seeds the same tables from synthetic balances via
//! [`SolventSetService::build_from_balances`] — the identical code path the
//! agent uses after fetching, minus the network.
//!
//! Development only: the resulting root reflects invented balances and must
//! never be published on-chain.
//!
//! ```text
//! zkpof-devseed --db solvency_agent.db --policy <hex32>
//!               [--epochs 3] [--members 32] [--include <hex20>]...
//! ```
//!
//! `--include` adds an address to every epoch (so its streak grows to
//! `--epochs`), which is how you make your own key a member of the seeded set.

use anyhow::{bail, Context, Result};
use zk_pof_agent::db::Database;
use zk_pof_agent::enrollment::parse_policy_id;
use zk_pof_agent::solvent_set_service::SolventSetService;

const ONE_ETH: u128 = 1_000_000_000_000_000_000;

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn arg_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == flag)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn parse_address(value: &str) -> Result<String> {
    let clean = value.strip_prefix("0x").unwrap_or(value).to_lowercase();
    let bytes = hex::decode(&clean).context("Invalid address hex")?;
    if bytes.len() != 20 {
        bail!("Invalid address length: expected 20 bytes, got {}", bytes.len());
    }
    Ok(clean)
}

/// A deterministic filler address, so repeated seeds produce the same set.
fn filler_address(index: usize) -> String {
    let mut bytes = [0u8; 20];
    bytes[0] = 0xde;
    bytes[1] = 0xad;
    bytes[18] = (index >> 8) as u8;
    bytes[19] = index as u8;
    hex::encode(bytes)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: zkpof-devseed --policy <hex32> [--db <path>] [--epochs <n>] \\\n\
             \x20                    [--members <n>] [--include <hex20>]...\n\n\
             Seeds a development solvent set from synthetic balances. Dev only."
        );
        return Ok(());
    }

    let db_path = arg_value(&args, "--db").unwrap_or_else(|| "solvency_agent.db".to_string());
    let policy_hex = arg_value(&args, "--policy").context("--policy <hex32> is required")?;
    let policy_id = parse_policy_id(&policy_hex).context("Invalid --policy")?;
    let policy_hex = hex::encode(policy_id);

    let epochs: u64 = arg_value(&args, "--epochs")
        .map(|v| v.parse())
        .transpose()
        .context("Invalid --epochs")?
        .unwrap_or(3);
    let members: usize = arg_value(&args, "--members")
        .map(|v| v.parse())
        .transpose()
        .context("Invalid --members")?
        .unwrap_or(32);
    if epochs == 0 {
        bail!("--epochs must be at least 1");
    }

    let included: Vec<String> = arg_values(&args, "--include")
        .iter()
        .map(|a| parse_address(a))
        .collect::<Result<_>>()?;

    let db = Database::open(&db_path).context("Failed to open the database")?;
    let service = SolventSetService::new(&db);

    // Each epoch rotates a few filler addresses in and out so streaks vary,
    // which is what makes the min-streak gate visible in the UI. Addresses
    // passed with --include are present in every epoch.
    for epoch in 1..=epochs {
        let mut balances: Vec<(String, u128)> = Vec::new();
        for address in &included {
            balances.push((address.clone(), 50 * ONE_ETH));
        }
        for i in 0..members {
            // A member drops out for one epoch every (i % epochs) rotation,
            // producing a spread of streaks rather than a uniform block.
            let skips = epochs.max(2);
            if (i as u64 % skips) == (epoch % skips) {
                continue;
            }
            balances.push((filler_address(i), (2 + (i as u128 % 20)) * ONE_ETH));
        }

        let block_number = 19_000_000 + epoch * 100;
        let result = service
            .build_from_balances(&policy_hex, epoch, block_number, ONE_ETH, &balances)
            .with_context(|| format!("Failed to build epoch {epoch}"))?;

        println!(
            "epoch {} → {} members, block {}, root 0x{}",
            result.epoch,
            result.member_count,
            result.block_number,
            hex::encode(result.root)
        );
    }

    println!("\nSeeded '{db_path}' for policy 0x{policy_hex}.");
    if !included.is_empty() {
        println!(
            "Included addresses have a streak of {epochs} in the latest epoch: {}",
            included.iter().map(|a| format!("0x{a}")).collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}
