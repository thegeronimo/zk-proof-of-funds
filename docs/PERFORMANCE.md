# Performance: sizes, proving cost, and scaling

What each step of the Privacy V2 flow costs, and how it grows.

> **These timings are estimates, not measurements.** Sizes below are exact:
> they follow from the data formats. Cycle counts and times are
> back-of-envelope figures and have not been benchmarked. Replace them with
> measured values (see [How to measure](#how-to-measure)) before quoting them
> anywhere.

Two facts shape every number here:

- The SP1 guest programs do not use SP1's accelerated (patched) crypto crates,
  so secp256k1, SHA-256 and Keccak run as plain RISC-V instructions.
- Every proof that reaches the chain is Groth16-wrapped. The wrapped proof is
  about 260 bytes and costs about 270k gas to verify however much work it
  covers, so cost differences are all in *generation*.

## Summary

| # | Step | Who | Input | Work done | Output size | Rough time or cost |
|---|---|---|---|---|---|---|
| 1 | Fetch balances | Operator | One `eth_getProof` call per candidate | Plain RPC, no proving | ~4 KB per candidate; ~1.2 GB at 300k | RPC-bound: minutes to hours |
| 2 | Derivation proof | Operator | Every candidate's state proof, plus the whole previous set | ~8 trie nodes hashed per candidate, then the set tree rebuilt | ~260 B proof + 448 B public values | Seconds to minutes at 100 candidates; cluster-hours at 300k |
| 3 | Scan proof (optional) | Operator | Every receipt of every block in the range | Rebuilds each block's receipts trie | ~260 B proof + 224 B public values | Heaviest step; grows with block count |
| 4 | Publish root | Operator, or anyone holding a valid proof | Proof, public values, ~600 B block header | One Groth16 check on-chain | One root per epoch | ~270k gas plus storage |
| 5 | Download set | User | Paged API, at most 10,000 entries per request | None | 24 B per address | Seconds |
| 6 | Build witness | User | The full set | About 2 hashes per address, outside the proof | ~19 to 21 sibling hashes, ~0.7 KB | About a second |
| 7 | Membership proof | User | Secret key, streak, Merkle path | 2 curve multiplications, 1 hash-to-curve, 1 Keccak, ~21 SHA-256 | ~260 B proof + 448 B public values | Minutes on a desktop CPU; not feasible on a phone today |
| 8 | Verify and consume | Relying protocol | ~0.7 KB of calldata | One Groth16 check on-chain, nullifier lookup | One nullifier marked used | ~270k gas plus storage |

## Candidates versus the solvent set

Derivation cost scales with the number of **candidates** (addresses checked),
not with the size of the **solvent set** (addresses that qualified), and not
with the number of users. A candidate that fails the threshold still costs a
full state-proof verification inside the proof. See
[PRIVACY_V2.md §4.4](../PRIVACY_V2.md) for the worked example.

## The set download (steps 5 and 6)

Each entry is a 20-byte address plus a 4-byte streak:

```
entry size = 20 B + 4 B = 24 B
raw size   = entries x 24 B
```

| Policy | Approximate entries | Raw size | API requests (10,000 per page) |
|---|---|---|---|
| At least 10 ETH | ~300,000 (rough; no current figure found) | 300,000 x 24 B = 7.2 MB | 30 |
| At least 1 ETH | ~1,300,000 (Etherscan, early 2025, via Cointelegraph) | 1,300,000 x 24 B = 31.2 MB | 130 |

The API returns JSON, so the bytes on the wire are several times the raw size.

To build the Merkle path the client hashes the whole set once: one hash per
leaf plus one per internal node, about `2 x entries` SHA-256 calls. That is
around a second even at 1.3 million entries.

## The membership proof (step 7)

### Why it takes minutes

The statement is small. The time comes from the proving pipeline:

1. **Curve arithmetic as CPU instructions.** Deriving the public key and the
   nullifier each need a secp256k1 scalar multiplication. Unaccelerated, each
   is millions of RISC-V instructions. Estimated total for the program: on the
   order of 10 million cycles.
2. **Three proving stages.** A STARK proof of the execution, a recursive
   compression to constant size, then a wrap to Groth16. The last two cost
   roughly the same however small the program is. One
   [independent benchmark](https://nomos-tech.notion.site/Preliminary-Research-ZKVM-s-for-CL-Design-1fd261aa09df819d9fdad4662e481c67)
   measured the wrap alone at about 94 seconds on CPU.
3. **CPU-only client.** `membership_prover.rs` builds the prover with the CPU
   backend.

### Why not on a phone

- The Groth16 wrap needs about 16 GB of RAM and an ~8 GB circuit artifact.
- The wrap runs through Succinct's `sp1-gnark` Docker image, which is
  published for amd64 only (also the reason it cannot run on Apple Silicon;
  see [STATUS.md](../STATUS.md)).
- The proof needs the raw secret key, which browser and mobile wallets do not
  expose. `zkpof-client` is the only supported path today.

### How it scales with the set size

Inside the proof, only the Merkle path depends on the set: one SHA-256 per
tree level, and

```
levels = ceil(log2(entries))
```

| Entries | Levels = hashes in the proof |
|---|---|
| 1,000 | 10 |
| 300,000 | 19 |
| 1,300,000 | 21 |
| 100,000,000 | 27 |

Growing the set from 300,000 to 100 million adds 8 hashes. At an estimated
15,000 cycles per unaccelerated SHA-256, the whole 21-level path is

```
21 x 15,000 = 315,000 cycles, about 3% of ~10,000,000
```

and it adds nothing to the two fixed stages. Proving time is effectively flat
in the set size. A bigger set buys a bigger anonymity set at almost no proving
cost; the price is bandwidth (step 5).

## The derivation proof (steps 1 and 2)

Cost is linear in the candidate count. Each candidate needs a Merkle-Patricia
proof of about 8 nodes verified inside the proof (an account proof for native
ETH, a storage proof for ERC-20), and the previous set is re-hashed to chain
streaks.

At mainnet scale this does not fit the sample policies:

| Quantity | At 300,000 candidates |
|---|---|
| RPC calls per epoch | 300,000 |
| Witness size | 300,000 x ~4 KB = ~1.2 GB |
| Proving work | Estimated hundreds of billions of cycles: hours on a GPU cluster or prover network |
| Epoch length in `config/policies.json` | 100 blocks, about 20 minutes |

The native-ETH path takes candidates from a configured list, not the whole
chain, so real deployments would be far smaller. The only derivation proof
generated so far (`zkpof-e2e derivation-compressed`) covered one candidate.

## The scan proof (step 3)

The receipt scan re-hashes every receipt of every block in its range. For the
completeness claim to mean anything, the range must start at the token's
deployment or at a checkpoint whose set is itself proven. For a long-lived
token that is years of blocks, so the scan is only workable incrementally from
checkpoints.

## What would bring the numbers down

- **Accelerated crypto.** Patching in SP1's precompiled secp256k1, SHA-256 and
  Keccak would cut cycle counts for every program. The fixed recursion and
  wrap stages remain.
- **Delegated proving.** Fast, but the prover sees the user's secret key.
- **A purpose-built membership circuit.** Phase 17 (gate G1 in
  [EXECUTION_PLAN.md](../EXECUTION_PLAN.md)): a Noir/Barretenberg circuit with
  a target of under ~30 s on a current phone. In such a circuit the SHA-256
  path becomes a larger share of the cost, hence the Poseidon-tree question.
- **Direct state proofs.** Phase 18 (gate G2): prove one EIP-1186 path per
  user and drop the global set, trading operator cost for user cost.

## How to measure

Each host-side prover logs `total_cycles` when it executes a guest program
(`membership_prover.rs`, `derivation_prover.rs`, `scan_prover.rs`). To replace
the estimates above:

```bash
# Build the guests (needs the SP1 toolchain)
cd program-membership && cargo prove build && cd ..
cd program-solvent-set && cargo prove build && cd ..

# Membership: emulate only, prints the cycle count and public values
cargo run --release --bin zkpof-client -- prove --execute-only \
  --policy <hex32> --agent <url> --verifier <hex20> \
  --beneficiary <hex20> --deadline <block> --config-hash <hex32>

# Derivation: a real compressed proof for one candidate
cargo run --release --bin zkpof-e2e -- derivation-compressed
```

Record wall-clock time, peak memory and cycle count per stage, on named
hardware, and update the tables here.
