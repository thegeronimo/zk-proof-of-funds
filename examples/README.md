# Integration Examples

This directory contains complete integration examples showing how to use the ZK Proof of Funds solvency system in different contexts.

## Which model should I integrate against?

There are two, and they present the **same identity** to your contract — a
32-byte value you can key storage by — so you can support either without
changing your accounting.

| | Monitored mode (V1) | Solvent-set mode (V2) |
|---|---|---|
| Interface | `ISolvencyOracle` | `ISolventSetOracle` |
| User setup | enrolls once with the agent | none — no enrollment at all |
| Agent knows the user's address | yes | no |
| What your contract receives | a `memberId` the caller already knew | a nullifier hash *returned* by the proof |
| Verification cost | ~8k gas (Merkle proof) | SP1 Groth16 verification (~270k) |
| Time dimension | none | proven streak of consecutive solvent epochs |
| Anonymity set | enrolled members | every solvent address on the chain |

Choose V1 when gas dominates and enrollment is acceptable. Choose V2 when
users must not reveal which address they hold funds in, or when you need
"solvent for >= k epochs" rather than a single snapshot.

## Solidity Contracts

### Monitored mode — the `ISolvencyOracle` pattern

### `contracts/SolvencyGatedPool.sol`
A DeFi lending pool that requires solvency proof for deposits. Only users who prove they hold >= threshold balance can deposit collateral, reducing counterparty risk.

**Key pattern**: Gate `deposit()` behind `oracle.isMemberSolvent()`.

### `contracts/SolvencyGatedGovernor.sol`
A DAO governance contract requiring solvency for voting. Ensures voters have "skin in the game" by verifying their financial backing before counting votes.

**Key pattern**: Gate `vote()` behind `oracle.isMemberSolvent()` with duplicate-vote prevention.

### `contracts/SolvencyGatedNFT.sol`
An NFT collection using solvency proofs as an allowlist mechanism. Replaces traditional whitelists with financial proof of stake.

**Key pattern**: Gate `mint()` behind `oracle.isMemberSolvent()` with one-mint-per-member enforcement.

### Solvent-set mode — the `ISolventSetOracle` pattern

#### `contracts/SolventSetGatedAirdrop.sol`
A one-claim-per-person airdrop for wallets that have *continuously* held above
a threshold, where no one learns which wallets claimed. The claimant never
enrolled and never revealed an address; the contract learns only a nullifier
hash.

**Key pattern**: call `oracle.verifyAndConsume()`, then check the returned
`minStreak` against your own requirement — the oracle enforces that the proof
attests to *some* minimum, but it cannot know yours. Note also that the payout
`recipient` is an ordinary argument unrelated to the proven identity: tying it
to the proving address would undo the unlinkability the proof just bought.

## TypeScript Integration Scripts

### `lending-pool-integration.ts`
Monitored mode, full flow: enrollment, status check, and deposit with proof.

### `governance-voting.ts`
Monitored mode voting: check eligibility, fetch proof, submit vote.

### `nft-gated-mint.ts`
Monitored mode mint: eligibility check, fetch proof, mint NFT.

### `solvent-set-airdrop.ts`
Solvent-set mode, full flow: download and locally re-verify the set, find
yourself in it client-side, decode and cross-check the proof's public values,
then claim. Shows the `zkpof-client` handoff — proof generation is native
because SP1 cannot prove in JavaScript and the nullifier needs raw key access.

## How to Run

### Prerequisites
1. Start the Solvency Agent backend:
   ```bash
   cd .. && cargo run -p zk-pof-backend
   ```

2. The agent will be available at `http://localhost:3000`.

### Running TypeScript examples
```bash
# Install the SDK (from workspace root)
cd ../sdk && npm install && npm run build

# Run an example
npx tsx lending-pool-integration.ts
npx tsx governance-voting.ts
npx tsx nft-gated-mint.ts
```

### Deploying example contracts
The Solidity contracts can be deployed using Foundry:

```bash
cd ../contracts
forge create examples/contracts/SolvencyGatedPool.sol:SolvencyGatedPool \
  --constructor-args $ORACLE_ADDRESS $POLICY_ID \
  --private-key $DEPLOYER_KEY
```

## Integration Pattern

### Monitored mode (V1)

The three `SolvencyGated*` examples follow this pattern:

```
                    +-----------+
                    |   User    |
                    +-----+-----+
                          |
            1. Sign enrollment message
                          |
                    +-----v-----+
                    |  Frontend  |  (React app or custom UI)
                    |   + SDK    |
                    +-----+-----+
                          |
            2. POST /enroll  |  3. GET /proof/{policyId}/{memberId}
                          |
                    +-----v-----+
                    |  Solvency  |  (Rust backend)
                    |   Agent    |
                    +-----+-----+
                          |
            4. Monitors balances, publishes Merkle roots
                          |
                    +-----v-----+
                    | On-Chain   |  (SolvencyRootOracle)
                    | Oracle     |
                    +-----+-----+
                          |
            5. dApp calls oracle.isMemberSolvent()
                          |
                    +-----v-----+
                    | Your dApp  |  (SolvencyGatedPool, Governor, NFT, etc.)
                    +-----------+
```

### Solvent-set mode (V2)

`SolventSetGatedAirdrop` inverts who does the work — note that nothing flows
from the user to the agent:

```
                    +-----------+
                    |   User    |
                    +-----+-----+
                          |
            1. GET /v2/solvent_set/{policyId}/leaves   (downloads ALL of it)
                          |
                    +-----v-----+
                    |  Solvency  |  sees only "someone fetched the set"
                    |   Agent    |  — never a query about an address
                    +-----+-----+
                          |
            2. Rebuild root + locate self, entirely client-side
                          |
                    +-----v------+
                    | zkpof-client|  (native; SP1 cannot prove in a browser,
                    |  prove      |   and the nullifier needs the raw key)
                    +-----+------+
                          |
            3. (proofBytes, publicValues) — no address, no enrollment
                          |
                    +-----v-----+
                    | Your dApp  |  oracle.verifyAndConsume(...)
                    +-----+-----+
                          |
            4. Returns nullifierHash + minStreak; you check minStreak >= k
                          |
                    +-----v-----+
                    | On-Chain   |  (SolventSetOracle)
                    | Oracle     |
                    +-----------+
```

## Gas Costs

| Operation | Gas Cost |
|-----------|----------|
| `updateRootTrusted()` | ~100k |
| `verifyMember()` | ~8k |
| `isMemberSolvent()` | ~9k |
| Deposit with proof | ~30k + proof verification |
| `publishRoot()` (Stage A) | ~114k (measured, median) |
| `verifyMembership()` contract logic | ~37k (measured, median) |
| `verifyAndConsume()` contract logic | ~88k (measured, median) |
| SP1 Groth16 verification | ~270k |

> The measured V2 figures come from `forge test --gas-report`, which uses
> `MockSP1Verifier` — they are the oracle's own logic and **exclude** proof
> verification. Add the ~270k Groth16 cost for a real end-to-end call.

The V2 verification cost is the price of the privacy and the streak guarantee:
a full Groth16 verification rather than a Merkle path walk. It is constant
regardless of set size.
| Vote with proof | ~50k + proof verification |
| Mint with proof | ~80k + proof verification |

The proof verification cost scales logarithmically: ~84 gas per tree level.
For a 1000-member tree (depth 10), verification adds ~840 gas.
