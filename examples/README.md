# Integration Examples

This directory contains complete integration examples showing how to use the ZK Proof of Funds solvency system in different contexts.

## Solidity Contracts

Example contracts demonstrating the `ISolvencyOracle` integration pattern:

### `contracts/SolvencyGatedPool.sol`
A DeFi lending pool that requires solvency proof for deposits. Only users who prove they hold >= threshold balance can deposit collateral, reducing counterparty risk.

**Key pattern**: Gate `deposit()` behind `oracle.isMemberSolvent()`.

### `contracts/SolvencyGatedGovernor.sol`
A DAO governance contract requiring solvency for voting. Ensures voters have "skin in the game" by verifying their financial backing before counting votes.

**Key pattern**: Gate `vote()` behind `oracle.isMemberSolvent()` with duplicate-vote prevention.

### `contracts/SolvencyGatedNFT.sol`
An NFT collection using solvency proofs as an allowlist mechanism. Replaces traditional whitelists with financial proof of stake.

**Key pattern**: Gate `mint()` behind `oracle.isMemberSolvent()` with one-mint-per-member enforcement.

## TypeScript Integration Scripts

### `lending-pool-integration.ts`
Full flow: enrollment, status check, and deposit with proof.

### `governance-voting.ts`
Voting flow: check eligibility, fetch proof, submit vote.

### `nft-gated-mint.ts`
Mint flow: eligibility check, fetch proof, mint NFT.

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

All examples follow the same pattern:

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

## Gas Costs

| Operation | Gas Cost |
|-----------|----------|
| `updateRootTrusted()` | ~100k |
| `verifyMember()` | ~8k |
| `isMemberSolvent()` | ~9k |
| Deposit with proof | ~30k + proof verification |
| Vote with proof | ~50k + proof verification |
| Mint with proof | ~80k + proof verification |

The proof verification cost scales logarithmically: ~84 gas per tree level.
For a 1000-member tree (depth 10), verification adds ~840 gas.
