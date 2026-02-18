# ZK Proof of Funds — User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [System Overview](#system-overview)
3. [Actors & Roles](#actors--roles)
4. [Prerequisites](#prerequisites)
5. [Running Locally](#running-locally)
6. [Actor Guides](#actor-guides)
   - [Operator Guide](#operator-guide)
   - [Member / User Guide](#member--user-guide)
   - [Integrator Guide](#integrator-guide)
7. [Deploying to Testnet (Sepolia)](#deploying-to-testnet-sepolia)
8. [Deploying to Mainnet](#deploying-to-mainnet)
9. [API Reference](#api-reference)
10. [Troubleshooting](#troubleshooting)

---

## Introduction

**ZK Proof of Funds** is a privacy-preserving solvency attestation system for EVM chains. It allows users to prove they hold a minimum balance without ever revealing their wallet address to on-chain observers or to the protocols they interact with.

**What it solves**: DeFi protocols that need to verify "does this user have >= X ETH?" face a dilemma — on-chain balance checks are public, gas-expensive, and require the user to reveal their identity. ZK Proof of Funds lets users enroll once, after which an agent continuously monitors their balance and publishes Merkle roots that any smart contract can verify cheaply (~10k gas).

**Key properties**:
- **Privacy**: A `memberId` is computed as `SHA256(signature)` — unlinkable to the wallet address
- **Non-custodial**: The agent only reads balances via RPC, never holds funds
- **Cheap verification**: ~10k gas per on-chain proof check (log₂(N) SHA-256 hashes)
- **Batch efficiency**: One on-chain transaction covers all members for a given epoch

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   OPERATOR sets up the Solvency Agent and creates policies          │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │           Solvency Agent (Rust backend)                  │      │
│   │  • REST API (enroll, proof, status, admin)               │      │
│   │  • Scheduler: triggers epoch updates periodically        │      │
│   │  • RPC Fetcher: reads balances from Ethereum node        │      │
│   │  • Merkle Service: builds trees, serves proofs           │      │
│   │  • Chain Publisher: submits Merkle roots on-chain        │      │
│   └────────────────────────────┬────────────────────────────┘      │
│                                │                                    │
│          ┌──────────────────── ┼ ──────────────────┐               │
│          ▼                     ▼                    ▼               │
│   MEMBERS enroll       On-chain Merkle roots   INTEGRATORS         │
│   via frontend         published each epoch    call oracle          │
│   (React app + SDK)                            in their dApps       │
│          │             ┌────────────────────┐       │              │
│          │             │ SolvencyRootOracle  │       │              │
│          └────────────►│ PolicyRegistry      │◄──────┘              │
│                        └────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────┘
```

### How an Epoch Works

1. **Epoch triggers** — The scheduler detects that `current_block >= last_epoch_block + epoch_length`
2. **Balance fetch** — The agent calls `eth_getBalance` (trusted mode) or `eth_getProof` (ZK mode) for each enrolled member
3. **Merkle tree** — A SHA-256 binary tree is built from all member statuses. Each leaf encodes `memberId || status || epoch || policyId`
4. **Root publication** — The agent submits `updateRootTrusted()` (trusted mode) or `updateRoot()` (ZK mode) to the oracle contract
5. **Proof serving** — Members can now fetch their Merkle proof from `GET /proof/{policyId}/{memberId}`
6. **On-chain verification** — dApps call `oracle.isMemberSolvent()` with the proof before granting access

---

## Actors & Roles

There are three distinct actors in the system:

### Operator
**Who**: A team or individual who runs the Solvency Agent infrastructure.

**Responsibilities**:
- Deploys the smart contracts (`PolicyRegistry`, `SolvencyRootOracle`)
- Runs the Solvency Agent backend
- Creates and manages policies (defining threshold, epoch length, TTL, etc.)
- Holds the `operator` private key used to sign root updates (trusted mode)
- Monitors the agent for health and publishes epoch roots

**Trust model**: In **trusted mode**, members and integrators trust the operator to run the agent honestly. In **ZK mode** (Phase 2), the SP1 proof removes this trust requirement — the contract cryptographically verifies the Merkle root.

---

### Member / User
**Who**: End users who want to prove they hold a minimum balance to access a gated dApp.

**Responsibilities**:
- Connects their wallet and signs an enrollment message (one-time, per policy)
- Keeps their enrolled wallet funded above the policy threshold
- Fetches Merkle proofs when submitting transactions to gated dApps

**Privacy properties**:
- The agent learns the wallet address (watch target) but this is never exposed on-chain or via the public API
- All on-chain interactions use the privacy-preserving `memberId` (`SHA256(signature)`)
- A member's wallet is unlinkable to their `memberId` by any party that only sees on-chain data

---

### Integrator
**Who**: A developer or team building a dApp that wants to gate access behind solvency checks.

**Responsibilities**:
- Imports the `ISolvencyOracle` interface into their Solidity contracts
- Calls `oracle.isMemberSolvent()` before granting privileged access
- Uses the TypeScript SDK to fetch proofs from the agent for their users
- Decides which policy (and therefore which threshold and operator) to trust

---

## Prerequisites

### For all users

| Tool | Version | Install |
|------|---------|---------|
| Git | Any | [git-scm.com](https://git-scm.com) |

### For Operators

| Tool | Version | Install |
|------|---------|---------|
| Rust + Cargo | 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Foundry (forge, cast) | Latest | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| An Ethereum RPC endpoint | — | [Alchemy](https://alchemy.com), [Infura](https://infura.io), or local node |
| An Ethereum wallet (operator key) | — | Generate with `cast wallet new` |

### For Members / Users

| Tool | Version | Install |
|------|---------|---------|
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| npm | 9+ | (bundled with Node.js) |
| A browser wallet | — | MetaMask, Rabby, Frame, etc. |

### For Integrators

| Tool | Version | Install |
|------|---------|---------|
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| npm | 9+ | (bundled with Node.js) |
| Foundry (for Solidity) | Latest | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |

---

## Running Locally

This section walks through running the entire system on your local machine using [Anvil](https://book.getfoundry.sh/anvil/) as a local Ethereum node.

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-org/zk-proof-of-funds.git
cd zk-proof-of-funds
```

### Step 2 — Start a local Ethereum node

Open a terminal and start Anvil:

```bash
anvil
```

Anvil prints 10 pre-funded accounts. Note the first account's address and private key — you'll use these as the **deployer** and **operator**:

```
Available Accounts
==================
(0) 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (10000 ETH)
(1) 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (10000 ETH)
...

Private Keys
==================
(0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
(1) 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
```

Keep this terminal open.

### Step 3 — Deploy the contracts

Open a second terminal:

```bash
cd contracts

# Install Foundry dependencies
forge install

# Deploy to local Anvil
DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast
```

The script will output the deployed addresses:

```
PolicyRegistry deployed at: 0x5FbDB2315678afecb367f032d93F642f64180aa3
SolvencyRootOracle deployed at: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
```

Copy these addresses — you'll need them in the next steps.

### Step 4 — Create a policy

Use `cast` to create a policy on-chain. This defines the rules for solvency verification:

```bash
# Policy parameters:
# - threshold: 1 ETH (1000000000000000000 wei)
# - token: native ETH (address(0))
# - chainId: 31337 (Anvil)
# - epochLengthBlocks: 10
# - maxBlockAge: 200
# - rootTTLBlocks: 1000
# - operator: account #0
# - scope: "local-test"
# - trustedMode: true

POLICY_REGISTRY=0x5FbDB2315678afecb367f032d93F642f64180aa3
OPERATOR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
POLICY_ID=0x0101010101010101010101010101010101010101010101010101010101010101

cast send $POLICY_REGISTRY \
  "createPolicy(bytes32,(uint256,address,uint64,uint64,uint64,uint64,address,string,bool,bool))" \
  $POLICY_ID \
  "(1000000000000000000,0x0000000000000000000000000000000000000000,31337,10,200,1000,$OPERATOR,local-test,true,true)" \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --rpc-url http://127.0.0.1:8545
```

### Step 5 — Start the Solvency Agent backend

Open a third terminal:

```bash
# Create a .env file
cat > .env.local << 'EOF'
RPC_URL=http://127.0.0.1:8545
CHAIN_ID=31337
OPERATOR_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ORACLE_ADDRESS=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
DATABASE_PATH=/tmp/solvency_local.db
BIND_ADDR=0.0.0.0:3000
POLL_INTERVAL_SECS=12
EOF

# Load env vars and start the backend
set -a && source .env.local && set +a
cargo run -p zk-pof-backend
```

Expected output:

```
INFO starting Solvency Agent API server
INFO database opened  db_path=/tmp/solvency_local.db
INFO listening       bind=0.0.0.0:3000
```

Verify it's healthy:

```bash
curl http://localhost:3000/health
# → {"status":"ok","version":"0.1.0"}
```

### Step 6 — Start the React frontend

Open a fourth terminal:

```bash
cd web

# Install dependencies
npm install

# Create local environment file
cat > .env.local << 'EOF'
VITE_AGENT_URL=http://localhost:3000
VITE_CHAIN_ID=31337
EOF

# Start the development server
npm run dev
```

The app is now running at **http://localhost:5173**.

### Step 7 — Verify everything works

```bash
# Check health
curl -s http://localhost:3000/health | jq .

# List members for the policy (empty to start)
curl -s http://localhost:3000/admin/members/0x0101010101010101010101010101010101010101010101010101010101010101 | jq .
```

You now have the full local stack running:
- **Anvil** at `http://localhost:8545`
- **Solvency Agent API** at `http://localhost:3000`
- **React app** at `http://localhost:5173`

---

## Actor Guides

### Operator Guide

As an operator, you are responsible for deploying the system and keeping it running.

#### 1. Generate an operator key

The operator key signs root updates in trusted mode. Keep it secure.

```bash
# Generate a new key using cast
cast wallet new

# Example output:
# Address:     0xABCD1234...
# Private key: 0x1234ABCD...
```

> ⚠️ **Never commit your private key to source control.** Use environment variables or a secrets manager.

#### 2. Deploy contracts

See [Step 3](#step-3--deploy-the-contracts) above for the local flow. For testnet/mainnet, see [Deploying to Testnet](#deploying-to-testnet-sepolia).

The deploy script deploys two contracts:
- **PolicyRegistry** — Manages policy configurations
- **SolvencyRootOracle** — Stores Merkle roots and handles verification

#### 3. Create a policy

Policies define the rules for a solvency check. Key parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `policyId` | `bytes32` | Unique identifier — choose any 32-byte value, e.g. `keccak256("my-policy-v1")` |
| `thresholdWei` | `uint256` | Minimum balance in wei (e.g. `1 ether = 1e18`) |
| `tokenAddress` | `address` | `address(0)` for native ETH, or an ERC-20 token address |
| `chainId` | `uint64` | EVM chain ID (1 = mainnet, 11155111 = Sepolia, 31337 = Anvil) |
| `epochLengthBlocks` | `uint64` | How often to update, in blocks (~12s/block on mainnet; 100 = ~20 min) |
| `maxBlockAge` | `uint64` | Max age of state proof in blocks. **Must be ≤ 256** (EVM blockhash limit) |
| `rootTTLBlocks` | `uint64` | How long a published root stays valid. Use `50400` (~7 days) as a safe default |
| `operator` | `address` | Your operator wallet address |
| `scope` | `string` | Short identifier for this policy (used for privacy scoping, e.g. `"my-dapp-v1"`) |
| `trustedMode` | `bool` | `true` for EIP-712 trusted mode; `false` for ZK proof mode |

You can compute a `policyId` deterministically:

```bash
cast keccak "my-protocol-solvency-v1"
# → 0x3f4a...b921
```

#### 4. Configure the agent

Create a `.env` file (keep it out of git):

```bash
# Required
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
CHAIN_ID=1
OPERATOR_PRIVATE_KEY=0xYOUR_OPERATOR_PRIVATE_KEY
ORACLE_ADDRESS=0xDEPLOYED_ORACLE_ADDRESS

# Optional (defaults shown)
DATABASE_PATH=solvency_agent.db
BIND_ADDR=0.0.0.0:3000
POLL_INTERVAL_SECS=12
SKIP_ON_CHAIN=false
```

#### 5. Run the agent

```bash
# Build the release binary
cargo build -p zk-pof-backend --release

# Run with the .env file loaded
set -a && source .env && set +a
./target/release/zk-pof-backend
```

Or with Docker (recommended for production):

```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build -p zk-pof-backend --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zk-pof-backend /usr/local/bin/
CMD ["zk-pof-backend"]
```

```bash
docker build -t solvency-agent .
docker run -d \
  --name solvency-agent \
  -e RPC_URL=... \
  -e OPERATOR_PRIVATE_KEY=... \
  -e ORACLE_ADDRESS=... \
  -v /data/solvency:/data \
  -e DATABASE_PATH=/data/solvency.db \
  -p 3000:3000 \
  solvency-agent
```

#### 6. Monitor the agent

Key endpoints for operational monitoring:

```bash
# Health check
curl http://localhost:3000/health

# List members for your policy
curl http://localhost:3000/admin/members/0xYOUR_POLICY_ID

# Check latest epoch
curl http://localhost:3000/admin/epochs/0xYOUR_POLICY_ID
```

Watch logs for:
- `epoch published` — An epoch root was submitted on-chain
- `member enrolled` — A new member joined
- `fetch_failed` — Balance fetch failed for a member (check RPC)

---

### Member / User Guide

As a member, you enroll once and then use your `memberId` and Merkle proofs to interact with solvency-gated dApps.

#### Using the React App

**1. Open the app**

Navigate to the app URL (locally: http://localhost:5173).

**2. Connect your wallet**

Click **"Connect Wallet"** and select your wallet from the list. The app supports MetaMask, Rabby, Frame, and any injected browser wallet.

> 💡 You must connect the wallet address you want to prove solvency for — this is the address the agent will monitor.

**3. Configure the policy**

Fill in:
- **Policy ID**: The `bytes32` identifier for the policy you want to enroll in. Get this from the dApp or operator. Example: `0x0101...0101`
- **Scope**: The policy's scope string (provided by the operator alongside the Policy ID). Example: `defi-protocol-v1`
- **Nonce**: A unique random value. The app pre-fills a random nonce — you can leave it as-is.

**4. Sign the enrollment message**

The app shows you the message you'll sign:

```
zkpof-holder-v1:defi-protocol-v1:839401
```

Click **"Sign Message"** — your wallet will prompt you to sign. This is a free off-chain signature (no gas required).

> 🔒 The signature never leaves your device; it's used only to compute your `memberId = SHA256(signature)` and to prove wallet control.

**5. Submit enrollment**

Click **"Enroll"**. The app sends your address and signature to the agent for verification. On success you'll see:

```
Enrollment Successful

Member ID: 0xf47a3b...9c12
Policy ID: 0x0101...0101
```

**Save your Member ID!** You'll need it to fetch proofs and interact with gated dApps. Copy it to a secure note.

**6. Check your status**

Click the **Dashboard** tab. Enter your Policy ID and Member ID to see:
- Current status: `solvent` / `insolvent` / `pending`
- Last observed balance
- Last checked block

Your status will be `pending` until the first epoch update runs (the agent runs an update every `epochLengthBlocks`).

#### Using the SDK in your own app

If you're building a custom frontend:

```typescript
import { SolvencyClient, buildEnrollmentMessage } from "@zk-proof-of-funds/sdk";

const client = new SolvencyClient({
  agentUrl: "https://agent.example.com",
});

// 1. Build the enrollment message
const scope = "defi-protocol-v1";  // get from operator
const nonce = crypto.randomUUID();
const message = buildEnrollmentMessage(scope, nonce);
// → "zkpof-holder-v1:defi-protocol-v1:<uuid>"

// 2. Sign with wallet (using wagmi/ethers/viem)
const signature = await signer.signMessage(message);

// 3. Enroll
const { member_id } = await client.enroll({
  policy_id: "0x0101...0101",
  wallet_address: "0xYourAddress",
  signature,
  signed_message: message,
});

console.log("Member ID:", member_id);
// Store member_id securely — it's your identity in this policy
```

#### Fetching a proof to submit to a dApp

When a dApp requires you to include a Merkle proof in a transaction:

```typescript
// Fetch the proof
const proof = await client.getMemberProof(policyId, memberId);

// The dApp will expect these values:
console.log({
  memberId:    proof.member_id,          // bytes32
  epoch:       proof.epoch,              // uint64
  merkleProof: proof.merkle_proof,       // bytes32[]
  leafIndex:   proof.leaf_index,         // uint256
  rootIndex:   0,                        // uint256 (0 = latest root)
});
```

Then pass those values to the contract:

```typescript
// Example: calling a gated dApp contract
const tx = await gatedContract.performAction(
  proof.member_id,      // memberId
  proof.epoch,          // epoch
  proof.merkle_proof,   // merkleProof
  proof.leaf_index,     // leafIndex
  0                     // rootIndex
);
```

> 💡 **Tip**: Fetch the proof immediately before submitting the transaction. Proofs expire when a new epoch is published; most deployments use a `rootTTLBlocks` of ~50,000 blocks (~7 days), but verify with the operator.

---

### Integrator Guide

As an integrator, you're building a dApp that requires solvency proofs from users.

#### Option A — Pure Solidity (on-chain checks only)

**1. Import the interface**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolvencyOracle} from "./interfaces/ISolvencyOracle.sol";
```

Or copy `contracts/src/interfaces/ISolvencyOracle.sol` into your project.

**2. Store oracle and policy references**

```solidity
contract MyDApp {
    ISolvencyOracle public immutable oracle;
    bytes32 public immutable policyId;

    constructor(address _oracle, bytes32 _policyId) {
        oracle = ISolvencyOracle(_oracle);
        policyId = _policyId;
    }
}
```

**3. Gate your functions**

```solidity
/// @notice Gate an action behind solvency proof.
/// @param memberId    The user's privacy-preserving ID (from agent enrollment).
/// @param epoch       The epoch of the proof (from agent API).
/// @param merkleProof Sibling hashes from leaf to root (from agent API).
/// @param leafIndex   The leaf's position in the tree (from agent API).
/// @param rootIndex   Index in the oracle's root history (use 0 for latest).
function myGatedFunction(
    bytes32 memberId,
    uint64 epoch,
    bytes32[] calldata merkleProof,
    uint256 leafIndex,
    uint256 rootIndex
) external {
    require(
        oracle.isMemberSolvent(policyId, memberId, epoch, merkleProof, leafIndex, rootIndex),
        "Must prove solvency"
    );

    // Your logic here...
}
```

The full `verifyMember` function (when you also want to check insolvent status):

```solidity
bool isVerified = oracle.verifyMember(
    policyId,
    memberId,
    status,       // 1 = solvent, 0 = insolvent
    epoch,
    merkleProof,
    leafIndex,
    rootIndex
);
```

**4. See the example contracts**

The `examples/contracts/` directory contains complete, working examples:

| Contract | Use case |
|----------|----------|
| `SolvencyGatedPool.sol` | DeFi lending pool — gate deposits |
| `SolvencyGatedGovernor.sol` | DAO voting — gate vote casting |
| `SolvencyGatedNFT.sol` | NFT collection — gate minting |

#### Option B — TypeScript SDK + Solidity

For frontends that need to fetch proofs and submit them in transactions:

**1. Install the SDK**

```bash
# From the workspace
npm install ../sdk

# Or from npm (once published)
npm install @zk-proof-of-funds/sdk
```

**2. Initialize the client**

```typescript
import { SolvencyClient } from "@zk-proof-of-funds/sdk";

const solvencyClient = new SolvencyClient({
  agentUrl: process.env.NEXT_PUBLIC_AGENT_URL ?? "http://localhost:3000",
});
```

**3. Implement the enrollment flow**

```typescript
import { buildEnrollmentMessage } from "@zk-proof-of-funds/sdk";

async function enrollUser(
  policyId: string,
  walletAddress: string,
  signMessage: (msg: string) => Promise<string>
): Promise<string> {
  // Build a deterministic-ish nonce (can use wallet's nonce or random)
  const nonce = Date.now().toString();
  const scope = "my-dapp-v1"; // match what you used when creating the policy
  const message = buildEnrollmentMessage(scope, nonce);

  const signature = await signMessage(message);

  const { member_id } = await solvencyClient.enroll({
    policy_id: policyId,
    wallet_address: walletAddress,
    signature,
    signed_message: message,
  });

  return member_id;
}
```

**4. Fetch proof and submit transaction**

```typescript
async function submitGatedTransaction(
  policyId: string,
  memberId: string,
  contract: ethers.Contract
) {
  // Get the latest Merkle proof
  const proof = await solvencyClient.getMemberProof(policyId, memberId);

  if (proof.status !== 1) {
    throw new Error("Member is not currently solvent");
  }

  // Submit to your contract
  const tx = await contract.myGatedFunction(
    proof.member_id,
    proof.epoch,
    proof.merkle_proof,
    proof.leaf_index,
    0  // rootIndex: 0 for latest
  );
  await tx.wait();
}
```

**5. Display member status in your UI**

```typescript
async function getMemberInfo(policyId: string, memberId: string) {
  const status = await solvencyClient.getMemberStatus(policyId, memberId);

  return {
    isSolvent: status.status === "solvent",
    lastBalance: BigInt(status.last_balance_wei),
    lastChecked: new Date(status.last_checked_block * 12 * 1000), // ~12s/block
  };
}
```

**6. Handle errors**

```typescript
import { SolvencyError } from "@zk-proof-of-funds/sdk";

try {
  const proof = await solvencyClient.getMemberProof(policyId, memberId);
} catch (err) {
  if (err instanceof SolvencyError) {
    switch (err.code) {
      case "NOT_FOUND":
        // Member not enrolled, or no epoch has run yet
        showEnrollmentPrompt();
        break;
      case "CONFLICT":
        // Member already enrolled (if from enroll() call)
        fetchExistingMemberId();
        break;
      case "TIMEOUT":
        // Agent is slow or unreachable
        showRetryMessage();
        break;
      default:
        showGenericError(err.message);
    }
  }
}
```

---

## Deploying to Testnet (Sepolia)

### Prerequisites

- A funded Sepolia wallet (get free ETH from [sepoliafaucet.com](https://sepoliafaucet.com))
- A Sepolia RPC URL ([Alchemy](https://alchemy.com) or [Infura](https://infura.io) free tier)
- `DEPLOYER_PRIVATE_KEY` — the key for the account that will deploy and own the contracts

### Step 1 — Deploy contracts to Sepolia

```bash
cd contracts

export DEPLOYER_PRIVATE_KEY=0xYOUR_DEPLOYER_KEY
export RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_ALCHEMY_KEY

# For trusted mode (no ZK), SP1_VERIFIER_ADDRESS can be zero address
export SP1_VERIFIER_ADDRESS=0x0000000000000000000000000000000000000000

forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --verify \
  --etherscan-api-key YOUR_ETHERSCAN_API_KEY
```

The `--verify` flag automatically verifies contracts on Etherscan/Sepolia Etherscan.

Note the deployed addresses from the output:

```
PolicyRegistry deployed at: 0xAAAA...
SolvencyRootOracle deployed at: 0xBBBB...
```

### Step 2 — Create a policy on Sepolia

```bash
POLICY_REGISTRY=0xAAAA...
OPERATOR_ADDRESS=0xYOUR_OPERATOR_ADDRESS
POLICY_ID=$(cast keccak "my-protocol-v1")

# 1 ETH threshold, 100-block epochs, 7-day TTL, Sepolia chain ID
cast send $POLICY_REGISTRY \
  "createPolicy(bytes32,(uint256,address,uint64,uint64,uint64,uint64,address,string,bool,bool))" \
  $POLICY_ID \
  "(1000000000000000000,0x0000000000000000000000000000000000000000,11155111,100,200,50400,$OPERATOR_ADDRESS,my-protocol-v1,true,true)" \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --rpc-url $RPC_URL
```

### Step 3 — Configure and run the agent on Sepolia

```bash
cat > .env.sepolia << EOF
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_ALCHEMY_KEY
CHAIN_ID=11155111
OPERATOR_PRIVATE_KEY=0xYOUR_OPERATOR_KEY
ORACLE_ADDRESS=0xBBBB...
DATABASE_PATH=/data/solvency_sepolia.db
BIND_ADDR=0.0.0.0:3000
POLL_INTERVAL_SECS=12
EOF

set -a && source .env.sepolia && set +a
cargo run -p zk-pof-backend --release
```

### Step 4 — Configure and deploy the frontend

```bash
cd web

cat > .env.production << EOF
VITE_AGENT_URL=https://your-agent.example.com
VITE_CHAIN_ID=11155111
EOF

npm run build
# Outputs to web/dist/ — deploy to Vercel, Netlify, GitHub Pages, etc.

# Example: Vercel deployment
npx vercel --prod
```

### Step 5 — Verify end-to-end on Sepolia

```bash
# 1. Health check
curl https://your-agent.example.com/health

# 2. Enroll a test member
curl -X POST https://your-agent.example.com/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "0xYOUR_POLICY_ID",
    "wallet_address": "0xYOUR_TEST_ADDRESS",
    "signature": "0xYOUR_SIGNATURE",
    "signed_message": "zkpof-holder-v1:my-protocol-v1:12345"
  }'

# 3. Wait for an epoch (100 blocks ≈ 20 min on Sepolia), then check proof
curl https://your-agent.example.com/proof/0xPOLICY_ID/0xMEMBER_ID
```

---

## Deploying to Mainnet

> ⚠️ **Mainnet deployment involves real funds. Review every configuration value carefully.**

### Security checklist

Before deploying to mainnet:

- [ ] Audit or thoroughly review the smart contracts
- [ ] Use a **hardware wallet** (Ledger, Trezor) or **multisig** (Safe) for the deployer and operator keys
- [ ] Set a conservative `rootTTLBlocks` (e.g. `50400` ≈ 7 days) to give users time to re-enroll if needed
- [ ] Set `maxBlockAge` ≤ 256 (the EVM blockhash window)
- [ ] Test the full flow on Sepolia first
- [ ] Ensure the RPC endpoint is reliable and not rate-limited (use a paid tier)
- [ ] Monitor the agent 24/7 — if it stops publishing roots, proofs will expire after `rootTTLBlocks`
- [ ] Back up the SQLite database regularly (or use PostgreSQL with replication)

### Step 1 — Deploy contracts to mainnet

```bash
cd contracts

export DEPLOYER_PRIVATE_KEY=0xYOUR_MAINNET_DEPLOYER_KEY  # Use hardware wallet
export RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_PROD_KEY

# For trusted mode on mainnet, SP1 verifier not needed
export SP1_VERIFIER_ADDRESS=0x0000000000000000000000000000000000000000

forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --verify \
  --etherscan-api-key YOUR_ETHERSCAN_API_KEY \
  --slow  # Slower nonce management for safety
```

### Step 2 — Create a mainnet policy

Use conservative parameters for mainnet:

```bash
POLICY_REGISTRY=0xDEPLOYED_REGISTRY
POLICY_ID=$(cast keccak "my-protocol-mainnet-v1")

cast send $POLICY_REGISTRY \
  "createPolicy(bytes32,(uint256,address,uint64,uint64,uint64,uint64,address,string,bool,bool))" \
  $POLICY_ID \
  "(1000000000000000000,0x0000000000000000000000000000000000000000,1,600,200,50400,$OPERATOR_ADDRESS,my-protocol-mainnet-v1,true,true)" \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --rpc-url $RPC_URL
```

Key differences from testnet:
- `chainId = 1` (mainnet)
- `epochLengthBlocks = 600` (~2 hours — reduce RPC costs, avoid unnecessary gas)
- `rootTTLBlocks = 50400` (~7 days at 12s/block)

### Step 3 — Run the agent in production

Use a process manager (systemd, supervisor) or container orchestration (Kubernetes, ECS):

**systemd service example** (`/etc/systemd/system/solvency-agent.service`):

```ini
[Unit]
Description=ZK Proof of Funds Solvency Agent
After=network.target

[Service]
Type=simple
User=solvency
WorkingDirectory=/opt/solvency-agent
EnvironmentFile=/etc/solvency-agent/env
ExecStart=/opt/solvency-agent/zk-pof-backend
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/solvency-agent/env (chmod 600, owned by root)
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
CHAIN_ID=1
OPERATOR_PRIVATE_KEY=0xYOUR_OPERATOR_KEY
ORACLE_ADDRESS=0xYOUR_ORACLE
DATABASE_PATH=/var/lib/solvency/solvency.db
BIND_ADDR=0.0.0.0:3000
POLL_INTERVAL_SECS=12

# Enable and start
systemctl daemon-reload
systemctl enable solvency-agent
systemctl start solvency-agent
systemctl status solvency-agent
```

### Step 4 — Set up monitoring

Key metrics to alert on:

| Check | Command | Alert if |
|-------|---------|----------|
| Agent health | `curl https://agent.example.com/health` | Non-200 response |
| Latest epoch age | Check `admin/epochs` response | `published_at_block` > `rootTTLBlocks / 2` blocks ago |
| Member count | Check `admin/members` | Unexpected drop |
| RPC latency | Monitor your RPC provider | P99 > 500ms |

**Simple cron-based health check** (add to `/etc/cron.d/solvency-monitor`):

```cron
*/5 * * * * root curl -sf https://agent.example.com/health || mail -s "Solvency Agent DOWN" ops@yourcompany.com
```

---

## API Reference

### Base URL

| Environment | URL |
|-------------|-----|
| Local dev | `http://localhost:3000` |
| Testnet | Configured by operator |
| Mainnet | Configured by operator |

### Integrator Endpoints

#### `POST /enroll`

Enroll a new member in a solvency policy.

**Request body**:
```json
{
  "policy_id": "0x0101...0101",
  "wallet_address": "0xabcd...ef00",
  "signature": "0x1234...5678",
  "signed_message": "zkpof-holder-v1:my-scope:12345"
}
```

**Response `200 OK`**:
```json
{
  "member_id": "0xf47a...9c12",
  "status": "enrolled",
  "effective_epoch": 5
}
```

**Errors**: `400` invalid signature/format, `409` already enrolled

---

#### `GET /proof/{policyId}/{memberId}`

Get the Merkle proof for a member to use in on-chain transactions.

**Response `200 OK`**:
```json
{
  "member_id": "0xf47a...9c12",
  "policy_id": "0x0101...0101",
  "status": 1,
  "epoch": 42,
  "leaf_index": 17,
  "merkle_proof": ["0xaaaa...", "0xbbbb...", "0xcccc..."],
  "root": "0xdddd...",
  "block_number": 19500000
}
```

**Note**: `status` is `1` (solvent) or `0` (insolvent). The `merkle_proof` array goes from leaf to root.

**Errors**: `404` member not found or no epochs yet, `400` invalid hex

---

#### `GET /status/{policyId}/{memberId}`

Check a member's current solvency status.

**Response `200 OK`**:
```json
{
  "member_id": "0xf47a...9c12",
  "policy_id": "0x0101...0101",
  "status": "solvent",
  "last_balance_wei": "1500000000000000000",
  "last_checked_block": 19500000,
  "effective_epoch": 3,
  "enrolled_at": 1719875400
}
```

**Status values**: `solvent` | `insolvent` | `pending` | `fetch_failed`

---

#### `GET /health`

**Response `200 OK`**:
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

### Admin Endpoints

#### `GET /admin/members/{policyId}`

List all enrolled members for a policy.

**Response `200 OK`**:
```json
{
  "policy_id": "0x0101...0101",
  "member_count": 3,
  "members": [
    {
      "member_id": "0xf47a...",
      "status": "solvent",
      "last_balance_wei": "1500000000000000000",
      "last_checked_block": 19500000,
      "effective_epoch": 3
    }
  ]
}
```

---

#### `GET /admin/epochs/{policyId}`

Get the latest epoch record for a policy.

**Response `200 OK`**:
```json
{
  "policy_id": "0x0101...0101",
  "latest_epoch": {
    "epoch": 42,
    "block_number": 19500000,
    "root": "0xdddd...",
    "member_count": 3,
    "published_at_block": 19500050
  }
}
```

`latest_epoch` is `null` if no epochs have been published yet.

---

## Troubleshooting

### Member enrollment fails with "Signature verification failed"

**Cause**: The wallet used to sign produces a different recovery than expected.

**Fix**:
1. Ensure you're signing the exact message string: `zkpof-holder-v1:{scope}:{nonce}`
2. Ensure the `wallet_address` in the request matches the address of the signing key
3. Ensure the `scope` matches the policy's configured scope (ask the operator)
4. Some wallets add extra newlines or prefixes — use `personal_sign` / `eth_sign` (EIP-191), not `eth_signTypedData`

---

### Member status is `pending` for a long time

**Cause**: The first epoch hasn't run yet, or `RPC_URL` is not configured.

**Fix**:
1. Check `GET /health` and `GET /admin/epochs/{policyId}`
2. If `latest_epoch` is `null`, the agent hasn't published an epoch yet
3. Verify `RPC_URL` is set in the agent's environment
4. Check agent logs for `fetch_failed` warnings

---

### `GET /proof` returns 404

**Causes**:
1. No epochs have been published yet (enrollment is too recent)
2. The `policyId` in the request doesn't match what was used at enrollment
3. The member was enrolled after the latest epoch ran (wait for the next epoch)

**Fix**: Check `GET /admin/epochs/{policyId}` — if `epoch < member.effective_epoch`, wait for the next epoch update.

---

### On-chain `isMemberSolvent` returns `false` despite a valid-looking proof

**Causes**:
1. The proof has expired (`rootTTLBlocks` elapsed since publication) — fetch a fresh proof
2. Wrong `rootIndex` — try `0` for the latest root
3. The `leafIndex` or `epoch` doesn't match the proof array — use values from the API exactly as returned
4. The `policyId` in the contract call doesn't match the enrolled policy

**Fix**: Fetch a fresh proof immediately before submitting the transaction. Never cache proofs.

---

### The agent keeps logging `BlockTooOld`

**Cause**: The state block used for balance checks is more than `maxBlockAge` blocks old.

**Fix**: Reduce `POLL_INTERVAL_SECS` so the agent runs more frequently, or increase `maxBlockAge` (max is 256).

---

### `forge script` fails with "missing hex prefix for hex string"

**Cause**: `DEPLOYER_PRIVATE_KEY` is set without the `0x` prefix.

**Fix**: Ensure the key starts with `0x`: `export DEPLOYER_PRIVATE_KEY=0x1234...`

---

### Frontend can't connect to the agent (CORS error)

**Cause**: The browser blocks cross-origin requests if the agent doesn't send CORS headers.

**Fix**: Run the backend behind a reverse proxy (nginx/Caddy) that adds CORS headers, or configure the Vite dev proxy:

```typescript
// web/vite.config.ts — already configured
server: {
  proxy: {
    "/api": {
      target: "http://localhost:3000",
      changeOrigin: true,
      rewrite: (p) => p.replace(/^\/api/, ""),
    },
  },
},
```

For production, add CORS headers to your nginx config:

```nginx
location / {
    add_header 'Access-Control-Allow-Origin' '$http_origin' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
    add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
    proxy_pass http://127.0.0.1:3000;
}
```
