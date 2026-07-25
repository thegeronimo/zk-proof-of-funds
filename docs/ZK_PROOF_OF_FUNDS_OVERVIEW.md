# ZK Proof of Funds: System Overview

**Privacy-Preserving Solvency Attestation for EVM Networks**

Version 1.0 | February 2026

---

## Table of Contents

1. [What is ZK Proof of Funds?](#1-what-is-zk-proof-of-funds)
2. [How It Works (Simple Version)](#2-how-it-works-simple-version)
3. [System Architecture](#3-system-architecture)
4. [For End Users (Members)](#4-for-end-users-members)
5. [For Service Providers (Relying Protocols)](#5-for-service-providers-relying-protocols)
6. [For Operators (Running the Solvency Agent)](#6-for-operators-running-the-solvency-agent)
7. [Privacy & Security Model](#7-privacy--security-model)
8. [Worked Example: Tiered Credit Card Program](#8-worked-example-tiered-credit-card-program)
9. [Technical Reference](#9-technical-reference)
10. [Glossary](#10-glossary)

---

## 1. What is ZK Proof of Funds?

ZK Proof of Funds is a **middleware-driven solvency attestation system** that lets users prove they hold a minimum balance on Ethereum without revealing their wallet address, exact balance, or any other private information.

### The Problem

Many decentralized applications need to verify that a user meets a financial threshold:

- A lending protocol wants to ensure depositors are creditworthy
- A governance system wants to restrict voting to stakeholders with meaningful skin-in-the-game
- A premium service wants to gate features based on staked assets
- An OTC desk needs counterparty solvency verification

Today, these checks either require the user to reveal their full wallet address (privacy violation) or rely on centralized attestation services (trust violation).

### The Solution

ZK Proof of Funds provides a **privacy-preserving, cryptographically verifiable** system where:

- Users **enroll once** by signing a message with their wallet
- The system **never learns the user's wallet address** during enrollment
- Users **submit their own balance proofs** from any Ethereum node
- A Solvency Agent **verifies proofs and publishes batch attestations** on-chain
- Relying protocols **check membership via a cheap on-chain call** (~8,000 gas)

The user's wallet address is never stored. Only a privacy-preserving identifier (a hash of their signature) links them to the system.

---

## 2. How It Works (Simple Version)

The system operates in four phases:

```
    ENROLL              PROVE               BATCH              VERIFY
   (one-time)         (per-epoch)          (agent)           (on-chain)

  +----------+      +------------+      +----------+      +----------+
  | User     |      | User       |      | Agent    |      | Protocol |
  | signs    | ---> | fetches    | ---> | verifies | ---> | checks   |
  | message  |      | own proof  |      | & batches|      | member-  |
  |          |      | from node  |      | into root|      | ship     |
  +----------+      +------------+      +----------+      +----------+

  No address         Address used        One Merkle         ~8,000 gas
  sent to agent      only locally        root for all       per check
```

**Step 1 - Enroll:** The user signs a message with their wallet. The signature proves wallet ownership. The system computes `memberId = SHA256(signature)` as their privacy-preserving identifier. No wallet address is stored or transmitted.

**Step 2 - Submit Proof:** The user fetches an EIP-1186 state proof (`eth_getProof`) from any Ethereum node, which cryptographically proves their balance at a specific block. They submit this proof to the Solvency Agent. The wallet address is used only to verify the proof and is immediately discarded.

**Step 3 - Batch:** The Solvency Agent verifies all submitted proofs, determines each member's solvency status, and builds a Merkle tree. A single Merkle root representing all members is published on-chain.

**Step 4 - Verify:** Any smart contract can verify a member's solvency status by checking a Merkle inclusion proof against the published root. The agent provides the proof data to the requesting protocol.

---

## 3. System Architecture

```
+------------------------------------------------------------------+
|                     ON-CHAIN (Ethereum)                           |
|                                                                  |
|  +---------------------------+  +-----------------------------+  |
|  | SolvencyRootOracle.sol    |  | PolicyRegistry.sol          |  |
|  |                           |  |                             |  |
|  |  Per-policy Merkle roots  |  |  Policy definitions         |  |
|  |  verifyMember()  ~8k gas  |  |  (threshold, epoch, TTL)    |  |
|  |  updateRoot()   ~100k gas |  |  Operator authorization     |  |
|  +---------------------------+  +-----------------------------+  |
+------------------------------------------------------------------+
              ^                            ^
              | updateRoot()               | registerPolicy()
              |                            |
+------------------------------------------------------------------+
|                 SOLVENCY AGENT (Off-Chain)                        |
|                                                                  |
|   Enrollment   |   Proof       |  Epoch       |  Chain           |
|   Service      |   Verifier    |  Processor   |  Publisher       |
|                |   (MPT)       |  (Merkle)    |  (Tx Submit)     |
|                                                                  |
|   REST API (Axum):                                               |
|   POST /enroll            POST /submit_proof                     |
|   GET  /proof             GET  /status                           |
|   POST /admin/trigger_epoch                                      |
+------------------------------------------------------------------+
              ^                            ^
              | Enroll & Submit            | Fetch Proof
              |                            |
+------------------------------------------------------------------+
|                    PARTICIPANTS                                   |
|                                                                  |
|   +----------+    +-------------+    +--------------------+      |
|   | End User |    | DApp / SDK  |    | Relying Protocol   |      |
|   | (wallet) |    | (fetches    |    | (calls oracle      |      |
|   |          |    |  proofs)    |    |  .verifyMember)    |      |
|   +----------+    +-------------+    +--------------------+      |
+------------------------------------------------------------------+
```

### Key Components

| Component | Role |
|-----------|------|
| **SolvencyRootOracle** | On-chain contract that stores batch Merkle roots and verifies membership |
| **PolicyRegistry** | On-chain registry of solvency policies (thresholds, epoch lengths, operators) |
| **Solvency Agent** | Off-chain middleware that processes enrollments, verifies proofs, builds Merkle trees, and publishes roots |
| **TypeScript SDK** | Client library for integrators to interact with the agent API |
| **Web Frontend** | React UI for enrollment and dashboard monitoring |

---

## 4. For End Users (Members)

### What You Need

- An Ethereum wallet (MetaMask, WalletConnect, etc.)
- A balance that meets the policy threshold

### Enrollment (One-Time Setup)

1. **Connect your wallet** to the enrollment interface
2. **Select a policy** you want to enroll in (e.g., "Premium DeFi Access: 10 ETH minimum")
3. **Sign a message** when prompted by your wallet. The message looks like:
   ```
   zkpof-holder-v1:defi-premium:847291
   ```
   This proves you control the wallet. No funds are transferred.
4. **Receive your Member ID** - a 32-byte hex string like `a7b3c9d1e5...`. Save this; it's your privacy-preserving identifier.

**What happens behind the scenes:**
- Your signature is sent to the Solvency Agent
- The agent verifies the signature is valid (recovers to a real address)
- Your Member ID = SHA256(your signature)
- No wallet address is sent to or stored by the agent

### Submitting Solvency Proofs

After enrollment, you periodically submit balance proofs to maintain your solvency status:

1. **Connect your wallet** on the dashboard
2. **Click "Submit Solvency Proof"** - the app will:
   - Call `eth_getProof` on your wallet's Ethereum node
   - Send the cryptographic proof to the Solvency Agent
   - The agent verifies your balance meets the threshold
3. **View your status** - solvent, insolvent, or pending

**What happens behind the scenes:**
- Your wallet calls `eth_getProof(yourAddress, [], blockNumber)` via your connected provider
- This returns a Merkle-Patricia Trie proof of your account state
- The proof (plus your address) is sent to the agent
- The agent verifies the proof against the Ethereum state root
- Your address is used only for proof verification and is immediately discarded
- Only your Member ID and solvency status (solvent/insolvent) are stored

### Privacy Guarantees for Users

| What is known | By whom |
|--------------|---------|
| Your wallet address | **Only you and your Ethereum node** (the agent discards it after proof verification) |
| Your exact balance | **Nobody** (only whether it's above or below the threshold) |
| Your Member ID | The Solvency Agent and relying protocols |
| Your solvency status | The Solvency Agent and (via on-chain root) anyone with your Merkle proof |
| Which policies you're in | The Solvency Agent (different policies use different Member IDs) |

### What You Don't Need to Do

- Run any software
- Monitor your balance
- Interact with the system after submitting your proof each epoch
- Manage private keys for the solvency system
- Pay gas (the agent pays for root publication)

---

## 5. For Service Providers (Relying Protocols)

### Integration Overview

As a service provider (DeFi protocol, dApp, DAO), you can gate functionality behind solvency verification with minimal smart contract changes.

### On-Chain Integration

Add a solvency check to any function:

```solidity
import {ISolvencyOracle} from "./interfaces/ISolvencyOracle.sol";

contract MyProtocol {
    ISolvencyOracle public oracle;
    bytes32 public policyId;

    function gatedAction(
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external {
        // Verify the member is solvent (~8,000 gas)
        bool solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch,
            merkleProof, leafIndex, rootIndex
        );
        require(solvent, "Solvency proof required");

        // Proceed with gated logic...
    }
}
```

### Off-Chain Integration (SDK)

Use the TypeScript SDK to fetch proofs for your users:

```typescript
import { SolvencyClient } from "@zk-proof-of-funds/sdk";

const client = new SolvencyClient({
  agentUrl: "https://agent.example.com",
});

// When a user wants to perform a gated action:
async function performGatedAction(memberId: string) {
  // 1. Fetch the Merkle proof from the agent
  const proof = await client.getMemberProof(POLICY_ID, memberId);

  // 2. Include it in the smart contract call
  const tx = await myContract.gatedAction(
    proof.member_id,
    proof.epoch,
    proof.merkle_proof,
    proof.leaf_index,
    0  // latest root
  );
}
```

### Setting Up a Policy

A policy defines what the solvency check verifies:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `thresholdWei` | Minimum balance required | 10 ETH = `10000000000000000000` |
| `epochLengthBlocks` | How often the root is updated | 7200 (~1 day) |
| `maxBlockAge` | Maximum age of state proofs | 256 blocks (~51 min) |
| `rootTTLBlocks` | How long a published root stays valid | 14400 (~2 days) |
| `operator` | Address authorized to publish roots | Solvency Agent's address |
| `scope` | Scoping string for Member ID generation | `"my-protocol-v1"` |
| `trustedMode` | Whether to use EIP-712 signatures (fast) or ZK proofs | `true` / `false` |

### Multi-Tier Policies

For tiered access (e.g., Bronze/Silver/Gold), create **multiple policies** with different thresholds:

```
Policy "bronze-tier":  thresholdWei = 1 ETH
Policy "silver-tier":  thresholdWei = 10 ETH
Policy "gold-tier":    thresholdWei = 100 ETH
```

Users enroll in each tier they qualify for. Your contract checks the appropriate policy.

### Cost Analysis

| Operation | Gas Cost | Frequency | Who Pays |
|-----------|----------|-----------|----------|
| Root publication (trusted mode) | ~100,000 | Once per epoch per policy | Agent operator |
| Root publication (ZK mode) | ~270,000 | Once per epoch per policy | Agent operator |
| Membership verification | ~8,000 | Per user action | User (or protocol) |

**Per-member amortized cost** for root publication: if 100 members are in a policy, each member's share of the publication cost is ~1,000 gas (trusted mode) or ~2,700 gas (ZK mode).

---

## 6. For Operators (Running the Solvency Agent)

### What the Agent Does

The Solvency Agent is the off-chain middleware that:

1. **Processes enrollments** - verifies signatures, computes Member IDs
2. **Receives and verifies proofs** - validates EIP-1186 state proofs against Ethereum state roots
3. **Builds Merkle trees** - creates per-policy solvency trees each epoch
4. **Publishes roots** - submits Merkle roots to the SolvencyRootOracle contract
5. **Serves proofs** - provides Merkle inclusion proofs to relying protocols on demand

### Running the Agent

```bash
# Environment variables
export DATABASE_PATH="solvency_agent.db"
export RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
export OPERATOR_PRIVATE_KEY="0x..."
export ORACLE_ADDRESS="0x..."
export CHAIN_ID="1"

# Start the server
cargo run --bin zk-pof-backend
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/enroll` | POST | Enroll a new member |
| `/submit_proof/:policyId/:memberId` | POST | Submit an EIP-1186 proof |
| `/proof/:policyId/:memberId` | GET | Get Merkle membership proof |
| `/status/:policyId/:memberId` | GET | Get member status |
| `/admin/members/:policyId` | GET | List all members |
| `/admin/epochs/:policyId` | GET | Epoch history |
| `/admin/trigger_epoch/:policyId` | POST | Manually trigger an epoch |

### Epoch Lifecycle

```
1. Admin triggers epoch (or scheduler fires automatically)

2. Agent reads proof submissions from the database
   - Members who submitted valid proofs: use verified balance
   - Members without proofs: use last known balance

3. For each eligible member:
   - Determine status: solvent (1) if balance >= threshold, insolvent (0) otherwise
   - Compute leaf: SHA256(memberId || status || epoch || policyId)

4. Build binary Merkle tree from all leaves

5. Publish root to SolvencyRootOracle contract
   - Trusted mode: sign with EIP-712 and submit
   - ZK mode: generate SP1 batch proof and submit

6. Store tree for serving individual Merkle proofs
```

### Trust Model

| What the operator CAN do | What the operator CANNOT do |
|--------------------------|----------------------------|
| Withhold updates (liveness) | Steal user funds (non-custodial) |
| See that proofs were submitted | See wallet addresses (discarded after verification) |
| Determine member solvency | Falsify statuses in ZK mode |

---

## 7. Privacy & Security Model

### Privacy Layers

```
Layer 1: Enrollment Privacy
  - User signs a message; agent receives only the signature
  - memberId = SHA256(signature) is non-invertible
  - Agent cannot determine the user's wallet address from enrollment

Layer 2: Proof Submission Privacy
  - User submits eth_getProof with their address
  - Address is used ONLY for MPT trie key computation
  - Address is immediately discarded after verification
  - Only memberId + solvent/insolvent status is stored

Layer 3: On-Chain Privacy
  - Only Merkle roots are published on-chain
  - Individual balances, addresses, and statuses are hidden
  - Verification requires a Merkle proof (served by the agent)

Layer 4: Cross-Policy Unlinkability
  - Different policy scopes produce different memberIds
  - Same user in "lending-pool" and "governance" scopes
    has two different, unlinkable memberIds
```

### Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Non-custodial** | Agent never controls funds | Only reads state via EIP-1186 proofs |
| **Correctness** | Statuses match on-chain reality | MPT proof verification against state roots |
| **Tamper-proof** (ZK mode) | Agent cannot falsify statuses | SP1 ZK proof verifies all balance checks |
| **Tamper-evident** (trusted mode) | Forgery detectable | EIP-712 signatures from known operator |
| **Replay-resistant** | Old proofs cannot be reused | Epoch number in leaf + root TTL expiry |
| **Forward-secure** | Balance drops detected | Insolvent status in next epoch |

### What Happens If...

| Scenario | System Response |
|----------|----------------|
| User's balance drops below threshold | Status changes to "insolvent" in the next epoch |
| User's balance recovers | Status changes back to "solvent" in the following epoch |
| Agent goes offline | Existing roots remain valid until TTL expires; alerts fire |
| Agent database is compromised | No wallet addresses stored; only Member IDs and statuses |
| User loses their Member ID | They can re-derive it by signing the same message again |
| RPC node returns false data | ZK proof verification catches inconsistencies with state root |

---

## 8. Worked Example: Tiered Credit Card Program

### Scenario

**CryptoCard Inc.** is a crypto-native credit card provider that offers different card tiers based on how much ETH a user holds. They want to verify holdings without learning users' wallet addresses.

### Tier Structure

| Tier | Required Balance | Benefits |
|------|-----------------|----------|
| **Standard** | 1 ETH (~$3,500) | Basic card, 1% cashback |
| **Silver** | 10 ETH (~$35,000) | Higher limits, 2% cashback, airport lounge access |
| **Gold** | 50 ETH (~$175,000) | Premium limits, 3% cashback, concierge, travel insurance |
| **Platinum** | 100 ETH (~$350,000) | Unlimited, 5% cashback, all Gold perks + private banking |

### Setup: Creating Policies

CryptoCard creates four solvency policies on-chain:

```solidity
// Standard Tier: 1 ETH minimum, checked daily
policyRegistry.createPolicy(Policy({
    thresholdWei: 1 ether,
    tokenAddress: address(0),       // Native ETH
    chainId: 1,                      // Ethereum mainnet
    epochLengthBlocks: 7200,         // ~1 day
    maxBlockAge: 256,
    rootTTLBlocks: 14400,            // ~2 days validity
    operator: SOLVENCY_AGENT_ADDR,
    scope: "cryptocard-standard-v1",
    trustedMode: true,
    active: true
}));
// Returns policyId: 0xaaaa...

// Silver Tier: 10 ETH minimum
// ... same structure, thresholdWei: 10 ether, scope: "cryptocard-silver-v1"
// Returns policyId: 0xbbbb...

// Gold Tier: 50 ETH minimum
// ... thresholdWei: 50 ether, scope: "cryptocard-gold-v1"
// Returns policyId: 0xcccc...

// Platinum Tier: 100 ETH minimum
// ... thresholdWei: 100 ether, scope: "cryptocard-platinum-v1"
// Returns policyId: 0xdddd...
```

### Integration: The Smart Contract

CryptoCard deploys a tiered access contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISolvencyOracle} from "./interfaces/ISolvencyOracle.sol";

contract CryptoCardTiers {
    ISolvencyOracle public immutable oracle;

    // Tier policy IDs
    bytes32 public constant STANDARD_POLICY = 0xaaaa...;
    bytes32 public constant SILVER_POLICY   = 0xbbbb...;
    bytes32 public constant GOLD_POLICY     = 0xcccc...;
    bytes32 public constant PLATINUM_POLICY = 0xdddd...;

    enum Tier { None, Standard, Silver, Gold, Platinum }

    // Track highest verified tier per member
    mapping(bytes32 => Tier) public memberTier;

    event TierVerified(bytes32 indexed memberId, Tier tier);

    /// @notice Verify a member's tier using their solvency proof.
    /// @dev The frontend calls the Solvency Agent API for each tier the user
    ///      qualifies for, then submits the highest tier proof here.
    function verifyTier(
        bytes32 policyId,
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external {
        bool solvent = oracle.isMemberSolvent(
            policyId, memberId, epoch,
            merkleProof, leafIndex, rootIndex
        );
        require(solvent, "Solvency proof invalid");

        Tier tier;
        if (policyId == PLATINUM_POLICY)     tier = Tier.Platinum;
        else if (policyId == GOLD_POLICY)    tier = Tier.Gold;
        else if (policyId == SILVER_POLICY)  tier = Tier.Silver;
        else if (policyId == STANDARD_POLICY) tier = Tier.Standard;
        else revert("Unknown policy");

        // Only upgrade, never downgrade within same epoch
        if (uint8(tier) > uint8(memberTier[memberId])) {
            memberTier[memberId] = tier;
            emit TierVerified(memberId, tier);
        }
    }

    /// @notice Check if a member has at least the required tier.
    function hasMinimumTier(
        bytes32 memberId,
        Tier requiredTier
    ) external view returns (bool) {
        return uint8(memberTier[memberId]) >= uint8(requiredTier);
    }
}
```

### User Journey: Alice Gets a Platinum Card

**Alice holds 120 ETH** and wants the Platinum card.

**Step 1: Enrollment**

Alice visits the CryptoCard enrollment page and enrolls in all four tiers:

```
For each tier (Standard, Silver, Gold, Platinum):
  1. Alice clicks "Enroll in [Tier]"
  2. Her wallet prompts her to sign:
     "zkpof-holder-v1:cryptocard-platinum-v1:583921"
  3. The signature is sent to the Solvency Agent
  4. Agent computes memberId = SHA256(signature)
  5. Alice receives her Member ID for that tier
```

Each tier has a different scope, so Alice gets four different Member IDs. This means her Standard tier membership cannot be linked to her Platinum tier membership by external observers.

**Step 2: Submitting Proofs**

Once per epoch (~daily), Alice opens the dashboard and clicks "Submit Solvency Proof" for each tier:

```
1. Alice's wallet calls eth_getProof(alice_address, [], latest_block)
2. The proof is submitted to the Solvency Agent
3. The agent verifies:
   - The MPT proof is valid against the Ethereum state root
   - Alice's balance (120 ETH) >= tier threshold
4. Result: "solvent" for all four tiers
5. Alice's address is discarded immediately
```

**Step 3: Epoch Processing**

The Solvency Agent processes each policy:

```
For "cryptocard-platinum-v1" (threshold: 100 ETH):
  - Alice submitted proof: balance = 120 ETH >= 100 ETH -> status = 1 (solvent)
  - Bob submitted proof:   balance = 80 ETH  <  100 ETH -> status = 0 (insolvent)
  - Carol: no proof submitted -> uses last known balance

  Build Merkle tree:
    leaf_0 = SHA256(alice_memberId || 0x01 || epoch || policyId)
    leaf_1 = SHA256(bob_memberId   || 0x00 || epoch || policyId)
    leaf_2 = SHA256(carol_memberId || 0x01 || epoch || policyId)
    ...
    root = Merkle root of all leaves

  Publish root on-chain via updateRootTrusted()
```

**Step 4: Using the Card**

When Alice wants to use her Platinum card benefits, the CryptoCard backend:

```typescript
// CryptoCard backend fetches proof from the Solvency Agent
const proof = await solvencyClient.getMemberProof(
  PLATINUM_POLICY_ID,
  alice_platinum_member_id
);

// Verify on-chain (or the frontend includes this in a transaction)
const tx = await cryptoCardContract.verifyTier(
  PLATINUM_POLICY_ID,
  proof.member_id,
  proof.epoch,
  proof.merkle_proof,
  proof.leaf_index,
  0  // latest root index
);
// Cost: ~8,000 gas
```

**Step 5: Automatic Tier Adjustment**

If Alice's balance drops to 40 ETH:

```
Next epoch:
  - Standard (1 ETH):   Alice = solvent    (40 >= 1)
  - Silver (10 ETH):    Alice = solvent    (40 >= 10)
  - Gold (50 ETH):      Alice = INSOLVENT  (40 < 50)
  - Platinum (100 ETH): Alice = INSOLVENT  (40 < 100)

CryptoCard's system detects that Alice's Platinum proof
now fails verification. She's automatically downgraded
to Silver tier until her balance recovers.
```

### Architecture Diagram for CryptoCard

```
  Alice's Wallet                  CryptoCard System
  +------------+                  +------------------+
  |            |  1. Sign msg     |                  |
  | MetaMask   |----------------->| Enrollment Page  |
  |            |  2. eth_getProof |                  |
  |            |----------------->| Dashboard        |
  +------------+                  +------------------+
                                         |
                                         v
                                  +------------------+
                                  | Solvency Agent   |
                                  |                  |
                                  | - Verify proofs  |
                                  | - Build trees    |
                                  | - Publish roots  |
                                  | - Serve proofs   |
                                  +------------------+
                                    |           |
                            publish |           | serve proof
                                    v           v
                                  +------------------+
                                  | Ethereum          |
                                  |                  |
                                  | SolvencyOracle   |
                                  | (4 policies:     |
                                  |  Standard/Silver |
                                  |  /Gold/Platinum) |
                                  +------------------+
                                         |
                                         | verifyMember()
                                         v
                                  +------------------+
                                  | CryptoCardTiers  |
                                  | Smart Contract   |
                                  |                  |
                                  | Gate card access |
                                  | based on tier    |
                                  +------------------+
```

### What CryptoCard Knows vs. Doesn't Know

| Information | Known to CryptoCard? |
|------------|---------------------|
| Alice's wallet address | **No** |
| Alice's exact ETH balance | **No** |
| Alice holds >= 100 ETH | **Yes** (while Platinum proof verifies) |
| Alice's other crypto holdings | **No** |
| Alice's transaction history | **No** |
| Alice's identity | Only if she provided KYC separately |
| Alice dropped below threshold | **Yes** (proof stops verifying in next epoch) |

### Cost Breakdown for CryptoCard

| Item | Cost | Frequency |
|------|------|-----------|
| Policy creation (4 tiers) | ~200k gas x 4 | One-time |
| Root publication per tier | ~100k gas | Daily per tier |
| Total daily publication (4 tiers) | ~400k gas (~$2-5 at typical gas prices) | Daily |
| Per-user tier verification | ~8k gas | Per card use |
| Solvency Agent hosting | Standard server costs | Ongoing |

For 1,000 cardholders across 4 tiers, the daily root publication cost is shared: approximately $0.005 per user per day.

---

## 9. Technical Reference

### Merkle Leaf Structure

Each member's status is encoded as a Merkle tree leaf:

```
leaf = SHA256(memberId || status || epoch || policyId)

Where:
  memberId:  32 bytes  (SHA256 of enrollment signature)
  status:     1 byte   (0x01 = solvent, 0x00 = insolvent)
  epoch:      8 bytes   (big-endian uint64)
  policyId:  32 bytes  (policy identifier)
```

### Member ID Computation

```
message  = "zkpof-holder-v1:{scope}:{nonce}"
signature = wallet.sign(message)
memberId  = SHA256(signature)
```

Properties:
- **Deterministic**: Same wallet + scope + nonce always produces the same memberId
- **Non-invertible**: Cannot recover the wallet address from the memberId
- **Unlinkable**: Different scopes produce different memberIds for the same wallet

### State Proof Verification (EIP-1186)

The system uses Ethereum's native `eth_getProof` RPC method to obtain cryptographic proofs of account state:

```
1. User calls: eth_getProof(address, [], blockNumber)

2. Node returns: {
     accountProof: [RLP-encoded MPT nodes...],
     balance: "0x...",
     nonce: "0x...",
     ...
   }

3. Agent verifies:
   a. Fetch state root for the given block
   b. Compute trie key = keccak256(address)
   c. Walk the MPT proof nodes from root to leaf
   d. Verify the proved account's balance >= threshold
```

### Smart Contract Interface

```solidity
interface ISolvencyOracle {
    /// Verify a member is included in a solvency root with given status.
    function verifyMember(
        bytes32 policyId,
        bytes32 memberId,
        uint8 status,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool);

    /// Convenience: verify member is solvent (status=1).
    function isMemberSolvent(
        bytes32 policyId,
        bytes32 memberId,
        uint64 epoch,
        bytes32[] calldata merkleProof,
        uint256 leafIndex,
        uint256 rootIndex
    ) external view returns (bool);
}
```

### Two Verification Modes

| Mode | Root Publication | Security Model | Gas Cost | Speed |
|------|-----------------|----------------|----------|-------|
| **Trusted** | EIP-712 operator signature | Trust the operator | ~100k gas | Instant |
| **ZK** | SP1 Groth16 proof | Trustless (ZK verified) | ~270k gas | Minutes (proving time) |

Both modes produce the same Merkle root structure, so relying protocols use the same `verifyMember()` interface regardless of mode.

---

## 10. Glossary

| Term | Definition |
|------|-----------|
| **Member** | A user enrolled in a solvency policy |
| **Member ID** | Privacy-preserving identifier: SHA256(enrollment signature) |
| **Policy** | A set of rules defining what balance threshold to check, how often, and on which chain |
| **Epoch** | A time interval (measured in blocks) at which the solvency state is updated |
| **Merkle Root** | A single 32-byte hash summarizing the solvency status of ALL members in a policy |
| **Merkle Proof** | A list of sibling hashes proving a specific member is included in the Merkle root |
| **Solvency Agent** | The off-chain middleware that processes proofs and publishes roots |
| **EIP-1186** | Ethereum standard for `eth_getProof` - cryptographic proof of account state |
| **MPT** | Merkle-Patricia Trie - Ethereum's state storage data structure |
| **SP1** | Succinct's zkVM - a zero-knowledge virtual machine for writing ZK circuits in Rust |
| **Trusted Mode** | Verification via operator's EIP-712 signature (fast, requires trust) |
| **ZK Mode** | Verification via SP1 zero-knowledge proof (slower, trustless) |
| **Root TTL** | Time-to-live for a published root - how long it remains valid for verification |
| **Scope** | A string used to generate unique Member IDs per policy (enables unlinkability) |

---

*ZK Proof of Funds is open-source software. For technical documentation, see ARCHITECTURE.md and the project repository.*
