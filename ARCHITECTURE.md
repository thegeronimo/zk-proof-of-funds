# ZK Proof of Funds — Solvency Agent Architecture

## 1. Objective

A **middleware-driven solvency attestation system** for EVM networks. A holder enrolls once (proves wallet control + initial threshold), then a **Solvency Agent** middleware continuously monitors enrolled members, batches their status into a single on-chain Merkle root per policy per epoch, and serves membership proofs to relying protocols on demand.

**Key properties:**
- **One-time enrollment**: User signs once to prove wallet control, never interacts again
- **Zero user involvement at use time**: Middleware handles all monitoring and proof generation
- **One ZK proof per policy per epoch**: Batch proof covers ALL members — cost amortized
- **Relying protocols check membership via Merkle proof**: `verifyMember(memberId, merkleProof, rootIndex)` — middleware supplies the proof, user just signs the tx
- **No challenge mechanism needed**: Middleware simply sets status=0 in next epoch if balance drops

### Use Cases
- DeFi protocol access gating (prove >$10k in assets for premium features)
- OTC/P2P trading counterparty solvency verification
- DAO governance qualification with automatic revocation on balance drop
- KYC-lite compliance (prove solvency without full disclosure)
- Credit/lending pre-qualification with continuous monitoring

### Design Principles
- **Privacy-first**: No data leakage beyond "member is solvent for policy X"
- **EVM-native**: On-chain verification via Solidity, leveraging BN254 precompiles
- **Non-custodial**: Uses EIP-1186 state proofs — no trusted third party holds funds
- **Continuous**: Middleware monitors automatically; no user action at verification time
- **Simple**: Simplest reliable proving system for EVM (SP1)

---

## 2. Key Design Choice: Middleware-Served Merkle Proofs

The critical design decision: **the Solvency Agent middleware provides the Merkle membership proof, not the user**.

### Flow at Verification Time

```
1. DApp calls Solvency Agent API:
   GET /proof/{policyId}/{memberId}

2. Agent returns:
   { merkleProof: [...], leafIndex: N, rootIndex: M, status: 1 }

3. DApp includes proof in smart contract call:
   protocol.doSomething(memberId, merkleProof, rootIndex)

4. Protocol's contract calls:
   oracle.verifyMember(policyId, memberId, merkleProof, rootIndex)
   → returns true/false
```

**Why this works:**
- User enrolled once and never needs to interact with the solvency system again
- The dApp (or SDK) fetches the proof from the agent transparently
- The on-chain contract just verifies a Merkle inclusion proof — cheap and simple
- No ZK proof verification at use time — only when the agent updates the root

---

## 3. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ON-CHAIN (EVM)                            │
│                                                                  │
│  ┌─────────────────────────┐  ┌───────────────────────────────┐  │
│  │  SolvencyRootOracle.sol │  │    PolicyRegistry.sol         │  │
│  │                         │  │                               │  │
│  │  - Per-policy Merkle    │  │  - Policy definitions         │  │
│  │    roots + epochs       │  │  - Threshold, chain, TTL      │  │
│  │  - verifyMember()       │  │  - Operator authorization     │  │
│  │  - ZK proof verification│  │                               │  │
│  │    on root updates only │  │                               │  │
│  └─────────────────────────┘  └───────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                          ▲                    ▲
                          │ updateRoot()       │ registerPolicy()
                          │ (with ZK proof)    │
┌─────────────────────────┼────────────────────┼───────────────────┐
│                    SOLVENCY AGENT (Off-Chain Middleware)          │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌──────────────┐   │
│  │ Scheduler│  │RPC       │  │Proof       │  │Chain         │   │
│  │          │──▶│Fetcher   │──▶│Workers     │──▶│Publisher     │   │
│  │ (cron/   │  │(EIP-1186)│  │(SP1 batch  │  │(submit tx)   │   │
│  │  block)  │  │          │  │ prover)    │  │              │   │
│  └──────────┘  └──────────┘  └────────────┘  └──────────────┘   │
│                                                                  │
│  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────┐   │
│  │ API Gateway      │  │ Merkle Proof      │  │  Database    │   │
│  │ (Axum)           │  │ Service           │  │  (members,   │   │
│  │ - enrollment     │  │ - serve proofs    │  │   epochs,    │   │
│  │ - status         │  │ - per member      │  │   trees)     │   │
│  │ - admin          │  │                   │  │              │   │
│  └──────────────────┘  └───────────────────┘  └──────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                          ▲
                          │ Enroll / Query
┌─────────────────────────┼────────────────────────────────────────┐
│                    USER / RELYING PROTOCOL                        │
│                                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐          │
│  │  Wallet   │  │  DApp/SDK    │  │  Relying Protocol │          │
│  │ (sign     │  │  (fetches    │  │  (calls oracle    │          │
│  │  once)    │  │   proof)     │  │   .verifyMember)  │          │
│  └──────────┘  └──────────────┘  └───────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Core Concepts

### 4.1 memberId / holderTag

A **privacy-preserving identifier** that binds the member to their enrollment without revealing their address.

```
memberId = SHA256(signature)
where signature = wallet.sign("zkpof-holder-v1:{scope}:{nonce}")
```

- **Deterministic**: Same wallet + scope + nonce always produces the same memberId
- **Unlinkable across scopes**: Different scopes produce different memberIds
- **Non-invertible**: Cannot recover the address from the memberId
- The nonce is provided by the agent at enrollment time

### 4.2 watchTarget

The Ethereum address the middleware monitors for balance changes. The member reveals this to the agent at enrollment time.

**Privacy trade-off**: The Solvency Agent knows which addresses it monitors. This is the same trust model as a custodial service — but the agent never has control of funds. The key privacy guarantee is: **relying protocols and other members never learn the address**.

### 4.3 Epoch Updates

The core loop of the Solvency Agent:

```
Every epoch (configurable per policy — e.g., every 100 blocks):
  1. Pick a recent block B (within 256-block blockhash window)
  2. For each enrolled member of this policy:
     a. Fetch eth_getProof(watchTarget, [], B) via EIP-1186
     b. Determine status: 1 if balance >= threshold, 0 otherwise
  3. Build Merkle tree: leaf_i = SHA256(memberId_i || status_i || epoch || policyId)
  4. Generate ONE SP1 proof covering the entire batch:
     - Proves all EIP-1186 proofs were verified correctly
     - Proves the Merkle root was computed correctly from the verified statuses
  5. Submit updateRoot(policyId, newRoot, epoch, blockNumber, zkProof) on-chain
  6. Store the Merkle tree for serving individual proofs
```

### 4.4 Solvency Merkle Tree

Each policy maintains a binary Merkle tree where:

```
leaf = SHA256(memberId || status || epoch || policyId)
  - memberId: 32 bytes (holder's privacy-preserving ID)
  - status:   1 byte (1 = solvent, 0 = insolvent/removed)
  - epoch:    8 bytes (current epoch number)
  - policyId: 32 bytes (which policy this leaf is for)
```

The root of this tree is published on-chain with a ZK proof attesting to its correctness.

### 4.5 Membership Verification

When a relying protocol needs to check if a member is solvent:

```solidity
// On-chain: O(log N) Merkle proof verification
function verifyMember(
    bytes32 policyId,
    bytes32 memberId,
    uint8 status,
    bytes32[] calldata merkleProof,
    uint256 rootIndex
) external view returns (bool) {
    bytes32 root = roots[policyId][rootIndex];
    require(root != bytes32(0), "No root");
    require(!isExpired(policyId, rootIndex), "Root expired");

    bytes32 leaf = sha256(abi.encodePacked(memberId, status, epochs[policyId][rootIndex], policyId));
    return verifyMerkleProof(merkleProof, root, leaf);
}
```

---

## 5. On-Chain Contracts

### 5.1 PolicyRegistry.sol

Stores policy definitions. Each policy specifies what the verifier wants proven.

```solidity
contract PolicyRegistry {
    struct Policy {
        uint256 thresholdWei;           // Minimum balance in wei
        address tokenAddress;            // address(0) = native ETH
        uint64  chainId;                 // EVM chain ID
        uint64  epochLengthBlocks;       // Blocks between epoch updates
        uint64  maxBlockAge;             // Max age of state proof (≤256 for blockhash)
        uint64  rootTTLBlocks;           // How long a published root stays valid
        address operator;                // Authorized Solvency Agent address
        string  scope;                   // For memberId scoping / unlinkability
        string  description;             // Human-readable
        bool    active;
    }

    mapping(bytes32 => Policy) public policies;

    event PolicyCreated(bytes32 indexed policyId, address operator);
    event PolicyUpdated(bytes32 indexed policyId);
    event PolicyDeactivated(bytes32 indexed policyId);

    function createPolicy(Policy calldata policy) external returns (bytes32 policyId);
    function updatePolicy(bytes32 policyId, Policy calldata policy) external;
    function deactivatePolicy(bytes32 policyId) external;
    function getPolicy(bytes32 policyId) external view returns (Policy memory);
}
```

### 5.2 SolvencyRootOracle.sol

The core on-chain contract. Stores per-policy Merkle roots and verifies membership proofs.

```solidity
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

contract SolvencyRootOracle {
    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable programVKey;   // SP1 batch program verification key

    struct RootEntry {
        bytes32 root;           // Merkle root of the solvency tree
        uint256 epoch;          // Epoch number
        uint256 blockNumber;    // Ethereum block the proofs reference
        uint256 publishedAt;    // Block when this root was published
        uint256 memberCount;    // Number of members in the tree
    }

    // policyId => array of root entries (append-only)
    mapping(bytes32 => RootEntry[]) public rootHistory;

    // policyId => latest root index
    mapping(bytes32 => uint256) public latestRootIndex;

    // Events
    event RootUpdated(
        bytes32 indexed policyId,
        uint256 indexed epoch,
        bytes32 root,
        uint256 blockNumber,
        uint256 memberCount
    );

    /// @notice Called by the Solvency Agent after each epoch.
    /// @dev Verifies the SP1 proof, then stores the new root.
    function updateRoot(
        bytes32 policyId,
        bytes32 newRoot,
        uint256 epoch,
        uint256 blockNumber,
        uint256 memberCount,
        bytes calldata proofBytes,
        bytes calldata publicValues
    ) external {
        Policy memory policy = policyRegistry.getPolicy(policyId);
        require(msg.sender == policy.operator, "Not operator");
        require(policy.active, "Policy inactive");

        // Verify block freshness
        require(block.number - blockNumber <= policy.maxBlockAge, "Block too old");
        require(blockhash(blockNumber) != bytes32(0), "Blockhash unavailable");

        // Verify SP1 proof — ensures all balances were correctly checked
        // and Merkle root was correctly derived
        sp1Verifier.verifyProof(programVKey, publicValues, proofBytes);

        // Decode and validate public values match the submitted parameters
        // (stateRoot, policyId, epoch, newRoot, threshold, memberCount, blockNumber, chainId)
        // ... decode and assert consistency ...

        // Store root
        rootHistory[policyId].push(RootEntry({
            root: newRoot,
            epoch: epoch,
            blockNumber: blockNumber,
            publishedAt: block.number,
            memberCount: memberCount
        }));
        latestRootIndex[policyId] = rootHistory[policyId].length - 1;

        emit RootUpdated(policyId, epoch, newRoot, blockNumber, memberCount);
    }

    /// @notice Verify that a member is included in a solvency root.
    /// @dev Called by relying protocols to gate access.
    function verifyMember(
        bytes32 policyId,
        bytes32 memberId,
        uint8 status,
        uint256 epoch,
        bytes32[] calldata merkleProof,
        uint256 rootIndex
    ) external view returns (bool) {
        RootEntry storage entry = rootHistory[policyId][rootIndex];
        require(entry.root != bytes32(0), "Root does not exist");

        // Check root hasn't expired
        Policy memory policy = policyRegistry.getPolicy(policyId);
        require(
            block.number <= entry.publishedAt + policy.rootTTLBlocks,
            "Root expired"
        );

        // Reconstruct leaf and verify Merkle proof
        bytes32 leaf = sha256(abi.encodePacked(memberId, status, epoch, policyId));
        return _verifyMerkleProof(merkleProof, entry.root, leaf);
    }

    /// @notice Convenience: verify member is solvent (status=1) in the latest root.
    function isMemberSolvent(
        bytes32 policyId,
        bytes32 memberId,
        bytes32[] calldata merkleProof
    ) external view returns (bool) {
        uint256 idx = latestRootIndex[policyId];
        RootEntry storage entry = rootHistory[policyId][idx];
        // ... TTL check ...
        bytes32 leaf = sha256(abi.encodePacked(memberId, uint8(1), entry.epoch, policyId));
        return _verifyMerkleProof(merkleProof, entry.root, leaf);
    }
}
```

**Gas costs (estimated):**
- `updateRoot()`: ~270k (SP1 Groth16 verification) + ~50k (storage) ≈ **~320k gas** per epoch per policy
- `verifyMember()`: ~5-10k gas (Merkle proof verification, log₂(N) hashes) — **very cheap**

---

## 6. ZK Program (SP1): Batch Solvency Root Updater

The SP1 program proves that a batch of EIP-1186 state proofs were verified correctly and that the published Merkle root correctly reflects the verified balances.

### 6.1 Public Outputs (committed via `sp1_zkvm::io::commit`)

| Index | Field | Type | Description |
|-------|-------|------|-------------|
| 0 | `state_root` | `[u8; 32]` | Ethereum state root the proofs are anchored to |
| 1 | `policy_id` | `[u8; 32]` | Which policy this batch covers |
| 2 | `epoch` | `u64` | Epoch number |
| 3 | `solvency_root` | `[u8; 32]` | Computed Merkle root of the solvency tree |
| 4 | `threshold_wei` | `u64` | Balance threshold for this policy |
| 5 | `member_count` | `u32` | Number of members in the tree |
| 6 | `block_number` | `u64` | Block number for the state proofs |
| 7 | `chain_id` | `u64` | EVM chain ID |

### 6.2 Private Inputs (read via `sp1_zkvm::io::read`)

For each member in the batch:
- `member_id: [u8; 32]` — the member's privacy-preserving ID
- `watch_target: [u8; 20]` — the Ethereum address to check
- `mpt_proof: Vec<Vec<u8>>` — EIP-1186 account proof nodes
- `expected_balance: u64` — the balance extracted from the proof (for consistency check)

Global inputs:
- `state_root: [u8; 32]` — expected Ethereum state root
- `policy_id: [u8; 32]`
- `epoch: u64`
- `threshold_wei: u64`
- `block_number: u64`
- `chain_id: u64`

### 6.3 Program Logic (Pseudocode)

```rust
#[sp1_zkvm::entrypoint]
fn main() {
    // 1. Read global inputs
    let state_root: [u8; 32] = sp1_zkvm::io::read();
    let policy_id: [u8; 32] = sp1_zkvm::io::read();
    let epoch: u64 = sp1_zkvm::io::read();
    let threshold_wei: u64 = sp1_zkvm::io::read();
    let block_number: u64 = sp1_zkvm::io::read();
    let chain_id: u64 = sp1_zkvm::io::read();
    let member_count: u32 = sp1_zkvm::io::read();

    // 2. Process each member
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(member_count as usize);

    for _ in 0..member_count {
        let member_id: [u8; 32] = sp1_zkvm::io::read();
        let watch_target: [u8; 20] = sp1_zkvm::io::read();
        let mpt_proof: Vec<Vec<u8>> = sp1_zkvm::io::read();

        // 2a. Verify EIP-1186 proof against state root
        let proven_balance = mpt::verify_account_balance(
            &mpt_proof, &state_root, &watch_target
        );

        // 2b. Determine status
        let status: u8 = if proven_balance >= threshold_wei { 1 } else { 0 };

        // 2c. Compute leaf
        let leaf = sha256(&[
            &member_id[..],
            &[status],
            &epoch.to_be_bytes(),
            &policy_id[..],
        ]);
        leaves.push(leaf);
    }

    // 3. Build Merkle tree and compute root
    let solvency_root = merkle::compute_root(&leaves);

    // 4. Commit public outputs
    sp1_zkvm::io::commit(&state_root);
    sp1_zkvm::io::commit(&policy_id);
    sp1_zkvm::io::commit(&epoch);
    sp1_zkvm::io::commit(&solvency_root);
    sp1_zkvm::io::commit(&threshold_wei);
    sp1_zkvm::io::commit(&member_count);
    sp1_zkvm::io::commit(&block_number);
    sp1_zkvm::io::commit(&chain_id);
}
```

### 6.4 Proving Cost

SP1 proving scales with program execution steps. For N members:
- Each member requires: MPT proof verification (~10-50k steps) + SHA-256 hashing (~500 steps)
- Merkle tree construction: N * log₂(N) SHA-256 hashes
- Estimated: ~100k steps per member → a batch of 100 members ≈ 10M steps
- SP1 can handle this with GPU proving or the Succinct Prover Network
- **On-chain cost is constant**: ~270k gas regardless of batch size (single Groth16 proof)

---

## 7. Solvency Agent: Functional Requirements

### FR1: Member Enrollment

```
POST /enroll
{
  "policyId": "0x...",
  "walletAddress": "0x...",        // watchTarget — revealed to agent
  "signature": "0x...",            // Proves wallet control
  "signedMessage": "zkpof-holder-v1:{scope}:{nonce}"
}

Response:
{
  "memberId": "0x...",             // SHA256(signature)
  "status": "enrolled",
  "effectiveEpoch": 42            // First epoch where member appears in tree
}
```

**Enrollment checks:**
1. Verify `ecrecover(signedMessage, signature) == walletAddress`
2. Fetch current balance via `eth_getBalance(walletAddress)` or `eth_getProof`
3. Verify balance >= policy threshold
4. Compute `memberId = SHA256(signature)`
5. Store member in database; include in next epoch update

### FR2: Epoch Update Loop

The core background process:

```
loop {
    for each active policy:
        if current_block >= last_epoch_block + policy.epochLengthBlocks:
            1. Select reference block B (recent, within 256-block window)
            2. For each enrolled member:
               - Fetch eth_getProof(watchTarget, [], B)
               - Record balance and status
            3. Build Merkle tree from member statuses
            4. Generate SP1 batch proof
            5. Submit updateRoot() transaction on-chain
            6. Store tree for Merkle proof serving
            7. Fire webhooks for status changes
    sleep(poll_interval)
}
```

### FR3: Serve Membership Proofs

```
GET /proof/{policyId}/{memberId}

Response:
{
  "memberId": "0x...",
  "policyId": "0x...",
  "status": 1,
  "epoch": 42,
  "rootIndex": 5,
  "merkleProof": ["0x...", "0x...", ...],
  "leafIndex": 17,
  "root": "0x...",
  "blockNumber": 19500000
}
```

This is what relying protocols (or their SDKs) call to get the data needed for `verifyMember()`.

### FR4: Transaction Builder

```
GET /tx/{policyId}/{memberId}

Response:
{
  "to": "0x... (SolvencyRootOracle address)",
  "data": "0x... (encoded verifyMember calldata)",
  "gasEstimate": 45000
}
```

Convenience endpoint: returns a pre-built transaction that a dApp can include in a multicall or use directly.

### FR5: Status API

```
GET /status/{policyId}/{memberId}

Response:
{
  "memberId": "0x...",
  "policyId": "0x...",
  "currentStatus": 1,          // 1 = solvent, 0 = insolvent
  "lastCheckedBlock": 19500000,
  "lastCheckedEpoch": 42,
  "enrolledAt": "2025-06-01T...",
  "watchTarget": null           // Never exposed to external callers
}
```

---

## 8. Non-Functional Requirements

| Requirement | Target | Notes |
|------------|--------|-------|
| Correctness | 100% of status bits match on-chain state | ZK proof guarantees this |
| Availability | 99.9% uptime for proof serving | Proofs are static per epoch — cacheable |
| Epoch latency | < 10 minutes from block selection to on-chain root | Depends on SP1 proving speed |
| Proof serving latency | < 100ms p99 | Simple DB lookup + tree traversal |
| Security | Agent compromise doesn't steal funds | Non-custodial: agent only reads state |
| Privacy | Watch targets never exposed via API | Only memberId visible externally |

---

## 9. Agent Internal Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SOLVENCY AGENT                        │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │              API Gateway (Axum)                    │    │
│  │  POST /enroll                                     │    │
│  │  GET  /proof/{policyId}/{memberId}                │    │
│  │  GET  /status/{policyId}/{memberId}               │    │
│  │  GET  /tx/{policyId}/{memberId}                   │    │
│  │  POST /admin/policy (create/update)               │    │
│  │  GET  /admin/members/{policyId}                   │    │
│  │  GET  /health                                     │    │
│  └────────────────────┬─────────────────────────────┘    │
│                       │                                   │
│  ┌────────────────────▼─────────────────────────────┐    │
│  │              Core Services                         │    │
│  │                                                    │    │
│  │  ┌────────────┐  ┌─────────────┐  ┌───────────┐  │    │
│  │  │ Scheduler  │  │ RPC Fetcher │  │  Proof    │  │    │
│  │  │            │  │             │  │  Workers  │  │    │
│  │  │ - epoch    │  │ - eth_get   │  │  - SP1    │  │    │
│  │  │   trigger  │──▶│   Proof    │──▶│    batch  │  │    │
│  │  │ - per-     │  │ - balance   │  │    prover │  │    │
│  │  │   policy   │  │   check    │  │  - tree   │  │    │
│  │  │   timing   │  │ - retry    │  │    build  │  │    │
│  │  └────────────┘  └─────────────┘  └─────┬─────┘  │    │
│  │                                          │        │    │
│  │  ┌──────────────┐  ┌────────────────────▼──────┐  │    │
│  │  │ Merkle Proof │  │   Chain Publisher         │  │    │
│  │  │ Service      │  │                           │  │    │
│  │  │              │◀─│   - submit updateRoot()   │  │    │
│  │  │ - per-member │  │   - gas management        │  │    │
│  │  │   proofs     │  │   - tx confirmation       │  │    │
│  │  │ - cached     │  │   - nonce management      │  │    │
│  │  └──────────────┘  └───────────────────────────┘  │    │
│  └────────────────────────────────────────────────────┘    │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │              Database (SQLite/Postgres)            │    │
│  │                                                    │    │
│  │  - members: memberId, watchTarget, policyId,      │    │
│  │             status, enrolledAt                     │    │
│  │  - epochs: policyId, epoch, blockNumber, root,    │    │
│  │            proofBytes, memberCount, publishedAt   │    │
│  │  - merkle_trees: epoch, policyId, leaves (JSON),  │    │
│  │                   for reconstructing proofs        │    │
│  │  - webhooks: url, policyId, events                │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Role |
|-----------|------|
| **API Gateway** | HTTP endpoints for enrollment, proof serving, status, admin |
| **Scheduler** | Triggers epoch updates per policy based on block intervals |
| **RPC Fetcher** | Fetches EIP-1186 state proofs for all members in a batch |
| **Proof Workers** | Generates SP1 batch proofs (can be distributed / use Succinct Network) |
| **Chain Publisher** | Submits `updateRoot()` transactions, handles gas, confirms inclusion |
| **Merkle Proof Service** | Stores complete Merkle trees, serves per-member inclusion proofs |
| **Database** | Persistent storage for members, epochs, trees, webhooks |

---

## 10. Algorithms

### 10.1 Block Selection

```
fn select_reference_block(policy: &Policy) -> u64 {
    let current = provider.get_block_number();
    // Pick a block that's recent but gives us time to generate proofs
    // before the blockhash expires (256 block window)
    let target = current - policy.max_block_age / 2;
    // Ensure it's within the blockhash window
    assert!(current - target < 256);
    target
}
```

### 10.2 Blockhash Window Constraint

- `blockhash(B)` only works for the last 256 blocks (~51 minutes at 12s/block)
- `maxBlockAge` in the policy MUST be ≤ 256
- The agent must complete proving and publish the root before `B` falls outside the window
- Mitigation: choose a block that's `maxBlockAge / 2` in the past, giving a buffer for proving time
- Future: EIP-2935 will extend the blockhash window; architecture is forward-compatible

### 10.3 Retry Strategy

```
For each RPC fetch:
  - Retry up to 3 times with exponential backoff
  - On persistent failure: mark member as "fetch_failed", exclude from epoch
  - Alert via webhook
  - Retry in next epoch

For SP1 proving:
  - Retry up to 2 times
  - On failure: skip epoch, alert operator
  - Proofs from previous epoch remain valid until rootTTL expires

For chain submission:
  - Retry with gas bump if tx isn't mined within 3 blocks
  - Nonce management: track pending nonces
```

### 10.4 Member Churn

- **New member**: Added to the tree in the next epoch after enrollment
- **Balance drop**: status flips to 0 in the next epoch — member stays in tree with status=0
- **Voluntary exit**: Member removed from tree in next epoch. Agent can provide an API endpoint for this.
- **Tree rebalancing**: Not needed — Merkle tree is rebuilt from scratch each epoch

---

## 11. External API Specification

### 11.1 Admin Endpoints

```
POST   /admin/policy              Create a new policy
PUT    /admin/policy/{policyId}   Update policy parameters
DELETE /admin/policy/{policyId}   Deactivate a policy
GET    /admin/members/{policyId}  List all members for a policy
GET    /admin/epochs/{policyId}   List epoch history
POST   /admin/webhook             Register a webhook
```

### 11.2 Integrator Endpoints

```
POST   /enroll                          Enroll a new member
GET    /proof/{policyId}/{memberId}     Get Merkle membership proof
GET    /tx/{policyId}/{memberId}        Get pre-built verify transaction
GET    /status/{policyId}/{memberId}    Get member status
GET    /policy/{policyId}               Get policy details
```

### 11.3 Webhooks

```json
POST {webhook_url}
{
  "event": "member.status_changed",
  "policyId": "0x...",
  "memberId": "0x...",
  "oldStatus": 1,
  "newStatus": 0,
  "epoch": 43,
  "blockNumber": 19500100,
  "timestamp": "2025-07-01T12:00:00Z"
}
```

Events:
- `member.enrolled` — new member added
- `member.status_changed` — member status changed (solvent ↔ insolvent)
- `epoch.completed` — new root published on-chain
- `epoch.failed` — epoch update failed (alert)

---

## 12. Trusted Mode (Fast Path)

For an immediate MVP or for policies where ZK overhead isn't justified, the agent can operate in **trusted mode** using EIP-712 signed assertions instead of ZK proofs.

### How It Works

```
Instead of:
  1. Generate SP1 batch proof (minutes)
  2. Verify on-chain via Groth16 (~270k gas)

Trusted mode does:
  1. Agent signs an EIP-712 typed data assertion:
     {
       policyId, memberId, status, epoch,
       blockNumber, stateRoot
     }
  2. On-chain: ecrecover the signature, check it's from the authorized operator
  3. Same Merkle root structure, but root is posted with a signature instead of a ZK proof
```

### Trust Model

- Requires trusting the Solvency Agent operator to be honest
- Suitable for: internal tools, low-stakes policies, development/testing
- Can be mixed: some policies use ZK, others use trusted mode
- Upgrade path: switch a policy from trusted → ZK mode without changing the relying protocol integration

### On-Chain Changes for Trusted Mode

```solidity
function updateRootTrusted(
    bytes32 policyId,
    bytes32 newRoot,
    uint256 epoch,
    uint256 blockNumber,
    uint256 memberCount,
    bytes calldata operatorSignature  // EIP-712 signature
) external {
    Policy memory policy = policyRegistry.getPolicy(policyId);
    require(policy.trustedMode, "ZK mode required");

    // Verify operator signature via EIP-712
    bytes32 digest = _hashTypedData(policyId, newRoot, epoch, blockNumber, memberCount);
    address signer = ECDSA.recover(digest, operatorSignature);
    require(signer == policy.operator, "Invalid operator signature");

    // Store root (same as ZK mode)
    rootHistory[policyId].push(RootEntry({...}));
}
```

---

## 13. Proving System: SP1 (Succinct)

### Why SP1?

| Criteria | SP1 | Halo2 | Groth16 (circom) | Noir |
|----------|-----|-------|------------------|------|
| Circuit language | **Standard Rust** | Rust (low-level DSL) | Circom DSL | Rust-like DSL |
| Dev complexity | Very Low | Very High | Medium | Low |
| On-chain gas | ~270k | ~300-500k+ | ~190k | ~300-500k |
| Solidity verifier | Audited (Veridise) | Fragile | Production | Pre-1.0 |
| Batch proving | Natural (iterate in Rust) | Complex (circuit design per batch size) | Not practical | Possible |
| MPT in circuit | Use existing Rust libs | Expensive Keccak gadgets | Very expensive | Expensive |

**SP1 is ideal for the batch model** because:
1. The batch proof iterates over N members in a standard Rust loop — no circuit re-design needed when N changes
2. MPT verification uses existing Rust libraries directly — no Keccak circuit gadgets
3. SHA-256 has a precompile in SP1 — fast hashing for Merkle tree construction
4. Single Groth16 proof regardless of batch size — constant on-chain cost

### How SP1 Works

```
Standard Rust Program
        │
        ▼
   RISC-V Compilation (sp1-build)
        │
        ▼
   STARK Proof of Execution
        │
        ▼
   Recursive STARK Compression
        │
        ▼
   Groth16 Wrap (gnark, BN254)  ← ~270k gas on-chain
        │
        ▼
   Solidity Verification (ISP1Verifier)
```

---

## 14. Crate / Module Structure

```
zk_proof_of_funds/
├── Cargo.toml                     # Workspace root
├── ARCHITECTURE.md                # This document
├── EXECUTION_PLAN.md              # Phased implementation plan
│
├── program/                       # SP1 ZK program (compiles to RISC-V)
│   ├── Cargo.toml                 #   NOT in workspace — built with `cargo prove build`
│   └── src/
│       ├── main.rs                # SP1 batch solvency root updater
│       ├── mpt.rs                 # MPT proof verification (EIP-1186)
│       └── merkle.rs              # Solvency Merkle tree construction
│
├── crates/
│   ├── common/                    # Shared types & utilities
│   │   └── src/
│   │       ├── lib.rs
│   │       └── types.rs           # Member, EpochRoot, Policy, MerkleProof, etc.
│   │
│   ├── agent/                     # Solvency Agent middleware
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── scheduler.rs       # Epoch trigger logic
│   │       ├── rpc_fetcher.rs     # EIP-1186 state proof fetching
│   │       ├── proof_worker.rs    # SP1 batch proof generation
│   │       ├── chain_publisher.rs # On-chain tx submission
│   │       ├── merkle_service.rs  # Merkle tree storage & proof serving
│   │       ├── enrollment.rs      # Member enrollment flow
│   │       └── db.rs              # Database operations
│   │
│   ├── backend/                   # HTTP API server (Axum)
│   │   └── src/
│   │       ├── main.rs            # Axum server setup
│   │       └── routes/
│   │           ├── enroll.rs      # POST /enroll
│   │           ├── proof.rs       # GET /proof/{policyId}/{memberId}
│   │           ├── status.rs      # GET /status/{policyId}/{memberId}
│   │           ├── tx.rs          # GET /tx/{policyId}/{memberId}
│   │           ├── admin.rs       # Admin endpoints
│   │           ├── webhook.rs     # Webhook management
│   │           └── health.rs      # GET /health
│   │
│   └── wasm/                      # WASM bindings (for SDK/browser integration)
│       ├── src/lib.rs
│       └── Cargo.toml
│
├── contracts/                     # Solidity smart contracts (Foundry)
│   ├── src/
│   │   ├── SolvencyRootOracle.sol # Core: root storage + member verification
│   │   ├── PolicyRegistry.sol     # Policy definitions
│   │   └── MerkleVerifier.sol     # Merkle proof verification library
│   ├── test/
│   │   ├── SolvencyRootOracle.t.sol
│   │   ├── PolicyRegistry.t.sol
│   │   └── Integration.t.sol
│   └── foundry.toml
│
├── web/                           # React frontend (future)
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
│
└── config/
    └── policies.json              # Default policy definitions
```

### Key Structural Changes from Previous Architecture

- **`crates/agent/`** replaces `crates/prover/` + `crates/verifier/` — the middleware model consolidates proving and verification into a single service
- **`SolvencyRootOracle.sol`** replaces `ZkPoFVerifier.sol` + `AttestationRegistry.sol` + `ChallengeManager.sol` — batch Merkle root model is much simpler
- **No `MPTVerifier.sol`** for challenges — on-chain MPT verification is no longer needed (middleware handles it off-chain via ZK)
- **No `ChallengeManager.sol`** — middleware simply updates the member's status in the next epoch

---

## 15. Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| ZK Proving System | **SP1 (Succinct)** | Standard Rust, batch-friendly, ~270k gas |
| Proof Wrapping | Groth16 over BN254 (via SP1) | EVM precompile compatible |
| Hash Functions | SHA-256 | SP1 precompile, used for Merkle tree + memberIds |
| State Proofs | EIP-1186 (eth_getProof) | Non-custodial balance verification |
| Smart Contracts | Solidity + Foundry | Industry standard |
| On-chain Verifier | SP1 ISP1Verifier contracts | Pre-deployed, audited by Veridise |
| Backend | Rust + Axum | Performance, shared types with SP1 program |
| Database | SQLite (dev) / PostgreSQL (prod) | Members, epochs, Merkle trees |
| Ethereum RPC | alloy-rs v1.x | Modern Rust Ethereum library |
| Frontend | React + TypeScript | Ecosystem compatibility |

---

## 16. Security Model

### 16.1 Trust Assumptions

- **Ethereum consensus**: State roots are correct (inherited from L1 security)
- **SP1 proving system**: Sound (STARK + Groth16 wrapping)
- **Solvency Agent**: Trusted to monitor honestly and publish roots on time. Cannot steal funds (non-custodial). Can only withhold updates (liveness failure, not safety failure).
- **RPC provider**: Honest state proof responses (mitigated by ZK proving the proofs are valid against a state root, and on-chain blockhash verification)

### 16.2 Attack Vectors & Mitigations

| Attack | Impact | Mitigation |
|--------|--------|-----------|
| Agent publishes false root | Members appear solvent when not | ZK proof of all balance checks prevents this |
| Agent goes offline | Roots expire, no new epochs | rootTTL provides grace period; alert via monitoring |
| Agent leaks watchTargets | Privacy breach | Encrypt DB; access controls; never expose via API |
| RPC returns false proofs | Incorrect status | ZK proof verifies MPT proofs against state root; blockhash anchoring |
| Replay old Merkle proof | Stale solvency claim | Root TTL expiry; epoch field in leaf prevents cross-epoch replay |
| Sybil enrollment | Fake members in tree | Signature verification ensures wallet control |
| Front-running enrollment | Attacker enrolls with victim's address | No harm — attacker pays for monitoring a public address |

### 16.3 Privacy Guarantees

- **Zero-knowledge**: On-chain, only the Merkle root is visible. Individual balances, addresses, and statuses are hidden.
- **Unlinkability**: Different policies use different scopes → different memberIds → cannot correlate across policies.
- **Agent privacy**: The Solvency Agent knows watchTargets but never exposes them via API. The `watchTarget` field is omitted from all external responses.
- **Relying protocol privacy**: Protocols only see memberIds and Merkle proofs. They cannot determine the underlying address.

### 16.4 What the Agent Can and Cannot Do

| Action | Possible? | Notes |
|--------|-----------|-------|
| Steal user funds | **No** | Non-custodial; agent only reads chain state |
| Falsify a member's status | **No** | ZK proof verifies all balance checks |
| Withhold updates (liveness) | **Yes** | Mitigated by rootTTL + monitoring + alerts |
| Learn member addresses | **Yes** | By design — agent needs watchTarget to monitor |
| Leak addresses to relying protocols | **No** | API never returns watchTarget |

---

## 17. EVM-Specific Considerations

### 17.1 Block Hash Oracle
- `BLOCKHASH` opcode returns hashes for the last 256 blocks (~51 min on mainnet at 12s/block)
- `maxBlockAge` in policy MUST be ≤ 256
- Agent must complete proving and publish root before reference block falls outside window
- Future: EIP-2935 will extend the window; architecture is forward-compatible

### 17.2 L2 Support (Future)
- **Optimistic Rollups** (Optimism, Arbitrum): State roots posted to L1 — agent can verify against L1 contract
- **ZK Rollups** (zkSync, Scroll, Linea): Native state proof verification
- Architecture supports per-chain policies via the `chainId` field

### 17.3 ERC-20 Token Balance
- For ERC-20 tokens, `eth_getProof` needs to include the storage proof for `balanceOf[address]`
- Storage slot computation: `keccak256(abi.encode(address, mapping_slot))`
- The SP1 program handles both account proofs (ETH) and storage proofs (ERC-20) in the same batch

### 17.4 Gas Costs (Estimated)

| Operation | Gas | Frequency |
|-----------|-----|-----------|
| `updateRoot()` with ZK proof | ~320k | Once per epoch per policy |
| `updateRootTrusted()` (trusted mode) | ~50k | Once per epoch per policy |
| `verifyMember()` | ~5-10k | Every time a protocol checks membership |

**Per-member amortized cost** = ~320k / N members per epoch. For 100 members = ~3.2k gas each.

---

## 18. Acceptance Criteria

1. A member can enroll once and be included in solvency roots without further interaction
2. The Solvency Agent automatically detects balance drops and updates status to 0 in the next epoch
3. Relying protocols can verify membership with a single on-chain call (~10k gas)
4. The ZK proof guarantees correctness — a compromised agent cannot falsify statuses
5. Member addresses (watchTargets) are never exposed via the API
6. Epoch updates complete within the blockhash window (256 blocks)
7. The system works in both ZK mode and trusted mode
8. Root TTL prevents stale solvency claims from being used indefinitely

---

## 19. Anti-Patterns to Avoid

- **Per-user ZK proofs at verification time**: Too expensive, too slow, bad UX
- **User-generated Merkle proofs**: User shouldn't need to run anything after enrollment
- **On-chain challenge mechanism**: Unnecessary complexity — middleware just updates the root
- **Bond/slash mechanics**: Not needed when middleware is the sole prover
- **Storing individual attestations on-chain**: A single Merkle root replaces N attestation records
- **Requiring user cooperation for revocation**: Middleware sets status=0 unilaterally
