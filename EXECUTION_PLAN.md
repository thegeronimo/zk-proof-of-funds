# ZK Proof of Funds — Solvency Agent Execution Plan

## Phase Overview

| Phase | Name | Goal | Estimated Effort | Status |
|-------|------|------|-----------------|--------|
| 0 | Foundation | Workspace restructure, SP1 setup, shared types | 2-3 days | ✅ DONE |
| 1 | Trusted Mode MVP | End-to-end flow with EIP-712 signatures (no ZK) | 3-5 days | ✅ DONE |
| 2 | SP1 Batch Program | ZK program for batch solvency root proving | 3-5 days | |
| 3 | Smart Contracts | SolvencyRootOracle + PolicyRegistry on-chain | 3-5 days | ✅ DONE |
| 4 | Agent Core | Scheduler, RPC fetcher, chain publisher | 3-5 days | |
| 5 | Merkle Proof Service + API | Proof serving, enrollment, status endpoints | 2-3 days | |
| 6 | Integration & Testing | End-to-end testing, testnet deployment | 3-5 days | |
| 7 | ERC-20 + L2 Support | Token balance proofs, multi-chain | 3-5 days | |
| 8 | Frontend & SDK | React UI, JavaScript SDK for integrators | 3-5 days | |
| 9 | Production Hardening | Monitoring, CI/CD, audit prep, documentation | 3-5 days | |
| 10 | Privacy V2 | Solvent-set membership + deterministic nullifiers (see PRIVACY_V2.md) | 3-5 days | ✅ DONE (initial) |
| 11 | Privacy V2 Completion | Proven set derivation (Stage B), streak solvency, client tooling | 3-5 days | ✅ DONE |
| 12 | Privacy V2 Follow-ups | ERC-20 proven builds, Stage B.2 completeness, wallet crypto, vkeys | 3-5 days | ✅ DONE |
| 13 | Privacy V2 Closeout | ERC-7524 nullifiers + scopes, on-chain completeness, witness tooling | 3-5 days | ✅ DONE |

**Total estimated effort: 28-46 days**

---

## Phase 0: Foundation ✅ COMPLETE

**Goal**: Restructure the workspace for the Solvency Agent model, install SP1 toolchain, define new shared types.

### Tasks

- [x] **0.1** Restructure Cargo workspace: ✅
  - Replace `crates/prover/` + `crates/verifier/` with `crates/agent/`
  - Keep `crates/common/`, `crates/backend/`
  - Remove stale `crates/circuit/` directory (Halo2 remnant)
  - Update workspace `Cargo.toml` members

- [x] **0.2** Define new shared types in `crates/common/src/types.rs`: ✅
  - `Member` — memberId, watchTarget, policyId, status, enrolledAt
  - `MemberStatus` — enum: Solvent, Insolvent, Pending, FetchFailed
  - `EpochRecord` — policyId, epoch, blockNumber, root, memberCount, publishedAt
  - `Policy` — id, thresholdWei, tokenAddress, chainId, epochLengthBlocks, maxBlockAge, rootTTLBlocks, operator, scope, description, trustedMode
  - `MerkleProofData` — memberId, status, epoch, merkleProof, leafIndex, rootIndex, root
  - `EnrollmentRequest` / `EnrollmentResponse`
  - `SolvencyAssertion` (for trusted mode) — EIP-712 typed data struct
  - Remove old types: ProofBundle, VerifierPublicInputs, VerificationResult, RailId, addr_commitment, nullifier, prover_bond, challenge_bond

- [x] **0.3** Add database dependency (SQLite for dev): ✅
  - Add `rusqlite` or `sqlx` to workspace dependencies
  - Define database schema for members, epochs, merkle_trees, webhooks

- [ ] **0.4** Install SP1 toolchain (deferred — not needed for Trusted Mode MVP):
  ```bash
  curl -L https://sp1up.succinct.xyz | bash
  sp1up
  ```
  - Update `program/Cargo.toml` to uncomment `sp1-zkvm = "4"`
  - Build SP1 program skeleton: `cd program && cargo prove build`

- [x] **0.5** Set up `crates/agent/` skeleton: ✅
  - `lib.rs` — module declarations
  - `scheduler.rs` — stub
  - `rpc_fetcher.rs` — stub
  - `proof_worker.rs` — stub
  - `chain_publisher.rs` — stub
  - `merkle_service.rs` — stub
  - `enrollment.rs` — stub
  - `db.rs` — stub

- [x] **0.6** Write unit tests for new type serialization ✅
  - Member round-trip, Policy serialization, MerkleProofData

- [x] **0.7** Verify workspace compiles: `cargo build && cargo test` ✅

### Deliverables ✅
- Restructured workspace with `crates/agent/` replacing prover/verifier
- New type definitions matching the Solvency Agent architecture
- SP1 toolchain deferred (not needed for Trusted Mode; program skeleton exists)
- 22 tests passing (types + merkle + db)

---

## Phase 1: Trusted Mode MVP ✅ COMPLETE

**Goal**: Build an end-to-end flow using EIP-712 signed assertions instead of ZK proofs. This is the fastest path to a working system and validates the entire architecture without SP1 proving overhead.

### Why Trusted Mode First?
- Validates the full enrollment → monitor → publish → verify flow
- No SP1 proving latency — instant epoch updates
- Tests all API endpoints, database, Merkle tree logic, contract interactions
- Can ship to early testers while ZK mode is built in parallel

### Tasks

- [x] **1.1** Implement enrollment flow in `crates/agent/src/enrollment.rs`: ✅
  - Verify ECDSA signature (ecrecover via alloy EIP-191)
  - Compute `memberId = SHA256(signature)`
  - Store member in database
  - Balance checking deferred to epoch update cycle

- [x] **1.2** Implement Merkle tree construction in `crates/agent/src/merkle_service.rs`: ✅
  - Binary SHA-256 Merkle tree wrapping `crates/common/src/merkle.rs`
  - `build_epoch_tree()` — computes leaves, builds tree, stores in DB as JSON
  - `get_member_proof()` — retrieves stored tree, generates inclusion proof
  - Unit tests: verify proof against root

- [x] **1.3** Implement basic scheduler in `crates/agent/src/scheduler.rs`: ✅
  - `check_epoch_due()` — pure function for epoch triggering
  - `run()` — async loop with `tokio::sync::broadcast` channels and shutdown
  - Per-policy scheduling via `PolicySchedule`

- [x] **1.4** Implement RPC balance fetcher in `crates/agent/src/rpc_fetcher.rs`: ✅
  - `get_balance()`, `get_balance_at_block()`, `get_block_number()`
  - `fetch_member_balances()` — batch with threshold comparison
  - Type-erased provider (`Box<dyn Provider + Send + Sync>`)
  - Mock module for testing

- [x] **1.5** Implement EIP-712 signing for trusted mode in `crates/agent/src/proof_worker.rs`: ✅
  - EIP-712 typed data via `alloy::sol!` macro (`SolvencyRootUpdate`)
  - `sign_trusted_assertion()` — signs with operator key
  - Domain: name="SolvencyRootOracle", version="1"

- [x] **1.5b** Implement epoch recording in `crates/agent/src/chain_publisher.rs`: ✅
  - `record_epoch()` — stores epoch in DB
  - On-chain tx submission deferred to Phase 3/4

- [x] **1.6** Implement database layer in `crates/agent/src/db.rs`: ✅
  - SQLite with rusqlite
  - Tables: members, epochs, merkle_trees, webhooks
  - CRUD operations for all entities

- [x] **1.7** Implement API endpoints in `crates/backend/`: ✅
  - `POST /enroll` — member enrollment with signature verification
  - `GET /proof/{policyId}/{memberId}` — Merkle proof serving
  - `GET /status/{policyId}/{memberId}` — member status
  - `GET /health` — health check
  - `GET /admin/members/{policyId}` — list members
  - `GET /admin/epochs/{policyId}` — epoch history

- [x] **1.8** Write integration tests: ✅
  - Full trusted mode flow: enroll → epoch → proof → verify
  - Status change across epochs (solvent → insolvent → solvent)
  - Multiple independent policies
  - EIP-712 signing verification
  - Scheduler epoch triggering logic
  - Member ID uniqueness (SHA256 determinism + avalanche)

### Deliverables ✅
- Working trusted mode end-to-end flow (51 tests passing)
- All API endpoints functional (6 routes: health, enroll, proof, status, admin/members, admin/epochs)
- Merkle tree construction + proof serving
- Database persistence (SQLite via rusqlite)
- Integration tests passing (6 integration tests covering full flow)
- EIP-712 trusted mode signing working
- 28 agent unit tests + 6 integration tests + 17 common tests = 51 total

---

## Phase 2: SP1 Batch Program

**Goal**: Build the SP1 ZK program that proves a batch of EIP-1186 state proofs and computes the solvency Merkle root.

### Tasks

- [ ] **2.1** Implement MPT verification in `program/src/mpt.rs`:
  - Verify EIP-1186 account proof: MPT nodes + state root + address → account balance
  - Use `alloy-trie` or minimal custom implementation (must compile to RISC-V)
  - RLP decoding of account structure (nonce, balance, storageHash, codeHash)
  - Unit tests with real Ethereum state proof data

- [ ] **2.2** Implement Merkle tree in `program/src/merkle.rs`:
  - Binary SHA-256 Merkle tree (must match off-chain implementation exactly)
  - `compute_root(leaves: &[[u8; 32]]) -> [u8; 32]`
  - Unit tests: verify root matches off-chain computation

- [ ] **2.3** Implement SP1 program entry point in `program/src/main.rs`:
  - Read global inputs (state_root, policy_id, epoch, threshold, block_number, chain_id, member_count)
  - For each member: read inputs, verify MPT proof, determine status, compute leaf
  - Build Merkle tree, compute root
  - Commit public outputs (state_root, policy_id, epoch, solvency_root, threshold, member_count, block_number, chain_id)

- [ ] **2.4** Implement host-side proof generation in `crates/agent/src/proof_worker.rs`:
  - Load SP1 ELF binary
  - Construct SP1 stdin with all member inputs
  - Call `ProverClient::prove()` for Groth16-wrapped proof
  - Support `ProverClient::execute()` for testing (no proof generation)
  - Parse public outputs from proof

- [ ] **2.5** End-to-end test with mock data:
  - Create mock members with mock MPT proofs
  - Generate SP1 proof with `execute()` mode (fast, no real proving)
  - Verify public outputs match expected values
  - Verify Merkle root matches off-chain computation

- [ ] **2.6** Test with real Ethereum state:
  - Fetch real `eth_getProof` for known addresses
  - Feed real MPT proofs into SP1 program
  - Verify proof generation succeeds with real data

### Deliverables
- SP1 batch program that verifies N state proofs and computes solvency Merkle root
- Host-side proof generation working
- Tests with both mock and real Ethereum data
- Benchmarks: proving time vs batch size

---

## Phase 3: Smart Contracts ✅ COMPLETE

**Goal**: Deploy Solidity contracts for on-chain root storage and membership verification.

### Tasks

- [x] **3.1** Set up Foundry project in `contracts/`: ✅
  - foundry.toml with solc 0.8.26, via_ir=true, cancun EVM, optimizer 200 runs
  - OpenZeppelin v5 (Ownable, EIP712, ECDSA)
  - SP1 contracts v6 (ISP1Verifier)
  - forge-std for testing

- [x] **3.2** Implement `PolicyRegistry.sol`: ✅
  - Policy struct: thresholdWei, tokenAddress, chainId, epochLengthBlocks, maxBlockAge, rootTTLBlocks, operator, scope, trustedMode, active
  - `createPolicy()`, `updatePolicy()`, `deactivatePolicy()`, `getPolicy()` with custom errors
  - Owner-only creation, owner-or-operator update, owner-only deactivation
  - Validates maxBlockAge ≤ 256, non-zero epoch length and TTL

- [x] **3.3** Implement `SolvencyRootOracle.sol`: ✅
  - `updateRoot()` — ZK mode: verify SP1 proof via ISP1Verifier, decode + validate public values
  - `updateRootTrusted()` — Trusted mode: verify EIP-712 operator signature (relayers can submit)
  - `verifyMember()` — Merkle proof + TTL + epoch match
  - `isMemberSolvent()` — convenience with status=1
  - `setProgramVKey()` — owner-only (updatable for Phase 2 vkey)
  - RootEntry packed into 2 storage slots (not 5)
  - EIP-712 domain/struct matches Rust proof_worker.rs exactly

- [x] **3.4** Implement `MerkleVerifier.sol` library: ✅
  - `computeLeaf()` — sha256(memberId || status || epoch || policyId) = 73 bytes
  - `verifyProof()` — index-based left/right hashing matching merkle.rs
  - Uses SHA-256 precompile (cheap: ~84 gas per level)

- [ ] **3.5** Generate SP1 verification key (deferred to Phase 2):
  - Placeholder vkey (bytes32(0)) used, updatable via setProgramVKey()

- [x] **3.6** Write Foundry tests: ✅
  - 12 MerkleVerifier tests (leaf computation, 2/3/4/8-leaf trees, invalid proofs)
  - 21 PolicyRegistry tests (CRUD, auth, validation, deactivation)
  - 25 SolvencyRootOracle tests (EIP-712, ZK mode, verifyMember, TTL, epochs, gas)
  - MockSP1Verifier for ZK code path testing

- [ ] **3.7** Deploy to local Anvil fork (deferred to Phase 6 integration testing)

### Deliverables ✅
- 4 Solidity contracts + 1 interface + 1 mock = 6 contract files
- 58 Foundry tests all passing
- Gas benchmarks: updateRootTrusted ~100k, verifyMember ~8k (both well under targets)
- Deploy script ready (contracts/script/Deploy.s.sol)

---

## Phase 4: Agent Core

**Goal**: Build the core Solvency Agent background services that run the epoch update loop.

### Tasks

- [ ] **4.1** Implement full RPC fetcher with EIP-1186 in `crates/agent/src/rpc_fetcher.rs`:
  - `eth_getProof(address, [], blockNumber)` for each member
  - Parse MPT proof nodes from response
  - Extract balance from proven account
  - Batch fetching with rate limiting
  - Retry logic with exponential backoff
  - Handle RPC failures gracefully (mark member as fetch_failed)

- [ ] **4.2** Implement full scheduler in `crates/agent/src/scheduler.rs`:
  - Block-based scheduling per policy
  - Handle multiple concurrent policies
  - Track last epoch block per policy
  - Graceful shutdown
  - Recovery after restart (resume from last completed epoch)

- [ ] **4.3** Implement chain publisher for ZK mode in `crates/agent/src/chain_publisher.rs`:
  - Build `updateRoot()` transaction with proof bytes
  - Gas estimation and management
  - Nonce tracking for sequential transactions
  - Transaction confirmation with retry
  - Gas bump if tx stuck
  - Support both ZK mode and trusted mode

- [ ] **4.4** Wire epoch update pipeline:
  ```
  Scheduler triggers →
    RPC Fetcher (fetch all balances) →
      Proof Worker (generate SP1 proof OR sign EIP-712) →
        Chain Publisher (submit updateRoot tx) →
          Merkle Service (store tree for proof serving) →
            Webhook Service (notify status changes)
  ```

- [ ] **4.5** Implement webhook service:
  - Register webhooks per policy
  - Fire webhooks on: member.enrolled, member.status_changed, epoch.completed, epoch.failed
  - Retry failed webhook deliveries
  - Webhook signing for verification

- [ ] **4.6** Implement configuration:
  - Environment variables / config file for: RPC URL, operator private key, database path, SP1 settings
  - Per-policy configuration from PolicyRegistry (read from chain or config file)

- [ ] **4.7** Integration tests:
  - Full epoch cycle: schedule → fetch → prove → publish → store
  - Multiple policies running concurrently
  - Member status change detection
  - Failure recovery

### Deliverables
- Fully functional Solvency Agent background service
- Epoch update loop running automatically
- Supports both ZK and trusted mode
- Webhook notifications working
- Integration tests passing

---

## Phase 5: Merkle Proof Service + API

**Goal**: Complete the API layer and Merkle proof serving for integrators.

### Tasks

- [ ] **5.1** Complete Merkle proof service in `crates/agent/src/merkle_service.rs`:
  - Store complete Merkle tree per epoch per policy
  - Serve per-member inclusion proofs on demand
  - Cache recent proofs for fast serving
  - Handle requests for historical epochs

- [ ] **5.2** Implement remaining API endpoints:
  - `GET /tx/{policyId}/{memberId}` — pre-built verify transaction
  - `GET /policy/{policyId}` — policy details
  - `POST /admin/policy` — create policy
  - `PUT /admin/policy/{policyId}` — update policy
  - `DELETE /admin/policy/{policyId}` — deactivate policy
  - `GET /admin/members/{policyId}` — list members
  - `GET /admin/epochs/{policyId}` — epoch history
  - `POST /admin/webhook` — register webhook
  - `DELETE /admin/webhook/{webhookId}` — remove webhook

- [ ] **5.3** API authentication and authorization:
  - API keys for integrators
  - Admin endpoints require operator authentication
  - Rate limiting

- [ ] **5.4** API documentation:
  - OpenAPI/Swagger spec
  - Example requests and responses

- [ ] **5.5** Load testing:
  - Benchmark proof serving under load (target: <100ms p99)
  - Benchmark enrollment throughput
  - Benchmark concurrent policy handling

### Deliverables
- Complete REST API matching the architecture spec
- Fast Merkle proof serving (<100ms p99)
- API documentation
- Load test results

---

## Phase 6: Integration & Testing

**Goal**: End-to-end testing on a testnet, hardening, edge cases.

### Tasks

- [ ] **6.1** Deploy contracts to Sepolia testnet:
  - Deploy PolicyRegistry, SolvencyRootOracle
  - Create test policies
  - Verify contracts on Etherscan

- [ ] **6.2** Run Solvency Agent against Sepolia:
  - Enroll real test wallets
  - Run epoch updates against real Ethereum state
  - Verify on-chain roots and Merkle proofs

- [ ] **6.3** Build a test relying protocol contract:
  - Simple contract that gates a function behind `oracle.verifyMember()`
  - Test full flow: enroll → epoch update → dApp calls agent for proof → dApp includes proof in tx → contract verifies

- [ ] **6.4** Edge case testing:
  - Member balance drops below threshold → status=0 in next epoch
  - Member balance recovers → status=1 in following epoch
  - New member enrolled mid-epoch → appears in next epoch
  - RPC failure for some members → graceful degradation
  - SP1 proving failure → epoch skipped, roots still valid from previous epoch
  - Multiple policies with different epoch lengths
  - Large batch (100+ members)
  - Root TTL expiry → verifyMember returns false

- [ ] **6.5** Security testing:
  - Attempt to submit invalid root (should fail ZK verification)
  - Attempt to use expired root (should fail TTL check)
  - Attempt to forge Merkle proof (should fail verification)
  - Unauthorized updateRoot call (should fail operator check)
  - Replay attacks with old proofs

- [ ] **6.6** Performance benchmarks:
  - SP1 proving time vs batch size (10, 50, 100, 500 members)
  - End-to-end epoch latency
  - On-chain gas for updateRoot and verifyMember
  - API response times under load

### Deliverables
- Successful testnet deployment and operation
- All edge cases tested and handled
- Security test results
- Performance benchmarks documented

---

## Phase 7: ERC-20 + L2 Support

**Goal**: Extend the system to support ERC-20 token balances and L2 networks.

### Tasks

- [ ] **7.1** Extend RPC fetcher for ERC-20 storage proofs:
  - `eth_getProof(tokenContract, [balanceSlot], blockNumber)`
  - Compute storage slot: `keccak256(abi.encode(holderAddress, mappingSlot))`
  - Parse storage proof for balance value

- [ ] **7.2** Extend SP1 program for storage proofs:
  - Verify both account proof (token contract exists) and storage proof (balanceOf[address])
  - Handle different storage layouts (standard ERC-20 mapping)
  - Same batch model: multiple members, some ETH, some ERC-20

- [ ] **7.3** Extend Policy to support ERC-20:
  - `tokenAddress` field: `address(0)` = native ETH, else ERC-20 contract address
  - `mappingSlot` field for ERC-20 storage layout
  - Token registry for known slot mappings (USDC, WETH, DAI, etc.)

- [ ] **7.4** L2 support (Optimism, Arbitrum, Base):
  - Per-chain policy configuration via `chainId`
  - Agent connects to L2 RPC endpoints
  - Same EIP-1186 proofs work on L2s (they expose the same API)
  - Separate Oracle deployments per chain, or cross-chain root publication

- [ ] **7.5** Tests with real tokens:
  - Fetch storage proofs for USDC, WETH, DAI balances
  - Generate batch proofs with mixed ETH + ERC-20 members
  - Test on L2 testnets (Optimism Sepolia, Arbitrum Sepolia)

### Deliverables
- ERC-20 balance proofs working in batch model
- L2 support for at least one rollup
- Tests with real token contracts

---

## Phase 8: Frontend & SDK

**Goal**: Build a frontend for enrollment/monitoring and a JavaScript SDK for integrators.

### Tasks

- [ ] **8.1** Set up React app (Vite + TypeScript + wagmi/viem):
  - Wallet connection (MetaMask, WalletConnect)
  - Policy browser

- [ ] **8.2** Enrollment UI:
  - Select policy → connect wallet → sign message → enroll
  - Show memberId and enrollment confirmation

- [ ] **8.3** Member dashboard:
  - Current status per policy
  - Epoch history
  - Balance monitoring status

- [ ] **8.4** JavaScript SDK for integrators:
  ```typescript
  const client = new SolvencyClient({ agentUrl: "..." });

  // Get membership proof for a smart contract call
  const proof = await client.getMemberProof(policyId, memberId);

  // Build verify calldata for contract interaction
  const calldata = client.buildVerifyCalldata(proof);
  ```

- [ ] **8.5** Integration examples:
  - Example dApp that gates a feature behind solvency verification
  - Example smart contract using `oracle.verifyMember()`

### Deliverables
- Working frontend with enrollment and monitoring
- JavaScript/TypeScript SDK
- Integration examples and documentation

---

## Phase 9: Production Hardening

**Goal**: Prepare for production deployment.

### Tasks

- [ ] **9.1** Monitoring and alerting:
  - Prometheus metrics for: epoch latency, proof generation time, API latency, member count, error rates
  - Grafana dashboards
  - PagerDuty/Slack alerts for epoch failures

- [ ] **9.2** Database migration to PostgreSQL:
  - SQLite → PostgreSQL for production workloads
  - Connection pooling
  - Backup strategy

- [ ] **9.3** CI/CD pipeline:
  - GitHub Actions: build, test, lint
  - Contract deployment automation
  - Docker containerization for the agent

- [ ] **9.4** Security audit preparation:
  - Document security model and assumptions
  - Smart contract audit scope
  - ZK program correctness review
  - Dependency audit

- [ ] **9.5** Documentation:
  - Operator guide: how to run a Solvency Agent
  - Integrator guide: how to integrate with a relying protocol
  - API reference
  - Smart contract documentation

- [ ] **9.6** Mainnet deployment:
  - Deploy contracts to Ethereum mainnet
  - Configure production agent
  - Initial policy setup
  - Monitoring in production

### Deliverables
- Production-ready system
- Comprehensive monitoring
- Documentation for operators and integrators
- Mainnet deployment

---

## Dependency Graph

```
Phase 0 (Foundation)
    │
    ├──► Phase 1 (Trusted Mode MVP)
    │         │
    │         ├──► Phase 5 (API + Proof Service)
    │         │         │
    │         │         └──► Phase 6 (Integration Testing)
    │         │                    │
    │         └──► Phase 4 (Agent Core)──┘
    │                    │
    │                    └──► Phase 7 (ERC-20 + L2)
    │
    ├──► Phase 2 (SP1 Batch Program)
    │         │
    │         └──► Phase 3 (Smart Contracts)──► Phase 4
    │
    └──► Phase 8 (Frontend & SDK) ◄── Phase 6
              │
              └──► Phase 9 (Production Hardening)
```

**Critical path**: Phase 0 → Phase 1 → Phase 4 → Phase 6 → Phase 9

**Parallelizable**:
- Phase 2 (SP1 Program) can start alongside Phase 1 (Trusted Mode)
- Phase 3 (Contracts) can start alongside Phase 1 once Phase 2 has the vkey
- Phase 8 (Frontend) can start once Phase 5 (API) is ready

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| SP1 proving too slow for epoch window | Can't publish roots in time | Medium | Trusted mode fallback; Succinct Prover Network; increase maxBlockAge |
| Large batches exceed SP1 memory | Can't prove large member sets | Medium | Split into sub-batches; tree of trees approach |
| alloy-trie incompatible with SP1 RISC-V | Can't reuse MPT lib in zkVM | Medium | Write minimal MPT verifier for the program |
| `blockhash` 256-block limit too tight | Tight window for proving | High | Block selection strategy; EIP-2935 when available |
| RPC rate limiting | Can't fetch all member proofs in time | Medium | Multiple RPC providers; caching; batch requests |
| SP1 SDK breaking changes | Migration effort | Low | Pin version; follow releases |
| Gas price spikes | Expensive epoch updates | Medium | Gas price oracle; configurable gas ceiling; skip epoch if too expensive |
| Agent key compromise | Unauthorized root updates | Low | HSM for operator key; multisig operator; ZK mode prevents false statuses |

---

## Getting Started

1. **Install tooling**:
   ```bash
   # Rust (if not installed)
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup update stable

   # SP1
   curl -L https://sp1up.succinct.xyz | bash
   sp1up

   # Foundry
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. **Build the workspace**: `cargo build && cargo test`

3. **Build SP1 program**: `cd program && cargo prove build`

4. **Start with Phase 0**: Restructure workspace and define types.

5. **Start Phase 1 immediately**: Trusted mode MVP gives you a working system fast.

---

## Phase 10: Privacy V2 — Solvent-Set Membership & Deterministic Nullifiers ✅ (initial)

**Goal**: Cryptographic (not policy-based) privacy from the agent, and sound
one-identity-per-key identifiers. Full design: **PRIVACY_V2.md**.

### Delivered

- [x] **10.1** PLUME-style deterministic nullifiers (`crates/common/src/plume.rs`):
  RFC 9380 hash-to-curve on secp256k1, Chaum-Pedersen DLEQ proofs, deterministic
  nonces. `memberId = SHA256(nullifier)` — unique per (key, policy).
- [x] **10.2** Legacy enrollment hardened: EIP-2 low-s enforcement closes the
  `(r, n-s, v^1)` malleability route to duplicate memberIds.
- [x] **10.3** Solvent-set trees (`crates/common/src/solvent_set.rs`) + membership
  statement with ABI-encoded public values (`crates/common/src/membership.rs`).
- [x] **10.4** SP1 membership program (`program-membership/`) — shares the
  statement code with the host mirror via `zk-pof-common`; builds with
  `cargo prove build`.
- [x] **10.5** Agent: `solvent_set_service.rs` (build from candidates, ERC-20
  Transfer-log discovery, ERC-20 `balanceOf` at block), `membership_prover.rs`
  (runtime-loaded ELF, execute + Groth16 prove), nullifier + solvent-set DB tables.
- [x] **10.6** Backend: `POST /v2/enroll`, `GET /v2/solvent_set/:policy_id`,
  `GET /v2/solvent_set/:policy_id/leaves`, `POST /v2/admin/build_solvent_set/:policy_id`.
- [x] **10.7** Contracts: `SolventSetOracle.sol` (publishRoot, verifyMembership,
  verifyAndConsume nullifier tracking) + 23 Foundry tests with MockSP1Verifier.
- [x] **10.8** SDK: solvent-set fetch + local tree/path computation (zero-dep),
  `enrollV2`, V2 types.
- [x] **10.9** Integration tests: full agent→client flow, stolen-path rejection,
  identity unification (enrollment memberId == membership-proof nullifier hash),
  and an `--ignored` SP1 emulator test proving guest ≡ native mirror.

### Remaining (tracked in PRIVACY_V2.md §6-7)

- [ ] Membership vkey generation + deployment wiring (`cargo prove vkey`)
- [ ] Wallet-side nullifier support (snap / local signer) + React app V2 flow
- [ ] Stage B: SP1-proven solvent-set derivation from receipt logs (ERC-20)
- [ ] Streak/time-weighted solvency leaf extension (anti-flash-loan)

---

## Phase 11: Privacy V2 Completion — Proven Derivation, Streak Solvency, Client Tooling

**Goal**: Close the gaps left by Phase 10 (see PRIVACY_V2.md §4.4/§7): remove the
operator-safety trust from solvent-set publication, add the time dimension
(streak solvency + unpredictable reference blocks), and ship the client-side
tooling that makes V2 usable end to end.

### Design decisions (normative)

- **Leaf v2 (streak-aware)**: `SHA256("zkpof-solvent-leaf-v2" || addr20 || streak_be4)`,
  `streak: u32 >= 1` = consecutive epochs (including this one) the address has
  been in the set. Replaces the v1 leaf everywhere in the V2 flow — nothing V2
  is deployed (placeholder vkeys), so the ABI evolves in place rather than
  versioning.
- **Membership public values v2 (192 bytes)**:
  `abi.encode(bytes32 root, bytes32 policyId, uint64 epoch, bytes32 nullifierHash,
  uint64 chainId, uint64 minStreak)` — the circuit asserts `witness.streak >= minStreak`,
  so a relying dApp requiring "solvent ≥ k epochs" checks `minStreak >= k`.
- **Derivation public values (320 bytes)**:
  `abi.encode(bytes32 stateRoot, bytes32 prevRoot, bytes32 newRoot, bytes32 policyId,
  uint64 epoch, uint64 blockNumber, uint64 chainId, uint256 thresholdWei,
  uint32 memberCount, uint32 candidateCount)`.
- **What the derivation proof guarantees (Stage B)**: every address in the
  published set had a balance ≥ threshold *proven via EIP-1186 against the
  block's state root*, and every streak is continuous with the previously
  published set (prev entries recommitted and matched against `prevRoot`).
  This removes the operator **safety** failure (including an insolvent
  address). Candidate **completeness** (censorship/liveness) remains
  operator-side — provable later by exhaustive receipt-trie enumeration
  ("Stage B.2", out of scope here).
- **On-chain state-root binding**: `publishRootProven` takes the RLP block
  header; checks `keccak256(headerRlp) == blockhash(pv.blockNumber)` (via an
  overridable `_blockhash` hook for testability/EIP-2935), extracts
  `stateRoot` with a fixed-shape RLP walk (items 0/1 are 32-byte strings,
  item 2 is a 20-byte string, item 3 is the state root — invariant for all
  Ethereum headers), and requires it to equal `pv.stateRoot`. Anyone can
  publish a proven root; the operator path remains for Stage A policies.
- **Unpredictable reference blocks**: `select_reference_block()` derives the
  sample offset from a recent blockhash, making "rent funds for the sampled
  block" strategies unable to predict which block will be sampled.

### Explicitly out of scope (with rationale)

- **Browser-native proving**: SP1 cannot prove in-browser; a dedicated
  circom/noir circuit needs a trusted setup and wallet PLUME support to be
  meaningful. The local-signer CLI (11.7) is the supported client prover.
- **MetaMask snap**: separate package + signing infra; CLI covers the
  raw-key path until wallet PLUME lands.
- **V1 (watched-tree) streaks**: the streak mechanism lands in the V2 flow;
  retrofitting the V1 leaf/contract/batch-program is deferred until V1
  policies need it.

### Tasks

- [ ] **11.1** Move account-MPT verification into `crates/common/src/mpt.rs`
  (agent re-exports) so SP1 guests share it; add `alloy-rlp` to common.
- [ ] **11.2** Streak-aware solvent sets in `crates/common/src/solvent_set.rs`
  (entries, leaf v2, paths) + membership statement with `minStreak`
  (192-byte ABI) + updated `program-membership/`; rebuild ELF.
- [ ] **11.3** `crates/common/src/solvent_derivation.rs` — host mirror of the
  derivation statement (per-candidate EIP-1186 verify, streak continuity,
  canonical set, 320-byte ABI) with synthetic-trie tests.
- [ ] **11.4** `program-solvent-set/` SP1 guest sharing the statement via
  zk-pof-common; build ELF; `crates/agent/src/derivation_prover.rs`
  (stdin builder, execute, Groth16 prove, runtime ELF loading).
- [ ] **11.5** Agent service: entries-with-streaks persistence (backward-
  compatible JSON), automatic streak computation from the previous set,
  `build_proven_from_candidates` (eth_getProof per candidate),
  `select_reference_block` + tests.
- [ ] **11.6** `SolventSetOracle`: 192-byte membership decode returning
  `(nullifierHash, minStreak)`; `publishRootProven` (header binding,
  derivation vkey, prev-root continuity, threshold/chain checks,
  permissionless); `proven` flag on entries; Foundry tests incl. RLP header
  fixture via `_blockhash` override harness.
- [ ] **11.7** Client tooling: `print-vkeys` bin (setup → bytes32 vkeys for
  deployment); `zkpof-client` bin (nullifier/enroll/witness/prove against a
  running agent — the local-signer path).
- [ ] **11.8** Backend: serve entries with streaks (keep `addresses` for
  compat); SDK: streak-aware utils/types/client.
- [ ] **11.9** Web app: solvent-set panel with client-side "is my wallet in
  the set" check (no address leaves the browser).
- [ ] **11.10** Docs (PRIVACY_V2.md Stage B status), full test sweep
  (both guests re-verified against mirrors in the SP1 emulator), commit.

---

## Phase 12: Privacy V2 Follow-ups — ERC-20 Proven Builds, Completeness, Wallet Crypto

**Goal**: Close the items PRIVACY_V2.md §7 left open after Phase 11: proven
builds for ERC-20 policies, the Stage B.2 completeness statement, production
vkeys, wallet-side nullifier crypto, and removing the last plaintext-address
transit from the legacy path.

### Delivered

- [x] **12.1** Storage-proof verification in `crates/common/src/mpt.rs`:
  `verify_account_state` (balance + storage root), `verify_storage_value`
  (balance-slot proofs under the token's storage root, key-generic trie walk),
  `erc20_balance_slot`, `account_trie_key`.
- [x] **12.2** ERC-20 derivation mode: witness carries the token contract's
  account proof + per-candidate storage proofs; public values extended to
  416 bytes with `token`, `balanceSlot`, and `candidatesRoot` (the Stage B.2
  composition surface). `SolventSetOracle` pins the `balanceOf` slot per
  policy (`setBalanceSlot`, operator-only) and cross-checks token/slot on
  proven publication. Agent fetches all storage proofs in one `eth_getProof`
  call; backend `proven` mode accepts ERC-20 policies with `balance_slot`.
- [x] **12.3** Stage B.2 completeness statement
  (`crates/common/src/receipt_scan.rs` + `program-receipt-scan/`): contiguous
  header-chain verification, **exhaustive** receipts-trie enumeration (a
  withheld node aborts — no Transfer can be hidden), legacy + EIP-2718 typed
  receipt parsing, Transfer participant extraction, `participants_root`
  committed with the same construction as the derivation proof's
  `candidates_root`. On-chain composition (root equality check) and
  witness-building ops tooling remain future work.
- [x] **12.4** Production vkeys: `print-vkeys` covers all three programs;
  generated values persisted in `config/vkeys.env` for Deploy.s.sol.
- [x] **12.5** Wallet-side PLUME: `@zk-proof-of-funds/sdk/plume` — a JS port
  of the nullifier + DLEQ crypto on audited @noble libraries, locked
  byte-for-byte to the Rust reference by shared test vectors (generated via
  `cargo test -p zk-pof-common emit_test_vectors -- --ignored`); ships
  `buildEnrollV2Request()` for any raw-key signer context (snap, embedded
  wallet). Core SDK stays dependency-free (separate subpath entry).
- [x] **12.6** Legacy `/submit_proof` privacy: accepts `trie_key`
  (keccak256(address), computed client-side — the plaintext address never
  transits); web app switched over; `wallet_address` retained as a
  deprecated fallback.

### Remaining (tracked in PRIVACY_V2.md §7)

- [ ] On-chain composition: require `scan.participants_root ==
  derivation.candidates_root` for completeness-proven publications
- [ ] Receipt-scan witness tooling (fetch raw receipts, rebuild tries)
- [ ] MetaMask snap packaging around `sdk/plume`
- [ ] Browser-native membership prover (dedicated circuit + trusted setup)


---

## Phase 13: Privacy V2 Closeout — ERC-7524 Alignment, Composition, Witness Tooling

**Goal**: Resolve every item PRIVACY_V2.md §7 still listed, either by
implementing it or by establishing (with evidence) that it is the wrong
solution shape and recording what replaces it.

### Research finding that reshaped the plan

MetaMask snaps **cannot** derive coin type 60 (it is reserved for MetaMask's
own EOAs), so a snap can never compute a PLUME nullifier for the user's
address — snap packaging was not a missing sprint, it was the wrong shape.
The path that works is wallet-native PLUME via **ERC-7524**
(`eth_getPlumeSignature`), which motivated 13.1.

### Delivered

- [x] **13.1** Nullifier realigned to ERC-7524: `N = htc(m ‖ sec1(pk))^sk`
  with the standard `secp256k1_XMD:SHA-256_SSWU_RO_` suite over a 32-byte
  message. A wallet implementing the ERC now derives the *same* member
  identity — wallet support becomes an integration, not a redesign.
- [x] **13.2** Scopes: `m` is a `scope_hash`, defaulting to
  `SHA256("zkpof-scope-v1:" ‖ policy_id)` (so policies stay mutually
  unlinkable) and configurable per policy for deliberate cross-policy shared
  identity. Membership publics carry `scopeHash` (224 bytes) and
  `SolventSetOracle` pins it via `effectiveScopeHash` / `setScopeHash`.
  Surfaced end-to-end: enrollment, `/v2/enroll`, `zkpof-client --scope`, JS.
- [x] **13.3** Schema fix found by the new shared-scope test: `members` was
  keyed by `member_id` alone, which made a shared identity unable to enroll in
  two policies. Key is now `(member_id, policy_id)`, with policy-scoped
  read/update helpers so one policy's epoch cannot clobber another's row.
- [x] **13.4** On-chain Stage B.2 composition:
  `publishRootProvenComplete` verifies the scan proof, enforces
  `participantsRoot == candidatesRoot`, requires the scan to cover the
  policy's token and end at the chain tip, and `requiresCompleteness` makes it
  mandatory per policy.
- [x] **13.5** Receipt-scan witness tooling: an ordered MPT **builder** in
  `crates/common/src/mpt.rs` (cross-checked byte-for-byte against the
  independent fixture constructions), plus `agent::scan_witness` +
  `zkpof-client scan-witness`, which rebuild headers and receipts tries and
  self-verify against `block.hash` / `receiptsRoot` before proving.
- [x] **13.6** `wallet_address` in `/submit_proof` now rejected by default
  (`ZKPOF_ALLOW_PLAINTEXT_ADDRESS=1` re-enables for un-migrated integrators).
- [x] **13.7** Vkeys regenerated for all three guests; docs rewritten so §7
  distinguishes *closed*, *genuinely remaining*, and *not planned*.

### Remaining (PRIVACY_V2.md §7)

- [ ] Native-ETH completeness (needs proven state enumeration — Stage C)
- [ ] Scan-range provenance (pin deployment block or a proven checkpoint)
- [ ] ERC-7524 proof-format adapter (against reference vectors)
- [ ] Browser-native prover (dedicated circuit + trusted setup ceremony)
