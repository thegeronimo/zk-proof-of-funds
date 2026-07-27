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
| 14 | Front-End Parity | Guided V2 prove flow, identity, on-chain provenance in the app | 3-5 days | ✅ DONE |
| 15 | Protocol Soundness | External-review release blockers: MPT, streaks, scan pinning, config versioning, proof binding, real E2E | 10-15 days | 🔴 NEXT |
| 16 | Ops Hardening & Honest Presentation | Authenticated control plane, fail-closed UI, real verification, copy audit | 5-8 days | 🟠 ∥ 15 |
| 17 | User-Proof Boundary Rework | Mode A/B split, browser-prover spike (gate G1), demo restructure | 8-12 days | 🟡 after 15 |
| 18 | Strategic Prototypes | Direct EIP-1186 state proof (gate G2), deferred capabilities | 8-12 days | 🟢 after 15-16 |

**Total estimated effort: 28-46 days (through Phase 14) + 31-47 days (Phases 15-18)**

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

---

## Phase 14: Front-End Parity — Surfacing Privacy V2 in the App

Closes PRIVACY_V2.md §6 rollout item 6. Phases 10–13 built the V2 protocol
(nullifiers, solvent sets, streaks, proven derivation, completeness), but the
React app still led with the V1 monitored-mode flow and exposed V2 through a
single read-only panel. Everything below is UI/SDK work against already-shipped
backend, contract, and crypto code — no protocol changes.

### Constraint that shapes the design

SP1 cannot prove in a browser (PRIVACY_V2.md §7), and PLUME nullifiers need raw
key access, which browser wallets do not grant. So two steps of the V2 flow are
*structurally* CLI-bound. The app does not pretend otherwise: it drives the user
to the exact `zkpof-client` invocation with every flag pre-filled, then accepts
the CLI's JSON output back and verifies it client-side. The handoff is the
feature, not a gap to hide.

### Design decisions

- **D1 — Lead with V2.** `/` becomes the guided prove flow. V1 monitored mode
  moves to `/monitored` and is labeled as such; it is not deleted (trusted-mode
  policies still use it).
- **D2 — Three key-handling paths, in preference order.** (a) generated
  `zkpof-client` command, copy-paste, no key in the browser; (b) feature-detect
  `eth_getPlumeSignature` (ERC-7524) and report support honestly — consuming a
  wallet-produced *proof* still needs the §7 adapter; (c) an explicitly gated
  "local key — dev only" path using `sdk/plume`, which computes the nullifier
  in-browser and transmits only public data. (c) is off by default behind a
  warning and never persists the key.
- **D3 — Trust nothing served.** Every root is rebuilt locally, every set of
  public values is decoded and cross-checked field-by-field against what the UI
  independently knows, and the on-chain entry is read directly from
  `SolventSetOracle` rather than taken from the agent.
- **D4 — Policies are picked, not pasted.** `config/policies.json` becomes the
  app's catalog; raw hex entry stays available as an escape hatch.

### Tasks

- [x] **14.1 Foundations.** Vite alias + `fs.allow` for `config/policies.json`;
  `web/src/config/policies.ts` (typed catalog, threshold/token/chain metadata)
  and `contracts.ts` (oracle + registry addresses from `VITE_*` env, minimal
  ABIs); shared UI primitives (`PolicyPicker`, `CopyButton`, `Field`,
  `CodeBlock`, `Callout`, `StatusPill`, `Stepper`); `usePolicySelection` hook
  with localStorage persistence so the policy follows the user across tabs.
- [x] **14.2 SDK parity.** Add `buildSolventSet()` and `triggerEpoch()` (the two
  backend routes with no client method) and a zero-dep
  `decodeMembershipPublicValues()` for the 224-byte ABI, with unit tests. Export
  the V2 admin types.
- [x] **14.3 Prove flow (`/`).** The centerpiece, four steps: pick policy →
  download + locally rebuild the set (with provenance) → locate address and read
  the streak locally → generate the `zkpof-client prove` command, paste its
  output back, decode and verify the public values, and emit
  `verifyMembership` / `verifyAndConsume` calldata for the relying dApp.
- [x] **14.4 Solvent-set explorer (`/set`).** The existing panel plus: on-chain
  entry comparison (root match, `proven` flag, `publishedAt`, TTL expiry),
  scope-hash display against `effectiveScopeHash`, a paginated entry table with
  streak distribution, and a raw-download button.
- [x] **14.5 Identity (`/identity`).** Derive scope hash and nullifier/memberId
  for a policy; show that this identity equals the monitored-mode `member_id`;
  V2 enrollment via the three D2 paths; `isNullifierUsed` check on-chain.
- [x] **14.6 Verify (`/verify`).** Decode pasted V2 public values without any
  other context (the dApp-integrator view), plus the retained V1 Merkle proof
  visualizer, split into two clearly labeled modes.
- [x] **14.7 Operator (`/operator`).** Build a solvent set (Stage A / Stage B
  proven / ERC-20 with `balance_slot` and Transfer-log discovery), trigger a V1
  epoch, and browse members and epoch history.
- [x] **14.8 Verification.** Seed a dev SQLite DB via `build_from_balances`
  (no RPC needed), run the real backend, and drive the full flow in a browser.
  `npm run typecheck` and `npm run build` clean for both `sdk/` and `web/`.

### Deliverables

- Every shipped backend route, SDK function, and oracle read reachable from the UI
- The V2 flow demonstrable end-to-end against a real agent, with the CLI handoff
  as an explicit, guided step
- PRIVACY_V2.md §6 item 6 closed

### Delivered

- **IA reordered around V2**: `/` is the prove flow; monitored mode moved to
  `/monitored` and is labeled legacy. Old routes redirect.
- **Policy catalog**: `config/policies.json` drives a picker shared by every
  screen, persisted in localStorage and surfaced in the header.
- **CLI handoff made exact**: the prove and identity screens emit fully
  populated `zkpof-client` commands and verify the JSON that comes back —
  decoding the 224-byte public values and cross-checking the root against the
  tree the *browser* rebuilt, plus policy, epoch, chain, scope, and streak.
- **On-chain provenance**: `SolventSetOracle` reads show whether a root was
  published at all, whether it was `proven`, when it expires, the effective
  scope hash, the membership vkey, and whether a nullifier was consumed.
- **SDK parity**: `buildSolventSet`, `triggerEpoch`, and
  `decodeMembershipPublicValues` / `checkMembershipPublicValues` (zero-dep,
  10 unit tests, cross-language vector shared with
  `crates/common/src/membership.rs`).
- **`zkpof-devseed`**: seeds a solvent set from synthetic balances via
  `build_from_balances`, so the whole client flow is exercisable without RPC.

### Fixed in passing

`/submit_proof`, `/proof`, `/status`, and the three `/admin` routes did not
canonicalize their path parameters, so a `0x`-prefixed policy or member ID
matched no row and returned an empty result rather than an error — an empty
member list read as "no members" instead of "wrong format". The V2 routes
already normalized via `parse_policy_id`; all routes now do (`canonical_hex`).

### Post-phase follow-ups (landed after the initial commit)

- **On-chain read path verified against a live deployment.** The oracle panels
  had only ever been exercised in their "not configured" state. Deploying
  `SolventSetOracle` + `PolicyRegistry` to anvil and publishing the seeded
  agent's exact root confirmed every field (root match, epoch, member count,
  TTL from the registry, scope hash, membership vkey), both the
  operator-asserted and proven badge states, and that the generated
  `verifyMembership` / `verifyAndConsume` selectors match the implementation.
- **Bug this surfaced:** reads resolved their RPC via `usePublicClient()` with
  no chain, so they followed wagmi's first configured chain rather than the
  oracle's. Fixed by pinning `VITE_ORACLE_CHAIN_ID` (falling back to the
  policy's `chain_id`), plus a warning when a proof's committed chainId
  disagrees with the oracle's — that combination reverts on-chain.
- **Docs and integrator parity.** `USER_GUIDE.md` now leads with the
  no-enrollment flow, has corrected navigation, and documents all 12 API
  routes (was 6, none of them V2). Added `ISolventSetOracle` and a worked
  `SolventSetGatedAirdrop` example + TypeScript script.

### Known gaps (unchanged by this phase)

- Proof generation stays in `zkpof-client`: SP1 cannot prove in a browser.
- `eth_getPlumeSignature` is feature-detected but a wallet-produced proof
  cannot be consumed without the ERC-7524 format adapter.
- The end-to-end run below was verified against a seeded agent; a real Groth16
  proof was not generated, as that needs the SP1 toolchain and a built ELF.

---

## External Review (2026-07) — Findings Assessment

An external protocol review of the Phase 10–14 system was received 2026-07-27.
Its findings were verified against the code before planning Phases 15–18. All
security-critical claims check out:

| # | Finding | Verified at | Status |
|---|---------|-------------|--------|
| R1 | MPT verifier accepts an empty proof as proof-of-absence against **any** nonempty root → zero balance | `crates/common/src/mpt.rs:231` (`walk_trie` returns `Ok(None)` before checking root ≟ `EMPTY_TRIE_ROOT`); `verify_account_state`/`verify_storage_value` map `None` → 0 | **Confirmed — critical.** Enables censoring qualifying accounts from a "complete" Stage B.2 root |
| R2 | Streaks not tied to distinct/ordered source blocks; epochs only `>` not `+1` | `SolventSetOracle.sol:572` (`epoch <= lastEpoch` is the only check); `solvent_derivation.rs:271` (streak = prev + 1, no block constraint) | **Confirmed — critical.** One balance observation can be replayed into an N-epoch streak |
| R3 | Stage B.2 scan range unpinned (`numBlocks` decoded then ignored, no start block) and `endBlockHash == blockhash(block.number-1)` makes full-history scans unpublishable in practice | `SolventSetOracle.sol:303,316-317` | **Confirmed — critical** |
| R4 | Policies/scopes/slots/vkeys mutable with no per-root pinning; operator can rewrite the whole policy incl. `active`; `updatePolicy` skips creation-time checks | `PolicyRegistry.sol:75-85`; `SolventSetOracle.sol` `SetEntry` stores no config/vkey hash; TTL read from *current* `rootTTLBlocks` at `:433` | **Confirmed — critical** |
| R5 | Membership proofs carry no verifier/action/nonce/deadline/beneficiary → replayable, copyable, front-runnable; nullifier namespace `[policyId][hash]` shared across all consumers | `crates/common/src/membership.rs:53-62`; `SolventSetOracle.sol:477-495` | **Confirmed — high** |
| R6 | No real Groth16 E2E ever ran (guest ELF → proof → deployed verifier → oracle) | Phase 14 "Known gaps" above | **Confirmed — high** |
| R7 | UI fails open on on-chain provenance (`void onChain.load(...)`; Continue gated only on local-root mismatch); Verify screen decodes without verifying | `web/src/components/ProveFlow.tsx:168-174,355`; `ProofViewer.tsx` | **Confirmed — high** |
| R8 | Admin/build routes unauthenticated; RPC failures silently excluded from sets | `crates/backend/src/main.rs:1395-1414` (no auth middleware anywhere) | **Confirmed — high** |
| R9 | Empty solvent set unrepresentable (`ZeroRoot` rejects); inline MPT children rejected (liveness for small tries); `chainId` editable though verifier chain == source chain; "reveals nothing" / "all qualifying addresses" copy overstated; EIP-2935 treated as future though live since Pectra (May 2025) | various, incl. `SolventSetOracle.sol:248,363,522`, `mpt.rs:275,326` | **Confirmed — medium** |

Review recommendations **adopted**: everything in Phases 15–16 (protocol
soundness + operational hardening); the Mode A / Mode B split (basic proof of
control should not require PLUME); CLI key-handling hardening; honest product
copy ("private threshold-balance attestation", not "solvency").

Adopted **as decision-gated spikes, not commitments**: the Noir/Barretenberg
browser membership prover and the direct EIP-1186 state-proof architecture
(Phases 17–18). Both are plausible but carry real unknowns (mobile proving
perf, Keccak/MPT circuit cost, a second proof system to maintain, a possible
Merkle-hash migration off SHA-256). Benchmarks decide, not preference.

**Deferred / rejected for now**:
- Full Stage B.2 recursive-accumulator redesign is deferred; the near-term fix
  is to *demote the completeness claim* (it is currently false) and pin scan
  ranges. The incremental-checkpoint redesign happens only if ERC-20
  completeness proves to be a product requirement (Phase 18 gate).
- Repo/product rename: copy changes only; no repo rename.
- Multisig + timelock governance: required before any mainnet deployment, but
  tracked under Phase 9 (production hardening), not blocking testnet work.

## Phase 15: Protocol Soundness — Release Blockers 🔴

Nothing in this phase is optional; until it lands, the system must be labeled
a **protocol simulation**, and no root may be described as "proven" or
"complete" in any surface. Contract changes here are breaking; that is
acceptable — nothing is deployed beyond dev/anvil.

### 15.1 MPT verifier correctness (R1) — do first, it's the worst bug

- [x] `walk_trie`: empty `proof_nodes` is valid **only** when
      `root == EMPTY_TRIE_ROOT`; any other root with an empty proof is an
      error, not absence. Fix `verify_account_state` / `verify_storage_value`
      / `verify_account_balance_with_key` accordingly.
- [x] Support embedded (inline, <32-byte) child nodes in branches and
      extensions — currently `bail!`ed, which breaks valid proofs in small
      storage tries. An inline child is the RLP list itself, not a hash ref;
      recurse into it without a hash check but count it against the node list.
- [x] Enforce that a leaf consumes the **entire** remaining key (assert
      `key_offset == 64` on acceptance) and that branch-terminated absence
      paths are well-formed non-inclusion (diverging leaf/extension is also
      valid absence — handle it explicitly rather than erroring).
- [x] Enforce canonical RLP and canonical hex-prefix encoding (reject
      non-minimal lengths, bad HP flags).
- [x] Test battery: (a) real mainnet `eth_getProof` vectors — inclusion,
      non-inclusion via empty branch child, non-inclusion via diverging leaf,
      small storage tries with embedded nodes; (b) malformed RLP corpus;
      (c) differential fuzz vs a reference implementation
      (`alloy-trie`/`eth-trie` in a dev-dependency harness, plus geth via RPC
      where available). Delete the two tests that assert the buggy behavior
      (`mpt.rs:435-447`).
- [x] Differential fuzzing against `alloy-trie` (reth's implementation),
      validated with negative controls.
- [ ] **External human cryptographic review of `mpt.rs`** — cannot be done
      in-repo; needs a third party.

### 15.2 Epoch/streak temporal enforcement (R2)

- [x] Normative epoch scheme in `PolicyRegistry`: add `startBlock`; define
      `epoch = (referenceBlock - startBlock) / epochLengthBlocks` and enforce
      on-chain: `epoch == lastEpoch + 1` (or explicit gap with streak reset
      semantics), `referenceBlock > lastReferenceBlock`, and
      `referenceBlock` inside epoch `epoch`'s window.
- [x] Bind the previous source block into the derivation statement: derivation
      publics gain `prev_block_number` (and the circuit asserts
      `block_number > prev_block_number`), so a proof cannot reuse the same
      snapshot even off-chain.
- [x] Randomized reference-block sampling moves from backend convenience to
      normative rule: `referenceBlock = sample(policyId, epoch, entropy)` where
      entropy is a blockhash finalized **after** the epoch window closes;
      contract recomputes and checks it on the proven path. Trusted path at
      minimum enforces window containment + monotonicity.
- [x] Remove the admin request's explicit block-number override for proven
      builds (keep for dev seeding only, behind the dev flag).
- [x] Docs: state plainly that a streak is one observation per epoch — an
      economic deterrent against balance rental, not proof of continuous
      holding.

### 15.3 Stage B.2 honesty + scan-range pinning (R3)

- [x] Stop storing scan results as bare `proven=true`. Replace the bool with
      an immutable provenance enum on `SetEntry`:
      `OPERATOR_ASSERTED | BALANCES_PROVEN | RANGE_SCAN_PROVEN` (full
      completeness tier reserved for the future redesign).
- [x] Pin the scan range: contract decodes and **stores** `startBlock`,
      `endBlock`, `numBlocks`, and requires
      `numBlocks == endBlock - startBlock + 1`; continuity check against the
      previous entry's scan range when one exists.
- [x] Replace `endBlockHash == blockhash(block.number - 1)` with a lookup
      through EIP-2935 (`_blockhash` already virtual — route through the
      system contract at `0x0000F90827F1C53a10cb7A02335B175320002935` with
      `blockhash` fallback), giving ~8191 blocks (~27h) of publication
      headroom instead of one block.
- [x] UI/docs: no surface may say "complete" for `RANGE_SCAN_PROVEN`; the
      badge says "balances proven for scanned range N–M".

### 15.4 Policy/config immutability + per-root pinning (R4)

- [x] Define `policyConfigHash = keccak256(abi.encode(threshold, token,
      chainId, epochLength, maxBlockAge, rootTTL, scopeHash, balanceSlot,
      provenance requirement, startBlock, version))`. A policy's config
      becomes immutable once its first root is published; changes require a
      new `version` (new policyId or `policyId+version` key).
- [x] `SetEntry` gains `policyConfigHash`, `membershipVKeyHash`,
      `derivationVKeyHash` (scan vkey when applicable), and an immutable
      `validUntil` computed at publication from the **source block** + the
      TTL in force at publication. `verifyMembership` checks
      `block.number <= validUntil` and takes an expected `policyConfigHash`
      the relying app pins.
- [x] `updatePolicy`: owner-only; restricted to operator rotation and
      `active`; re-run all creation-time validation. Operator loses the
      ability to rewrite policy or flip `active`; `setScopeHash` /
      `setBalanceSlot` / `setRequiresCompleteness` become one-time-before-
      first-publication (then frozen into the config hash).
- [x] Vkey rotation (`setMembershipVKey` etc.) only affects **future**
      publications; verification uses the entry's pinned vkey hash. Add
      per-root revocation (`revokeRoot(policyId, index)`, owner) and keep
      global pause.

### 15.5 Proof context binding + nullifier namespacing (R5)

- [x] Membership publics gain a presentation context:
      `verifierContract`, `verifierChainId`, `actionId`, `beneficiary`,
      `nonce`, `deadline`, `policyConfigHash`. Circuit commits to all of
      them; `verifyMembership`/`verifyAndConsume` check
      `verifierContract == address(this)` (or registered consumer),
      `verifierChainId == block.chainid`, `block.number <= deadline`.
- [x] Nullifier consumption keyed
      `[consumer][policyConfigHash][actionId][nullifierHash]` so one dApp
      cannot burn another's namespace, and front-running a proof tx no longer
      denies the legitimate user (the proof is bound to `beneficiary`).
- [x] Update `zkpof-client`, SDK decoder (public-values ABI grows —
      version the schema), cross-language vectors, and the web calldata
      generators.

### 15.6 Real cryptographic end-to-end (R6)

- [ ] CI job (self-hosted or Succinct network) that builds every guest ELF,
      generates real Groth16 proofs for: membership, native-ETH derivation,
      ERC-20 derivation, receipt scan; verifies each against the **deployed**
      SP1 verifier + oracle on anvil; then mutates one field at a time (proof
      byte, each public value, root, vkey, scan range) and asserts rejection.
- [x] Reproducible artifact manifest committed per release: guest commits,
      rust/SP1 versions, ELF hashes, vkeys, verifier address + bytecode hash,
      public-values schema version, proof size, proving time/memory,
      verification gas.
- [ ] Until this passes: all demo surfaces label proofs "simulation".

### Exit criteria

`cargo test` + `forge test` green including the new adversarial suites; one
full real-proof E2E on record; no UI surface overstating provenance.

### Delivered (2026-07-27)

**15.1 — MPT verifier.** `walk_trie` was rewritten around an explicit `Step`
state machine. An empty proof is now valid **only** against `EMPTY_TRIE_ROOT`;
against any other root it is an error, closing R1. Embedded (<32-byte) child
nodes are walked inline rather than rejected, leaves must consume the full
64-nibble key, non-inclusion is handled explicitly (empty branch child *or*
diverging leaf/extension), trailing proof nodes are rejected, and RLP/HP
encodings must be canonical (no leading-zero integers, valid HP flag, zero
padding nibble, no trailing bytes after a node). The two tests that asserted
the buggy behaviour are gone; in their place are inclusion/non-inclusion tests
over constructed tries, an embedded-node test, canonical-encoding rejections,
and a seeded randomized round-trip that builds tries of up to 200 random keys,
extracts each proof, and checks that absent keys are provably absent and that
truncating any proof makes absence *un*provable.

**15.2 — Epoch/streak.** `DerivationPublicValues` gained `prev_block_number`
(ABI 416 → 448 bytes) and the statement asserts `block_number >
prev_block_number`. On-chain, `_validateEpochSchedule` replaces
`_validateEpochIncreasing`: epochs must be sequential (`last + 1`), reference
blocks must strictly advance, and each reference block must fall inside its own
epoch window derived from the new `Policy.startBlock` / `epochLengthBlocks`.
The contract binds the proof's `prevBlockNumber` to the stored previous
entry's block, so a publisher cannot supply an invented older block to satisfy
the circuit inequality while re-proving one snapshot. Stage A is held to the
same schedule — it previously stored an arbitrary operator-supplied block.

**15.3 — Stage B.2.** `proven: bool` became an immutable `Provenance` enum
(`OperatorAsserted` / `BalancesProven` / `RangeScanProven`). Scan public values
gained `start_block` / `end_block` (224 bytes), and the range is now *proven*
rather than asserted: `parse_header` reads header item 8 (block number) and the
statement checks each header's number is contiguous, so the committed range
describes the blocks actually scanned. On-chain the range is stored, validated
for internal consistency, and checked for contiguity with the previous entry.
`_blockhash` routes through the EIP-2935 history contract (8191-block window)
with a BLOCKHASH fallback, replacing the `blockhash(block.number - 1)` rule
that made a historical scan unpublishable in practice.

**15.4 — Config pinning.** `PolicyRegistry` gained `configHash`, `startBlock`,
`version`, and freeze-on-first-publication (the oracle is the authorized
freezer). `updatePolicy` is owner-only, re-runs all creation-time validation
(it previously skipped the operator/epoch/TTL checks entirely), and post-freeze
permits only operator rotation. `SetEntry` now pins `policyConfigHash`, both
vkey hashes, and an immutable `validUntil` computed from the *source* block —
verification no longer reads the policy's mutable current TTL. Added per-root
`revokeRoot` and per-policy `setPublicationPaused`; `setScopeHash` /
`setBalanceSlot` / `setRequiresCompleteness` are now rejected once any root
exists.

**15.5 — Proof context.** Membership publics gained a `PresentationContext`
(policyConfigHash, verifier, verifierChainId, actionId, beneficiary, nonce,
deadline), taking the blob to 448 bytes. `verifyMembership` checks the verifier
is this contract, the chain matches, the deadline has not passed, and the
config hash equals the entry's. `verifyAndConsume` additionally requires
`beneficiary == msg.sender`, which is what defeats mempool front-running, and
consumption is keyed by `(consumer, policyConfigHash, actionId)` so one dApp
can no longer exhaust another's namespace.

**16.1 — Backend.** All four operator routes sit behind a `ZKPOF_ADMIN_TOKEN`
bearer check with audit logging; the server refuses to start unauthenticated
unless `ZKPOF_DEV_INSECURE_ADMIN=1`. Balance-fetch failures are no longer
silently dropped — unresolved candidates are reported and, by default, abort
the build (an RPC outage is not evidence of insolvency). `/v2/solvent_set`
serves a snapshot manifest (schema, content SHA-256, size, entry count,
mirrors from `ZKPOF_SNAPSHOT_MIRRORS`). An empty set now hashes to a
domain-separated `EMPTY_SET_ROOT` sentinel, mirrored as a Solidity constant, so
"nobody qualified" is publishable while `bytes32(0)` stays reserved for "no
root at all". The first-epoch discriminator moved to `prev_block_number == 0`
so the sentinel does not collide with "no previous publication".

**16.2 — Web.** `provenanceGate` centralizes the fail-closed decision; the
prove flow now *awaits* the on-chain read (it previously fired it unawaited and
advanced) and blocks progression unless served root, locally-rebuilt root, and
on-chain entry all agree and the entry is live, unrevoked, and meets the
policy's provenance requirement. The sandbox escape is opt-in via
`VITE_ALLOW_UNVERIFIED_PROVENANCE=1` and labelled. The Verify screen performs a
real `verifyMembership` `eth_call` and only shows a green state when the oracle
accepts; decoding is explicitly labelled as not verification. The generated CLI
command no longer contains a `--sk <KEY>` placeholder and now carries the
presentation-context flags. Copy audit: "Prove solvency" → "Prove a threshold
balance", the exact statement is spelled out on the result step, provenance
badges distinguish balances-proven from range-scanned, unlinkability is scoped
correctly, and the set page discloses its targeting-artefact nature.

**16.3 — CLI.** `zkpof-client` refuses `--sk` on argv outright with
instructions, reading the key from a hidden TTY prompt, `--sk-stdin`, or
`--sk-env`, held in `Zeroizing` buffers.

**§4.7 — chain model made explicit.** `policy.chainId == block.chainid` is now
enforced at publication, and the web app's chain field is read-only whenever
the oracle's chain is known. The source chain and the verifier chain *are* the
same chain — the state root is bound through this chain's own block hashes —
so an editable field implied a cross-chain capability that does not exist.
Real cross-chain verification needs a light client or checkpoint oracle
(Phase 18).

**Fixed in passing.** `crates/agent/src/proof_worker.rs` loaded its guest ELF
with compile-time `include_bytes!`, so the whole workspace failed to build
without a prebuilt ELF — the V2 provers already load at runtime for exactly
this reason; V1 now matches. `program/Cargo.toml` was missing the empty
`[workspace]` table its three sibling guests carry, so `cargo prove build`
failed inside a git worktree.

### Still open in Phase 15/16 (after the 2026-07-27 remainder pass)

Only two things remain, and neither can be closed from inside the repo:

- **15.1 — external human review of `mpt.rs`.** Differential fuzzing against
  `alloy-trie` (reth's implementation) now covers randomized inclusion,
  non-inclusion, the empty-proof rule, and byte-flip/truncate/duplicate
  mutations, in both directions (`crates/common/tests/mpt_differential.rs`).
  Notably, `alloy-trie` independently enforces the same empty-proof rule this
  phase introduced, which is outside confirmation that the R1 fix is correct
  semantics rather than merely stricter. Both differential tests were checked
  with negative controls. What remains is a third-party cryptographic review,
  which is a human task.

- **15.6 — the real Groth16 leg.** `scripts/real-proof-e2e.sh` now runs green
  end to end without Docker: reproducible guest builds, artifact manifest,
  vkey derivation, the full contract-level publish/verify cycle with a
  one-field-at-a-time mutation matrix (`contracts/test/E2EMutation.t.sol`,
  27 tests), and a live deployment to anvil. What is still missing is
  generating real Groth16 proofs and submitting them against a deployed
  `SP1VerifierGroth16` — that needs Docker + ~16 GB RAM or a Succinct network
  key. **Until it passes, every surface must keep saying "protocol
  simulation": the contract logic is verified, the proof-system integration
  is not.**

### Delivered in the remainder pass (2026-07-27)

**Reference-block sampling is normative and enforced (15.2).** The old
sampler drew from the *current* block's hash, so an operator could watch the
entropy and re-roll by waiting — the randomness was real but the choice of
when to consume it was unconstrained. The draw is now fixed by the hash of
the first block *after* the epoch's window:

```
reference = windowStart
          + keccak(DOMAIN, policyConfigHash, epoch, blockhash(windowEnd))
            % epochLengthBlocks
```

so it does not exist while balances in the window can still move, and every
publisher computes the same answer. `publishRootProven` requires the proven
block to equal the draw; `maxBlockAge` now bounds how long after the window
closes a publication may land, which is the only freshness notion that
survives a block the publisher does not choose. `sampledReferenceBlock()` is
public so agents can compute what the chain will demand. The Rust mirror and
the Solidity implementation are both pinned to a vector computed with an
independent keccak implementation.

**Build parameters come from the chain (16.1).** New `policy_reader` module
reads threshold/token/slot/config-hash from the registry + oracle. Anything
the caller sends is cross-checked and drift is a hard error; the hard-coded
1 ETH default is gone. The `block_number` override is refused outright for
proven builds and gated behind `ZKPOF_DEV_ALLOW_BLOCK_OVERRIDE=1` otherwise.

**Web (16.2).** The silent scope fallback is gone — if the authoritative
scope read fails the flow stops rather than deriving a guess, since a policy
with a shared scope would otherwise bind the wrong identity namespace. The
operator console left primary navigation for `/console/operator` behind
`VITE_ENABLE_OPERATOR_CONSOLE=1`.

**Docs.** PRIVACY_V2 §4 now states what a streak of N actually means — the
threshold was met at N *sampled observations*, not held continuously — and
that interfaces must not say "held for N epochs".

## Phase 16: Operational Hardening & Honest Presentation 🟠

Independent of Phase 15's contract work; can proceed in parallel.

### 16.1 Backend (R8)

- [x] Split operator routes (`/v2/admin/*`, `/admin/*`) onto an authenticated
      control plane: bearer token minimum (env-configured), designed so mTLS /
      signed requests can replace it; rate limits + audit log (who, what,
      when, result) on every operator action.
- [x] Build parameters come from the pinned on-chain policy version, not the
      request body; remove the hard-coded 1 ETH defaults in enrollment and
      set building.
- [x] Completeness-sensitive builds **abort** on any unresolved candidate
      (RPC failure ≠ insolvent); Stage A builds report excluded candidates in
      the build result instead of logging silently.
- [x] Snapshot data availability: publish a content-addressed snapshot
      manifest (schema version, SHA-256, size, entry count, mirror URLs)
      alongside each root; `/v2/solvent_set` serves the manifest; the SDK
      verifies content hash before rebuilding the root.
- [x] Empty-set representability: domain-separated sentinel root
      `SHA256("zkpof-empty-solvent-set-v1")` accepted by both publish paths,
      understood by SDK/web.

### 16.2 Web app fail-closed + real verification (R7)

- [x] Production mode (default when an oracle is configured): the prove flow
      **awaits** the on-chain read and blocks progression unless agent root ==
      locally rebuilt root == on-chain root, entry unexpired, provenance meets
      the policy's requirement, config hash matches, chain matches. Dev
      sandbox mode keeps the current permissive behavior behind an explicit
      banner.
- [x] No silent scope fallback: if the authoritative on-chain scope read
      fails, the flow stops rather than deriving locally.
- [x] Verify screen performs an actual `eth_call` (`verifyMembership` /
      staticcall of `verifyAndConsume`) against the configured oracle and
      reports distinct states: decodes / context matches / **cryptographically
      valid** / root recognized+unexpired / nullifier unused. The raw decoder
      moves to an "Inspect raw public values" advanced section. No green
      check without a verifier call.
- [x] Copy audit (R9): "solvency" → "threshold-balance attestation" in user
      surfaces; exact statement ("controlled an account meeting X at
      historical snapshot(s)") shown on the prove and verify screens; "cannot
      be linked" → scoped-unlinkability wording; "all qualifying addresses" →
      "balances proven for the supplied candidate set"; EOA-only stated
      explicitly; solvent-set publication leakage disclosed on `/set`, full
      address/streak table behind an "auditor" disclosure toggle.
- [x] Enforce `policy.chainId == oracle chainid` (read-only display, no
      editable field) until a real cross-chain design exists.
- [x] `/operator` leaves primary navigation; it becomes a separate
      authenticated console route wired to the 16.1 control plane.

### 16.3 CLI key handling (interim, until Phase 17 removes the need)

- [x] `zkpof-client` refuses `--sk` via argv: hidden TTY prompt or
      `--sk-stdin` / `--sk-env` only; zeroize key material
      (`zeroize` crate), disable core dumps on supported platforms, never log
      key-bearing state; web app stops generating commands containing key
      placeholders (prompts instead).

## Phase 17: User-Proof Boundary Rework 🟡

The review's central product point, accepted: basic proof-of-control (Mode A)
must not require PLUME, a raw key, or a terminal. PLUME becomes an optional
uniqueness capability (Mode B).

### 17.1 Mode split (protocol + product)

- [ ] Policy capability flag: `requiresUniqueness`. Mode A membership
      statement drops the nullifier: witness = ordinary wallet ECDSA signature
      over the Phase 15.5 presentation context + Merkle path + streak;
      publics = context + root + policyConfigHash (no stable identity
      revealed, replay prevented by nonce/deadline, not nullifier).
- [ ] Mode B (existing PLUME path) is requested by the relying policy only;
      `/identity` disappears from the default flow and becomes an advanced
      screen shown for Mode B policies.
- [ ] Wallet UX: Mode A signs a structured EIP-712 `ProofRequest`
      (domain, action, nonce, deadline, "does not transfer funds") — works
      with hardware wallets today.

### 17.2 Browser prover spike (decision gate G1)

- [ ] Prototype the Mode A membership circuit in Noir/Barretenberg
      (UltraHonk, Keccak transcript): secp256k1 ECDSA verify, address
      derivation, Merkle path, streak ≥ min, context binding. Generate the
      Solidity verifier.
- [ ] Benchmark on desktop Chrome/Safari, iPhone Safari, Android Chrome,
      single-thread + low-memory fallback: proving time, peak memory, proof
      size, verification gas.
- [ ] Evaluate the Merkle-hash question: SHA-256 path cost in-circuit vs a
      dual-commitment tree (Poseidon membership root + SHA-256 snapshot hash,
      cross-linked in the derivation program). Prototype both before choosing.
- [ ] **Gate G1**: ship browser proving if mobile proof time is acceptable
      (< ~30s target on a current phone) and the second proof system's
      maintenance cost is justified; otherwise ship a signed, reproducible
      native companion app (not a CLI) and keep the circuit for later.
- [ ] Privacy boundary: the prover runs on a dedicated origin (installed PWA /
      extension / native), receiving a public `ProofRequest` via deep link/QR
      and returning only proof + publics — the relying page never sees
      address, signature, or path. (This is the §10 fix; the wagmi wallet
      connection moves out of relying-party-controlled JS.)

### 17.3 Demo restructure (after G1)

- [ ] Single-transaction demo: proof request screen (plain-language statement,
      revealed/hidden lists, validity) → trusted prover → verified result
      unlocking a real gated action (the existing `SolventSetGatedAirdrop` or
      a lending-quote example). Advanced drawer holds roots, hashes, vkeys,
      gas. `/set` becomes the separate auditor console.

## Phase 18: Strategic Prototypes & Decision Gates 🟢

Only after Phases 15–16 land. Purpose: choose the long-term default
architecture with data.

### 18.1 Direct EIP-1186 state-proof prototype (decision gate G2)

- [ ] Circuit (SP1 guest first — the fixed Phase 15.1 MPT code is reusable
      as-is): canonical header → state root → account/storage path → balance ≥
      threshold → wallet-signature control → presentation context; optional
      K randomized historical samples via EIP-2935.
- [ ] Compare against the solvent-set mode on: proving time/memory, RPC
      address-privacy story (user RPC / own node / relay), operator trust,
      download size, mobile viability, gas, integration complexity.
- [ ] **Gate G2**: pick the default mode per use case using the review's
      decision matrix (set mode for high-volume shared-policy gating; direct
      mode for one-off pure proof of funds). Expose both as policy
      capabilities rather than replacing one with the other.

### 18.2 Deferred capabilities (unblocked by G1/G2 outcomes)

- [ ] Stage B.2 incremental checkpoint redesign (range proofs chained via
      recursion, EIP-2935 headroom, pinned deployment-block checkpoint) — only
      if ERC-20 completeness is a confirmed product requirement.
- [ ] ERC-7524 wallet integration + action-scoped nullifiers (Mode B polish).
- [ ] ERC-1271 / Safe / 4337 adapters (zkVM `isValidSignature` execution).
- [ ] Token adapters (proxy/codehash pinning, rebase handling, zkVM
      `balanceOf` execution for non-mapping tokens).
- [ ] Cross-chain source verification (light client / checkpoint oracle) —
      until then `sourceChainId == verifierChainId` stays enforced.
- [ ] Governance hardening for mainnet: multisig + timelock owner, emergency
      pause, separately governed revocation (with Phase 9).

### Sequencing summary

```
Phase 15 (protocol blockers)  ──┬──►  Phase 17 (mode split + G1 spike)
Phase 16 (ops + honesty, ∥ 15) ─┘         │
                                          ▼
                              Phase 18 (direct-state G2, deferred caps)
```

Rule of thumb throughout: **fix soundness before polishing the interface, and
let benchmarks — not architectural preference — pick the user-proof boundary.**
