// ─── SDK Configuration ──────────────────────────────────────────────────────

/** Configuration for the SolvencyClient. */
export interface SolvencyClientConfig {
  /** Base URL of the Solvency Agent API (e.g., "http://localhost:3000"). */
  agentUrl: string;
  /** Optional request timeout in milliseconds (default: 30000). */
  timeoutMs?: number;
  /** Optional custom fetch implementation (default: globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
}

// ─── Enrollment ─────────────────────────────────────────────────────────────

/** Request body for POST /enroll. */
export interface EnrollmentRequest {
  /** Hex-encoded 32-byte policy identifier. */
  policy_id: string;
  /** Hex-encoded 65-byte ECDSA signature (with or without 0x prefix). */
  signature: string;
  /** The signed message: "zkpof-holder-v1:{scope}:{nonce}". */
  signed_message: string;
}

/** Response from POST /enroll. */
export interface EnrollmentResponse {
  /** Hex-encoded 32-byte privacy-preserving member ID (SHA256 of signature). */
  member_id: string;
  /** Enrollment status (always "enrolled" on success). */
  status: string;
  /** First epoch in which this member will appear in the solvency tree. */
  effective_epoch: number;
}

// ─── Proof Submission ──────────────────────────────────────────────────────

/** Request body for POST /submit_proof/{policyId}/{memberId}. */
export interface ProofSubmissionRequest {
  /** Hex-encoded Ethereum address (used transiently for MPT verification, NOT stored). */
  wallet_address: string;
  /** Hex-encoded RLP-encoded MPT proof nodes from eth_getProof. */
  proof_nodes: string[];
  /** Block number the proof references. */
  block_number: number;
}

/** Response from POST /submit_proof/{policyId}/{memberId}. */
export interface ProofSubmissionResponse {
  /** Hex-encoded 32-byte member ID. */
  member_id: string;
  /** Hex-encoded 32-byte policy ID. */
  policy_id: string;
  /** Epoch the proof was submitted for. */
  epoch: number;
  /** Block number the proof references. */
  block_number: number;
  /** Verified balance in wei (string to handle large numbers). */
  balance_wei: string;
  /** Whether the balance meets the policy threshold. */
  is_solvent: boolean;
  /** Solvency status string ("solvent" or "insolvent"). */
  status: string;
}

// ─── Merkle Proof ───────────────────────────────────────────────────────────

/** Merkle membership proof returned by GET /proof/{policyId}/{memberId}. */
export interface MerkleProofData {
  /** Hex-encoded 32-byte member ID. */
  member_id: string;
  /** Hex-encoded 32-byte policy ID. */
  policy_id: string;
  /** Status byte: 1 = solvent, 0 = insolvent. */
  status: number;
  /** Epoch number this proof was generated for. */
  epoch: number;
  /** Leaf index in the Merkle tree (0-based). */
  leaf_index: number;
  /** Array of hex-encoded 32-byte sibling hashes (leaf to root). */
  merkle_proof: string[];
  /** Hex-encoded 32-byte Merkle root. */
  root: string;
  /** Block number the state proofs reference. */
  block_number: number;
}

// ─── Member Status ──────────────────────────────────────────────────────────

/** Member status returned by GET /status/{policyId}/{memberId}. */
export interface MemberStatus {
  /** Hex-encoded 32-byte member ID. */
  member_id: string;
  /** Hex-encoded 32-byte policy ID. */
  policy_id: string;
  /** Current solvency status. */
  status: "solvent" | "insolvent" | "pending" | "fetch_failed";
  /** Last observed balance in wei (string to handle large numbers). */
  last_balance_wei: string;
  /** Last block at which balance was checked. */
  last_checked_block: number;
  /** First epoch the member appears in. */
  effective_epoch: number;
  /** Unix timestamp of enrollment. */
  enrolled_at: number;
}

// ─── Admin Types ────────────────────────────────────────────────────────────

/** A member entry in the admin members list. */
export interface AdminMember {
  /** Hex-encoded 32-byte member ID. */
  member_id: string;
  /** Current solvency status. */
  status: string;
  /** Last observed balance in wei. */
  last_balance_wei: string;
  /** Last block at which balance was checked. */
  last_checked_block: number;
  /** First epoch the member appears in. */
  effective_epoch: number;
}

/** Response from GET /admin/members/{policyId}. */
export interface AdminMembersResponse {
  /** Hex-encoded 32-byte policy ID. */
  policy_id: string;
  /** Number of enrolled members. */
  member_count: number;
  /** List of member entries. */
  members: AdminMember[];
}

/** Epoch entry in the admin epoch history. */
export interface EpochEntry {
  /** Epoch number. */
  epoch: number;
  /** Block number the state proofs reference. */
  block_number: number;
  /** Hex-encoded 32-byte Merkle root. */
  root: string;
  /** Number of members in this epoch's tree. */
  member_count: number;
  /** Block at which the root was published on-chain. */
  published_at_block: number;
}

/** Response from GET /admin/epochs/{policyId}. */
export interface AdminEpochsResponse {
  /** Hex-encoded 32-byte policy ID. */
  policy_id: string;
  /** Latest epoch record (null if no epochs yet). */
  latest_epoch: EpochEntry | null;
}

// ─── Health ─────────────────────────────────────────────────────────────────

/** Response from GET /health. */
export interface HealthResponse {
  /** Service status (normally "ok"). */
  status: string;
  /** Service version string. */
  version: string;
}

// ─── Privacy V2 (PRIVACY_V2.md) ─────────────────────────────────────────────

/**
 * Request body for POST /v2/enroll — nullifier enrollment.
 *
 * Requires raw key access to compute (wallets cannot produce PLUME-style
 * nullifiers yet); see PRIVACY_V2.md §3.3. All fields hex-encoded, 0x optional.
 */
export interface EnrollV2Request {
  /** 32-byte policy ID. */
  policy_id: string;
  /** 33-byte compressed secp256k1 public key. */
  public_key: string;
  /** 33-byte compressed nullifier point. */
  nullifier: string;
  /** DLEQ commitment A (33 bytes). */
  dleq_a: string;
  /** DLEQ commitment B (33 bytes). */
  dleq_b: string;
  /** DLEQ response s (32 bytes). */
  dleq_s: string;
}

/** Response from POST /v2/enroll. */
export interface EnrollV2Response {
  /** memberId = SHA256(nullifier) — unique per (key, policy). */
  member_id: string;
  /** Enrollment status ("enrolled"). */
  status: string;
  /** First epoch this member appears in. */
  effective_epoch: number;
  /** Enrollment mode ("nullifier"). */
  mode: string;
}

/** Response from GET /v2/solvent_set/:policy_id. */
export interface SolventSetInfo {
  /** Canonical policy ID (lowercase hex). */
  policy_id: string;
  /** Solvent-set epoch number. */
  epoch: number;
  /** Reference block balances were sampled at. */
  block_number: number;
  /** Solvent-set Merkle root (0x-prefixed hex). */
  root: string;
  /** Number of addresses in the set. */
  member_count: number;
}

/** Response from GET /v2/solvent_set/:policy_id/leaves. */
export interface SolventSetLeavesPage {
  policy_id: string;
  epoch: number;
  block_number: number;
  root: string;
  /** Total entries in the set. */
  total: number;
  /** Page offset. */
  offset: number;
  /** Page size limit. */
  limit: number;
  /** Addresses in this page (lowercase hex, no 0x, canonical order). */
  addresses: string[];
  /** Entries in this page as [address, streak] pairs (canonical order). */
  entries: [string, number][];
}

// ─── Errors ─────────────────────────────────────────────────────────────────

/** Error codes returned by the SDK. */
export type SolvencyErrorCode =
  | "NETWORK_ERROR"
  | "INVALID_REQUEST"
  | "NOT_FOUND"
  | "CONFLICT"
  | "SERVER_ERROR"
  | "TIMEOUT";
