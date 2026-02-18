// ─── Client ──────────────────────────────────────────────────────────────────
export { SolvencyClient, SolvencyError } from "./SolvencyClient";

// ─── Types ───────────────────────────────────────────────────────────────────
export type {
  SolvencyClientConfig,
  EnrollmentRequest,
  EnrollmentResponse,
  MerkleProofData,
  MemberStatus,
  AdminMember,
  AdminMembersResponse,
  EpochEntry,
  AdminEpochsResponse,
  HealthResponse,
  SolvencyErrorCode,
} from "./types";

// ─── Crypto Utilities ────────────────────────────────────────────────────────
export {
  computeMemberId,
  buildEnrollmentMessage,
  verifySignatureFormat,
} from "./utils/crypto";

// ─── Merkle Utilities ────────────────────────────────────────────────────────
export { computeLeaf, verifyProof } from "./utils/merkle";

// ─── Formatting Utilities ────────────────────────────────────────────────────
export {
  toHex,
  fromHex,
  ensureHexPrefix,
  stripHexPrefix,
  isValidAddress,
  isValidBytes32,
  isValidSignature,
} from "./utils/formatting";
