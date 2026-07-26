// ─── Client ──────────────────────────────────────────────────────────────────
export { SolvencyClient, SolvencyError } from "./SolvencyClient";

// ─── Types ───────────────────────────────────────────────────────────────────
export type {
  SolvencyClientConfig,
  EnrollmentRequest,
  EnrollmentResponse,
  ProofSubmissionRequest,
  ProofSubmissionResponse,
  MerkleProofData,
  MemberStatus,
  AdminMember,
  AdminMembersResponse,
  EpochEntry,
  AdminEpochsResponse,
  HealthResponse,
  SolvencyErrorCode,
  EnrollV2Request,
  EnrollV2Response,
  SolventSetInfo,
  SolventSetLeavesPage,
  BuildSolventSetRequest,
  BuildSolventSetResponse,
  TriggerEpochResponse,
} from "./types";

// ─── Crypto Utilities ────────────────────────────────────────────────────────
export {
  computeMemberId,
  buildEnrollmentMessage,
  verifySignatureFormat,
} from "./utils/crypto";

// ─── Merkle Utilities ────────────────────────────────────────────────────────
export { computeLeaf, verifyProof } from "./utils/merkle";

// ─── Solvent-Set Utilities (Privacy V2) ──────────────────────────────────────
export {
  computeSolventLeaf,
  computeSolventSetRoot,
  computeSolventSetPath,
  verifySolventMembership,
} from "./utils/solventSet";
export type { SolventSetPath, SolventSetEntryTuple } from "./utils/solventSet";

// ─── Membership Public Values (Privacy V2) ───────────────────────────────────
export {
  decodeMembershipPublicValues,
  checkMembershipPublicValues,
  MEMBERSHIP_PUBLIC_VALUES_LEN,
} from "./utils/membership";
export type {
  MembershipPublicValues,
  MembershipExpectation,
  MembershipCheckResult,
  MembershipCheckFailure,
} from "./utils/membership";

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
