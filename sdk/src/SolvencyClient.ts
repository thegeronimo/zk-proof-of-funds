import type {
  SolvencyClientConfig,
  EnrollmentRequest,
  EnrollmentResponse,
  ProofSubmissionRequest,
  ProofSubmissionResponse,
  MerkleProofData,
  MemberStatus,
  AdminMembersResponse,
  AdminEpochsResponse,
  HealthResponse,
  SolvencyErrorCode,
  EnrollV2Request,
  EnrollV2Response,
  SolventSetInfo,
  SolventSetLeavesPage,
} from "./types";

/** Error thrown by SDK methods with a typed error code. */
export class SolvencyError extends Error {
  constructor(
    public readonly code: SolvencyErrorCode,
    message: string,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = "SolvencyError";
  }
}

/**
 * Client for the ZK Proof of Funds Solvency Agent REST API.
 *
 * Zero external dependencies — uses the global `fetch` API.
 *
 * @example
 * ```typescript
 * const client = new SolvencyClient({ agentUrl: "http://localhost:3000" });
 *
 * // Enroll a member (no wallet address sent to agent)
 * const { member_id } = await client.enroll({
 *   policy_id: "0x...",
 *   signature: "0x...",
 *   signed_message: "zkpof-holder-v1:my-scope:42",
 * });
 *
 * // Submit a solvency proof (wallet address used transiently, never stored)
 * const result = await client.submitProof(policyId, member_id, {
 *   wallet_address: "0x...",
 *   proof_nodes: ["0x...", ...],
 *   block_number: 19500000,
 * });
 *
 * // Fetch a Merkle proof for on-chain verification
 * const proof = await client.getMemberProof(policyId, member_id);
 * ```
 */
export class SolvencyClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof globalThis.fetch;

  constructor(config: SolvencyClientConfig) {
    // Strip trailing slash
    this.baseUrl = config.agentUrl.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.fetchFn = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  // ─── Core Methods ───────────────────────────────────────────────────────

  /**
   * Enroll a new member in a solvency policy.
   *
   * The member must first sign the enrollment message with their wallet.
   * The agent verifies the signature, computes a privacy-preserving memberId,
   * and stores the member. No wallet address is sent or stored by the agent.
   *
   * @throws {SolvencyError} INVALID_REQUEST (400), CONFLICT (409), SERVER_ERROR (500)
   */
  async enroll(req: EnrollmentRequest): Promise<EnrollmentResponse> {
    return this.post<EnrollmentResponse>("/enroll", req);
  }

  /**
   * Submit an EIP-1186 state proof to verify solvency for a member.
   *
   * The user fetches `eth_getProof` from their own Ethereum node and submits
   * the proof here. The agent verifies the MPT proof against the state root,
   * extracts the balance, and stores the verified result.
   *
   * The wallet_address is used ONLY for MPT verification (computing
   * keccak256(address) as the trie key) and is immediately discarded.
   *
   * @param policyId Hex-encoded 32-byte policy ID.
   * @param memberId Hex-encoded 32-byte member ID.
   * @param req Proof submission request containing wallet address, proof nodes, and block number.
   * @throws {SolvencyError} NOT_FOUND (404), INVALID_REQUEST (400), SERVER_ERROR (500)
   */
  async submitProof(
    policyId: string,
    memberId: string,
    req: ProofSubmissionRequest
  ): Promise<ProofSubmissionResponse> {
    return this.post<ProofSubmissionResponse>(
      `/submit_proof/${policyId}/${memberId}`,
      req
    );
  }

  // ─── Privacy V2 Methods (PRIVACY_V2.md) ─────────────────────────────────

  /**
   * Enroll with a deterministic nullifier + DLEQ proof (Privacy V2).
   *
   * memberId = SHA256(nullifier), cryptographically unique per (key, policy) —
   * unlike legacy enrollment, a wallet cannot mint multiple identities for
   * one policy. Requires raw key access to compute the nullifier
   * (PRIVACY_V2.md §3.3).
   *
   * @throws {SolvencyError} INVALID_REQUEST (400), CONFLICT (409)
   */
  async enrollV2(req: EnrollV2Request): Promise<EnrollV2Response> {
    return this.post<EnrollV2Response>("/v2/enroll", req);
  }

  /**
   * Get the latest solvent-set root metadata for a policy.
   *
   * @throws {SolvencyError} NOT_FOUND (404), INVALID_REQUEST (400)
   */
  async getSolventSet(policyId: string): Promise<SolventSetInfo> {
    return this.get<SolventSetInfo>(`/v2/solvent_set/${policyId}`);
  }

  /**
   * Get one page of the solvent set's public address list.
   *
   * @throws {SolvencyError} NOT_FOUND (404), INVALID_REQUEST (400)
   */
  async getSolventSetLeaves(
    policyId: string,
    opts: { epoch?: number; offset?: number; limit?: number } = {}
  ): Promise<SolventSetLeavesPage> {
    const params = new URLSearchParams();
    if (opts.epoch !== undefined) params.set("epoch", String(opts.epoch));
    if (opts.offset !== undefined) params.set("offset", String(opts.offset));
    if (opts.limit !== undefined) params.set("limit", String(opts.limit));
    const query = params.toString();
    return this.get<SolventSetLeavesPage>(
      `/v2/solvent_set/${policyId}/leaves${query ? `?${query}` : ""}`
    );
  }

  /**
   * Download the complete solvent-set address list (all pages).
   *
   * Downloading the full set — rather than querying for a specific address —
   * is what keeps the lookup oblivious: use it with
   * `computeSolventSetPath()` to build a membership path locally.
   *
   * @throws {SolvencyError} NOT_FOUND (404), INVALID_REQUEST (400)
   */
  async fetchAllSolventSetAddresses(
    policyId: string,
    epoch?: number
  ): Promise<{ info: SolventSetInfo; addresses: string[] }> {
    const pageSize = 10_000;
    const first = await this.getSolventSetLeaves(policyId, {
      epoch,
      offset: 0,
      limit: pageSize,
    });
    const addresses = [...first.addresses];
    while (addresses.length < first.total) {
      const page = await this.getSolventSetLeaves(policyId, {
        epoch: first.epoch,
        offset: addresses.length,
        limit: pageSize,
      });
      if (page.addresses.length === 0) break; // defensive: avoid infinite loop
      addresses.push(...page.addresses);
    }
    return {
      info: {
        policy_id: first.policy_id,
        epoch: first.epoch,
        block_number: first.block_number,
        root: first.root,
        member_count: first.total,
      },
      addresses,
    };
  }

  /**
   * Get a Merkle membership proof for a member.
   *
   * The proof can be submitted to the SolvencyRootOracle contract's
   * `verifyMember()` or `isMemberSolvent()` functions.
   *
   * @param policyId Hex-encoded 32-byte policy ID.
   * @param memberId Hex-encoded 32-byte member ID.
   * @throws {SolvencyError} NOT_FOUND (404), INVALID_REQUEST (400)
   */
  async getMemberProof(
    policyId: string,
    memberId: string
  ): Promise<MerkleProofData> {
    return this.get<MerkleProofData>(`/proof/${policyId}/${memberId}`);
  }

  /**
   * Get the current status of a member.
   *
   * @param policyId Hex-encoded 32-byte policy ID.
   * @param memberId Hex-encoded 32-byte member ID.
   * @throws {SolvencyError} NOT_FOUND (404)
   */
  async getMemberStatus(
    policyId: string,
    memberId: string
  ): Promise<MemberStatus> {
    return this.get<MemberStatus>(`/status/${policyId}/${memberId}`);
  }

  // ─── Admin Methods ──────────────────────────────────────────────────────

  /**
   * List all members enrolled in a policy.
   *
   * @param policyId Hex-encoded 32-byte policy ID.
   */
  async listMembers(policyId: string): Promise<AdminMembersResponse> {
    return this.get<AdminMembersResponse>(`/admin/members/${policyId}`);
  }

  /**
   * Get epoch history for a policy.
   *
   * @param policyId Hex-encoded 32-byte policy ID.
   */
  async getEpochHistory(policyId: string): Promise<AdminEpochsResponse> {
    return this.get<AdminEpochsResponse>(`/admin/epochs/${policyId}`);
  }

  // ─── Utility Methods ────────────────────────────────────────────────────

  /**
   * Check the health of the Solvency Agent API.
   */
  async health(): Promise<HealthResponse> {
    return this.get<HealthResponse>("/health");
  }

  // ─── Private HTTP Methods ───────────────────────────────────────────────

  private async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(url, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        const code = this.mapStatusCode(response.status);
        const message =
          (data as { error?: string }).error ??
          `HTTP ${response.status}: ${response.statusText}`;
        throw new SolvencyError(code, message, response.status);
      }

      return data as T;
    } catch (error) {
      if (error instanceof SolvencyError) throw error;

      if (error instanceof DOMException && error.name === "AbortError") {
        throw new SolvencyError(
          "TIMEOUT",
          `Request to ${path} timed out after ${this.timeoutMs}ms`
        );
      }

      throw new SolvencyError(
        "NETWORK_ERROR",
        `Failed to fetch ${url}: ${error instanceof Error ? error.message : String(error)}`
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  private mapStatusCode(status: number): SolvencyErrorCode {
    if (status === 400) return "INVALID_REQUEST";
    if (status === 404) return "NOT_FOUND";
    if (status === 409) return "CONFLICT";
    return "SERVER_ERROR";
  }
}
