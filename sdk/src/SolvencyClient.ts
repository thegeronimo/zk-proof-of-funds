import type {
  SolvencyClientConfig,
  EnrollmentRequest,
  EnrollmentResponse,
  MerkleProofData,
  MemberStatus,
  AdminMembersResponse,
  AdminEpochsResponse,
  HealthResponse,
  SolvencyErrorCode,
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
 * // Enroll a member
 * const { member_id } = await client.enroll({
 *   policy_id: "0x...",
 *   wallet_address: "0x...",
 *   signature: "0x...",
 *   signed_message: "zkpof-holder-v1:my-scope:42",
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
   * and stores the member for future solvency monitoring.
   *
   * @throws {SolvencyError} INVALID_REQUEST (400), CONFLICT (409), SERVER_ERROR (500)
   */
  async enroll(req: EnrollmentRequest): Promise<EnrollmentResponse> {
    return this.post<EnrollmentResponse>("/enroll", req);
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
