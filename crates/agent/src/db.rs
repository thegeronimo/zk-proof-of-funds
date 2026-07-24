//! Database — persistent storage for members, epochs, Merkle trees, proof submissions, webhooks.
//!
//! Uses SQLite for development and PostgreSQL for production.
//!
//! ## Schema
//!
//! - `members`: memberId, policyId, status, enrolledAt, effectiveEpoch, lastBalanceWei, lastCheckedBlock
//! - `proof_submissions`: memberId, policyId, epoch, blockNumber, balanceWei, isSolvent
//! - `epochs`: policyId, epoch, blockNumber, root, proofBytes, memberCount, publishedAtBlock
//! - `merkle_trees`: policyId, epoch, leaves (JSON blob of leaf hashes)
//! - `webhooks`: id, url, policyId, events (comma-separated), active
//!
//! ## Privacy
//!
//! The `members` table does NOT store wallet addresses (watch_target).
//! The agent never persists any address data. Users submit their own
//! EIP-1186 proofs, and the agent only stores the memberId and verified balance.

use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;

/// Database handle wrapping a SQLite connection.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    /// Create all tables if they don't exist.
    fn create_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS members (
                member_id       TEXT PRIMARY KEY,   -- hex-encoded 32 bytes (SHA256 of signature)
                policy_id       TEXT NOT NULL,       -- hex-encoded 32 bytes
                status          TEXT NOT NULL DEFAULT 'pending',  -- solvent/insolvent/pending/fetch_failed
                enrolled_at     INTEGER NOT NULL,    -- unix timestamp
                effective_epoch INTEGER NOT NULL,     -- first epoch this member appears in
                last_balance_wei TEXT NOT NULL DEFAULT '0',  -- stored as string (can exceed i64 for large balances)
                last_checked_block INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_members_policy ON members(policy_id);
            CREATE INDEX IF NOT EXISTS idx_members_status ON members(policy_id, status);

            CREATE TABLE IF NOT EXISTS proof_submissions (
                member_id       TEXT NOT NULL,       -- hex-encoded 32 bytes
                policy_id       TEXT NOT NULL,       -- hex-encoded 32 bytes
                epoch           INTEGER NOT NULL,    -- epoch this proof is for
                block_number    INTEGER NOT NULL,    -- block the MPT proof references
                balance_wei     TEXT NOT NULL,       -- verified balance extracted from MPT proof
                is_solvent      INTEGER NOT NULL,    -- 1 or 0
                submitted_at    TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (member_id, policy_id, epoch)
            );

            CREATE INDEX IF NOT EXISTS idx_proof_submissions_epoch ON proof_submissions(policy_id, epoch);

            CREATE TABLE IF NOT EXISTS epochs (
                policy_id       TEXT NOT NULL,       -- hex-encoded 32 bytes
                epoch           INTEGER NOT NULL,
                block_number    INTEGER NOT NULL,
                root            TEXT NOT NULL,       -- hex-encoded 32 bytes
                member_count    INTEGER NOT NULL,
                published_at_block INTEGER NOT NULL DEFAULT 0,
                proof_bytes     BLOB,                -- SP1 proof or empty for trusted mode
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (policy_id, epoch)
            );

            CREATE TABLE IF NOT EXISTS merkle_trees (
                policy_id       TEXT NOT NULL,
                epoch           INTEGER NOT NULL,
                leaves_json     TEXT NOT NULL,       -- JSON array of hex-encoded leaf hashes
                PRIMARY KEY (policy_id, epoch)
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                url             TEXT NOT NULL,
                policy_id       TEXT NOT NULL,
                events          TEXT NOT NULL,       -- comma-separated event types
                active          INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_webhooks_policy ON webhooks(policy_id, active);

            CREATE TABLE IF NOT EXISTS nullifiers (
                policy_id       TEXT NOT NULL,       -- canonical lowercase hex (32 bytes)
                nullifier_hash  TEXT NOT NULL,       -- hex 32 bytes; equals the member_id
                nullifier       TEXT NOT NULL,       -- hex 33-byte compressed secp256k1 point
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (policy_id, nullifier_hash)
            );

            CREATE TABLE IF NOT EXISTS solvent_sets (
                policy_id       TEXT NOT NULL,
                epoch           INTEGER NOT NULL,
                block_number    INTEGER NOT NULL,    -- reference block balances were sampled at
                root            TEXT NOT NULL,       -- hex 32-byte solvent-set Merkle root
                member_count    INTEGER NOT NULL,
                addresses_json  TEXT NOT NULL,       -- JSON array of hex addresses (canonical order)
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (policy_id, epoch)
            );
            "
        )?;
        Ok(())
    }

    // ── Members ─────────────────────────────────────────────────────────

    /// Insert a new member.
    ///
    /// No wallet address is stored — the agent only knows the memberId.
    pub fn insert_member(
        &self,
        member_id: &str,
        policy_id: &str,
        enrolled_at: u64,
        effective_epoch: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO members (member_id, policy_id, status, enrolled_at, effective_epoch)
             VALUES (?1, ?2, 'pending', ?3, ?4)",
            params![member_id, policy_id, enrolled_at, effective_epoch],
        )?;
        Ok(())
    }

    /// Get all members for a policy.
    pub fn get_members_for_policy(&self, policy_id: &str) -> Result<Vec<MemberRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_id, policy_id, status, enrolled_at,
                    effective_epoch, last_balance_wei, last_checked_block
             FROM members WHERE policy_id = ?1"
        )?;
        let rows = stmt.query_map(params![policy_id], |row| {
            Ok(MemberRow {
                member_id: row.get(0)?,
                policy_id: row.get(1)?,
                status: row.get(2)?,
                enrolled_at: row.get(3)?,
                effective_epoch: row.get(4)?,
                last_balance_wei: row.get(5)?,
                last_checked_block: row.get(6)?,
            })
        })?;
        let mut members = Vec::new();
        for row in rows {
            members.push(row?);
        }
        Ok(members)
    }

    /// Get a single member by ID.
    pub fn get_member(&self, member_id: &str) -> Result<Option<MemberRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_id, policy_id, status, enrolled_at,
                    effective_epoch, last_balance_wei, last_checked_block
             FROM members WHERE member_id = ?1"
        )?;
        let mut rows = stmt.query_map(params![member_id], |row| {
            Ok(MemberRow {
                member_id: row.get(0)?,
                policy_id: row.get(1)?,
                status: row.get(2)?,
                enrolled_at: row.get(3)?,
                effective_epoch: row.get(4)?,
                last_balance_wei: row.get(5)?,
                last_checked_block: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Update a member's status and balance after an epoch check.
    pub fn update_member_status(
        &self,
        member_id: &str,
        status: &str,
        balance_wei: &str,
        checked_block: u64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE members SET status = ?1, last_balance_wei = ?2, last_checked_block = ?3
             WHERE member_id = ?4",
            params![status, balance_wei, checked_block, member_id],
        )?;
        Ok(())
    }

    // ── Epochs ──────────────────────────────────────────────────────────

    /// Insert a completed epoch record.
    pub fn insert_epoch(
        &self,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        root: &str,
        member_count: u32,
        published_at_block: u64,
        proof_bytes: Option<&[u8]>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO epochs (policy_id, epoch, block_number, root, member_count, published_at_block, proof_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![policy_id, epoch, block_number, root, member_count, published_at_block, proof_bytes],
        )?;
        Ok(())
    }

    /// Get the latest epoch for a policy.
    pub fn get_latest_epoch(&self, policy_id: &str) -> Result<Option<EpochRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT policy_id, epoch, block_number, root, member_count, published_at_block
             FROM epochs WHERE policy_id = ?1 ORDER BY epoch DESC LIMIT 1"
        )?;
        let mut rows = stmt.query_map(params![policy_id], |row| {
            Ok(EpochRow {
                policy_id: row.get(0)?,
                epoch: row.get(1)?,
                block_number: row.get(2)?,
                root: row.get(3)?,
                member_count: row.get(4)?,
                published_at_block: row.get(5)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    // ── Merkle Trees ────────────────────────────────────────────────────

    /// Store the complete Merkle tree leaves for an epoch (as JSON array of hex strings).
    pub fn store_merkle_tree(
        &self,
        policy_id: &str,
        epoch: u64,
        leaves_json: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO merkle_trees (policy_id, epoch, leaves_json)
             VALUES (?1, ?2, ?3)",
            params![policy_id, epoch, leaves_json],
        )?;
        Ok(())
    }

    /// Retrieve the Merkle tree leaves for an epoch.
    pub fn get_merkle_tree(&self, policy_id: &str, epoch: u64) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT leaves_json FROM merkle_trees WHERE policy_id = ?1 AND epoch = ?2"
        )?;
        let mut rows = stmt.query_map(params![policy_id, epoch], |row| {
            row.get::<_, String>(0)
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    // ── Proof Submissions ──────────────────────────────────────────────

    /// Insert or update a proof submission for a member/policy/epoch.
    ///
    /// Called when a user submits an MPT proof via `/submit_proof`.
    /// The balance and solvency status are already verified by the MPT verifier.
    pub fn insert_proof_submission(
        &self,
        member_id: &str,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        balance_wei: &str,
        is_solvent: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO proof_submissions
                (member_id, policy_id, epoch, block_number, balance_wei, is_solvent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                member_id,
                policy_id,
                epoch,
                block_number,
                balance_wei,
                is_solvent as i32,
            ],
        )?;
        Ok(())
    }

    /// Get all proof submissions for a policy/epoch.
    ///
    /// Used during epoch processing to determine each member's solvency status.
    pub fn get_proof_submissions_for_epoch(
        &self,
        policy_id: &str,
        epoch: u64,
    ) -> Result<Vec<ProofSubmissionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_id, policy_id, epoch, block_number, balance_wei, is_solvent
             FROM proof_submissions WHERE policy_id = ?1 AND epoch = ?2"
        )?;
        let rows = stmt.query_map(params![policy_id, epoch], |row| {
            Ok(ProofSubmissionRow {
                member_id: row.get(0)?,
                policy_id: row.get(1)?,
                epoch: row.get(2)?,
                block_number: row.get(3)?,
                balance_wei: row.get(4)?,
                is_solvent: row.get::<_, i32>(5)? != 0,
            })
        })?;
        let mut submissions = Vec::new();
        for row in rows {
            submissions.push(row?);
        }
        Ok(submissions)
    }

    /// Get the latest proof submission for a specific member in a policy.
    pub fn get_latest_proof_submission(
        &self,
        member_id: &str,
        policy_id: &str,
    ) -> Result<Option<ProofSubmissionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_id, policy_id, epoch, block_number, balance_wei, is_solvent
             FROM proof_submissions WHERE member_id = ?1 AND policy_id = ?2
             ORDER BY epoch DESC LIMIT 1"
        )?;
        let mut rows = stmt.query_map(params![member_id, policy_id], |row| {
            Ok(ProofSubmissionRow {
                member_id: row.get(0)?,
                policy_id: row.get(1)?,
                epoch: row.get(2)?,
                block_number: row.get(3)?,
                balance_wei: row.get(4)?,
                is_solvent: row.get::<_, i32>(5)? != 0,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    // ── Nullifiers (Privacy V2) ─────────────────────────────────────────

    /// Register a nullifier for a policy. Fails if it is already registered —
    /// this is what enforces "one identity per key per policy".
    pub fn insert_nullifier(
        &self,
        policy_id: &str,
        nullifier_hash: &str,
        nullifier: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO nullifiers (policy_id, nullifier_hash, nullifier) VALUES (?1, ?2, ?3)",
            params![policy_id, nullifier_hash, nullifier],
        )?;
        Ok(())
    }

    /// Check whether a nullifier hash is already registered for a policy.
    pub fn nullifier_exists(&self, policy_id: &str, nullifier_hash: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            "SELECT 1 FROM nullifiers WHERE policy_id = ?1 AND nullifier_hash = ?2",
        )?;
        Ok(stmt.exists(params![policy_id, nullifier_hash])?)
    }

    // ── Solvent Sets (Privacy V2) ───────────────────────────────────────

    /// Store a solvent set for a policy epoch (replaces any prior build of the
    /// same epoch — rebuilds are idempotent).
    pub fn store_solvent_set(
        &self,
        policy_id: &str,
        epoch: u64,
        block_number: u64,
        root: &str,
        member_count: u32,
        addresses_json: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO solvent_sets
                (policy_id, epoch, block_number, root, member_count, addresses_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![policy_id, epoch, block_number, root, member_count, addresses_json],
        )?;
        Ok(())
    }

    /// Get the solvent set for a specific policy epoch.
    pub fn get_solvent_set(&self, policy_id: &str, epoch: u64) -> Result<Option<SolventSetRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT policy_id, epoch, block_number, root, member_count, addresses_json
             FROM solvent_sets WHERE policy_id = ?1 AND epoch = ?2",
        )?;
        let mut rows = stmt.query_map(params![policy_id, epoch], Self::map_solvent_set_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get the most recent solvent set for a policy.
    pub fn get_latest_solvent_set(&self, policy_id: &str) -> Result<Option<SolventSetRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT policy_id, epoch, block_number, root, member_count, addresses_json
             FROM solvent_sets WHERE policy_id = ?1 ORDER BY epoch DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![policy_id], Self::map_solvent_set_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get the most recent solvent set strictly before the given epoch.
    ///
    /// Used for streak continuity: rebuilding epoch N must chain from N-1's
    /// streaks even when N itself was already (partially) built.
    pub fn get_latest_solvent_set_before(
        &self,
        policy_id: &str,
        epoch: u64,
    ) -> Result<Option<SolventSetRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT policy_id, epoch, block_number, root, member_count, addresses_json
             FROM solvent_sets WHERE policy_id = ?1 AND epoch < ?2 ORDER BY epoch DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![policy_id, epoch], Self::map_solvent_set_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    fn map_solvent_set_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SolventSetRow> {
        Ok(SolventSetRow {
            policy_id: row.get(0)?,
            epoch: row.get(1)?,
            block_number: row.get(2)?,
            root: row.get(3)?,
            member_count: row.get(4)?,
            addresses_json: row.get(5)?,
        })
    }

    // ── Webhooks ────────────────────────────────────────────────────────

    /// Register a new webhook.
    pub fn insert_webhook(&self, url: &str, policy_id: &str, events: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO webhooks (url, policy_id, events) VALUES (?1, ?2, ?3)",
            params![url, policy_id, events],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get active webhooks for a policy.
    pub fn get_webhooks_for_policy(&self, policy_id: &str) -> Result<Vec<WebhookRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, url, policy_id, events FROM webhooks WHERE policy_id = ?1 AND active = 1"
        )?;
        let rows = stmt.query_map(params![policy_id], |row| {
            Ok(WebhookRow {
                id: row.get(0)?,
                url: row.get(1)?,
                policy_id: row.get(2)?,
                events: row.get(3)?,
            })
        })?;
        let mut webhooks = Vec::new();
        for row in rows {
            webhooks.push(row?);
        }
        Ok(webhooks)
    }
}

// ─── Row types ──────────────────────────────────────────────────────────────

/// A member row from the database.
///
/// No wallet address is stored — the agent only retains the privacy-preserving memberId.
#[derive(Debug, Clone)]
pub struct MemberRow {
    pub member_id: String,
    pub policy_id: String,
    pub status: String,
    pub enrolled_at: u64,
    pub effective_epoch: u64,
    pub last_balance_wei: String,  // Stored as string to support large balances (up to U256)
    pub last_checked_block: u64,
}

/// A proof submission row from the database.
///
/// Represents a user-submitted MPT proof that has been verified by the agent.
#[derive(Debug, Clone)]
pub struct ProofSubmissionRow {
    pub member_id: String,
    pub policy_id: String,
    pub epoch: u64,
    pub block_number: u64,
    pub balance_wei: String,
    pub is_solvent: bool,
}

/// An epoch row from the database.
#[derive(Debug, Clone)]
pub struct EpochRow {
    pub policy_id: String,
    pub epoch: u64,
    pub block_number: u64,
    pub root: String,
    pub member_count: u32,
    pub published_at_block: u64,
}

/// A webhook row from the database.
#[derive(Debug, Clone)]
pub struct WebhookRow {
    pub id: i64,
    pub url: String,
    pub policy_id: String,
    pub events: String,
}

/// A solvent-set row from the database (Privacy V2).
#[derive(Debug, Clone)]
pub struct SolventSetRow {
    pub policy_id: String,
    pub epoch: u64,
    pub block_number: u64,
    pub root: String,
    pub member_count: u32,
    pub addresses_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_database() {
        let db = Database::open_in_memory().unwrap();
        // Tables should be created without error
        assert!(db.get_members_for_policy("test").unwrap().is_empty());
    }

    #[test]
    fn test_member_crud() {
        let db = Database::open_in_memory().unwrap();

        // Insert a member (no wallet address stored)
        db.insert_member(
            "aabbcc",
            "policy_001",
            1700000000,
            42,
        ).unwrap();

        // Retrieve by policy
        let members = db.get_members_for_policy("policy_001").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].member_id, "aabbcc");
        assert_eq!(members[0].status, "pending");
        assert_eq!(members[0].effective_epoch, 42);

        // Retrieve by ID
        let member = db.get_member("aabbcc").unwrap().unwrap();
        assert_eq!(member.policy_id, "policy_001");

        // Update status (10 ETH in wei — exceeds i64 max, stored as string)
        db.update_member_status("aabbcc", "solvent", "10000000000000000000", 19_500_000).unwrap();
        let updated = db.get_member("aabbcc").unwrap().unwrap();
        assert_eq!(updated.status, "solvent");
        assert_eq!(updated.last_balance_wei, "10000000000000000000");
        assert_eq!(updated.last_checked_block, 19_500_000);
    }

    #[test]
    fn test_proof_submission_crud() {
        let db = Database::open_in_memory().unwrap();

        // Insert a proof submission
        db.insert_proof_submission(
            "member_001",
            "policy_001",
            1,
            19_000_000,
            "5000000000000000000",
            true,
        ).unwrap();

        // Retrieve by epoch
        let submissions = db.get_proof_submissions_for_epoch("policy_001", 1).unwrap();
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0].member_id, "member_001");
        assert_eq!(submissions[0].balance_wei, "5000000000000000000");
        assert!(submissions[0].is_solvent);

        // Get latest for member
        let latest = db.get_latest_proof_submission("member_001", "policy_001").unwrap().unwrap();
        assert_eq!(latest.epoch, 1);

        // Insert for next epoch (should not affect epoch 1)
        db.insert_proof_submission(
            "member_001",
            "policy_001",
            2,
            19_000_100,
            "100000000000000000",
            false,
        ).unwrap();

        let submissions_e1 = db.get_proof_submissions_for_epoch("policy_001", 1).unwrap();
        assert_eq!(submissions_e1.len(), 1);

        let submissions_e2 = db.get_proof_submissions_for_epoch("policy_001", 2).unwrap();
        assert_eq!(submissions_e2.len(), 1);
        assert!(!submissions_e2[0].is_solvent);

        // Latest should be epoch 2
        let latest = db.get_latest_proof_submission("member_001", "policy_001").unwrap().unwrap();
        assert_eq!(latest.epoch, 2);
    }

    #[test]
    fn test_epoch_crud() {
        let db = Database::open_in_memory().unwrap();

        db.insert_epoch("policy_001", 1, 19_000_000, "aabb", 10, 19_000_050, None).unwrap();
        db.insert_epoch("policy_001", 2, 19_000_100, "ccdd", 11, 19_000_150, None).unwrap();

        let latest = db.get_latest_epoch("policy_001").unwrap().unwrap();
        assert_eq!(latest.epoch, 2);
        assert_eq!(latest.root, "ccdd");
        assert_eq!(latest.member_count, 11);
    }

    #[test]
    fn test_merkle_tree_storage() {
        let db = Database::open_in_memory().unwrap();

        let leaves_json = r#"["aabb","ccdd","eeff"]"#;
        db.store_merkle_tree("policy_001", 42, leaves_json).unwrap();

        let retrieved = db.get_merkle_tree("policy_001", 42).unwrap().unwrap();
        assert_eq!(retrieved, leaves_json);

        // Non-existent epoch returns None
        assert!(db.get_merkle_tree("policy_001", 99).unwrap().is_none());
    }

    #[test]
    fn test_nullifier_uniqueness() {
        let db = Database::open_in_memory().unwrap();

        db.insert_nullifier("policy_a", "hash_1", "02aabb").unwrap();
        assert!(db.nullifier_exists("policy_a", "hash_1").unwrap());
        assert!(!db.nullifier_exists("policy_a", "hash_2").unwrap());
        assert!(!db.nullifier_exists("policy_b", "hash_1").unwrap());

        // Same (policy, nullifier) must be rejected — one identity per key per policy.
        assert!(db.insert_nullifier("policy_a", "hash_1", "02aabb").is_err());
        // Same nullifier under a different policy is a different identity.
        db.insert_nullifier("policy_b", "hash_1", "02aabb").unwrap();
    }

    #[test]
    fn test_solvent_set_crud() {
        let db = Database::open_in_memory().unwrap();

        db.store_solvent_set("policy_a", 1, 19_000_000, "rootaa", 3, r#"["aa","bb","cc"]"#)
            .unwrap();
        db.store_solvent_set("policy_a", 2, 19_000_100, "rootbb", 4, r#"["aa","bb","cc","dd"]"#)
            .unwrap();

        let e1 = db.get_solvent_set("policy_a", 1).unwrap().unwrap();
        assert_eq!(e1.root, "rootaa");
        assert_eq!(e1.member_count, 3);
        assert_eq!(e1.block_number, 19_000_000);

        let latest = db.get_latest_solvent_set("policy_a").unwrap().unwrap();
        assert_eq!(latest.epoch, 2);
        assert_eq!(latest.root, "rootbb");

        // Rebuilding an epoch replaces it (idempotent).
        db.store_solvent_set("policy_a", 2, 19_000_101, "rootcc", 5, r#"["aa"]"#).unwrap();
        let rebuilt = db.get_latest_solvent_set("policy_a").unwrap().unwrap();
        assert_eq!(rebuilt.root, "rootcc");
        assert_eq!(rebuilt.member_count, 5);

        assert!(db.get_solvent_set("policy_a", 99).unwrap().is_none());
        assert!(db.get_latest_solvent_set("policy_zzz").unwrap().is_none());
    }

    #[test]
    fn test_webhook_crud() {
        let db = Database::open_in_memory().unwrap();

        let id = db.insert_webhook(
            "https://example.com/hook",
            "policy_001",
            "member.enrolled,epoch.completed",
        ).unwrap();
        assert!(id > 0);

        let hooks = db.get_webhooks_for_policy("policy_001").unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].url, "https://example.com/hook");
        assert_eq!(hooks[0].events, "member.enrolled,epoch.completed");
    }
}
