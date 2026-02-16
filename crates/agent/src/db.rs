//! Database — persistent storage for members, epochs, Merkle trees, webhooks.
//!
//! Uses SQLite for development and PostgreSQL for production.
//!
//! ## Schema
//!
//! - `members`: memberId, watchTarget, policyId, status, enrolledAt, effectiveEpoch, lastBalanceWei, lastCheckedBlock
//! - `epochs`: policyId, epoch, blockNumber, root, proofBytes, memberCount, publishedAtBlock
//! - `merkle_trees`: policyId, epoch, leaves (JSON blob of leaf hashes)
//! - `webhooks`: id, url, policyId, events (comma-separated), active

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
                member_id       TEXT PRIMARY KEY,   -- hex-encoded 32 bytes
                watch_target    TEXT NOT NULL,       -- hex-encoded 20 bytes
                policy_id       TEXT NOT NULL,       -- hex-encoded 32 bytes
                status          TEXT NOT NULL DEFAULT 'pending',  -- solvent/insolvent/pending/fetch_failed
                enrolled_at     INTEGER NOT NULL,    -- unix timestamp
                effective_epoch INTEGER NOT NULL,     -- first epoch this member appears in
                last_balance_wei TEXT NOT NULL DEFAULT '0',  -- stored as string (can exceed i64 for large balances)
                last_checked_block INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_members_policy ON members(policy_id);
            CREATE INDEX IF NOT EXISTS idx_members_status ON members(policy_id, status);

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
            "
        )?;
        Ok(())
    }

    // ── Members ─────────────────────────────────────────────────────────

    /// Insert a new member.
    pub fn insert_member(
        &self,
        member_id: &str,
        watch_target: &str,
        policy_id: &str,
        enrolled_at: u64,
        effective_epoch: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO members (member_id, watch_target, policy_id, status, enrolled_at, effective_epoch)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5)",
            params![member_id, watch_target, policy_id, enrolled_at, effective_epoch],
        )?;
        Ok(())
    }

    /// Get all members for a policy.
    pub fn get_members_for_policy(&self, policy_id: &str) -> Result<Vec<MemberRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_id, watch_target, policy_id, status, enrolled_at,
                    effective_epoch, last_balance_wei, last_checked_block
             FROM members WHERE policy_id = ?1"
        )?;
        let rows = stmt.query_map(params![policy_id], |row| {
            Ok(MemberRow {
                member_id: row.get(0)?,
                watch_target: row.get(1)?,
                policy_id: row.get(2)?,
                status: row.get(3)?,
                enrolled_at: row.get(4)?,
                effective_epoch: row.get(5)?,
                last_balance_wei: row.get(6)?,
                last_checked_block: row.get(7)?,
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
            "SELECT member_id, watch_target, policy_id, status, enrolled_at,
                    effective_epoch, last_balance_wei, last_checked_block
             FROM members WHERE member_id = ?1"
        )?;
        let mut rows = stmt.query_map(params![member_id], |row| {
            Ok(MemberRow {
                member_id: row.get(0)?,
                watch_target: row.get(1)?,
                policy_id: row.get(2)?,
                status: row.get(3)?,
                enrolled_at: row.get(4)?,
                effective_epoch: row.get(5)?,
                last_balance_wei: row.get(6)?,
                last_checked_block: row.get(7)?,
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
#[derive(Debug, Clone)]
pub struct MemberRow {
    pub member_id: String,
    pub watch_target: String,
    pub policy_id: String,
    pub status: String,
    pub enrolled_at: u64,
    pub effective_epoch: u64,
    pub last_balance_wei: String,  // Stored as string to support large balances (up to U256)
    pub last_checked_block: u64,
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

        // Insert a member
        db.insert_member(
            "aabbcc",
            "0x1234567890abcdef1234567890abcdef12345678",
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
        assert_eq!(member.watch_target, "0x1234567890abcdef1234567890abcdef12345678");

        // Update status (10 ETH in wei — exceeds i64 max, stored as string)
        db.update_member_status("aabbcc", "solvent", "10000000000000000000", 19_500_000).unwrap();
        let updated = db.get_member("aabbcc").unwrap().unwrap();
        assert_eq!(updated.status, "solvent");
        assert_eq!(updated.last_balance_wei, "10000000000000000000");
        assert_eq!(updated.last_checked_block, 19_500_000);
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
