//! Solvency Agent — the core middleware for ZK Proof of Funds.
//!
//! The agent continuously monitors enrolled members, generates batch ZK proofs
//! (or EIP-712 signed assertions in trusted mode), publishes solvency Merkle
//! roots on-chain, and serves per-member inclusion proofs to relying protocols.
//!
//! ## Components
//!
//! - **Scheduler** — triggers epoch updates per policy based on block intervals
//! - **RPC Fetcher** — fetches EIP-1186 state proofs for all members in a batch
//! - **Proof Workers** — generates SP1 batch proofs or EIP-712 signatures
//! - **Chain Publisher** — submits updateRoot() transactions on-chain
//! - **Merkle Service** — stores Merkle trees and serves per-member proofs
//! - **Enrollment** — handles member enrollment and signature verification
//! - **Database** — persistent storage for members, epochs, trees

pub mod config;
pub mod scheduler;
pub mod rpc_fetcher;
pub mod proof_worker;
pub mod chain_publisher;
pub mod merkle_service;
pub mod enrollment;
pub mod epoch_processor;
pub mod webhook;
pub mod db;
