//! Solvency Agent — the core middleware for ZK Proof of Funds.
//!
//! The agent verifies user-submitted state proofs, builds solvency Merkle trees,
//! and publishes roots on-chain. The agent **never stores wallet addresses** —
//! users submit their own EIP-1186 proofs, and the agent only retains the
//! privacy-preserving memberId (= SHA256(signature)).
//!
//! ## Components
//!
//! - **Scheduler** — triggers epoch updates per policy based on block intervals
//! - **RPC Fetcher** — fetches block state roots for proof verification
//! - **MPT Verifier** — verifies EIP-1186 account proofs against state roots
//! - **Proof Workers** — generates SP1 batch proofs for on-chain verification
//! - **Chain Publisher** — submits updateRoot() transactions on-chain
//! - **Merkle Service** — stores Merkle trees and serves per-member proofs
//! - **Enrollment** — handles member enrollment and signature verification
//! - **Database** — persistent storage for members, epochs, trees, proof submissions

pub mod config;
pub mod scheduler;
pub mod rpc_fetcher;
pub mod mpt_verifier;
pub mod proof_worker;
pub mod chain_publisher;
pub mod merkle_service;
pub mod enrollment;
pub mod epoch_processor;
pub mod solvent_set_service;
pub mod membership_prover;
pub mod derivation_prover;
pub mod webhook;
pub mod db;
