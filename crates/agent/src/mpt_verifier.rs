//! Host-side MPT verification — re-export of the shared implementation.
//!
//! The account-proof verifier lives in `zk_pof_common::mpt` so the SP1
//! derivation guest (`program-solvent-set/`) shares it byte-for-byte with the
//! host. This module keeps the historical `zk_pof_agent::mpt_verifier` path
//! working for the backend and existing callers.

pub use zk_pof_common::mpt::{balance_meets_threshold, verify_account_balance};
