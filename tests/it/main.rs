//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/internal` still holds the library's `#[path]` unit tests.
//!
//! `account_service` is a module here too; its 12 tests are the `bot` tier of
//! `cmeet/ci/land-tests.txt` (they need the original authenticated CBLC_PROOF_DIRECTORY and
//! CBLC_BB artifacts), so the land skips them by name and the per-repo CI runs them.
mod account_service;
mod balance;
mod claim_transactions;
#[path = "../common/mod.rs"]
mod common;
mod gates;
mod legal_common;
mod legal_database;
mod legal_self_ban_status;
mod legal_transactions;
mod legal_turso;
mod passport;
mod payments;
mod profile;
mod storage;
mod turso;
