//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/internal` still holds the library's `#[path]` unit tests.
//!
//! `tests/account_service.rs` stays its own target: `cmeet/ci/land-tests.txt` marks it
//! `bot` (needs original authenticated native artifact fixtures), so the land never runs it.
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
