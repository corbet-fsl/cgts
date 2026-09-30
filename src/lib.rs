//! Community gate orchestration. Leaves verify evidence; this facade retains only
//! gate metadata and opaque single-use markers. See `docs/CONTRACT.md`.
#![forbid(unsafe_code)]

mod engine;
pub mod gates;
mod model;
mod passport;
pub mod pins;
pub mod storage;

pub use crbk::{GateLevel, MembershipState, Snapshot};
pub use engine::*;
pub use model::*;
pub use passport::*;
pub use storage::{LibsqlStore, MemoryStore, SCHEMA, Storage};

/// Failures never grant a gate and never expose upstream input or diagnostics.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Malformed trusted configuration or request context.
    #[error("invalid gate context")]
    Invalid,
    /// A community, subject, action or policy binding differs.
    #[error("gate scope mismatch")]
    Scope,
    /// Gate or provider is off, absent or null in the snapshot.
    #[error("gate unavailable")]
    Disabled,
    /// The complete private balance extension relation has not been proven.
    #[error("balance and record gates unavailable: extension proofs are not enabled")]
    ExtensionsUnavailable,
    /// Evidence failed verification or was already spent.
    #[error("gate refused")]
    Refused,
    /// An active legal restriction covers this action.
    #[error("action vetoed")]
    Vetoed,
    /// Storage failed or returned malformed data. No automatic write retries.
    #[error("gate storage unavailable")]
    Storage,
    /// The legal authority service failed; this is never green.
    #[error("legal gate unavailable")]
    Legal,
    /// A rulebook policy is malformed.
    #[error("invalid gate policy")]
    Policy,
}

impl From<crlt::Error> for Error {
    fn from(_: crlt::Error) -> Self {
        Self::Storage
    }
}

/// Redacted facade result.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn identifier(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}

pub(crate) fn component(value: &str) -> Result<()> {
    identifier(value)?;
    if value.contains('/') {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
