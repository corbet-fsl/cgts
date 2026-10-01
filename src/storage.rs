//! Current gate facts and unlinkable spent markers, through crlt only.
use crate::*;
use crlt::params;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{Arc, Mutex},
};

/// Append to the composition root's complete migration list. No fixed version.
pub const SCHEMA: &str = include_str!("schema.sql");

/// Trusted community-bound storage. `commit` must atomically reject an already
/// claimed marker and replace the current fact; failures must leave both intact.
/// Reads are complete or fail. Evidence bytes and timestamps never enter storage.
pub trait Storage: Send + Sync {
    /// Fixed service-selected community.
    fn community(&self) -> &str;
    /// Current facts, ordered by gate/provider; expired facts may be returned.
    fn load(&self, subject: &str) -> impl Future<Output = Result<Vec<GateResult>>> + Send;
    /// Atomic first claim and optional current-result replacement. No histories.
    fn commit(
        &self,
        result: Option<&GateResult>,
        claim: Option<&Claim>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Remove one fact without rearming any spent marker.
    fn remove(
        &self,
        subject: &str,
        gate: &str,
        provider: &str,
    ) -> impl Future<Output = Result<()>> + Send;
}

fn validate(result: Option<&GateResult>) -> Result<()> {
    if let Some(result) = result {
        result.validate()?;
        if result.valid_until % 86_400 != 0 {
            return Err(Error::Invalid);
        }
        if result.level != GateLevel::Community {
            return Err(Error::Scope);
        }
    }
    Ok(())
}

fn key(subject: &str, gate: &str, provider: &str) -> Result<(String, String, String)> {
    identifier(subject)?;
    component(gate)?;
    component(provider)?;
    Ok((subject.into(), gate.into(), provider.into()))
}

#[derive(Default)]
struct State {
    results: BTreeMap<(String, String, String), GateResult>,
    claims: BTreeSet<(String, Vec<u8>)>,
}

/// Real atomic memory implementation. Clones share data; restart loses claims.
/// Use libSQL for durable voucher and balance redemption.
#[derive(Clone)]
pub struct MemoryStore {
    community: String,
    state: Arc<Mutex<State>>,
}

impl MemoryStore {
    /// Create an empty namespace for tests or disposable development.
    pub fn new(community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        identifier(&community)?;
        Ok(Self {
            community,
            state: Arc::default(),
        })
    }
}

impl Storage for MemoryStore {
    fn community(&self) -> &str {
        &self.community
    }
    async fn load(&self, subject: &str) -> Result<Vec<GateResult>> {
        identifier(subject)?;
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        Ok(state
            .results
            .range((subject.into(), String::new(), String::new())..)
            .take_while(|((owner, _, _), _)| owner == subject)
            .map(|(_, result)| result.clone())
            .collect())
    }
    async fn commit(&self, result: Option<&GateResult>, claim: Option<&Claim>) -> Result<()> {
        validate(result)?;
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        if let Some(claim) = claim
            && !state
                .claims
                .insert((claim.domain.clone(), claim.marker.clone()))
        {
            return Err(Error::Refused);
        }
        if let Some(result) = result {
            state.results.insert(
                (
                    result.subject.clone(),
                    result.gate.clone(),
                    result.provider.clone(),
                ),
                result.clone(),
            );
        }
        Ok(())
    }
    async fn remove(&self, subject: &str, gate: &str, provider: &str) -> Result<()> {
        let key = key(subject, gate, provider)?;
        self.state
            .lock()
            .map_err(|_| Error::Storage)?
            .results
            .remove(&key);
        Ok(())
    }
}

const LOAD: &str = "SELECT gate, provider, valid_until FROM cgts_results WHERE subject = ?1 ORDER BY gate, provider";
const DELETE: &str = "DELETE FROM cgts_results WHERE subject = ?1 AND gate = ?2 AND provider = ?3";
const INSERT: &str =
    "INSERT INTO cgts_results (subject, gate, provider, valid_until) VALUES (?1, ?2, ?3, ?4)";
const CLAIM: &str = "SELECT marker FROM cgts_spent WHERE domain = ?1 AND marker = ?2";
const SPEND: &str = "INSERT INTO cgts_spent (domain, marker) VALUES (?1, ?2)";

/// Native libSQL adapter using the service's shared crlt pool. No driver fallback.
#[derive(Clone)]
pub struct LibsqlStore {
    community: String,
    db: crlt::Community,
}

impl LibsqlStore {
    /// Apply [`SCHEMA`] before constructing this capability, including on reopen.
    pub fn new(db: &crlt::Db, community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        identifier(&community)?;
        Ok(Self {
            db: db.community(community.clone())?,
            community,
        })
    }

    /// Check every production query/write shape against real SQLite query plans.
    pub async fn check_query_plans(&self) -> Result<()> {
        let plans = [
            (LOAD, Vec::from(params!["subject"])),
            (DELETE, Vec::from(params!["subject", "gate", "provider"])),
            (
                INSERT,
                Vec::from(params!["subject", "gate", "provider", 1i64]),
            ),
            (CLAIM, Vec::from(params!["gate", vec![0u8]])),
            (SPEND, Vec::from(params!["gate", vec![0u8]])),
        ];
        for (statement, parameters) in plans {
            self.db
                .explain(statement, parameters)
                .await?
                .assert_indexed()?;
        }
        Ok(())
    }
}

impl Storage for LibsqlStore {
    fn community(&self) -> &str {
        &self.community
    }
    async fn load(&self, subject: &str) -> Result<Vec<GateResult>> {
        identifier(subject)?;
        self.db
            .query(LOAD, [subject])
            .await?
            .into_iter()
            .map(|row| {
                let result = GateResult {
                    gate: row.get_str(0)?.into(),
                    provider: row.get_str(1)?.into(),
                    valid_until: row.get_i64(2)?,
                    level: GateLevel::Community,
                    subject: subject.into(),
                };
                validate(Some(&result)).map_err(|_| Error::Storage)?;
                Ok(result)
            })
            .collect()
    }
    async fn commit(&self, result: Option<&GateResult>, claim: Option<&Claim>) -> Result<()> {
        validate(result)?;
        if result.is_none() && claim.is_none() {
            return Ok(());
        }
        let mut tx = self.db.tx().await?;
        if let Some(claim) = claim {
            if !tx
                .query(CLAIM, params![claim.domain.clone(), claim.marker.clone()])
                .await?
                .is_empty()
            {
                return Err(Error::Refused);
            }
            tx.execute(SPEND, params![claim.domain.clone(), claim.marker.clone()])
                .await?;
        }
        if let Some(result) = result {
            tx.execute(
                DELETE,
                params![
                    result.subject.clone(),
                    result.gate.clone(),
                    result.provider.clone()
                ],
            )
            .await?;
            tx.execute(
                INSERT,
                params![
                    result.subject.clone(),
                    result.gate.clone(),
                    result.provider.clone(),
                    result.valid_until
                ],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn remove(&self, subject: &str, gate: &str, provider: &str) -> Result<()> {
        key(subject, gate, provider)?;
        self.db
            .execute(DELETE, params![subject, gate, provider])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/storage.rs"]
mod tests;
