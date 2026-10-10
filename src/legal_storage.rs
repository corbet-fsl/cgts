//! Host-owned persistence for clbs legal metadata. The domain library has no database connection.
use crlt::{Db, Row, Value, params};

use clbs::{Append, Counts, Error, Order, OrderKind, Period, Record, Result, Revocation, Store};

/// Trusted DDL for the service's complete crlt migration history.
/// The composition root assigns its version and applies it before constructing stores.
pub const SCHEMA: &str = include_str!("legal_schema.sql");

const BY_ID: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope, starts_at, ends_at FROM clbs_orders WHERE id = ?1";
const ACTIVE: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope, starts_at, ends_at FROM clbs_orders WHERE subject = ?1 AND starts_at <= ?2 AND (ends_at IS NULL OR ends_at > ?2) ORDER BY id";
const REVOCATIONS: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope, starts_at, ends_at FROM clbs_orders WHERE starts_at <= ?1 AND (ends_at IS NULL OR ends_at > ?1) ORDER BY id";
const COUNTS: &str = "SELECT COUNT(CASE WHEN kind = 'legal' THEN 1 END), COUNT(CASE WHEN kind = 'self_ban' THEN 1 END), COUNT(CASE WHEN kind = 'legal' AND starts_at <= ?1 AND (ends_at IS NULL OR ends_at > ?1) THEN 1 END), COUNT(CASE WHEN kind = 'self_ban' AND starts_at <= ?1 AND (ends_at IS NULL OR ends_at > ?1) THEN 1 END) FROM clbs_orders";
const INSERT: &str = "INSERT INTO clbs_orders (id, subject, reference, entered_by, kind, authority, scope, starts_at, ends_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

/// libSQL persistence through crlt's scoped, index-checked database facade.
/// Deploy one database per community. Clones share the underlying database pool.
#[derive(Clone)]
pub struct LibsqlStore {
    community: String,
    db: crlt::Community,
}

impl LibsqlStore {
    /// Bind a trusted service-selected database and community. Apply [`SCHEMA`]
    /// using `Db::migrate` first, including after reopening a database.
    pub fn new(db: &Db, community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        text(&community)?;
        Ok(Self {
            db: db.community(community.clone()).map_err(db_error)?,
            community,
        })
    }

    fn decode(&self, row: &Row) -> Result<Record> {
        let kind = match (
            row.get_str(4).map_err(db_error)?,
            row.get_value(5).map_err(db_error)?,
        ) {
            ("legal", Value::Text(authority)) => OrderKind::Legal {
                authority: authority.clone(),
            },
            ("self_ban", Value::Null) => OrderKind::SelfBan,
            _ => return Err(Error::Storage),
        };
        let order = Order {
            community: self.community.clone(),
            id: row.get_str(0).map_err(db_error)?.into(),
            subject: row.get_str(1).map_err(db_error)?.into(),
            reference: row.get_str(2).map_err(db_error)?.into(),
            entered_by: row.get_str(3).map_err(db_error)?.into(),
            kind,
            scope: serde_json::from_str(row.get_str(6).map_err(db_error)?)
                .map_err(|_| Error::Storage)?,
            period: Period {
                starts_at: row.get_i64(7).map_err(db_error)?,
                ends_at: optional_time(row, 8)?,
            },
        };
        Record::restore_trusted(order).map_err(|_| Error::Storage)
    }
}

impl Store for LibsqlStore {
    fn community(&self) -> &str {
        &self.community
    }

    async fn append(&self, record: &Record) -> Result<Append> {
        let order = record.order();
        if order.community != self.community {
            return Err(Error::CommunityMismatch);
        }
        order.validate()?;
        let mut tx = self.db.tx().await.map_err(db_error)?;
        let existing = tx
            .query(BY_ID, [order.id.as_str()])
            .await
            .map_err(db_error)?;
        if let Some(row) = existing.first() {
            let same = self.decode(row)? == *record;
            tx.rollback().await.map_err(db_error)?;
            return if same {
                Ok(Append::Unchanged)
            } else {
                Err(Error::Conflict)
            };
        }
        let (kind, authority) = match &order.kind {
            OrderKind::Legal { authority } => ("legal", Some(authority.clone())),
            OrderKind::SelfBan => ("self_ban", None),
        };
        let scope = serde_json::to_string(&order.scope).map_err(|_| Error::Storage)?;
        tx.execute(
            INSERT,
            params![
                order.id.clone(),
                order.subject.clone(),
                order.reference.clone(),
                order.entered_by.clone(),
                kind,
                authority,
                scope,
                order.period.starts_at,
                order.period.ends_at
            ],
        )
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(Append::Inserted)
    }

    async fn record(&self, id: &str) -> Result<Option<Record>> {
        text(id)?;
        self.db
            .query(BY_ID, [id])
            .await
            .map_err(db_error)?
            .first()
            .map(|row| self.decode(row))
            .transpose()
    }

    async fn active(&self, subject: &str, at: i64) -> Result<Vec<Record>> {
        text(subject)?;
        timestamp(at)?;
        self.db
            .query(ACTIVE, params![subject, at])
            .await
            .map_err(db_error)?
            .iter()
            .map(|row| self.decode(row))
            .collect()
    }

    async fn revocations(&self, at: i64) -> Result<Vec<Revocation>> {
        timestamp(at)?;
        self.db
            .query(REVOCATIONS, [at])
            .await
            .map_err(db_error)?
            .iter()
            .map(|row| self.decode(row).map(Revocation::from))
            .collect()
    }

    async fn counts(&self, at: i64) -> Result<Counts> {
        timestamp(at)?;
        let rows = self.db.query(COUNTS, [at]).await.map_err(db_error)?;
        let row = rows.first().ok_or(Error::Storage)?;
        let count = |index| -> Result<u64> {
            row.get_i64(index)
                .map_err(db_error)?
                .try_into()
                .map_err(|_| Error::Storage)
        };
        Ok(Counts {
            legal_orders: count(0)?,
            self_bans: count(1)?,
            active_legal_orders: count(2)?,
            active_self_bans: count(3)?,
        })
    }
}

fn optional_time(row: &Row, index: usize) -> Result<Option<i64>> {
    match row.get_value(index).map_err(db_error)? {
        Value::Null => Ok(None),
        Value::Integer(value) => Ok(Some(*value)),
        _ => Err(Error::Storage),
    }
}

#[cfg(test)]
#[path = "tests/legal_plans.rs"]
mod tests;

fn db_error(_: crlt::Error) -> Error {
    Error::Storage
}
fn text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(Error::Invalid("invalid legal storage identifier"))
    } else {
        Ok(())
    }
}
fn timestamp(at: i64) -> Result<()> {
    if at < 0 {
        Err(Error::Invalid("timestamp must be nonnegative"))
    } else {
        Ok(())
    }
}
