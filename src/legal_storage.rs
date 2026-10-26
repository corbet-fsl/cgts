//! Host-owned persistence for clbs legal metadata. The domain library has no database connection.
use crlt::{Db, Row, Value, params};
use std::{future::Future, pin::Pin};

use clbs::{Append, Counts, Error, Order, OrderKind, Record, Result, Revocation, Store};

/// Trusted DDL for the service's complete crlt migration history.
/// The composition root assigns its version and applies it before constructing stores.
pub const SCHEMA: &str = include_str!("legal_schema.sql");

/// Additive scope migration, applied after [`SCHEMA`]. History is immutable,
/// so the scope column arrives in its own migration: existing rows keep their
/// meaning and read back as member scope, which is exactly what they are
/// (community scope did not exist before this migration).
pub const SCOPE_SCHEMA: &str = "ALTER TABLE clbs_orders ADD COLUMN scope TEXT NOT NULL DEFAULT 'member' CHECK (scope IN ('member', 'community'))";

const BY_ID: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope FROM clbs_orders WHERE id = ?1";
const SELF_BAN: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope FROM clbs_orders WHERE subject = ?1 AND kind = 'self_ban' LIMIT 1";
const ORDERS: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope FROM clbs_orders WHERE subject = ?1 ORDER BY id";
const REVOCATIONS: &str = "SELECT id, subject, reference, entered_by, kind, authority, scope FROM clbs_orders ORDER BY id";
const COUNTS: &str = "SELECT COUNT(CASE WHEN kind = 'legal' THEN 1 END), COUNT(CASE WHEN kind = 'self_ban' THEN 1 END) FROM clbs_orders";
const INSERT: &str = "INSERT INTO clbs_orders (id, subject, reference, entered_by, kind, authority, scope) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

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
        let scope = match row.get_str(6).map_err(db_error)? {
            "member" => clbs::Scope::Member,
            "community" => clbs::Scope::Community,
            _ => return Err(Error::Storage),
        };
        let order = Order {
            community: self.community.clone(),
            id: row.get_str(0).map_err(db_error)?.into(),
            subject: row.get_str(1).map_err(db_error)?.into(),
            reference: row.get_str(2).map_err(db_error)?.into(),
            entered_by: row.get_str(3).map_err(db_error)?.into(),
            kind,
            scope,
        };
        Record::restore_trusted(order).map_err(|_| Error::Storage)
    }
    /// Append verified metadata and the host's notice in one scoped transaction.
    /// The notice runs only for a new record, after immutable metadata checks.
    /// It receives a borrow, so it cannot consume/commit the transaction. crlt
    /// also refuses transaction-control SQL. Failure/cancellation rolls back
    /// both writes; a commit error requires exact trusted-record reconciliation.
    /// Identical retries do not run the notice again or advance its generation.
    pub async fn append_with(
        &self,
        record: &Record,
        notice: impl for<'a> FnOnce(
            &'a mut crlt::Transaction,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>
        + Send,
    ) -> Result<Append> {
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
        let scope = match order.scope {
            clbs::Scope::Member => "member",
            clbs::Scope::Community => "community",
        };
        tx.execute(
            INSERT,
            params![
                order.id.clone(),
                order.subject.clone(),
                order.reference.clone(),
                order.entered_by.clone(),
                kind,
                authority,
                scope
            ],
        )
        .await
        .map_err(db_error)?;
        if let Err(error) = notice(&mut tx).await {
            tx.rollback().await.map_err(db_error)?;
            return Err(error);
        }
        tx.commit().await.map_err(db_error)?;
        Ok(Append::Inserted)
    }
}

impl Store for LibsqlStore {
    fn community(&self) -> &str {
        &self.community
    }

    async fn append(&self, record: &Record) -> Result<Append> {
        self.append_with(record, |_| Box::pin(async { Ok(()) }))
            .await
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

    async fn self_ban_record(&self, subject: &str) -> Result<Option<Record>> {
        text(subject)?;
        self.db
            .query(SELF_BAN, [subject])
            .await
            .map_err(db_error)?
            .first()
            .map(|row| self.decode(row))
            .transpose()
    }

    async fn orders(&self, subject: &str) -> Result<Vec<Record>> {
        text(subject)?;
        self.db
            .query(ORDERS, [subject])
            .await
            .map_err(db_error)?
            .iter()
            .map(|row| self.decode(row))
            .collect()
    }

    async fn revocations(&self) -> Result<Vec<Revocation>> {
        self.db
            .query(REVOCATIONS, params![])
            .await
            .map_err(db_error)?
            .iter()
            .map(|row| self.decode(row).map(Revocation::from))
            .collect()
    }

    async fn counts(&self) -> Result<Counts> {
        let rows = self.db.query(COUNTS, params![]).await.map_err(db_error)?;
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
        })
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
