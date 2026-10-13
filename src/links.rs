//! Durable atomic voucher-link storage through crlt. The record holds no issuer.
use crlt::params;
use cvch::link::{Link, LinkId, LinkStore};

const INSERT: &str = "INSERT INTO cgts_links (id, body) VALUES (?1, ?2)";
const LOAD: &str = "SELECT body FROM cgts_links WHERE id = ?1";
const SAVE: &str = "UPDATE cgts_links SET body = ?2 WHERE id = ?1";

/// Native libSQL link store using the service's shared crlt pool.
#[derive(Clone)]
pub struct LibsqlLinks {
    db: crlt::Community,
}

impl LibsqlLinks {
    /// Apply [`crate::SCHEMA`] before constructing this capability.
    pub fn new(db: &crlt::Db, community: impl Into<String>) -> crate::Result<Self> {
        let community = community.into();
        crate::identifier(&community)?;
        Ok(Self {
            db: db.community(community)?,
        })
    }

    /// Check every production query shape against real SQLite query plans.
    pub async fn check_query_plans(&self) -> crate::Result<()> {
        for (statement, parameters) in [
            (INSERT, Vec::from(params!["id", "{}"])),
            (LOAD, Vec::from(params!["id"])),
            (SAVE, Vec::from(params!["id", "{}"])),
        ] {
            self.db
                .explain(statement, parameters)
                .await?
                .assert_indexed()?;
        }
        Ok(())
    }
}

fn stored<E>(_: E) -> cvch::Error {
    cvch::Error::Rejected
}

impl LinkStore for LibsqlLinks {
    async fn insert(&self, link: Link) -> Result<(), cvch::Error> {
        let body = serde_json::to_string(&link).map_err(stored)?;
        self.db
            .execute(INSERT, params![link.id().as_str(), body])
            .await
            .map_err(stored)?;
        Ok(())
    }

    async fn update<R: Send>(
        &self,
        id: &LinkId,
        change: impl FnOnce(&mut Link) -> Result<R, cvch::Error> + Send,
    ) -> Result<R, cvch::Error> {
        let mut tx = self.db.tx().await.map_err(stored)?;
        let rows = tx.query(LOAD, params![id.as_str()]).await.map_err(stored)?;
        let row = rows.first().ok_or(cvch::Error::Rejected)?;
        let mut link: Link =
            serde_json::from_str(row.get_str(0).map_err(stored)?).map_err(stored)?;
        let result = change(&mut link)?;
        let body = serde_json::to_string(&link).map_err(stored)?;
        tx.execute(SAVE, params![id.as_str(), body])
            .await
            .map_err(stored)?;
        tx.commit().await.map_err(stored)?;
        Ok(result)
    }
}
