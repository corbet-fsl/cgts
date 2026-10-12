//! Real verified metadata and caller-owned notices share one scoped transaction.
#[path = "legal_common/mod.rs"]
mod common;
use cgts::legal_storage::{LibsqlStore, SCHEMA};
use clbs::{Append, Error, Gate, MemoryStore, Record, Store};
use common::{TestVerifier, legal, sign};

const NOTICE_SCHEMA: &str = "CREATE TABLE legal_notice (community_id TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY (community_id, id)) WITHOUT ROWID;";
async fn fixture() -> (tempfile::TempDir, crlt::Db, LibsqlStore, Record) {
    let directory = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("atomic.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[
        crlt::Migration::new(1, "legal", SCHEMA),
        crlt::Migration::new(2, "notice", NOTICE_SCHEMA),
    ])
    .await
    .unwrap();
    let source = Gate::new(
        MemoryStore::new("community-a").unwrap(),
        TestVerifier::new("community-a"),
    );
    source.record_legal(&sign(legal("atomic"))).await.unwrap();
    let record = source.record("atomic").await.unwrap().unwrap();
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    (directory, db, store, record)
}

#[tokio::test]
async fn verified_order_and_notice_commit_once_and_survive_reopening() {
    let (directory, db, store, record) = fixture().await;
    assert_eq!(
        store
            .append_with(&record, |tx| Box::pin(async move {
                tx.execute("INSERT INTO legal_notice (id) VALUES (?1)", ["atomic"])
                    .await
                    .map_err(|_| Error::Storage)?;
                Ok(())
            }))
            .await
            .unwrap(),
        Append::Inserted
    );
    assert_eq!(
        store
            .append_with(&record, |_| Box::pin(async {
                panic!("identical retry must not emit another notice")
            }))
            .await
            .unwrap(),
        Append::Unchanged
    );
    drop(store);
    drop(db);
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("atomic.db").display()),
        "",
    ))
    .await
    .unwrap();
    // Reopening applies the same migrations again; nothing is pending.
    assert_eq!(
        db.migrate(&[
            crlt::Migration::new(1, "legal", SCHEMA),
            crlt::Migration::new(2, "notice", NOTICE_SCHEMA),
        ])
        .await
        .unwrap(),
        0
    );
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    assert_eq!(store.record("atomic").await.unwrap(), Some(record));
    let rows = db
        .community("community-a")
        .unwrap()
        .query("SELECT id FROM legal_notice WHERE id = ?1", ["atomic"])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        db.community("community-b")
            .unwrap()
            .query("SELECT id FROM legal_notice WHERE id = ?1", ["atomic"])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_notice_failure_rolls_back_both_notice_and_verified_order() {
    let (_directory, db, store, record) = fixture().await;
    assert_eq!(
        store
            .append_with(&record, |tx| Box::pin(async move {
                tx.execute("INSERT INTO legal_notice (id) VALUES (?1)", ["atomic"])
                    .await
                    .map_err(|_| Error::Storage)?;
                Err(Error::Denied)
            }))
            .await,
        Err(Error::Denied)
    );
    assert_eq!(store.record("atomic").await.unwrap(), None);
    assert!(
        db.community("community-a")
            .unwrap()
            .query("SELECT id FROM legal_notice WHERE id = ?1", ["atomic"])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.append(&record).await.unwrap(), Append::Inserted);
}

#[tokio::test]
async fn a_notice_cannot_commit_with_transaction_control_sql() {
    let (_directory, _db, store, record) = fixture().await;
    assert_eq!(
        store
            .append_with(&record, |tx| Box::pin(async move {
                tx.execute("COMMIT", ()).await.map_err(|_| Error::Storage)?;
                Ok(())
            }))
            .await,
        Err(Error::Storage)
    );
    assert_eq!(store.record("atomic").await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_notice_rolls_back_both_writes() {
    let (_directory, db, store, record) = fixture().await;
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let task = tokio::spawn({
        let store = store.clone();
        let record = record.clone();
        async move {
            store
                .append_with(&record, |tx| {
                    Box::pin(async move {
                        tx.execute("INSERT INTO legal_notice (id) VALUES (?1)", ["atomic"])
                            .await
                            .map_err(|_| Error::Storage)?;
                        entered.send(()).unwrap();
                        std::future::pending::<()>().await;
                        Ok(())
                    })
                })
                .await
        }
    });
    waiting.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(store.record("atomic").await.unwrap(), None);
    assert!(
        db.community("community-a")
            .unwrap()
            .query("SELECT id FROM legal_notice WHERE id = ?1", ["atomic"])
            .await
            .unwrap()
            .is_empty()
    );
}
