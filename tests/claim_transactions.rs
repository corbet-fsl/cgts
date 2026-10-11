//! Actual SQLite single-use storage only: these tests do not mint voucher or
//! admission authority. The host must supply genuine leaf-verified claims.
use cgts::{Claim, Error, LibsqlStore, Storage};

async fn fixture() -> (tempfile::TempDir, crlt::Db, LibsqlStore) {
    let directory = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("claims.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[crlt::Migration::new(1, "gates", cgts::SCHEMA)])
        .await
        .unwrap();
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    (directory, db, store)
}
fn claim(value: u8) -> Claim {
    Claim::new("cvch", vec![value; 32]).unwrap()
}

#[tokio::test]
async fn caller_commits_original_claims_together_and_reopen_keeps_them_spent() {
    let (directory, db, store) = fixture().await;
    let tx = db.community("community-a").unwrap().tx().await.unwrap();
    let tx = store.claim_in_transaction(tx, &claim(1)).await.unwrap();
    let tx = store.claim_in_transaction(tx, &claim(2)).await.unwrap();
    tx.commit().await.unwrap();
    drop(store);
    drop(db);
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("claims.db").display()),
        "",
    ))
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    for value in [1, 2] {
        assert_eq!(
            store.commit(None, Some(&claim(value))).await,
            Err(Error::Refused)
        );
    }
    let other = LibsqlStore::new(&db, "community-b").unwrap();
    other.commit(None, Some(&claim(1))).await.unwrap();
}

#[tokio::test]
async fn later_duplicate_rolls_back_the_entire_owned_writer() {
    let (_directory, db, store) = fixture().await;
    store.commit(None, Some(&claim(1))).await.unwrap();
    let tx = db.community("community-a").unwrap().tx().await.unwrap();
    let tx = store.claim_in_transaction(tx, &claim(2)).await.unwrap();
    assert_eq!(
        store.claim_in_transaction(tx, &claim(1)).await.err(),
        Some(Error::Refused)
    );
    // The caller has no transaction left to accidentally commit claim 2.
    store.commit(None, Some(&claim(2))).await.unwrap();
    assert_eq!(
        store.commit(None, Some(&claim(1))).await,
        Err(Error::Refused)
    );
}

#[tokio::test]
async fn foreign_scope_and_separately_opened_same_database_refuse() {
    let (directory, db, store) = fixture().await;
    let foreign = db.community("community-b").unwrap().tx().await.unwrap();
    assert_eq!(
        store.claim_in_transaction(foreign, &claim(1)).await.err(),
        Some(Error::Scope)
    );
    let independent = crlt::Db::open(crlt::Config::new(
        format!("file://{}", directory.path().join("claims.db").display()),
        "",
    ))
    .await
    .unwrap();
    // Load the actual migration metadata on the independently opened handle.
    independent
        .migrate(&[crlt::Migration::new(1, "gates", cgts::SCHEMA)])
        .await
        .unwrap();
    let tx = independent
        .community("community-a")
        .unwrap()
        .tx()
        .await
        .unwrap();
    assert_eq!(
        store.claim_in_transaction(tx, &claim(1)).await.err(),
        Some(Error::Scope)
    );
    store.commit(None, Some(&claim(1))).await.unwrap();
}

#[tokio::test]
async fn cancelling_before_next_owner_poll_rolls_back_already_staged_claim() {
    let (_directory, db, store) = fixture().await;
    let tx = db.community("community-a").unwrap().tx().await.unwrap();
    let tx = store.claim_in_transaction(tx, &claim(1)).await.unwrap();
    let next = claim(2);
    let pending = store.claim_in_transaction(tx, &next);
    // Even an unpolled future owns the writer. Dropping it cannot leak the
    // earlier successful staging back to a caller as a committable transaction.
    drop(pending);
    store.commit(None, Some(&claim(1))).await.unwrap();
    store.commit(None, Some(&claim(2))).await.unwrap();
}
