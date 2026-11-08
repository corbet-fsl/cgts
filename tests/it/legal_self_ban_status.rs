//! A permanent self-ban receipt is exact, scoped to its community, and survives reopening storage.
use crate::legal_common as common;
use cgts::legal_storage::LibsqlStore;
use clbs::Gate;
use common::*;

#[tokio::test]
async fn indexed_permanent_receipt_is_exact_scoped_and_survives_reopening() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("receipts.db");
    let db = open(&path).await;
    let gate = Gate::new(
        LibsqlStore::new(&db, "community-a").unwrap(),
        TestVerifier::new("community-a"),
    );
    assert!(gate.self_ban_record("alice").await.unwrap().is_none());
    gate.record_legal(&sign(legal("legal"))).await.unwrap();
    assert!(gate.self_ban_record("alice").await.unwrap().is_none());
    gate.self_ban(&sign(ban("receipt"))).await.unwrap();
    let expected = gate.record("receipt").await.unwrap().unwrap();
    assert!(matches!(
        gate.check("alice").await.unwrap(),
        clbs::State::Red(_)
    ));
    assert!(gate.self_ban_record("alice").await.unwrap() == Some(expected.clone()));
    assert!(gate.self_ban_record("other").await.unwrap().is_none());
    let other = Gate::new(
        LibsqlStore::new(&db, "community-b").unwrap(),
        TestVerifier::new("community-b"),
    );
    assert!(other.self_ban_record("alice").await.unwrap().is_none());
    drop(other);
    drop(gate);
    drop(db);
    let db = open(&path).await;
    let gate = Gate::new(
        LibsqlStore::new(&db, "community-a").unwrap(),
        TestVerifier::new("community-a"),
    );
    assert!(gate.self_ban_record("alice").await.unwrap() == Some(expected));
}
