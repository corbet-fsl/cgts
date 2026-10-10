//! Real host-owned database persistence, isolation, concurrency and failure boundaries.
use cgts::legal_storage::{LibsqlStore, SCHEMA};
#[path = "legal_common/mod.rs"]
mod common;

use clbs::{Append, Counts, Error, Gate, MemoryStore, State, Store};
use common::{TestClock, TestVerifier, ban, legal, sign};
use crlt::{Config, Db, Migration};

#[tokio::test]
async fn reopening_preserves_expired_orders_and_self_bans() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("persist.db");
    let url = format!("file://{}", path.display());
    {
        let db = common::open(&path).await;
        assert_eq!(
            db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
                .await
                .unwrap(),
            0
        );
        let gate = Gate::new(
            LibsqlStore::new(&db, "community-a").unwrap(),
            TestVerifier::new("community-a"),
            TestClock::new(150),
        );
        gate.record_legal(&sign(legal("legal"))).await.unwrap();
        gate.self_ban(&sign(ban("self"))).await.unwrap();
        for _ in 0..10 {
            assert_eq!(gate.check("unknown").await.unwrap(), State::Green);
        }
    }
    let db = Db::open(Config::new(url, "")).await.unwrap();
    assert_eq!(
        db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
            .await
            .unwrap(),
        0
    );
    let gate = Gate::new(
        LibsqlStore::new(&db, "community-a").unwrap(),
        TestVerifier::new("community-a"),
        TestClock::new(i64::MAX),
    );
    assert_eq!(
        gate.record("legal").await.unwrap().unwrap().order(),
        &legal("legal")
    );
    assert_eq!(
        gate.record("self").await.unwrap().unwrap().order(),
        &ban("self")
    );
    assert_eq!(
        gate.counts().await.unwrap(),
        Counts {
            legal_orders: 1,
            self_bans: 1,
            active_legal_orders: 0,
            active_self_bans: 1
        }
    );
    assert_eq!(gate.revocations().await.unwrap().len(), 1);
    // Reads create no records, and the durable table has no evidence or check-time columns.
    let rows = db
        .community("community-a")
        .unwrap()
        .query("SELECT * FROM clbs_orders ORDER BY id", ())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].columns().len(), 10);
    for column in rows[0].columns() {
        assert!(
            ![
                "proof",
                "signature",
                "last_used",
                "checked_at",
                "created_at"
            ]
            .contains(&column.as_str())
        );
    }
}

async fn isolation<S: Store + Clone>(first: S, second: S) {
    let a = Gate::new(
        first.clone(),
        TestVerifier::new("community-a"),
        TestClock::new(150),
    );
    let b = Gate::new(
        second.clone(),
        TestVerifier::new("community-b"),
        TestClock::new(150),
    );
    a.record_legal(&sign(legal("shared-id"))).await.unwrap();
    assert_eq!(b.check("alice").await.unwrap(), State::Green);
    assert_eq!(b.record("shared-id").await.unwrap(), None);
    assert!(b.revocations().await.unwrap().is_empty());
    assert_eq!(b.counts().await.unwrap(), Counts::default());
    let record = a.record("shared-id").await.unwrap().unwrap();
    assert_eq!(second.append(&record).await, Err(Error::CommunityMismatch));
    assert_eq!(
        b.record_legal(&sign(legal("wrong"))).await,
        Err(Error::CommunityMismatch)
    );
    let mut other = legal("shared-id");
    other.community = "community-b".into();
    other.subject = "bob".into();
    b.record_legal(&sign(other)).await.unwrap();
    assert_eq!(a.check("bob").await.unwrap(), State::Green);
    assert_eq!(a.counts().await.unwrap().legal_orders, 1);
    assert_eq!(b.counts().await.unwrap().legal_orders, 1);
    assert_eq!(a.revocations().await.unwrap()[0].subject, "alice");
    assert_eq!(b.revocations().await.unwrap()[0].subject, "bob");
}

#[tokio::test]
async fn communities_are_isolated_in_one_database() {
    let directory = tempfile::tempdir().unwrap();
    let db = common::open(&directory.path().join("isolation.db")).await;
    isolation(
        LibsqlStore::new(&db, "community-a").unwrap(),
        LibsqlStore::new(&db, "community-b").unwrap(),
    )
    .await;
}

#[tokio::test]
async fn memory_communities_and_clones_are_isolated() {
    isolation(
        MemoryStore::new("community-a").unwrap(),
        MemoryStore::new("community-b").unwrap(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_commit_one_record() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "file://{}",
        directory.path().join("concurrent.db").display()
    );
    let mut config = Config::new(url, "");
    config.max_connections = 2;
    let db = Db::open(config).await.unwrap();
    db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
        .await
        .unwrap();
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let clone = store.clone();
        tasks.spawn(async move {
            Gate::new(clone, TestVerifier::new("community-a"), TestClock::new(150))
                .record_legal(&sign(legal("same")))
                .await
        });
    }
    let mut inserted = 0;
    let mut unchanged = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap().unwrap() {
            Append::Inserted => inserted += 1,
            Append::Unchanged => unchanged += 1,
        }
    }
    assert_eq!((inserted, unchanged), (1, 7));
    assert_eq!(store.counts(150).await.unwrap().legal_orders, 1);
}

#[tokio::test]
async fn missing_schema_and_corrupt_metadata_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("failures.db").display());
    let db = Db::open(Config::new(url, "")).await.unwrap();
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    assert_eq!(gate.check("alice").await, Err(Error::Storage));
    assert_eq!(
        gate.record_legal(&sign(legal("missing"))).await,
        Err(Error::Storage)
    );
    db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
        .await
        .unwrap();
    assert_eq!(gate.counts().await.unwrap(), Counts::default());
    gate.record_legal(&sign(legal("corrupt"))).await.unwrap();
    // Out-of-band writes are trusted administration; invalid data must still fail closed.
    db.community("community-a")
        .unwrap()
        .execute(
            "UPDATE clbs_orders SET scope = ?1 WHERE id = ?2",
            ["{invalid-json", "corrupt"],
        )
        .await
        .unwrap();
    assert_eq!(gate.check("alice").await, Err(Error::Storage));
    assert_eq!(gate.record("corrupt").await, Err(Error::Storage));
    assert_eq!(gate.revocations().await, Err(Error::Storage));
    assert_eq!(
        format!("{:?}", gate.check("alice").await.unwrap_err()),
        "Storage"
    );
}

#[tokio::test]
async fn row_limits_refuse_partial_verdicts_and_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("limit.db");
    let db = common::open(&path).await;
    let full = Gate::new(
        LibsqlStore::new(&db, "community-a").unwrap(),
        TestVerifier::new("community-a"),
        TestClock::new(150),
    );
    full.record_legal(&sign(legal("one"))).await.unwrap();
    full.record_legal(&sign(legal("two"))).await.unwrap();
    let mut config = Config::new(format!("file://{}", path.display()), "");
    config.max_rows = 1;
    let limited_db = Db::open(config).await.unwrap();
    limited_db
        .migrate(&[Migration::new(1, "clbs", SCHEMA)])
        .await
        .unwrap();
    let limited = Gate::new(
        LibsqlStore::new(&limited_db, "community-a").unwrap(),
        TestVerifier::new("community-a"),
        TestClock::new(150),
    );
    assert_eq!(limited.check("alice").await, Err(Error::Storage));
    assert_eq!(
        limited.check_action("alice", "read").await,
        Err(Error::Storage)
    );
    assert_eq!(limited.revocations().await, Err(Error::Storage));
    assert!(limited.record("one").await.unwrap().is_some());
    assert_eq!(limited.counts().await.unwrap().legal_orders, 2);
}

#[test]
fn invalid_community_identifiers_are_rejected() {
    for community in ["", " ", "a\0b", "a\nb"] {
        assert!(MemoryStore::new(community).is_err());
    }
}

#[test]
fn system_clock_returns_supported_samples_and_safe_errors() {
    use clbs::{Clock, SystemClock};
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let at = SystemClock.now().unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(at >= 0);
    assert!((before..=after).contains(&(at as u64)));
    for error in [
        Error::Invalid("static validation failure"),
        Error::Denied,
        Error::CommunityMismatch,
        Error::Conflict,
        Error::Storage,
        Error::Clock,
    ] {
        assert!(!error.to_string().is_empty());
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(format!("{:?}", clbs::OrderKind::SelfBan), "SelfBan");
}

#[tokio::test]
async fn malformed_sql_types_and_valid_json_with_invalid_scope_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let db = common::open(&directory.path().join("invalid-types.db")).await;
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    let gate = Gate::new(
        store.clone(),
        TestVerifier::new("community-a"),
        TestClock::new(150),
    );
    let scoped = db.community("community-a").unwrap();
    for (id, sql, value) in [
        (
            "authority-type",
            "UPDATE clbs_orders SET authority = ?1 WHERE id = ?2",
            crlt::Value::Blob(vec![1, 2, 3]),
        ),
        (
            "end-type",
            "UPDATE clbs_orders SET ends_at = ?1 WHERE id = ?2",
            crlt::Value::Text("not-a-timestamp".into()),
        ),
        (
            "empty-scope",
            "UPDATE clbs_orders SET scope = ?1 WHERE id = ?2",
            crlt::Value::Text("{\"Actions\":[]}".into()),
        ),
    ] {
        gate.record_legal(&sign(legal(id))).await.unwrap();
        scoped.execute(sql, crlt::params![value, id]).await.unwrap();
        assert_eq!(store.record(id).await, Err(Error::Storage), "{id}");
        assert_eq!(
            gate.record_legal(&sign(legal(id))).await,
            Err(Error::Storage)
        );
    }
    assert_eq!(store.revocations(150).await, Err(Error::Storage));
}

#[tokio::test]
async fn host_storage_checks_identifiers_time_and_conflicting_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let db = common::open(&directory.path().join("validation.db")).await;
    for id in ["", " ", "a\0b", &"x".repeat(1025)] {
        assert!(LibsqlStore::new(&db, id).is_err());
    }
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    assert!(store.record("").await.is_err());
    assert!(store.active("", 150).await.is_err());
    assert!(store.active("alice", -1).await.is_err());
    assert!(store.revocations(-1).await.is_err());
    assert!(store.counts(-1).await.is_err());
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    gate.record_legal(&sign(legal("same"))).await.unwrap();
    assert_eq!(
        gate.record_legal(&sign(legal("same"))).await.unwrap(),
        Append::Unchanged
    );
    let mut changed = legal("same");
    changed.reference = "different".into();
    assert_eq!(
        gate.record_legal(&sign(changed)).await,
        Err(Error::Conflict)
    );
}
