//! Real atomic memory and libSQL storage round trips and failure cases.
mod common;
use cgts::*;
use common::*;

#[tokio::test]
async fn reopen_isolation_and_all_index_plans() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("persistent.db");
    {
        let db = open(&path).await;
        let snapshot = snapshot("garden", "cvch");
        sql(&db, "garden")
            .run(
                context(&snapshot),
                &gate(),
                &voucher("garden", "persist", 2000),
            )
            .await
            .unwrap();
        LibsqlStore::new(&db, "garden")
            .unwrap()
            .check_query_plans()
            .await
            .unwrap();
    }
    let db = open(&path).await;
    let snapshot = snapshot("garden", "cvch");
    let keeper = sql(&db, "garden");
    assert_eq!(keeper.collect(context(&snapshot)).await.unwrap().len(), 1);
    assert!(matches!(
        keeper
            .run(
                context(&snapshot),
                &gate(),
                &voucher("garden", "persist", 2000)
            )
            .await,
        Err(Error::Refused)
    ));
    assert!(
        LibsqlStore::new(&db, "other")
            .unwrap()
            .load("alice")
            .await
            .unwrap()
            .is_empty()
    );
    let other = common::snapshot("other", "cvch");
    sql(&db, "other")
        .run(context(&other), &gate(), &voucher("other", "persist", 2000))
        .await
        .unwrap();
    // Markers reveal no subject, receipt time or raw evidence.
    let rows = db
        .community("garden")
        .unwrap()
        .query(
            "SELECT domain, marker FROM cgts_spent WHERE domain = ?1",
            ["cvch"],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].columns(), ["domain", "marker"]);
    assert_eq!(
        rows[0].get_value(1).unwrap(),
        &crlt::Value::Blob(cvch::receipt_id("persist").into_bytes())
    );
}

#[tokio::test]
async fn competing_redemptions_have_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("race.db")).await;
    let keeper = sql(&db, "garden");
    let snapshot = snapshot("garden", "cvch");
    let a = context(&snapshot);
    let b = Context {
        subject: "bob",
        ..a
    };
    let gate = gate();
    let input = voucher("garden", "race", 2000);
    let (first, second) = tokio::join!(keeper.run(a, &gate, &input), keeper.run(b, &gate, &input));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(
        keeper.collect(a).await.unwrap().len() + keeper.collect(b).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn failed_result_write_rolls_back_spend_and_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("rollback.db")).await;
    // A service-owned stricter schema models a real storage failure after claim.
    let db2 = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("strict.db").display()),
        "",
    ))
    .await
    .unwrap();
    let strict = SCHEMA.replace(
        "valid_until > 0",
        "valid_until > 0 AND valid_until <= 2592000",
    );
    db2.migrate(&[
        crlt::Migration::new(1, "strict-gates", &strict),
        crlt::Migration::new(2, "legal", clbs::SCHEMA),
    ])
    .await
    .unwrap();
    let mut snapshot = snapshot("garden", "cvch");
    let keeper = sql(&db2, "garden");
    keeper
        .run(context(&snapshot), &gate(), &voucher("garden", "old", 2000))
        .await
        .unwrap();
    snapshot
        .content
        .insert(gates::VOUCHER_VALIDITY_DAYS.into(), 31.into());
    assert!(matches!(
        keeper
            .run(context(&snapshot), &gate(), &voucher("garden", "new", 3000))
            .await,
        Err(Error::Storage)
    ));
    assert_eq!(
        keeper.collect(context(&snapshot)).await.unwrap()[0].valid_until,
        2_592_000
    );
    snapshot
        .content
        .insert(gates::VOUCHER_VALIDITY_DAYS.into(), 30.into());
    keeper
        .run(context(&snapshot), &gate(), &voucher("garden", "new", 2400))
        .await
        .unwrap();
    // Two namespaces with different schema failures do not contaminate the pool.
    LibsqlStore::new(&db, "garden")
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
}

#[tokio::test]
async fn missing_schema_legal_failure_and_corrupt_results_never_allow() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("broken.db").display()),
        "",
    ))
    .await
    .unwrap();
    let snapshot = snapshot("garden", "cvch");
    assert_eq!(
        LibsqlStore::new(&db, "garden")
            .unwrap()
            .check_query_plans()
            .await,
        Err(Error::Storage)
    );
    assert!(matches!(
        sql(&db, "garden")
            .decide(context(&snapshot), MembershipState::Pending, &[])
            .await,
        Err(Error::Legal)
    ));
    migrate(&db).await;
    db.community("garden").unwrap().execute("INSERT INTO cgts_results (subject, gate, provider, valid_until) VALUES (?1, ?2, ?3, ?4)", crlt::params!["alice", "bad/gate", "local", 86400i64]).await.unwrap();
    assert!(matches!(
        sql(&db, "garden").collect(context(&snapshot)).await,
        Err(Error::Storage)
    ));
}

#[tokio::test]
async fn memory_claim_and_result_commit_share_the_same_contract() {
    let store = MemoryStore::new("garden").unwrap();
    let result = GateResult {
        gate: "cvch".into(),
        level: GateLevel::Community,
        subject: "alice".into(),
        provider: "local".into(),
        valid_until: 86400,
    };
    let claim = Claim::new("cvch", vec![1; 32]).unwrap();
    let invalid = GateResult {
        valid_until: 0,
        ..result.clone()
    };
    assert!(store.commit(Some(&invalid), Some(&claim)).await.is_err());
    let precise = GateResult {
        valid_until: 86401,
        ..result.clone()
    };
    assert!(store.commit(Some(&precise), Some(&claim)).await.is_err());
    store.commit(Some(&result), Some(&claim)).await.unwrap();
    let replacement = GateResult {
        valid_until: 172800,
        ..result.clone()
    };
    assert_eq!(
        store.commit(Some(&replacement), Some(&claim)).await,
        Err(Error::Refused)
    );
    assert_eq!(store.load("alice").await.unwrap(), [result]);
    assert!(store.load("").await.is_err());
    assert!(store.remove("alice", "bad/gate", "local").await.is_err());
}

async fn optional_claim_and_result_parity(store: impl Storage) {
    store.commit(None, None).await.unwrap();
    let first = Claim::new("cvch", vec![1; 32]).unwrap();
    store.commit(None, Some(&first)).await.unwrap();
    assert_eq!(store.commit(None, Some(&first)).await, Err(Error::Refused));
    assert!(store.load("alice").await.unwrap().is_empty());
    let result = GateResult {
        gate: "cvch".into(),
        level: GateLevel::Community,
        subject: "alice".into(),
        provider: "local".into(),
        valid_until: 86400,
    };
    let global = GateResult {
        level: GateLevel::Global,
        ..result.clone()
    };
    let second = Claim::new("cvch", vec![2; 32]).unwrap();
    assert_eq!(
        store.commit(Some(&global), Some(&second)).await,
        Err(Error::Scope)
    );
    store.commit(Some(&result), Some(&second)).await.unwrap();
    let later = GateResult {
        valid_until: 172800,
        ..result.clone()
    };
    store.commit(Some(&later), None).await.unwrap();
    let other = GateResult {
        subject: "bob".into(),
        ..result
    };
    store.commit(Some(&other), None).await.unwrap();
    assert_eq!(store.load("alice").await.unwrap(), [later]);
    assert_eq!(store.load("bob").await.unwrap(), [other]);
    store.remove("alice", "cvch", "local").await.unwrap();
    store.remove("alice", "cvch", "local").await.unwrap();
    assert!(store.load("alice").await.unwrap().is_empty());
    assert_eq!(store.commit(None, Some(&second)).await, Err(Error::Refused));
    for (subject, gate, provider) in [("", "cvch", "local"), ("alice", "cvch", "bad/provider")] {
        assert_eq!(
            store.remove(subject, gate, provider).await,
            Err(Error::Invalid)
        );
    }
}

#[tokio::test]
async fn memory_and_sql_preserve_claims_across_optional_writes_and_removal() {
    optional_claim_and_result_parity(MemoryStore::new("garden").unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("optional.db")).await;
    optional_claim_and_result_parity(LibsqlStore::new(&db, "garden").unwrap()).await;
}

#[tokio::test]
async fn imported_storage_type_corruption_is_a_closed_failure() {
    let dir = tempfile::tempdir().unwrap();
    let schema = SCHEMA
        .replace("gate TEXT NOT NULL", "gate BLOB NOT NULL")
        .replace("provider TEXT NOT NULL", "provider BLOB NOT NULL")
        .replace(
            "valid_until INTEGER NOT NULL CHECK (valid_until > 0 AND valid_until % 86400 = 0)",
            "valid_until BLOB NOT NULL",
        );
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("imported.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[crlt::Migration::new(1, "imported", &schema)])
        .await
        .unwrap();
    let raw = db.community("garden").unwrap();
    let store = LibsqlStore::new(&db, "garden").unwrap();
    for (gate, provider, expiry) in [
        (
            crlt::Value::Blob(vec![1]),
            crlt::Value::Text("local".into()),
            crlt::Value::Integer(86400),
        ),
        (
            crlt::Value::Text("cvch".into()),
            crlt::Value::Blob(vec![1]),
            crlt::Value::Integer(86400),
        ),
        (
            crlt::Value::Text("cvch".into()),
            crlt::Value::Text("local".into()),
            crlt::Value::Real(1.5),
        ),
        (
            crlt::Value::Text("cvch".into()),
            crlt::Value::Text("local".into()),
            crlt::Value::Integer(86401),
        ),
    ] {
        raw.execute(
            "INSERT INTO cgts_results (subject, gate, provider, valid_until) VALUES (?1, ?2, ?3, ?4)",
            crlt::params!["alice", gate, provider, expiry],
        )
        .await
        .unwrap();
        assert_eq!(store.load("alice").await, Err(Error::Storage));
        raw.execute("DELETE FROM cgts_results WHERE subject = ?1", ["alice"])
            .await
            .unwrap();
    }
    assert!(store.load("alice").await.unwrap().is_empty());
}

#[test]
fn identifiers_and_claim_markers_enforce_byte_boundaries() {
    for value in [" ".to_owned(), "x".repeat(257), "a\0b".to_owned()] {
        assert!(matches!(MemoryStore::new(value), Err(Error::Invalid)));
    }
    assert!(MemoryStore::new("x".repeat(256)).is_ok());
    for marker in [vec![], vec![1; 129]] {
        assert!(matches!(Claim::new("cvch", marker), Err(Error::Invalid)));
    }
    assert!(Claim::new("cvch", vec![1; 128]).is_ok());
    assert!(matches!(
        Claim::new("bad/domain", vec![1]),
        Err(Error::Invalid)
    ));
}

#[tokio::test]
async fn query_plan_check_refuses_an_import_missing_the_spend_table() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            dir.path().join("incomplete-schema.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    let results_only = SCHEMA.split("CREATE TABLE cgts_spent").next().unwrap();
    db.migrate(&[crlt::Migration::new(1, "incomplete-import", results_only)])
        .await
        .unwrap();
    assert_eq!(
        LibsqlStore::new(&db, "garden")
            .unwrap()
            .check_query_plans()
            .await,
        Err(Error::Storage)
    );
}

#[tokio::test]
async fn imported_rowid_schema_with_a_real_scan_fails_the_plan_gate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scan.db");
    // A real imported schema can preserve namespace integrity yet lose the
    // gate-specific index. Populate and analyze it with the maintained driver.
    let schema = SCHEMA
        .replace(
            "PRIMARY KEY (community_id, subject, gate, provider)",
            "id INTEGER NOT NULL, PRIMARY KEY (community_id, id)",
        )
        .replace(" WITHOUT ROWID", "");
    let imported = libsql::Builder::new_local(&path).build().await.unwrap();
    let connection = imported.connect().unwrap();
    connection.execute_batch(&schema).await.unwrap();
    for id in 0..100i64 {
        connection.execute(
            "INSERT INTO cgts_results (community_id, id, subject, gate, provider, valid_until) VALUES ('garden', ?1, 'subject', ?2, 'provider', 86400)",
            libsql::params![id, format!("gate{id}")],
        ).await.unwrap();
    }
    connection.execute_batch("ANALYZE").await.unwrap();
    drop(connection);
    drop(imported);
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    db.migrate(&[]).await.unwrap();
    let store = LibsqlStore::new(&db, "garden").unwrap();
    assert_eq!(store.check_query_plans().await, Err(Error::Storage));
    assert_eq!(store.load("subject").await, Err(Error::Storage));
}
