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
