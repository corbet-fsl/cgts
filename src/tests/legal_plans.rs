use super::*;
use crlt::{Config, Migration};

#[tokio::test]
async fn every_query_uses_an_index() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("plans.db").display());
    let db = Db::open(Config::new(url, "")).await.unwrap();
    db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
        .await
        .unwrap();
    let scoped = db.community("community-a").unwrap();
    // Populate two namespaces so both isolation and selective plans matter.
    for community in ["community-a", "community-b"] {
        let handle = db.community(community).unwrap();
        handle
            .execute(
                INSERT,
                params!["id", "alice", "reference", "root", "legal", "court"],
            )
            .await
            .unwrap();
    }
    for (sql, values) in [
        (BY_ID, vec![Value::Text("id".into())]),
        (ORDERS, vec![Value::Text("alice".into())]),
        (REVOCATIONS, vec![]),
        (COUNTS, vec![]),
        (
            INSERT,
            vec![
                Value::Text("next".into()),
                Value::Text("alice".into()),
                Value::Text("reference".into()),
                Value::Text("root".into()),
                Value::Text("legal".into()),
                Value::Text("court".into()),
            ],
        ),
    ] {
        scoped
            .explain(sql, values)
            .await
            .unwrap()
            .assert_indexed()
            .unwrap();
    }
    // Execute every read as well: these exercise crlt's SQL scoping and decoding.
    assert_eq!(scoped.query(BY_ID, ["id"]).await.unwrap().len(), 1);
    assert_eq!(scoped.query(ORDERS, ["alice"]).await.unwrap().len(), 1);
    assert_eq!(scoped.query(REVOCATIONS, params![]).await.unwrap().len(), 1);
    assert_eq!(
        scoped.query(COUNTS, params![]).await.unwrap()[0]
            .get_i64(0)
            .unwrap(),
        1
    );
}
