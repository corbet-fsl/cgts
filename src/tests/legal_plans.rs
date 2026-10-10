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
                params![
                    "id",
                    "alice",
                    "reference",
                    "root",
                    "legal",
                    "court",
                    "\"All\"",
                    100,
                    200
                ],
            )
            .await
            .unwrap();
    }
    for (sql, values) in [
        (BY_ID, vec![Value::Text("id".into())]),
        (
            ACTIVE,
            vec![Value::Text("alice".into()), Value::Integer(150)],
        ),
        (REVOCATIONS, vec![Value::Integer(150)]),
        (COUNTS, vec![Value::Integer(150)]),
        (
            INSERT,
            vec![
                Value::Text("next".into()),
                Value::Text("alice".into()),
                Value::Text("reference".into()),
                Value::Text("root".into()),
                Value::Text("legal".into()),
                Value::Text("court".into()),
                Value::Text("\"All\"".into()),
                Value::Integer(100),
                Value::Integer(200),
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
    assert_eq!(
        scoped
            .query(ACTIVE, params!["alice", 150])
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(scoped.query(REVOCATIONS, [150]).await.unwrap().len(), 1);
    assert_eq!(
        scoped.query(COUNTS, [150]).await.unwrap()[0]
            .get_i64(0)
            .unwrap(),
        1
    );
}
