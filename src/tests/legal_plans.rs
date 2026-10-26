use super::*;
use crlt::{Config, Migration};

#[tokio::test]
async fn every_query_uses_an_index() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("plans.db").display());
    let db = Db::open(Config::new(url, "")).await.unwrap();
    db.migrate(&[
        Migration::new(1, "clbs", SCHEMA),
        Migration::new(2, "clbs-scope", SCOPE_SCHEMA),
    ])
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
                    "member"
                ],
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
                Value::Text("member".into()),
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

/// Order scope survives the libSQL round-trip: a recorded community-scope
/// order reads back as community scope, so `community_legal_state` over
/// stored records reports Red. Member orders and legacy rows (written before
/// the scope column existed) stay member scope and never redden a community.
#[tokio::test]
async fn community_scope_survives_the_libsql_round_trip() {
    use clbs::{Order, OrderKind, Record, Scope, Store as _};
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("scope.db").display());
    let db = Db::open(Config::new(url, "")).await.unwrap();
    db.migrate(&[
        Migration::new(1, "clbs", SCHEMA),
        Migration::new(2, "clbs-scope", SCOPE_SCHEMA),
    ])
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    let member = Order {
        community: "community-a".into(),
        id: "member-1".into(),
        subject: "alice".into(),
        reference: "ref".into(),
        entered_by: "root".into(),
        kind: OrderKind::Legal {
            authority: "court".into(),
        },
        scope: Scope::Member,
    };
    let community = Order {
        community: "community-a".into(),
        id: "comm-1".into(),
        subject: "community-a".into(),
        reference: "ref".into(),
        entered_by: "root".into(),
        kind: OrderKind::Legal {
            authority: "court".into(),
        },
        scope: Scope::Community,
    };
    assert_eq!(
        store
            .append(&Record::restore_trusted(member).unwrap())
            .await
            .unwrap(),
        clbs::Append::Inserted
    );
    assert_eq!(
        store
            .append(&Record::restore_trusted(community).unwrap())
            .await
            .unwrap(),
        clbs::Append::Inserted
    );
    // A row written before the scope column existed reads back as member
    // scope: legacy rows can never redden a community.
    db.community("community-a")
        .unwrap()
        .execute(
            "INSERT INTO clbs_orders (id, subject, reference, entered_by, kind, authority) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["legacy-1", "community-a", "ref", "root", "legal", "court"],
        )
        .await
        .unwrap();
    let records = store.orders("community-a").await.unwrap();
    assert_eq!(records.len(), 2);
    let scope_of = |id: &str| {
        records
            .iter()
            .find(|record| record.order().id == id)
            .map(|record| record.order().scope)
    };
    assert_eq!(scope_of("comm-1"), Some(Scope::Community));
    assert_eq!(scope_of("legacy-1"), Some(Scope::Member));
    assert!(matches!(
        clbs::community_legal_state("community-a", &records),
        clbs::State::Red(_)
    ));
    // Another community stays green on the same records.
    assert_eq!(
        clbs::community_legal_state("community-b", &records),
        clbs::State::Green
    );
    let gate = clbs::Gate::new(store, DenyAll);
    assert!(matches!(
        gate.check("alice").await.unwrap(),
        clbs::State::Red(_)
    ));
    assert_eq!(gate.check("bob").await.unwrap(), clbs::State::Green);
}

#[derive(Clone)]
struct DenyAll;

impl clbs::Verifier for DenyAll {
    async fn verify_legal(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}
