//! Optional live Turso round trip using caller-provided test credentials only.
#[path = "legal_common/mod.rs"]
mod common;

use cgts::legal_storage::{LibsqlStore, SCHEMA};
use clbs::{Append, Gate, State};
use common::{TestClock, TestVerifier, legal, sign};
use crlt::{Config, Db, Migration};

#[tokio::test]
#[ignore = "requires explicit operator authorization and disposable remote database"]
async fn optional_real_turso_round_trip() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("skipped: TURSO_URL and TURSO_TOKEN are required");
        return;
    };
    if url.trim().is_empty() || token.trim().is_empty() {
        eprintln!("skipped: TURSO_URL and TURSO_TOKEN must be nonempty");
        return;
    }
    // Never display upstream errors: HTTP diagnostics can contain credentials.
    let db = Db::open(Config::new(url, token))
        .await
        .unwrap_or_else(|_| panic!("Turso connection failed"));
    db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
        .await
        .unwrap_or_else(|_| panic!("Turso migration failed; use a disposable database"));
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let community = format!("clbs-test-{}-{unique}", std::process::id());
    let store = LibsqlStore::new(&db, &community).unwrap();
    let clock = TestClock::new(150);
    let gate = Gate::new(store, TestVerifier::new(&community), clock.clone());
    let mut order = legal("remote-round-trip");
    order.community = community;
    let signed = sign(order);
    assert_eq!(gate.record_legal(&signed).await.unwrap(), Append::Inserted);
    assert_eq!(gate.record_legal(&signed).await.unwrap(), Append::Unchanged);
    assert_eq!(
        gate.record("remote-round-trip")
            .await
            .unwrap()
            .unwrap()
            .order(),
        &signed.order
    );
    assert!(matches!(gate.check("alice").await.unwrap(), State::Red(_)));
    assert_eq!(gate.revocations().await.unwrap().len(), 1);
    assert_eq!(gate.counts().await.unwrap().active_legal_orders, 1);
    clock.set(200);
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
    assert_eq!(gate.counts().await.unwrap().legal_orders, 1);
}
