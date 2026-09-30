//! Optional real Turso round trip; public CI supplies no credentials.
mod common;
use cgts::*;
use common::*;

#[tokio::test]
async fn optional_real_turso() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("Skipped live Turso: both environment credentials are required");
        return;
    };
    if url.is_empty() || token.is_empty() {
        eprintln!("Skipped live Turso: empty credentials");
        return;
    }
    // Use a disposable database. The unique namespace retains only synthetic rows.
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    migrate(&db).await;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let community = format!("cgts-test-{unique}");
    let snapshot = snapshot(&community, "cvch");
    let keeper = sql(&db, &community);
    keeper
        .run(
            context(&snapshot),
            &gate(),
            &voucher(&community, "one", 2000),
        )
        .await
        .unwrap();
    assert_eq!(keeper.collect(context(&snapshot)).await.unwrap().len(), 1);
    LibsqlStore::new(&db, &community)
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
}
