#![allow(dead_code)]
use cgts::legal_storage::{LibsqlStore, SCHEMA};

use clbs::{Error, Order, OrderKind, Result, SignedOrder, Verifier};
use crlt::{Config, Db, Migration};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use tempfile::TempDir;

pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

pub fn legal(id: &str) -> Order {
    Order {
        community: "community-a".into(),
        id: id.into(),
        subject: "alice".into(),
        reference: "case-reference".into(),
        entered_by: "root".into(),
        kind: OrderKind::Legal {
            authority: "court".into(),
        },
    }
}

pub fn ban(id: &str) -> Order {
    Order {
        kind: OrderKind::SelfBan,
        entered_by: "alice".into(),
        ..legal(id)
    }
}

pub fn sign(order: Order) -> SignedOrder {
    let signer = match order.kind {
        OrderKind::Legal { .. } => key(7),
        OrderKind::SelfBan => key(8),
    };
    let proof = signer
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    SignedOrder { order, proof }
}

pub async fn open(path: &std::path::Path) -> Db {
    let url = format!("file://{}", path.display());
    let db = Db::open(Config::new(url, "")).await.unwrap();
    assert_eq!(
        db.migrate(&[Migration::new(1, "clbs", SCHEMA)])
            .await
            .unwrap(),
        1
    );
    db
}

pub async fn sql_fixture() -> (Option<TempDir>, LibsqlStore) {
    let directory = tempfile::tempdir().unwrap();
    let db = open(&directory.path().join("orders.db")).await;
    let store = LibsqlStore::new(&db, "community-a").unwrap();
    (Some(directory), store)
}

pub async fn memory_fixture() -> (Option<TempDir>, clbs::MemoryStore) {
    (None, clbs::MemoryStore::new("community-a").unwrap())
}
