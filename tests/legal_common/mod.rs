#![allow(dead_code)]
use cgts::legal_storage::{LibsqlStore, SCHEMA};

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use clbs::{Clock, Error, Order, OrderKind, Period, Result, Scope, SignedOrder, Verifier};
use crlt::{Config, Db, Migration};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use tempfile::TempDir;

#[derive(Clone)]
pub struct TestClock(pub Arc<AtomicI64>);

impl TestClock {
    pub fn new(at: i64) -> Self {
        Self(Arc::new(AtomicI64::new(at)))
    }
    pub fn set(&self, at: i64) {
        self.0.store(at, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Result<i64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

// Test-only verifier for authentic signatures and a fixed authorized test actor.
// It is not a qualified e-signature or passkey adapter. No clbs logic is mocked.
#[derive(Clone)]
pub struct TestVerifier {
    community: String,
    legal: VerifyingKey,
    member: VerifyingKey,
}

impl TestVerifier {
    pub fn new(community: &str) -> Self {
        Self {
            community: community.into(),
            legal: key(7).verifying_key(),
            member: key(8).verifying_key(),
        }
    }

    fn verify(&self, submission: &SignedOrder, key: &VerifyingKey) -> Result<()> {
        if submission.order.community != self.community {
            return Err(Error::Denied);
        }
        let signature = Signature::from_slice(&submission.proof).map_err(|_| Error::Denied)?;
        key.verify_strict(&submission.order.signing_payload()?, &signature)
            .map_err(|_| Error::Denied)
    }
}

impl Verifier for TestVerifier {
    async fn verify_legal(&self, submission: &SignedOrder) -> Result<()> {
        if submission.order.kind
            != (OrderKind::Legal {
                authority: "court".into(),
            })
            || submission.order.entered_by != "root"
        {
            return Err(Error::Denied);
        }
        self.verify(submission, &self.legal)
    }

    async fn verify_self_ban(&self, submission: &SignedOrder) -> Result<()> {
        if submission.order.subject != "alice" {
            return Err(Error::Denied);
        }
        self.verify(submission, &self.member)
    }
}

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
        scope: Scope::Actions(["publish".into()].into()),
        period: Period {
            starts_at: 100,
            ends_at: Some(200),
        },
    }
}

pub fn ban(id: &str) -> Order {
    Order {
        kind: OrderKind::SelfBan,
        entered_by: "alice".into(),
        scope: Scope::All,
        period: Period {
            starts_at: 100,
            ends_at: None,
        },
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
