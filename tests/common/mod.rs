#![allow(dead_code)]
use cgts::*;
use ed25519_dalek::{Signer, SigningKey};

pub fn snapshot(community: &str, gate: &str) -> Snapshot {
    let level = GateLevel::Community;
    let policy = crbk::ActionPolicy {
        all_of: vec![crbk::Requirement {
            gate: gate.into(),
            level,
            provider: None,
        }],
        ..Default::default()
    };
    Snapshot {
        community: community.into(),
        kind: crbk::SnapshotKind::Settings,
        revision: 1,
        policy_epoch: 2,
        issued: 100,
        content: [
            (crbk::gate_key(level, gate), true.into()),
            (gates::VOUCHER_VALIDITY_DAYS.into(), 30.into()),
            (crbk::provider_key(level, gate, "local"), true.into()),
            (
                crbk::action_key("enter"),
                serde_json::to_value(policy).unwrap(),
            ),
        ]
        .into(),
    }
}
pub fn context(snapshot: &Snapshot) -> Context<'_> {
    Context {
        snapshot,
        subject: "alice",
        action: "enter",
        now: 1100,
    }
}
pub fn voucher(community: &str, id: &str, expiry: u64) -> cvch::Voucher {
    let binding = cvch::member_binding(&cvch::receipt_id(id), b"alice");
    cvch::Voucher {
        member_binding: binding.clone(),
        id: id.into(),
        valid_until: expiry,
        signature: SigningKey::from_bytes(&[7; 32])
            .sign(&cvch::issuance_bytes(id, expiry, community, &binding))
            .to_bytes()
            .to_vec(),
    }
}
pub fn gate() -> gates::VoucherGate {
    gates::VoucherGate::new("local", SigningKey::from_bytes(&[7; 32]).verifying_key()).unwrap()
}

// A real signature/authority test adapter, not a legal qualification claim.
#[derive(Clone)]
pub struct Authority;
impl clbs::Verifier for Authority {
    async fn verify_legal(&self, submission: &clbs::SignedOrder) -> clbs::Result<()> {
        if submission.order.entered_by != "root"
            || submission.order.kind
                != (clbs::OrderKind::Legal {
                    authority: "test-court".into(),
                })
        {
            return Err(clbs::Error::Denied);
        }
        let signature = ed25519_dalek::Signature::from_slice(&submission.proof)
            .map_err(|_| clbs::Error::Denied)?;
        SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .verify_strict(&submission.order.signing_payload()?, &signature)
            .map_err(|_| clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}
#[derive(Clone, Copy)]
pub struct Clock;
impl clbs::Clock for Clock {
    fn now(&self) -> clbs::Result<i64> {
        Ok(1100)
    }
}

pub fn order(community: &str) -> clbs::SignedOrder {
    let order = clbs::Order {
        community: community.into(),
        id: "order-1".into(),
        subject: "alice".into(),
        reference: "test-reference".into(),
        entered_by: "root".into(),
        kind: clbs::OrderKind::Legal {
            authority: "test-court".into(),
        },
        scope: clbs::Scope::Actions(["enter".into()].into()),
        period: clbs::Period {
            starts_at: 1100,
            ends_at: Some(1200),
        },
    };
    let proof = SigningKey::from_bytes(&[9; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    clbs::SignedOrder { order, proof }
}
pub fn memory(community: &str) -> Gatekeeper<MemoryStore, LegalGate<clbs::MemoryStore, Authority>> {
    Gatekeeper::new(
        MemoryStore::new(community).unwrap(),
        LegalGate::new(clbs::MemoryStore::new(community).unwrap(), Authority),
    )
    .unwrap()
}
pub async fn open(path: &std::path::Path) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    migrate(&db).await;
    db
}
pub async fn migrate(db: &crlt::Db) {
    let migrations = [
        crlt::Migration::new(1, "gates", SCHEMA),
        crlt::Migration::new(2, "legal", clbs::SCHEMA),
    ];
    db.migrate(&migrations).await.unwrap();
    assert_eq!(db.migrate(&migrations).await.unwrap(), 0);
}
pub fn sql(
    db: &crlt::Db,
    community: &str,
) -> Gatekeeper<LibsqlStore, LegalGate<clbs::LibsqlStore, Authority>> {
    Gatekeeper::new(
        LibsqlStore::new(db, community).unwrap(),
        LegalGate::new(clbs::LibsqlStore::new(db, community).unwrap(), Authority),
    )
    .unwrap()
}

// Policy evaluation is only a test oracle here. cplc owns it in production.
pub struct Decision {
    pub allowed: bool,
    pub legal_veto: bool,
}
pub trait TestPolicy {
    fn decide(
        &self,
        context: Context<'_>,
        membership: MembershipState,
        checked: &[CheckedGate],
    ) -> impl std::future::Future<Output = Result<Decision>>;
}
impl<S: Storage, L: LegalVeto> TestPolicy for Gatekeeper<S, L> {
    async fn decide(
        &self,
        context: Context<'_>,
        membership: MembershipState,
        checked: &[CheckedGate],
    ) -> Result<Decision> {
        let checked = match self.check(context, checked.to_vec()).await {
            Err(Error::Vetoed) => {
                return Ok(Decision {
                    allowed: false,
                    legal_veto: true,
                });
            }
            result => result?,
        };
        let gates = checked.in_context(context)?;
        let decision = context
            .snapshot
            .may(
                crbk::Subject {
                    id: context.subject,
                    membership,
                },
                context.action,
                &gates,
                context.now,
            )
            .map_err(|_| Error::Policy)?;
        Ok(Decision {
            allowed: decision.allowed,
            legal_veto: false,
        })
    }
}
