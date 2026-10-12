//! Real signed status operations through the original Balance service and SQL.
//! Status does not invoke ZK verification; the configured native verifier is real.
//! Requires existing authenticated CBLC_PROOF_DIRECTORY and CBLC_BB fixture inputs.
#[path = "account_service/authority.rs"]
mod authority;
mod common;
#[path = "account_service/host.rs"]
mod host;
#[path = "account_service/native.rs"]
mod native;
#[path = "account_service/shutdown.rs"]
mod shutdown;
#[path = "account_service/storage.rs"]
mod storage;
use cblc::{accounting::*, accounting_ledger::*, accounting_service::*, admission::*};
use cgts::*;
use common::*;
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

fn policy_signer() -> csgn::Signer {
    csgn::Signer::new(
        "garden",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        0,
        100_000,
    )
    .unwrap()
}

fn policy() -> AccountLedgerPolicy {
    AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 3000,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 1024,
        checkpoint_period_seconds: 1000,
    }
}

struct Member {
    pseudonym: cpsd::Pseudonym,
    grant: AdmissionGrant,
    authorization: DeviceAuthorization,
    request: AccountStatusRequest,
}
impl Member {
    fn new() -> Self {
        let pseudonym = cpsd::HolderSecret::generate(&mut rand::rngs::OsRng)
            .pseudonym(&cpsd::CommunityId::new("garden").unwrap());
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let device = SigningKey::from_bytes(&[2; 32]);
        let root = SigningKey::from_bytes(&[3; 32]);
        let mut grant = AdmissionGrant {
            version: 3,
            issuer_key_id: B64.encode(&Sha256::digest(issuer.verifying_key().to_bytes())),
            community_id: "garden".into(),
            member_id: member_id(&pseudonym.to_bytes()),
            pseudonym: pseudonym.to_hex(),
            chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
            policy_digest: B64.encode(&[4; 32]),
            policy_epoch: 1,
            passport_policy_digest: B64.encode(&[5; 32]),
            issued_at: 1050,
            expires_at: 1200,
            signature: String::new(),
        };
        grant.signature = B64.encode(
            &policy_signer()
                .sign(
                    csgn::Kind::Credential,
                    &admission_bytes(&grant).unwrap(),
                    grant.issued_at,
                    grant.expires_at,
                )
                .unwrap(),
        );
        let mut authorization = DeviceAuthorization {
            version: 1,
            community_id: "garden".into(),
            member_id: grant.member_id.clone(),
            root_public_key: B64.encode(&root.verifying_key().to_bytes()),
            device_public_key: grant.chat_public_key.clone(),
            issued_at: 1050,
            expires_at: 1200,
            signature: String::new(),
        };
        authorization.signature = B64.encode(
            &root
                .sign(&device_authorization_bytes(&authorization).unwrap())
                .to_bytes(),
        );
        let mut request = AccountStatusRequest {
            community: Sha256::digest(b"garden").into(),
            owner: B64
                .decode(grant.member_id.as_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
            request_id: None,
            challenge: [5; 32],
            chat_public_key: grant.chat_public_key.clone(),
            issued_at: 1080,
            expires_at: 1180,
            signature: String::new(),
        };
        request.signature = B64.encode(
            &device
                .sign(&account_status_bytes(&request).unwrap())
                .to_bytes(),
        );
        Self {
            pseudonym,
            grant,
            authorization,
            request,
        }
    }
    fn wire(&self) -> AccountServiceRequest {
        AccountServiceRequest::Status {
            grant: self.grant.clone(),
            authorization: self.authorization.clone(),
            request: self.request.clone(),
        }
    }
}

async fn service<C: Fn() -> u64 + Send + 'static>(
    path: std::path::PathBuf,
    community: &str,
    clock: C,
) -> AccountService<NativeAccountVerifier, C> {
    let community = community.to_owned();
    tokio::task::spawn_blocking(move || {
        let verifier = native::verifier();
        let ledger = storage::open(
            &path,
            AdmissionTrust {
                community_id: community,
                policy_digest: B64.encode(&[4; 32]),
                policy_keys: policy_signer().key_ring().clone(),
            },
            policy(),
            verifier,
            ed25519_dalek_v2::SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        AccountService::new(ledger, clock, 100_000).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn original_signed_status_and_live_clock_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let member = Member::new();
    let settings = snapshot("garden", "cblc");
    let subject = member.pseudonym.to_hex();
    let ctx = Context {
        subject: &subject,
        ..context(&settings)
    };
    let clock = Arc::new(AtomicU64::new(1100));
    let read_clock = clock.clone();
    let keeper = memory("garden")
        .with_account_service(
            service(dir.path().join("accounts"), "garden", move || {
                read_clock.load(Ordering::SeqCst)
            })
            .await,
        )
        .await
        .unwrap();
    let answer = keeper
        .account(ctx, member.pseudonym, member.wire(), ())
        .await
        .unwrap();
    let AccountServiceResponse::Status(answer) = answer else {
        panic!("status response")
    };
    verify_account_status_response(
        &answer,
        &member.request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(answer.observed_at, 1100);
    assert!(answer.acceptance.is_none());
    assert!(keeper.collect(ctx).await.unwrap().is_empty());
    let other = Member::new();
    assert!(matches!(
        keeper
            .account(ctx, other.pseudonym, member.wire(), ())
            .await,
        Err(Error::Scope)
    ));
    let mut wrong = member.wire();
    if let AccountServiceRequest::Status { ref mut grant, .. } = wrong {
        grant.pseudonym = other.grant.pseudonym;
    }
    assert!(matches!(
        keeper
            .account(ctx, member.pseudonym, wrong, ())
            .await,
        Err(Error::Account(cblc::Error::Admission))
    ));
    clock.store(1200, Ordering::SeqCst);
    assert!(matches!(
        keeper
            .account(ctx, member.pseudonym, member.wire(), ())
            .await,
        Err(Error::Account(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_keeps_the_actual_lease_until_service_completion() {
    let dir = tempfile::tempdir().unwrap();
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = AtomicBool::new(true);
    let keeper = Arc::new(
        memory("garden")
            .with_account_service(
                service(dir.path().join("accounts"), "garden", move || {
                    if first.swap(false, Ordering::SeqCst) {
                        entered.send(()).unwrap();
                        resume.recv_timeout(Duration::from_secs(30)).unwrap();
                    }
                    1100
                })
                .await,
            )
            .await
            .unwrap(),
    );
    let queue = Arc::new(tokio::sync::Mutex::new(()));
    let lease = queue.clone().lock_owned().await;
    let caller = keeper.clone();
    let task = tokio::spawn(async move {
        let member = Member::new();
        let settings = snapshot("garden", "cblc");
        let subject = member.pseudonym.to_hex();
        caller
            .account(
                Context {
                    subject: &subject,
                    ..context(&settings)
                },
                member.pseudonym,
                member.wire(),
                lease,
            )
            .await
    });
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(queue.try_lock().is_err());
    release.send(()).unwrap();
    let _completed = tokio::time::timeout(Duration::from_secs(30), queue.lock())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_panicked_service_remains_fenced_and_unconfigured_services_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let member = Member::new();
    let settings = snapshot("garden", "cblc");
    let subject = member.pseudonym.to_hex();
    let ctx = Context {
        subject: &subject,
        ..context(&settings)
    };
    assert!(matches!(
        memory("garden")
            .account(ctx, member.pseudonym, member.wire(), ())
            .await,
        Err(Error::Disabled)
    ));
    let keeper = memory("garden")
        .with_account_service(
            service(dir.path().join("accounts"), "garden", || {
                panic!("clock unavailable")
            })
            .await,
        )
        .await
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            keeper
                .account(ctx, member.pseudonym, member.wire(), ())
                .await,
            Err(Error::Storage)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_service_scope_and_single_installation_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let wrong = service(dir.path().join("other"), "other", || 1100).await;
    assert!(matches!(
        memory("garden").with_account_service(wrong).await,
        Err(Error::Scope)
    ));
    let first = service(dir.path().join("first"), "garden", || 1100).await;
    let keeper = memory("garden").with_account_service(first).await.unwrap();
    let second = service(dir.path().join("second"), "garden", || 1100).await;
    assert!(matches!(
        keeper.with_account_service(second).await,
        Err(Error::Invalid)
    ));
}
