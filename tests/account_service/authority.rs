//! Queue/cancellation routing to the real ledger's final owner callback.
//! The external owner always refuses: these tests cannot authorize a proof.
use super::*;

struct RefusedOwner {
    called: Arc<AtomicU64>,
    _lease: tokio::sync::OwnedMutexGuard<()>,
}
impl cblc::storage::CommitAuthority for RefusedOwner {
    fn check(&self, observed: u64) -> std::result::Result<(), cblc::Error> {
        assert_eq!(observed, 1100);
        self.called.fetch_add(1, Ordering::SeqCst);
        Err(cblc::Error::Admission)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn member_queue_reaches_actual_final_authority_before_signed_status_release() {
    let dir = tempfile::tempdir().unwrap();
    let keeper = memory("garden")
        .with_account_service(service(dir.path().join("authorized"), "garden", || 1100).await)
        .await
        .unwrap();
    let member = Member::new();
    let settings = snapshot("garden", "cblc");
    let subject = member.pseudonym.to_hex();
    let ctx = Context {
        subject: &subject,
        ..context(&settings)
    };
    let queue = Arc::new(tokio::sync::Mutex::new(()));
    let called = Arc::new(AtomicU64::new(0));
    let owner = Arc::new(RefusedOwner {
        called: called.clone(),
        _lease: queue.clone().lock_owned().await,
    });
    assert!(matches!(
        keeper
            .account_authorized(ctx, member.pseudonym.clone(), member.wire(), owner)
            .await,
        Err(Error::Account(cblc::Error::Admission))
    ));
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert!(queue.try_lock().is_ok());

    // The independently signed original request and native service are valid;
    // the refusal above comes from the required member authority at its cut.
    let response = keeper
        .account(ctx, member.pseudonym.clone(), member.wire(), ())
        .await
        .unwrap();
    let AccountServiceResponse::Status(status) = response else {
        panic!("original status response")
    };
    verify_account_status_response(
        &status,
        &member.request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(status.acceptance.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_member_caller_cannot_drop_queued_owner_before_actual_service_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = AtomicBool::new(true);
    let keeper = Arc::new(
        memory("garden")
            .with_account_service(
                service(dir.path().join("cancel-authorized"), "garden", move || {
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
    let called = Arc::new(AtomicU64::new(0));
    let owner = Arc::new(RefusedOwner {
        called: called.clone(),
        _lease: queue.clone().lock_owned().await,
    });
    let caller = keeper.clone();
    let task = tokio::spawn(async move {
        let member = Member::new();
        let settings = snapshot("garden", "cblc");
        let subject = member.pseudonym.to_hex();
        caller
            .account_authorized(
                Context {
                    subject: &subject,
                    ..context(&settings)
                },
                member.pseudonym.clone(),
                member.wire(),
                owner,
            )
            .await
    });
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(queue.try_lock().is_err());
    assert_eq!(called.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    let released = tokio::time::timeout(Duration::from_secs(30), queue.lock())
        .await
        .unwrap();
    assert_eq!(called.load(Ordering::SeqCst), 1);
    drop(released);
    keeper.account_shutdown().unwrap().shutdown().await.unwrap();
}
