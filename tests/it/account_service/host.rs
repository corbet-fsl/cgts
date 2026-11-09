//! Same native owner and actual retained guard for privileged host operations.
use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn host_tuning_returns_the_same_lease_and_member_work_sees_the_same_owner() {
    let dir = tempfile::tempdir().unwrap();
    let keeper = memory("garden")
        .with_account_service(service(dir.path().join("host"), "garden", || 1100).await)
        .await
        .unwrap();
    let queue = Arc::new(tokio::sync::Mutex::new(()));
    let lease = queue.clone().lock_owned().await;
    let (response, returned) = keeper
        .account_host(
            HostRequest::TuneWaiting {
                expected_revision: 0,
                seconds: 1100,
            },
            lease,
        )
        .await
        .unwrap();
    let HostResponse::WaitingPeriod(tuning) = response else {
        panic!("native tuning")
    };
    assert_eq!(tuning.revision, 1);
    assert_eq!(tuning.seconds, 1100);
    assert!(queue.try_lock().is_err());
    drop(returned);
    assert!(queue.try_lock().is_ok());
    let member = Member::new();
    let settings = snapshot("garden", "cblc");
    let subject = member.pseudonym.to_hex();
    let answer = keeper
        .account(
            Context {
                subject: &subject,
                ..context(&settings)
            },
            member.pseudonym,
            member.wire(),
            (),
        )
        .await
        .unwrap();
    let AccountServiceResponse::Status(answer) = answer else {
        panic!("same owner status")
    };
    verify_account_status_response(
        &answer,
        &member.request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(answer.acceptance.is_none());
    assert!(matches!(
        keeper
            .account_host(
                HostRequest::TuneWaiting {
                    expected_revision: 0,
                    seconds: 1200
                },
                (),
            )
            .await,
        Err(Error::Account(cblc::Error::PolicyMismatch))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_host_operation_keeps_lease_then_reconciles_the_original_native_revision() {
    let dir = tempfile::tempdir().unwrap();
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = AtomicBool::new(true);
    let keeper = Arc::new(
        memory("garden")
            .with_account_service(
                service(dir.path().join("host-cancel"), "garden", move || {
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
        caller
            .account_host(
                HostRequest::TuneWaiting {
                    expected_revision: 0,
                    seconds: 1100,
                },
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
    let completed = tokio::time::timeout(Duration::from_secs(30), queue.lock())
        .await
        .unwrap();
    drop(completed);
    // Use the existing owner; its actual committed revision survived cancellation.
    let (response, ()) = keeper
        .account_host(
            HostRequest::TuneWaiting {
                expected_revision: 1,
                seconds: 1200,
            },
            (),
        )
        .await
        .unwrap();
    let HostResponse::WaitingPeriod(tuning) = response else {
        panic!("reconciled tuning")
    };
    assert_eq!(tuning.revision, 2);
    assert_eq!(tuning.seconds, 1200);
}

#[tokio::test(flavor = "multi_thread")]
async fn absent_native_publication_capability_never_fabricates_bootstrap_or_record_material() {
    let dir = tempfile::tempdir().unwrap();
    let keeper = memory("garden")
        .with_account_service(
            service(dir.path().join("host-unconfigured"), "garden", || 1100).await,
        )
        .await
        .unwrap();
    for request in [
        HostRequest::VerifierMaterial {
            revision: 1,
            policy_epoch: 1,
        },
        HostRequest::PublishRecord {
            revision: 1,
            policy_epoch: 1,
            period_seconds: 100,
        },
        HostRequest::SettleBatch(Vec::new()),
    ] {
        assert!(matches!(
            keeper.account_host(request, ()).await,
            Err(Error::Account(cblc::Error::UnsupportedCapability))
        ));
    }
}
