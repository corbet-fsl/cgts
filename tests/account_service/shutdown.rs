//! Real native service/SQL lifetime. Clock blocking exposes the owned join cut.
use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn native_shutdown_reaches_the_actual_verifier_clones_after_a_genuine_proof_succeeds() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("CBLC_PROOF_DIRECTORY")
            .expect("Original native account proofs are required"),
    );
    let records: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("ledger-records.json")).unwrap())
            .unwrap();
    let statement: cblc::accounting::AccountStatement =
        serde_json::from_value(records[0]["statement"].clone()).unwrap();
    let proof = data_encoding::HEXLOWER
        .decode(records[0]["proof"].as_str().unwrap().as_bytes())
        .unwrap();
    let verifier = native::verifier_with_limit(cblc::extensions::EXTENSION_PROOF_BYTES);
    let retained = verifier.clone();
    // Prove the exact supplied statement/proof succeeds with the real worker
    // before asserting cancellation. A preexisting refusal cannot satisfy it.
    let (retained, statement, proof) = tokio::task::spawn_blocking(move || {
        assert_eq!(retained.verify(&statement, &proof), Ok(()));
        (retained, statement, proof)
    })
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut configured = policy();
    configured.max_proof_bytes = cblc::extensions::EXTENSION_PROOF_BYTES;
    let path = dir.path().join("native-clone-shutdown");
    let service = tokio::task::spawn_blocking(move || {
        let ledger = storage::open(
            path,
            AdmissionTrust {
                community_id: "garden".into(),
                policy_digest: B64.encode(&[4; 32]),
                policy_keys: policy_signer().key_ring().clone(),
            },
            configured,
            verifier,
            ed25519_dalek_v2::SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        AccountService::new(ledger, || 1100, cblc::extensions::EXTENSION_PROOF_BYTES).unwrap()
    })
    .await
    .unwrap();
    let keeper = memory("garden")
        .with_native_account_service(service)
        .await
        .unwrap();
    keeper.account_shutdown().unwrap().shutdown().await.unwrap();
    assert_eq!(
        retained.verify(&statement, &proof),
        Err(cblc::Error::CryptoProvider)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_shutdown_waiters_still_join_the_same_worker_before_releasing_its_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (entered, started) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = AtomicBool::new(true);
    let samples = Arc::new(AtomicU64::new(0));
    let observed = samples.clone();
    let keeper = Arc::new(
        memory("garden")
            .with_native_account_service(
                service(dir.path().join("native-shutdown"), "garden", move || {
                    observed.fetch_add(1, Ordering::SeqCst);
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
    let shutdown = keeper.account_shutdown().unwrap();
    let queue = Arc::new(tokio::sync::Mutex::new(()));
    let lease = queue.clone().lock_owned().await;
    let owner = keeper.clone();
    let task = tokio::spawn(async move {
        let member = Member::new();
        let snapshot = snapshot("garden", "cblc");
        let subject = member.pseudonym.to_hex();
        owner
            .account(
                Context {
                    subject: &subject,
                    ..context(&snapshot)
                },
                member.pseudonym,
                member.wire(),
                lease,
            )
            .await
    });
    tokio::task::spawn_blocking(move || started.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
    // Both waits genuinely poll teardown, then cancel while the real operation
    // remains blocked. The second cannot report success from an empty Join slot.
    for _ in 0..2 {
        assert!(
            tokio::time::timeout(Duration::from_millis(20), shutdown.shutdown())
                .await
                .is_err()
        );
        assert!(queue.try_lock().is_err());
    }
    assert!(matches!(
        keeper
            .account_host(
                HostRequest::TuneWaiting {
                    expected_revision: 0,
                    seconds: 1100
                },
                ()
            )
            .await,
        Err(Error::Storage)
    ));
    assert_eq!(samples.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), shutdown.shutdown())
        .await
        .unwrap()
        .unwrap();
    // Work may already have affected durable clock/state. The fenced result is
    // uncertainty, never a false known-nonexecution response or success bytes.
    assert!(matches!(task.await.unwrap(), Err(Error::Storage)));
    assert!(queue.try_lock().is_ok());
    let completed_samples = samples.load(Ordering::SeqCst);
    assert!(matches!(
        keeper
            .account_host(
                HostRequest::TuneWaiting {
                    expected_revision: 0,
                    seconds: 1100
                },
                ()
            )
            .await,
        Err(Error::Storage)
    ));
    assert_eq!(samples.load(Ordering::SeqCst), completed_samples);
    // Every later host waiter sees the actual same completed join.
    shutdown.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn generic_service_shutdown_drains_without_claiming_native_preemption() {
    let dir = tempfile::tempdir().unwrap();
    let keeper = memory("garden")
        .with_account_service(service(dir.path().join("generic-drain"), "garden", || 1100).await)
        .await
        .unwrap();
    let shutdown = keeper.account_shutdown().unwrap();
    shutdown.shutdown().await.unwrap();
    assert!(matches!(
        keeper
            .account_host(
                HostRequest::TuneWaiting {
                    expected_revision: 0,
                    seconds: 1100
                },
                ()
            )
            .await,
        Err(Error::Storage)
    ));
    shutdown.clone().shutdown().await.unwrap();
}
