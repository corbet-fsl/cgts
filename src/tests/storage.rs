use super::*;

#[tokio::test]
async fn a_real_poisoned_mutex_refuses_every_storage_operation() {
    let store = MemoryStore::new("garden").unwrap();
    let shared = store.clone();
    let failure = std::thread::spawn(move || {
        let _guard = shared.state.lock().unwrap();
        panic!("interrupt an actual memory-store writer");
    })
    .join();
    assert!(failure.is_err());
    assert_eq!(store.load("alice").await, Err(Error::Storage));
    assert_eq!(store.commit(None, None).await, Err(Error::Storage));
    assert_eq!(
        store.remove("alice", "cvch", "local").await,
        Err(Error::Storage)
    );
}

#[derive(Clone)]
struct SignedAuthority(ed25519_dalek::VerifyingKey);

impl clbs::Verifier for SignedAuthority {
    async fn verify_legal(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
        let signature =
            ed25519_dalek::Signature::from_slice(&order.proof).map_err(|_| clbs::Error::Denied)?;
        self.0
            .verify_strict(&order.order.signing_payload()?, &signature)
            .map_err(|_| clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
        self.verify_legal(order).await
    }
}

#[tokio::test]
async fn corrupted_real_memory_results_never_cross_subject_or_level() {
    let store = MemoryStore::new("garden").unwrap();
    let fact = GateResult {
        gate: "phone".into(),
        level: GateLevel::Community,
        subject: "alice".into(),
        provider: "local".into(),
        valid_until: 86400,
    };
    store.commit(Some(&fact), None).await.unwrap();
    let keeper = Gatekeeper::new(
        store.clone(),
        LegalGate::new(
            clbs::MemoryStore::new("garden").unwrap(),
            SignedAuthority(ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key()),
        ),
    )
    .unwrap();
    let snapshot = Snapshot {
        community: "garden".into(),
        kind: crbk::SnapshotKind::Settings,
        revision: 1,
        policy_epoch: 2,
        issued: 100,
        content: Default::default(),
    };
    let context = Context {
        snapshot: &snapshot,
        subject: "alice",
        action: "enter",
        now: 1100,
    };
    assert!(keeper.collect(context).await.unwrap().is_empty());
    // Inject corruption into the actual retained state after its real commit.
    // The concrete store and orchestration still perform their normal reads.
    for changed in [
        GateResult {
            subject: "bob".into(),
            ..fact.clone()
        },
        GateResult {
            level: GateLevel::Global,
            ..fact.clone()
        },
    ] {
        *store
            .state
            .lock()
            .unwrap()
            .results
            .values_mut()
            .next()
            .unwrap() = changed;
        assert_eq!(keeper.collect(context).await, Err(Error::Storage));
    }
    *store
        .state
        .lock()
        .unwrap()
        .results
        .values_mut()
        .next()
        .unwrap() = fact;
    assert!(keeper.collect(context).await.unwrap().is_empty());
}
