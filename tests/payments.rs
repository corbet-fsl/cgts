//! Payment facts cross the gate boundary without retaining provider data.
mod common;
use cgts::*;
use common::*;
use cpmt::payments as p;
use std::sync::Arc;

struct Provider;
impl p::Adapter for Provider {
    fn max_input_bytes(&self) -> usize {
        16384
    }
    fn capabilities(&self) -> p::Capabilities {
        p::Capabilities {
            id: "local".into(),
            operations: vec!["collect".into()],
        }
    }
    async fn execute(
        &self,
        _: &p::Instruction,
        _: &str,
        _: Option<&p::Private>,
    ) -> p::Result<p::Observation> {
        Ok(p::Observation {
            claim: Some(p::Private::new(b"private-receipt".to_vec())),
            ..p::Observation::fact(p::State::Collected)
        })
    }
    async fn observe(&self, _: &str, _: Option<&p::Private>) -> p::Result<p::Observation> {
        Err(p::Error::Unsupported)
    }
}
async fn evidence(until: u64) -> p::Evidence {
    let mut payments = p::Payments::new(p::MemoryJournal::default(), [7; 32]).unwrap();
    payments.register(Arc::new(Provider)).unwrap();
    let request = p::Instruction {
        id: [1; 32],
        parent: None,
        adapter: "local".into(),
        operation: "collect".into(),
        binding: p::Binding {
            scope: "garden".into(),
            subject: "alice".into(),
            action: "enter".into(),
        },
        expires_at: 2000,
        terms: p::Private::new(vec![]),
        evidence: p::Private::new(b"private-wallet".to_vec()),
    };
    payments
        .execute(&request, 1100)
        .await
        .unwrap()
        .outcome
        .evidence(&request.binding, p::State::Collected, 1100, until)
        .unwrap()
}

async fn roundtrip<S: Storage, L: LegalVeto>(keeper: Gatekeeper<S, L>) {
    let gate = payments::PaymentGate::new("crpt".into(), "local".into(), true).unwrap();
    let snapshot = snapshot("garden", "crpt");
    let context = context(&snapshot);
    let evidence = evidence(172800).await;
    assert_eq!(
        keeper
            .steps(context, &[gate.descriptor()])
            .await
            .unwrap()
            .len(),
        1
    );
    let checked = keeper.run(context, &gate, &evidence).await.unwrap();
    let json = serde_json::to_value(checked.result()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"gate":"crpt","level":"community","subject":"alice","provider":"local","valid_until":172800})
    );
    assert!(matches!(
        keeper.run(context, &gate, &evidence).await,
        Err(Error::Refused)
    ));
    assert_eq!(keeper.collect(context).await.unwrap().len(), 1);
}

#[tokio::test]
async fn payment_receipt_and_minimal_gate_result_commit_once_in_memory_and_libsql() {
    roundtrip(memory("garden")).await;
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("gates.db")).await;
    roundtrip(sql(&db, "garden")).await;
}

#[tokio::test]
async fn transient_payments_and_context_expiry_checks_use_the_existing_gate_contract() {
    let snapshot = snapshot("garden", "cpmt");
    let context = context(&snapshot);
    let gate = payments::PaymentGate::new("cpmt".into(), "local".into(), false).unwrap();
    let proof = evidence(1200).await;
    let keeper = memory("garden");
    keeper.run(context, &gate, &proof).await.unwrap();
    assert!(keeper.collect(context).await.unwrap().is_empty());
    for context in [
        Context {
            subject: "bob",
            ..context
        },
        Context {
            action: "other",
            ..context
        },
        Context {
            now: 1200,
            ..context
        },
        Context { now: -1, ..context },
    ] {
        assert!(gate.verify(context, &proof).await.is_err());
    }
    assert!(payments::PaymentGate::new("bad/gate".into(), "local".into(), false).is_err());
    assert!(payments::PaymentGate::new("cpmt".into(), "".into(), false).is_err());
    let other = payments::PaymentGate::new("cpmt".into(), "other".into(), false).unwrap();
    assert!(other.verify(context, &proof).await.is_err());
    assert!(
        gate.verify(context, &evidence(u64::MAX).await)
            .await
            .is_err()
    );
}
