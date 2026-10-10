//! Payment facts cross the gate boundary without retaining provider data.
mod common;
use cgts::*;
use common::*;
use cpmt::payments as p;
use std::sync::Arc;

struct Provider;
impl p::Adapter for Provider {
    fn mode(&self) -> cpmt::cost::Mode {
        cpmt::cost::Mode::Production
    }
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
        dispatch: &cpmt::cost::Dispatch<'_>,
        _: &str,
        _: Option<&p::Private>,
    ) -> p::Result<p::Observation> {
        dispatch.check("local", cpmt::cost::Mode::Production)?;
        Ok(p::Observation {
            satisfies_terms: true,
            claim: Some(p::Private::new(b"private-receipt".to_vec())),
            ..p::Observation::fact(p::State::Collected)
        })
    }
    async fn observe(
        &self,
        _: &cpmt::cost::Dispatch<'_>,
        _: Option<&p::Private>,
    ) -> p::Result<p::Observation> {
        Err(p::Error::Unsupported)
    }
}
async fn operation() -> (p::Payments<p::MemoryJournal>, p::Instruction, p::Outcome) {
    let mut payments =
        p::Payments::new(p::MemoryJournal::default(), [7; 32], Arc::new(|| 1100)).unwrap();
    payments.register(Arc::new(Provider)).unwrap();
    let request = p::Instruction {
        id: [1; 32],
        kind: p::Action::Execute,
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
    let outcome = payments
        .dispatch(&request, permit(&payments, &request), 1100)
        .await
        .unwrap()
        .outcome;
    (payments, request, outcome)
}
async fn evidence(until: u64) -> p::Evidence {
    let (_, request, outcome) = operation().await;
    outcome
        .evidence(&request.binding, p::State::Collected, 1100, until)
        .unwrap()
}
async fn access(start: u64, end: u64) -> cpmt::access::PaidAccess {
    let (payments, instruction, outcome) = operation().await;
    payments
        .paid_access(
            &instruction,
            &outcome,
            cpmt::access::Request {
                level: "gold".into(),
                period: cpmt::access::Period { start, end },
                requires: p::State::Collected,
            },
            1100,
        )
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

fn permit(
    payments: &p::Payments<p::MemoryJournal>,
    request: &p::Instruction,
) -> cpmt::cost::DispatchPermit<String> {
    use cpmt::cost::*;
    let amount = Amount {
        unit: Unit {
            code: "inert-fixture-fee".into(),
            scale: 0,
        },
        atoms: 0,
    };
    let quote = payments
        .preview(
            request,
            Price::Exact(amount.clone()),
            "inert fixture; no provider I/O".into(),
            2000,
        )
        .unwrap();
    Plan::new(
        vec![Offer {
            candidate: Candidate::new("local".into(), ["collect".to_string()]),
            quote,
        }],
        Config::new(["local".into()], ["collect".to_string()]),
        CostOrder::Configured,
        amount,
        1,
        Mode::Production,
        1100,
    )
    .unwrap()
    .start()
    .begin(1100)
    .unwrap()
}

#[tokio::test]
async fn paid_access_handoff_checks_level_and_period_without_financial_data() {
    let gate =
        payments::PaidAccessGate::new("cpmt".into(), "local".into(), "gold".into(), true).unwrap();
    let snapshot = snapshot("garden", "cpmt");
    let context = context(&snapshot);
    assert_eq!(gate.descriptor().steps[0].input, "cpmt.PaidAccess");
    let keeper = memory("garden");
    let short = access(1100, 1200).await;
    assert!(matches!(
        keeper.run(context, &gate, &short).await,
        Err(Error::Invalid)
    ));
    // Retained facts use the existing UTC-day boundary; refusal above must not
    // consume the receipt before a valid retained projection is supplied.
    let access = access(1100, 172800).await;
    let checked = keeper.run(context, &gate, &access).await.unwrap();
    assert_eq!(
        serde_json::to_value(checked.result()).unwrap(),
        serde_json::json!({"gate":"cpmt","level":"community","subject":"alice","provider":"local","valid_until":172800})
    );
    assert!(keeper.run(context, &gate, &access).await.is_err());
    for now in [-1, 1099, 172800] {
        assert!(
            gate.verify(Context { now, ..context }, &access)
                .await
                .is_err()
        );
    }
    let different =
        payments::PaidAccessGate::new("cpmt".into(), "local".into(), "platinum".into(), false)
            .unwrap();
    assert!(different.verify(context, &access).await.is_err());
    assert!(payments::PaidAccessGate::new("cpmt".into(), "local".into(), "".into(), true).is_err());
    assert!(payments::PaidAccessGate::new("".into(), "local".into(), "gold".into(), true).is_err());
}
