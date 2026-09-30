//! Real issuer signatures and fail-closed balance-leaf integration.
mod common;
use cblc::{accounting::*, extensions::*};
use cgts::*;
use common::*;
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};

fn extension_policy() -> ExtensionPolicy {
    ExtensionPolicy {
        revision: 1,
        public_record_quorum: 5,
        change_token_cost: 1,
        deposit_delay_seconds: 60,
        minimum_deposit_batch: 2,
    }
}
fn scope() -> AccountProofScope {
    AccountProofScope {
        circuit_digest: [51; 32],
        verifying_key_digest: [52; 32],
    }
}
fn gate<'a>(policy: &'a ExtensionPolicy) -> gates::BalanceGate<'a> {
    gates::BalanceGate {
        provider: "local",
        community: "garden",
        subject: "alice",
        action: "enter",
        accounting_community: [1; 32],
        owner: [2; 32],
        binding: [3; 32],
        operator_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        proof_scope: scope(),
        policy,
    }
}

// A real signed issuer assertion at cgts's documented relying-party boundary.
// This does not claim to generate or test the outstanding extension ZK circuit.
fn spend() -> gates::ChangeSpend {
    let policy = AccountPolicy {
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
    };
    let device = SigningKey::from_bytes(&[8; 32]);
    let mut request = AccountRequest {
        statement: AccountStatement {
            protocol_version: 2,
            community: [1; 32],
            owner: [2; 32],
            policy_digest: policy.digest(&[1; 32]).unwrap(),
            enrollment_root: [1; 32],
            now: 1050,
            valid_until: policy.proof_valid_until(1050).unwrap(),
            genesis: false,
            previous_version: 0,
            next_version: 1,
            previous_state: [2; 32],
            next_state: [3; 32],
            settlement_marker: [4; 32],
            policy,
        },
        request_id: [5; 32],
        proof_scope: scope(),
        chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
        issued_at: 1050,
        expires_at: 1500,
        proof: vec![1, 2, 3],
        signature: String::new(),
    };
    request.signature = B64.encode(
        &device
            .sign(&account_request_bytes(&request).unwrap())
            .to_bytes(),
    );
    let update = ExtendedUpdate {
        previous_inbox: Inbox::default(),
        inbox: Inbox::default(),
        effect: Effect::Change { binding: [3; 32] },
    };
    let mut acceptance = AccountAcceptance {
        statement: request.statement.clone(),
        request_id: request.request_id,
        request_digest: extended_request_digest(&request, &update, &extension_policy()).unwrap(),
        proof_scope: scope(),
        accepted_at: 1060,
        signature: String::new(),
    };
    acceptance.signature = B64.encode(
        &SigningKey::from_bytes(&[9; 32])
            .sign(&account_acceptance_bytes(&acceptance).unwrap())
            .to_bytes(),
    );
    gates::ChangeSpend {
        request,
        acceptance,
        update,
    }
}

#[tokio::test]
async fn signed_acceptance_alone_cannot_enable_the_unproven_extension() {
    let policy = extension_policy();
    let snapshot = snapshot("garden", "cblc");
    let keeper = memory("garden");
    assert!(matches!(
        gate(&policy).verify(context(&snapshot), &spend()).await,
        Err(Error::ExtensionsUnavailable)
    ));
    assert!(matches!(
        keeper
            .run(context(&snapshot), &gate(&policy), &spend())
            .await,
        Err(Error::ExtensionsUnavailable)
    ));
    assert!(keeper.collect(context(&snapshot)).await.unwrap().is_empty());
}

#[tokio::test]
async fn wrong_effect_subject_owner_scope_binding_expiry_and_signature_fail() {
    let keeper = memory("garden");
    let snapshot = snapshot("garden", "cblc");
    let policy = extension_policy();
    let mut gate = gate(&policy);
    let input = spend();
    assert!(matches!(
        keeper
            .run(
                Context {
                    subject: "bob",
                    ..context(&snapshot)
                },
                &gate,
                &input
            )
            .await,
        Err(Error::ExtensionsUnavailable)
    ));
    assert!(matches!(
        keeper
            .run(
                Context {
                    action: "other",
                    ..context(&snapshot)
                },
                &gate,
                &input
            )
            .await,
        Err(Error::ExtensionsUnavailable)
    ));
    assert!(matches!(
        keeper
            .run(
                Context {
                    now: 1500,
                    ..context(&snapshot)
                },
                &gate,
                &input
            )
            .await,
        Err(Error::ExtensionsUnavailable)
    ));
    gate.binding = [6; 32];
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    gate.binding = [3; 32];
    gate.owner = [7; 32];
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    gate.owner = [2; 32];
    gate.proof_scope.circuit_digest = [8; 32];
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    gate.proof_scope = scope();
    for effect in [Effect::Update, Effect::Change { binding: [0; 32] }] {
        let mut invalid = spend();
        invalid.update.effect = effect;
        assert!(matches!(
            keeper.run(context(&snapshot), &gate, &invalid).await,
            Err(Error::ExtensionsUnavailable)
        ));
    }
    let mut invalid = spend();
    invalid.acceptance.signature = B64.encode(&[0; 64]);
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &invalid).await,
        Err(Error::ExtensionsUnavailable)
    ));
    invalid = spend();
    invalid.request.proof[0] ^= 1;
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &invalid).await,
        Err(Error::ExtensionsUnavailable)
    ));
    // Even a signed issuer assertion cannot activate an unproven circuit.
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
}

#[tokio::test]
async fn record_gate_refuses_without_the_complete_extension_relation() {
    use cblc::accounting_ledger::{AccountLedger, AccountLedgerPolicy};
    use cblc::accounting_service::{ProcessAccountVerifier, ProcessVerifierConfig};
    use std::sync::{Arc, Mutex};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record-ledger.db");
    let ledger = tokio::task::spawn_blocking(move || {
        // The real process adapter is not invoked: a legacy ledger must refuse
        // record proofs before any worker could treat them as ordinary v2 proofs.
        let verifier = ProcessAccountVerifier::new(ProcessVerifierConfig {
            node: "/unconfigured/node".into(),
            script: "/unconfigured/worker.mjs".into(),
            artifact_config: "/unconfigured/artifacts.json".into(),
            scope: scope(),
            timeout: std::time::Duration::from_secs(1),
            maximum_parallel: 1,
            max_proof_bytes: 1024,
            node_heap_megabytes: 64,
        })
        .unwrap();
        AccountLedger::open(
            path,
            cblc::admission::AdmissionTrust {
                community_id: "garden".into(),
                policy_digest: B64.encode(&[1; 32]),
                issuer_public_key: SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
            },
            AccountLedgerPolicy {
                account: spend().request.statement.policy,
                max_authorization_seconds: 100,
                max_proof_bytes: 1024,
                checkpoint_period_seconds: 1000,
            },
            verifier,
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap()
    })
    .await
    .unwrap();
    let mut gate = gates::RecordGate {
        provider: "local",
        community: "garden",
        subject: "alice",
        action: "enter",
        owner: [2; 32],
        expected: RecordContext {
            purpose: RecordUse::ForumListing,
            challenge: [1; 32],
            expires_at: 1150,
        },
        ledger: Arc::new(Mutex::new(ledger)),
        clock: Arc::new(Clock),
    };
    let snapshot = snapshot("garden", "cblc");
    let keeper = memory("garden");
    let mut input = gates::RecordProof {
        record: PublicRecord {
            context: gate.expected.clone(),
            community: [1; 32],
            owner: [2; 32],
            version: 1,
            state: [3; 32],
            inbox: Inbox::default(),
            shares: None,
        },
        proof: vec![1, 2, 3],
    };
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    input.record.context.purpose = RecordUse::FirstContact;
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    input.proof.clear();
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    gate.subject = "bob";
    assert!(matches!(
        keeper.run(context(&snapshot), &gate, &input).await,
        Err(Error::ExtensionsUnavailable)
    ));
    assert!(keeper.collect(context(&snapshot)).await.unwrap().is_empty());
    // The standalone leaf owns a runtime: its final drop, like construction,
    // belongs outside async execution. Services normally retain the shared ledger.
    tokio::task::spawn_blocking(move || drop(gate))
        .await
        .unwrap();
}

#[test]
fn pin_spend_uses_the_leaf_binding_and_stays_disabled_for_every_transition() {
    use cpns::{
        Fingerprint,
        server::{Change, Pin},
    };
    let member = "01".repeat(48);
    let other = "02".repeat(48);
    let base = Change {
        community: "garden",
        member: &member,
        field: "age",
        expected: Pin {
            fingerprint: Fingerprint::from_bytes([1; 32]),
            revision: 1,
        },
        replacement: Fingerprint::from_bytes([2; 32]),
    };
    let binding = pins::change_binding(&base).unwrap();
    assert_eq!(binding, cblc::pins::change_binding(&base).unwrap());
    for change in [
        Change {
            community: "other",
            ..base
        },
        Change {
            member: &other,
            ..base
        },
        Change {
            field: "other",
            ..base
        },
        Change {
            expected: Pin {
                revision: 2,
                ..base.expected
            },
            ..base
        },
        Change {
            expected: Pin {
                fingerprint: Fingerprint::from_bytes([3; 32]),
                ..base.expected
            },
            ..base
        },
        Change {
            replacement: Fingerprint::from_bytes([4; 32]),
            ..base
        },
    ] {
        assert_ne!(pins::change_binding(&change).unwrap(), binding);
        assert!(matches!(
            pins::verify_pin_change(&change, &spend()),
            Err(Error::ExtensionsUnavailable)
        ));
    }
    assert!(matches!(
        pins::verify_pin_change(&base, &spend()),
        Err(Error::ExtensionsUnavailable)
    ));
}
