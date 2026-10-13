//! Signed voucher, rulebook and mandatory legal-veto integration tests.
mod common;
use cgts::*;
use common::*;

async fn round_trip<S: Storage, L: LegalVeto>(keeper: Gatekeeper<S, L>) {
    assert_eq!(keeper.community(), "garden");
    let snapshot = snapshot("garden", "cvch");
    let context = context(&snapshot);
    assert!(keeper.collect(context).await.unwrap().is_empty());
    assert!(
        !keeper
            .decide(context, MembershipState::Pending, &[])
            .await
            .unwrap()
            .allowed
    );
    let checked = keeper
        .run(context, &gate(), &voucher("garden", "one", 2000))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(checked.result()).unwrap(),
        serde_json::json!({
            "gate":"cvch", "level":"community", "subject":"alice", "provider":"local", "valid_until":2592000
        })
    );
    assert!(
        keeper
            .decide(context, MembershipState::Pending, &[checked])
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(keeper.collect(context).await.unwrap().len(), 1);
    assert!(
        keeper
            .decide(context, MembershipState::Pending, &[])
            .await
            .unwrap()
            .allowed
    );
    assert!(matches!(
        keeper
            .run(context, &gate(), &voucher("garden", "one", 2000))
            .await,
        Err(Error::Refused)
    ));
    assert!(matches!(
        keeper
            .run(
                Context {
                    subject: "bob",
                    ..context
                },
                &gate(),
                &voucher("garden", "one", 2000)
            )
            .await,
        Err(Error::Refused)
    ));
    assert!(
        keeper
            .collect(Context {
                subject: "bob",
                ..context
            })
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        keeper
            .collect(Context {
                now: 2_592_000,
                ..context
            })
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !keeper
            .decide(
                Context {
                    now: 2_592_000,
                    ..context
                },
                MembershipState::Pending,
                &[]
            )
            .await
            .unwrap()
            .allowed
    );
    keeper
        .run(context, &gate(), &voucher("garden", "renewal", 3000))
        .await
        .unwrap();
    let current = keeper.collect(context).await.unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].valid_until, 2_592_000);
    keeper.withdraw("alice", "cvch", "local").await.unwrap();
    assert!(keeper.collect(context).await.unwrap().is_empty());
    assert!(matches!(
        keeper
            .run(context, &gate(), &voucher("garden", "renewal", 3000))
            .await,
        Err(Error::Refused)
    ));
}

#[tokio::test]
async fn memory_round_trip() {
    round_trip(memory("garden")).await;
}
#[tokio::test]
async fn libsql_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("gates.db")).await;
    round_trip(sql(&db, "garden")).await;
}

#[tokio::test]
async fn switches_hide_steps_and_prevent_execution_without_burning() {
    let keeper = memory("garden");
    let gate = gate();
    let descriptor = gate.descriptor();
    let mut snapshot = snapshot("garden", "cvch");
    for key in [
        crbk::gate_key(GateLevel::Community, "cvch"),
        crbk::provider_key(GateLevel::Community, "cvch", "local"),
    ] {
        for value in [None, Some(serde_json::Value::Null), Some(false.into())] {
            let old = snapshot.content.remove(&key).unwrap();
            if let Some(value) = value {
                snapshot.content.insert(key.clone(), value);
            }
            let context = context(&snapshot);
            assert!(
                keeper
                    .steps(context, std::slice::from_ref(&descriptor))
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                keeper
                    .run(context, &gate, &voucher("garden", "disabled", 2000))
                    .await,
                Err(Error::Disabled)
            ));
            snapshot.content.insert(key.clone(), old);
        }
    }
    assert_eq!(
        keeper
            .steps(context(&snapshot), &[descriptor])
            .await
            .unwrap()
            .len(),
        1
    );
    keeper
        .run(
            context(&snapshot),
            &gate,
            &voucher("garden", "disabled", 2000),
        )
        .await
        .unwrap();
    snapshot.content.insert(
        crbk::provider_key(GateLevel::Community, "cvch", "local"),
        false.into(),
    );
    assert!(keeper.collect(context(&snapshot)).await.unwrap().is_empty());
}

#[tokio::test]
async fn forged_expired_cross_community_and_untrusted_contexts_fail() {
    let keeper = memory("garden");
    let mut snapshot = snapshot("garden", "cvch");
    let input = voucher("garden", "not-burned", 2000);
    let mut forged = input.clone();
    forged.secret.replace_range(
        ..1,
        if forged.secret.starts_with('0') {
            "1"
        } else {
            "0"
        },
    );
    for input in [
        forged,
        voucher("elsewhere", "not-burned", 2000),
        voucher("garden", "expired", 1100),
        cvch::link::Request::new(
            &cvch::link::Token::from_entropy([9; 32]).unwrap(),
            &[1; cvch::link::NONCE_BYTES],
        ),
    ] {
        assert!(matches!(
            keeper.run(context(&snapshot), &gate(), &input).await,
            Err(Error::Refused)
        ));
    }
    for bad in [
        Context {
            now: -1,
            ..context(&snapshot)
        },
        Context {
            subject: "",
            ..context(&snapshot)
        },
    ] {
        assert!(matches!(keeper.collect(bad).await, Err(Error::Invalid)));
    }
    snapshot.issued = 1101;
    assert!(matches!(
        keeper.collect(context(&snapshot)).await,
        Err(Error::Invalid)
    ));
    snapshot.issued = 100;
    snapshot.community = "elsewhere".into();
    assert!(matches!(
        keeper.collect(context(&snapshot)).await,
        Err(Error::Scope)
    ));
    snapshot.community = "garden".into();
    keeper
        .run(context(&snapshot), &gate(), &input)
        .await
        .unwrap();
    assert!(
        gates::VoucherGate::new(
            "alias/provider",
            std::sync::Arc::new(cvch::link::MemoryLinks::default()),
            std::sync::Arc::new(cvch::link::MemoryAllowance::default()),
            std::sync::Arc::new(|_| false),
        )
        .is_err()
    );
}

#[tokio::test]
async fn missing_age_metadata_and_wrong_action_bindings_fail_closed() {
    let keeper = memory("garden");
    let mut snapshot = snapshot("garden", "cvch");
    let checked = keeper
        .run(context(&snapshot), &gate(), &voucher("garden", "one", 2000))
        .await
        .unwrap();
    let mut policy: crbk::ActionPolicy =
        serde_json::from_value(snapshot.content[&crbk::action_key("enter")].clone()).unwrap();
    policy.maximum_proof_age = Some(1000);
    snapshot.content.insert(
        crbk::action_key("enter"),
        serde_json::to_value(policy).unwrap(),
    );
    assert!(
        !keeper
            .decide(context(&snapshot), MembershipState::Pending, &[])
            .await
            .unwrap()
            .allowed
    );
    let wrong = Context {
        action: "edit",
        ..context(&snapshot)
    };
    assert!(matches!(
        keeper
            .decide(wrong, MembershipState::Pending, &[checked])
            .await,
        Err(Error::Scope)
    ));
}

#[tokio::test]
async fn real_legal_order_cannot_be_bypassed_by_switch_or_empty_policy() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("legal.db")).await;
    let keeper = sql(&db, "garden");
    let legal = clbs::Gate::new(
        clbs::LibsqlStore::new(&db, "garden").unwrap(),
        Authority,
        Clock,
    );
    let mut snapshot = snapshot("garden", "cvch");
    snapshot.content.insert(
        crbk::action_key("enter"),
        serde_json::to_value(crbk::ActionPolicy::default()).unwrap(),
    );
    snapshot
        .content
        .insert(crbk::gate_key(GateLevel::Community, "clbs"), false.into());
    assert!(
        keeper
            .decide(context(&snapshot), MembershipState::Pending, &[])
            .await
            .unwrap()
            .allowed
    );
    legal.record_legal(&order("garden")).await.unwrap();
    let verdict = keeper
        .decide(context(&snapshot), MembershipState::Pending, &[])
        .await
        .unwrap();
    assert!(!verdict.allowed && verdict.legal_veto);
    assert!(matches!(
        keeper
            .run(context(&snapshot), &gate(), &voucher("garden", "one", 2000))
            .await,
        Err(Error::Vetoed)
    ));
    assert!(
        keeper
            .steps(
                Context {
                    action: "edit",
                    ..context(&snapshot)
                },
                &[gate().descriptor()]
            )
            .await
            .is_ok()
    );
    assert!(
        keeper
            .decide(
                Context {
                    now: 1200,
                    ..context(&snapshot)
                },
                MembershipState::Pending,
                &[]
            )
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn mismatched_community_capabilities_are_rejected() {
    assert!(matches!(
        Gatekeeper::new(
            MemoryStore::new("a").unwrap(),
            LegalGate::new(clbs::MemoryStore::new("b").unwrap(), Authority)
        ),
        Err(Error::Scope)
    ));
}

#[tokio::test]
async fn checked_collection_rejects_other_action_time_revision_epoch_and_subject() {
    let keeper = memory("garden");
    let original = snapshot("garden", "cvch");
    let ctx = context(&original);
    let checked = keeper.check(ctx, Vec::new()).await.unwrap();
    assert!(checked.in_context(ctx).unwrap().is_empty());
    for changed in [
        Context {
            action: "other",
            ..ctx
        },
        Context {
            now: ctx.now + 1,
            ..ctx
        },
        Context {
            subject: "bob",
            ..ctx
        },
    ] {
        assert!(matches!(checked.in_context(changed), Err(Error::Scope)));
    }
    let mut other = original.clone();
    other.revision += 1;
    assert!(
        checked
            .in_context(Context {
                snapshot: &other,
                ..ctx
            })
            .is_err()
    );
    other = original.clone();
    other.policy_epoch += 1;
    assert!(
        checked
            .in_context(Context {
                snapshot: &other,
                ..ctx
            })
            .is_err()
    );
}

#[test]
fn gate_result_debug_does_not_expose_the_subject() {
    let result = GateResult {
        gate: "cvch".into(),
        level: GateLevel::Community,
        subject: "private-member".into(),
        provider: "local".into(),
        valid_until: 2000,
    };
    assert_eq!(format!("{result:?}"), "GateResult { .. }");
}

#[tokio::test]
async fn voucher_link_admits_its_first_bearer_and_uses_coarse_policy_validity() {
    let keeper = memory("garden");
    let mut snapshot = snapshot("garden", "cvch");
    snapshot
        .content
        .insert(gates::VOUCHER_VALIDITY_DAYS.into(), 14.into());
    let input = voucher("garden", "bound", 1200);
    let checked = keeper
        .run(context(&snapshot), &gate(), &input)
        .await
        .unwrap();
    assert_eq!(checked.result().valid_until, 14 * 86400);
    assert!(matches!(
        keeper
            .run(
                Context {
                    subject: "latecomer",
                    ..context(&snapshot)
                },
                &gate(),
                &input
            )
            .await,
        Err(Error::Refused)
    ));
    assert_eq!(
        keeper
            .collect(Context {
                now: 1200,
                ..context(&snapshot)
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn sign_off_waits_then_admits_once_and_decline_spends_nothing() {
    let keeper = memory("garden");
    let snapshot = snapshot("garden", "cvch");
    let (input, id) = signoff_voucher("garden", "multi");
    let waiting = Context {
        subject: "alice",
        ..context(&snapshot)
    };
    assert_eq!(
        keeper.run(waiting, &gate(), &input).await.err(),
        Some(Error::Pending)
    );
    assert!(keeper.collect(waiting).await.unwrap().is_empty());
    // A second presentation while waiting changes nothing.
    assert_eq!(
        keeper.run(waiting, &gate(), &input).await.err(),
        Some(Error::Pending)
    );
    let decision = |member: &'static str, confirm: bool| {
        let id = id.clone();
        block_on(async move {
            let vouching = cvch::link::Vouching {
                store: &**links(),
                allowance: &**allowance(),
            };
            vouching.decide(&id, "sponsor", member, confirm).await
        })
    };
    assert_eq!(decision("alice", true), Ok(true));
    keeper.run(waiting, &gate(), &input).await.unwrap();
    assert_eq!(keeper.collect(waiting).await.unwrap().len(), 1);
    // Once proven, the same person cannot be proven again from the same link.
    assert!(matches!(
        keeper.run(waiting, &gate(), &input).await,
        Err(Error::Refused)
    ));
    let bob = Context {
        subject: "bob",
        ..context(&snapshot)
    };
    assert_eq!(
        keeper.run(bob, &gate(), &input).await.err(),
        Some(Error::Pending)
    );
    assert_eq!(decision("bob", false), Ok(false));
    assert!(matches!(
        keeper.run(bob, &gate(), &input).await,
        Err(Error::Pending)
    ));
}

#[tokio::test]
async fn checked_evidence_cannot_hide_changed_settings_behind_the_same_revision() {
    let actual = snapshot("garden", "cvch");
    let mut altered = actual.clone();
    altered
        .content
        .insert(gates::VOUCHER_VALIDITY_DAYS.into(), 365.into());
    let keeper = memory("garden");
    let receipt = keeper
        .run(
            context(&altered),
            &gate(),
            &voucher("garden", "altered-policy", 2000),
        )
        .await
        .unwrap();
    assert_eq!(receipt.in_context(context(&actual)), Err(Error::Scope));
    let mut altered_time = altered.clone();
    altered_time.issued -= 1;
    assert_eq!(
        receipt.in_context(context(&altered_time)),
        Err(Error::Scope)
    );
}

#[tokio::test]
async fn every_retained_provider_expiry_is_rounded_down_to_a_day() {
    // A host adapter over real signed voucher verification: its retained lifetime
    // is the authenticated redemption deadline, so the facade must round it.
    struct SignedDeadline(GateLevel, i64);
    impl Gate for SignedDeadline {
        type Input = cvch::link::Request;
        fn descriptor(&self) -> Descriptor {
            Descriptor {
                level: self.0,
                ..gate().descriptor()
            }
        }
        async fn verify(&self, context: Context<'_>, input: &cvch::link::Request) -> Result<Proof> {
            gate().verify(context, input).await?;
            Ok(Proof::retained(self.1))
        }
    }
    let keeper = memory("garden");
    let snapshot = snapshot("garden", "cvch");
    let context = Context {
        now: 86401,
        ..context(&snapshot)
    };
    let provider = SignedDeadline(GateLevel::Community, 172923);
    let late = SignedDeadline(GateLevel::Community, 86402);
    let accepted = voucher("garden", "deadline", 172923);
    let checked = keeper.run(context, &provider, &accepted).await.unwrap();
    assert_eq!(checked.result().valid_until, 172800);
    assert_eq!(
        keeper.collect(context).await.unwrap()[0].valid_until,
        172800
    );
    // Authentic unexpired evidence can still have a coarse deadline in the past.
    let short = voucher("garden", "short-deadline", 86402);
    assert!(matches!(
        keeper.run(context, &late, &short).await,
        Err(Error::Refused)
    ));
    assert_eq!(
        keeper.collect(context).await.unwrap()[0].valid_until,
        172800
    );
    assert!(matches!(
        keeper
            .run(
                context,
                &SignedDeadline(GateLevel::Global, 172923),
                &accepted
            )
            .await,
        Err(Error::Scope)
    ));
    assert!(matches!(
        keeper.check(context, vec![checked.clone(), checked]).await,
        Err(Error::Scope)
    ));
}

#[tokio::test]
async fn registered_metadata_and_snapshot_bounds_are_checked_before_execution() {
    let keeper = memory("garden");
    let original = snapshot("garden", "cvch");
    for steps in [vec![], vec![gate().descriptor().steps[0].clone(); 33]] {
        let descriptor = Descriptor {
            steps,
            ..gate().descriptor()
        };
        assert!(matches!(
            keeper.steps(context(&original), &[descriptor]).await,
            Err(Error::Invalid)
        ));
    }
    let mut descriptor = gate().descriptor();
    descriptor.level = GateLevel::Global;
    assert!(
        keeper
            .steps(context(&original), &[descriptor])
            .await
            .unwrap()
            .is_empty()
    );
    for (issued, revision) in [(-1, 1), (100, 0)] {
        let mut snapshot = original.clone();
        snapshot.issued = issued;
        snapshot.revision = revision;
        assert!(matches!(
            keeper.collect(context(&snapshot)).await,
            Err(Error::Invalid)
        ));
    }
    for value in [
        serde_json::Value::Null,
        "thirty".into(),
        0.into(),
        366.into(),
    ] {
        let mut snapshot = original.clone();
        snapshot
            .content
            .insert(gates::VOUCHER_VALIDITY_DAYS.into(), value);
        assert!(matches!(
            keeper
                .run(
                    context(&snapshot),
                    &gate(),
                    &voucher("garden", "valid-policy", 2000)
                )
                .await,
            Err(Error::Policy)
        ));
    }
    keeper
        .run(
            context(&original),
            &gate(),
            &voucher("garden", "valid-policy", 2000),
        )
        .await
        .unwrap();
}

#[test]
fn voucher_catalogue_definition_is_idempotent_and_keeps_host_configuration() {
    let mut book = crbk::Rulebook::default();
    gates::define_settings(&mut book).unwrap();
    let first = book.catalog().clone();
    gates::define_settings(&mut book).unwrap();
    assert_eq!(book.catalog(), &first);
    let mut configured = crbk::Rulebook::default();
    let mut custom = first[gates::VOUCHER_VALIDITY_DAYS].clone();
    custom.default = 14.into();
    configured
        .define(gates::VOUCHER_VALIDITY_DAYS, custom.clone())
        .unwrap();
    gates::define_settings(&mut configured).unwrap();
    assert_eq!(configured.catalog()[gates::VOUCHER_VALIDITY_DAYS], custom);
}
