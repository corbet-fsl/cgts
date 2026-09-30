//! Verification of the upstream signed profile fixture through the facade.
mod common;
use cgts::*;
use common::*;

// Frozen, publicly generated cgrd wire fixture. No production identity or key.
#[derive(serde::Deserialize)]
struct Fixture {
    bundle: cgrd::Bundle,
    settings: Vec<u8>,
    schema: Vec<u8>,
    keys: Vec<u8>,
}

#[tokio::test]
async fn actual_signed_profile_is_bound_to_scope_and_never_retained() {
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/profile.json")).unwrap();
    let keys = csgn::KeyRing::from_cbor(&fixture.keys).unwrap();
    let mut gate = gates::ProfileGate {
        provider: "local",
        schema: &fixture.schema,
        scope: cgrd::Scope::Public,
        policy: cgrd::Policy {
            community: "garden",
            keys: &keys,
            now: 1100,
            minimum_epoch: 2,
            minimum_settings_revision: 1,
            minimum_schema_revision: 1,
            maximum_snapshot_age: 200,
            settings: &fixture.settings,
        },
    };
    let keeper = memory("garden");
    let snapshot = snapshot("garden", "cgrd");
    let context = context(&snapshot);
    let checked = keeper.run(context, &gate, &fixture.bundle).await.unwrap();
    assert_eq!(checked.result().valid_until, 1101);
    assert!(keeper.collect(context).await.unwrap().is_empty());
    assert!(
        keeper
            .decide(context, MembershipState::Pending, &[checked])
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !keeper
            .decide(context, MembershipState::Pending, &[])
            .await
            .unwrap()
            .allowed
    );
    gate.scope = cgrd::Scope::Full;
    assert!(matches!(
        keeper.run(context, &gate, &fixture.bundle).await,
        Err(Error::Refused)
    ));
    gate.scope = cgrd::Scope::Public;
    assert!(matches!(
        keeper
            .run(
                Context {
                    subject: "bob",
                    ..context
                },
                &gate,
                &fixture.bundle
            )
            .await,
        Err(Error::Refused)
    ));
    let mut bad = fixture.bundle.clone();
    bad.signature[0] ^= 1;
    assert!(matches!(
        keeper.run(context, &gate, &bad).await,
        Err(Error::Refused)
    ));
    gate.policy.now = 1101;
    assert!(matches!(
        keeper.run(context, &gate, &fixture.bundle).await,
        Err(Error::Scope)
    ));
    gate.policy.now = 1100;
    gate.policy.minimum_settings_revision = 2;
    assert!(matches!(
        keeper.run(context, &gate, &fixture.bundle).await,
        Err(Error::Refused)
    ));
}
