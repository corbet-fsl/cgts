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
    assert!(matches!(
        gate.verify(Context { now: -1, ..context }, &fixture.bundle)
            .await,
        Err(Error::Invalid)
    ));
    gate.policy.community = "other";
    assert!(matches!(
        gate.verify(context, &fixture.bundle).await,
        Err(Error::Scope)
    ));
    gate.policy.community = "garden";
    gate.policy.minimum_epoch = 1;
    assert!(matches!(
        gate.verify(context, &fixture.bundle).await,
        Err(Error::Scope)
    ));
    gate.policy.minimum_epoch = 2;
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

#[tokio::test]
async fn actual_full_profile_accepts_private_pin_openings_without_retaining_them() {
    use ed25519_dalek::Signer as _;
    let mut fixture: Fixture = serde_json::from_str(include_str!("fixtures/profile.json")).unwrap();
    let keys = csgn::KeyRing::from_cbor(&fixture.keys).unwrap();
    let mut body: cgrd::BundleContent = serde_json::from_slice(&fixture.bundle.payload).unwrap();
    let verified = keys
        .verify(&body.credential, csgn::Kind::Credential, 1100)
        .unwrap();
    let mut credential: cgrd::Credential = serde_json::from_slice(verified.payload()).unwrap();
    let mut profile = serde_json::to_value(&body.profile).unwrap();
    profile["scope"] = "full".into();
    profile["profile"]["private"] = serde_json::json!({"secret": true});
    body.profile = serde_json::from_value(profile).unwrap();
    let salt = cpns::Salt::from_bytes(vec![44; 16]).unwrap();
    credential.pins.push(cgrd::Pin {
        field: "secret".into(),
        fingerprint: *cpns::fingerprint_v2(
            &cpns::FingerprintContext {
                community: "garden",
                member: "alice",
                field: "secret",
            },
            &cgrd::pin_value_bytes(&true.into()),
            &salt,
        )
        .as_bytes(),
    });
    body.openings.push(cgrd::Opening {
        field: "secret".into(),
        salt: salt.as_bytes().to_vec(),
    });
    // Same public deterministic upstream fixture keys, never operational credentials.
    let mut issuer = csgn::Signer::new(
        "garden",
        csgn::SecretKey::from_seed(&mut [11; 32]),
        1000,
        10000,
    )
    .unwrap();
    body.credential = issuer
        .sign(
            csgn::Kind::Credential,
            &serde_json::to_vec(&credential).unwrap(),
            1000,
            2000,
        )
        .unwrap();
    fixture.bundle.payload = serde_json::to_vec(&body).unwrap();
    fixture.bundle.signature = ed25519_dalek::SigningKey::from_bytes(&[22; 32])
        .sign(&cgrd::binding_bytes(&fixture.bundle.payload))
        .to_bytes()
        .to_vec();
    let gate = gates::ProfileGate {
        provider: "local",
        schema: &fixture.schema,
        scope: cgrd::Scope::Full,
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
    let snapshot = snapshot("garden", "cgrd");
    let keeper = memory("garden");
    let checked = keeper
        .run(context(&snapshot), &gate, &fixture.bundle)
        .await
        .unwrap();
    assert_eq!(checked.result().valid_until, 1101);
    assert!(keeper.collect(context(&snapshot)).await.unwrap().is_empty());
}
