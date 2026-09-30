//! Real blind issuance, authenticated presentation, replay and scope boundaries.
mod common;
use cgts::*;
use common::*;
use rand::{SeedableRng, rngs::StdRng};

#[tokio::test]
async fn verified_global_gates_bind_subject_scope_epoch_and_action() {
    let mut rng = StdRng::seed_from_u64(61);
    let phone = cpsd::GateId::new("phone").unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("shared").unwrap(),
        vec![phone.clone()],
    )
    .unwrap();
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let auth = cpsd::AuthenticatedIssuance::new([1; 32], [2; 32]);
    let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new("global").unwrap(), 10).unwrap();
    let nonce = cpsd::issuance_challenge(&mut rng, &issuance, issuer.public_key(), &auth, 2000)
        .await
        .unwrap();
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    let attributes = cpsd::PassportAttributes::new(86400, 4).with_gate(phone.clone(), 86400);
    let answer = cpsd::issue_blind_once(
        &mut rng,
        &issuance,
        &issuer,
        &auth,
        &request,
        &nonce,
        &attributes,
        1100,
    )
    .await
    .unwrap();
    let passport = pending.finish(&answer).unwrap();
    let verifier = cpsd::Verifier::new(
        cpsd::MemoryStore::new(cpsd::CommunityId::new("garden").unwrap(), 10).unwrap(),
        vec![issuer.public_key().clone()],
    )
    .unwrap();
    let request = verifier
        .request_for_epoch(&mut rng, 4, [phone], 1200, 86400)
        .await
        .unwrap();
    let mut signer =
        csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [3; 32]), 0, 86400).unwrap();
    let cose = signer
        .sign(csgn::Kind::Credential, &request.to_bytes(), 0, 1201)
        .unwrap();
    let origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        request.community().clone(),
        signer.key_ring().clone(),
    );
    let wrong = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("other").unwrap(),
        signer.key_ring().clone(),
    );
    assert!(passport.present(&mut rng, &wrong, &cose, 1100).is_err());
    let proof = passport.present(&mut rng, &origin, &cose, 1100).unwrap();
    assert!(matches!(
        verify_passport(&verifier, &mut rng, &request, &proof, 5, 1100).await,
        Err(Error::Refused)
    ));
    let verified = verify_passport(&verifier, &mut rng, &request, &proof, 4, 1100)
        .await
        .unwrap();
    assert_eq!(verified.global_epoch(), 4);
    assert!(matches!(
        verify_passport(&verifier, &mut rng, &request, &proof, 4, 1100).await,
        Err(Error::Refused)
    ));
    let subject = verified.pseudonym().to_hex();
    let mut snapshot = snapshot("garden", "phone");
    snapshot
        .content
        .insert(crbk::gate_key(GateLevel::Global, "phone"), true.into());
    snapshot.content.insert(
        crbk::provider_key(GateLevel::Global, "phone", "cpsd"),
        true.into(),
    );
    snapshot.content.insert(
        crbk::action_key("enter"),
        serde_json::to_value(crbk::ActionPolicy {
            all_of: vec![crbk::Requirement {
                gate: "phone".into(),
                level: GateLevel::Global,
                provider: None,
            }],
            ..Default::default()
        })
        .unwrap(),
    );
    let context = Context {
        subject: &subject,
        ..context(&snapshot)
    };
    let keeper = memory("garden");
    let gates = verified.gates(context).unwrap();
    assert!(
        keeper
            .decide(context, MembershipState::Pending, &gates)
            .await
            .unwrap()
            .allowed
    );
    assert!(keeper.collect(context).await.unwrap().is_empty());
    assert!(
        verified
            .gates(Context {
                subject: "other",
                ..context
            })
            .is_err()
    );
    assert!(
        verified
            .gates(Context {
                now: 1101,
                ..context
            })
            .is_err()
    );
    assert!(
        gates[0]
            .in_context(Context {
                action: "edit",
                ..context
            })
            .is_err()
    );
    assert!(
        keeper
            .check(context, vec![gates[0].clone(), gates[0].clone()])
            .await
            .is_err()
    );
}
