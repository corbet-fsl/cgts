//! Original daily owner operations on the same native accounting worker.
use super::*;
use cblc::{
    settlement::{SettlementConfig, SettlementIssuer, SettlementSubmission},
    storage::CommitAuthority,
};

pub(super) fn reconcile<V: AccountProofVerifier, C: Fn() -> u64>(
    service: &mut AccountService<V, C>,
    config: SettlementConfig,
    issuer: SettlementIssuer,
    incarnation: String,
    revision: u64,
    authority: Arc<dyn CommitAuthority>,
) -> std::result::Result<HostResponse, cblc::Error> {
    let expected = (
        config.epoch.clone(),
        config.policy_epoch,
        config.period_seconds,
        config.quota,
    );
    let installed =
        service.reconcile_daily_settlement_with_issuer(config, issuer, incarnation, authority)?;
    if installed != expected.0 {
        return Err(cblc::Error::PolicyMismatch);
    }
    // The projection immediately follows the actual native reconciliation on
    // this same service. Caller Policy publication still owns authentication.
    let material = service.public_verifier_material(revision, expected.1)?;
    let settings = material
        .settlement
        .as_ref()
        .ok_or(cblc::Error::UnsupportedCapability)?;
    if settings.epoch != expected.0
        || settings.policy_epoch != expected.1
        || settings.period_seconds != expected.2
        || settings.quota != expected.3
    {
        return Err(cblc::Error::PolicyMismatch);
    }
    Ok(HostResponse::VerifierMaterial(material))
}

pub(super) fn stage<V: AccountProofVerifier, C: Fn() -> u64>(
    service: &mut AccountService<V, C>,
    submission: SettlementSubmission,
) -> std::result::Result<HostResponse, cblc::Error> {
    // This command carries no member identity/session. Only actual native
    // Deposit plus dedicated-token verification can stage operational facts.
    service
        .stage_settlement(&submission)
        .map(HostResponse::Settlement)
}
