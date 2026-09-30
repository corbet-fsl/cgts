//! Verified global evidence, without retaining a global person identifier.
use crate::{CheckedGate, Context, Error, GateLevel, GateResult, Result};

/// A successfully consumed cpsd presentation challenge. A bare pseudonym cannot
/// construct this capability; only the actual stateful verifier can produce it.
///
/// ```compile_fail
/// let pseudonym: cpsd::Pseudonym = todo!();
/// let verified: cgts::VerifiedPassport = pseudonym.into();
/// ```
pub struct VerifiedPassport {
    subject: cpsd::Pseudonym,
    community: Vec<u8>,
    epoch: u64,
    gates: Vec<String>,
    valid_until: i64,
    checked_at: i64,
}

impl VerifiedPassport {
    /// Canonical community-scoped identity, never a global holder identity.
    pub fn pseudonym(&self) -> &cpsd::Pseudonym {
        &self.subject
    }
    /// Authenticated global epoch, independent of the community policy epoch.
    pub fn global_epoch(&self) -> u64 {
        self.epoch
    }
    /// Bind global facts to the same action and effective community publication
    /// as the community checks. No gate is stored in the community result table.
    pub fn gates(&self, context: Context<'_>) -> Result<Vec<CheckedGate>> {
        context.validate(&context.snapshot.community)?;
        if self.community != context.snapshot.community.as_bytes()
            || self.subject.to_hex() != context.subject
            || self.checked_at != context.now
            || self.valid_until <= context.now
        {
            return Err(Error::Scope);
        }
        Ok(self
            .gates
            .iter()
            .map(|gate| CheckedGate {
                result: GateResult {
                    gate: gate.clone(),
                    level: GateLevel::Global,
                    subject: context.subject.into(),
                    provider: "cpsd".into(),
                    valid_until: self.valid_until,
                },
                community: context.snapshot.community.clone(),
                action: context.action.into(),
                revision: context.snapshot.revision,
                epoch: context.snapshot.policy_epoch,
                now: context.now,
                settings: context.snapshot.content.clone(),
                issued: context.snapshot.issued,
            })
            .collect())
    }
}

/// Verify real BBS+ evidence and consume its replay challenge before constructing
/// a witness. The service supplies the current authenticated global epoch.
/// Shared cohort expiry is required; independent hidden expiries cannot safely
/// become longer-lived gate metadata. Cohort timestamps are UTC-day boundaries.
pub async fn verify_passport<S: cpsd::ChallengeStore, R: rand::RngCore + rand::CryptoRng>(
    verifier: &cpsd::Verifier<S>,
    rng: &mut R,
    request: &cpsd::PresentationRequest,
    proof: &cpsd::Presentation,
    current_global_epoch: u64,
    now: u64,
) -> Result<VerifiedPassport> {
    let expiry = request
        .epoch_expiry()
        .filter(|expiry| expiry % 86_400 == 0)
        .ok_or(Error::Invalid)?;
    let valid_until = i64::try_from(expiry).map_err(|_| Error::Invalid)?;
    let checked_at = i64::try_from(now).map_err(|_| Error::Invalid)?;
    if valid_until <= checked_at {
        return Err(Error::Refused);
    }
    let subject = verifier
        .verify(rng, request, proof, current_global_epoch, now)
        .await
        .map_err(|_| Error::Refused)?;
    Ok(VerifiedPassport {
        subject,
        community: request.community().as_bytes().to_vec(),
        epoch: current_global_epoch,
        gates: request
            .required_gates()
            .iter()
            .map(|gate| gate.as_str().to_owned())
            .collect(),
        valid_until,
        checked_at,
    })
}
