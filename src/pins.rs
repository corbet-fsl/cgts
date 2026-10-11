//! Canonical pin-spend boundary. Only the configured native account worker can
//! create the sealed completed-spend capability; signatures alone cannot.
use crate::{Error, Result};
use cpns::server::{Change, ChangeTokenVerifier, TokenRejected};

/// Evidence that an irreversible change spend authorized one exact transition.
/// There is deliberately no public constructor or deserializer.
///
/// ```compile_fail
/// let raw: cgts::gates::ChangeSpend = todo!();
/// let spent: cgts::pins::SpentChange = raw.into();
/// ```
pub struct SpentChange {
    pub(crate) verified: cblc::pins::VerifiedPinChange,
}

/// The production CPNS adapter accepts only the sealed native owner capability.
#[derive(Clone, Copy, Default)]
pub struct PinSpendVerifier;

impl ChangeTokenVerifier for PinSpendVerifier {
    type Token = SpentChange;
    async fn verify_spent(
        &self,
        change: &Change<'_>,
        spent: &SpentChange,
    ) -> std::result::Result<(), TokenRejected> {
        spent
            .verified
            .check_change(change)
            .map_err(|_| TokenRejected)
    }
}

/// Transient host-selected exact change and bounded original receipt bytes.
/// This request is untrusted evidence, never a spend capability or wire command.
pub struct PinChangeRequest {
    community: String,
    member: String,
    field: String,
    expected: cpns::server::Pin,
    replacement: cpns::Fingerprint,
    evidence: Vec<u8>,
}
impl PinChangeRequest {
    /// The membership owner supplies the actual pending change independently of
    /// the receipt. The same service enforces its possibly narrower byte limit.
    pub fn new(change: &Change<'_>, evidence: &[u8]) -> Result<Self> {
        change_binding(change)?;
        if evidence.is_empty() || evidence.len() > 16 * 1024 * 1024 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            community: change.community.into(),
            member: change.member.into(),
            field: change.field.into(),
            expected: change.expected,
            replacement: change.replacement,
            evidence: evidence.to_vec(),
        })
    }
    pub(crate) fn verify<V, C>(
        self,
        service: &mut cblc::accounting_service::AccountService<V, C>,
    ) -> std::result::Result<SpentChange, cblc::Error>
    where
        V: cblc::accounting::AccountProofVerifier,
        C: Fn() -> u64,
    {
        service
            .verify_completed_pin_change(
                &Change {
                    community: &self.community,
                    member: &self.member,
                    field: &self.field,
                    expected: self.expected,
                    replacement: self.replacement,
                },
                &self.evidence,
            )
            .map(|verified| SpentChange { verified })
    }
}

/// Leaf-owned framed commitment to community, canonical pseudonym, field,
/// expected digest/revision and replacement digest. No facade hash is invented.
pub fn change_binding(change: &Change<'_>) -> Result<[u8; 32]> {
    cblc::pins::change_binding(change).map_err(|_| Error::Invalid)
}

/// Verify a completed spend before handing its opaque witness to cmbr/cpns.
/// Currently always refuses: a signed acceptance is insufficient evidence of
/// the hidden extension relation. No marker is consumed and no pin is changed.
/// Once enabled, cpns must still atomically compare digest AND revision; an
/// uncertain commit is reconciled by reading that same pin, never spending twice.
pub fn verify_pin_change(
    change: &Change<'_>,
    _: &crate::gates::ChangeSpend,
) -> Result<SpentChange> {
    change_binding(change)?;
    Err(Error::ExtensionsUnavailable)
}

/// Wire entry point for the pin-change flow. No wire evidence can activate an
/// disabled extension integration, regardless of feature unification downstream.
pub fn verify_encoded_pin_change(change: &Change<'_>, _: &[u8]) -> Result<SpentChange> {
    change_binding(change)?;
    Err(Error::ExtensionsUnavailable)
}
