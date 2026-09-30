//! Canonical pin-spend boundary. Activation is closed until cblc proves its
//! private extension relation; issuer signatures alone cannot create a witness.
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
    _sealed: (),
}

/// The only production cpns spend adapter used by cmbr. It fails closed while
/// extension proofs are unavailable, including when a dependency enables a
/// cblc issuer harness feature through feature unification.
#[derive(Clone, Copy, Default)]
pub struct PinSpendVerifier;

impl ChangeTokenVerifier for PinSpendVerifier {
    type Token = SpentChange;
    async fn verify_spent(
        &self,
        _: &Change<'_>,
        _: &SpentChange,
    ) -> std::result::Result<(), TokenRejected> {
        Err(TokenRejected)
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
/// unproven extension, regardless of feature unification in downstream crates.
pub fn verify_encoded_pin_change(change: &Change<'_>, _: &[u8]) -> Result<SpentChange> {
    change_binding(change)?;
    Err(Error::ExtensionsUnavailable)
}
