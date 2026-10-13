//! Adapters delegate execution and cryptography to the existing leaves.
use crate::*;

fn description(gate: &str, provider: &str, text: &str, input: &str) -> Descriptor {
    Descriptor {
        gate: gate.into(),
        provider: provider.into(),
        level: GateLevel::Community,
        steps: vec![Step {
            id: "submit".into(),
            description: text.into(),
            input: input.into(),
        }],
    }
}

/// Voucher gate over cvch links. The service owns the link store; the
/// redeeming member supplies only the link request, with a notice sealed to the
/// issuer's device that this gate relays opaque. A link that waits for the
/// issuer's sign-off is [`Error::Pending`]: the member presents the same link
/// again to learn the decision. The gate never learns an issuer.
pub struct VoucherGate<S> {
    provider: String,
    links: std::sync::Arc<S>,
}

impl<S> VoucherGate<S> {
    /// The provider names the voucher service; links come from trusted storage.
    pub fn new(provider: impl Into<String>, links: std::sync::Arc<S>) -> Result<Self> {
        let provider = provider.into();
        component(&provider)?;
        Ok(Self { provider, links })
    }
}

impl<S: cvch::link::LinkStore> Gate for VoucherGate<S> {
    type Input = cvch::link::Request;
    fn descriptor(&self) -> Descriptor {
        description(
            "cvch",
            &self.provider,
            "Present a voucher link.",
            "cvch.link.Request",
        )
    }
    async fn verify(&self, context: Context<'_>, request: &Self::Input) -> Result<Proof> {
        let days = context
            .snapshot
            .content
            .get(VOUCHER_VALIDITY_DAYS)
            .and_then(serde_json::Value::as_i64)
            .filter(|days| (1..=365).contains(days))
            .ok_or(Error::Policy)?;
        let now = u64::try_from(context.now).map_err(|_| Error::Invalid)?;
        let expiry = (context.now / 86_400)
            .checked_add(days)
            .and_then(|days| days.checked_mul(86_400))
            .ok_or(Error::Invalid)?;
        let (presentation, notice) = request.parts().map_err(|_| Error::Refused)?;
        let community = &context.snapshot.community;
        let subject = context.subject;
        let outcome = self
            .links
            .update(presentation.id(), |link| {
                if link.community() != community {
                    return Err(cvch::Error::Rejected);
                }
                link.apply(&presentation, subject, &notice, now)
            })
            .await
            .map_err(|_| Error::Refused)?;
        match outcome {
            cvch::link::Outcome::Waiting => Err(Error::Pending),
            cvch::link::Outcome::Admitted | cvch::link::Outcome::Known => {
                // The link store owns the use count; this claim makes the proof
                // once-only per person and atomic with its commit, so a failed
                // commit can simply be retried.
                let claim = Claim::new("cvch", presentation.id().claim(subject).into_bytes())?;
                Ok(Proof::retained(expiry).with_claim(claim))
            }
        }
    }
}

/// Profile gate using cgrd's authenticated bundle and signed snapshots. The
/// configured scope is a minimum: a public-only check cannot assert full validity.
pub struct ProfileGate<'a> {
    /// Provider identifier from trusted service configuration.
    pub provider: &'a str,
    /// Verifier-owned keys, time, revision/epoch floors and signed settings.
    pub policy: cgrd::Policy<'a>,
    /// Signed schema, authenticated inside cgrd.
    pub schema: &'a [u8],
    /// Required profile projection.
    pub scope: cgrd::Scope,
}

impl Gate for ProfileGate<'_> {
    type Input = cgrd::Bundle;
    fn descriptor(&self) -> Descriptor {
        description(
            "cgrd",
            self.provider,
            "Present the signed profile and required pin openings.",
            "cgrd.Bundle",
        )
    }
    async fn verify(&self, context: Context<'_>, bundle: &Self::Input) -> Result<Proof> {
        if self.policy.community != context.snapshot.community
            || self.policy.now != u64::try_from(context.now).map_err(|_| Error::Invalid)?
            || self.policy.minimum_epoch < context.snapshot.policy_epoch
        {
            return Err(Error::Scope);
        }
        match cgrd::check(bundle, &self.policy, self.schema) {
            cgrd::Admission::Admitted {
                community,
                member,
                scope,
                ..
            } if community == context.snapshot.community
                && member == context.subject
                && (scope == cgrd::Scope::Full || self.scope == cgrd::Scope::Public) =>
            {
                // Leaf success is current at this second only. Do not turn profile
                // validity into a stored badge that outlives edits or revocations.
                Ok(Proof::transient(
                    context.now.checked_add(1).ok_or(Error::Invalid)?,
                ))
            }
            _ => Err(Error::Refused),
        }
    }
}

/// Transient issuer acceptance of an extended change spend. No balance, hidden
/// witness, proof or acceptance is stored by cgts.
pub struct ChangeSpend {
    /// Complete cblc request bound into the issuer's acceptance.
    pub request: cblc::accounting::AccountRequest,
    /// Verified issuer response, still untrusted until the leaf checks it.
    pub acceptance: cblc::accounting::AccountAcceptance,
    /// Exact extended effect and inbox supplied to the issuer.
    pub update: cblc::extensions::ExtendedUpdate,
}

/// Balance-as-gate adapter for cblc's signed, single-use change permissions.
/// Configuration is trusted and must be bound to the actual pending field edit.
/// The issuer must activate a complete extension verifier; cgts never substitutes
/// ordinary v2 acceptance or a signature for the hidden balance relation.
pub struct BalanceGate<'a> {
    /// Configured provider.
    pub provider: &'a str,
    /// Community name corresponding to the configured opaque accounting scope.
    pub community: &'a str,
    /// Authenticated community pseudonym corresponding to `owner`.
    pub subject: &'a str,
    /// Exact operation authorized by this field change.
    pub action: &'a str,
    /// Opaque accounting community ID selected by the service.
    pub accounting_community: [u8; 32],
    /// Opaque accounting owner bound by the service to `subject`.
    pub owner: [u8; 32],
    /// Nonzero opaque commitment to the exact pending field edit, computed by a leaf.
    pub binding: [u8; 32],
    /// Authenticated cblc issuer public key.
    pub operator_key: [u8; 32],
    /// Pinned complete extension circuit and verification key.
    pub proof_scope: cblc::accounting::AccountProofScope,
    /// Immutable extension policy, supplied by the service.
    pub policy: &'a cblc::extensions::ExtensionPolicy,
}

impl Gate for BalanceGate<'_> {
    type Input = ChangeSpend;
    fn descriptor(&self) -> Descriptor {
        description(
            "cblc",
            self.provider,
            "Present an issuer-approved change-token spend for this field edit.",
            "cblc.ChangeSpend",
        )
    }
    async fn verify(&self, _: Context<'_>, _: &Self::Input) -> Result<Proof> {
        Err(Error::ExtensionsUnavailable)
    }
}

/// Public-record proof supplied transiently to the balance leaf. Below-quorum
/// records still require a proof; no raw counters are accepted or retained.
pub struct RecordProof {
    /// Opaque current-state binding and optional relative shares.
    pub record: cblc::extensions::PublicRecord,
    /// Complete extension proof, checked only by the configured leaf verifier.
    pub proof: Vec<u8>,
}

/// cblc's required fresh record gate for forum listing and first contact.
/// The service selects the ledger, authenticated owner and expected challenge;
/// request data cannot select them. Run inside a Tokio runtime.
/// The ledger uses caller-owned atomic storage. Its host adapter determines any
/// blocking construction/drop requirements; cblc itself opens no database.
pub struct RecordGate<'a, V: cblc::accounting::AccountProofVerifier> {
    /// Configured provider.
    pub provider: &'a str,
    /// Community corresponding to the configured issuer ledger.
    pub community: &'a str,
    /// Authenticated pseudonym corresponding to `owner`.
    pub subject: &'a str,
    /// Exact service action corresponding to `expected.purpose`.
    pub action: &'a str,
    /// Community accounting owner, selected independently of member input.
    pub owner: [u8; 32],
    /// Relying-service challenge, intended use and exclusive expiry.
    pub expected: cblc::extensions::RecordContext,
    /// Existing cblc issuer with a complete extension verifier configured.
    pub ledger: std::sync::Arc<std::sync::Mutex<cblc::accounting_ledger::AccountLedger<V>>>,
    /// Trusted clock, also checked after the blocking proof operation.
    pub clock: std::sync::Arc<dyn clbs::Clock>,
}

impl<V: cblc::accounting::AccountProofVerifier + Send + 'static> Gate for RecordGate<'_, V> {
    type Input = RecordProof;
    fn descriptor(&self) -> Descriptor {
        description(
            "cblc",
            self.provider,
            "Prove the current balance record for this action and challenge.",
            "cblc.RecordProof",
        )
    }
    async fn verify(&self, _: Context<'_>, _: &Self::Input) -> Result<Proof> {
        Err(Error::ExtensionsUnavailable)
    }
}

/// Resolved voucher gate validity, separate from the signed redemption deadline.
pub const VOUCHER_VALIDITY_DAYS: &str = "voucher.validity_days";
/// Whether the issuer's device signs and shares "vouched for by <handle>"
/// (devices read it from the trust feed; the gate never sees an issuer).
/// Default on. Turning it off is immediate and final for earlier admissions;
/// turning it on again affects only later ones.
pub const VOUCHER_SPONSOR_VISIBLE: &str = "voucher.sponsor_visible";

/// Install the voucher catalogue entry without overriding a service definition.
pub fn define_settings(book: &mut crbk::Rulebook) -> Result<()> {
    if !book.catalog().contains_key(VOUCHER_VALIDITY_DAYS) {
        book.define(
            VOUCHER_VALIDITY_DAYS,
            crbk::Setting {
                value_type: crbk::SettingType::Integer,
                nullable: false,
                default: 30.into(),
                bounds: crbk::Bounds {
                    min: Some(1.into()),
                    max: Some(365.into()),
                },
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .map_err(|_| Error::Policy)?;
    }
    if !book.catalog().contains_key(VOUCHER_SPONSOR_VISIBLE) {
        book.define(
            VOUCHER_SPONSOR_VISIBLE,
            crbk::Setting {
                value_type: crbk::SettingType::Boolean,
                nullable: false,
                default: true.into(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .map_err(|_| Error::Policy)?;
    }
    Ok(())
}
