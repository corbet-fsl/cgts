//! Minimal cpmt/crpt handoff. Payment execution and policy stay in their owners.
use crate::*;
use cpmt::payments::{Binding, Evidence};

/// Paid access by application-defined level and period. Financial terms are
/// verified and transformed inside cpmt/crpt before this boundary.
pub struct PaidAccessGate {
    payment: PaymentGate,
    level: String,
}
impl PaidAccessGate {
    /// Require this exact application level; levels have no implicit ordering.
    pub fn new(gate: String, provider: String, level: String, retain: bool) -> Result<Self> {
        component(&level)?;
        Ok(Self {
            payment: PaymentGate::new(gate, provider, retain)?,
            level,
        })
    }
}
impl Gate for PaidAccessGate {
    type Input = cpmt::access::PaidAccess;
    fn descriptor(&self) -> Descriptor {
        let mut descriptor = self.payment.descriptor();
        descriptor.steps[0].description = "Complete payment for the required access level.".into();
        descriptor.steps[0].input = "cpmt.PaidAccess".into();
        descriptor
    }
    async fn verify(&self, context: Context<'_>, access: &Self::Input) -> Result<Proof> {
        let binding = Binding {
            scope: context.snapshot.community.clone(),
            subject: context.subject.into(),
            action: context.action.into(),
        };
        let now = u64::try_from(context.now).map_err(|_| Error::Invalid)?;
        let (level, _) = access
            .in_context(&binding, now)
            .map_err(|_| Error::Refused)?;
        if level != self.level {
            return Err(Error::Refused);
        }
        self.payment.verify(context, access.evidence()).await
    }
}

/// Community payment gate over an already verified in-process payment fact.
/// The caller chooses the acceptable fact and lifetime inside the payment boundary.
pub struct PaymentGate {
    gate: String,
    provider: String,
    retain: bool,
}

impl PaymentGate {
    /// Bind the rulebook gate/provider and caller-selected retention behavior.
    pub fn new(gate: String, provider: String, retain: bool) -> Result<Self> {
        component(&gate)?;
        component(&provider)?;
        Ok(Self {
            gate,
            provider,
            retain,
        })
    }
}

impl Gate for PaymentGate {
    type Input = Evidence;
    fn descriptor(&self) -> Descriptor {
        Descriptor {
            gate: self.gate.clone(),
            provider: self.provider.clone(),
            level: GateLevel::Community,
            steps: vec![Step {
                id: "payment".into(),
                description: "Complete the requested payment operation.".into(),
                input: "cpmt.Evidence".into(),
            }],
        }
    }
    async fn verify(&self, context: Context<'_>, evidence: &Evidence) -> Result<Proof> {
        let now = u64::try_from(context.now).map_err(|_| Error::Invalid)?;
        let binding = Binding {
            scope: context.snapshot.community.clone(),
            subject: context.subject.into(),
            action: context.action.into(),
        };
        let (provider, until) = evidence
            .in_context(&binding, now)
            .map_err(|_| Error::Refused)?;
        if provider != self.provider {
            return Err(Error::Refused);
        }
        let until = i64::try_from(until).map_err(|_| Error::Refused)?;
        let proof = if self.retain {
            Proof::retained(until)
        } else {
            Proof::transient(until)
        };
        // One receipt cannot be spent again by choosing a different gate/provider.
        Ok(proof.with_claim(Claim::new("payment", evidence.claim().to_vec())?))
    }
}
