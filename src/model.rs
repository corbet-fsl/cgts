use crate::{Error, GateLevel, Result, Snapshot, component, identifier};
use serde::Serialize;

/// The complete public gate result. No raw evidence, score or issuance timestamp.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GateResult {
    /// Gate identifier.
    pub gate: String,
    /// Global or community proof scope.
    pub level: GateLevel,
    /// Opaque community pseudonym (or global holder for the development helper).
    pub subject: String,
    /// Provider identifier, never a sponsor identity.
    pub provider: String,
    /// Exclusive Unix-second expiry.
    pub valid_until: i64,
}

impl GateResult {
    pub(crate) fn validate(&self) -> Result<()> {
        component(&self.gate)?;
        component(&self.provider)?;
        identifier(&self.subject)?;
        if self.valid_until <= 0 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Trusted server context. Authenticate the snapshot, subject, action and clock
/// before construction; this is not a member-facing request deserialization type.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// Active, authenticated rulebook publication for this community.
    pub snapshot: &'a Snapshot,
    /// Authenticated community pseudonym.
    pub subject: &'a str,
    /// Exact operation being checked or performed.
    pub action: &'a str,
    /// Trusted nonnegative Unix seconds; never retained.
    pub now: i64,
}

impl Context<'_> {
    pub(crate) fn validate(&self, community: &str) -> Result<()> {
        identifier(self.subject)?;
        identifier(self.action)?;
        identifier(community)?;
        if self.snapshot.community != community {
            return Err(Error::Scope);
        }
        if self.now < 0
            || self.snapshot.issued < 0
            || self.snapshot.issued > self.now
            || self.snapshot.revision == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Headless input description. Contains identifiers and explanatory text only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Step {
    /// Stable client dispatch key, not a URL or executable instruction.
    pub id: String,
    /// Plain text suitable for any client.
    pub description: String,
    /// Leaf protocol payload type; clients submit evidence directly to its route.
    pub input: String,
}

/// Server-registered gate and provider. No member evidence belongs here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    /// Gate identifier used in crbk control keys.
    pub gate: String,
    /// Provider identifier used in crbk control keys.
    pub provider: String,
    /// Scope; cgts only runs community gates.
    pub level: GateLevel,
    /// Ordered headless steps; the facade does not prescribe UI navigation.
    pub steps: Vec<Step>,
}

impl Descriptor {
    pub(crate) fn validate(&self) -> Result<()> {
        component(&self.gate)?;
        component(&self.provider)?;
        if self.steps.is_empty() || self.steps.len() > 32 {
            return Err(Error::Invalid);
        }
        for step in &self.steps {
            component(&step.id)?;
            identifier(&step.input)?;
            identifier(&step.description)?;
        }
        Ok(())
    }

    /// Whether both exact crbk switches are true. Missing/null values are off.
    pub fn enabled(&self, snapshot: &Snapshot) -> bool {
        [
            crbk::gate_key(self.level, &self.gate),
            crbk::provider_key(self.level, &self.gate, &self.provider),
        ]
        .iter()
        .all(|key| snapshot.content.get(key).and_then(|v| v.as_bool()) == Some(true))
    }
}

/// A nullifier, never a voucher, proof, profile or sponsor key.
#[derive(Clone)]
pub struct Claim {
    pub(crate) domain: String,
    pub(crate) marker: Vec<u8>,
}

impl Claim {
    /// Construct an opaque, domain-separated marker computed by a trusted leaf.
    /// No timestamps or member bindings are retained with this marker.
    pub fn new(domain: impl Into<String>, marker: Vec<u8>) -> Result<Self> {
        let domain = domain.into();
        component(&domain)?;
        if marker.is_empty() || marker.len() > 128 {
            return Err(Error::Invalid);
        }
        Ok(Self { domain, marker })
    }
}

/// Evidence verified by a trusted server gate implementation. Never deserialize
/// this type from a client. The facade supplies subject/gate/provider bindings.
pub struct Proof {
    pub(crate) valid_until: i64,
    pub(crate) retain: bool,
    pub(crate) claim: Option<Claim>,
}

impl Proof {
    /// A reusable fact, retained until replacement or explicit withdrawal.
    pub fn retained(valid_until: i64) -> Self {
        Self {
            valid_until,
            retain: true,
            claim: None,
        }
    }
    /// A fresh check for one action; never stored as a reusable pass.
    pub fn transient(valid_until: i64) -> Self {
        Self {
            valid_until,
            retain: false,
            claim: None,
        }
    }
    /// Require an atomic first claim before exposing the result.
    pub fn with_claim(mut self, claim: Claim) -> Self {
        self.claim = Some(claim);
        self
    }
}

/// An in-process checked result, bound to the exact action and snapshot.
/// Its public wire representation is available via [`Self::result`].
#[derive(Clone)]
pub struct CheckedGate {
    pub(crate) result: GateResult,
    pub(crate) community: String,
    pub(crate) action: String,
    pub(crate) revision: u64,
    pub(crate) epoch: u64,
    pub(crate) now: i64,
    pub(crate) settings: crbk::Values,
    pub(crate) issued: i64,
}

impl CheckedGate {
    /// Metadata only. A serialized result is not authentication evidence.
    pub fn result(&self) -> &GateResult {
        &self.result
    }
}

impl CheckedGate {
    /// Validate the full check binding before supplying metadata to cplc.
    pub fn in_context(&self, context: Context<'_>) -> Result<&GateResult> {
        context.validate(&self.community)?;
        if self.action != context.action
            || self.result.subject != context.subject
            || self.revision != context.snapshot.revision
            || self.epoch != context.snapshot.policy_epoch
            || self.now != context.now
            || self.settings != context.snapshot.content
            || self.issued != context.snapshot.issued
        {
            return Err(Error::Scope);
        }
        Ok(&self.result)
    }
}

/// Complete checked gate collection, including the mandatory legal veto.
/// The empty collection is also produced only after a live legal check.
///
/// ```compile_fail
/// let raw: Vec<cgts::GateResult> = Vec::new();
/// let checked: cgts::CheckedGates = raw.into();
/// ```
pub struct CheckedGates {
    pub(crate) context: CheckedGate,
    pub(crate) gates: Vec<CheckedGate>,
}

impl CheckedGates {
    /// Validate every action, subject, time, revision and effective epoch binding.
    pub fn in_context(&self, context: Context<'_>) -> Result<Vec<crbk::GateResult>> {
        self.context.in_context(context)?;
        self.gates
            .iter()
            .map(|gate| {
                let result = gate.in_context(context)?;
                Ok(crbk::GateResult {
                    gate: result.gate.clone(),
                    level: result.level,
                    subject: result.subject.clone(),
                    provider: result.provider.clone(),
                    community: (result.level == GateLevel::Community)
                        .then(|| context.snapshot.community.clone()),
                    valid_until: result.valid_until,
                    proven_at: None,
                })
            })
            .collect()
    }
}

impl std::fmt::Debug for GateResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateResult").finish_non_exhaustive()
    }
}
