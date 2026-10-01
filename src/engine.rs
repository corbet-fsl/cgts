use crate::*;
use std::future::Future;

/// A trusted, server-selected leaf adapter. Input is transient, never logged or
/// stored by the facade. Implementations must bind evidence to the entire context.
pub trait Gate: Sync {
    /// Leaf-specific request, without a facade-wide raw-data envelope.
    type Input: Sync + ?Sized;
    /// Headless metadata and rulebook identity.
    fn descriptor(&self) -> Descriptor;
    /// Delegate verification to the leaf; success attests this context only.
    fn verify(
        &self,
        context: Context<'_>,
        input: &Self::Input,
    ) -> impl Future<Output = Result<Proof>> + Send;
}

/// Community legal veto boundary. Errors must never be converted to green.
pub trait LegalVeto: Send + Sync {
    /// Fixed community selected by the service.
    fn community(&self) -> &str;
    /// Check this exact action without recording a request.
    fn check(&self, context: Context<'_>) -> impl Future<Output = Result<()>> + Send;
}

/// Thin adapter over clbs, with shared cloneable stores and verifier configuration.
/// Administration uses clbs directly; this adapter cannot create legal orders.
pub struct LegalGate<S, V> {
    store: S,
    verifier: V,
}

impl<S: clbs::Store, V: clbs::Verifier> LegalGate<S, V> {
    /// Bind the leaf's storage and authority verifier.
    pub fn new(store: S, verifier: V) -> Self {
        Self { store, verifier }
    }
}

#[derive(Clone, Copy)]
struct At(i64);
impl clbs::Clock for At {
    fn now(&self) -> clbs::Result<i64> {
        Ok(self.0)
    }
}

impl<S: clbs::Store + Clone, V: clbs::Verifier + Clone> LegalVeto for LegalGate<S, V> {
    fn community(&self) -> &str {
        self.store.community()
    }
    async fn check(&self, context: Context<'_>) -> Result<()> {
        context.validate(self.community())?;
        let gate = clbs::Gate::new(self.store.clone(), self.verifier.clone(), At(context.now));
        match gate
            .check_action(context.subject, context.action)
            .await
            .map_err(|_| Error::Legal)?
        {
            clbs::State::Green => Ok(()),
            clbs::State::Red(_) => Err(Error::Vetoed),
        }
    }
}

/// Community-bound orchestration; no cryptographic or policy engine lives here.
pub struct Gatekeeper<S, L> {
    store: S,
    legal: L,
}

impl<S: Storage, L: LegalVeto> Gatekeeper<S, L> {
    /// Reject mismatched community capabilities before any gate can run.
    pub fn new(store: S, legal: L) -> Result<Self> {
        identifier(store.community())?;
        if store.community() != legal.community() {
            return Err(Error::Scope);
        }
        Ok(Self { store, legal })
    }

    /// Immutable community shared by this gatekeeper's storage and legal veto.
    pub fn community(&self) -> &str {
        self.store.community()
    }

    /// Only enabled community gates/providers appear in the lobby.
    pub async fn steps(
        &self,
        context: Context<'_>,
        registered: &[Descriptor],
    ) -> Result<Vec<Descriptor>> {
        self.preflight(context).await?;
        let mut steps = Vec::new();
        for descriptor in registered {
            descriptor.validate()?;
            if descriptor.level == GateLevel::Community && descriptor.enabled(context.snapshot) {
                steps.push(descriptor.clone());
            }
        }
        Ok(steps)
    }

    /// Run a leaf after switch/veto checks, then atomically commit any nullifier
    /// and retained result. Failed evidence does not erase an earlier valid fact.
    pub async fn run<G: Gate>(
        &self,
        context: Context<'_>,
        gate: &G,
        input: &G::Input,
    ) -> Result<CheckedGate> {
        self.preflight(context).await?;
        let descriptor = gate.descriptor();
        descriptor.validate()?;
        if descriptor.gate == "cblc" {
            return Err(Error::ExtensionsUnavailable);
        }
        if descriptor.level != GateLevel::Community {
            return Err(Error::Scope);
        }
        if !descriptor.enabled(context.snapshot) {
            return Err(Error::Disabled);
        }
        let proof = gate.verify(context, input).await?;
        let result = GateResult {
            gate: descriptor.gate,
            level: descriptor.level,
            subject: context.subject.into(),
            provider: descriptor.provider,
            valid_until: if proof.retain {
                proof.valid_until / 86_400 * 86_400
            } else {
                proof.valid_until
            },
        };
        result.validate()?;
        if result.valid_until <= context.now {
            return Err(Error::Refused);
        }
        // Recheck mutable legal state after a potentially slow provider operation.
        self.legal.check(context).await?;
        self.store
            .commit(proof.retain.then_some(&result), proof.claim.as_ref())
            .await?;
        Ok(CheckedGate {
            result,
            community: self.store.community().into(),
            action: context.action.into(),
            revision: context.snapshot.revision,
            epoch: context.snapshot.policy_epoch,
            now: context.now,
            settings: context.snapshot.content.clone(),
            issued: context.snapshot.issued,
        })
    }

    /// List retained, currently enabled and unexpired results for this subject.
    /// Transient profile checks and balance spends never appear here.
    pub async fn collect(&self, context: Context<'_>) -> Result<Vec<GateResult>> {
        self.preflight(context).await?;
        self.current(context).await
    }

    /// Collect checked evidence for cplc without making an admission decision.
    /// Legal state is checked even when there are no required gates.
    pub async fn check(
        &self,
        context: Context<'_>,
        fresh: Vec<CheckedGate>,
    ) -> Result<CheckedGates> {
        self.preflight(context).await?;
        let bind = |result| CheckedGate {
            result,
            community: self.store.community().into(),
            action: context.action.into(),
            revision: context.snapshot.revision,
            epoch: context.snapshot.policy_epoch,
            now: context.now,
            settings: context.snapshot.content.clone(),
            issued: context.snapshot.issued,
        };
        let mut gates: Vec<_> = self.current(context).await?.into_iter().map(bind).collect();
        let mut seen = std::collections::BTreeSet::new();
        for gate in fresh {
            if !seen.insert((gate.result.level, gate.result.gate.clone())) {
                return Err(Error::Scope);
            }
            gate.in_context(context)?;
            gates.retain(|old| {
                old.result.gate != gate.result.gate || old.result.level != gate.result.level
            });
            gates.push(gate);
        }
        Ok(CheckedGates {
            context: bind(GateResult {
                gate: "legal-context".into(),
                level: GateLevel::Community,
                subject: context.subject.into(),
                provider: "clbs".into(),
                valid_until: context.now,
            }),
            gates,
        })
    }

    /// Remove one reusable fact after a trusted provider revocation. Authorization
    /// belongs to the service. Single-use tombstones are deliberately retained.
    pub async fn withdraw(&self, subject: &str, gate: &str, provider: &str) -> Result<()> {
        self.store.remove(subject, gate, provider).await
    }

    async fn preflight(&self, context: Context<'_>) -> Result<()> {
        context.validate(self.store.community())?;
        self.legal.check(context).await
    }

    async fn current(&self, context: Context<'_>) -> Result<Vec<GateResult>> {
        let mut current = Vec::new();
        for result in self.store.load(context.subject).await? {
            result.validate().map_err(|_| Error::Storage)?;
            if result.subject != context.subject || result.level != GateLevel::Community {
                return Err(Error::Storage);
            }
            let descriptor = Descriptor {
                gate: result.gate.clone(),
                provider: result.provider.clone(),
                level: result.level,
                steps: Vec::new(),
            };
            if result.valid_until > context.now && descriptor.enabled(context.snapshot) {
                current.push(result);
            }
        }
        Ok(current)
    }
}
