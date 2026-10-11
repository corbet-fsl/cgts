//! Privileged typed owner commands. These are never member wire DTOs.
use super::*;

/// Host configuration and settlement only; no deserializer or signing callback.
/// The host independently authenticates common roots, operators and input batches.
pub enum HostRequest {
    /// Produce one original epoch object and corresponding actual verifier material.
    PublishRecord {
        /// Current Policy-supplied publication counter.
        revision: u64,
        /// Current authenticated community policy epoch.
        policy_epoch: u64,
        /// Explicit configured period, never a descriptor-derived default.
        period_seconds: u64,
    },
    /// Bootstrap actual owner material; absent record epoch remains explicitly absent.
    VerifierMaterial { revision: u64, policy_epoch: u64 },
    /// Install an independently verified common enrollment checkpoint.
    VerifiedCheckpoint { slot: u64, root: [u8; 32] },
    /// Update only the original host-authorized waiting-period setting.
    TuneWaiting {
        /// Exact previously observed tuning revision.
        expected_revision: u64,
        /// Explicit host-authorized waiting duration.
        seconds: u64,
    },
    /// Original delayed anonymous batch, with unchanged native proof/CAS rules.
    SettleBatch(Vec<(cblc::extensions::Deposit, Vec<u8>)>),
}

/// Data from the same native owner. Publication data becomes authenticated only
/// after the actual caller Policy signer and Beacon publish it under their lease.
pub enum HostResponse {
    /// Original publication object and matching actual native material.
    Record {
        /// Original common encrypted object and descriptor.
        publication: cblc::accounting_ledger::record_epoch::RecordEpochPublication,
        /// Material projected by that same native ledger owner.
        material: cblc::publication::PublicVerifierMaterial,
    },
    /// Actual bootstrap material; absent epoch confers no G2 authority.
    VerifierMaterial(cblc::publication::PublicVerifierMaterial),
    /// Original verified checkpoint operation completed.
    Checkpoint,
    /// Actual durable waiting configuration after native commit.
    WaitingPeriod(cblc::accounting_ledger::WaitingPeriodTuning),
    /// Original batch completed; uncertain outcomes return an error instead.
    Settled,
}

impl Accounts {
    pub(crate) async fn host<H: Send + 'static>(
        &self,
        request: HostRequest,
        authority: H,
    ) -> Result<(HostResponse, H)> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.0
            .send(Box::new(move |service| {
                let result = service
                    .host(request)
                    .map_err(Error::Account)
                    .map(|result| (result, authority));
                // Success returns the same guard for Policy/Beacon completion. If
                // the caller cancelled, its guard drops here after native work.
                let _ = reply.send(result);
            }))
            .map_err(|_| Error::Storage)?;
        response.await.map_err(|_| Error::Storage)?
    }
}
