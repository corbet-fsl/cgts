//! The configured common producer and native ledger share one command worker.
use super::*;
use cblc::enrollment::{
    AccountingDelegation, EnrollmentEntry, EnrollmentService, ExpectedAdmission,
};

/// Owned independently current host expectations for a queued enrollment cut.
/// These fields are data; the mandatory real CommitAuthority supplies currentness.
#[derive(Clone)]
pub struct EnrollmentExpected {
    /// Actual configured digest and independently authenticated Policy ring.
    pub trust: cblc::admission::AdmissionTrust,
    /// Effective epoch from the held Policy owner.
    pub policy_epoch: u64,
    /// Exact authenticated global passport cohort from that same owner.
    pub passport_policy_digest: String,
}
impl EnrollmentExpected {
    fn borrowed(&self) -> ExpectedAdmission<'_> {
        ExpectedAdmission {
            trust: &self.trust,
            policy_epoch: self.policy_epoch,
            passport_policy_digest: &self.passport_policy_digest,
        }
    }
}

struct Combined<V: AccountProofVerifier, C: Fn() -> u64, E: Fn() -> u64> {
    ledger: AccountService<V, C>,
    enrollment: EnrollmentService<E>,
}
impl<V, C, E> Service for Combined<V, C, E>
where
    V: AccountProofVerifier + Send,
    C: Fn() -> u64 + Send,
    E: Fn() -> u64 + Send,
{
    fn enroll(
        &mut self,
        pseudonym: &[u8; 48],
        delegation: AccountingDelegation,
        expected: EnrollmentExpected,
        authority: Arc<dyn cblc::storage::CommitAuthority>,
    ) -> std::result::Result<EnrollmentEntry, cblc::Error> {
        self.enrollment
            .enroll_for_member(pseudonym, &delegation, expected.borrowed(), authority)
    }
    fn host(&mut self, request: HostRequest) -> std::result::Result<HostResponse, cblc::Error> {
        match request {
            HostRequest::PrepareCheckpoint {
                expected,
                authority,
            } => self
                .enrollment
                .prepare_checkpoint(expected.borrowed(), authority)
                .map(HostResponse::PendingCheckpoint),
            HostRequest::InstallCheckpoint { pending, authority } => self
                .ledger
                .publish_pending_checkpoint(pending, authority)
                .map(HostResponse::InstalledCheckpoint),
            HostRequest::AcknowledgeCheckpoint(installed) => self
                .enrollment
                .acknowledge(installed)
                .map(|publication| HostResponse::EnrollmentCheckpoint(Some(publication))),
            HostRequest::EnrollmentCheckpoint { slot } => self
                .enrollment
                .checkpoint(slot)
                .map(HostResponse::EnrollmentCheckpoint),
            other => Service::host(&mut self.ledger, other),
        }
    }
    fn handle(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
    ) -> std::result::Result<AccountServiceResponse, cblc::Error> {
        Service::handle(&mut self.ledger, pseudonym, request)
    }
    fn handle_authorized(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
        authority: Arc<dyn cblc::storage::CommitAuthority>,
    ) -> std::result::Result<AccountServiceResponse, cblc::Error> {
        Service::handle_authorized(&mut self.ledger, pseudonym, request, authority)
    }
}

impl Accounts {
    pub(crate) fn with_enrollment<V, C, E>(
        ledger: AccountService<V, C>,
        enrollment: EnrollmentService<E>,
    ) -> Result<Self>
    where
        V: AccountProofVerifier + Send + 'static,
        C: Fn() -> u64 + Send + 'static,
        E: Fn() -> u64 + Send + 'static,
    {
        Self::start(Combined { ledger, enrollment }, None)
    }
    pub(crate) fn native_with_enrollment<C, E>(
        ledger: AccountService<cblc::accounting_service::NativeAccountVerifier, C>,
        enrollment: EnrollmentService<E>,
    ) -> Result<Self>
    where
        C: Fn() -> u64 + Send + 'static,
        E: Fn() -> u64 + Send + 'static,
    {
        let cancellation = ledger.cancellation();
        Self::start(Combined { ledger, enrollment }, Some(cancellation))
    }
    pub(crate) async fn enroll(
        &self,
        pseudonym: [u8; 48],
        delegation: AccountingDelegation,
        expected: EnrollmentExpected,
        authority: Arc<dyn cblc::storage::CommitAuthority>,
    ) -> Result<EnrollmentEntry> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let state = self.shutdown.state();
        self.shutdown.send(Box::new(move |service| {
            let result = if state.closed() {
                Err(Error::Storage)
            } else {
                service
                    .enroll(&pseudonym, delegation, expected, authority)
                    .map_err(Error::Account)
            };
            let result = if state.closed() {
                Err(Error::Storage)
            } else {
                result
            };
            let _ = reply.send(result);
        }))?;
        response.await.map_err(|_| Error::Storage)?
    }
}
