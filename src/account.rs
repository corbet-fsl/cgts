//! The single configured Balance service, executed outside the async executor.
use crate::{Error, Result};
use cblc::{accounting::AccountProofVerifier, accounting_service::AccountService};
use std::sync::{Arc, mpsc};

mod host;
pub use host::{HostRequest, HostResponse};
mod shutdown;
pub use shutdown::AccountShutdown;

pub use cblc::accounting_service::{AccountServiceRequest, AccountServiceResponse};

trait Service: Send {
    fn host(&mut self, request: HostRequest) -> std::result::Result<HostResponse, cblc::Error>;
    fn handle(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
    ) -> std::result::Result<AccountServiceResponse, cblc::Error>;
}

impl<V, C> Service for AccountService<V, C>
where
    V: AccountProofVerifier + Send,
    C: Fn() -> u64 + Send,
{
    fn host(&mut self, request: HostRequest) -> std::result::Result<HostResponse, cblc::Error> {
        match request {
            HostRequest::ReconcileAdmissionKeys(request) => self
                .reconcile_admission_keys(request)
                .map(HostResponse::AdmissionKeys),
            HostRequest::VerifyPinChange(request) => {
                request.verify(self).map(HostResponse::VerifiedPinChange)
            }
            HostRequest::PublishRecord {
                revision,
                policy_epoch,
                period_seconds,
            } => {
                let publication = self.publish_record_epoch(policy_epoch, period_seconds)?;
                let material = self.public_verifier_material(revision, policy_epoch)?;
                if material.record_epoch.as_ref() != Some(publication.descriptor()) {
                    return Err(cblc::Error::PolicyMismatch);
                }
                Ok(HostResponse::Record {
                    publication,
                    material,
                })
            }
            HostRequest::VerifierMaterial {
                revision,
                policy_epoch,
            } => self
                .public_verifier_material(revision, policy_epoch)
                .map(HostResponse::VerifierMaterial),
            HostRequest::VerifiedCheckpoint { slot, root } => {
                self.publish_verified_checkpoint(slot, root)?;
                Ok(HostResponse::Checkpoint)
            }
            HostRequest::TuneWaiting {
                expected_revision,
                seconds,
            } => self
                .tune_waiting_period(expected_revision, seconds)
                .map(HostResponse::WaitingPeriod),
            HostRequest::SettleBatch(batch) => {
                self.deposit_batch(&batch)?;
                Ok(HostResponse::Settled)
            }
        }
    }

    fn handle(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
    ) -> std::result::Result<AccountServiceResponse, cblc::Error> {
        self.handle_for_member(pseudonym, request)
    }
}

type Command = Box<dyn FnOnce(&mut dyn Service) + Send>;

pub(crate) struct Accounts {
    shutdown: AccountShutdown,
}

impl Accounts {
    pub(crate) fn new<V, C>(service: AccountService<V, C>) -> Result<Self>
    where
        V: AccountProofVerifier + Send + 'static,
        C: Fn() -> u64 + Send + 'static,
    {
        Self::start(service, None)
    }

    pub(crate) fn native<C>(
        service: AccountService<cblc::accounting_service::NativeAccountVerifier, C>,
    ) -> Result<Self>
    where
        C: Fn() -> u64 + Send + 'static,
    {
        let cancellation = service.cancellation();
        Self::start(service, Some(cancellation))
    }

    fn start<V, C>(
        mut service: AccountService<V, C>,
        cancellation: Option<cblc::accounting_service::NativeAccountCancellation>,
    ) -> Result<Self>
    where
        V: AccountProofVerifier + Send + 'static,
        C: Fn() -> u64 + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel::<Command>();
        let state = Arc::new(shutdown::State::default());
        // Balance's original native store owns its runtime. Both all operations
        // and its final drop belong outside the async executor. A single worker
        // owns that exact service; no parallel ledger or state copy is created.
        let worker = std::thread::Builder::new()
            .name("balance-service".into())
            .spawn(move || {
                for command in receiver {
                    command(&mut service);
                }
            })
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            shutdown: AccountShutdown::new(sender, worker, cancellation, state),
        })
    }

    pub(crate) fn shutdown(&self) -> AccountShutdown {
        self.shutdown.clone()
    }

    pub(crate) async fn handle<H: Send + 'static>(
        &self,
        pseudonym: [u8; 48],
        request: AccountServiceRequest,
        authority: H,
    ) -> Result<AccountServiceResponse> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let state = self.shutdown.state();
        self.shutdown.send(Box::new(move |service| {
            // Actual owner leases survive caller cancellation and remain
            // held until the original service has finished its operation.
            let _authority = authority;
            let result = if state.closed() {
                Err(Error::Storage)
            } else {
                service.handle(&pseudonym, request).map_err(Error::Account)
            };
            let result = if state.closed() {
                Err(Error::Storage)
            } else {
                result
            };
            let _ = reply.send(result);
        }))?;
        // If the worker panics, its receiver drops and permanently fences this
        // service. Pending and future calls fail; there is no reconstruction.
        response.await.map_err(|_| Error::Storage)?
    }
}

impl Drop for Accounts {
    fn drop(&mut self) {
        let _ = self.shutdown.begin_shutdown();
    }
}
