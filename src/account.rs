//! The single configured Balance service, executed outside the async executor.
use crate::{Error, Result};
use cblc::{accounting::AccountProofVerifier, accounting_service::AccountService};
use std::sync::mpsc;

pub use cblc::accounting_service::{AccountServiceRequest, AccountServiceResponse};

trait Service: Send {
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
    fn handle(
        &mut self,
        pseudonym: &[u8; 48],
        request: AccountServiceRequest,
    ) -> std::result::Result<AccountServiceResponse, cblc::Error> {
        self.handle_for_member(pseudonym, request)
    }
}

type Command = Box<dyn FnOnce(&mut dyn Service) + Send>;

pub(crate) struct Accounts(mpsc::Sender<Command>);

impl Accounts {
    pub(crate) fn new<V, C>(mut service: AccountService<V, C>) -> Result<Self>
    where
        V: AccountProofVerifier + Send + 'static,
        C: Fn() -> u64 + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel::<Command>();
        // Balance's original native store owns its runtime. Both all operations
        // and its final drop belong outside the async executor. A single worker
        // owns that exact service; no parallel ledger or state copy is created.
        std::thread::Builder::new()
            .name("balance-service".into())
            .spawn(move || {
                for command in receiver {
                    command(&mut service);
                }
            })
            .map_err(|_| Error::Storage)?;
        Ok(Self(sender))
    }

    pub(crate) async fn handle<H: Send + 'static>(
        &self,
        pseudonym: [u8; 48],
        request: AccountServiceRequest,
        authority: H,
    ) -> Result<AccountServiceResponse> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.0
            .send(Box::new(move |service| {
                // Actual owner leases survive caller cancellation and remain
                // held until the original service has finished its operation.
                let _authority = authority;
                let result = service.handle(&pseudonym, request).map_err(Error::Account);
                let _ = reply.send(result);
            }))
            .map_err(|_| Error::Storage)?;
        // If the worker panics, its receiver drops and permanently fences this
        // service. Pending and future calls fail; there is no reconstruction.
        response.await.map_err(|_| Error::Storage)?
    }
}
