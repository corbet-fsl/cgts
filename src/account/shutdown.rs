//! Host-owned service teardown. Completion means the actual worker was joined.
use super::*;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

#[derive(Default)]
pub(super) struct State(AtomicBool);
impl State {
    pub(super) fn closed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct Inner {
    state: Arc<State>,
    sender: Mutex<Option<mpsc::Sender<Command>>>,
    join: Mutex<Join>,
    cancellation: Option<cblc::accounting_service::NativeAccountCancellation>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Pending,
    StartFailed,
    Joined(bool),
}
struct Attempt(tokio::sync::watch::Sender<Completion>);
struct Join {
    worker: Option<JoinHandle<()>>,
    attempt: Option<Arc<Attempt>>,
}

/// Retain outside member/Policy/Community locks. Shutdown fences new work and
/// joins the one original service before its storage/runtime may be torn down.
/// Native construction also cancels its actual proof workers; generic services
/// drain without claiming preemption. This type is never a member wire input.
#[derive(Clone)]
#[must_use = "retain and await the shutdown handle before host runtime teardown"]
pub struct AccountShutdown(Arc<Inner>);
impl AccountShutdown {
    pub(super) fn new(
        sender: mpsc::Sender<Command>,
        worker: JoinHandle<()>,
        cancellation: Option<cblc::accounting_service::NativeAccountCancellation>,
        state: Arc<State>,
    ) -> Self {
        Self(Arc::new(Inner {
            state,
            sender: Mutex::new(Some(sender)),
            join: Mutex::new(Join {
                worker: Some(worker),
                attempt: None,
            }),
            cancellation,
        }))
    }
    pub(super) fn state(&self) -> Arc<State> {
        self.0.state.clone()
    }
    pub(super) fn send(&self, command: Command) -> Result<()> {
        let sender = self.0.sender.lock().map_err(|_| Error::Storage)?;
        if self.0.state.closed() {
            return Err(Error::Storage);
        }
        sender
            .as_ref()
            .ok_or(Error::Storage)?
            .send(command)
            .map_err(|_| Error::Storage)
    }
    /// Start the shared join attempt without blocking an async reactor. This
    /// also fences submissions and cancels actual native proof execution.
    /// Success reports initiation only: the host must still await `shutdown`
    /// before runtime teardown. A failed start retains the worker for retry.
    pub fn begin_shutdown(&self) -> Result<()> {
        let attempt = self.begin();
        let completion = *attempt.0.borrow();
        match completion {
            Completion::StartFailed | Completion::Joined(false) => Err(Error::Storage),
            Completion::Pending | Completion::Joined(true) => Ok(()),
        }
    }
    /// Irreversibly fence submissions, cancel actual native proof execution,
    /// and await service final drop plus its thread join. Caller cancellation
    /// cannot abandon that join; concurrent waiters observe the same outcome.
    /// This is mandatory cleanup, not a hard operating-system time guarantee.
    pub async fn shutdown(&self) -> Result<()> {
        let attempt = self.begin();
        let mut completed = attempt.0.subscribe();
        loop {
            match *completed.borrow_and_update() {
                Completion::Joined(true) => return Ok(()),
                Completion::Joined(false) | Completion::StartFailed => return Err(Error::Storage),
                Completion::Pending => {}
            }
            completed.changed().await.map_err(|_| Error::Storage)?;
        }
    }
    fn begin(&self) -> Arc<Attempt> {
        self.0.fence();
        let (attempt, start) = self.0.attempt();
        if start {
            let inner = self.0.clone();
            let finishing = attempt.clone();
            // The join belongs outside the async runtime whose lifetime it
            // protects. A cancelled async waiter leaves this owner running.
            if std::thread::Builder::new()
                .name("balance-service-join".into())
                .spawn(move || {
                    let worker = inner
                        .join
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .worker
                        .take();
                    let joined = worker.is_some_and(|worker| worker.join().is_ok());
                    finishing.0.send_replace(Completion::Joined(joined));
                })
                .is_err()
            {
                // Existing waiters retain this failed attempt. A retry gets a
                // new one; it cannot erase their error or imply an actual join.
                attempt.0.send_replace(Completion::StartFailed);
            }
        }
        attempt
    }
}
impl Inner {
    fn attempt(&self) -> (Arc<Attempt>, bool) {
        let mut join = self
            .join
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(attempt) = &join.attempt
            && *attempt.0.borrow() != Completion::StartFailed
        {
            return (attempt.clone(), false);
        }
        let (completed, _) = tokio::sync::watch::channel(Completion::Pending);
        let attempt = Arc::new(Attempt(completed));
        join.attempt = Some(attempt.clone());
        (attempt, true)
    }
    fn fence(&self) {
        self.state.0.store(true, Ordering::Release);
        let sender = self
            .sender
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        drop(sender);
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.fence();
        // Drop cannot block the reactor that an in-flight storage operation may
        // need. Hosts retain an external handle and explicitly await shutdown on
        // every success/error path; Drop alone never reports joined completion.
    }
}

#[cfg(test)]
#[path = "../../tests/internal/account_shutdown.rs"]
mod tests;
