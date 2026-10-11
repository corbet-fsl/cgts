//! Join coordination only; no native verifier or accepting authority exists here.
use super::*;

#[tokio::test]
async fn failed_join_start_notifies_original_waiters_and_retry_waits_for_actual_join() {
    let (sender, receiver) = mpsc::channel::<Command>();
    let (release, resume) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        drop(receiver);
        resume.recv().unwrap();
    });
    let owner = AccountShutdown::new(sender, worker, None, Arc::new(State::default()));
    let (failed, start) = owner.0.attempt();
    assert!(start);
    let (concurrent, start) = owner.0.attempt();
    assert!(!start);
    assert!(Arc::ptr_eq(&failed, &concurrent));
    let mut waiter = concurrent.0.subscribe();
    // Exercise exactly the production OS-spawn-failure notification, without
    // exhausting host resources or introducing a synthetic native verdict.
    failed.0.send_replace(Completion::StartFailed);
    waiter.changed().await.unwrap();
    assert!(matches!(*waiter.borrow(), Completion::StartFailed));
    assert!(owner.0.join.lock().unwrap().worker.is_some());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), owner.shutdown())
            .await
            .is_err()
    );
    let (retry, start) = owner.0.attempt();
    assert!(!start);
    assert!(!Arc::ptr_eq(&failed, &retry));
    assert!(matches!(*retry.0.borrow(), Completion::Pending));
    assert!(matches!(*waiter.borrow(), Completion::StartFailed));
    release.send(()).unwrap();
    owner.shutdown().await.unwrap();
    assert!(matches!(*retry.0.borrow(), Completion::Joined(true)));
    assert!(matches!(*waiter.borrow(), Completion::StartFailed));
}
