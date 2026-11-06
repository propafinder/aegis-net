use super::*;

fn fixture_admission(
    unauthenticated: &Arc<Semaphore>,
    established: &Arc<Semaphore>,
    deadline: tokio::time::Instant,
) -> QuicAdmission {
    QuicAdmission {
        deadline,
        unauthenticated_permit: Some(unauthenticated.clone().try_acquire_owned().unwrap()),
        established: established.clone(),
        established_permit: None,
        authenticated: Arc::new(AtomicBool::new(false)),
    }
}

#[test]
fn unlimited_established_configuration_still_bounds_quic_admission() {
    assert_eq!(quic_unauthenticated_limit(0), 64);
    assert_eq!(quic_unauthenticated_limit(1), 1);
    assert_eq!(quic_unauthenticated_limit(1000), 64);
}

#[tokio::test]
async fn promotion_releases_admission_and_owns_established_capacity() {
    let unauthenticated = Arc::new(Semaphore::new(2));
    let established = Arc::new(Semaphore::new(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut admission = fixture_admission(&unauthenticated, &established, deadline);
    assert_eq!(unauthenticated.available_permits(), 1);
    assert_eq!(established.available_permits(), 1);
    admission.promote().unwrap();
    assert_eq!(unauthenticated.available_permits(), 2);
    assert_eq!(established.available_permits(), 0);
    assert!(admission.authenticated.load(Ordering::Acquire));
    drop(admission);
    assert_eq!(established.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn expired_credential_cannot_promote_even_when_capacity_is_free() {
    let unauthenticated = Arc::new(Semaphore::new(1));
    let established = Arc::new(Semaphore::new(1));
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let mut admission = fixture_admission(&unauthenticated, &established, deadline);
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(admission.promote().is_err());
    assert!(!admission.authenticated.load(Ordering::Acquire));
    assert_eq!(established.available_permits(), 1);
    drop(admission);
    assert_eq!(unauthenticated.available_permits(), 1);
}

#[tokio::test]
async fn established_saturation_does_not_wait_or_release_unowned_capacity() {
    let unauthenticated = Arc::new(Semaphore::new(1));
    let established = Arc::new(Semaphore::new(1));
    let active_session = established.clone().try_acquire_owned().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut admission = fixture_admission(&unauthenticated, &established, deadline);
    assert!(admission.promote().is_err());
    assert!(!admission.authenticated.load(Ordering::Acquire));
    drop(admission);
    assert_eq!(unauthenticated.available_permits(), 1);
    assert_eq!(established.available_permits(), 0);
    drop(active_session);
    assert_eq!(established.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn later_ingress_steps_use_the_original_clock_and_return_the_slot() {
    let unauthenticated = Arc::new(Semaphore::new(1));
    let established = Arc::new(Semaphore::new(1));
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_millis(100);
    let admission = fixture_admission(&unauthenticated, &established, deadline);
    let flag = admission.authenticated.clone();
    let result = await_quic_admitted_session(
        async move {
            let _admission = admission;
            tokio::time::sleep(Duration::from_millis(70)).await;
            tokio::time::sleep(Duration::from_millis(70)).await;
        },
        deadline,
        flag,
    )
    .await;
    assert!(result.is_err());
    let elapsed = tokio::time::Instant::now() - start;
    assert!(elapsed >= Duration::from_millis(100));
    assert!(
        elapsed < Duration::from_millis(140),
        "later steps cannot renew the budget"
    );
    assert_eq!(unauthenticated.available_permits(), 1);
    assert_eq!(established.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn admitted_session_retains_capacity_and_outlives_the_read_deadline() {
    let unauthenticated = Arc::new(Semaphore::new(1));
    let established = Arc::new(Semaphore::new(1));
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let mut admission = fixture_admission(&unauthenticated, &established, deadline);
    let flag = admission.authenticated.clone();
    let available = established.clone();
    await_quic_admitted_session(
        async move {
            tokio::time::sleep(Duration::from_millis(70)).await;
            admission.promote().unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(available.available_permits(), 0);
            drop(admission);
        },
        deadline,
        flag,
    )
    .await
    .expect("authenticated session keeps its original lifetime policy");
    assert_eq!(unauthenticated.available_permits(), 1);
    assert_eq!(established.available_permits(), 1);
}

#[tokio::test]
async fn cancelled_admission_releases_only_its_owned_slot() {
    let unauthenticated = Arc::new(Semaphore::new(1));
    let established = Arc::new(Semaphore::new(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let admission = fixture_admission(&unauthenticated, &established, deadline);
    let flag = admission.authenticated.clone();
    let mut future = Box::pin(await_quic_admitted_session(
        async move {
            let _admission = admission;
            std::future::pending::<()>().await;
        },
        deadline,
        flag,
    ));
    assert!(futures::poll!(future.as_mut()).is_pending());
    drop(future);
    assert_eq!(unauthenticated.available_permits(), 1);
    assert_eq!(established.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn queued_admission_refuses_before_first_session_poll_at_or_after_expiry() {
    // The outer future is deliberately not polled until the original cutoff.
    // Exact-boundary and already-expired workers must both drop their ownership
    // without entering Incoming conversion/TLS work, represented by the counter.
    for first_poll_after_ms in [100, 101] {
        let unauthenticated = Arc::new(Semaphore::new(1));
        let established = Arc::new(Semaphore::new(1));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let admission = fixture_admission(&unauthenticated, &established, deadline);
        let flag = admission.authenticated.clone();
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let session_entered = entered.clone();
        let unpolled = await_quic_admitted_session(
            async move {
                let _admission = admission;
                session_entered.fetch_add(1, Ordering::Relaxed);
                std::future::pending::<()>().await;
            },
            deadline,
            flag,
        );
        assert_eq!(unauthenticated.available_permits(), 0);
        assert_eq!(established.available_permits(), 1);
        tokio::time::advance(Duration::from_millis(first_poll_after_ms)).await;
        assert_eq!(
            entered.load(Ordering::Relaxed),
            0,
            "fixture remained unpolled"
        );
        assert!(
            unpolled.await.is_err(),
            "expired queued admission is refused"
        );
        assert_eq!(
            entered.load(Ordering::Relaxed),
            0,
            "expired admission must not poll the session or initiate TLS"
        );
        assert_eq!(unauthenticated.available_permits(), 1);
        assert_eq!(established.available_permits(), 1);
    }
}
