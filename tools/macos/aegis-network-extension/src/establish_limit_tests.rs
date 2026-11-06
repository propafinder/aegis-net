//! EstablishLimiter (B-06 S16g): the cap, the ACK reserve and priority, the
//! bounded wait, the authentication backoff and the refusal classes.
use super::*;
use std::{future::Future, pin::Pin, task::Poll};

const LONG: Duration = Duration::from_secs(5);
const SHORT: Duration = Duration::from_millis(30);

/// Poll `future` once; Some when it finished.
async fn poll_once<F: Future + Unpin>(future: &mut F) -> Option<F::Output> {
    std::future::poll_fn(|cx| match Pin::new(&mut *future).poll(cx) {
        Poll::Ready(output) => Poll::Ready(Some(output)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

/// Let other tasks run for a moment.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn flows_never_take_the_ack_reserve_and_the_total_is_capped() {
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    // S16j-4: flows take at most 16 of 20 permits, the pool's 4
    // connections of 4 handshakes each; S16k: the ACK reserve is 4, two
    // pre-warm slots and two requests in flight.
    assert_eq!((ESTABLISH_PERMITS, ACK_RESERVE), (20, 4));
    assert_eq!(ESTABLISH_PERMITS - ACK_RESERVE, 16);
    assert_eq!(FLOW_PERMITS, 16);
    assert_eq!(
        FLOW_PERMITS,
        crate::flow_pool::POOL_CONNS * crate::flow_pool::H_CONN
    );
    assert_eq!(
        ACK_RESERVE,
        crate::provider_session_body::PREWARM_SLOTS + crate::provider_session_body::ACK_IN_FLIGHT
    );
    let mut held = Vec::new();
    for _ in 0..ESTABLISH_PERMITS - ACK_RESERVE {
        held.push(limiter.acquire(Purpose::Flow, SHORT).await.unwrap());
    }
    assert!(limiter.flows_establishing());
    // One more flow finds no permit within its budget and is refused.
    let started = Instant::now();
    let refused = limiter.acquire(Purpose::Flow, SHORT).await.unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= SHORT);
    assert!(started.elapsed() < LONG);
    assert_eq!(limiter.flow_timeouts(), 1);
    // The reserve stays for the ACK path, and nothing more.
    for _ in 0..ACK_RESERVE {
        held.push(limiter.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    assert_eq!(
        limiter.active(),
        (ACK_RESERVE, ESTABLISH_PERMITS - ACK_RESERVE)
    );
    assert!(limiter.acquire(Purpose::Ack, SHORT).await.is_err());
    assert_eq!(limiter.high_water(), ESTABLISH_PERMITS);
    // Every permit returns on drop.
    held.clear();
    assert_eq!(limiter.active(), (0, 0));
    assert!(!limiter.flows_establishing());
    // With no flows the ACK path may use every permit.
    for _ in 0..ESTABLISH_PERMITS {
        held.push(limiter.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
}

#[tokio::test]
async fn a_waiting_ack_establishment_goes_before_every_waiting_flow() {
    let limiter = EstablishLimiter::for_test(3, 1, AUTH_BACKOFF);
    let flow_a = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    let _flow_b = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    let _ack = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    // Full: a flow queues first, an ACK-path establishment after it.
    let mut flow = Box::pin(limiter.acquire(Purpose::Flow, LONG));
    assert!(poll_once(&mut flow).await.is_none());
    let mut ack = Box::pin(limiter.acquire(Purpose::Ack, LONG));
    assert!(poll_once(&mut ack).await.is_none());
    // A flow permit returns: the ACK waiter takes it, although the flow
    // waited longer and flows are under their own cap.
    drop(flow_a);
    // Polled first, the flow still finds the freed permit kept for the ACK.
    assert!(poll_once(&mut flow).await.is_none());
    let ack_permit = tokio::time::timeout(Duration::from_secs(1), &mut ack)
        .await
        .expect("the ACK waiter never got the released permit")
        .unwrap();
    assert!(poll_once(&mut flow).await.is_none());
    // Once no ACK waits, the flow gets the next permit.
    drop(ack_permit);
    let flow_permit = tokio::time::timeout(Duration::from_secs(1), &mut flow)
        .await
        .expect("the flow never got a permit")
        .unwrap();
    assert_eq!(limiter.active(), (1, 2));
    drop(flow_permit);
}

#[tokio::test]
async fn a_cancelled_wait_leaves_the_queue() {
    let limiter = EstablishLimiter::for_test(2, 1, AUTH_BACKOFF);
    let _ack = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    let flow = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    // An ACK waiter that is dropped no longer holds flows back.
    let mut ack = Box::pin(limiter.acquire(Purpose::Ack, LONG));
    assert!(poll_once(&mut ack).await.is_none());
    drop(ack);
    drop(flow);
    let _flow = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    // A dropped flow waiter no longer counts as establishing.
    drop(_flow);
    let _flow = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    let mut waiting = Box::pin(limiter.acquire(Purpose::Flow, LONG));
    assert!(poll_once(&mut waiting).await.is_none());
    drop(_flow);
    drop(waiting);
    assert!(!limiter.flows_establishing());
}

#[tokio::test]
async fn an_auth_failure_backs_every_establishment_off() {
    let backoff = Duration::from_millis(300);
    let limiter = EstablishLimiter::for_test(6, 2, backoff);
    let permit = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    limiter.judge(Purpose::Flow, &auth_refused());
    assert_eq!(limiter.auth_failures(), 1);
    assert!(limiter.backing_off());
    drop(permit);
    // Neither class starts within the backoff, however many permits are free.
    for purpose in [Purpose::Ack, Purpose::Flow] {
        assert!(
            limiter.acquire(purpose, SHORT).await.is_err(),
            "{purpose:?}"
        );
    }
    let failed = Instant::now();
    let permit = limiter.acquire(Purpose::Ack, LONG).await.unwrap();
    // The 30 ms waits above ran inside the 300 ms backoff.
    assert!(failed.elapsed() >= backoff - 2 * SHORT - Duration::from_millis(20));
    assert!(!limiter.backing_off());
    drop(permit);
    // Another refusal is not authentication class: no backoff.
    let other = io::Error::new(io::ErrorKind::PermissionDenied, "prepared crypto refused");
    limiter.judge(Purpose::Flow, &other);
    assert_eq!(limiter.auth_failures(), 1);
    assert!(!limiter.backing_off());
    let _ = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
}

#[tokio::test]
async fn the_production_backoff_is_at_least_two_seconds() {
    assert!(AUTH_BACKOFF >= Duration::from_secs(2));
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    limiter.auth_failure(Purpose::Ack);
    let failed = Instant::now();
    let permit = limiter.acquire(Purpose::Flow, LONG).await.unwrap();
    assert!(
        failed.elapsed() >= Duration::from_millis(1_990),
        "{:?}",
        failed.elapsed()
    );
    drop(permit);
}

#[tokio::test]
async fn the_backoff_carries_to_a_rebuilt_session_of_the_epoch() {
    let epoch = AuthBackoff::default();
    let backoff = Duration::from_millis(200);
    let lost = EstablishLimiter::with_limits(6, 2, backoff, epoch.clone());
    lost.auth_failure(Purpose::Ack);
    drop(lost);
    let rebuilt = EstablishLimiter::with_limits(6, 2, backoff, epoch);
    assert!(rebuilt.backing_off());
    assert!(rebuilt.acquire(Purpose::Ack, SHORT).await.is_err());
    // A session of another epoch is not held back.
    let other = EstablishLimiter::with_limits(6, 2, backoff, AuthBackoff::default());
    let _ = other.acquire(Purpose::Ack, SHORT).await.unwrap();
}

#[tokio::test]
async fn queueing_is_logged_at_most_once_per_interval() {
    let limiter = EstablishLimiter::for_test(1, 0, AUTH_BACKOFF);
    let held = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    let mut waiters = Vec::new();
    for _ in 0..16 {
        let mut waiter = Box::pin(limiter.acquire(Purpose::Flow, LONG));
        assert!(poll_once(&mut waiter).await.is_none());
        waiters.push(waiter);
    }
    assert_eq!(limiter.queue_logs(), 1);
    drop(waiters);
    drop(held);
    settle().await;
    assert!(!limiter.flows_establishing());
}

/// `error` as the held-crypto paths judge an anyhow error.
fn judged(error: &anyhow::Error) -> &(dyn StdError + 'static) {
    let error: &(dyn StdError + Send + Sync + 'static) = error.as_ref();
    error
}

#[test]
fn refusal_classes() {
    let alert = rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate);
    let wrapped = io::Error::new(io::ErrorKind::InvalidData, alert.clone());
    assert!(tls_failure(&alert));
    assert!(tls_failure(&wrapped));
    // A TLS error is authentication class at every step, however wrapped.
    assert!(handshake_auth_class(&wrapped));
    assert!(exchange_auth_class(&wrapped));
    assert!(!exchange_unanswered(&wrapped));
    let in_anyhow = anyhow::Error::from(io::Error::new(io::ErrorKind::InvalidData, alert.clone()))
        .context("outer");
    assert!(tls_failure(judged(&in_anyhow)));
    assert!(handshake_auth_class(judged(&in_anyhow)));
    // A TLS error under a reset is still a TLS error.
    let reset_alert = io::Error::new(
        io::ErrorKind::ConnectionReset,
        io::Error::new(io::ErrorKind::InvalidData, alert.clone()),
    );
    assert!(exchange_auth_class(&reset_alert));
    assert!(!exchange_unanswered(&reset_alert));
    // Every explicit carrier refusal aegis-client raises is authentication
    // class, with or without context; nothing else it raises as a message.
    for refusal in [
        "secure carrier rejected with HTTP 403 Forbidden",
        "invalid secure carrier content type",
        "secure carrier requires HTTP/2",
        "required ECH was not accepted by the relay (status=Rejected)",
    ] {
        let error = anyhow::anyhow!("{refusal}");
        assert!(handshake_auth_class(judged(&error)), "{refusal}");
        assert!(!tls_failure(judged(&error)), "{refusal}");
        let error = anyhow::anyhow!("{refusal}").context("held carrier");
        assert!(handshake_auth_class(judged(&error)), "{refusal}");
    }
    assert_eq!(CARRIER_REFUSALS.len(), 4);
    // Transport ends inside H2 are not: the driver ending before the carrier
    // response, an h2 error that hides its io error, any unknown message.
    for opaque in [
        "H2 driver ended before carrier response: Ok(())",
        "H2 driver ended before carrier response: Err(Error { kind: Io(Kind(BrokenPipe)) })",
        "connection error received: not a result of an error",
        "stream error received: refused stream before processing any application logic",
        "secure carrier",
    ] {
        let error = anyhow::anyhow!("{opaque}");
        assert!(!handshake_auth_class(judged(&error)), "{opaque}");
    }
    // Neither is a timeout, any transport drop, an H2 reset mapped to an
    // io error, or a local network error, at a handshake.
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
        io::ErrorKind::Other,
        io::ErrorKind::NetworkDown,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::AddrNotAvailable,
        io::ErrorKind::InvalidData,
    ] {
        let dropped = io::Error::from(kind);
        assert!(!handshake_auth_class(&dropped), "{kind:?}");
        assert!(!tls_failure(&dropped), "{kind:?}");
        assert!(!exchange_auth_class(&dropped), "{kind:?}");
        let in_anyhow = anyhow::Error::from(io::Error::from(kind)).context("connect");
        assert!(!handshake_auth_class(judged(&in_anyhow)), "{kind:?}");
    }
    // After the inner handshake, the relay ending the channel before the
    // Open status is an unanswered Open; a timeout or another error is not.
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
    ] {
        assert!(exchange_unanswered(&io::Error::from(kind)), "{kind:?}");
        let in_anyhow = anyhow::Error::from(io::Error::from(kind)).context("read status");
        assert!(exchange_unanswered(judged(&in_anyhow)), "{kind:?}");
    }
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::Other,
        io::ErrorKind::InvalidData,
    ] {
        assert!(!exchange_unanswered(&io::Error::from(kind)), "{kind:?}");
    }
    let late_drop = io::Error::new(
        io::ErrorKind::UnexpectedEof,
        io::Error::from(io::ErrorKind::TimedOut),
    );
    assert!(!exchange_unanswered(&late_drop));
    // A complete reply that is refused, or an elapsed deadline, is neither.
    let refused_ack = anyhow::anyhow!("policy ACK nonce mismatch");
    assert!(!exchange_auth_class(judged(&refused_ack)));
    assert!(!exchange_unanswered(judged(&refused_ack)));
    let elapsed_read = rt_elapsed();
    assert!(!exchange_auth_class(judged(&elapsed_read)));
    assert!(!exchange_unanswered(judged(&elapsed_read)));
    let elapsed = rt_elapsed().context("held carrier connect deadline exhausted");
    assert!(!handshake_auth_class(judged(&elapsed)));
    // Only the typed refusals are judged, each as its own class.
    assert!(is_auth_refused(&auth_refused()));
    assert!(!is_open_unanswered(&auth_refused()));
    assert!(is_open_unanswered(&open_unanswered()));
    assert!(!is_auth_refused(&open_unanswered()));
    for typed in [auth_refused(), open_unanswered()] {
        assert_eq!(typed.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(typed.to_string(), "prepared crypto refused");
    }
    let plain = io::Error::new(io::ErrorKind::PermissionDenied, "prepared crypto refused");
    assert!(!is_auth_refused(&plain));
    assert!(!is_open_unanswered(&plain));
    assert!(!is_auth_refused(&wrapped));
}

/// A real tokio timeout error, wrapped as anyhow wraps it.
fn rt_elapsed() -> anyhow::Error {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let elapsed = runtime
        .block_on(async {
            tokio::time::timeout(Duration::ZERO, std::future::pending::<()>()).await
        })
        .unwrap_err();
    anyhow::Error::from(elapsed)
}

#[tokio::test]
async fn after_the_backoff_one_probe_per_purpose_runs_until_the_relay_answers_one() {
    let backoff = Duration::from_millis(100);
    let limiter = EstablishLimiter::for_test(6, 2, backoff);
    assert!(!limiter.probing());
    limiter.auth_failure(Purpose::Flow);
    assert!(limiter.probing());
    // The first flow after the backoff runs alone among flows...
    let probe = limiter.acquire(Purpose::Flow, LONG).await.unwrap();
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    // ...but never holds the ACK path back: one ACK-path probe beside it,
    // and no second one.
    let ack_probe = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    assert!(limiter.acquire(Purpose::Ack, SHORT).await.is_err());
    drop(ack_probe);
    // A flow probe past its Open request still counts until its status.
    let mut probe = probe;
    probe.request_written();
    assert_eq!((limiter.active(), limiter.unverified()), ((0, 0), 1));
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    // A probe that ends unanswered keeps establishments single.
    drop(probe);
    assert_eq!(limiter.unverified(), 0);
    let probe = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    let mut next = Box::pin(limiter.acquire(Purpose::Ack, LONG));
    assert!(poll_once(&mut next).await.is_none());
    // An answered probe lifts it: the waiter starts, and more beside it.
    probe.succeeded();
    assert!(!limiter.probing());
    let next = tokio::time::timeout(Duration::from_secs(1), next)
        .await
        .expect("the waiter never started after the verified probe")
        .unwrap();
    let beside = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    let flows = (
        limiter.acquire(Purpose::Flow, SHORT).await.unwrap(),
        limiter.acquire(Purpose::Flow, SHORT).await.unwrap(),
    );
    assert_eq!(limiter.active(), (2, 2));
    drop((beside, flows));
    // An establishment that began before a later failure was answered: it
    // proves nothing about that failure, so establishments stay single.
    limiter.auth_failure(Purpose::Flow);
    next.succeeded();
    assert!(limiter.probing());
    let probe = limiter.acquire(Purpose::Flow, LONG).await.unwrap();
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    probe.succeeded();
    assert!(!limiter.probing());
    // Probing carries to a rebuilt session of the epoch, as the backoff does.
    let epoch = AuthBackoff::default();
    let lost = EstablishLimiter::with_limits(6, 2, Duration::ZERO, epoch.clone());
    lost.auth_failure(Purpose::Ack);
    let rebuilt = EstablishLimiter::with_limits(6, 2, Duration::ZERO, epoch);
    assert!(rebuilt.probing());
    let first = rebuilt.acquire(Purpose::Ack, SHORT).await.unwrap();
    assert!(rebuilt.acquire(Purpose::Ack, SHORT).await.is_err());
    first.succeeded();
    assert!(!lost.probing());
}

#[tokio::test]
async fn an_unanswered_open_backs_off_flows_alone_and_then_probes_one_flow() {
    let mut limiter = EstablishLimiter::for_test(6, 2, AUTH_BACKOFF);
    let backoff = Duration::from_millis(300);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(backoff, FLOW_OPENS, LIVE_FLOWS);
    let permit = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    limiter.judge(Purpose::Flow, &open_unanswered());
    drop(permit);
    assert_eq!(limiter.flow_refusals(), 1);
    assert_eq!(limiter.auth_failures(), 0);
    // Not authentication class: the epoch neither backs off nor probes, and
    // the ACK path starts at once, several beside each other.
    assert!(!limiter.backing_off());
    assert!(!limiter.probing());
    assert!(limiter.flows_backing_off());
    let acks = (
        limiter.acquire(Purpose::Ack, Duration::ZERO).await.unwrap(),
        limiter.acquire(Purpose::Ack, Duration::ZERO).await.unwrap(),
    );
    // Flows wait out their backoff.
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    let failed = Instant::now();
    let probe = limiter.acquire(Purpose::Flow, LONG).await.unwrap();
    assert!(failed.elapsed() >= backoff - SHORT - Duration::from_millis(20));
    assert!(!limiter.flows_backing_off());
    // Then one flow at a time until a flow's status arrives.
    assert!(limiter.flows_probing());
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    let mut next = Box::pin(limiter.acquire(Purpose::Flow, LONG));
    assert!(poll_once(&mut next).await.is_none());
    probe.succeeded();
    assert!(!limiter.flows_probing());
    let next = tokio::time::timeout(Duration::from_secs(1), next)
        .await
        .expect("the waiting flow never started after the answered probe")
        .unwrap();
    let beside = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    assert_eq!(limiter.active(), (2, 2));
    drop((acks, next, beside));
    // The same refusal on the ACK path is not judged a flow refusal.
    limiter.judge(Purpose::Ack, &open_unanswered());
    assert_eq!(limiter.flow_refusals(), 1);
    assert!(!limiter.flows_backing_off());
    // A flow that began before a later unanswered Open got its status: it
    // proves nothing about that refusal, so flows stay single.
    let early = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    limiter.judge(Purpose::Flow, &open_unanswered());
    early.succeeded();
    assert!(limiter.flows_probing());
    let probe = limiter.acquire(Purpose::Flow, LONG).await.unwrap();
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    probe.succeeded();
    assert!(!limiter.flows_probing());
}

#[tokio::test]
async fn a_flow_past_its_open_request_returns_its_permit_but_counts_under_flow_opens() {
    let mut limiter = EstablishLimiter::for_test(4, 2, AUTH_BACKOFF);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, 3, LIVE_FLOWS);
    // Two flow permits: both flows write their Open and await the status.
    let mut first = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    let mut second = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    first.request_written();
    second.request_written();
    // Written twice is still one unanswered Open.
    second.request_written();
    assert_eq!((limiter.active(), limiter.unverified()), ((0, 0), 2));
    // A slow target no longer holds a permit: a third flow starts...
    let third = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    // ...but no more than `FLOW_OPENS` establish or await a status at once.
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    // An ACK-path permit is never moved by `request_written`.
    let mut ack = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    ack.request_written();
    assert_eq!((limiter.active(), limiter.unverified()), ((1, 1), 2));
    drop(ack);
    // A status (or a failure) ends the count.
    first.succeeded();
    drop(second);
    assert_eq!(limiter.unverified(), 0);
    let fourth = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    drop((third, fourth));
    assert_eq!((limiter.active(), limiter.unverified()), ((0, 0), 0));
    assert_eq!(limiter.high_water(), 2);
}

#[test]
fn live_flows_are_capped_and_return_on_drop() {
    let mut limiter = EstablishLimiter::for_test(6, 2, AUTH_BACKOFF);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, 2);
    let first = limiter.live_flow().unwrap();
    let second = limiter.live_flow().unwrap();
    assert_eq!(limiter.live(), 2);
    assert!(limiter.live_flow().is_none());
    assert!(limiter.live_flow().is_none());
    assert_eq!(limiter.live_refusals(), 2);
    drop(first);
    let third = limiter.live_flow().unwrap();
    drop((second, third));
    assert_eq!(limiter.live(), 0);
    // The production cap (248, the pool's bound) keeps room under the
    // relay's 1024 sessions per IP for both pre-warms and one request.
    let production = EstablishLimiter::new(AuthBackoff::default());
    let live: Vec<_> = (0..LIVE_FLOWS)
        .map(|_| production.live_flow().unwrap())
        .collect();
    assert!(production.live_flow().is_none());
    drop(live);
    assert_eq!(production.live(), 0);
}

#[tokio::test]
async fn while_probing_a_bound_reack_takes_the_ack_slot_before_an_earlier_prewarm() {
    let backoff = Duration::from_millis(100);
    let limiter = EstablishLimiter::for_test(6, 2, backoff);
    limiter.auth_failure(Purpose::Ack);
    // A pre-warm queues first, then the fresh re-ACK holding the request.
    let mut prewarm = Box::pin(limiter.acquire(Purpose::Ack, LONG));
    assert!(poll_once(&mut prewarm).await.is_none());
    let mut bound = Box::pin(limiter.acquire_bound(LONG));
    assert!(poll_once(&mut bound).await.is_none());
    tokio::time::sleep(backoff + Duration::from_millis(20)).await;
    // The pre-warm is polled first once the backoff ends, and yields.
    assert!(
        poll_once(&mut prewarm).await.is_none(),
        "a pre-warm took the probe slot ahead of the bound re-ACK"
    );
    let reack = tokio::time::timeout(Duration::from_secs(1), bound)
        .await
        .expect("the bound re-ACK never started")
        .unwrap();
    // Still one ACK-path probe at a time until the relay answers it.
    assert!(poll_once(&mut prewarm).await.is_none());
    reack.succeeded();
    assert!(!limiter.probing());
    let _warm = tokio::time::timeout(Duration::from_secs(1), prewarm)
        .await
        .expect("the pre-warm never started after the answered re-ACK")
        .unwrap();
    assert_eq!(limiter.active(), (1, 0));
}

#[tokio::test]
async fn a_prewarm_that_yielded_to_a_bound_reack_starts_once_that_reack_took_its_permit() {
    let limiter = EstablishLimiter::for_test(3, 1, AUTH_BACKOFF);
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(limiter.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    let mut bound = Box::pin(limiter.acquire_bound(LONG));
    assert!(poll_once(&mut bound).await.is_none());
    let mut prewarm = Box::pin(limiter.acquire(Purpose::Ack, LONG));
    assert!(poll_once(&mut prewarm).await.is_none());
    // Two permits return at once: the pre-warm, woken first, yields to the
    // waiting re-ACK, and is woken again once the re-ACK took its permit.
    held.truncate(1);
    assert!(poll_once(&mut prewarm).await.is_none());
    let _reack = tokio::time::timeout(Duration::from_secs(1), bound)
        .await
        .expect("the bound re-ACK never started")
        .unwrap();
    let _warm = tokio::time::timeout(Duration::from_secs(1), prewarm)
        .await
        .expect("the yielded pre-warm was never woken again")
        .unwrap();
    assert_eq!(limiter.active(), (3, 0));
    // A bound re-ACK that leaves the queue lets pre-warms through again.
    let mut bound = Box::pin(limiter.acquire_bound(LONG));
    assert!(poll_once(&mut bound).await.is_none());
    drop(bound);
    held.clear();
    let _next = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
}

#[tokio::test]
async fn a_repin_strands_the_current_sessions_relay_sessions_for_the_epochs_live_cap() {
    let epoch = AuthBackoff::default();
    // A relay whose room is the live cap itself (10 live flows).
    const RELAY: usize = 10 + ACK_SESSIONS + LIVE_MARGIN;
    let mut old = EstablishLimiter::with_limits(6, 3, AUTH_BACKOFF, epoch.clone());
    EstablishLimiter::tune(&mut old).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, 10);
    EstablishLimiter::tune(&mut old).set_relay_sessions(RELAY);
    epoch.register(&old);
    let live: Vec<_> = (0..4).map(|_| old.live_flow().unwrap()).collect();
    let ack = old.acquire(Purpose::Ack, SHORT).await.unwrap();
    let now = Instant::now();
    // Four live flows and one ACK-path channel stay counted by the relay.
    assert_eq!(epoch.strand_current(now), 5);
    // A second re-pin before the session ended counts nothing again.
    assert_eq!(epoch.strand_current(now), 0);
    drop((live, ack));
    // The epoch's rebuilt session keeps its live flows under the relay's
    // cap together with the stranded ones.
    let mut rebuilt = EstablishLimiter::with_limits(6, 3, AUTH_BACKOFF, epoch.clone());
    EstablishLimiter::tune(&mut rebuilt).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, 10);
    EstablishLimiter::tune(&mut rebuilt).set_relay_sessions(RELAY);
    epoch.register(&rebuilt);
    let flows: Vec<_> = (0..5).map(|_| rebuilt.live_flow().unwrap()).collect();
    assert!(rebuilt.live_flow().is_none());
    assert_eq!(rebuilt.live_refusals(), 1);
    // Until the relay has reaped them.
    assert_eq!(
        epoch.stranded_at(now + STRANDED_HOLD - Duration::from_millis(1)),
        5
    );
    assert_eq!(epoch.stranded_at(now + STRANDED_HOLD), 0);
    drop(flows);
    // A session with nothing at the relay strands nothing; an epoch whose
    // session ended has none to strand.
    let empty = EstablishLimiter::new(AuthBackoff::default());
    assert_eq!(empty.epoch.strand_current(Instant::now()), 0);
    let gone = AuthBackoff::default();
    drop(EstablishLimiter::new(gone.clone()));
    assert_eq!(gone.strand_current(Instant::now()), 0);
}

#[tokio::test]
async fn before_sleep_no_establishment_starts_until_the_wake_or_the_bound() {
    let epoch = AuthBackoff::default();
    let limiter = EstablishLimiter::new(epoch.clone());
    epoch.quiesce(Instant::now());
    assert!(limiter.acquire(Purpose::Ack, SHORT).await.is_err());
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    // Not authentication class: no probing afterwards.
    assert!(!limiter.probing());
    let mut waiting = Box::pin(limiter.acquire(Purpose::Ack, LONG));
    assert!(poll_once(&mut waiting).await.is_none());
    // The wake lets the waiter start at once.
    epoch.resume();
    let _ack = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("the wake did not resume establishments")
        .unwrap();
    let _flow = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    // Without a wake the pause ends after QUIESCE_MAX of awake time.
    epoch.quiesce(Instant::now() - QUIESCE_MAX);
    let _late = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
}

#[test]
fn every_wake_advances_the_epoch_wake_generation() {
    // S16h: a pooled connection dialed before a wake is drained, so every
    // wake counts, with or without the pause before it, and a session
    // rebuilt in the epoch reads the same generation.
    let epoch = AuthBackoff::default();
    let limiter = EstablishLimiter::new(epoch.clone());
    assert_eq!(limiter.wake_generation(), 0);
    epoch.quiesce(Instant::now());
    assert_eq!(limiter.wake_generation(), 0);
    epoch.resume();
    assert_eq!(limiter.wake_generation(), 1);
    // A wake whose sleep notification never came.
    epoch.resume();
    assert_eq!(limiter.wake_generation(), 2);
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert_eq!(rebuilt.wake_generation(), 2);
    // Another epoch has its own.
    assert_eq!(
        EstablishLimiter::new(AuthBackoff::default()).wake_generation(),
        0
    );
}

#[tokio::test]
async fn flow_opens_admit_every_flow_permit_and_sixteen_awaiting_a_status() {
    // S16j-4: 32 flows establishing or awaiting their Open status, at most:
    // the 16 flow permits and 16 awaiting a status.
    assert_eq!(FLOW_OPENS, 32);
    assert_eq!(FLOW_OPENS % (ESTABLISH_PERMITS - ACK_RESERVE), 0);
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let mut written = Vec::new();
    for _ in 0..FLOW_OPENS / (ESTABLISH_PERMITS - ACK_RESERVE) {
        let mut round: Vec<_> = Vec::new();
        for _ in 0..ESTABLISH_PERMITS - ACK_RESERVE {
            round.push(limiter.acquire(Purpose::Flow, SHORT).await.unwrap());
        }
        for permit in &mut round {
            permit.request_written();
        }
        written.extend(round);
    }
    assert_eq!(
        (limiter.active(), limiter.unverified()),
        ((0, 0), FLOW_OPENS)
    );
    // Every permit is free, yet no 33rd flow opens until a status arrives.
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
    let _ack = limiter.acquire(Purpose::Ack, SHORT).await.unwrap();
    written.pop().unwrap().succeeded();
    let _next = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    assert_eq!(limiter.high_water(), ESTABLISH_PERMITS - ACK_RESERVE);
}

#[tokio::test]
async fn stranded_handshakes_narrow_the_epochs_permits_until_the_relay_deadline() {
    // S16h-7: a re-pin strands the current session's establishments in
    // progress; they may hold relay handshakes until the relay's 5 s
    // deadline, so for 6 s every session of the epoch runs at most the
    // relay's 32, less a skew of 2 and those.
    assert_eq!(RELAY_HANDSHAKES_PER_IP - HANDSHAKE_SKEW, 30);
    assert_eq!(STRANDED_HS_HOLD, Duration::from_secs(6));
    let epoch = AuthBackoff::default();
    let old = EstablishLimiter::new(epoch.clone());
    let mut held = Vec::new();
    for _ in 0..ESTABLISH_PERMITS - ACK_RESERVE {
        held.push(old.acquire(Purpose::Flow, SHORT).await.unwrap());
    }
    // Both S16k requests in flight on the ACK path (its pre-warm slots
    // idle): 18 establishments in all.
    let acks = crate::provider_session_body::ACK_IN_FLIGHT;
    assert_eq!(acks, 2);
    for _ in 0..acks {
        held.push(old.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    assert_eq!(old.active(), (acks, 16));
    // A flow past its Open request and still unanswered may hold one too:
    // the lost path may never have carried its Finished.
    held[0].request_written();
    assert_eq!((old.active(), old.unverified()), ((acks, 15), 1));
    let now = Instant::now();
    // No ACK-path channel or live flow: only the 18 handshakes are stranded
    // (the 2 ACK-path establishments are its held sessions).
    assert_eq!(epoch.strand_current(now), acks);
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert_eq!(rebuilt.effective_permits(now), 12);
    assert_eq!(
        rebuilt.effective_permits(now + STRANDED_HS_HOLD - Duration::from_millis(1)),
        12
    );
    // Meanwhile 8 flows and the ACK reserve of 4, and nothing more.
    let mut flows = Vec::new();
    for _ in 0..12 - ACK_RESERVE {
        flows.push(rebuilt.acquire(Purpose::Flow, SHORT).await.unwrap());
    }
    assert_eq!(flows.len(), 8);
    assert!(rebuilt.acquire(Purpose::Flow, SHORT).await.is_err());
    let acks = ack_permits(&rebuilt, ACK_RESERVE).await;
    assert!(rebuilt.acquire(Purpose::Ack, SHORT).await.is_err());
    assert_eq!(rebuilt.active(), (ACK_RESERVE, 8));
    drop((flows, acks, held));
    // Then every permit again (read last: reading prunes what expired).
    assert_eq!(
        rebuilt.effective_permits(now + STRANDED_HS_HOLD),
        ESTABLISH_PERMITS
    );
    // S16k: room of exactly the ACK reserve and one leaves one flow beside
    // the whole reserve.
    let edge = AuthBackoff::default();
    let stranded = (RELAY_HANDSHAKES_PER_IP - HANDSHAKE_SKEW) - (ACK_RESERVE + 1);
    assert_eq!(stranded, 25);
    let busy = EstablishLimiter::with_limits(stranded, 3, AUTH_BACKOFF, edge.clone());
    edge.register(&busy);
    let mut edge_held = Vec::new();
    for _ in 0..stranded {
        edge_held.push(busy.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    edge.strand_current(now);
    let edged = EstablishLimiter::new(edge.clone());
    assert_eq!(edged.effective_permits(now), ACK_RESERVE + 1);
    let flow = edged.acquire(Purpose::Flow, SHORT).await.unwrap();
    assert!(edged.acquire(Purpose::Flow, SHORT).await.is_err());
    let edge_acks = ack_permits(&edged, ACK_RESERVE).await;
    assert!(edged.acquire(Purpose::Ack, SHORT).await.is_err());
    assert_eq!(edged.active(), (ACK_RESERVE, 1));
    drop((flow, edge_acks, edge_held));
    // More stranded than the relay's room leaves no permit at all, the ACK
    // path's included, rather than handshakes the relay would refuse;
    // another epoch is not narrowed.
    let crowded = AuthBackoff::default();
    let many = EstablishLimiter::with_limits(36, 3, AUTH_BACKOFF, crowded.clone());
    crowded.register(&many);
    let mut held = Vec::new();
    for _ in 0..36 {
        held.push(many.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    crowded.strand_current(now);
    let squeezed = EstablishLimiter::new(crowded.clone());
    assert_eq!(squeezed.effective_permits(now), 0);
    assert!(squeezed.acquire(Purpose::Ack, SHORT).await.is_err());
    assert!(squeezed.acquire(Purpose::Flow, SHORT).await.is_err());
    assert_eq!(squeezed.active(), (0, 0));
    // Room under the ACK reserve goes to the ACK path alone.
    let tight = AuthBackoff::default();
    let twenty_eight = EstablishLimiter::with_limits(28, 3, AUTH_BACKOFF, tight.clone());
    tight.register(&twenty_eight);
    for _ in 0..28 {
        held.push(twenty_eight.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    tight.strand_current(now);
    let narrow = EstablishLimiter::new(tight.clone());
    assert_eq!(narrow.effective_permits(now), 2);
    assert!(narrow.acquire(Purpose::Flow, SHORT).await.is_err());
    let acks = ack_permits(&narrow, 2).await;
    assert!(narrow.acquire(Purpose::Ack, SHORT).await.is_err());
    assert_eq!(narrow.active(), (2, 0));
    drop(acks);
    assert_eq!(
        EstablishLimiter::new(AuthBackoff::default()).effective_permits(now),
        ESTABLISH_PERMITS
    );
}

/// `n` ACK-path permits of `limiter`.
async fn ack_permits(limiter: &Arc<EstablishLimiter>, n: usize) -> Vec<EstablishPermit> {
    let mut acks = Vec::new();
    for _ in 0..n {
        acks.push(limiter.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    acks
}

/// Hold every permit of `limiter` a fresh session may take, the ACK path's
/// first, and the flows' beyond it.
async fn hold_all(limiter: &Arc<EstablishLimiter>, held: &mut Vec<EstablishPermit>) {
    let permits = limiter.effective_permits(Instant::now());
    held.extend(ack_permits(limiter, permits.min(ACK_RESERVE)).await);
    for _ in ACK_RESERVE..permits {
        held.push(limiter.acquire(Purpose::Flow, SHORT).await.unwrap());
    }
    assert!(limiter.acquire(Purpose::Ack, SHORT).await.is_err());
    assert!(limiter.acquire(Purpose::Flow, SHORT).await.is_err());
}

#[tokio::test]
async fn stranded_and_new_handshakes_stay_under_the_relays_thirty_two_across_re_pins() {
    // The relay counts every stranded handshake, every permit of the new
    // session and its skew: never more than its 32 per peer IP, after a
    // re-pin of a session at every permit (20 stranded) and after two
    // re-pins within the hold (20, then the next session's own 10), though
    // no permit then remains even for the ACK path.
    let epoch = AuthBackoff::default();
    let first = EstablishLimiter::new(epoch.clone());
    let mut held = Vec::new();
    hold_all(&first, &mut held).await;
    assert_eq!(
        first.active(),
        (ACK_RESERVE, ESTABLISH_PERMITS - ACK_RESERVE)
    );
    let now = Instant::now();
    let mut stranded = 0;
    assert_eq!(30 - ESTABLISH_PERMITS, 10);
    for (repin, permits) in [(1, 10), (2, 0)] {
        epoch.strand_current(now);
        let (count, _) = epoch.stranded_hs_at(now);
        assert!(count > stranded, "re-pin {repin}: {count}");
        stranded = count;
        let next = EstablishLimiter::new(epoch.clone());
        let effective = next.effective_permits(now);
        assert_eq!(effective, permits, "re-pin {repin}");
        assert!(
            stranded + effective + HANDSHAKE_SKEW <= RELAY_HANDSHAKES_PER_IP,
            "re-pin {repin}: {stranded} + {effective}"
        );
        // The session takes what it may: the ACK path first, flows only
        // beyond the reserve, never a permit past the relay's room.
        hold_all(&next, &mut held).await;
        assert_eq!(
            next.active(),
            (
                permits.min(ACK_RESERVE),
                permits.saturating_sub(ACK_RESERVE)
            ),
            "re-pin {repin}"
        );
    }
    // Every permit again once the stranded handshakes expire.
    let later = EstablishLimiter::new(epoch.clone());
    assert_eq!(
        later.effective_permits(now + STRANDED_HS_HOLD),
        ESTABLISH_PERMITS
    );
}

#[tokio::test]
async fn stranded_written_flows_count_from_their_write_and_only_while_unanswered() {
    let epoch = AuthBackoff::default();
    let old = EstablishLimiter::new(epoch.clone());
    let before = Instant::now();
    let mut written = Vec::new();
    // Three Opens written, then 13 more 100 ms later.
    let mut mid = before;
    for n in 0..ESTABLISH_PERMITS - ACK_RESERVE {
        if n == 3 {
            mid = Instant::now();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut permit = old.acquire(Purpose::Flow, SHORT).await.unwrap();
        permit.request_written();
        written.push(permit);
    }
    // Three statuses arrived: those flows hold nothing at the relay.
    for permit in written.drain(..3) {
        permit.succeeded();
    }
    let after = Instant::now();
    assert_eq!((old.active(), old.unverified()), ((0, 0), 13));
    // Stranded 2 s after the writes: the 13 unanswered of the 16 written,
    // so 30 - 13 permits.
    let strand = after + Duration::from_secs(2);
    epoch.strand_current(strand);
    assert_eq!(epoch.stranded_hs_recorded(), 13);
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert_eq!(rebuilt.effective_permits(strand), 17);
    // Each counts until `STRANDED_HS_HOLD` after its write (the relay's
    // deadline runs from before it), not after the strand.
    assert_eq!(
        rebuilt.effective_permits(before + STRANDED_HS_HOLD - Duration::from_millis(1)),
        17
    );
    // The unanswered ones are taken as the latest writes, the longest held.
    assert_eq!(rebuilt.effective_permits(mid + STRANDED_HS_HOLD), 17);
    assert_eq!(
        rebuilt.effective_permits(after + STRANDED_HS_HOLD),
        ESTABLISH_PERMITS
    );
    // An Open written longer ago than the hold is not stranded at all.
    let late = AuthBackoff::default();
    let stale = EstablishLimiter::new(late.clone());
    let mut permit = stale.acquire(Purpose::Flow, SHORT).await.unwrap();
    permit.request_written();
    let written_at = Instant::now();
    late.strand_current(written_at + STRANDED_HS_HOLD);
    assert_eq!(late.stranded_hs_recorded(), 0);
    drop((written, permit));
}

#[tokio::test]
async fn the_open_writes_kept_for_a_strand_are_bounded_by_the_open_cap() {
    let mut limiter = EstablishLimiter::for_test(4, 1, AUTH_BACKOFF);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, 5, LIVE_FLOWS);
    for _ in 0..12 {
        let mut permit = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
        permit.request_written();
        permit.succeeded();
    }
    assert_eq!(limiter.writes_kept(), 5);
}

#[tokio::test]
async fn a_flow_waiting_on_stranded_handshakes_starts_once_they_expire() {
    // No release comes when stranded handshakes expire: the waiter wakes at
    // the expiry by itself.
    let epoch = AuthBackoff::default();
    let old = EstablishLimiter::new(epoch.clone());
    let mut held = Vec::new();
    for _ in 0..ESTABLISH_PERMITS - ACK_RESERVE {
        held.push(old.acquire(Purpose::Flow, SHORT).await.unwrap());
    }
    // Both S16k requests in flight on the ACK path: 18 stranded in all.
    let acks = crate::provider_session_body::ACK_IN_FLIGHT;
    for _ in 0..acks {
        held.push(old.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    let expires = Duration::from_millis(300);
    let stranded_at = Instant::now() + expires - STRANDED_HS_HOLD;
    epoch.strand_current(stranded_at);
    let rebuilt = EstablishLimiter::new(epoch.clone());
    // 30 less the 18 stranded: the reserve of 4 and 8 flows.
    assert_eq!(
        rebuilt.effective_permits(Instant::now()),
        (RELAY_HANDSHAKES_PER_IP - HANDSHAKE_SKEW) - (FLOW_PERMITS + acks)
    );
    assert_eq!(rebuilt.effective_permits(Instant::now()), ACK_RESERVE + 8);
    let mut first = Vec::new();
    for _ in 0..8 {
        first.push(rebuilt.acquire(Purpose::Flow, SHORT).await.unwrap());
    }
    assert!(rebuilt.acquire(Purpose::Flow, SHORT).await.is_err());
    let started = Instant::now();
    let second = tokio::time::timeout(LONG / 2, rebuilt.acquire(Purpose::Flow, LONG))
        .await
        .expect("the waiting flow never woke when the stranded handshakes expired")
        .unwrap();
    assert!(started.elapsed() >= expires - Duration::from_millis(100));
    assert_eq!(rebuilt.effective_permits(Instant::now()), ESTABLISH_PERMITS);
    drop((first, second, held));
}

// ---- S16h-8b, 8d: the epoch's strike ledger and stall fallback ----

#[test]
fn the_strike_ledger_counts_from_its_first_entry_and_expires_as_the_relays() {
    // aegis-server keys an IP's failures by the first and prunes the whole
    // entry STRIKE_WINDOW after it (rate_limit.rs), however many follow.
    assert_eq!(STRIKE_WINDOW, Duration::from_secs(300));
    let t = Instant::now();
    let at = |s: u64| t + Duration::from_secs(s);
    let mut ledger = StrikeLedger::default();
    assert_eq!(ledger.at(t), 0);
    assert_eq!(ledger.expires(t), None);
    assert_eq!(ledger.record(t), 1);
    assert_eq!(ledger.record(at(200)), 2);
    assert_eq!(ledger.at(at(299)), 2);
    assert_eq!(ledger.expires(at(299)), Some(at(300)));
    // The later entry expires with the first.
    assert_eq!(ledger.at(at(300)), 0);
    assert_eq!(ledger.expires(at(300)), None);
    // An entry after the expiry starts a new count from itself.
    assert_eq!(ledger.record(at(301)), 1);
    assert_eq!(ledger.at(at(600)), 1);
    assert_eq!(ledger.at(at(601)), 0);
}

#[test]
fn two_stall_deaths_within_a_minute_switch_the_fallback_on_for_five_minutes() {
    assert_eq!(
        (STALL_DEATHS, STALL_DEATH_WINDOW, FALLBACK_HOLD),
        (2, Duration::from_secs(60), Duration::from_secs(300))
    );
    let t = Instant::now();
    let at = |s: u64| t + Duration::from_secs(s);
    let mut book = StallBook::default();
    // One death, then another more than a minute later: never on.
    assert!(!book.death(t));
    assert!(!book.death(at(61)));
    assert!(!book.active(at(61)));
    // A third within the minute of the second: on for FALLBACK_HOLD.
    assert!(book.death(at(100)));
    assert_eq!(book.switched, 1);
    assert!(book.active(at(100)) && book.active(at(399)));
    assert!(!book.active(at(400)));
    assert_eq!(book.ends(at(399)), Some(at(400)));
    // Two more within a minute renew it from the later one.
    assert!(!book.death(at(370)));
    assert!(book.death(at(380)));
    assert_eq!(book.switched, 2);
    assert!(book.active(at(679)) && !book.active(at(680)));
}

#[test]
fn pool_modes_narrow_flow_permits_by_level_and_fallback() {
    let mode = |strikes, fallback| PoolMode { strikes, fallback };
    assert_eq!(
        (L1_FLOW_PERMITS, L2_FLOW_PERMITS, FALLBACK_FLOW_PERMITS),
        (4, 1, 3)
    );
    assert_eq!(mode(0, false).flow_permits(), None);
    assert_eq!(mode(1, false).flow_permits(), Some(4));
    assert_eq!(mode(2, false).flow_permits(), Some(1));
    assert_eq!(mode(5, false).flow_permits(), Some(1));
    assert_eq!(mode(0, true).flow_permits(), Some(3));
    assert_eq!(mode(1, true).flow_permits(), Some(3));
    assert_eq!(mode(2, true).flow_permits(), Some(1));
    assert!(!mode(1, true).needs_proof());
    assert!(mode(2, false).needs_proof());
}

/// How many flow permits `limiter` grants at once now.
async fn flow_permits(limiter: &Arc<EstablishLimiter>) -> usize {
    let mut held = Vec::new();
    while let Ok(permit) = limiter.acquire(Purpose::Flow, SHORT).await {
        held.push(permit);
    }
    held.len()
}

#[tokio::test]
async fn strikes_narrow_flows_alone_and_carry_to_a_rebuilt_session() {
    let epoch = AuthBackoff::default();
    let limiter = EstablishLimiter::new(epoch.clone());
    assert_eq!(
        flow_permits(&limiter).await,
        ESTABLISH_PERMITS - ACK_RESERVE
    );
    // Level 1: one handshake per pool connection.
    assert_eq!(limiter.strike(), 1);
    assert_eq!(flow_permits(&limiter).await, L1_FLOW_PERMITS);
    // Level 2: one at a time.
    assert_eq!(limiter.strike(), 2);
    assert_eq!(flow_permits(&limiter).await, L2_FLOW_PERMITS);
    // The ACK path keeps every permit flows leave it, and no backoff.
    let held = vec![limiter.acquire(Purpose::Flow, SHORT).await.unwrap()];
    let acks = ack_permits(&limiter, ESTABLISH_PERMITS - 1).await;
    assert!(!limiter.backing_off() && !limiter.probing());
    drop((acks, held));
    // S17: the session is rebuilt in the same epoch. Its new limiter (and
    // its pool) starts at the same level.
    drop(limiter);
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert_eq!(rebuilt.strikes(), 2);
    assert_eq!(
        rebuilt.pool_mode(),
        PoolMode {
            strikes: 2,
            fallback: false
        }
    );
    assert_eq!(flow_permits(&rebuilt).await, L2_FLOW_PERMITS);
    // Another epoch's sessions start clean.
    let other = EstablishLimiter::new(AuthBackoff::default());
    assert_eq!(other.strikes(), 0);
    assert_eq!(flow_permits(&other).await, ESTABLISH_PERMITS - ACK_RESERVE);
}

#[tokio::test]
async fn the_stall_fallback_leaves_flows_three_permits_and_carries_to_a_rebuilt_session() {
    let epoch = AuthBackoff::default();
    let limiter = EstablishLimiter::new(epoch.clone());
    let deaths = limiter.stall_deaths();
    deaths.died();
    assert_eq!(
        (limiter.fallbacks(), limiter.pool_mode().fallback),
        (0, false)
    );
    assert_eq!(
        flow_permits(&limiter).await,
        ESTABLISH_PERMITS - ACK_RESERVE
    );
    deaths.died();
    assert_eq!(
        (limiter.fallbacks(), limiter.pool_mode().fallback),
        (1, true)
    );
    assert_eq!(flow_permits(&limiter).await, FALLBACK_FLOW_PERMITS);
    let acks = ack_permits(&limiter, ESTABLISH_PERMITS).await;
    drop(acks);
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert!(rebuilt.pool_mode().fallback);
    assert_eq!(flow_permits(&rebuilt).await, FALLBACK_FLOW_PERMITS);
}

#[tokio::test]
async fn a_flow_waiting_at_strike_level_two_starts_once_the_ledger_expires() {
    // No release comes when the ledger expires: the waiter wakes at the
    // expiry by itself.
    let epoch = AuthBackoff::default();
    let limiter = EstablishLimiter::new(epoch.clone());
    let expires = Duration::from_millis(300);
    let Some(first) = (Instant::now() + expires).checked_sub(STRIKE_WINDOW) else {
        // A clock younger than the window cannot hold an old entry.
        return;
    };
    epoch.strike_at(first);
    epoch.strike_at(first);
    assert_eq!(limiter.strikes(), 2);
    let _first = limiter.acquire(Purpose::Flow, SHORT).await.unwrap();
    let started = Instant::now();
    let second = tokio::time::timeout(LONG / 2, limiter.acquire(Purpose::Flow, LONG))
        .await
        .expect("the waiting flow never woke when the ledger expired")
        .unwrap();
    assert!(started.elapsed() >= expires - Duration::from_millis(100));
    assert_eq!(limiter.strikes(), 0);
    assert_eq!(epoch.mode_at(Instant::now()), PoolMode::default());
    drop(second);
}

#[tokio::test]
async fn a_prewarm_permit_is_granted_now_or_never() {
    // S16i-1: a pool pre-dial's permit never waits and never runs while a
    // backoff, probing, the pause before sleep or a waiting establishment
    // is in force; it is a flow permit and counts as one.
    let epoch = AuthBackoff::default();
    let mut limiter = EstablishLimiter::with_limits(4, 1, Duration::from_millis(60), epoch.clone());
    EstablishLimiter::tune(&mut limiter).set_flow_limits(
        Duration::from_millis(60),
        FLOW_OPENS,
        LIVE_FLOWS,
    );
    let permit = limiter.try_prewarm().expect("an idle limiter grants one");
    assert_eq!(limiter.active(), (0, 1));
    drop(permit);
    assert_eq!(limiter.active(), (0, 0));
    // The flows' permits all held: none.
    let held: Vec<_> = [
        limiter.acquire(Purpose::Flow, SHORT).await.unwrap(),
        limiter.acquire(Purpose::Flow, SHORT).await.unwrap(),
        limiter.acquire(Purpose::Flow, SHORT).await.unwrap(),
    ]
    .into();
    assert!(limiter.try_prewarm().is_none());
    // A flow waiting for a permit goes first.
    let mut waiting = Box::pin(limiter.acquire(Purpose::Flow, LONG));
    assert!(poll_once(&mut waiting).await.is_none());
    drop(held);
    assert!(limiter.try_prewarm().is_none());
    let flow = waiting.await.unwrap();
    assert!(limiter.try_prewarm().is_some());
    drop(flow);
    // The pause before sleep, until the wake.
    epoch.quiesce(Instant::now());
    assert!(limiter.try_prewarm().is_none());
    epoch.resume();
    assert!(limiter.try_prewarm().is_some());
    // The flows' own backoff, then their probing until a status.
    limiter.flow_unanswered();
    assert!(limiter.try_prewarm().is_none());
    tokio::time::sleep(Duration::from_millis(60) + SHORT).await;
    assert!(!limiter.flows_backing_off());
    assert!(limiter.flows_probing());
    assert!(limiter.try_prewarm().is_none());
    limiter
        .acquire(Purpose::Flow, SHORT)
        .await
        .unwrap()
        .succeeded();
    assert!(limiter.try_prewarm().is_some());
    // The epoch's backoff, then its probing until the relay answers.
    limiter.auth_failure(Purpose::Flow);
    assert!(limiter.try_prewarm().is_none());
    tokio::time::sleep(Duration::from_millis(60) + SHORT).await;
    assert!(!limiter.backing_off());
    assert!(limiter.probing());
    assert!(limiter.try_prewarm().is_none());
    limiter
        .acquire(Purpose::Ack, SHORT)
        .await
        .unwrap()
        .succeeded();
    assert!(limiter.try_prewarm().is_some());
    // Never a flow's timeout, never in the queue log.
    assert_eq!(limiter.flow_timeouts(), 0);
}

#[tokio::test]
async fn the_epoch_records_running_and_flow_outcomes_across_its_sessions() {
    use crate::flow_log::{Outcome, Refusal};
    let epoch = AuthBackoff::default();
    let first = EstablishLimiter::new(epoch.clone());
    assert!(!first.epoch_running());
    epoch.mark_running();
    first.flow_opened(Outcome::Refused(Refusal::PoolWait), Duration::from_secs(5));
    // A rebuilt session of the epoch shares both.
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert!(rebuilt.epoch_running());
    rebuilt.flow_opened(Outcome::Refused(Refusal::PoolWait), Duration::from_secs(5));
    assert_eq!(rebuilt.refusals(Refusal::PoolWait), 2);
    rebuilt.flush_flow_log(true);
    assert_eq!(
        first.flow_log_lines(),
        [
            "flow_open pool_wait ms:le5000",
            "flow_refused class:pool_wait n:1",
            "flow_open pool_wait ms:le5000",
            "flow_refused class:pool_wait n:1",
        ]
    );
    // Another epoch's are its own.
    let other = EstablishLimiter::new(AuthBackoff::default());
    assert!(!other.epoch_running());
    assert!(other.flow_log_lines().is_empty());
}

/// S16i-2: the live cap is the least of the signed `max_flows`, the
/// relay's sessions per peer IP less the ACK path's and the margin, and
/// what the pool carries at its stream cap.
#[test]
fn live_cap_derivation() {
    assert_eq!((ACK_SESSIONS, LIVE_MARGIN), (ACK_RESERVE, 5));
    assert_eq!(LIVE_FLOWS_MAX, 4 * 62);
    // Today's relay: 128 sessions per peer IP.
    assert_eq!(live_cap_for(256, 128), 119);
    assert_eq!(live_cap_for(64, 128), 64);
    assert_eq!(live_cap_for(512, 128), 119);
    // A relay at 1024 sessions: the pool's bound.
    assert_eq!(live_cap_for(256, 1024), 248);
    assert_eq!(live_cap_for(64, 1024), 64);
    // This build's relay value and the unbound default.
    assert_eq!(RELAY_SESSIONS_PER_IP, 1024);
    assert_eq!(live_cap(256), 248);
    assert_eq!(live_cap(64), 64);
    assert_eq!(LIVE_FLOWS, live_cap(usize::MAX));
    assert!(live_cap(512) + ACK_RESERVE < RELAY_SESSIONS_PER_IP);
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    assert_eq!(limiter.live_cap(), LIVE_FLOWS);
}

/// S16i-2: binding the signed `max_flows` lowers the session's live cap;
/// the place past it waits, and is refused at its deadline.
#[tokio::test]
async fn bind_signed_max_flows_lowers_cap() {
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    limiter.bind_signed_max_flows(64);
    assert_eq!(limiter.live_cap(), 64);
    let deadline = Instant::now() + SHORT;
    let mut live = Vec::new();
    for _ in 0..64 {
        live.push(limiter.acquire_live(deadline).await.unwrap());
    }
    assert_eq!(limiter.live(), 64);
    let started = Instant::now();
    let refused = limiter.acquire_live(Instant::now() + SHORT).await;
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(started.elapsed() >= SHORT);
    assert_eq!(limiter.live_refusals(), 1);
    assert_eq!(limiter.live_waiting(), 0);
    // The 65th waits, and takes the first place returned.
    let mut waiting = Box::pin(limiter.acquire_live(Instant::now() + LONG));
    assert!(poll_once(&mut waiting).await.is_none());
    assert_eq!(limiter.live_waiting(), 1);
    live.pop();
    let admitted = tokio::time::timeout(SHORT, waiting).await.unwrap().unwrap();
    assert_eq!((limiter.live(), limiter.live_high_water()), (64, 64));
    drop((live, admitted));
    assert_eq!(limiter.live(), 0);
    // A ticket admitted before a bind lowered the cap takes no place.
    let mut ticket = limiter.live_ticket();
    limiter
        .live_ready(&ticket, Instant::now() + SHORT)
        .await
        .unwrap();
    limiter.bind_signed_max_flows(0);
    assert!(limiter.take_live(&mut ticket).is_none());
    assert_eq!(limiter.live_waiting(), 1);
    drop(ticket);
    assert_eq!(limiter.live_waiting(), 0);
    // A signed cap above the relay's leaves the relay's.
    limiter.bind_signed_max_flows(512);
    assert_eq!(limiter.live_cap(), LIVE_FLOWS);
}

/// S16i-2: a live place returned admits the oldest waiter within one
/// recheck, and a later waiter never overtakes it.
#[tokio::test]
async fn live_wait_admitted_on_release() {
    let mut limiter = EstablishLimiter::for_test(6, 2, AUTH_BACKOFF);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, 2);
    let first = limiter.acquire_live(Instant::now() + SHORT).await.unwrap();
    let second = limiter.acquire_live(Instant::now() + SHORT).await.unwrap();
    let third = tokio::spawn({
        let limiter = limiter.clone();
        async move { limiter.acquire_live(Instant::now() + LONG).await }
    });
    settle().await;
    let fourth = tokio::spawn({
        let limiter = limiter.clone();
        async move { limiter.acquire_live(Instant::now() + LONG).await }
    });
    settle().await;
    assert_eq!(limiter.live_waiting(), 2);
    // No place taken past the queue either.
    assert!(limiter.live_flow().is_none());
    let released = Instant::now();
    drop(first);
    let third = tokio::time::timeout(crate::held_relay_services::RECHECK, third)
        .await
        .expect("the oldest waiter was not admitted within one recheck")
        .unwrap()
        .unwrap();
    assert!(released.elapsed() <= crate::held_relay_services::RECHECK);
    settle().await;
    assert!(!fourth.is_finished());
    assert_eq!((limiter.live(), limiter.live_waiting()), (2, 1));
    drop(second);
    let fourth = tokio::time::timeout(crate::held_relay_services::RECHECK, fourth)
        .await
        .expect("the next waiter was not admitted")
        .unwrap()
        .unwrap();
    // A waiter that leaves the queue lets the next one through.
    let mut leaving = Box::pin(limiter.acquire_live(Instant::now() + LONG));
    assert!(poll_once(&mut leaving).await.is_none());
    let mut next = Box::pin(limiter.acquire_live(Instant::now() + LONG));
    assert!(poll_once(&mut next).await.is_none());
    drop(third);
    // The returned place is the older waiter's, polled or not.
    settle().await;
    assert!(poll_once(&mut next).await.is_none());
    drop(leaving);
    let next = tokio::time::timeout(SHORT, next).await.unwrap().unwrap();
    assert_eq!((limiter.live(), limiter.live_waiting()), (2, 0));
    drop((fourth, next));
    assert_eq!(limiter.live(), 0);
    assert_eq!(limiter.live_refusals(), 1);
    // A ticket that may take a place keeps it from a flow with no ticket
    // until it takes it or leaves.
    let held = limiter.live_flow().unwrap();
    let mut ticket = limiter.live_ticket();
    limiter
        .live_ready(&ticket, Instant::now() + SHORT)
        .await
        .unwrap();
    assert!(limiter.live_flow().is_none());
    let taken = limiter.take_live(&mut ticket).unwrap();
    assert!(limiter.take_live(&mut ticket).is_none());
    drop((held, taken, ticket));
    assert_eq!((limiter.live(), limiter.live_waiting()), (0, 0));
}

/// S16i-2: a stranded count that expires frees live places with no
/// release: a waiter is admitted as it expires, not at its deadline.
#[tokio::test]
async fn live_wait_admitted_when_stranded_sessions_expire() {
    let epoch = AuthBackoff::default();
    let mut limiter = EstablishLimiter::with_limits(6, 3, AUTH_BACKOFF, epoch.clone());
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, 2);
    // A relay whose room is the live cap itself (2 live flows).
    EstablishLimiter::tune(&mut limiter).set_relay_sessions(2 + ACK_SESSIONS + LIVE_MARGIN);
    let expires = Instant::now() + Duration::from_millis(100);
    epoch.slots().stranded.push((2, expires));
    let started = Instant::now();
    let live = limiter.acquire_live(started + LONG).await.unwrap();
    assert!(Instant::now() >= expires);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    drop(live);
}

/// Review fix (v21 prep): a re-pin's stranded sessions narrow the relay's
/// room, not the pool's bound. Against relay-a's 1024 sessions per IP a
/// session rebuilt after a re-pin at the live cap (248 live flows and the
/// ACK path's 4, 252 stranded) keeps every one of its 248 live places, as it
/// does with 153 stranded; only a relay with no room left narrows it.
#[tokio::test]
async fn a_repin_at_the_live_cap_leaves_the_rebuilt_session_every_live_place_at_1024() {
    assert_eq!((RELAY_SESSIONS_PER_IP, LIVE_FLOWS), (1024, 248));
    let epoch = AuthBackoff::default();
    let old = EstablishLimiter::new(epoch.clone());
    let live: Vec<_> = (0..LIVE_FLOWS).map(|_| old.live_flow().unwrap()).collect();
    let mut acks = Vec::new();
    for _ in 0..ACK_SESSIONS {
        acks.push(old.acquire(Purpose::Ack, SHORT).await.unwrap());
    }
    let now = Instant::now();
    assert_eq!(epoch.strand_current(now), LIVE_FLOWS + ACK_SESSIONS);
    drop((live, acks));
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert_eq!(rebuilt.live_room(Instant::now()).0, LIVE_FLOWS);
    let flows: Vec<_> = (0..LIVE_FLOWS)
        .map(|_| rebuilt.live_flow().unwrap())
        .collect();
    assert!(rebuilt.live_flow().is_none());
    // The relay holds the stranded and the new sessions with room to spare.
    assert!(
        epoch.stranded_now() + flows.len() + ACK_SESSIONS + LIVE_MARGIN <= RELAY_SESSIONS_PER_IP
    );
    drop(flows);
    // A signed cap of 64 is not narrowed by 67 stranded sessions either.
    let small = AuthBackoff::default();
    small
        .slots()
        .stranded
        .push((64 + ACK_SESSIONS, now + STRANDED_HOLD));
    let bound = EstablishLimiter::new(small.clone());
    bound.bind_signed_max_flows(64);
    assert_eq!(bound.live_room(Instant::now()).0, 64);
    // 150 live at the switch (153 stranded) still leaves all 248.
    let mid = AuthBackoff::default();
    mid.slots()
        .stranded
        .push((150 + ACK_SESSIONS, now + STRANDED_HOLD));
    let rebuilt = EstablishLimiter::new(mid.clone());
    assert_eq!(rebuilt.live_room(Instant::now()).0, LIVE_FLOWS);
    // A relay left with fewer free sessions than the cap narrows it.
    let full = AuthBackoff::default();
    full.slots().stranded.push((900, now + STRANDED_HOLD));
    let narrowed = EstablishLimiter::new(full.clone());
    assert_eq!(
        narrowed.live_room(Instant::now()).0,
        RELAY_SESSIONS_PER_IP - ACK_SESSIONS - LIVE_MARGIN - 900
    );
}

/// Review fix (v21 prep): against a relay at aegis-server's 128 sessions
/// per IP, whose room (119 with S16k's ACK reserve of 4) is also the live
/// cap, a re-pin's stranded sessions still take the rebuilt session's live
/// places one for one: the room less the stranded count, none with the
/// room or more stranded.
#[test]
fn a_repin_against_a_128_relay_leaves_its_room_less_the_stranded_sessions() {
    const RELAY: usize = 128;
    const LIVE: usize = RELAY - ACK_SESSIONS - LIVE_MARGIN;
    assert_eq!(LIVE, 119);
    assert_eq!(live_cap_for(usize::MAX, RELAY), LIVE);
    let now = Instant::now();
    for (stranded, room) in [
        (0, LIVE),
        (30, LIVE - 30),
        (LIVE - 1, 1),
        (LIVE, 0),
        (252, 0),
    ] {
        let epoch = AuthBackoff::default();
        if stranded > 0 {
            epoch.slots().stranded.push((stranded, now + STRANDED_HOLD));
        }
        let mut limiter = EstablishLimiter::with_limits(6, 3, AUTH_BACKOFF, epoch.clone());
        EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, LIVE);
        EstablishLimiter::tune(&mut limiter).set_relay_sessions(RELAY);
        assert_eq!(limiter.live_room(now).0, room, "{stranded} stranded");
        let flows: Vec<_> = (0..room).map(|_| limiter.live_flow().unwrap()).collect();
        assert!(limiter.live_flow().is_none(), "{stranded} stranded");
        if stranded <= LIVE {
            assert!(stranded + flows.len() + ACK_SESSIONS + LIVE_MARGIN <= RELAY);
        }
    }
}
