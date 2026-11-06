//! v40 (CP-D3 M1): the provider's use of aegis-core's carrier failover
//! controller: plans, tickets, signals and their classification.
use super::*;
use aegis_core::brain::carrier_failover::CarrierState;

/// A profile identity of its own per test: the registry is per process.
fn identity(name: &str) -> [u8; 32] {
    profile_identity(&format!("test-{name}-{}", std::process::id()))
}

fn policy() -> CarrierFailoverSettings {
    CarrierFailoverSettings {
        base_cooldown_ms: 1_000,
        max_cooldown_ms: 8_000,
        degraded_threshold: 2,
        max_networks: 4,
        ..CarrierFailoverSettings::default()
    }
}

fn network(byte: u8) -> NetworkKey {
    NetworkKey::derive(&[byte; 32], &[b"test"])
}

fn state(id: [u8; 32], net: NetworkKey, carrier: usize) -> CarrierState {
    inspect(id, |controller| {
        controller.state(net, carrier, Instant::now())
    })
    .unwrap()
}

#[test]
fn a_single_pin_has_no_controller_and_dials_its_pin() {
    let id = identity("single");
    let carriers = SessionCarriers::plan(id, None, 1, NetworkKey::UNKNOWN).unwrap();
    assert_eq!(carriers.order(), &[0]);
    assert!(carriers.ticket(0).is_none());
    assert!(inspect(id, |_| ()).is_none(), "nothing is kept");
    // A pool without a policy keeps its profile order and learns nothing.
    let carriers = SessionCarriers::plan(id, None, 3, NetworkKey::UNKNOWN).unwrap();
    assert_eq!(carriers.order(), &[0, 1, 2]);
    assert!(SessionCarriers::plan(id, None, 0, NetworkKey::UNKNOWN).is_err());
    assert!(SessionCarriers::plan(id, None, 17, NetworkKey::UNKNOWN).is_err());
}

#[test]
fn a_pre_authentication_fault_fails_the_attempt_and_the_next_build_prefers_the_fallback() {
    let id = identity("preauth");
    let net = network(1);
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    assert_eq!(carriers.order(), &[0, 1]);
    let first = carriers.ticket(0).unwrap();
    assert!(!first.failed());
    first.fault(CarrierSignal::DialTimeout);
    assert!(first.failed(), "the build moves on");
    assert!(matches!(state(id, net, 0), CarrierState::Cooling { .. }));
    // A later fault of the same failed attempt changes nothing more.
    first.fault(CarrierSignal::HandshakeReset);
    let second = carriers.ticket(1).unwrap();
    second.opened();
    assert_eq!(
        inspect(id, |controller| controller.active(net)).unwrap(),
        Some(1)
    );
    drop((first, second, carriers));
    // The next build on this network tries the cooled pin last.
    let next = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    assert_eq!(next.order(), &[1, 0]);
    // Another network has its own memory.
    let elsewhere = SessionCarriers::plan(id, Some(&policy()), 2, network(2)).unwrap();
    assert_eq!(elsewhere.order(), &[0, 1]);
}

#[test]
fn post_authentication_signals_are_never_pre_auth_faults_and_degrade_once_per_session() {
    let id = identity("degrade");
    let net = network(3);
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    // Before the session opened nothing post-authentication is recorded.
    ticket.degraded(CarrierSignal::SessionFreeze);
    ticket.fault(CarrierSignal::SessionFreeze);
    assert!(!ticket.failed());
    assert_eq!(state(id, net, 0), CarrierState::Closed);
    ticket.opened();
    assert!(ticket.is_open());
    ticket.degraded(CarrierSignal::SessionFreeze);
    ticket.degraded(CarrierSignal::ThroughputCollapse);
    // Threshold 2: one session's degradation alone keeps the pin usable.
    assert_eq!(state(id, net, 0), CarrierState::Closed);
    ticket.closed(true);
    drop((ticket, carriers));
    // A second session's freeze (a lease that ran out) opens the breaker.
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    assert_eq!(carriers.order(), &[0, 1]);
    let ticket = carriers.ticket(0).unwrap();
    ticket.opened();
    ticket.closed(true);
    assert!(matches!(state(id, net, 0), CarrierState::Cooling { .. }));
    assert_eq!(
        inspect(id, |controller| controller.last_signal(net, 0)).unwrap(),
        Some(CarrierSignal::SessionFreeze)
    );
}

#[test]
fn a_clean_session_end_is_healthy_and_clears_its_degradation() {
    let id = identity("healthy");
    let net = network(4);
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    ticket.opened();
    ticket.degraded(CarrierSignal::ThroughputCollapse);
    ticket.closed(false);
    drop((ticket, carriers));
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    ticket.opened();
    ticket.closed(false); // healthy: the count clears
    drop((ticket, carriers));
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    ticket.opened();
    ticket.degraded(CarrierSignal::SessionFreeze);
    ticket.closed(false);
    // One degradation since the clean end: still below the threshold.
    assert_eq!(state(id, net, 0), CarrierState::Closed);
}

#[test]
fn faults_of_an_open_session_record_once_and_lose_the_pin_at_the_second() {
    let id = identity("lost");
    let net = network(5);
    let carriers = SessionCarriers::plan(id, Some(&policy()), 3, net).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    ticket.opened();
    ticket.fault(CarrierSignal::DialRefused);
    assert!(
        !ticket.lost(),
        "one transient dial failure keeps the session"
    );
    assert!(matches!(state(id, net, 0), CarrierState::Cooling { .. }));
    ticket.fault(CarrierSignal::DialTimeout);
    assert!(ticket.lost(), "the second ends it");
    // Recorded once: the first cooldown (1 s), never a doubled one.
    match state(id, net, 0) {
        CarrierState::Cooling { remaining } => {
            assert!(remaining <= Duration::from_millis(1_000), "{remaining:?}")
        }
        other => panic!("{other:?}"),
    }
    // A lost session is never a healthy end.
    ticket.closed(false);
    assert_eq!(
        inspect(id, |c| c.last_signal(net, 0)).unwrap(),
        Some(CarrierSignal::DialRefused)
    );
}

#[test]
fn an_unattempted_trial_and_an_unsettled_ticket_release_as_neutral() {
    let id = identity("trial");
    let net = network(6);
    let mut quick = policy();
    quick.base_cooldown_ms = 100;
    quick.max_cooldown_ms = 100;
    let carriers = SessionCarriers::plan(id, Some(&quick), 2, net).unwrap();
    carriers
        .ticket(0)
        .unwrap()
        .fault(CarrierSignal::DialRefused);
    drop(carriers);
    std::thread::sleep(Duration::from_millis(150));
    // Cooled down: one build probes it first, single flight.
    let probing = SessionCarriers::plan(id, Some(&quick), 2, net).unwrap();
    assert_eq!(probing.order(), &[0, 1]);
    assert_eq!(state(id, net, 0), CarrierState::TrialInFlight);
    let concurrent = SessionCarriers::plan(id, Some(&quick), 2, net).unwrap();
    assert_eq!(concurrent.order(), &[1, 0], "the trial is reserved");
    drop(concurrent);
    // The probing build ended before it tried: the trial is released.
    drop(probing);
    assert_eq!(state(id, net, 0), CarrierState::TrialReady);
    // A ticket dropped unsettled is neutral too.
    let probing = SessionCarriers::plan(id, Some(&quick), 2, net).unwrap();
    let ticket = probing.ticket(0).unwrap();
    drop(ticket);
    assert_eq!(state(id, net, 0), CarrierState::TrialReady);
    drop(probing);
    // A trial that opens closes the breaker.
    let probing = SessionCarriers::plan(id, Some(&quick), 2, net).unwrap();
    probing.ticket(0).unwrap().opened();
    assert_eq!(state(id, net, 0), CarrierState::Closed);
}

#[test]
fn the_liveness_policy_sets_the_collapse_threshold() {
    let id = identity("liveness");
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, network(7)).unwrap();
    assert_eq!(
        carriers.ticket(0).unwrap().collapse_rtt(),
        Some(Duration::from_millis(4_000))
    );
    let mut off = policy();
    off.liveness_interval_ms = 0;
    let id = identity("liveness-off");
    let carriers = SessionCarriers::plan(id, Some(&off), 2, network(7)).unwrap();
    assert_eq!(carriers.ticket(0).unwrap().collapse_rtt(), None);
}

#[test]
fn a_profile_keeps_one_controller_and_a_changed_pool_size_is_refused() {
    let id = identity("registry");
    let net = network(8);
    let carriers = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    carriers
        .ticket(0)
        .unwrap()
        .fault(CarrierSignal::EdgeRefused);
    drop(carriers);
    let again = SessionCarriers::plan(id, Some(&policy()), 2, net).unwrap();
    assert_eq!(again.order(), &[1, 0], "the same controller remembers");
    assert!(SessionCarriers::plan(id, Some(&policy()), 3, net).is_err());
    assert_ne!(profile_identity("a"), profile_identity("b"));
}

fn io(kind: io::ErrorKind) -> anyhow::Error {
    anyhow::Error::new(io::Error::from(kind))
}

fn judged(error: &anyhow::Error) -> &(dyn StdError + 'static) {
    error.as_ref()
}

#[tokio::test]
async fn outer_failures_map_to_the_linux_clients_signals_and_identity_or_tls_refusals_to_none() {
    let cut = [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
    ];
    for kind in cut {
        assert_eq!(
            outer_signal(judged(&io(kind))),
            Some(CarrierSignal::HandshakeReset),
            "{kind:?}"
        );
    }
    let message = anyhow::anyhow!("held carrier connect deadline exhausted");
    assert_eq!(
        outer_signal(judged(&message)),
        None,
        "a message alone is no class"
    );
    // connect_h2_from_held's own deadline, as it reports it.
    let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();
    let deadline = anyhow::Error::new(elapsed).context("held carrier connect deadline exhausted");
    assert_eq!(
        outer_signal(judged(&deadline)),
        Some(CarrierSignal::EstablishmentTimeout)
    );
    let timed_out = io(io::ErrorKind::TimedOut);
    assert_eq!(
        outer_signal(judged(&timed_out)),
        Some(CarrierSignal::EstablishmentTimeout)
    );
    for refusal in [
        "secure carrier rejected with HTTP 403 Forbidden",
        "invalid secure carrier content type",
        "secure carrier requires HTTP/2",
    ] {
        assert_eq!(
            outer_signal(judged(&anyhow::anyhow!(refusal))),
            Some(CarrierSignal::EdgeRefused),
            "{refusal}"
        );
        assert_eq!(
            stream_refusal_signal(judged(&anyhow::anyhow!(refusal))),
            Some(CarrierSignal::EdgeRefused)
        );
    }
    assert_eq!(
        outer_signal(judged(&anyhow::anyhow!(
            "H2 driver ended before carrier response: Ok(())"
        ))),
        Some(CarrierSignal::HandshakeReset)
    );
    let lost = anyhow::Error::new(crate::flow_pool::CarrierLost {
        end: crate::flow_pool::ConnEnd::LocalClose,
        unprocessed: true,
    });
    assert_eq!(
        outer_signal(judged(&lost)),
        Some(CarrierSignal::HandshakeReset)
    );
    let reset = anyhow::Error::new(h2::Error::from(h2::Reason::REFUSED_STREAM));
    assert_eq!(
        outer_signal(judged(&reset)),
        Some(CarrierSignal::EdgeRefused)
    );
    // After the session opened, a reset or a connection end under a stream
    // is the pool's own retry, never a fault of the pin.
    assert_eq!(stream_refusal_signal(judged(&reset)), None);
    assert_eq!(stream_refusal_signal(judged(&lost)), None);
    assert_eq!(
        stream_refusal_signal(judged(&io(io::ErrorKind::ConnectionReset))),
        None
    );
    // A TLS error (certificate, alert, ECH rejection) and a refused required
    // ECH stay terminal: never a carrier signal.
    let tls = anyhow::Error::new(io::Error::new(
        io::ErrorKind::InvalidData,
        tokio_rustls::rustls::Error::AlertReceived(
            tokio_rustls::rustls::AlertDescription::BadCertificate,
        ),
    ));
    assert_eq!(outer_signal(judged(&tls)), None);
    assert_eq!(stream_refusal_signal(judged(&tls)), None);
    let ech = anyhow::anyhow!("required ECH was not accepted by the relay (status=Rejected)");
    assert_eq!(outer_signal(judged(&ech)), None);
    assert_eq!(stream_refusal_signal(judged(&ech)), None);
    assert_eq!(outer_signal(judged(&anyhow::anyhow!("local policy"))), None);
    assert_eq!(dial_signal(true), CarrierSignal::DialTimeout);
    assert_eq!(dial_signal(false), CarrierSignal::DialRefused);
}
