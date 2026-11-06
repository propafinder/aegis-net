//! B-06 S23 renewal: the due rule, the monitor's decision table, the step
//! before capture against a loopback enrollment authority (issued, failed
//! with bounded backoff, journaled and recovered, cut between response and
//! Store commit, expired), bound renewal sockets, stop, the XPC verbs and a
//! session sealed for renewal that rebuilds onto the successor.
use super::*;
use crate::{
    app_group::{CapturedAppGroupInputs, CapturedRenewalInputs},
    local_identity::CapturedLocalIdentity,
    provider_session::SessionPhase,
    provider_session_body::{
        spawn_pinned,
        tests::{saved, store_locked, wait_until},
        EpochPins,
    },
    provider_xpc::{
        self, CertStatusReport, Observer, PingReport, RenewReport, Reply, StatusReport, Verb,
    },
    renewal_journal::{self, cut},
    session_rebuild::{classify, Recovery, REFUSALS},
    test_enrollment::{Answer, Successor, TestAuthority, RENEWED_GENERATION, RENEWED_SNAPSHOT},
    test_fixture::ReadyTree,
    test_relay::{
        AckReply, Behavior, RelayIdentity, TestRelay, ADMISSION_TIMEOUT, MAX_ACK_VALID_MS,
    },
};
use aegis_client::protected_online_expectation::ProtectedOnlineExpectation;
use aegis_core::secure_channel::enrollment::protocol::{Operation, ProofPurpose, RequestBinding};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};

thread_local! {
    /// Test override of the import generation the expired gate reads.
    pub(crate) static GENERATION: Cell<Option<u64>> = const { Cell::new(None) };
    /// v31: test override of the process leak guard the step reads:
    /// `Some(relay)` guards with that relay tuple armed (`Some(None)`: none).
    pub(crate) static ARMED_RELAY: Cell<Option<Option<SocketAddr>>> = const { Cell::new(None) };
    /// v31 review: every `identity_renewal` log line this thread wrote, its
    /// fields joined by one space.
    static LOGGED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// v31 review: the step and the monitor log through here (`log_with`).
pub(crate) fn record_log(fields: &[&str]) {
    LOGGED.with(|logged| logged.borrow_mut().push(fields.join(" ")));
}

/// The lines logged on this thread since the last call, which clears them.
fn take_logged() -> Vec<String> {
    LOGGED.with(|logged| std::mem::take(&mut *logged.borrow_mut()))
}

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

fn now() -> u64 {
    registry::unix_now().unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A tree whose certificate began `age` seconds ago, for `lifetime`.
fn aged(authority: SocketAddr, age: u64, lifetime: u64) -> ReadyTree {
    ReadyTree::renewable(
        "127.0.0.1:443".parse().unwrap(),
        authority,
        now() - age,
        lifetime,
    )
}

/// A due tree (17 h into 24 h: due since 1 h), its successor and authority.
fn due_with(
    answers: impl FnMut(usize, Option<ProofPurpose>) -> Answer + Send + 'static,
) -> (ReadyTree, Successor, TestAuthority) {
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), answers);
    (tree, successor, authority)
}

struct Harness {
    renewal: RenewalHandle,
    bound: Arc<Mutex<Vec<u32>>>,
    captures: AtomicUsize,
    stop: Arc<AtomicBool>,
}

impl Harness {
    fn new() -> Self {
        Self {
            renewal: RenewalHandle::default(),
            bound: Arc::default(),
            captures: AtomicUsize::new(0),
            stop: Arc::default(),
        }
    }

    /// The production step over the unsigned test root, loopback-bound.
    fn run(&self, tree: &ReadyTree) -> Result<(), Refusal> {
        let lo = RelayInterface::loopback_for_test();
        let interface = move |_| Ok(lo.clone());
        let stop = self.stop.clone();
        let stopping = move || stop.load(Ordering::SeqCst);
        before_capture(
            &Step {
                renewal: &self.renewal,
                interface: &interface,
                stop: &stopping,
                bound: Some(self.bound.clone()),
            },
            || {
                self.captures.fetch_add(1, Ordering::SeqCst);
                CapturedRenewalInputs::capture_test_root(tree.root())
            },
        )
    }

    /// `run` over another App Group container (an import target).
    fn run_at(&self, container: &std::path::Path) -> Result<(), Refusal> {
        let lo = RelayInterface::loopback_for_test();
        let interface = move |_| Ok(lo.clone());
        before_capture(
            &Step {
                renewal: &self.renewal,
                interface: &interface,
                stop: &|| false,
                bound: Some(self.bound.clone()),
            },
            || {
                self.captures.fetch_add(1, Ordering::SeqCst);
                CapturedRenewalInputs::capture_test_root(container)
            },
        )
    }

    fn token(&self) -> String {
        self.renewal.with(|state| state.token(now()))
    }
}

fn journal_absent(tree: &ReadyTree) -> bool {
    [renewal_journal::REQUEST, renewal_journal::RESPONSE]
        .iter()
        .all(|leaf| !tree.identity_dir().join(leaf).exists())
}

/// The Store's admitted certificate fingerprint, not_after and generation.
fn installed(tree: &ReadyTree) -> (String, u64, Option<u64>) {
    let store =
        ProtectedOnlineExpectation::open_existing(&tree.identity_dir(), tree.profile_sha256())
            .unwrap();
    let online = store.expectation_at(now()).unwrap();
    (
        online.certificate_sha256,
        online.not_after_unix_secs,
        online.issued_generation,
    )
}

/// A fresh provider claim admits exactly the successor (S22 custody).
fn admits_successor(tree: &ReadyTree, successor: &Successor) {
    let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    assert_eq!(
        inputs.held_window(),
        (successor.not_before, successor.not_after)
    );
    let identity = CapturedLocalIdentity::from_claim(inputs).unwrap();
    drop(identity);
    assert_eq!(
        installed(tree),
        (
            successor.fingerprint.clone(),
            successor.not_after,
            Some(RENEWED_GENERATION)
        )
    );
    assert_eq!(
        std::fs::read(tree.identity_dir().join("device.pem")).unwrap(),
        successor.certificate_pem.as_bytes()
    );
    assert!(journal_absent(tree));
}

fn bound_only_to(harness: &Harness, interface: &RelayInterface) -> usize {
    let bound = harness.bound.lock().unwrap();
    assert!(
        bound.iter().all(|index| *index == interface.index()),
        "{bound:?}"
    );
    bound.len()
}

// ---------------------------------------------------------------------------
// The due rule and the monitor.

#[test]
fn renewal_due_rule_matches_the_library_at_every_boundary() {
    // macos-test-1, 22 Oct 2026: due 04:17:33 UTC, expired 12:17:33 UTC.
    let (nb, na) = (1_792_585_053, 1_792_671_453);
    let library = |nb: u64, na: u64| nb + (na - nb) * 2 / 3;
    assert_eq!(renewal_due_at(nb, na), 1_792_642_653);
    for (nb, na) in [(nb, na), (0, 3), (100, 160), (5, 5), (1_000, 1_001)] {
        assert_eq!(renewal_due_at(nb, na), library(nb, na), "{nb} {na}");
    }
    let due = renewal_due_at(nb, na);
    for (at, expected) in [
        (nb - 1, Window::NotYetValid),
        (nb, Window::Valid),
        (due - 1, Window::Valid),
        (due, Window::Due),
        (na - 1, Window::Due),
        (na, Window::Expired),
        (u64::MAX, Window::Expired),
    ] {
        assert_eq!(identity_window(at, nb, na), expected, "{at}");
    }
}

#[test]
fn renewal_attempt_waits_a_bounded_skew_margin_after_due() {
    let (nb, na) = (1_792_585_053, 1_792_671_453);
    assert_eq!(
        renewal_attempt_at(nb, na),
        renewal_due_at(nb, na) + SKEW_MARGIN_SECS
    );
    // Never more than a quarter of the time left from due to expiry.
    assert_eq!(renewal_attempt_at(100, 160), 145);
    assert_eq!(renewal_attempt_at(0, 3), 2);
    assert_eq!(renewal_attempt_at(5, 5), 5);
    for (nb, na) in [(nb, na), (100, 160), (0, 3), (1_000, 1_001)] {
        assert!(renewal_attempt_at(nb, na) < na, "{nb} {na}");
    }
}

#[test]
fn renewal_backoff_doubles_to_its_cap_and_never_reaches_expiry() {
    let delays: Vec<u64> = (1..=8).map(backoff_secs).collect();
    assert_eq!(delays, [60, 120, 240, 480, 900, 900, 900, 900]);
    assert_eq!(backoff_secs(u32::MAX), BACKOFF_CAP_SECS);
    let mut state = RenewalState::default();
    state.observed(1_000, 10_000, false);
    state.failed(9_000, FailureClass::Unavailable, false);
    assert_eq!((state.attempts, state.next_attempt_at), (1, 9_060));
    state.failed(9_970, FailureClass::Timeout, false);
    // 9_970 + 120 would pass not_after: the last attempt is before it.
    assert_eq!((state.attempts, state.next_attempt_at), (2, 9_999));
    assert_eq!(state.token(9_980), "failed:timeout");
}

#[test]
fn renewal_monitor_seals_only_a_live_due_session_outside_backoff() {
    let (nb, na) = (1_000, 4_000);
    let due = renewal_due_at(nb, na);
    let at = renewal_attempt_at(nb, na);
    assert_eq!(at, due + SKEW_MARGIN_SECS);
    let mut state = RenewalState::default();
    assert_eq!(decide(at, &state, false, true), Action::None, "no window");
    state.admitted(nb, na);
    assert_eq!(
        decide(due - 1, &state, false, true),
        Action::None,
        "not due"
    );
    // Due, but within the skew margin the authority may still refuse it.
    assert_eq!(decide(due, &state, false, true), Action::None, "margin");
    assert_eq!(decide(at - 1, &state, false, true), Action::None, "margin");
    assert_eq!(decide(at, &state, false, true), Action::Seal);
    assert_eq!(decide(na - 1, &state, false, true), Action::Seal);
    assert_eq!(decide(na, &state, false, true), Action::None, "expired");
    assert_eq!(decide(nb - 1, &state, false, true), Action::None);
    assert_eq!(decide(at, &state, false, false), Action::None, "not live");
    assert_eq!(decide(at, &state, true, true), Action::SkipAuthBackoff);
    state.next_attempt_at = at + 10;
    assert_eq!(decide(at + 9, &state, false, true), Action::None, "backoff");
    assert_eq!(decide(at + 10, &state, false, true), Action::Seal);
    state.forced = true;
    assert_eq!(decide(at + 9, &state, false, true), Action::Seal, "forced");
    // A forced renewal does not wait out the margin.
    assert_eq!(decide(due, &state, false, true), Action::Seal, "forced");
    state.forced = false;
    state.pending = true;
    assert_eq!(
        decide(due - 1, &state, false, true),
        Action::None,
        "pending, backoff"
    );
    state.next_attempt_at = 0;
    assert_eq!(
        decide(due - 1, &state, false, true),
        Action::Seal,
        "pending"
    );
    state.last = Last::InProgress;
    assert_eq!(
        decide(due, &state, false, true),
        Action::None,
        "in progress"
    );
}

#[test]
fn renewal_monitor_checks_every_interval_and_sooner_once_forced() {
    let handle = RenewalHandle::default();
    let start = Instant::now();
    assert!(check_due(&handle, start));
    assert!(!check_due(
        &handle,
        start + CHECK_INTERVAL - Duration::from_millis(1)
    ));
    assert!(check_due(&handle, start + CHECK_INTERVAL));
    handle.with(|state| state.forced = true);
    let at = start + CHECK_INTERVAL;
    assert!(!check_due(
        &handle,
        at + FORCED_CHECK_INTERVAL - Duration::from_millis(1)
    ));
    assert!(check_due(&handle, at + FORCED_CHECK_INTERVAL));
}

#[test]
fn renew_verb_is_refused_unless_due_or_journaled() {
    assert_eq!(request_renewal_of(None, 10), Err("no_epoch"));
    let handle = RenewalHandle::default();
    assert_eq!(
        request_renewal_of(Some(&handle), 10),
        Err("identity_unknown")
    );
    handle.with(|state| state.admitted(1_000, 4_000));
    let due = renewal_due_at(1_000, 4_000);
    assert_eq!(
        request_renewal_of(Some(&handle), due - 1),
        Err("renewal_not_due")
    );
    assert!(!handle.snapshot().forced);
    assert_eq!(
        request_renewal_of(Some(&handle), 4_000),
        Err("identity_expired")
    );
    assert_eq!(
        request_renewal_of(Some(&handle), due),
        Ok("renew_scheduled")
    );
    assert!(handle.snapshot().forced);
    let pending = RenewalHandle::default();
    pending.with(|state| state.observed(1_000, 4_000, true));
    assert_eq!(
        request_renewal_of(Some(&pending), 1_500),
        Ok("renew_scheduled")
    );
}

#[test]
fn cert_status_reports_window_state_and_failures_without_material() {
    assert_eq!(cert_status_of(None, 1), Err("no_epoch"));
    let handle = RenewalHandle::default();
    assert_eq!(cert_status_of(Some(&handle), 1).unwrap().state, "unknown");
    handle.with(|state| state.admitted(1_000, 4_000));
    let report = cert_status_of(Some(&handle), 1_500).unwrap();
    assert_eq!(
        report,
        CertStatusReport {
            state: "valid".into(),
            not_before: Some(1_000),
            not_after: Some(4_000),
            renew_at: Some(3_000),
            attempts: 0,
            last_attempt_at: None,
            next_attempt_at: None,
            last_failure: None,
            failing_since: None,
            check: None,
        }
    );
    assert_eq!(cert_status_of(Some(&handle), 3_000).unwrap().state, "due");
    handle.with(|state| {
        state.last_attempt_at = Some(3_100);
        state.failed(3_100, FailureClass::Unavailable, false);
    });
    let failed = cert_status_of(Some(&handle), 3_200).unwrap();
    assert_eq!(failed.state, "failed:unavailable");
    assert_eq!(failed.last_failure.as_deref(), Some("unavailable"));
    assert_eq!((failed.attempts, failed.next_attempt_at), (1, Some(3_160)));
    handle.with(|state| state.pending = true);
    assert_eq!(
        cert_status_of(Some(&handle), 3_200).unwrap().state,
        "pending"
    );
    assert_eq!(
        cert_status_of(Some(&handle), 4_000).unwrap().state,
        "expired"
    );
    handle.with(|state| state.renewed(3_500, 9_000));
    assert_eq!(
        cert_status_of(Some(&handle), 3_600).unwrap().state,
        "renewed_pending_ack"
    );
    handle.with(|state| state.admitted(3_500, 9_000));
    assert_eq!(cert_status_of(Some(&handle), 3_600).unwrap().state, "valid");
    // v32: the check, beside local_refused only, and the new states.
    handle.with(|state| {
        state.failed_at(
            6_600,
            FailureClass::LocalRefused,
            Journal::Blocking,
            Some(renewal_journal::SUCCESSOR_NOT_EXTENDING),
        );
        state.issued = Some(renewal_journal::SUCCESSOR_NOT_EXTENDING);
    });
    let superseded = cert_status_of(Some(&handle), 6_700).unwrap();
    assert_eq!(superseded.state, "superseded");
    assert_eq!(
        superseded.check.as_deref(),
        Some(renewal_journal::SUCCESSOR_NOT_EXTENDING)
    );
    // v32 review: a later failure of the superseded request keeps naming
    // the receipt check.
    handle.with(|state| state.failed_at(6_750, FailureClass::Rejected, Journal::Blocking, None));
    let later = cert_status_of(Some(&handle), 6_760).unwrap();
    assert_eq!(
        (later.state.as_str(), later.last_failure.as_deref()),
        ("superseded", Some("rejected"))
    );
    assert_eq!(
        later.check.as_deref(),
        Some(renewal_journal::SUCCESSOR_NOT_EXTENDING)
    );
    handle.with(|state| state.failed_at(6_800, FailureClass::Rejected, Journal::Parked, None));
    let parked = cert_status_of(Some(&handle), 6_900).unwrap();
    assert_eq!((parked.state.as_str(), parked.check), ("parked", None));
    // v32 review: a refused park keeps the authority's class beside its
    // check (no issued answer: the step's own observation clears it).
    handle.with(|state| {
        state.issued = None;
        state.failed_at(
            6_900,
            FailureClass::Rejected,
            Journal::Blocking,
            Some(renewal_journal::PARKED_REFUSED),
        )
    });
    let refused = cert_status_of(Some(&handle), 6_950).unwrap();
    assert_eq!(
        (refused.state.as_str(), refused.last_failure.as_deref()),
        ("pending", Some("rejected"))
    );
    assert_eq!(
        refused.check.as_deref(),
        Some(renewal_journal::PARKED_REFUSED)
    );
    handle.with(|state| state.admitted(3_500, 9_000));
    // Every token, failure class and log line is a stable code.
    for class in [
        FailureClass::Unavailable,
        FailureClass::Timeout,
        FailureClass::Rejected,
        FailureClass::RecoveryRequired,
        FailureClass::LocalRefused,
        FailureClass::InterfaceUnresolved,
    ] {
        assert!(provider_xpc::FAILURE_CLASSES.contains(&class.token()));
        let state = format!("state:failed:{}", class.token());
        assert!(crate::apple::stable_fields(
            "identity_renewal",
            &[&state, "attempt:3", "next_s:900"]
        ));
    }
    for state in [
        "state:due",
        "state:start",
        "state:issued",
        "state:expired",
        "state:stopped",
        "state:not_due",
        "state:pending",
        "state:skipped:auth_backoff",
    ] {
        assert!(crate::apple::stable_fields(
            "identity_renewal",
            &[state, "attempt:0"]
        ));
    }
}

#[test]
fn renewal_refusal_codes_are_listed_and_recoverable() {
    for code in [
        IDENTITY_RENEWAL_DUE,
        IDENTITY_RENEWAL_PENDING,
        IDENTITY_RENEWAL_STOPPED,
        renewal_journal::BUSY,
        SESSION_IDENTITY_EXPIRED,
    ] {
        assert!(
            REFUSALS.iter().any(|(listed, _)| *listed == code),
            "{code} unlisted"
        );
        assert_eq!(classify(code), Recovery::Recoverable, "{code}");
    }
}

// ---------------------------------------------------------------------------
// The journal's encodings.

#[test]
fn renewal_journal_writes_the_binary_record_bytes_and_never_parses_invitations() {
    let record = br#"{"certificate_sha256":"aa","device_ca_sha256":"bb","device_id":"fixture-device-1","phase":"ready","version":1}"#;
    assert_eq!(
        renewal_journal::test_access::record_round_trip(record).unwrap(),
        br#"{"version":1,"device_id":"fixture-device-1","phase":"ready","device_ca_sha256":"bb","certificate_sha256":"aa"}"#
    );
    // Missing, wrong-version, unknown-key and unknown-phase records.
    for bad in [
        &br#"{"version":1,"device_id":"fixture-device-1","phase":"ready","device_ca_sha256":"bb"}"#[..],
        br#"{"version":2,"device_id":"fixture-device-1","phase":"ready","device_ca_sha256":"bb","certificate_sha256":"aa"}"#,
        br#"{"version":1,"device_id":"fixture-device-1","phase":"ready","device_ca_sha256":"bb","certificate_sha256":"aa","x":1}"#,
        br#"{"version":1,"device_id":"fixture-device-1","phase":"other","device_ca_sha256":"bb","certificate_sha256":"aa"}"#,
    ] {
        assert!(renewal_journal::test_access::record_round_trip(bad).is_none());
    }
    let binding = |operation: &str| {
        format!(
            r#"{{"operation":"{operation}","request_id":"{}","profile_sha256":"{}","csr_sha256":"{}","predecessor_sha256":null}}"#,
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64)
        )
    };
    let renew = format!(
        r#"{{"version":1,"binding":{},"predecessor_certificate_pem":null,"invitation":null}}"#,
        binding("renew")
    );
    assert!(renewal_journal::test_access::pending_parses(
        renew.as_bytes()
    ));
    for refused in [
        format!(
            r#"{{"version":1,"binding":{},"predecessor_certificate_pem":null,"invitation":"{}"}}"#,
            binding("renew"),
            "a".repeat(64)
        ),
        format!(
            r#"{{"version":1,"binding":{},"predecessor_certificate_pem":null,"invitation":null}}"#,
            binding("redeem")
        ),
    ] {
        assert!(!renewal_journal::test_access::pending_parses(
            refused.as_bytes()
        ));
    }
}

// ---------------------------------------------------------------------------
// The step before capture, against the loopback authority.

#[test]
fn renewal_before_due_contacts_nothing_and_writes_nothing() {
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 60, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Issue);
    let harness = Harness::new();
    let before = std::fs::read(tree.identity_dir().join("device.pem")).unwrap();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(harness.token(), "valid");
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    // Known valid window: the next step does no I/O at all.
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    assert_eq!(authority.accepts(), 0);
    assert!(journal_absent(&tree));
    assert_eq!(
        std::fs::read(tree.identity_dir().join("device.pem")).unwrap(),
        before
    );
    assert_eq!(
        request_renewal_of(Some(&harness.renewal), now()),
        Err("renewal_not_due")
    );
    // No Store lock or tree lease outlives the step.
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn renewal_due_renews_once_on_bound_sockets_and_the_next_capture_admits_it() {
    let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
    let old = tree.online().certificate_sha256.clone();
    let harness = Harness::new();
    assert_eq!(harness.token(), "unknown");
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
    let seen = authority.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].purpose, ProofPurpose::Authorize);
    assert_ne!(successor.fingerprint, old);
    admits_successor(&tree, &successor);
    assert_eq!(harness.token(), "renewed_pending_ack");
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(
        (report.not_before, report.not_after, report.attempts),
        (Some(successor.not_before), Some(successor.not_after), 0)
    );
    // Every renewal socket was bound to the given (pinned) interface.
    assert_eq!(
        bound_only_to(&harness, &RelayInterface::loopback_for_test()),
        1
    );
    // Renewed and valid: the next step is quiet.
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 1);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn renewal_failure_keeps_the_old_certificate_with_bounded_backoff() {
    // A dead authority: every connection ends before outer TLS.
    let (tree, _successor, authority) = due_with(|_, _| Answer::Close);
    let old = installed(&tree);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()), "old certificate is captured");
    assert_eq!(authority.accepts(), 3, "three attempts in one step");
    assert!(journal_absent(&tree), "no request before a challenge");
    assert_eq!(installed(&tree), old);
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(report.state, "failed:unavailable");
    assert_eq!(report.attempts, 1);
    let next = report.next_attempt_at.unwrap();
    assert!(next + 2 >= now() + BACKOFF_FIRST_SECS && next <= now() + BACKOFF_FIRST_SECS);
    // Within the backoff: no attempt, the old certificate again.
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 3);
    // Once due again: the next attempt, and the delay doubles.
    harness.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 6);
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(report.attempts, 2);
    assert!(report.next_attempt_at.unwrap() + 2 >= now() + 2 * BACKOFF_FIRST_SECS);
    assert_eq!(
        bound_only_to(&harness, &RelayInterface::loopback_for_test()),
        6
    );
    assert_eq!(installed(&tree), old);
}

#[test]
fn renewal_busy_journals_then_receipt_and_authorize_recover_exactly_once() {
    let mode = Arc::new(AtomicU8::new(0));
    let answering = mode.clone();
    let (tree, successor, authority) = due_with(move |index, purpose| match purpose {
        None => Answer::Issue,
        Some(_) if answering.load(Ordering::SeqCst) == 1 => Answer::Issue,
        Some(_) if index == 2 => Answer::Unavailable,
        Some(_) => Answer::Busy,
    });
    let harness = Harness::new();
    let refused = harness.run(&tree).unwrap_err();
    assert_eq!(refused.code, IDENTITY_RENEWAL_PENDING);
    assert_eq!(refused.recovery, Recovery::Recoverable);
    assert_eq!(harness.token(), "pending");
    let purposes: Vec<_> = authority.seen().iter().map(|seen| seen.purpose).collect();
    assert_eq!(
        purposes,
        [
            ProofPurpose::Authorize,
            ProofPurpose::Receipt,
            ProofPurpose::Receipt
        ]
    );
    assert!(tree.identity_dir().join(renewal_journal::REQUEST).exists());
    // Beside that journal a session capture would be terminal custody: the
    // step's own refusal is what keeps the rebuild recoverable.
    let capture = CapturedAppGroupInputs::capture_test_root(tree.root())
        .err()
        .unwrap();
    assert_eq!(
        Refusal::custody(&capture).code,
        crate::identity_custody::JOURNAL_PENDING
    );
    assert_eq!(Refusal::custody(&capture).recovery, Recovery::Terminal);
    // Within the backoff the journal still refuses, recoverably.
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING
    );
    assert_eq!(authority.seen().len(), 3);
    // The authority recovers: receipt first (none issued), then authorize.
    mode.store(1, Ordering::SeqCst);
    harness.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(harness.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(seen.len(), 5);
    assert_eq!(
        (seen[3].purpose, seen[4].purpose),
        (ProofPurpose::Receipt, ProofPurpose::Authorize)
    );
    assert!(seen
        .iter()
        .all(|request| request.request_id == seen[0].request_id));
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_parks_after_the_authority_rejects_outside_the_skew_window() {
    // v32 (T3): a request the authority only ever rejected is parked, and
    // the installed certificate is captured beside it (v31: refused with
    // identity_renewal_pending and the request kept blocking). v32 review:
    // only a request written in this step (or parked, or settled under this
    // process's watch); one found journaled at the start is never parked
    // (`renewal_never_parks_a_request_whose_earlier_answer_may_be_lost`).
    for (answer, class) in [
        (Answer::Rejected, "rejected"),
        (Answer::RecoveryRequired, "recovery_required"),
    ] {
        let (tree, _successor, authority) = due_with(move |_, _| answer);
        let old = installed(&tree);
        let harness = Harness::new();
        take_logged();
        assert_eq!(harness.run(&tree), Ok(()), "{answer:?}");
        // One authorization, rejected.
        let requests = 1;
        assert_eq!(authority.seen().len(), requests);
        assert_eq!(authority.issued(), 0);
        assert!(!tree.identity_dir().join(renewal_journal::REQUEST).exists());
        assert!(tree.identity_dir().join(renewal_journal::PARKED).exists());
        // The capture admits the installed certificate beside it.
        let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        assert_eq!(
            inputs.held_window(),
            (tree.not_before(), tree.not_before() + DAY)
        );
        drop(inputs);
        assert_eq!(installed(&tree), old);
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!(report.state, "parked", "{answer:?}");
        assert_eq!(report.last_failure.as_deref(), Some(class));
        assert_eq!(report.check, None);
        // Far past the skew margin: the full backoff, never a short retry.
        let next = report.next_attempt_at.unwrap();
        assert!(next + 2 >= now() + BACKOFF_FIRST_SECS, "{answer:?}");
        let logged = take_logged();
        assert!(
            logged.contains(&format!("state:parked attempt:1 check:{class}")),
            "{logged:?}"
        );
        // A second start inside the backoff: no dial, the capture again.
        assert_eq!(harness.run(&tree), Ok(()));
        assert_eq!(authority.seen().len(), requests);
        assert!(take_logged()
            .iter()
            .any(|line| line.starts_with("state:waiting:parked attempt:0 next_s:")));
    }
}

/// v32 review: the step's request stays the blocking journal, the start is
/// refused and the session capture with it (no relay dial can present a
/// predecessor the authority may have superseded).
fn kept_blocking(tree: &ReadyTree, harness: &Harness, class: &str, case: &str) {
    assert!(leaf_exists(tree, renewal_journal::REQUEST), "{case}");
    assert!(!leaf_exists(tree, renewal_journal::PARKED), "{case}");
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(report.state, "pending", "{case}");
    assert_eq!(report.last_failure.as_deref(), Some(class), "{case}");
    assert_eq!(report.check, None, "{case}");
    let capture = CapturedAppGroupInputs::capture_test_root(tree.root())
        .err()
        .unwrap();
    assert_eq!(
        Refusal::custody(&capture).code,
        crate::identity_custody::JOURNAL_PENDING,
        "{case}"
    );
}

#[test]
fn renewal_never_parks_a_request_whose_earlier_answer_may_be_lost() {
    // v32 review: Rejected does not prove the authority committed nothing
    // (aegis-server answers Rejected for every issuer error, another
    // device's retained issuance among them), so a request one of whose
    // requests went unanswered is never parked (v32 parked it and captured
    // the predecessor the authority's registry no longer names).
    //
    // (a) In one step: the authority commits the authorization and its
    // answer is lost; the receipt and a second authorization are rejected.
    let (tree, _successor, authority) = due_with(|index, purpose| match (index, purpose) {
        (_, None) => Answer::Issue,
        (0, Some(_)) => Answer::DropResponse,
        _ => Answer::Rejected,
    });
    let harness = Harness::new();
    take_logged();
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING,
        "same step"
    );
    assert_eq!(authority.issued(), 1, "committed");
    let purposes: Vec<_> = authority.seen().iter().map(|seen| seen.purpose).collect();
    assert_eq!(
        purposes,
        [
            ProofPurpose::Authorize,
            ProofPurpose::Receipt,
            ProofPurpose::Authorize
        ]
    );
    kept_blocking(&tree, &harness, "rejected", "same step");
    let logged = take_logged();
    assert!(lines_from(&logged, "state:parked").is_empty(), "{logged:?}");
    assert!(logged.contains(&"state:failed:rejected attempt:1 next_s:60 dials:3".to_string()));

    // (b) Across Connects of one provider process: the first Connect's
    // committed answer is lost, then the authority is unavailable; the next
    // Connect (at once: the outcome is unknown) is rejected twice.
    let _generation = Generation::set(32_101);
    let mode = Arc::new(AtomicU8::new(0));
    let answering = mode.clone();
    let (tree, _successor, authority) =
        due_with(
            move |index, purpose| match (answering.load(Ordering::SeqCst), index, purpose) {
                (_, _, None) => Answer::Issue,
                (0, 0, Some(_)) => Answer::DropResponse,
                (0, _, Some(_)) => Answer::Unavailable,
                _ => Answer::Rejected,
            },
        );
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    assert_eq!(authority.issued(), 1);
    mode.store(1, Ordering::SeqCst);
    let second = Harness::carried(&carry);
    assert_eq!(
        second.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING,
        "second connect"
    );
    let purposes: Vec<_> = authority.seen()[3..]
        .iter()
        .map(|seen| seen.purpose)
        .collect();
    assert_eq!(purposes, [ProofPurpose::Receipt, ProofPurpose::Authorize]);
    kept_blocking(&tree, &second, "rejected", "second connect");
    // The rejection paces it: the third Connect makes no dial.
    let third = Harness::carried(&carry);
    take_logged();
    assert_eq!(
        third.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING,
        "third connect"
    );
    assert_eq!(authority.seen().len(), 5, "paced");
    assert!(take_logged()
        .iter()
        .any(|line| line.starts_with("state:pending attempt:0 next_s:")));

    // (c) A request journaled before this provider process started (v31
    // left it, or the provider restarted: for macos-test-2, v32's first
    // Connect after an authority CA, profile or registry change): its
    // history is unknown, so a rejection keeps it journaled at any time.
    for (answer, class) in [
        (Answer::Rejected, "rejected"),
        (Answer::RecoveryRequired, "recovery_required"),
    ] {
        let (tree, _successor, authority) = due_with(move |_, _| answer);
        journal_request(&tree);
        let request = read_leaf(&tree, renewal_journal::REQUEST);
        let harness = Harness::new();
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{answer:?}"
        );
        // The receipt first; only a rejected receipt is followed by an
        // authorization.
        assert_eq!(
            authority.seen().len(),
            1 + usize::from(answer == Answer::Rejected)
        );
        assert_eq!(read_leaf(&tree, renewal_journal::REQUEST), request);
        kept_blocking(&tree, &harness, class, "journaled");
    }
}

#[test]
fn renewal_supersedes_on_a_successor_signed_before_the_due_instant() {
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    // Signed before the predecessor's due instant: not a renewal of it.
    let early = Successor::signed_at(&tree, tree.not_before() + HOUR, DAY);
    let authority = TestAuthority::spawn(listener, &tree, early, |_, _| Answer::Issue);
    let old = installed(&tree);
    let pem = std::fs::read(tree.identity_dir().join("device.pem")).unwrap();
    let harness = Harness::new();
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING
    );
    assert_eq!(authority.issued(), 1);
    // Verified before any write: no response, no replacement, never parked.
    assert!(!tree.identity_dir().join(renewal_journal::RESPONSE).exists());
    assert!(!tree.identity_dir().join(renewal_journal::PARKED).exists());
    assert!(tree.identity_dir().join(renewal_journal::REQUEST).exists());
    assert_eq!(
        std::fs::read(tree.identity_dir().join("device.pem")).unwrap(),
        pem
    );
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(report.state, "superseded");
    assert_eq!(report.last_failure.as_deref(), Some("local_refused"));
    assert_eq!(
        report.check.as_deref(),
        Some(renewal_journal::SUCCESSOR_BEFORE_DUE)
    );
    // The installed record still names the predecessor.
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tree.identity_dir().join("identity.json")).unwrap())
            .unwrap();
    assert_eq!(record["certificate_sha256"], old.0.as_str());
}

#[test]
fn renewal_lost_response_is_recovered_by_receipt_in_the_same_step() {
    let (tree, successor, authority) = due_with(|index, _| {
        if index == 0 {
            Answer::DropResponse
        } else {
            Answer::Issue
        }
    });
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(
        seen.iter().map(|s| s.purpose).collect::<Vec<_>>(),
        [ProofPurpose::Authorize, ProofPurpose::Receipt]
    );
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_cut_between_response_and_store_commit_recovers_one_identity_on_next_start() {
    for point in [
        "response_saved",
        "certificate_replaced",
        "record_saved",
        "completed_saved",
        "request_removed",
    ] {
        let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
        let harness = Harness::new();
        cut::set(Some(point));
        let refused = harness.run(&tree);
        cut::set(None);
        assert_eq!(
            refused.unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{point}"
        );
        assert!(
            tree.identity_dir().join(renewal_journal::RESPONSE).exists(),
            "{point}"
        );
        // The request goes first; the response alone recovers the last cut.
        assert_eq!(
            tree.identity_dir().join(renewal_journal::REQUEST).exists(),
            point != "request_removed",
            "{point}"
        );
        assert_eq!(authority.issued(), 1);
        // A provider restart: a new epoch's step finishes it locally.
        let restarted = Harness::new();
        assert_eq!(restarted.run(&tree), Ok(()), "{point}");
        assert_eq!(authority.accepts(), 1, "{point}: no network on recovery");
        assert_eq!(restarted.token(), "renewed_pending_ack");
        admits_successor(&tree, &successor);
        // Exactly one identity: the record, certificate and receipt agree.
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(tree.identity_dir().join("identity.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record["certificate_sha256"], successor.fingerprint.as_str());
        let completed: serde_json::Value = serde_json::from_slice(
            &std::fs::read(tree.identity_dir().join("online-completed.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            completed["receipt"]["certificate_sha256"],
            successor.fingerprint.as_str()
        );
        assert_eq!(
            completed["predecessor_certificate_pem"],
            tree.certificate_pem()
        );
        let leftovers: Vec<_> = std::fs::read_dir(tree.identity_dir())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{point}: {leftovers:?}");
    }
}

#[test]
fn renewal_of_an_expired_identity_is_refused_without_an_attempt_loop() {
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Issue);
    GENERATION.with(|generation| generation.set(Some(41)));
    // v32: the epoch's record is carried (the next Connect's epoch below).
    let carry: Arc<Carry> = Arc::default();
    let harness = Harness::carried(&carry);
    let refused = harness.run(&tree).unwrap_err();
    assert_eq!(refused.code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(refused.recovery, Recovery::Recoverable);
    assert_eq!(harness.token(), "expired");
    assert_eq!(
        request_renewal_of(Some(&harness.renewal), now()),
        Err("identity_expired")
    );
    // The gate: no capture, no lease, no Store and no network while the
    // import generation is unchanged.
    for _ in 0..3 {
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            SESSION_IDENTITY_EXPIRED
        );
    }
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    assert_eq!(authority.accepts(), 0);
    assert!(journal_absent(&tree));
    // v32: the next Connect's new epoch takes up the carried gate: no
    // capture either.
    let next = Harness::carried(&carry);
    assert_eq!(next.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(next.captures.load(Ordering::SeqCst), 0);
    // A committed import (or forget) lifts the gate for one fresh look.
    GENERATION.with(|generation| generation.set(Some(42)));
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(harness.captures.load(Ordering::SeqCst), 2);
    GENERATION.with(|generation| generation.set(None));
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn renewal_expired_gate_lifts_once_an_import_or_forget_commits() {
    use crate::identity_import::{
        forget_identity, import_tree,
        tests::{gate, payload_of, uid, TempContainer},
        IDENTITY_GENERATION,
    };
    let target = TempContainer::new();
    let source = ReadyTree::with_online_completed("127.0.0.1:443".parse().unwrap());
    // An epoch gated on an expired identity under the current generation.
    let harness = Harness::new();
    let gated = IDENTITY_GENERATION.load(Ordering::Acquire);
    harness
        .renewal
        .with(|state| state.expired_under = Some((gated, 0)));
    // The gate holds no capture lease: the import commits beside it.
    import_tree(target.path(), uid(), gate(), &payload_of(&source), |_| {}).unwrap();
    let imported = IDENTITY_GENERATION.load(Ordering::Acquire);
    assert!(imported > gated);
    // The next step looks again and admits the imported identity.
    assert_eq!(harness.run_at(target.path()), Ok(()));
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    assert_eq!(harness.token(), "valid");
    forget_identity(target.path(), uid(), gate()).unwrap();
    assert!(IDENTITY_GENERATION.load(Ordering::Acquire) > imported);
}

/// An expired predecessor with a Renew request journaled before expiry.
fn expired_with_request(answer: Answer) -> (ReadyTree, Successor, TestAuthority, RequestBinding) {
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let old_not_after = tree.not_before() + DAY;
    // The authority committed it ten minutes before the predecessor expired.
    let successor = Successor::signed_at(&tree, old_not_after - 600, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), move |_, _| answer);
    let binding = journal_request(&tree);
    (tree, successor, authority, binding)
}

/// Journal a Renew request of the installed certificate, as an earlier
/// step that never got its answer would have.
fn journal_request(tree: &ReadyTree) -> RequestBinding {
    let binding = RequestBinding {
        operation: Operation::Renew,
        request_id: "e".repeat(64),
        profile_sha256: tree.profile_sha256().into(),
        csr_sha256: sha256_hex(tree.csr_pem().as_bytes()),
        predecessor_sha256: Some(tree.online().certificate_sha256.clone()),
    };
    let request = format!(
        r#"{{"version":1,"binding":{},"predecessor_certificate_pem":{},"invitation":null}}"#,
        serde_json::to_string(&binding).unwrap(),
        serde_json::to_string(tree.certificate_pem()).unwrap()
    );
    tree.write_identity_file(renewal_journal::REQUEST, request.as_bytes());
    binding
}

#[test]
fn renewal_of_an_expired_identity_recovers_only_a_request_journaled_before_expiry() {
    let (tree, successor, authority, binding) = expired_with_request(Answer::Issue);
    authority.remember(binding);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].purpose, ProofPurpose::Receipt, "receipt only");
    admits_successor(&tree, &successor);

    // Nothing to recover: one receipt attempt, then the expired gate.
    let (tree, _successor, authority, _binding) = expired_with_request(Answer::Issue);
    GENERATION.with(|generation| generation.set(Some(7)));
    let harness = Harness::new();
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(
        authority
            .seen()
            .iter()
            .map(|s| s.purpose)
            .collect::<Vec<_>>(),
        [ProofPurpose::Receipt],
        "never an authorization with an expired predecessor"
    );
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    assert_eq!(authority.seen().len(), 1);
    GENERATION.with(|generation| generation.set(None));
}

#[test]
fn renewal_step_ends_promptly_on_provider_stop() {
    let (tree, _successor, authority) = due_with(|_, _| Answer::Hang);
    let harness = Harness::new();
    let stop = harness.stop.clone();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::SeqCst);
    });
    let started = Instant::now();
    let refused = harness.run(&tree).unwrap_err();
    let took = started.elapsed();
    stopper.join().unwrap();
    assert_eq!(refused.code, IDENTITY_RENEWAL_STOPPED);
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert!(authority.accepts() >= 1);
    assert!(journal_absent(&tree));
    assert_ne!(harness.token(), "in_progress");
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn renewal_busy_store_is_a_recoverable_refusal() {
    let (tree, _successor, authority) = due_with(|_, _| Answer::Issue);
    let held = aegis_client::protected_identity_store::ProtectedIdentityStore::open_existing(
        &tree.identity_dir(),
    )
    .unwrap();
    let harness = Harness::new();
    let refused = harness.run(&tree).unwrap_err();
    assert_eq!(refused.code, renewal_journal::BUSY);
    assert_eq!(refused.recovery, Recovery::Recoverable);
    assert_eq!(authority.accepts(), 0);
    drop(held);
}

#[test]
fn renewal_due_within_the_skew_margin_contacts_nothing_yet() {
    let listener = TestAuthority::bind();
    // Ten seconds past due (16 h into 24 h), inside the 60 s margin.
    let tree = aged(listener.local_addr().unwrap(), 16 * HOUR + 10, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Issue);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(harness.token(), "due");
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    // Known and still inside the margin: the next step does no I/O.
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
    assert_eq!(authority.accepts(), 0);
    assert!(journal_absent(&tree));
    // A forced renewal does not wait for the margin.
    assert_eq!(
        request_renewal_of(Some(&harness.renewal), now()),
        Ok("renew_scheduled")
    );
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
}

#[test]
fn renewal_fresh_authorization_refused_near_due_retries_soon() {
    // v32: only a fresh authorization the authority rejected inside the
    // skew window keeps v31's blocking request and short retry; a fresh
    // RecoveryRequired is parked with the full backoff. v32 review: a
    // journaled request's rejection keeps it journaled (its history is
    // unknown to this process) with the full backoff.
    for (answer, journaled, short) in [
        (Answer::Rejected, false, true),
        (Answer::RecoveryRequired, false, false),
        // A request journaled earlier is no fresh authorization.
        (Answer::Rejected, true, false),
    ] {
        let listener = TestAuthority::bind();
        // Ten seconds past the first scheduled attempt (due + 60 s).
        let tree = aged(listener.local_addr().unwrap(), 16 * HOUR + 70, DAY);
        let successor = Successor::for_tree(&tree, DAY);
        let authority = TestAuthority::spawn(listener, &tree, successor, move |_, _| answer);
        if journaled {
            journal_request(&tree);
        }
        let harness = Harness::new();
        let ran = harness.run(&tree);
        // A journaled request asks for its receipt first.
        assert_eq!(authority.seen().len(), 1 + usize::from(journaled));
        let next = harness.renewal.snapshot().next_attempt_at;
        if short {
            // The authority's clock may lag ours: a short retry.
            assert_eq!(ran.unwrap_err().code, IDENTITY_RENEWAL_PENDING);
            assert!(tree.identity_dir().join(renewal_journal::REQUEST).exists());
            assert!(next <= now() + SKEW_RETRY_SECS, "{answer:?}");
            assert!(next + 2 >= now() + SKEW_RETRY_SECS, "{answer:?}");
        } else {
            if journaled {
                assert_eq!(ran.unwrap_err().code, IDENTITY_RENEWAL_PENDING);
                assert!(tree.identity_dir().join(renewal_journal::REQUEST).exists());
                assert!(!tree.identity_dir().join(renewal_journal::PARKED).exists());
            } else {
                assert_eq!(ran, Ok(()), "{answer:?} {journaled}");
                assert!(tree.identity_dir().join(renewal_journal::PARKED).exists());
                assert!(!tree.identity_dir().join(renewal_journal::REQUEST).exists());
            }
            assert!(
                next + 2 >= now() + BACKOFF_FIRST_SECS,
                "{answer:?} {journaled}"
            );
        }
    }
}

#[test]
fn renewal_tolerates_an_authority_clock_a_few_seconds_ahead() {
    // (challenge clock lead, successor not_before lead): both waited for,
    // and each alone (a successor signed ahead of a challenge that is not).
    for (ahead, signed_ahead) in [(2, 2), (0, 2)] {
        let listener = TestAuthority::bind();
        let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
        let successor = Successor::signed_at(&tree, now() + signed_ahead, DAY);
        let authority =
            TestAuthority::spawn(listener, &tree, successor.clone(), |_, _| Answer::Issue);
        authority.set_clock_ahead(ahead);
        let harness = Harness::new();
        assert_eq!(harness.run(&tree), Ok(()), "{ahead} {signed_ahead}");
        assert!(now() >= successor.not_before);
        assert_eq!(authority.issued(), 1);
        assert_eq!(authority.seen().len(), 1);
        admits_successor(&tree, &successor);
    }
}

#[test]
fn renewal_challenge_our_clock_cannot_sign_journals_nothing() {
    let (tree, _successor, authority) = due_with(|_, _| Answer::Issue);
    // Ten seconds ahead: more than the bounded clock wait.
    authority.set_clock_ahead(10);
    let old = installed(&tree);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()), "the old certificate carries on");
    assert!(journal_absent(&tree));
    assert_eq!(authority.seen().len(), 0, "no request was sent");
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(report.last_failure.as_deref(), Some("local_refused"));
    assert_eq!(installed(&tree), old);
}

#[test]
fn renewal_stalled_attempt_leaves_receipt_recovery_its_time() {
    // The first connection commits the successor and then stalls.
    let (tree, successor, authority) = due_with(|index, _| {
        if index == 0 {
            Answer::Stall
        } else {
            Answer::Issue
        }
    });
    let harness = Harness::new();
    let started = Instant::now();
    assert_eq!(harness.run(&tree), Ok(()));
    assert!(started.elapsed() < RENEWAL_BUDGET);
    assert_eq!(
        authority
            .seen()
            .iter()
            .map(|seen| seen.purpose)
            .collect::<Vec<_>>(),
        [ProofPurpose::Authorize, ProofPurpose::Receipt]
    );
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_inner_tls_keeps_the_product_crypto_policy() {
    use tokio_rustls::rustls::{crypto::ring, NamedGroup};
    let tree = aged("127.0.0.1:9".parse().unwrap(), 60, DAY);
    let mut inputs = CapturedRenewalInputs::capture_test_root(tree.root()).unwrap();
    let authority = crate::renewal_exchange::EnrollmentAuthority::from_held(
        inputs.public_payload().unwrap(),
        inputs.bridge_snapshot().unwrap(),
        inputs.bundle_path(),
        inputs.identity_path(),
    )
    .unwrap();
    let config = authority.inner_config();
    let provider = config.crypto_provider();
    assert_eq!(
        provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<Vec<_>>(),
        [
            ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256.suite(),
            ring::cipher_suite::TLS13_AES_128_GCM_SHA256.suite(),
        ]
    );
    assert_eq!(
        provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect::<Vec<_>>(),
        [NamedGroup::X25519]
    );
    assert_eq!(
        config.alpn_protocols,
        [crate::renewal_exchange::ENROLLMENT_ALPN.to_vec()]
    );
}

#[test]
fn renewal_expired_gate_lifts_once_the_clock_is_back_before_not_after() {
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 60, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Issue);
    let (nb, na) = (tree.not_before(), tree.not_before() + DAY);
    GENERATION.with(|generation| generation.set(Some(51)));
    // A clock jumped past not_after judged this identity expired.
    let harness = Harness::new();
    harness.renewal.with(|state| {
        state.observed(nb, na, false);
        state.gate_expired(51, true);
    });
    let mut judged = harness.renewal.snapshot();
    assert!(judged.gated(na, 51), "still past not_after");
    assert!(judged.gated(na + DAY, 51));
    assert!(!judged.gated(na - 1, 51), "clock corrected");
    assert_eq!(judged.expired_under, None);
    let mut other = harness.renewal.snapshot();
    assert!(!other.gated(na, 52), "another import generation");
    // The clock is right again: the next step looks again, the gate lifts
    // and the still valid identity is captured.
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(harness.token(), "valid");
    assert_eq!(harness.renewal.snapshot().expired_under, None);
    assert_eq!(authority.accepts(), 0);
    GENERATION.with(|generation| generation.set(None));
}

#[test]
fn renewal_tampered_receipt_window_stays_a_terminal_refusal() {
    let tree = aged("127.0.0.1:9".parse().unwrap(), 2 * HOUR, DAY);
    // online-completed.json edited to end a minute after it began: a past
    // not_after the signed device.pem does not carry.
    let leaf = tree.identity_dir().join("online-completed.json");
    let mut completed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&leaf).unwrap()).unwrap();
    completed["receipt"]["not_after_unix_secs"] = (tree.not_before() + 60).into();
    tree.write_identity_file(
        "online-completed.json",
        &serde_json::to_vec(&completed).unwrap(),
    );
    // The renewal step does not judge it (the Store's window is valid) ...
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    // ... and the capture refuses it as tampering: terminal, never the
    // recoverable session_identity_expired an honest expiry is.
    let refused = CapturedAppGroupInputs::capture_test_root(tree.root())
        .err()
        .unwrap();
    let refusal = Refusal::custody(&refused);
    assert_eq!(refusal.code, crate::identity_custody::COMPLETION_REFUSED);
    assert_eq!(refusal.recovery, Recovery::Terminal);
    assert_ne!(refusal.code, SESSION_IDENTITY_EXPIRED);
}

#[test]
fn renewal_publication_ends_with_its_epoch() {
    let first = RenewalHandle::default();
    first.with(|state| state.admitted(1_000, 4_000));
    publish(&first);
    assert_eq!(cert_status().unwrap().not_after, Some(4_000));
    let second = RenewalHandle::default();
    publish(&second);
    // An older epoch ending keeps the newer publication.
    unpublish(&first);
    assert_eq!(cert_status().unwrap().state, "unknown");
    unpublish(&second);
    assert_eq!(cert_status(), Err("no_epoch"));
    assert_eq!(request_renewal(), Err("no_epoch"));
    // Nothing reaches an ended epoch's state.
    assert!(!first.snapshot().forced);
}

// ---------------------------------------------------------------------------
// Sessions.

#[test]
fn renewal_session_with_an_expired_held_receipt_refuses_recoverably() {
    let tree = aged("127.0.0.1:9".parse().unwrap(), 25 * HOUR, DAY);
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let pins = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
    let mut session = spawn_pinned(saved(&tree), claim, |_| {}, None, pins, None).unwrap();
    assert!(wait_until(Duration::from_secs(5), || {
        matches!(session.phase(), SessionPhase::Sealed | SessionPhase::Joined)
    })
    .is_some());
    assert!(session.try_join(Duration::from_secs(3)));
    let code = session.refusal().unwrap();
    assert_eq!(code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(classify(code), Recovery::Recoverable);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn renewal_due_session_is_sealed_and_rebuilt_onto_the_successor_without_restart() {
    let authority_listener = TestAuthority::bind();
    let relay_listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::renewable(
        relay_listener.local_addr().unwrap(),
        authority_listener.local_addr().unwrap(),
        now() - 17 * HOUR,
        DAY,
    ));
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(authority_listener, &tree, successor.clone(), |_, _| {
        Answer::Issue
    });
    let (outer_cert, outer_key) = tree.outer_server_der();
    let (inner_cert, inner_key) = tree.inner_server_pem();
    let identity = RelayIdentity::new_allowing(
        outer_cert,
        outer_key,
        inner_cert.as_bytes(),
        inner_key.as_bytes(),
        tree.device_ca_pem().as_bytes(),
        vec![
            tree.online().certificate_sha256.clone(),
            successor.fingerprint.clone(),
        ],
    );
    let old_reply = AckReply::for_tree(&tree);
    let renewed_reply = AckReply {
        certificate_sha256: successor.fingerprint.clone(),
        certificate_not_after_unix_secs: successor.not_after,
        policy_not_after_unix_secs: now() + 60,
        generation: RENEWED_GENERATION,
        snapshot_sha256: RENEWED_SNAPSHOT.into(),
        effective_valid_for_ms: MAX_ACK_VALID_MS,
    };
    let renewed = Arc::new(AtomicBool::new(false));
    let serving = renewed.clone();
    let _relay = TestRelay::spawn_each(relay_listener, identity, move |_| {
        Some(Behavior::AckThenClose {
            reply: if serving.load(Ordering::SeqCst) {
                renewed_reply.clone()
            } else {
                old_reply.clone()
            },
            idle: ADMISSION_TIMEOUT,
        })
    });
    let lo = RelayInterface::loopback_for_test();
    let pins = EpochPins::pinned_for_test(lo.clone());
    // The epoch's first session admits the predecessor.
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let mut first = spawn_pinned(saved(&tree), claim, |_| {}, None, pins.clone(), None).unwrap();
    assert!(wait_until(Duration::from_secs(5), || first.phase()
        == SessionPhase::Ready)
    .is_some());
    assert_eq!(
        pins.admitted().map(|a| (a.not_before, a.not_after)),
        Some((tree.not_before(), tree.not_before() + DAY))
    );
    // The monitor seals it for renewal (as the provider's drain tick does).
    let renewal = pins.renewal();
    let action = decide(now(), &renewal.snapshot(), false, first.probe().ready());
    assert_eq!(action, Action::Seal);
    first.seal(IDENTITY_RENEWAL_DUE);
    assert!(first.try_join(Duration::from_secs(3)));
    assert_eq!(first.refusal(), Some(IDENTITY_RENEWAL_DUE));
    renewed.store(true, Ordering::SeqCst);
    // The rebuild factory: renewal on the pinned interface, then a capture.
    let bound: Arc<Mutex<Vec<u32>>> = Arc::default();
    let pinned = pins.clone();
    let interface = move |_| pinned.get().ok_or(crate::relay_socket::UNRESOLVED);
    before_capture(
        &Step {
            renewal: &renewal,
            interface: &interface,
            stop: &|| false,
            bound: Some(bound.clone()),
        },
        || CapturedRenewalInputs::capture_test_root(tree.root()),
    )
    .unwrap();
    {
        let bound = bound.lock().unwrap();
        assert!(!bound.is_empty() && bound.iter().all(|index| *index == lo.index()));
    }
    assert_eq!(
        renewal.with(|state| state.token(now())),
        "renewed_pending_ack"
    );
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let mut rebuilt = spawn_pinned(saved(&tree), claim, |_| {}, None, pins.clone(), None).unwrap();
    assert!(
        wait_until(Duration::from_secs(5), || rebuilt.phase()
            == SessionPhase::Ready)
        .is_some(),
        "{:?}",
        rebuilt.refusal()
    );
    // The same epoch now runs on the successor: admitted window, state and
    // the Store's issuance all name it.
    assert_eq!(
        pins.admitted().map(|a| (a.not_before, a.not_after)),
        Some((successor.not_before, successor.not_after))
    );
    assert_eq!(renewal.with(|state| state.token(now())), "valid");
    assert_eq!(
        decide(now(), &renewal.snapshot(), false, true),
        Action::None
    );
    assert_eq!(authority.issued(), 1);
    rebuilt.seal("provider_stop");
    assert!(rebuilt.try_join(Duration::from_secs(3)));
    assert_eq!(
        installed(&tree),
        (
            successor.fingerprint.clone(),
            successor.not_after,
            Some(RENEWED_GENERATION)
        )
    );
}

// ---------------------------------------------------------------------------
// XPC verbs and the host parser.

struct RenewalObserver {
    handle: RenewalHandle,
    authorized: bool,
    authorizations: crate::identity_import::authorization::AuthorizationGate,
}

impl Observer for RenewalObserver {
    fn ping(&self) -> PingReport {
        unreachable!("ping")
    }
    fn status(&self) -> StatusReport {
        unreachable!("status")
    }
    fn authorize(&self, _peer_euid: u32) -> Result<(), &'static str> {
        if self.authorized {
            Ok(())
        } else {
            Err("peer_not_console_user")
        }
    }
    fn admit_authorization(&self, form: Option<&[u8]>) -> Result<(), &'static str> {
        self.authorizations.admit(
            form,
            &crate::identity_import::authorization::test_support::AdmitEveryForm,
        )
    }
    fn cert_status(&self) -> Result<CertStatusReport, &'static str> {
        cert_status_of(Some(&self.handle), 3_100)
    }
    fn renew(&self) -> Result<RenewReport, &'static str> {
        request_renewal_of(Some(&self.handle), 3_100).map(|outcome| RenewReport {
            outcome: outcome.into(),
        })
    }
}

#[test]
fn renewal_xpc_verbs_round_trip_and_renew_needs_authorization() {
    let host = |args: &[&str]| {
        crate::host_lifecycle::parse_host_args(
            &args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>(),
        )
    };
    for (verb, name, flag) in [
        (Verb::CertStatus, "cert-status", "--cert-status"),
        (Verb::Renew, "renew", "--renew"),
    ] {
        assert_eq!(Verb::from_flag(flag), Some(verb));
        let request = provider_xpc::encode_request(verb);
        assert_eq!(provider_xpc::decode_request(&request), Ok(verb));
        assert!(String::from_utf8(request).unwrap().contains(name));
        assert_eq!(
            host(&["host", flag]),
            Ok(crate::host_lifecycle::HostCommand::Xpc(verb))
        );
        assert!(host(&["host", flag, "operand"]).is_err());
    }
    let handle = RenewalHandle::default();
    handle.with(|state| state.admitted(1_000, 4_000));
    let observer = RenewalObserver {
        handle: handle.clone(),
        authorized: true,
        authorizations: crate::identity_import::authorization::AuthorizationGate::new(),
    };
    let reply = provider_xpc::respond(
        Ok(provider_xpc::encode_request(Verb::CertStatus)),
        &observer,
    );
    let decoded = provider_xpc::decode_reply(&reply, Verb::CertStatus).unwrap();
    let Reply::CertStatus(report) = &decoded else {
        panic!("{decoded:?}");
    };
    assert_eq!(report.state, "due");
    assert_eq!(report.renew_at, Some(3_000));
    let text = String::from_utf8(reply.clone()).unwrap();
    assert!(!text.contains("BEGIN") && !text.contains('/'), "{text}");
    // Round trip of every field, and refusal of unknown tokens or keys.
    let full = Reply::CertStatus(CertStatusReport {
        state: "failed:timeout".into(),
        not_before: Some(1),
        not_after: Some(4),
        renew_at: Some(3),
        attempts: 2,
        last_attempt_at: Some(3),
        next_attempt_at: Some(5),
        last_failure: Some("timeout".into()),
        failing_since: None,
        check: None,
    });
    let bytes = provider_xpc::encode_reply(&full).unwrap();
    assert_eq!(
        provider_xpc::decode_reply(&bytes, Verb::CertStatus),
        Ok(full)
    );
    for (from, to) in [
        ("failed:timeout", "failed:other"),
        ("\"last_failure\":\"timeout\"", "\"last_failure\":\"BEGIN\""),
        ("\"renew_at\":3", "\"renew_at\":null"),
        ("\"attempts\":2", "\"attempts\":2,\"key\":1"),
    ] {
        let text = String::from_utf8(bytes.clone()).unwrap().replace(from, to);
        assert!(
            provider_xpc::decode_reply(text.as_bytes(), Verb::CertStatus).is_err(),
            "{to}"
        );
    }
    // Renew: refused without a peer (the plain responder has none) ...
    let reply = provider_xpc::respond(Ok(provider_xpc::encode_request(Verb::Renew)), &observer);
    assert_eq!(
        provider_xpc::decode_reply(&reply, Verb::Renew),
        Ok(Reply::Refused("peer_unidentified".into()))
    );
    assert!(!handle.snapshot().forced);
    // ... refused for an authorized peer without an administrator's
    // approval ...
    let frame = provider_xpc::encode_request(Verb::Renew);
    let bare: [(&std::ffi::CStr, &[u8]); 1] = [(c"frame", frame.as_slice())];
    let reply = provider_xpc::respond_entries(&bare, Some(501), &observer);
    assert_eq!(
        provider_xpc::decode_reply(&reply, Verb::Renew),
        Ok(Reply::Refused("identity_authorization_missing".into()))
    );
    assert!(!handle.snapshot().forced);
    // ... and with one, scheduled once: the same approval is not reusable.
    // v30: a v26 to v29 host's form, under the legacy key, is refused
    // before anything else ...
    let form = crate::identity_import::authorization::test_support::fresh_form();
    let legacy: [(&std::ffi::CStr, &[u8]); 2] =
        [(c"frame", frame.as_slice()), (c"authorization", &form)];
    let reply = provider_xpc::respond_entries(&legacy, Some(501), &observer);
    assert_eq!(
        provider_xpc::decode_reply(&reply, Verb::Renew),
        Ok(Reply::Refused(
            "identity_authorization_host_outdated".into()
        ))
    );
    assert!(!handle.snapshot().forced);
    let form = crate::identity_import::authorization::test_support::fresh_form();
    let entries: [(&std::ffi::CStr, &[u8]); 2] = [
        (c"frame", frame.as_slice()),
        (
            crate::identity_import::authorization::AUTHORIZATION_KEY,
            &form,
        ),
    ];
    let reply = provider_xpc::respond_entries(&entries, Some(501), &observer);
    let scheduled = Reply::Renew(RenewReport {
        outcome: "renew_scheduled".into(),
    });
    assert_eq!(
        provider_xpc::decode_reply(&reply, Verb::Renew),
        Ok(scheduled.clone())
    );
    assert!(handle.snapshot().forced);
    assert_eq!(crate::host_lifecycle::xpc_reply_exit(&scheduled), 0);
    let reply = provider_xpc::respond_entries(&entries, Some(501), &observer);
    assert_eq!(
        provider_xpc::decode_reply(&reply, Verb::Renew),
        Ok(Reply::Refused("identity_authorization_replayed".into()))
    );
    let refusing = RenewalObserver {
        handle: RenewalHandle::default(),
        authorized: false,
        authorizations: crate::identity_import::authorization::AuthorizationGate::new(),
    };
    let reply = provider_xpc::respond_entries(&entries, Some(501), &refusing);
    assert_eq!(
        provider_xpc::decode_reply(&reply, Verb::Renew),
        Ok(Reply::Refused("peer_not_console_user".into()))
    );
}

// ---------------------------------------------------------------------------
// v31 (S23b): no dial beside the armed guard, no teardown for a renewal
// that cannot help, the carried backoff, one connect after a starved step.

/// A loopback authority that never answers: its listen queue (one
/// connection, never accepted) is full, so every further SYN is dropped
/// and a connect times out, as port 9445 did in window-v30-ifswitch-r3.
struct Blackhole {
    listener: std::net::TcpListener,
    _held: std::net::TcpStream,
}

impl Blackhole {
    fn bind() -> Self {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // SAFETY: a listening socket this test owns; only its backlog
        // changes.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let held = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let probe = std::net::TcpStream::connect_timeout(
            &listener.local_addr().unwrap(),
            Duration::from_millis(300),
        );
        assert_eq!(
            probe.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::TimedOut),
            "the queue must be full: no answer, no refusal"
        );
        Self {
            listener,
            _held: held,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }
}

/// The import generation override for one test, reset on drop.
struct Generation;

impl Generation {
    fn set(generation: u64) -> Self {
        GENERATION.with(|cell| cell.set(Some(generation)));
        Self
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        GENERATION.with(|cell| cell.set(None));
    }
}

/// The leak-guard override for one test (`ARMED_RELAY`), reset on drop.
struct Armed;

impl Armed {
    fn relay(relay: Option<SocketAddr>) -> Self {
        ARMED_RELAY.with(|cell| cell.set(Some(relay)));
        Self
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        ARMED_RELAY.with(|cell| cell.set(None));
    }
}

impl Harness {
    /// v31: a provider start whose handle is kept in `carry`.
    fn carried(carry: &Arc<Carry>) -> Self {
        Self {
            renewal: RenewalHandle::carried(carry.clone()),
            ..Self::new()
        }
    }
}

/// A live, Running session that has been up for a minute, unguarded.
const LIVE: Monitor = Monitor {
    auth_backoff: false,
    live: true,
    guarded: false,
    live_for: Some(Duration::from_secs(60)),
};

/// Every monitor check from `from` to `to` on the 5 s grid: the actions
/// taken.
fn monitor_over(handle: &RenewalHandle, from: u64, to: u64, monitor: &Monitor) -> Vec<Action> {
    (from..to)
        .step_by(usize::try_from(CHECK_INTERVAL.as_secs()).unwrap())
        .map(|at| monitor_step(handle, at, monitor))
        .collect()
}

#[test]
fn renewal_v31_classes_states_and_log_lines_are_stable_tokens() {
    assert_eq!(FailureClass::ConnectTimeout.token(), "connect_timeout");
    for (class, transport) in [
        (FailureClass::ConnectTimeout, true),
        (FailureClass::Unavailable, true),
        (FailureClass::InterfaceUnresolved, true),
        (FailureClass::Timeout, false),
        (FailureClass::Rejected, false),
        (FailureClass::RecoveryRequired, false),
        (FailureClass::LocalRefused, false),
    ] {
        assert_eq!(class.is_transport(), transport, "{class:?}");
        assert!(provider_xpc::FAILURE_CLASSES.contains(&class.token()));
        let state = format!("state:failed:{}", class.token());
        assert!(crate::apple::stable_fields(
            "identity_renewal",
            &[&state, "attempt:3", "next_s:900", "dials:3"]
        ));
    }
    assert!(provider_xpc::CERT_STATES.contains(&"deferred:guarded"));
    for fields in [
        &["state:deferred:guarded", "attempt:0", "remaining_s:142049"][..],
        &["state:held:transport", "attempt:1"],
        &["state:held:young", "attempt:0"],
        &["state:start", "attempt:2", "connects:1"],
        &["state:issued", "attempt:1", "dials:1"],
    ] {
        assert!(
            crate::apple::stable_fields("identity_renewal", fields),
            "{fields:?}"
        );
    }
    let mut state = RenewalState::default();
    state.observed(1_000, 4_000, false);
    state.deferred = true;
    assert_eq!(state.token(3_500), "deferred:guarded");
    assert_eq!(
        state.token(2_000),
        "valid",
        "only a due renewal is deferred"
    );
    assert_eq!(state.token(4_000), "expired");
    state.pending = true;
    assert_eq!(state.token(3_500), "pending");
    // v32: a superseded request, and a parked one (after a deferral).
    state.issued = Some(renewal_journal::SUCCESSOR_NOT_EXTENDING);
    assert_eq!(state.token(3_500), "superseded");
    state.pending = false;
    state.parked = true;
    assert_eq!(state.token(3_500), "deferred:guarded");
    state.deferred = false;
    assert_eq!(state.token(3_500), "parked");
    for fields in [
        &[
            "state:superseded",
            "attempt:1",
            "check:renewal_successor_not_extending",
        ][..],
        &[
            "state:refused",
            "attempt:1",
            "check:renewal_successor_not_yet_valid",
        ],
        &["state:parked", "attempt:1", "check:rejected"],
        &["state:held:parked", "attempt:1"],
    ] {
        assert!(
            crate::apple::stable_fields("identity_renewal", fields),
            "{fields:?}"
        );
    }
}

#[test]
fn renewal_monitor_never_seals_beside_the_guard_after_a_transport_failure_or_a_young_session() {
    let (nb, na) = (1_000, 4_000);
    let at = renewal_attempt_at(nb, na);
    let mut state = RenewalState::default();
    state.admitted(nb, na);
    let with = |change: fn(&mut Monitor)| {
        let mut monitor = LIVE;
        change(&mut monitor);
        monitor
    };
    assert_eq!(judge(at, &state, &LIVE), Action::Seal, "the baseline");
    assert_eq!(judge(at - 1, &state, &LIVE), Action::None, "not yet");
    // The armed guard forbids the dial: deferred, never a seal, even
    // under an authentication backoff.
    let guarded = with(|m| m.guarded = true);
    assert_eq!(judge(at, &state, &guarded), Action::DeferGuarded);
    let both = with(|m| {
        m.guarded = true;
        m.auth_backoff = true;
    });
    assert_eq!(judge(at, &state, &both), Action::DeferGuarded);
    // A session younger than the S17 stable period (or of unknown age).
    for young in [
        Some(Duration::ZERO),
        Some(STABLE - Duration::from_millis(1)),
        None,
    ] {
        let monitor = Monitor {
            live_for: young,
            ..LIVE
        };
        assert_eq!(judge(at, &state, &monitor), Action::HoldYoung, "{young:?}");
    }
    let stable = Monitor {
        live_for: Some(STABLE),
        ..LIVE
    };
    assert_eq!(judge(at, &state, &stable), Action::Seal);
    assert_eq!(
        judge(at, &state, &with(|m| m.auth_backoff = true)),
        Action::SkipAuthBackoff
    );
    // After a transport-class failure with no journal: never a seal.
    for class in [
        FailureClass::ConnectTimeout,
        FailureClass::Unavailable,
        FailureClass::InterfaceUnresolved,
    ] {
        let mut failed = state.clone();
        failed.failed(at, class, false);
        let next = failed.next_attempt_at;
        assert_eq!(judge(next - 1, &failed, &LIVE), Action::None, "{class:?}");
        assert_eq!(
            judge(next, &failed, &LIVE),
            Action::HoldTransport,
            "{class:?}"
        );
        // Guarded still wins: it is a deferral, not a transport hold.
        assert_eq!(judge(next, &failed, &guarded), Action::DeferGuarded);
        // v31 review: the hold ends in the last stretch before expiry (an
        // expiry tears the session down anyway); the guard and a young
        // session still hold it.
        let ends = transport_hold_ends_at(nb, na);
        assert!(next < ends, "{class:?}");
        assert_eq!(judge(ends - 1, &failed, &LIVE), Action::HoldTransport);
        assert_eq!(judge(ends, &failed, &LIVE), Action::Seal, "{class:?}");
        assert_eq!(judge(na - 1, &failed, &LIVE), Action::Seal, "{class:?}");
        assert_eq!(judge(ends, &failed, &guarded), Action::DeferGuarded);
        assert_eq!(
            judge(
                ends,
                &failed,
                &Monitor {
                    live_for: Some(Duration::from_secs(5)),
                    ..LIVE
                }
            ),
            Action::HoldYoung
        );
        // A journaled request is no such case.
        failed.pending = true;
        assert_eq!(judge(next, &failed, &LIVE), Action::Seal, "{class:?}");
        // An operator's forced renewal may seal, once the session is stable.
        failed.pending = false;
        failed.forced = true;
        assert_eq!(judge(next, &failed, &LIVE), Action::Seal, "{class:?}");
        let young = Monitor {
            live_for: Some(Duration::from_secs(5)),
            ..LIVE
        };
        assert_eq!(judge(next, &failed, &young), Action::HoldYoung);
    }
    // Other failures (the authority answered or timed out once connected).
    for class in [
        FailureClass::Timeout,
        FailureClass::Rejected,
        FailureClass::RecoveryRequired,
        FailureClass::LocalRefused,
    ] {
        let mut failed = state.clone();
        failed.failed(at, class, false);
        assert_eq!(
            judge(failed.next_attempt_at, &failed, &LIVE),
            Action::Seal,
            "{class:?}"
        );
    }
}

#[test]
fn renewal_monitor_seals_zero_times_before_the_last_stretch_after_a_transport_failure() {
    let (nb, na) = (1_000, 1_000 + DAY);
    let at = renewal_attempt_at(nb, na);
    let handle = RenewalHandle::default();
    handle.with(|state| {
        state.admitted(nb, na);
        state.failed(at, FailureClass::ConnectTimeout, false);
    });
    // Every 5 s check from the failure to the last stretch before expiry,
    // across all its backoff steps (no attempt runs in between: nothing
    // rebuilds).
    let ends = transport_hold_ends_at(nb, na);
    let actions = monitor_over(&handle, at, ends, &LIVE);
    assert!(!actions.contains(&Action::Seal), "a seal for a renewal");
    assert!(actions.contains(&Action::HoldTransport));
    assert_eq!(
        handle.with(|state| state.token(at + 120)),
        "failed:connect_timeout"
    );
    // v31 review: in the last stretch every check seals until expiry (in
    // production the first seal's rebuild runs the attempt), none after.
    let late = monitor_over(&handle, ends, na + 30, &LIVE);
    for (check, action) in (ends..).step_by(5).zip(&late) {
        let expected = if check < na {
            Action::Seal
        } else {
            Action::None
        };
        assert_eq!(*action, expected, "{check}");
    }
    // Beside the armed guard: deferred, surfaced, and still no seal.
    let deferred = RenewalHandle::default();
    deferred.with(|state| state.admitted(nb, na));
    let guarded = Monitor {
        guarded: true,
        ..LIVE
    };
    let actions = monitor_over(&deferred, at, na + 30, &guarded);
    assert!(!actions.contains(&Action::Seal));
    assert!(actions
        .iter()
        .all(|a| matches!(a, Action::DeferGuarded | Action::None)));
    assert_eq!(
        deferred.with(|state| state.token(at + 10)),
        "deferred:guarded"
    );
    let report = cert_status_of(Some(&deferred), at + 10).unwrap();
    assert_eq!(report.state, "deferred:guarded");
    assert_eq!(report.attempts, 0, "a deferral is no attempt");
    // A forced renewal is ended by the deferral (no 250 ms checks).
    deferred.with(|state| state.forced = true);
    assert_eq!(
        monitor_step(&deferred, at + 20, &guarded),
        Action::DeferGuarded
    );
    assert!(!deferred.snapshot().forced);
    // Unguarded and stable again (a provider start reconnected): it seals.
    assert_eq!(monitor_step(&deferred, at + 25, &LIVE), Action::Seal);
    assert_eq!(deferred.with(|state| state.token(at + 25)), "due");
}

#[test]
fn renewal_record_is_carried_across_epochs_by_window_and_import_generation() {
    let carry: Arc<Carry> = Arc::default();
    let first = RenewalHandle::carried(carry.clone());
    first.with(|state| {
        state.observed(1_000, 4_000, false);
        state.carry_in(7, 3_100);
        state.last_attempt_at = Some(3_100);
        state.failed(3_100, FailureClass::ConnectTimeout, false);
        state.starved = true;
        state.last_dials = 3;
    });
    let kept = carry.get().unwrap();
    assert_eq!(kept.key, (1_000, 4_000, 7));
    assert_eq!((kept.attempts, kept.next_attempt_at), (1, 3_160));
    assert_eq!(kept.failing_since, Some(3_100));
    // The next epoch of the same identity and generation takes it up ...
    let second = RenewalHandle::carried(carry.clone());
    second.with(|state| {
        state.observed(1_000, 4_000, false);
        state.carry_in(7, 3_100);
    });
    let taken = second.snapshot();
    assert_eq!((taken.attempts, taken.next_attempt_at), (1, 3_160));
    assert_eq!(taken.last_failure, Some(FailureClass::ConnectTimeout));
    assert!(taken.starved);
    assert_eq!(taken.token(3_120), "failed:connect_timeout");
    // ... but not under another import generation or identity window.
    for (window, generation) in [((1_000, 4_000), 8), ((1_000, 5_000), 7)] {
        let other = RenewalHandle::carried(carry.clone());
        other.with(|state| {
            state.observed(window.0, window.1, false);
            state.carry_in(generation, 3_100);
        });
        let fresh = other.snapshot();
        assert_eq!(
            (fresh.attempts, fresh.next_attempt_at),
            (0, 0),
            "{window:?}"
        );
        assert!(!fresh.starved);
    }
    // The newest record replaced the kept one (key 1_000..5_000, 7).
    assert_eq!(carry.get().unwrap().key, (1_000, 5_000, 7));
    // A handle without a carry never writes one.
    let plain = RenewalHandle::default();
    plain.with(|state| {
        state.observed(1_000, 4_000, false);
        state.carry_in(7, 3_100);
        state.failed(3_100, FailureClass::Unavailable, false);
    });
    assert_eq!(carry.get().unwrap().key, (1_000, 5_000, 7));
    // cert-status while no epoch runs: the kept record, else no_epoch.
    second.with(|state| state.failed(3_200, FailureClass::ConnectTimeout, false));
    let report = cert_status_with(None, Some(&carry), 7, 3_300).unwrap();
    assert_eq!(report.state, "failed:connect_timeout");
    assert_eq!((report.attempts, report.failing_since), (2, Some(3_100)));
    assert_eq!(cert_status_with(None, None, 7, 3_300), Err("no_epoch"));
    assert_eq!(
        cert_status_with(None, Some(&Carry::default()), 7, 3_300),
        Err("no_epoch")
    );
    // An import or forget since then hides the older identity's record.
    assert_eq!(
        cert_status_with(None, Some(&carry), 8, 3_300),
        Err("no_epoch")
    );
    // A published epoch answers for itself.
    let published = cert_status_with(Some(&plain), Some(&carry), 8, 3_300).unwrap();
    assert_eq!(published.last_failure.as_deref(), Some("unavailable"));
    // Only a changed record is written: the monitor's checks (every 2 ms
    // tick reads the state) leave a newer epoch's record in place.
    let newer = RenewalHandle::carried(carry.clone());
    newer.with(|state| {
        state.observed(1_000, 9_000, false);
        state.carry_in(7, 3_100);
    });
    assert!(check_due(&second, Instant::now()));
    second.with(|_| ());
    assert_eq!(carry.get().unwrap().key, (1_000, 9_000, 7));
}

#[test]
fn renewal_unreachable_authority_backs_off_across_epochs_with_one_connect_and_no_early_seal() {
    let _generation = Generation::set(31_001);
    let blackhole = Blackhole::bind();
    let tree = aged(blackhole.addr(), 17 * HOUR, DAY);
    let old = installed(&tree);
    let carry: Arc<Carry> = Arc::default();
    // A provider start in the Due window (the guard is Open).
    let first = Harness::carried(&carry);
    let started = Instant::now();
    assert_eq!(first.run(&tree), Ok(()), "the old certificate carries on");
    let took = started.elapsed();
    assert!(
        took >= 3 * crate::renewal_exchange::CONNECT_BUDGET && took < RENEWAL_BUDGET,
        "{took:?}"
    );
    let state = first.renewal.snapshot();
    assert_eq!(state.last_dials, 3);
    assert!(state.starved, "every connect timed out");
    let report = cert_status_of(Some(&first.renewal), now()).unwrap();
    assert_eq!(report.state, "failed:connect_timeout");
    assert_eq!(report.last_failure.as_deref(), Some("connect_timeout"));
    assert_eq!(report.attempts, 1);
    let since = report.failing_since.unwrap();
    assert!(since + 30 >= now() && since <= now());
    assert!(journal_absent(&tree), "no request without a challenge");
    assert_eq!(installed(&tree), old);
    assert!(bound_only_to(&first, &RelayInterface::loopback_for_test()) == 0);
    // The running session's monitor, across the backoff steps up to the
    // last stretch before expiry: no seal (v31 review: there it seals).
    let next = report.next_attempt_at.unwrap();
    let ends = transport_hold_ends_at(report.not_before.unwrap(), report.not_after.unwrap());
    assert!(next < ends);
    let actions = monitor_over(&first.renewal, now(), ends, &LIVE);
    assert!(!actions.contains(&Action::Seal));
    assert!(actions.contains(&Action::HoldTransport));
    assert_eq!(
        judge(ends, &first.renewal.snapshot(), &LIVE),
        Action::Seal,
        "the last stretch"
    );
    // The next Connect in the backoff: no exchange before its settings.
    let second = Harness::carried(&carry);
    let started = Instant::now();
    assert_eq!(second.run(&tree), Ok(()));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    let resumed = second.renewal.snapshot();
    assert_eq!((resumed.attempts, resumed.next_attempt_at), (1, next));
    assert_eq!(resumed.token(now()), "failed:connect_timeout");
    // Once due again: one connect attempt, not three, and the backoff
    // doubles; the failing run keeps its start.
    second.renewal.with(|state| state.next_attempt_at = 0);
    let started = Instant::now();
    assert_eq!(second.run(&tree), Ok(()));
    let took = started.elapsed();
    assert!(
        took >= crate::renewal_exchange::CONNECT_BUDGET
            && took < 2 * crate::renewal_exchange::CONNECT_BUDGET,
        "{took:?}"
    );
    let state = second.renewal.snapshot();
    assert_eq!((state.last_dials, state.attempts), (1, 2));
    assert!(state.starved);
    assert_eq!(state.failing_since, Some(since));
    assert!(state.next_attempt_at + 2 >= now() + 2 * BACKOFF_FIRST_SECS);
    assert_eq!(carry.get().unwrap().attempts, 2);
    assert!(journal_absent(&tree));
    assert_eq!(installed(&tree), old);
}

#[test]
fn renewal_returns_to_three_connects_after_any_connect_succeeds() {
    // A dead authority that accepts and closes: every connect succeeds.
    let (tree, _successor, authority) = due_with(|_, _| Answer::Close);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 3);
    assert!(!harness.renewal.snapshot().starved, "connects succeeded");
    // As if that step's connects had all timed out.
    harness.renewal.with(|state| {
        state.starved = true;
        state.next_attempt_at = 0;
    });
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 4, "one connect after a starved step");
    let state = harness.renewal.snapshot();
    assert_eq!(state.last_dials, 1);
    assert!(!state.starved, "a connect succeeded");
    assert_eq!(state.last_failure, Some(FailureClass::Unavailable));
    harness.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 7, "three again");
    assert_eq!(harness.renewal.snapshot().last_dials, 3);
}

#[test]
fn renewal_due_beside_the_armed_guard_is_deferred_and_dials_nothing() {
    let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
    let relay: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let harness = Harness::new();
    {
        let _armed = Armed::relay(Some(relay));
        // A rebuild while armed: the old certificate, no dial, deferred.
        assert_eq!(harness.run(&tree), Ok(()));
        assert_eq!(harness.token(), "deferred:guarded");
        assert_eq!(authority.accepts(), 0);
        assert_eq!(harness.captures.load(Ordering::SeqCst), 1);
        assert!(journal_absent(&tree));
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!((report.attempts, report.last_attempt_at), (0, None));
        // A forced renewal is deferred too, and ended.
        assert_eq!(
            request_renewal_of(Some(&harness.renewal), now()),
            Ok("renew_scheduled")
        );
        assert_eq!(harness.run(&tree), Ok(()));
        assert_eq!(authority.accepts(), 0);
        assert!(!harness.renewal.snapshot().forced);
        // A torn guard read guards with no relay: refused as well.
        let _torn = Armed::relay(None);
        assert_eq!(harness.run(&tree), Ok(()));
        assert_eq!(authority.accepts(), 0);
    }
    // The next provider start, before its arm (the guard Open): it runs.
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
    assert_eq!(harness.token(), "renewed_pending_ack");
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_to_the_relays_own_tuple_runs_beside_the_armed_guard() {
    // Option B: the profile's authority is the armed relay tuple, so its
    // dial is relay traffic and the renewal is not deferred.
    let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
    let tuple = authority_tuple(&tree);
    let _armed = Armed::relay(Some(tuple));
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
}

/// v40 (CP-D3 D1, variant B): a carrier pool whose enrollment authority is
/// one of its pins (the fronted edge's 443 carries both traffic and
/// `/enrollment.v1.Authority/Exchange`). The renewal dials that pin as one
/// single-carrier attempt: before v40 the held connector refused it, since
/// the pool's failover policy was kept on a carrier with no pool.
#[test]
fn a_pooled_profile_renews_through_its_fronted_edge_pin_beside_the_armed_guard() {
    let listener = TestAuthority::bind();
    let edge = listener.local_addr().unwrap();
    let tree = ReadyTree::pooled_as(
        "127.0.0.1:443".parse().unwrap(),
        &[edge],
        crate::test_fixture::Issuance {
            authority: edge,
            not_before: Some(now() - 17 * HOUR),
            lifetime_secs: DAY,
            ..Default::default()
        },
    );
    assert_eq!(tree.pins().len(), 2);
    assert_eq!(authority_tuple(&tree), edge);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), |_, _| Answer::Issue);
    // The guard holds the pool; the edge pin is one of its exact tuples.
    let _armed = Armed::relay(Some(edge));
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
    assert_eq!(harness.token(), "renewed_pending_ack");
    admits_successor(&tree, &successor);
}

/// The held profile's numeric authority of `tree`.
fn authority_tuple(tree: &ReadyTree) -> SocketAddr {
    let mut inputs = CapturedRenewalInputs::capture_test_root(tree.root()).unwrap();
    crate::renewal_exchange::authority_address(&inputs.public_payload().unwrap()[0]).unwrap()
}

#[test]
fn renewal_journal_and_expiry_beside_the_armed_guard_stay_refused_without_a_dial() {
    let relay: SocketAddr = "127.0.0.1:443".parse().unwrap();
    // A journaled request: still pending, no receipt recovery while armed.
    let (tree, _successor, authority) = due_with(|_, _| Answer::Issue);
    journal_request(&tree);
    let harness = Harness::new();
    {
        let _armed = Armed::relay(Some(relay));
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING
        );
        assert_eq!(authority.accepts(), 0);
        assert_eq!(harness.token(), "pending");
    }
    // An expired identity with a request journaled before expiry: blocked,
    // and its receipt recovery waits for a provider start too.
    let (tree, _successor, authority, _binding) = expired_with_request(Answer::Issue);
    let _generation = Generation::set(31_002);
    let harness = Harness::new();
    let _armed = Armed::relay(Some(relay));
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(authority.accepts(), 0);
}

#[test]
fn renewal_attempt_due_within_one_check_interval_runs_in_this_step() {
    // Four seconds before the first scheduled attempt (due + 60 s): a
    // concurrent rebuild runs it now instead of a seal moments later.
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 16 * HOUR + 56, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), |_, _| Answer::Issue);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
    // The backoff the same way: a retry due in 4 s runs, one in 7 s waits.
    let (tree, _successor, authority) = due_with(|_, _| Answer::Close);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 3);
    harness
        .renewal
        .with(|state| state.next_attempt_at = now() + FOLD_SECS + 2);
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 3, "not within one check interval");
    harness
        .renewal
        .with(|state| state.next_attempt_at = now() + FOLD_SECS - 1);
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 6, "folded into this step");
}

#[test]
fn cert_status_renewal_line_names_the_failure_and_stays_address_free() {
    assert_eq!(provider_xpc::utc_text(0), "1970-01-01T00:00:00Z");
    assert_eq!(provider_xpc::utc_text(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(
        provider_xpc::utc_text(1_709_164_800),
        "2024-02-29T00:00:00Z"
    );
    assert_eq!(
        provider_xpc::utc_text(1_793_043_979),
        "2026-10-26T19:46:19Z"
    );
    assert_eq!(
        provider_xpc::utc_text(1_793_187_830),
        "2026-10-28T11:43:50Z"
    );
    assert_eq!(
        provider_xpc::utc_text(4_102_444_800),
        "2100-01-01T00:00:00Z"
    );
    assert_eq!(
        provider_xpc::utc_text(253_402_300_799),
        "9999-12-31T23:59:59Z"
    );
    let base = CertStatusReport {
        state: "failed:connect_timeout".into(),
        not_before: Some(1_793_101_430),
        not_after: Some(1_793_187_830),
        renew_at: Some(1_793_159_030),
        attempts: 2,
        last_attempt_at: Some(1_793_160_000),
        next_attempt_at: Some(1_793_160_120),
        last_failure: Some("connect_timeout".into()),
        failing_since: Some(1_793_159_100),
        check: None,
    };
    assert_eq!(
        base.renewal_line().unwrap(),
        "renewal failing (connect_timeout) since 2026-10-28T03:45:00Z, expires at 2026-10-28T11:43:50Z, 2 attempts"
    );
    let deferred = CertStatusReport {
        state: "deferred:guarded".into(),
        attempts: 0,
        last_failure: None,
        failing_since: None,
        ..base.clone()
    };
    assert_eq!(
        deferred.renewal_line().unwrap(),
        "renewal deferred:guarded (due since 2026-10-28T03:43:50Z; runs at the next connect), expires at 2026-10-28T11:43:50Z, 0 attempts"
    );
    let deferred_failing = CertStatusReport {
        state: "deferred:guarded".into(),
        ..base.clone()
    };
    assert!(deferred_failing
        .renewal_line()
        .unwrap()
        .ends_with(", 2 attempts, last failure connect_timeout since 2026-10-28T03:45:00Z"));
    let expired = CertStatusReport {
        state: "expired".into(),
        attempts: 1,
        ..base.clone()
    };
    assert_eq!(
        expired.renewal_line().unwrap(),
        "renewal expired at 2026-10-28T11:43:50Z (1 attempt): import a new identity"
    );
    for healthy in ["valid", "due", "renewed_pending_ack", "unknown"] {
        let report = CertStatusReport {
            state: healthy.into(),
            attempts: 0,
            last_failure: None,
            failing_since: None,
            ..base.clone()
        };
        assert_eq!(report.renewal_line(), None, "{healthy}");
    }
    for line in [
        base.renewal_line().unwrap(),
        deferred.renewal_line().unwrap(),
        expired.renewal_line().unwrap(),
    ] {
        assert!(!line.contains("127.0.0.1") && !line.contains('/'), "{line}");
    }
    // The wire: `failing_since` only when set; v30's eight keys still
    // decode; a since without a failure class is refused.
    let reply = Reply::CertStatus(base.clone());
    let bytes = provider_xpc::encode_reply(&reply).unwrap();
    assert_eq!(
        provider_xpc::decode_reply(&bytes, Verb::CertStatus),
        Ok(reply)
    );
    let quiet = Reply::CertStatus(deferred.clone());
    let text = String::from_utf8(provider_xpc::encode_reply(&quiet).unwrap()).unwrap();
    assert!(!text.contains("failing_since"), "{text}");
    assert_eq!(
        provider_xpc::decode_reply(text.as_bytes(), Verb::CertStatus),
        Ok(quiet)
    );
    let text = String::from_utf8(bytes).unwrap();
    for (from, to) in [
        (
            "\"last_failure\":\"connect_timeout\"",
            "\"last_failure\":null",
        ),
        ("\"failing_since\":1793159100", "\"failing_since\":\"x\""),
        ("\"failing_since\":1793159100", "\"failing_since\":null"),
    ] {
        let changed = text.replace(from, to);
        assert_ne!(changed, text, "{from}");
        assert!(
            provider_xpc::decode_reply(changed.as_bytes(), Verb::CertStatus).is_err(),
            "{to}"
        );
    }
    // The host asks for the line after an answered --status or --ping only.
    use crate::host_lifecycle::{renewal_line, renewal_line_wanted, shows_renewal_line};
    let answered: Result<Reply, &'static str> = Ok(Reply::Status(StatusReport {
        session_phase: "ready".into(),
        session_refusal: None,
    }));
    assert!(renewal_line_wanted(Verb::Status, &answered));
    assert!(renewal_line_wanted(Verb::Ping, &answered));
    for verb in [
        Verb::CertStatus,
        Verb::Renew,
        Verb::Import,
        Verb::FilterStatus,
    ] {
        assert!(!shows_renewal_line(verb), "{verb:?}");
        assert!(!renewal_line_wanted(verb, &answered), "{verb:?}");
    }
    assert!(!renewal_line_wanted(
        Verb::Status,
        &Ok(Reply::Refused("x".into()))
    ));
    assert!(!renewal_line_wanted(Verb::Status, &Err("xpc_unavailable")));
    assert_eq!(
        renewal_line(&Ok(Reply::CertStatus(base.clone()))),
        base.renewal_line()
    );
    assert_eq!(renewal_line(&Ok(Reply::Refused("no_epoch".into()))), None);
    assert_eq!(renewal_line(&Err("reply_malformed")), None);
}

// ---------------------------------------------------------------------------
// v31 review findings.

#[test]
fn renewal_transport_hold_ends_in_the_last_stretch_so_a_session_renews_before_expiry() {
    // The last stretch: an hour before not_after, at most half the time
    // from due to not_after.
    let (nb, na) = (1_000, 1_000 + DAY);
    assert_eq!(transport_hold_ends_at(nb, na), na - LAST_STRETCH_SECS);
    assert_eq!(transport_hold_ends_at(1_000, 4_000), 3_500);
    assert_eq!(transport_hold_ends_at(5, 5), 5);
    for (nb, na) in [(nb, na), (1_000, 4_000), (0, 3), (100, 160), (1_000, 1_001)] {
        let ends = transport_hold_ends_at(nb, na);
        assert!(ends >= renewal_due_at(nb, na) && ends <= na, "{nb} {na}");
    }
    // Option B (the authority is the relay's tuple, so unguarded): one
    // connect timeout at the first scheduled attempt, then a stable session
    // with no path change, lease loss or wake for the rest of the lifetime.
    let at = renewal_attempt_at(nb, na);
    let ends = transport_hold_ends_at(nb, na);
    let handle = RenewalHandle::default();
    handle.with(|state| {
        state.admitted(nb, na);
        state.failed(at, FailureClass::ConnectTimeout, false);
    });
    let checks: Vec<(u64, Action)> = (at..na)
        .step_by(5)
        .map(|check| (check, monitor_step(&handle, check, &LIVE)))
        .collect();
    let first_seal = checks
        .iter()
        .find(|(_, action)| *action == Action::Seal)
        .map(|(check, _)| *check)
        .expect("one sealed attempt before expiry");
    assert_eq!(first_seal, ends, "the last stretch's first check");
    assert!(checks
        .iter()
        .filter(|(check, _)| *check < ends)
        .all(|(_, action)| *action != Action::Seal));
    // That seal's rebuild renews: half an hour before not_after, the last
    // connect timeout's backoff over, against an authority that answers.
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), DAY - 30 * 60, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), |_, _| Answer::Issue);
    let harness = Harness::new();
    let (tnb, tna) = (tree.not_before(), tree.not_before() + DAY);
    harness.renewal.with(|state| {
        state.admitted(tnb, tna);
        state.failed(now() - 120, FailureClass::ConnectTimeout, false);
    });
    assert!(now() >= transport_hold_ends_at(tnb, tna));
    assert_eq!(monitor_step(&harness.renewal, now(), &LIVE), Action::Seal);
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_stop_during_a_connect_counts_no_connect_timeout_and_records_no_attempt() {
    // An authority whose connects never complete: the stop comes inside the
    // first connect, well before its own CONNECT_BUDGET.
    let blackhole = Blackhole::bind();
    let tree = aged(blackhole.addr(), 17 * HOUR, DAY);
    let harness = Harness::new();
    // The record of an earlier step whose connects answered.
    harness.renewal.with(|state| {
        state.last_dials = 3;
        state.last_attempt_at = Some(1_234);
    });
    let stop = harness.stop.clone();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::SeqCst);
    });
    let started = Instant::now();
    let refused = harness.run(&tree).unwrap_err();
    let took = started.elapsed();
    stopper.join().unwrap();
    assert_eq!(refused.code, IDENTITY_RENEWAL_STOPPED);
    assert!(took < crate::renewal_exchange::CONNECT_BUDGET, "{took:?}");
    let state = harness.renewal.snapshot();
    // No connect timed out: the next step (the next Connect) makes all
    // three connects, and the record names no attempt for this step.
    assert!(!state.starved, "a stop is no connect timeout");
    assert_eq!(state.last_dials, 3);
    assert_eq!(state.last_attempt_at, Some(1_234));
    assert_eq!((state.attempts, state.last_failure), (0, None));
    assert_eq!(harness.token(), "due");
    assert!(journal_absent(&tree));
}

#[test]
fn renewal_saved_response_finished_at_the_next_start_replaces_the_carried_record() {
    let _generation = Generation::set(31_003);
    let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
    let (nb, na) = (tree.not_before(), tree.not_before() + DAY);
    let carry: Arc<Carry> = Arc::default();
    // The successor's response is saved, then a later Store write fails.
    let first = Harness::carried(&carry);
    cut::set(Some("certificate_replaced"));
    let refused = first.run(&tree);
    cut::set(None);
    assert_eq!(refused.unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    let kept = carry.get().unwrap();
    assert_eq!(kept.key, (nb, na, 31_003));
    assert!(kept.pending);
    // The next start (same process) finishes it locally, with no network.
    let second = Harness::carried(&carry);
    assert_eq!(second.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 1);
    // Disconnected: cert-status from the carry names the successor, never
    // the predecessor's pending (later expired) record.
    let report = cert_status_with(None, Some(&carry), 31_003, now()).unwrap();
    assert_eq!(
        (report.not_before, report.not_after),
        (Some(successor.not_before), Some(successor.not_after))
    );
    assert_eq!(report.state, "renewed_pending_ack");
    assert_eq!((report.attempts, report.last_failure), (0, None));
    // The epoch's session admits it, and the carry follows.
    second
        .renewal
        .with(|state| state.admitted(successor.not_before, successor.not_after));
    let report = cert_status_with(None, Some(&carry), 31_003, now()).unwrap();
    assert_eq!(report.state, "valid");
    assert_eq!(report.not_after, Some(successor.not_after));
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_journaled_request_is_recovered_at_the_next_connect_despite_the_carried_backoff() {
    let _generation = Generation::set(31_004);
    let mode = Arc::new(AtomicU8::new(0));
    let answering = mode.clone();
    let (tree, successor, authority) = due_with(move |index, purpose| match purpose {
        None => Answer::Issue,
        Some(_) if answering.load(Ordering::SeqCst) == 1 => Answer::Issue,
        Some(_) if index == 2 => Answer::Unavailable,
        Some(_) => Answer::Busy,
    });
    let carry: Arc<Carry> = Arc::default();
    // A start journals a request and gets no answer: refused, backed off.
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    let kept = carry.get().unwrap();
    assert!(kept.pending);
    assert_eq!(kept.attempts, 1);
    assert!(kept.next_attempt_at > now() + FOLD_SECS);
    assert_eq!(authority.seen().len(), 3);
    // The authority is back. The next Connect, inside the carried backoff
    // (the refused start left no epoch for --renew to force), tries the
    // receipt recovery at once instead of refusing unasked.
    mode.store(1, Ordering::SeqCst);
    take_logged();
    let second = Harness::carried(&carry);
    assert_eq!(second.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(
        (seen.len(), seen[3].purpose, seen[4].purpose),
        (5, ProofPurpose::Receipt, ProofPurpose::Authorize)
    );
    assert!(seen
        .iter()
        .all(|request| request.request_id == seen[0].request_id));
    // The attempt count was carried (the backoff keeps doubling).
    assert!(
        take_logged().contains(&"state:start attempt:2 connects:3".to_string()),
        "the second attempt"
    );
    admits_successor(&tree, &successor);
    // Without a journal the carried backoff still holds (the old
    // certificate carries traffic meanwhile).
    let mut state = RenewalState {
        carry: Some(Arc::new(Carry::default())),
        ..RenewalState::default()
    };
    state.observed(1_000, 4_000, false);
    state.carry_in(9, 3_150);
    state.failed(3_100, FailureClass::Unavailable, false);
    let carried = state.carry.clone().unwrap();
    carried.set(state.carried().unwrap());
    for (pending, next) in [(false, 3_160), (true, 0)] {
        let mut fresh = RenewalState {
            carry: Some(carried.clone()),
            ..RenewalState::default()
        };
        fresh.observed(1_000, 4_000, pending);
        fresh.carry_in(9, 3_150);
        assert_eq!(
            (fresh.attempts, fresh.next_attempt_at),
            (1, next),
            "{pending}"
        );
    }
}

#[test]
fn renewal_one_guarded_deferral_is_logged_once_by_the_step_and_the_monitor() {
    let deferrals = |lines: &[String]| {
        lines
            .iter()
            .filter(|line| line.starts_with("state:deferred:guarded "))
            .count()
    };
    let (tree, _successor, authority) = due_with(|_, _| Answer::Issue);
    let guarded = Monitor {
        guarded: true,
        ..LIVE
    };
    let reasserting = Monitor {
        live: false,
        ..guarded
    };
    let harness = Harness::new();
    let _armed = Armed::relay(Some("127.0.0.1:443".parse().unwrap()));
    take_logged();
    // A natural rebuild's step defers (and logs) first, then the monitor's
    // checks see the same deferral, with a not-live check between them.
    assert_eq!(harness.run(&tree), Ok(()));
    let at = now();
    assert_eq!(
        monitor_step(&harness.renewal, at, &guarded),
        Action::DeferGuarded
    );
    assert_eq!(
        monitor_step(&harness.renewal, at + 5, &reasserting),
        Action::None
    );
    assert_eq!(
        monitor_step(&harness.renewal, at + 10, &guarded),
        Action::DeferGuarded
    );
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(deferrals(&take_logged()), 1, "one deferral, one line");
    assert_eq!(authority.accepts(), 0);
    // A deferral that ended (an unguarded check sealed) and a new one: a
    // second line.
    assert_eq!(monitor_step(&harness.renewal, at + 15, &LIVE), Action::Seal);
    assert_eq!(
        monitor_step(&harness.renewal, at + 20, &guarded),
        Action::DeferGuarded
    );
    assert_eq!(deferrals(&take_logged()), 1);
    // The monitor alone: one line over a whole guarded Due window, not-live
    // checks included.
    let (nb, na) = (1_000, 1_000 + DAY);
    let alone = RenewalHandle::default();
    alone.with(|state| state.admitted(nb, na));
    let from = renewal_attempt_at(nb, na);
    for (index, check) in (from..na).step_by(5).enumerate() {
        let monitor = if index % 7 == 3 {
            &reasserting
        } else {
            &guarded
        };
        monitor_step(&alone, check, monitor);
    }
    assert_eq!(deferrals(&take_logged()), 1);
}

// ---------------------------------------------------------------------------
// v32 (S23c): renewal outcomes that can never be installed. An issued
// receipt the client refuses is superseded (never parked, paced, the check
// named); a request the authority only rejected is parked beside the
// captured certificate; the expired gate and the backoff are carried.

/// The live incident of 27 October 2026 (macos-test-2): the predecessor's
/// window, the instant the authority issued its 24 h successor, and the
/// test CA's notAfter.
const LIVE_PREDECESSOR: (u64, u64) = (1_792_693_436, 1_793_187_830);
const LIVE_ISSUED_AT: u64 = 1_793_082_041;
const LIVE_CA_NOT_AFTER: u64 = 1_793_188_333;

fn lines_from(logged: &[String], prefix: &str) -> Vec<String> {
    logged
        .iter()
        .filter(|line| line.starts_with(prefix))
        .cloned()
        .collect()
}

/// The binding of the parked request on disk.
fn parked_binding(tree: &ReadyTree) -> RequestBinding {
    let parked: serde_json::Value = serde_json::from_slice(
        &std::fs::read(tree.identity_dir().join(renewal_journal::PARKED)).unwrap(),
    )
    .unwrap();
    serde_json::from_value(parked["binding"].clone()).unwrap()
}

/// A Renew request of `predecessor_sha256` (and that PEM) with
/// `request_id`, in the journal's bytes, at `leaf`.
fn write_request(
    tree: &ReadyTree,
    leaf: &str,
    request_id: char,
    predecessor_sha256: &str,
) -> RequestBinding {
    let binding = RequestBinding {
        operation: Operation::Renew,
        request_id: request_id.to_string().repeat(64),
        profile_sha256: tree.profile_sha256().into(),
        csr_sha256: sha256_hex(tree.csr_pem().as_bytes()),
        predecessor_sha256: Some(predecessor_sha256.into()),
    };
    let request = format!(
        r#"{{"version":1,"binding":{},"predecessor_certificate_pem":{},"invitation":null}}"#,
        serde_json::to_string(&binding).unwrap(),
        serde_json::to_string(tree.certificate_pem()).unwrap()
    );
    tree.write_identity_file(leaf, request.as_bytes());
    binding
}

fn leaf_exists(tree: &ReadyTree, leaf: &str) -> bool {
    tree.identity_dir().join(leaf).exists()
}

fn read_leaf(tree: &ReadyTree, leaf: &str) -> Vec<u8> {
    std::fs::read(tree.identity_dir().join(leaf)).unwrap()
}

/// The answers of a mode switch: `Rejected` until `mode` is 1, `Issue`
/// once it is, `Close` at the accept while it is 2, `Drop` after the
/// request while it is 3.
fn switched(mode: &Arc<AtomicU8>) -> impl FnMut(usize, Option<ProofPurpose>) -> Answer + Send {
    let mode = mode.clone();
    move |_, purpose| match (mode.load(Ordering::SeqCst), purpose) {
        (2, None) => Answer::Close,
        (_, None) => Answer::Issue,
        (1, Some(_)) => Answer::Issue,
        (3, Some(_)) => Answer::Drop,
        (_, Some(_)) => Answer::Rejected,
    }
}

#[test]
fn renewal_supersedes_an_issued_successor_that_does_not_extend_the_predecessor() {
    // T1: issued at the predecessor's due time, valid 6 h: it ends an hour
    // before the predecessor (v31: the same refusal, then a redial at every
    // Connect with only `local_refused` to show for it).
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let shorter = Successor::for_tree(&tree, 6 * HOUR);
    let predecessor_not_after = tree.not_before() + DAY;
    assert!(shorter.not_after < predecessor_not_after);
    assert!(predecessor_not_after - shorter.not_after <= HOUR + 2);
    let authority = TestAuthority::spawn(listener, &tree, shorter, |_, _| Answer::Issue);
    let pem = read_leaf(&tree, "device.pem");
    let harness = Harness::new();
    take_logged();
    let refused = harness.run(&tree).unwrap_err();
    assert_eq!(refused.code, IDENTITY_RENEWAL_PENDING);
    assert_eq!(refused.recovery, Recovery::Recoverable);
    assert_eq!(authority.issued(), 1);
    // Nothing saved, never parked: the authority's registry names the
    // successor, so the relay refuses the predecessor.
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    assert!(!leaf_exists(&tree, renewal_journal::RESPONSE));
    assert!(!leaf_exists(&tree, renewal_journal::PARKED));
    assert_eq!(read_leaf(&tree, "device.pem"), pem);
    let report = harness.renewal.with(|state| state.report(now()));
    assert_eq!(report.state, "superseded");
    assert_eq!(report.last_failure.as_deref(), Some("local_refused"));
    assert_eq!(
        report.check.as_deref(),
        Some(renewal_journal::SUCCESSOR_NOT_EXTENDING)
    );
    let logged = take_logged();
    assert_eq!(
        logged[logged.len() - 2..],
        [
            "state:failed:local_refused attempt:1 next_s:60 dials:1".to_string(),
            "state:superseded attempt:1 check:renewal_successor_not_extending".to_string(),
        ],
        "{logged:?}"
    );
    // The session capture stays refused (the journal), so no relay dial
    // presents the superseded predecessor.
    let capture = CapturedAppGroupInputs::capture_test_root(tree.root())
        .err()
        .unwrap();
    assert_eq!(
        Refusal::custody(&capture).code,
        crate::identity_custody::JOURNAL_PENDING
    );
}

#[test]
fn renewal_superseded_request_never_redials_at_each_connect() {
    // T2, the live incident with its own timeline shifted to now:
    // predecessor 2026-10-22T18:23:56Z..2026-10-28T11:43:50Z (494394 s),
    // the device CA ending 2026-10-28T11:52:13Z, a v31 journaled request,
    // and the authority's 24 h successor issued 2026-10-27T06:20:41Z,
    // which receipt recovery returns at every Connect.
    let _generation = Generation::set(32_002);
    assert_eq!(
        provider_xpc::utc_text(LIVE_PREDECESSOR.0),
        "2026-10-22T18:23:56Z"
    );
    assert_eq!(
        provider_xpc::utc_text(LIVE_PREDECESSOR.1),
        "2026-10-28T11:43:50Z"
    );
    assert_eq!(
        provider_xpc::utc_text(LIVE_ISSUED_AT),
        "2026-10-27T06:20:41Z"
    );
    assert_eq!(
        provider_xpc::utc_text(LIVE_CA_NOT_AFTER),
        "2026-10-28T11:52:13Z"
    );
    assert_eq!(
        provider_xpc::utc_text(renewal_due_at(LIVE_PREDECESSOR.0, LIVE_PREDECESSOR.1)),
        "2026-10-26T13:57:12Z"
    );
    assert_eq!(
        provider_xpc::utc_text(LIVE_ISSUED_AT + DAY),
        "2026-10-28T06:20:41Z"
    );
    let listener = TestAuthority::bind();
    let t = now();
    let nb = t - (LIVE_ISSUED_AT - LIVE_PREDECESSOR.0);
    let tree = ReadyTree::issued_as(
        "127.0.0.1:443".parse().unwrap(),
        crate::test_fixture::Issuance {
            authority: listener.local_addr().unwrap(),
            not_before: Some(nb),
            lifetime_secs: LIVE_PREDECESSOR.1 - LIVE_PREDECESSOR.0,
            ca_not_after: Some(nb + (LIVE_CA_NOT_AFTER - LIVE_PREDECESSOR.0)),
            ..crate::test_fixture::Issuance::default()
        },
    );
    let na = nb + (LIVE_PREDECESSOR.1 - LIVE_PREDECESSOR.0);
    // The authority signs now + 24 h: it fits under the CA (503 s after
    // the predecessor) and ends 19389 s before the predecessor.
    let shorter = Successor::signed_at(&tree, t, DAY);
    assert_eq!(na - shorter.not_after, 19_389);
    // A lifetime that would extend the predecessor would outlive the CA.
    assert!(aegis_core::secure_channel::enrollment::sign_csr(
        tree.device_id(),
        tree.csr_pem(),
        tree.device_ca_pem(),
        tree.device_ca_key_pem(),
        t,
        na - t + 504,
    )
    .is_err());
    let authority = TestAuthority::spawn(listener, &tree, shorter, |_, _| Answer::Issue);
    let binding = journal_request(&tree);
    authority.remember(binding.clone());
    let carry: Arc<Carry> = Arc::default();
    take_logged();
    let first = now();
    for connect in 0..5 {
        let harness = Harness::carried(&carry);
        let refused = harness.run(&tree).unwrap_err();
        assert_eq!(refused.code, IDENTITY_RENEWAL_PENDING, "{connect}");
        assert_eq!(refused.recovery, Recovery::Recoverable);
    }
    // One receipt recovery in five Connects (v31: five, each Receipt then
    // Authorize), never parked, the check named.
    assert_eq!(authority.accepts(), 1);
    let seen = authority.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].purpose, ProofPurpose::Receipt);
    assert_eq!(seen[0].request_id, binding.request_id);
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    assert!(!leaf_exists(&tree, renewal_journal::PARKED));
    let report = carry.report(now(), 32_002).unwrap();
    assert_eq!(report.state, "superseded");
    assert_eq!(report.attempts, 1);
    assert_eq!(
        report.check.as_deref(),
        Some(renewal_journal::SUCCESSOR_NOT_EXTENDING)
    );
    let next = report.next_attempt_at.unwrap();
    assert!(next >= first + BACKOFF_FIRST_SECS && next <= now() + BACKOFF_FIRST_SECS);
    let logged = take_logged();
    assert_eq!(lines_from(&logged, "state:start ").len(), 1, "{logged:?}");
    assert_eq!(lines_from(&logged, "state:pending ").len(), 4, "{logged:?}");
    assert!(
        logged.contains(&"state:superseded attempt:1 check:renewal_successor_not_extending".into())
    );
    // Once the carried backoff ends: one more exchange, receipt only.
    let mut kept = carry.get().unwrap();
    kept.next_attempt_at = 0;
    carry.set(kept);
    let harness = Harness::carried(&carry);
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING
    );
    let purposes: Vec<_> = authority.seen().iter().map(|seen| seen.purpose).collect();
    assert_eq!(purposes, [ProofPurpose::Receipt, ProofPurpose::Receipt]);
    let report = carry.report(now(), 32_002).unwrap();
    assert_eq!((report.state.as_str(), report.attempts), ("superseded", 2));
    assert!(report.next_attempt_at.unwrap() + 2 >= now() + 2 * BACKOFF_FIRST_SECS);
}

#[test]
fn renewal_docs_state_the_incident_bands_and_no_cut_off_by_expiry_alone() {
    // v32 review: the live guidance in the macOS docs, bound to the rules
    // the code and the authority follow.
    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    let limits = flat(include_str!(
        "../../../../docs/platforms/macos/known-limits.md"
    ));
    let operate = flat(include_str!("../../../../docs/platforms/macos/operate.md"));
    let from = limits
        .find("## Renewal outcomes that cannot be installed (v32)")
        .expect("v32 section");
    let v32 = &limits[from..];
    let v32 = &v32[..v32.find("## Not yet proven").expect("next section")];
    // The incident's three bands: the authority signs now + L and refuses
    // a certificate that would outlive its CA; the successor extends the
    // predecessor only when signed after na - L.
    let (nb, na) = LIVE_PREDECESSOR;
    let first = renewal_attempt_at(nb, na);
    let extends_from = na - DAY;
    let fits_until = LIVE_CA_NOT_AFTER - DAY;
    assert_eq!(
        (
            extends_from - first,
            fits_until - extends_from,
            na - fits_until
        ),
        (78_338, 503, 85_897)
    );
    for at in [first, extends_from, fits_until] {
        let at = provider_xpc::utc_text(at);
        assert!(v32.contains(&at), "{at}");
    }
    for span in ["(78338 s)", "(503 s)", "(85897 s)"] {
        assert!(v32.contains(span), "{span}");
    }
    assert!(!v32.contains("the CA's end only closed"));
    assert!(v32.contains("the CA's notAfter must be at least due + 60 s + L"));
    // The receipt stops replaying at the earliest of the successor's expiry
    // and an authority change; a request journaled before a restart is
    // never parked, so no time-only cut-off is promised.
    assert!(!operate.contains("Do not connect macos-test-2 after about"));
    assert!(!v32.contains("parks the request and captures the superseded predecessor"));
    for text in [v32, operate.as_str()] {
        assert!(text.contains("CA, profile or registry"));
        assert!(text.contains("never parked"));
    }
    // Troubleshooting: no row says the tunnel connects in the rollback case.
    let rows: Vec<_> = include_str!("../../../../docs/platforms/macos/troubleshooting.md")
        .lines()
        .filter(|row| row.contains("rollback to v31"))
        .collect();
    assert!(!rows.is_empty());
    for row in rows {
        assert!(!row.contains("the tunnel still connects"), "{row}");
        assert!(row.contains("the tunnel does not connect"), "{row}");
    }
}

#[test]
fn renewal_rejected_after_an_issued_answer_never_parks() {
    // T3b: an issued answer was seen (signed 10 s ahead: still not valid
    // after the bounded clock wait); the receipt is then gone (Rejected).
    let _generation = Generation::set(32_003);
    let mode = Arc::new(AtomicU8::new(1));
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let ahead = Successor::signed_at(&tree, now() + 10, DAY);
    let authority = TestAuthority::spawn(listener, &tree, ahead, switched(&mode));
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    let report = carry.report(now(), 32_003).unwrap();
    assert_eq!(report.state, "pending", "a transient check");
    assert_eq!(
        report.check.as_deref(),
        Some(renewal_journal::NOT_YET_VALID)
    );
    // After the backoff: the receipt only, Rejected, and still blocking.
    mode.store(0, Ordering::SeqCst);
    let mut kept = carry.get().unwrap();
    kept.next_attempt_at = 0;
    carry.set(kept);
    let second = Harness::carried(&carry);
    assert_eq!(
        second.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING
    );
    let purposes: Vec<_> = authority.seen().iter().map(|seen| seen.purpose).collect();
    assert_eq!(purposes, [ProofPurpose::Authorize, ProofPurpose::Receipt]);
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    assert!(!leaf_exists(&tree, renewal_journal::PARKED));
    assert_eq!(carry.report(now(), 32_003).unwrap().state, "pending");
}

#[test]
fn renewal_superseded_request_keeps_its_check_after_a_later_failure() {
    // v32 review: once superseded, a later receipt-only attempt that is
    // rejected (the authority stopped replaying the receipt) or gets no
    // answer still names the receipt check: in `cert-status`, the host line
    // and the log (v32 lost it: `renewal superseded (rejected)`).
    let mode = Arc::new(AtomicU8::new(1));
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let shorter = Successor::for_tree(&tree, 6 * HOUR);
    let authority = TestAuthority::spawn(listener, &tree, shorter, switched(&mode));
    let harness = Harness::new();
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING
    );
    let code = renewal_journal::SUCCESSOR_NOT_EXTENDING;
    for (attempt, mode_now, class, dials) in [(2, 0, "rejected", 1), (3, 3, "unavailable", 3)] {
        mode.store(mode_now, Ordering::SeqCst);
        harness.renewal.with(|state| state.next_attempt_at = 0);
        take_logged();
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{class}"
        );
        assert_eq!(
            authority.seen().last().unwrap().purpose,
            ProofPurpose::Receipt,
            "{class}: receipt only"
        );
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!(report.state, "superseded", "{class}");
        assert_eq!(report.last_failure.as_deref(), Some(class));
        assert_eq!(report.check.as_deref(), Some(code), "{class}");
        // The host decodes it and names the check.
        let reply = Reply::CertStatus(report.clone());
        let bytes = provider_xpc::encode_reply(&reply).unwrap();
        assert_eq!(
            provider_xpc::decode_reply(&bytes, Verb::CertStatus),
            Ok(reply),
            "{class}"
        );
        assert!(
            report
                .renewal_line()
                .unwrap()
                .starts_with(&format!("renewal superseded ({code}) since ")),
            "{class}"
        );
        let logged = take_logged();
        let next = backoff_secs(attempt);
        assert_eq!(
            logged[logged.len() - 2..],
            [
                format!("state:failed:{class} attempt:{attempt} next_s:{next} dials:{dials}"),
                format!("state:superseded attempt:{attempt} check:{code}"),
            ],
            "{logged:?}"
        );
        assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    }
}

#[test]
fn renewal_a_refused_park_keeps_the_authoritys_answer_paces_and_gates() {
    // v32 review: the park of a definite rejection can be refused (a parked
    // request of the installed certificate beside it, or a journal write);
    // the failure is still the authority's: logged and reported as
    // `rejected` with the refusal's check, paced like any rejection, and
    // once expired it closes the carried gate (v32: `local_refused`, a
    // redial at every Connect and no gate).
    //
    // (a) Due: a fresh authorization rejected in the skew window keeps the
    // request journaled (settled); a parked request of the installed
    // certificate then appears beside it, and the next rejection's park is
    // refused.
    let _generation = Generation::set(32_110);
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 16 * HOUR + 70, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Rejected);
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    let installed_sha256 = tree.online().certificate_sha256.clone();
    write_request(&tree, renewal_journal::PARKED, 'a', &installed_sha256);
    let parked = read_leaf(&tree, renewal_journal::PARKED);
    first.renewal.with(|state| state.next_attempt_at = 0);
    take_logged();
    assert_eq!(first.run(&tree).unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    assert_eq!(authority.seen().len(), 3);
    assert_eq!(read_leaf(&tree, renewal_journal::PARKED), parked);
    let logged = take_logged();
    assert_eq!(
        logged[logged.len() - 2..],
        [
            "state:failed:rejected attempt:2 next_s:120 dials:2".to_string(),
            "state:refused attempt:2 check:renewal_parked_refused".to_string(),
        ],
        "{logged:?}"
    );
    let report = carry.report(now(), 32_110).unwrap();
    assert_eq!(report.state, "pending");
    assert_eq!(report.last_failure.as_deref(), Some("rejected"));
    assert_eq!(
        report.check.as_deref(),
        Some(renewal_journal::PARKED_REFUSED)
    );
    let reply = Reply::CertStatus(report.clone());
    let bytes = provider_xpc::encode_reply(&reply).unwrap();
    assert_eq!(
        provider_xpc::decode_reply(&bytes, Verb::CertStatus),
        Ok(reply)
    );
    // Paced: the next Connect makes no dial.
    let next = Harness::carried(&carry);
    assert_eq!(next.run(&tree).unwrap_err().code, IDENTITY_RENEWAL_PENDING);
    assert_eq!(authority.seen().len(), 3, "paced");

    // (b) Expired: a parked request's receipt is rejected and its park is
    // refused (cut before the rename): the definite rejection closes the
    // carried gate, so the next Connect captures nothing.
    let _expired = Generation::set(32_111);
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let successor = Successor::signed_at(&tree, tree.not_before() + DAY - 600, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Rejected);
    let installed_sha256 = tree.online().certificate_sha256.clone();
    write_request(&tree, renewal_journal::PARKED, 'd', &installed_sha256);
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    take_logged();
    cut::set(Some("park_begin"));
    let ran = first.run(&tree);
    cut::set(None);
    assert_eq!(ran.unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(authority.seen().len(), 1);
    assert!(leaf_exists(&tree, renewal_journal::REQUEST), "unparked");
    let logged = take_logged();
    assert_eq!(
        logged[logged.len() - 2..],
        [
            format!("state:failed:rejected attempt:1 next_s:{EXPIRED_RECOVERY_SECS} dials:1"),
            "state:refused attempt:1 check:renewal_test_crash".to_string(),
        ],
        "{logged:?}"
    );
    assert!(carry.get().unwrap().expired_under.is_some(), "carried gate");
    let next = Harness::carried(&carry);
    assert_eq!(next.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(next.captures.load(Ordering::SeqCst), 0, "no capture");
    assert_eq!(authority.accepts(), 1);
}

#[test]
fn renewal_unparks_before_the_first_request_byte_and_installs_once_the_authority_recovers() {
    // T4.
    let mode = Arc::new(AtomicU8::new(0));
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), switched(&mode));
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    assert!(leaf_exists(&tree, renewal_journal::PARKED));
    let binding = parked_binding(&tree);
    assert_eq!(authority.seen()[0].request_id, binding.request_id);
    // The authority committed it after all; the next attempt is due.
    authority.remember(binding.clone());
    let dir = tree.identity_dir();
    authority.probe(move || {
        dir.join(renewal_journal::REQUEST).exists() && !dir.join(renewal_journal::PARKED).exists()
    });
    mode.store(1, Ordering::SeqCst);
    harness.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(harness.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        (seen[1].purpose, seen[1].request_id.as_str()),
        (ProofPurpose::Receipt, binding.request_id.as_str())
    );
    // Journaled again before its first byte.
    assert_eq!(authority.probed(), [true]);
    assert_eq!(authority.issued(), 1);
    admits_successor(&tree, &successor);
    assert!(!leaf_exists(&tree, renewal_journal::PARKED));
}

#[test]
fn renewal_parked_transport_failure_before_and_after_the_unpark() {
    // T5.
    let _generation = Generation::set(32_005);
    let mode = Arc::new(AtomicU8::new(0));
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), switched(&mode));
    let carry: Arc<Carry> = Arc::default();
    let harness = Harness::carried(&carry);
    assert_eq!(harness.run(&tree), Ok(()));
    let parked = read_leaf(&tree, renewal_journal::PARKED);
    // (a) Every connect ends before any challenge: no unpark, the capture.
    mode.store(2, Ordering::SeqCst);
    harness.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), 4);
    assert_eq!(read_leaf(&tree, renewal_journal::PARKED), parked);
    assert!(!leaf_exists(&tree, renewal_journal::REQUEST));
    assert_eq!(harness.token(), "parked");
    CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    // (b) The authority reads the request and drops it: unparked, its
    // outcome unknown, so blocking.
    mode.store(3, Ordering::SeqCst);
    harness.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        IDENTITY_RENEWAL_PENDING
    );
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    assert!(!leaf_exists(&tree, renewal_journal::PARKED));
    let report = carry.report(now(), 32_005).unwrap();
    assert_eq!(report.state, "pending");
    assert_eq!(report.last_failure.as_deref(), Some("unavailable"));
    // The next Connect retries it at once, receipt first, and installs.
    mode.store(1, Ordering::SeqCst);
    let before = authority.seen().len();
    let next = Harness::carried(&carry);
    assert_eq!(next.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(seen[before].purpose, ProofPurpose::Receipt);
    assert!(seen
        .iter()
        .all(|request| request.request_id == seen[0].request_id));
    admits_successor(&tree, &successor);
}

#[test]
fn renewal_names_every_definitive_receipt_check_and_supersedes() {
    // T6: each definitive receipt check, through the network.
    fn other_profile(receipt: &mut aegis_core::secure_channel::enrollment_wire::EnrollmentReceipt) {
        receipt.binding.profile_sha256 = "f".repeat(64);
    }
    fn other_device(receipt: &mut aegis_core::secure_channel::enrollment_wire::EnrollmentReceipt) {
        receipt.device_id = "fixture-device-2".into();
    }
    fn edited_window(receipt: &mut aegis_core::secure_channel::enrollment_wire::EnrollmentReceipt) {
        receipt.not_after_unix_secs += 1;
    }
    type Edit = Option<fn(&mut aegis_core::secure_channel::enrollment_wire::EnrollmentReceipt)>;
    let cases: [(&str, Edit, &str); 6] = [
        (
            "profile",
            Some(other_profile),
            renewal_journal::RECEIPT_BINDING,
        ),
        (
            "device",
            Some(other_device),
            renewal_journal::RECEIPT_IDENTITY,
        ),
        ("ca", None, renewal_journal::SUCCESSOR_CERTIFICATE),
        (
            "window",
            Some(edited_window),
            renewal_journal::RECEIPT_METADATA,
        ),
        ("early", None, renewal_journal::SUCCESSOR_BEFORE_DUE),
        ("shorter", None, renewal_journal::SUCCESSOR_NOT_EXTENDING),
    ];
    for (case, edit, code) in cases {
        let listener = TestAuthority::bind();
        let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
        let successor = match case {
            "ca" => {
                let (ca, key) = crate::test_fixture::signing_ca();
                Successor::signed_by(&tree, &ca.pem(), &key.serialize_pem(), now(), DAY)
            }
            "early" => Successor::signed_at(&tree, tree.not_before() + HOUR, DAY),
            "shorter" => Successor::for_tree(&tree, 6 * HOUR),
            _ => Successor::for_tree(&tree, DAY),
        };
        let answer = if edit.is_some() {
            Answer::IssueEdited
        } else {
            Answer::Issue
        };
        let authority = TestAuthority::spawn(listener, &tree, successor, move |_, _| answer);
        if let Some(edit) = edit {
            authority.edit(edit);
        }
        let pem = read_leaf(&tree, "device.pem");
        let harness = Harness::new();
        take_logged();
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{case}"
        );
        assert!(leaf_exists(&tree, renewal_journal::REQUEST), "{case}");
        assert!(!leaf_exists(&tree, renewal_journal::PARKED), "{case}");
        assert!(!leaf_exists(&tree, renewal_journal::RESPONSE), "{case}");
        assert_eq!(read_leaf(&tree, "device.pem"), pem, "{case}");
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!(report.state, "superseded", "{case}");
        assert_eq!(report.check.as_deref(), Some(code), "{case}");
        assert!(renewal_journal::definitive(code), "{case}");
        assert!(
            take_logged().contains(&format!("state:superseded attempt:1 check:{code}")),
            "{case}"
        );
    }
    // After expiry (receipt recovery only): a successor signed at or after
    // the predecessor's expiry; definitive, so the expired gate closes.
    let _generation = Generation::set(32_006);
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let late = Successor::signed_at(&tree, tree.not_before() + DAY + 60, DAY);
    let authority = TestAuthority::spawn(listener, &tree, late, |_, _| Answer::Issue);
    authority.remember(journal_request(&tree));
    let harness = Harness::new();
    take_logged();
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert!(take_logged().contains(&format!(
        "state:superseded attempt:1 check:{}",
        renewal_journal::SUCCESSOR_AFTER_EXPIRY
    )));
    assert_eq!(
        harness.renewal.snapshot().expired_under.map(|gate| gate.0),
        Some(32_006)
    );
    assert!(renewal_journal::definitive(
        renewal_journal::SUCCESSOR_AFTER_EXPIRY
    ));
    // A malformed receipt never passes the wire (`read_response` validates
    // it); the journal's own check names it all the same.
    let tree = aged("127.0.0.1:9".parse().unwrap(), 17 * HOUR, DAY);
    let binding = journal_request(&tree);
    let successor = Successor::for_tree(&tree, DAY);
    let journal =
        renewal_journal::RenewalJournal::open(&tree.identity_dir(), tree.profile_sha256()).unwrap();
    let malformed = aegis_core::secure_channel::enrollment_wire::EnrollmentReceipt {
        version: 2,
        binding,
        device_id: tree.device_id().into(),
        certificate_pem: successor.certificate_pem.clone(),
        certificate_sha256: successor.fingerprint.clone(),
        not_before_unix_secs: successor.not_before,
        not_after_unix_secs: successor.not_after,
        issued_generation: RENEWED_GENERATION,
        snapshot_sha256: RENEWED_SNAPSHOT.into(),
        state: aegis_core::secure_channel::enrollment_wire::ReceiptState::IssuedPendingDistribution,
    };
    assert_eq!(
        journal.accept(&malformed, now()).unwrap_err(),
        renewal_journal::RECEIPT_MALFORMED
    );
    assert!(renewal_journal::definitive(
        renewal_journal::RECEIPT_MALFORMED
    ));
    drop(journal);
    assert!(!leaf_exists(&tree, renewal_journal::RESPONSE));
}

#[test]
fn renewal_transient_post_issue_refusals_block_paced_and_never_gate() {
    // T7: a successor still ahead of our clock after the bounded wait, and
    // one already expired by our clock (an authority clock behind ours).
    for (case, code) in [
        ("ahead", renewal_journal::NOT_YET_VALID),
        ("expired", renewal_journal::SUCCESSOR_EXPIRED),
    ] {
        let listener = TestAuthority::bind();
        let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
        let successor = if case == "ahead" {
            Successor::signed_at(&tree, now() + 10, DAY)
        } else {
            Successor::signed_at(&tree, now() - 3 * HOUR, 2 * HOUR)
        };
        let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Issue);
        let harness = Harness::new();
        take_logged();
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{case}"
        );
        assert!(leaf_exists(&tree, renewal_journal::REQUEST));
        assert!(!leaf_exists(&tree, renewal_journal::PARKED));
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!(report.state, "pending", "{case}: never superseded");
        assert_eq!(report.check.as_deref(), Some(code));
        assert!(!renewal_journal::definitive(code));
        assert!(take_logged().contains(&format!("state:refused attempt:1 check:{code}")));
        // Paced: a second start inside the backoff makes no dial.
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING
        );
        assert_eq!(authority.seen().len(), 1, "{case}");
    }
    // Expired: a receipt-only answer already expired by our clock is no
    // reason for the gate; a retry after EXPIRED_RECOVERY_SECS dials again.
    let _generation = Generation::set(32_007);
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let old_not_after = tree.not_before() + DAY;
    let stale = Successor::signed_at(&tree, old_not_after - 600, 300);
    let authority = TestAuthority::spawn(listener, &tree, stale, |_, _| Answer::Issue);
    authority.remember(journal_request(&tree));
    let carry: Arc<Carry> = Arc::default();
    let harness = Harness::carried(&carry);
    assert_eq!(
        harness.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    let state = harness.renewal.snapshot();
    assert_eq!(state.expired_under, None, "no gate");
    assert_eq!(state.check, Some(renewal_journal::SUCCESSOR_EXPIRED));
    assert!(state.next_attempt_at + 2 >= now() + EXPIRED_RECOVERY_SECS);
    // Paced across Connects too: a new epoch takes up the expired window's
    // next attempt beside the journaled request.
    let next = Harness::carried(&carry);
    assert_eq!(next.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(authority.seen().len(), 1, "paced");
    next.renewal.with(|state| state.next_attempt_at = 0);
    assert_eq!(next.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(authority.seen().len(), 2, "dials again");
}

#[test]
fn renewal_cut_around_park_and_unpark_recovers_without_a_loop() {
    // T8.
    for point in ["park_begin", "parked", "unparked"] {
        let mode = Arc::new(AtomicU8::new(0));
        let listener = TestAuthority::bind();
        let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
        let successor = Successor::for_tree(&tree, DAY);
        let authority = TestAuthority::spawn(listener, &tree, successor.clone(), switched(&mode));
        let harness = Harness::new();
        if point == "unparked" {
            // Parked first; the cut comes in the next attempt's unpark.
            assert_eq!(harness.run(&tree), Ok(()));
            harness.renewal.with(|state| state.next_attempt_at = 0);
        }
        cut::set(Some(point));
        let cut_run = harness.run(&tree);
        cut::set(None);
        assert_eq!(
            cut_run.unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{point}"
        );
        match point {
            "park_begin" | "unparked" => {
                assert!(leaf_exists(&tree, renewal_journal::REQUEST), "{point}");
                assert!(!leaf_exists(&tree, renewal_journal::PARKED), "{point}");
            }
            _ => {
                assert!(!leaf_exists(&tree, renewal_journal::REQUEST), "{point}");
                assert!(leaf_exists(&tree, renewal_journal::PARKED), "{point}");
            }
        }
        let sent = authority.seen().len();
        // A provider restart: the next start recovers it.
        let next = Harness::new();
        if point == "parked" {
            // Parked, and the next start's record is fresh: it resumes it.
            next.renewal.with(|state| state.next_attempt_at = 0);
        }
        mode.store(1, Ordering::SeqCst);
        assert_eq!(next.run(&tree), Ok(()), "{point}");
        let seen = authority.seen();
        assert_eq!(seen[sent].purpose, ProofPurpose::Receipt, "{point}");
        assert!(
            seen.iter()
                .all(|request| request.request_id == seen[0].request_id),
            "{point}: one request id"
        );
        assert_eq!(authority.issued(), 1, "{point}");
        admits_successor(&tree, &successor);
        assert!(!leaf_exists(&tree, renewal_journal::PARKED));
    }
}

#[test]
fn renewal_never_overwrites_or_ignores_a_parked_request_id() {
    // T9 (a): a parked request of the installed certificate beside a
    // journaled one (a v31 rollback): the rejected request is never parked
    // over it. v32 review: the journaled request is v31's (its history
    // unknown to this process), so it is never parked at all: the start is
    // refused at every Connect (the tunnel does not connect), and the
    // rejection paces the next Connects (v32 redialed Receipt and Authorize
    // at every one).
    let _generation = Generation::set(32_109);
    let (tree, _successor, authority) = due_with(|_, _| Answer::Rejected);
    let installed_sha256 = tree.online().certificate_sha256.clone();
    write_request(&tree, renewal_journal::PARKED, 'a', &installed_sha256);
    write_request(&tree, renewal_journal::REQUEST, 'b', &installed_sha256);
    let parked = read_leaf(&tree, renewal_journal::PARKED);
    let request = read_leaf(&tree, renewal_journal::REQUEST);
    let carry: Arc<Carry> = Arc::default();
    take_logged();
    let mut requests = Vec::new();
    for connect in 0..3 {
        let harness = Harness::carried(&carry);
        assert_eq!(
            harness.run(&tree).unwrap_err().code,
            IDENTITY_RENEWAL_PENDING,
            "{connect}"
        );
        requests.push(authority.seen().len());
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!(
            (report.state.as_str(), report.last_failure.as_deref()),
            ("pending", Some("rejected")),
            "{connect}"
        );
        assert_eq!(report.check, None, "{connect}");
        assert!(
            CapturedAppGroupInputs::capture_test_root(tree.root()).is_err(),
            "{connect}: no capture"
        );
    }
    assert_eq!(requests, [2, 2, 2], "one receipt and one authorization");
    assert!(authority
        .seen()
        .iter()
        .all(|seen| seen.request_id == "b".repeat(64)));
    assert_eq!(read_leaf(&tree, renewal_journal::PARKED), parked);
    assert_eq!(read_leaf(&tree, renewal_journal::REQUEST), request);
    let logged = take_logged();
    assert!(
        lines_from(&logged, "state:refused").is_empty(),
        "{logged:?}"
    );
    assert_eq!(lines_from(&logged, "state:pending attempt:0").len(), 2);
    // (b) A parked request that cannot be read (a second hard link) or
    // parsed: renewal refused once, no dial, no fresh request; the capture.
    for broken in ["link", "garbage"] {
        let (tree, _successor, authority) = due_with(|_, _| Answer::Issue);
        let installed_sha256 = tree.online().certificate_sha256.clone();
        if broken == "link" {
            write_request(&tree, renewal_journal::PARKED, 'a', &installed_sha256);
            std::fs::hard_link(
                tree.identity_dir().join(renewal_journal::PARKED),
                tree.identity_dir().join("parked-second-link"),
            )
            .unwrap();
        } else {
            tree.write_identity_file(renewal_journal::PARKED, b"{}");
        }
        let parked = read_leaf(&tree, renewal_journal::PARKED);
        let harness = Harness::new();
        take_logged();
        for _ in 0..2 {
            assert_eq!(harness.run(&tree), Ok(()), "{broken}");
        }
        assert_eq!(authority.accepts(), 0, "{broken}");
        assert!(!leaf_exists(&tree, renewal_journal::REQUEST), "{broken}");
        assert_eq!(read_leaf(&tree, renewal_journal::PARKED), parked);
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let logged = take_logged();
        assert_eq!(
            lines_from(
                &logged,
                "state:refused attempt:0 check:renewal_parked_refused"
            )
            .len(),
            1,
            "{broken}: {logged:?}"
        );
        let report = harness.renewal.with(|state| state.report(now()));
        assert_eq!(
            report.check.as_deref(),
            Some(renewal_journal::PARKED_REFUSED)
        );
        assert!(report
            .renewal_line()
            .unwrap()
            .contains("renewal_parked_refused"));
    }
}

#[test]
fn renewal_an_unreadable_parked_leaf_never_refuses_a_verified_successor() {
    // v32 review: a journaled request (here v31's) is recovered by its
    // receipt while an unreadable parked leaf lies beside it (a second hard
    // link, or bytes that do not parse). The successor verified for that
    // request is the only certificate the authority names: it is installed
    // and the unreadable leaf left in place (v32 refused the successor at
    // every attempt, `renewal_parked_refused`, until an import).
    for broken in ["link", "garbage"] {
        let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
        authority.remember(journal_request(&tree));
        let installed_sha256 = tree.online().certificate_sha256.clone();
        if broken == "link" {
            write_request(&tree, renewal_journal::PARKED, 'a', &installed_sha256);
            std::fs::hard_link(
                tree.identity_dir().join(renewal_journal::PARKED),
                tree.identity_dir().join("parked-second-link"),
            )
            .unwrap();
        } else {
            tree.write_identity_file(renewal_journal::PARKED, b"{}");
        }
        let parked = read_leaf(&tree, renewal_journal::PARKED);
        let harness = Harness::new();
        assert_eq!(harness.run(&tree), Ok(()), "{broken}");
        let seen = authority.seen();
        assert_eq!(
            (seen.len(), seen[0].purpose),
            (1, ProofPurpose::Receipt),
            "{broken}"
        );
        assert_eq!(harness.token(), "renewed_pending_ack", "{broken}");
        admits_successor(&tree, &successor);
        assert_eq!(read_leaf(&tree, renewal_journal::PARKED), parked);
    }
}

#[test]
fn renewal_stale_parked_request_is_removed_before_the_first_identity_write() {
    // T10: a parked request of another (an older) certificate.
    for cut_at in [None, Some("stale_parked_removed")] {
        let (tree, successor, authority) = due_with(|_, _| Answer::Issue);
        write_request(&tree, renewal_journal::PARKED, 'c', &"a".repeat(64));
        {
            let journal =
                renewal_journal::RenewalJournal::open(&tree.identity_dir(), tree.profile_sha256())
                    .unwrap();
            let status = journal.status(now()).unwrap();
            assert!(!status.pending && !status.parked && !status.parked_refused);
        }
        let harness = Harness::new();
        cut::set(cut_at);
        let ran = harness.run(&tree);
        cut::set(None);
        // A fresh request beside it, never the stale request id.
        assert!(authority
            .seen()
            .iter()
            .all(|seen| seen.request_id != "c".repeat(64)));
        if cut_at.is_some() {
            assert_eq!(ran.unwrap_err().code, IDENTITY_RENEWAL_PENDING);
            assert!(!leaf_exists(&tree, renewal_journal::PARKED));
            assert!(!leaf_exists(&tree, renewal_journal::RESPONSE));
            assert!(leaf_exists(&tree, renewal_journal::REQUEST));
            assert_eq!(Harness::new().run(&tree), Ok(()));
        } else {
            assert_eq!(ran, Ok(()));
        }
        assert_eq!(authority.issued(), 1);
        admits_successor(&tree, &successor);
        assert!(!leaf_exists(&tree, renewal_journal::PARKED));
    }
}

#[test]
fn renewal_monitor_holds_a_parked_request_and_defers_forced_renewals_to_the_next_connect() {
    // T11.
    let (nb, na) = (1_000, 1_000 + DAY);
    let at = renewal_attempt_at(nb, na);
    let handle = RenewalHandle::default();
    handle.with(|state| {
        state.admitted(nb, na);
        state.failed_at(at, FailureClass::Rejected, Journal::Parked, None);
    });
    let state = handle.snapshot();
    let next = state.next_attempt_at;
    assert_eq!(state.token(next), "parked");
    assert_eq!(judge(next - 1, &state, &LIVE), Action::None, "the backoff");
    assert_eq!(judge(next, &state, &LIVE), Action::HoldParked);
    let ends = transport_hold_ends_at(nb, na);
    assert_eq!(judge(ends - 1, &state, &LIVE), Action::HoldParked);
    assert_eq!(judge(ends, &state, &LIVE), Action::Seal, "the last stretch");
    let guarded = Monitor {
        guarded: true,
        ..LIVE
    };
    assert_eq!(judge(next, &state, &guarded), Action::DeferGuarded);
    let mut forced = state.clone();
    forced.forced = true;
    assert_eq!(judge(next, &forced, &LIVE), Action::Seal, "forced");
    // An unreadable parked request refuses every attempt before any dial:
    // held even in the last stretch (a seal could never help).
    let mut refused = RenewalState::default();
    refused.admitted(nb, na);
    refused.check = Some(renewal_journal::PARKED_REFUSED);
    refused.last_failure = Some(FailureClass::LocalRefused);
    assert_eq!(judge(at, &refused, &LIVE), Action::HoldParked);
    assert_eq!(judge(na - 1, &refused, &LIVE), Action::HoldParked);
    refused.forced = true;
    assert_eq!(judge(at, &refused, &LIVE), Action::Seal, "forced");
    // Logged once per change.
    take_logged();
    let actions = monitor_over(&handle, next, next + 60, &LIVE);
    assert!(actions.iter().all(|action| *action == Action::HoldParked));
    assert_eq!(
        take_logged(),
        ["state:held:parked attempt:1".to_string()],
        "one line"
    );
    // A forced renewal the guard defers runs at the next Connect.
    handle.with(|state| state.forced = true);
    assert_eq!(
        monitor_step(&handle, next + 60, &guarded),
        Action::DeferGuarded
    );
    let state = handle.snapshot();
    assert_eq!((state.next_attempt_at, state.forced), (0, false));
    // The renew verb is accepted beside a parked request.
    let parked = RenewalHandle::default();
    parked.with(|state| {
        state.observed_with(1_000, 4_000, false, true);
    });
    assert_eq!(
        request_renewal_of(Some(&parked), 1_500),
        Ok("renew_scheduled")
    );
}

#[test]
fn renewal_expired_gate_is_carried_across_connects() {
    // T13: a definite receipt-only Rejected (v32 review: of a parked
    // request, every answer of which was a rejection) closes the gate; a
    // new epoch (the next Connect) under the same import generation
    // captures nothing.
    let _generation = Generation::set(32_013);
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let successor = Successor::signed_at(&tree, tree.not_before() + DAY - 600, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor, |_, _| Answer::Rejected);
    let installed_sha256 = tree.online().certificate_sha256.clone();
    write_request(&tree, renewal_journal::PARKED, 'd', &installed_sha256);
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(authority.seen().len(), 1);
    assert!(leaf_exists(&tree, renewal_journal::PARKED), "parked again");
    assert!(carry.get().unwrap().expired_under.is_some());
    let second = Harness::carried(&carry);
    assert_eq!(
        second.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(second.captures.load(Ordering::SeqCst), 0, "no capture");
    assert_eq!(authority.accepts(), 1);
    // Another import generation lifts it for one fresh look.
    let _other = Generation::set(32_014);
    let third = Harness::carried(&carry);
    assert_eq!(third.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(third.captures.load(Ordering::SeqCst), 1);
    // v32 review: a receipt-only Rejected of a request journaled before
    // this process (its outcome unknown: the authority may have committed
    // a successor and answered Rejected only for another device's retained
    // issuance) closes the gate for its epoch only. The next Connect looks
    // again, paced by EXPIRED_RECOVERY_SECS, and recovers the committed
    // successor once the authority replays it (v32 carried the gate: no
    // capture and no dial until an import).
    let _transient = Generation::set(32_016);
    let mode = Arc::new(AtomicU8::new(0));
    let answering = mode.clone();
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 25 * HOUR, DAY);
    let successor = Successor::signed_at(&tree, tree.not_before() + DAY - 600, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), move |_, _| {
        if answering.load(Ordering::SeqCst) == 1 {
            Answer::Issue
        } else {
            Answer::Rejected
        }
    });
    let binding = journal_request(&tree);
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    assert_eq!(authority.seen().len(), 1);
    assert!(
        first.renewal.snapshot().expired_under.is_some(),
        "this epoch"
    );
    assert_eq!(carry.get().unwrap().expired_under, None, "not carried");
    assert!(leaf_exists(&tree, renewal_journal::REQUEST), "never parked");
    let second = Harness::carried(&carry);
    assert_eq!(
        second.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(second.captures.load(Ordering::SeqCst), 1, "looks again");
    assert_eq!(authority.seen().len(), 1, "paced");
    // EXPIRED_RECOVERY_SECS later the authority replays the successor.
    authority.remember(binding);
    mode.store(1, Ordering::SeqCst);
    let mut kept = carry.get().unwrap();
    kept.next_attempt_at = 0;
    carry.set(kept);
    let third = Harness::carried(&carry);
    assert_eq!(third.run(&tree), Ok(()));
    let seen = authority.seen();
    assert_eq!(
        (seen.len(), seen[1].purpose),
        (2, ProofPurpose::Receipt),
        "receipt only"
    );
    admits_successor(&tree, &successor);
    // The expired window's backoff (EXPIRED_RECOVERY_SECS) is carried too,
    // beside a journaled request whose outcome is unknown (the authority
    // read the receipt request and dropped it): the next epoch makes no
    // dial before it (v31: a dial at every Connect).
    let _unknown = Generation::set(32_015);
    let (tree, _successor, authority, _binding) = expired_with_request(Answer::Drop);
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree).unwrap_err().code, SESSION_IDENTITY_EXPIRED);
    let sent = authority.seen().len();
    assert!(sent >= 1);
    assert!(leaf_exists(&tree, renewal_journal::REQUEST));
    let kept = carry.get().unwrap();
    assert_eq!((kept.issued, kept.expired_under), (None, None), "no gate");
    assert!(kept.next_attempt_at + 2 >= now() + EXPIRED_RECOVERY_SECS);
    let second = Harness::carried(&carry);
    assert_eq!(
        second.run(&tree).unwrap_err().code,
        SESSION_IDENTITY_EXPIRED
    );
    assert_eq!(authority.seen().len(), sent, "paced across Connects");
}

#[test]
fn renewal_codes_are_stable_listed_and_classified() {
    // T15.
    let step_codes = [
        crate::renewal_exchange::CLOCK_SKEW,
        crate::renewal_exchange::AUTHORITY_REFUSED,
        "session_clock_failed",
        RUNTIME_FAILED,
        EXPECTATION_REFUSED,
    ];
    for code in renewal_journal::CHECKS.iter().chain(&step_codes) {
        assert!(provider_xpc::RENEWAL_CHECKS.contains(code), "{code}");
        assert!(code.len() <= 64, "{code}");
        for state in ["state:refused", "state:superseded"] {
            let check = format!("check:{code}");
            assert!(
                crate::apple::stable_fields("identity_renewal", &[state, "attempt:3", &check]),
                "{code}"
            );
        }
    }
    assert_eq!(
        provider_xpc::RENEWAL_CHECKS.len(),
        renewal_journal::CHECKS.len() + step_codes.len()
    );
    for code in renewal_journal::CHECKS {
        let expected = matches!(
            code,
            renewal_journal::RECEIPT_MALFORMED
                | renewal_journal::RECEIPT_BINDING
                | renewal_journal::RECEIPT_IDENTITY
                | renewal_journal::SUCCESSOR_CERTIFICATE
                | renewal_journal::RECEIPT_METADATA
                | renewal_journal::SUCCESSOR_BEFORE_DUE
                | renewal_journal::SUCCESSOR_AFTER_EXPIRY
                | renewal_journal::SUCCESSOR_NOT_EXTENDING
        );
        assert_eq!(renewal_journal::definitive(code), expected, "{code}");
    }
    for state in ["parked", "superseded"] {
        assert!(provider_xpc::CERT_STATES.contains(&state));
    }
    for fields in [
        &["state:parked", "attempt:1", "check:rejected"][..],
        &["state:parked", "attempt:1", "check:recovery_required"],
        &["state:waiting:parked", "attempt:0", "next_s:60"],
        &["state:held:parked", "attempt:1"],
        &[
            "state:failed:local_refused",
            "attempt:1",
            "next_s:60",
            "dials:1",
        ],
    ] {
        assert!(
            crate::apple::stable_fields("identity_renewal", fields),
            "{fields:?}"
        );
    }
    // PARKED is no journal leaf of the capture and no import member.
    assert!(!crate::identity_custody::JOURNAL.contains(&renewal_journal::PARKED));
    assert!(crate::identity_import::IMPORT_MEMBERS
        .iter()
        .all(|member| member.leaf != renewal_journal::PARKED));
    // Tokens: superseded only for a definitive issued answer, parked after
    // a deferral but before the window's own.
    let mut state = RenewalState::default();
    state.observed_with(1_000, 4_000, true, false);
    state.issued = Some(renewal_journal::SUCCESSOR_NOT_EXTENDING);
    assert_eq!(state.token(3_500), "superseded");
    state.issued = Some(renewal_journal::NOT_YET_VALID);
    assert_eq!(state.token(3_500), "pending");
    state.observed_with(1_000, 4_000, false, true);
    assert_eq!(state.issued, None);
    assert_eq!(state.token(3_500), "parked");
    state.deferred = true;
    assert_eq!(state.token(3_500), "deferred:guarded");
    assert_eq!(state.token(4_000), "expired");
}

#[test]
fn import_of_a_new_identity_under_a_new_ca_clears_superseded_parked_and_blocking_renewals() {
    // T16 (macos-test-3 replacing macos-test-2): another device id and a
    // fresh device CA, imported beside each renewal journal state.
    use crate::identity_import::{
        import_tree,
        tests::{gate, payload_of, uid},
        IDENTITY_GENERATION,
    };
    let replacement = ReadyTree::issued_as(
        "127.0.0.1:443".parse().unwrap(),
        crate::test_fixture::Issuance {
            authority: "127.0.0.1:9".parse().unwrap(),
            device_id: "fixture-device-3",
            ..crate::test_fixture::Issuance::default()
        },
    );
    for state in ["superseded", "parked", "blocking"] {
        let listener = TestAuthority::bind();
        let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
        let (successor, answer) = match state {
            "superseded" => (Successor::for_tree(&tree, 6 * HOUR), Answer::Issue),
            "parked" => (Successor::for_tree(&tree, DAY), Answer::Rejected),
            _ => (Successor::for_tree(&tree, DAY), Answer::Drop),
        };
        let authority = TestAuthority::spawn(listener, &tree, successor, move |_, _| answer);
        let carry: Arc<Carry> = Arc::default();
        let harness = Harness::carried(&carry);
        let ran = harness.run(&tree);
        assert_eq!(ran.is_ok(), state == "parked", "{state}");
        assert_eq!(
            harness.token(),
            if state == "blocking" {
                "pending"
            } else {
                state
            }
        );
        let gate = gate();
        if state == "parked" {
            // A parked request runs an epoch: its lease refuses the import
            // until the Disconnect.
            let lease = gate.lease();
            assert_eq!(
                import_tree(tree.root(), uid(), gate, &payload_of(&replacement), |_| {}).err(),
                Some("session_live")
            );
            drop(lease);
        }
        let before = IDENTITY_GENERATION.load(Ordering::Acquire);
        let report =
            import_tree(tree.root(), uid(), gate, &payload_of(&replacement), |_| {}).unwrap();
        assert!(report.retired_removed, "{state}");
        assert!(IDENTITY_GENERATION.load(Ordering::Acquire) > before);
        for leaf in [
            renewal_journal::REQUEST,
            renewal_journal::RESPONSE,
            renewal_journal::PARKED,
        ] {
            assert!(!leaf_exists(&tree, leaf), "{state}: {leaf}");
        }
        // The next start: the new identity, no dial, no carried record.
        let accepts = authority.accepts();
        let next = Harness::carried(&carry);
        assert_eq!(next.run_at(tree.root()), Ok(()), "{state}");
        assert_eq!(authority.accepts(), accepts);
        let status = next.renewal.with(|state| state.report(now()));
        assert_eq!(status.state, "valid", "{state}");
        assert_eq!((status.check, status.last_failure), (None, None));
        let kept = next.renewal.snapshot();
        assert_eq!(
            (kept.issued, kept.parked, kept.expired_under),
            (None, false, None)
        );
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    }
}

#[test]
fn renewal_parked_attempt_beside_the_armed_guard_defers_and_still_captures() {
    // T17.
    let (tree, _successor, authority) = due_with(|_, _| Answer::Rejected);
    let harness = Harness::new();
    assert_eq!(harness.run(&tree), Ok(()));
    let parked = read_leaf(&tree, renewal_journal::PARKED);
    let accepts = authority.accepts();
    harness.renewal.with(|state| state.next_attempt_at = 0);
    let _armed = Armed::relay(Some("127.0.0.1:443".parse().unwrap()));
    take_logged();
    assert_eq!(harness.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), accepts, "no dial");
    let logged = take_logged();
    assert_eq!(
        lines_from(&logged, "state:deferred:guarded ").len(),
        1,
        "{logged:?}"
    );
    assert_eq!(read_leaf(&tree, renewal_journal::PARKED), parked);
    assert!(!leaf_exists(&tree, renewal_journal::REQUEST));
    assert_eq!(harness.token(), "deferred:guarded");
}

#[test]
fn renewal_forced_renew_deferred_by_the_guard_runs_at_the_next_connect() {
    // T18.
    let _generation = Generation::set(32_018);
    let mode = Arc::new(AtomicU8::new(0));
    let listener = TestAuthority::bind();
    let tree = aged(listener.local_addr().unwrap(), 17 * HOUR, DAY);
    let successor = Successor::for_tree(&tree, DAY);
    let authority = TestAuthority::spawn(listener, &tree, successor.clone(), switched(&mode));
    let carry: Arc<Carry> = Arc::default();
    let first = Harness::carried(&carry);
    assert_eq!(first.run(&tree), Ok(()));
    let binding = parked_binding(&tree);
    // Inside the backoff: the operator forces it; the guard defers it.
    assert!(first.renewal.snapshot().next_attempt_at > now());
    assert_eq!(
        request_renewal_of(Some(&first.renewal), now()),
        Ok("renew_scheduled")
    );
    let guarded = Monitor {
        guarded: true,
        ..LIVE
    };
    assert_eq!(
        monitor_step(&first.renewal, now(), &guarded),
        Action::DeferGuarded
    );
    assert_eq!(carry.get().unwrap().next_attempt_at, 0);
    // The next Connect runs it at once: one dial, the receipt first.
    authority.remember(binding.clone());
    mode.store(1, Ordering::SeqCst);
    let accepts = authority.accepts();
    let second = Harness::carried(&carry);
    assert_eq!(second.run(&tree), Ok(()));
    assert_eq!(authority.accepts(), accepts + 1);
    let seen = authority.seen();
    assert_eq!(
        (seen.last().unwrap().purpose, seen.len()),
        (ProofPurpose::Receipt, 2)
    );
    admits_successor(&tree, &successor);
}
