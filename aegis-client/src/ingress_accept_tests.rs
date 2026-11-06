//! Actual post-startup owner tests. Native error values are injected, never OS exhaustion.
use super::*;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;

const USER: &str = "accept-fixture-user";
const PASSWORD: &str = "synthetic-accept-fixture-password";

#[cfg(windows)]
const RESOURCE_ERRNO: i32 = 10_024;
#[cfg(not(windows))]
const RESOURCE_ERRNO: i32 = 24;

// A real-wall watchdog is independent of the explicitly stepped Tokio clock.
// It owns no task or socket; losing this select drops its future.
async fn bounded(work: impl std::future::Future<Output = ()>) {
    let started = std::time::Instant::now();
    tokio::select! {
        biased;
        () = work => (),
        () = async {
            loop {
                assert!(started.elapsed() < Duration::from_secs(20), "fixture real-wall cutoff");
                tokio::task::yield_now().await;
            }
        } => unreachable!(),
    }
}

struct PausedSetup(Option<JoinHandle<()>>);
impl PausedSetup {
    fn new() -> Self {
        let started = std::time::Instant::now();
        Self(Some(tokio::spawn(async move {
            loop {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "owned setup cutoff"
                );
                tokio::task::yield_now().await;
            }
        })))
    }
    async fn finish(mut self) {
        let task = self.0.take().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
impl Drop for PausedSetup {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

struct FaultBackend {
    real: Arc<Socks5FallbackBackend>,
    faults: tokio::sync::Mutex<mpsc::Receiver<std::io::Error>>,
    observed_faults: Arc<Mutex<Vec<Instant>>>,
    fatal: Notify,
    shutdowns: AtomicUsize,
}
#[async_trait]
impl IngressBackend for Arc<FaultBackend> {
    fn id(&self) -> &'static str {
        self.real.id()
    }
    fn runtime_id(&self) -> &'static str {
        self.real.runtime_id()
    }
    fn kind(&self) -> ingress::IngressKind {
        self.real.kind()
    }
    fn is_available(&self) -> bool {
        self.real.is_available()
    }
    fn listen_addr(&self) -> Option<SocketAddr> {
        self.real.listen_addr()
    }
    fn runtime_status(&self) -> ingress::IngressBackendRuntimeStatus {
        self.real.runtime_status()
    }
    async fn failure(&self) -> &'static str {
        self.fatal.notified().await;
        "fixture_required_listener"
    }
    async fn accept(&self) -> std::io::Result<ingress::IngressSessionIntent> {
        let mut faults = self.faults.lock().await;
        tokio::select! {
            biased;
            error = faults.recv() => {
                let error = error.expect("fixture holds bounded sender until owner exits");
                let mut observed = self.observed_faults.lock().unwrap();
                assert!(observed.len() < 8, "finite fault script");
                observed.push(Instant::now());
                Err(error)
            }
            result = self.real.accept() => result,
        }
    }
    async fn shutdown(&self) {
        self.real.shutdown().await;
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

type TraceEvents = Vec<(String, BTreeMap<String, String>)>;
#[derive(Clone, Default)]
struct CapturedTrace(Arc<Mutex<TraceEvents>>);
impl tracing::Subscriber for CapturedTrace {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        let mut events = self.0.lock().unwrap();
        assert!(events.len() < 8, "finite admitted diagnostic fixture");
        events.push((event.metadata().level().to_string(), fields.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

struct Fixture {
    backend: Arc<FaultBackend>,
    faults: mpsc::Sender<std::io::Error>,
    stop: watch::Sender<bool>,
    owner: Option<JoinHandle<anyhow::Result<()>>>,
    sessions: Arc<Mutex<Vec<JoinHandle<()>>>>,
    diagnostics: Arc<Mutex<Vec<(Instant, serde_json::Value)>>>,
    traces: CapturedTrace,
    setup: Option<PausedSetup>,
}
impl Fixture {
    async fn start() -> Self {
        let setup = PausedSetup::new();
        let mut cfg = Settings {
            mode: Mode::Direct,
            ..Settings::default()
        };
        cfg.direct.strategies = vec!["passthrough".into()];
        cfg.direct.epsilon = 0.0;
        cfg.direct.persist_state = false;
        cfg.socks.listen = "127.0.0.1:0".parse().unwrap();
        cfg.socks.auth_user = Some(USER.into());
        cfg.socks.auth_token = Some(PASSWORD.into());
        let real = Arc::new(
            Socks5FallbackBackend::bind_from_settings(&cfg.socks)
                .await
                .unwrap(),
        );
        let runtime = RuntimeContext::from_settings(&cfg).await.unwrap();
        let (faults, fault_rx) = mpsc::channel(8);
        let backend = Arc::new(FaultBackend {
            real,
            faults: tokio::sync::Mutex::new(fault_rx),
            observed_faults: Arc::new(Mutex::new(Vec::new())),
            fatal: Notify::new(),
            shutdowns: AtomicUsize::new(0),
        });
        let context = IngressLateRuntimeContext {
            backend_id: backend.id().into(),
            backend_runtime_id: backend.runtime_id().into(),
            backend_kind: format!("{:?}", backend.kind()),
            backend_kind_code: backend.kind().as_code(),
            requested_primary: "Socks5".into(),
            requested_primary_code: "socks5",
            mode: "Direct".into(),
            mode_code: "direct",
            wide_supported: None,
            wide_platform_family_supported: None,
            wide_runtime_readiness: None,
            rollout_profile: None,
            rollout_profile_code: None,
            prerouting_interface: None,
            path_code: "fixture_socks5",
            fallback_reason_code: None,
            fallback_reason: None,
            bind_error_code: None,
        };
        let (stop, stopped) = watch::channel(false);
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let traces = CapturedTrace::default();
        let owner_backend = backend.clone();
        let owner_diagnostics = diagnostics.clone();
        let owner_sessions = sessions.clone();
        let owner_traces = traces.clone();
        let owner = tokio::spawn(async move {
            let mut selected_sessions = None;
            let mut renewal = device_renewal::Supervisor::start(None, &cfg).await.unwrap();
            #[cfg(target_os = "linux")]
            let mut workers = wide_workers::WideWorkers::new();
            run_ingress_owner(
                ClientIngressOwner {
                    backend: Box::new(owner_backend),
                    cfg,
                    runtime,
                    broker: DefaultSessionBroker {
                        defer_relay_resolution: false,
                    },
                    late_runtime_context: context,
                    external_shutdown: Some(stopped),
                    stdin_shutdown: None,
                    selected_sessions: &mut selected_sessions,
                    device_renewal: &mut renewal,
                    #[cfg(target_os = "linux")]
                    wide_workers: &mut workers,
                    #[cfg(target_os = "linux")]
                    wide_forward_gate: crate::ingress::wide::forward_gate::ForwardGate::closed(),
                    #[cfg(target_os = "linux")]
                    selected_signals: None,
                },
                move |error, context| {
                    // Actual production formatter and field builder, under a local
                    // subscriber. This intentionally does not touch GLOBAL_STREAM.
                    tracing::subscriber::with_default(owner_traces.clone(), || {
                        trace_ingress_accept_failure(error, context);
                    });
                    let fields = ingress_accept_failure_fields(error, context);
                    let mut diagnostics = owner_diagnostics.lock().unwrap();
                    assert!(diagnostics.len() < 8, "finite diagnostic fixture");
                    diagnostics.push((Instant::now(), fields));
                },
                move |task| {
                    let mut sessions = owner_sessions.lock().unwrap();
                    assert!(sessions.len() < 2, "fixture owns only two actual sessions");
                    sessions.push(task);
                },
            )
            .await
        });
        Self {
            backend,
            faults,
            stop,
            owner: Some(owner),
            sessions,
            diagnostics,
            traces,
            setup: Some(setup),
        }
    }
    async fn finish_setup(&mut self) {
        self.setup.take().unwrap().finish().await;
    }
    fn arm(&self, errors: impl IntoIterator<Item = std::io::Error>) {
        for error in errors {
            self.faults.try_send(error).unwrap();
        }
    }
    fn count(&self) -> usize {
        self.backend.observed_faults.lock().unwrap().len()
    }
    fn times(&self, origin: Instant) -> Vec<u64> {
        self.backend
            .observed_faults
            .lock()
            .unwrap()
            .iter()
            .map(|time| time.duration_since(origin).as_millis() as u64)
            .collect()
    }
    async fn authenticated_connect(&self, target: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(self.backend.real.listen_addr().unwrap())
            .await
            .unwrap();
        stream.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        let mut credentials = vec![1, USER.len() as u8];
        credentials.extend_from_slice(USER.as_bytes());
        credentials.push(PASSWORD.len() as u8);
        credentials.extend_from_slice(PASSWORD.as_bytes());
        stream.write_all(&credentials).await.unwrap();
        let mut status = [0; 2];
        stream.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [1, 0]);
        let std::net::IpAddr::V4(ip) = target.ip() else {
            panic!("owned IPv4 target")
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        stream
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        let _ = self.stop.send(true);
        let result = self.owner.take().unwrap().await.unwrap();
        let tasks: Vec<_> = self.sessions.lock().unwrap().drain(..).collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(self.backend.shutdowns.load(Ordering::SeqCst), 1);
        result
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            owner.abort();
        }
        for task in self.sessions.lock().unwrap().iter() {
            task.abort();
        }
        // Failure emergency cancellation is not an awaited-cleanup receipt.
    }
}

async fn pump() {
    for _ in 0..256 {
        tokio::task::yield_now().await;
    }
}
fn resource() -> std::io::Error {
    std::io::Error::from_raw_os_error(RESOURCE_ERRNO)
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn native_resource_retries_follow_one_absolute_cutoff_and_cap_actual() {
    bounded(async {
        let mut fixture = Fixture::start().await;
        fixture.finish_setup().await;
        let origin = Instant::now();
        fixture.arm((0..7).map(|_| resource()));
        pump().await;
        assert_eq!(
            fixture.count(),
            1,
            "first native failure must not immediately drain finite burst"
        );
        let mut expected = vec![0];
        for delay in [50, 100, 200, 400, 800, 1000] {
            tokio::time::advance(Duration::from_millis(delay - 1)).await;
            pump().await;
            assert_eq!(
                fixture.times(origin),
                expected,
                "accept before original retry cutoff"
            );
            tokio::time::advance(Duration::from_millis(1)).await;
            pump().await;
            expected.push(expected.last().unwrap() + delay);
            assert_eq!(fixture.times(origin), expected);
        }
        assert_eq!(expected, [0, 50, 150, 350, 750, 1550, 2550]);
        fixture.finish().await.unwrap();
    })
    .await;
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn false_watch_wakeup_does_not_rearm_retry_actual() {
    bounded(async {
        let mut fixture = Fixture::start().await;
        fixture.finish_setup().await;
        let origin = Instant::now();
        fixture.arm([resource(), resource()]);
        pump().await;
        assert_eq!(fixture.count(), 1);
        tokio::time::advance(Duration::from_millis(10)).await;
        fixture.stop.send(false).unwrap();
        pump().await;
        tokio::time::advance(Duration::from_millis(39)).await;
        pump().await;
        assert_eq!(fixture.times(origin), [0]);
        tokio::time::advance(Duration::from_millis(1)).await;
        pump().await;
        assert_eq!(fixture.times(origin), [0, 50]);
        fixture.finish().await.unwrap();
    })
    .await;
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn resource_diagnostics_admit_before_actual_formatting_and_json_actual() {
    bounded(async {
        let mut fixture = Fixture::start().await;
        fixture.finish_setup().await;
        fixture.arm([resource(), resource(), resource()]);
        pump().await;
        assert_eq!(
            fixture.diagnostics.lock().unwrap().len(),
            1,
            "admit before actual emitter"
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        pump().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        pump().await;
        assert_eq!(fixture.count(), 3);
        assert_eq!(fixture.diagnostics.lock().unwrap().len(), 1);
        {
            let traces = fixture.traces.0.lock().unwrap();
            assert_eq!(traces.len(), 1);
            assert_eq!(traces[0].0, "WARN");
            assert_eq!(
                traces[0].1["event_code"],
                RuntimeEventCode::IngressAcceptFailed.as_str()
            );
            let fields = &fixture.diagnostics.lock().unwrap()[0].1;
            assert_eq!(fields["backend_kind_code"], "socks5_fallback");
            assert_eq!(fields["startup_path_code"], "fixture_socks5");
            assert!(fields["error"].as_str().unwrap().contains("os error"));
        }
        tokio::time::advance(Duration::from_millis(850)).await;
        fixture.arm([resource()]);
        pump().await;
        assert_eq!(fixture.diagnostics.lock().unwrap().len(), 2);
        fixture.finish().await.unwrap();
    })
    .await;
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn successful_intent_resets_backoff_but_not_diagnostic_interval_actual() {
    bounded(async {
        let mut fixture = Fixture::start().await;
        let unused_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = unused_target.local_addr().unwrap();
        fixture.finish_setup().await;
        fixture.arm([resource()]);
        pump().await;
        tokio::time::advance(Duration::from_millis(50)).await;
        let mut client = fixture.authenticated_connect(target).await;
        client.shutdown().await.unwrap();
        drop(client);
        let origin = Instant::now();
        fixture.arm([resource(), resource()]);
        pump().await;
        assert_eq!(fixture.count(), 2);
        assert_eq!(fixture.diagnostics.lock().unwrap().len(), 1);
        tokio::time::advance(Duration::from_millis(49)).await;
        pump().await;
        assert_eq!(fixture.count(), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        pump().await;
        let times = fixture.backend.observed_faults.lock().unwrap().clone();
        assert_eq!(times[2].duration_since(origin), Duration::from_millis(50));
        assert_eq!(fixture.diagnostics.lock().unwrap().len(), 1);
        fixture.finish().await.unwrap();
    })
    .await;
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn staged_and_unknown_errors_keep_existing_immediate_policy_actual() {
    bounded(async {
        let mut fixture = Fixture::start().await;
        fixture.finish_setup().await;
        let origin = Instant::now();
        fixture.arm([
            std::io::Error::from_raw_os_error(123_456),
            std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "synthetic nonnative memory",
            ),
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "socks5_negotiation_limit: fixture",
            ),
        ]);
        pump().await;
        assert_eq!(fixture.times(origin), [0, 0, 0]);
        assert_eq!(fixture.diagnostics.lock().unwrap().len(), 3);
        fixture.finish().await.unwrap();
    })
    .await;
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn stop_and_required_listener_failure_remain_selectable_and_drain_pending_socks_actual() {
    bounded(async {
        for fatal in [false, true] {
            let mut fixture = Fixture::start().await;
            let mut stalled = TcpStream::connect(fixture.backend.real.listen_addr().unwrap()).await.unwrap();
            stalled.write_all(&[5, 1, 2]).await.unwrap();
            let mut method = [0; 2];
            stalled.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 2]);
            fixture.finish_setup().await;
            let origin = Instant::now();
            fixture.arm([resource()]);
            pump().await;
            assert_eq!(fixture.count(), 1);
            if fatal { fixture.backend.fatal.notify_one(); } else { fixture.stop.send(true).unwrap(); }
            let result = fixture.finish().await;
            assert_eq!(Instant::now(), origin, "stop must not wait for retry timer");
            if fatal {
                assert_eq!(result.unwrap_err().to_string(), "required ingress listener fixture_required_listener stopped; client must restart");
            } else { result.unwrap(); }
            let mut byte = [0];
            assert_eq!(stalled.read(&mut byte).await.unwrap(), 0);
        }
    }).await;
}

struct OwnedTarget(Option<JoinHandle<()>>);
impl Drop for OwnedTarget {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
fn request(marker: &str) -> Vec<u8> {
    format!("GET /{marker} HTTP/1.1\r\nHost: fixture.local\r\n\r\n").into_bytes()
}
fn response(marker: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{marker}",
        marker.len()
    )
    .into_bytes()
}
async fn exchange(client: &mut TcpStream, marker: &str) {
    client.write_all(&request(marker)).await.unwrap();
    let expected = response(marker);
    let mut observed = vec![0; expected.len()];
    client.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, expected);
}

#[tokio::test(start_paused = true)]
#[ignore = "actual isolated owner case; parent owns its process"]
async fn authenticated_direct_session_progress_survives_resource_retry_and_recovers_actual() {
    bounded(async {
        let mut fixture = Fixture::start().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let mut target_task = OwnedTarget(Some(tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            for markers in [vec!["before", "during"], vec!["after"]] {
                let (mut peer, _) = listener.accept().await.unwrap();
                peers.spawn(async move {
                    for marker in markers {
                        let expected = request(marker);
                        let mut observed = vec![0; expected.len()];
                        peer.read_exact(&mut observed).await.unwrap();
                        assert_eq!(observed, expected);
                        peer.write_all(&response(marker)).await.unwrap();
                    }
                    let mut remaining = Vec::new();
                    peer.read_to_end(&mut remaining).await.unwrap();
                    assert!(remaining.is_empty());
                    peer.shutdown().await.unwrap();
                });
            }
            while let Some(result) = peers.join_next().await {
                result.unwrap();
            }
        })));
        let mut first = fixture.authenticated_connect(target).await;
        exchange(&mut first, "before").await;
        fixture.finish_setup().await;
        let origin = Instant::now();
        fixture.arm([resource(), resource()]);
        pump().await;
        assert_eq!(
            fixture.count(),
            1,
            "actual established session precedes finite fault"
        );
        exchange(&mut first, "during").await;
        assert_eq!(
            Instant::now(),
            origin,
            "retained progress before retry cutoff"
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        pump().await;
        assert_eq!(fixture.count(), 2);
        tokio::time::advance(Duration::from_millis(100)).await;
        let mut second = fixture.authenticated_connect(target).await;
        exchange(&mut second, "after").await;
        first.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        let mut end = Vec::new();
        first.read_to_end(&mut end).await.unwrap();
        assert!(end.is_empty());
        second.read_to_end(&mut end).await.unwrap();
        assert!(end.is_empty());
        target_task.0.take().unwrap().await.unwrap();
        fixture.finish().await.unwrap();
    })
    .await;
}

// Real Direct runtime also emits existing global events. Isolate those globals
// from older suites; this is test custody, not a new product process owner.
fn isolated(name: &str) {
    struct Child(Option<std::process::Child>);
    impl Drop for Child {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut child = Child(Some(
        std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("ingress_accept_tests::{name}_actual"))
            .arg("--ignored")
            .arg("--test-threads=1")
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap(),
    ));
    let cutoff = std::time::Instant::now() + Duration::from_secs(25);
    loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            // wait observes this exact owned child; inherited diagnostics are
            // retained by the unique outer Cargo receipt, without pipe waits.
            child.0.take().unwrap().wait().unwrap();
            assert!(status.success(), "actual isolated case {name}: {status}");
            return;
        }
        assert!(
            std::time::Instant::now() < cutoff,
            "owned child cutoff: {name}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn native_resource_retries_follow_one_absolute_cutoff_and_cap() {
    isolated("native_resource_retries_follow_one_absolute_cutoff_and_cap");
}

#[test]
fn false_watch_wakeup_does_not_rearm_retry() {
    isolated("false_watch_wakeup_does_not_rearm_retry");
}

#[test]
fn resource_diagnostics_admit_before_actual_formatting_and_json() {
    isolated("resource_diagnostics_admit_before_actual_formatting_and_json");
}

#[test]
fn successful_intent_resets_backoff_but_not_diagnostic_interval() {
    isolated("successful_intent_resets_backoff_but_not_diagnostic_interval");
}

#[test]
fn staged_and_unknown_errors_keep_existing_immediate_policy() {
    isolated("staged_and_unknown_errors_keep_existing_immediate_policy");
}

#[test]
fn stop_and_required_listener_failure_remain_selectable_and_drain_pending_socks() {
    isolated("stop_and_required_listener_failure_remain_selectable_and_drain_pending_socks");
}

#[test]
fn authenticated_direct_session_progress_survives_resource_retry_and_recovers() {
    isolated("authenticated_direct_session_progress_survives_resource_retry_and_recovers");
}
