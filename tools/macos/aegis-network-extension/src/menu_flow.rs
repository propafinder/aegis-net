//! v39 (B-06 menu-bar app, source only; not yet run installed): what the
//! menu-bar app runs, as sequences of the host's own CLI verbs.
//!
//! Every step is one run of this same signed `aegis-ne-host` executable with
//! one existing verb (`HostVerb::args`, which the tests bind to
//! `host_lifecycle::parse_host_args`), bounded from outside as well
//! (`HostVerb::bound`, past the verb's own watchdog). The menu app therefore
//! inherits every check of the CLI unchanged: the identity gate and the
//! administrator prompt of `--import`, the reviewed filter of
//! `--enable-filter`, the provider's terms for `--save-profile` and
//! `--connect`, the exact-intent match of `--disconnect`. It never runs
//! `--disable-filter`, `--remove-filter`, `--forget-identity`, `--renew`,
//! `--remove-profile`, `--deactivate` or `--window-policy`, and it connects
//! only while the leak guard is configured, enabled and attached.

use crate::{
    configuration::PROVIDER_ID,
    menu_l10n::tr,
    menu_model::{
        self, explain, field, parse_extension_list, parse_filter_status, parse_list, result_line,
        stderr_code, ExtensionState, GuardState, JoinStep, NativeStatus, Observation, Probe,
        APPROVAL_STDERR_PREFIX,
    },
    provider_xpc::{decode_reply, Reply, Verb},
};
use std::{
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// The read-only system tool the menu reads the extension's state from.
pub const SYSTEMEXTENSIONSCTL: &str = "/usr/bin/systemextensionsctl";

/// One host verb the menu app may run. There is deliberately no variant for
/// a verb that weakens the leak guard or removes an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostVerb {
    List,
    /// Bare `--status`: the provider's session phase.
    ProviderStatus,
    Ping,
    CertStatus,
    ProfileTerms,
    FilterStatus,
    EnableFilter,
    RequestActivation,
    Import {
        dir: PathBuf,
        remove_source: bool,
    },
    /// v45 `--enroll FILE --remove-source [--replace-identity]`: the menu
    /// passes its own private copy of the chosen file, which the host
    /// removes after a commit.
    Enroll {
        path: PathBuf,
        replace_identity: bool,
    },
    SaveProfile {
        relay: IpAddr,
        replace_existing: bool,
    },
    Connect {
        owner_generation: String,
        relay: IpAddr,
    },
    Disconnect {
        owner_generation: String,
        relay: IpAddr,
    },
    EmergencyStop,
}

/// The XPC verbs' own bound is 10 s; profile and filter-status verbs 30 s;
/// activation, filter enable and the administrator prompt 120 s.
const XPC_BOUND: Duration = Duration::from_secs(20);
const PROFILE_BOUND: Duration = Duration::from_secs(45);
const LONG_BOUND: Duration = Duration::from_secs(140);
/// The prompt (120 s) then the one bounded import exchange (10 s).
const IMPORT_BOUND: Duration = Duration::from_secs(170);
/// v45: the precheck (3 x 10 s), the redeem (60 s), the prompt (120 s) and
/// the import (10 s).
const ENROLL_BOUND: Duration = Duration::from_secs(260);

impl HostVerb {
    /// The CLI arguments, exactly as an operator would type them.
    pub fn args(&self) -> Vec<String> {
        let owned = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        match self {
            HostVerb::List => owned(&["--list"]),
            HostVerb::ProviderStatus => owned(&["--status"]),
            HostVerb::Ping => owned(&["--ping"]),
            HostVerb::CertStatus => owned(&["--cert-status"]),
            HostVerb::ProfileTerms => owned(&["--profile-terms"]),
            HostVerb::FilterStatus => owned(&["--filter-status"]),
            HostVerb::EnableFilter => owned(&["--enable-filter"]),
            HostVerb::RequestActivation => owned(&["--request-activation", PROVIDER_ID]),
            HostVerb::Import { dir, remove_source } => {
                let mut args = vec!["--import".to_owned(), dir.to_string_lossy().into_owned()];
                if *remove_source {
                    args.push("--remove-source".into());
                }
                args
            }
            HostVerb::Enroll {
                path,
                replace_identity,
            } => {
                let mut args = vec![
                    "--enroll".to_owned(),
                    path.to_string_lossy().into_owned(),
                    "--remove-source".to_owned(),
                ];
                if *replace_identity {
                    args.push("--replace-identity".into());
                }
                args
            }
            HostVerb::SaveProfile {
                relay,
                replace_existing,
            } => {
                let mut args = vec![
                    "--save-profile".to_owned(),
                    PROVIDER_ID.to_owned(),
                    relay.to_string(),
                ];
                if *replace_existing {
                    args.push("--replace-existing".into());
                }
                args
            }
            HostVerb::Connect {
                owner_generation,
                relay,
            } => vec![
                "--connect".into(),
                PROVIDER_ID.into(),
                owner_generation.clone(),
                relay.to_string(),
            ],
            HostVerb::Disconnect {
                owner_generation,
                relay,
            } => vec![
                "--disconnect".into(),
                PROVIDER_ID.into(),
                owner_generation.clone(),
                relay.to_string(),
            ],
            HostVerb::EmergencyStop => owned(&["--emergency-stop"]),
        }
    }

    /// The outer bound: the verb's own bound plus a margin, after which the
    /// child is killed and the result is unknown.
    pub fn bound(&self) -> Duration {
        match self {
            HostVerb::ProviderStatus
            | HostVerb::Ping
            | HostVerb::CertStatus
            | HostVerb::ProfileTerms => XPC_BOUND,
            HostVerb::List
            | HostVerb::FilterStatus
            | HostVerb::SaveProfile { .. }
            | HostVerb::Connect { .. }
            | HostVerb::Disconnect { .. }
            | HostVerb::EmergencyStop => PROFILE_BOUND,
            HostVerb::EnableFilter | HostVerb::RequestActivation => LONG_BOUND,
            HostVerb::Import { .. } => IMPORT_BOUND,
            HostVerb::Enroll { .. } => ENROLL_BOUND,
        }
    }

    /// A short name for the event log (never an operand).
    pub fn name(&self) -> &'static str {
        match self {
            HostVerb::List => "list",
            HostVerb::ProviderStatus => "status",
            HostVerb::Ping => "ping",
            HostVerb::CertStatus => "cert-status",
            HostVerb::ProfileTerms => "profile-terms",
            HostVerb::FilterStatus => "filter-status",
            HostVerb::EnableFilter => "enable-filter",
            HostVerb::RequestActivation => "request-activation",
            HostVerb::Import {
                remove_source: true,
                ..
            } => "import --remove-source",
            HostVerb::Import { .. } => "import",
            HostVerb::Enroll {
                replace_identity: true,
                ..
            } => "enroll --replace-identity",
            HostVerb::Enroll { .. } => "enroll",
            HostVerb::SaveProfile {
                replace_existing: true,
                ..
            } => "save-profile --replace-existing",
            HostVerb::SaveProfile { .. } => "save-profile",
            HostVerb::Connect { .. } => "connect",
            HostVerb::Disconnect { .. } => "disconnect",
            HostVerb::EmergencyStop => "emergency-stop",
        }
    }
}

/// What one child run returned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Run {
    /// `None` when the child was killed (outer bound) or could not start.
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl Run {
    pub fn ok(&self) -> bool {
        self.exit == Some(0)
    }

    pub fn code(&self) -> Option<String> {
        stderr_code(&self.stderr)
    }

    /// One event-log line: the verb, its exit and its code.
    pub fn summary(&self, verb: &str) -> String {
        format!(
            "{verb} exit={} code={}{}",
            self.exit
                .map_or_else(|| "none".to_owned(), |exit| exit.to_string()),
            self.code().as_deref().unwrap_or("none"),
            if self.timed_out {
                " outer_bound_expired"
            } else {
                ""
            }
        )
    }

    fn failed<T>(&self) -> Probe<T> {
        Probe::Failed {
            exit: self.exit,
            code: self.code(),
        }
    }

    /// The provider's decoded reply on the first stdout line.
    fn reply(&self, verb: Verb) -> Option<Reply> {
        if !self.ok() {
            return None;
        }
        let line = self.stdout.lines().next()?;
        decode_reply(line.as_bytes(), verb).ok()
    }
}

/// Runs host verbs (this executable) and the read-only system tool.
pub trait Runner {
    fn host(&mut self, verb: &HostVerb, on_stderr: &mut dyn FnMut(&str)) -> Run;
    fn extension_list(&mut self) -> Run;
}

/// The real runner: the app's own host executable as a child process.
pub struct ProcessRunner {
    exe: PathBuf,
}

impl ProcessRunner {
    pub fn new(exe: PathBuf) -> Self {
        Self { exe }
    }
}

impl Runner for ProcessRunner {
    fn host(&mut self, verb: &HostVerb, on_stderr: &mut dyn FnMut(&str)) -> Run {
        run_bounded(&self.exe, &verb.args(), verb.bound(), on_stderr)
    }

    fn extension_list(&mut self) -> Run {
        run_bounded(
            Path::new(SYSTEMEXTENSIONSCTL),
            &["list".to_owned()],
            Duration::from_secs(15),
            &mut |_| {},
        )
    }
}

/// Each stream keeps at most this much; the rest is read and dropped so the
/// child never blocks on a full pipe.
const MAX_OUTPUT: usize = 256 * 1024;

fn read_capped(mut stream: impl Read) -> String {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = MAX_OUTPUT.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..n.min(room)]);
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// Run `program args` with no stdin, give each stderr line to `on_stderr`
/// as it arrives, and kill the child (SIGKILL) after `bound`.
pub fn run_bounded(
    program: &Path,
    args: &[String],
    bound: Duration,
    on_stderr: &mut dyn FnMut(&str),
) -> Run {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            return Run {
                exit: None,
                stderr: format!("spawn_failed errno_{}", error.raw_os_error().unwrap_or(0)),
                ..Run::default()
            }
        }
    };
    let stdout = child
        .stdout
        .take()
        .map(|out| std::thread::spawn(move || read_capped(out)));
    let (lines, received) = mpsc::channel::<String>();
    let stderr = child.stderr.take().map(|err| {
        std::thread::spawn(move || {
            let mut kept = 0usize;
            let mut reader = std::io::BufReader::new(err);
            let mut line = String::new();
            loop {
                line.clear();
                match std::io::BufRead::read_line(&mut reader, &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        kept += n;
                        if kept <= MAX_OUTPUT {
                            let _ = lines.send(line.trim_end_matches('\n').to_owned());
                        }
                    }
                }
            }
        })
    });
    let deadline = Instant::now() + bound;
    let mut err_text = String::new();
    let mut take_line = |line: String, err_text: &mut String| {
        on_stderr(&line);
        err_text.push_str(&line);
        err_text.push('\n');
    };
    let (exit, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.code(), false),
            Ok(None) => {}
            Err(_) => break (None, false),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break (None, true);
        }
        match received.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => take_line(line, &mut err_text),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(Duration::from_millis(20))
            }
        }
    };
    if let Some(handle) = stderr {
        let _ = handle.join();
    }
    while let Ok(line) = received.try_recv() {
        take_line(line, &mut err_text);
    }
    let out_text = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    Run {
        exit,
        stdout: out_text,
        stderr: err_text,
        timed_out,
    }
}

/// The result of one menu action.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    /// What the menu tells the user.
    pub message: String,
    /// Event-log lines (verb, exit, code; no operand).
    pub events: Vec<String>,
    /// An activation reported that it waits for the System Settings switch.
    pub approval_needed: bool,
}

impl Outcome {
    fn done(message: impl Into<String>, events: Vec<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            events,
            approval_needed: false,
        }
    }

    fn failed(message: impl Into<String>, events: Vec<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            events,
            approval_needed: false,
        }
    }
}

fn step(runner: &mut dyn Runner, verb: &HostVerb, events: &mut Vec<String>) -> Run {
    let run = runner.host(verb, &mut |_| {});
    events.push(run.summary(verb.name()));
    run
}

/// Read everything the menu shows. `full` also reads the slower or rarer
/// facts (the extension list, the certificate, the leak guard, identity
/// presence); a light refresh reads the profile and the provider's phase.
/// Only read-only verbs run here.
pub fn refresh(
    runner: &mut dyn Runner,
    obs: &mut Observation,
    full: bool,
    now: u64,
) -> Vec<String> {
    let mut events = Vec::new();
    let enabled_before = matches!(obs.extension, ExtensionState::Enabled { .. });
    if full || !enabled_before {
        let run = runner.extension_list();
        obs.extension = if run.ok() {
            parse_extension_list(&run.stdout)
        } else {
            events.push(run.summary("systemextensionsctl list"));
            ExtensionState::Unknown
        };
    }
    let enabled = matches!(obs.extension, ExtensionState::Enabled { .. });
    if enabled {
        obs.approval_requested = false;
    }
    let run = runner.host(&HostVerb::List, &mut |_| {});
    obs.profiles = if run.ok() {
        match parse_list(&run.stdout) {
            Ok(profiles) => Probe::Ok(profiles),
            Err(code) => Probe::Failed {
                exit: run.exit,
                code: Some(code.into()),
            },
        }
    } else {
        events.push(run.summary("list"));
        run.failed()
    };
    obs.note_status(now);
    // An unreadable extension list does not stop the provider queries: they
    // fail on their own (exit 69) when nothing answers.
    if !enabled && obs.extension != ExtensionState::Unknown {
        obs.provider = Probe::Unknown;
        obs.identity_present = None;
        obs.cert = None;
        obs.filter = Probe::Unknown;
        obs.refreshed = true;
        return events;
    }
    let run = runner.host(&HostVerb::ProviderStatus, &mut |_| {});
    obs.provider = match run.reply(Verb::Status) {
        Some(Reply::Status(status)) => Probe::Ok(status),
        _ => {
            events.push(run.summary("status"));
            run.failed()
        }
    };
    let reachable = !obs.provider.provider_unreachable();
    if reachable && (full || obs.identity_present != Some(true)) {
        let run = runner.host(&HostVerb::Ping, &mut |_| {});
        obs.identity_present = match run.reply(Verb::Ping) {
            Some(Reply::Ping(ping)) => Some(ping.identity_present),
            _ => {
                events.push(run.summary("ping"));
                None
            }
        };
    }
    let up = obs.native_status().is_some_and(NativeStatus::tunnel_up);
    if reachable && (full || up || obs.cert.is_none()) {
        let run = runner.host(&HostVerb::CertStatus, &mut |_| {});
        obs.cert = match run.reply(Verb::CertStatus) {
            Some(Reply::CertStatus(report)) => Some(report),
            // `no_epoch`: no record yet (no session since the provider
            // started); anything else is shown in the event log.
            _ => {
                if run.code().as_deref() != Some("no_epoch") {
                    events.push(run.summary("cert-status"));
                }
                None
            }
        };
    }
    if full || matches!(obs.filter, Probe::Unknown) {
        let run = runner.host(&HostVerb::FilterStatus, &mut |_| {});
        obs.filter = match parse_filter_status(&run.stdout) {
            Some(view) => Probe::Ok(view),
            None => {
                events.push(run.summary("filter-status"));
                run.failed()
            }
        };
    }
    obs.refreshed = true;
    events
}

/// The leak guard must be configured, enabled and attached before a
/// connect; a missing or disabled configuration is turned on first
/// (`--enable-filter`, macOS's Allow alert on the first save).
fn ensure_guard(runner: &mut dyn Runner, events: &mut Vec<String>) -> Result<(), String> {
    let read = |runner: &mut dyn Runner, events: &mut Vec<String>| {
        let run = step(runner, &HostVerb::FilterStatus, events);
        parse_filter_status(&run.stdout).map_or(GuardState::Failed, |view| view.guard())
    };
    let mut guard = read(runner, events);
    if guard == GuardState::Off {
        let run = step(runner, &HostVerb::EnableFilter, events);
        let outcome = result_line(&run.stdout, "filter_result=")
            .and_then(|line| field(line, "filter_result"));
        if outcome != Some("ok") {
            return Err(explain::enable_filter(outcome));
        }
        guard = read(runner, events);
    }
    match guard {
        GuardState::On { .. } => Ok(()),
        _ => Err(tr(
            "The leak guard is not running, so AEGIS does not connect. Choose Turn On Leak Guard, or restart the Mac and try again.",
            "Защита от утечек не работает, поэтому AEGIS не подключается. Выберите «Включить защиту от утечек…» или перезагрузите Mac и повторите.",
        )
        .into()),
    }
}

/// The relay host of the provider's held, signed terms.
fn held_relay(runner: &mut dyn Runner, events: &mut Vec<String>) -> Result<IpAddr, String> {
    let run = step(runner, &HostVerb::ProfileTerms, events);
    match run.reply(Verb::ProfileTerms) {
        Some(Reply::ProfileTerms(terms)) => Ok(terms.relay.ip()),
        _ => Err(explain::with_code(
            &explain::provider(run.exit),
            run.code().as_deref(),
        )),
    }
}

/// Save (or, `replace`, rewrite the one idle) AEGIS profile for `relay`;
/// the owner generation the host minted.
fn save(
    runner: &mut dyn Runner,
    relay: IpAddr,
    replace: bool,
    events: &mut Vec<String>,
) -> Result<String, String> {
    let run = step(
        runner,
        &HostVerb::SaveProfile {
            relay,
            replace_existing: replace,
        },
        events,
    );
    let line = result_line(&run.stdout, "owner_generation=");
    match (
        run.ok(),
        line.and_then(|l| field(l, "saved")),
        line.and_then(|l| field(l, "owner_generation")),
    ) {
        (true, Some("true"), Some(generation)) => Ok(generation.to_owned()),
        _ => {
            let code = run.code();
            Err(explain::with_code(
                &explain::profile(code.as_deref()),
                code.as_deref(),
            ))
        }
    }
}

/// The one AEGIS profile's owner generation, saving or rewriting it when
/// there is none or it no longer matches.
fn owned_generation(
    runner: &mut dyn Runner,
    relay: IpAddr,
    events: &mut Vec<String>,
) -> Result<String, String> {
    let run = step(runner, &HostVerb::List, events);
    let profiles = parse_list(&run.stdout).map_err(|code| {
        explain::with_code(
            tr(
                "AEGIS could not read its VPN configuration.",
                "AEGIS не удалось прочитать свою конфигурацию VPN.",
            ),
            Some(code),
        )
    })?;
    match profiles.as_slice() {
        [] => save(runner, relay, false, events),
        [profile] => match &profile.owner_generation {
            Some(generation) if profile.intent_valid => Ok(generation.clone()),
            _ if NativeStatus::from_raw(profile.native_vpn_status).tunnel_up() => {
                Err(explain::profile(Some("existing_profile_not_idle")))
            }
            _ => save(runner, relay, true, events),
        },
        _ => Err(explain::profile(Some("multiple_provider_profiles_refused"))),
    }
}

/// A connect that failed because the saved profile no longer matches the
/// held terms: the profile is rewritten once and the connect retried.
const STALE_PROFILE: [&str; 4] = [
    "saved_profile_typed_intent_mismatch",
    "saved_profile_generation_mismatch",
    "profile_generation_changed",
    "profile_relay_mismatch",
];

/// Connect: leak guard on, the held relay, the one profile (saved or
/// rewritten when needed), then `--connect`. A requested start is not an
/// observed connection; the menu's refresh shows what macOS reports.
pub fn connect(runner: &mut dyn Runner) -> Outcome {
    let mut events = Vec::new();
    if let Err(message) = ensure_guard(runner, &mut events) {
        return Outcome::failed(message, events);
    }
    let relay = match held_relay(runner, &mut events) {
        Ok(relay) => relay,
        Err(message) => return Outcome::failed(message, events),
    };
    let generation = match owned_generation(runner, relay, &mut events) {
        Ok(generation) => generation,
        Err(message) => return Outcome::failed(message, events),
    };
    let start = |runner: &mut dyn Runner, generation: String, events: &mut Vec<String>| {
        step(
            runner,
            &HostVerb::Connect {
                owner_generation: generation,
                relay,
            },
            events,
        )
    };
    let mut run = start(runner, generation, &mut events);
    if !run.ok()
        && run
            .code()
            .is_some_and(|code| STALE_PROFILE.contains(&code.as_str()))
    {
        match save(runner, relay, true, &mut events) {
            Ok(generation) => run = start(runner, generation, &mut events),
            Err(message) => return Outcome::failed(message, events),
        }
    }
    if run.ok() {
        Outcome::done(tr("Connecting…", "Подключение…"), events)
    } else {
        let code = run.code();
        Outcome::failed(
            explain::with_code(&explain::profile(code.as_deref()), code.as_deref()),
            events,
        )
    }
}

/// Disconnect the one profile by its exact saved intent; when that cannot
/// be named (no terms, a stale profile) or is refused, request a stop of
/// every AEGIS profile (`--emergency-stop`). A requested stop is not an
/// observed disconnect; the menu's refresh shows it.
pub fn disconnect(runner: &mut dyn Runner) -> Outcome {
    let mut events = Vec::new();
    let run = step(runner, &HostVerb::List, &mut events);
    let generation = parse_list(&run.stdout)
        .ok()
        .and_then(|profiles| match profiles.as_slice() {
            [profile] => profile.owner_generation.clone(),
            _ => None,
        });
    let relay = held_relay(runner, &mut events).ok();
    if let (Some(owner_generation), Some(relay)) = (generation, relay) {
        let run = step(
            runner,
            &HostVerb::Disconnect {
                owner_generation,
                relay,
            },
            &mut events,
        );
        if run.ok() {
            return Outcome::done(tr("Disconnecting…", "Отключение…"), events);
        }
    }
    let mut outcome = force_stop(runner);
    events.append(&mut outcome.events);
    outcome.events = events;
    outcome
}

/// `--emergency-stop`: a stop request for every AEGIS profile.
pub fn force_stop(runner: &mut dyn Runner) -> Outcome {
    let mut events = Vec::new();
    let run = step(runner, &HostVerb::EmergencyStop, &mut events);
    if run.ok() {
        Outcome::done(tr("Stop requested.", "Остановка запрошена."), events)
    } else {
        Outcome::failed(
            explain::with_code(
                tr(
                    "AEGIS could not ask macOS to stop the tunnel. Open System Settings > VPN and switch AEGIS off.",
                    "AEGIS не удалось попросить macOS остановить туннель. Откройте «Системные настройки» > VPN и выключите AEGIS.",
                ),
                run.code().as_deref(),
            ),
            events,
        )
    }
}

/// `--enable-filter` (macOS's "filter network content" Allow alert).
pub fn enable_guard(runner: &mut dyn Runner) -> Outcome {
    let mut events = Vec::new();
    let run = step(runner, &HostVerb::EnableFilter, &mut events);
    let outcome =
        result_line(&run.stdout, "filter_result=").and_then(|line| field(line, "filter_result"));
    let message = explain::enable_filter(outcome);
    if outcome == Some("ok") {
        Outcome::done(message, events)
    } else {
        Outcome::failed(message, events)
    }
}

/// `--request-activation`; `on_approval` runs as soon as the host reports
/// that Apple waits for the switch in System Settings.
pub fn activate(runner: &mut dyn Runner, on_approval: &mut dyn FnMut()) -> Outcome {
    let mut events = Vec::new();
    let mut approval = false;
    let run = runner.host(&HostVerb::RequestActivation, &mut |line| {
        if line.starts_with(APPROVAL_STDERR_PREFIX) && !approval {
            approval = true;
            on_approval();
        }
    });
    events.push(run.summary("request-activation"));
    let reported = result_line(&run.stdout, "activation_result=")
        .and_then(|line| field(line, "needs_user_approval"))
        == Some("true");
    let message = explain::activation(run.exit);
    let mut outcome = if run.ok() {
        Outcome::done(message, events)
    } else {
        Outcome::failed(message, events)
    };
    outcome.approval_needed = !run.ok() && (approval || reported || run.exit == Some(14));
    outcome
}

/// `--import DIR [--remove-source]`: the host's own admission, the
/// administrator prompt and the manifest check.
pub fn import(runner: &mut dyn Runner, dir: &Path, remove_source: bool) -> Outcome {
    let mut events = Vec::new();
    let run = step(
        runner,
        &HostVerb::Import {
            dir: dir.to_path_buf(),
            remove_source,
        },
        &mut events,
    );
    let code = run.code();
    let message = explain::import(run.exit, code.as_deref());
    // 73 and 74 committed the new identity; the rest did not, or may not.
    if matches!(run.exit, Some(0 | 73 | 74)) {
        Outcome::done(message, events)
    } else {
        Outcome::failed(explain::with_code(&message, code.as_deref()), events)
    }
}

/// Setup's VPN step: the one profile for the held relay ("Add VPN
/// Configurations" on its first save).
pub fn add_vpn_configuration(runner: &mut dyn Runner) -> Outcome {
    let mut events = Vec::new();
    let relay = match held_relay(runner, &mut events) {
        Ok(relay) => relay,
        Err(message) => return Outcome::failed(message, events),
    };
    match owned_generation(runner, relay, &mut events) {
        Ok(_) => Outcome::done(
            tr(
                "The VPN configuration is ready.",
                "Конфигурация VPN готова.",
            ),
            events,
        ),
        Err(message) => Outcome::failed(message, events),
    }
}

/// v45: `--enroll COPY --remove-source [--replace-identity]`: the host's
/// package admission, precheck, staging and redeem, then the existing
/// import with its administrator prompt. `on_step` hears each progress
/// line. Joined only for a committed import (`enroll_result=joined`).
pub fn join(
    runner: &mut dyn Runner,
    path: &Path,
    replace_identity: bool,
    on_step: &mut dyn FnMut(JoinStep),
) -> Outcome {
    let verb = HostVerb::Enroll {
        path: path.to_path_buf(),
        replace_identity,
    };
    let run = runner.host(&verb, &mut |line| {
        if let Some(step) = JoinStep::from_progress(line) {
            on_step(step);
        }
    });
    let events = vec![run.summary(verb.name())];
    let code = run.code();
    let message = explain::join(run.exit, code.as_deref());
    let joined = result_line(&run.stdout, "enroll_result=")
        .and_then(|line| field(line, "enroll_result"))
        == Some("joined");
    if joined && matches!(run.exit, Some(0 | 73 | 74)) {
        Outcome::done(message, events)
    } else {
        Outcome::failed(explain::with_code(&message, code.as_deref()), events)
    }
}

/// Whether the menu may start an import now (the provider refuses one while
/// a session is live; the menu says so first).
pub fn import_allowed(obs: &Observation) -> bool {
    !obs.native_status()
        .is_some_and(menu_model::NativeStatus::tunnel_up)
}

/// v45: a join is allowed when an import is (no tunnel).
pub fn join_allowed(obs: &Observation) -> bool {
    import_allowed(obs)
}

#[cfg(test)]
#[path = "menu_flow_tests.rs"]
mod tests;
