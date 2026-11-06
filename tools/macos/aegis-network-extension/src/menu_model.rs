//! v39 (B-06 menu-bar app, source only; not yet run installed): the pure
//! state model of the AEGIS menu-bar app.
//!
//! The menu-bar app (`bin/host.rs` started from Finder with no arguments)
//! implements no host verb of its own. Every action runs this same signed
//! executable as a child with one existing CLI verb (`menu_flow::HostVerb`),
//! so every identity, filter, profile and leak-guard check is the CLI's own
//! and nothing here can relax one. This module reads what those verbs (and
//! the read-only `systemextensionsctl list`) print and decides what the menu
//! shows and offers. Nothing here calls Apple or changes any state.

use crate::{
    app_group::APPROVED_TEAM_ID,
    configuration::PROVIDER_ID,
    host_lifecycle::{parse_bundle_version, ProfileLine},
    menu_l10n::{lang, tr, Lang},
    provider_xpc::{utc_text, CertStatusReport, StatusReport},
};

/// Apple activates a system extension only for an app in /Applications, so
/// the menu app offers setup only from this executable path.
pub const INSTALLED_EXECUTABLE: &str = "/Applications/AEGIS.app/Contents/MacOS/aegis-ne-host";

/// A Connecting status (macOS holds drop-all routes while it lasts) longer
/// than this is shown as blocked by the leak guard.
pub const CONNECTING_GRACE_SECS: u64 = 45;

/// A Disconnecting status longer than this offers the forced stop.
pub const DISCONNECTING_GRACE_SECS: u64 = 20;

/// A certificate that ends within this is flagged in the menu.
pub const EXPIRY_WARNING_SECS: u64 = 24 * 3600;

/// The `aegis-ne-host` stderr line `--request-activation` prints when Apple
/// asks the user to approve the extension in System Settings.
pub const APPROVAL_STDERR_PREFIX: &str = "System Settings approval required";

/// Whether this launch is the menu-bar app: started by LaunchServices
/// (Finder, `open`) with no verb, never from a terminal. A terminal launch
/// without arguments keeps the CLI's usage error (exit 2), so every script
/// and the CLI contract are unchanged. Older LaunchServices pass one
/// `-psn_...` process serial number.
pub fn launched_as_app(args: &[String], stdin_is_terminal: bool) -> bool {
    if stdin_is_terminal {
        return false;
    }
    match args {
        [_] => true,
        [_, psn] => psn.starts_with("-psn_"),
        _ => false,
    }
}

/// Whether `exe` (canonical) is the installed app's host executable.
pub fn in_applications(exe: &str) -> bool {
    exe == INSTALLED_EXECUTABLE
}

/// Apple's `NEVPNStatus` of the saved AEGIS profile, as `--list` prints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStatus {
    Invalid,
    Disconnected,
    Connecting,
    Connected,
    Reasserting,
    Disconnecting,
    Other(isize),
}

impl NativeStatus {
    pub fn from_raw(raw: isize) -> Self {
        match raw {
            0 => Self::Invalid,
            1 => Self::Disconnected,
            2 => Self::Connecting,
            3 => Self::Connected,
            4 => Self::Reasserting,
            5 => Self::Disconnecting,
            other => Self::Other(other),
        }
    }

    /// A tunnel exists (or is being built or torn down): macOS may hold
    /// traffic for it, and an import or setup step must wait.
    pub fn tunnel_up(self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::Connected | Self::Reasserting | Self::Disconnecting
        )
    }
}

/// The provider's state as `systemextensionsctl list` shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ExtensionState {
    /// Not read yet, or the tool failed.
    #[default]
    Unknown,
    /// No copy of this provider (of the reviewed team) is listed.
    NotFound,
    /// `[activated enabled]`; `build` is its CFBundleVersion.
    Enabled { build: Option<String> },
    /// `[activated waiting for user]`: the switch in System Settings.
    AwaitingApproval,
    /// `[activated disabled]`: switched off in System Settings.
    Disabled,
    /// `[validating ...]`: Apple is still checking it.
    Validating,
    /// Only stopped copies (`terminated waiting to uninstall on reboot`).
    Inactive,
}

/// Parse `systemextensionsctl list` (tab-separated: enabled, active, team,
/// `bundleID (short/build)`, name, `[state]`). Only this provider of the
/// reviewed team counts; the newest enabled build wins.
pub fn parse_extension_list(text: &str) -> ExtensionState {
    let mut seen = false;
    let mut enabled: Option<Option<String>> = None;
    let (mut awaiting, mut disabled, mut validating) = (false, false, false);
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 6 || fields[2].trim() != APPROVED_TEAM_ID {
            continue;
        }
        let Some(version) = fields[3]
            .strip_prefix(PROVIDER_ID)
            .and_then(|rest| rest.strip_prefix(" ("))
            .and_then(|rest| rest.strip_suffix(')'))
        else {
            continue;
        };
        seen = true;
        let build = version.split_once('/').map(|(_, build)| build.to_owned());
        let state = fields[5]
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        match state {
            "activated enabled" => {
                let rank = |b: &Option<String>| b.as_deref().and_then(parse_bundle_version);
                if enabled
                    .as_ref()
                    .is_none_or(|current| rank(&build) > rank(current))
                {
                    enabled = Some(build);
                }
            }
            "activated waiting for user" => awaiting = true,
            "activated disabled" => disabled = true,
            other if other.starts_with("validating") => validating = true,
            _ => {}
        }
    }
    match enabled {
        Some(build) => ExtensionState::Enabled { build },
        None if awaiting => ExtensionState::AwaitingApproval,
        None if disabled => ExtensionState::Disabled,
        None if validating => ExtensionState::Validating,
        None if seen => ExtensionState::Inactive,
        None => ExtensionState::NotFound,
    }
}

/// Whether the app's own CFBundleVersion is newer than the enabled
/// extension's: the extension must be replaced (`--request-activation`
/// replaces only a numerically newer build).
pub fn update_pending(app_build: Option<&str>, extension_build: Option<&str>) -> bool {
    match (
        app_build.and_then(parse_bundle_version),
        extension_build.and_then(parse_bundle_version),
    ) {
        (Some(app), Some(extension)) => app > extension,
        _ => false,
    }
}

/// `--list` stdout: every `profile ...` line through `ProfileLine::parse`
/// (the parser the host's own tests bind to its printer), then the
/// `profiles=N` total, which must count them.
pub fn parse_list(stdout: &str) -> Result<Vec<ProfileLine>, &'static str> {
    let mut profiles = Vec::new();
    let mut total = None;
    for line in stdout.lines() {
        if line.starts_with("profile ") {
            profiles.push(ProfileLine::parse(line)?);
        } else if let Some(rest) = line.strip_prefix("profiles=") {
            let count = rest
                .split(' ')
                .next()
                .and_then(|n| n.parse::<usize>().ok())
                .ok_or("list_total_malformed")?;
            total = Some(count);
        }
    }
    match total {
        Some(count) if count == profiles.len() => Ok(profiles),
        Some(_) => Err("list_count_mismatch"),
        None => Err("list_total_missing"),
    }
}

/// The value of `key` in one `key=value key=value` result line.
pub fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ')
        .filter_map(|word| word.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

/// The first stdout line that starts with `prefix` (the host's result
/// line; `--filter-status` may print the provider's JSON after it).
pub fn result_line<'a>(stdout: &'a str, prefix: &str) -> Option<&'a str> {
    stdout.lines().find(|line| line.starts_with(prefix))
}

/// A stable code token (`[a-z][a-z0-9_:.-]*`) as the host prints them.
fn is_code(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 96
        && token.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:.-".contains(&b))
}

/// The refusal code a host verb wrote last on stderr: the last word of the
/// last line that ends in a code (`owner_generation=G CODE`,
/// `provider_refused CODE` or `CODE` alone). Prose lines (banners, the
/// renewal line) never end in one.
pub fn stderr_code(stderr: &str) -> Option<String> {
    stderr.lines().rev().find_map(|line| {
        let last = line.split_whitespace().last()?;
        (is_code(last) && !last.contains('=')).then(|| last.to_owned())
    })
}

/// What one read-only probe returned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Probe<T> {
    /// Not asked yet (or not asked because a precondition failed).
    #[default]
    Unknown,
    Ok(T),
    /// The verb failed: its exit code (none when it was killed at the outer
    /// bound) and its stderr code.
    Failed {
        exit: Option<i32>,
        code: Option<String>,
    },
}

impl<T> Probe<T> {
    pub fn ok(&self) -> Option<&T> {
        match self {
            Probe::Ok(value) => Some(value),
            _ => None,
        }
    }

    /// The probe failed because the provider's XPC service did not answer
    /// (exit 69) or was not reached in time (75).
    pub fn provider_unreachable(&self) -> bool {
        matches!(
            self,
            Probe::Failed {
                exit: Some(69 | 75),
                ..
            }
        )
    }
}

/// `--filter-status`'s first line: the outcome and, when the provider
/// answered, its mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterView {
    /// `ok`, `not_configured`, `disabled`, `field_mismatch`, `not_attached`,
    /// `provider_unavailable`, `failed`, `timeout`, ...
    pub outcome: String,
    /// `open` or `guarding`, only when the provider answered.
    pub mode: Option<String>,
}

pub fn parse_filter_status(stdout: &str) -> Option<FilterView> {
    let line = result_line(stdout, "filter_result=")?;
    Some(FilterView {
        outcome: field(line, "filter_result")?.to_owned(),
        mode: field(line, "mode").map(str::to_owned),
    })
}

/// The leak guard (the S20b packet filter) as the menu shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardState {
    Unknown,
    /// Configured, exact, enabled and attached; `guarding` while a tunnel
    /// session holds it armed.
    On {
        guarding: bool,
    },
    /// Not configured, disabled or not the reviewed configuration: the menu
    /// app turns it on (`--enable-filter`) before it connects.
    Off,
    /// Enabled, but the provider does not report it attached or does not
    /// answer.
    NotRunning,
    /// The readback itself failed.
    Failed,
}

impl FilterView {
    pub fn guard(&self) -> GuardState {
        match self.outcome.as_str() {
            "ok" => GuardState::On {
                guarding: self.mode.as_deref() == Some("guarding"),
            },
            "not_configured" | "disabled" | "field_mismatch" => GuardState::Off,
            "not_attached" | "provider_unavailable" => GuardState::NotRunning,
            _ => GuardState::Failed,
        }
    }
}

/// The certificate as the menu shows it, from the provider's
/// `cert-status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertFacet {
    Unknown,
    Valid {
        not_after: Option<u64>,
    },
    /// Due, in progress or issued and awaiting the relay's acknowledgement.
    Renewing {
        not_after: Option<u64>,
    },
    /// v31: due while connected; it renews at the next Connect.
    Deferred {
        not_after: Option<u64>,
    },
    Failing {
        class: String,
        not_after: Option<u64>,
    },
    /// A journaled request awaits its answer; a Connect retries it.
    Pending,
    /// v32: the authority rejected the request; the old certificate works.
    Parked {
        not_after: Option<u64>,
    },
    /// v32: the relay no longer admits the installed certificate.
    Superseded,
    Expired {
        not_after: Option<u64>,
    },
    NotYetValid,
}

pub fn cert_facet(report: &CertStatusReport, now: u64) -> CertFacet {
    let not_after = report.not_after;
    let expired_by_clock = not_after.is_some_and(|end| end <= now);
    match report.state.as_str() {
        "expired" => CertFacet::Expired { not_after },
        "superseded" => CertFacet::Superseded,
        _ if expired_by_clock => CertFacet::Expired { not_after },
        "valid" => CertFacet::Valid { not_after },
        "due" | "in_progress" | "renewed_pending_ack" => CertFacet::Renewing { not_after },
        "deferred:guarded" => CertFacet::Deferred { not_after },
        "pending" => CertFacet::Pending,
        "parked" => CertFacet::Parked { not_after },
        "not_yet_valid" => CertFacet::NotYetValid,
        state => match state.strip_prefix("failed:") {
            Some(class) => CertFacet::Failing {
                class: class.to_owned(),
                not_after,
            },
            None => CertFacet::Unknown,
        },
    }
}

/// `2026-11-05T14:00:00Z` as `2026-11-05 14:00 UTC`.
pub fn friendly_utc(seconds: u64) -> String {
    let text = utc_text(seconds);
    format!("{} {} UTC", &text[..10], &text[11..16])
}

impl CertFacet {
    /// Only a new identity (a new invitation, imported) helps.
    pub fn needs_new_identity(&self) -> bool {
        matches!(self, CertFacet::Expired { .. } | CertFacet::Superseded)
    }

    /// The certificate line of the menu.
    pub fn text(&self, now: u64) -> String {
        let until = |end: &Option<u64>| {
            end.map_or_else(|| tr("unknown", "неизвестно").to_owned(), friendly_utc)
        };
        let soon = |end: &Option<u64>| {
            end.is_some_and(|end| end > now && end - now <= EXPIRY_WARNING_SECS)
        };
        let ru = lang() == Lang::Ru;
        match self {
            CertFacet::Unknown => tr("Certificate: not checked yet", "Сертификат: ещё не проверен").into(),
            CertFacet::Valid { not_after } if soon(not_after) && ru => format!(
                "Сертификат: действует до {} (обновится при следующем подключении)",
                until(not_after)
            ),
            CertFacet::Valid { not_after } if soon(not_after) => format!(
                "Certificate: valid until {} (renews at the next connect)",
                until(not_after)
            ),
            CertFacet::Valid { not_after } if ru => {
                format!("Сертификат: действует до {}", until(not_after))
            }
            CertFacet::Valid { not_after } => {
                format!("Certificate: valid until {}", until(not_after))
            }
            CertFacet::Renewing { not_after } if ru => {
                format!("Сертификат: обновляется (действует до {})", until(not_after))
            }
            CertFacet::Renewing { not_after } => {
                format!("Certificate: renewing (valid until {})", until(not_after))
            }
            CertFacet::Deferred { not_after } if ru => format!(
                "Сертификат: обновление ждёт следующего подключения; отключитесь и подключитесь до {}",
                until(not_after)
            ),
            CertFacet::Deferred { not_after } => format!(
                "Certificate: renewal waits for the next connect; disconnect and connect before {}",
                until(not_after)
            ),
            CertFacet::Failing { class, not_after } if ru => format!(
                "Сертификат: обновление не удаётся ({class}); действует до {}",
                until(not_after)
            ),
            CertFacet::Failing { class, not_after } => format!(
                "Certificate: renewal failing ({class}); valid until {}",
                until(not_after)
            ),
            CertFacet::Pending => tr(
                "Certificate: renewal pending; Connect retries it",
                "Сертификат: обновление ожидает; «Подключить» повторит его",
            )
            .into(),
            CertFacet::Parked { not_after } if ru => format!(
                "Сертификат: обновление отложено; действует до {}",
                until(not_after)
            ),
            CertFacet::Parked { not_after } => format!(
                "Certificate: renewal postponed; valid until {}",
                until(not_after)
            ),
            CertFacet::Superseded => tr(
                "Certificate: replaced by the server; ask for a new invitation",
                "Сертификат: заменён сервером; попросите новое приглашение",
            )
            .into(),
            CertFacet::Expired { not_after } if ru => format!(
                "Сертификат: истёк {}; попросите новое приглашение",
                until(not_after)
            ),
            CertFacet::Expired { not_after } => format!(
                "Certificate: expired at {}; ask for a new invitation",
                until(not_after)
            ),
            CertFacet::NotYetValid => tr(
                "Certificate: not valid yet; check the Mac's date and time",
                "Сертификат: ещё не действует; проверьте дату и время на Mac",
            )
            .into(),
        }
    }
}

/// v45: the step a join (`--enroll`) reports on stderr
/// (`host_enroll::PROGRESS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinStep {
    Checking,
    Preparing,
    Contacting,
    Approving,
    Importing,
}

impl JoinStep {
    /// The step of one `enroll_progress=STEP` stderr line.
    pub fn from_progress(line: &str) -> Option<Self> {
        match line.strip_prefix(crate::host_enroll::PROGRESS)? {
            "checking" => Some(Self::Checking),
            "preparing" => Some(Self::Preparing),
            "contacting" => Some(Self::Contacting),
            "approving" => Some(Self::Approving),
            "importing" | "finishing" => Some(Self::Importing),
            _ => None,
        }
    }
}

/// A menu action in progress (one child verb sequence at a time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    Checking,
    Activating,
    EnablingGuard,
    Importing,
    /// v45: joining with an invitation file, at this step.
    Joining(JoinStep),
    SavingProfile,
    Connecting,
    Disconnecting,
    Stopping,
}

impl Activity {
    pub fn label(self) -> &'static str {
        match self {
            Activity::Checking => tr("Checking…", "Проверка…"),
            Activity::Activating => tr(
                "Turning on the network extension…",
                "Включение сетевого расширения…",
            ),
            Activity::EnablingGuard => {
                tr("Turning on the leak guard…", "Включение защиты от утечек…")
            }
            Activity::Importing => tr("Importing your invitation…", "Импорт приглашения…"),
            Activity::Joining(JoinStep::Checking) => tr(
                "Joining: checking the invitation…",
                "Присоединение: проверка приглашения…",
            ),
            Activity::Joining(JoinStep::Preparing) => tr(
                "Joining: creating this Mac's key…",
                "Присоединение: создание ключа этого Mac…",
            ),
            Activity::Joining(JoinStep::Contacting) => tr(
                "Joining: contacting the AEGIS server…",
                "Присоединение: связь с сервером AEGIS…",
            ),
            Activity::Joining(JoinStep::Approving) => tr(
                "Joining: waiting for the administrator password…",
                "Присоединение: ожидание пароля администратора…",
            ),
            Activity::Joining(JoinStep::Importing) => tr(
                "Joining: installing your identity…",
                "Присоединение: установка удостоверения…",
            ),
            Activity::SavingProfile => tr(
                "Adding the VPN configuration…",
                "Добавление конфигурации VPN…",
            ),
            Activity::Connecting => tr("Connecting…", "Подключение…"),
            Activity::Disconnecting => tr("Disconnecting…", "Отключение…"),
            Activity::Stopping => tr("Stopping the tunnel…", "Остановка туннеля…"),
        }
    }
}

/// Everything the menu knows, refreshed by `menu_flow::refresh`.
#[derive(Clone, Debug, Default)]
pub struct Observation {
    /// At least one refresh finished.
    pub refreshed: bool,
    /// The app runs from /Applications (`in_applications`).
    pub in_applications: bool,
    /// The running app's CFBundleVersion.
    pub app_build: Option<String>,
    pub extension: ExtensionState,
    pub profiles: Probe<Vec<ProfileLine>>,
    /// Bare `--status`: the provider's session phase and last refusal.
    pub provider: Probe<StatusReport>,
    /// `--ping`: whether the provider holds an imported identity.
    pub identity_present: Option<bool>,
    /// The last answered `--cert-status`.
    pub cert: Option<CertStatusReport>,
    pub filter: Probe<FilterView>,
    /// The native status and when it was first seen.
    pub status_since: Option<(isize, u64)>,
    pub activity: Option<Activity>,
    /// An activation reported that it waits for the System Settings switch
    /// and no activation has completed since.
    pub approval_requested: bool,
    /// The last action's outcome, for the menu.
    pub notice: Option<String>,
}

impl Observation {
    /// The single AEGIS profile, when exactly one exists.
    pub fn profile(&self) -> Option<&ProfileLine> {
        match self.profiles.ok()?.as_slice() {
            [profile] => Some(profile),
            _ => None,
        }
    }

    pub fn native_status(&self) -> Option<NativeStatus> {
        self.profile()
            .map(|profile| NativeStatus::from_raw(profile.native_vpn_status))
    }

    /// Record the native status now seen (keeps the first-seen time while it
    /// does not change).
    pub fn note_status(&mut self, now: u64) {
        let raw = self.profile().map(|profile| profile.native_vpn_status);
        self.status_since = match (raw, self.status_since) {
            (Some(raw), Some((seen, since))) if seen == raw => Some((seen, since)),
            (Some(raw), _) => Some((raw, now)),
            (None, _) => None,
        };
    }

    fn status_age(&self, now: u64) -> u64 {
        self.status_since
            .map_or(0, |(_, since)| now.saturating_sub(since))
    }

    pub fn guard(&self) -> GuardState {
        self.filter
            .ok()
            .map_or(GuardState::Unknown, FilterView::guard)
    }

    pub fn cert_facet(&self, now: u64) -> CertFacet {
        self.cert
            .as_ref()
            .map_or(CertFacet::Unknown, |report| cert_facet(report, now))
    }

    /// v45: a join needs no confirmation to replace the held identity: there
    /// is none, or it can no longer connect. Unknown presence asks.
    pub fn identity_replaceable(&self, now: u64) -> bool {
        self.identity_present == Some(false)
            || self.cert_facet(now).needs_new_identity()
            || self.refused_expired()
    }

    /// The provider refused the last session start for an expired identity.
    fn refused_expired(&self) -> bool {
        self.provider.ok().is_some_and(|status| {
            status.session_refusal.as_deref() == Some("session_identity_expired")
        })
    }

    fn extension_build(&self) -> Option<&str> {
        match &self.extension {
            ExtensionState::Enabled { build } => build.as_deref(),
            _ => None,
        }
    }
}

/// A setup step the menu walks the user through, in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    ActivateExtension,
    UpdateExtension,
    TurnOnLeakGuard,
    ImportIdentity,
    AddVpnConfiguration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    /// macOS shows Reasserting: the session was lost and is being rebuilt;
    /// every packet is dropped meanwhile.
    Reconnecting,
    /// Connecting for longer than `CONNECTING_GRACE_SECS`.
    StillConnecting,
}

/// The one state the menu-bar icon and title show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primary {
    Checking,
    MoveToApplications,
    NeedsApproval,
    Setup(SetupStep),
    Busy(Activity),
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Blocked(BlockReason),
    CertificateExpired { blocked: bool },
    CertificateRenewing,
    ExtensionNotResponding,
}

/// The actions the menu enables.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Actions {
    pub connect: bool,
    pub disconnect: bool,
    /// `--emergency-stop`: stop requests for every AEGIS profile.
    pub force_stop: bool,
    pub setup: Option<SetupStep>,
    pub open_settings: bool,
    pub enable_guard: bool,
    /// The folder import (`--import`); v45: in the More submenu.
    pub import: bool,
    /// v45: "Join with Invitation…" (`--enroll`).
    pub join: bool,
    /// v45: shown at the top of the menu (no identity yet, or it can no
    /// longer connect) instead of in the More submenu.
    pub join_prominent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuView {
    pub primary: Primary,
    pub title: String,
    /// SF Symbol name for the menu-bar icon.
    pub symbol: &'static str,
    /// Information lines (not clickable).
    pub details: Vec<String>,
    pub actions: Actions,
}

impl Primary {
    pub fn title(self) -> String {
        let text = match self {
            Primary::Checking => tr("Checking…", "Проверка…"),
            Primary::MoveToApplications => tr(
                "Move AEGIS to the Applications folder",
                "Переместите AEGIS в папку «Программы»",
            ),
            Primary::NeedsApproval => tr(
                "Needs approval in System Settings",
                "Нужно разрешение в Системных настройках",
            ),
            Primary::Setup(SetupStep::ActivateExtension) => tr(
                "Setup needed: turn on the network extension",
                "Нужна настройка: включите сетевое расширение",
            ),
            Primary::Setup(SetupStep::UpdateExtension) => tr(
                "Update ready: finish installing it",
                "Обновление готово: завершите установку",
            ),
            Primary::Setup(SetupStep::TurnOnLeakGuard) => tr(
                "Setup needed: turn on the leak guard",
                "Нужна настройка: включите защиту от утечек",
            ),
            Primary::Setup(SetupStep::ImportIdentity) => tr(
                "Setup needed: join with your invitation",
                "Нужна настройка: присоединитесь по приглашению",
            ),
            Primary::Setup(SetupStep::AddVpnConfiguration) => tr(
                "Setup needed: add the VPN configuration",
                "Нужна настройка: добавьте конфигурацию VPN",
            ),
            Primary::Busy(activity) => activity.label(),
            Primary::Disconnected => tr("Disconnected", "Отключено"),
            Primary::Connecting => tr("Connecting…", "Подключение…"),
            Primary::Connected => tr("Connected", "Подключено"),
            Primary::Disconnecting => tr("Disconnecting…", "Отключение…"),
            Primary::Blocked(BlockReason::Reconnecting) => tr(
                "Blocked by leak guard (reconnecting)",
                "Заблокировано защитой от утечек (переподключение)",
            ),
            Primary::Blocked(BlockReason::StillConnecting) => tr(
                "Blocked by leak guard (still connecting)",
                "Заблокировано защитой от утечек (подключение затянулось)",
            ),
            Primary::CertificateExpired { blocked: true } => tr(
                "Certificate expired: traffic blocked",
                "Сертификат истёк: трафик заблокирован",
            ),
            Primary::CertificateExpired { blocked: false } => tr(
                "Certificate expired: ask for a new invitation",
                "Сертификат истёк: попросите новое приглашение",
            ),
            Primary::CertificateRenewing => tr("Certificate renewing", "Сертификат обновляется"),
            Primary::ExtensionNotResponding => tr(
                "Network extension not responding",
                "Сетевое расширение не отвечает",
            ),
        };
        text.to_owned()
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Primary::Checking | Primary::Busy(_) => "shield.lefthalf.filled",
            Primary::MoveToApplications | Primary::Setup(_) => "shield.slash",
            Primary::NeedsApproval | Primary::ExtensionNotResponding => "exclamationmark.shield",
            Primary::Disconnected => "shield",
            Primary::Connecting | Primary::Disconnecting => "shield.lefthalf.filled",
            Primary::Connected => "lock.shield.fill",
            Primary::Blocked(_) => "xmark.shield.fill",
            Primary::CertificateExpired { .. } => "exclamationmark.shield.fill",
            Primary::CertificateRenewing => "clock.arrow.circlepath",
        }
    }
}

/// The menu for one observation at `now` (Unix seconds).
pub fn derive(obs: &Observation, now: u64) -> MenuView {
    let primary = primary(obs, now);
    let native = obs.native_status();
    let up = native.is_some_and(NativeStatus::tunnel_up);
    let idle = obs.activity.is_none();
    let enabled = matches!(obs.extension, ExtensionState::Enabled { .. });
    let cert = obs.cert_facet(now);
    let dead = cert.needs_new_identity() || obs.refused_expired();
    let guard = obs.guard();
    let mut actions = Actions {
        connect: idle
            && matches!(
                primary,
                Primary::Disconnected
                    | Primary::CertificateRenewing
                    | Primary::Setup(SetupStep::TurnOnLeakGuard | SetupStep::AddVpnConfiguration)
            ),
        disconnect: idle && up,
        force_stop: idle
            && (matches!(
                primary,
                Primary::Blocked(_) | Primary::CertificateExpired { blocked: true }
            ) || (native == Some(NativeStatus::Disconnecting)
                && obs.status_age(now) > DISCONNECTING_GRACE_SECS)),
        setup: None,
        open_settings: matches!(primary, Primary::NeedsApproval),
        enable_guard: idle && enabled && guard == GuardState::Off,
        import: idle && enabled && !up,
        join: idle && enabled && !up,
        join_prominent: obs.identity_present == Some(false) || dead,
    };
    actions.setup = match primary {
        Primary::Setup(step) if idle => Some(step),
        Primary::NeedsApproval if idle => Some(SetupStep::ActivateExtension),
        _ => None,
    };
    let mut details = Vec::new();
    if obs.refreshed && enabled {
        details.push(guard_text(guard));
        if obs.identity_present != Some(false) && obs.cert.is_some() {
            details.push(cert.text(now));
        }
    }
    if enabled && up && update_pending(obs.app_build.as_deref(), obs.extension_build()) {
        details.push(
            tr(
                "Update ready: disconnect, then choose Finish Update",
                "Обновление готово: отключитесь и выберите «Завершить обновление…»",
            )
            .into(),
        );
    }
    if dead && !matches!(primary, Primary::CertificateExpired { .. }) {
        details.push(
            tr(
                "The certificate can no longer connect: ask for a new invitation, then choose Join with Invitation",
                "С этим сертификатом подключиться нельзя: попросите новое приглашение и выберите «Присоединиться по приглашению…»",
            )
            .into(),
        );
    }
    if let Some(notice) = &obs.notice {
        details.push(notice.clone());
    }
    MenuView {
        primary,
        title: primary.title(),
        symbol: primary.symbol(),
        details,
        actions,
    }
}

fn guard_text(guard: GuardState) -> String {
    match guard {
        GuardState::On { guarding: true } => tr(
            "Leak guard: on, guarding traffic",
            "Защита от утечек: включена, трафик под защитой",
        ),
        GuardState::On { guarding: false } => tr("Leak guard: on", "Защита от утечек: включена"),
        GuardState::Off => tr(
            "Leak guard: off (AEGIS turns it on before it connects)",
            "Защита от утечек: выключена (AEGIS включит её перед подключением)",
        ),
        GuardState::NotRunning => tr(
            "Leak guard: on, but not running",
            "Защита от утечек: включена, но не работает",
        ),
        GuardState::Failed => tr(
            "Leak guard: could not be read",
            "Защита от утечек: состояние не прочитано",
        ),
        GuardState::Unknown => tr(
            "Leak guard: not checked yet",
            "Защита от утечек: ещё не проверена",
        ),
    }
    .to_owned()
}

fn primary(obs: &Observation, now: u64) -> Primary {
    if !obs.refreshed {
        return Primary::Checking;
    }
    if !obs.in_applications {
        return Primary::MoveToApplications;
    }
    let enabled = matches!(obs.extension, ExtensionState::Enabled { .. });
    if obs.extension == ExtensionState::AwaitingApproval || (obs.approval_requested && !enabled) {
        return Primary::NeedsApproval;
    }
    if let Some(activity) = obs.activity {
        return Primary::Busy(activity);
    }
    match obs.extension {
        ExtensionState::Disabled => return Primary::NeedsApproval,
        ExtensionState::NotFound | ExtensionState::Inactive => {
            return Primary::Setup(SetupStep::ActivateExtension)
        }
        ExtensionState::Validating => return Primary::Busy(Activity::Activating),
        ExtensionState::Enabled { .. }
        | ExtensionState::Unknown
        | ExtensionState::AwaitingApproval => {}
    }
    let cert = obs.cert_facet(now);
    let dead = cert.needs_new_identity() || obs.refused_expired();
    match obs.native_status() {
        Some(status) if status.tunnel_up() && dead && status != NativeStatus::Disconnecting => {
            return Primary::CertificateExpired { blocked: true }
        }
        Some(NativeStatus::Reasserting) => return Primary::Blocked(BlockReason::Reconnecting),
        Some(NativeStatus::Connecting) if obs.status_age(now) > CONNECTING_GRACE_SECS => {
            return Primary::Blocked(BlockReason::StillConnecting)
        }
        Some(NativeStatus::Connecting) => return Primary::Connecting,
        Some(NativeStatus::Disconnecting) => return Primary::Disconnecting,
        Some(NativeStatus::Connected) => return Primary::Connected,
        _ => {}
    }
    // No tunnel: what setup (if any) is still missing, in setup order.
    if enabled && update_pending(obs.app_build.as_deref(), obs.extension_build()) {
        return Primary::Setup(SetupStep::UpdateExtension);
    }
    if enabled && obs.provider.provider_unreachable() {
        return Primary::ExtensionNotResponding;
    }
    if obs.guard() == GuardState::Off {
        return Primary::Setup(SetupStep::TurnOnLeakGuard);
    }
    if obs.identity_present == Some(false) {
        return Primary::Setup(SetupStep::ImportIdentity);
    }
    if dead {
        return Primary::CertificateExpired { blocked: false };
    }
    if matches!(obs.profiles.ok(), Some(profiles) if profiles.is_empty()) {
        return Primary::Setup(SetupStep::AddVpnConfiguration);
    }
    if cert == CertFacet::Pending {
        return Primary::CertificateRenewing;
    }
    Primary::Disconnected
}

/// The next setup step the wizard should run, or `None` when setup is
/// complete (or cannot continue from here).
pub fn next_setup_step(view: &MenuView) -> Option<SetupStep> {
    view.actions.setup
}

/// Plain-language explanations of host results, for alerts.
pub mod explain {
    use crate::menu_l10n::tr;

    const SEND_DIAGNOSTICS: (&str, &str) = (
        "Copy the diagnostics and send them to the person who invited you.",
        "Скопируйте диагностику и отправьте её тому, кто вас пригласил.",
    );

    fn with_diagnostics(en: &'static str, ru: &'static str) -> String {
        format!(
            "{} {}",
            tr(en, ru),
            tr(SEND_DIAGNOSTICS.0, SEND_DIAGNOSTICS.1)
        )
    }

    /// `--request-activation`'s exit code.
    pub fn activation(exit: Option<i32>) -> String {
        match exit {
            Some(0) => tr("The AEGIS network extension is on.", "Сетевое расширение AEGIS включено.").into(),
            Some(10) => tr(
                "macOS finishes turning on the AEGIS network extension after a restart. Restart the Mac, then open AEGIS again.",
                "macOS завершит включение сетевого расширения AEGIS после перезагрузки. Перезагрузите Mac и снова откройте AEGIS.",
            )
            .into(),
            Some(11) => with_diagnostics(
                "macOS could not turn on the AEGIS network extension.",
                "macOS не удалось включить сетевое расширение AEGIS.",
            ),
            Some(12) => tr(
                "The request to turn on the AEGIS network extension was cancelled.",
                "Запрос на включение сетевого расширения AEGIS отменён.",
            )
            .into(),
            Some(13) => tr(
                "A newer or equal version of the AEGIS network extension is already installed. Install the newest AEGIS app and try again.",
                "Уже установлена такая же или более новая версия сетевого расширения AEGIS. Установите самую новую версию AEGIS и повторите попытку.",
            )
            .into(),
            Some(14) => tr(
                "macOS is waiting for you to allow AEGIS in System Settings. Switch AEGIS on there, then choose Finish Setup again.",
                "macOS ждёт, пока вы разрешите AEGIS в Системных настройках. Включите там AEGIS и снова выберите «Завершить настройку…».",
            )
            .into(),
            Some(75) | None => tr(
                "macOS did not answer in time. Choose Finish Setup again.",
                "macOS не ответила вовремя. Снова выберите «Завершить настройку…».",
            )
            .into(),
            Some(_) => with_diagnostics(
                "macOS refused the request.",
                "macOS отклонила запрос.",
            ),
        }
    }

    /// `--enable-filter`'s outcome name.
    pub fn enable_filter(outcome: Option<&str>) -> String {
        match outcome {
            Some("ok") => tr("The leak guard is on.", "Защита от утечек включена.").into(),
            Some("permission_denied") => tr(
                "The leak guard needs your permission. Choose Turn On Leak Guard again and click Allow when macOS asks whether AEGIS may filter network content.",
                "Защите от утечек нужно ваше разрешение. Снова выберите «Включить защиту от утечек…» и нажмите «Разрешить», когда macOS спросит, может ли AEGIS фильтровать сетевой контент.",
            )
            .into(),
            Some("timeout") => tr(
                "macOS did not answer in time. Choose Turn On Leak Guard again and answer the macOS alert.",
                "macOS не ответила вовремя. Снова выберите «Включить защиту от утечек…» и ответьте на запрос macOS.",
            )
            .into(),
            _ => with_diagnostics(
                "macOS could not turn on the leak guard.",
                "macOS не удалось включить защиту от утечек.",
            ),
        }
    }

    /// `--import`'s exit code and stderr code.
    pub fn import(exit: Option<i32>, code: Option<&str>) -> String {
        match (exit, code) {
            (Some(0), _) => tr("Your invitation was imported.", "Приглашение импортировано.").into(),
            (Some(66), Some("import_source_missing")) => tr(
                "This folder is incomplete. Choose the AEGIS folder you received: it holds exactly two folders, bundle and identity, with your enrolled identity.",
                "Папка неполная. Выберите полученную папку AEGIS: в ней ровно две папки, bundle и identity, с вашим удостоверением.",
            )
            .into(),
            (Some(66), Some("import_source_not_private" | "import_source_not_owned")) => tr(
                "This folder must be private to you. In Finder select it, choose File > Get Info, and under Sharing & Permissions set every entry other than you to No Access (also for the bundle and identity folders inside), then try again.",
                "Папка должна быть доступна только вам. Выберите её в Finder, выберите «Файл» > «Свойства» и в разделе «Общий доступ и права доступа» установите «Нет доступа» для всех, кроме вас (и для папок bundle и identity внутри), затем повторите.",
            )
            .into(),
            (Some(66), Some("import_source_unexpected_entry")) => tr(
                "This folder holds an item AEGIS does not expect. It must hold only the bundle and identity folders it came with. Finder may have added a hidden .DS_Store file: in Finder press Shift-Command-Period to show hidden files, move .DS_Store to the Trash, and try again.",
                "В папке есть лишний объект: в ней должны быть только папки bundle и identity. Finder мог добавить скрытый файл .DS_Store: нажмите в Finder Shift-Command-точка, чтобы показать скрытые файлы, переместите .DS_Store в Корзину и повторите.",
            )
            .into(),
            (Some(66), Some("import_source_symlink" | "import_source_not_directory")) => tr(
                "Choose the folder itself, not an alias to it.",
                "Выберите саму папку, а не псевдоним.",
            )
            .into(),
            (Some(66), _) => tr(
                "AEGIS could not read this folder as an invitation. Choose the AEGIS folder you received and try again.",
                "AEGIS не удалось прочитать эту папку как приглашение. Выберите полученную папку AEGIS и повторите.",
            )
            .into(),
            (Some(67), _) => tr(
                "No administrator approved the import. Nothing was changed.",
                "Администратор не подтвердил импорт. Ничего не изменено.",
            )
            .into(),
            (Some(65), Some("session_live")) => tr(
                "Disconnect first, then import.",
                "Сначала отключитесь, затем импортируйте.",
            )
            .into(),
            (Some(65), _) => tr(
                "The AEGIS network extension refused this invitation. Ask the person who invited you for a new one.",
                "Сетевое расширение AEGIS отклонило это приглашение. Попросите у пригласившего новое.",
            )
            .into(),
            (Some(69), _) => tr(
                "The AEGIS network extension is not running. Choose Finish Setup first.",
                "Сетевое расширение AEGIS не запущено. Сначала выберите «Завершить настройку…».",
            )
            .into(),
            (Some(73), _) => tr(
                "Your invitation was imported, but its folder could not be removed completely. Move it to the Trash yourself.",
                "Приглашение импортировано, но папку не удалось удалить полностью. Переместите её в Корзину сами.",
            )
            .into(),
            (Some(74), _) => with_diagnostics(
                "Your invitation was imported, but the previous identity could not be removed completely.",
                "Приглашение импортировано, но прежнее удостоверение не удалось удалить полностью.",
            ),
            (Some(76), _) => tr(
                "AEGIS could not confirm what was imported. Your folder was kept. Try again.",
                "AEGIS не удалось подтвердить, что именно импортировано. Папка сохранена. Повторите попытку.",
            )
            .into(),
            (Some(75 | 77), _) | (None, _) => tr(
                "AEGIS could not confirm the import. Your folder was kept. Try the import again.",
                "AEGIS не удалось подтвердить импорт. Папка сохранена. Повторите импорт.",
            )
            .into(),
            (Some(_), _) => with_diagnostics("The import failed.", "Импорт не удался."),
        }
    }

    /// v45: why an invitation file was refused (`invite_package` code),
    /// before or by `--enroll` (exit 40).
    pub fn invitation_file(code: Option<&str>) -> String {
        match code {
            Some("invite_symlink" | "invite_not_regular") => tr(
                "Choose the invitation file itself, not an alias or a folder.",
                "Выберите сам файл приглашения, а не псевдоним или папку.",
            )
            .into(),
            Some("invite_extension_required") => tr(
                "Choose the invitation file you received: its name ends in .aegis-invite.",
                "Выберите полученный файл приглашения: его имя оканчивается на .aegis-invite.",
            )
            .into(),
            Some(
                "invite_not_owned" | "invite_linked" | "invite_writable_by_others"
                | "invite_not_canonical_path",
            ) => tr(
                "AEGIS cannot use the invitation file where it is. Move it to your Downloads folder and try again.",
                "AEGIS не может использовать файл приглашения в этом месте. Переместите его в папку «Загрузки» и повторите.",
            )
            .into(),
            Some("invite_missing" | "invite_unreadable") => tr(
                "AEGIS could not read the invitation file. Choose it again.",
                "AEGIS не удалось прочитать файл приглашения. Выберите его снова.",
            )
            .into(),
            _ => tr(
                "This file is not a valid AEGIS invitation, or it was changed. Ask the person who invited you to send it again.",
                "Этот файл — не действующее приглашение AEGIS, или он был изменён. Попросите пригласившего прислать его снова.",
            )
            .into(),
        }
    }

    /// v45: `--enroll`'s exit code and stderr code.
    pub fn join(exit: Option<i32>, code: Option<&str>) -> String {
        match (exit, code) {
            (Some(0), _) => tr(
                "You joined AEGIS. Choose Connect to start the tunnel.",
                "Вы присоединились к AEGIS. Выберите «Подключить», чтобы запустить туннель.",
            )
            .into(),
            (Some(73), _) => tr(
                "You joined AEGIS, but some temporary files could not be removed. Choose Connect to start the tunnel.",
                "Вы присоединились к AEGIS, но часть временных файлов не удалось удалить. Выберите «Подключить», чтобы запустить туннель.",
            )
            .into(),
            (Some(74), _) => with_diagnostics(
                "You joined AEGIS, but the previous identity could not be removed completely.",
                "Вы присоединились к AEGIS, но прежнее удостоверение не удалось удалить полностью.",
            ),
            (Some(40), code) => invitation_file(code),
            (Some(41), _) => tr(
                "This Mac already has a working AEGIS identity. Join with another invitation only if the person who invited you asked you to.",
                "На этом Mac уже есть рабочее удостоверение AEGIS. Присоединяйтесь по другому приглашению, только если вас об этом попросил пригласивший.",
            )
            .into(),
            (Some(42), _) | (Some(65), Some("session_live")) => tr(
                "Disconnect first, then join.",
                "Сначала отключитесь, затем присоединяйтесь.",
            )
            .into(),
            (Some(43), _) => tr(
                "This invitation has expired or was already used. Ask the person who invited you for a new one.",
                "Срок действия приглашения истёк, или оно уже использовано. Попросите у пригласившего новое.",
            )
            .into(),
            (Some(44), _) => tr(
                "AEGIS could not reach its server. Check the internet connection, then try again with the same invitation file.",
                "AEGIS не удалось связаться со своим сервером. Проверьте подключение к интернету и повторите с тем же файлом приглашения.",
            )
            .into(),
            (Some(45), Some("enroll_certificate_expired")) => tr(
                "The certificate issued for this invitation has already expired. Ask the person who invited you for a new invitation.",
                "Сертификат, выданный по этому приглашению, уже истёк. Попросите у пригласившего новое приглашение.",
            )
            .into(),
            (Some(45), Some("enroll_certificate_not_yet_valid" | "enroll_clock_failed")) => tr(
                "This Mac's date and time look wrong. Turn on Set time and date automatically in System Settings > General > Date & Time, then try again.",
                "Дата и время на этом Mac, похоже, неверны. Включите «Устанавливать дату и время автоматически» в «Системные настройки» > «Основные» > «Дата и время» и повторите.",
            )
            .into(),
            (Some(45), Some("enroll_busy")) => tr(
                "AEGIS is already joining with this invitation. Wait a minute, then try again.",
                "AEGIS уже присоединяется по этому приглашению. Подождите минуту и повторите.",
            )
            .into(),
            (Some(45 | 66), _) => with_diagnostics(
                "AEGIS could not prepare this Mac for joining.",
                "AEGIS не удалось подготовить этот Mac к присоединению.",
            ),
            (Some(46), _) => with_diagnostics(
                "The AEGIS server cannot accept this Mac until the person who invited you fixes it there.",
                "Сервер AEGIS не примет этот Mac, пока пригласивший не исправит это на сервере.",
            ),
            (Some(67), _) => tr(
                "No administrator password was entered, so nothing was installed. Choose Join with Invitation again with the same file to finish.",
                "Пароль администратора не введён, поэтому ничего не установлено. Снова выберите «Присоединиться по приглашению…» с тем же файлом, чтобы завершить.",
            )
            .into(),
            (Some(69), _) => tr(
                "The AEGIS network extension is not running. Choose Set Up AEGIS first.",
                "Сетевое расширение AEGIS не запущено. Сначала выберите «Настроить AEGIS…».",
            )
            .into(),
            (Some(65), _) => with_diagnostics(
                "The AEGIS network extension refused the new identity.",
                "Сетевое расширение AEGIS отклонило новое удостоверение.",
            ),
            (Some(75..=77), _) | (None, _) => tr(
                "AEGIS could not confirm the result. Try again with the same invitation file.",
                "AEGIS не удалось подтвердить результат. Повторите с тем же файлом приглашения.",
            )
            .into(),
            (Some(_), _) => with_diagnostics("Joining failed.", "Присоединиться не удалось."),
        }
    }

    /// A provider query (`--profile-terms`, `--status`) that failed.
    pub fn provider(exit: Option<i32>) -> String {
        match exit {
            Some(65) => tr(
                "The AEGIS network extension refused the request. If you have not joined with your invitation yet, do that first; otherwise copy the diagnostics and send them to the person who invited you.",
                "Сетевое расширение AEGIS отклонило запрос. Если вы ещё не присоединились по приглашению, сначала сделайте это; иначе скопируйте диагностику и отправьте её тому, кто вас пригласил.",
            )
            .into(),
            Some(69) => tr(
                "The AEGIS network extension is not running. Choose Finish Setup first.",
                "Сетевое расширение AEGIS не запущено. Сначала выберите «Завершить настройку…».",
            )
            .into(),
            _ => tr(
                "The AEGIS network extension did not answer in time. Try again.",
                "Сетевое расширение AEGIS не ответило вовремя. Повторите попытку.",
            )
            .into(),
        }
    }

    /// `message` and, when the host named one, its code for support.
    pub fn with_code(message: &str, code: Option<&str>) -> String {
        match code {
            Some(code) => format!("{message} ({} {code})", tr("code:", "код:")),
            None => message.to_owned(),
        }
    }

    /// A profile verb (`--save-profile`, `--connect`, `--disconnect`).
    pub fn profile(code: Option<&str>) -> String {
        match code {
            Some("connect_state_refused") => tr(
                "The tunnel is already connecting or connected.",
                "Туннель уже подключается или подключён.",
            )
            .into(),
            Some("existing_profile_not_idle") => tr(
                "Disconnect first, then try again.",
                "Сначала отключитесь, затем повторите.",
            )
            .into(),
            Some("multiple_provider_profiles_refused" | "exact_owned_profile_required") => tr(
                "More than one AEGIS VPN configuration exists. Remove the extra ones in System Settings > VPN, then try again.",
                "Есть несколько конфигураций VPN AEGIS. Удалите лишние в «Системные настройки» > VPN и повторите.",
            )
            .into(),
            Some("operation_expired") => tr(
                "macOS did not answer in time. If it asked to add a VPN configuration, allow it, then try again.",
                "macOS не ответила вовремя. Если она просила добавить конфигурацию VPN, разрешите и повторите.",
            )
            .into(),
            Some("profile_save_failed") => tr(
                "The VPN configuration was not added. Try again and allow it when macOS asks (your password or Touch ID).",
                "Конфигурация VPN не добавлена. Повторите и разрешите, когда macOS спросит (пароль или Touch ID).",
            )
            .into(),
            Some("profile_relay_mismatch") => tr(
                "Your invitation names a different relay than the VPN configuration. Try again; AEGIS updates the configuration.",
                "Ваше приглашение указывает другой сервер, чем конфигурация VPN. Повторите — AEGIS обновит конфигурацию.",
            )
            .into(),
            Some("provider_start_refused") => with_diagnostics(
                "macOS refused to start the tunnel.",
                "macOS отказалась запустить туннель.",
            ),
            _ => with_diagnostics(
                "The VPN configuration could not be used.",
                "Не удалось использовать конфигурацию VPN.",
            ),
        }
    }
}

#[cfg(test)]
#[path = "menu_model_tests.rs"]
mod tests;
