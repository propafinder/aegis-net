//! Общие типы конфигурации (клиент; сервер — свой файл в `aegis-server`).

use crate::masque::DEFAULT_MASQUE_PATH;
use crate::stealth_rotation::{current_unix_secs, surface_epoch, DriftSurface};
use crate::HybridGenevaPolicyRequirements;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Direct,
    Relay,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    /// Optional compositional admission contract; absence preserves existing profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_plan: Option<crate::traffic_privacy::plan::PrivacyPlan>,
    #[serde(default)]
    pub stealth_mode: StealthMode,
    #[serde(default)]
    pub local_stealth_profile: LocalStealthProfile,
    #[serde(default)]
    pub process_alias: Option<String>,
    #[serde(default)]
    pub ingress: IngressSettings,
    #[serde(default = "default_socks")]
    pub socks: SocksSettings,
    #[serde(default)]
    pub direct: DirectSettings,
    #[serde(default)]
    pub relay: RelaySettings,
    /// Presence selects the Windows system IP tunnel. Older clients reject this
    /// field rather than silently downgrading a full tunnel to SOCKS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_tunnel: Option<crate::tunnel_policy::WindowsTunnelSettings>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StealthMode {
    #[default]
    Disabled,
    Balanced,
}

impl StealthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Balanced => "balanced",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalStealthProfile {
    #[default]
    Disabled,
    LocalHardened,
}

impl LocalStealthProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LocalHardened => "local_hardened",
        }
    }
}

fn default_socks() -> SocksSettings {
    SocksSettings {
        listen: "127.0.0.1:0".parse().expect("valid"),
        auth_token: None,
        auth_user: None,
        require_loopback: true,
        allowed_uids: Vec::new(),
        unix_socket: None,
    }
}

fn default_hidden_state_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".aegis")
        .join("state.json")
}

fn default_state_path_literal() -> &'static Path {
    Path::new("~/.cache/aegis/state.json")
}

/// The visible state file that a hardened profile has replaced, if any.
///
/// `apply_local_stealth_profile` redirects the Brain state to a dot-directory
/// so a seized disk shows no `aegis/state.json` activity trail. It only
/// changes where the *next* write goes: a host that ran unhardened first keeps
/// its old file, and that file is exactly the trail the redirect exists to
/// avoid. The fleet client had one dated two days before the live state.
///
/// Returns the stale path only when the config actually resolved to the hidden
/// location, so an operator who set `state_path` by hand is never touched.
pub fn superseded_visible_state_path(state_path: &Path) -> Option<PathBuf> {
    if state_path != default_hidden_state_path() {
        return None;
    }
    let visible = default_state_path();
    visible.exists().then_some(visible)
}

const LOCAL_STEALTH_PROCESS_ALIAS_CATALOG: [&str; 3] =
    ["netd-helper", "sysupdaterd", "cacheagentd"];
const BALANCED_DIRECT_STACK_PROFILE_CATALOG: [&str; 4] =
    ["linux", "macos", "windows11", "android13"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressSettings {
    #[serde(default)]
    pub primary: IngressPrimary,
    #[serde(default = "default_allow_ingress_fallback")]
    pub allow_fallback: bool,
    #[serde(default)]
    pub wide: WideIngressSettings,
}

fn default_allow_ingress_fallback() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IngressPrimary {
    #[default]
    Wide,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WideIngressSettings {
    #[serde(default = "default_wide_ingress_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub platform_backend: WidePlatformBackend,
    #[serde(default)]
    pub rollout_profile: WideRolloutProfile,
    /// Явное ограничение PREROUTING scope для rollout_profile = "prerouting_scoped".
    #[serde(default)]
    pub prerouting_interface: Option<String>,
    #[serde(default = "default_wide_ingress_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_capture_dns")]
    pub capture_dns: bool,
    /// Requested UDP capture contract; non-default values are surfaced early via preflight before a runtime path exists.
    #[serde(default)]
    pub udp_capture_contract: WideUdpCaptureContract,
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
    #[serde(default)]
    pub udp_preview_ports: Vec<u16>,
    #[serde(default)]
    pub default_mark: u32,
    /// Windows WFP proof-only target for the controlled TCP MVP. When set with
    /// platform_backend="windows_wfp_ale", the Windows wide listener maps every
    /// accepted redirected TCP stream to this original destination.
    #[serde(default)]
    pub controlled_tcp_target: Option<SocketAddr>,
    /// Optional hostname for the single controlled Windows target. This is
    /// operator input, never automatic DNS recovery or a multi-target mapping.
    #[serde(default)]
    pub controlled_tcp_target_host: Option<String>,
    /// DNS preview fake-IP listener. When `Some(addr)`, aegis-client spawns a
    /// synthetic DNS server that responds to A queries with fake IPs from
    /// `dns_preview_fake_ip_pool`; the subsequent TCP connect to that fake IP is
    /// captured by the wide REDIRECT and the hostname is recovered from the shared
    /// FakeIpMap (see wide::linux). This is the working DNS-under-wide path used by
    /// --dns=preview, and it does NOT depend on `capture_dns` (which only governs
    /// the separate, redirect-fragile UDP/53 socket path). Default None (disabled).
    /// Typical operator value: `"127.0.0.1:53"` (requires stopping systemd-resolved).
    #[serde(default)]
    pub dns_preview_listen: Option<SocketAddr>,
    /// Fake-IP pool used by the DNS preview server. CIDR string.
    /// Default `198.18.0.0/15` (RFC 2544 reserved benchmark range, not
    /// routable on the public internet). Operator must ensure this does
    /// not overlap any LAN/VPN route.
    #[serde(default = "default_dns_preview_fake_ip_pool")]
    pub dns_preview_fake_ip_pool: String,
    /// TTL (seconds) for fake-IP DNS A-record responses. Short by design so
    /// stale mappings don't linger; default 60. Operators on stable networks
    /// can raise; lab/research can lower for faster mapping churn observation.
    #[serde(default = "default_dns_preview_fake_ip_ttl_secs")]
    pub dns_preview_fake_ip_ttl_secs: u32,
    /// Upstream resolver reached through the authenticated UDP relay plan for
    /// DNS types the local fake-IP responder cannot synthesize (AAAA, TXT,
    /// SRV, HTTPS, ...). The client never dials this address natively.
    #[serde(default = "default_dns_relay_upstream")]
    pub dns_relay_upstream: SocketAddr,
    /// When true, the Linux client also launches the production IPv6 TUN+smoltcp
    /// engine alongside the v4 REDIRECT leg, carrying IPv6 TCP+UDP to the relay
    /// (the only mode where IPv6 is tunnelled rather than fail-closed-blocked).
    /// Gate for the `full-wide-tun` and `full-wide-hybrid-geneva` product modes;
    /// every other mode leaves this false and keeps IPv6 fail-closed. Default
    /// false.
    #[serde(default)]
    pub ipv6_tun_carried: bool,
    /// Loopback port the generic-UDP redirect proxy binds when
    /// `udp_capture_contract = generic_capture_unstable`. The wide firewall
    /// REDIRECTs generic (and, in carry mode, DNS) UDP here; the proxy recovers
    /// the pre-NAT destination via conntrack and carries the datagram over
    /// MASQUE, so generic UDP + QUIC are tunnelled instead of fail-closed. When
    /// `None` the client derives `listen` port + 1. Must match the firewall's
    /// `AEGIS_WIDE_UDP_REDIRECT_PORT`.
    #[serde(default)]
    pub udp_redirect_port: Option<u16>,
}

fn default_wide_ingress_enabled() -> bool {
    true
}

fn default_wide_ingress_listen() -> SocketAddr {
    // Loopback default since v0.3.0: prevents accidental LAN exposure on
    // multihomed VPS hosts where 0.0.0.0:15080 would be reachable from
    // any network neighbour. Operators who want LAN-share scenarios
    // override via config (`[ingress.wide] listen = "0.0.0.0:15080"`).
    "127.0.0.1:15080"
        .parse()
        .expect("valid wide ingress listen")
}

fn default_capture_dns() -> bool {
    // NOTE: this is the *client's* master UDP-capture switch in wide mode (the
    // preflight only reports/permits a UDP capture contract when it is on). It is
    // the effective default only for a config that omits the key; both
    // config.example.toml and install.sh set it explicitly. `capture_dns=true`
    // alone does NOT black-hole DNS -- that only happens if the firewall ALSO
    // REDIRECTs UDP/53 -> WIDE_PORT (a separate `--dns=capture` step), because a
    // plain REDIRECT ruleset has no IP_ORIGDSTADDR recovery. The reliable
    // DNS-under-wide path is instead the fake-IP `dns_preview_listen` server
    // (aegis-wide-enable.sh --dns=preview), which is independent of this flag.
    true
}

fn default_dns_port() -> u16 {
    53
}

fn default_dns_preview_fake_ip_pool() -> String {
    "198.18.0.0/15".to_string()
}

fn default_dns_preview_fake_ip_ttl_secs() -> u32 {
    60
}

fn default_dns_relay_upstream() -> SocketAddr {
    "1.1.1.1:53".parse().expect("valid DNS relay upstream")
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WideUdpCaptureContract {
    #[default]
    PreviewAllowlistOnly,
    GenericCaptureUnstable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WidePlatformBackend {
    #[default]
    Auto,
    LinuxRedirect,
    LinuxTproxy,
    /// Linux NFQUEUE observer backend. Diverts matched packets to a userspace
    /// netfilter queue where AEGIS decodes IPv4/TCP headers, emits a witness
    /// event with the pre-NAT original destination tuple, and ACCEPTs the
    /// packet back to the kernel. This is a complement to [`Self::LinuxTproxy`],
    /// not a replacement: it does not terminate connections in userspace.
    /// Useful for hosts where TPROXY is policy-blocked or where the operator
    /// wants per-packet original-dst witness on top of the regular ingress
    /// path. The runtime consumer (nfnetlink socket) ships in a later batch;
    /// this variant currently activates the packet-decoder + helper script
    /// scaffolding only.
    LinuxNfqueueObserver,
    Windivert,
    WindowsWfpAle,
    MacosPf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WideRolloutProfile {
    #[default]
    OutputOnlySafe,
    PreroutingScoped,
    TransparentPrivileged,
}

impl Default for IngressSettings {
    fn default() -> Self {
        Self {
            primary: IngressPrimary::default(),
            allow_fallback: default_allow_ingress_fallback(),
            wide: WideIngressSettings::default(),
        }
    }
}

impl Default for WideIngressSettings {
    fn default() -> Self {
        Self {
            enabled: default_wide_ingress_enabled(),
            platform_backend: WidePlatformBackend::default(),
            rollout_profile: WideRolloutProfile::default(),
            prerouting_interface: None,
            listen: default_wide_ingress_listen(),
            capture_dns: default_capture_dns(),
            udp_capture_contract: WideUdpCaptureContract::default(),
            dns_port: default_dns_port(),
            udp_preview_ports: Vec::new(),
            default_mark: 0,
            controlled_tcp_target: None,
            controlled_tcp_target_host: None,
            dns_preview_listen: None,
            dns_preview_fake_ip_pool: default_dns_preview_fake_ip_pool(),
            dns_preview_fake_ip_ttl_secs: default_dns_preview_fake_ip_ttl_secs(),
            dns_relay_upstream: default_dns_relay_upstream(),
            ipv6_tun_carried: false,
            udp_redirect_port: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksSettings {
    pub listen: SocketAddr,

    /// RFC 1929 username/password auth. When present, the SOCKS5
    /// listener requires `auth_user` (default "aegis") and this token
    /// for connect; method 0x02 is offered. None = legacy no-auth (any
    /// local process can use the SOCKS proxy without credentials).
    /// install.sh client auto-generates a per-install random token so
    /// rogue local processes (same UID, different application) can't
    /// piggyback on the tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,

    /// Optional override for the username (default "aegis").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_user: Option<String>,

    /// Reject connections from non-loopback peers before the SOCKS handshake,
    /// including when `listen` is a wildcard. Default true. This is an address
    /// boundary, not a local process or UID identity check.
    #[serde(default = "default_socks_require_loopback")]
    pub require_loopback: bool,

    /// Reserved UID policy. Non-empty lists are rejected because the current
    /// TCP listener cannot authenticate a peer UID. Empty means no UID gate;
    /// use `auth_token` to require SOCKS credentials.
    #[serde(default)]
    pub allowed_uids: Vec<u32>,

    /// Reserved UNIX socket listener. Any configured path is rejected until
    /// a listener with an enforceable peer-identity policy is implemented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_socket: Option<std::path::PathBuf>,
}

impl SocksSettings {
    pub fn validate_tcp_policy(&self) -> Result<(), String> {
        if !self.allowed_uids.is_empty() {
            return Err(
                "socks.allowed_uids is unsupported by the TCP listener; use SOCKS authentication"
                    .into(),
            );
        }
        if self.unix_socket.is_some() {
            return Err(
                "socks.unix_socket is unsupported; no UNIX socket listener is implemented".into(),
            );
        }
        Ok(())
    }
}

fn default_socks_require_loopback() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelTransportFamily {
    LegacyTls,
    HttpsWs,
    GrpcStream,
    GrpcDatagram,
    MasqueDerived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WireMimicryMode {
    #[default]
    Disabled,
    /// Strict: requires capture-backed TTL observation (prior SYN-ACK).
    /// Refuses to fire preface on cold state, emits
    /// `mimicry_capability_wire_activation_reason=capture_backed_ttl_missing`.
    /// Protective default — no strategy leak from guessed TTL but no
    /// wire preface on relay-primarily deployments где observer never warms.
    LinuxExperimentalTtlPreface,
    /// Cold-start permissive: uses `SAFE_DEFAULT_COLD_START_TTL` (Linux
    /// kernel default = 64) when capture-backed TTL is absent, emits
    /// distinctive `activation_reason=cold_start_safe_default_ttl` и
    /// `runtime_slice=linux_experimental_ipv4_ttl_preface_cold_start`
    /// чтобы telemetry могла отличить cold-start preface от capture-backed.
    /// When observer does provide a hint, this mode behaves identically к
    /// strict `LinuxExperimentalTtlPreface` (observed > default).
    /// v0.1.2 lift для A4 hostile-path chicken-and-egg resolution.
    LinuxExperimentalTtlPrefaceSafeDefaultCold,
    /// Practical wire mimicry without raw caps: per-session sampled TCP
    /// socket options (IP_TTL, SO_SNDBUF, TCP_NODELAY) applied before TLS
    /// handshake. Each session draws fresh values from plausible OS-family
    /// distributions — observed packets therefore carry per-session TTL
    /// variation rather than a single canonical Linux 64. Activates whenever
    /// the configured mode is `soft_wire_socket_options`; no CAP_NET_RAW
    /// or CAP_NET_ADMIN required. Designed for relay-mode sessions where
    /// the TCP-layer fingerprint is observable to middleboxes between
    /// client and relay.
    SoftWireSocketOptions,
}

impl WireMimicryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LinuxExperimentalTtlPreface => "linux_experimental_ttl_preface",
            Self::LinuxExperimentalTtlPrefaceSafeDefaultCold => {
                "linux_experimental_ttl_preface_safe_default_cold"
            }
            Self::SoftWireSocketOptions => "soft_wire_socket_options",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayTlsBackend {
    /// Rustls TLS backend, used by enrolled-device/ECH profiles and by builds
    /// without the `chrome-like-tls` feature. It does not claim Chrome JA4 parity.
    Rustls,
    /// Chrome-class ClientHello via the AWS-LC (BoringSSL-family) backend:
    /// GREASE + extension permutation + X25519MLKEM768 groups + brotli cert
    /// compression. Historical canonical JA4 observations cover named builds,
    /// not every HTTP identity or complete session. The policy User-Agent and
    /// measured browser version can differ. This is the configuration default;
    /// builds without `chrome-like-tls` use rustls at connect time, and enrolled
    /// profiles select rustls explicitly (see `relay::tls_backend`).
    #[default]
    ChromeLikeExperimental,
}

impl RelayTlsBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rustls => "rustls",
            Self::ChromeLikeExperimental => "chrome_like_experimental",
        }
    }

    /// Do we claim this backend is indistinguishable from a browser for a whole
    /// SESSION — not just at the ClientHello?
    ///
    /// Deliberately `false`, and it should stay that way until each item below
    /// has a wire artifact. It is not a statement that mimicry is broken; it is
    /// the difference between "our ClientHello is Chrome's" and "everything we
    /// put on the wire is Chrome's".
    ///
    /// Historical scoped observations, NOT sufficient on their own:
    /// - Canonical ClientHello JA4 equals the measured Chrome 151 value
    ///   (`t13d1516h2_8daaf6152771_806a8c22fdea`), including the ML-DSA
    ///   signature algorithms — `artifacts/live/2026-08-10/chrome-canonical-ja4-parity`,
    ///   guarded by `scripts/test-chrome-canonical-ja4-parity-contract.sh`.
    ///
    /// - August 11 QUIC JA4 and HTTP/2 SETTINGS/pseudo-header observations are
    ///   retained in `artifacts/live/2026-08-11/quic-masque-ja4-parity` and
    ///   `http2-settings-vs-chrome`. The SETTINGS comparison is NOT MATCHING,
    ///   not a parity observation. Neither artifact certifies enrolled profiles,
    ///   every current feature build, QUIC transport parameters or Initial shape.
    ///
    /// Still unproven, each of which can separate us from a browser:
    /// - HTTP/2 SETTINGS parity, complete HTTP identity/ClientHello coherence
    ///   and all carrier variants.
    /// - QUIC transport parameters and packet/Initial behavior beyond JA4.
    /// - Session shape over time: packet sizes, inter-arrival timing, and the
    ///   request/response rhythm. `witness_indistinguishability_score` is the
    ///   instrument for this and it has not been re-run since the scorer was
    ///   fixed, so the matrix currently carries no valid value.
    ///
    /// Flipping this to `true` is a public claim about what a censor cannot
    /// see. A matching JA4 alone cannot justify that whole-session claim.
    pub fn browser_identical_claimed(self) -> bool {
        false
    }

    /// True when this backend emits a browser-class ClientHello (the JA4 of a
    /// real browser). When it does, the HTTP identity carried over the same
    /// connection (User-Agent, Accept-Language) MUST be coherent with that
    /// browser — otherwise a censor sees an impossible pair (e.g. a Chrome JA4
    /// under a `curl/8.7.1` User-Agent), which is a reliable relay detector.
    /// The relay session-profile builder consults this to force a coherent
    /// browser HTTP identity instead of an arbitrary catalog User-Agent.
    pub fn is_browser_class(self) -> bool {
        match self {
            Self::Rustls => false,
            Self::ChromeLikeExperimental => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSettings {
    /// Opt-in recent-observation route learning. Missing preserves the existing Brain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_routes: Option<crate::brain::recent_routes::RecentRoutesSettings>,
    /// Explicit consent to retain per-target learning on disk; relay mode remains RAM-only.
    #[serde(default)]
    pub persist_state: bool,
    #[serde(default = "default_state_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_strategies")]
    pub strategies: Vec<String>,
    #[serde(default = "default_epsilon")]
    pub epsilon: f64,
    #[serde(default = "default_first_timeout_ms")]
    pub first_chunk_timeout_ms: u64,
    /// Порог "заморозки" сессии: если после отправки >= N байт всё замирает, это считается freeze.
    #[serde(default = "default_freeze_threshold_bytes")]
    pub freeze_threshold_bytes: usize,
    /// Порог деградировавшего успеха: latency выше этого значения считается `SuccessDegraded`.
    #[serde(default = "default_degraded_latency_ms")]
    pub degraded_latency_ms: u64,
    /// Evolved Geneva strategy, in the Geneva DSL, e.g.
    /// `[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4}(),)-| \/`.
    ///
    /// When set, the `geneva` strategy becomes selectable and executes this
    /// program as its decoy plan (see `strategies::geneva`). Requires raw IPv4
    /// plus exact TCP sequence numbers, so the planner filters it out on hosts
    /// without `raw-socket` + CAP_NET_RAW/CAP_NET_ADMIN rather than pretending it
    /// is active. A syntactically valid program with no rules is rejected at load
    /// rather than silently applying no evasion. The live bridge accepts only
    /// the subset it can serialize exactly; unsupported triggers/fields and
    /// programs with no executable decoy effect fail configuration loading.
    #[serde(default)]
    pub geneva_strategy: Option<String>,
    /// Marks the explicit `full-wide-hybrid-geneva` runtime contract. This is
    /// deliberately separate from merely configuring a Geneva strategy: when
    /// enabled, startup validates the complete fail-closed route contour
    /// (Geneva-only direct plan, Auto handoff, gRPC TCP relay and MASQUE UDP).
    #[serde(default)]
    pub hybrid_geneva: bool,
    /// Вставка GREASE в ClientHello (меняет длину записи).
    #[serde(default)]
    pub tls_grease: bool,
    /// Случайная смена регистра символов в SNI.
    #[serde(default)]
    pub sni_case_obfuscate: bool,
    /// Подмена hostname в SNI на заданную строку (произвольная длина; после GREASE/opaque, до Lua chunk).
    #[serde(default)]
    pub tls_sni_replace: Option<String>,
    /// Расширение 0xFAC7 с SHA256(secret)[:16], secret из `AEGIS_OPAQUE_SECRET`.
    #[serde(default)]
    pub inject_opaque_extension: bool,
    /// JSON-профиль IPG/джиттера для Ghost-LURK (`ghost_lurk.rs`).
    #[serde(default)]
    pub ghost_profile: Option<PathBuf>,
    /// Джиттер Ghost-LURK перед каждой попыткой стратегии (новое TCP).
    #[serde(default = "default_ghost_jitter_before_attempt")]
    pub ghost_jitter_before_attempt: bool,
    /// Профиль TCP до connect: `default`, `windows11`, `android13`, `linux`, `macos`.
    #[serde(default)]
    pub stack_profile: Option<String>,
    /// Отдельный packet/wire contour поверх userspace mimicry.
    #[serde(default)]
    pub wire_mimicry_mode: WireMimicryMode,
    /// Lua-скрипт с глобальной `order(preferred, ip_ver)` — переупорядочивание после Brain (нужен `--features lua`).
    #[serde(default)]
    pub lua_order_script: Option<PathBuf>,
    /// Lua-скрипт с `mutate_chunk(data, ip_ver)` — правка первого буфера после встроенных TLS-опций.
    #[serde(default)]
    pub lua_chunk_script: Option<PathBuf>,
}

fn default_state_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("aegis")
        .join("state.json")
}

fn default_strategies() -> Vec<String> {
    vec!["multisplit".into(), "passthrough".into()]
}

fn default_epsilon() -> f64 {
    0.1
}

fn default_first_timeout_ms() -> u64 {
    8000
}

fn default_freeze_threshold_bytes() -> usize {
    16 * 1024
}

fn default_degraded_latency_ms() -> u64 {
    5000
}

fn default_ghost_jitter_before_attempt() -> bool {
    true
}

impl Default for DirectSettings {
    fn default() -> Self {
        Self {
            recent_routes: None,
            persist_state: false,
            state_path: default_state_path(),
            strategies: default_strategies(),
            epsilon: default_epsilon(),
            first_chunk_timeout_ms: default_first_timeout_ms(),
            freeze_threshold_bytes: default_freeze_threshold_bytes(),
            degraded_latency_ms: default_degraded_latency_ms(),
            geneva_strategy: None,
            hybrid_geneva: false,
            tls_grease: false,
            sni_case_obfuscate: false,
            tls_sni_replace: None,
            inject_opaque_extension: false,
            ghost_profile: None,
            ghost_jitter_before_attempt: default_ghost_jitter_before_attempt(),
            stack_profile: None,
            wire_mimicry_mode: WireMimicryMode::Disabled,
            lua_order_script: None,
            lua_chunk_script: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEndpointBanditSettings {
    pub algorithm: crate::brain::recent_routes::paper_bandit::PaperAlgorithm,
    pub max_profiles: usize,
    pub max_contexts_per_profile: usize,
    pub pre_auth_block_ms: u64,
    /// Operator-declared conditional giant-component/bijective dependency policy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_dependency_policy"
    )]
    pub dependency_policy: Option<crate::research_topology::LiveDependencyPolicy>,
}
fn deserialize_dependency_policy<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::research_topology::LiveDependencyPolicy>, D::Error> {
    crate::research_topology::LiveDependencyPolicy::deserialize(deserializer).map(Some)
}
impl RelayEndpointBanditSettings {
    pub fn validate(&self, relay: &RelaySettings) -> Result<(), String> {
        self.algorithm.validate()?;
        if let Some(policy) = &self.dependency_policy {
            policy
                .validate(relay.endpoints.len())
                .map_err(|e| e.to_string())?;
        }
        if !(1..=16).contains(&self.max_profiles)
            || !(1..=64).contains(&self.max_contexts_per_profile)
            || !(1..=60_000).contains(&self.pre_auth_block_ms)
            || !(2..=16).contains(&relay.endpoints.len())
            || relay.inner_tls.is_none()
            || relay.masque_server.is_some()
            || relay.masque_server_name.is_some()
            || !(1..=60_000).contains(&relay.connect_timeout_ms)
            || !relay.auth_token.is_empty()
            || relay.server != relay.endpoints[0].server
            || relay.server_name != relay.endpoints[0].server_name
        {
            return Err("endpoint bandit requires a bounded explicit device-TLS pool".into());
        }
        let mut pins = std::collections::BTreeSet::new();
        for endpoint in &relay.endpoints {
            let address: std::net::SocketAddr = endpoint
                .server
                .parse()
                .map_err(|_| "endpoint bandit requires numeric socket pins".to_owned())?;
            if address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || !pins.insert(address)
                || endpoint.server_name.is_empty()
                || endpoint.server_name.len() > 253
                || rustls::pki_types::ServerName::try_from(endpoint.server_name.clone()).is_err()
                || endpoint.masque_server.is_some()
                || endpoint.masque_server_name.is_some()
            {
                return Err("endpoint bandit pin or pool identity refused".into());
            }
        }
        Ok(())
    }
}

/// Trust selection used only by MASQUE/QUIC. TCP relay trust is unchanged.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MasqueTrustMode {
    /// Backward-compatible platform trust plus an optional configured CA.
    #[default]
    SystemAndConfiguredCa,
    /// Require a usable configured CA and exclude platform trust anchors.
    ConfiguredCaOnly,
}

impl MasqueTrustMode {
    fn is_legacy(&self) -> bool {
        *self == Self::SystemAndConfiguredCa
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySettings {
    /// Explicit authenticated H2 route order. Other carrier families retain
    /// their separate profile admission until their trust models can compose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_program: Option<crate::carrier_program::CarrierProgramSettings>,
    /// Explicit endpoint learning; absent preserves pool order and allocates no state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_bandit: Option<RelayEndpointBanditSettings>,
    /// Ordered carrier failover across the explicit endpoint pool (carrier
    /// program D3). Absent preserves the fixed per-session pool order. It
    /// requires device inner TLS, two or more numeric pool endpoints and no
    /// endpoint bandit; it never adds a carrier or a native-egress outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_failover: Option<crate::brain::carrier_failover::CarrierFailoverSettings>,
    /// Explicit paired fixed-frame profile inside device-authenticated gRPC/H2.
    /// Absence preserves the old wire; disagreement never falls back unshaped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_shaping: Option<crate::carrier_runtime::PrivacySettings>,
    /// Explicit private HTTPS carrier policy; inner device authentication remains mandatory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_bridge: Option<crate::https_bridge::ClientSettings>,
    /// Private web-response admission path. The signed route binds public fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_response: Option<crate::web_response_profile::WebResponseSettings>,
    /// Controlled Linux relay-outer Geneva request. Missing means ordinary relay behavior.
    #[serde(default)]
    pub outer_geneva: Option<crate::relay_geneva::RelayOuterGenevaSettings>,
    /// Opt-in authenticated inner channel. The first version requires relay
    /// mode, SOCKS TCP and grpc_stream only; unsupported paths fail closed.
    #[serde(default)]
    pub inner_tls: Option<crate::secure_channel::ClientSettings>,
    pub server: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default)]
    pub endpoints: Vec<RelayEndpointSettings>,
    pub auth_token: String,
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// Pinned, DNS-authenticated binary ECHConfigList for the outer relay name.
    ///
    /// The file contains the base64-decoded `ech` HTTPS/SVCB parameter. Its
    /// presence is an explicit fail-closed request for real RFC 9849 ECH: a
    /// malformed list, unsupported HPKE suite, rejected offer, or backend that
    /// cannot negotiate ECH aborts the connection. It is never treated as
    /// GREASE and never falls back to a clear inner ClientHello.
    #[serde(default)]
    pub ech_config_list: Option<PathBuf>,
    /// Public ECHConfigList embedded by an explicitly pinned device profile.
    /// Mutually exclusive with the file setting; absence preserves legacy TLS.
    /// Decoding and HPKE validation happen before any TLS offer or payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech_config_list_base64: Option<String>,
    #[serde(default = "default_transport_priority")]
    pub transport_priority: Vec<TunnelTransportFamily>,
    /// Optional transport plan used only by UDP relay sessions. When omitted,
    /// UDP keeps the backward-compatible behavior of filtering
    /// `transport_priority` down to UDP-capable families.
    ///
    /// This split is required by hybrid fronted full-wide deployments: TCP can
    /// stay pinned to Cloudflare-compatible `grpc_stream`, while UDP uses a
    /// direct `masque_derived` endpoint without making direct MASQUE eligible
    /// for ordinary TCP sessions.
    #[serde(default)]
    pub udp_transport_priority: Option<Vec<TunnelTransportFamily>>,
    #[serde(default = "default_websocket_path")]
    pub websocket_path: String,
    #[serde(default = "default_websocket_path_pool")]
    pub websocket_path_pool: Vec<String>,
    #[serde(default = "default_grpc_path")]
    pub grpc_path: String,
    #[serde(default = "default_grpc_path_pool")]
    pub grpc_path_pool: Vec<String>,
    #[serde(default = "default_masque_path")]
    pub masque_path: String,
    #[serde(default = "default_masque_path_pool")]
    pub masque_path_pool: Vec<String>,
    /// Optional QUIC/H3 endpoint for `CONNECT`/`CONNECT-UDP`; defaults to `server`.
    #[serde(default)]
    pub masque_server: Option<String>,
    /// TLS/HTTP authority used only for the direct MASQUE endpoint. When
    /// omitted, clients retain the backward-compatible relay `server_name`.
    /// Hybrid fronting needs this split because the TCP and direct UDP legs can
    /// present certificates for different names.
    #[serde(default)]
    pub masque_server_name: Option<String>,
    /// Optional CA bundle used ONLY to validate the direct MASQUE/QUIC endpoint
    /// (`masque_server`), falling back to `ca_cert` when unset. A direct-MASQUE
    /// origin behind Cloudflare presents a CloudFlare Origin CA cert that the
    /// public/`ca_cert` trust does not cover; point this at that origin's CA (e.g.
    /// the CloudFlare Origin Root) so the IPv6/UDP MASQUE leg validates without
    /// broadening trust for the fronted TCP path. Used by `full-wide-tun` IPv6 UDP.
    #[serde(default)]
    pub masque_ca_cert: Option<PathBuf>,
    /// Explicit MASQUE-only trust policy. ConfiguredCaOnly requires a usable
    /// masque_ca_cert (or the existing ca_cert fallback); no platform roots or
    /// broader trust fallback are admitted. Omission retains the legacy union.
    #[serde(default, skip_serializing_if = "MasqueTrustMode::is_legacy")]
    pub masque_trust_mode: MasqueTrustMode,
    #[serde(default = "default_tunnel_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// QUIC keepalive cadence for idle MASQUE TCP/UDP sessions. `0` disables keepalive.
    #[serde(default = "default_masque_keep_alive_interval_ms")]
    pub masque_keep_alive_interval_ms: u64,
    /// Maximum QUIC idle timeout for MASQUE sessions. `0` disables the timeout.
    #[serde(default = "default_masque_max_idle_timeout_ms")]
    pub masque_max_idle_timeout_ms: u64,
    /// Phase B TLS/browser profile target class used for telemetry and future
    /// ClientHello tuning. This is advisory until a runtime TLS profile adapter
    /// is explicitly enabled.
    #[serde(default)]
    pub tls_profile_target_class: Option<String>,
    /// Runtime TLS backend for relay TCP transports.
    ///
    /// Configuration defaults to `chrome_like_experimental`; availability
    /// depends on build features. Enrolled profiles and ECH require rustls.
    /// Builds without `chrome-like-tls` use rustls at connection time. Neither
    /// selection claims whole-session browser indistinguishability.
    #[serde(default)]
    pub tls_backend: RelayTlsBackend,
    /// Relay-side wire mimicry mode. Defaults to `Disabled` for backwards
    /// compatibility. `SoftWireSocketOptions` activates per-session TCP
    /// socket option sampling (IP_TTL, SO_SNDBUF, TCP_NODELAY) — no raw
    /// caps required. `LinuxExperimentalTtlPreface*` variants stay
    /// reserved for the direct-path TCP_REPAIR preface and currently
    /// no-op in the relay path (they need raw caps the relay client
    /// service does not run with).
    #[serde(default)]
    pub wire_mimicry_mode: WireMimicryMode,
    #[serde(default)]
    pub policy: RelayPolicySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayEndpointSettings {
    pub server: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default)]
    pub masque_server: Option<String>,
    #[serde(default)]
    pub masque_server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayPolicySettings {
    #[serde(default = "default_rotate_transports")]
    pub rotate_transports_per_session: bool,
    #[serde(default = "default_max_transport_attempts")]
    pub max_transport_attempts: usize,
    #[serde(default = "default_write_chunk_size")]
    pub write_chunk_size: usize,
    #[serde(default)]
    pub inter_chunk_delay_ms: u64,
    #[serde(default = "default_drift_epoch_secs")]
    pub drift_epoch_secs: u64,
    /// Optional relay surface profile pin for provider-specific live proofs or
    /// deployments that must use one known-good fronted contour. Invalid pins
    /// are ignored by the client and fall back to the normal drift catalog.
    #[serde(default)]
    pub surface_profile_id: Option<String>,
    /// Adaptive transport ordering: when true (and enough live outcomes have
    /// accumulated), Brain selection influences the per-session transport order.
    /// The legacy sample guard counts strategy trials across keys, not trials
    /// for this target. Baseline strategy selection and translation into relay
    /// families have separate hard-block/fallback policies. The configured
    /// order is retained while the cold-state minimum-sample guard applies;
    /// this setting does not prove per-target learning or exclusion.
    #[serde(default = "default_adaptive_transport")]
    pub adaptive_transport: bool,
}

fn default_server_name() -> String {
    "localhost".into()
}

fn default_transport_priority() -> Vec<TunnelTransportFamily> {
    // LegacyTls is NOT in the default plan.
    //
    // It offers ALPN `http/1.1` alone (relay::surface::legacy_tls_wire_alpn),
    // putting JA4 t13d1515h1_8daaf6152771_e4c2b8c727f2 on the wire — plainly
    // not Chrome, whose offer is `h2,http/1.1`. Measured on the fleet: under
    // the middlebox_delay profile roughly one connection in six fell through to
    // LegacyTls and emitted that fingerprint
    // (artifacts/live/2026-08-11/fingerprint-oracle-root-cause).
    //
    // That made it adversary-triggerable: induce loss or reorder, watch HttpsWs
    // fail, and the fallback hands the censor an identifiable ClientHello. A
    // tell the adversary can switch on is worse than a static one.
    //
    // It cannot simply offer Chrome's list instead — the relay routes h2 to the
    // gRPC handler, so a LegacyTls connection that negotiated h2 would reach
    // the wrong one. GrpcStream already covers the fallback role with a
    // scoped Chrome-like ClientHello offer, not proven byte identity or
    // whole-session parity. Dropping LegacyTls removes this particular tell
    // rather than narrowing it.
    //
    // Operators talking to a relay too old for the h2 paths put it back
    // explicitly via `relay.transport_priority`.
    vec![
        TunnelTransportFamily::HttpsWs,
        TunnelTransportFamily::GrpcStream,
        TunnelTransportFamily::MasqueDerived,
    ]
}

/// Shared default WebSocket primary mount. Explicit configuration overrides it.
pub const DEFAULT_WEBSOCKET_PATH: &str = "/socket";
/// Compatibility mounts used alongside the default WebSocket primary.
pub const DEFAULT_WEBSOCKET_PATH_POOL: [&str; 3] = ["/ws", "/realtime/connect", "/aegis/ws"];
/// Shared default gRPC primary mount. Explicit configuration overrides it.
pub const DEFAULT_GRPC_PATH: &str = "/rpc.Tunnel/Open";
/// Compatibility mounts used alongside the default gRPC primary.
pub const DEFAULT_GRPC_PATH_POOL: [&str; 3] = [
    "/cdn.tunnel.v1.Session/Open",
    "/grpc.gateway.v1.Proxy/Connect",
    "/aegis.tunnel.v1.TunnelService/Open",
];

fn default_websocket_path() -> String {
    // The primary is neutral, but the compatibility pool still includes a
    // product-branded path. A fresh install is not guaranteed brand-free when
    // runtime selection or an installer uses that pool.
    DEFAULT_WEBSOCKET_PATH.into()
}

fn default_websocket_path_pool() -> Vec<String> {
    // Path pool: three entries total, including two CDN/realtime conventions
    // and the legacy AEGIS-branded path so per-session selection still
    // hits deployed servers running older defaults.
    DEFAULT_WEBSOCKET_PATH_POOL
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_grpc_path() -> String {
    // The neutral primary does not remove the product-branded compatibility
    // mount. Installer choices and pool selection are separate policies.
    DEFAULT_GRPC_PATH.into()
}

fn default_grpc_path_pool() -> Vec<String> {
    // Path pool: three plausible gRPC service mounts (cdn-session, grpc-web
    // bridge, and the legacy AEGIS-named service path). The catalog is shared
    // and selectable; it is not a per-deployment unprobeable path guarantee.
    DEFAULT_GRPC_PATH_POOL
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_tunnel_connect_timeout_ms() -> u64 {
    5000
}

fn default_masque_keep_alive_interval_ms() -> u64 {
    10_000
}

fn default_masque_max_idle_timeout_ms() -> u64 {
    120_000
}

fn default_masque_path() -> String {
    DEFAULT_MASQUE_PATH.into()
}

fn default_masque_path_pool() -> Vec<String> {
    // Path pool expansion: three MASQUE CONNECT-UDP mounts. The canonical
    // RFC 9298 `.well-known/masque/udp` is the primary (see `default_masque_path`);
    // this pool covers alternate mounts that deployments use for A/B testing
    // and zone separation so per-target fingerprinting cannot lock on a
    // single MASQUE path string.
    vec![
        "/.well-known/masque/connect-udp".into(),
        "/masque/v1/udp".into(),
        "/relay/datagram".into(),
    ]
}

fn default_rotate_transports() -> bool {
    true
}

fn default_max_transport_attempts() -> usize {
    4
}

fn default_drift_epoch_secs() -> u64 {
    900
}

fn default_write_chunk_size() -> usize {
    16 * 1024
}

impl Default for RelayPolicySettings {
    fn default() -> Self {
        Self {
            rotate_transports_per_session: default_rotate_transports(),
            max_transport_attempts: default_max_transport_attempts(),
            write_chunk_size: default_write_chunk_size(),
            inter_chunk_delay_ms: 0,
            drift_epoch_secs: default_drift_epoch_secs(),
            surface_profile_id: None,
            adaptive_transport: default_adaptive_transport(),
        }
    }
}

fn default_adaptive_transport() -> bool {
    true
}

impl RelaySettings {
    pub fn validate_inner_tls_transport(&self) -> Result<(), String> {
        if let Some(program) = &self.carrier_program {
            program.validate(self)?;
        }
        if self.masque_trust_mode == MasqueTrustMode::ConfiguredCaOnly
            && self
                .masque_ca_cert
                .as_deref()
                .or(self.ca_cert.as_deref())
                .is_none_or(|path| path.as_os_str().is_empty())
        {
            return Err("configured_ca_only MASQUE requires a configured CA file".into());
        }
        if let Some(bandit) = &self.endpoint_bandit {
            bandit.validate(self)?;
        }
        if let Some(failover) = &self.carrier_failover {
            failover.validate()?;
            if self.inner_tls.is_none()
                || self.endpoint_bandit.is_some()
                || !(2..=crate::brain::carrier_failover::MAX_CARRIERS)
                    .contains(&self.endpoints.len())
            {
                return Err("carrier failover requires device inner TLS, an explicit pool of 2 to 16 endpoints and no endpoint bandit".into());
            }
        }
        if let Some(shaping) = &self.authenticated_shaping {
            shaping
                .validate()
                .map_err(|_| "invalid authenticated relay shaping profile".to_owned())?;
            if self.inner_tls.is_none() {
                return Err("authenticated relay shaping requires device inner TLS".into());
            }
            if !(1..=60_000).contains(&self.connect_timeout_ms) {
                return Err(
                    "authenticated relay shaping establishment timeout must be 1..60000ms".into(),
                );
            }
        }
        if let Some(bridge) = &self.https_bridge {
            bridge
                .validate()
                .map_err(|_| "invalid HTTPS bridge policy".to_owned())?;
            // A signed carrier program binds this gate only to its typed
            // bridge routes. Direct/fronted attempts must omit the key.
            let scoped_bridge = self
                .carrier_program
                .as_ref()
                .is_some_and(|program| program.bridge.is_some());
            if self.inner_tls.is_none()
                || !self.auth_token.is_empty()
                || (!scoped_bridge
                    && (bridge.validate_authority(&self.server_name).is_err()
                        || self
                            .endpoints
                            .iter()
                            .any(|e| bridge.validate_authority(&e.server_name).is_err())))
            {
                return Err("HTTPS bridge requires device inner TLS, empty legacy token and the pinned authority for every endpoint".into());
            }
        }
        if let Some(web) = &self.web_response {
            web.validate().map_err(str::to_owned)?;
            // Per-attempt copies drop the already validated signed pool. Their
            // exact selected authority still has to match the private policy.
            if self.inner_tls.is_none()
                || !self.auth_token.is_empty()
                || self
                    .carrier_program
                    .as_ref()
                    .is_some_and(|p| p.web_response.is_none())
                || (self.carrier_program.is_none() && web.authority != self.server_name)
            {
                return Err("web-response requires a signed route and device inner TLS".into());
            }
        }
        if self.inner_tls.is_some()
            && (self.transport_priority != [TunnelTransportFamily::GrpcStream]
                || self.ca_cert.is_none()
                || !matches!(
                    self.udp_transport_priority.as_deref(),
                    Some([] | [TunnelTransportFamily::GrpcDatagram])
                )
                || self.connect_timeout_ms == 0
                || self.tls_backend != RelayTlsBackend::Rustls
                || self.wire_mimicry_mode != WireMimicryMode::Disabled)
        {
            return Err("inner TLS requires grpc_stream only, explicit outer ca_cert, UDP disabled or grpc_datagram only, rustls, disabled wire mimicry and a nonzero connect timeout".into());
        }
        Ok(())
    }
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            carrier_program: None,
            endpoint_bandit: None,
            carrier_failover: None,
            authenticated_shaping: None,
            https_bridge: None,
            web_response: None,
            outer_geneva: None,
            inner_tls: None,
            server: "127.0.0.1:8443".into(),
            server_name: default_server_name(),
            endpoints: Vec::new(),
            auth_token: String::new(),
            ca_cert: None,
            ech_config_list: None,
            ech_config_list_base64: None,
            transport_priority: default_transport_priority(),
            udp_transport_priority: None,
            websocket_path: default_websocket_path(),
            websocket_path_pool: default_websocket_path_pool(),
            grpc_path: default_grpc_path(),
            grpc_path_pool: default_grpc_path_pool(),
            masque_path: default_masque_path(),
            masque_path_pool: default_masque_path_pool(),
            masque_server: None,
            masque_server_name: None,
            masque_ca_cert: None,
            masque_trust_mode: MasqueTrustMode::default(),
            connect_timeout_ms: default_tunnel_connect_timeout_ms(),
            masque_keep_alive_interval_ms: default_masque_keep_alive_interval_ms(),
            masque_max_idle_timeout_ms: default_masque_max_idle_timeout_ms(),
            tls_profile_target_class: None,
            tls_backend: RelayTlsBackend::default(),
            wire_mimicry_mode: WireMimicryMode::Disabled,
            policy: RelayPolicySettings::default(),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Direct,
            stealth_mode: StealthMode::default(),
            local_stealth_profile: LocalStealthProfile::default(),
            process_alias: None,
            ingress: IngressSettings::default(),
            socks: default_socks(),
            direct: DirectSettings::default(),
            relay: RelaySettings::default(),
            privacy_plan: None,
            windows_tunnel: None,
        }
    }
}

impl Settings {
    /// Pure admission: invoke before private identity reads, sockets or native policy.
    pub fn validate_privacy_plan(&self) -> Result<(), String> {
        crate::traffic_privacy::plan::admit(self).map(|_| ())
    }

    pub fn validate_ech(&self) -> Result<(), String> {
        if self.relay.ech_config_list.is_some() && self.relay.ech_config_list_base64.is_some() {
            return Err("relay ECH file and inline config are mutually exclusive".into());
        }
        if let Some(encoded) = &self.relay.ech_config_list_base64 {
            if encoded.is_empty() || encoded.len() > 21848 {
                return Err("relay inline ECH config is empty or exceeds its size bound".into());
            }
        }
        if self.relay.ech_config_list.is_none() && self.relay.ech_config_list_base64.is_none() {
            return Ok(());
        }
        match self.relay.tls_backend {
            RelayTlsBackend::Rustls | RelayTlsBackend::ChromeLikeExperimental => {}
        }
        if self.relay.server_name.trim().is_empty()
            || self.relay.server_name.parse::<std::net::IpAddr>().is_ok()
        {
            return Err("relay.ech_config_list requires a DNS relay server_name".into());
        }
        let scoped_fronted = self.relay.carrier_program.as_ref().is_some_and(|program| {
            program.ech_scope == Some(crate::carrier_program::CarrierEchScope::FrontedOnly)
        });
        if scoped_fronted {
            let program = self.relay.carrier_program.as_ref().unwrap();
            program.validate_public(&self.relay)?;
            // The signed FrontedH2 endpoint supplies the ECH authority. It
            // may differ from a direct primary; selection removes the offer
            // from every other role before any socket or private-key I/O.
        } else if self.relay.endpoints.iter().any(|endpoint| {
            endpoint.server_name.trim().is_empty()
                || endpoint.server_name.parse::<std::net::IpAddr>().is_ok()
                || endpoint.server_name != self.relay.server_name
        }) {
            return Err(
                "relay.ech_config_list requires every endpoint to use the same DNS server_name"
                    .into(),
            );
        }
        let tcp_uses_masque = self
            .relay
            .transport_priority
            .contains(&TunnelTransportFamily::MasqueDerived);
        let udp_uses_masque = self
            .relay
            .udp_transport_priority
            .as_deref()
            .unwrap_or(&self.relay.transport_priority)
            .contains(&TunnelTransportFamily::MasqueDerived);
        if tcp_uses_masque || udp_uses_masque {
            let matches_pinned_name = |name: Option<&str>| {
                name.filter(|name| !name.trim().is_empty())
                    .is_none_or(|name| name == self.relay.server_name)
            };
            if !matches_pinned_name(self.relay.masque_server_name.as_deref())
                || self
                    .relay
                    .endpoints
                    .iter()
                    .any(|endpoint| !matches_pinned_name(endpoint.masque_server_name.as_deref()))
            {
                return Err(
                    "relay ECH requires MASQUE endpoints to use the pinned relay DNS server_name"
                        .into(),
                );
            }
        }
        Ok(())
    }

    pub fn validate_inner_tls(&self) -> Result<(), String> {
        self.relay.validate_inner_tls_transport()?;
        if self.relay.inner_tls.is_none() {
            return Ok(());
        }
        if !matches!(self.mode, Mode::Relay) {
            return Err("inner TLS requires mode=relay; direct/auto fallback is forbidden".into());
        }
        Ok(())
    }

    pub fn materialize_stealth_profiles(&mut self) {
        let now_secs = current_unix_secs();
        self.apply_stealth_mode_with_now(now_secs);
        self.apply_local_stealth_profile_with_now(now_secs);
    }

    /// Validate the explicit Geneva hybrid runtime contract. Ordinary direct,
    /// relay and Auto configurations are untouched unless `hybrid_geneva=true`.
    pub fn validate_hybrid_geneva(&self) -> Result<(), String> {
        if !self.direct.hybrid_geneva {
            return Ok(());
        }

        if !matches!(self.mode, Mode::Auto) {
            return Err("direct.hybrid_geneva requires mode=auto for typed relay handoff".into());
        }
        if self
            .direct
            .geneva_strategy
            .as_deref()
            .is_none_or(|strategy| strategy.trim().is_empty())
        {
            return Err("direct.hybrid_geneva requires a non-empty geneva_strategy".into());
        }
        if self.direct.strategies.as_slice() != ["geneva"] {
            return Err(
                "direct.hybrid_geneva requires strategies=[\"geneva\"] exactly; native passthrough and alternate direct routes are forbidden"
                    .into(),
            );
        }

        let tcp_grpc_only =
            self.relay.transport_priority.as_slice() == [TunnelTransportFamily::GrpcStream];
        let udp_masque_primary = matches!(
            self.relay.udp_transport_priority.as_deref(),
            Some([TunnelTransportFamily::MasqueDerived])
                | Some([
                    TunnelTransportFamily::MasqueDerived,
                    TunnelTransportFamily::GrpcDatagram
                ])
        );
        HybridGenevaPolicyRequirements {
            grpc_relay_configured: tcp_grpc_only
                && !self.relay.server.trim().is_empty()
                && !self.relay.server_name.trim().is_empty()
                && !self.relay.auth_token.trim().is_empty(),
            masque_relay_configured: udp_masque_primary
                && self
                    .relay
                    .masque_server
                    .as_deref()
                    .is_some_and(|server| !server.trim().is_empty()),
            passthrough_enabled: self
                .direct
                .strategies
                .iter()
                .any(|strategy| strategy == "passthrough"),
        }
        .validate()
        .map_err(|error| error.to_string())?;

        Ok(())
    }

    pub fn apply_stealth_mode(&mut self) {
        self.apply_stealth_mode_with_now(current_unix_secs());
    }

    fn apply_stealth_mode_with_now(&mut self, now_secs: u64) {
        if !matches!(self.stealth_mode, StealthMode::Balanced) {
            return;
        }
        if matches!(self.local_stealth_profile, LocalStealthProfile::Disabled) {
            self.local_stealth_profile = LocalStealthProfile::LocalHardened;
        }
        if self.direct.stack_profile.is_none() {
            self.direct.stack_profile = Some(
                select_balanced_direct_stack_profile(self.relay.policy.drift_epoch_secs, now_secs)
                    .to_string(),
            );
        }
    }

    pub fn apply_local_stealth_profile(&mut self) {
        self.apply_local_stealth_profile_with_now(current_unix_secs());
    }

    fn apply_local_stealth_profile_with_now(&mut self, now_secs: u64) {
        if !matches!(
            self.local_stealth_profile,
            LocalStealthProfile::LocalHardened
        ) {
            return;
        }
        self.ingress.allow_fallback = false;
        if self.process_alias.is_none() {
            self.process_alias = Some(
                select_local_stealth_process_alias(self.relay.policy.drift_epoch_secs, now_secs)
                    .to_string(),
            );
        }
        if self.direct.state_path == default_state_path()
            || self.direct.state_path == default_state_path_literal()
        {
            self.direct.state_path = default_hidden_state_path();
        }
    }
}

#[cfg(test)]
mod ech_config_tests {
    use super::*;

    #[test]
    fn ech_accepts_masque_with_the_pinned_dns_name_for_tcp_and_udp() {
        let mut settings = Settings::default();
        settings.relay.ech_config_list_base64 = Some("AQID".into());
        settings.relay.tls_backend = RelayTlsBackend::Rustls;
        settings.relay.server_name = "relay.example".into();
        settings.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        settings
            .validate_ech()
            .expect("required QUIC ECH is supported");
        settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings
            .validate_ech()
            .expect("UDP MASQUE retains required ECH");
    }

    #[test]
    fn inline_ech_is_explicit_bounded_and_mutually_exclusive_with_files() {
        let mut settings = Settings::default();
        settings.relay.ech_config_list_base64 = Some("AQID".into());
        settings.relay.tls_backend = RelayTlsBackend::Rustls;
        settings.relay.server_name = "relay.example".into();
        settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        settings.validate_ech().unwrap();
        settings.relay.ech_config_list = Some("ech.bin".into());
        assert!(settings.validate_ech().is_err());
        settings.relay.ech_config_list = None;
        settings.relay.ech_config_list_base64 = Some(String::new());
        assert!(settings.validate_ech().is_err());
        settings.relay.ech_config_list_base64 = Some("A".repeat(21849));
        assert!(settings.validate_ech().is_err());
        settings.relay.ech_config_list_base64 = Some("AQID".into());
        settings.relay.tls_backend = RelayTlsBackend::ChromeLikeExperimental;
        settings
            .validate_ech()
            .expect("chrome-like TLS carries ECH on AWS-LC");
        settings.relay.tls_backend = RelayTlsBackend::Rustls;
        settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings.validate_ech().unwrap();
    }

    #[test]
    fn ech_requires_rustls_and_a_dns_inner_name() {
        let mut settings = Settings::default();
        settings.relay.ech_config_list = Some("ech.bin".into());
        settings.relay.tls_backend = RelayTlsBackend::Rustls;
        settings.relay.server_name = "relay.example".into();
        settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        settings.validate_ech().unwrap();

        settings.relay.server_name = "192.0.2.10".into();
        assert!(settings.validate_ech().is_err());
        settings.relay.server_name = "relay.example".into();
        settings.relay.tls_backend = RelayTlsBackend::ChromeLikeExperimental;
        settings
            .validate_ech()
            .expect("chrome-like TLS carries ECH on AWS-LC");

        settings.relay.tls_backend = RelayTlsBackend::Rustls;
        settings.relay.endpoints.push(RelayEndpointSettings {
            server: "192.0.2.20:443".into(),
            server_name: "different.example".into(),
            masque_server: None,
            masque_server_name: None,
        });
        assert!(settings.validate_ech().is_err());
    }

    #[test]
    fn ech_masque_rejects_global_and_pool_name_drift() {
        let mut settings = Settings::default();
        settings.relay.ech_config_list = Some("ech.bin".into());
        settings.relay.tls_backend = RelayTlsBackend::Rustls;
        settings.relay.server_name = "relay.example".into();

        settings.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        settings.validate_ech().unwrap();
        settings.relay.masque_server_name = Some("different.example".into());
        assert!(settings.validate_ech().is_err());
        settings.relay.masque_server_name = Some("relay.example".into());
        settings.validate_ech().unwrap();
        settings.relay.endpoints.push(RelayEndpointSettings {
            server: "192.0.2.20:443".into(),
            server_name: "relay.example".into(),
            masque_server: None,
            masque_server_name: Some("different.example".into()),
        });
        assert!(settings.validate_ech().is_err());
        settings.relay.endpoints[0].masque_server_name = None;

        settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings.validate_ech().unwrap();
        settings.relay.masque_server_name = Some("192.0.2.30".into());
        assert!(settings.validate_ech().is_err());

        settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        settings.validate_ech().unwrap();
    }
}

fn select_local_stealth_process_alias(base_epoch_secs: u64, now_secs: u64) -> &'static str {
    let epoch = surface_epoch(base_epoch_secs, now_secs, DriftSurface::LocalState);
    LOCAL_STEALTH_PROCESS_ALIAS_CATALOG
        [(epoch as usize) % LOCAL_STEALTH_PROCESS_ALIAS_CATALOG.len()]
}

fn select_balanced_direct_stack_profile(base_epoch_secs: u64, now_secs: u64) -> &'static str {
    let epoch = surface_epoch(base_epoch_secs, now_secs, DriftSurface::DirectFingerprint);
    BALANCED_DIRECT_STACK_PROFILE_CATALOG
        [(epoch as usize) % BALANCED_DIRECT_STACK_PROFILE_CATALOG.len()]
}

#[cfg(test)]
mod tests {
    // The default plan must not contain a transport that offers ALPN
    // `http/1.1` alone. LegacyTls does, which puts a non-Chrome JA4
    // (t13d1515h1_...) on the wire, and it was reachable by inducing loss:
    // HttpsWs fails, the planner falls through, the censor gets an
    // identifiable ClientHello. Measured at ~1 connection in 6 under the
    // middlebox_delay netem profile before it was dropped.
    #[test]
    fn default_transport_plan_has_no_http1_only_fallback() {
        let plan = default_transport_priority();
        assert!(
            !plan.contains(&TunnelTransportFamily::LegacyTls),
            "LegacyTls offers ALPN http/1.1 alone; putting it in the default plan gives an \
             adversary who induces loss a way to force a distinguishable ClientHello"
        );
        assert!(
            plan.contains(&TunnelTransportFamily::GrpcStream),
            "something Chrome-shaped has to remain as the fallback after HttpsWs"
        );
    }

    #[test]
    fn relay_config_accepts_independent_udp_transport_plan() {
        let relay: RelaySettings = toml::from_str(
            r#"
server = "front.example.test:443"
server_name = "front.example.test"
auth_token = "contract"
transport_priority = ["grpc_stream"]
udp_transport_priority = ["masque_derived", "grpc_datagram"]
masque_server = "203.0.113.10:443"
masque_server_name = "masque.example.test"
"#,
        )
        .expect("parse hybrid fronted relay settings");

        assert_eq!(
            relay.transport_priority,
            vec![TunnelTransportFamily::GrpcStream]
        );
        assert_eq!(
            relay.udp_transport_priority,
            Some(vec![
                TunnelTransportFamily::MasqueDerived,
                TunnelTransportFamily::GrpcDatagram
            ])
        );
        assert_eq!(
            relay.masque_server_name.as_deref(),
            Some("masque.example.test")
        );
    }

    use super::*;

    #[test]
    fn carrier_failover_requires_enrolled_pool_without_bandit_and_parses_from_toml() {
        let relay: RelaySettings = toml::from_str(
            r#"
server = "192.0.2.10:443"
server_name = "relay.example.test"
auth_token = ""
ca_cert = "/etc/aegis/client/ca.pem"
transport_priority = ["grpc_stream"]
udp_transport_priority = ["grpc_datagram"]
tls_backend = "rustls"

[inner_tls]
server_name = "inner.example.test"
server_ca = "/etc/aegis/client/inner-ca.pem"
cert = "/var/lib/aegis/device.pem"
key = "/var/lib/aegis/device.key"

[[endpoints]]
server = "192.0.2.10:443"
server_name = "relay.example.test"

[[endpoints]]
server = "198.51.100.20:443"
server_name = "edge.example.test"

[carrier_failover]
base_cooldown_ms = 2000
"#,
        )
        .expect("parse enrolled failover pool");
        let failover = relay.carrier_failover.clone().expect("explicit policy");
        assert_eq!(failover.base_cooldown_ms, 2000);
        assert_eq!(
            failover.max_cooldown_ms,
            crate::brain::carrier_failover::CarrierFailoverSettings::default().max_cooldown_ms
        );
        relay.validate_inner_tls_transport().unwrap();

        let mut single = relay.clone();
        single.endpoints.truncate(1);
        assert!(single.validate_inner_tls_transport().is_err());
        let mut legacy = relay.clone();
        legacy.inner_tls = None;
        legacy.transport_priority = default_transport_priority();
        legacy.udp_transport_priority = None;
        assert!(legacy.validate_inner_tls_transport().is_err());
        let mut invalid = relay.clone();
        invalid
            .carrier_failover
            .as_mut()
            .unwrap()
            .degraded_threshold = 0;
        assert!(invalid.validate_inner_tls_transport().is_err());
        let mut absent = relay;
        absent.carrier_failover = None;
        absent.validate_inner_tls_transport().unwrap();
        assert!(!toml::to_string(&absent)
            .unwrap()
            .contains("carrier_failover"));
        assert!(toml::from_str::<RelaySettings>(
            "server = \"x:1\"\nauth_token = \"\"\n[carrier_failover]\nnative_fallback = true\n"
        )
        .is_err());
    }

    #[test]
    fn local_stealth_profile_forces_local_hardening_defaults() {
        let mut cfg = Settings {
            local_stealth_profile: LocalStealthProfile::LocalHardened,
            ..Settings::default()
        };
        cfg.ingress.allow_fallback = true;
        cfg.apply_local_stealth_profile_with_now(10_000);
        assert!(!cfg.ingress.allow_fallback);
        assert!(cfg.process_alias.is_some());
        assert_ne!(cfg.direct.state_path, default_state_path());
        assert_eq!(cfg.direct.state_path, default_hidden_state_path());
    }

    #[test]
    fn superseded_state_path_only_fires_for_the_hidden_default() {
        // An operator who set state_path by hand must never have a file
        // deleted underneath them, however much it looks like the default.
        assert_eq!(
            superseded_visible_state_path(Path::new("/srv/aegis/state.json")),
            None
        );
        assert_eq!(superseded_visible_state_path(&default_state_path()), None);
    }

    #[test]
    fn relay_tls_backend_defaults_to_chrome_like() {
        // JA4 parity vs live Chrome is proven (test-chrome-like-tls-ja4-parity-contract.sh),
        // so the chrome-like backend is now the default; release builds ship the
        // chrome-like-tls feature, and feature-less builds degrade to rustls at
        // connect time (relay::tls_backend). browser_identical_claimed stays a
        // measured claim (false) until a wire-artifact promotes it.
        let cfg = RelaySettings::default();
        assert_eq!(cfg.tls_backend, RelayTlsBackend::ChromeLikeExperimental);
        assert_eq!(cfg.tls_backend.as_str(), "chrome_like_experimental");
    }

    #[test]
    fn relay_tls_backend_accepts_guarded_chrome_like_value() {
        let backend: RelayTlsBackend =
            serde_json::from_str("\"chrome_like_experimental\"").expect("backend");
        assert_eq!(backend, RelayTlsBackend::ChromeLikeExperimental);
        assert_eq!(backend.as_str(), "chrome_like_experimental");
        assert!(!backend.browser_identical_claimed());
    }

    #[test]
    fn local_stealth_profile_preserves_explicit_alias_and_state_path() {
        let mut cfg = Settings {
            local_stealth_profile: LocalStealthProfile::LocalHardened,
            process_alias: Some("manual-agentd".into()),
            ..Settings::default()
        };
        cfg.direct.state_path = PathBuf::from("/tmp/custom-state.json");
        cfg.apply_local_stealth_profile_with_now(10_000);
        assert_eq!(cfg.process_alias.as_deref(), Some("manual-agentd"));
        assert_eq!(
            cfg.direct.state_path,
            PathBuf::from("/tmp/custom-state.json")
        );
    }

    #[test]
    fn local_stealth_alias_selection_is_stable_for_same_window() {
        let a = select_local_stealth_process_alias(900, 10_000);
        let b = select_local_stealth_process_alias(900, 10_030);
        assert_eq!(a, b);
    }

    #[test]
    fn balanced_stealth_mode_enables_local_profile_and_direct_stack_profile() {
        let mut cfg = Settings {
            stealth_mode: StealthMode::Balanced,
            ..Settings::default()
        };
        cfg.apply_stealth_mode_with_now(10_000);
        assert_eq!(
            cfg.local_stealth_profile,
            LocalStealthProfile::LocalHardened
        );
        assert!(cfg.direct.stack_profile.is_some());
    }

    #[test]
    fn balanced_stealth_mode_preserves_explicit_local_profile_and_stack_profile() {
        let mut cfg = Settings {
            stealth_mode: StealthMode::Balanced,
            local_stealth_profile: LocalStealthProfile::LocalHardened,
            ..Settings::default()
        };
        cfg.direct.stack_profile = Some("macos".into());
        cfg.apply_stealth_mode_with_now(10_000);
        assert_eq!(
            cfg.local_stealth_profile,
            LocalStealthProfile::LocalHardened
        );
        assert_eq!(cfg.direct.stack_profile.as_deref(), Some("macos"));
    }

    #[test]
    fn balanced_stack_profile_selection_is_stable_for_same_window() {
        let a = select_balanced_direct_stack_profile(900, 10_000);
        let b = select_balanced_direct_stack_profile(900, 10_030);
        assert_eq!(a, b);
    }
}
