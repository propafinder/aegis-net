//! Server configuration with limits, fallback policy, and rate limiting.

use aegis_core::config_types::{
    DEFAULT_GRPC_PATH, DEFAULT_GRPC_PATH_POOL, DEFAULT_WEBSOCKET_PATH, DEFAULT_WEBSOCKET_PATH_POOL,
};
use aegis_core::DEFAULT_MASQUE_PATH;
use serde::Deserialize;
use std::path::Path;
use std::path::PathBuf;

#[cfg(test)]
#[path = "config/legacy_tcp_limits_tests.rs"]
mod legacy_tcp_limits_tests;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Shared-token authentication is disabled when inner TLS is configured.
    #[serde(default)]
    pub auth_token: String,
    /// Time-bounded compatibility credentials used only during a staged
    /// client migration. The primary `auth_token` is always tried first.
    #[serde(default)]
    pub legacy_auth_tokens: Vec<LegacyAuthTokenConfig>,
    #[serde(default)]
    pub process_alias: Option<String>,

    /// Operational log privacy. Sensitive request context stays disabled
    /// unless the server configuration explicitly opts in.
    #[serde(default)]
    pub logging: OperationalLoggingConfig,

    /// Fallback policy: "close" | "proxy:host:port" | host:port (legacy).
    #[serde(default = "default_fallback")]
    pub fallback: String,

    /// Connection and I/O limits.
    #[serde(default)]
    pub limits: ServerLimits,

    /// Rate limiting for auth failures.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Egress policy applied after authentication and after DNS resolution.
    #[serde(default)]
    pub target_policy: TargetPolicyConfig,

    /// Tunnel transport settings for M4 multi-transport ingress.
    #[serde(default)]
    pub transport: TransportConfig,

    /// Client bundle endpoint settings (v0.2.0 S3). When enabled, the
    /// TLS listener at `listen` also serves `GET <bundle_path_prefix>?
    /// token=<plaintext>` and returns the pre-built client bundle tarball
    /// once per token. Operators issue tokens via
    /// `aegis-server bundle-token issue --bundle-path ... [--comment ...]`.
    #[serde(default)]
    pub bundle_endpoint: BundleEndpointConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalLoggingConfig {
    /// Include peer addresses and diagnostic error text in operational logs.
    /// Environment log filters cannot enable this setting.
    #[serde(default)]
    pub include_sensitive_context: bool,
}

impl OperationalLoggingConfig {
    pub(crate) const fn policy(&self) -> crate::operational_log::OperationalLogPolicy {
        crate::operational_log::OperationalLogPolicy::new(self.include_sensitive_context)
    }
}

/// A legacy tunnel credential accepted during an explicitly bounded migration.
///
/// `id` is safe telemetry (never the secret) and `not_after_unix_secs` is a
/// hard runtime cutoff. Keeping this as an array of tables lets operators
/// restrict each old credential to only the relay group that historically
/// accepted it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyAuthTokenConfig {
    pub id: String,
    pub auth_token: String,
    pub not_after_unix_secs: u64,
}

pub const MAX_LEGACY_AUTH_TOKENS: usize = 3;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEndpointConfig {
    /// Disabled by default — operators explicitly opt-in (`enabled = true`)
    /// because exposing a bundle endpoint extends the server's public
    /// attack surface. When disabled, any GET request whose path starts
    /// with `bundle_path_prefix` is rejected with 404.
    #[serde(default)]
    pub enabled: bool,
    /// Absolute path to the JSON token store. Created on first use (mode
    /// 0700 parent dir, 0600 file). Default: `/var/lib/aegis/bundle-tokens.json`.
    #[serde(default = "default_bundle_token_store_path")]
    pub token_store_path: PathBuf,
    /// Token lifetime в seconds after issuance. Default 24h. Operators
    /// can override via CLI per-token при issue.
    #[serde(default = "default_bundle_token_ttl_secs")]
    pub default_token_ttl_secs: u64,
    /// HTTP path prefix that routes в the bundle handler. Default
    /// `/bundle`. Keep это distinct from websocket / gRPC paths to avoid
    /// collision on the shared TLS listener.
    #[serde(default = "default_bundle_path_prefix")]
    pub path_prefix: String,
}

impl Default for BundleEndpointConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token_store_path: default_bundle_token_store_path(),
            default_token_ttl_secs: default_bundle_token_ttl_secs(),
            path_prefix: default_bundle_path_prefix(),
        }
    }
}

fn default_bundle_token_store_path() -> PathBuf {
    PathBuf::from("/var/lib/aegis/bundle-tokens.json")
}

fn default_bundle_token_ttl_secs() -> u64 {
    24 * 60 * 60
}

fn default_bundle_path_prefix() -> String {
    "/bundle".into()
}

/// Server resource limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLimits {
    /// Max concurrent connections (0 = unlimited).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Concurrent unauthenticated TCP sockets per kernel-reported peer IP.
    #[serde(default = "default_max_unauthenticated_connections_per_ip")]
    pub max_unauthenticated_connections_per_ip: usize,
    /// Max auth field length in relay request (bytes).
    #[serde(default = "default_max_auth_len")]
    pub max_auth_len: usize,
    /// Max host field length in relay request (bytes). RFC 1035 = 253.
    #[serde(default = "default_max_host_len")]
    pub max_host_len: usize,
    /// Read timeout for relay handshake (ms).
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    /// One authenticated legacy TCP DNS/connect establishment budget (ms).
    #[serde(default = "default_legacy_tcp_connect_timeout_ms")]
    pub legacy_tcp_connect_timeout_ms: u64,
    /// Authenticated legacy TCP silence budget across both directions (ms).
    /// Successful payload bytes renew it; active tunnels have no total lifetime cap.
    #[serde(default = "default_legacy_tcp_idle_timeout_ms")]
    pub legacy_tcp_idle_timeout_ms: u64,
    /// Write timeout (ms). Legacy TCP applies this to each control response and
    /// to stalled payload writes, flushes and half-closes in either direction.
    #[serde(default = "default_write_timeout_ms")]
    pub write_timeout_ms: u64,
    /// Maximum graceful drain duration. Zero requests immediate session cleanup.
    #[serde(default = "default_shutdown_grace_ms")]
    pub shutdown_grace_ms: u64,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_unauthenticated_connections_per_ip: default_max_unauthenticated_connections_per_ip(
            ),
            max_auth_len: default_max_auth_len(),
            max_host_len: default_max_host_len(),
            read_timeout_ms: default_read_timeout_ms(),
            legacy_tcp_connect_timeout_ms: default_legacy_tcp_connect_timeout_ms(),
            legacy_tcp_idle_timeout_ms: default_legacy_tcp_idle_timeout_ms(),
            write_timeout_ms: default_write_timeout_ms(),
            shutdown_grace_ms: default_shutdown_grace_ms(),
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    /// Max auth failures from one IP before ban.
    #[serde(default = "default_max_failures")]
    pub max_auth_failures_per_ip: u32,
    /// Ban duration (seconds).
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
    /// Socket peer ranges allowed to supply `forwarded_ip_header`. Empty means
    /// every listener is direct and every forwarded identity is ignored.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    /// Single-IP HTTP header accepted only from `trusted_proxy_cidrs` peers.
    #[serde(default = "default_forwarded_ip_header")]
    pub forwarded_ip_header: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetPolicyProfile {
    /// Normal shared/public relay: no access to local, private, metadata,
    /// documentation, benchmark, multicast or reserved address space.
    #[default]
    PublicInternet,
    /// Explicit single-tenant VPN contract. Allows private destinations but
    /// still rejects port zero and honors `allowed_ports`.
    FullVpnEgress,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPolicyConfig {
    #[serde(default)]
    pub profile: TargetPolicyProfile,
    /// Empty means any non-zero port; otherwise only listed ports are allowed.
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}

impl Default for TargetPolicyConfig {
    fn default() -> Self {
        Self {
            profile: TargetPolicyProfile::PublicInternet,
            allowed_ports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// Maximum simultaneous requests on each outer H2 connection.
    #[serde(default = "default_h2_max_concurrent_streams")]
    pub h2_max_concurrent_streams: u32,
    /// Explicit paired fixed-frame profile for authenticated gRPC/H2 traffic.
    #[serde(default)]
    pub authenticated_shaping: Option<aegis_core::carrier_runtime::PrivacySettings>,
    #[serde(default)]
    pub https_bridge: Option<aegis_core::https_bridge::ServerSettings>,
    /// Exclusive CDN-fronted, device-enrolled origin: only requests carrying
    /// the CDN-injected origin key reach inner TLS or enrollment forwarding.
    #[serde(default)]
    pub fronted_origin: Option<aegis_core::fronted_origin::Settings>,
    #[serde(default)]
    pub inner_tls: Option<aegis_core::secure_channel::ServerSettings>,
    /// Optional private Unix socket acknowledging live authorization state.
    #[serde(default)]
    pub device_policy_status_socket: Option<PathBuf>,
    #[serde(default = "default_websocket_path")]
    pub websocket_path: String,
    #[serde(default = "default_websocket_path_pool")]
    pub websocket_path_pool: Vec<String>,
    /// Dedicated RFC 8441 path carrying the enrolled inner TLS protocol.
    /// Never dispatch this path to the legacy shared-token WebSocket handler.
    #[serde(default)]
    pub secure_websocket_path: Option<String>,
    /// Dedicated synthetic enrolled H3 CONNECT authority on the QUIC listener. Legacy
    /// shared-token MASQUE CONNECT and CONNECT-UDP remain separate.
    #[serde(default)]
    pub secure_quic_authority: Option<String>,
    #[serde(default = "default_grpc_path")]
    pub grpc_path: String,
    #[serde(default = "default_grpc_path_pool")]
    pub grpc_path_pool: Vec<String>,
    #[serde(default = "default_masque_path")]
    pub masque_path: String,
    #[serde(default = "default_masque_path_pool")]
    pub masque_path_pool: Vec<String>,
    /// QUIC/H3 endpoint for `CONNECT` and `CONNECT-UDP` ingress. Defaults to the TCP `listen` host:port.
    #[serde(default)]
    pub quic_listen: Option<String>,
    /// Require QUIC startup and continued ingress health before claiming ready.
    /// Set false explicitly for a deployment that permits TCP-only service.
    #[serde(default = "default_quic_required")]
    pub quic_required: bool,
    /// QUIC keepalive cadence for idle MASQUE sessions. `0` disables keepalive.
    #[serde(default = "default_quic_keep_alive_interval_ms")]
    pub quic_keep_alive_interval_ms: u64,
    /// Maximum QUIC idle timeout for MASQUE sessions. `0` disables the timeout.
    #[serde(default = "default_quic_max_idle_timeout_ms")]
    pub quic_max_idle_timeout_ms: u64,
}

fn default_h2_max_concurrent_streams() -> u32 {
    32
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            h2_max_concurrent_streams: default_h2_max_concurrent_streams(),
            authenticated_shaping: None,
            https_bridge: None,
            fronted_origin: None,
            inner_tls: None,
            device_policy_status_socket: None,
            websocket_path: default_websocket_path(),
            websocket_path_pool: default_websocket_path_pool(),
            secure_websocket_path: None,
            secure_quic_authority: None,
            grpc_path: default_grpc_path(),
            grpc_path_pool: default_grpc_path_pool(),
            masque_path: default_masque_path(),
            masque_path_pool: default_masque_path_pool(),
            quic_listen: None,
            quic_required: default_quic_required(),
            quic_keep_alive_interval_ms: default_quic_keep_alive_interval_ms(),
            quic_max_idle_timeout_ms: default_quic_max_idle_timeout_ms(),
        }
    }
}

impl TransportConfig {
    pub fn accepts_websocket_path(&self, candidate: &str) -> bool {
        candidate == self.websocket_path
            || self
                .websocket_path_pool
                .iter()
                .any(|path| path == candidate)
    }

    pub fn accepts_grpc_path(&self, candidate: &str) -> bool {
        candidate == self.grpc_path || self.grpc_path_pool.iter().any(|path| path == candidate)
    }

    pub fn accepted_masque_paths(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.masque_path.as_str())
            .chain(self.masque_path_pool.iter().map(String::as_str))
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            max_auth_failures_per_ip: default_max_failures(),
            ban_duration_secs: default_ban_duration(),
            trusted_proxy_cidrs: Vec::new(),
            forwarded_ip_header: default_forwarded_ip_header(),
        }
    }
}

fn default_fallback() -> String {
    "close".into()
}
fn default_max_connections() -> usize {
    1000
}
fn default_max_unauthenticated_connections_per_ip() -> usize {
    32
}
fn default_max_auth_len() -> usize {
    256
}
fn default_max_host_len() -> usize {
    253
}
fn default_read_timeout_ms() -> u64 {
    30_000
}
fn default_legacy_tcp_connect_timeout_ms() -> u64 {
    10_000
}
fn default_legacy_tcp_idle_timeout_ms() -> u64 {
    300_000
}
fn default_write_timeout_ms() -> u64 {
    30_000
}
fn default_shutdown_grace_ms() -> u64 {
    30_000
}
fn default_quic_required() -> bool {
    true
}
fn default_rate_limit_enabled() -> bool {
    true
}
fn default_max_failures() -> u32 {
    3
}
fn default_ban_duration() -> u64 {
    300
}
fn default_forwarded_ip_header() -> String {
    "cf-connecting-ip".into()
}
fn default_websocket_path() -> String {
    // Neutral default: matches the client-side neutral primary. The legacy
    // AEGIS-branded path stays in the pool so deployed clients running
    // older defaults still negotiate successfully.
    DEFAULT_WEBSOCKET_PATH.into()
}
fn default_websocket_path_pool() -> Vec<String> {
    DEFAULT_WEBSOCKET_PATH_POOL
        .into_iter()
        .map(str::to_owned)
        .collect()
}
fn default_grpc_path() -> String {
    // The primary path is neutral; the compatibility pool still contains a
    // product-branded mount. Installer choices and runtime pool selection mean
    // a fresh install is not guaranteed to be brand-free on the wire.
    DEFAULT_GRPC_PATH.into()
}
fn default_grpc_path_pool() -> Vec<String> {
    DEFAULT_GRPC_PATH_POOL
        .into_iter()
        .map(str::to_owned)
        .collect()
}
fn default_masque_path() -> String {
    DEFAULT_MASQUE_PATH.into()
}
fn default_masque_path_pool() -> Vec<String> {
    vec![
        "/.well-known/masque/connect-udp".into(),
        "/masque/v1/udp".into(),
        "/relay/datagram".into(),
    ]
}

fn default_quic_keep_alive_interval_ms() -> u64 {
    10_000
}

fn default_quic_max_idle_timeout_ms() -> u64 {
    120_000
}

pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<ServerConfig> {
    let path = path.as_ref();
    let bytes = aegis_core::secret_file::read_config(path, 4 * 1024 * 1024)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| anyhow::anyhow!("config_encoding_invalid"))?;
    let mut cfg: ServerConfig =
        toml::from_str(s).map_err(|_| anyhow::anyhow!("config_parse_invalid"))?;
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    // Resolve cert/key relative to the config file so cargo-run and container
    // mounts behave the same way.
    cfg.cert = resolve_config_relative_path(config_dir, &cfg.cert);
    cfg.key = resolve_config_relative_path(config_dir, &cfg.key);
    if let Some(inner) = &mut cfg.transport.inner_tls {
        inner.resolve_paths(config_dir);
    }
    cfg.validate_auth_tokens()?;
    Ok(cfg)
}

impl ServerConfig {
    /// Validate the keyring before any listener is bound.
    pub fn validate_auth_tokens(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=4096).contains(&self.limits.max_unauthenticated_connections_per_ip),
            "unauthenticated TCP connections per IP must be 1..4096"
        );
        anyhow::ensure!(
            (1..=60_000).contains(&self.limits.read_timeout_ms),
            "relay admission timeout must be 1..60000ms"
        );
        // These deadlines apply only to the legacy shared-token TCP path.
        // Device-only origins retain their existing configuration contract.
        anyhow::ensure!(
            (1..=1024).contains(&self.transport.h2_max_concurrent_streams),
            "outer H2 concurrent streams must be 1..1024"
        );
        if self.transport.inner_tls.is_none() {
            anyhow::ensure!(
                (1..=60_000).contains(&self.limits.legacy_tcp_connect_timeout_ms),
                "legacy TCP establishment timeout must be 1..60000ms"
            );
            anyhow::ensure!(
                (1..=86_400_000).contains(&self.limits.legacy_tcp_idle_timeout_ms),
                "legacy TCP authenticated idle timeout must be 1..86400000ms"
            );
            anyhow::ensure!(
                (1..=60_000).contains(&self.limits.write_timeout_ms),
                "legacy TCP write timeout must be 1..60000ms"
            );
        }
        if let Some(shaping) = &self.transport.authenticated_shaping {
            shaping.validate()?;
            anyhow::ensure!(
                self.transport.inner_tls.is_some(),
                "authenticated relay shaping requires device inner TLS"
            );
        }
        if let Some(path) = &self.transport.secure_websocket_path {
            anyhow::ensure!(
                self.transport.inner_tls.is_some()
                    && self.auth_token.is_empty()
                    && self.legacy_auth_tokens.is_empty()
                    && path == aegis_core::carrier_program::SECURE_WS_PATH
                    && !self.transport.accepts_websocket_path(path)
                    && !self.transport.accepts_grpc_path(path)
                    && self.transport.https_bridge.is_none(),
                "secure WebSocket requires exclusive inner TLS and a distinct admitted path"
            );
        }
        if let Some(authority) = &self.transport.secure_quic_authority {
            anyhow::ensure!(
                self.transport.inner_tls.is_some()
                    && self.auth_token.is_empty()
                    && self.legacy_auth_tokens.is_empty()
                    && authority == aegis_core::carrier_program::SECURE_QUIC_AUTHORITY
                    && self.transport.https_bridge.is_none()
                    && self.transport.quic_required,
                "enrolled QUIC requires exclusive device TLS and fixed distinct H3 path"
            );
        }
        if let Some(bridge) = &self.transport.https_bridge {
            bridge.validate()?;
            anyhow::ensure!(self.transport.inner_tls.is_some()
                && self.auth_token.is_empty() && self.legacy_auth_tokens.is_empty()
                && self.fallback == "close" && !self.transport.quic_required
                && self.transport.quic_listen.is_none() && !self.bundle_endpoint.enabled,
                "HTTPS bridge requires exclusive inner TLS, closed fallback, disabled QUIC and separate public distribution");
            let inner = self
                .transport
                .inner_tls
                .as_ref()
                .expect("validated inner TLS");
            anyhow::ensure!(
                bridge.carrier.credential_file != self.key
                    && bridge.carrier.credential_file != inner.key,
                "HTTPS bridge requires a separate admission credential"
            );
        }
        if let Some(fronted) = &self.transport.fronted_origin {
            fronted.validate()?;
            anyhow::ensure!(
                self.transport.inner_tls.is_some()
                    && self.transport.https_bridge.is_none()
                    && self.auth_token.is_empty()
                    && self.legacy_auth_tokens.is_empty()
                    && self.fallback == "close"
                    && !self.transport.quic_required
                    && self.transport.quic_listen.is_none()
                    && !self.bundle_endpoint.enabled
                    && !self.rate_limit.trusted_proxy_cidrs.is_empty(),
                "fronted origin requires exclusive inner TLS, no HTTPS bridge or shared token, closed fallback, disabled QUIC and bundle endpoint, and explicit trusted CDN proxy ranges"
            );
            let inner = self
                .transport
                .inner_tls
                .as_ref()
                .expect("validated inner TLS");
            for path in fronted.credential_paths() {
                anyhow::ensure!(
                    path != self.key && path != inner.key,
                    "fronted origin requires separate origin-pull credentials"
                );
            }
        }
        if let Some(path) = &self.transport.device_policy_status_socket {
            anyhow::ensure!(cfg!(unix) && path.is_absolute()
                && self.transport.inner_tls.as_ref().is_some_and(|inner| inner.device_registry.is_some()),
                "private device policy status requires Unix, absolute socket path and dynamic registry");
        }
        if self.transport.inner_tls.is_some() {
            anyhow::ensure!(
                self.legacy_auth_tokens.is_empty(),
                "inner TLS requires an exclusive origin; remove legacy_auth_tokens"
            );
            if !self.auth_token.is_empty() {
                aegis_core::auth_token::validate(&self.auth_token).map_err(anyhow::Error::msg)?;
            }
            return Ok(());
        }
        aegis_core::auth_token::validate(&self.auth_token).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(!self.auth_token.is_empty(), "auth_token must not be empty");
        anyhow::ensure!(
            self.auth_token.len() <= self.limits.max_auth_len,
            "auth_token len {} exceeds max {}",
            self.auth_token.len(),
            self.limits.max_auth_len
        );
        anyhow::ensure!(
            self.legacy_auth_tokens.len() <= MAX_LEGACY_AUTH_TOKENS,
            "legacy_auth_tokens has {} entries; maximum is {}",
            self.legacy_auth_tokens.len(),
            MAX_LEGACY_AUTH_TOKENS
        );

        let mut ids = std::collections::HashSet::new();
        let mut secrets = std::collections::HashSet::new();
        secrets.insert(self.auth_token.as_str());
        for legacy in &self.legacy_auth_tokens {
            aegis_core::auth_token::validate(&legacy.auth_token).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                !legacy.id.is_empty()
                    && legacy.id.len() <= 32
                    && legacy
                        .id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
                "legacy auth id must be 1-32 ASCII letters, digits, '_' or '-': {:?}",
                legacy.id
            );
            anyhow::ensure!(
                legacy.id != "current",
                "legacy auth id 'current' is reserved"
            );
            anyhow::ensure!(
                ids.insert(legacy.id.as_str()),
                "duplicate legacy auth id {:?}",
                legacy.id
            );
            anyhow::ensure!(
                !legacy.auth_token.is_empty(),
                "legacy auth token {:?} must not be empty",
                legacy.id
            );
            anyhow::ensure!(
                legacy.auth_token.len() <= self.limits.max_auth_len,
                "legacy auth token {:?} len {} exceeds max {}",
                legacy.id,
                legacy.auth_token.len(),
                self.limits.max_auth_len
            );
            anyhow::ensure!(
                legacy.not_after_unix_secs > 0,
                "legacy auth token {:?} requires a non-zero not_after_unix_secs",
                legacy.id
            );
            anyhow::ensure!(
                secrets.insert(legacy.auth_token.as_str()),
                "legacy auth token {:?} duplicates another configured credential",
                legacy.id
            );
        }
        Ok(())
    }
}

fn resolve_config_relative_path(config_dir: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_relative() {
        config_dir.join(candidate)
    } else {
        candidate.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_server_config_keys() {
        let error = toml::from_str::<ServerConfig>(
            r#"
listen = "127.0.0.1:8443"
cert = "cert.pem"
key = "key.pem"
auth_token = "token"

[transport]
grpc_paht = "/typo"
"#,
        )
        .expect_err("unknown server config key must not be silently ignored");
        assert!(error.to_string().contains("unknown field `grpc_paht`"));
    }

    #[test]
    fn owner_macos_test_relay_capacity_preserves_handshake_budget() {
        let cfg: ServerConfig = toml::from_str(include_str!(
            "../tests/fixtures/macos-test-relay-server.toml"
        ))
        .unwrap();
        cfg.validate_auth_tokens().unwrap();
        assert_eq!(cfg.listen, "198.51.100.247:443");
        assert_eq!(cfg.transport.h2_max_concurrent_streams, 128);
        let limits = &cfg.transport.inner_tls.as_ref().unwrap().admission;
        assert_eq!(limits.max_sessions_per_peer, 1024);
        assert_eq!(limits.max_sessions, 4096);
        assert_eq!(limits.max_handshakes_per_peer, 16);
        assert_eq!(limits.max_handshakes, 128);
    }

    #[test]
    fn outer_h2_stream_limit_defaults_overrides_and_refuses_invalid_bounds() {
        assert_eq!(TransportConfig::default().h2_max_concurrent_streams, 32);
        let base = format!(
            r#"listen = "127.0.0.1:8443"
cert = "cert.pem"
key = "key.pem"
auth_token = "{}"
"#,
            "abcd".repeat(16)
        );
        for (maximum, valid) in [
            (0, false),
            (1, true),
            (128, true),
            (1024, true),
            (1025, false),
        ] {
            let cfg: ServerConfig = toml::from_str(&format!(
                "{base}\n[transport]\nh2_max_concurrent_streams = {maximum}\n"
            ))
            .unwrap();
            assert_eq!(cfg.transport.h2_max_concurrent_streams, maximum);
            let validation = cfg.validate_auth_tokens();
            assert_eq!(validation.is_ok(), valid, "{validation:?}");
        }
    }

    #[test]
    fn operational_logging_is_private_by_default_and_explicitly_opted_in() {
        let base = r#"
listen = "127.0.0.1:8443"
cert = "cert.pem"
key = "key.pem"
auth_token = "token"
"#;
        let default_cfg: ServerConfig = toml::from_str(base).unwrap();
        assert!(!default_cfg.logging.include_sensitive_context);

        let opted_in: ServerConfig = toml::from_str(&format!(
            "{base}\n[logging]\ninclude_sensitive_context = true\n"
        ))
        .unwrap();
        assert!(opted_in.logging.include_sensitive_context);
    }

    #[test]
    fn https_bridge_configuration_refuses_legacy_and_fallback_bypass() {
        let root = std::env::temp_dir();
        let mut cfg: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:8443"
cert = "outer.pem"
key = "outer.key"
[transport]
quic_required = false
[transport.inner_tls]
cert = "inner.pem"
key = "inner.key"
client_ca = "ca.pem"
allowed_client_sha256 = ["{}"]
"#,
            "ab".repeat(32)
        ))
        .unwrap();
        cfg.transport.https_bridge = Some(aegis_core::https_bridge::ServerSettings {
            carrier: aegis_core::https_bridge::ClientSettings {
                authority: "bridge.test".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
                credential_file: root.join("bridge-key"),
            },
            site_html: "<!doctype html><title>Public site</title>".into(),
        });
        assert!(cfg.validate_auth_tokens().is_ok());
        let mut bypass = cfg.clone();
        bypass.transport.inner_tls = None;
        assert!(bypass.validate_auth_tokens().is_err());
        let mut bypass = cfg.clone();
        bypass.auth_token = "ab".repeat(32);
        assert!(bypass.validate_auth_tokens().is_err());
        let mut bypass = cfg.clone();
        bypass.transport.quic_required = true;
        assert!(bypass.validate_auth_tokens().is_err());
        let mut bypass = cfg.clone();
        bypass.transport.quic_listen = Some("127.0.0.1:8443".into());
        assert!(bypass.validate_auth_tokens().is_err());
        let mut bypass = cfg.clone();
        bypass.fallback = "proxy:127.0.0.1:80".into();
        assert!(bypass.validate_auth_tokens().is_err());
        let mut bypass = cfg;
        bypass.bundle_endpoint.enabled = true;
        assert!(bypass.validate_auth_tokens().is_err());
    }

    #[test]
    fn secure_websocket_uses_only_fixed_device_path_and_exclusive_identity() {
        let mut cfg: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:8443"
cert = "outer.pem"
key = "outer.key"
[transport]
secure_websocket_path = "/v2/device/ws"
[transport.inner_tls]
cert = "inner.pem"
key = "inner.key"
client_ca = "ca.pem"
allowed_client_sha256 = ["{}"]
"#,
            "ab".repeat(32)
        ))
        .unwrap();
        assert!(cfg.validate_auth_tokens().is_ok());
        cfg.transport.secure_websocket_path = Some(cfg.transport.websocket_path.clone());
        assert!(cfg.validate_auth_tokens().is_err());
        cfg.transport.secure_websocket_path = Some("/other".into());
        assert!(cfg.validate_auth_tokens().is_err());
        cfg.transport.secure_websocket_path =
            Some(aegis_core::carrier_program::SECURE_WS_PATH.into());
        cfg.auth_token = "legacy-token".into();
        assert!(cfg.validate_auth_tokens().is_err());
        cfg.auth_token.clear();
        cfg.transport.inner_tls = None;
        assert!(cfg.validate_auth_tokens().is_err());
    }

    #[test]
    fn enrolled_quic_requires_fixed_path_and_exclusive_device_identity() {
        let mut cfg: ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:8443"
cert = "outer.pem"
key = "outer.key"
[transport]
secure_quic_authority = "device.aegis.invalid:443"
[transport.inner_tls]
cert = "inner.pem"
key = "inner.key"
client_ca = "ca.pem"
allowed_client_sha256 = ["{}"]
"#,
            "ab".repeat(32)
        ))
        .unwrap();
        cfg.validate_auth_tokens().unwrap();
        cfg.transport.secure_quic_authority = Some("/masque/v1/udp".into());
        assert!(cfg.validate_auth_tokens().is_err());
        cfg.transport.secure_quic_authority =
            Some(aegis_core::carrier_program::SECURE_QUIC_AUTHORITY.into());
        cfg.auth_token = "legacy-token".into();
        assert!(cfg.validate_auth_tokens().is_err());
        cfg.auth_token.clear();
        cfg.transport.inner_tls = None;
        assert!(cfg.validate_auth_tokens().is_err());
    }
}
