//! User-facing Ubuntu **wide product modes** and the explicit per-class traffic
//! policy each one resolves to.
//!
//! This is the Rust-owned source of truth for what a normal user gets when they
//! install AEGIS and pick a mode: which traffic class is carried, which is
//! fail-closed, and what the leak risk is. The Bash installer orchestrates around
//! this model (selecting it, printing its summary, applying firewall scripts); it
//! does **not** re-encode policy. The product-gate verdict vocabulary lives here
//! too so claims are checked in one place.
//!
//! Honest architecture note: NFQUEUE is AEGIS's observe/policy/packet-verdict
//! layer, **not** a relay. The `full-wide-nfqueue` product mode therefore carries
//! TCP IPv4 via the REDIRECT relay path and uses NFQUEUE (plus firewall rules) to
//! fail-close or observe the classes REDIRECT cannot safely carry (generic UDP,
//! QUIC, IPv6). Every class is either carried or fail-closed — no silent native
//! leak — which is an honest `UBUNTU_FULL_WIDE_PARTIAL`, not `READY`.

use serde::Serialize;

use crate::config_types::WidePlatformBackend;

/// Explicit policy for generic outbound UDP under a wide mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideUdpPolicy {
    /// UDP is not captured; the kernel sends it natively. HIGH leak risk. Never a
    /// safe mode.
    Native,
    /// Block outbound generic UDP (incl. QUIC/HTTP3 UDP/443 and WebRTC). Fail
    /// closed. This is NOT UDP tunnelling — it is a deliberate drop.
    Block,
    /// Carry eligible UDP through the fail-closed UDP relay plan. The historical
    /// serialized name remains `masque_direct`: MASQUE is preferred when
    /// configured, with `grpc_datagram` over H2/TCP as the non-native fallback.
    ///
    /// On Linux local-host the redirect proxy recovers the original destination
    /// from conntrack and returns relay responses through the reverse path.
    /// Inner TLS device profiles permit only authenticated grpc_datagram; the
    /// identifier alone does not establish which wire transport was selected.
    /// Live lifecycle evidence is separate from this configuration policy.
    MasqueDirect,
    /// Only the documented preview allowlist behaviour (e.g. scoped DNS), not
    /// full generic UDP.
    PreviewAllowlist,
}

/// Explicit policy for DNS (UDP/53) under a wide mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideDnsPolicy {
    /// DNS sent natively (uncaptured). HIGH leak risk; never a safe mode.
    Native,
    /// DNS handled by the AEGIS preview/capture path (fake-IP listener / recovery).
    Preview,
    /// DNS blocked/fail-closed (resolution must go through a captured path or fail).
    Block,
}

/// Explicit policy for IPv6 (TCP + UDP) under a wide mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideIpv6Policy {
    /// IPv6 sent natively (uncaptured). HIGH leak risk; never a safe mode.
    Native,
    /// IPv6 blocked/fail-closed (no native IPv6 egress).
    Block,
    /// IPv6 observed by NFQUEUE and fail-closed unless a relay can carry the IPv6
    /// target. "Capture" here means observed + prevented from leaking; it is only
    /// a relayed path when an IPv6-capable relay target exists, otherwise it is
    /// fail-closed (PARTIAL, never READY on block alone).
    Capture,
    /// IPv6 TCP **and** UDP carried bidirectionally through the TUN+smoltcp path
    /// (smoltcp terminates the flow, the payload uses the configured relay
    /// transport, and the response is injected through the TUN). The policy
    /// requires fail-closed behavior on relay errors; live lifecycle evidence
    /// must independently verify capture and the persistent firewall.
    TunCarried,
}

/// How a QUIC/HTTP3 (UDP/443) flow is treated, derived from the UDP policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideQuicDisposition {
    /// QUIC carried via the UDP relay plan (historical policy name = masque_direct).
    MasqueDirect,
    /// QUIC blocked so the application falls back to TCP (then captured).
    BlockedForceTcpFallback,
    /// QUIC sent natively (wide-compat / native UDP only). HIGH leak risk.
    Native,
}

/// Coarse leak-risk rating surfaced to the user at install time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideLeakRisk {
    /// No wide capture configured (per-app only); not a wide leak claim.
    NotWide,
    /// Low residual leak risk: every wide class carried or fail-closed.
    Low,
    /// High leak risk: one or more classes egress natively.
    High,
}

/// Capture scope of a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideScope {
    /// Per-application only (SOCKS); not system-wide.
    PerApp,
    /// This host's own locally-generated traffic (OUTPUT).
    LocalHost,
    /// Downstream/routed traffic through this host acting as a gateway.
    Gateway,
}

/// User-facing Ubuntu wide product modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WideProductMode {
    /// Per-app SOCKS only. Not wide. No firewall rules.
    SocksOnly,
    /// Local TCP IPv4 captured by REDIRECT; DNS preview/capture or block; generic
    /// UDP blocked; QUIC blocked (TCP fallback); IPv6 blocked. Safe default.
    WideRedirectSafe,
    /// Like wide-redirect-safe but generic UDP via MASQUE direct if health passes
    /// (else block, never native). Explicit opt-in.
    WideUdpDirect,
    /// Routed/GRE/downstream gateway (TPROXY). Not local desktop-wide.
    GatewayTproxy,
    /// Target product mode: local apps without proxy. TCP IPv4 via REDIRECT;
    /// DNS, generic UDP and IPv6 all either carried or fail-closed via NFQUEUE
    /// policy plus firewall. Fail-closed on unsupported/error. No silent leak.
    FullWideNfqueue,
    /// Full-wide with **all five legs carried**: TCP IPv4 (REDIRECT), DNS
    /// (preview/recovery), IPv4 UDP (relay-carried bidirectional), and IPv6
    /// TCP+UDP (TUN+smoltcp, bidirectional). The only mode where IPv6 UDP is
    /// carried rather than fail-closed. Combines the REDIRECT backend (v4) and
    /// the TUN+smoltcp backend (v6). Fail-closed on relay error — no native leak.
    FullWideTun,
    /// Experimental hybrid profile: direct Geneva for IPv4 TCP, fronted gRPC
    /// relay for IPv6 TCP and replay-safe direct failures, and the fail-closed
    /// MASQUE → gRPC/H2 UDP plan. An ambiguous post-send direct failure blocks instead of replaying
    /// application bytes. Direct IPv4 exposes the destination address to the
    /// access network. The profile is explicit opt-in and never falls through
    /// to a native passthrough route.
    FullWideHybridGeneva,
    /// TCP captured but UDP/DNS may be native. Prints HIGH LEAK RISK. Not for
    /// hostile networks.
    WideCompat,
}

/// Product-gate verdict vocabulary. The only values a gate may emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UbuntuWideVerdict {
    /// Full wide carried/fail-closed with live proof incl. UDP carried + IPv6
    /// carried + reboot/crash/cleanup no-leak. The only value that may be called
    /// "wide ready".
    UbuntuFullWideReady,
    /// TCP + DNS carried and generic UDP carried **bidirectionally** (MASQUE
    /// direct, app receives the response), with IPv6 still fail-closed and no
    /// direct leaks. Stronger than PARTIAL (UDP is no longer merely fail-closed)
    /// but not READY (IPv6 not carried). Live-proven on Ubuntu 26.04.
    UbuntuFullWideStrongPartial,
    /// TCP/DNS work; UDP/IPv6 relay incomplete but fail-closed; no direct leaks.
    UbuntuFullWidePartial,
    /// Blocked by a true external blocker (host/approval/secret/kernel).
    UbuntuFullWideBlocked,
    /// A direct leak occurred in a supported safe/full mode.
    UbuntuFullWideFail,
    /// Only gateway/downstream wide proven (not local desktop-wide).
    UbuntuGatewayWideOnly,
    /// Only TCP wide proven (UDP/DNS/IPv6 not yet).
    UbuntuTcpWideOnly,
}

impl UbuntuWideVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UbuntuFullWideReady => "UBUNTU_FULL_WIDE_READY",
            Self::UbuntuFullWideStrongPartial => "UBUNTU_FULL_WIDE_STRONG_PARTIAL",
            Self::UbuntuFullWidePartial => "UBUNTU_FULL_WIDE_PARTIAL",
            Self::UbuntuFullWideBlocked => "UBUNTU_FULL_WIDE_BLOCKED",
            Self::UbuntuFullWideFail => "UBUNTU_FULL_WIDE_FAIL",
            Self::UbuntuGatewayWideOnly => "UBUNTU_GATEWAY_WIDE_ONLY",
            Self::UbuntuTcpWideOnly => "UBUNTU_TCP_WIDE_ONLY",
        }
    }
}

macro_rules! str_enum {
    ($ty:ty, $($variant:path => $s:literal),+ $(,)?) => {
        impl $ty {
            pub fn as_str(self) -> &'static str {
                match self { $($variant => $s),+ }
            }
            pub fn parse_str(s: &str) -> Option<Self> {
                match s { $($s => Some($variant)),+, _ => None }
            }
        }
    };
}

str_enum!(WideUdpPolicy,
    WideUdpPolicy::Native => "native",
    WideUdpPolicy::Block => "block",
    WideUdpPolicy::MasqueDirect => "masque_direct",
    WideUdpPolicy::PreviewAllowlist => "preview_allowlist",
);
str_enum!(WideDnsPolicy,
    WideDnsPolicy::Native => "native",
    WideDnsPolicy::Preview => "preview",
    WideDnsPolicy::Block => "block",
);
str_enum!(WideIpv6Policy,
    WideIpv6Policy::Native => "native",
    WideIpv6Policy::Block => "block",
    WideIpv6Policy::Capture => "capture",
    WideIpv6Policy::TunCarried => "tun_carried",
);
str_enum!(WideProductMode,
    WideProductMode::SocksOnly => "socks-only",
    WideProductMode::WideRedirectSafe => "wide-redirect-safe",
    WideProductMode::WideUdpDirect => "wide-udp-direct",
    WideProductMode::GatewayTproxy => "gateway-tproxy",
    WideProductMode::FullWideNfqueue => "full-wide-nfqueue",
    WideProductMode::FullWideTun => "full-wide-tun",
    WideProductMode::FullWideHybridGeneva => "full-wide-hybrid-geneva",
    WideProductMode::WideCompat => "wide-compat",
);

/// A fully-resolved description of a wide product mode: every traffic class's
/// disposition plus the leak-risk rating and the internal backend it activates.
/// Serialisable so the installer / `wide status` / gate can print it verbatim.
#[derive(Debug, Clone, Serialize)]
pub struct WideProductProfile {
    pub mode: &'static str,
    pub is_wide: bool,
    pub scope: WideScope,
    pub tcp_ipv4: &'static str,
    pub udp_policy: WideUdpPolicy,
    pub dns_policy: WideDnsPolicy,
    pub ipv6_policy: WideIpv6Policy,
    pub quic: WideQuicDisposition,
    pub webrtc: &'static str,
    pub leak_risk: WideLeakRisk,
    /// True only for modes a user can safely run on a hostile/censored network
    /// (no native UDP/DNS/IPv6 leak).
    pub safe_for_hostile_network: bool,
    /// Whether a SOCKS listener is also available as a per-app fallback.
    pub socks_fallback: bool,
    /// Internal operator backend(s) this product mode activates.
    pub platform_backend: WidePlatformBackend,
    pub internal_operator_modes: &'static [&'static str],
    pub summary_note: &'static str,
}

/// Exact transport contract for a public, per-device inner-TLS profile.
/// `udp_policy=masque_direct` is the legacy capture-policy identifier; the
/// separate `udp_transport` is authoritative about the selected wire transport.
#[derive(Debug, Serialize)]
pub struct InnerTlsDeviceProfile {
    pub product_mode: &'static str,
    pub capture_scope: WideScope,
    pub tcp_transport: &'static str,
    pub udp_transport: &'static str,
    pub inner_tls: bool,
    pub native_fallback: bool,
    pub requires_privileged_capture: bool,
    pub udp_policy: WideUdpPolicy,
    pub dns_policy: WideDnsPolicy,
    pub ipv6_policy: WideIpv6Policy,
}

pub fn resolve_inner_tls_device_profile(
    mode: WideProductMode,
    udp: bool,
) -> Result<InnerTlsDeviceProfile, String> {
    if !matches!(
        mode,
        WideProductMode::SocksOnly | WideProductMode::FullWideTun
    ) {
        return Err("unsupported inner TLS device product mode".into());
    }
    if mode == WideProductMode::FullWideTun && !udp {
        return Err("full-wide-tun device profile requires explicit UDP permission".into());
    }
    let policy = mode.default_profile();
    Ok(InnerTlsDeviceProfile {
        product_mode: mode.as_str(),
        capture_scope: policy.scope,
        tcp_transport: "grpc_stream",
        udp_transport: if udp { "grpc_datagram" } else { "disabled" },
        inner_tls: true,
        native_fallback: false,
        requires_privileged_capture: mode == WideProductMode::FullWideTun,
        udp_policy: policy.udp_policy,
        dns_policy: policy.dns_policy,
        ipv6_policy: policy.ipv6_policy,
    })
}

/// Build the fixed capture configuration without changing host networking.
/// Installer privilege, cgroup and persistent-firewall gates remain mandatory.
pub fn inner_tls_device_ingress(
    mode: WideProductMode,
    udp: bool,
) -> Result<crate::IngressSettings, String> {
    resolve_inner_tls_device_profile(mode, udp)?;
    let full = mode == WideProductMode::FullWideTun;
    Ok(crate::IngressSettings {
        primary: if full {
            crate::IngressPrimary::Wide
        } else {
            crate::IngressPrimary::Socks5
        },
        allow_fallback: false,
        wide: crate::WideIngressSettings {
            enabled: full,
            platform_backend: if full {
                WidePlatformBackend::LinuxRedirect
            } else {
                WidePlatformBackend::Auto
            },
            capture_dns: full,
            udp_capture_contract: if full {
                crate::WideUdpCaptureContract::GenericCaptureUnstable
            } else {
                crate::WideUdpCaptureContract::PreviewAllowlistOnly
            },
            dns_preview_listen: full.then(|| "127.0.0.1:53".parse().expect("literal DNS listener")),
            ipv6_tun_carried: full,
            udp_redirect_port: full.then_some(15081),
            ..Default::default()
        },
    })
}

/// Validate the rendered policy, including after the real configuration loader
/// materializes defaults. This accepts no direct/MASQUE or ingress downgrade.
pub fn validate_inner_tls_device_settings(
    mode: WideProductMode,
    udp: bool,
    settings: &crate::Settings,
) -> Result<(), String> {
    settings.validate_privacy_plan()?;
    let expected = if let Some(tunnel) = &settings.windows_tunnel {
        if mode != WideProductMode::FullWideTun
            || !udp
            || !tunnel.include_routes.is_empty()
            || !tunnel.kill_switch
            || !tunnel.configure_dns
        {
            return Err(
                "Windows device profile requires full capture, DNS and persistent protection"
                    .into(),
            );
        }
        tunnel.validate()?;
        tunnel.relay_pins(&settings.relay)?;
        // Windows owns capture through Wintun. It must not inherit the Linux
        // redirect backend, nor reinterpret a public SOCKS profile as full-wide.
        crate::IngressSettings {
            primary: crate::IngressPrimary::Socks5,
            allow_fallback: false,
            wide: crate::WideIngressSettings {
                enabled: false,
                ..Default::default()
            },
        }
    } else {
        inner_tls_device_ingress(mode, udp)?
    };
    settings.validate_inner_tls()?;
    let expected_udp = if udp {
        vec![crate::TunnelTransportFamily::GrpcDatagram]
    } else {
        vec![]
    };
    if settings.relay.inner_tls.is_none()
        || !settings.relay.auth_token.is_empty()
        || settings.direct.hybrid_geneva
        || settings.relay.udp_transport_priority.as_ref() != Some(&expected_udp)
        || settings.relay.masque_server.is_some()
        || settings.relay.masque_server_name.is_some()
        || settings.relay.masque_ca_cert.is_some()
        || serde_json::to_value(&settings.ingress).map_err(|e| e.to_string())?
            != serde_json::to_value(expected).map_err(|e| e.to_string())?
    {
        return Err("inner TLS device transport or capture policy changed".into());
    }
    if !settings.relay.endpoints.is_empty() {
        let endpoints = &settings.relay.endpoints;
        if endpoints.len() > 16
            || endpoints[0].server != settings.relay.server
            || endpoints[0].server_name != settings.relay.server_name
        {
            return Err("inner TLS relay pool must be bounded and begin with the primary".into());
        }
        let mut seen = std::collections::HashSet::new();
        for endpoint in endpoints {
            if endpoint.masque_server.is_some()
                || endpoint.masque_server_name.is_some()
                || !seen.insert((&endpoint.server, &endpoint.server_name))
                || rustls::pki_types::ServerName::try_from(endpoint.server_name.clone()).is_err()
            {
                return Err(
                    "inner TLS relay pool contains an invalid or duplicate endpoint".into(),
                );
            }
            // Pools are explicit numeric pins, including SOCKS profiles. Never
            // introduce a DNS lookup outside the protected tunnel on failover.
            validate_device_relay_pin(&endpoint.server)?;
        }
    }
    if mode == WideProductMode::FullWideTun {
        validate_device_relay_pin(&settings.relay.server)?;
    }
    Ok(())
}

fn validate_device_relay_pin(server: &str) -> Result<(), String> {
    let address: std::net::SocketAddrV4 = server
        .parse()
        .map_err(|_| "device profile requires a pinned IPv4 relay endpoint")?;
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || address.ip().is_broadcast()
        || address.ip().octets()[..2] == [198, 18]
        || address.ip().octets()[..2] == [198, 19]
    {
        return Err(
            "full-wide-tun device relay endpoint is unusable or overlaps the DNS preview pool"
                .into(),
        );
    }
    Ok(())
}

impl WideProductMode {
    /// True for modes that must never silently use native UDP/DNS/IPv6.
    pub fn is_safe(self) -> bool {
        self.default_profile().safe_for_hostile_network
    }

    /// The default resolved profile for a mode (before any operator override).
    pub fn default_profile(self) -> WideProductProfile {
        match self {
            Self::SocksOnly => WideProductProfile {
                mode: self.as_str(),
                is_wide: false,
                scope: WideScope::PerApp,
                tcp_ipv4: "per-app via SOCKS5 (apps pointed at the listener)",
                udp_policy: WideUdpPolicy::Native,
                dns_policy: WideDnsPolicy::Native,
                ipv6_policy: WideIpv6Policy::Native,
                quic: WideQuicDisposition::Native,
                webrtc: "native (not captured — per-app SOCKS only)",
                leak_risk: WideLeakRisk::NotWide,
                safe_for_hostile_network: false,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::Auto,
                internal_operator_modes: &["client-socks"],
                summary_note: "Not a wide mode: only apps explicitly pointed at the \
                               SOCKS5 listener are carried; everything else is native.",
            },
            Self::WideRedirectSafe => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::LocalHost,
                tcp_ipv4: "captured by REDIRECT -> tunnel -> relay",
                udp_policy: WideUdpPolicy::Block,
                dns_policy: WideDnsPolicy::Preview,
                ipv6_policy: WideIpv6Policy::Block,
                quic: WideQuicDisposition::BlockedForceTcpFallback,
                webrtc: "blocked (UDP fail-closed)",
                leak_risk: WideLeakRisk::Low,
                safe_for_hostile_network: true,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::LinuxRedirect,
                internal_operator_modes: &["client-wide-redirect"],
                summary_note: "Safe default: local TCP carried; generic UDP, QUIC and \
                               IPv6 fail-closed; DNS via preview. No native leak.",
            },
            Self::WideUdpDirect => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::LocalHost,
                tcp_ipv4: "captured by REDIRECT -> tunnel -> relay",
                udp_policy: WideUdpPolicy::MasqueDirect,
                dns_policy: WideDnsPolicy::Preview,
                ipv6_policy: WideIpv6Policy::Block,
                quic: WideQuicDisposition::MasqueDirect,
                webrtc: "via MASQUE direct if health passes, else blocked",
                leak_risk: WideLeakRisk::Low,
                safe_for_hostile_network: true,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::LinuxRedirect,
                internal_operator_modes: &["client-wide-redirect", "masque-direct"],
                summary_note: "Opt-in: generic UDP/QUIC carried BIDIRECTIONALLY via \
                               MASQUE direct when the health check passes (IPv4 local \
                               host, live-proven: the app receives the response); on \
                               failure UDP is blocked, never native. Not Cloudflare UDP. \
                               IPv6 fail-closed.",
            },
            Self::GatewayTproxy => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::Gateway,
                tcp_ipv4: "downstream TCP captured by TPROXY -> tunnel -> relay",
                udp_policy: WideUdpPolicy::PreviewAllowlist,
                dns_policy: WideDnsPolicy::Preview,
                ipv6_policy: WideIpv6Policy::Block,
                quic: WideQuicDisposition::BlockedForceTcpFallback,
                webrtc: "blocked (outside scoped preview)",
                leak_risk: WideLeakRisk::Low,
                safe_for_hostile_network: true,
                socks_fallback: false,
                platform_backend: WidePlatformBackend::LinuxTproxy,
                internal_operator_modes: &["client-wide-tproxy"],
                summary_note: "Gateway/routed mode for DOWNSTREAM hosts (not local \
                               desktop-wide). Captures per the gateway proof.",
            },
            Self::FullWideNfqueue => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::LocalHost,
                tcp_ipv4: "captured by REDIRECT -> tunnel -> relay (NFQUEUE observes)",
                udp_policy: WideUdpPolicy::Block,
                dns_policy: WideDnsPolicy::Preview,
                ipv6_policy: WideIpv6Policy::Capture,
                quic: WideQuicDisposition::BlockedForceTcpFallback,
                webrtc: "blocked (NFQUEUE/firewall fail-closed)",
                leak_risk: WideLeakRisk::Low,
                safe_for_hostile_network: true,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::LinuxNfqueueObserver,
                internal_operator_modes: &["client-wide-redirect", "client-wide-nfqueue-observer"],
                summary_note: "Target product mode: TCP carried via REDIRECT; generic \
                               UDP/QUIC fail-closed; IPv6 observed by NFQUEUE and \
                               fail-closed; DNS via preview. Fail-closed on error. \
                               Honest PARTIAL (UDP/IPv6 not relayed) — no silent leak.",
            },
            Self::FullWideTun => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::LocalHost,
                tcp_ipv4: "captured by REDIRECT -> tunnel -> relay",
                udp_policy: WideUdpPolicy::MasqueDirect,
                dns_policy: WideDnsPolicy::Preview,
                ipv6_policy: WideIpv6Policy::TunCarried,
                quic: WideQuicDisposition::MasqueDirect,
                webrtc: "carried through the configured UDP relay transport, else blocked",
                leak_risk: WideLeakRisk::Low,
                safe_for_hostile_network: true,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::LinuxRedirect,
                internal_operator_modes: &[
                    "client-wide-redirect",
                    "udp-redirect-proxy",
                    "client-ipv6-tun-smoltcp",
                ],
                summary_note: "All five legs: TCP IPv4 via REDIRECT; DNS via \
                               preview/recovery; IPv4 UDP bidirectional through the configured \
                               authenticated UDP relay plan; IPv6 TCP and IPv6 UDP via \
                               TUN+smoltcp -> relay. Inner TLS device profiles select \
                               grpc_datagram over H2/TCP only; other profiles may configure \
                               MASQUE. Unavailable paths fail closed. Runtime capability \
                               and persistent-firewall lifecycle require separate proof.",
            },
            Self::FullWideHybridGeneva => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::LocalHost,
                tcp_ipv4: "captured by REDIRECT -> direct Geneva; replay-safe terminal -> fronted gRPC relay; ambiguous post-send terminal -> block",
                udp_policy: WideUdpPolicy::MasqueDirect,
                dns_policy: WideDnsPolicy::Preview,
                ipv6_policy: WideIpv6Policy::TunCarried,
                quic: WideQuicDisposition::MasqueDirect,
                webrtc: "carried via direct MASQUE when healthy, else blocked",
                leak_risk: WideLeakRisk::Low,
                safe_for_hostile_network: true,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::LinuxRedirect,
                internal_operator_modes: &[
                    "client-wide-redirect",
                    "udp-redirect-proxy",
                    "client-ipv6-tun-smoltcp",
                ],
                summary_note: "EXPERIMENTAL explicit opt-in. IPv4 TCP first uses direct \
                               Geneva, so the access network sees the real destination IP. \
                               Planning/capability and other provably pre-send terminals hand \
                               off to the fronted gRPC relay; an ambiguous post-send failure \
                               blocks instead of replaying application bytes. IPv6 TCP uses the \
                               relay directly. UDP uses direct MASQUE. Every unavailable carry \
                               path fails closed; native passthrough is forbidden.",
            },
            Self::WideCompat => WideProductProfile {
                mode: self.as_str(),
                is_wide: true,
                scope: WideScope::LocalHost,
                tcp_ipv4: "captured by REDIRECT -> tunnel -> relay",
                udp_policy: WideUdpPolicy::Native,
                dns_policy: WideDnsPolicy::Native,
                ipv6_policy: WideIpv6Policy::Native,
                quic: WideQuicDisposition::Native,
                webrtc: "native (NOT captured)",
                leak_risk: WideLeakRisk::High,
                safe_for_hostile_network: false,
                socks_fallback: true,
                platform_backend: WidePlatformBackend::LinuxRedirect,
                internal_operator_modes: &["client-wide-redirect"],
                summary_note: "HIGH LEAK RISK: TCP captured but UDP, DNS and IPv6 may \
                               egress natively. Compatibility only — NOT for hostile \
                               networks.",
            },
        }
    }

    /// Resolve a profile with optional operator overrides for udp/dns/ipv6.
    ///
    /// Enforces the core safety invariant: a **safe** mode may not be silently
    /// downgraded to a native (uncaptured) policy. Such an override is rejected
    /// with an error string the caller surfaces to the user (who must instead
    /// pick `wide-compat` and accept the HIGH LEAK RISK warning).
    pub fn resolve(
        self,
        udp: Option<WideUdpPolicy>,
        dns: Option<WideDnsPolicy>,
        ipv6: Option<WideIpv6Policy>,
    ) -> Result<WideProductProfile, String> {
        let mut p = self.default_profile();
        if self == Self::FullWideHybridGeneva
            && (udp.is_some_and(|value| value != p.udp_policy)
                || dns.is_some_and(|value| value != p.dns_policy)
                || ipv6.is_some_and(|value| value != p.ipv6_policy))
        {
            return Err(
                "mode 'full-wide-hybrid-geneva' has a fixed fail-closed route matrix; UDP, DNS and IPv6 policy overrides may not change it"
                    .into(),
            );
        }
        let safe = p.safe_for_hostile_network;
        if let Some(u) = udp {
            if safe && u == WideUdpPolicy::Native {
                return Err(format!(
                    "mode '{}' is a safe mode and cannot use udp_policy=native \
                     (would leak). Use 'wide-compat' if you accept native UDP.",
                    self.as_str()
                ));
            }
            p.udp_policy = u;
            p.quic = quic_from_udp(u);
        }
        if let Some(d) = dns {
            if safe && d == WideDnsPolicy::Native {
                return Err(format!(
                    "mode '{}' is a safe mode and cannot use dns_policy=native \
                     (would leak). Use 'wide-compat' if you accept native DNS.",
                    self.as_str()
                ));
            }
            p.dns_policy = d;
        }
        if let Some(v) = ipv6 {
            if safe && v == WideIpv6Policy::Native {
                return Err(format!(
                    "mode '{}' is a safe mode and cannot use ipv6_policy=native \
                     (would leak). Use 'wide-compat' if you accept native IPv6.",
                    self.as_str()
                ));
            }
            p.ipv6_policy = v;
        }
        Ok(p)
    }

    /// All modes, for menu/listing.
    pub fn all() -> &'static [WideProductMode] {
        &[
            Self::SocksOnly,
            Self::WideRedirectSafe,
            Self::WideUdpDirect,
            Self::GatewayTproxy,
            Self::FullWideNfqueue,
            Self::FullWideTun,
            Self::FullWideHybridGeneva,
            Self::WideCompat,
        ]
    }
}

fn quic_from_udp(udp: WideUdpPolicy) -> WideQuicDisposition {
    match udp {
        WideUdpPolicy::MasqueDirect => WideQuicDisposition::MasqueDirect,
        WideUdpPolicy::Native => WideQuicDisposition::Native,
        WideUdpPolicy::Block | WideUdpPolicy::PreviewAllowlist => {
            WideQuicDisposition::BlockedForceTcpFallback
        }
    }
}

impl WideLeakRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotWide => "not_wide",
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

impl WideScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerApp => "per_app",
            Self::LocalHost => "local_host",
            Self::Gateway => "gateway",
        }
    }
}

impl WideQuicDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MasqueDirect => "masque_direct",
            Self::BlockedForceTcpFallback => "blocked_force_tcp_fallback",
            Self::Native => "native",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_profiles_allow_only_the_two_explicit_modes() {
        for mode in WideProductMode::all() {
            assert_eq!(
                resolve_inner_tls_device_profile(*mode, true).is_ok(),
                matches!(
                    mode,
                    WideProductMode::SocksOnly | WideProductMode::FullWideTun
                )
            );
        }
        assert!(resolve_inner_tls_device_profile(WideProductMode::FullWideTun, false).is_err());
        let profile = resolve_inner_tls_device_profile(WideProductMode::FullWideTun, true).unwrap();
        assert_eq!(profile.udp_transport, "grpc_datagram");
        assert_eq!(profile.tcp_transport, "grpc_stream");
        assert!(!profile.native_fallback);
        assert!(profile.requires_privileged_capture);
        let ingress = inner_tls_device_ingress(WideProductMode::SocksOnly, false).unwrap();
        assert!(!ingress.wide.enabled);
        assert!(!ingress.allow_fallback);
        assert_eq!(ingress.primary, crate::IngressPrimary::Socks5);
    }

    #[test]
    fn windows_device_policy_binds_full_capture_and_rejects_downgrades() {
        let cfg: crate::Settings = toml::from_str(
            r#"
mode = "relay"
[ingress]
primary = "socks5"
allow_fallback = false
[ingress.wide]
enabled = false
[relay]
server = "192.0.2.10:443"
server_name = "outer.test"
ca_cert = "outer-ca.pem"
auth_token = ""
transport_priority = ["grpc_stream"]
udp_transport_priority = ["grpc_datagram"]
tls_backend = "rustls"
[relay.inner_tls]
server_name = "inner.test"
server_ca = "inner-ca.pem"
cert = "device.pem"
key = "device.key"
[windows_tunnel]
"#,
        )
        .unwrap();
        let full = WideProductMode::FullWideTun;
        validate_inner_tls_device_settings(full, true, &cfg).unwrap();
        assert!(
            validate_inner_tls_device_settings(WideProductMode::SocksOnly, true, &cfg).is_err()
        );
        assert!(validate_inner_tls_device_settings(full, false, &cfg).is_err());
        for mutation in 0..5 {
            let mut changed = cfg.clone();
            match mutation {
                0 => {
                    changed.windows_tunnel.as_mut().unwrap().include_routes =
                        vec!["192.0.2.0/24".into()]
                }
                1 => changed.windows_tunnel.as_mut().unwrap().kill_switch = false,
                2 => changed.windows_tunnel.as_mut().unwrap().configure_dns = false,
                3 => changed.ingress.allow_fallback = true,
                _ => changed.ingress.wide.enabled = true,
            }
            assert!(validate_inner_tls_device_settings(full, true, &changed).is_err());
        }
    }

    #[test]
    fn all_modes_round_trip_str() {
        for m in WideProductMode::all() {
            assert_eq!(WideProductMode::parse_str(m.as_str()), Some(*m));
        }
    }

    #[test]
    fn safe_modes_never_default_to_native() {
        for m in WideProductMode::all() {
            let p = m.default_profile();
            if p.safe_for_hostile_network {
                assert_ne!(p.udp_policy, WideUdpPolicy::Native, "{} udp", m.as_str());
                assert_ne!(p.dns_policy, WideDnsPolicy::Native, "{} dns", m.as_str());
                assert_ne!(p.ipv6_policy, WideIpv6Policy::Native, "{} ipv6", m.as_str());
                assert_ne!(p.leak_risk, WideLeakRisk::High, "{} leak", m.as_str());
            }
        }
    }

    #[test]
    fn wide_compat_is_high_leak_and_unsafe() {
        let p = WideProductMode::WideCompat.default_profile();
        assert!(!p.safe_for_hostile_network);
        assert_eq!(p.leak_risk, WideLeakRisk::High);
        assert_eq!(p.udp_policy, WideUdpPolicy::Native);
    }

    #[test]
    fn safe_mode_rejects_native_overrides() {
        let m = WideProductMode::WideRedirectSafe;
        assert!(m.resolve(Some(WideUdpPolicy::Native), None, None).is_err());
        assert!(m.resolve(None, Some(WideDnsPolicy::Native), None).is_err());
        assert!(m.resolve(None, None, Some(WideIpv6Policy::Native)).is_err());
        // A non-native override is accepted.
        assert!(m.resolve(Some(WideUdpPolicy::Block), None, None).is_ok());
    }

    #[test]
    fn wide_compat_allows_native_override() {
        let m = WideProductMode::WideCompat;
        let p = m
            .resolve(
                Some(WideUdpPolicy::Native),
                Some(WideDnsPolicy::Native),
                None,
            )
            .expect("wide-compat permits native");
        assert_eq!(p.udp_policy, WideUdpPolicy::Native);
    }

    #[test]
    fn full_wide_nfqueue_is_partial_shaped() {
        // Target mode: TCP carried, generic UDP fail-closed, IPv6 capture/fail-closed.
        let p = WideProductMode::FullWideNfqueue.default_profile();
        assert!(p.is_wide);
        assert_eq!(p.scope, WideScope::LocalHost);
        assert_eq!(p.udp_policy, WideUdpPolicy::Block);
        assert_eq!(p.ipv6_policy, WideIpv6Policy::Capture);
        assert_eq!(
            p.platform_backend,
            WidePlatformBackend::LinuxNfqueueObserver
        );
        assert!(p.safe_for_hostile_network);
        assert_eq!(p.leak_risk, WideLeakRisk::Low);
    }

    #[test]
    fn masque_direct_mode_carries_quic() {
        let p = WideProductMode::WideUdpDirect.default_profile();
        assert_eq!(p.udp_policy, WideUdpPolicy::MasqueDirect);
        assert_eq!(p.quic, WideQuicDisposition::MasqueDirect);
    }

    #[test]
    fn hybrid_geneva_profile_snapshot_is_explicit_and_fail_closed() {
        let profile = WideProductMode::FullWideHybridGeneva.default_profile();
        let snapshot = serde_json::to_value(&profile).expect("serialize hybrid profile");

        assert_eq!(snapshot["mode"], "full-wide-hybrid-geneva");
        assert_eq!(snapshot["scope"], "local_host");
        assert_eq!(snapshot["udp_policy"], "masque_direct");
        assert_eq!(snapshot["dns_policy"], "preview");
        assert_eq!(snapshot["ipv6_policy"], "tun_carried");
        assert_eq!(snapshot["quic"], "masque_direct");
        assert_eq!(snapshot["leak_risk"], "low");
        assert_eq!(snapshot["safe_for_hostile_network"], true);
        assert_eq!(snapshot["platform_backend"], "linux_redirect");
        assert!(snapshot["tcp_ipv4"]
            .as_str()
            .is_some_and(|value| value.contains("direct Geneva")));
        assert!(snapshot["summary_note"]
            .as_str()
            .is_some_and(|value| value.contains("real destination IP")));
        assert!(snapshot["summary_note"]
            .as_str()
            .is_some_and(|value| value.contains("native passthrough is forbidden")));
    }

    #[test]
    fn hybrid_geneva_profile_rejects_route_matrix_overrides() {
        let mode = WideProductMode::FullWideHybridGeneva;
        assert!(mode
            .resolve(Some(WideUdpPolicy::Block), None, None)
            .is_err());
        assert!(mode
            .resolve(None, Some(WideDnsPolicy::Block), None)
            .is_err());
        assert!(mode
            .resolve(None, None, Some(WideIpv6Policy::Block))
            .is_err());

        assert!(mode
            .resolve(
                Some(WideUdpPolicy::MasqueDirect),
                Some(WideDnsPolicy::Preview),
                Some(WideIpv6Policy::TunCarried),
            )
            .is_ok());
    }

    #[test]
    fn existing_full_wide_tun_profile_remains_relay_only_for_tcp() {
        let profile = WideProductMode::FullWideTun.default_profile();
        assert_eq!(profile.mode, "full-wide-tun");
        assert_eq!(profile.tcp_ipv4, "captured by REDIRECT -> tunnel -> relay");
        assert_eq!(profile.udp_policy, WideUdpPolicy::MasqueDirect);
        assert_eq!(profile.ipv6_policy, WideIpv6Policy::TunCarried);
        assert!(!profile.tcp_ipv4.to_ascii_lowercase().contains("geneva"));
        assert!(!profile.summary_note.to_ascii_lowercase().contains("geneva"));
    }

    #[test]
    fn verdict_strings_stable() {
        assert_eq!(
            UbuntuWideVerdict::UbuntuFullWidePartial.as_str(),
            "UBUNTU_FULL_WIDE_PARTIAL"
        );
        assert_eq!(
            UbuntuWideVerdict::UbuntuFullWideReady.as_str(),
            "UBUNTU_FULL_WIDE_READY"
        );
    }
}
