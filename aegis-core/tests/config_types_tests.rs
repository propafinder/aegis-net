use aegis_core::{
    IngressPrimary, LocalStealthProfile, Settings, StealthMode, TunnelTransportFamily,
    WidePlatformBackend, WideRolloutProfile, WideUdpCaptureContract,
};

#[test]
fn parse_client_example_toml_with_transport_priority() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../config.example.toml"
    ));
    let mut cfg: Settings = toml::from_str(raw).expect("parse config.example.toml");
    cfg.materialize_stealth_profiles();
    assert!(matches!(cfg.mode, aegis_core::Mode::Direct));
    assert_eq!(cfg.stealth_mode, StealthMode::Balanced);
    assert_eq!(
        cfg.local_stealth_profile,
        LocalStealthProfile::LocalHardened
    );
    assert_eq!(cfg.ingress.primary, IngressPrimary::Wide);
    assert!(!cfg.ingress.allow_fallback);
    assert!(cfg.direct.stack_profile.is_some());
    assert!(cfg.ingress.wide.enabled);
    assert_eq!(cfg.ingress.wide.platform_backend, WidePlatformBackend::Auto);
    assert_eq!(
        cfg.ingress.wide.rollout_profile,
        WideRolloutProfile::OutputOnlySafe
    );
    assert_eq!(cfg.ingress.wide.prerouting_interface, None);
    assert_eq!(cfg.ingress.wide.listen, "0.0.0.0:15080".parse().unwrap());
    assert!(!cfg.ingress.wide.capture_dns); // safe baseline: DNS capture opt-in via aegis-privileged-dns.toml.example
    assert_eq!(
        cfg.ingress.wide.udp_capture_contract,
        WideUdpCaptureContract::PreviewAllowlistOnly
    );
    assert_eq!(cfg.ingress.wide.dns_port, 53);
    assert!(cfg.ingress.wide.udp_preview_ports.is_empty());
    assert_eq!(cfg.ingress.wide.default_mark, 0);
    assert_eq!(
        cfg.relay.transport_priority,
        vec![
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::GrpcStream,
            TunnelTransportFamily::MasqueDerived,
        ]
    );
    assert!(!cfg
        .relay
        .transport_priority
        .contains(&TunnelTransportFamily::LegacyTls));
    // Neutral defaults after Phase 2.2 de-branding: the on-wire primary
    // path no longer contains the string "aegis". The legacy AEGIS-named
    // values move into the pool so per-session selection still negotiates
    // successfully against deployed servers running older defaults.
    assert_eq!(cfg.relay.websocket_path, "/socket");
    assert_eq!(
        cfg.relay.websocket_path_pool,
        vec!["/ws", "/realtime/connect", "/aegis/ws"]
    );
    assert_eq!(cfg.relay.grpc_path, "/rpc.Tunnel/Open");
    assert_eq!(
        cfg.relay.grpc_path_pool,
        vec![
            "/cdn.tunnel.v1.Session/Open",
            "/grpc.gateway.v1.Proxy/Connect",
            "/aegis.tunnel.v1.TunnelService/Open"
        ]
    );
    assert_eq!(cfg.relay.masque_path, "/.well-known/masque/udp");
    assert_eq!(
        cfg.relay.masque_path_pool,
        vec![
            "/.well-known/masque/connect-udp",
            "/masque/v1/udp",
            "/relay/datagram"
        ]
    );
    assert_eq!(cfg.relay.masque_keep_alive_interval_ms, 10_000);
    assert_eq!(cfg.relay.masque_max_idle_timeout_ms, 120_000);
    assert_eq!(cfg.relay.tls_profile_target_class, None);
    assert!(cfg.relay.policy.rotate_transports_per_session);
    assert_eq!(cfg.relay.policy.max_transport_attempts, 4);
    assert_eq!(cfg.relay.policy.write_chunk_size, 16 * 1024);
    assert_eq!(cfg.relay.policy.inter_chunk_delay_ms, 0);
    assert_eq!(cfg.relay.policy.drift_epoch_secs, 900);
}

#[test]
fn parse_phase_b_tls_profile_target_class() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "relay"

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "token"
tls_profile_target_class = "https_ws"
"#,
    )
    .expect("parse tls profile target config");
    assert_eq!(
        cfg.relay.tls_profile_target_class.as_deref(),
        Some("https_ws")
    );
}

#[test]
fn parse_explicit_wide_rollout_profile() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "direct"

[ingress]
primary = "wide"

[ingress.wide]
rollout_profile = "transparent_privileged"
"#,
    )
    .expect("parse rollout_profile config");
    assert_eq!(
        cfg.ingress.wide.rollout_profile,
        WideRolloutProfile::TransparentPrivileged
    );
}

#[test]
fn parse_prerouting_interface_scope() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "direct"

[ingress]
primary = "wide"

[ingress.wide]
rollout_profile = "prerouting_scoped"
prerouting_interface = "eth0"
"#,
    )
    .expect("parse prerouting interface config");
    assert_eq!(
        cfg.ingress.wide.rollout_profile,
        WideRolloutProfile::PreroutingScoped
    );
    assert_eq!(
        cfg.ingress.wide.prerouting_interface.as_deref(),
        Some("eth0")
    );
}

#[test]
fn parse_explicit_linux_redirect_backend() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "direct"

[ingress]
primary = "wide"

[ingress.wide]
platform_backend = "linux_redirect"
"#,
    )
    .expect("parse linux_redirect config");
    assert_eq!(
        cfg.ingress.wide.platform_backend,
        WidePlatformBackend::LinuxRedirect
    );
}

#[test]
fn parse_explicit_dns_port_override() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "direct"

[ingress]
primary = "wide"

[ingress.wide]
capture_dns = true
dns_port = 5353
"#,
    )
    .expect("parse dns_port config");
    assert!(cfg.ingress.wide.capture_dns);
    assert_eq!(cfg.ingress.wide.dns_port, 5353);
}

#[test]
fn parse_explicit_udp_preview_ports_override() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "direct"

[ingress]
primary = "wide"

[ingress.wide]
capture_dns = true
dns_port = 53
udp_preview_ports = [5353, 853]
"#,
    )
    .expect("parse udp_preview_ports config");
    assert!(cfg.ingress.wide.capture_dns);
    assert_eq!(cfg.ingress.wide.dns_port, 53);
    assert_eq!(cfg.ingress.wide.udp_preview_ports, vec![5353, 853]);
}

#[test]
fn parse_explicit_udp_capture_contract_override() {
    let cfg: Settings = toml::from_str(
        r#"
mode = "direct"

[ingress]
primary = "wide"

[ingress.wide]
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
"#,
    )
    .expect("parse udp_capture_contract config");
    assert!(cfg.ingress.wide.capture_dns);
    assert_eq!(
        cfg.ingress.wide.udp_capture_contract,
        WideUdpCaptureContract::GenericCaptureUnstable
    );
}

#[test]
fn reject_unknown_top_level_and_nested_config_keys() {
    let top_level = toml::from_str::<Settings>(
        r#"
mode = "relay"
transports = ["grpc_stream"]
"#,
    )
    .expect_err("unknown top-level transport pin must not be silently ignored");
    assert!(top_level.to_string().contains("unknown field `transports`"));

    let nested = toml::from_str::<Settings>(
        r#"
mode = "relay"

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "token"
transport_priorty = ["grpc_stream"]
"#,
    )
    .expect_err("misspelled nested key must not be silently ignored");
    assert!(nested
        .to_string()
        .contains("unknown field `transport_priorty`"));
}
