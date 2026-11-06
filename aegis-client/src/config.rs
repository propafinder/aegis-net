use aegis_core::Settings;
use anyhow::Context;
#[cfg(test)]
use std::fs;
use std::path::Path;

pub fn load_config(path: impl AsRef<Path>) -> anyhow::Result<Settings> {
    let p = path.as_ref();
    let bytes = aegis_core::secret_file::read_config(p, 4 * 1024 * 1024)
        .context("config_file_access_rejected")?;
    let s = std::str::from_utf8(&bytes).context("config_encoding_invalid")?;
    // TOML's Display includes source lines, which can contain credentials.
    let mut cfg: Settings =
        toml::from_str(s).map_err(|_| anyhow::anyhow!("config_parse_invalid"))?;
    cfg.validate_privacy_plan().map_err(anyhow::Error::msg)?;
    #[cfg(not(windows))]
    if cfg.windows_tunnel.is_some() {
        anyhow::bail!("Windows system tunnel cannot run on this platform");
    }
    cfg.socks
        .validate_tcp_policy()
        .map_err(anyhow::Error::msg)?;
    if !cfg.relay.auth_token.is_empty() {
        aegis_core::auth_token::validate(&cfg.relay.auth_token).map_err(anyhow::Error::msg)?;
    }
    cfg.materialize_stealth_profiles();
    cfg.validate_ech().map_err(anyhow::Error::msg)?;
    cfg.validate_inner_tls().map_err(anyhow::Error::msg)?;
    cfg.validate_relay_outer_geneva()
        .map_err(anyhow::Error::msg)?;
    let base = p.parent().unwrap_or_else(|| Path::new("."));
    if let Some(ca) = &mut cfg.relay.masque_ca_cert {
        if ca.is_relative() {
            *ca = base.join(&*ca);
        }
    }
    if let Some(ech) = &mut cfg.relay.ech_config_list {
        if ech.is_relative() {
            *ech = base.join(&*ech);
        }
    }
    if let Some(inner) = &mut cfg.relay.inner_tls {
        inner.resolve_paths(base);
        if let Some(bridge) = &cfg.relay.https_bridge {
            crate::device_bundle::online::validate_https_bridge_credential_file(bridge)?;
            anyhow::ensure!(
                bridge.credential_file != inner.key && bridge.credential_file != inner.cert,
                "HTTPS bridge credential rejected"
            );
            bridge
                .load_credential()
                .map_err(|_| anyhow::anyhow!("HTTPS bridge credential rejected"))?;
        }
        if let Some(web) = &cfg.relay.web_response {
            aegis_client::device_web_response::credential(web, &inner.key, &inner.cert)?;
        }
        if let Some(outer_ca) = &mut cfg.relay.ca_cert {
            if outer_ca.is_relative() {
                *outer_ca = base.join(&*outer_ca);
            }
        }
        aegis_core::secure_channel::Client::load(inner)
            .context("validate inner TLS identity and trust")?;
    }
    cfg.validate_hybrid_geneva()
        .map_err(anyhow::Error::msg)
        .context("validate hybrid Geneva config")?;
    validate_hybrid_build_compatibility(&cfg)?;
    #[cfg(target_os = "linux")]
    if cfg.ingress.primary == aegis_core::IngressPrimary::Wide {
        crate::ingress::wide::dns_preview::validate_dns_preview_config(
            &cfg.ingress.wide,
            &cfg.relay,
        )
        .context("validate DNS preview bootstrap config")?;
    }
    Ok(cfg)
}

// Match fresh legacy carrier admission: authenticated inner TLS is exempt.
pub(crate) fn validate_hybrid_build_compatibility(cfg: &Settings) -> anyhow::Result<()> {
    anyhow::ensure!(
        !(cfg!(feature = "legacy-challenge-v1")
            && cfg.direct.hybrid_geneva
            && cfg.relay.inner_tls.is_none()),
        "hybrid Geneva shared-token fallback is incompatible with legacy-challenge-v1 raw-only mode"
    );
    Ok(())
}

pub use aegis_client::runtime_paths::expand_tilde;

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{LocalStealthProfile, StealthMode};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scoped_masque_ca_resolves_from_config_parent_without_changing_edge_trust() {
        let path = unique_temp_path("aegis-scoped-masque-ca");
        let ca = path.with_extension("masque-ca.pem");
        fs::write(&ca, b"public-ca-fixture").unwrap();
        for reference in [
            ca.file_name().unwrap().to_string_lossy().into_owned(),
            ca.to_string_lossy().into_owned(),
        ] {
            fs::write(
                &path,
                format!(
                    "mode = 'relay'\n[relay]\nserver = '127.0.0.1:443'\nauth_token = ''\nca_cert = '/edge/system-ca.pem'\nmasque_ca_cert = '{reference}'\n"
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let cfg = load_config(&path).unwrap();
            assert_eq!(cfg.relay.masque_ca_cert.as_deref(), Some(ca.as_path()));
            assert_eq!(
                fs::read(cfg.relay.masque_ca_cert.unwrap()).unwrap(),
                b"public-ca-fixture"
            );
            assert_eq!(
                cfg.relay.ca_cert.as_deref(),
                Some(Path::new("/edge/system-ca.pem"))
            );
        }
        fs::write(&path, "mode = 'relay'\n").unwrap();
        assert!(load_config(&path).unwrap().relay.masque_ca_cert.is_none());
        fs::remove_file(ca).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn privacy_admission_precedes_missing_identity_and_invalid_secret_validation() {
        let path = unique_temp_path("aegis-privacy-first");
        for request in [
            "packet_modifiers = ['poisson_schedule']",
            "packet_modifiers = ['constant_cadence', 'randomized_schedule']",
            "requested_guarantee = 'whole_flow_differential_privacy'",
        ] {
            fs::write(&path, format!("mode = 'relay'\n[privacy_plan]\n{request}\n[relay]\nserver = '127.0.0.1:443'\nserver_name = 'relay.test'\nauth_token = 'synthetic-secret-not-to-render'\nca_cert = 'absent-outer'\ntransport_priority = ['grpc_stream']\nudp_transport_priority = []\n[relay.inner_tls]\nserver_name = 'relay.test'\nserver_ca = 'absent-ca'\ncert = 'absent-cert'\nkey = 'absent-key'\n")).unwrap();
            let error = format!("{:#}", load_config(&path).unwrap_err());
            assert!(error.starts_with("privacy_plan:"), "{error}");
            assert!(!error.contains("identity"));
            assert!(!error.contains("synthetic-secret"));
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn exponential_owner_and_public_gap_admission_precede_identity_loading() {
        let path = unique_temp_path("aegis-exponential-owner");
        for (declared, pacing, cadence, queue, expected) in [
            ("constant_cadence", true, 1000, 5500, "differs"),
            ("poisson_schedule", false, 1000, 5500, "differs"),
            ("poisson_schedule", true, 999, 5500, "runtime profile"),
            ("poisson_schedule", true, 1000, 5499, "runtime profile"),
            // Correct public plan reaches private identity validation, and only
            // then refuses this deliberately absent test key/trust material.
            (
                "poisson_schedule",
                true,
                1000,
                5500,
                "validate inner TLS identity",
            ),
        ] {
            let optional_pacing = if pacing {
                "[relay.authenticated_shaping.poisson_pacing]\nmean_interval_us = 1000\nmax_gap_us = 1000000\n"
            } else {
                ""
            };
            fs::write(&path, format!("mode = 'relay'\n[privacy_plan]\npacket_modifiers = ['{declared}']\n[privacy_plan.framing_budget]\nmax_payload_bytes = 256\nmax_buffer_bytes = 1024\nmax_wire_bytes_per_direction = 8192\nmax_session_ms = 10000\nmax_queue_delay_ms = 5500\n[relay]\nserver = '127.0.0.1:443'\nserver_name = 'relay.test'\nauth_token = ''\nca_cert = 'absent-outer'\ntls_backend = 'rustls'\ntransport_priority = ['grpc_stream']\nudp_transport_priority = []\n[relay.inner_tls]\nserver_name = 'relay.test'\nserver_ca = 'absent-ca'\ncert = 'absent-cert'\nkey = 'absent-key'\n[relay.authenticated_shaping]\npayload_bytes = 256\ncadence_ms = {cadence}\nbuffer_bytes = 1024\nmax_wire_bytes = 8192\nio_timeout_ms = 100\nsession_timeout_ms = 10000\nmax_queue_delay_ms = {queue}\n{optional_pacing}")).unwrap();
            let error = format!("{:#}", load_config(&path).unwrap_err());
            assert!(error.contains(expected), "{error}");
            if expected != "validate inner TLS identity" {
                assert!(error.starts_with("privacy_plan:"), "{error}");
                assert!(!error.contains("validate inner TLS identity"));
            }
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn socks_config_rejects_unsupported_identity_policies() {
        for policy in [
            "allowed_uids = [0]",
            "unix_socket = 'unused-test-socks.sock'",
        ] {
            let path = unique_temp_path("aegis-socks-policy");
            fs::write(
                &path,
                format!("mode = 'relay'\n[socks]\nlisten = '127.0.0.1:0'\n{policy}\n"),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let error = format!("{:#}", load_config(&path).unwrap_err());
            assert!(error.contains("unsupported"), "{error}");
            fs::remove_file(path).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preview_bootstrap_config_accepts_staged_socks_then_requires_pinning() {
        let path = unique_temp_path("aegis-preview-bootstrap");
        let source = r#"
mode = "relay"
[ingress]
primary = "socks5"
[ingress.wide]
enabled = true
dns_preview_listen = "127.0.0.1:0"
[relay]
server = "unresolved.example.test:443"
server_name = "relay.example.test"
auth_token = "28f468436cfb55b06488208e057a22207ac36977d0af34507b0fc67f149e8b28"
transport_priority = ["legacy_tls"]
"#;
        fs::write(&path, source).unwrap();
        load_config(&path).expect("staged SOCKS install does not activate DNS preview");
        fs::write(
            &path,
            source.replace("primary = \"socks5\"", "primary = \"wide\""),
        )
        .unwrap();
        assert!(format!("{:#}", load_config(&path).unwrap_err()).contains("dns_preview_bootstrap"));
        fs::write(
            &path,
            source
                .replace("primary = \"socks5\"", "primary = \"wide\"")
                .replace("unresolved.example.test:443", "127.0.0.1:443"),
        )
        .unwrap();
        let cfg = load_config(&path).expect("numeric dial + DNS TLS authority");
        assert_eq!(cfg.relay.server_name, "relay.example.test");
        fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preview_bootstrap_config_checks_inline_and_array_table_endpoints() {
        let path = unique_temp_path("aegis-preview-endpoints");
        let base = r#"
mode = "relay"
[ingress]
primary = "wide"
[ingress.wide]
dns_preview_listen = "127.0.0.1:0"
[relay]
server = ""
server_name = ""
auth_token = "28f468436cfb55b06488208e057a22207ac36977d0af34507b0fc67f149e8b28"
transport_priority = ["legacy_tls"]
"#;
        for endpoints in [
            "endpoints = [{ server = \"ENDPOINT:443\", server_name = \"relay.test\" }]",
            "[[relay.endpoints]]\nserver = \"ENDPOINT:443\"\nserver_name = \"relay.test\"",
        ] {
            for endpoint in ["relay.test", "198.18.0.2", "127.0.0.1"] {
                fs::write(
                    &path,
                    format!("{base}{}", endpoints.replace("ENDPOINT", endpoint)),
                )
                .unwrap();
                assert_eq!(
                    load_config(&path).is_ok(),
                    endpoint == "127.0.0.1",
                    "{endpoint} / {endpoints}"
                );
            }
        }
        fs::remove_file(path).unwrap();
    }

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{name}-{}-{nonce}.toml", std::process::id()));
        #[cfg(windows)]
        {
            aegis_core::windows_file::write_private_new(&path, b"", false).unwrap();
            path
        }
        #[cfg(not(windows))]
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&path).unwrap();
            path
        }
    }

    #[test]
    fn parse_errors_never_render_config_secrets() {
        let path = unique_temp_path("aegis-invalid-secret");
        fs::write(&path, "auth_token = 'synthetic-do-not-print\n").unwrap();
        let message = format!("{:#}", load_config(&path).unwrap_err());
        assert!(message.contains("config_parse_invalid"));
        assert!(!message.contains("synthetic-do-not-print"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_config_applies_local_stealth_profile_defaults() {
        let path = unique_temp_path("aegis-local-stealth-profile");
        fs::write(
            &path,
            r#"
mode = "direct"
local_stealth_profile = "local_hardened"

[ingress]
allow_fallback = true

[direct]
state_path = "~/.cache/aegis/state.json"
"#,
        )
        .expect("write config");

        let cfg = load_config(&path).expect("load config");
        assert_eq!(
            cfg.local_stealth_profile,
            LocalStealthProfile::LocalHardened
        );
        assert!(!cfg.ingress.allow_fallback);
        assert!(cfg.process_alias.is_some());
        assert_ne!(
            cfg.direct.state_path,
            std::path::PathBuf::from("~/.cache/aegis/state.json")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_preserves_explicit_local_overrides_under_profile() {
        let path = unique_temp_path("aegis-local-stealth-overrides");
        fs::write(
            &path,
            r#"
mode = "direct"
local_stealth_profile = "local_hardened"
process_alias = "manual-agentd"

[ingress]
allow_fallback = true

[direct]
state_path = "/tmp/custom-state.json"
"#,
        )
        .expect("write config");

        let cfg = load_config(&path).expect("load config");
        assert_eq!(cfg.process_alias.as_deref(), Some("manual-agentd"));
        assert!(!cfg.ingress.allow_fallback);
        assert_eq!(
            cfg.direct.state_path,
            std::path::PathBuf::from("/tmp/custom-state.json")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_materializes_balanced_stealth_mode() {
        let path = unique_temp_path("aegis-balanced-stealth-mode");
        fs::write(
            &path,
            r#"
mode = "direct"
stealth_mode = "balanced"
"#,
        )
        .expect("write config");

        let cfg = load_config(&path).expect("load config");
        assert_eq!(cfg.stealth_mode, StealthMode::Balanced);
        assert_eq!(
            cfg.local_stealth_profile,
            LocalStealthProfile::LocalHardened
        );
        assert!(cfg.direct.stack_profile.is_some());
        assert!(!cfg.ingress.allow_fallback);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_preserves_explicit_stack_profile_under_balanced_stealth_mode() {
        let path = unique_temp_path("aegis-balanced-stealth-stack-profile");
        fs::write(
            &path,
            r#"
mode = "direct"
stealth_mode = "balanced"

[direct]
stack_profile = "macos"
"#,
        )
        .expect("write config");

        let cfg = load_config(&path).expect("load config");
        assert_eq!(cfg.direct.stack_profile.as_deref(), Some("macos"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_preserves_windows_client_paths() {
        let path = unique_temp_path("aegis-windows-client-paths");
        fs::write(
            &path,
            r#"
mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = true

[socks]
listen = "127.0.0.1:1080"

[direct]
state_path = 'C:\Users\aegis\AppData\Local\AEGIS\state\state.json'

[relay]
server = "192.0.2.10:8443"
server_name = "relay.example.invalid"
auth_token = "ba8b7bb8335065943f8fb805e41f83f879ca6d7fe2374cef4fd988160eaa823e" # SHA-256 of a public fixture label; never issued.
ca_cert = 'C:\ProgramData\AEGIS\client\ca.pem'
"#,
        )
        .expect("write config");

        let cfg = load_config(&path).expect("load config");
        assert_eq!(cfg.socks.listen.to_string(), "127.0.0.1:1080");
        assert_eq!(
            cfg.direct.state_path,
            std::path::PathBuf::from(r"C:\Users\aegis\AppData\Local\AEGIS\state\state.json")
        );
        assert_eq!(
            cfg.relay.ca_cert,
            Some(std::path::PathBuf::from(
                r"C:\ProgramData\AEGIS\client\ca.pem"
            ))
        );
        let _ = fs::remove_file(path);
    }

    fn valid_hybrid_geneva_config() -> &'static str {
        r#"
mode = "auto"

[direct]
strategies = ["geneva"]
geneva_strategy = '[TCP:flags:PA]-duplicate(,)-| \/'
hybrid_geneva = true

[relay]
server = "front.example.test:443"
server_name = "front.example.test"
auth_token = "4bb47b50331913110a3d9bc7cd1e9ab5a131ddc8a21e70167b32be650cfccf45"
transport_priority = ["grpc_stream"]
udp_transport_priority = ["masque_derived", "grpc_datagram"]
masque_server = "203.0.113.10:443"
masque_server_name = "masque.example.test"
"#
    }

    #[cfg(not(feature = "legacy-challenge-v1"))]
    #[test]
    fn load_config_accepts_complete_hybrid_geneva_contract() {
        let path = unique_temp_path("aegis-hybrid-geneva-valid");
        fs::write(&path, valid_hybrid_geneva_config()).expect("write config");

        let cfg = load_config(&path).expect("load complete hybrid config");
        assert!(cfg.direct.hybrid_geneva);
        assert_eq!(cfg.direct.strategies, ["geneva"]);
        let encoded = toml::to_string(&cfg).expect("serialize hybrid config");
        let round_trip: Settings =
            toml::from_str(&encoded).expect("parse serialized hybrid config");
        round_trip
            .validate_hybrid_geneva()
            .expect("round-tripped hybrid contract");
        assert!(round_trip.direct.hybrid_geneva);
        assert_eq!(round_trip.direct.strategies, ["geneva"]);
        let _ = fs::remove_file(path);
    }

    #[cfg(feature = "legacy-challenge-v1")]
    #[test]
    fn load_config_rejects_otherwise_valid_raw_only_hybrid_build() {
        let cfg: Settings = toml::from_str(valid_hybrid_geneva_config()).unwrap();
        cfg.validate_hybrid_geneva()
            .expect("ordinary hybrid contract is valid");
        let path = unique_temp_path("aegis-hybrid-raw-build-refusal");
        fs::write(&path, valid_hybrid_geneva_config()).unwrap();
        let error = load_config(&path).expect_err("raw-only build cannot serve hybrid gRPC");
        assert_eq!(error.to_string(), "hybrid Geneva shared-token fallback is incompatible with legacy-challenge-v1 raw-only mode");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn hybrid_build_guard_preserves_authenticated_inner_tls_and_plain_raw_relay() {
        let mut cfg: Settings = toml::from_str(valid_hybrid_geneva_config()).unwrap();
        cfg.relay.inner_tls = Some(aegis_core::secure_channel::ClientSettings {
            server_name: "fixture.test".into(),
            server_ca: "fixture-ca.pem".into(),
            cert: "fixture-cert.pem".into(),
            key: "fixture-key.pem".into(),
        });
        // Pure compatibility only; load_config still validates actual identity files.
        cfg.validate_hybrid_geneva().unwrap();
        validate_hybrid_build_compatibility(&cfg).expect("secure carrier is exempt");
        cfg.relay.inner_tls = None;
        cfg.direct.hybrid_geneva = false;
        validate_hybrid_build_compatibility(&cfg).expect("ordinary raw relay remains admitted");
    }

    #[test]
    fn load_config_rejects_hybrid_geneva_passthrough() {
        let path = unique_temp_path("aegis-hybrid-geneva-passthrough");
        let text = valid_hybrid_geneva_config().replace(
            "strategies = [\"geneva\"]",
            "strategies = [\"geneva\", \"passthrough\"]",
        );
        fs::write(&path, text).expect("write config");

        let error = load_config(&path).expect_err("passthrough must fail closed");
        assert!(format!("{error:#}").contains("native passthrough"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_hybrid_geneva_without_exact_relay_plans() {
        let path = unique_temp_path("aegis-hybrid-geneva-relays");
        let text = valid_hybrid_geneva_config().replace(
            "transport_priority = [\"grpc_stream\"]",
            "transport_priority = [\"https_ws\", \"grpc_stream\"]",
        );
        fs::write(&path, text).expect("write config");

        let error = load_config(&path).expect_err("non-pinned TCP plan must fail");
        assert!(format!("{error:#}").contains("authenticated gRPC relay"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_hybrid_geneva_without_direct_masque_endpoint() {
        let path = unique_temp_path("aegis-hybrid-geneva-masque");
        let text = valid_hybrid_geneva_config().replace(
            "masque_server = \"203.0.113.10:443\"",
            "masque_server = \"\"",
        );
        fs::write(&path, text).expect("write config");

        let error = load_config(&path).expect_err("missing MASQUE endpoint must fail");
        assert!(format!("{error:#}").contains("MASQUE relay"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_hybrid_geneva_outside_auto_mode() {
        let path = unique_temp_path("aegis-hybrid-geneva-mode");
        let text = valid_hybrid_geneva_config().replace("mode = \"auto\"", "mode = \"direct\"");
        fs::write(&path, text).expect("write config");

        let error = load_config(&path).expect_err("direct mode must not claim hybrid handoff");
        assert!(format!("{error:#}").contains("requires mode=auto"));
        let _ = fs::remove_file(path);
    }
}
