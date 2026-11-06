//! Configuration fixtures for the separately scoped legacy TCP policy.
use super::*;

// Deterministic public test data only; never use this token for provisioning.
const SYNTHETIC_AUTH_TOKEN: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn legacy_config(limits: &str) -> ServerConfig {
    toml::from_str(&format!(
        "listen = \"127.0.0.1:8443\"\ncert = \"synthetic.pem\"\nkey = \"synthetic.key\"\nauth_token = \"{}\"\n[limits]\n{limits}",
        SYNTHETIC_AUTH_TOKEN,
    ))
    .unwrap()
}

#[test]
fn omitted_legacy_tcp_deadlines_have_finite_defaults() {
    let cfg = legacy_config("");
    assert_eq!(cfg.limits.legacy_tcp_connect_timeout_ms, 10_000);
    assert_eq!(cfg.limits.legacy_tcp_idle_timeout_ms, 300_000);
    assert_eq!(cfg.limits.write_timeout_ms, 30_000);
    cfg.validate_auth_tokens().unwrap();
}

#[test]
fn legacy_tcp_accepts_explicit_long_idle_policy_without_total_lifetime_limit() {
    let cfg = legacy_config(
        "legacy_tcp_connect_timeout_ms = 60000\nlegacy_tcp_idle_timeout_ms = 86400000\nwrite_timeout_ms = 60000\n",
    );
    cfg.validate_auth_tokens().unwrap();
    assert_eq!(cfg.limits.legacy_tcp_idle_timeout_ms, 86_400_000);
}

#[test]
fn zero_and_excessive_legacy_tcp_deadlines_are_rejected() {
    for (limits, expected_error) in [
        (
            "legacy_tcp_connect_timeout_ms = 0",
            "legacy TCP establishment timeout must be 1..60000ms",
        ),
        (
            "legacy_tcp_connect_timeout_ms = 60001",
            "legacy TCP establishment timeout must be 1..60000ms",
        ),
        (
            "legacy_tcp_idle_timeout_ms = 0",
            "legacy TCP authenticated idle timeout must be 1..86400000ms",
        ),
        (
            "legacy_tcp_idle_timeout_ms = 86400001",
            "legacy TCP authenticated idle timeout must be 1..86400000ms",
        ),
        (
            "write_timeout_ms = 0",
            "legacy TCP write timeout must be 1..60000ms",
        ),
        (
            "write_timeout_ms = 60001",
            "legacy TCP write timeout must be 1..60000ms",
        ),
    ] {
        let cfg = legacy_config(limits);
        aegis_core::auth_token::validate(&cfg.auth_token).unwrap();
        let error = cfg.validate_auth_tokens().unwrap_err();
        assert_eq!(error.to_string(), expected_error, "{limits}");
    }
}
