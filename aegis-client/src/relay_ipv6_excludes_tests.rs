//! Actual configuration and pre-capture exclusion controls; no worker or route activation.

use super::{relay_ipv6_excludes, Settings};
use aegis_core::wide_product::{
    inner_tls_device_ingress, validate_inner_tls_device_settings, WideProductMode,
};
use aegis_core::{
    IngressPrimary, Mode, RelayEndpointSettings, RelaySettings, TunnelTransportFamily,
};
use std::net::IpAddr;

fn ip(address: &str) -> IpAddr {
    address.parse().unwrap()
}

fn endpoint(server: &str, masque_server: Option<&str>) -> RelayEndpointSettings {
    RelayEndpointSettings {
        server: server.into(),
        server_name: "relay.example.test".into(),
        masque_server: masque_server.map(str::to_owned),
        masque_server_name: masque_server.map(|_| "masque.example.test".into()),
    }
}

fn load_private_config(directory: &tempfile::TempDir, name: &str, settings: &Settings) -> Settings {
    let path = directory.path().join(name);
    aegis_core::secret_file::write_private_new(
        &path,
        toml::to_string(settings).unwrap().as_bytes(),
    )
    .unwrap();
    let loaded = crate::config::load_config(&path).unwrap();
    // The general loader calls this on Linux. Exercise the same production
    // bootstrap gate on the other supported test hosts, without a copied rule.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    crate::ingress::wide::dns_preview::validate_dns_preview_config(
        &loaded.ingress.wide,
        &loaded.relay,
    )
    .unwrap();
    assert!(matches!(loaded.mode, Mode::Relay));
    assert_eq!(loaded.ingress.primary, IngressPrimary::Wide);
    assert!(loaded.ingress.wide.enabled);
    assert!(loaded.ingress.wide.ipv6_tun_carried);
    assert!(!loaded.ingress.allow_fallback);
    loaded
}

fn custom_fullwide(relay: RelaySettings) -> Settings {
    let mut settings = Settings {
        mode: Mode::Relay,
        ingress: inner_tls_device_ingress(WideProductMode::FullWideTun, true).unwrap(),
        relay,
        ..Default::default()
    };
    settings.relay.inner_tls = None;
    settings.relay.server_name = "relay.example.test".into();
    // Synthetic non-repeated bytes satisfy the actual admission validator.
    settings.relay.auth_token = (0..32).map(|byte| format!("{byte:02x}")).collect();
    settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
    let directory = tempfile::tempdir().unwrap();
    load_private_config(&directory, "custom.toml", &settings)
}

#[test]
fn custom_fullwide_top_level_masque_ipv6_is_in_actual_pre_capture_exclusions() {
    let mut relay = Settings::default().relay;
    relay.server = "192.0.2.10:443".into();
    relay.masque_server = Some("[2001:db8::41]:443".into());
    let loaded = custom_fullwide(relay);
    assert_eq!(relay_ipv6_excludes(&loaded.relay), vec![ip("2001:db8::41")]);
}

#[test]
fn custom_fullwide_shared_and_endpoint_specific_masque_ipv6_are_both_excluded() {
    let mut relay = Settings::default().relay;
    relay.server = "192.0.2.10:443".into();
    relay.masque_server = Some("[2001:db8::41]:443".into());
    relay.endpoints = vec![
        endpoint("192.0.2.11:443", None),
        endpoint("192.0.2.12:443", Some("[2001:db8::42]:8443")),
    ];
    let loaded = custom_fullwide(relay);
    assert_eq!(
        relay_ipv6_excludes(&loaded.relay),
        vec![ip("2001:db8::41"), ip("2001:db8::42")]
    );
}

#[test]
fn custom_fullwide_endpoint_only_masque_ipv6_is_excluded_without_shared_override() {
    let mut relay = Settings::default().relay;
    relay.server = "192.0.2.10:443".into();
    relay.endpoints = vec![endpoint("192.0.2.11:443", Some("[2001:db8::42]:8443"))];
    let loaded = custom_fullwide(relay);
    assert_eq!(relay_ipv6_excludes(&loaded.relay), vec![ip("2001:db8::42")]);
}

#[test]
fn custom_fullwide_ipv4_masque_keeps_empty_ipv6_exclusions() {
    let mut relay = Settings::default().relay;
    relay.server = "192.0.2.10:443".into();
    relay.masque_server = Some("192.0.2.41:443".into());
    relay.endpoints = vec![endpoint("192.0.2.11:443", Some("192.0.2.42:8443"))];
    let loaded = custom_fullwide(relay);
    assert!(relay_ipv6_excludes(&loaded.relay).is_empty());
}

#[test]
fn custom_fullwide_tcp_then_masque_exclusions_are_stable_and_deduplicated_by_ip() {
    let mut relay = Settings::default().relay;
    relay.server = "[2001:db8::10]:443".into();
    relay.masque_server = Some("[2001:db8::11]:8443".into());
    relay.endpoints = vec![
        endpoint("[2001:db8::11]:443", Some("[2001:db8::41]:8443")),
        endpoint("[2001:db8::10]:8443", Some("[2001:db8::41]:443")),
        endpoint("192.0.2.11:443", Some("[2001:db8::42]:443")),
    ];
    let loaded = custom_fullwide(relay);
    assert_eq!(
        relay_ipv6_excludes(&loaded.relay),
        vec![
            ip("2001:db8::10"),
            ip("2001:db8::11"),
            ip("2001:db8::41"),
            ip("2001:db8::42")
        ]
    );
}

#[test]
fn custom_fullwide_masque_fallback_retains_existing_tcp_ipv6_exclusions() {
    let mut relay = Settings::default().relay;
    relay.server = "[2001:db8::10]:443".into();
    relay.endpoints = vec![endpoint("[2001:db8::11]:443", None)];
    let loaded = custom_fullwide(relay);
    assert_eq!(
        relay_ipv6_excludes(&loaded.relay),
        vec![ip("2001:db8::10"), ip("2001:db8::11")]
    );
}

#[test]
fn masque_override_collection_uses_only_socket_address_literals() {
    let mut relay = Settings::default().relay;
    relay.server = "[2001:db8::10]:443".into();
    relay.masque_server = Some("unresolved-masque.invalid:443".into());
    relay.endpoints = vec![
        endpoint("192.0.2.11:443", Some("2001:db8::41")),
        endpoint("192.0.2.12:443", Some("[2001:db8::42]:not-a-port")),
    ];
    // Invalid direct dial inputs intentionally bypass the configuration loader.
    // The actual collector must not add DNS support to the SocketAddr dial path.
    assert_eq!(relay_ipv6_excludes(&relay), vec![ip("2001:db8::10")]);
}

#[test]
fn actual_strict_fullwide_device_gate_still_rejects_top_level_and_endpoint_masque() {
    let directory = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["inner.example.test".into()]).unwrap();
    let certificate = directory.path().join("fixture-cert.pem");
    let key = directory.path().join("fixture-key.pem");
    aegis_core::secret_file::write_private_new(&certificate, cert.pem().as_bytes()).unwrap();
    aegis_core::secret_file::write_private_new(&key, key_pair.serialize_pem().as_bytes()).unwrap();
    let mut settings = Settings {
        mode: Mode::Relay,
        ingress: inner_tls_device_ingress(WideProductMode::FullWideTun, true).unwrap(),
        ..Default::default()
    };
    settings.relay.server = "192.0.2.10:443".into();
    settings.relay.server_name = "relay.example.test".into();
    settings.relay.auth_token.clear();
    settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
    settings.relay.ca_cert = Some(certificate.clone());
    settings.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
    settings.relay.inner_tls = Some(aegis_core::secure_channel::ClientSettings {
        server_name: "inner.example.test".into(),
        server_ca: certificate.clone(),
        cert: certificate,
        key,
    });
    let valid = load_private_config(&directory, "device.toml", &settings);
    validate_inner_tls_device_settings(WideProductMode::FullWideTun, true, &valid).unwrap();

    let mut top_level = settings.clone();
    top_level.relay.masque_server = Some("[2001:db8::41]:443".into());
    let loaded = load_private_config(&directory, "device-top-level-masque.toml", &top_level);
    assert_eq!(
        validate_inner_tls_device_settings(WideProductMode::FullWideTun, true, &loaded)
            .unwrap_err(),
        "inner TLS device transport or capture policy changed"
    );

    let mut pooled = settings;
    pooled.relay.endpoints = vec![endpoint("192.0.2.10:443", Some("[2001:db8::42]:8443"))];
    let loaded = load_private_config(&directory, "device-endpoint-masque.toml", &pooled);
    assert_eq!(
        validate_inner_tls_device_settings(WideProductMode::FullWideTun, true, &loaded)
            .unwrap_err(),
        "inner TLS relay pool contains an invalid or duplicate endpoint"
    );
}
