//! v40 (CP-D3 M1, D2): the signed carrier pool's admission, its per-pin held
//! connectors and the ECH rotation of a pin's TLS name.
use super::*;
use aegis_core::{
    brain::carrier_failover::CarrierFailoverSettings, secure_channel::ClientSettings,
    RelayEndpointSettings, RelayTlsBackend, TunnelTransportFamily,
};

const EDGE: &str = "edge.fronted.test";

fn endpoint(server: &str, name: &str) -> RelayEndpointSettings {
    RelayEndpointSettings {
        server: server.into(),
        server_name: name.into(),
        masque_server: None,
        masque_server_name: None,
    }
}

/// The relay settings a signed v4 pool renders to: `pins` with their TLS
/// names, the primary first, and the default failover policy for two or
/// more pins.
fn pool(pins: &[(&str, &str)]) -> RelaySettings {
    RelaySettings {
        server: pins[0].0.into(),
        server_name: pins[0].1.into(),
        endpoints: pins.iter().map(|(pin, name)| endpoint(pin, name)).collect(),
        ca_cert: Some("/nonexistent/outer-ca.pem".into()),
        inner_tls: Some(ClientSettings {
            server_name: "origin.test".into(),
            server_ca: "/nonexistent/inner-ca.pem".into(),
            cert: "/nonexistent/device.pem".into(),
            key: "/nonexistent/device.key".into(),
        }),
        transport_priority: vec![TunnelTransportFamily::GrpcStream],
        udp_transport_priority: Some(vec![TunnelTransportFamily::GrpcDatagram]),
        tls_backend: RelayTlsBackend::Rustls,
        carrier_failover: (pins.len() >= 2).then(CarrierFailoverSettings::default),
        ..RelaySettings::default()
    }
}

fn outer_ca() -> Vec<u8> {
    rcgen::generate_simple_self_signed(vec!["relay.test".into()])
        .unwrap()
        .cert
        .pem()
        .into_bytes()
}

#[test]
fn a_signed_pool_preloads_one_held_connector_per_exact_pin_in_profile_order() {
    let settings = pool(&[
        ("192.0.2.10:443", "relay.test"),
        ("198.51.100.20:443", EDGE),
        ("198.51.100.21:443", EDGE),
    ]);
    let held = HeldCarriers::from_held(&settings, &outer_ca()).unwrap();
    assert_eq!(held.len(), 3);
    assert_eq!(
        held.pins(),
        vec![
            "192.0.2.10:443".parse::<SocketAddr>().unwrap(),
            "198.51.100.20:443".parse().unwrap(),
            "198.51.100.21:443".parse().unwrap(),
        ]
    );
    assert_eq!(held.primary().peer(), held.pins()[0]);
    // Each pin dials with its own TLS name and no pool policy: one
    // attempt is admitted exactly as a single carrier is.
    for (index, name) in [(0, "relay.test"), (1, EDGE), (2, EDGE)] {
        let carrier = held.get(index).unwrap();
        assert_eq!(carrier.relay().server, carrier.peer().to_string());
        assert_eq!(carrier.relay().server_name, name);
        assert!(carrier.relay().endpoints.is_empty());
        assert!(carrier.relay().carrier_failover.is_none());
        assert!(carrier.relay().validate_inner_tls_transport().is_ok());
        // The pin's request names its own authority.
        let request = aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
            carrier.relay(),
            None,
            aegis_core::https_bridge::Purpose::Traffic,
        )
        .unwrap();
        assert_eq!(request.uri().host(), Some(name));
    }
    assert!(held.get(3).is_none());
    // A single pin is the pool of one, exactly as before.
    let single = pool(&[("192.0.2.10:443", "relay.test")]);
    let held = HeldCarriers::from_held(&single, &outer_ca()).unwrap();
    assert_eq!(
        held.pins(),
        vec!["192.0.2.10:443".parse::<std::net::SocketAddr>().unwrap()]
    );
}

#[test]
fn a_pool_that_is_not_exact_numeric_and_primary_first_is_refused() {
    let ca = outer_ca();
    let refused = |settings: &RelaySettings| HeldCarriers::from_held(settings, &ca).is_err();
    let good = pool(&[
        ("192.0.2.10:443", "relay.test"),
        ("198.51.100.20:443", EDGE),
    ]);
    assert!(!refused(&good));
    // No explicit pool (a v3 profile), or the primary not first.
    let mut empty = good.clone();
    empty.endpoints.clear();
    assert!(refused(&empty));
    let mut reordered = good.clone();
    reordered.endpoints.swap(0, 1);
    assert!(refused(&reordered));
    // A name instead of a numeric pin (no DNS outside the tunnel), a zero
    // port, an unspecified, multicast or broadcast address.
    for bad in [
        "edge.fronted.test:443",
        "198.51.100.20:0",
        "0.0.0.0:443",
        "224.0.0.1:443",
        "255.255.255.255:443",
        "[::]:443",
    ] {
        let mut settings = good.clone();
        settings.endpoints[1].server = bad.into();
        assert!(refused(&settings), "{bad}");
    }
    // A repeated pin: the pool is exact, each pin once.
    let mut repeated = good.clone();
    repeated.endpoints[1] = endpoint("192.0.2.10:443", EDGE);
    assert!(refused(&repeated));
    // An empty TLS name.
    let mut unnamed = good.clone();
    unnamed.endpoints[1].server_name = " ".into();
    assert!(refused(&unnamed));
    // More pins than the guard's bound.
    let pins: Vec<String> = (0..=MAX_PINS)
        .map(|n| format!("198.51.100.{n}:443"))
        .collect();
    let mut oversized = pool(&[("198.51.100.0:443", "relay.test")]);
    oversized.endpoints = pins.iter().map(|pin| endpoint(pin, "relay.test")).collect();
    assert!(refused(&oversized));
    // The shapes no provider owner exists for.
    let mut bandit = good.clone();
    bandit.carrier_failover = None;
    bandit.endpoint_bandit = Some(aegis_core::RelayEndpointBanditSettings {
        algorithm: aegis_core::brain::recent_routes::paper_bandit::PaperAlgorithm::SlidingWindow {
            rounds: 16,
            xi: 1.0,
        },
        max_profiles: 16,
        max_contexts_per_profile: 16,
        pre_auth_block_ms: 1000,
        dependency_policy: None,
    });
    assert!(refused(&bandit));
    let mut shaped = good.clone();
    shaped.authenticated_shaping = Some(aegis_core::carrier_runtime::PrivacySettings {
        payload_bytes: 1024,
        cadence_ms: 10,
        buffer_bytes: 4096,
        max_wire_bytes: 8_388_608,
        io_timeout_ms: 1000,
        session_timeout_ms: 10_000,
        max_queue_delay_ms: 10_000,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    });
    assert!(refused(&shaped));
    // A held CA the connector cannot use.
    assert!(HeldCarriers::from_held(&good, b"not a certificate").is_err());
}

/// aegis-client's synthetic ECHConfigList (X25519/HKDF-SHA256, AES-128-GCM,
/// a structurally valid public key), one config per `(id, public_name)`.
pub(crate) fn synthetic_list(entries: &[(u8, &str)]) -> Vec<u8> {
    let mut configs = Vec::new();
    for (config_id, public_name) in entries {
        let mut contents = vec![*config_id, 0, 32, 0, 32, 9];
        contents.extend([0; 31]);
        contents.extend([0, 4, 0, 1, 0, 1, 0]);
        contents.push(public_name.len() as u8);
        contents.extend(public_name.as_bytes());
        contents.extend([0, 0]);
        configs.extend([0xfe, 0x0d]);
        configs.extend((contents.len() as u16).to_be_bytes());
        configs.extend(contents);
    }
    let mut list = (configs.len() as u16).to_be_bytes().to_vec();
    list.extend(configs);
    list
}

/// Standard base64 with padding (no dependency of this crate offers it).
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The handshake error an edge's authenticated ECH rejection carries.
pub(crate) fn rejection(retry: Option<&[u8]>) -> std::io::Error {
    use tokio_rustls::rustls::internal::msgs::{
        codec::{Codec, Reader},
        handshake::EchConfigPayload,
    };
    let configs = retry.map(|list| Vec::<EchConfigPayload>::read(&mut Reader::init(list)).unwrap());
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        tokio_rustls::rustls::Error::PeerIncompatible(
            tokio_rustls::rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
        ),
    )
}

/// A pool of two CDN edge pins sharing one ECH-pinned TLS name (D1 + D2);
/// the test's own name keeps its rotation apart from every other test's.
fn ech_pool(name: &str, pinned: &[u8]) -> RelaySettings {
    let mut settings = pool(&[("198.51.100.30:443", name), ("198.51.100.31:443", name)]);
    settings.ech_config_list_base64 = Some(base64(pinned));
    settings
}

#[test]
fn the_test_base64_matches_the_standard_alphabet_and_padding() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
}

#[test]
fn an_admitted_ech_rotation_rebuilds_every_pin_of_its_name_and_a_refused_redial_forgets_it() {
    let ca = outer_ca();
    let pinned = synthetic_list(&[(1, "cloudflare-ech.com")]);
    let settings = ech_pool("rotate.edge.test", &pinned);
    let held = HeldCarriers::from_held(&settings, &ca).unwrap();
    assert!(!held.has_rotation(0) && !held.has_rotation(1));
    let config =
        |index: usize| std::sync::Arc::as_ptr(held.get(index).unwrap().connector().config());
    let preloaded = (config(0), config(1));
    // Not an ECH rejection: judged as before, nothing learned.
    let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
    assert_eq!(held.ech_rejected(0, &reset, &ca), EchRedial::NotEch);
    assert!(!held.has_rotation(0));
    // A rejection without retry configs: fail closed, nothing learned.
    assert_eq!(
        held.ech_rejected(0, &rejection(None), &ca),
        EchRedial::Refused
    );
    assert!(!held.has_rotation(0));
    // Retry configs that keep the pinned public name: admitted, and every
    // pin of that TLS name now dials with them (one redial).
    let rotated = synthetic_list(&[(2, "cloudflare-ech.com")]);
    assert_eq!((config(0), config(1)), preloaded, "nothing rebuilt yet");
    assert_eq!(
        held.ech_rejected(0, &rejection(Some(&rotated)), &ca),
        EchRedial::Redial
    );
    assert!(held.has_rotation(0) && held.has_rotation(1));
    // Both pins of the name now hold a connector built with the rotation.
    let rotated_configs = (config(0), config(1));
    assert!(rotated_configs.0 != preloaded.0 && rotated_configs.1 != preloaded.1);
    // The redial was rejected too: the rotation is forgotten and every pin
    // returns to a connector built from its pinned list.
    held.forget_rotation(0, &ca);
    assert!(!held.has_rotation(0) && !held.has_rotation(1));
    assert!(config(0) != rotated_configs.0 && config(1) != rotated_configs.1);
}

#[test]
fn retry_configs_that_change_the_pinned_public_name_are_refused() {
    let ca = outer_ca();
    let pinned = synthetic_list(&[(1, "cloudflare-ech.com")]);
    let held = HeldCarriers::from_held(&ech_pool("name.edge.test", &pinned), &ca).unwrap();
    let other = synthetic_list(&[(2, "attacker.example")]);
    assert_eq!(
        held.ech_rejected(1, &rejection(Some(&other)), &ca),
        EchRedial::Refused
    );
    assert!(!held.has_rotation(0) && !held.has_rotation(1));
    // An index outside the pool learns nothing.
    let rotated = synthetic_list(&[(2, "cloudflare-ech.com")]);
    assert_eq!(
        held.ech_rejected(7, &rejection(Some(&rotated)), &ca),
        EchRedial::NotEch
    );
    assert!(!held.has_rotation(0));
}

#[test]
fn failed_rotation_rebuild_restores_all_pins_and_forgets_the_cache() {
    let ca = outer_ca();
    let pinned = synthetic_list(&[(1, "cloudflare-ech.com")]);
    let held =
        HeldCarriers::from_held(&ech_pool("failed-rebuild.edge.test", &pinned), &ca).unwrap();
    let initial: Vec<_> = (0..held.len())
        .map(|index| std::sync::Arc::as_ptr(held.get(index).unwrap().connector().config()))
        .collect();
    let rotated = synthetic_list(&[(2, "cloudflare-ech.com")]);
    // The authenticated retry list is admissible, but the held CA supplied
    // for the rebuild is invalid. No connector generation or rotation may
    // survive this failure.
    assert_eq!(
        held.ech_rejected(0, &rejection(Some(&rotated)), b"invalid CA"),
        EchRedial::Refused
    );
    assert!(!held.has_rotation(0) && !held.has_rotation(1));
    let after: Vec<_> = (0..held.len())
        .map(|index| std::sync::Arc::as_ptr(held.get(index).unwrap().connector().config()))
        .collect();
    assert_eq!(after, initial);
}

#[test]
fn a_new_pool_remembers_its_cached_generation_and_cannot_erase_a_later_rotation() {
    let ca = outer_ca();
    let pinned = synthetic_list(&[(1, "cloudflare-ech.com")]);
    let settings = ech_pool("competing.edge.test", &pinned);
    let first = HeldCarriers::from_held(&settings, &ca).unwrap();
    let first_retry = synthetic_list(&[(2, "cloudflare-ech.com")]);
    assert_eq!(
        first.ech_rejected(0, &rejection(Some(&first_retry)), &ca),
        EchRedial::Redial
    );
    let second = HeldCarriers::from_held(&settings, &ca).unwrap();
    assert!(second.has_rotation(0));
    let second_loaded: Vec<_> = (0..second.len())
        .map(|index| std::sync::Arc::as_ptr(second.get(index).unwrap().connector().config()))
        .collect();
    // A different pool learned a newer authenticated generation. The old
    // pool's failed redial must only restore its own pins; it may not erase
    // that newer global generation.
    let newer = synthetic_list(&[(3, "cloudflare-ech.com")]);
    assert_eq!(
        first.ech_rejected(0, &rejection(Some(&newer)), &ca),
        EchRedial::Redial
    );
    second.forget_rotation(0, &ca);
    assert!(aegis_client::ech_policy::has_rotation(
        second.get(0).unwrap().relay()
    ));
    let second_restored: Vec<_> = (0..second.len())
        .map(|index| std::sync::Arc::as_ptr(second.get(index).unwrap().connector().config()))
        .collect();
    assert_ne!(second_restored, second_loaded);
    first.forget_rotation(0, &ca);
    assert!(!aegis_client::ech_policy::has_rotation(
        first.get(0).unwrap().relay()
    ));
}

#[test]
fn rotation_of_one_tls_name_keeps_a_different_name_connector_immutable() {
    let ca = outer_ca();
    let pinned = synthetic_list(&[(1, "cloudflare-ech.com")]);
    let mut settings = pool(&[
        ("192.0.2.10:443", "direct-name.test"),
        ("198.51.100.30:443", "isolated-edge.test"),
        ("198.51.100.31:443", "isolated-edge.test"),
    ]);
    settings.ech_config_list_base64 = Some(base64(&pinned));
    let held = HeldCarriers::from_held(&settings, &ca).unwrap();
    let direct = std::sync::Arc::as_ptr(held.get(0).unwrap().connector().config());
    let edges =
        [1, 2].map(|index| std::sync::Arc::as_ptr(held.get(index).unwrap().connector().config()));
    let rotated = synthetic_list(&[(2, "cloudflare-ech.com")]);
    assert_eq!(
        held.ech_rejected(1, &rejection(Some(&rotated)), &ca),
        EchRedial::Redial
    );
    assert_eq!(
        std::sync::Arc::as_ptr(held.get(0).unwrap().connector().config()),
        direct
    );
    for index in [1, 2] {
        assert_ne!(
            std::sync::Arc::as_ptr(held.get(index).unwrap().connector().config()),
            edges[index - 1]
        );
    }
    held.forget_rotation(1, &ca);
    assert_eq!(
        std::sync::Arc::as_ptr(held.get(0).unwrap().connector().config()),
        direct
    );
}

#[test]
fn same_sni_direct_pin_without_ech_survives_fronted_rotation_and_new_pool() {
    use aegis_core::carrier_program::{
        CarrierChannel, CarrierEchScope, CarrierProgramSettings, CarrierRoute,
    };
    let ca = outer_ca();
    let pinned = synthetic_list(&[(1, "cloudflare-ech.com")]);
    let mut settings = pool(&[
        ("192.0.2.40:443", "shared-sni.edge.test"),
        ("198.51.100.40:443", "shared-sni.edge.test"),
        ("198.51.100.41:443", "shared-sni.edge.test"),
    ]);
    settings.ech_config_list_base64 = Some(base64(&pinned));
    settings.carrier_program = Some(CarrierProgramSettings {
        routes: vec![
            CarrierRoute {
                channel: CarrierChannel::DirectH2,
                endpoint_index: 0,
            },
            CarrierRoute {
                channel: CarrierChannel::FrontedH2,
                endpoint_index: 1,
            },
            CarrierRoute {
                channel: CarrierChannel::FrontedH2,
                endpoint_index: 2,
            },
        ],
        bridge: None,
        web_response: None,
        ech_scope: Some(CarrierEchScope::FrontedOnly),
        fronted_ech_authority: Some("shared-sni.edge.test".into()),
    });
    let first = HeldCarriers::from_held(&settings, &ca).unwrap();
    assert!(first
        .get(0)
        .unwrap()
        .relay()
        .ech_config_list_base64
        .is_none());
    assert!(first
        .get(1)
        .unwrap()
        .relay()
        .ech_config_list_base64
        .is_some());
    let direct = std::sync::Arc::as_ptr(first.get(0).unwrap().connector().config());
    let rotated = synthetic_list(&[(2, "cloudflare-ech.com")]);
    assert_eq!(
        first.ech_rejected(1, &rejection(Some(&rotated)), &ca),
        EchRedial::Redial
    );
    assert_eq!(
        std::sync::Arc::as_ptr(first.get(0).unwrap().connector().config()),
        direct
    );
    assert!(first.has_rotation(1) && first.has_rotation(2));
    assert!(!first.has_rotation(0));
    let second = HeldCarriers::from_held(&settings, &ca).unwrap();
    assert!(second.has_rotation(1) && second.has_rotation(2));
    assert!(!second.has_rotation(0));
    let direct_second = std::sync::Arc::as_ptr(second.get(0).unwrap().connector().config());
    second.forget_rotation(1, &ca);
    assert_eq!(
        std::sync::Arc::as_ptr(second.get(0).unwrap().connector().config()),
        direct_second
    );
    assert!(!second.has_rotation(1));
}
