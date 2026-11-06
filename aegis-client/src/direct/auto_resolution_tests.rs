//! Candidate owner controls. Resolver injection counts actual route selection;
//! no carrier/authenticated open or target-network success is simulated here.

use super::*;
use aegis_core::{
    AsyncStateStore, ExternalCalibrationSnapshot, ExternalKnowledgePrior, TunnelTransportFamily,
};
use std::cell::Cell;

fn target() -> ConnectTarget {
    ConnectTarget {
        host: "route-owner.example".into(),
        port: 443,
    }
}
fn deferred() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}
fn ready_relay() -> RelaySettings {
    RelaySettings {
        auth_token: "controlled-fixture-credential".into(),
        transport_priority: vec![TunnelTransportFamily::GrpcStream],
        ..RelaySettings::default()
    }
}
fn brain() -> Brain {
    Brain::new(
        0.0,
        vec!["passthrough".into()],
        AsyncStateStore::ephemeral(),
    )
}
fn dns_error() -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "controlled local lookup refusal",
    ))
}

#[tokio::test]
async fn dns_failure_selects_admitted_relay_by_original_name() {
    let count = Cell::new(0);
    let target = target();
    let relay = ready_relay();
    assert!(relay::runtime_fallback_ready(&relay));
    let route = select_auto_target_route_with(
        &target,
        deferred(),
        &brain(),
        &DirectSettings::default(),
        &DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::RelayOrFailClosed,
        },
        true,
        || {
            count.set(count.get() + 1);
            std::future::ready(dns_error())
        },
    )
    .await
    .unwrap();
    assert_eq!(count.get(), 1);
    assert_eq!(target.host, "route-owner.example");
    assert_eq!(
        route,
        AutoTargetRoute::RelayByName {
            reason_code: "auto_target_resolution_failed"
        }
    );
}

#[tokio::test]
async fn failed_dns_cannot_bypass_credentials_or_transport_refusal() {
    let absent_credentials = RelaySettings::default();
    let mut refused_transport = ready_relay();
    refused_transport.transport_priority.clear();
    let mut absent_endpoint = ready_relay();
    absent_endpoint.server.clear();
    absent_endpoint.server_name.clear();
    for relay in [absent_credentials, refused_transport, absent_endpoint] {
        assert!(!relay::runtime_fallback_ready(&relay));
        let count = Cell::new(0);
        let error = select_auto_target_route_with(
            &target(),
            deferred(),
            &brain(),
            &DirectSettings::default(),
            &DirectFallbackContext {
                relay: &relay,
                terminal_policy: DirectTerminalPolicy::RelayOrFailClosed,
            },
            true,
            || {
                count.set(count.get() + 1);
                std::future::ready(dns_error())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(count.get(), 1);
        assert!(error.to_string().starts_with("auto_target_resolution:"));
    }
}

#[tokio::test]
async fn required_hybrid_relay_refusal_does_not_resolve_or_choose_direct() {
    let count = Cell::new(0);
    let relay = RelaySettings::default();
    let direct = DirectSettings {
        hybrid_geneva: true,
        ..DirectSettings::default()
    };
    let error = select_auto_target_route_with(
        &target(),
        deferred(),
        &brain(),
        &direct,
        &DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::HybridRelayOrFailClosed,
        },
        false,
        || {
            count.set(count.get() + 1);
            std::future::ready(Ok("127.0.0.1:443".parse().unwrap()))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(count.get(), 0);
    assert!(error.to_string().starts_with("auto_relay_policy_refused:"));
}

#[tokio::test]
async fn capability_relay_route_avoids_dns_and_does_not_create_address_history() {
    let count = Cell::new(0);
    let relay = ready_relay();
    let direct = DirectSettings {
        hybrid_geneva: true,
        ..DirectSettings::default()
    };
    let store = AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["geneva".into()], store.clone());
    let route = select_auto_target_route_with(
        &target(),
        deferred(),
        &brain,
        &direct,
        &DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::HybridRelayOrFailClosed,
        },
        false,
        || {
            count.set(count.get() + 1);
            std::future::ready(dns_error())
        },
    )
    .await
    .unwrap();
    assert_eq!(count.get(), 0);
    assert_eq!(
        route,
        AutoTargetRoute::RelayByName {
            reason_code: "direct_capability_unavailable"
        }
    );
    let snapshot = store.snapshot().await;
    assert!(snapshot.key_registry.is_empty());
    assert!(snapshot.hybrid_route_stats.is_empty());
}

#[tokio::test]
async fn external_hard_hybrid_refusal_survives_successful_resolver() {
    let store = AsyncStateStore::ephemeral();
    store
        .update(|snapshot| {
            snapshot.external_calibration = Some(ExternalCalibrationSnapshot {
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "direct_geneva".into(),
                    score: 0.0,
                    confidence: 1.0,
                    hard_excluded: true,
                    fail_closed: true,
                    ..Default::default()
                }],
                ..Default::default()
            });
        })
        .await;
    let brain = Brain::new(0.0, vec!["geneva".into()], store.clone());
    let relay = RelaySettings::default();
    let direct = DirectSettings {
        hybrid_geneva: true,
        ..DirectSettings::default()
    };
    let count = Cell::new(0);
    let error = select_auto_target_route_with(
        &target(),
        deferred(),
        &brain,
        &direct,
        &DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::HybridRelayOrFailClosed,
        },
        true,
        || {
            count.set(count.get() + 1);
            std::future::ready(Ok("127.0.0.1:443".parse().unwrap()))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(count.get(), 0);
    assert!(error.to_string().starts_with("auto_relay_policy_refused:"));
    assert!(store.snapshot().await.key_registry.is_empty());
}

#[tokio::test]
async fn successful_dns_keeps_exact_address_and_literal_skips_resolver() {
    let relay = RelaySettings::default();
    let fallback = DirectFallbackContext {
        relay: &relay,
        terminal_policy: DirectTerminalPolicy::RelayOrFailClosed,
    };
    let count = Cell::new(0);
    let address: SocketAddr = "[::1]:443".parse().unwrap();
    let route = select_auto_target_route_with(
        &target(),
        deferred(),
        &brain(),
        &DirectSettings::default(),
        &fallback,
        true,
        || {
            count.set(count.get() + 1);
            std::future::ready(Ok(address))
        },
    )
    .await
    .unwrap();
    assert_eq!(count.get(), 1);
    assert_eq!(route, AutoTargetRoute::Direct(address));
    let literal = ConnectTarget {
        host: "127.0.0.1".into(),
        port: 443,
    };
    let route = select_auto_target_route_with(
        &literal,
        "127.0.0.1:443".parse().unwrap(),
        &brain(),
        &DirectSettings::default(),
        &fallback,
        true,
        || {
            count.set(count.get() + 1);
            std::future::ready(dns_error())
        },
    )
    .await
    .unwrap();
    assert_eq!(count.get(), 1);
    assert_eq!(
        route,
        AutoTargetRoute::Direct("127.0.0.1:443".parse().unwrap())
    );
}

#[tokio::test]
async fn direct_preservation_policy_does_not_gain_dns_failure_fallback() {
    let relay = ready_relay();
    let error = select_auto_target_route_with(
        &target(),
        deferred(),
        &brain(),
        &DirectSettings::default(),
        &DirectFallbackContext {
            relay: &relay,
            terminal_policy: DirectTerminalPolicy::PreserveDirectFailure,
        },
        true,
        || std::future::ready(dns_error()),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().starts_with("auto_target_resolution:"));
}
