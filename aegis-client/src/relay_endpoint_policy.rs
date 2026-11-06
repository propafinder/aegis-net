//! Pure relay endpoint and TLS authority selection shared by binary and provider owners.
//! This module does not dial, authenticate, or admit a PacketTunnel.

use aegis_core::{
    carrier_program::{CarrierChannel, CarrierEchScope},
    RelaySettings,
};
use rustls::pki_types::ServerName;
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRelayEndpoint {
    /// Admitted role of this exact signed route; absent for legacy pools.
    pub channel: Option<CarrierChannel>,
    pub server: String,
    pub server_name: String,
    pub masque_server: Option<String>,
    pub masque_server_name: Option<String>,
}

pub fn effective_relay_endpoints(settings: &RelaySettings) -> Vec<EffectiveRelayEndpoint> {
    if settings.endpoints.is_empty() {
        return vec![EffectiveRelayEndpoint {
            channel: None,
            server: settings.server.clone(),
            server_name: settings.server_name.clone(),
            masque_server: settings.masque_server.clone(),
            masque_server_name: settings.masque_server_name.clone(),
        }];
    }
    let ordered: Vec<_> = match &settings.carrier_program {
        Some(program) => program
            .routes
            .iter()
            .filter_map(|route| {
                settings
                    .endpoints
                    .get(route.endpoint_index)
                    .map(|endpoint| (Some(route.channel), endpoint))
            })
            .collect(),
        None => settings
            .endpoints
            .iter()
            .map(|endpoint| (None, endpoint))
            .collect(),
    };
    ordered
        .into_iter()
        .map(|(channel, endpoint)| EffectiveRelayEndpoint {
            channel,
            server: endpoint.server.clone(),
            server_name: endpoint.server_name.clone(),
            masque_server: endpoint.masque_server.clone(),
            masque_server_name: endpoint.masque_server_name.clone(),
        })
        .collect()
}

pub fn effective_relay_udp_endpoints(settings: &RelaySettings) -> Vec<EffectiveRelayEndpoint> {
    match &settings.carrier_program {
        None => effective_relay_endpoints(settings),
        Some(program) => program
            .routes
            .iter()
            .filter(|route| {
                matches!(
                    route.channel,
                    CarrierChannel::DirectH2 | CarrierChannel::OwnHttpsBridge
                )
            })
            .filter_map(|route| {
                settings
                    .endpoints
                    .get(route.endpoint_index)
                    .map(|endpoint| (route.channel, endpoint))
            })
            .map(|(channel, endpoint)| EffectiveRelayEndpoint {
                channel: Some(channel),
                server: endpoint.server.clone(),
                server_name: endpoint.server_name.clone(),
                masque_server: endpoint.masque_server.clone(),
                masque_server_name: endpoint.masque_server_name.clone(),
            })
            .collect(),
    }
}

pub fn relay_settings_for_endpoint(
    settings: &RelaySettings,
    endpoint: &EffectiveRelayEndpoint,
) -> RelaySettings {
    let mut selected = settings.clone();
    selected.server = endpoint.server.clone();
    selected.server_name = endpoint.server_name.clone();
    // An endpoint-specific MASQUE address wins. Otherwise preserve the
    // top-level direct-MASQUE override. This lets a Cloudflare TCP endpoint
    // pool share one explicitly configured direct UDP origin; previously the
    // pool silently discarded the top-level override and dialed the fronted
    // hostname for QUIC instead.
    selected.masque_server = endpoint
        .masque_server
        .clone()
        .or_else(|| settings.masque_server.clone());
    // An endpoint-specific MASQUE address must not inherit a top-level name
    // for a different direct origin. Its explicit name wins; when absent the
    // backward-compatible endpoint server_name is used. A shared top-level
    // MASQUE endpoint keeps the explicit top-level authority.
    if endpoint.masque_server.is_some() {
        selected.masque_server_name = endpoint.masque_server_name.clone();
    } else if settings.masque_server.is_some() {
        // Inheriting a global direct dial also inherits its effective
        // authority, including the documented fallback to the global name.
        // A TCP pool must not reinterpret that direct certificate per entry.
        selected.masque_server_name = Some(
            settings
                .masque_server_name
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(&settings.server_name)
                .to_owned(),
        );
    }
    selected.endpoints = Vec::new();
    if settings.carrier_program.is_some()
        && endpoint.channel != Some(CarrierChannel::OwnHttpsBridge)
    {
        // Never send a private bridge admission credential to a direct or
        // operator-fronted endpoint, even when it shares the same TLS name.
        selected.https_bridge = None;
    }
    if settings.carrier_program.is_some() && endpoint.channel != Some(CarrierChannel::WebResponse) {
        // Never offer the separate web admission key to H2, bridge or WS.
        selected.web_response = None;
    }
    if settings
        .carrier_program
        .as_ref()
        .is_some_and(|program| program.ech_scope == Some(CarrierEchScope::FrontedOnly))
        && endpoint.channel != Some(CarrierChannel::FrontedH2)
    {
        // Only the signed fronted endpoint may offer its ECHConfigList. The
        // direct primary, WS, own bridge, web response and QUIC each have a
        // separate trust/credential boundary and never inherit that offer.
        selected.ech_config_list = None;
        selected.ech_config_list_base64 = None;
    }
    selected.carrier_program = None;
    // Pool admission and ordering belong to the original immutable caller
    // profile; one selected endpoint is a single carrier attempt.
    selected.endpoint_bandit = None;
    selected.carrier_failover = None;
    selected
}

pub fn endpoint_runtime_ready(endpoint: &EffectiveRelayEndpoint) -> bool {
    !endpoint.server.trim().is_empty() && !endpoint.server_name.trim().is_empty()
}

pub struct RelayTransportAuthority {
    pub tls_server_name: ServerName<'static>,
    pub authority_host: String,
    pub send_sni: bool,
}

pub fn relay_transport_authority(
    settings: &RelaySettings,
) -> anyhow::Result<RelayTransportAuthority> {
    transport_authority_for_host(settings.server_name.trim(), "server_name")
}

pub fn transport_authority_for_host(
    authority_host: &str,
    field_name: &str,
) -> anyhow::Result<RelayTransportAuthority> {
    anyhow::ensure!(!authority_host.is_empty(), "invalid {field_name}");
    if let Ok(ip) = authority_host.parse::<IpAddr>() {
        return Ok(RelayTransportAuthority {
            tls_server_name: ServerName::IpAddress(ip.into()),
            authority_host: authority_host.to_string(),
            send_sni: false,
        });
    }
    let tls_server_name: ServerName<'static> = authority_host
        .to_string()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {field_name}"))?;
    Ok(RelayTransportAuthority {
        tls_server_name,
        authority_host: authority_host.to_string(),
        send_sni: true,
    })
}

pub fn format_authority_host(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::RelayEndpointSettings;

    #[test]
    fn admitted_route_order_drives_endpoint_selection_and_selected_copy_drops_plan() {
        use aegis_core::carrier_program::{CarrierChannel, CarrierProgramSettings, CarrierRoute};
        let settings = RelaySettings {
            endpoints: vec![
                RelayEndpointSettings {
                    server: "192.0.2.10:443".into(),
                    server_name: "relay.example".into(),
                    masque_server: None,
                    masque_server_name: None,
                },
                RelayEndpointSettings {
                    server: "192.0.2.11:443".into(),
                    server_name: "relay.example".into(),
                    masque_server: None,
                    masque_server_name: None,
                },
            ],
            carrier_program: Some(CarrierProgramSettings {
                bridge: None,
                web_response: None,
                ech_scope: None,
                fronted_ech_authority: None,
                routes: vec![
                    CarrierRoute {
                        channel: CarrierChannel::DirectH2,
                        endpoint_index: 1,
                    },
                    CarrierRoute {
                        channel: CarrierChannel::FrontedH2,
                        endpoint_index: 0,
                    },
                ],
            }),
            ..RelaySettings::default()
        };
        let selected = effective_relay_endpoints(&settings);
        assert_eq!(selected[0].server, "192.0.2.11:443");
        assert_eq!(selected[1].server, "192.0.2.10:443");
        let udp = effective_relay_udp_endpoints(&settings);
        assert_eq!(udp.len(), 1);
        assert_eq!(udp[0].server, "192.0.2.11:443");
        let copy = relay_settings_for_endpoint(&settings, &selected[0]);
        assert!(copy.carrier_program.is_none());
        assert!(copy.endpoints.is_empty());
    }

    #[test]
    fn selected_endpoint_preserves_global_masque_authority_and_clears_pool() {
        let mut settings = RelaySettings {
            server_name: "origin.example".into(),
            masque_server: Some("192.0.2.8:443".into()),
            masque_server_name: None,
            ..RelaySettings::default()
        };
        settings.endpoints = vec![RelayEndpointSettings {
            server: "front.example:443".into(),
            server_name: "front.example".into(),
            masque_server: None,
            masque_server_name: None,
        }];
        let selected =
            relay_settings_for_endpoint(&settings, &effective_relay_endpoints(&settings)[0]);
        assert_eq!(selected.server, "front.example:443");
        assert_eq!(selected.masque_server.as_deref(), Some("192.0.2.8:443"));
        assert_eq!(
            selected.masque_server_name.as_deref(),
            Some("origin.example")
        );
        assert!(selected.endpoints.is_empty());
        assert!(selected.endpoint_bandit.is_none());
        assert!(selected.carrier_failover.is_none());
    }

    #[test]
    fn endpoint_specific_masque_does_not_inherit_global_authority() {
        let mut settings = RelaySettings {
            masque_server: Some("192.0.2.8:443".into()),
            masque_server_name: Some("global.example".into()),
            ..RelaySettings::default()
        };
        settings.endpoints = vec![RelayEndpointSettings {
            server: "front.example:443".into(),
            server_name: "front.example".into(),
            masque_server: Some("192.0.2.9:443".into()),
            masque_server_name: None,
        }];
        let selected =
            relay_settings_for_endpoint(&settings, &effective_relay_endpoints(&settings)[0]);
        assert_eq!(selected.masque_server.as_deref(), Some("192.0.2.9:443"));
        assert!(selected.masque_server_name.is_none());
    }

    #[test]
    fn authority_refuses_empty_and_separates_dns_from_ip_sni() {
        assert!(transport_authority_for_host("", "fixture").is_err());
        assert!(transport_authority_for_host("bad name", "fixture").is_err());
        let dns = transport_authority_for_host("relay.example", "fixture").unwrap();
        assert!(dns.send_sni);
        assert!(matches!(dns.tls_server_name, ServerName::DnsName(_)));
        let ip = transport_authority_for_host("2001:db8::1", "fixture").unwrap();
        assert!(!ip.send_sni);
        assert!(matches!(ip.tls_server_name, ServerName::IpAddress(_)));
        assert_eq!(format_authority_host(&ip.authority_host), "[2001:db8::1]");
    }

    #[test]
    fn runtime_ready_requires_both_dial_and_tls_name() {
        let mut endpoint = EffectiveRelayEndpoint {
            channel: None,
            server: "relay.example:443".into(),
            server_name: "relay.example".into(),
            masque_server: None,
            masque_server_name: None,
        };
        assert!(endpoint_runtime_ready(&endpoint));
        endpoint.server_name = "   ".into();
        assert!(!endpoint_runtime_ready(&endpoint));
    }

    #[test]
    fn signed_web_fallback_never_exposes_key_to_other_routes_and_clears_only_own_ech() {
        use aegis_core::carrier_program::{
            CarrierProgramSettings, CarrierRoute, WebResponseDeclaration,
        };
        let mut settings = RelaySettings {
            endpoints: vec![
                RelayEndpointSettings {
                    server: "192.0.2.10:443".into(),
                    server_name: "fronted.example".into(),
                    masque_server: None,
                    masque_server_name: None,
                },
                RelayEndpointSettings {
                    server: "192.0.2.11:443".into(),
                    server_name: "web.example".into(),
                    masque_server: None,
                    masque_server_name: None,
                },
            ],
            ..Default::default()
        };
        let private = aegis_core::web_response_profile::WebResponseSettings {
            authority: "web.example".into(),
            descriptor_path: "/private/descriptor".into(),
            allowed_ingress_ips: vec!["192.0.2.11".parse().unwrap()],
            credential_file: std::path::PathBuf::from("private-web-key"),
        };
        settings.web_response = Some(private.clone());
        settings.ech_config_list_base64 = Some("synthetic-fronted-ech".into());
        settings.carrier_program = Some(CarrierProgramSettings {
            routes: vec![
                CarrierRoute {
                    channel: CarrierChannel::FrontedH2,
                    endpoint_index: 0,
                },
                CarrierRoute {
                    channel: CarrierChannel::WebResponse,
                    endpoint_index: 1,
                },
            ],
            bridge: None,
            web_response: Some(WebResponseDeclaration {
                authority: private.authority.clone(),
                descriptor_path: private.descriptor_path.clone(),
                allowed_ingress_ips: private.allowed_ingress_ips.clone(),
            }),
            ech_scope: Some(CarrierEchScope::FrontedOnly),
            fronted_ech_authority: None,
        });
        let endpoints = effective_relay_endpoints(&settings);
        let fronted = relay_settings_for_endpoint(&settings, &endpoints[0]);
        assert!(fronted.web_response.is_none());
        assert_eq!(
            fronted.ech_config_list_base64,
            settings.ech_config_list_base64
        );
        let web = relay_settings_for_endpoint(&settings, &endpoints[1]);
        assert_eq!(web.web_response, Some(private));
        assert!(web.ech_config_list_base64.is_none());
        assert!(web.ech_config_list.is_none());
        assert_eq!(effective_relay_udp_endpoints(&settings).len(), 0);
    }

    #[test]
    fn signed_direct_to_bridge_route_keeps_private_gate_off_direct_attempt() {
        use aegis_core::carrier_program::{
            BridgeDeclaration, CarrierProgramSettings, CarrierRoute,
        };
        let mut settings = RelaySettings {
            endpoints: vec![
                RelayEndpointSettings {
                    server: "192.0.2.10:443".into(),
                    server_name: "direct.example".into(),
                    masque_server: None,
                    masque_server_name: None,
                },
                RelayEndpointSettings {
                    server: "192.0.2.11:443".into(),
                    server_name: "bridge.example".into(),
                    masque_server: None,
                    masque_server_name: None,
                },
            ],
            ..Default::default()
        };
        settings.https_bridge = Some(aegis_core::https_bridge::ClientSettings {
            authority: "bridge.example".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: std::path::PathBuf::from("/private/bridge-key"),
        });
        settings.carrier_program = Some(CarrierProgramSettings {
            routes: vec![
                CarrierRoute {
                    channel: CarrierChannel::DirectH2,
                    endpoint_index: 0,
                },
                CarrierRoute {
                    channel: CarrierChannel::OwnHttpsBridge,
                    endpoint_index: 1,
                },
            ],
            bridge: Some(BridgeDeclaration {
                authority: "bridge.example".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
            }),
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
        });
        let endpoints = effective_relay_endpoints(&settings);
        assert_eq!(endpoints[0].channel, Some(CarrierChannel::DirectH2));
        assert_eq!(endpoints[1].channel, Some(CarrierChannel::OwnHttpsBridge));
        assert!(relay_settings_for_endpoint(&settings, &endpoints[0])
            .https_bridge
            .is_none());
        assert!(relay_settings_for_endpoint(&settings, &endpoints[1])
            .https_bridge
            .is_some());
        settings.carrier_program.as_mut().unwrap().routes[0].channel = CarrierChannel::FrontedH2;
        settings.carrier_program.as_mut().unwrap().ech_scope = Some(CarrierEchScope::FrontedOnly);
        settings.ech_config_list_base64 = Some("pinned-fronted-config".into());
        let scoped = effective_relay_endpoints(&settings);
        assert_eq!(
            relay_settings_for_endpoint(&settings, &scoped[0]).ech_config_list_base64,
            Some("pinned-fronted-config".into())
        );
        assert!(relay_settings_for_endpoint(&settings, &scoped[1])
            .ech_config_list_base64
            .is_none());
    }

    #[test]
    fn six_route_selection_isolates_ech_private_sidecars_and_udp() {
        use aegis_core::carrier_program::{
            BridgeDeclaration, CarrierProgramSettings, CarrierRoute, WebResponseDeclaration,
        };
        let names = [
            "direct.example",
            "fronted.example",
            "bridge.example",
            "ws.example",
            "web.example",
            "quic.example",
        ];
        let channels = [
            CarrierChannel::DirectH2,
            CarrierChannel::FrontedH2,
            CarrierChannel::OwnHttpsBridge,
            CarrierChannel::HttpsWs,
            CarrierChannel::WebResponse,
            CarrierChannel::MasqueQuic,
        ];
        let mut settings = RelaySettings {
            server: "192.0.2.10:443".into(),
            server_name: names[0].into(),
            endpoints: names
                .iter()
                .enumerate()
                .map(|(index, name)| RelayEndpointSettings {
                    server: format!("192.0.2.{}:443", index + 10),
                    server_name: (*name).into(),
                    masque_server: None,
                    masque_server_name: None,
                })
                .collect(),
            ..Default::default()
        };
        settings.ech_config_list_base64 = Some("signed-fronted-ech".into());
        let bridge = aegis_core::https_bridge::ClientSettings {
            authority: names[2].into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: std::path::PathBuf::from("private-bridge-key"),
        };
        let web = aegis_core::web_response_profile::WebResponseSettings {
            authority: names[4].into(),
            descriptor_path: "/private/descriptor".into(),
            allowed_ingress_ips: vec!["192.0.2.20".parse().unwrap()],
            credential_file: std::path::PathBuf::from("private-web-key"),
        };
        settings.https_bridge = Some(bridge.clone());
        settings.web_response = Some(web.clone());
        settings.carrier_program = Some(CarrierProgramSettings {
            routes: channels
                .iter()
                .enumerate()
                .map(|(index, channel)| CarrierRoute {
                    channel: *channel,
                    endpoint_index: index,
                })
                .collect(),
            bridge: Some(BridgeDeclaration {
                authority: names[2].into(),
                path: bridge.path.clone(),
                enrollment_path: bridge.enrollment_path.clone(),
            }),
            web_response: Some(WebResponseDeclaration {
                authority: names[4].into(),
                descriptor_path: web.descriptor_path.clone(),
                allowed_ingress_ips: web.allowed_ingress_ips.clone(),
            }),
            ech_scope: Some(CarrierEchScope::FrontedOnly),
            fronted_ech_authority: Some(names[1].into()),
        });
        let endpoints = effective_relay_endpoints(&settings);
        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| endpoint.channel.unwrap())
                .collect::<Vec<_>>(),
            channels
        );
        let udp = effective_relay_udp_endpoints(&settings);
        assert_eq!(
            udp.iter()
                .map(|endpoint| endpoint.channel.unwrap())
                .collect::<Vec<_>>(),
            [CarrierChannel::DirectH2, CarrierChannel::OwnHttpsBridge,]
        );
        for (index, endpoint) in endpoints.iter().enumerate() {
            let selected = relay_settings_for_endpoint(&settings, endpoint);
            assert_eq!(selected.server_name, names[index]);
            assert_eq!(selected.ech_config_list_base64.is_some(), index == 1);
            assert_eq!(selected.https_bridge.is_some(), index == 2);
            assert_eq!(selected.web_response.is_some(), index == 4);
            assert!(selected.carrier_program.is_none());
            assert!(selected.endpoints.is_empty());
        }
    }
}
