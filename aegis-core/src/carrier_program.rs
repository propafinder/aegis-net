//! Operator-declared carrier routes. A route names a wire implementation and
//! an endpoint; it does not assert that a CDN, censor, or country accepts it.

use crate::config_types::{RelaySettings, RelayTlsBackend, TunnelTransportFamily};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierChannel {
    DirectH2,
    FrontedH2,
    OwnHttpsBridge,
    GrpcDatagramDirect,
    GrpcDatagramFronted,
    HttpsWs,
    MasqueQuic,
    Geneva,
    WebResponse,
    SfuMedia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAdmission {
    AuthenticatedEndpoint,
    OutsideH2RouteProgram,
    ExperimentalOnly,
}

impl CarrierChannel {
    pub const fn admission(self) -> ChannelAdmission {
        match self {
            Self::DirectH2
            | Self::FrontedH2
            | Self::OwnHttpsBridge
            | Self::HttpsWs
            | Self::WebResponse
            | Self::MasqueQuic => ChannelAdmission::AuthenticatedEndpoint,
            Self::GrpcDatagramDirect | Self::Geneva => ChannelAdmission::OutsideH2RouteProgram,
            Self::GrpcDatagramFronted | Self::SfuMedia => ChannelAdmission::ExperimentalOnly,
        }
    }
}

pub const CHANNELS: [CarrierChannel; 10] = [
    CarrierChannel::DirectH2,
    CarrierChannel::FrontedH2,
    CarrierChannel::OwnHttpsBridge,
    CarrierChannel::GrpcDatagramDirect,
    CarrierChannel::GrpcDatagramFronted,
    CarrierChannel::HttpsWs,
    CarrierChannel::MasqueQuic,
    CarrierChannel::Geneva,
    CarrierChannel::WebResponse,
    CarrierChannel::SfuMedia,
];

/// The signed `https_ws` route implies this protocol path. It is deliberately
/// separate from operator-selected legacy token WebSocket mounts.
pub const SECURE_WS_PATH: &str = "/v2/device/ws";
/// Separate enrolled QUIC/H3 CONNECT route. Legacy token MASQUE paths never
/// dispatch here; the first authorization remains the inner device TLS.
pub const SECURE_QUIC_AUTHORITY: &str = "device.aegis.invalid:443";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierRoute {
    pub channel: CarrierChannel,
    /// Index into `relay.endpoints`. The route list determines attempt order.
    pub endpoint_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierProgramSettings {
    pub routes: Vec<CarrierRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgeDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_response: Option<WebResponseDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech_scope: Option<CarrierEchScope>,
    /// Exact signed DNS authority that receives a fronted ECH offer when the
    /// primary endpoint is a separate direct origin. Older fronted-primary
    /// profiles may omit this and retain their original primary binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fronted_ech_authority: Option<String>,
}

/// Explicit signed permission to keep ECH only on the fronted TLS routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierEchScope {
    FrontedOnly,
}

/// Public, signed bridge policy. The credential remains in the private sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeDeclaration {
    pub authority: String,
    pub path: String,
    pub enrollment_path: String,
}

/// Signed bootstrap descriptor and ingress allowlist. The key file is private.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebResponseDeclaration {
    pub authority: String,
    pub descriptor_path: String,
    pub allowed_ingress_ips: Vec<IpAddr>,
}

/// Public, digest-bound SFU locations. The broker admission key, media
/// bearer and device private key belong only in the captured private owner.
/// This declaration is inert unless an installed media owner explicitly
/// invokes the capability-specific validator below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SfuDeclaration {
    pub broker: SocketAddr,
    pub broker_tls_name: String,
    pub broker_ca_sha256: String,
    pub media: SocketAddr,
    pub media_tls_name: String,
    pub media_ca_sha256: String,
    pub allowed_media_ips: Vec<IpAddr>,
}

impl SfuDeclaration {
    fn valid(&self) -> bool {
        fn socket_valid(socket: SocketAddr) -> bool {
            socket.port() != 0 && !socket.ip().is_unspecified() && !socket.ip().is_multicast()
        }
        fn digest_valid(digest: &str) -> bool {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        socket_valid(self.broker)
            && socket_valid(self.media)
            && self.broker != self.media
            && (1..=8).contains(&self.allowed_media_ips.len())
            && self.allowed_media_ips.contains(&self.media.ip())
            && self.allowed_media_ips.iter().all(|ip| {
                !ip.is_unspecified() && !ip.is_multicast() && ip.is_ipv4() == self.media.is_ipv4()
            })
            && rustls::pki_types::ServerName::try_from(self.broker_tls_name.clone()).is_ok()
            && rustls::pki_types::ServerName::try_from(self.media_tls_name.clone()).is_ok()
            && digest_valid(&self.broker_ca_sha256)
            && digest_valid(&self.media_ca_sha256)
    }
}

impl WebResponseDeclaration {
    fn valid(&self) -> bool {
        crate::https_bridge::valid_authority(&self.authority)
            && crate::https_bridge::valid_path(&self.descriptor_path)
            && (1..=16).contains(&self.allowed_ingress_ips.len())
            && self
                .allowed_ingress_ips
                .iter()
                .all(|ip| !ip.is_unspecified() && !ip.is_multicast())
    }

    fn matches_private(&self, private: &crate::web_response_profile::WebResponseSettings) -> bool {
        self.authority == private.authority
            && self.descriptor_path == private.descriptor_path
            && self.allowed_ingress_ips == private.allowed_ingress_ips
    }
}

impl BridgeDeclaration {
    fn valid(&self) -> bool {
        crate::https_bridge::valid_authority(&self.authority)
            && crate::https_bridge::valid_path(&self.path)
            && crate::https_bridge::valid_path(&self.enrollment_path)
            && self.path != self.enrollment_path
    }

    fn matches_private(&self, private: &crate::https_bridge::ClientSettings) -> bool {
        self.authority == private.authority
            && self.path == private.path
            && self.enrollment_path == private.enrollment_path
    }
}

impl CarrierProgramSettings {
    /// A separate, explicit opt-in for a complete installed SFU owner. The
    /// ordinary validator continues to reject `SfuMedia` everywhere. The
    /// media route must be the final signed endpoint after a valid H2 prefix;
    /// the signed declaration binds both signaling destinations and the
    /// numeric ICE IP allowlist before any private bearer is read.
    pub fn validate_public_sfu_capability(
        &self,
        relay: &RelaySettings,
        media: &SfuDeclaration,
    ) -> Result<(), String> {
        let invalid =
            || "SFU media capability requires exact signed locations and H2 prefix".to_owned();
        if !media.valid()
            || self.routes.len() != 2
            || self.routes.len() != relay.endpoints.len()
            || self.routes[0].channel != CarrierChannel::DirectH2
            || self.routes[0].endpoint_index != 0
            || relay.endpoint_bandit.is_some()
            || relay.carrier_failover.is_some()
            || self.bridge.is_some()
            || self.web_response.is_some()
            || self.ech_scope.is_some()
            || self.fronted_ech_authority.is_some()
        {
            return Err(invalid());
        }
        let Some(last) = self.routes.last() else {
            return Err(invalid());
        };
        if last.channel != CarrierChannel::SfuMedia
            || last.endpoint_index != relay.endpoints.len() - 1
            || relay.endpoints[last.endpoint_index]
                .server
                .parse::<SocketAddr>()
                .ok()
                != Some(media.media)
            || relay.endpoints[last.endpoint_index].server_name != media.media_tls_name
        {
            return Err(invalid());
        }
        let mut prefix = self.clone();
        prefix.routes.pop();
        let mut prefix_relay = relay.clone();
        prefix_relay.endpoints.pop();
        prefix.validate_public(&prefix_relay)?;
        Ok(())
    }

    pub fn validate(&self, relay: &RelaySettings) -> Result<(), String> {
        self.validate_public(relay)?;
        let bridge_match: Result<(), String> = match (&self.bridge, &relay.https_bridge) {
            (Some(public), Some(private)) if public.matches_private(private) => Ok(()),
            // Preserve the older standalone private bridge configuration.
            // A signed public profile never reaches this case at preflight:
            // its private sidecar is deliberately unavailable there.
            (None, Some(_))
                if self
                    .routes
                    .iter()
                    .all(|route| route.channel == CarrierChannel::OwnHttpsBridge) =>
            {
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err("carrier route program private bridge differs from signed declaration".into()),
        };
        bridge_match?;
        match (&self.web_response, &relay.web_response) {
            (Some(public), Some(private)) if public.matches_private(private) => Ok(()),
            (None, None) => Ok(()),
            _ => Err(
                "carrier route program private web-response differs from signed declaration".into(),
            ),
        }
    }

    /// Public bundle preflight: verifies the route and bridge contract without
    /// reading a private sidecar or treating the plan as an executable config.
    pub fn validate_public(&self, relay: &RelaySettings) -> Result<(), String> {
        let invalid =
            || "carrier route program requires a bounded authenticated H2 endpoint pool".to_owned();
        if self.routes.is_empty()
            || self.routes.len() > 6
            || self.routes.len() != relay.endpoints.len()
            || relay.inner_tls.is_none()
            || !relay.auth_token.is_empty()
            || relay.ca_cert.is_none()
            || relay.tls_backend != RelayTlsBackend::Rustls
            || relay.transport_priority != [TunnelTransportFamily::GrpcStream]
            || relay.masque_server.is_some()
            || relay.masque_server_name.is_some()
        {
            return Err(invalid());
        }
        let mut indices = BTreeSet::new();
        let mut sockets = BTreeSet::new();
        let mut direct_seen = false;
        let mut fronted_seen = false;
        let mut bridge_seen = false;
        let mut ws_seen = false;
        let mut web_seen = false;
        let mut quic_seen = false;
        for route in &self.routes {
            if route.channel.admission() != ChannelAdmission::AuthenticatedEndpoint
                || !indices.insert(route.endpoint_index)
            {
                return Err(invalid());
            }
            let endpoint = relay
                .endpoints
                .get(route.endpoint_index)
                .ok_or_else(invalid)?;
            let socket: SocketAddr = endpoint.server.parse().map_err(|_| invalid())?;
            if socket.port() == 0
                || socket.ip().is_unspecified()
                || socket.ip().is_multicast()
                || !sockets.insert(socket)
                || endpoint.server_name.trim().is_empty()
                || rustls::pki_types::ServerName::try_from(endpoint.server_name.clone()).is_err()
                || (route.channel == CarrierChannel::FrontedH2
                    && endpoint.server_name.parse::<IpAddr>().is_ok())
                || endpoint.masque_server.is_some()
                || endpoint.masque_server_name.is_some()
            {
                return Err(invalid());
            }
            match route.channel {
                CarrierChannel::DirectH2 => {
                    if direct_seen
                        || fronted_seen
                        || bridge_seen
                        || ws_seen
                        || web_seen
                        || quic_seen
                    {
                        return Err(invalid());
                    }
                    direct_seen = true;
                }
                CarrierChannel::FrontedH2 => {
                    if fronted_seen || bridge_seen || ws_seen || web_seen || quic_seen {
                        return Err(invalid());
                    }
                    fronted_seen = true;
                }
                CarrierChannel::OwnHttpsBridge => {
                    if bridge_seen || ws_seen || web_seen || quic_seen {
                        return Err(invalid());
                    }
                    bridge_seen = true;
                    match (&self.bridge, &relay.https_bridge) {
                        (Some(bridge), _)
                            if bridge.valid() && bridge.authority == endpoint.server_name => {}
                        (None, Some(private))
                            if private.validate_authority(&endpoint.server_name).is_ok() => {}
                        _ => return Err(invalid()),
                    }
                }
                CarrierChannel::HttpsWs => {
                    // Only a signed direct-origin WS fallback, with its own
                    // endpoint and no bridge/web credential on this attempt.
                    if ws_seen || web_seen || quic_seen || !direct_seen {
                        return Err(invalid());
                    }
                    ws_seen = true;
                }
                CarrierChannel::WebResponse => {
                    // The separate web-response service is a TCP-only fallback.
                    // A descriptor may redirect only to a signed ingress IP.
                    if web_seen
                        || quic_seen
                        || !(direct_seen || fronted_seen || bridge_seen || ws_seen)
                    {
                        return Err(invalid());
                    }
                    match &self.web_response {
                        Some(web) if web.valid() && web.authority == endpoint.server_name => {}
                        _ => return Err(invalid()),
                    }
                    web_seen = true;
                }
                CarrierChannel::MasqueQuic => {
                    // Direct UDP/443 only, with the same signed socket and
                    // authority as this endpoint. No legacy token, alternate
                    // MASQUE socket, CDN claim, or implicit UDP forwarding.
                    if quic_seen || !direct_seen {
                        return Err(invalid());
                    }
                    quic_seen = true;
                }
                _ => return Err(invalid()),
            }
        }
        if self.bridge.is_some() && !bridge_seen {
            return Err(invalid());
        }
        if self.web_response.is_some() != web_seen {
            return Err(invalid());
        }
        let has_ech = relay.ech_config_list.is_some() || relay.ech_config_list_base64.is_some();
        if self.ech_scope.is_some() && (!has_ech || !fronted_seen || self.routes.len() == 1) {
            return Err(
                "carrier route program ECH scope requires a signed fronted route and separate nonfronted carrier"
                    .into(),
            );
        }
        match (self.ech_scope, self.fronted_ech_authority.as_deref()) {
            (Some(CarrierEchScope::FrontedOnly), Some(authority)) => {
                if authority.parse::<IpAddr>().is_ok()
                    || self.routes.iter().any(|route| {
                        route.channel == CarrierChannel::FrontedH2
                            && relay.endpoints[route.endpoint_index].server_name != authority
                    })
                {
                    return Err("fronted ECH authority differs from signed endpoint".into());
                }
            }
            (Some(CarrierEchScope::FrontedOnly), None) => {
                if !self.routes.iter().any(|route| {
                    route.channel == CarrierChannel::FrontedH2
                        && route.endpoint_index == 0
                        && relay.endpoints[0].server_name == relay.server_name
                }) {
                    return Err("direct-primary fronted ECH requires signed authority".into());
                }
            }
            (None, Some(_)) => return Err("fronted ECH authority requires scoped ECH".into()),
            (None, None) => {}
        }
        // ECH is global in the source profile but applied only to the signed
        // fronted route at selection. Any other role requires explicit scope.
        if has_ech
            && self.ech_scope != Some(CarrierEchScope::FrontedOnly)
            && self
                .routes
                .iter()
                .any(|route| route.channel != CarrierChannel::FrontedH2)
        {
            return Err(
                "carrier route program cannot apply fronted ECH to a nonfronted route".into(),
            );
        }
        if relay
            .udp_transport_priority
            .as_deref()
            .is_some_and(|udp| udp.contains(&TunnelTransportFamily::GrpcDatagram))
            && !self.routes.iter().any(|route| {
                matches!(
                    route.channel,
                    CarrierChannel::DirectH2 | CarrierChannel::OwnHttpsBridge
                )
            })
        {
            return Err("carrier route program has no admitted direct datagram endpoint".into());
        }
        Ok(())
    }

    pub fn ordered_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.routes.iter().map(|route| route.endpoint_index)
    }

    /// Fronted H2 currently carries TCP only in this program. Never infer
    /// fronted datagram support from a TCP route label.
    pub fn udp_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.routes.iter().filter_map(|route| {
            matches!(
                route.channel,
                CarrierChannel::DirectH2 | CarrierChannel::OwnHttpsBridge
            )
            .then_some(route.endpoint_index)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_types::{
        RelayEndpointBanditSettings, RelayEndpointSettings, RelayTlsBackend,
    };
    use crate::secure_channel;
    use std::path::PathBuf;

    #[test]
    fn sfu_capability_is_explicit_and_binds_exact_signed_locations() {
        let mut relay = profile();
        relay.endpoints[1].server_name = "media.example".into();
        let plan = CarrierProgramSettings {
            routes: vec![
                route(CarrierChannel::DirectH2, 0),
                route(CarrierChannel::SfuMedia, 1),
            ],
            bridge: None,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
        };
        let media = SfuDeclaration {
            broker: "192.0.2.12:9447".parse().unwrap(),
            broker_tls_name: "broker.example".into(),
            broker_ca_sha256: "a".repeat(64),
            media: "192.0.2.11:443".parse().unwrap(),
            media_tls_name: "media.example".into(),
            media_ca_sha256: "b".repeat(64),
            allowed_media_ips: vec!["192.0.2.11".parse().unwrap()],
        };
        // Every ordinary caller keeps the current experimental refusal.
        assert!(plan.validate_public(&relay).is_err());
        plan.validate_public_sfu_capability(&relay, &media).unwrap();
        let mut changed = media.clone();
        changed.media.set_port(444);
        assert!(plan
            .validate_public_sfu_capability(&relay, &changed)
            .is_err());
        changed = media.clone();
        changed.allowed_media_ips.clear();
        assert!(plan
            .validate_public_sfu_capability(&relay, &changed)
            .is_err());
        let mut wrong_order = plan.clone();
        wrong_order.routes.reverse();
        assert!(wrong_order
            .validate_public_sfu_capability(&relay, &media)
            .is_err());
        let mut wrong_endpoint = relay.clone();
        wrong_endpoint.endpoints[1].server = "192.0.2.13:443".into();
        assert!(plan
            .validate_public_sfu_capability(&wrong_endpoint, &media)
            .is_err());
    }

    #[test]
    fn web_response_requires_signed_descriptor_private_key_and_exact_ingress() {
        let mut relay = profile();
        relay.endpoints[1].server_name = "web.example".into();
        let public = WebResponseDeclaration {
            authority: "web.example".into(),
            descriptor_path: "/private/descriptor".into(),
            allowed_ingress_ips: vec!["192.0.2.11".parse().unwrap()],
        };
        let plan = CarrierProgramSettings {
            routes: vec![
                route(CarrierChannel::DirectH2, 0),
                route(CarrierChannel::WebResponse, 1),
            ],
            bridge: None,
            web_response: Some(public.clone()),
            ech_scope: None,
            fronted_ech_authority: None,
        };
        plan.validate_public(&relay).unwrap();
        relay.carrier_program = Some(plan.clone());
        assert!(relay.validate_inner_tls_transport().is_err());
        relay.web_response = Some(crate::web_response_profile::WebResponseSettings {
            authority: public.authority.clone(),
            descriptor_path: public.descriptor_path.clone(),
            allowed_ingress_ips: public.allowed_ingress_ips.clone(),
            credential_file: PathBuf::from(if cfg!(windows) {
                r"C:\Aegis-test\web-key"
            } else {
                "/private/web-key"
            }),
        });
        relay.validate_inner_tls_transport().unwrap();
        let mut foreign = relay.clone();
        foreign.web_response.as_mut().unwrap().allowed_ingress_ips =
            vec!["192.0.2.12".parse().unwrap()];
        assert!(foreign.validate_inner_tls_transport().is_err());
        let mut absent = plan.clone();
        absent.web_response = None;
        assert!(absent.validate_public(&relay).is_err());
        let mut numeric = plan.clone();
        numeric.web_response.as_mut().unwrap().authority = "192.0.2.11".into();
        assert!(numeric.validate_public(&relay).is_err());
        let mut ech = relay.clone();
        ech.ech_config_list_base64 = Some("must-not-leak".into());
        assert!(plan.validate_public(&ech).is_err());
    }

    fn route(channel: CarrierChannel, endpoint_index: usize) -> CarrierRoute {
        CarrierRoute {
            channel,
            endpoint_index,
        }
    }

    fn private_bridge_key() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\Aegis-test\bridge-key")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/private/bridge-key")
        }
    }

    fn profile() -> RelaySettings {
        let mut relay = RelaySettings::default();
        relay.auth_token.clear();
        relay.ca_cert = Some(PathBuf::from("outer-ca.pem"));
        relay.tls_backend = RelayTlsBackend::Rustls;
        relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        relay.udp_transport_priority = Some(vec![]);
        relay.inner_tls = Some(secure_channel::ClientSettings {
            server_name: "inner.example".into(),
            server_ca: PathBuf::from("inner-ca.pem"),
            cert: PathBuf::from("device.pem"),
            key: PathBuf::from("device.key"),
        });
        relay.endpoints = ["192.0.2.10:443", "192.0.2.11:443"]
            .into_iter()
            .map(|server| RelayEndpointSettings {
                server: server.into(),
                server_name: "relay.example".into(),
                masque_server: None,
                masque_server_name: None,
            })
            .collect();
        relay
    }

    #[test]
    fn enrolled_quic_is_a_direct_signed_inner_tls_fallback_only() {
        let mut relay = profile();
        let mut plan = CarrierProgramSettings {
            bridge: None,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
            routes: vec![
                route(CarrierChannel::DirectH2, 0),
                route(CarrierChannel::MasqueQuic, 1),
            ],
        };
        relay.carrier_program = Some(plan.clone());
        relay.validate_inner_tls_transport().unwrap();
        assert_eq!(plan.udp_indices().collect::<Vec<_>>(), vec![0]);
        let mut after_quic = plan.clone();
        after_quic.routes.push(route(CarrierChannel::FrontedH2, 2));
        relay.endpoints.push(RelayEndpointSettings {
            server: "192.0.2.12:443".into(),
            server_name: "relay.example".into(),
            masque_server: None,
            masque_server_name: None,
        });
        assert!(after_quic.validate_public(&relay).is_err());
        relay.endpoints.pop();
        plan.routes[0].channel = CarrierChannel::FrontedH2;
        assert!(plan.validate_public(&relay).is_err());
        plan.routes[0].channel = CarrierChannel::DirectH2;
        plan.routes[1].endpoint_index = 0;
        assert!(plan.validate_public(&relay).is_err());
        plan.routes[1].endpoint_index = 1;
        relay.auth_token = "legacy-token".into();
        assert!(plan.validate_public(&relay).is_err());
        relay.auth_token.clear();
        relay.masque_server = Some("192.0.2.20:443".into());
        assert!(plan.validate_public(&relay).is_err());
        relay.masque_server = None;
        relay.ech_config_list_base64 = Some("fronted-offer".into());
        assert!(plan.validate_public(&relay).is_err());
    }

    #[test]
    fn enrolled_direct_then_fronted_is_ordered_and_unsupported_routes_refuse() {
        let relay = profile();
        let mut plan = CarrierProgramSettings {
            bridge: None,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
            routes: vec![
                route(CarrierChannel::DirectH2, 1),
                route(CarrierChannel::FrontedH2, 0),
            ],
        };
        plan.validate(&relay).unwrap();
        assert_eq!(plan.ordered_indices().collect::<Vec<_>>(), [1, 0]);
        assert_eq!(plan.udp_indices().collect::<Vec<_>>(), [1]);
        plan.routes[1].channel = CarrierChannel::SfuMedia;
        assert!(plan.validate(&relay).is_err());
        plan.routes[1].channel = CarrierChannel::HttpsWs;
        assert!(plan.validate(&relay).is_ok());
        let mut wrong = relay.clone();
        wrong.ech_config_list_base64 = Some("fronted-ech".into());
        assert!(plan.validate(&wrong).is_err());
        plan.routes[0].channel = CarrierChannel::FrontedH2;
        assert!(plan.validate(&relay).is_err());
        plan.routes[0].channel = CarrierChannel::DirectH2;
        plan.routes[1].channel = CarrierChannel::MasqueQuic;
        plan.validate(&relay).unwrap();
        assert_eq!(plan.udp_indices().collect::<Vec<_>>(), [1]);
        plan.routes.swap(0, 1);
        assert!(plan.validate(&relay).is_err());
    }

    #[test]
    fn route_aliases_and_global_ech_mix_refuse() {
        let mut relay = profile();
        let mut plan = CarrierProgramSettings {
            bridge: None,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
            routes: vec![
                route(CarrierChannel::DirectH2, 0),
                route(CarrierChannel::FrontedH2, 0),
            ],
        };
        assert!(plan.validate(&relay).is_err());
        plan.routes[1].endpoint_index = 1;
        relay.endpoints[1].server = relay.endpoints[0].server.clone();
        assert!(plan.validate(&relay).is_err());
        relay.endpoints[1].server = "192.0.2.11:443".into();
        relay.ech_config_list_base64 = Some("explicit-ech".into());
        assert!(plan.validate(&relay).is_err());
        relay.ech_config_list_base64 = None;
        relay.auth_token = "legacy-token".into();
        assert!(plan.validate(&relay).is_err());
        relay.auth_token.clear();
        relay.endpoints[1].server_name = "invalid TLS name with space".into();
        assert!(plan.validate(&relay).is_err());
        relay.endpoints[1].server_name = "192.0.2.11".into();
        plan.routes[1].channel = CarrierChannel::FrontedH2;
        assert!(plan.validate(&relay).is_err());
    }

    #[test]
    fn optional_endpoint_learning_keeps_the_same_authenticated_route_pool() {
        let mut relay = profile();
        relay.server = relay.endpoints[0].server.clone();
        relay.server_name = relay.endpoints[0].server_name.clone();
        relay.endpoint_bandit = Some(RelayEndpointBanditSettings {
            algorithm: crate::brain::recent_routes::paper_bandit::PaperAlgorithm::SlidingWindow {
                rounds: 16,
                xi: 1.0,
            },
            max_profiles: 16,
            max_contexts_per_profile: 16,
            pre_auth_block_ms: 1000,
            dependency_policy: None,
        });
        relay.carrier_program = Some(CarrierProgramSettings {
            bridge: None,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
            routes: vec![
                route(CarrierChannel::DirectH2, 1),
                route(CarrierChannel::FrontedH2, 0),
            ],
        });
        relay.validate_inner_tls_transport().unwrap();
        relay.endpoints[1].server = relay.endpoints[0].server.clone();
        assert!(relay.validate_inner_tls_transport().is_err());
    }

    #[test]
    fn fronted_only_datagram_is_rejected_before_runtime() {
        let mut relay = profile();
        relay.endpoints.truncate(1);
        relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        let plan = CarrierProgramSettings {
            bridge: None,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
            routes: vec![route(CarrierChannel::FrontedH2, 0)],
        };
        assert!(plan.validate(&relay).is_err());
        relay.udp_transport_priority = Some(vec![]);
        plan.validate(&relay).unwrap();
    }

    #[test]
    fn signed_bridge_pool_requires_exact_private_contract_and_same_authority() {
        let mut relay = profile();
        relay.server_name = "relay.example".into();
        let declared = BridgeDeclaration {
            authority: "relay.example".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
        };
        let mut plan = CarrierProgramSettings {
            routes: vec![
                route(CarrierChannel::DirectH2, 1),
                route(CarrierChannel::OwnHttpsBridge, 0),
            ],
            bridge: Some(declared.clone()),
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
        };
        plan.validate_public(&relay).unwrap();
        assert!(plan.validate(&relay).is_err());
        relay.https_bridge = Some(crate::https_bridge::ClientSettings {
            authority: declared.authority.clone(),
            path: declared.path.clone(),
            enrollment_path: declared.enrollment_path.clone(),
            credential_file: private_bridge_key(),
        });
        plan.validate(&relay).unwrap();
        relay.endpoints[1].server_name = "direct.example".into();
        plan.validate_public(&relay).unwrap();
        relay.endpoints[1].server_name = "relay.example".into();
        let mut duplicate = plan.clone();
        duplicate.routes[0].channel = CarrierChannel::OwnHttpsBridge;
        assert!(duplicate.validate_public(&relay).is_err());
        let mut legacy = plan.clone();
        legacy.bridge = None;
        assert!(legacy.validate(&relay).is_err());
        legacy.routes = vec![route(CarrierChannel::OwnHttpsBridge, 0)];
        let mut standalone = relay.clone();
        standalone.endpoints.truncate(1);
        legacy.validate(&standalone).unwrap();
        relay.server = relay.endpoints[0].server.clone();
        relay.endpoint_bandit = Some(RelayEndpointBanditSettings {
            algorithm: crate::brain::recent_routes::paper_bandit::PaperAlgorithm::SlidingWindow {
                rounds: 16,
                xi: 1.0,
            },
            max_profiles: 16,
            max_contexts_per_profile: 16,
            pre_auth_block_ms: 1000,
            dependency_policy: None,
        });
        relay.carrier_program = Some(plan.clone());
        relay.validate_inner_tls_transport().unwrap();
        assert_eq!(plan.ordered_indices().collect::<Vec<_>>(), [1, 0]);
        assert_eq!(plan.udp_indices().collect::<Vec<_>>(), [1, 0]);
        relay.https_bridge.as_mut().unwrap().path = "/private/other".into();
        assert!(plan.validate(&relay).is_err());
        relay.https_bridge.as_mut().unwrap().path = declared.path.clone();
        relay.endpoints[0].server_name = "different.example".into();
        assert!(plan.validate_public(&relay).is_err());
        relay.endpoints[0].server_name = declared.authority.clone();
        plan.bridge.as_mut().unwrap().enrollment_path = "/private/stream".into();
        assert!(plan.validate_public(&relay).is_err());
        plan.bridge.as_mut().unwrap().enrollment_path = declared.enrollment_path;
        plan.routes[1].channel = CarrierChannel::FrontedH2;
        assert!(plan.validate_public(&relay).is_err());
    }

    #[test]
    fn direct_then_own_bridge_is_a_typed_pre_auth_fallback() {
        let mut relay = profile();
        relay.server = relay.endpoints[0].server.clone();
        relay.server_name = relay.endpoints[0].server_name.clone();
        relay.endpoints[1].server_name = "bridge.example".into();
        let private = crate::https_bridge::ClientSettings {
            authority: "bridge.example".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: private_bridge_key(),
        };
        let plan = CarrierProgramSettings {
            routes: vec![
                route(CarrierChannel::DirectH2, 0),
                route(CarrierChannel::OwnHttpsBridge, 1),
            ],
            bridge: Some(BridgeDeclaration {
                authority: private.authority.clone(),
                path: private.path.clone(),
                enrollment_path: private.enrollment_path.clone(),
            }),
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
        };
        plan.validate_public(&relay).unwrap();
        assert!(plan.validate(&relay).is_err());
        relay.https_bridge = Some(private);
        relay.carrier_program = Some(plan.clone());
        relay.validate_inner_tls_transport().unwrap();
        assert_eq!(plan.ordered_indices().collect::<Vec<_>>(), [0, 1]);
        relay.https_bridge.as_mut().unwrap().authority = "other.example".into();
        assert!(relay.validate_inner_tls_transport().is_err());
    }

    #[test]
    fn signed_fronted_ech_scope_keeps_a_separate_bridge_authority() {
        let mut relay = profile();
        relay.server = relay.endpoints[0].server.clone();
        relay.server_name = "front.example".into();
        relay.endpoints[0].server_name = relay.server_name.clone();
        relay.endpoints[1].server_name = "bridge.example".into();
        relay.ech_config_list_base64 = Some("AQID".into());
        let bridge = crate::https_bridge::ClientSettings {
            authority: "bridge.example".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: private_bridge_key(),
        };
        let mut plan = CarrierProgramSettings {
            routes: vec![
                route(CarrierChannel::FrontedH2, 0),
                route(CarrierChannel::OwnHttpsBridge, 1),
            ],
            bridge: Some(BridgeDeclaration {
                authority: bridge.authority.clone(),
                path: bridge.path.clone(),
                enrollment_path: bridge.enrollment_path.clone(),
            }),
            web_response: None,
            ech_scope: Some(CarrierEchScope::FrontedOnly),
            fronted_ech_authority: None,
        };
        relay.carrier_program = Some(plan.clone());
        crate::Settings {
            relay: relay.clone(),
            ..Default::default()
        }
        .validate_ech()
        .unwrap();
        plan.validate_public(&relay).unwrap();
        relay.https_bridge = Some(bridge);
        relay.validate_inner_tls_transport().unwrap();
        plan.ech_scope = None;
        assert!(plan.validate_public(&relay).is_err());
        plan.ech_scope = Some(CarrierEchScope::FrontedOnly);
        plan.routes[0].channel = CarrierChannel::DirectH2;
        assert!(plan.validate_public(&relay).is_err());
        plan.routes[0].channel = CarrierChannel::FrontedH2;
        relay.endpoints[0].server_name = "foreign.example".into();
        assert!(crate::Settings {
            relay,
            ..Default::default()
        }
        .validate_ech()
        .is_err());
    }

    #[test]
    fn six_signed_routes_bind_fronted_ech_without_credential_or_udp_aliases() {
        let mut relay = profile();
        relay.server_name = "direct.example".into();
        relay.endpoints = [
            "direct.example",
            "fronted.example",
            "bridge.example",
            "ws.example",
            "web.example",
            "quic.example",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, name)| RelayEndpointSettings {
            server: format!("192.0.2.{}:443", index + 10),
            server_name: name.into(),
            masque_server: None,
            masque_server_name: None,
        })
        .collect();
        relay.server = relay.endpoints[0].server.clone();
        relay.ech_config_list_base64 = Some("AQID".into());
        let mut plan = CarrierProgramSettings {
            routes: [
                CarrierChannel::DirectH2,
                CarrierChannel::FrontedH2,
                CarrierChannel::OwnHttpsBridge,
                CarrierChannel::HttpsWs,
                CarrierChannel::WebResponse,
                CarrierChannel::MasqueQuic,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, channel)| route(channel, index))
            .collect(),
            bridge: Some(BridgeDeclaration {
                authority: "bridge.example".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
            }),
            web_response: Some(WebResponseDeclaration {
                authority: "web.example".into(),
                descriptor_path: "/private/descriptor".into(),
                allowed_ingress_ips: vec!["192.0.2.20".parse().unwrap()],
            }),
            ech_scope: Some(CarrierEchScope::FrontedOnly),
            fronted_ech_authority: Some("fronted.example".into()),
        };
        plan.validate_public(&relay).unwrap();
        assert_eq!(
            plan.ordered_indices().collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!(plan.udp_indices().collect::<Vec<_>>(), [0, 2]);
        relay.carrier_program = Some(plan.clone());
        crate::Settings {
            relay: relay.clone(),
            ..Default::default()
        }
        .validate_ech()
        .unwrap();
        plan.fronted_ech_authority = None;
        assert!(plan.validate_public(&relay).is_err());
        plan.fronted_ech_authority = Some("wrong.example".into());
        assert!(plan.validate_public(&relay).is_err());
        plan.fronted_ech_authority = Some("fronted.example".into());
        plan.ech_scope = None;
        assert!(plan.validate_public(&relay).is_err());
        plan.ech_scope = Some(CarrierEchScope::FrontedOnly);
        plan.routes.swap(4, 5);
        assert!(plan.validate_public(&relay).is_err());
    }
}
