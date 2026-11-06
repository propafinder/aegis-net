//! R16 source-only admission value. It is not a dialer or provider factory.
//! The next owner must preload the cryptographic clients from the retained
//! descriptors before any async work and keep the App Group capture alive.
use crate::app_group::{
    CapturedAppGroupInputs, CapturedBridgeSnapshot, CapturedSfuSnapshot,
    CapturedWebResponseSnapshot,
};
use crate::packet_engine::PacketEngineConfig;
use crate::runtime_binding::SignedRuntimeTerms;
use aegis_client::{
    device_bundle_profile::{self, MacosPacketPolicy},
    public_profile_file::profile_digest_bytes,
};
use aegis_core::carrier_program::{CarrierChannel, SfuDeclaration};
use aegis_core::{secure_channel::enrollment, wide_product::WideProductMode, Settings};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use subtle::ConstantTimeEq;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "bound relay policy refused",
    )
}

#[allow(dead_code)]
pub(crate) struct BoundRelayPolicy {
    settings: Settings,
    public_digest: String,
    // The exact four public files are owned, not reloaded to compare policy.
    public: [Vec<u8>; 4],
    bridge: Option<CapturedBridgeSnapshot>,
    web_response: Option<CapturedWebResponseSnapshot>,
    sfu_media: Option<CapturedSfuSnapshot>,
    sfu_declaration: Option<SfuDeclaration>,
    macos_packet: Option<MacosPacketPolicy>,
}

#[allow(dead_code)]
impl BoundRelayPolicy {
    pub(crate) fn capture(inputs: &mut CapturedAppGroupInputs) -> io::Result<Self> {
        let public = inputs.captured_public_payload()?;
        let bridge = inputs.captured_bridge_snapshot()?;
        let web_response = inputs.captured_web_response_snapshot()?;
        let sfu_media = inputs.captured_sfu_media_snapshot()?;
        let result = Self::from_snapshot_with_web_sfu(
            public,
            bridge,
            web_response,
            sfu_media,
            inputs.bundle_path(),
            inputs.identity_path(),
        )?;
        if result.public_digest != inputs.captured_public_profile_digest()? {
            return Err(refused());
        }
        inputs.revalidate()?;
        Ok(result)
    }

    pub(crate) fn from_snapshot(
        public: [Vec<u8>; 4],
        bridge: Option<CapturedBridgeSnapshot>,
        bundle: &Path,
        identity: &Path,
    ) -> io::Result<Self> {
        Self::from_snapshot_with_web(public, bridge, None, bundle, identity)
    }

    pub(crate) fn from_snapshot_with_web(
        public: [Vec<u8>; 4],
        bridge: Option<CapturedBridgeSnapshot>,
        web_response: Option<CapturedWebResponseSnapshot>,
        bundle: &Path,
        identity: &Path,
    ) -> io::Result<Self> {
        Self::from_snapshot_with_web_sfu(public, bridge, web_response, None, bundle, identity)
    }

    pub(crate) fn from_snapshot_with_web_sfu(
        public: [Vec<u8>; 4],
        bridge: Option<CapturedBridgeSnapshot>,
        web_response: Option<CapturedWebResponseSnapshot>,
        sfu_media: Option<CapturedSfuSnapshot>,
        bundle: &Path,
        identity: &Path,
    ) -> io::Result<Self> {
        let profile = if sfu_media.is_some() {
            device_bundle_profile::validate_profile_sfu_capability(&public[0])
        } else {
            device_bundle_profile::validate_profile(&public[0])
        }
        .map_err(|_| refused())?;
        match (&profile.sfu_media, &sfu_media) {
            (None, None) => {}
            (Some(signed), Some(held)) => {
                crate::sfu_media_custody::admit_public_roots(
                    &held.broker_ca,
                    &held.media_ca,
                    signed,
                )?;
                if held.broker_key.iter().all(|b| *b == b'0') {
                    return Err(refused());
                }
                // The feature-linked media owner is not yet admissible: its
                // WebRTC reactor and peer-close tasks must be joined before
                // Store/filter leases can be released. Keep every installed
                // build fail closed until that lifecycle proof is complete.
                return Err(refused());
            }
            _ => return Err(refused()),
        }
        if profile.mode().map_err(|_| refused())? != WideProductMode::FullWideTun || !profile.udp {
            return Err(refused());
        }
        for bytes in &public[1..] {
            device_bundle_profile::validate_ca(bytes).map_err(|_| refused())?;
        }
        enrollment::validate_device_ca(&public[3]).map_err(|_| refused())?;
        let mut settings = if profile.sfu_media.is_some() {
            device_bundle_profile::policy_settings_with_overlay_sfu_capability(
                &profile, identity, bundle,
            )
        } else {
            device_bundle_profile::policy_settings_with_overlay(&profile, identity, bundle, false)
        }
        .map_err(|_| refused())?;
        settings.relay.ca_cert = Some(bundle.join("outer-ca.pem"));
        if let Some(inner) = &mut settings.relay.inner_tls {
            inner.server_ca = bundle.join("inner-ca.pem");
        } else {
            return Err(refused());
        }
        settings.relay.https_bridge = bridge.as_ref().map(|held| held.settings.clone());
        settings.relay.web_response = web_response.as_ref().map(|held| held.settings.clone());
        if web_response.is_some() && settings.relay.carrier_program.is_none() {
            return Err(refused());
        }
        if let Some(held) = &bridge {
            if held.secret.iter().all(|b| *b == b'0')
                || held
                    .secret
                    .iter()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
            {
                return Err(refused());
            }
        }
        if settings.relay.carrier_program.is_none() {
            if let Some(bridge) = &settings.relay.https_bridge {
                bridge
                    .validate_authority(&profile.outer_server_name)
                    .map_err(|_| refused())?;
            }
        }
        if let Some(program) = &settings.relay.carrier_program {
            // The provider owns H2 and the RFC 8441 WS byte stream on its
            // signed physical TCP pin. WebResponse uses a separate owned
            // bootstrap, authenticated descriptor, ingress and flow service.
            // Enrolled QUIC requires its explicit held UDP owner feature.
            // SFU is eligible only with its complete
            // feature-gated owner and exact signed private capture.
            if program.routes.iter().any(|route| {
                !matches!(
                    route.channel,
                    CarrierChannel::DirectH2
                        | CarrierChannel::FrontedH2
                        | CarrierChannel::OwnHttpsBridge
                        | CarrierChannel::HttpsWs
                        | CarrierChannel::WebResponse
                ) && !(cfg!(feature = "enrolled-quic")
                    && route.channel == CarrierChannel::MasqueQuic)
                    && !(cfg!(feature = "sfu-media-vp8")
                        && sfu_media.is_some()
                        && route.channel == CarrierChannel::SfuMedia)
            }) {
                return Err(refused());
            }
            if let Some(media) = profile.sfu_media.as_ref() {
                program
                    .validate_public_sfu_capability(&settings.relay, media)
                    .map_err(|_| refused())?;
            } else {
                program.validate(&settings.relay).map_err(|_| refused())?;
            }
        }
        settings.validate_ech().map_err(|_| refused())?;
        let digest = profile_digest_bytes(&public);
        Ok(Self {
            settings,
            public_digest: digest,
            public,
            bridge,
            web_response,
            sfu_media,
            sfu_declaration: profile.sfu_media,
            macos_packet: profile.macos_packet,
        })
    }

    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) fn take_sfu_media(&mut self) -> Option<(SfuDeclaration, CapturedSfuSnapshot)> {
        Some((self.sfu_declaration.take()?, self.sfu_media.take()?))
    }

    pub(crate) fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The digest of the four held public files (v40: the identity the
    /// carrier failover controller of this profile is kept under).
    pub(crate) fn public_digest(&self) -> &str {
        &self.public_digest
    }

    /// Derive all packet-worker values from the retained signed bundle.
    /// The native manager MTU must match exactly; no local default supplies a
    /// missing field. This remains inert until a held relay service exists.
    pub(crate) fn packet_config(
        &self,
        saved_mtu: u16,
        saved_dns: &[IpAddr],
    ) -> io::Result<PacketEngineConfig> {
        let signed = self.macos_packet.as_ref().ok_or_else(refused)?;
        if signed.mtu != saved_mtu || signed.dns_servers.as_slice() != saved_dns {
            return Err(refused());
        }
        Ok(PacketEngineConfig {
            relay: self.settings.relay.clone(),
            max_flows: usize::from(signed.max_flows),
            idle: Duration::from_millis(signed.idle_ms),
            mtu: usize::from(signed.mtu),
            dns_upstream: signed.dns_upstream,
        })
    }

    /// The runtime terms this held signed bundle authorizes: the exact
    /// numeric relay host, the native DNS list and MTU of its macOS packet
    /// section, and the digest of the four public files it was built from.
    /// A bundle without a macOS packet section authorizes no runtime binding.
    pub(crate) fn signed_runtime_terms(&self) -> io::Result<SignedRuntimeTerms<'_>> {
        let signed = self.macos_packet.as_ref().ok_or_else(refused)?;
        let relay: SocketAddr = self.settings.relay.server.parse().map_err(|_| refused())?;
        Ok(SignedRuntimeTerms {
            relay: relay.ip(),
            dns: &signed.dns_servers,
            mtu: signed.mtu,
            profile_sha256: &self.public_digest,
        })
    }

    /// The held profile's enrollment authority, if it names one (v31: for
    /// the renewal monitor's guard check, never armed in the leak guard).
    pub(crate) fn authority_address(&self) -> Option<SocketAddr> {
        crate::renewal_exchange::authority_address(&self.public[0]).ok()
    }

    pub(crate) fn outer_ca(&self) -> &[u8] {
        &self.public[1]
    }

    pub(crate) fn inner_ca(&self) -> &[u8] {
        &self.public[2]
    }

    pub(crate) fn bridge_matches(&self, other: Option<&CapturedBridgeSnapshot>) -> bool {
        match (&self.bridge, other) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                expected.settings == actual.settings
                    && bool::from(expected.secret.as_slice().ct_eq(actual.secret.as_slice()))
            }
            _ => false,
        }
    }

    pub(crate) fn web_matches(&self, other: Option<&CapturedWebResponseSnapshot>) -> bool {
        match (&self.web_response, other) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                expected.settings == actual.settings
                    && bool::from(expected.secret.as_slice().ct_eq(actual.secret.as_slice()))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::https_bridge::ClientSettings as BridgeSettings;
    use aegis_core::web_response_profile::WebResponseSettings;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use serde_json::json;
    use zeroize::Zeroizing;

    fn held(settings: BridgeSettings) -> CapturedBridgeSnapshot {
        CapturedBridgeSnapshot {
            settings,
            secret: Zeroizing::new([b'a'; 64]),
        }
    }

    #[test]
    fn second_held_bridge_snapshot_must_match_secret_and_policy() {
        let bundle = Path::new("/private/tmp/b06-r20-bundle");
        let identity = Path::new("/private/tmp/b06-r20-identity");
        let settings = BridgeSettings {
            authority: "relay.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: identity.join("bridge-credential"),
        };
        let policy = BoundRelayPolicy::from_snapshot(
            fixture(),
            Some(held(settings.clone())),
            bundle,
            identity,
        )
        .unwrap();
        let matching = held(settings.clone());
        assert!(policy.bridge_matches(Some(&matching)));
        let mut changed = held(settings);
        changed.secret.fill(b'b');
        assert!(!policy.bridge_matches(Some(&changed)));
        assert!(!policy.bridge_matches(None));
    }

    fn fixture() -> [Vec<u8>; 4] {
        let mut ca = CertificateParams::new(vec![]).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let pem = ca.self_signed(&key).unwrap().pem().into_bytes();
        let profile = json!({
            "schema":"aegis_device_bundle_v4", "product_mode":"full-wide-tun", "udp":true,
            "relay_server":"127.0.0.1:443", "outer_server_name":"relay.test",
            "inner_server_name":"origin.test",
            "relay_endpoints":[{"server":"127.0.0.1:443","server_name":"relay.test"}],
            "enrollment":{"protocol":"aegis-enrollment-v1", "authority_server":"127.0.0.1:8443",
                "outer_server_name":"authority.test", "inner_server_name":"issuer.test",
                "automatic_renewal":true, "renewal_policy":"same-key-v1"}
        });
        [
            serde_json::to_vec(&profile).unwrap(),
            pem.clone(),
            pem.clone(),
            pem,
        ]
    }

    #[test]
    fn packet_config_requires_exact_signed_policy_and_saved_mtu() {
        let bundle = Path::new("/private/tmp/b06-r47-bundle");
        let identity = Path::new("/private/tmp/b06-r47-identity");
        let dns: Vec<IpAddr> = vec!["198.51.100.1".parse().unwrap()];
        let legacy = BoundRelayPolicy::from_snapshot(fixture(), None, bundle, identity).unwrap();
        assert!(legacy.packet_config(1400, &dns).is_err());

        let mut signed = fixture();
        let mut profile: serde_json::Value = serde_json::from_slice(&signed[0]).unwrap();
        profile["macos_packet"] = json!({
            "mtu":1400,
            "dns_servers":["198.51.100.1"],
            "dns_upstream":"198.51.100.53:53",
            "max_flows":64,
            "idle_ms":30_000
        });
        signed[0] = serde_json::to_vec(&profile).unwrap();
        let policy =
            BoundRelayPolicy::from_snapshot(signed.clone(), None, bundle, identity).unwrap();
        assert!(policy.packet_config(1399, &dns).is_err());
        assert!(policy
            .packet_config(1400, &["198.51.100.2".parse().unwrap()])
            .is_err());
        let config = policy.packet_config(1400, &dns).unwrap();
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.max_flows, 64);
        assert_eq!(config.idle, Duration::from_secs(30));
        assert_eq!(
            config.dns_upstream,
            "198.51.100.53:53".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(config.relay.server, "127.0.0.1:443");

        for bad in [
            json!(null),
            json!({"mtu":1279,"dns_servers":["198.51.100.1"],"dns_upstream":"198.51.100.53:53","max_flows":64,"idle_ms":30_000}),
            json!({"mtu":1400,"dns_servers":[],"dns_upstream":"198.51.100.53:53","max_flows":64,"idle_ms":30_000}),
            json!({"mtu":1400,"dns_servers":["127.0.0.1"],"dns_upstream":"198.51.100.53:53","max_flows":64,"idle_ms":30_000}),
            json!({"mtu":1400,"dns_servers":["198.51.100.1"],"dns_upstream":"127.0.0.1:53","max_flows":64,"idle_ms":30_000}),
            json!({"mtu":1400,"dns_servers":["198.51.100.1"],"dns_upstream":"198.51.100.53:53","max_flows":513,"idle_ms":30_000}),
            json!({"mtu":1400,"dns_servers":["198.51.100.1"],"dns_upstream":"198.51.100.53:53","max_flows":64,"idle_ms":0}),
            json!({"mtu":1400,"dns_servers":["198.51.100.1"],"dns_upstream":"198.51.100.53:53","max_flows":64,"idle_ms":30_000,"secret":"forbidden"}),
        ] {
            let mut altered = signed.clone();
            let mut profile: serde_json::Value = serde_json::from_slice(&altered[0]).unwrap();
            profile["macos_packet"] = bad;
            altered[0] = serde_json::to_vec(&profile).unwrap();
            assert!(BoundRelayPolicy::from_snapshot(altered, None, bundle, identity).is_err());
        }
    }

    #[test]
    fn complete_public_policy_and_private_bridge_are_derived_without_caller_settings() {
        let bundle = Path::new("/private/tmp/b06-r16-bundle");
        let identity = Path::new("/private/tmp/b06-r16-identity");
        let bridge = BridgeSettings {
            authority: "relay.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: identity.join("bridge-credential"),
        };
        let policy = BoundRelayPolicy::from_snapshot(
            fixture(),
            Some(held(bridge.clone())),
            bundle,
            identity,
        )
        .unwrap();
        assert_eq!(policy.settings.relay.https_bridge, Some(bridge.clone()));
        assert_eq!(policy.settings.relay.server, "127.0.0.1:443");
        assert_eq!(policy.settings.relay.endpoints.len(), 1);
        assert_eq!(
            policy.settings.relay.ca_cert.as_deref(),
            Some(bundle.join("outer-ca.pem").as_path())
        );
        assert_eq!(
            policy.settings.relay.inner_tls.as_ref().unwrap().server_ca,
            bundle.join("inner-ca.pem")
        );
        assert!(policy.settings.relay.auth_token.is_empty());
        assert!(policy.settings.relay.outer_geneva.is_none());
        assert!(policy.settings.relay.endpoint_bandit.is_none());
        assert!(policy.settings.relay.authenticated_shaping.is_none());
        let mut wrong_bridge = bridge;
        wrong_bridge.authority = "wrong.test".into();
        assert!(BoundRelayPolicy::from_snapshot(
            fixture(),
            Some(held(wrong_bridge)),
            bundle,
            identity
        )
        .is_err());
        let mut wrong_secret = held(policy.settings.relay.https_bridge.clone().unwrap());
        wrong_secret.secret.fill(b'0');
        assert!(
            BoundRelayPolicy::from_snapshot(fixture(), Some(wrong_secret), bundle, identity)
                .is_err()
        );
        let mut wrong_ca = fixture();
        wrong_ca[1] = b"not a CA".to_vec();
        assert!(BoundRelayPolicy::from_snapshot(wrong_ca, None, bundle, identity).is_err());
        let mut wrong_mode = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&wrong_mode[0]).unwrap();
        value["product_mode"] = "socks-only".into();
        wrong_mode[0] = serde_json::to_vec(&value).unwrap();
        assert!(BoundRelayPolicy::from_snapshot(wrong_mode, None, bundle, identity).is_err());
    }

    #[test]
    fn mixed_direct_and_bridge_program_requires_exact_held_bridge() {
        let bundle = Path::new("/private/tmp/b06-mixed-bundle");
        let identity = Path::new("/private/tmp/b06-mixed-identity");
        let mut public = fixture();
        let mut profile: serde_json::Value = serde_json::from_slice(&public[0]).unwrap();
        profile["relay_endpoints"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "server":"127.0.0.2:443", "server_name":"bridge.test"
            }));
        profile["carrier_program"] = json!({
            "routes":[
                {"channel":"direct_h2","endpoint_index":0},
                {"channel":"own_https_bridge","endpoint_index":1}
            ],
            "bridge":{"authority":"bridge.test","path":"/private/stream",
                "enrollment_path":"/private/enroll"}
        });
        public[0] = serde_json::to_vec(&profile).unwrap();
        let bridge = BridgeSettings {
            authority: "bridge.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: identity.join("bridge-credential"),
        };
        let policy = BoundRelayPolicy::from_snapshot(
            public.clone(),
            Some(held(bridge.clone())),
            bundle,
            identity,
        )
        .unwrap();
        assert_eq!(policy.settings.relay.endpoints.len(), 2);
        assert!(BoundRelayPolicy::from_snapshot(public.clone(), None, bundle, identity).is_err());
        let mut wrong = bridge;
        wrong.path = "/other".into();
        assert!(
            BoundRelayPolicy::from_snapshot(public, Some(held(wrong)), bundle, identity).is_err()
        );
    }

    #[test]
    fn ws_requires_exact_signed_route_and_quic_requires_its_owner_feature() {
        let bundle = Path::new("/private/tmp/b06-unsupported-bundle");
        let identity = Path::new("/private/tmp/b06-unsupported-identity");
        let mut public = fixture();
        let mut profile: serde_json::Value = serde_json::from_slice(&public[0]).unwrap();
        profile["relay_endpoints"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "server":"127.0.0.2:443", "server_name":"ws.test"
            }));
        profile["carrier_program"] = json!({"routes":[
            {"channel":"direct_h2","endpoint_index":0},
            {"channel":"https_ws","endpoint_index":1}
        ]});
        public[0] = serde_json::to_vec(&profile).unwrap();
        assert!(BoundRelayPolicy::from_snapshot(public.clone(), None, bundle, identity).is_ok());
        profile["carrier_program"]["routes"][1]["channel"] = json!("masque_quic");
        public[0] = serde_json::to_vec(&profile).unwrap();
        assert_eq!(
            BoundRelayPolicy::from_snapshot(public, None, bundle, identity).is_ok(),
            cfg!(feature = "enrolled-quic"),
        );
    }

    #[test]
    fn web_route_requires_held_key_and_exact_signed_descriptor_scope() {
        let bundle = Path::new("/private/tmp/b06-web-bundle");
        let identity = Path::new("/private/tmp/b06-web-identity");
        let mut public = fixture();
        let mut profile: serde_json::Value = serde_json::from_slice(&public[0]).unwrap();
        profile["relay_endpoints"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "server":"127.0.0.2:443", "server_name":"web.test"
            }));
        profile["carrier_program"] = json!({
            "routes":[
                {"channel":"direct_h2","endpoint_index":0},
                {"channel":"web_response","endpoint_index":1}
            ],
            "web_response":{
                "authority":"web.test", "descriptor_path":"/private/descriptor",
                "allowed_ingress_ips":["127.0.0.3"]
            }
        });
        public[0] = serde_json::to_vec(&profile).unwrap();
        let held = || CapturedWebResponseSnapshot {
            settings: WebResponseSettings {
                authority: "web.test".into(),
                descriptor_path: "/private/descriptor".into(),
                allowed_ingress_ips: vec!["127.0.0.3".parse().unwrap()],
                credential_file: identity.join("web-key"),
            },
            secret: Zeroizing::new([b'a'; 64]),
        };
        assert!(BoundRelayPolicy::from_snapshot_with_web(
            public.clone(),
            None,
            Some(held()),
            bundle,
            identity
        )
        .is_ok());
        assert!(BoundRelayPolicy::from_snapshot_with_web(
            public.clone(),
            None,
            None,
            bundle,
            identity
        )
        .is_err());
        let mut wrong = held();
        wrong.settings.allowed_ingress_ips = vec!["127.0.0.4".parse().unwrap()];
        assert!(BoundRelayPolicy::from_snapshot_with_web(
            public,
            None,
            Some(wrong),
            bundle,
            identity
        )
        .is_err());
    }

    #[test]
    fn nondefault_public_shaping_and_endpoint_bandit_survive_bound_derivation() {
        let bundle = Path::new("/private/tmp/b06-r17-bundle");
        let identity = Path::new("/private/tmp/b06-r17-identity");
        let mut shaped = fixture();
        let mut profile: serde_json::Value = serde_json::from_slice(&shaped[0]).unwrap();
        profile["authenticated_shaping"] = json!({
            "payload_bytes":1024,"cadence_ms":10,"buffer_bytes":4096,
            "max_wire_bytes":8388608,"io_timeout_ms":1000,"session_timeout_ms":10000,
            "max_queue_delay_ms":10000
        });
        profile["privacy_plan"] = json!({
            "packet_modifiers":["constant_cadence"],
            "framing_budget":{"max_payload_bytes":1024,"max_buffer_bytes":4096,
                "max_wire_bytes_per_direction":8388608,"max_session_ms":10000,
                "max_queue_delay_ms":200000}
        });
        shaped[0] = serde_json::to_vec(&profile).unwrap();
        let bound = BoundRelayPolicy::from_snapshot(shaped, None, bundle, identity).unwrap();
        assert!(bound.settings.relay.authenticated_shaping.is_some());
        assert!(bound.settings.privacy_plan.is_some());

        let mut pooled = fixture();
        let mut profile: serde_json::Value = serde_json::from_slice(&pooled[0]).unwrap();
        profile["relay_endpoints"]
            .as_array_mut()
            .unwrap()
            .push(json!({"server":"127.0.0.2:443","server_name":"relay.test"}));
        profile["endpoint_bandit"] = json!({
            "algorithm":{"algorithm":"sliding_window","rounds":16,"xi":1.0},
            "max_profiles":16,"max_contexts_per_profile":8,"pre_auth_block_ms":1000
        });
        pooled[0] = serde_json::to_vec(&profile).unwrap();
        let bound = BoundRelayPolicy::from_snapshot(pooled, None, bundle, identity).unwrap();
        assert_eq!(bound.settings.relay.endpoints.len(), 2);
        assert!(bound.settings.relay.endpoint_bandit.is_some());
    }
}
