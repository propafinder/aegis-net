//! One shared read-only public bundle parser and installed online profile validator.
use crate::credential_path_policy::clean_absolute_directory;
use crate::public_profile_file::{profile_digest_bytes, read_public, MAX_PUBLIC_BYTES, MEMBERS};
use aegis_core::secure_channel::{self, enrollment};
use aegis_core::wide_product::{
    inner_tls_device_ingress, resolve_inner_tls_device_profile, validate_inner_tls_device_settings,
    WideProductMode,
};
use anyhow::{ensure, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

#[path = "device_bundle_profile_online.rs"]
pub mod online;

fn relay_transport_order_keys(order: &[aegis_core::TunnelTransportFamily]) -> Vec<String> {
    use aegis_core::TunnelTransportFamily;
    order
        .iter()
        .map(|family| match family {
            TunnelTransportFamily::LegacyTls => "legacy_tls",
            TunnelTransportFamily::HttpsWs => "https_ws",
            TunnelTransportFamily::GrpcStream => "grpc_stream",
            TunnelTransportFamily::GrpcDatagram => "grpc_datagram",
            TunnelTransportFamily::MasqueDerived => "masque_derived",
        })
        .map(ToString::to_string)
        .collect()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProfile {
    /// Signed public route order for enrolled H2 endpoints. Absent on older
    /// bundles; included in the existing four-member bundle digest.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub carrier_program: Option<aegis_core::carrier_program::CarrierProgramSettings>,
    /// Explicit public SFU destinations and numeric ICE IP policy. This is
    /// digest-bound but inert for ordinary bundle/profile entrypoints.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub sfu_media: Option<aegis_core::carrier_program::SfuDeclaration>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub endpoint_bandit: Option<aegis_core::RelayEndpointBanditSettings>,
    pub schema: String,
    pub relay_server: String,
    pub outer_server_name: String,
    pub inner_server_name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_endpoints"
    )]
    pub relay_endpoints: Option<Vec<PublicEndpoint>>,
    #[serde(default)]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_mode: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "online::deserialize_metadata"
    )]
    pub enrollment: Option<online::EnrollmentMetadata>,
    /// Explicit public ECHConfigList bytes, included in the profile digest.
    /// No filesystem paths, credentials, discovery or implicit TLS fallback.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_ech_config"
    )]
    pub ech_config_list: Option<String>,
    /// Public paired relay policy. The raw bundle digest binds these exact bytes;
    /// no credentials, private filesystem paths or carrier fallback are accepted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub authenticated_shaping: Option<aegis_core::carrier_runtime::PrivacySettings>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub privacy_plan: Option<aegis_core::traffic_privacy::plan::PrivacyPlan>,
    /// Ranks only the already admitted managed relay transports.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub recent_routes: Option<aegis_core::brain::recent_routes::RecentRoutesSettings>,
    /// Explicit ordered-carrier failover policy for the v4 relay pool (D3).
    /// Absent: the default policy applies to a pool of two or more endpoints
    /// without an endpoint bandit. Bound by the profile digest; it only
    /// reorders the listed carriers and has no native-egress outcome.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub carrier_failover: Option<aegis_core::brain::carrier_failover::CarrierFailoverSettings>,
    /// Explicit macOS packet worker inputs, included in the signed public
    /// profile digest. Older profiles parse but cannot construct that worker.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_public_option"
    )]
    pub macos_packet: Option<MacosPacketPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MacosPacketPolicy {
    pub mtu: u16,
    /// Native NE DNS servers; the saved manager must request this exact list.
    pub dns_servers: Vec<IpAddr>,
    pub dns_upstream: SocketAddr,
    pub max_flows: u16,
    pub idle_ms: u64,
}

impl MacosPacketPolicy {
    pub fn validate(&self) -> Result<()> {
        fn usable_ip(ip: IpAddr) -> bool {
            match ip {
                IpAddr::V4(v4) => {
                    !v4.is_unspecified()
                        && !v4.is_multicast()
                        && !v4.is_loopback()
                        && !v4.is_link_local()
                        && !v4.is_broadcast()
                }
                IpAddr::V6(v6) => {
                    !v6.is_unspecified()
                        && !v6.is_multicast()
                        && !v6.is_loopback()
                        && !v6.is_unicast_link_local()
                        && v6.to_ipv4_mapped().is_none()
                }
            }
        }
        ensure!(
            (1280..=1500).contains(&self.mtu)
                && (1..=2).contains(&self.dns_servers.len())
                && self.dns_servers.iter().copied().all(usable_ip)
                && self.dns_upstream.port() != 0
                && usable_ip(self.dns_upstream.ip())
                && (1..=512).contains(&self.max_flows)
                && (1..=600_000).contains(&self.idle_ms),
            "invalid macOS packet policy"
        );
        Ok(())
    }
}

pub fn deserialize_public_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Absence preserves defaults; an explicitly supplied null is not a policy.
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEndpoint {
    pub server: String,
    pub server_name: String,
}

pub fn deserialize_endpoints<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<PublicEndpoint>>, D::Error> {
    Vec::<PublicEndpoint>::deserialize(deserializer).map(Some)
}

pub fn deserialize_ech_config<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl PublicProfile {
    pub fn endpoints(&self) -> Vec<aegis_core::RelayEndpointSettings> {
        self.relay_endpoints
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|endpoint| aegis_core::RelayEndpointSettings {
                server: endpoint.server.clone(),
                server_name: endpoint.server_name.clone(),
                masque_server: None,
                masque_server_name: None,
            })
            .collect()
    }

    /// The failover policy an installed client runs for this profile.
    pub fn effective_carrier_failover(
        &self,
    ) -> Option<aegis_core::brain::carrier_failover::CarrierFailoverSettings> {
        if self.carrier_failover.is_some() {
            return self.carrier_failover.clone();
        }
        // The last signed SFU endpoint is a separate, explicitly admitted
        // media capability. A generic two-endpoint H2 failover would turn it
        // into an ordinary carrier before the media owner is authorized.
        if self.sfu_media.is_some() {
            return None;
        }
        (self.endpoint_bandit.is_none()
            && self
                .relay_endpoints
                .as_ref()
                .is_some_and(|pool| pool.len() >= 2))
        .then(Default::default)
    }

    pub fn mode(&self) -> Result<WideProductMode> {
        if self.schema == "aegis_device_bundle_v4" {
            let endpoints = self
                .relay_endpoints
                .as_ref()
                .context("v4 requires an explicit relay pool")?;
            ensure!(
                !endpoints.is_empty() && endpoints.len() <= 16,
                "relay pool must contain 1 to 16 endpoints"
            );
            ensure!(
                endpoints[0].server == self.relay_server
                    && endpoints[0].server_name == self.outer_server_name,
                "relay pool must begin with the primary endpoint"
            );
        } else {
            ensure!(
                self.relay_endpoints.is_none(),
                "relay pools require the v4 profile schema"
            );
        }
        let mode = match (self.schema.as_str(), self.product_mode.as_deref()) {
            ("aegis_device_bundle_v1", None) => WideProductMode::SocksOnly,
            ("aegis_device_bundle_v2", Some("socks-only")) => WideProductMode::SocksOnly,
            ("aegis_device_bundle_v2", Some("full-wide-tun")) => WideProductMode::FullWideTun,
            ("aegis_device_bundle_v3" | "aegis_device_bundle_v4", Some("socks-only")) => {
                WideProductMode::SocksOnly
            }
            ("aegis_device_bundle_v3" | "aegis_device_bundle_v4", Some("full-wide-tun")) => {
                WideProductMode::FullWideTun
            }
            _ => anyhow::bail!("unsupported device bundle schema or product_mode"),
        };
        match (self.schema.as_str(), &self.enrollment) {
            ("aegis_device_bundle_v3" | "aegis_device_bundle_v4", Some(metadata)) => {
                metadata.validate(mode)?
            }
            ("aegis_device_bundle_v3" | "aegis_device_bundle_v4", None) => {
                anyhow::bail!("online profile requires explicit enrollment policy")
            }
            (_, Some(_)) => anyhow::bail!("online enrollment requires the v3 or v4 profile schema"),
            (_, None) => {}
        }
        if let Some(policy) = &self.carrier_failover {
            ensure!(
                self.schema == "aegis_device_bundle_v4"
                    && self.endpoint_bandit.is_none()
                    && self
                        .relay_endpoints
                        .as_ref()
                        .is_some_and(|pool| pool.len() >= 2),
                "carrier failover requires a v4 relay pool of two or more endpoints and no endpoint bandit"
            );
            policy.validate().map_err(anyhow::Error::msg)?;
        }
        if let Some(packet) = &self.macos_packet {
            ensure!(
                self.schema == "aegis_device_bundle_v4"
                    && mode == WideProductMode::FullWideTun
                    && self.udp,
                "macOS packet policy requires v4 full-wide UDP"
            );
            packet.validate()?;
        }
        if self.sfu_media.is_some() {
            ensure!(
                self.schema == "aegis_device_bundle_v4"
                    && mode == WideProductMode::FullWideTun
                    && self.udp
                    && self.carrier_program.as_ref().is_some_and(|program| {
                        program.routes.last().is_some_and(|route| {
                            route.channel == aegis_core::carrier_program::CarrierChannel::SfuMedia
                        })
                    }),
                "SFU media requires an explicit v4 full-wide route and UDP policy"
            );
        }
        resolve_inner_tls_device_profile(mode, self.udp).map_err(anyhow::Error::msg)?;
        Ok(mode)
    }
}

pub fn inspection(profile: &PublicProfile) -> Result<serde_json::Value> {
    let mode = profile.mode()?;
    let mut output = serde_json::to_value(profile)?;
    output["product_mode"] = mode.as_str().into();
    output["resolved"] = serde_json::to_value(
        resolve_inner_tls_device_profile(mode, profile.udp).map_err(anyhow::Error::msg)?,
    )?;
    Ok(output)
}

pub fn validate_ca(bytes: &[u8]) -> Result<()> {
    enrollment::validate_public_certificate_chain(bytes)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(bytes) {
        roots.add(certificate.context("invalid public CA PEM")?)?;
    }
    ensure!(!roots.is_empty(), "public CA file has no certificates");
    Ok(())
}

pub fn load(directory: &Path) -> Result<PublicProfile> {
    load_snapshot(directory).map(|(profile, _, _)| profile)
}

pub fn load_snapshot(
    directory: &Path,
) -> Result<(PublicProfile, String, BTreeMap<String, String>)> {
    use sha2::{Digest, Sha256};
    enrollment::trusted_parent(&directory.join("bundle.json"))?;
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "public bundle directories and links are forbidden"
        );
        names.push(entry.file_name());
    }
    names.sort();
    let mut expected: Vec<std::ffi::OsString> = MEMBERS.iter().map(|name| (*name).into()).collect();
    expected.sort();
    ensure!(
        names == expected,
        "public bundle requires exactly bundle.json and three CA files"
    );
    let payload = [
        read_public(&directory.join(MEMBERS[0]))?,
        read_public(&directory.join(MEMBERS[1]))?,
        read_public(&directory.join(MEMBERS[2]))?,
        read_public(&directory.join(MEMBERS[3]))?,
    ];
    let profile = validate_profile(&payload[0])?;
    for bytes in &payload[1..] {
        validate_ca(bytes)?;
    }
    enrollment::validate_device_ca(&payload[3])?;
    let member_pins = MEMBERS
        .iter()
        .zip(&payload)
        .map(|(name, bytes)| ((*name).to_owned(), hex::encode(Sha256::digest(bytes))))
        .collect();
    Ok((profile, profile_digest_bytes(&payload), member_pins))
}

pub fn validate_profile(bytes: &[u8]) -> Result<PublicProfile> {
    validate_profile_with_capability(bytes, false)
}

/// Only an installed provider with a complete, feature-gated media owner may
/// use this preflight. The ordinary public-profile validator still refuses
/// every `sfu_media` route.
pub fn validate_profile_sfu_capability(bytes: &[u8]) -> Result<PublicProfile> {
    validate_profile_with_capability(bytes, true)
}

fn validate_profile_with_capability(bytes: &[u8], sfu_capability: bool) -> Result<PublicProfile> {
    ensure!(
        bytes.len() as u64 <= MAX_PUBLIC_BYTES,
        "public bundle profile too large"
    );
    let profile: PublicProfile =
        serde_json::from_slice(bytes).context("invalid public bundle profile")?;
    profile.mode()?;
    let authority: http::uri::Authority = profile
        .relay_server
        .parse()
        .context("invalid relay address")?;
    ensure!(
        authority.port_u16().is_some_and(|port| port > 0),
        "relay address requires an explicit nonzero port"
    );
    for name in [&profile.outer_server_name, &profile.inner_server_name] {
        ServerName::try_from(name.clone()).context("invalid public TLS server name")?;
    }
    // Validate the complete fixed policy before copying any public input or
    // pinning a profile. Full-wide DNS preview requires an IPv4 dial endpoint.
    // These are policy-only placeholders; never create or read these paths.
    // A Unix root is not an absolute path on Windows.
    #[cfg(windows)]
    let (identity, config) = (r"C:\AEGIS-policy\identity", r"C:\AEGIS-policy\config");
    #[cfg(not(windows))]
    let (identity, config) = ("/var/lib/aegis-identity/client", "/etc/aegis/client");
    policy_settings_inner(
        &profile,
        Path::new(identity),
        Path::new(config),
        false,
        sfu_capability,
    )?;
    Ok(profile)
}

pub fn profile_digest(bundle: &Path) -> Result<String> {
    Ok(profile_digest_bytes(&[
        read_public(&bundle.join(MEMBERS[0]))?,
        read_public(&bundle.join(MEMBERS[1]))?,
        read_public(&bundle.join(MEMBERS[2]))?,
        read_public(&bundle.join(MEMBERS[3]))?,
    ]))
}

pub fn settings(
    profile: &PublicProfile,
    identity: &Path,
    config: &Path,
) -> Result<aegis_core::Settings> {
    ensure!(
        clean_absolute_directory(identity) && clean_absolute_directory(config),
        "identity and config paths must be clean absolute directories"
    );
    ensure!(
        !directories_overlap(identity, config)?,
        "private device identity must be outside configuration snapshots"
    );
    policy_settings(profile, identity, config)
}

pub fn policy_settings(
    profile: &PublicProfile,
    identity: &Path,
    config: &Path,
) -> Result<aegis_core::Settings> {
    policy_settings_with_overlay(profile, identity, config, true)
}

pub fn policy_settings_with_overlay(
    profile: &PublicProfile,
    identity: &Path,
    config: &Path,
    private_overlay: bool,
) -> Result<aegis_core::Settings> {
    policy_settings_inner(profile, identity, config, private_overlay, false)
}

/// A provider-only policy rendering after full media feature and private
/// custody admission. The caller still has to capture every secret and hold
/// the signed profile bytes through the session terminal join.
pub fn policy_settings_with_overlay_sfu_capability(
    profile: &PublicProfile,
    identity: &Path,
    config: &Path,
) -> Result<aegis_core::Settings> {
    policy_settings_inner(profile, identity, config, false, true)
}

fn policy_settings_inner(
    profile: &PublicProfile,
    identity: &Path,
    config: &Path,
    private_overlay: bool,
    sfu_capability: bool,
) -> Result<aegis_core::Settings> {
    let mode = profile.mode()?;
    let mut settings = aegis_core::Settings {
        mode: aegis_core::Mode::Relay,
        local_stealth_profile: aegis_core::LocalStealthProfile::LocalHardened,
        ..Default::default()
    };
    settings.ingress = inner_tls_device_ingress(mode, profile.udp).map_err(anyhow::Error::msg)?;
    if cfg!(windows) && mode == WideProductMode::FullWideTun {
        // The same public capture policy uses Wintun on Windows; do not
        // require an operator to rewrite a Linux redirect configuration.
        settings.ingress = aegis_core::IngressSettings {
            primary: aegis_core::IngressPrimary::Socks5,
            allow_fallback: false,
            wide: aegis_core::WideIngressSettings {
                enabled: false,
                ..Default::default()
            },
        };
        settings.windows_tunnel = Some(Default::default());
    }
    settings.socks.listen = "127.0.0.1:1080".parse()?;
    settings.relay.server.clone_from(&profile.relay_server);
    settings.relay.endpoints = profile.endpoints();
    settings
        .relay
        .server_name
        .clone_from(&profile.outer_server_name);
    settings.relay.auth_token.clear();
    settings.relay.ca_cert = Some(config.join("ca.pem"));
    settings.relay.transport_priority = vec![aegis_core::TunnelTransportFamily::GrpcStream];
    settings.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
    if let Some(encoded) = &profile.ech_config_list {
        crate::ech_policy::inline_ech_config(encoded)?;
        if let Some(metadata) = &profile.enrollment {
            metadata.validate_ech_name()?;
        }
        settings.relay.ech_config_list_base64 = Some(encoded.clone());
    }
    settings.relay.wire_mimicry_mode = aegis_core::WireMimicryMode::Disabled;
    settings.relay.connect_timeout_ms = 5000;
    settings.relay.udp_transport_priority = Some(if profile.udp {
        vec![aegis_core::TunnelTransportFamily::GrpcDatagram]
    } else {
        Vec::new()
    });
    settings.relay.grpc_path = secure_channel::GRPC_PATH.into();
    settings.relay.grpc_path_pool.clear();
    settings.relay.inner_tls = Some(secure_channel::ClientSettings {
        server_name: profile.inner_server_name.clone(),
        server_ca: config.join("inner-ca.pem"),
        cert: identity.join("device.pem"),
        key: identity.join("device.key"),
    });
    settings.relay.endpoint_bandit = profile.endpoint_bandit.clone();
    settings.relay.carrier_program = profile.carrier_program.clone();
    settings.relay.carrier_failover = profile.effective_carrier_failover();
    settings.relay.authenticated_shaping = profile.authenticated_shaping.clone();
    settings.privacy_plan = profile.privacy_plan.clone();
    settings.direct.recent_routes = profile.recent_routes.clone();
    // Public policy admission must precede the private overlay's credential I/O.
    settings
        .validate_privacy_plan()
        .map_err(anyhow::Error::msg)?;
    if let Some(recent) = &settings.direct.recent_routes {
        recent
            .validate(&relay_transport_order_keys(
                &settings.relay.transport_priority,
            ))
            .map_err(anyhow::Error::msg)?;
    }
    if private_overlay {
        settings.relay.https_bridge = online::load_https_bridge(identity)?;
        settings.relay.web_response = crate::device_web_response::load(identity)?;
    }
    settings.validate_ech().map_err(anyhow::Error::msg)?;
    // Public preflight has no private bridge credential. Validate its signed
    // route and authority/path contract, then validate the remaining device
    // policy without constructing a runnable bridge config. Render without an
    // identity is validate-only and never writes these planning settings.
    if sfu_capability {
        let program = settings
            .relay
            .carrier_program
            .as_ref()
            .context("SFU capability requires signed route program")?;
        let media = profile
            .sfu_media
            .as_ref()
            .context("SFU capability requires signed media declaration")?;
        program
            .validate_public_sfu_capability(&settings.relay, media)
            .map_err(anyhow::Error::msg)?;
        let mut preview = settings.clone();
        preview.relay.carrier_program = None;
        validate_inner_tls_device_settings(mode, profile.udp, &preview)
            .map_err(anyhow::Error::msg)?;
    } else if !private_overlay
        && settings
            .relay
            .carrier_program
            .as_ref()
            .is_some_and(|program| program.bridge.is_some() || program.web_response.is_some())
    {
        settings
            .relay
            .carrier_program
            .as_ref()
            .unwrap()
            .validate_public(&settings.relay)
            .map_err(anyhow::Error::msg)?;
        let mut preview = settings.clone();
        preview.relay.carrier_program = None;
        validate_inner_tls_device_settings(mode, profile.udp, &preview)
            .map_err(anyhow::Error::msg)?;
    } else {
        validate_inner_tls_device_settings(mode, profile.udp, &settings)
            .map_err(anyhow::Error::msg)?;
    }
    Ok(settings)
}

#[cfg(not(windows))]
pub fn directories_overlap(left: &Path, right: &Path) -> Result<bool> {
    Ok(left.starts_with(right) || right.starts_with(left))
}

#[cfg(windows)]
pub fn directories_overlap(left: &Path, right: &Path) -> Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    fn resolved(path: &Path) -> Result<PathBuf> {
        aegis_core::windows_file::reject_reparse_ancestry(path)?;
        let mut ancestor = path;
        let mut missing = Vec::new();
        loop {
            match ancestor.canonicalize() {
                Ok(mut absolute) => {
                    for part in missing.into_iter().rev() {
                        absolute.push(part);
                    }
                    return Ok(absolute);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(ancestor.file_name().context("directory ancestor missing")?);
                    ancestor = ancestor.parent().context("directory root missing")?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    // Resolve existing short-name/drive-prefix aliases. Missing descendants
    // still require the OS ordinal case comparison, including Unicode names.
    let left = resolved(left)?;
    let right = resolved(right)?;
    for (a, b) in left.components().zip(right.components()) {
        let a: Vec<u16> = a.as_os_str().encode_wide().collect();
        let b: Vec<u16> = b.as_os_str().encode_wide().collect();
        let order = unsafe {
            CompareStringOrdinal(
                a.as_ptr(),
                a.len().try_into()?,
                b.as_ptr(),
                b.len().try_into()?,
                1,
            )
        };
        if order == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if order != CSTR_EQUAL {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod carrier_failover_profile_tests {
    use super::*;
    use aegis_core::brain::carrier_failover::CarrierFailoverSettings;
    use serde_json::{json, Value};

    fn profile(endpoints: usize) -> Value {
        let pool: Vec<Value> = [
            ("198.51.100.10:443", "relay.test"),
            ("203.0.113.20:443", "edge.test"),
            ("203.0.113.21:443", "edge.test"),
        ]
        .iter()
        .take(endpoints)
        .map(|(server, name)| json!({"server": server, "server_name": name}))
        .collect();
        json!({
            "schema": "aegis_device_bundle_v4",
            "relay_server": "198.51.100.10:443",
            "outer_server_name": "relay.test",
            "inner_server_name": "inner.test",
            "relay_endpoints": pool,
            "udp": true,
            "product_mode": "full-wide-tun",
            "enrollment": {
                "protocol": "aegis-enrollment-v1",
                "authority_server": "198.51.100.10:9445",
                "outer_server_name": "relay.test",
                "inner_server_name": "enroll.test",
                "automatic_renewal": true,
                "renewal_policy": "same-key-v1"
            }
        })
    }

    fn rendered(value: &Value) -> Result<aegis_core::Settings> {
        let profile = validate_profile(&serde_json::to_vec(value).unwrap())?;
        policy_settings_with_overlay(
            &profile,
            Path::new("/var/lib/aegis-identity/client"),
            Path::new("/etc/aegis/client"),
            false,
        )
    }

    #[test]
    fn pool_of_two_or_more_gets_the_default_policy_and_single_endpoint_none() {
        let single = rendered(&profile(1)).unwrap();
        assert!(single.relay.carrier_failover.is_none());
        for endpoints in [2, 3] {
            let pool = rendered(&profile(endpoints)).unwrap();
            assert_eq!(
                pool.relay.carrier_failover,
                Some(CarrierFailoverSettings::default())
            );
            assert_eq!(pool.relay.endpoints.len(), endpoints);
            // Enrolled transport plan is unchanged by failover.
            assert_eq!(
                pool.relay.transport_priority,
                vec![aegis_core::TunnelTransportFamily::GrpcStream]
            );
            assert_eq!(
                pool.relay.udp_transport_priority,
                Some(vec![aegis_core::TunnelTransportFamily::GrpcDatagram])
            );
            // The installed TOML carries the policy explicitly.
            let toml = toml::to_string_pretty(&pool).unwrap();
            assert!(toml.contains("[relay.carrier_failover]"), "{toml}");
            let reloaded: aegis_core::Settings = toml::from_str(&toml).unwrap();
            assert_eq!(reloaded.relay.carrier_failover, pool.relay.carrier_failover);
        }
    }

    #[test]
    fn explicit_policy_is_bound_by_the_digest_and_rendered_verbatim() {
        let mut value = profile(2);
        let implicit = serde_json::to_vec(&value).unwrap();
        value["carrier_failover"] = json!({"base_cooldown_ms": 2000, "liveness_interval_ms": 0});
        let explicit = serde_json::to_vec(&value).unwrap();
        let settings = rendered(&value).unwrap();
        let policy = settings.relay.carrier_failover.unwrap();
        assert_eq!(policy.base_cooldown_ms, 2000);
        assert!(!policy.liveness_enabled());
        let members = |first: Vec<u8>| [first, b"o".to_vec(), b"i".to_vec(), b"d".to_vec()];
        assert_ne!(
            profile_digest_bytes(&members(implicit)),
            profile_digest_bytes(&members(explicit))
        );
    }

    #[test]
    fn invalid_or_inapplicable_policies_refuse() {
        let cases = [
            (profile(1), json!({})),
            (profile(2), json!(null)),
            (profile(2), json!({"degraded_threshold": 0})),
            (profile(2), json!({"native_fallback": true})),
            (profile(2), json!({"max_networks": 65})),
        ];
        for (mut value, policy) in cases {
            value["carrier_failover"] = policy.clone();
            assert!(rendered(&value).is_err(), "{policy}");
        }
        let mut v3 = profile(1);
        v3["schema"] = "aegis_device_bundle_v3".into();
        v3.as_object_mut().unwrap().remove("relay_endpoints");
        assert!(rendered(&v3).unwrap().relay.carrier_failover.is_none());
        v3["carrier_failover"] = json!({});
        assert!(rendered(&v3).is_err());
    }
}

#[cfg(test)]
mod macos_packet_tests {
    use super::*;
    use serde_json::{json, Value};

    fn profile() -> Value {
        json!({
            "schema": "aegis_device_bundle_v4",
            "relay_server": "198.51.100.10:443",
            "outer_server_name": "relay.test",
            "inner_server_name": "inner.test",
            "relay_endpoints": [{"server": "198.51.100.10:443", "server_name": "relay.test"}],
            "udp": true,
            "product_mode": "full-wide-tun",
            "enrollment": {
                "protocol": "aegis-enrollment-v1",
                "authority_server": "198.51.100.10:9445",
                "outer_server_name": "relay.test",
                "inner_server_name": "enroll.test",
                "automatic_renewal": true,
                "renewal_policy": "same-key-v1"
            }
        })
    }

    fn packet() -> Value {
        json!({"mtu": 1280, "dns_servers": ["198.19.255.2", "fd00:ae61::2"],
            "dns_upstream": "1.1.1.1:53", "max_flows": 256, "idle_ms": 120000})
    }

    #[test]
    fn validates_optional_packet_policy_and_binds_it_in_profile_digest() {
        let mut value = profile();
        let legacy = serde_json::to_vec(&value).unwrap();
        assert!(validate_profile(&legacy).unwrap().macos_packet.is_none());
        value["macos_packet"] = packet();
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed = validate_profile(&bytes).unwrap();
        assert_eq!(parsed.macos_packet.unwrap().mtu, 1280);
        let mut members = [
            legacy,
            b"outer".to_vec(),
            b"inner".to_vec(),
            b"device".to_vec(),
        ];
        let legacy_digest = profile_digest_bytes(&members);
        members[0] = bytes;
        let packet_digest = profile_digest_bytes(&members);
        assert_ne!(legacy_digest, packet_digest);
        value["macos_packet"]["idle_ms"] = 120001.into();
        members[0] = serde_json::to_vec(&value).unwrap();
        assert!(validate_profile(&members[0]).is_ok());
        assert_ne!(packet_digest, profile_digest_bytes(&members));
    }

    #[test]
    fn rejects_invalid_packet_sections_and_incompatible_profiles() {
        let mut invalid = vec![Value::Null];
        for (key, value) in [
            ("mtu", json!(1279)),
            ("mtu", json!(1501)),
            ("dns_servers", json!([])),
            ("dns_servers", json!(["127.0.0.1"])),
            ("dns_upstream", json!("1.1.1.1:0")),
            ("dns_upstream", json!("[::ffff:1.1.1.1]:53")),
            ("max_flows", json!(0)),
            ("idle_ms", json!(600001)),
            ("unknown", json!(true)),
        ] {
            let mut bad = packet();
            bad[key] = value;
            invalid.push(bad);
        }
        let mut missing = packet();
        missing.as_object_mut().unwrap().remove("dns_upstream");
        invalid.push(missing);
        for section in invalid {
            let mut bad = profile();
            bad["macos_packet"] = section;
            assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        for (key, value) in [("udp", json!(false)), ("product_mode", json!("socks-only"))] {
            let mut bad = profile();
            bad["macos_packet"] = packet();
            bad[key] = value;
            assert!(validate_profile(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
}

#[cfg(test)]
mod sfu_profile_capability_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signed_sfu_bundle_is_inert_until_explicit_provider_capability() {
        let profile = json!({
            "schema": "aegis_device_bundle_v4",
            "relay_server": "198.51.100.10:443",
            "outer_server_name": "relay.test",
            "inner_server_name": "inner.test",
            "relay_endpoints": [
                {"server": "198.51.100.10:443", "server_name": "relay.test"},
                {"server": "198.51.100.11:443", "server_name": "media.test"}
            ],
            "carrier_program": {"routes": [
                {"channel": "direct_h2", "endpoint_index": 0},
                {"channel": "sfu_media", "endpoint_index": 1}
            ]},
            "sfu_media": {
                "broker": "198.51.100.12:9447",
                "broker_tls_name": "broker.test",
                "broker_ca_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "media": "198.51.100.11:443",
                "media_tls_name": "media.test",
                "media_ca_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "allowed_media_ips": ["198.51.100.11"]
            },
            "udp": true,
            "product_mode": "full-wide-tun",
            "enrollment": {
                "protocol": "aegis-enrollment-v1",
                "authority_server": "198.51.100.10:9445",
                "outer_server_name": "relay.test",
                "inner_server_name": "enroll.test",
                "automatic_renewal": true,
                "renewal_policy": "same-key-v1"
            }
        });
        let bytes = serde_json::to_vec(&profile).unwrap();
        assert!(validate_profile(&bytes).is_err());
        let accepted = validate_profile_sfu_capability(&bytes).unwrap();
        assert!(accepted.effective_carrier_failover().is_none());
        assert!(policy_settings_with_overlay(
            &accepted,
            Path::new("/var/lib/aegis-identity/client"),
            Path::new("/etc/aegis/client"),
            false
        )
        .is_err());
        policy_settings_with_overlay_sfu_capability(
            &accepted,
            Path::new("/var/lib/aegis-identity/client"),
            Path::new("/etc/aegis/client"),
        )
        .unwrap();
        let mut missing = profile.clone();
        missing.as_object_mut().unwrap().remove("sfu_media");
        assert!(validate_profile_sfu_capability(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut failover = profile.clone();
        failover["carrier_failover"] = serde_json::to_value(
            aegis_core::brain::carrier_failover::CarrierFailoverSettings::default(),
        )
        .unwrap();
        assert!(validate_profile_sfu_capability(&serde_json::to_vec(&failover).unwrap()).is_err());
        let mut changed = profile;
        changed["sfu_media"]["media"] = json!("198.51.100.13:443");
        assert!(validate_profile_sfu_capability(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
}
