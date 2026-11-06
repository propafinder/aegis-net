//! Explicit online additions to an immutable four-member public device profile.
use super::{load, profile_digest, read_public, WideProductMode};
pub use aegis_client::credential_path_policy::validate_https_bridge_credential_file;
use aegis_core::{secure_channel::enrollment_tls, RelaySettings};
use anyhow::{ensure, Context, Result};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};

/// Private installed carrier intent is separate from the public four-file pin.
/// Only a missing leaf under an already trusted parent means no overlay.
pub fn load_https_bridge(
    identity: &Path,
) -> Result<Option<aegis_core::https_bridge::ClientSettings>> {
    use aegis_core::{https_bridge, secret_file};
    ensure!(
        https_bridge::clean_absolute(identity) && super::clean_absolute_directory(identity),
        "HTTPS bridge sidecar rejected"
    );
    let path = identity.join(https_bridge::SIDECAR);
    secret_file::trusted_read_parent(&path)
        .map_err(|_| anyhow::anyhow!("HTTPS bridge sidecar rejected"))?;
    let bytes = match secret_file::read(&path, 8192) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A disappeared parent must not be interpreted as an absent leaf.
            secret_file::trusted_read_parent(&path)
                .map_err(|_| anyhow::anyhow!("HTTPS bridge sidecar rejected"))?;
            return Ok(None);
        }
        Err(_) => return Err(anyhow::anyhow!("HTTPS bridge sidecar rejected")),
    };
    let input = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("HTTPS bridge sidecar rejected"))?;
    // TOML diagnostics can contain source text; discard the parser's error.
    let bridge: https_bridge::ClientSettings =
        toml::from_str(input).map_err(|_| anyhow::anyhow!("HTTPS bridge sidecar rejected"))?;
    validate_https_bridge_credential_file(&bridge)?;
    bridge
        .load_credential()
        .map_err(|_| anyhow::anyhow!("HTTPS bridge credential rejected"))?;
    Ok(Some(bridge))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentMetadata {
    protocol: String,
    authority_server: String,
    outer_server_name: String,
    inner_server_name: String,
    automatic_renewal: bool,
    renewal_policy: String,
}

pub fn deserialize_metadata<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<EnrollmentMetadata>, D::Error> {
    // Missing is allowed only for v1/v2; an explicit null must not make an
    // otherwise unknown online field silently acceptable in historical schemas.
    EnrollmentMetadata::deserialize(deserializer).map(Some)
}

impl EnrollmentMetadata {
    pub fn validate_ech_name(&self) -> Result<()> {
        ensure!(
            matches!(
                ServerName::try_from(self.outer_server_name.clone())?,
                ServerName::DnsName(_)
            ),
            "ECH enrollment carrier requires a DNS TLS server name"
        );
        Ok(())
    }

    pub fn validate(&self, mode: WideProductMode) -> Result<()> {
        ensure!(
            self.protocol == "aegis-enrollment-v1"
                && self.automatic_renewal
                && self.renewal_policy == "same-key-v1",
            "unsupported online enrollment or renewal policy"
        );
        validate_authority(&self.authority_server)?;
        for name in [&self.outer_server_name, &self.inner_server_name] {
            ensure!(name.len() <= 253, "enrollment TLS name is too long");
            ServerName::try_from(name.clone()).context("invalid enrollment TLS server name")?;
        }
        if mode == WideProductMode::FullWideTun {
            let address: SocketAddrV4 = self
                .authority_server
                .parse()
                .context("full-wide enrollment requires a pinned IPv4 authority endpoint")?;
            let ip = address.ip();
            ensure!(
                !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && ip.octets()[..2] != [198, 18]
                    && ip.octets()[..2] != [198, 19],
                "enrollment authority is unusable or overlaps the DNS preview pool"
            );
        }
        Ok(())
    }
}

fn validate_authority(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value.is_ascii()
            && !value.bytes().any(|b| b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'@' | b'/' | b'?' | b'#' | b'\\')),
        "enrollment authority must be a host and explicit port, without URL/userinfo"
    );
    let authority: http::uri::Authority = value.parse().context("invalid enrollment authority")?;
    ensure!(
        !authority.host().is_empty() && authority.port_u16().is_some_and(|p| p > 0),
        "enrollment authority requires a host and nonzero port"
    );
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    ServerName::try_from(host.to_owned()).context("invalid enrollment authority host")?;
    Ok(())
}

/// Construction validates the profile and its complete four-file digest; it
/// never rewrites a prepared device's existing trust pin.
pub struct OnlineProfile {
    digest: String,
    carrier: RelaySettings,
    tls: enrollment_tls::ClientSettings,
}

/// Public metadata only: privileged parent must not read worker-owned stores
/// or HTTPS bridge credentials to select its exact authority TCP exception.
#[cfg(target_os = "macos")]
pub fn full_wide_authority_pin(bundle: &Path) -> Result<std::net::SocketAddr> {
    let profile = load(bundle)?;
    ensure!(
        profile.mode()? == WideProductMode::FullWideTun && profile.udp,
        "worker bundle requires full-wide-tun with UDP"
    );
    let metadata = profile
        .enrollment
        .context("worker bundle requires online identity")?;
    let address: std::net::SocketAddr = metadata
        .authority_server
        .parse()
        .map_err(|_| anyhow::anyhow!("worker authority must be a numeric pin"))?;
    ensure!(
        address.port() > 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
        "worker authority pin rejected"
    );
    Ok(address)
}

impl OnlineProfile {
    /// Match the installed traffic configuration to the immutable public
    /// profile before local repair, network access or ingress initialization.
    pub fn for_runtime(bundle: &Path, settings: &aegis_core::Settings) -> Result<(Self, PathBuf)> {
        ensure!(
            super::clean_absolute_directory(bundle),
            "online runtime bundle requires a clean absolute directory"
        );
        let public = load(bundle)?;
        // Bind optional installed algorithms to the same immutable four-member
        // public profile before accessing any private overlay or identity file.
        ensure!(
            serde_json::to_value(&settings.relay.endpoint_bandit)?
                == serde_json::to_value(&public.endpoint_bandit)?
                && settings.relay.carrier_program == public.carrier_program
                && settings.relay.authenticated_shaping == public.authenticated_shaping
                && serde_json::to_value(&settings.privacy_plan)?
                    == serde_json::to_value(&public.privacy_plan)?
                && serde_json::to_value(&settings.direct.recent_routes)?
                    == serde_json::to_value(&public.recent_routes)?
                && settings.relay.carrier_failover == public.effective_carrier_failover(),
            "online runtime research policy differs from public profile"
        );
        let identity = settings
            .relay
            .inner_tls
            .as_ref()
            .context("online runtime requires device inner TLS")?;
        let directory = identity
            .key
            .parent()
            .context("device identity directory missing")?;
        ensure!(
            super::clean_absolute_directory(directory)
                && identity.key == directory.join("device.key")
                && identity.cert == directory.join("device.pem")
                && !directory.starts_with(bundle)
                && !bundle.starts_with(directory),
            "online runtime requires final identity files outside the public bundle"
        );
        ensure!(
            settings.relay.https_bridge == load_https_bridge(directory)?,
            "online runtime HTTPS bridge differs from private installed policy"
        );
        ensure!(
            settings.relay.web_response == crate::device_web_response::load(directory)?,
            "online runtime web-response differs from private installed policy"
        );
        aegis_core::wide_product::validate_inner_tls_device_settings(
            public.mode()?,
            public.udp,
            settings,
        )
        .map_err(anyhow::Error::msg)?;
        ensure!(
            settings.relay.server == public.relay_server
                && settings.relay.server_name == public.outer_server_name
                && settings.relay.endpoints == public.endpoints()
                && identity.server_name == public.inner_server_name,
            "online runtime traffic configuration differs from public profile"
        );
        ensure!(
            settings.relay.ech_config_list_base64 == public.ech_config_list
                && (public.ech_config_list.is_none() || settings.relay.ech_config_list.is_none()),
            "online runtime ECH configuration differs from public profile"
        );
        let outer_ca = settings
            .relay
            .ca_cert
            .as_deref()
            .context("outer trust missing")?;
        for (installed, member) in [
            (outer_ca, "outer-ca.pem"),
            (identity.server_ca.as_path(), "inner-ca.pem"),
            (directory.join("device-ca.pem").as_path(), "device-ca.pem"),
        ] {
            ensure!(
                read_public(installed)? == read_public(&bundle.join(member))?,
                "online runtime trust anchors differ from public profile"
            );
        }
        let online = Self::load(bundle, directory)?;
        ensure!(
            settings.relay.https_bridge == online.carrier.https_bridge,
            "online runtime HTTPS bridge changed during validation"
        );
        Ok((online, directory.to_owned()))
    }

    pub fn load(bundle: &Path, identity: &Path) -> Result<Self> {
        let profile = load(bundle)?;
        let metadata = profile
            .enrollment
            .context("online enrollment requires a v3 profile")?;
        let digest = profile_digest(bundle)?;
        let recorded = read_public(&identity.join("bundle-profile.sha256"))?;
        ensure!(
            recorded == digest.as_bytes(),
            "online profile differs from the prepared trust pin"
        );
        if profile.ech_config_list.is_some() {
            metadata.validate_ech_name()?;
        }
        let mut carrier = RelaySettings {
            server: metadata.authority_server,
            server_name: metadata.outer_server_name,
            ca_cert: Some(bundle.join("outer-ca.pem")),
            auth_token: String::new(),
            connect_timeout_ms: 5000,
            ..Default::default()
        };
        carrier.https_bridge = load_https_bridge(identity)?;
        if let Some(bridge) = &carrier.https_bridge {
            bridge
                .validate_authority(&carrier.server_name)
                .map_err(|_| anyhow::anyhow!("HTTPS bridge enrollment authority rejected"))?;
        }
        if let Some(encoded) = profile.ech_config_list {
            carrier.ech_config_list_base64 = Some(encoded);
            carrier.tls_backend = aegis_core::RelayTlsBackend::Rustls;
            carrier.transport_priority = vec![aegis_core::TunnelTransportFamily::GrpcStream];
            carrier.udp_transport_priority = Some(Vec::new());
            aegis_core::Settings {
                relay: carrier.clone(),
                ..Default::default()
            }
            .validate_ech()
            .map_err(anyhow::Error::msg)?;
        }
        let tls = enrollment_tls::ClientSettings {
            server_name: metadata.inner_server_name,
            server_ca: bundle.join("inner-ca.pem"),
        };
        Ok(Self {
            digest,
            carrier,
            tls,
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn carrier(&self) -> &RelaySettings {
        &self.carrier
    }
    pub fn tls(&self) -> &enrollment_tls::ClientSettings {
        &self.tls
    }
}

/// The store receives only a validated intent and serializes its pin change.
/// No ordinary profile load/renew call may overwrite bundle-profile.sha256.
pub struct OnlineMigration {
    old_digest: String,
    new_digest: String,
}

impl OnlineMigration {
    pub fn validate(old_bundle: &Path, new_bundle: &Path) -> Result<Self> {
        let old = load(old_bundle)?;
        let new = load(new_bundle)?;
        ensure!(
            matches!(
                old.schema.as_str(),
                "aegis_device_bundle_v1" | "aegis_device_bundle_v2"
            ) && new.schema == "aegis_device_bundle_v3",
            "online migration requires a v1/v2 predecessor and v3 successor"
        );
        ensure!(
            old.mode()? == new.mode()?
                && old.udp == new.udp
                && old.relay_server == new.relay_server
                && old.outer_server_name == new.outer_server_name
                && old.inner_server_name == new.inner_server_name,
            "online migration cannot change the relay, identity or product policy"
        );
        for name in &super::MEMBERS[1..] {
            ensure!(
                read_public(&old_bundle.join(name))? == read_public(&new_bundle.join(name))?,
                "online migration cannot replace trust anchors"
            );
        }
        Ok(Self {
            old_digest: profile_digest(old_bundle)?,
            new_digest: profile_digest(new_bundle)?,
        })
    }
    pub fn old_digest(&self) -> &str {
        &self.old_digest
    }
    pub fn new_digest(&self) -> &str {
        &self.new_digest
    }
}
