//! QUIC crypto selection for the MASQUE transport.
//!
//! MASQUE is the one relay transport that speaks QUIC, and until now it always
//! used rustls — so while the TCP transports presented a Chrome ClientHello,
//! MASQUE presented a rustls one. This module is the single seam where that is
//! decided, so the three MASQUE entry points cannot drift apart.
//!
//! With the `chrome-like-quic` feature and the Chrome-like backend selected,
//! the handshake goes through `aegis-quic-boring`, whose ClientHello is
//! byte-equal to live Chrome's (see that crate's `tests/chrome_live_ja4.rs`).
//! Otherwise it falls back to rustls. An explicit configured-only MASQUE
//! trust policy retains the same restricted anchors across this fallback.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use aegis_core::{MasqueTrustMode, RelaySettings, RelayTlsBackend};
use rustls::pki_types::{pem::PemObject, CertificateDer};

use super::{load_roots, RelayTransportAuthority};

#[cfg(all(test, feature = "chrome-like-tls"))]
mod ech_tests;

#[cfg(test)]
mod configured_anchor_tests;

/// Build the QUIC client config for a MASQUE session.
pub(crate) fn masque_quic_client_config(
    settings: &RelaySettings,
    authority: &RelayTransportAuthority,
) -> anyhow::Result<quinn::ClientConfig> {
    anyhow::ensure!(
        settings.inner_tls.is_none(),
        "MASQUE is unavailable with inner TLS v1"
    );
    let ech_required =
        settings.ech_config_list.is_some() || settings.ech_config_list_base64.is_some();
    if ech_required {
        anyhow::ensure!(
            authority.send_sni && authority.authority_host == settings.server_name,
            "required QUIC ECH requires the pinned relay DNS server_name"
        );
    }
    // An explicit configured-only request is validated before backend selection.
    // Keep its fresh roots for Rustls fallback; Chrome reads only the same CA
    // path through its existing CaFile mode, never the platform union.
    let configured_roots = if settings.masque_trust_mode == MasqueTrustMode::ConfiguredCaOnly {
        Some(masque_roots_with(settings, load_roots)?)
    } else {
        None
    };
    let _ca = settings
        .masque_ca_cert
        .as_deref()
        .or(settings.ca_cert.as_deref());

    #[cfg(feature = "chrome-like-quic")]
    if settings.tls_backend == RelayTlsBackend::ChromeLikeExperimental {
        match chrome_quic_client_config(
            settings,
            _ca,
            settings.masque_trust_mode,
            authority.send_sni,
        ) {
            Ok(config) => return Ok(config),
            // Required ECH keeps the configured backend: the ECH list stays
            // on the Chrome-like stack or the session fails. No rustls
            // fallback with a different ClientHello.
            Err(err) if ech_required => {
                return Err(err.context("required QUIC ECH has no chrome-like QUIC config"));
            }
            Err(err) => {
                // Preserve the existing backend fallback. Configured-only
                // roots were validated above and remain exclusive below.
                tracing::warn!(
                    error = %err,
                    "chrome-like QUIC crypto unavailable; falling back to rustls for MASQUE"
                );
            }
        }
    }

    #[cfg(not(feature = "chrome-like-quic"))]
    if settings.tls_backend == RelayTlsBackend::ChromeLikeExperimental {
        anyhow::ensure!(
            !ech_required,
            "required QUIC ECH with tls_backend=chrome_like_experimental needs the \
             chrome-like-quic feature; set tls_backend=rustls to use rustls"
        );
        // Same shape as the TCP backend's feature-less fallback: a build
        // without the feature still connects, just with a rustls fingerprint.
        tracing::warn!(
            "masque chrome-like QUIC not compiled in (needs the chrome-like-quic feature); \
             falling back to rustls for this MASQUE session"
        );
    }

    match configured_roots {
        Some(roots) => rustls_quic_client_config_from_roots(settings, authority, roots),
        None => rustls_quic_client_config(settings, authority),
    }
}

/// Enrolled H3 uses only the issued outer CA and a fresh Rustls QUIC context.
/// It never falls through to the legacy MASQUE token or platform trust union.
pub(crate) fn enrolled_h3_client_config(
    settings: &RelaySettings,
    authority: &RelayTransportAuthority,
) -> anyhow::Result<quinn::ClientConfig> {
    anyhow::ensure!(
        settings.inner_tls.is_some()
            && settings.tls_backend == RelayTlsBackend::Rustls
            && settings.masque_server.is_none()
            && settings.masque_server_name.is_none()
            && settings.ech_config_list.is_none()
            && settings.ech_config_list_base64.is_none(),
        "enrolled H3 requires pinned direct QUIC and inner device TLS"
    );
    let roots = configured_masque_roots(settings.ca_cert.as_deref())?;
    let identity = settings.inner_tls.as_ref().expect("checked inner TLS");
    let (certs, key) = aegis_core::secure_channel::enrolled_quic_client_identity(identity)?;
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)?;
    crypto.alpn_protocols = aegis_chrome_profile::chrome_stable().quic.alpn_wire();
    crypto.enable_sni = authority.send_sni;
    crypto.resumption = rustls::client::Resumption::disabled();
    crypto.enable_early_data = false;
    crypto.key_log = Arc::new(rustls::NoKeyLog);
    quinn_config(crypto)
}

fn rustls_quic_client_config(
    settings: &RelaySettings,
    authority: &RelayTransportAuthority,
) -> anyhow::Result<quinn::ClientConfig> {
    let crypto = rustls_masque_tls_config(settings, authority)?;
    // Rustls rejects a real ECH offer at Finished if acceptance is absent.
    // Quinn's awaited connection therefore fails before any H3 request. None
    // of the three MASQUE callers uses 0-RTT or retries without this config.
    quinn_config(crypto)
}

fn rustls_quic_client_config_from_roots(
    settings: &RelaySettings,
    authority: &RelayTransportAuthority,
    roots: rustls::RootCertStore,
) -> anyhow::Result<quinn::ClientConfig> {
    quinn_config(rustls_masque_tls_config_from_roots(
        settings, authority, roots,
    )?)
}

fn quinn_config(crypto: rustls::ClientConfig) -> anyhow::Result<quinn::ClientConfig> {
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    // A new ClientConfig retains a new token store; no per-association cache.
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

fn rustls_masque_tls_config(
    settings: &RelaySettings,
    authority: &RelayTransportAuthority,
) -> anyhow::Result<rustls::ClientConfig> {
    let roots = masque_roots_with(settings, load_roots)?;
    rustls_masque_tls_config_from_roots(settings, authority, roots)
}

fn rustls_masque_tls_config_from_roots(
    settings: &RelaySettings,
    authority: &RelayTransportAuthority,
    roots: rustls::RootCertStore,
) -> anyhow::Result<rustls::ClientConfig> {
    super::tls_backend::rustls_client_config_for_settings_with_roots(
        settings,
        &aegis_chrome_profile::chrome_stable().quic.alpn_wire(),
        authority.send_sni,
        true,
        roots,
    )
}

// The callback is the unchanged platform-plus-CA loader in production. Tests
// can supply an owned synthetic platform anchor without modifying OS trust.
fn masque_roots_with(
    settings: &RelaySettings,
    legacy_loader: impl FnOnce(Option<&Path>) -> anyhow::Result<rustls::RootCertStore>,
) -> anyhow::Result<rustls::RootCertStore> {
    let ca = settings
        .masque_ca_cert
        .as_deref()
        .or(settings.ca_cert.as_deref());
    match settings.masque_trust_mode {
        MasqueTrustMode::SystemAndConfiguredCa => legacy_loader(ca),
        MasqueTrustMode::ConfiguredCaOnly => configured_masque_roots(ca),
    }
}

const CONFIGURED_CA_BYTE_CAP: u64 = 4 * 1024 * 1024;

fn configured_masque_roots(ca: Option<&Path>) -> anyhow::Result<rustls::RootCertStore> {
    let refuse = || anyhow::anyhow!("configured_ca_only MASQUE CA file refused");
    let path = ca
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(refuse)?;
    let file = std::fs::File::open(path).map_err(|_| refuse())?;
    let metadata = file.metadata().map_err(|_| refuse())?;
    anyhow::ensure!(
        metadata.is_file() && (1..=CONFIGURED_CA_BYTE_CAP).contains(&metadata.len()),
        "configured_ca_only MASQUE CA file refused"
    );
    let mut bytes = Vec::new();
    file.take(CONFIGURED_CA_BYTE_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= CONFIGURED_CA_BYTE_CAP,
        "configured_ca_only MASQUE CA file refused"
    );
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&bytes) {
        roots
            .add(cert.map_err(|_| refuse())?)
            .map_err(|_| refuse())?;
    }
    anyhow::ensure!(
        !roots.is_empty(),
        "configured_ca_only MASQUE CA file refused"
    );
    Ok(roots)
}

#[cfg(feature = "chrome-like-quic")]
fn chrome_quic_client_config(
    settings: &RelaySettings,
    ca: Option<&std::path::Path>,
    trust_mode: MasqueTrustMode,
    send_sni: bool,
) -> anyhow::Result<quinn::ClientConfig> {
    use aegis_quic_boring::config::ctx::Trust;
    use aegis_quic_boring::session::client_config::ChromeQuicClientConfig;

    let trust = match (trust_mode, ca) {
        (MasqueTrustMode::ConfiguredCaOnly, Some(path)) => Trust::CaFile(path.to_path_buf()),
        (MasqueTrustMode::ConfiguredCaOnly, None) => {
            anyhow::bail!("configured_ca_only MASQUE CA file refused")
        }
        (MasqueTrustMode::SystemAndConfiguredCa, Some(path)) => {
            Trust::SystemAndCaFile(path.to_path_buf())
        }
        (MasqueTrustMode::SystemAndConfiguredCa, None) => Trust::System,
    };
    let ech = aegis_client::ech_policy::effective_ech_config_list(settings)?;
    let alpn = aegis_chrome_profile::chrome_stable().quic.alpn_wire();
    let config = ChromeQuicClientConfig::with_sni_and_ech(alpn, trust, send_sni, ech)
        .map_err(|e| anyhow::anyhow!("chrome-like QUIC client config: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The binary installs the process-wide rustls provider at startup; tests
    /// that exercise the rustls path have to do the same.
    fn install_rustls_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn settings() -> RelaySettings {
        RelaySettings {
            server_name: "relay.example".to_string(),
            ..RelaySettings::default()
        }
    }

    /// Whatever the build features, a config must always come back — the
    /// fingerprint choice must never be able to break connectivity.
    #[test]
    fn always_yields_a_config() {
        install_rustls_provider();
        let settings = settings();
        let authority = super::super::relay_transport_authority(&settings).expect("authority");
        assert!(masque_quic_client_config(&settings, &authority).is_ok());
    }

    #[test]
    fn rustls_backend_is_honoured() {
        install_rustls_provider();
        let mut settings = settings();
        settings.tls_backend = RelayTlsBackend::Rustls;
        let authority = super::super::relay_transport_authority(&settings).expect("authority");
        assert!(masque_quic_client_config(&settings, &authority).is_ok());
    }

    /// An IP authority must not advertise SNI on either path.
    #[test]
    fn ip_authority_suppresses_sni() {
        install_rustls_provider();
        let mut settings = settings();
        settings.server_name = "192.0.2.7".to_string();
        let authority = super::super::relay_transport_authority(&settings).expect("authority");
        assert!(!authority.send_sni);
        assert!(masque_quic_client_config(&settings, &authority).is_ok());
    }

    #[test]
    fn required_ech_masque_never_falls_back_to_a_different_backend_or_name() {
        install_rustls_provider();
        use base64::Engine;
        let mut settings = settings();
        settings.ech_config_list_base64 = Some(super::super::inline_ech_fixture());
        let authority = super::super::relay_transport_authority(&settings).unwrap();
        settings.tls_backend = RelayTlsBackend::ChromeLikeExperimental;
        // Chrome-like QUIC carries the pinned ECH list itself when compiled
        // in; without the feature, required ECH refuses instead of quietly
        // switching to the rustls ClientHello.
        assert_eq!(
            masque_quic_client_config(&settings, &authority).is_ok(),
            cfg!(feature = "chrome-like-quic")
        );
        // A list only rustls can offer (DHKEM P-256) must not slide to rustls
        // under a chrome-like configuration either.
        let p256 = {
            let mut contents = vec![2, 0x00, 0x10, 0, 65];
            contents.extend([4; 65]);
            contents.extend([0, 4, 0, 1, 0, 1, 0, 13]);
            contents.extend(b"cover.example");
            contents.extend([0, 0]);
            let mut config = vec![0xfe, 0x0d];
            config.extend((contents.len() as u16).to_be_bytes());
            config.extend(contents);
            let mut list = (config.len() as u16).to_be_bytes().to_vec();
            list.extend(config);
            base64::engine::general_purpose::STANDARD.encode(list)
        };
        let pinned_x25519 = settings.ech_config_list_base64.replace(p256);
        assert!(masque_quic_client_config(&settings, &authority).is_err());
        settings.tls_backend = RelayTlsBackend::Rustls;
        assert!(masque_quic_client_config(&settings, &authority).is_ok());
        settings.ech_config_list_base64 = pinned_x25519;
        assert!(masque_quic_client_config(&settings, &authority).is_ok());
        let wrong_name =
            super::super::transport_authority_for_host("other.example", "test").unwrap();
        assert!(masque_quic_client_config(&settings, &wrong_name).is_err());
        let ip = super::super::transport_authority_for_host("192.0.2.1", "test").unwrap();
        assert!(masque_quic_client_config(&settings, &ip).is_err());
    }

    #[test]
    fn required_ech_masque_rejects_invalid_or_conflicting_pins_before_connect() {
        let mut settings = settings();
        settings.tls_backend = RelayTlsBackend::Rustls;
        let authority = super::super::relay_transport_authority(&settings).unwrap();
        settings.ech_config_list_base64 = Some("AQID".into());
        assert!(masque_quic_client_config(&settings, &authority).is_err());
        settings.ech_config_list_base64 = Some(super::super::inline_ech_fixture());
        settings.ech_config_list = Some("never-open-conflicting-config.bin".into());
        assert!(masque_quic_client_config(&settings, &authority).is_err());
    }
}
