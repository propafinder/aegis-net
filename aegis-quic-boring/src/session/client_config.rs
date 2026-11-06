//! `quinn_proto::crypto::ClientConfig` — the handle handed to quinn.
//!
//! One config owns the Chrome-like `SSL_CTX` and spawns a [`BoringSession`] per
//! connection.

use std::sync::Arc;

use quinn_proto::crypto::{ClientConfig, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::ConnectError;

use crate::config::ctx::{SslCtx, Trust};
use crate::session::tls_session::BoringSession;
use crate::Error;

/// Chrome-fingerprint QUIC client config.
pub struct ChromeQuicClientConfig {
    ctx: SslCtx,
    alpn: Vec<Vec<u8>>,
    send_sni: bool,
    ech_config_list: Option<Vec<u8>>,
}

impl ChromeQuicClientConfig {
    /// Build a config with the given ALPN list (typically `["h3"]`) and trust
    /// anchors.
    pub fn new(alpn: Vec<Vec<u8>>, trust: Trust) -> Result<Self, Error> {
        Self::with_sni(alpn, trust, true)
    }

    /// As [`Self::new`], but able to suppress the SNI extension while keeping
    /// certificate verification against the same name.
    pub fn with_sni(alpn: Vec<Vec<u8>>, trust: Trust, send_sni: bool) -> Result<Self, Error> {
        Self::with_sni_and_ech(alpn, trust, send_sni, None)
    }

    /// As [`Self::with_sni`], offering a real ECHConfigList on the same
    /// Chrome-like QUIC ClientHello. `None` keeps ECH GREASE when the profile
    /// asks for it.
    pub fn with_sni_and_ech(
        alpn: Vec<Vec<u8>>,
        trust: Trust,
        send_sni: bool,
        ech_config_list: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let refs: Vec<&[u8]> = alpn.iter().map(|p| p.as_slice()).collect();
        let ctx = SslCtx::new_chrome(&refs, &trust)?;
        Ok(ChromeQuicClientConfig {
            ctx,
            alpn,
            send_sni,
            ech_config_list,
        })
    }

    /// HTTP/3 over the system trust store — the common case.
    pub fn h3_system_roots() -> Result<Self, Error> {
        Self::new(vec![b"h3".to_vec()], Trust::System)
    }

    /// HTTP/3 pinned to a specific CA bundle (the AEGIS relay CA).
    pub fn h3_with_ca(ca: impl Into<std::path::PathBuf>) -> Result<Self, Error> {
        Self::new(vec![b"h3".to_vec()], Trust::CaFile(ca.into()))
    }
}

impl ClientConfig for ChromeQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        BoringSession::new_client(
            &self.ctx,
            server_name,
            &self.alpn,
            params,
            self.send_sni,
            self.ech_config_list.as_deref(),
        )
        .map(|s| Box::new(s) as Box<dyn Session>)
        .map_err(|_| ConnectError::InvalidServerName(server_name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_h3_config() {
        assert!(ChromeQuicClientConfig::h3_system_roots().is_ok());
    }
}
