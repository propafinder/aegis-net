//! The `quinn_proto::crypto::Session` implementation.
//!
//! This is the state machine seam: quinn calls `read_handshake` /
//! `write_handshake`, we drive BoringSSL, and the QUIC callbacks fill
//! [`SessionState`], which we then translate into quinn `Keys`.

use std::any::Any;
use std::sync::Mutex;

use quinn_proto::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};

use crate::crypto::{keys, retry};
use crate::ffi::ssl::Ssl;
use crate::session::handshake_data::HandshakeData;
use crate::session::state::SessionState;

pub struct BoringSession {
    // All calls into the non-thread-safe C object, including getters and
    // exporters required by shared Session methods, hold this lock.
    ssl: Mutex<Ssl>,
    /// Boxed so its address is stable: BoringSSL holds a raw pointer to it.
    state: Box<SessionState>,
    server_name: Option<String>,
    side: Side,
    /// Set once `handshake_data` has been reported to quinn.
    handshake_data_reported: bool,
    ech_required: bool,
}

impl BoringSession {
    /// Build a client session. `state` is boxed first so that the pointer
    /// handed to BoringSSL stays valid for the session's lifetime.
    pub(crate) fn new_client(
        ctx: &crate::config::ctx::SslCtx,
        server_name: &str,
        alpn: &[Vec<u8>],
        params: &TransportParameters,
        send_sni: bool,
        ech_config_list: Option<&[u8]>,
    ) -> Result<Self, crate::Error> {
        let mut state = Box::new(SessionState::new());
        let mut ssl =
            unsafe { Ssl::new_client(ctx, state.as_mut() as *mut SessionState, ech_config_list)? };

        ssl.set_server_name(server_name, send_sni)?;
        // Chrome negotiates ALPS for HTTP/3.
        if aegis_chrome_profile::chrome_stable()
            .quic
            .alps_new_codepoint
        {
            if let Some(h3) = alpn.iter().find(|p| p.as_slice() == b"h3") {
                ssl.enable_alps(h3)?;
            }
        }

        let mut encoded = Vec::new();
        params.write(&mut encoded);
        ssl.set_transport_params(&encoded)?;

        Ok(BoringSession {
            ssl: Mutex::new(ssl),
            state,
            server_name: Some(server_name.to_string()),
            side: Side::Client,
            handshake_data_reported: false,
            ech_required: ech_config_list.is_some(),
        })
    }

    fn tls_error(what: &'static str) -> TransportError {
        TransportError {
            code: TransportErrorCode::crypto(0x50), // internal_error alert
            frame: None,
            reason: what.to_string(),
        }
    }

    /// Map an alert recorded by the `send_alert` callback onto a quinn error.
    fn alert_error(&self) -> Option<TransportError> {
        self.state.alert.map(|alert| TransportError {
            code: TransportErrorCode::crypto(alert),
            frame: None,
            reason: format!("TLS alert {alert}"),
        })
    }
}

impl Session for BoringSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        keys::initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.handshake_data_reported {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.ssl.lock().expect("SSL lock poisoned").alpn_protocol(),
            server_name: self.server_name.clone(),
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // Chain verification is done by BoringSSL against the configured trust
        // anchors; exporting the parsed chain to the application is not needed
        // by AEGIS and is deliberately not implemented rather than faked.
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.state.early_keys()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        // 0-RTT is not offered by this profile.
        None
    }

    fn is_handshaking(&self) -> bool {
        !self
            .ssl
            .lock()
            .expect("SSL lock poisoned")
            .is_handshake_done()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        let mut ssl = self.ssl.lock().expect("SSL lock poisoned");
        let level = ssl.read_level();
        ssl.provide_data(level, buf)
            .map_err(|_| Self::tls_error("SSL_provide_quic_data"))?;

        let done = if ssl.is_handshake_done() {
            ssl.process_post_handshake()
                .map_err(|_| Self::tls_error("post-handshake"))?;
            true
        } else {
            ssl.do_handshake().map_err(|_| {
                self.alert_error()
                    .unwrap_or_else(|| Self::tls_error("handshake failed"))
            })?
        };
        if done && self.ech_required && unsafe { aws_lc_sys::SSL_ech_accepted(ssl.as_ptr()) } != 1 {
            return Err(Self::tls_error("required ECH was not accepted"));
        }

        // quinn wants `true` exactly once, when handshake data first becomes
        // available — which for TLS 1.3 is when ALPN/SNI are settled, i.e. as
        // soon as the peer's first flight has been processed.
        let has_alpn = ssl.alpn_protocol().is_some();
        drop(ssl);
        if !self.handshake_data_reported && (done || has_alpn) {
            self.handshake_data_reported = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self
            .ssl
            .lock()
            .expect("SSL lock poisoned")
            .peer_transport_params()
        {
            None => Ok(None),
            Some(raw) => {
                let mut cursor = std::io::Cursor::new(raw);
                TransportParameters::read(self.side, &mut cursor)
                    .map(Some)
                    .map_err(|e| TransportError {
                        code: TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                        frame: None,
                        reason: e.to_string(),
                    })
            }
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        // Kick the handshake so BoringSSL produces the first flight (the
        // ClientHello) without waiting for peer data.
        if self.is_handshaking() {
            let _ = self.ssl.lock().expect("SSL lock poisoned").do_handshake();
        }
        self.state.take_handshake_data(buf);
        self.state.take_next_keys()
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.state.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        retry::is_valid(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.ssl
            .lock()
            .expect("SSL lock poisoned")
            .export_keying_material(output, label, context)
            .map_err(|_| ExportKeyingMaterialError)
    }
}
