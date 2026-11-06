//! Safe-ish RAII wrapper around a single BoringSSL `SSL` object driven in QUIC
//! mode. Everything `unsafe` about the handshake is confined to this file.

use std::ffi::CString;
use std::net::IpAddr;
use std::os::raw::c_int;
use std::ptr::NonNull;

use crate::config::ctx::SslCtx;
use crate::level::Level;
use crate::session::state::SessionState;
use crate::Error;

/// `SSL_ERROR_WANT_READ` — the handshake is waiting for peer data, which for
/// QUIC means "nothing to do until more CRYPTO frames arrive".
const SSL_ERROR_WANT_READ: c_int = 2;

pub(crate) struct Ssl {
    ssl: NonNull<aws_lc_sys::SSL>,
}

// Moving an exclusively owned SSL object is permitted. Concurrent use is not:
// BoringSession serializes even read-only C calls through its Mutex<Ssl>.
unsafe impl Send for Ssl {}

impl Ssl {
    /// Create a client `SSL` from `ctx` and bind `state` to it for the QUIC
    /// callbacks.
    ///
    /// # Safety
    /// `state` must outlive the returned `Ssl` and must not move.
    pub unsafe fn new_client(
        ctx: &SslCtx,
        state: *mut SessionState,
        ech_config_list: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let ssl = NonNull::new(aws_lc_sys::SSL_new(ctx.as_ptr())).ok_or(Error::Ssl("SSL_new"))?;
        let this = Ssl { ssl };
        if !super::ex_data::attach(ssl.as_ptr(), state) {
            return Err(Error::Ssl("attach session state"));
        }
        aws_lc_sys::SSL_set_connect_state(ssl.as_ptr());
        let quic = aegis_chrome_profile::chrome_stable();
        if let Some(list) = ech_config_list {
            if list.is_empty()
                || aws_lc_sys::SSL_set1_ech_config_list(ssl.as_ptr(), list.as_ptr(), list.len())
                    != 1
            {
                return Err(Error::Ssl("set ECH config list"));
            }
        } else if quic.quic.ech_grease {
            aws_lc_sys::SSL_set_enable_ech_grease(ssl.as_ptr(), 1);
        }
        Ok(this)
    }

    pub fn as_ptr(&self) -> *mut aws_lc_sys::SSL {
        self.ssl.as_ptr()
    }

    /// Set SNI and enable hostname (or IP) verification.
    ///
    /// `send_sni` only controls whether the name is *advertised*; certificate
    /// verification against it always stays on. A literal IP never carries SNI
    /// (browsers omit it), regardless of the flag.
    pub fn set_server_name(&mut self, name: &str, send_sni: bool) -> Result<(), Error> {
        let c = CString::new(name).map_err(|_| Error::Ssl("server name contains NUL"))?;
        unsafe {
            if name.parse::<IpAddr>().is_ok() {
                // No SNI for a literal IP (as browsers do); verify the IP instead.
                let param = aws_lc_sys::SSL_get0_param(self.as_ptr());
                if param.is_null()
                    || aws_lc_sys::X509_VERIFY_PARAM_set1_ip_asc(param, c.as_ptr()) != 1
                {
                    return Err(Error::Ssl("set IP verification"));
                }
            } else {
                if send_sni && aws_lc_sys::SSL_set_tlsext_host_name(self.as_ptr(), c.as_ptr()) != 1
                {
                    return Err(Error::Ssl("set SNI"));
                }
                if aws_lc_sys::SSL_set1_host(self.as_ptr(), c.as_ptr()) != 1 {
                    return Err(Error::Ssl("set hostname verification"));
                }
            }
        }
        Ok(())
    }

    /// Advertise ALPS for the given ALPN protocol, as Chrome does for HTTP/3.
    pub fn enable_alps(&mut self, proto: &[u8]) -> Result<(), Error> {
        unsafe {
            aws_lc_sys::SSL_set_alps_use_new_codepoint(self.as_ptr(), 1);
            let settings: [u8; 0] = [];
            if aws_lc_sys::SSL_add_application_settings(
                self.as_ptr(),
                proto.as_ptr(),
                proto.len(),
                settings.as_ptr(),
                settings.len(),
            ) != 1
            {
                return Err(Error::Ssl("enable ALPS"));
            }
        }
        Ok(())
    }

    /// Set the `quic_transport_parameters` extension payload.
    pub fn set_transport_params(&mut self, params: &[u8]) -> Result<(), Error> {
        // BoringSSL rejects an empty parameter block outright
        // (QUIC_TRANSPORT_PARAMETERS_MISCONFIGURED); catch it here so the
        // failure names the cause instead of surfacing as an empty flight.
        if params.is_empty() {
            return Err(Error::Ssl("empty QUIC transport parameters"));
        }
        unsafe {
            if aws_lc_sys::SSL_set_quic_transport_params(
                self.as_ptr(),
                params.as_ptr(),
                params.len(),
            ) != 1
            {
                return Err(Error::Ssl("set QUIC transport parameters"));
            }
        }
        Ok(())
    }

    /// The peer's `quic_transport_parameters`, once received.
    pub fn peer_transport_params(&self) -> Option<Vec<u8>> {
        unsafe {
            let mut ptr = std::ptr::null();
            let mut len = 0usize;
            aws_lc_sys::SSL_get_peer_quic_transport_params(self.as_ptr(), &mut ptr, &mut len);
            if ptr.is_null() || len == 0 {
                None
            } else {
                // Never let a borrow of C-owned memory outlive the SSL lock.
                Some(std::slice::from_raw_parts(ptr, len).to_vec())
            }
        }
    }

    /// The encryption level BoringSSL currently expects to read at.
    pub fn read_level(&self) -> Level {
        let raw = unsafe { aws_lc_sys::SSL_quic_read_level(self.as_ptr()) };
        Level::from_native(raw).unwrap_or(Level::Initial)
    }

    /// Feed received CRYPTO-frame bytes at `level`.
    pub fn provide_data(&mut self, level: Level, data: &[u8]) -> Result<(), Error> {
        unsafe {
            if aws_lc_sys::SSL_provide_quic_data(
                self.as_ptr(),
                level.as_native(),
                data.as_ptr(),
                data.len(),
            ) != 1
            {
                return Err(Error::Ssl("SSL_provide_quic_data"));
            }
        }
        Ok(())
    }

    /// Drive the handshake. Returns `Ok(true)` once it has completed,
    /// `Ok(false)` while more peer data is needed.
    pub fn do_handshake(&mut self) -> Result<bool, Error> {
        let rc = unsafe { aws_lc_sys::SSL_do_handshake(self.as_ptr()) };
        if rc == 1 {
            return Ok(true);
        }
        match unsafe { aws_lc_sys::SSL_get_error(self.as_ptr(), rc) } {
            SSL_ERROR_WANT_READ => Ok(false),
            _ => Err(Error::Ssl("SSL_do_handshake")),
        }
    }

    /// Process post-handshake messages (e.g. NewSessionTicket).
    pub fn process_post_handshake(&mut self) -> Result<(), Error> {
        unsafe {
            if aws_lc_sys::SSL_process_quic_post_handshake(self.as_ptr()) != 1 {
                return Err(Error::Ssl("SSL_process_quic_post_handshake"));
            }
        }
        Ok(())
    }

    pub fn is_handshake_done(&self) -> bool {
        unsafe { aws_lc_sys::SSL_in_init(self.as_ptr()) == 0 }
    }

    /// Negotiated ALPN protocol, if any.
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        unsafe {
            let mut ptr = std::ptr::null();
            let mut len = 0u32;
            aws_lc_sys::SSL_get0_alpn_selected(self.as_ptr(), &mut ptr, &mut len);
            if ptr.is_null() || len == 0 {
                None
            } else {
                Some(std::slice::from_raw_parts(ptr, len as usize).to_vec())
            }
        }
    }

    /// TLS exporter (RFC 8446 §7.5), used by quinn for keying material export.
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            let rc = aws_lc_sys::SSL_export_keying_material(
                self.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                label.as_ptr() as *const _,
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            );
            if rc != 1 {
                return Err(Error::Crypto("SSL_export_keying_material"));
            }
        }
        Ok(())
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { aws_lc_sys::SSL_free(self.ssl.as_ptr()) }
    }
}
