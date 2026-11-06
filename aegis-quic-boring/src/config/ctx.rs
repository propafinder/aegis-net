//! The Chrome-like QUIC `SSL_CTX`: an owned, reusable handshake template.
//!
//! Everything fingerprint-visible is set here — GREASE, extension permutation,
//! TLS 1.3-only version range, cipher suites, groups, sigalgs, certificate
//! compression — plus the QUIC hook table. One `SslCtx` is built per client
//! config and shared by every connection it starts.

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::ptr;
use std::ptr::NonNull;

use crate::config::{ciphers, extensions, groups};
use crate::ffi::quic_method::QUIC_METHOD;
use crate::Error;

/// Owned `SSL_CTX` configured for Chrome-like QUIC.
pub struct SslCtx {
    ctx: NonNull<aws_lc_sys::SSL_CTX>,
}

// The SSL_CTX is only mutated during construction; afterwards BoringSSL's own
// locking makes concurrent `SSL_new` safe.
unsafe impl Send for SslCtx {}
unsafe impl Sync for SslCtx {}

/// How the peer certificate chain is verified.
pub enum Trust {
    /// Use the system trust store.
    System,
    /// Use only a specific CA bundle (the AEGIS relay CA).
    CaFile(std::path::PathBuf),
    /// System trust store plus an extra CA bundle — what the relay client
    /// wants when it pins its own CA but still talks to public hosts.
    SystemAndCaFile(std::path::PathBuf),
}

impl SslCtx {
    /// Build the Chrome-like QUIC context.
    pub fn new_chrome(alpn: &[&[u8]], trust: &Trust) -> Result<Self, Error> {
        aws_lc_sys::init();
        unsafe {
            let ctx = NonNull::new(aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_method()))
                .ok_or(Error::Ssl("SSL_CTX_new"))?;
            let this = SslCtx { ctx };

            // QUIC is TLS 1.3 only (RFC 9001 §4.2).
            let v13 = aws_lc_sys::TLS1_3_VERSION as u16;
            if aws_lc_sys::SSL_CTX_set_min_proto_version(ctx.as_ptr(), v13) != 1
                || aws_lc_sys::SSL_CTX_set_max_proto_version(ctx.as_ptr(), v13) != 1
            {
                return Err(Error::Ssl("pin TLS 1.3 for QUIC"));
            }

            // Chrome-visible shape.
            //
            // GREASE is deliberately OFF here. Chrome GREASEs its *TCP*
            // ClientHello, but two independent captures of live Chrome 150 on
            // QUIC (IP origin and hostname origin, see tests/chrome_live_ja4.rs)
            // show no GREASE cipher, extension, or group. Enabling it would add
            // values Chrome never sends — invisible to JA4, obvious to a
            // byte-level classifier.
            let quic = aegis_chrome_profile::chrome_stable();
            aws_lc_sys::SSL_CTX_set_grease_enabled(
                ctx.as_ptr(),
                if quic.quic.grease { 1 } else { 0 },
            );
            aws_lc_sys::SSL_CTX_set_permute_extensions(
                ctx.as_ptr(),
                if quic.quic.permute_extensions { 1 } else { 0 },
            );
            ciphers::configure(ctx)?;
            groups::configure(ctx)?;
            extensions::configure(ctx)?;
            // Omit TrustAnchorID on every platform until a native permuted
            // implementation is available; the custom-extension API appends it
            // after the built-in extension permutation in locked AWS-LC 0.44.

            aws_lc_sys::SSL_CTX_set_verify(ctx.as_ptr(), aws_lc_sys::SSL_VERIFY_PEER, None);
            configure_trust(ctx, trust)?;

            if !alpn.is_empty() {
                let wire = alpn_wire(alpn)?;
                // Returns 0 on success, unlike most of the API.
                if aws_lc_sys::SSL_CTX_set_alpn_protos(ctx.as_ptr(), wire.as_ptr(), wire.len()) != 0
                {
                    return Err(Error::Ssl("set ALPN"));
                }
            }

            if aws_lc_sys::SSL_CTX_set_quic_method(ctx.as_ptr(), &QUIC_METHOD) != 1 {
                return Err(Error::Ssl("SSL_CTX_set_quic_method"));
            }

            Ok(this)
        }
    }

    pub fn as_ptr(&self) -> *mut aws_lc_sys::SSL_CTX {
        self.ctx.as_ptr()
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe { aws_lc_sys::SSL_CTX_free(self.ctx.as_ptr()) }
    }
}

unsafe fn configure_trust(ctx: NonNull<aws_lc_sys::SSL_CTX>, trust: &Trust) -> Result<(), Error> {
    #[cfg(windows)]
    {
        let (ca, system) = match trust {
            Trust::System => (None, true),
            Trust::CaFile(path) => (Some(path.as_path()), false),
            Trust::SystemAndCaFile(path) => (Some(path.as_path()), true),
        };
        super::windows_trust::load(ctx, ca, system)
    }
    #[cfg(unix)]
    {
        match trust {
            Trust::System => {
                if aws_lc_sys::SSL_CTX_set_default_verify_paths(ctx.as_ptr()) != 1 {
                    return Err(Error::Ssl("load system trust store"));
                }
            }
            Trust::CaFile(path) => {
                let c = cstring_path(path)?;
                if aws_lc_sys::SSL_CTX_load_verify_locations(ctx.as_ptr(), c.as_ptr(), ptr::null())
                    != 1
                {
                    return Err(Error::Ssl("load CA bundle"));
                }
            }
            Trust::SystemAndCaFile(path) => {
                if aws_lc_sys::SSL_CTX_set_default_verify_paths(ctx.as_ptr()) != 1 {
                    return Err(Error::Ssl("load system trust store"));
                }
                let c = cstring_path(path)?;
                if aws_lc_sys::SSL_CTX_load_verify_locations(ctx.as_ptr(), c.as_ptr(), ptr::null())
                    != 1
                {
                    return Err(Error::Ssl("load CA bundle"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn cstring_path(path: &Path) -> Result<CString, Error> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Ssl("CA path contains NUL"))
}

/// Encode ALPN protocols in TLS wire form (length-prefixed).
pub fn alpn_wire(protocols: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut wire = Vec::new();
    for proto in protocols {
        if proto.is_empty() || proto.len() > u8::MAX as usize {
            return Err(Error::Ssl("invalid ALPN protocol length"));
        }
        wire.push(proto.len() as u8);
        wire.extend_from_slice(proto);
    }
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_wire_is_length_prefixed() {
        assert_eq!(alpn_wire(&[b"h3"]).unwrap(), vec![2, b'h', b'3']);
        assert_eq!(
            alpn_wire(&[b"h3", b"h3-29"]).unwrap(),
            vec![2, b'h', b'3', 5, b'h', b'3', b'-', b'2', b'9']
        );
    }

    #[test]
    fn alpn_wire_rejects_empty_protocol() {
        assert!(alpn_wire(&[b""]).is_err());
    }

    #[test]
    fn chrome_ctx_builds() {
        let ctx = SslCtx::new_chrome(&[b"h3"], &Trust::System);
        assert!(ctx.is_ok(), "{:?}", ctx.err());
    }
}
