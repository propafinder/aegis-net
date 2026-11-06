//! Cipher-suite configuration for the Chrome-like QUIC ClientHello.
//!
//! QUIC is TLS 1.3 only (RFC 9001 §4.2), so unlike the TCP profile there is no
//! TLS 1.2 cipher list — only the three TLS 1.3 suites, in Chrome's order.

use std::ffi::CString;
use std::ptr::NonNull;

use crate::Error;

/// # Safety
/// `ctx` must be a valid `SSL_CTX*`.
pub unsafe fn configure(ctx: NonNull<aws_lc_sys::SSL_CTX>) -> Result<(), Error> {
    let suites = CString::new(
        aegis_chrome_profile::chrome_stable()
            .quic
            .tls13_cipher_string(),
    )
    .expect("TLS 1.3 cipher list has no NUL");
    if aws_lc_sys::SSL_CTX_set_ciphersuites(ctx.as_ptr(), suites.as_ptr()) != 1 {
        return Err(Error::Ssl("set Chrome TLS 1.3 cipher suites"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn suite_order_matches_the_profile() {
        let order = &aegis_chrome_profile::chrome_stable().quic.tls13_ciphers;
        assert_eq!(
            order.as_slice(),
            [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256"
            ]
        );
    }
}
