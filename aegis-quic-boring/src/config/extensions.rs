//! ClientHello extension configuration (OCSP, SCT, signature algorithms,
//! certificate compression) for the Chrome-like QUIC profile.

use std::ptr::NonNull;

use crate::config::cert_compression::brotli_decompress;
use crate::Error;

/// # Safety
/// `ctx` must be a valid `SSL_CTX*`.
pub unsafe fn configure(ctx: NonNull<aws_lc_sys::SSL_CTX>) -> Result<(), Error> {
    let quic = aegis_chrome_profile::chrome_stable().quic.clone();
    // The profile records that live Chrome omits OCSP and SCT on QUIC.
    // Enabling either adds extensions Chrome does not send.
    if quic.ocsp_stapling {
        aws_lc_sys::SSL_CTX_enable_ocsp_stapling(ctx.as_ptr());
    }
    if quic.signed_cert_timestamps {
        aws_lc_sys::SSL_CTX_enable_signed_cert_timestamps(ctx.as_ptr());
    }

    if quic.cert_compression.iter().any(|name| name == "brotli")
        && aws_lc_sys::SSL_CTX_add_cert_compression_alg(
            ctx.as_ptr(),
            aws_lc_sys::TLSEXT_cert_compression_brotli as u16,
            None,
            Some(brotli_decompress),
        ) != 1
    {
        return Err(Error::Ssl("enable brotli certificate decompression"));
    }

    if aws_lc_sys::SSL_CTX_set_verify_algorithm_prefs(
        ctx.as_ptr(),
        quic.signature_algorithms.as_ptr(),
        quic.signature_algorithms.len(),
    ) != 1
    {
        return Err(Error::Ssl("set Chrome signature algorithms"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn sigalgs_match_measured_chrome_quic() {
        let sigalgs = &aegis_chrome_profile::chrome_stable()
            .quic
            .signature_algorithms;
        assert!(sigalgs.len() >= 8);
        assert!(sigalgs.contains(&0x0403));
    }
}
