//! Chrome 152 advertises an empty TrustAnchorIDList (draft codepoint 0xca34).
//! This is a certificate-selection hint, never an additional source of trust.
//! AWS-LC 0.44 lacks the native API, so use its custom-extension boundary.
use crate::Error;
use aws_lc_sys as ssl;
use std::{ffi::c_void, ptr::NonNull};

const TYPE: u32 = 0xca34;
static EMPTY_LIST: [u8; 2] = [0, 0];

/// # Safety
/// `ctx` must be a live, exclusively accessed context from this AWS-LC instance.
pub unsafe fn configure(ctx: NonNull<ssl::SSL_CTX>) -> Result<(), Error> {
    if ssl::SSL_CTX_add_client_custom_ext(
        ctx.as_ptr(),
        TYPE,
        Some(add),
        None,
        std::ptr::null_mut(),
        Some(parse),
        std::ptr::null_mut(),
    ) != 1
    {
        return Err(Error::Ssl("configure trust anchor hint"));
    }
    Ok(())
}
unsafe extern "C" fn add(
    _: *mut ssl::SSL,
    _: u32,
    out: *mut *const u8,
    len: *mut usize,
    _: *mut i32,
    _: *mut c_void,
) -> i32 {
    *out = EMPTY_LIST.as_ptr();
    *len = EMPTY_LIST.len();
    1
}
unsafe extern "C" fn parse(
    session: *mut ssl::SSL,
    _: u32,
    bytes: *const u8,
    length: usize,
    alert: *mut i32,
    _: *mut c_void,
) -> i32 {
    if ssl::SSL_version(session) < 0x0304 {
        *alert = 110; // unsupported_extension, as required for TLS 1.2
        return 0;
    }
    if bytes.is_null()
        || !(3..=u16::MAX as usize).contains(&length)
        || !valid_response(std::slice::from_raw_parts(bytes, length))
    {
        *alert = 50; // decode_error
        return 0;
    }
    // Do not install, persist or trust server-advertised anchor identifiers.
    // The normal configured Windows/extra-CA certificate verifier still runs.
    1
}
fn valid_response(bytes: &[u8]) -> bool {
    if bytes.len() < 3 || u16::from_be_bytes([bytes[0], bytes[1]]) as usize != bytes.len() - 2 {
        return false;
    }
    let mut rest = &bytes[2..];
    while let Some((&length, tail)) = rest.split_first() {
        if length == 0 || tail.len() < length as usize {
            return false;
        }
        rest = &tail[length as usize..];
    }
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anchor_response_is_bounded_and_structurally_validated() {
        assert!(valid_response(&[0, 2, 1, 17]));
        assert!(valid_response(&[0, 5, 1, 17, 2, 18, 19]));
        for malformed in [
            &[][..],
            &[0, 0],
            &[0, 1, 0],
            &[0, 2, 2, 1],
            &[0, 2, 1, 17, 18],
        ] {
            assert!(!valid_response(malformed));
        }
    }
}
