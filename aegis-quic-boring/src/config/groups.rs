//! Supported-groups (key share) configuration for the Chrome-like QUIC
//! ClientHello.
//!
//! Kept identical to the measured Chrome-stable TCP profile
//! (`aegis-client/src/relay/tls_backend/aws_lc.rs`) so both transports present
//! the same group list — a mismatch between our TCP and QUIC handshakes would
//! itself be a fingerprint.

use std::ffi::CString;
use std::ptr::NonNull;

use crate::Error;

/// # Safety
/// `ctx` must be a valid `SSL_CTX*`.
pub unsafe fn configure(ctx: NonNull<aws_lc_sys::SSL_CTX>) -> Result<(), Error> {
    let groups = CString::new(aegis_chrome_profile::chrome_stable().quic.groups_string())
        .expect("group list has no NUL");
    if aws_lc_sys::SSL_CTX_set1_groups_list(ctx.as_ptr(), groups.as_ptr()) != 1 {
        return Err(Error::Ssl("set Chrome supported groups"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn post_quantum_group_is_first() {
        assert_eq!(
            aegis_chrome_profile::chrome_stable()
                .quic
                .groups
                .first()
                .map(String::as_str),
            Some("X25519MLKEM768")
        );
    }

    #[test]
    fn quic_groups_follow_the_profile() {
        let groups = &aegis_chrome_profile::chrome_stable().quic.groups;
        assert!(groups
            .first()
            .is_some_and(|group| group == "X25519MLKEM768"));
        assert!(groups.len() >= 3);
    }
}
