//! The `SSL_QUIC_METHOD` hooks (BoringSSL `ssl.h`).
//!
//! BoringSSL calls these synchronously from inside `SSL_do_handshake`; each one
//! recovers the [`SessionState`] from ex_data and records what happened. All
//! five return 1 on success and 0 to fail the handshake.

use std::os::raw::c_int;
use std::slice;

use crate::crypto::suite::Suite;
use crate::ffi::ex_data;
use crate::level::Level;

/// Resolve the negotiated suite from a `SSL_CIPHER*`.
unsafe fn suite_of(cipher: *const aws_lc_sys::SSL_CIPHER) -> Option<Suite> {
    if cipher.is_null() {
        return None;
    }
    Suite::from_protocol_id(aws_lc_sys::SSL_CIPHER_get_protocol_id(cipher))
}

unsafe extern "C" fn set_read_secret(
    ssl: *mut aws_lc_sys::SSL,
    level: aws_lc_sys::ssl_encryption_level_t,
    cipher: *const aws_lc_sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    match (
        ex_data::state(ssl),
        Level::from_native(level),
        suite_of(cipher),
    ) {
        (Some(state), Some(level), Some(suite)) => {
            state.set_read_secret(level, suite, slice::from_raw_parts(secret, secret_len));
            1
        }
        _ => 0,
    }
}

unsafe extern "C" fn set_write_secret(
    ssl: *mut aws_lc_sys::SSL,
    level: aws_lc_sys::ssl_encryption_level_t,
    cipher: *const aws_lc_sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    match (
        ex_data::state(ssl),
        Level::from_native(level),
        suite_of(cipher),
    ) {
        (Some(state), Some(level), Some(suite)) => {
            state.set_write_secret(level, suite, slice::from_raw_parts(secret, secret_len));
            1
        }
        _ => 0,
    }
}

unsafe extern "C" fn add_handshake_data(
    ssl: *mut aws_lc_sys::SSL,
    level: aws_lc_sys::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    match (ex_data::state(ssl), Level::from_native(level)) {
        (Some(state), Some(level)) => {
            state.add_handshake_data(level, slice::from_raw_parts(data, len));
            1
        }
        _ => 0,
    }
}

/// QUIC packetises on its own schedule, so there is nothing to flush here —
/// quinn pulls the buffered bytes out via `Session::write_handshake`.
unsafe extern "C" fn flush_flight(_ssl: *mut aws_lc_sys::SSL) -> c_int {
    1
}

unsafe extern "C" fn send_alert(
    ssl: *mut aws_lc_sys::SSL,
    _level: aws_lc_sys::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    match ex_data::state(ssl) {
        Some(state) => {
            state.set_alert(alert);
            1
        }
        None => 0,
    }
}

/// The hook table handed to `SSL_set_quic_method`. Must outlive every `SSL`
/// that references it — being `'static` satisfies that.
pub static QUIC_METHOD: aws_lc_sys::SSL_QUIC_METHOD = aws_lc_sys::SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};
