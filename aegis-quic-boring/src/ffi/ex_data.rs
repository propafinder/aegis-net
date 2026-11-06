//! Attaching our [`SessionState`] to a BoringSSL `SSL` object.
//!
//! The `SSL_QUIC_METHOD` callbacks receive only the `SSL*`, so the state has to
//! travel with it. We register one process-wide ex_data index and store a raw
//! pointer to the state the `Session` owns.

use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::OnceLock;

use crate::session::state::SessionState;

static INDEX: OnceLock<c_int> = OnceLock::new();

/// The process-wide ex_data index used to attach [`SessionState`] to an `SSL`.
pub fn index() -> c_int {
    *INDEX.get_or_init(|| unsafe {
        aws_lc_sys::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None)
    })
}

/// Attach `state` to `ssl`.
///
/// # Safety
/// `ssl` must be a valid `SSL*`, and `state` must remain valid and not move for
/// as long as `ssl` may invoke the QUIC callbacks.
pub unsafe fn attach(ssl: *mut aws_lc_sys::SSL, state: *mut SessionState) -> bool {
    aws_lc_sys::SSL_set_ex_data(ssl, index(), state as *mut c_void) == 1
}

/// Recover the state attached to `ssl`.
///
/// # Safety
/// Must only be called from inside a BoringSSL callback on `ssl` (i.e. while
/// the owning `Session` is not itself borrowing the state), so that the
/// returned `&mut` is unique.
pub unsafe fn state<'a>(ssl: *mut aws_lc_sys::SSL) -> Option<&'a mut SessionState> {
    let raw = aws_lc_sys::SSL_get_ex_data(ssl, index()) as *mut SessionState;
    if raw.is_null() {
        None
    } else {
        Some(&mut *raw)
    }
}
