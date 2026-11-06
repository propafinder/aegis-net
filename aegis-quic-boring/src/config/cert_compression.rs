//! Brotli certificate decompression (RFC 8879), which Chrome advertises.
//!
//! Advertising `compress_certificate` without being able to decompress would
//! break real connections, so the decompressor is wired up for real — bounded
//! by [`MAX_DECOMPRESSED_CERT_CHAIN`] to keep a hostile server from forcing an
//! unbounded allocation.

use std::io::Read;
use std::os::raw::c_int;

/// Upper bound on a decompressed certificate chain (same bound as the TCP
/// backend).
pub const MAX_DECOMPRESSED_CERT_CHAIN: usize = 16 * 1024 * 1024;

/// BoringSSL certificate-decompression callback.
///
/// # Safety
/// Called by BoringSSL with a valid `out` slot and `input`/`input_len` pair.
pub unsafe extern "C" fn brotli_decompress(
    _ssl: *mut aws_lc_sys::SSL,
    out: *mut *mut aws_lc_sys::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    if out.is_null()
        || input.is_null()
        || uncompressed_len == 0
        || uncompressed_len > MAX_DECOMPRESSED_CERT_CHAIN
    {
        return 0;
    }

    let compressed = std::slice::from_raw_parts(input, input_len);
    let mut decoder = brotli::Decompressor::new(std::io::Cursor::new(compressed), 4096)
        .take((uncompressed_len as u64).saturating_add(1));
    let mut decompressed = Vec::with_capacity(uncompressed_len.min(64 * 1024));
    if decoder.read_to_end(&mut decompressed).is_err() || decompressed.len() != uncompressed_len {
        return 0;
    }

    let buffer = aws_lc_sys::CRYPTO_BUFFER_new(
        decompressed.as_ptr(),
        decompressed.len(),
        std::ptr::null_mut(),
    );
    if buffer.is_null() {
        return 0;
    }

    *out = buffer;
    1
}
