//! TLS 1.3 `HKDF-Expand-Label` (RFC 8446 §7.1), the primitive QUIC key
//! derivation is built on (RFC 9001 §5).
//!
//! ```text
//! HKDF-Expand-Label(Secret, Label, Context, Length) =
//!     HKDF-Expand(Secret, HkdfLabel, Length)
//! struct {
//!     uint16 length = Length;
//!     opaque label<7..255> = "tls13 " + Label;
//!     opaque context<0..255> = Context;
//! } HkdfLabel;
//! ```

use ring::hkdf::{KeyType, Prk};

/// A one-off HKDF output-length wrapper so `ring`'s typed `expand` can produce
/// an arbitrary number of bytes.
struct Len(usize);
impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Build the `HkdfLabel` info bytes for `HKDF-Expand-Label`.
fn hkdf_label(length: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    // "tls13 " prefix (RFC 8446) — QUIC uses the same TLS 1.3 label space.
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

/// `HKDF-Expand-Label(prk, label, context, out.len())`, filling `out`.
pub fn expand_label(prk: &Prk, label: &[u8], context: &[u8], out: &mut [u8]) {
    let info = hkdf_label(out.len() as u16, label, context);
    let info_chunks: [&[u8]; 1] = [&info];
    let okm = prk
        .expand(&info_chunks, Len(out.len()))
        .expect("hkdf expand: output length within HKDF bound");
    okm.fill(out).expect("hkdf fill: length matches");
}

/// Convenience: expand into a fixed-size array.
pub fn expand_label_n<const N: usize>(prk: &Prk, label: &[u8], context: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    expand_label(prk, label, context, &mut out);
    out
}
