//! GREASE, obfuscation SNI (регистр), подмена SNI произвольной длины, опциональное opaque-расширение (Auth / REALITY).

use crate::error::{AegisError, Result};
use crate::protocols::tls::is_likely_tls_client_hello;
use rand::Rng;

fn parse_error(message: &str) -> AegisError {
    AegisError::TlsParse(message.into())
}

fn checked_end(start: usize, len: usize) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| parse_error("ClientHello offset overflow"))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = checked_end(*offset, len)?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| parse_error("ClientHello field out of bounds"))?;
    *offset = end;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<usize> {
    let value = take(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]) as usize)
}

fn u24_write(out: &mut [u8], v: usize) {
    out[0] = ((v >> 16) & 0xff) as u8;
    out[1] = ((v >> 8) & 0xff) as u8;
    out[2] = (v & 0xff) as u8;
}

fn u24_len(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

struct SniLayout {
    length_pos: usize,
    value_start: usize,
    value_end: usize,
}

struct ClientHelloLayout {
    handshake_len: usize,
    extensions_length_pos: usize,
    extensions_len: usize,
    extensions_end: usize,
    sni: Option<SniLayout>,
}

/// Only a complete ClientHello occupying the first record can be rewritten.
/// Later records may follow in the input and are preserved byte for byte.
/// Validate every extension, including those after SNI, before any mutation.
fn client_hello_layout(buf: &[u8]) -> Result<ClientHelloLayout> {
    if !is_likely_tls_client_hello(buf) {
        return Err(parse_error("not client hello"));
    }
    let mut record_offset = 3;
    let record_len = read_u16(buf, &mut record_offset)?;
    let record_end = checked_end(5, record_len)?;
    let record = buf
        .get(5..record_end)
        .ok_or_else(|| parse_error("short TLS record"))?;
    let header = record
        .get(..4)
        .ok_or_else(|| parse_error("short handshake header"))?;
    let handshake_len = u24_len(&header[1..4]);
    if checked_end(4, handshake_len)? != record.len() {
        return Err(parse_error(
            "ClientHello must occupy one complete TLS record",
        ));
    }
    let ch = &record[4..];
    let mut offset = 0;
    take(ch, &mut offset, 2 + 32)?;
    let session_id_len = take(ch, &mut offset, 1)?[0] as usize;
    take(ch, &mut offset, session_id_len)?;
    let cipher_suites_len = read_u16(ch, &mut offset)?;
    take(ch, &mut offset, cipher_suites_len)?;
    let compression_len = take(ch, &mut offset, 1)?[0] as usize;
    take(ch, &mut offset, compression_len)?;
    let extensions_length_pos = checked_end(9, offset)?;
    let extensions_len = read_u16(ch, &mut offset)?;
    let extensions_start = checked_end(9, offset)?;
    let extensions = take(ch, &mut offset, extensions_len)?;
    if offset != ch.len() {
        return Err(parse_error("trailing ClientHello bytes outside extensions"));
    }
    let extensions_end = checked_end(extensions_start, extensions_len)?;
    let mut extension_offset = 0;
    let mut sni = None;
    while extension_offset < extensions.len() {
        let header = take(extensions, &mut extension_offset, 4)?;
        let extension_type = u16::from_be_bytes([header[0], header[1]]);
        let value_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let value_start = checked_end(extensions_start, extension_offset)?;
        take(extensions, &mut extension_offset, value_len)?;
        if extension_type == 0 && sni.is_none() {
            sni = Some(SniLayout {
                length_pos: value_start - 2,
                value_start,
                value_end: checked_end(value_start, value_len)?,
            });
        }
    }
    Ok(ClientHelloLayout {
        handshake_len,
        extensions_length_pos,
        extensions_len,
        extensions_end,
        sni,
    })
}

struct MutationLengths {
    extensions: u16,
    handshake: usize,
    record: u16,
}

fn changed_len(current: usize, removed: usize, added: usize) -> Result<usize> {
    current
        .checked_sub(removed)
        .and_then(|len| len.checked_add(added))
        .ok_or_else(|| parse_error("ClientHello length overflow"))
}

/// All fallible length checks precede splice, so Err preserves the input.
fn mutation_lengths(
    layout: &ClientHelloLayout,
    removed: usize,
    added: usize,
) -> Result<MutationLengths> {
    let extensions = u16::try_from(changed_len(layout.extensions_len, removed, added)?)
        .map_err(|_| parse_error("extensions too large"))?;
    let handshake = changed_len(layout.handshake_len, removed, added)?;
    if handshake > 0xffffff {
        return Err(parse_error("hs len overflow"));
    }
    let record = u16::try_from(checked_end(4, handshake)?)
        .map_err(|_| parse_error("record len overflow"))?;
    Ok(MutationLengths {
        extensions,
        handshake,
        record,
    })
}

fn write_lengths(buf: &mut [u8], layout: &ClientHelloLayout, lengths: &MutationLengths) {
    let offset = layout.extensions_length_pos;
    buf[offset..offset + 2].copy_from_slice(&lengths.extensions.to_be_bytes());
    u24_write(&mut buf[6..9], lengths.handshake);
    buf[3..5].copy_from_slice(&lengths.record.to_be_bytes());
}

fn append_extension(buf: &mut Vec<u8>, extension: &[u8]) -> Result<()> {
    let layout = client_hello_layout(buf)?;
    let lengths = mutation_lengths(&layout, 0, extension.len())?;
    buf.splice(
        layout.extensions_end..layout.extensions_end,
        extension.iter().copied(),
    );
    write_lengths(buf, &layout, &lengths);
    Ok(())
}

/// Случайный регистр букв a–z / A–Z в диапазоне SNI (простые DPI по строке).
pub fn obfuscate_sni_case(buf: &mut [u8], range: (usize, usize)) {
    let (s, len) = range;
    if s + len > buf.len() {
        return;
    }
    let mut rng = rand::thread_rng();
    for b in &mut buf[s..s + len] {
        if (*b).is_ascii_alphabetic() && rng.gen_bool(0.5) {
            if b.is_ascii_lowercase() {
                *b = b.to_ascii_uppercase();
            } else {
                *b = b.to_ascii_lowercase();
            }
        }
    }
}

/// Вставка GREASE-расширения (RFC 8701) в конец списка расширений ClientHello.
pub fn inject_grease_extension(buf: &mut Vec<u8>) -> Result<()> {
    let grease_types = [[0x0a, 0x0a], [0x1a, 0x1a], [0x2a, 0x2a], [0x3a, 0x3a]];
    let mut rng = rand::thread_rng();
    let gt = grease_types[rng.gen_range(0..grease_types.len())];
    append_extension(buf, &[gt[0], gt[1], 0, 0])
}

/// Приватное расширение `0xFAC7` + opaque payload (например HMAC от auth; не KeyShare — см. docs).
pub fn inject_opaque_extension(buf: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| parse_error("opaque extension payload too large"))?;
    let mut opaque_ext = Vec::with_capacity(checked_end(4, payload.len())?);
    opaque_ext.extend_from_slice(&[0xfa, 0xc7]);
    opaque_ext.extend_from_slice(&payload_len.to_be_bytes());
    opaque_ext.extend_from_slice(payload);
    append_extension(buf, &opaque_ext)
}

fn encode_sni_extension_value_single(host: &[u8]) -> Result<Vec<u8>> {
    if host.is_empty() || host.len() > 255 {
        return Err(parse_error("bad sni hostname"));
    }
    let list_len = 3 + host.len();
    let mut v = Vec::with_capacity(2 + list_len);
    v.extend_from_slice(&(list_len as u16).to_be_bytes());
    v.push(0);
    v.extend_from_slice(&(host.len() as u16).to_be_bytes());
    v.extend_from_slice(host);
    Ok(v)
}

/// Подмена SNI на один `host_name` произвольной длины (всё значение расширения 0x0000 пересобирается).
pub fn replace_sni_hostname(buf: &mut Vec<u8>, new_hostname: &str) -> Result<()> {
    let new_value = encode_sni_extension_value_single(new_hostname.as_bytes())?;
    let layout = client_hello_layout(buf)?;
    let sni = layout
        .sni
        .as_ref()
        .ok_or_else(|| parse_error("sni not found"))?;
    let lengths = mutation_lengths(&layout, sni.value_end - sni.value_start, new_value.len())?;
    buf.splice(sni.value_start..sni.value_end, new_value.iter().copied());
    buf[sni.length_pos..sni.length_pos + 2]
        .copy_from_slice(&(new_value.len() as u16).to_be_bytes());
    write_lengths(buf, &layout, &lengths);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // AUDIT REPRO (H1 remainder): a ClientHello whose u24 handshake length
    // (bytes 6..9) lies about the body size must be rejected, not panic on the
    // `buf[body_start..body_start + hs_len]` slice.
    #[test]
    fn audit_inject_opaque_rejects_lying_hs_len_without_panic() {
        // Minimal buffer that passes is_likely_tls_client_hello (buf[0]=22,
        // buf[5]=1, len>=11) but claims a 0xFFFFFF-byte handshake body.
        let mut buf = vec![
            22u8, 0x03, 0x01, 0x00, 0x06, 0x01, 0xff, 0xff, 0xff, 0x00, 0x00,
        ];
        let r = inject_opaque_extension(&mut buf, &[0xde, 0xad]);
        assert!(r.is_err(), "expected Err on lying hs_len, got {r:?}");
    }
}
