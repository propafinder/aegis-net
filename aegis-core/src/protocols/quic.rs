//! QUIC Long Header Initial: padding и coalescing (уровень приложения).

use rand::Rng;

/// Минимальный размер UDP datagram для «скрытия» структуры (эвристика).
pub const QUIC_INITIAL_MIN_PADDED: usize = 1200;

#[derive(Debug, Clone)]
pub struct QuicLongHeader {
    pub version: u32,
    pub dcid_len: u8,
    pub dcid: Vec<u8>,
    pub scid_len: u8,
    pub scid: Vec<u8>,
}

/// Распознавание long header (не Version Negotiation): первый байт & 0x80 != 0, version != 0.
pub fn looks_like_quic_long_header(pkt: &[u8]) -> bool {
    pkt.first().map(|b| (b & 0x80) != 0).unwrap_or(false)
        && pkt.len() >= 6
        && u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]) != 0
}

/// Дописать нулями до `target` байт (если меньше).
pub fn pad_initial_datagram(pkt: &mut Vec<u8>, target: usize) {
    if pkt.len() < target {
        pkt.resize(target, 0);
    }
}

/// Coalescing: два UDP payload в один datagram (для DPI, ожидающего один QUIC).
pub fn coalesce_datagrams(a: &[u8], b: &[u8], max_total: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(a.len() + b.len() + 16);
    out.extend_from_slice(a);
    if rng.gen_bool(0.3) && !out.is_empty() && out.len() + b.len() <= max_total {
        // «между» пакетами иногда вставляем padding byte (эвристика)
        out.push(0);
    }
    out.extend_from_slice(b);
    if out.len() < QUIC_INITIAL_MIN_PADDED && out.len() < max_total {
        pad_initial_datagram(&mut out, QUIC_INITIAL_MIN_PADDED.min(max_total));
    }
    out
}
