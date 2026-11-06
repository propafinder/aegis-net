//! Эвристики по TCP (сырой заголовок SYN-ACK или наблюдаемые поля).

use serde::{Deserialize, Serialize};

/// Разобранный TCP-заголовок (первые 20+ байт IP payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeaderSnapshot {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub data_offset_bytes: usize,
    pub tcp_options: TcpOptionsSnapshot,
}

/// Наблюдаемые TCP options из заголовка SYN/SYN-ACK или первого data packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TcpOptionsSnapshot {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: bool,
}

/// Классификация удалённой стороны по эвристикам (не истина, для Brain/логов).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServerType {
    Unknown,
    LikelyCdn,
    LikelyGoogle,
    LikelyCloudflare,
}

impl ServerType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::LikelyCdn => "likely_cdn",
            Self::LikelyGoogle => "likely_google",
            Self::LikelyCloudflare => "likely_cloudflare",
        }
    }
}

/// Грубый профиль TCP receive window.
///
/// Это coarse fingerprint hint, а не точная сигнатура конкретного стека.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WindowProfile {
    Tiny,
    Small,
    Medium,
    Large,
    Huge,
}

impl WindowProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Huge => "huge",
        }
    }

    pub fn from_window(window: u16) -> Self {
        ConnFingerprint::classify_window_profile(window)
    }
}

/// Результат «отпечатка» из доступных данных.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnFingerprint {
    pub window: u16,
    pub window_profile: WindowProfile,
    pub ttl_hint: Option<u8>,
    pub server_type: ServerType,
}

impl ConnFingerprint {
    /// Классифицирует тип сервера по размеру TCP receive window.
    ///
    /// Диапазоны — coarse heuristic, не точная сигнатура:
    /// - `65535`          → CDN (max 16-bit window, типично для anycast-балансировщиков)
    /// - `60000..=65534`  → Cloudflare (специфичная для GFE-Cloudflare начальная window)
    /// - `14600..=29200`  → Google (кратное MSS 1460 и PMTU 1472; p0f Google-Linux profile)
    /// - иначе            → Unknown
    pub fn classify_window(window: u16) -> ServerType {
        if window == 65535 {
            ServerType::LikelyCdn
        } else if (60000..=65534).contains(&window) {
            ServerType::LikelyCloudflare
        } else if (14600..=29200).contains(&window) {
            ServerType::LikelyGoogle
        } else {
            ServerType::Unknown
        }
    }

    pub fn classify_window_profile(window: u16) -> WindowProfile {
        match window {
            0..=4095 => WindowProfile::Tiny,
            4096..=16383 => WindowProfile::Small,
            16384..=32767 => WindowProfile::Medium,
            32768..=60000 => WindowProfile::Large,
            _ => WindowProfile::Huge,
        }
    }
}

/// Разбор минимум 20 байт TCP после IP-заголовка (без IP — передать срез с TCP).
pub fn parse_tcp_header(tcp: &[u8]) -> Option<TcpHeaderSnapshot> {
    if tcp.len() < 20 {
        return None;
    }
    let src = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > tcp.len() {
        return None;
    }
    let win = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some(TcpHeaderSnapshot {
        src_port: src,
        dst_port: dst,
        seq,
        ack,
        window: win,
        data_offset_bytes: data_off,
        tcp_options: parse_tcp_options(&tcp[20..data_off]),
    })
}

fn parse_tcp_options(options: &[u8]) -> TcpOptionsSnapshot {
    let mut parsed = TcpOptionsSnapshot::default();
    let mut idx = 0usize;
    while idx < options.len() {
        match options[idx] {
            0 => break,
            1 => {
                idx += 1;
            }
            kind => {
                let Some(&len) = options.get(idx + 1) else {
                    break;
                };
                let len = len as usize;
                if len < 2 || idx + len > options.len() {
                    break;
                }
                let data = &options[idx + 2..idx + len];
                match kind {
                    2 if len == 4 => {
                        parsed.mss = Some(u16::from_be_bytes([data[0], data[1]]));
                    }
                    3 if len == 3 => {
                        parsed.window_scale = Some(data[0]);
                    }
                    4 if len == 2 => {
                        parsed.sack_permitted = true;
                    }
                    8 if len == 10 => {
                        parsed.timestamps = true;
                    }
                    _ => {}
                }
                idx += len;
            }
        }
    }
    parsed
}

/// Собрать отпечаток из снимка TCP (TTL с IP сюда не входит — передайте отдельно).
pub fn from_tcp_snapshot(snap: &TcpHeaderSnapshot, ip_ttl: Option<u8>) -> ConnFingerprint {
    ConnFingerprint {
        window: snap.window,
        window_profile: ConnFingerprint::classify_window_profile(snap.window),
        ttl_hint: ip_ttl,
        server_type: ConnFingerprint::classify_window(snap.window),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_header_extracts_syn_options_snapshot() {
        let tcp = [
            0x01, 0xbb, 0xc3, 0x50, 0, 0, 0, 1, 0, 0, 0, 2, 0xa0, 0x12, 0xfa, 0xf0, 0, 0, 0, 0, 2,
            4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 8,
        ];
        let header = parse_tcp_header(&tcp).expect("parse tcp header");
        assert_eq!(header.data_offset_bytes, 40);
        assert_eq!(header.tcp_options.mss, Some(1460));
        assert_eq!(header.tcp_options.window_scale, Some(8));
        assert!(header.tcp_options.sack_permitted);
        assert!(header.tcp_options.timestamps);
    }
}
