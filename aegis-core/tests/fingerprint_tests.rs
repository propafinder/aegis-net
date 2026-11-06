//! Разбор TCP-заголовка для тестов.

use aegis_core::fingerprint::{from_tcp_snapshot, parse_tcp_header, ConnFingerprint};
use aegis_core::ServerType;

#[test]
fn parse_minimal_tcp() {
    let mut t = [0u8; 24];
    t[0..2].copy_from_slice(&80u16.to_be_bytes());
    t[2..4].copy_from_slice(&443u16.to_be_bytes());
    t[12] = 0x50;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    let s = parse_tcp_header(&t).expect("tcp");
    assert_eq!(s.src_port, 80);
    assert_eq!(s.dst_port, 443);
    assert_eq!(s.window, 65535);
    let fp = from_tcp_snapshot(&s, Some(55));
    assert_eq!(fp.ttl_hint, Some(55));
}

/// Явный контракт classify_window диапазонов.
///
/// Все граничные и репрезентативные значения должны давать ожидаемый ServerType.
/// Изменение этих граней — намеренная смена публичного heuristic-контракта.
#[test]
fn classify_window_boundary_contract() {
    // CDN: точное значение 65535
    assert_eq!(
        ConnFingerprint::classify_window(65535),
        ServerType::LikelyCdn
    );

    // Cloudflare: 60000..=65534
    assert_eq!(
        ConnFingerprint::classify_window(60000),
        ServerType::LikelyCloudflare
    );
    assert_eq!(
        ConnFingerprint::classify_window(62000),
        ServerType::LikelyCloudflare
    );
    assert_eq!(
        ConnFingerprint::classify_window(65534),
        ServerType::LikelyCloudflare
    );

    // Google: 14600..=29200 (кратное MSS/PMTU, p0f Google-Linux profile)
    assert_eq!(
        ConnFingerprint::classify_window(14600),
        ServerType::LikelyGoogle
    );
    assert_eq!(
        ConnFingerprint::classify_window(29200),
        ServerType::LikelyGoogle
    );
    assert_eq!(
        ConnFingerprint::classify_window(21000),
        ServerType::LikelyGoogle
    );

    // Unknown: всё что не попадает в выше перечисленные диапазоны
    assert_eq!(ConnFingerprint::classify_window(0), ServerType::Unknown);
    assert_eq!(ConnFingerprint::classify_window(4096), ServerType::Unknown);
    assert_eq!(ConnFingerprint::classify_window(13000), ServerType::Unknown);
    assert_eq!(ConnFingerprint::classify_window(30000), ServerType::Unknown);
    assert_eq!(ConnFingerprint::classify_window(59999), ServerType::Unknown);
}

/// Проверяем что from_tcp_snapshot корректно пробрасывает classify_window в server_type.
#[test]
fn from_tcp_snapshot_reflects_server_type() {
    // Google window
    let mut t = [0u8; 20];
    t[12] = 0x50; // data offset = 5*4 = 20
    t[14..16].copy_from_slice(&29200u16.to_be_bytes());
    let s = parse_tcp_header(&t).expect("tcp header parsed");
    let fp = from_tcp_snapshot(&s, Some(64));
    assert_eq!(fp.server_type, ServerType::LikelyGoogle);
    assert_eq!(fp.ttl_hint, Some(64));

    // CDN window
    let mut t2 = [0u8; 20];
    t2[12] = 0x50;
    t2[14..16].copy_from_slice(&65535u16.to_be_bytes());
    let s2 = parse_tcp_header(&t2).expect("tcp header parsed");
    let fp2 = from_tcp_snapshot(&s2, None);
    assert_eq!(fp2.server_type, ServerType::LikelyCdn);
}
