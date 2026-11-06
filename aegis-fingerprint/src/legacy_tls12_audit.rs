//! Audit a TLS ClientHello byte buffer for legacy TLS 1.2 extensions
//! that should NOT appear in a TLS 1.3 hello.
//!
//! Real Chrome/Firefox/Safari TLS 1.3 hellos omit:
//!   - `ec_point_formats` (extension 11) — only relevant for ECDHE in 1.2
//!   - `session_ticket` (extension 35) — replaced by PSK in 1.3
//!   - `extended_master_secret` (extension 23) — implicit in 1.3
//!   - `status_request` (extension 5) — OCSP stapling negotiated differently in 1.3
//!
//! rustls 0.23 still emits some of these in 1.3 hellos. The
//! browser-class TLS pcap baseline measurement at
//! `evidence-archive/live/2026-05-16/browser-class-tls-pcap-baseline/` lists
//! their presence as one of the four NOT_ACHIEVED markers.
//!
//! This module ships the *audit* side of the fix — a strict scan that
//! returns which legacy extensions are present in a captured hello. It
//! is used by:
//!
//! 1. The adversarial DPI testbed to measure how far AEGIS hellos are
//!    from a browser-family target.
//! 2. The future uTLS port / rustls fork to assert post-fix that the
//!    legacy extensions have actually been dropped.
//!
//! The audit is read-only and does NOT modify the hello. Dropping the
//! extensions from the actual emitted bytes requires rustls
//! customisation that is not part of this batch — same upstream gap
//! as the GREASE injector.

use serde::{Deserialize, Serialize};

/// Legacy TLS 1.2 extensions that should not appear in a 1.3
/// ClientHello. The repr equals the on-wire extension `type` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum LegacyTls12Extension {
    StatusRequest = 0x0005,
    EcPointFormats = 0x000B,
    ExtendedMasterSecret = 0x0017,
    SessionTicket = 0x0023,
}

impl LegacyTls12Extension {
    /// The on-wire extension type code.
    pub fn type_code(self) -> u16 {
        self as u16
    }

    /// Static slice of every legacy extension this audit knows about,
    /// in extension-type order. Useful for table-driven test fixtures.
    pub const fn all() -> &'static [LegacyTls12Extension] {
        &[
            Self::StatusRequest,
            Self::EcPointFormats,
            Self::ExtendedMasterSecret,
            Self::SessionTicket,
        ]
    }

    fn from_type_code(code: u16) -> Option<Self> {
        match code {
            0x0005 => Some(Self::StatusRequest),
            0x000B => Some(Self::EcPointFormats),
            0x0017 => Some(Self::ExtendedMasterSecret),
            0x0023 => Some(Self::SessionTicket),
            _ => None,
        }
    }
}

/// Result of auditing a ClientHello against the legacy-1.2 extension set.
///
/// `negotiates_tls13` is detected from the supported_versions extension
/// (extension 43). If the hello does not advertise TLS 1.3 we still
/// report the legacy extensions but the verdict is informational —
/// legacy extensions in a legacy hello are not a bug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTls12AuditReport {
    pub negotiates_tls13: bool,
    pub legacy_extensions_present: Vec<LegacyTls12Extension>,
}

impl LegacyTls12AuditReport {
    /// `true` iff the hello declares TLS 1.3 support AND emits at least
    /// one of the legacy 1.2 extensions — i.e. browser-class mimicry is
    /// regressing on the extension-set marker.
    pub fn is_legacy_regression(&self) -> bool {
        self.negotiates_tls13 && !self.legacy_extensions_present.is_empty()
    }

    /// Count of distinct legacy extensions found.
    pub fn legacy_count(&self) -> usize {
        self.legacy_extensions_present.len()
    }
}

/// Audit the given ClientHello bytes.
///
/// Returns `None` if the input is not a parseable TLS 1.x ClientHello.
/// Delegates the extension enumeration + TLS 1.3 detection to
/// `aegis_core::protocols::tls::parse_client_hello_core`, which is
/// already proven by the existing TLS parser test suite.
pub fn audit_client_hello(buf: &[u8]) -> Option<LegacyTls12AuditReport> {
    let core = aegis_core::protocols::tls::parse_client_hello_core(buf)?;

    let mut legacy: Vec<LegacyTls12Extension> = core
        .extension_types
        .iter()
        .copied()
        .filter_map(LegacyTls12Extension::from_type_code)
        .collect();
    legacy.sort_by_key(|e| e.type_code());
    legacy.dedup();

    // TLS 1.3 detection: extension 43 (supported_versions) lists 0x0304.
    // The core parser doesn't expose supported_versions content, so we
    // do a focused scan of the extension list inside the ClientHello.
    let negotiates_tls13 = supported_versions_advertises_tls13(buf).unwrap_or(false);

    Some(LegacyTls12AuditReport {
        negotiates_tls13,
        legacy_extensions_present: legacy,
    })
}

/// Locate the supported_versions extension (type 0x002B) inside a TLS
/// ClientHello byte buffer and return `true` if it advertises 0x0304
/// (TLS 1.3). The walk is deliberately bounded — we never read past
/// the declared extension lengths.
fn supported_versions_advertises_tls13(buf: &[u8]) -> Option<bool> {
    // TLS record header (5 bytes) + handshake header (4 bytes) before
    // the ClientHello body. Locate the extensions block by following the
    // ClientHello structure.
    if buf.len() < 5 + 4 {
        return None;
    }
    // Skip TLS record header.
    let hs = &buf[5..];
    // Handshake type must be 1 (ClientHello).
    if hs.first().copied() != Some(0x01) {
        return None;
    }
    // Skip 4-byte handshake header (type + 24-bit length).
    let body = &hs[4..];
    // legacy_version (2) + random (32).
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let mut p = 2 + 32;
    // session_id (1-byte length + bytes).
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    // cipher_suites (2-byte length + bytes).
    if body.len() < p + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs_len;
    // compression_methods (1-byte length + bytes).
    if body.len() < p + 1 {
        return None;
    }
    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;
    // extensions (2-byte length + bytes).
    if body.len() < p + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    if body.len() < ext_end {
        return None;
    }
    while p + 4 <= ext_end {
        let ty = u16::from_be_bytes([body[p], body[p + 1]]);
        let ln = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if ty == 0x002B {
            // supported_versions content: 1-byte length + N×2-byte versions.
            if body.len() < p + 1 {
                return None;
            }
            let sv_len = body[p] as usize;
            if p + 1 + sv_len > body.len() {
                return None;
            }
            let mut sp = p + 1;
            let sv_end = p + 1 + sv_len;
            while sp + 2 <= sv_end {
                let v = u16::from_be_bytes([body[sp], body[sp + 1]]);
                if v == 0x0304 {
                    return Some(true);
                }
                sp += 2;
            }
            return Some(false);
        }
        p += ln;
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but parseable TLS 1.3-advertising ClientHello
    /// with a configurable set of extensions. Used by every test below.
    fn build_client_hello(extensions: &[(u16, Vec<u8>)], advertise_tls13: bool) -> Vec<u8> {
        // ClientHello body:
        //   legacy_version (2) | random (32) | sid_len(1)+sid | cs_len(2)+cs |
        //   comp_len(1)+comp | ext_len(2)+exts
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
                      // cipher_suites = TLS_AES_128_GCM_SHA256 only
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]); // compression: 1 method, null

        // Build extensions block.
        let mut exts = Vec::new();
        let mut emit = |ty: u16, data: &[u8]| {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(data);
        };
        if advertise_tls13 {
            // supported_versions (43) advertising TLS 1.3.
            //   selected_versions_len (1) | versions (2 bytes each)
            emit(0x002B, &[0x02, 0x03, 0x04]);
        }
        for (ty, data) in extensions {
            emit(*ty, data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header: type=1 (ClientHello), 24-bit length.
        let body_len = body.len();
        let mut hs = vec![
            0x01,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&body);

        // TLS record header: type=22 (Handshake), version 0x0301, length.
        let mut rec = vec![0x16];
        rec.extend_from_slice(&[0x03, 0x01]);
        let hs_len = hs.len();
        rec.extend_from_slice(&(hs_len as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn audit_flags_all_four_legacy_extensions() {
        let hello = build_client_hello(
            &[
                (0x0005, vec![0x00, 0x01, 0x40, 0x00, 0x00]), // status_request
                (0x000B, vec![0x01, 0x00]),                   // ec_point_formats
                (0x0017, vec![]),                             // extended_master_secret
                (0x0023, vec![]),                             // session_ticket
            ],
            true,
        );
        let report = audit_client_hello(&hello).expect("parse hello");
        assert!(report.negotiates_tls13);
        assert!(report.is_legacy_regression());
        assert_eq!(report.legacy_count(), 4);
        let expected = [
            LegacyTls12Extension::StatusRequest,
            LegacyTls12Extension::EcPointFormats,
            LegacyTls12Extension::ExtendedMasterSecret,
            LegacyTls12Extension::SessionTicket,
        ];
        for e in expected {
            assert!(
                report.legacy_extensions_present.contains(&e),
                "missing {e:?}"
            );
        }
    }

    #[test]
    fn audit_clean_tls13_hello_reports_no_regression() {
        // Hello advertises 1.3 and emits NO legacy extensions.
        let hello = build_client_hello(&[], true);
        let report = audit_client_hello(&hello).expect("parse hello");
        assert!(report.negotiates_tls13);
        assert!(!report.is_legacy_regression());
        assert_eq!(report.legacy_count(), 0);
    }

    #[test]
    fn audit_tls12_hello_with_legacy_extensions_is_not_regression() {
        // Hello does NOT advertise 1.3. Legacy extensions are fine.
        let hello = build_client_hello(
            &[
                (0x0005, vec![0x00, 0x01, 0x40, 0x00, 0x00]),
                (0x000B, vec![0x01, 0x00]),
            ],
            false,
        );
        let report = audit_client_hello(&hello).expect("parse hello");
        assert!(!report.negotiates_tls13);
        assert!(!report.is_legacy_regression());
        // Legacy extensions are still reported; the verdict on
        // "regression" is what differs.
        assert_eq!(report.legacy_count(), 2);
    }

    #[test]
    fn audit_rejects_non_clienthello_buffer() {
        assert!(audit_client_hello(&[]).is_none());
        assert!(audit_client_hello(&[0u8; 4]).is_none());
        assert!(audit_client_hello(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn legacy_extension_type_codes_match_iana_assignments() {
        // Static sanity for the type_code() projections — these are
        // wire-format constants from IANA, so a typo would silently
        // break every consumer.
        assert_eq!(LegacyTls12Extension::StatusRequest.type_code(), 5);
        assert_eq!(LegacyTls12Extension::EcPointFormats.type_code(), 11);
        assert_eq!(LegacyTls12Extension::ExtendedMasterSecret.type_code(), 23);
        assert_eq!(LegacyTls12Extension::SessionTicket.type_code(), 35);
    }
}
