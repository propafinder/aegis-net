//! JA4 TLS client fingerprint (FoxIO JA4 spec).
//!
//! Layout: `<a>_<b>_<c>` where
//! - **a** = transport (`q` QUIC / `t` TCP) + TLS version (`13`) + SNI present
//!   (`d` domain / `i` IP or absent) + 2-digit cipher count + 2-digit extension
//!   count + first and last character of the first ALPN value (`00` if none),
//! - **b** = first 12 hex of SHA-256 over the *sorted* cipher list,
//! - **c** = first 12 hex of SHA-256 over the *sorted* extension list (SNI and
//!   ALPN removed) + `_` + the signature algorithms in their original order.
//!
//! GREASE values are excluded everywhere. Counts saturate at 99.

use ring::digest::{digest, SHA256};

use super::clienthello::{ext, ClientHello};

/// Which transport the hello was carried over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Quic,
    Tcp,
}

impl Transport {
    fn letter(self) -> char {
        match self {
            Transport::Quic => 'q',
            Transport::Tcp => 't',
        }
    }
}

fn version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    }
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn truncated_sha256(input: &str) -> String {
    // The spec uses the literal string "000000000000" for an empty list.
    if input.is_empty() {
        return "000000000000".to_string();
    }
    let d = digest(&SHA256, input.as_bytes());
    d.as_ref()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// A parsed JA4 fingerprint, with the pre-hash inputs kept for debugging and
/// for diffing two hellos field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4 {
    pub a: String,
    pub b: String,
    pub c: String,
    /// The sorted cipher list that was hashed into `b`.
    pub cipher_input: String,
    /// The sorted extension list + sigalgs that was hashed into `c`.
    pub extension_input: String,
}

impl std::fmt::Display for Ja4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}_{}", self.a, self.b, self.c)
    }
}

/// Compute the JA4 fingerprint of a parsed ClientHello.
pub fn compute(hello: &ClientHello, transport: Transport) -> Ja4 {
    let ciphers = hello.real_cipher_suites();

    // The extension *count* includes every non-GREASE extension; the hashed
    // *list* omits SNI and ALPN (they are already encoded in `a`).
    let all_exts = hello.real_extensions();
    let mut hashed_exts: Vec<u16> = all_exts
        .iter()
        .copied()
        .filter(|e| *e != ext::SERVER_NAME && *e != ext::ALPN)
        .collect();

    let sni = if hello.server_name.is_some() {
        'd'
    } else {
        'i'
    };

    let alpn = hello
        .alpn
        .first()
        .filter(|p| !p.is_empty())
        .map(|p| {
            let first = p[0] as char;
            let last = p[p.len() - 1] as char;
            format!("{first}{last}")
        })
        .unwrap_or_else(|| "00".to_string());

    let a = format!(
        "{}{}{}{:02}{:02}{}",
        transport.letter(),
        version_code(hello.max_version()),
        sni,
        ciphers.len().min(99),
        all_exts.len().min(99),
        alpn
    );

    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_input = hex_list(&sorted_ciphers);

    hashed_exts.sort_unstable();
    let sigalgs = hex_list(&hello.signature_algorithms);
    let extension_input = if sigalgs.is_empty() {
        hex_list(&hashed_exts)
    } else {
        format!("{}_{}", hex_list(&hashed_exts), sigalgs)
    };

    Ja4 {
        a,
        b: truncated_sha256(&cipher_input),
        c: truncated_sha256(&extension_input),
        cipher_input,
        extension_input,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::clienthello::ClientHello;

    fn hello() -> ClientHello {
        ClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![0x0a0a, 0x1301, 0x1302, 0x1303],
            extensions: vec![0x1a1a, 0, 43, 13, 16, 10, 57],
            supported_versions: vec![0x0a0a, 0x0304],
            signature_algorithms: vec![0x0403, 0x0804],
            supported_groups: vec![0x0a0a, 0x11ec, 0x001d],
            alpn: vec![b"h3".to_vec()],
            server_name: Some("example.com".into()),
        }
    }

    #[test]
    fn a_segment_encodes_transport_version_sni_counts_alpn() {
        let ja4 = compute(&hello(), Transport::Quic);
        // q + 13 + d + 3 ciphers + 6 non-GREASE extensions + h3
        assert_eq!(ja4.a, "q13d0306h3");
        assert_eq!(compute(&hello(), Transport::Tcp).a, "t13d0306h3");
    }

    #[test]
    fn grease_is_excluded_from_hashes() {
        let ja4 = compute(&hello(), Transport::Quic);
        assert!(!ja4.cipher_input.contains("0a0a"));
        assert!(!ja4.extension_input.contains("1a1a"));
    }

    #[test]
    fn sni_and_alpn_are_excluded_from_the_extension_hash() {
        let ja4 = compute(&hello(), Transport::Quic);
        // 0000 (SNI) and 0010 (ALPN) must not appear in the hashed list
        let list = ja4.extension_input.split('_').next().unwrap().to_string();
        assert!(!list.split(',').any(|e| e == "0000" || e == "0010"));
        // but sorted 000a, 000d, 002b, 0039 do
        assert_eq!(list, "000a,000d,002b,0039");
    }

    #[test]
    fn ciphers_are_sorted_not_ordered() {
        let mut h = hello();
        h.cipher_suites = vec![0x1303, 0x1301, 0x1302];
        let sorted = compute(&h, Transport::Quic);
        h.cipher_suites = vec![0x1301, 0x1302, 0x1303];
        let ordered = compute(&h, Transport::Quic);
        assert_eq!(sorted.b, ordered.b, "JA4 b must be order-independent");
    }

    #[test]
    fn sigalgs_keep_their_order() {
        let mut h = hello();
        h.signature_algorithms = vec![0x0804, 0x0403];
        let flipped = compute(&h, Transport::Quic);
        assert_ne!(
            flipped.c,
            compute(&hello(), Transport::Quic).c,
            "JA4 c must be sensitive to sigalg order"
        );
    }

    #[test]
    fn missing_alpn_is_encoded_as_double_zero() {
        let mut h = hello();
        h.alpn.clear();
        assert!(compute(&h, Transport::Quic).a.ends_with("00"));
    }

    #[test]
    fn empty_lists_hash_to_the_zero_sentinel() {
        assert_eq!(truncated_sha256(""), "000000000000");
    }
}
