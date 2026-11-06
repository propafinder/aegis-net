//! Minimal TLS ClientHello parser — just enough to fingerprint our own
//! handshake.
//!
//! This exists so the crate can prove, in its own test suite, that the
//! ClientHello it emits is Chrome-shaped: no external capture tooling in the
//! loop for the structural checks. It parses only what a fingerprint needs and
//! rejects anything malformed rather than guessing.

use crate::Error;

/// GREASE code points (RFC 8701) — excluded from every fingerprint.
pub fn is_grease(value: u16) -> bool {
    // 0x0a0a, 0x1a1a, ... 0xfafa: both bytes equal and low nibble 0xa.
    let [hi, lo] = value.to_be_bytes();
    hi == lo && (hi & 0x0f) == 0x0a
}

/// The fingerprint-relevant contents of a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version` from the record body.
    pub legacy_version: u16,
    /// Offered cipher suites, in order, GREASE included.
    pub cipher_suites: Vec<u16>,
    /// Extension types, in the order sent, GREASE included.
    pub extensions: Vec<u16>,
    /// `supported_versions` values, if the extension is present.
    pub supported_versions: Vec<u16>,
    /// `signature_algorithms` values, in order.
    pub signature_algorithms: Vec<u16>,
    /// `supported_groups` values, in order.
    pub supported_groups: Vec<u16>,
    /// ALPN protocols, in order.
    pub alpn: Vec<Vec<u8>>,
    /// SNI host name, if sent.
    pub server_name: Option<String>,
}

/// Extension type constants we care about.
pub mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const ALPN: u16 = 16;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 57;
}

/// A cursor that never panics on truncated input.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(Error::Crypto("ClientHello truncated"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, Error> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// Read a length-prefixed block (`u8` or `u16` length) as a sub-reader.
    fn block_u8(&mut self) -> Result<Reader<'a>, Error> {
        let len = self.u8()? as usize;
        Ok(Reader::new(self.take(len)?))
    }

    fn block_u16(&mut self) -> Result<Reader<'a>, Error> {
        let len = self.u16()? as usize;
        Ok(Reader::new(self.take(len)?))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Read the whole remainder as a list of `u16`s.
    fn u16_list(&mut self) -> Result<Vec<u16>, Error> {
        let mut out = Vec::with_capacity(self.remaining() / 2);
        while self.remaining() >= 2 {
            out.push(self.u16()?);
        }
        Ok(out)
    }
}

/// Parse a TLS handshake message that must be a ClientHello.
///
/// `buf` is the handshake-layer bytes (no TLS record header) — exactly what
/// QUIC carries in CRYPTO frames.
pub fn parse(buf: &[u8]) -> Result<ClientHello, Error> {
    let mut r = Reader::new(buf);

    if r.u8()? != 1 {
        return Err(Error::Crypto("not a ClientHello"));
    }
    let body_len = r.u24()? as usize;
    let mut body = Reader::new(r.take(body_len)?);

    let legacy_version = body.u16()?;
    let _random = body.take(32)?;
    let _legacy_session_id = body.block_u8()?;

    let cipher_suites = body.block_u16()?.u16_list()?;
    let _compression = body.block_u8()?;

    let mut hello = ClientHello {
        legacy_version,
        cipher_suites,
        extensions: Vec::new(),
        supported_versions: Vec::new(),
        signature_algorithms: Vec::new(),
        supported_groups: Vec::new(),
        alpn: Vec::new(),
        server_name: None,
    };

    // Extensions are optional in the wire format, but every modern hello has them.
    if body.remaining() >= 2 {
        let mut exts = body.block_u16()?;
        while exts.remaining() >= 4 {
            let ext_type = exts.u16()?;
            let mut ext_body = exts.block_u16()?;
            hello.extensions.push(ext_type);
            parse_extension(ext_type, &mut ext_body, &mut hello)?;
        }
    }

    Ok(hello)
}

fn parse_extension(
    ext_type: u16,
    body: &mut Reader<'_>,
    hello: &mut ClientHello,
) -> Result<(), Error> {
    match ext_type {
        ext::SUPPORTED_VERSIONS => {
            hello.supported_versions = body.block_u8()?.u16_list()?;
        }
        ext::SIGNATURE_ALGORITHMS => {
            hello.signature_algorithms = body.block_u16()?.u16_list()?;
        }
        ext::SUPPORTED_GROUPS => {
            hello.supported_groups = body.block_u16()?.u16_list()?;
        }
        ext::ALPN => {
            let mut list = body.block_u16()?;
            while list.remaining() >= 1 {
                let proto = list.block_u8()?;
                hello.alpn.push(proto.buf.to_vec());
            }
        }
        ext::SERVER_NAME => {
            let mut list = body.block_u16()?;
            if list.remaining() >= 3 {
                let name_type = list.u8()?;
                let name = list.block_u16()?;
                if name_type == 0 {
                    hello.server_name = String::from_utf8(name.buf.to_vec()).ok();
                }
            }
        }
        _ => {}
    }
    Ok(())
}

impl ClientHello {
    /// Cipher suites with GREASE removed.
    pub fn real_cipher_suites(&self) -> Vec<u16> {
        self.cipher_suites
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect()
    }

    /// Extension types with GREASE removed.
    pub fn real_extensions(&self) -> Vec<u16> {
        self.extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect()
    }

    pub fn has_extension(&self, ext_type: u16) -> bool {
        self.extensions.contains(&ext_type)
    }

    /// True if any GREASE value appears in ciphers, extensions, or groups.
    pub fn uses_grease(&self) -> bool {
        self.cipher_suites.iter().any(|v| is_grease(*v))
            || self.extensions.iter().any(|v| is_grease(*v))
            || self.supported_groups.iter().any(|v| is_grease(*v))
    }

    /// Highest TLS version offered (from `supported_versions`, ignoring GREASE).
    pub fn max_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a0b));
        assert!(!is_grease(0x0b0b));
    }

    /// Hand-built minimal ClientHello, to pin the parser's framing.
    fn minimal_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&4u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&0x0a0au16.to_be_bytes()); // GREASE
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression len
        body.push(0);

        let mut exts = Vec::new();
        // supported_versions
        exts.extend_from_slice(&43u16.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.push(2);
        exts.extend_from_slice(&0x0304u16.to_be_bytes());
        // ALPN: h3
        let alpn_body = [0u8, 3, 2, b'h', b'3'];
        exts.extend_from_slice(&16u16.to_be_bytes());
        exts.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn_body);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = vec![1u8];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn parses_minimal_hello() {
        let hello = parse(&minimal_hello()).unwrap();
        assert_eq!(hello.cipher_suites, vec![0x0a0a, 0x1301]);
        assert_eq!(hello.real_cipher_suites(), vec![0x1301]);
        assert_eq!(hello.alpn, vec![b"h3".to_vec()]);
        assert_eq!(hello.max_version(), 0x0304);
        assert!(hello.uses_grease());
        assert!(hello.has_extension(ext::ALPN));
    }

    #[test]
    fn rejects_truncated_and_wrong_type() {
        let full = minimal_hello();
        for cut in [1, 5, 20, full.len() - 1] {
            assert!(parse(&full[..cut]).is_err(), "accepted truncation at {cut}");
        }
        let mut wrong = full.clone();
        wrong[0] = 2; // ServerHello
        assert!(parse(&wrong).is_err());
    }
}
