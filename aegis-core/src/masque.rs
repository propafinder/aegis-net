use crate::error::{AegisError, Result};

pub const DEFAULT_MASQUE_PATH: &str = "/.well-known/masque/udp";

pub fn build_connect_udp_path(base_path: &str, host: &str, port: u16) -> Result<String> {
    if host.is_empty() {
        return Err(AegisError::Config("empty MASQUE target host".into()));
    }
    let base = normalize_base_path(base_path)?;
    Ok(format!("{}/{}/{}/", base, percent_encode_host(host), port))
}

pub fn parse_connect_udp_path(path: &str, base_path: &str) -> Result<(String, u16)> {
    let base = normalize_base_path(base_path)?;
    let trimmed = path.trim_end_matches('/');
    let suffix = trimmed
        .strip_prefix(&base)
        .ok_or_else(|| AegisError::Protocol("MASQUE path prefix mismatch".into()))?;
    let suffix = suffix.trim_start_matches('/');
    let mut parts = suffix.split('/');
    let host = parts
        .next()
        .ok_or_else(|| AegisError::Protocol("missing MASQUE target host".into()))?;
    let port = parts
        .next()
        .ok_or_else(|| AegisError::Protocol("missing MASQUE target port".into()))?;
    if parts.next().is_some() {
        return Err(AegisError::Protocol("unexpected MASQUE path suffix".into()));
    }
    let host = percent_decode_host(host)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| AegisError::Protocol("invalid MASQUE target port".into()))?;
    Ok((host, port))
}

fn normalize_base_path(base_path: &str) -> Result<String> {
    if !base_path.starts_with('/') {
        return Err(AegisError::Config("MASQUE path must start with '/'".into()));
    }
    let trimmed = base_path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(AegisError::Config("MASQUE path cannot be empty".into()));
    }
    Ok(trimmed.to_string())
}

fn percent_encode_host(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    for b in host.bytes() {
        let safe = matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(nibble_to_hex((b >> 4) & 0x0f));
            out.push(nibble_to_hex(b & 0x0f));
        }
    }
    out
}

fn percent_decode_host(host: &str) -> Result<String> {
    let bytes = host.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(AegisError::Protocol("truncated percent-encoding".into()));
            }
            let hi = hex_to_nibble(bytes[i + 1])?;
            let lo = hex_to_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out)
        .map_err(|_| AegisError::Protocol("decoded MASQUE host is not utf8".into()))
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0' + n),
        10..=15 => char::from(b'A' + (n - 10)),
        _ => unreachable!(),
    }
}

fn hex_to_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(AegisError::Protocol(
            "invalid hex digit in percent-encoding".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_udp_path_roundtrip_ipv4() {
        let path = build_connect_udp_path(DEFAULT_MASQUE_PATH, "192.0.2.1", 443).unwrap();
        assert_eq!(
            parse_connect_udp_path(&path, DEFAULT_MASQUE_PATH).unwrap(),
            ("192.0.2.1".into(), 443)
        );
    }

    #[test]
    fn connect_udp_path_roundtrip_ipv6() {
        let path = build_connect_udp_path(DEFAULT_MASQUE_PATH, "2001:db8::42", 784).unwrap();
        assert_eq!(path, "/.well-known/masque/udp/2001%3Adb8%3A%3A42/784/");
        assert_eq!(
            parse_connect_udp_path(&path, DEFAULT_MASQUE_PATH).unwrap(),
            ("2001:db8::42".into(), 784)
        );
    }
}
