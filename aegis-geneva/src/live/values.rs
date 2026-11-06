//! Geneva textual wire values, without a Scapy/Python dependency.
use super::program::ProgramError;
use crate::packet::{field::Proto, model::tcp_flags};
pub fn ip_flags(text: &str) -> Result<u16, ProgramError> {
    if let Ok(value) = text.parse::<u16>() {
        return if value <= 7 {
            Ok(value << 13)
        } else {
            Err(ProgramError::Syntax)
        };
    }
    let mut bits = 0;
    for name in text.split('+') {
        bits |= match name {
            "" => 0,
            "MF" => 8192,
            "DF" => 16384,
            "evil" => 32768,
            _ => return Err(ProgramError::Syntax),
        };
    }
    Ok(bits)
}
pub fn flags_text(proto: Proto, bits: u16) -> String {
    if proto == Proto::Tcp {
        return tcp_flags::render(bits);
    }
    [(8192, "MF"), (16384, "DF"), (32768, "evil")]
        .into_iter()
        .filter_map(|(bit, name)| (bits & bit != 0).then_some(name))
        .collect::<Vec<_>>()
        .join("+")
}
pub fn quote_utf8_ignore(bytes: &[u8]) -> String {
    let mut valid = Vec::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(_) => {
                valid.extend_from_slice(remaining);
                break;
            }
            Err(e) => {
                let good = e.valid_up_to();
                valid.extend_from_slice(&remaining[..good]);
                let skip = e.error_len().unwrap_or(remaining.len() - good);
                remaining = &remaining[good + skip..];
            }
        }
    }
    let mut quoted = String::new();
    for byte in valid {
        if byte.is_ascii_alphanumeric() || b"-_.~/".contains(&byte) {
            quoted.push(char::from(byte));
        } else {
            quoted.push_str(&format!("%{byte:02X}"));
        }
    }
    quoted
}
pub fn unquote(text: &str) -> Result<Vec<u8>, ProgramError> {
    let raw = text.as_bytes();
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len() {
                return Err(ProgramError::Syntax);
            }
            let word = std::str::from_utf8(&raw[i + 1..i + 3]).map_err(|_| ProgramError::Syntax)?;
            bytes.push(u8::from_str_radix(word, 16).map_err(|_| ProgramError::Syntax)?);
            i += 3;
        } else {
            bytes.push(raw[i]);
            i += 1;
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    // Match urllib.unquote(string).encode(utf8), including replacement of invalid UTF-8.
    let mut result = text.as_bytes().to_vec();
    for (token,value) in [(b"__HTTP_REQUEST__".as_slice(),b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".as_slice()),(b"__DNS_REQUEST__".as_slice(),b"\x009ib\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x08faceface\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01+\x00\x04\xc7\xbf2I\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00".as_slice())]{let mut out=Vec::new();let mut rest=result.as_slice();while let Some(at)=rest.windows(token.len()).position(|window|window==token){out.extend_from_slice(&rest[..at]);out.extend_from_slice(value);rest=&rest[at+token.len()..];}out.extend_from_slice(rest);result=out;}
    Ok(result)
}
