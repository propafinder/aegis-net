//! Бинарный фрейм Relay после TLS handshake (фаза A; Auth в KeyShare — отдельная фаза).

use crate::error::{AegisError, Result};

/// Магия запроса от клиента к серверу.
pub const RELAY_REQ_MAGIC: &[u8; 4] = b"AEG1";
/// Магия ответа сервера клиенту.
pub const RELAY_RESP_MAGIC: &[u8; 4] = b"AEGR";

pub const RELAY_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRequest {
    pub auth: Vec<u8>,
    pub host: String,
    pub port: u16,
}

/// Кодирует запрос установки туннеля.
pub fn encode_relay_request(req: &RelayRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 2 + req.auth.len() + 2 + req.host.len() + 2);
    out.extend_from_slice(RELAY_REQ_MAGIC);
    out.extend_from_slice(&RELAY_VERSION.to_be_bytes());
    out.extend_from_slice(&(req.auth.len() as u16).to_be_bytes());
    out.extend_from_slice(&req.auth);
    out.extend_from_slice(&(req.host.len() as u16).to_be_bytes());
    out.extend_from_slice(req.host.as_bytes());
    out.extend_from_slice(&req.port.to_be_bytes());
    out
}

/// Декодирует полный буфер запроса (после TLS).
pub fn decode_relay_request(buf: &[u8]) -> Result<RelayRequest> {
    if buf.len() < 4 + 2 + 2 {
        return Err(AegisError::RelayCodec("truncated header".into()));
    }
    if &buf[0..4] != RELAY_REQ_MAGIC {
        return Err(AegisError::RelayCodec("bad magic".into()));
    }
    let ver = u16::from_be_bytes([buf[4], buf[5]]);
    if ver != RELAY_VERSION {
        return Err(AegisError::RelayCodec(format!("unsupported version {ver}")));
    }
    let auth_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut o = 8;
    if buf.len() < o + auth_len + 2 {
        return Err(AegisError::RelayCodec("truncated auth".into()));
    }
    let auth = buf[o..o + auth_len].to_vec();
    o += auth_len;
    let host_len = u16::from_be_bytes([buf[o], buf[o + 1]]) as usize;
    o += 2;
    if buf.len() < o + host_len + 2 {
        return Err(AegisError::RelayCodec("truncated host".into()));
    }
    let host = std::str::from_utf8(&buf[o..o + host_len])
        .map_err(|_| AegisError::RelayCodec("host not utf8".into()))?
        .to_string();
    o += host_len;
    let port = u16::from_be_bytes([buf[o], buf[o + 1]]);
    Ok(RelayRequest { auth, host, port })
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Ok = 0,
    AuthFailed = 1,
    BadTarget = 2,
}

pub fn encode_relay_response(status: RelayStatus, msg: Option<&str>) -> Vec<u8> {
    let msg_bytes = msg.unwrap_or("").as_bytes();
    let mut out = Vec::with_capacity(4 + 2 + 1 + 2 + msg_bytes.len());
    out.extend_from_slice(RELAY_RESP_MAGIC);
    out.extend_from_slice(&RELAY_VERSION.to_be_bytes());
    out.push(status as u8);
    out.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(msg_bytes);
    out
}

pub fn decode_relay_response(buf: &[u8]) -> Result<(RelayStatus, String)> {
    if buf.len() < 4 + 2 + 1 + 2 {
        return Err(AegisError::RelayCodec("truncated response".into()));
    }
    if &buf[0..4] != RELAY_RESP_MAGIC {
        return Err(AegisError::RelayCodec("bad response magic".into()));
    }
    let status_byte = buf[6];
    let status = match status_byte {
        0 => RelayStatus::Ok,
        1 => RelayStatus::AuthFailed,
        2 => RelayStatus::BadTarget,
        _ => return Err(AegisError::RelayCodec("unknown status".into())),
    };
    let msg_len = u16::from_be_bytes([buf[7], buf[8]]) as usize;
    if buf.len() < 9 + msg_len {
        return Err(AegisError::RelayCodec("truncated msg".into()));
    }
    let msg = String::from_utf8_lossy(&buf[9..9 + msg_len]).into_owned();
    Ok((status, msg))
}
