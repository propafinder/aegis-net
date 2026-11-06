//! Transport-agnostic tunnel control framing.
//!
//! Цель M4: убрать сигнатурные magic bytes из relay handshake и дать общий
//! encrypted envelope для TCP/TLS, WebSocket, gRPC и QUIC family transport-ов.

/// Explicit raw-legacy challenge/proof admission; default v3 dispatch is unchanged.
#[cfg(feature = "legacy-challenge-v1")]
pub mod fresh_legacy;

use crate::error::{AegisError, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const TUNNEL_SALT_LEN: usize = 16;
pub const TUNNEL_NONCE_LEN: usize = 12;
pub const TUNNEL_VERSION: u8 = 3;
pub const TUNNEL_KIND_REQUEST: u8 = 1;
pub const TUNNEL_KIND_RESPONSE: u8 = 2;
/// Datagram session request carried inside the same authenticated v3 envelope.
///
/// Keeping the version and the existing stream kind unchanged preserves the
/// wire contract for every deployed TCP, WebSocket, gRPC-stream and MASQUE
/// client.  A new server can distinguish a message-preserving UDP session only
/// after decrypting the control frame; an old server rejects this kind cleanly.
pub const TUNNEL_KIND_DATAGRAM_REQUEST: u8 = 3;
pub const TUNNEL_REQUEST_NONCE_LEN: usize = 16;
pub const TUNNEL_REQUEST_TAG_LEN: usize = 16;

/// Limit for the encrypted control frame on raw stream transports.
pub const MAX_TUNNEL_CONTROL_FRAME: usize = 16 * 1024;

/// Opt-in WebSocket TCP half-close. Only when requested in the encrypted HTTP
/// handshake and acknowledged in the authenticated TunnelResponse.message does
/// an empty binary frame mean directional EOF. WebSocket Close stays bilateral.
pub const WEBSOCKET_HALF_CLOSE_HEADER: &str = "x-stream-mode";
pub const WEBSOCKET_HALF_CLOSE_MODE: &str = "half-close-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRequestKind {
    Stream,
    Datagram,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedTunnelRequest {
    pub request: TunnelRequest,
    pub kind: TunnelRequestKind,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Ok = 0,
    AuthFailed = 1,
    BadTarget = 2,
    TransportUnavailable = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelResponse {
    pub status: TunnelStatus,
    pub message: String,
}

pub fn seal_tunnel_request(req: &TunnelRequest, auth_secret: &[u8]) -> Result<Vec<u8>> {
    seal_tunnel_request_with_kind(req, TunnelRequestKind::Stream, auth_secret)
}

pub fn seal_tunnel_datagram_request(req: &TunnelRequest, auth_secret: &[u8]) -> Result<Vec<u8>> {
    seal_tunnel_request_with_kind(req, TunnelRequestKind::Datagram, auth_secret)
}

fn seal_tunnel_request_with_kind(
    req: &TunnelRequest,
    kind: TunnelRequestKind,
    auth_secret: &[u8],
) -> Result<Vec<u8>> {
    let mut session_nonce = [0u8; TUNNEL_REQUEST_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut session_nonce);
    let session_tag = derive_request_session_tag(auth_secret, &req.host, req.port, &session_nonce);
    let mut plain = Vec::with_capacity(
        4 + req.host.len() + 2 + TUNNEL_REQUEST_NONCE_LEN + TUNNEL_REQUEST_TAG_LEN,
    );
    plain.push(TUNNEL_VERSION);
    plain.push(match kind {
        TunnelRequestKind::Stream => TUNNEL_KIND_REQUEST,
        TunnelRequestKind::Datagram => TUNNEL_KIND_DATAGRAM_REQUEST,
    });
    plain.extend_from_slice(&(req.host.len() as u16).to_be_bytes());
    plain.extend_from_slice(req.host.as_bytes());
    plain.extend_from_slice(&req.port.to_be_bytes());
    plain.extend_from_slice(&session_nonce);
    plain.extend_from_slice(&session_tag);
    seal_control_payload(&plain, auth_secret)
}

pub fn open_tunnel_request(frame: &[u8], auth_secret: &[u8]) -> Result<TunnelRequest> {
    let opened = open_tunnel_request_with_kind(frame, auth_secret)?;
    if opened.kind != TunnelRequestKind::Stream {
        return Err(AegisError::RelayCodec(
            "bad tunnel request version/kind".into(),
        ));
    }
    Ok(opened.request)
}

pub fn open_tunnel_request_with_kind(
    frame: &[u8],
    auth_secret: &[u8],
) -> Result<OpenedTunnelRequest> {
    let plain = open_control_payload(frame, auth_secret)?;
    if plain.len() < 6 {
        return Err(AegisError::RelayCodec("truncated tunnel request".into()));
    }
    if plain[0] != TUNNEL_VERSION {
        return Err(AegisError::RelayCodec(
            "bad tunnel request version/kind".into(),
        ));
    }
    let kind = match plain[1] {
        TUNNEL_KIND_REQUEST => TunnelRequestKind::Stream,
        TUNNEL_KIND_DATAGRAM_REQUEST => TunnelRequestKind::Datagram,
        _ => {
            return Err(AegisError::RelayCodec(
                "bad tunnel request version/kind".into(),
            ))
        }
    };
    let host_len = u16::from_be_bytes([plain[2], plain[3]]) as usize;
    if plain.len() != 4 + host_len + 2 + TUNNEL_REQUEST_NONCE_LEN + TUNNEL_REQUEST_TAG_LEN {
        return Err(AegisError::RelayCodec("bad tunnel request length".into()));
    }
    let host = std::str::from_utf8(&plain[4..4 + host_len])
        .map_err(|_| AegisError::RelayCodec("tunnel host not utf8".into()))?
        .to_string();
    let port_offset = 4 + host_len;
    let port = u16::from_be_bytes([plain[port_offset], plain[port_offset + 1]]);
    let nonce_offset = port_offset + 2;
    let mut session_nonce = [0u8; TUNNEL_REQUEST_NONCE_LEN];
    session_nonce.copy_from_slice(&plain[nonce_offset..nonce_offset + TUNNEL_REQUEST_NONCE_LEN]);
    let tag_offset = nonce_offset + TUNNEL_REQUEST_NONCE_LEN;
    let presented_tag = &plain[tag_offset..tag_offset + TUNNEL_REQUEST_TAG_LEN];
    let expected_tag = derive_request_session_tag(auth_secret, &host, port, &session_nonce);
    if expected_tag.as_slice() != presented_tag {
        return Err(AegisError::Auth);
    }
    Ok(OpenedTunnelRequest {
        request: TunnelRequest { host, port },
        kind,
    })
}

pub fn seal_tunnel_response(resp: &TunnelResponse, auth_secret: &[u8]) -> Result<Vec<u8>> {
    let msg = resp.message.as_bytes();
    let mut plain = Vec::with_capacity(5 + msg.len());
    plain.push(TUNNEL_VERSION);
    plain.push(TUNNEL_KIND_RESPONSE);
    plain.push(resp.status as u8);
    plain.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    plain.extend_from_slice(msg);
    seal_control_payload(&plain, auth_secret)
}

pub fn open_tunnel_response(frame: &[u8], auth_secret: &[u8]) -> Result<TunnelResponse> {
    let plain = open_control_payload(frame, auth_secret)?;
    if plain.len() < 5 {
        return Err(AegisError::RelayCodec("truncated tunnel response".into()));
    }
    if plain[0] != TUNNEL_VERSION || plain[1] != TUNNEL_KIND_RESPONSE {
        return Err(AegisError::RelayCodec(
            "bad tunnel response version/kind".into(),
        ));
    }
    let status = match plain[2] {
        0 => TunnelStatus::Ok,
        1 => TunnelStatus::AuthFailed,
        2 => TunnelStatus::BadTarget,
        3 => TunnelStatus::TransportUnavailable,
        _ => {
            return Err(AegisError::RelayCodec(
                "unknown tunnel response status".into(),
            ))
        }
    };
    let msg_len = u16::from_be_bytes([plain[3], plain[4]]) as usize;
    if plain.len() != 5 + msg_len {
        return Err(AegisError::RelayCodec("bad tunnel response length".into()));
    }
    let message = String::from_utf8_lossy(&plain[5..]).into_owned();
    Ok(TunnelResponse { status, message })
}

/// Simple raw-stream wrapper for legacy TLS transport.
pub fn encode_stream_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub async fn read_stream_frame<R: AsyncRead + Unpin>(r: &mut R, max_len: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let len = u32::from_be_bytes(head) as usize;
    if len == 0 || len > max_len {
        return Err(AegisError::RelayCodec(format!(
            "bad tunnel frame length {len}"
        )));
    }
    let mut frame = vec![0u8; len];
    r.read_exact(&mut frame).await?;
    Ok(frame)
}

fn seal_control_payload(plain: &[u8], auth_secret: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; TUNNEL_SALT_LEN];
    let mut nonce = [0u8; TUNNEL_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = derive_key(auth_secret, &salt)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| AegisError::RelayCodec("encrypt tunnel control payload".into()))?;

    let mut out = Vec::with_capacity(TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_control_payload(frame: &[u8], auth_secret: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN + 16 {
        return Err(AegisError::RelayCodec(
            "truncated encrypted tunnel frame".into(),
        ));
    }
    let salt = &frame[..TUNNEL_SALT_LEN];
    let nonce = &frame[TUNNEL_SALT_LEN..TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN];
    let ciphertext = &frame[TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN..];
    let key = derive_key(auth_secret, salt)?;
    let cipher = ChaCha20Poly1305::new(&key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AegisError::RelayCodec("decrypt tunnel control payload".into()))
}

fn derive_key(auth_secret: &[u8], salt: &[u8]) -> Result<Key> {
    let hk = Hkdf::<Sha256>::new(Some(salt), auth_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"aegis-tunnel-v3", &mut okm)
        .map_err(|_| AegisError::RelayCodec("hkdf expand tunnel key".into()))?;
    Ok(*Key::from_slice(&okm))
}

fn derive_request_session_tag(
    auth_secret: &[u8],
    host: &str,
    port: u16,
    session_nonce: &[u8; TUNNEL_REQUEST_NONCE_LEN],
) -> [u8; TUNNEL_REQUEST_TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"aegis-tunnel-request-session-v3");
    hasher.update(auth_secret);
    hasher.update(session_nonce);
    hasher.update(host.as_bytes());
    hasher.update(port.to_be_bytes());
    let digest = hasher.finalize();
    let mut tag = [0u8; TUNNEL_REQUEST_TAG_LEN];
    tag.copy_from_slice(&digest[..TUNNEL_REQUEST_TAG_LEN]);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = TunnelRequest {
            host: "example.org".into(),
            port: 443,
        };
        let frame = seal_tunnel_request(&req, b"secret").unwrap();
        let got = open_tunnel_request(&frame, b"secret").unwrap();
        assert_eq!(got, req);
    }

    #[test]
    fn datagram_request_roundtrip_is_typed_and_not_accepted_as_stream() {
        let req = TunnelRequest {
            host: "resolver.example".into(),
            port: 53,
        };
        let frame = seal_tunnel_datagram_request(&req, b"secret").unwrap();
        let got = open_tunnel_request_with_kind(&frame, b"secret").unwrap();
        assert_eq!(got.request, req);
        assert_eq!(got.kind, TunnelRequestKind::Datagram);
        assert!(open_tunnel_request(&frame, b"secret").is_err());
    }

    #[test]
    fn response_roundtrip() {
        let resp = TunnelResponse {
            status: TunnelStatus::Ok,
            message: "ok".into(),
        };
        let frame = seal_tunnel_response(&resp, b"secret").unwrap();
        let got = open_tunnel_response(&frame, b"secret").unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn wrong_secret_fails() {
        let req = TunnelRequest {
            host: "example.org".into(),
            port: 443,
        };
        let frame = seal_tunnel_request(&req, b"secret").unwrap();
        assert!(open_tunnel_request(&frame, b"wrong").is_err());
    }

    #[test]
    fn request_session_tag_is_bound_to_target() {
        let req = TunnelRequest {
            host: "example.org".into(),
            port: 443,
        };
        let frame = seal_tunnel_request(&req, b"secret").unwrap();
        let mut plain = open_control_payload(&frame, b"secret").unwrap();
        let host_len = u16::from_be_bytes([plain[2], plain[3]]) as usize;
        let port_offset = 4 + host_len;
        plain[port_offset] = 0x00;
        plain[port_offset + 1] = 0x50;
        let tampered = seal_control_payload(&plain, b"secret").unwrap();
        assert!(matches!(
            open_tunnel_request(&tampered, b"secret"),
            Err(AegisError::Auth)
        ));
    }

    #[tokio::test]
    async fn stream_frame_roundtrip() {
        let payload = b"abc123".to_vec();
        let bytes = encode_stream_frame(&payload);
        let (mut tx, mut rx) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let _ = tokio::io::AsyncWriteExt::write_all(&mut tx, &bytes).await;
        });
        let got = read_stream_frame(&mut rx, MAX_TUNNEL_CONTROL_FRAME)
            .await
            .unwrap();
        assert_eq!(got, payload);
    }
}
