//! Минимальный SOCKS5 RFC 1928 (TCP CONNECT + UDP ASSOCIATE).
//!
//! v0.3.0: добавлен RFC 1929 username/password auth (метод 0x02).
//! Когда [`SocksAuthCfg::expected_password`] задан — клиент обязан пройти
//! auth handshake; иначе соединение разрывается. Без auth (legacy mode)
//! работает прежний код пути `handshake_no_auth` — оставлен для
//! backcompat с conf'ами без `socks.auth_token`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ERR_NOT_SOCKS5: &str = "not socks5";
const ERR_UNSUPPORTED_COMMAND: &str = "unsupported socks5 command";
const ERR_AUTH_REJECTED: &str = "socks5 auth rejected";
const ERR_AUTH_NOT_OFFERED: &str = "socks5 client did not offer userpass auth";

/// Configuration for the SOCKS5 listener auth gate.
#[derive(Clone)]
pub struct SocksAuthCfg {
    /// Expected RFC 1929 username (default "aegis" if `auth_user` cfg is None).
    pub expected_user: String,
    /// Expected RFC 1929 password. Constant-time compared during handshake.
    pub expected_password: String,
}

impl std::fmt::Debug for SocksAuthCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SocksAuthCfg([redacted])")
    }
}

impl Drop for SocksAuthCfg {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.expected_user.zeroize();
        self.expected_password.zeroize();
    }
}

impl SocksAuthCfg {
    pub fn from_local(auth: &aegis_core::local_socks_auth::LocalSocksAuth) -> Self {
        Self::from_config(auth.password(), Some(auth.username()))
    }

    pub fn from_config(token: &str, user: Option<&str>) -> Self {
        Self {
            expected_user: user.unwrap_or("aegis").to_string(),
            expected_password: token.to_string(),
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub use aegis_client::relay_runtime_types::{ConnectTarget, UdpPacket};

#[derive(Debug, Clone)]
pub enum ClientRequest {
    Connect(ConnectTarget),
    UdpAssociate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestReadFailureReply {
    CommandNotSupported,
    GeneralFailure,
}

pub async fn handshake_no_auth(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            ERR_NOT_SOCKS5,
        ));
    }
    let n = buf[1] as usize;
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?;
    Ok(())
}

/// Auth-aware SOCKS5 handshake. If `cfg` is `Some`, requires RFC 1929
/// username/password auth; otherwise falls through to legacy no-auth.
pub async fn handshake(stream: &mut TcpStream, cfg: Option<&SocksAuthCfg>) -> std::io::Result<()> {
    let Some(cfg) = cfg else {
        return handshake_no_auth(stream).await;
    };

    if !(1..=255).contains(&cfg.expected_user.len())
        || !(1..=255).contains(&cfg.expected_password.len())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            ERR_AUTH_REJECTED,
        ));
    }
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            ERR_NOT_SOCKS5,
        ));
    }
    let n = hdr[1] as usize;
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&0x02) {
        // Method 0xFF = no acceptable methods. Closes connection.
        let _ = stream.write_all(&[5, 0xFF]).await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            ERR_AUTH_NOT_OFFERED,
        ));
    }

    // Tell client to use username/password (method 0x02).
    stream.write_all(&[5, 0x02]).await?;

    // RFC 1929 sub-negotiation:
    //   VER ULEN UNAME PLEN PASSWD
    let mut sub_hdr = [0u8; 2];
    stream.read_exact(&mut sub_hdr).await?;
    if sub_hdr[0] != 0x01 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rfc1929 subnegotiation version != 1",
        ));
    }
    let ulen = sub_hdr[1] as usize;
    let mut uname = zeroize::Zeroizing::new(vec![0u8; ulen]);
    stream.read_exact(&mut uname).await?;
    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;
    let mut password = zeroize::Zeroizing::new(vec![0u8; plen]);
    stream.read_exact(&mut password).await?;

    let user_ok = ct_eq(&uname, cfg.expected_user.as_bytes());
    let pw_ok = ct_eq(&password, cfg.expected_password.as_bytes());

    if user_ok && pw_ok {
        // RFC 1929 success status = 0x00.
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(())
    } else {
        // Status != 0 = auth rejected. Per RFC, server must close.
        let _ = stream.write_all(&[0x01, 0x01]).await;
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            ERR_AUTH_REJECTED,
        ))
    }
}

pub async fn read_client_request(stream: &mut TcpStream) -> std::io::Result<ClientRequest> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            ERR_NOT_SOCKS5,
        ));
    }
    match hdr[1] {
        1 => Ok(ClientRequest::Connect(
            read_target_after_header(stream, hdr[3]).await?,
        )),
        3 => {
            let _client_bind = read_target_after_header(stream, hdr[3]).await?;
            Ok(ClientRequest::UdpAssociate)
        }
        _ => {
            // Consume the bounded request address before closing. Winsock
            // otherwise resets a socket with unread data, losing the REP=7
            // response. An incomplete/invalid request cannot stall rejection.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                read_target_after_header(stream, hdr[3]),
            )
            .await;
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_UNSUPPORTED_COMMAND,
            ))
        }
    }
}

pub fn classify_request_read_error(err: &std::io::Error) -> RequestReadFailureReply {
    if err.kind() == std::io::ErrorKind::InvalidData && err.to_string() == ERR_UNSUPPORTED_COMMAND {
        RequestReadFailureReply::CommandNotSupported
    } else {
        RequestReadFailureReply::GeneralFailure
    }
}

async fn read_target_after_header(
    stream: &mut TcpStream,
    atyp: u8,
) -> std::io::Result<ConnectTarget> {
    match atyp {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let host = Ipv4Addr::from(ip).to_string();
            Ok(ConnectTarget { host, port })
        }
        3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let len = l[0] as usize;
            let mut host = vec![0u8; len];
            stream.read_exact(&mut host).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let host = String::from_utf8_lossy(&host).into_owned();
            Ok(ConnectTarget { host, port })
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let port = u16::from_be_bytes(p);
            let host = Ipv6Addr::from(ip).to_string();
            Ok(ConnectTarget { host, port })
        }
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "atyp")),
    }
}

pub fn parse_udp_packet(packet: &[u8]) -> std::io::Result<UdpPacket> {
    if packet.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short socks5 udp packet",
        ));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad socks5 udp reserved bytes",
        ));
    }
    if packet[2] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fragmented socks5 udp packets are unsupported",
        ));
    }
    let atyp = packet[3];
    let (target, payload_offset) = match atyp {
        1 => {
            if packet.len() < 10 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "short ipv4 udp packet",
                ));
            }
            let host = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]).to_string();
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            (ConnectTarget { host, port }, 10)
        }
        3 => {
            if packet.len() < 5 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "short domain udp packet",
                ));
            }
            let len = packet[4] as usize;
            let host_end = 5 + len;
            if packet.len() < host_end + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated domain udp packet",
                ));
            }
            let host = String::from_utf8_lossy(&packet[5..host_end]).into_owned();
            let port = u16::from_be_bytes([packet[host_end], packet[host_end + 1]]);
            (ConnectTarget { host, port }, host_end + 2)
        }
        4 => {
            if packet.len() < 22 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "short ipv6 udp packet",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&packet[4..20]);
            let host = Ipv6Addr::from(ip).to_string();
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            (ConnectTarget { host, port }, 22)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported socks5 udp atyp",
            ))
        }
    };
    Ok(UdpPacket {
        target,
        payload: packet[payload_offset..].to_vec(),
    })
}

pub fn encode_udp_packet(target: &ConnectTarget, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = vec![0u8, 0, 0];
    if let Ok(ip) = target.host.parse::<Ipv4Addr>() {
        out.push(1);
        out.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target.host.parse::<Ipv6Addr>() {
        out.push(4);
        out.extend_from_slice(&ip.octets());
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "domain too long for socks5 udp packet",
            ));
        }
        out.push(3);
        out.push(host.len() as u8);
        out.extend_from_slice(host);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub async fn send_success(stream: &mut TcpStream, bind: SocketAddr) -> std::io::Result<()> {
    send_reply(stream, 0, bind).await
}

pub async fn send_command_not_supported(stream: &mut TcpStream) -> std::io::Result<()> {
    send_reply(stream, 7, default_reply_bind(stream)).await
}

pub async fn send_host_unreachable(stream: &mut TcpStream) -> std::io::Result<()> {
    send_reply(stream, 4, default_reply_bind(stream)).await
}

pub async fn send_general_failure(stream: &mut TcpStream) -> std::io::Result<()> {
    send_reply(stream, 1, default_reply_bind(stream)).await
}

async fn send_reply(stream: &mut TcpStream, code: u8, bind: SocketAddr) -> std::io::Result<()> {
    let mut resp = vec![5u8, code, 0];
    match bind {
        SocketAddr::V4(a) => {
            resp.push(1);
            resp.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            resp.push(4);
            resp.extend_from_slice(&a.ip().octets());
        }
    }
    resp.extend_from_slice(&bind.port().to_be_bytes());
    stream.write_all(&resp).await
}

fn default_reply_bind(stream: &TcpStream) -> SocketAddr {
    match stream.peer_addr() {
        Ok(addr) if addr.is_ipv6() => "[::]:0".parse().expect("valid ipv6 wildcard"),
        _ => "0.0.0.0:0".parse().expect("valid ipv4 wildcard"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    // Synthetic loopback credentials; no deployment authentication material.
    const AUTH_USER: &str = "auth-fixture";
    const AUTH_PASSWORD: &str = "synthetic-password";

    async fn auth_pair() -> (TcpStream, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let cfg = SocksAuthCfg::from_config(AUTH_PASSWORD, Some(AUTH_USER));
            handshake(&mut stream, Some(&cfg)).await
        });
        (TcpStream::connect(addr).await.unwrap(), server)
    }

    fn credentials(user: &[u8], password: &[u8]) -> Vec<u8> {
        let mut bytes = vec![1, user.len() as u8];
        bytes.extend_from_slice(user);
        bytes.push(password.len() as u8);
        bytes.extend_from_slice(password);
        bytes
    }

    async fn select_auth(client: &mut TcpStream) {
        client.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut selected = [0; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
    }

    #[tokio::test]
    async fn rfc1929_valid_credentials_succeed() {
        timeout(Duration::from_secs(2), async {
            let (mut client, server) = auth_pair().await;
            select_auth(&mut client).await;
            client
                .write_all(&credentials(AUTH_USER.as_bytes(), AUTH_PASSWORD.as_bytes()))
                .await
                .unwrap();
            let mut status = [0; 2];
            client.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [1, 0]);
            server.await.unwrap().unwrap();
        })
        .await
        .expect("valid RFC1929 exchange must complete");
    }

    #[tokio::test]
    async fn rfc1929_wrong_or_empty_credentials_are_rejected() {
        timeout(Duration::from_secs(2), async {
            for (user, password) in [
                (b"wrong-user".as_slice(), AUTH_PASSWORD.as_bytes()),
                (AUTH_USER.as_bytes(), b"wrong-password".as_slice()),
                (b"".as_slice(), AUTH_PASSWORD.as_bytes()),
                (AUTH_USER.as_bytes(), b"".as_slice()),
            ] {
                let (mut client, server) = auth_pair().await;
                select_auth(&mut client).await;
                client
                    .write_all(&credentials(user, password))
                    .await
                    .unwrap();
                let mut status = [0; 2];
                client.read_exact(&mut status).await.unwrap();
                assert_eq!(status, [1, 1]);
                let err = server.await.unwrap().unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(err.to_string(), ERR_AUTH_REJECTED);
                let mut closed = [0; 1];
                assert_eq!(client.read(&mut closed).await.unwrap(), 0);
            }
        })
        .await
        .expect("invalid credentials must receive rejection and close");
    }

    #[tokio::test]
    async fn rfc1929_missing_method_is_rejected_without_auth_downgrade() {
        timeout(Duration::from_secs(2), async {
            for greeting in [&[5, 1, 0][..], &[5, 0][..]] {
                let (mut client, server) = auth_pair().await;
                client.write_all(greeting).await.unwrap();
                let mut selected = [0; 2];
                client.read_exact(&mut selected).await.unwrap();
                assert_eq!(selected, [5, 255]);
                let err = server.await.unwrap().unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(err.to_string(), ERR_AUTH_NOT_OFFERED);
            }
        })
        .await
        .expect("auth-required listener must reject no-auth-only clients");
    }

    #[tokio::test]
    async fn rfc1929_invalid_version_and_truncated_credentials_fail() {
        timeout(Duration::from_secs(2), async {
            for bytes in [&[2, 0][..], &[1, 3, b'a'][..]] {
                let (mut client, server) = auth_pair().await;
                select_auth(&mut client).await;
                client.write_all(bytes).await.unwrap();
                client.shutdown().await.unwrap();
                let err = server.await.unwrap().unwrap_err();
                if bytes[0] != 1 {
                    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
                } else {
                    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
                }
            }
        })
        .await
        .expect("malformed RFC1929 exchange must not authenticate");
    }

    #[test]
    fn udp_packet_roundtrip_domain() {
        let packet = encode_udp_packet(
            &ConnectTarget {
                host: "example.org".into(),
                port: 443,
            },
            b"hello",
        )
        .unwrap();
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(
            parsed,
            UdpPacket {
                target: ConnectTarget {
                    host: "example.org".into(),
                    port: 443,
                },
                payload: b"hello".to_vec(),
            }
        );
    }
}
