use super::{
    IngressKind, IngressResponse, IngressSessionIntent, IngressTransport, UdpDatagramResponse,
    UdpSessionControl,
};
use crate::socks5::ConnectTarget;
use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug)]
pub struct BrokeredTcpConnect {
    pub ingress_kind: IngressKind,
    pub client: TcpStream,
    pub target: ConnectTarget,
    pub dst: SocketAddr,
}

#[derive(Debug)]
pub struct BrokeredUdpAssociate {
    pub ingress_kind: IngressKind,
    pub control: UdpSessionControl,
    pub udp_socket: UdpSocket,
    pub client_ip: IpAddr,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub struct BrokeredUdpDatagram {
    pub ingress_kind: IngressKind,
    pub control: UdpSessionControl,
    pub client_ip: IpAddr,
    pub target: ConnectTarget,
    pub payload: Vec<u8>,
    pub response: UdpDatagramResponse,
}

#[derive(Debug)]
pub enum BrokeredSession {
    TcpConnect(BrokeredTcpConnect),
    UdpAssociate(BrokeredUdpAssociate),
    #[cfg_attr(not(test), allow(dead_code))]
    UdpDatagram(BrokeredUdpDatagram),
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("resolve target {target_host}:{target_port}: {source}")]
    Resolve {
        target_host: String,
        target_port: u16,
        source: io::Error,
    },
    #[error("bind relay udp socket ({bind_addr}, client_ip={client_ip}, stage={stage}): {source}")]
    UdpBind {
        client_ip: IpAddr,
        bind_addr: String,
        stage: &'static str,
        source: io::Error,
    },
    #[error("ingress response failed ({request_kind}, action={response_action}): {source}")]
    Response {
        request_kind: &'static str,
        response_action: &'static str,
        source: io::Error,
    },
}

impl BrokerError {
    fn io_error_kind_code(source: &io::Error) -> &'static str {
        match source.kind() {
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::ConnectionRefused => "connection_refused",
            io::ErrorKind::ConnectionReset => "connection_reset",
            io::ErrorKind::ConnectionAborted => "connection_aborted",
            io::ErrorKind::NotConnected => "not_connected",
            io::ErrorKind::AddrInUse => "addr_in_use",
            io::ErrorKind::AddrNotAvailable => "addr_not_available",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::AlreadyExists => "already_exists",
            io::ErrorKind::WouldBlock => "would_block",
            io::ErrorKind::NotADirectory => "not_a_directory",
            io::ErrorKind::IsADirectory => "is_a_directory",
            io::ErrorKind::DirectoryNotEmpty => "directory_not_empty",
            io::ErrorKind::InvalidInput => "invalid_input",
            io::ErrorKind::InvalidData => "invalid_data",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::WriteZero => "write_zero",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::Unsupported => "unsupported",
            io::ErrorKind::UnexpectedEof => "unexpected_eof",
            _ => "other",
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Resolve { .. } => "resolve_failed",
            Self::UdpBind { .. } => "udp_bind_failed",
            Self::Response { .. } => "response_failed",
        }
    }

    pub fn source_error_kind(&self) -> &'static str {
        match self {
            Self::Resolve { source, .. }
            | Self::UdpBind { source, .. }
            | Self::Response { source, .. } => Self::io_error_kind_code(source),
        }
    }

    pub fn request_kind(&self) -> &'static str {
        match self {
            Self::Resolve { .. }
            | Self::Response {
                request_kind: "TcpConnect",
                ..
            } => "TcpConnect",
            Self::UdpBind { .. }
            | Self::Response {
                request_kind: "UdpAssociate",
                ..
            } => "UdpAssociate",
            Self::Response { request_kind, .. } => request_kind,
        }
    }

    pub fn broker_stage(&self) -> &'static str {
        match self {
            Self::Resolve { .. } => "resolve_target",
            Self::UdpBind { stage, .. } => stage,
            Self::Response { .. } => "send_response",
        }
    }

    pub fn target_host(&self) -> Option<&str> {
        match self {
            Self::Resolve { target_host, .. } => Some(target_host.as_str()),
            _ => None,
        }
    }

    pub fn target_port(&self) -> Option<u16> {
        match self {
            Self::Resolve { target_port, .. } => Some(*target_port),
            _ => None,
        }
    }

    pub fn client_ip(&self) -> Option<IpAddr> {
        match self {
            Self::UdpBind { client_ip, .. } => Some(*client_ip),
            _ => None,
        }
    }

    pub fn bind_addr(&self) -> Option<&str> {
        match self {
            Self::UdpBind { bind_addr, .. } => Some(bind_addr.as_str()),
            _ => None,
        }
    }

    pub fn response_action(&self) -> Option<&'static str> {
        match self {
            Self::Response {
                response_action, ..
            } => Some(*response_action),
            _ => None,
        }
    }
}

async fn reject_udp_associate_setup_failure(
    response: IngressResponse,
    control: &mut UdpSessionControl,
    client_ip: IpAddr,
    bind_addr: &str,
    stage: &'static str,
    source: io::Error,
) -> Result<BrokerError, BrokerError> {
    if let Some(stream) = control.as_socks_stream_mut() {
        response
            .send_general_failure(stream)
            .await
            .map_err(|source| BrokerError::Response {
                request_kind: "UdpAssociate",
                response_action: "send_general_failure",
                source,
            })?;
    }
    Ok(BrokerError::UdpBind {
        client_ip,
        bind_addr: bind_addr.to_string(),
        stage,
        source,
    })
}

#[async_trait]
pub trait SessionBroker: Send + Sync {
    async fn normalize(
        &self,
        ingress: IngressSessionIntent,
    ) -> Result<BrokeredSession, BrokerError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultSessionBroker {
    /// Defer hostname resolution to the route owner. Relay resolves remotely;
    /// Auto resolves locally only if its admitted route needs a direct address.
    /// A hostname receives an advisory unspecified bound address here, while
    /// IP literals are concrete without a local DNS query (audit C1/45).
    pub defer_relay_resolution: bool,
}

#[async_trait]
impl SessionBroker for DefaultSessionBroker {
    async fn normalize(
        &self,
        ingress: IngressSessionIntent,
    ) -> Result<BrokeredSession, BrokerError> {
        match ingress.transport {
            IngressTransport::TcpConnect(mut intent) => {
                // The configured route owner receives the original hostname.
                // Relay and Auto defer here; Direct retains its existing lookup
                // and host-unreachable response. BND.ADDR is advisory for CONNECT
                // clients, so deferred names use an unspecified address.
                let dst = if self.defer_relay_resolution {
                    match intent.target.host.parse::<IpAddr>() {
                        Ok(ip) => SocketAddr::new(ip, intent.target.port),
                        Err(_) => SocketAddr::new(
                            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            intent.target.port,
                        ),
                    }
                } else {
                    match intent.target.resolve().await {
                        Ok(dst) => dst,
                        Err(source) => {
                            intent
                                .response
                                .send_host_unreachable(&mut intent.client)
                                .await
                                .map_err(|source| BrokerError::Response {
                                    request_kind: "TcpConnect",
                                    response_action: "send_host_unreachable",
                                    source,
                                })?;
                            return Err(BrokerError::Resolve {
                                target_host: intent.target.host.clone(),
                                target_port: intent.target.port,
                                source,
                            });
                        }
                    }
                };
                intent
                    .response
                    .send_connect_success(&mut intent.client, dst)
                    .await
                    .map_err(|source| BrokerError::Response {
                        request_kind: "TcpConnect",
                        response_action: "send_connect_success",
                        source,
                    })?;
                Ok(BrokeredSession::TcpConnect(BrokeredTcpConnect {
                    ingress_kind: ingress.kind,
                    client: intent.client,
                    target: intent.target,
                    dst,
                }))
            }
            IngressTransport::UdpAssociate(mut intent) => {
                let bind_addr = if intent.client_ip.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                // The broker owns the transitional contract: backend-specific
                // ingress becomes a runtime-ready UDP relay session here.
                let udp_socket = match UdpSocket::bind(bind_addr).await {
                    Ok(socket) => socket,
                    Err(source) => {
                        return Err(reject_udp_associate_setup_failure(
                            intent.response,
                            &mut intent.control,
                            intent.client_ip,
                            bind_addr,
                            "bind_udp_socket",
                            source,
                        )
                        .await?);
                    }
                };
                let bind = match udp_socket.local_addr() {
                    Ok(bind) => bind,
                    Err(source) => {
                        return Err(reject_udp_associate_setup_failure(
                            intent.response,
                            &mut intent.control,
                            intent.client_ip,
                            bind_addr,
                            "read_udp_local_addr",
                            source,
                        )
                        .await?);
                    }
                };
                if let UdpSessionControl::SocksControl(stream) = &mut intent.control {
                    intent
                        .response
                        .send_udp_success(stream, bind)
                        .await
                        .map_err(|source| BrokerError::Response {
                            request_kind: "UdpAssociate",
                            response_action: "send_udp_success",
                            source,
                        })?;
                }
                Ok(BrokeredSession::UdpAssociate(BrokeredUdpAssociate {
                    ingress_kind: ingress.kind,
                    control: intent.control,
                    udp_socket,
                    client_ip: intent.client_ip,
                }))
            }
            IngressTransport::UdpDatagram(intent) => {
                Ok(BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: ingress.kind,
                    control: intent.control,
                    client_ip: intent.client_ip,
                    target: intent.target,
                    payload: intent.payload,
                    response: intent.response,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect client");
        let (server, _) = listener.accept().await.expect("accept server");
        (client, server)
    }

    #[tokio::test]
    async fn udp_local_addr_failure_still_sends_general_failure() {
        let (mut client, control) = tcp_pair().await;
        let mut control = UdpSessionControl::SocksControl(control);
        let err = reject_udp_associate_setup_failure(
            IngressResponse::Socks5,
            &mut control,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "0.0.0.0:0",
            "read_udp_local_addr",
            io::Error::other("local addr failed"),
        )
        .await
        .expect("broker error");
        match err {
            BrokerError::UdpBind {
                stage, bind_addr, ..
            } => {
                assert_eq!(stage, "read_udp_local_addr");
                assert_eq!(bind_addr, "0.0.0.0:0");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mut reply = [0u8; 10];
        client
            .read_exact(&mut reply)
            .await
            .expect("read socks failure");
        assert_eq!(reply[0], 5);
        assert_eq!(reply[1], 1);
    }

    #[tokio::test]
    async fn native_udp_datagram_normalizes_without_udp_bind() {
        let broker = DefaultSessionBroker::default();
        let ingress = IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: "127.0.0.1:5302".parse().expect("peer"),
            transport: IngressTransport::UdpDatagram(super::super::UdpDatagramIntent {
                control: UdpSessionControl::Detached,
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                target: ConnectTarget {
                    host: "8.8.8.8".into(),
                    port: 53,
                },
                payload: vec![1, 2, 3, 4],
                response: UdpDatagramResponse::Detached,
            }),
        };

        let session = broker.normalize(ingress).await.expect("normalize");
        match session {
            BrokeredSession::UdpDatagram(datagram) => {
                assert_eq!(datagram.ingress_kind, IngressKind::WidePrimary);
                assert_eq!(datagram.client_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(datagram.target.host, "8.8.8.8");
                assert_eq!(datagram.target.port, 53);
                assert_eq!(datagram.payload, vec![1, 2, 3, 4]);
                assert!(matches!(datagram.control, UdpSessionControl::Detached));
                assert!(matches!(datagram.response, UdpDatagramResponse::Detached));
            }
            other => panic!("unexpected session: {other:?}"),
        }
    }

    #[tokio::test]
    async fn wide_tcp_resolve_failure_closes_stream_without_socks_reply() {
        let broker = DefaultSessionBroker::default();
        let (mut client, server) = tcp_pair().await;
        let ingress = IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: "127.0.0.1:5303".parse().expect("peer"),
            transport: IngressTransport::TcpConnect(super::super::TcpConnectIntent {
                client: server,
                target: ConnectTarget {
                    host: "nonexistent.invalid".into(),
                    port: 443,
                },
                response: IngressResponse::None,
                target_lease: None,
            }),
        };

        let err = broker
            .normalize(ingress)
            .await
            .expect_err("normalize should fail");
        assert_eq!(err.error_code(), "resolve_failed");
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("stream close timeout")
            .expect("read after close");
        assert_eq!(read, 0, "wide resolve failure should close the stream");
    }

    #[tokio::test]
    async fn relay_defer_does_not_resolve_hostname_locally() {
        // Audit C1 regression: in relay-defer mode a hostname target must NOT be
        // resolved locally (no getaddrinfo). A deliberately unresolvable hostname
        // must still normalize successfully — proving no DNS query was attempted —
        // and yield an unspecified placeholder dst that carries the hostname on to
        // the relay. The non-defer path (above) resolves and fails on the same host.
        let broker = DefaultSessionBroker {
            defer_relay_resolution: true,
        };
        let (_client, server) = tcp_pair().await;
        let ingress = IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: "127.0.0.1:5304".parse().expect("peer"),
            transport: IngressTransport::TcpConnect(super::super::TcpConnectIntent {
                client: server,
                target: ConnectTarget {
                    host: "nonexistent.invalid".into(),
                    port: 443,
                },
                response: IngressResponse::None,
                target_lease: None,
            }),
        };

        let session = broker
            .normalize(ingress)
            .await
            .expect("relay-defer normalize must succeed without DNS");
        match session {
            BrokeredSession::TcpConnect(tcp) => {
                assert_eq!(tcp.target.host, "nonexistent.invalid");
                assert_eq!(tcp.target.port, 443);
                assert!(
                    tcp.dst.ip().is_unspecified(),
                    "deferred hostname should yield a placeholder dst, got {}",
                    tcp.dst
                );
                assert_eq!(tcp.dst.port(), 443);
            }
            other => panic!("unexpected session: {other:?}"),
        }
    }
}
