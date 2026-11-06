//! Actual private loopback TURN server, independent of the carrier ICE runtime.
//! No external TURN/STUN, account, interface change or field-network claim.
use aegis_webrtc::{
    accept, connect, AdmissionKey, BrokerLimits, Cancellation, CarrierConfig, IcePolicy,
    OwnedBroker, TurnServer,
};
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use turn::{
    auth::{generate_auth_key, AuthHandler},
    relay::relay_static::RelayAddressGeneratorStatic,
    server::{
        config::{ConnConfig, ServerConfig},
        Server,
    },
};
use turn_util::{vnet::net::Net, Conn};

const USER: &str = "isolated-fixture";
const REALM: &str = "aegis-loopback-test";
const PASSWORD: &str = "synthetic-never-production";

struct Auth;
impl AuthHandler for Auth {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src: SocketAddr,
    ) -> Result<Vec<u8>, turn::Error> {
        if username != USER || realm != REALM || !src.ip().is_loopback() {
            return Err(turn::Error::Other("fixture admission refused".into()));
        }
        Ok(generate_auth_key(USER, REALM, PASSWORD))
    }
}

/// Count actual TURN channel-data datagrams at the separately owned server.
/// Control-only allocations cannot satisfy the positive transport assertion.
struct CountedConn {
    socket: UdpSocket,
    sent_channel_bytes: AtomicUsize,
    received_channel_bytes: AtomicUsize,
}
fn channel_bytes(buf: &[u8]) -> usize {
    if buf.len() >= 4 && (buf[0] & 0xc0) == 0x40 {
        let declared = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if declared <= buf.len() - 4 {
            return declared;
        }
    }
    0
}
#[async_trait]
impl Conn for CountedConn {
    async fn connect(&self, addr: SocketAddr) -> turn_util::Result<()> {
        Conn::connect(&self.socket, addr).await
    }
    async fn recv(&self, buf: &mut [u8]) -> turn_util::Result<usize> {
        Conn::recv(&self.socket, buf).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> turn_util::Result<(usize, SocketAddr)> {
        let result = Conn::recv_from(&self.socket, buf).await?;
        self.received_channel_bytes
            .fetch_add(channel_bytes(&buf[..result.0]), Ordering::Relaxed);
        Ok(result)
    }
    async fn send(&self, buf: &[u8]) -> turn_util::Result<usize> {
        Conn::send(&self.socket, buf).await
    }
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> turn_util::Result<usize> {
        let result = Conn::send_to(&self.socket, buf, target).await?;
        self.sent_channel_bytes
            .fetch_add(channel_bytes(&buf[..result]), Ordering::Relaxed);
        Ok(result)
    }
    fn local_addr(&self) -> turn_util::Result<SocketAddr> {
        Conn::local_addr(&self.socket)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Conn::remote_addr(&self.socket)
    }
    async fn close(&self) -> turn_util::Result<()> {
        Conn::close(&self.socket).await
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
struct Fixture(Arc<Server>);
impl Drop for Fixture {
    fn drop(&mut self) {
        let server = self.0.clone();
        // A failed assertion/outer deadline must also release the private server.
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), server.close()).await;
        });
    }
}
fn broker() -> Arc<OwnedBroker> {
    Arc::new(
        OwnedBroker::new(
            AdmissionKey::from_bytes([1; 32]).unwrap(),
            AdmissionKey::from_bytes([2; 32]).unwrap(),
            BrokerLimits::default(),
        )
        .unwrap(),
    )
}
fn config(endpoint: SocketAddr) -> CarrierConfig {
    CarrierConfig {
        ice: IcePolicy::RelayOnly {
            servers: vec![TurnServer::udp(endpoint, USER.into(), PASSWORD.into()).unwrap()],
            allowed_relay_ips: vec!["127.0.0.1".parse().unwrap()],
        },
        connect_timeout: Duration::from_secs(8),
        stall_timeout: Duration::from_secs(5),
        max_lifetime: Duration::from_secs(20),
        ..CarrierConfig::loopback()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_turn_only_nominated_pair_carries_bytes_through_owned_relay() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let conn = Arc::new(CountedConn {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            sent_channel_bytes: AtomicUsize::new(0),
            received_channel_bytes: AtomicUsize::new(0),
        });
        let endpoint = conn.socket.local_addr().unwrap();
        let server = Arc::new(
            Server::new(ServerConfig {
                conn_configs: vec![ConnConfig {
                    conn: conn.clone(),
                    relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                        relay_address: "127.0.0.1".parse().unwrap(),
                        address: "127.0.0.1".into(),
                        net: Arc::new(Net::new(None)),
                    }),
                }],
                realm: REALM.into(),
                auth_handler: Arc::new(Auth),
                channel_bind_timeout: Duration::from_secs(30),
                alloc_close_notify: None,
            })
            .await
            .unwrap(),
        );
        let _cleanup = Fixture(server.clone());
        let broker = broker();
        let (client, intermediary) = tokio::join!(
            connect(
                config(endpoint),
                broker.clone(),
                AdmissionKey::from_bytes([1; 32]).unwrap(),
                Cancellation::new()
            ),
            accept(
                config(endpoint),
                broker,
                AdmissionKey::from_bytes([2; 32]).unwrap(),
                Cancellation::new()
            )
        );
        let mut client = client.expect("actual TURN client negotiation");
        let mut intermediary = intermediary.expect("actual TURN intermediary negotiation");
        for stream in [&client, &intermediary] {
            let evidence = stream.path_evidence();
            assert!(evidence.relay_only && evidence.nominated_pair_checked);
            assert_eq!(evidence.local_type, "relay");
            assert_eq!(evidence.remote_type, "relay");
            assert!(!evidence.media_session_verified);
        }
        let payload: Vec<u8> = (0..160_000).map(|n| (n % 251) as u8).collect();
        let peer = tokio::spawn(async move {
            let mut data = Vec::new();
            intermediary.read_to_end(&mut data).await.unwrap();
            intermediary.write_all(&data).await.unwrap();
            intermediary.shutdown().await.unwrap();
            intermediary.close().await;
            data
        });
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, payload);
        assert_eq!(peer.await.unwrap(), payload);
        assert!(conn.sent_channel_bytes.load(Ordering::Relaxed) >= payload.len());
        assert!(conn.received_channel_bytes.load(Ordering::Relaxed) >= payload.len());
        client.close().await;
        tokio::time::timeout(Duration::from_secs(2), server.close())
            .await
            .unwrap()
            .unwrap();
    })
    .await
    .expect("bounded private TURN fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_turn_refuses_without_falling_back_to_direct_host_candidates() {
    tokio::time::timeout(Duration::from_secs(6), async {
        let unused = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = unused.local_addr().unwrap();
        drop(unused);
        let mut cfg = config(endpoint);
        cfg.connect_timeout = Duration::from_secs(2);
        let broker = broker();
        let outcome = connect(
            cfg,
            broker,
            AdmissionKey::from_bytes([1; 32]).unwrap(),
            Cancellation::new(),
        )
        .await;
        assert!(
            outcome.is_err(),
            "TURN outage must not return any direct carrier"
        );
    })
    .await
    .expect("bounded TURN outage refusal");
}
