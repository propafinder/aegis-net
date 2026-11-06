use aegis_core::build_connect_udp_path;
use aegis_core::tunnel::{
    open_tunnel_response, seal_tunnel_datagram_request, seal_tunnel_request, TunnelRequest,
    TunnelStatus,
};
use bytes::{Buf, Bytes};
use futures::{SinkExt, StreamExt};
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[tokio::test]
async fn websocket_tunnel_smoke() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let tls = env
        .tls_connector()
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let request = format!("wss://localhost{}", env.cfg.transport.websocket_path)
        .into_client_request()
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(request, tls)
        .await
        .expect("ws handshake");
    let frame = seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: env.target_port,
        },
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(frame))
        .await
        .expect("send ws tunnel");
    let msg = ws.next().await.expect("ws response").expect("ws msg");
    let tokio_tungstenite::tungstenite::Message::Binary(resp_frame) = msg else {
        panic!("unexpected websocket response");
    };
    let resp = open_tunnel_response(
        &resp_frame,
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    assert_eq!(resp.status, TunnelStatus::Ok);
}

// REGRESSION: the server accepted the WebSocket with tungstenite's default
// limits — 64 MiB per message, 16 MiB per frame, unlimited write buffer — and
// the FIRST message it reads is the tunnel request, before the token is
// checked. Any peer that could complete a WebSocket handshake could therefore
// make the server allocate 64 MiB with no credential, times
// limits.max_connections (1000 by default).
#[tokio::test]
async fn websocket_refuses_an_oversized_pre_auth_frame() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let tls = env
        .tls_connector()
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let request = format!("wss://localhost{}", env.cfg.transport.websocket_path)
        .into_client_request()
        .unwrap();
    // Raise the client's own limits so the client is not what refuses this;
    // the point is that the SERVER must not buffer it.
    let client_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: None,
        max_frame_size: None,
        ..Default::default()
    };
    let (mut ws, _) =
        tokio_tungstenite::client_async_with_config(request, tls, Some(client_config))
            .await
            .expect("ws handshake");

    // 8 MiB of junk in place of a tunnel request: well under the old 64 MiB
    // default, well over anything the protocol needs.
    let junk = vec![0x41u8; 8 * 1024 * 1024];
    let _ = ws
        .send(tokio_tungstenite::tungstenite::Message::Binary(junk))
        .await;

    // The server must drop us rather than buffer it. Either the frame is
    // refused outright (message-too-large close) or the connection ends; what
    // must NOT happen is a successful tunnel.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
        .await
        .expect("server must not hang on an oversized pre-auth frame");
    match outcome {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => {}
        Some(Ok(other)) => panic!("expected refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn websocket_tunnel_smoke_accepts_rotated_pool_path_with_legacy_credential() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let tls = env
        .tls_connector()
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let request = format!(
        "wss://localhost{}",
        env.cfg.transport.websocket_path_pool[0]
    )
    .into_client_request()
    .unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(request, tls)
        .await
        .expect("ws handshake");
    let frame = seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: env.target_port,
        },
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
    )
    .unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(frame))
        .await
        .expect("send ws tunnel");
    let msg = ws.next().await.expect("ws response").expect("ws msg");
    let tokio_tungstenite::tungstenite::Message::Binary(resp_frame) = msg else {
        panic!("unexpected websocket response");
    };
    let resp = open_tunnel_response(
        &resp_frame,
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
    )
    .unwrap();
    assert_eq!(resp.status, TunnelStatus::Ok);
}

#[tokio::test]
async fn grpc_tunnel_smoke_with_legacy_credential() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let mut cfg = env.client_tls_config();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tls = connector
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri(&env.cfg.transport.grpc_path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response_fut, mut send) = client.send_request(req, false).unwrap();
    let frame = seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: env.target_port,
        },
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
    )
    .unwrap();
    send.send_data(grpc_frame(&frame), false).unwrap();
    let response = response_fut.await.expect("grpc response");
    assert!(response.status().is_success());
    let mut body = response.into_body();
    let mut pending = Vec::new();
    let resp_frame = read_grpc_message(&mut body, &mut pending)
        .await
        .expect("grpc message")
        .expect("grpc payload");
    let resp = open_tunnel_response(
        &resp_frame,
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
    )
    .unwrap();
    assert_eq!(resp.status, TunnelStatus::Ok);
}

#[tokio::test]
async fn grpc_datagram_preserves_udp_message_boundaries_bidirectionally() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp echo bind");
    let udp_port = udp_echo.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((len, peer)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..len], peer).await;
        }
    });

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let mut cfg = env.client_tls_config();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tls = connector
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri(&env.cfg.transport.grpc_path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response_fut, mut send) = client.send_request(request, false).unwrap();
    let frame = seal_tunnel_datagram_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: udp_port,
        },
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    send.send_data(grpc_frame(&frame), false).unwrap();
    let response = response_fut.await.expect("grpc response");
    assert!(response.status().is_success());
    let mut body = response.into_body();
    let mut pending = Vec::new();
    let response_frame = read_grpc_message(&mut body, &mut pending)
        .await
        .expect("grpc response message")
        .expect("grpc response payload");
    let response = open_tunnel_response(
        &response_frame,
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    assert_eq!(response.status, TunnelStatus::Ok);

    // Seventy messages together exceed the default h2 stream window. Each response
    // must release capacity before later messages can be delivered, while every
    // 1 KiB UDP boundary remains intact.
    let datagrams: Vec<Vec<u8>> = (0..70)
        .map(|index| vec![0x40 + (index % 32) as u8; 1_000])
        .collect();
    for (index, expected) in datagrams.into_iter().enumerate() {
        send.send_data(grpc_frame(&expected), false).unwrap();
        let echoed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_grpc_message(&mut body, &mut pending),
        )
        .await
        .unwrap_or_else(|_| panic!("UDP response {index} timeout"))
        .expect("read UDP response")
        .expect("UDP response payload");
        assert_eq!(echoed, expected);
    }
    let _ = send.send_data(Bytes::new(), true);
}

#[tokio::test]
async fn idle_grpc_datagram_stream_is_closed_by_server_bound() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start_with_transport_limits(30_000, 10, 20, 100).await;
    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let mut cfg = env.client_tls_config();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tls = connector
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method("POST")
        .uri(&env.cfg.transport.grpc_path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response_fut, mut send) = client.send_request(request, false).unwrap();
    let frame = seal_tunnel_datagram_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: env.target_port,
        },
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    send.send_data(grpc_frame(&frame), false).unwrap();
    let mut body = response_fut.await.expect("grpc response").into_body();
    let mut pending = Vec::new();
    let response_frame = read_grpc_message(&mut body, &mut pending)
        .await
        .expect("grpc response message")
        .expect("grpc response payload");
    let response = open_tunnel_response(
        &response_frame,
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    assert_eq!(response.status, TunnelStatus::Ok);

    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        read_grpc_message(&mut body, &mut pending),
    )
    .await
    .expect("idle gRPC datagram stream was not bounded");
    match closed {
        Ok(None) => {}
        Err(error) => {
            let benign = error.chain().any(|cause| {
                cause
                    .downcast_ref::<h2::Error>()
                    .and_then(h2::Error::reason)
                    .is_some_and(|reason| reason == h2::Reason::NO_ERROR)
            });
            assert!(benign, "idle close returned a non-benign error: {error:#}");
        }
        Ok(Some(payload)) => panic!("unexpected payload after idle bound: {payload:?}"),
    }
}

// REGRESSION: the server read gRPC body chunks into its own buffer and never
// called `release_capacity`, so h2's receive window (65535 bytes by default)
// closed for good once ~64 KiB had been uploaded. The tunnel was already
// established at that point, so the upload direction simply hung until a
// timeout and it read as a network fault. Anything over 64 KiB — a file
// upload, a large POST — could not traverse the gRPC transport.
#[tokio::test]
async fn grpc_tunnel_carries_more_than_the_h2_receive_window() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    // A target that actually drains, so the only thing that can stall the
    // upload is the h2 window.
    let sink = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("sink bind");
    let sink_port = sink.local_addr().expect("addr").port();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel::<usize>();
    // Four times the default 65535-byte window: enough that a single missing
    // release cannot be papered over by the initial credit.
    const UPLOAD_BYTES: usize = 256 * 1024;
    tokio::spawn(async move {
        let (mut stream, _) = sink.accept().await.expect("sink accept");
        let mut total = 0usize;
        let mut buf = vec![0u8; 16 * 1024];
        while total < UPLOAD_BYTES {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        let _ = received_tx.send(total);
    });

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let mut cfg = env.client_tls_config();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tls = connector
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri(&env.cfg.transport.grpc_path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response_fut, mut send) = client.send_request(req, false).unwrap();
    let frame = seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: sink_port,
        },
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    send.send_data(grpc_frame(&frame), false).unwrap();
    let response = response_fut.await.expect("grpc response");
    assert!(response.status().is_success());
    let mut body = response.into_body();
    let mut pending = Vec::new();
    let resp_frame = read_grpc_message(&mut body, &mut pending)
        .await
        .expect("grpc message")
        .expect("grpc payload");
    let resp = open_tunnel_response(
        &resp_frame,
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    assert_eq!(resp.status, TunnelStatus::Ok);

    let chunk = vec![0x5au8; 16 * 1024];
    let mut sent = 0usize;
    while sent < UPLOAD_BYTES {
        let payload = grpc_frame(&chunk);
        send.reserve_capacity(payload.len());
        // Wait for the peer to grant send capacity. Before the fix the server
        // stops granting it after ~64 KiB and this never resolves.
        let granted = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            futures::future::poll_fn(|cx| send.poll_capacity(cx)),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "h2 send capacity never returned after {sent} bytes — receive window not released"
            )
        });
        granted.expect("capacity stream open").expect("capacity");
        send.send_data(payload, false).expect("send chunk");
        sent += chunk.len();
    }
    let _ = send.send_data(Bytes::new(), true);

    let total = tokio::time::timeout(std::time::Duration::from_secs(15), received_rx)
        .await
        .expect("target should receive the full upload, not stall at the h2 window")
        .expect("sink task");
    assert_eq!(
        total, UPLOAD_BYTES,
        "the whole upload must reach the target"
    );
}

// RFC 8441: WebSocket carried over an HTTP/2 stream via extended CONNECT.
//
// This exists so the https_ws transport can stop being the only thing on the
// wire that offers ALPN `http/1.1` alone. Chrome offers `h2,http/1.1` and
// sends ALPS; a client forced to ask for http/1.1 is distinguishable on the
// ClientHello — measured on the fleet as t13d1515h1_... against Chrome's
// t13d1516h2_... (artifacts/live/2026-08-10/wire-ja4-https-ws-vs-chrome).
#[tokio::test]
async fn websocket_over_h2_extended_connect_tunnel() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    let mut cfg = env.client_tls_config();
    // The point of the exercise: h2, not http/1.1.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tls = connector
        .connect(env.server_name(), tcp)
        .await
        .expect("tls");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!(
            "https://localhost{}",
            env.cfg.transport.websocket_path
        ))
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(h2::ext::Protocol::from("websocket"));

    let (response_fut, send) = client.send_request(req, false).expect("extended CONNECT");
    let response = response_fut.await.expect("connect response");
    assert_eq!(
        response.status(),
        200,
        "the relay must accept :protocol=websocket over h2"
    );

    // The WebSocket starts right after the 200 — no HTTP/1.1 Upgrade.
    let stream = H2ClientStream::new(send, response.into_body());
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    let frame = seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: env.target_port,
        },
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(frame))
        .await
        .expect("send tunnel request over h2");
    let msg = ws.next().await.expect("ws response").expect("ws msg");
    let tokio_tungstenite::tungstenite::Message::Binary(resp_frame) = msg else {
        panic!("unexpected websocket response over h2");
    };
    let resp = open_tunnel_response(
        &resp_frame,
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
    )
    .unwrap();
    assert_eq!(resp.status, TunnelStatus::Ok);
}

// Same adapter shape the server uses, for the client side of the test.
struct H2ClientStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    pending: Bytes,
}

impl H2ClientStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            pending: Bytes::new(),
        }
    }
}

impl tokio::io::AsyncRead for H2ClientStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let take = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..take]);
                this.pending.advance(take);
                return std::task::Poll::Ready(Ok(()));
            }
            match std::task::ready!(this.recv.poll_data(cx)) {
                None => return std::task::Poll::Ready(Ok(())),
                Some(Err(err)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(err)));
                }
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    if len > 0 {
                        let _ = this.recv.flow_control().release_capacity(len);
                    }
                    this.pending = chunk;
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for H2ClientStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(buf.len());
        let granted = match std::task::ready!(this.send.poll_capacity(cx)) {
            None => {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "h2 stream closed",
                )))
            }
            Some(Err(err)) => return std::task::Poll::Ready(Err(std::io::Error::other(err))),
            Some(Ok(granted)) => granted,
        };
        let take = granted.min(buf.len());
        if take == 0 {
            return std::task::Poll::Pending;
        }
        this.send
            .send_data(Bytes::copy_from_slice(&buf[..take]), false)
            .map_err(std::io::Error::other)?;
        std::task::Poll::Ready(Ok(take))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let _ = this.send.send_data(Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

// RED TEAM REGRESSION: plain HTTP on the TLS port used to get a 6-byte TLS
// decode_error alert from rustls, because the non-TLS bytes never reached
// AEGIS code. A Cloudflare-fronted origin — what this relay claims to be —
// answers with an HTTP 400 page. That was one of five probes that
// distinguished the relay from a fronted control.
#[tokio::test]
async fn plain_http_on_the_tls_port_answers_like_a_fronted_origin() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let mut tcp = TcpStream::connect(env.server_addr())
        .await
        .expect("tcp connect");
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n")
        .await
        .expect("send plain http");

    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tcp.read_to_end(&mut response),
    )
    .await
    .expect("relay must answer, not hang")
    .expect("read response");

    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 400 "),
        "expected a fronted-origin HTTP 400, got {:?}",
        &text[..text.len().min(80)]
    );
    assert!(
        text.contains("Server: "),
        "the decoy identity must be present"
    );
    assert!(
        response.len() > 100,
        "a 6-byte TLS alert is the thing being fixed; got {} bytes",
        response.len()
    );
}

#[tokio::test]
async fn masque_derived_tunnel_smoke_with_legacy_credential() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo bind");
    let echo_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for c in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(c.expect("pem cert")).expect("add root");
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(env.server_addr().parse().unwrap(), "localhost")
        .expect("quic connect start")
        .await
        .expect("quic connect");
    let quic = h3_quinn::Connection::new(conn);
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (_h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await.expect("h3 build");
    let mut req_stream = send_request
        .send_request(
            http::Request::builder()
                .method("CONNECT")
                .uri(format!("https://127.0.0.1:{echo_port}"))
                .body(())
                .expect("h3 connect request"),
        )
        .await
        .expect("send h3 connect request");
    let open = seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: echo_port,
        },
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
    )
    .unwrap();
    req_stream
        .send_data(Bytes::from(open))
        .await
        .expect("write h3 connect tunnel request");
    let response = req_stream
        .recv_response()
        .await
        .expect("h3 connect response");
    assert!(response.status().is_success());
    let mut resp_frame = req_stream
        .recv_data()
        .await
        .expect("read h3 connect response body")
        .expect("h3 connect tunnel response");
    let resp_frame = resp_frame.copy_to_bytes(resp_frame.remaining());
    let resp = open_tunnel_response(
        resp_frame.as_ref(),
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
    )
    .unwrap();
    assert_eq!(resp.status, TunnelStatus::Ok);

    req_stream
        .send_data(Bytes::from_static(b"ping"))
        .await
        .expect("write h3 connect payload");
    let mut echoed = req_stream
        .recv_data()
        .await
        .expect("read h3 connect payload")
        .expect("echo payload");
    let echoed = echoed.copy_to_bytes(echoed.remaining());
    assert_eq!(echoed.as_ref(), b"ping");
}

#[tokio::test]
async fn masque_tcp_drains_large_response_after_request_fin() {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let env = TestEnv::start().await;
        eprintln!("MASQUE drain: relay started");
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let target = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            eprintln!(
                "MASQUE drain: target received FIN ({} bytes)",
                request.len()
            );
            assert_eq!(request.len(), expected.len(), "target request length");
            assert!(request == expected, "target request content");
            stream.write_all(&request).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut crypto = env.client_tls_config();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        // Force the relay to observe response backpressure before it queues FIN.
        transport.stream_receive_window(quinn::VarInt::from_u32(64 * 1024));
        client_config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect(env.server_addr().parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        eprintln!("MASQUE drain: QUIC connected");
        let (mut driver, mut sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let driver_task =
            tokio::spawn(async move { futures::future::poll_fn(|cx| driver.poll_close(cx)).await });
        let mut stream = sender
            .send_request(
                http::Request::builder()
                    .method("CONNECT")
                    .uri(format!("https://127.0.0.1:{echo_port}"))
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(Bytes::from(
                seal_tunnel_request(
                    &TunnelRequest {
                        host: "127.0.0.1".into(),
                        port: echo_port,
                    },
                    env.cfg.auth_token.as_bytes(),
                )
                .unwrap(),
            ))
            .await
            .unwrap();
        assert!(stream.recv_response().await.unwrap().status().is_success());
        let mut ack = stream.recv_data().await.unwrap().unwrap();
        let ack = ack.copy_to_bytes(ack.remaining());
        assert_eq!(
            open_tunnel_response(&ack, env.cfg.auth_token.as_bytes())
                .unwrap()
                .status,
            TunnelStatus::Ok
        );
        eprintln!("MASQUE drain: authenticated");
        for chunk in payload.chunks(16 * 1024) {
            stream
                .send_data(Bytes::copy_from_slice(chunk))
                .await
                .unwrap();
        }
        stream.finish().await.unwrap();
        eprintln!("MASQUE drain: request sent");
        let mut received = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                Ok(None) => break,
                Err(error) => panic!(
                    "response ended after {} of {} bytes: {error}",
                    received.len(),
                    payload.len()
                ),
            }
        }
        assert_eq!(
            received.len(),
            payload.len(),
            "complete response before clean EOF"
        );
        assert!(received == payload, "response content");
        target.await.unwrap();
        conn.close(quinn::VarInt::from_u32(0), b"response received");
        driver_task.await.unwrap();
        endpoint.wait_idle().await;
    })
    .await
    .expect("large MASQUE response watchdog");
}

#[tokio::test]
async fn h3_connect_without_pre_auth_data_is_bounded() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start_with_read_timeout(50).await;

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for cert in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(cert.expect("pem cert")).expect("add root");
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));
    let conn = endpoint
        .connect(env.server_addr().parse().unwrap(), "localhost")
        .expect("quic connect start")
        .await
        .expect("quic connect");
    let quic = h3_quinn::Connection::new(conn);
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    let (_h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await.expect("h3 build");
    let request = http::Request::builder()
        .method("CONNECT")
        .uri(format!("https://127.0.0.1:{}", env.target_port))
        .body(())
        .expect("h3 connect request");
    let mut stream = send_request
        .send_request(request)
        .await
        .expect("send h3 connect headers");

    // Deliberately do not send or finish the request DATA. The unauthenticated
    // stream must not pin the shared connection permit beyond read_timeout_ms.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv_response())
        .await
        .expect("server left an unauthenticated h3 CONNECT hanging");
    if let Ok(response) = outcome {
        assert!(
            !response.status().is_success(),
            "missing pre-auth DATA unexpectedly opened a tunnel"
        );
    }
}

#[tokio::test]
async fn idle_h3_connection_cannot_starve_the_shared_tcp_listener() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start_with_limits(50, 1).await;

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for cert in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(cert.expect("pem cert")).expect("add root");
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));

    // Complete QUIC/TLS, then deliberately send no H3 request at all. With a
    // one-permit shared budget this used to starve TCP forever because server
    // keepalives prevented QUIC's idle timeout from firing.
    let _idle_quic = endpoint
        .connect(env.server_addr().parse().unwrap(), "localhost")
        .expect("quic connect start")
        .await
        .expect("quic connect");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let tcp_tls = async {
        let tcp = TcpStream::connect(env.server_addr()).await?;
        env.tls_connector()
            .connect(env.server_name(), tcp)
            .await
            .map(|_| ())
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), tcp_tls)
        .await
        .expect("TCP probe hung after idle H3 timeout")
        .expect("idle H3 connection kept the shared TCP/QUIC permit pinned");
}

#[tokio::test]
async fn connect_udp_tunnel_smoke_with_legacy_credential() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // One shared permit makes a leaked CONNECT-UDP session immediately
    // observable. Keepalives are deliberately shorter than the configured
    // idle bound, reproducing the production condition where transport idle
    // never fires on its own.
    let env = TestEnv::start_with_transport_limits(30_000, 1, 20, 100).await;

    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp echo bind");
    let udp_port = udp_echo.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = udp_echo.recv_from(&mut buf).await else {
                break;
            };
            let _ = udp_echo.send_to(&buf[..n], peer).await;
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for c in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(c.expect("pem cert")).expect("add root");
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(env.server_addr().parse().unwrap(), "localhost")
        .expect("quic connect start")
        .await
        .expect("quic connect");
    let quic = h3_quinn::Connection::new(conn);
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await.expect("h3 build");

    let path = build_connect_udp_path(&env.cfg.transport.masque_path, "127.0.0.1", udp_port)
        .expect("build connect-udp path");
    let mut request = http::Request::builder()
        .method("CONNECT")
        .uri(format!(
            "https://localhost:{}{}",
            reserve_port_from_addr(&env.server_addr()),
            path
        ))
        .header("capsule-protocol", "?1")
        .header(
            http::header::AUTHORIZATION,
            connect_udp_credential(
                "f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
                "127.0.0.1",
                udp_port,
            ),
        )
        .body(())
        .expect("connect-udp request");
    request.extensions_mut().insert(Protocol::CONNECT_UDP);

    let mut req_stream = send_request
        .send_request(request)
        .await
        .expect("send connect-udp request");
    req_stream
        .finish()
        .await
        .expect("finish connect-udp request");
    let response = req_stream
        .recv_response()
        .await
        .expect("connect-udp response");
    assert!(response.status().is_success());

    let stream_id = req_stream.id();
    let mut datagram_sender = h3_conn.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_conn.get_datagram_reader();
    datagram_sender
        .send_datagram(Bytes::from_static(b"\x00ping"))
        .expect("send udp datagram");
    let datagram = datagram_reader
        .read_datagram()
        .await
        .expect("read udp datagram");
    assert_eq!(datagram.stream_id(), stream_id);
    assert_eq!(datagram.into_payload().as_ref(), b"\x00ping");

    // Deliberately keep every client-side H3/QUIC handle alive. The server's
    // CONNECT-UDP application-idle guard must still release the one shared
    // permit, otherwise even an ordinary TCP/TLS connection is starved.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let tcp_tls = async {
        let tcp = TcpStream::connect(env.server_addr()).await?;
        env.tls_connector()
            .connect(env.server_name(), tcp)
            .await
            .map(|_| ())
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), tcp_tls)
        .await
        .expect("TCP probe hung after CONNECT-UDP application idle timeout")
        .expect("idle CONNECT-UDP session kept the shared permit pinned");
}

/// Seal a `TunnelRequest` as the `Authorization: Bearer` credential the relay
/// requires on CONNECT-UDP.
fn connect_udp_credential(auth_token: &str, host: &str, port: u16) -> String {
    let sealed = seal_tunnel_request(
        &TunnelRequest {
            host: host.to_string(),
            port,
        },
        auth_token.as_bytes(),
    )
    .expect("seal connect-udp credential");
    format!("Bearer {}", hex::encode(sealed))
}

// REGRESSION: CONNECT-UDP used to relay datagrams for anyone who knew the
// (compiled-in, public) MASQUE path — an open UDP proxy usable for amplification
// and SSRF, and a one-packet AEGIS oracle for a censor. An unauthenticated or
// wrongly-scoped request must never reach the relay loop, and must be answered with
// the generic web decoy rather than a bare AEGIS error.
#[tokio::test]
async fn connect_udp_without_credential_is_refused() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for c in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(c.expect("pem cert")).expect("add root");
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let path = build_connect_udp_path(&env.cfg.transport.masque_path, "127.0.0.1", 9)
        .expect("build connect-udp path");
    let uri = format!(
        "https://localhost:{}{}",
        reserve_port_from_addr(&env.server_addr()),
        path
    );

    // (label, credential) — every case must be refused.
    let cases = [
        (
            // Keep this before the three authentication failures below: it
            // proves valid credentials remain target-scoped, independently of
            // the rate-limit assertion that follows.
            "credential scoped to another target",
            Some(connect_udp_credential(
                &env.cfg.auth_token,
                "127.0.0.1",
                1234,
            )),
        ),
        ("no credential", None),
        ("garbage credential", Some("Bearer deadbeef".to_string())),
        (
            "credential sealed with the wrong token",
            Some(connect_udp_credential("wrong-token", "127.0.0.1", 9)),
        ),
    ];

    for (label, credential) in cases {
        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
        endpoint.set_default_client_config(client_cfg.clone());
        let conn = endpoint
            .connect(env.server_addr().parse().unwrap(), "localhost")
            .expect("quic connect start")
            .await
            .expect("quic connect");
        let quic = h3_quinn::Connection::new(conn);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (_h3_conn, mut send_request) =
            builder.build::<_, _, Bytes>(quic).await.expect("h3 build");

        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri(uri.clone())
            .header("capsule-protocol", "?1");
        if let Some(credential) = credential {
            request = request.header(http::header::AUTHORIZATION, credential);
        }
        let mut request = request.body(()).expect("connect-udp request");
        request.extensions_mut().insert(Protocol::CONNECT_UDP);

        let mut req_stream = send_request
            .send_request(request)
            .await
            .expect("send connect-udp request");
        let _ = req_stream.finish().await;

        // Refused with a response: it must be the web decoy, never a success that
        // would put the relay loop in front of an unauthenticated peer. Refused by
        // closing the stream instead is equally fine, and indistinguishable from an
        // origin that simply does not serve the path — hence `if let`, not a match
        // with an empty error arm.
        if let Ok(response) = req_stream.recv_response().await {
            assert!(
                !response.status().is_success(),
                "{label}: unauthenticated CONNECT-UDP was accepted ({})",
                response.status()
            );
            let body = format!("{response:?}").to_lowercase();
            for tell in ["aegis", "tunnel", "relay", "token"] {
                assert!(
                    !body.contains(tell),
                    "{label}: response leaked the tell {tell:?}"
                );
            }
        }
    }

    // The three invalid credentials above reach the default limit. A new QUIC
    // connection carrying a genuinely valid credential from the same source
    // must now be dropped. Before the regression fix, direct H3/MASQUE did not
    // participate in the limiter and this request returned 200.
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(env.server_addr().parse().unwrap(), "localhost")
        .expect("quic connect start")
        .await
        .expect("quic connect");
    let quic = h3_quinn::Connection::new(conn);
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (_h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await.expect("h3 build");
    let mut request = http::Request::builder()
        .method("CONNECT")
        .uri(uri)
        .header("capsule-protocol", "?1")
        .header(
            http::header::AUTHORIZATION,
            connect_udp_credential(&env.cfg.auth_token, "127.0.0.1", 9),
        )
        .body(())
        .expect("connect-udp request after ban");
    request.extensions_mut().insert(Protocol::CONNECT_UDP);
    let banned_outcome = match send_request.send_request(request).await {
        Ok(mut stream) => {
            let _ = stream.finish().await;
            stream.recv_response().await.ok()
        }
        Err(_) => None,
    };
    assert!(
        banned_outcome.is_none(),
        "valid CONNECT-UDP unexpectedly succeeded after the source exhausted its auth budget: {banned_outcome:?}"
    );
}

// Active-probing hardening: a plain h3 request (a browser-shaped GET) to the
// QUIC/MASQUE endpoint — the vector an active prober scanning the origin's
// UDP/443 would use — must look like an ordinary h3 web origin, not leak a bare
// AEGIS status. The response must come from the shared decoy deck (web-like
// status + a plausible Server header + no AEGIS/relay/tunnel/token tell).
#[tokio::test]
async fn h3_probe_request_gets_web_decoy_not_bare_status() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = TestEnv::start().await;

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&env.cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for c in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(c.expect("pem cert")).expect("add root");
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic cfg");
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(env.server_addr().parse().unwrap(), "localhost")
        .expect("quic connect start")
        .await
        .expect("quic connect");
    let quic = h3_quinn::Connection::new(conn);
    let (mut conn_driver, mut send_request) = h3::client::builder()
        .build::<_, _, Bytes>(quic)
        .await
        .expect("h3 build");
    // The h3 client connection must be driven concurrently or the request
    // stream cannot make progress; without it recv_response races the server's
    // benign post-decoy close.
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| conn_driver.poll_close(cx)).await });

    // A plain GET, exactly as a scanner probing an https/h3 endpoint would send.
    let request = http::Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/",
            reserve_port_from_addr(&env.server_addr())
        ))
        .body(())
        .expect("get request");
    let mut req_stream = send_request.send_request(request).await.expect("send get");
    req_stream.finish().await.expect("finish get");
    let response = req_stream.recv_response().await.expect("get response");

    // Web-like status from the decoy deck — never a bare AEGIS 400.
    let status = response.status().as_u16();
    assert!(
        matches!(status, 403 | 404 | 410),
        "h3 probe must get a stock web status, got {status}"
    );
    assert_ne!(status, 400, "bare 400 is the pre-decoy AEGIS tell");
    let server = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ["nginx", "Apache", "openresty", "Caddy"]
            .iter()
            .any(|s| server.starts_with(s)),
        "decoy must advertise a plausible origin Server, got {server:?}"
    );

    // Body (if any) must carry no AEGIS/relay/tunnel/token tell. Tolerant of the
    // benign connection teardown after the server finishes the decoy stream.
    let mut body = Vec::new();
    while let Ok(Some(mut chunk)) = req_stream.recv_data().await {
        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
    let body = String::from_utf8_lossy(&body).to_lowercase();
    for tell in ["aegis", "relay", "tunnel", "token"] {
        assert!(!body.contains(tell), "h3 decoy body leaked a tell: {tell}");
    }
    driver.abort();
}

struct TestEnv {
    _dir: tempfile::TempDir,
    cfg: aegis_server::config::ServerConfig,
    cert_path: std::path::PathBuf,
    target_port: u16,
}

impl TestEnv {
    async fn start() -> Self {
        Self::start_with_read_timeout(30_000).await
    }

    async fn start_with_read_timeout(read_timeout_ms: u64) -> Self {
        Self::start_with_limits(read_timeout_ms, 1_000).await
    }

    async fn start_with_limits(read_timeout_ms: u64, max_connections: usize) -> Self {
        let transport = aegis_server::config::TransportConfig::default();
        Self::start_with_transport(read_timeout_ms, max_connections, transport).await
    }

    async fn start_with_transport_limits(
        read_timeout_ms: u64,
        max_connections: usize,
        quic_keep_alive_interval_ms: u64,
        quic_max_idle_timeout_ms: u64,
    ) -> Self {
        let transport = aegis_server::config::TransportConfig {
            quic_keep_alive_interval_ms,
            quic_max_idle_timeout_ms,
            ..Default::default()
        };
        Self::start_with_transport(read_timeout_ms, max_connections, transport).await
    }

    async fn start_with_transport(
        read_timeout_ms: u64,
        max_connections: usize,
        transport: aegis_server::config::TransportConfig,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        #[cfg(not(windows))]
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(
            &key_path,
            key_pair.serialize_pem().as_bytes(),
            false,
        )
        .expect("write private fixture key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let dummy = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("dummy bind");
        let target_port = dummy.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let _ = dummy.accept().await;
            }
        });

        let tcp_port = reserve_port();
        let mut cfg = aegis_server::config::ServerConfig {
            listen: format!("127.0.0.1:{tcp_port}"),
            cert: cert_path.clone(),
            key: key_path,
            auth_token: "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into(),
            legacy_auth_tokens: vec![aegis_server::config::LegacyAuthTokenConfig {
                id: "legacy-test".into(),
                auth_token: "f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca"
                    .into(),
                not_after_unix_secs: u64::MAX,
            }],
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: aegis_server::config::TargetPolicyConfig {
                profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
                allowed_ports: Vec::new(),
            },
            transport,
            bundle_endpoint: Default::default(),
        };
        cfg.limits.read_timeout_ms = read_timeout_ms;
        cfg.limits.max_connections = max_connections;
        let server_cfg = cfg.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            aegis_server::run_server_with_ready(server_cfg, Some(ready_tx))
                .await
                .expect("fixture relay runtime");
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
            .await
            .expect("fixture relay readiness deadline")
            .expect("fixture relay listener readiness");

        Self {
            _dir: dir,
            cfg,
            cert_path,
            target_port,
        }
    }

    fn server_addr(&self) -> String {
        self.cfg.listen.clone()
    }

    fn client_tls_config(&self) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        let pem = std::fs::read(&self.cert_path).expect("read cert");
        let mut rd = std::io::BufReader::new(pem.as_slice());
        for c in CertificateDer::pem_reader_iter(&mut rd) {
            roots.add(c.expect("pem cert")).expect("add root");
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn tls_connector(&self) -> TlsConnector {
        TlsConnector::from(Arc::new(self.client_tls_config()))
    }

    fn server_name(&self) -> ServerName<'static> {
        "localhost".to_string().try_into().expect("dns")
    }
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn reserve_port_from_addr(addr: &str) -> u16 {
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .expect("socket addr port")
}

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

async fn read_grpc_message(
    recv: &mut h2::RecvStream,
    pending: &mut Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        if pending.len() >= 5 {
            let len = u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
            if pending.len() >= 5 + len {
                let payload = pending[5..5 + len].to_vec();
                pending.drain(..5 + len);
                return Ok(Some(payload));
            }
        }
        let Some(chunk) = recv.data().await else {
            return Ok(None);
        };
        let chunk = chunk?;
        let chunk_len = chunk.len();
        pending.extend_from_slice(&chunk);
        recv.flow_control().release_capacity(chunk_len)?;
    }
}
