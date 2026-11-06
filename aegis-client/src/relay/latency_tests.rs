//! Real owner timing witness: TLS control authentication, data and held lifetime.
use super::*;
use aegis_core::tunnel::TunnelResponse;
#[cfg(not(feature = "legacy-challenge-v1"))]
use aegis_core::tunnel::{
    encode_stream_frame, open_tunnel_request, read_stream_frame, seal_tunnel_response,
    MAX_TUNNEL_CONTROL_FRAME,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FIRST_UPLOAD: &[u8] = b"latency-initial-upload";
const FIRST_REPLY: &[u8] = b"latency-initial-response";
const LATE_UPLOAD: &[u8] = b"latency-late-upload";
const LATE_REPLY: &[u8] = b"latency-late-response";

pub(crate) struct ActualTimingWitness {
    pub(crate) outcome: RelayOutcome,
    pub(crate) first_reply_upper: Duration,
}

/// No spawned child can outlive cancellation: join owns the actual owner,
/// synthetic relay and application futures under one fixed eighteen-second cap.
pub(crate) async fn actual_held_relay_outcome() -> ActualTimingWitness {
    tokio::time::timeout(Duration::from_secs(18), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        tls_backend::load_roots(None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, cert.pem()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let settings = RelaySettings {
            server: listener.local_addr().unwrap().to_string(),
            server_name: "localhost".into(),
            auth_token: "synthetic-latency-control-only".into(),
            ca_cert: Some(ca),
            tls_backend: aegis_core::RelayTlsBackend::Rustls,
            transport_priority: vec![TunnelTransportFamily::LegacyTls],
            ..Default::default()
        };
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (app, local) = tokio::join!(
            TcpStream::connect(local_listener.local_addr().unwrap()),
            local_listener.accept()
        );
        let mut app = app.unwrap();
        let (local, _) = local.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let witness_started = Instant::now();
        let owner = run_relay_tunnel(
            local,
            &settings,
            "latency.fixture.invalid".into(),
            443,
            None,
            None,
            Some(&tx),
        );
        let peer = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            #[cfg(not(feature = "legacy-challenge-v1"))]
            {
                let frame = read_stream_frame(&mut tls, MAX_TUNNEL_CONTROL_FRAME)
                    .await
                    .unwrap();
                let request = open_tunnel_request(&frame, settings.auth_token.as_bytes()).unwrap();
                assert_eq!(request.host, "latency.fixture.invalid");
                assert_eq!(request.port, 443);
                let ack = seal_tunnel_response(
                    &TunnelResponse {
                        status: TunnelStatus::Ok,
                        message: String::new(),
                    },
                    settings.auth_token.as_bytes(),
                )
                .unwrap();
                tls.write_all(&encode_stream_frame(&ack)).await.unwrap();
            }
            #[cfg(feature = "legacy-challenge-v1")]
            {
                use aegis_core::tunnel::fresh_legacy::{admit_raw, KeyCandidate};
                let authority = ();
                let keys = [KeyCandidate {
                    authority: &authority,
                    secret: settings.auth_token.as_bytes(),
                    expires: None,
                }];
                let admitted = admit_raw(
                    &mut tls,
                    &keys,
                    tokio::time::Instant::now() + Duration::from_secs(18),
                    Duration::from_secs(18),
                    |_| true,
                    |request, _| async move {
                        assert_eq!(request.host, "latency.fixture.invalid");
                        assert_eq!(request.port, 443);
                        Ok((
                            Some(()),
                            TunnelResponse {
                                status: TunnelStatus::Ok,
                                message: String::new(),
                            },
                        ))
                    },
                )
                .await
                .unwrap();
                assert_eq!(admitted, Some(()), "fresh proof and bound Ok Final");
            }
            let mut initial = vec![0; FIRST_UPLOAD.len()];
            tls.read_exact(&mut initial).await.unwrap();
            assert_eq!(initial, FIRST_UPLOAD);
            tls.write_all(FIRST_REPLY).await.unwrap();
            let mut late = vec![0; LATE_UPLOAD.len()];
            tls.read_exact(&mut late).await.unwrap();
            assert_eq!(late, LATE_UPLOAD);
            tls.write_all(LATE_REPLY).await.unwrap();
            let mut extra = Vec::new();
            tls.read_to_end(&mut extra).await.unwrap();
            assert!(
                extra.is_empty(),
                "each upload occurs exactly once; no replay"
            );
            tls.shutdown().await.unwrap();
        };
        let application = async {
            app.write_all(FIRST_UPLOAD).await.unwrap();
            let mut initial = vec![0; FIRST_REPLY.len()];
            app.read_exact(&mut initial).await.unwrap();
            assert_eq!(initial, FIRST_REPLY);
            let upper = witness_started.elapsed();
            let hold = upper + Duration::from_millis(100);
            assert!(
                upper + hold < Duration::from_secs(10),
                "bounded setup too slow for causal hold"
            );
            tokio::time::sleep(hold).await;
            app.write_all(LATE_UPLOAD).await.unwrap();
            app.shutdown().await.unwrap();
            let mut late = Vec::new();
            app.read_to_end(&mut late).await.unwrap();
            assert_eq!(
                late, LATE_REPLY,
                "late data and independent half-close survive the hold"
            );
            upper
        };
        let (result, (), first_reply_upper) = tokio::join!(owner, peer, application);
        result.unwrap();
        drop(tx);
        let outcome = rx.recv().await.expect("actual owner emits its outcome");
        assert!(rx.recv().await.is_none(), "one real attempt only");
        assert_eq!(outcome.transport, TunnelTransportFamily::LegacyTls);
        assert_eq!(outcome.signal, aegis_core::signals::FailSignal::Success);
        assert_eq!(
            outcome.bytes_sent,
            (FIRST_UPLOAD.len() + LATE_UPLOAD.len()) as u64
        );
        assert_eq!(
            outcome.bytes_received_observed,
            (FIRST_REPLY.len() + LATE_REPLY.len()) as u64
        );
        ActualTimingWitness {
            outcome,
            first_reply_upper,
        }
    })
    .await
    .expect("original eighteen-second fixture bound")
}
