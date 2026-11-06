use super::{connect_tls, local_session_pre_open_aborted, policy, relay_transport_authority};
use aegis_core::tunnel::{
    open_tunnel_response, seal_tunnel_datagram_request, seal_tunnel_request, TunnelRequest,
    TunnelStatus,
};
use aegis_core::RelaySettings;
use anyhow::Context;
use bytes::Bytes;
use http::{Request, Uri};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::socks5::{ConnectTarget, UdpPacket};

fn chrome_h2_protocol() -> &'static [u8] {
    aegis_chrome_profile::chrome_stable()
        .tls
        .alpn_h2
        .first()
        .expect("chrome profile h2 alpn")
        .as_bytes()
}

#[cfg(test)]
mod diagnostics;

/// Bound on a single inbound gRPC message from the relay.
///
/// Besides matching the server-side contract, this prevents a compromised or
/// malformed relay from making the client buffer toward the 4 GiB limit of the
/// gRPC length prefix before a complete frame is available.
const MAX_GRPC_MESSAGE_BYTES: usize = 1024 * 1024;

/// Static diagnostic state only: no endpoint, target, credentials or payload.
/// TLS setup includes synchronous trust preparation, which Tokio cannot preempt.
#[derive(Clone, Copy)]
enum EstablishmentStage {
    TcpDial,
    TlsSetup,
    H2Handshake,
    OpenWrite,
    ResponseHeaders,
    OpenAck,
}

impl EstablishmentStage {
    fn code(self) -> &'static str {
        match self {
            Self::TcpDial => "tcp_dial",
            Self::TlsSetup => "tls_setup",
            Self::H2Handshake => "h2_handshake",
            Self::OpenWrite => "open_write",
            Self::ResponseHeaders => "response_headers",
            Self::OpenAck => "open_ack",
        }
    }
}

/// A stream owns its H2 driver, including while establishment is pending.
/// Dropping a timed-out/cancelled attempt must also close its relay connection.
struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl AbortOnDrop {
    fn new(handle: tokio::task::AbortHandle) -> Self {
        Self(Some(handle))
    }

    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

fn benign_h2_close(err: &anyhow::Error) -> bool {
    if super::benign_io_close(err) {
        return true;
    }
    err.chain().any(|cause| {
        if let Some(h2_err) = cause.downcast_ref::<h2::Error>() {
            return h2_err
                .reason()
                .map(|reason| {
                    matches!(
                        reason,
                        h2::Reason::NO_ERROR | h2::Reason::CANCEL | h2::Reason::STREAM_CLOSED
                    )
                })
                .unwrap_or(false);
        }
        false
    })
}

pub async fn run_grpc_tunnel(
    local: &mut TcpStream,
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    target_host: String,
    target_port: u16,
    initial_payload: Option<&[u8]>,
    counters: &super::RelaySessionCounters,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    let local_fd = local.as_raw_fd();
    // One budget covers the entire establishment, not just the TCP dial. The
    // application payload and long-lived relay loop deliberately stay outside
    // this deadline, and nothing can replay payload before the open is accepted.
    let mut establishment_stage = EstablishmentStage::TcpDial;
    #[cfg(test)]
    let witness = diagnostics::Witness::default();
    let opened = tokio::time::timeout(
        std::time::Duration::from_millis(settings.connect_timeout_ms),
        async {
            let tcp = super::geneva_outer::connect(settings)
                .await
                .with_context(|| format!("connect grpc relay {}", settings.server))?;
            super::apply_soft_wire_plan_to_stream(
                &tcp,
                settings,
                Some((target_host.as_str(), target_port)),
            );
            let authority = relay_transport_authority(settings)?;
            establishment_stage = EstablishmentStage::TlsSetup;
            #[cfg(test)]
            let tls = super::tls_backend::connect_tls_with_wire_witness(
                settings,
                tcp,
                authority.tls_server_name,
                &authority.authority_host,
                Some(chrome_h2_protocol()),
                authority.send_sni,
                witness.wire_io(),
            )
            .await?;

            #[cfg(not(test))]
            let tls = connect_tls(
                settings,
                tcp,
                authority.tls_server_name,
                &authority.authority_host,
                Some(chrome_h2_protocol()),
                authority.send_sni,
            )
            .await?;

            // Only ordinary tests collect local TLS application-I/O metadata.
            // This does not observe encrypted socket bytes or peer ACKs.
            #[cfg(test)]
            let tls = witness.observe_io(tls);
            establishment_stage = EstablishmentStage::H2Handshake;
            let (mut client, connection) = super::surface::chrome_like_h2_builder()
                .handshake(tls)
                .await
                .context("h2 handshake")?;
            #[cfg(test)]
            let connection = witness.observe(connection);
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let driver = AbortOnDrop::new(driver.abort_handle());

            let uri = grpc_request_uri(&authority.authority_host, &profile.grpc_path)?;
            let mut req = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(())?;
            super::apply_grpc_request_shape_headers(req.headers_mut(), profile)?;
            let (response_fut, mut send_stream) = client.send_request(req, false)?;
            #[cfg(test)]
            witness.request_queued();

            if local_session_pre_open_aborted(local, initial_payload) {
                return Ok(None);
            }

            establishment_stage = EstablishmentStage::OpenWrite;
            let open = seal_tunnel_request(
                &TunnelRequest {
                    host: target_host,
                    port: target_port,
                },
                settings.auth_token.as_bytes(),
            )?;
            if let Err(err) = send_stream
                .send_data(grpc_frame(&open), false)
                .context("send grpc tunnel request")
            {
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }
            #[cfg(test)]
            witness.open_queued();

            if local_session_pre_open_aborted(local, initial_payload) {
                return Ok(None);
            }

            establishment_stage = EstablishmentStage::ResponseHeaders;
            let response = match response_fut.await.context("grpc response headers") {
                Ok(response) => {
                    #[cfg(test)]
                    witness.headers_received();
                    response
                }
                Err(err) => {
                    #[cfg(test)]
                    witness.headers_error();
                    if local_session_pre_open_aborted(local, initial_payload) {
                        return Ok(None);
                    }
                    return Err(err);
                }
            };
            if !response.status().is_success() {
                anyhow::bail!("grpc status {}", response.status());
            }
            let mut recv_stream = response.into_body();
            let mut recv_buf = Vec::new();
            establishment_stage = EstablishmentStage::OpenAck;
            let resp_frame = read_grpc_message(&mut recv_stream, &mut recv_buf)
                .await?
                .ok_or_else(|| anyhow::anyhow!("grpc closed before tunnel response"));
            let resp_frame = match resp_frame {
                Ok(resp_frame) => resp_frame,
                Err(err) => {
                    if local_session_pre_open_aborted(local, initial_payload) {
                        return Ok(None);
                    }
                    return Err(err);
                }
            };
            let resp = open_tunnel_response(&resp_frame, settings.auth_token.as_bytes())?;
            if resp.status != TunnelStatus::Ok {
                return Err(super::tunnel_response_error(
                    "grpc tunnel error",
                    resp.status,
                    resp.message,
                ));
            }
            anyhow::Ok(Some((send_stream, recv_stream, recv_buf, driver)))
        },
    )
    .await
    .with_context(|| {
        let message = format!(
            "grpc tunnel establishment timed out after {}ms (stage={})",
            settings.connect_timeout_ms,
            establishment_stage.code()
        );
        #[cfg(test)]
        let message = format!("{message}; {}", witness.snapshot());
        message
    })?;
    #[cfg(test)]
    let opened = opened.map_err(|err| err.context(witness.snapshot()));
    let opened = opened?;
    let Some((mut send_stream, mut recv_stream, mut recv_buf, mut driver)) = opened else {
        return Ok(());
    };
    counters.mark_opened();
    if let Some(payload) = initial_payload.filter(|payload| !payload.is_empty()) {
        if let Err(err) = send_stream.send_data(grpc_frame(payload), false) {
            let err = anyhow::Error::from(err);
            if benign_h2_close(&err) {
                return Ok(());
            }
            return Err(err);
        }
        policy::maybe_delay(profile).await;
    }

    let (mut local_read, mut local_write) = tokio::io::split(local);
    let client_to_grpc = async {
        let mut buf = vec![0u8; policy::write_chunk_size(profile)];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                if let Err(err) = send_stream.send_data(Bytes::new(), true) {
                    let err = anyhow::Error::from(err);
                    if !benign_h2_close(&err) {
                        return Err(err);
                    }
                }
                break;
            }
            counters.add_sent(n);
            if let Err(err) = send_stream.send_data(grpc_frame(&buf[..n]), false) {
                let err = anyhow::Error::from(err);
                if benign_h2_close(&err) {
                    break;
                }
                return Err(err);
            }
            policy::maybe_delay(profile).await;
        }
        anyhow::Ok(())
    };
    let grpc_to_client = async {
        loop {
            let chunk = match read_grpc_message(&mut recv_stream, &mut recv_buf).await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(err) => {
                    if benign_h2_close(&err) {
                        break;
                    }
                    return Err(err);
                }
            };
            counters.add_received(chunk.len());
            if let Err(err) = local_write.write_all(&chunk).await {
                #[cfg(unix)]
                if super::local_session_aborted_fd(local_fd) {
                    return Ok(());
                }
                return Err(err.into());
            }
        }
        anyhow::Ok(())
    };
    tokio::try_join!(client_to_grpc, grpc_to_client)?;
    // send_data queues frames. A normally completed tunnel must let the H2
    // driver flush its final DATA/END_STREAM after these stream handles drop.
    driver.disarm();
    Ok(())
}

/// Send one UDP datagram through a gRPC/H2 stream and return the first reply.
/// Only failures before application payload commitment are safe to fail over.
pub async fn run_grpc_udp_datagram_once(
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    target: ConnectTarget,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(settings.connect_timeout_ms);
    anyhow::ensure!(
        payload.len() <= u16::MAX as usize,
        "UDP datagram too large: {} bytes",
        payload.len()
    );
    let (mut send_stream, mut recv_stream, mut recv_buf, mut driver) =
        open_grpc_datagram_session(settings, profile, &target, deadline).await?;
    let result = async {
        send_grpc_message(&mut send_stream, payload, false)
            .await
            .context("send grpc UDP datagram")?;
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(settings.connect_timeout_ms),
            read_grpc_message(&mut recv_stream, &mut recv_buf),
        )
        .await
        .with_context(|| {
            format!(
                "grpc UDP response timed out after {}ms",
                settings.connect_timeout_ms
            )
        })??
        .ok_or_else(|| anyhow::anyhow!("grpc closed before UDP response"))?;
        let _ = send_stream.send_data(Bytes::new(), true);
        anyhow::Ok(response)
    }
    .await
    .map_err(super::udp_payload_committed);
    if result.is_ok() {
        driver.disarm();
    }
    result
}

/// Persistent message-preserving UDP flow over the fronted gRPC endpoint.
/// A borrowed receiver lets the caller retry the same logical flow on the
/// next transport only while no application datagram has been consumed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub async fn run_grpc_udp_flow(
    settings: &RelaySettings,
    target_host: &str,
    target_port: u16,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    incoming_tx: &mpsc::Sender<UdpPacket>,
) -> anyhow::Result<()> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(settings.connect_timeout_ms);
    let profile = policy::build_session_profile_with_brain_bias(
        settings,
        Some((target_host, target_port)),
        Default::default(),
    );
    let target = ConnectTarget {
        host: target_host.to_string(),
        port: target_port,
    };
    let (mut send_stream, mut recv_stream, mut recv_buf, mut driver) =
        open_grpc_datagram_session(settings, &profile, &target, deadline).await?;

    let mut payload_committed = false;
    let result = async {
        loop {
            tokio::select! {
                outbound = outbound_rx.recv() => {
                    let Some(payload) = outbound else {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        break;
                    };
                    // Receiving consumes this datagram even if validation or the
                    // subsequent send fails. The caller must not replay the flow.
                    payload_committed = true;
                    anyhow::ensure!(
                        payload.len() <= u16::MAX as usize,
                        "UDP datagram too large: {} bytes",
                        payload.len()
                    );
                    send_grpc_message(&mut send_stream, &payload, false)
                        .await
                        .context("send grpc UDP datagram")?;
                }
                incoming = read_grpc_message(&mut recv_stream, &mut recv_buf) => {
                    let payload = match incoming {
                        Ok(Some(payload)) => payload,
                        Ok(None) => break,
                        Err(err) if benign_h2_close(&err) => break,
                        Err(err) => return Err(err),
                    };
                    if incoming_tx.send(UdpPacket {
                        target: target.clone(),
                        payload,
                    }).await.is_err() {
                        break;
                    }
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            // Preserve queued final DATA/END_STREAM on graceful channel close.
            driver.disarm();
            Ok(())
        }
        Err(err) if payload_committed => Err(super::udp_payload_committed(err)),
        Err(err) => Err(err),
    }
}

async fn open_grpc_datagram_session(
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    target: &ConnectTarget,
    deadline: tokio::time::Instant,
) -> anyhow::Result<(h2::SendStream<Bytes>, h2::RecvStream, Vec<u8>, AbortOnDrop)> {
    let mut establishment_stage = EstablishmentStage::TcpDial;
    tokio::time::timeout_at(deadline, async {
        let tcp = super::geneva_outer::connect(settings)
            .await
            .with_context(|| format!("connect grpc relay {}", settings.server))?;
        super::apply_soft_wire_plan_to_stream(
            &tcp,
            settings,
            Some((target.host.as_str(), target.port)),
        );
        let authority = relay_transport_authority(settings)?;
        establishment_stage = EstablishmentStage::TlsSetup;
        let tls = connect_tls(
            settings,
            tcp,
            authority.tls_server_name,
            &authority.authority_host,
            Some(chrome_h2_protocol()),
            authority.send_sni,
        )
        .await?;
        establishment_stage = EstablishmentStage::H2Handshake;
        let (mut client, connection) = super::surface::chrome_like_h2_builder()
            .handshake(tls)
            .await
            .context("h2 handshake")?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let driver = AbortOnDrop::new(driver.abort_handle());

        let uri = grpc_request_uri(&authority.authority_host, &profile.grpc_path)?;
        let mut req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())?;
        super::apply_grpc_request_shape_headers(req.headers_mut(), profile)?;
        let (response_fut, mut send_stream) = client.send_request(req, false)?;
        establishment_stage = EstablishmentStage::OpenWrite;
        let open = seal_tunnel_datagram_request(
            &TunnelRequest {
                host: target.host.clone(),
                port: target.port,
            },
            settings.auth_token.as_bytes(),
        )?;
        send_grpc_message(&mut send_stream, &open, false).await?;

        establishment_stage = EstablishmentStage::ResponseHeaders;
        let response = response_fut
            .await
            .context("grpc datagram response headers")?;
        if !response.status().is_success() {
            anyhow::bail!("grpc datagram status {}", response.status());
        }
        let mut recv_stream = response.into_body();
        let mut recv_buf = Vec::new();
        establishment_stage = EstablishmentStage::OpenAck;
        let resp_frame = read_grpc_message(&mut recv_stream, &mut recv_buf)
            .await?
            .ok_or_else(|| anyhow::anyhow!("grpc closed before datagram tunnel response"))?;
        let resp = open_tunnel_response(&resp_frame, settings.auth_token.as_bytes())?;
        if resp.status != TunnelStatus::Ok {
            return Err(super::tunnel_response_error(
                "grpc datagram tunnel error",
                resp.status,
                resp.message,
            ));
        }
        anyhow::Ok((send_stream, recv_stream, recv_buf, driver))
    })
    .await
    .with_context(|| {
        format!(
            "grpc datagram establishment timed out after {}ms (stage={})",
            settings.connect_timeout_ms,
            establishment_stage.code()
        )
    })?
}

fn grpc_request_uri(authority_host: &str, path: &str) -> anyhow::Result<Uri> {
    anyhow::ensure!(path.starts_with('/'), "grpc path must be absolute");
    let uri = format!("https://{authority_host}{path}");
    uri.parse::<Uri>().context("build grpc request uri")
}

/// Send one complete gRPC message without relying on h2's unbounded implicit
/// buffering. The gRPC frame may span several HTTP/2 DATA frames; the receiver
/// reassembles those bytes before exposing the single datagram.
async fn send_grpc_message(
    send: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_of_stream: bool,
) -> anyhow::Result<()> {
    let frame = grpc_frame(payload);
    send.reserve_capacity(frame.len());
    let mut offset = 0;
    while offset < frame.len() {
        // Always poll instead of sampling `capacity()`: poll_capacity registers
        // the wake-up needed after the current HTTP/2 window is exhausted.
        // Treat a zero grant as Pending while keeping the reservation intact.
        let capacity = std::future::poll_fn(|cx| match send.poll_capacity(cx) {
            std::task::Poll::Ready(Some(Ok(0))) => std::task::Poll::Pending,
            other => other,
        })
        .await
        .ok_or_else(|| anyhow::anyhow!("grpc send stream closed while awaiting capacity"))??;
        let len = capacity.min(frame.len() - offset);
        let last = offset + len == frame.len();
        send.send_data(frame.slice(offset..offset + len), end_of_stream && last)
            .context("send grpc message data")?;
        offset += len;
    }
    Ok(())
}

pub(crate) fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

pub(crate) async fn read_grpc_message(
    recv: &mut h2::RecvStream,
    pending: &mut Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        if pending.len() >= 5 {
            let len = u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
            if len > MAX_GRPC_MESSAGE_BYTES {
                anyhow::bail!(
                    "grpc message length {len} exceeds {MAX_GRPC_MESSAGE_BYTES}-byte limit"
                );
            }
            if pending.len() >= 5 + len {
                let payload = pending[5..5 + len].to_vec();
                pending.drain(..5 + len);
                return Ok(Some(payload));
            }
        }

        let Some(chunk) = recv.data().await else {
            if !pending.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete gRPC message at END_STREAM",
                )
                .into());
            }
            return Ok(None);
        };
        let chunk = chunk.context("grpc data frame")?;
        let chunk_len = chunk.len();
        pending.extend_from_slice(&chunk);
        // `h2` does not automatically return receive-window capacity when the
        // application copies a DATA chunk. Without this release the relay can
        // deliver only one default HTTP/2 window (~64 KiB); larger downloads
        // then stall until the CDN resets the otherwise healthy stream.
        recv.flow_control()
            .release_capacity(chunk_len)
            .context("release h2 receive window")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::tunnel::{open_tunnel_request, seal_tunnel_response, TunnelResponse};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    const TEST_WATCHDOG: Duration = Duration::from_secs(15);
    // This is a network-stage budget after fixture preparation, not a cold OS
    // trust-store benchmark. Every test still requires its intended stage and
    // the same single production deadline.
    const TEST_OPEN_TIMEOUT_MS: u64 = 3_000;
    const TEST_INITIAL_PAYLOAD: &[u8] = b"initial loopback message";
    const TEST_LATE_PAYLOAD: &[u8] = b"message after establishment deadline";

    struct LoopbackRelay {
        listener: TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
        settings: RelaySettings,
        cert_path: PathBuf,
    }

    impl LoopbackRelay {
        async fn new() -> Self {
            use std::io::Write as _;

            // A cold macOS keychain enumeration can exceed the short network
            // fixture budget before the peer reaches TLS/H2. Prepare it once
            // outside the measured opening. The real connect path still loads
            // roots and verifies the fixture certificate normally; there is no
            // mock trust store or production timeout change. Cold synchronous
            // OS operations remain a separate, non-preemptible boundary.
            static PREPARE_NATIVE_ROOTS: std::sync::Once = std::sync::Once::new();
            PREPARE_NATIVE_ROOTS.call_once(|| {
                drop(super::super::tls_backend::load_roots(None).expect("prepare native trust"));
            });

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("relay bind");
            let _ = rustls::crypto::ring::default_provider().install_default();
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("test cert");
            let cert_path = std::env::temp_dir().join(format!(
                "aegis-grpc-open-{}-{:016x}.pem",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cert_path)
                .expect("create test CA")
                .write_all(cert.pem().as_bytes())
                .expect("write test CA");
            let mut tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
                )
                .expect("server TLS config");
            tls.alpn_protocols = vec![b"h2".to_vec()];
            let settings = RelaySettings {
                server: listener.local_addr().expect("relay address").to_string(),
                server_name: "localhost".into(),
                auth_token: "loopback-grpc-test-token".into(),
                ca_cert: Some(cert_path.clone()),
                connect_timeout_ms: TEST_OPEN_TIMEOUT_MS,
                tls_backend: aegis_core::RelayTlsBackend::Rustls,
                ..Default::default()
            };
            Self {
                listener,
                acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
                settings,
                cert_path,
            }
        }

        async fn serve_stalled(
            &self,
            stage: StalledStage,
            ready: oneshot::Sender<()>,
            datagram: bool,
            pre_headers_delay: Duration,
        ) {
            let (mut tcp, _) = self.listener.accept().await.expect("accept relay TCP");
            if matches!(stage, StalledStage::Tls) {
                tcp.read_exact(&mut [0]).await.expect("receive TLS hello");
                ready.send(()).expect("TLS stage receiver");
                // A cancelled TLS handshake must close the actual connection.
                tokio::io::copy(&mut tcp, &mut tokio::io::sink())
                    .await
                    .expect("TLS peer observes close");
                return;
            }
            let mut tls = self.acceptor.accept(tcp).await.expect("accept relay TLS");
            if matches!(stage, StalledStage::H2) {
                tls.read_exact(&mut [0]).await.expect("receive H2 preface");
                ready.send(()).expect("H2 stage receiver");
                // An aborted H2 driver may omit TLS close_notify; either EOF
                // or a TLS truncation error proves the socket was released.
                let _ = tokio::io::copy(&mut tls, &mut tokio::io::sink()).await;
                return;
            }
            let mut connection = h2::server::handshake(tls).await.expect("server H2");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("request present")
                .expect("request accepted");
            let session = async {
                let mut recv = request.into_body();
                let mut pending = Vec::new();
                let open = read_grpc_message(&mut recv, &mut pending)
                    .await
                    .expect("read open")
                    .expect("open present");
                let opened = aegis_core::tunnel::open_tunnel_request_with_kind(
                    &open,
                    self.settings.auth_token.as_bytes(),
                )
                .expect("valid typed open");
                assert_eq!(opened.request.host, "127.0.0.1");
                assert_eq!(
                    opened.kind,
                    if datagram {
                        aegis_core::tunnel::TunnelRequestKind::Datagram
                    } else {
                        aegis_core::tunnel::TunnelRequestKind::Stream
                    }
                );
                tokio::time::sleep(pre_headers_delay).await;
                let _send = if matches!(stage, StalledStage::OpenAck) {
                    Some(
                        respond
                            .send_response(http::Response::new(()), false)
                            .expect("send response headers"),
                    )
                } else {
                    None
                };
                ready.send(()).expect("open stage receiver");
                // The only pre-ack message is the open request, never the
                // supplied application payload. Wait for cancellation/EOF.
                assert!(!matches!(
                    read_grpc_message(&mut recv, &mut pending).await,
                    Ok(Some(_))
                ));
            };
            tokio::pin!(session);
            tokio::select! {
                () = &mut session => {
                    let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
                }
                _ = std::future::poll_fn(|cx| connection.poll_closed(cx)) => {
                    // Drain any buffered DATA even if the driver noticed EOF
                    // first, so a pre-ack payload cannot escape the assertion.
                    session.await;
                }
            }
        }
    }

    impl Drop for LoopbackRelay {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.cert_path);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum StalledStage {
        Tls,
        H2,
        Headers,
        OpenAck,
    }

    fn expected_timeout_stage(stage: StalledStage) -> &'static str {
        match stage {
            StalledStage::Tls => "tls_setup",
            // The client handshake writes its preface without waiting for
            // peer SETTINGS; both silent H2 and withheld headers wait here.
            StalledStage::H2 | StalledStage::Headers => "response_headers",
            StalledStage::OpenAck => "open_ack",
        }
    }

    fn test_profile() -> policy::RelaySessionProfile {
        policy::RelaySessionProfile {
            grpc_path: "/loopback.Tunnel/Open".into(),
            user_agent: "loopback-test",
            accept_header: "*/*",
            write_chunk_size: 4096,
            ..Default::default()
        }
    }

    async fn local_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("local bind");
        let peer = TcpStream::connect(listener.local_addr().expect("local address"))
            .await
            .expect("connect local");
        let (local, _) = listener.accept().await.expect("accept local");
        (local, peer)
    }

    async fn assert_stalled_setup(stage: StalledStage, cancel: bool) {
        tokio::time::timeout(TEST_WATCHDOG, async {
            let relay = LoopbackRelay::new().await;
            let mut settings = relay.settings.clone();
            if cancel {
                settings.connect_timeout_ms = 60_000;
            }
            let (ready_tx, ready_rx) = oneshot::channel();
            let mut server = tokio::spawn(async move {
                relay
                    .serve_stalled(stage, ready_tx, false, Duration::ZERO)
                    .await;
            });
            let _server_guard = AbortOnDrop::new(server.abort_handle());
            let (mut local, _peer) = local_tcp_pair().await;
            let started = tokio::time::Instant::now();
            let counters = super::super::RelaySessionCounters::default();
            let task_counters = counters.clone();
            let mut client = tokio::spawn(async move {
                run_grpc_tunnel(
                    &mut local,
                    &settings,
                    &test_profile(),
                    "127.0.0.1".into(),
                    43210,
                    Some(TEST_INITIAL_PAYLOAD),
                    &task_counters,
                )
                .await
            });
            let _client_guard = AbortOnDrop::new(client.abort_handle());
            if ready_rx.await.is_err() {
                let client_result = (&mut client).await;
                let server_result = (&mut server).await;
                panic!(
                    "{stage:?} stall stage was not reached after {:?}; \
                     client result: {client_result:#?}; server result: {server_result:#?}",
                    started.elapsed()
                );
            }
            if cancel {
                client.abort();
                assert!(client.await.expect_err("client cancelled").is_cancelled());
            } else {
                let err = (&mut client)
                    .await
                    .expect("client task")
                    .expect_err("establishment must time out");
                assert!(
                    err.to_string().contains(&format!(
                        "grpc tunnel establishment timed out after {TEST_OPEN_TIMEOUT_MS}ms"
                    )),
                    "unexpected establishment error: {err:#}"
                );
                assert!(err.downcast_ref::<tokio::time::error::Elapsed>().is_some());
                assert!(
                    err.to_string()
                        .contains(&format!("(stage={})", expected_timeout_stage(stage))),
                    "timeout must identify the actual stalled stage: {err:#}"
                );
                if matches!(stage, StalledStage::Headers | StalledStage::OpenAck) {
                    let diagnostic = err.to_string();
                    assert!(
                        diagnostic.contains("h2_driver=polled"),
                        "actual H2 driver must have been polled: {diagnostic}"
                    );
                    assert!(diagnostic.contains("request_queued=true, open_queued=true"));
                    assert!(diagnostic.contains("headers_error=false"));
                    assert!(
                        diagnostic.contains(if matches!(stage, StalledStage::OpenAck) {
                            "headers_received=true"
                        } else {
                            "headers_received=false"
                        })
                    );
                }
            }
            // Joining proves the peer saw close, not merely that our caller
            // returned while leaving a detached connection in the background.
            assert!(
                !counters.was_opened(),
                "stalled opening must remain retryable"
            );
            (&mut server).await.expect("stalled server exits on close");
        })
        .await
        .expect("stalled setup and task cancellation are bounded");
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_bounds_stalled_tls_handshake() {
        assert_stalled_setup(StalledStage::Tls, false).await;
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_bounds_silent_h2_peer() {
        assert_stalled_setup(StalledStage::H2, false).await;
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_bounds_stalled_response_headers() {
        assert_stalled_setup(StalledStage::Headers, false).await;
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_bounds_stalled_open_ack() {
        assert_stalled_setup(StalledStage::OpenAck, false).await;
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_cancellation_closes_h2_driver() {
        assert_stalled_setup(StalledStage::OpenAck, true).await;
    }

    #[tokio::test]
    async fn tcp_grpc_actual_driver_protocol_error_retains_response_error_custody() {
        tokio::time::timeout(TEST_WATCHDOG, async {
            let relay = LoopbackRelay::new().await;
            let settings = relay.settings.clone();
            let server = tokio::spawn(async move {
                let (tcp, _) = relay.listener.accept().await.expect("actual relay TCP");
                let mut tls = relay.acceptor.accept(tcp).await.expect("actual relay TLS");
                let mut preface = [0; 24];
                tls.read_exact(&mut preface)
                    .await
                    .expect("actual client H2 preface");
                assert!(preface == *b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                // A real invalid SETTINGS stream id triggers the original H2
                // driver's error and wakes the pending response future.
                tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 1])
                    .await
                    .expect("invalid SETTINGS fixture");
                let _ = tokio::io::copy(&mut tls, &mut tokio::io::sink()).await;
            });
            let _server_guard = AbortOnDrop::new(server.abort_handle());
            let (mut local, _peer) = local_tcp_pair().await;
            let counters = super::super::RelaySessionCounters::default();
            let err = run_grpc_tunnel(
                &mut local,
                &settings,
                &test_profile(),
                "127.0.0.1".into(),
                43210,
                Some(TEST_INITIAL_PAYLOAD),
                &counters,
            )
            .await
            .expect_err("actual invalid SETTINGS must fail establishment");
            assert!(err
                .chain()
                .filter_map(|e| e.downcast_ref::<h2::Error>())
                .any(|e| e.reason() == Some(h2::Reason::PROTOCOL_ERROR)));
            assert!(err.downcast_ref::<tokio::time::error::Elapsed>().is_none());
            let diagnostic = err.to_string();
            assert!(diagnostic.contains("h2_driver=terminal_error"));
            assert!(diagnostic.contains("driver_error=goaway"));
            assert!(diagnostic.contains("request_queued=true, open_queued=true"));
            assert!(diagnostic.contains("headers_received=false, headers_error=true"));
            assert!(!counters.was_opened());
            assert_eq!(counters.sent(), 0);
            assert_eq!(counters.received(), 0);
            server
                .await
                .expect("actual invalid-settings peer observed close");
        })
        .await
        .expect("actual TLS/H2 protocol failure and peer close are bounded");
    }

    async fn assert_udp_stalled_setup(stage: StalledStage, cancel: bool, delayed: bool) {
        tokio::time::timeout(TEST_WATCHDOG, async {
            let relay = LoopbackRelay::new().await;
            let mut settings = relay.settings.clone();
            if cancel {
                settings.connect_timeout_ms = 60_000;
            }
            let delay = if delayed {
                Duration::from_millis(1_700)
            } else {
                Duration::ZERO
            };
            let (ready_tx, ready_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                relay.serve_stalled(stage, ready_tx, true, delay).await;
            });
            let _server_guard = AbortOnDrop::new(server.abort_handle());
            let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
            outbound_tx
                .send(TEST_INITIAL_PAYLOAD.to_vec())
                .await
                .expect("queue payload");
            let (incoming_tx, _incoming_rx) = mpsc::channel(1);
            let started = tokio::time::Instant::now();
            let client = tokio::spawn(async move {
                let result = run_grpc_udp_flow(
                    &settings,
                    "127.0.0.1",
                    43210,
                    &mut outbound_rx,
                    &incoming_tx,
                )
                .await;
                assert_eq!(
                    outbound_rx
                        .try_recv()
                        .expect("pre-open payload not consumed"),
                    TEST_INITIAL_PAYLOAD
                );
                result
            });
            let _client_guard = AbortOnDrop::new(client.abort_handle());
            ready_rx.await.expect("actual UDP opening stage reached");
            if cancel {
                client.abort();
                assert!(client.await.expect_err("cancel client").is_cancelled());
            } else {
                let err = client
                    .await
                    .expect("client task")
                    .expect_err("opening deadline");
                assert!(
                    err.downcast_ref::<tokio::time::error::Elapsed>().is_some(),
                    "{err:#}"
                );
                assert!(
                    err.to_string()
                        .contains(&format!("(stage={})", expected_timeout_stage(stage))),
                    "UDP timeout must identify the actual stalled stage: {err:#}"
                );
                assert!(
                    !super::super::udp_payload_was_committed(&err),
                    "open control is not payload"
                );
                assert!(
                    started.elapsed() < Duration::from_millis(TEST_OPEN_TIMEOUT_MS + 900),
                    "staged opening must not reset the absolute deadline"
                );
            }
            server.await.expect("UDP peer observes owned H2/TLS close");
        })
        .await
        .expect("UDP opening watchdog");
    }

    #[tokio::test]
    async fn udp_grpc_establishment_bounds_each_stage_without_consuming_payload() {
        for stage in [
            StalledStage::Tls,
            StalledStage::H2,
            StalledStage::Headers,
            StalledStage::OpenAck,
        ] {
            assert_udp_stalled_setup(stage, false, false).await;
        }
    }

    #[tokio::test]
    async fn udp_grpc_establishment_uses_one_deadline_across_headers_and_ack() {
        assert_udp_stalled_setup(StalledStage::OpenAck, false, true).await;
    }

    #[tokio::test]
    async fn udp_grpc_establishment_cancellation_closes_owned_driver() {
        assert_udp_stalled_setup(StalledStage::OpenAck, true, false).await;
    }

    #[tokio::test]
    async fn udp_grpc_payload_error_after_open_is_not_retryable_or_lifetime_limited() {
        for one_shot in [false, true] {
            tokio::time::timeout(TEST_WATCHDOG, async {
                let relay = LoopbackRelay::new().await;
                let settings = relay.settings.clone();
                let (seen_tx, seen_rx) = oneshot::channel();
                let server = tokio::spawn(async move {
                    let (tcp, _) = relay.listener.accept().await.expect("accept TCP");
                    let tls = relay.acceptor.accept(tcp).await.expect("accept TLS");
                    let mut connection = h2::server::handshake(tls).await.expect("H2");
                    let (request, mut respond) = connection.accept().await.expect("request").expect("H2 request");
                    let session = async {
                        let mut recv = request.into_body();
                        let mut pending = Vec::new();
                        let open = read_grpc_message(&mut recv, &mut pending).await.expect("open").expect("open frame");
                        let opened = aegis_core::tunnel::open_tunnel_request_with_kind(&open, relay.settings.auth_token.as_bytes()).expect("typed open");
                        assert_eq!(opened.kind, aegis_core::tunnel::TunnelRequestKind::Datagram);
                        let mut send = respond.send_response(http::Response::new(()), false).expect("headers");
                        let ack = seal_tunnel_response(&TunnelResponse { status: TunnelStatus::Ok, message: String::new() }, relay.settings.auth_token.as_bytes()).expect("ack");
                        send.send_data(grpc_frame(&ack), false).expect("send ack");
                        let payload = read_grpc_message(&mut recv, &mut pending).await.expect("payload").expect("payload frame");
                        assert_eq!(payload, TEST_INITIAL_PAYLOAD);
                        seen_tx.send(()).expect("payload counter receiver");
                        if !one_shot {
                            // A flow remains established after the opening
                            // deadline; only one-shot response waits expire.
                            tokio::time::sleep(Duration::from_millis(TEST_OPEN_TIMEOUT_MS + 100)).await;
                        }
                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                    };
                    tokio::pin!(session);
                    tokio::select! {
                        () = &mut session => {}
                        _ = std::future::poll_fn(|cx| connection.poll_closed(cx)) => { session.await; }
                    }
                    let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
                });
                let _guard = AbortOnDrop::new(server.abort_handle());
                let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
                outbound_tx.send(TEST_INITIAL_PAYLOAD.to_vec()).await.expect("queue payload");
                let (incoming_tx, _incoming_rx) = mpsc::channel(1);
                let result = if one_shot {
                    run_grpc_udp_datagram_once(&settings, &test_profile(), ConnectTarget { host: "127.0.0.1".into(), port: 43210 }, TEST_INITIAL_PAYLOAD).await.map(|_| ())
                } else {
                    run_grpc_udp_flow(&settings, "127.0.0.1", 43210, &mut outbound_rx, &incoming_tx).await
                };
                seen_rx.await.expect("exactly one payload reached relay");
                let err = result.expect_err("post-payload error");
                assert!(super::super::udp_payload_was_committed(&err), "{err:#}");
                if !one_shot {
                    assert!(err.downcast_ref::<tokio::time::error::Elapsed>().is_none(), "stream lifetime is outside opening deadline");
                }
                server.await.expect("error closes owned driver");
            }).await.expect("post-payload error watchdog");
        }
    }

    async fn assert_successful_setup(early_response_end: bool) {
        tokio::time::timeout(TEST_WATCHDOG, async {
            let relay = LoopbackRelay::new().await;
            let settings = relay.settings.clone();
            let (initial_tx, initial_rx) = oneshot::channel();
            let mut server = tokio::spawn(async move {
                let (tcp, _) = relay.listener.accept().await.expect("accept relay TCP");
                let tls = relay.acceptor.accept(tcp).await.expect("accept relay TLS");
                let mut connection = h2::server::handshake(tls).await.expect("server H2");
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .expect("request present")
                    .expect("request accepted");
                let session = async {
                    let mut recv = request.into_body();
                    let mut pending = Vec::new();
                    let open = read_grpc_message(&mut recv, &mut pending)
                        .await
                        .expect("read open")
                        .expect("open present");
                    open_tunnel_request(&open, relay.settings.auth_token.as_bytes())
                        .expect("valid open");
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .expect("send response headers");
                    let ack = seal_tunnel_response(
                        &TunnelResponse {
                            status: TunnelStatus::Ok,
                            message: String::new(),
                        },
                        relay.settings.auth_token.as_bytes(),
                    )
                    .expect("seal open ack");
                    send.send_data(grpc_frame(&ack), early_response_end)
                        .expect("send ack");
                    let initial = read_grpc_message(&mut recv, &mut pending)
                        .await
                        .expect("read initial payload")
                        .expect("initial payload present");
                    assert_eq!(initial, TEST_INITIAL_PAYLOAD);
                    if !early_response_end {
                        send.send_data(grpc_frame(&initial), false)
                            .expect("echo initial payload");
                    }
                    initial_tx.send(()).expect("initial payload receiver");
                    let mut late = Vec::new();
                    while late.len() < TEST_LATE_PAYLOAD.len() {
                        let payload = read_grpc_message(&mut recv, &mut pending)
                            .await
                            .expect("read payload")
                            .expect("payload present");
                        late.extend_from_slice(&payload);
                        if !early_response_end {
                            send.send_data(grpc_frame(&payload), false)
                                .expect("echo payload");
                        }
                    }
                    assert_eq!(late, TEST_LATE_PAYLOAD, "payload arrives once and in order");
                    assert!(read_grpc_message(&mut recv, &mut pending)
                        .await
                        .expect("read local end")
                        .is_none());
                    if !early_response_end {
                        send.send_data(Bytes::new(), true).expect("finish echo");
                    }
                };
                tokio::pin!(session);
                tokio::select! {
                    () = &mut session => {}
                    _ = std::future::poll_fn(|cx| connection.poll_closed(cx)) => {
                        session.await;
                    }
                }
                // Flush the final END_STREAM and let the client's owned
                // driver close naturally when both copy directions finish.
                let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
            });
            let _server_guard = AbortOnDrop::new(server.abort_handle());
            let (mut local, mut peer) = local_tcp_pair().await;
            let counters = super::super::RelaySessionCounters::default();
            let task_counters = counters.clone();
            let mut client = tokio::spawn(async move {
                run_grpc_tunnel(
                    &mut local,
                    &settings,
                    &test_profile(),
                    "127.0.0.1".into(),
                    43210,
                    Some(TEST_INITIAL_PAYLOAD),
                    &task_counters,
                )
                .await
            });
            let _client_guard = AbortOnDrop::new(client.abort_handle());
            initial_rx.await.expect("initial payload reached relay");
            assert!(
                counters.was_opened(),
                "authenticated open disables replay before payload"
            );
            if !early_response_end {
                let mut initial_echo = vec![0; TEST_INITIAL_PAYLOAD.len()];
                peer.read_exact(&mut initial_echo)
                    .await
                    .expect("initial echo");
                assert_eq!(initial_echo, TEST_INITIAL_PAYLOAD);
            }
            tokio::time::sleep(Duration::from_millis(TEST_OPEN_TIMEOUT_MS + 100)).await;
            assert!(!client.is_finished(), "established tunnel remains open");
            peer.write_all(TEST_LATE_PAYLOAD)
                .await
                .expect("late payload");
            if !early_response_end {
                let mut late_echo = vec![0; TEST_LATE_PAYLOAD.len()];
                peer.read_exact(&mut late_echo).await.expect("late echo");
                assert_eq!(late_echo, TEST_LATE_PAYLOAD);
            }
            peer.shutdown().await.expect("local half-close");
            (&mut client)
                .await
                .expect("client task")
                .expect("tunnel result");
            (&mut server).await.expect("server task");
        })
        .await
        .expect("successful setup, late data and shutdown are bounded");
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_deadline_does_not_limit_data_transfer_or_replay_payload() {
        assert_successful_setup(false).await;
    }

    #[tokio::test]
    async fn tcp_grpc_establishment_flushes_last_payload_after_response_half_close() {
        assert_successful_setup(true).await;
    }

    #[tokio::test]
    async fn large_grpc_message_replenishes_h2_receive_window() {
        const PAYLOAD_LEN: usize = 256 * 1024;

        let (client_io, server_io) = tokio::io::duplex(512 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io)
                .await
                .expect("server h2 handshake");
            while let Some(request) = connection.accept().await {
                let (_request, mut respond) = request.expect("server request");
                tokio::spawn(async move {
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .expect("response");
                    let mut send = respond
                        .send_response(response, false)
                        .expect("send response headers");
                    let frame = grpc_frame(&vec![0x5a; PAYLOAD_LEN]);
                    let mut offset = 0;
                    send.reserve_capacity(frame.len());
                    while offset < frame.len() {
                        let granted = if send.capacity() > 0 {
                            send.capacity()
                        } else {
                            std::future::poll_fn(|cx| send.poll_capacity(cx))
                                .await
                                .expect("stream still open")
                                .expect("stream capacity")
                        };
                        if granted == 0 {
                            continue;
                        }
                        let n = granted.min(16 * 1024).min(frame.len() - offset);
                        let end_stream = offset + n == frame.len();
                        send.send_data(frame.slice(offset..offset + n), end_stream)
                            .expect("send response data");
                        offset += n;
                    }
                });
            }
        });

        let (mut client, connection) = h2::client::handshake(client_io)
            .await
            .expect("client h2 handshake");
        let driver = tokio::spawn(connection);
        let request = http::Request::builder()
            .method("POST")
            .uri("https://relay.example.test/aegis.Tunnel/Open")
            .body(())
            .expect("request");
        let (response, _send) = client
            .send_request(request, true)
            .expect("send client request");
        let mut recv = response.await.expect("response headers").into_body();
        let mut pending = Vec::new();
        let payload = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            read_grpc_message(&mut recv, &mut pending),
        )
        .await
        .expect("large response must not stall at the default h2 window")
        .expect("read grpc message")
        .expect("grpc message present");

        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert!(payload.iter().all(|byte| *byte == 0x5a));

        drop(client);
        driver.abort();
        server.abort();
    }

    #[test]
    fn grpc_request_uri_includes_scheme_and_authority() {
        let uri = grpc_request_uri("relay.example.org", "/pkg.Service/Open").expect("uri");
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(
            uri.authority().map(|authority| authority.as_str()),
            Some("relay.example.org")
        );
        assert_eq!(uri.path(), "/pkg.Service/Open");
    }

    #[test]
    fn grpc_request_uri_rejects_relative_path() {
        let err = grpc_request_uri("relay.example.org", "pkg.Service/Open")
            .expect_err("relative grpc path should fail");
        assert!(err.to_string().contains("grpc path must be absolute"));
    }

    #[test]
    fn benign_h2_close_accepts_cancel_reset() {
        assert!(benign_h2_close(&anyhow::Error::new(h2::Error::from(
            h2::Reason::CANCEL
        ))));
        assert!(benign_h2_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof"
        ))));
        assert!(!benign_h2_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout"
        ))));
    }
}

#[cfg(test)]
#[path = "grpc/end_stream_tests.rs"]
mod end_stream_tests;
