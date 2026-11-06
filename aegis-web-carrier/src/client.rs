use crate::{
    convert, failed,
    protocol::{self, Frame, Reply, FIN, OPEN},
    rejected,
    settings::CONTENT_TYPE,
    Cancellation, ClientSettings, Credential, Descriptor, Limits, KEY_HEADER,
};
use bytes::Bytes;
use http::Request;
use rand::RngCore;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;

/// Verified outer TLS must be configured by the existing native TLS policy.
pub struct Client;
impl Client {
    pub async fn discover(
        connector: TlsConnector,
        bootstrap: SocketAddr,
        settings: &ClientSettings,
        credential: &Credential,
        limits: &Limits,
    ) -> io::Result<Descriptor> {
        settings.validate()?;
        limits.validate()?;
        let mut connection =
            Connection::open(connector, bootstrap, &settings.authority, limits).await?;
        Self::discover_on_connection(&mut connection, settings, credential, limits).await
    }

    /// Use a caller-owned, already connected socket. A NetworkExtension must
    /// bind this socket to its admitted physical interface before connecting.
    /// The socket's exact peer is checked against the signed bootstrap pin
    /// by the caller; this API never opens a substitute socket.
    pub async fn discover_on(
        connector: TlsConnector,
        tcp: TcpStream,
        bootstrap: SocketAddr,
        settings: &ClientSettings,
        credential: &Credential,
        limits: &Limits,
    ) -> io::Result<Descriptor> {
        settings.validate()?;
        limits.validate()?;
        if tcp.peer_addr()? != bootstrap {
            return Err(rejected());
        }
        let mut connection =
            Connection::open_on(connector, tcp, &settings.authority, limits).await?;
        Self::discover_on_connection(&mut connection, settings, credential, limits).await
    }

    async fn discover_on_connection(
        connection: &mut Connection,
        settings: &ClientSettings,
        credential: &Credential,
        limits: &Limits,
    ) -> io::Result<Descriptor> {
        let body = connection
            .request(
                &settings.authority,
                &settings.descriptor_path,
                credential,
                Bytes::new(),
                4096,
                limits,
            )
            .await?;
        let descriptor: Descriptor = serde_json::from_slice(&body).map_err(convert)?;
        descriptor.validate(settings, limits)?;
        Ok(descriptor)
    }
    pub async fn connect(
        connector: TlsConnector,
        settings: &ClientSettings,
        descriptor: Descriptor,
        credential: Credential,
        limits: Limits,
    ) -> io::Result<WebStream> {
        descriptor.validate(settings, &limits)?;
        let connection = Connection::open(
            connector,
            descriptor.ingress,
            &descriptor.authority,
            &limits,
        )
        .await?;
        Self::connect_on_connection(connection, descriptor, credential, limits).await
    }

    /// Use a caller-owned ingress socket; no implicit TCP dial or alternate
    /// ingress is permitted after descriptor validation.
    pub async fn connect_on(
        connector: TlsConnector,
        tcp: TcpStream,
        settings: &ClientSettings,
        descriptor: Descriptor,
        credential: Credential,
        limits: Limits,
    ) -> io::Result<WebStream> {
        descriptor.validate(settings, &limits)?;
        if tcp.peer_addr()? != descriptor.ingress {
            return Err(rejected());
        }
        let connection =
            Connection::open_on(connector, tcp, &descriptor.authority, &limits).await?;
        Self::connect_on_connection(connection, descriptor, credential, limits).await
    }

    async fn connect_on_connection(
        mut connection: Connection,
        descriptor: Descriptor,
        credential: Credential,
        limits: Limits,
    ) -> io::Result<WebStream> {
        let mut id = [0; 32];
        rand::thread_rng().fill_bytes(&mut id);
        let open = Frame {
            id,
            sequence: 0,
            ack: 0,
            flags: OPEN,
            data: Bytes::new(),
        };
        let response = connection
            .exchange(&descriptor, &credential, open, &limits)
            .await?;
        if response.fin || !response.data.is_empty() {
            return Err(rejected());
        }
        let (application, mut carrier) = tokio::io::duplex(descriptor.frame_bytes * 2);
        let cancellation = Cancellation::default();
        let stop = cancellation.clone();
        let state = Arc::new(StreamState::default());
        let pumping_state = state.clone();
        let (terminal, terminal_rx) = watch::channel(false);
        let pump = tokio::spawn(async move {
            let result = tokio::select! {biased;_=stop.cancelled()=>Ok(()),result=pump(&mut carrier,&mut connection,descriptor,credential,limits,id,&pumping_state)=>result};
            if result.is_err() {
                // Publish the terminal failure before dropping the actual duplex
                // endpoint can wake an application reader with an apparent EOF.
                pumping_state.failed.store(true, Ordering::Release);
            }
            terminal.send_replace(true);
            result
        });
        Ok(WebStream {
            io: application,
            pump: Some(pump),
            cancellation,
            state,
            terminal: terminal_rx,
        })
    }
}
/// Dropping this stream cancels its pump and the pump-owned H2 driver. No
/// reconnection, carrier fallback, session replay or new application open occurs.
pub struct WebStream {
    io: DuplexStream,
    pump: Option<JoinHandle<io::Result<()>>>,
    cancellation: Cancellation,
    state: Arc<StreamState>,
    terminal: watch::Receiver<bool>,
}
#[derive(Default)]
struct StreamState {
    failed: AtomicBool,
    received_fin: AtomicBool,
}
impl StreamState {
    fn check(&self) -> io::Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(failed());
        }
        Ok(())
    }
}
impl WebStream {
    /// Observe any pump termination after this stream is transferred into
    /// inner TLS. A closed sender also means terminal (including task abort).
    /// The owning session must fail its packet gate when this resolves.
    pub fn terminal_watch(&self) -> watch::Receiver<bool> {
        self.terminal.clone()
    }

    pub async fn cancel(mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.pump.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for WebStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = &self.pump {
            task.abort();
        }
    }
}
impl AsyncRead for WebStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.state.check() {
            return Poll::Ready(Err(error));
        }
        let requested = buf.remaining();
        if requested == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if buf.filled().len() == before
                    && !self.state.received_fin.load(Ordering::Acquire) =>
            {
                Poll::Ready(Err(failed()))
            }
            result => result,
        }
    }
}
impl AsyncWrite for WebStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.state.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.state.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.state.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
struct Connection {
    send: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Connection {
    async fn open(
        connector: TlsConnector,
        address: SocketAddr,
        authority: &str,
        limits: &Limits,
    ) -> io::Result<Self> {
        let name = rustls::pki_types::ServerName::try_from(authority.to_owned())
            .map_err(|_| rejected())?;
        tokio::time::timeout(limits.request_timeout, async {
            let tcp = TcpStream::connect(address).await?;
            Self::handshake(connector, tcp, name).await
        })
        .await
        .map_err(convert)?
    }

    async fn open_on(
        connector: TlsConnector,
        tcp: TcpStream,
        authority: &str,
        limits: &Limits,
    ) -> io::Result<Self> {
        let name = rustls::pki_types::ServerName::try_from(authority.to_owned())
            .map_err(|_| rejected())?;
        tokio::time::timeout(
            limits.request_timeout,
            Self::handshake(connector, tcp, name),
        )
        .await
        .map_err(convert)?
    }

    async fn handshake(
        connector: TlsConnector,
        tcp: TcpStream,
        name: rustls::pki_types::ServerName<'static>,
    ) -> io::Result<Self> {
        let tls = connector.connect(name, tcp).await.map_err(convert)?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(rejected());
        }
        let mut builder = h2::client::Builder::new();
        builder.max_header_list_size(8192);
        let (send, connection) = builder.handshake::<_, Bytes>(tls).await.map_err(convert)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { send, driver })
    }
    async fn request(
        &mut self,
        authority: &str,
        path: &str,
        credential: &Credential,
        body: Bytes,
        max: usize,
        limits: &Limits,
    ) -> io::Result<Bytes> {
        tokio::time::timeout(limits.request_timeout, async {
            let request = Request::builder()
                .method("POST")
                .uri(format!("https://{authority}{path}"))
                .header("content-type", CONTENT_TYPE)
                .header(KEY_HEADER, credential.header_value())
                .body(())
                .map_err(convert)?;
            let send = self.send.clone().ready().await.map_err(convert)?;
            self.send = send;
            let (response, stream) = self.send.send_request(request, false).map_err(convert)?;
            protocol::send(stream, body).await?;
            let response = response.await.map_err(convert)?;
            if response.status() != http::StatusCode::OK {
                return Err(rejected());
            }
            protocol::collect(response.into_body(), max).await
        })
        .await
        .map_err(convert)?
    }
    async fn exchange(
        &mut self,
        descriptor: &Descriptor,
        credential: &Credential,
        frame: Frame,
        limits: &Limits,
    ) -> io::Result<Reply> {
        let sequence = frame.sequence;
        let id = frame.id;
        let body = self
            .request(
                &descriptor.authority,
                &descriptor.path,
                credential,
                frame.encode(),
                protocol::RESPONSE_HEADER + descriptor.frame_bytes,
                limits,
            )
            .await?;
        let reply = Reply::decode(body, descriptor.frame_bytes)?;
        if reply.id != id || reply.sequence != sequence {
            return Err(rejected());
        }
        Ok(reply)
    }
}
async fn pump(
    carrier: &mut DuplexStream,
    connection: &mut Connection,
    descriptor: Descriptor,
    credential: Credential,
    limits: Limits,
    id: [u8; 32],
    state: &StreamState,
) -> io::Result<()> {
    let (mut read, mut write) = tokio::io::split(carrier);
    let mut sequence = 1u64;
    let mut upload_closed = false;
    let mut download_closed = false;
    let mut bytes = vec![0; descriptor.frame_bytes];
    loop {
        let (data, flags) = if upload_closed {
            tokio::time::sleep(limits.poll_interval).await;
            (Bytes::new(), 0)
        } else {
            match tokio::time::timeout(limits.poll_interval, read.read(&mut bytes)).await {
                Ok(Ok(0)) => {
                    upload_closed = true;
                    (Bytes::new(), FIN)
                }
                Ok(Ok(n)) => (Bytes::copy_from_slice(&bytes[..n]), 0),
                Ok(Err(error)) => return Err(error),
                Err(_) => (Bytes::new(), 0),
            }
        };
        let reply = connection
            .exchange(
                &descriptor,
                &credential,
                Frame {
                    id,
                    sequence,
                    ack: sequence - 1,
                    flags,
                    data,
                },
                &limits,
            )
            .await?;
        if !reply.data.is_empty() {
            tokio::time::timeout(limits.request_timeout, write.write_all(&reply.data))
                .await
                .map_err(convert)??;
        }
        if reply.fin && !download_closed {
            // Only the protocol's explicit ordered FIN authorizes a clean EOF.
            state.received_fin.store(true, Ordering::Release);
            write.shutdown().await?;
            download_closed = true;
        }
        if upload_closed && download_closed {
            return Ok(());
        }
        sequence = sequence.checked_add(1).ok_or_else(failed)?;
    }
}
