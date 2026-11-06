use crate::{
    convert, failed,
    protocol::{self, Frame, Reply, CANCEL, FIN, OPEN},
    rejected,
    settings::{now_ms, CONTENT_TYPE},
    Cancellation, Credential, Descriptor, InMemorySessionLedger, Limits, ServerSettings,
    SessionLedger,
};
use bytes::Bytes;
use http::{Method, Request, Response};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpListener,
    sync::{mpsc, Semaphore},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_rustls::TlsAcceptor;

struct Lifetime {
    opened: Instant,
    state: AtomicU8,
    completed_at_ns: AtomicU64,
    limits: Limits,
}
impl Lifetime {
    fn expired(&self, last: Instant) -> bool {
        let state = self.state.load(Ordering::Acquire);
        let fixed = self.opened.elapsed() >= self.limits.max_lifetime
            || last.elapsed() >= self.limits.idle_timeout;
        let drain = state == 3
            && self
                .opened
                .elapsed()
                .as_nanos()
                .saturating_sub(self.completed_at_ns.load(Ordering::Acquire) as u128)
                >= self.limits.request_timeout.as_nanos();
        if state == 2 {
            return true;
        }
        if fixed || drain {
            self.cancel();
            return true;
        }
        if state == 0 && self.opened.elapsed() >= self.limits.unauthenticated_timeout {
            // Authentication can finish between timer polling and this check.
            // Cancel only if the state is still unauthenticated at the CAS.
            return self
                .state
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                || self.state.load(Ordering::Acquire) == 2;
        }
        false
    }
    fn cancel(&self) {
        self.state.store(2, Ordering::Release);
    }
    fn finished(&self) {
        // Admitted sessions last at most one hour. Saturation also prevents
        // wraparound if an application is retained long after cancellation.
        self.completed_at_ns.store(
            u64::try_from(self.opened.elapsed().as_nanos()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
        loop {
            let state = self.state.load(Ordering::Acquire);
            let next = match state {
                0 => 2,
                1 => 3,
                _ => return,
            };
            if self
                .state
                .compare_exchange(state, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}
/// Call only after successful inner `accept_with_lease`; this never authorizes egress.
#[derive(Clone)]
pub struct AuthenticationHandle(Arc<Lifetime>);
impl AuthenticationHandle {
    pub fn mark_authenticated(&self) -> io::Result<()> {
        if self.0.opened.elapsed() >= self.0.limits.unauthenticated_timeout
            || self.0.opened.elapsed() >= self.0.limits.max_lifetime
        {
            return Err(rejected());
        }
        self.0
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| rejected())?;
        Ok(())
    }
    pub fn cancel(&self) {
        self.0.cancel();
    }
}
pub struct AcceptedSession {
    stream: ApplicationStream,
    authentication: AuthenticationHandle,
    peer_ip: IpAddr,
}
impl AcceptedSession {
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }
    pub fn into_parts(self) -> (ApplicationStream, AuthenticationHandle) {
        (self.stream, self.authentication)
    }
}
/// Application ownership ends authenticated admission. A fixed drain interval
/// lets already prepared final TLS bytes complete; requests cannot extend it.
pub struct ApplicationStream {
    io: DuplexStream,
    lifetime: Arc<Lifetime>,
}
impl Drop for ApplicationStream {
    fn drop(&mut self) {
        self.lifetime.finished();
    }
}
impl tokio::io::AsyncRead for ApplicationStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for ApplicationStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
struct Upload {
    data: Bytes,
    fin: bool,
}
struct Download {
    data: Bytes,
    fin: bool,
}
struct SessionData {
    next: u64,
    previous_digest: [u8; 32],
    previous_reply: Bytes,
    last_activity: Instant,
    up: mpsc::Sender<Upload>,
    down: mpsc::Receiver<Download>,
    input_closed: bool,
    output_closed: bool,
}
struct Session {
    _ledger_claim: ClaimedLedgerSession,
    owner: u64,
    ingress: SocketAddr,
    path: String,
    lifetime: Arc<Lifetime>,
    data: Mutex<SessionData>,
    exchange_lock: tokio::sync::Mutex<()>,
    worker: JoinHandle<()>,
    cancellation: Cancellation,
}
struct ClaimedLedgerSession {
    ledger: Arc<dyn SessionLedger>,
    id: [u8; 32],
    owner: u64,
}
impl Drop for ClaimedLedgerSession {
    fn drop(&mut self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let ledger = self.ledger.clone();
            let id = self.id;
            let owner = self.owner;
            runtime.spawn(async move {
                let _ = ledger.release(id, owner).await;
            });
        }
        // A runtime crash still leaves the bounded expiry as the capacity
        // fallback; it never makes a stale claim valid again.
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.lifetime.cancel();
        self.cancellation.cancel();
        self.worker.abort();
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ServerStats {
    pub active_sessions: usize,
    pub active_connections: usize,
    pub active_requests: usize,
    /// Saturating resource accept-error count across this server's listeners.
    pub resource_accept_errors: u64,
    /// Independent observation, not a health flag or a coherent count/code pair.
    pub last_resource_accept_errno: Option<i32>,
}
#[derive(Default)]
struct ResourceAcceptObservations {
    count: AtomicU64,
    last_errno: AtomicI32,
}
impl ResourceAcceptObservations {
    fn observe(&self, raw_errno: i32) {
        let _ = self
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        self.last_errno.store(raw_errno, Ordering::Relaxed);
    }
    fn snapshot(&self) -> (u64, Option<i32>) {
        let code = self.last_errno.load(Ordering::Relaxed);
        (
            self.count.load(Ordering::Relaxed),
            (code != 0).then_some(code),
        )
    }
}
fn resource_accept_errno(error: &io::Error) -> Option<i32> {
    let raw = error.raw_os_error()?;
    // sys/errno.h: ENOMEM, ENFILE, EMFILE, ENOBUFS on Darwin.
    #[cfg(target_os = "macos")]
    const CODES: &[i32] = &[12, 23, 24, 55];
    // Linux libc constants: ENOMEM, ENFILE, EMFILE; ENOBUFS has a
    // platform-specific value, checked here only on x86_64 and aarch64.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const CODES: &[i32] = &[12, 23, 24, 105];
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    const CODES: &[i32] = &[12, 23, 24];
    // WinSock WSAEMFILE and WSAENOBUFS, never the CRT/Unix errno values.
    #[cfg(windows)]
    const CODES: &[i32] = &[10_024, 10_055];
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    const CODES: &[i32] = &[];
    CODES.contains(&raw).then_some(raw)
}
struct PublishedDescriptor {
    value: Descriptor,
    expires: Instant,
}
pub struct Server {
    settings: ServerSettings,
    credential: Credential,
    limits: Limits,
    descriptor: Mutex<Option<PublishedDescriptor>>,
    sessions: Mutex<HashMap<[u8; 32], Arc<Session>>>,
    open_lock: tokio::sync::Mutex<()>,
    ledger: Arc<dyn SessionLedger>,
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    resource_accept: ResourceAcceptObservations,
}
impl Server {
    pub fn new(
        settings: ServerSettings,
        credential: Credential,
        limits: Limits,
    ) -> io::Result<Arc<Self>> {
        Self::with_ledger(
            settings,
            credential,
            limits,
            Arc::new(InMemorySessionLedger::default()),
        )
    }

    /// Provide a shared atomic ledger for session fencing across instances.
    /// Application bytes and authentication remain owned by this process.
    pub fn with_ledger(
        settings: ServerSettings,
        credential: Credential,
        limits: Limits,
        ledger: Arc<dyn SessionLedger>,
    ) -> io::Result<Arc<Self>> {
        settings.validate()?;
        limits.validate()?;
        Ok(Arc::new(Self {
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            requests: Arc::new(Semaphore::new(limits.max_requests)),
            settings,
            credential,
            limits,
            descriptor: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            open_lock: tokio::sync::Mutex::new(()),
            ledger,
            resource_accept: ResourceAcceptObservations::default(),
        }))
    }
    /// Publish a new *already bound* ingress. Old sessions retain their connection
    /// and route; there is no session replay/migration onto a new connection.
    pub fn rotate_ingress(&self, ingress: SocketAddr) -> io::Result<Descriptor> {
        if ingress.port() == 0 || ingress.ip().is_unspecified() || ingress.ip().is_multicast() {
            return Err(rejected());
        }
        let mut current = self.descriptor.lock().map_err(|_| failed())?;
        let generation = current.as_ref().map_or(Ok(1), |d| {
            d.value.generation.checked_add(1).ok_or_else(rejected)
        })?;
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let path = format!(
            "/response/{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let descriptor = Descriptor {
            version: 1,
            authority: self.settings.client.authority.clone(),
            ingress,
            path,
            generation,
            expires_unix_ms: now_ms()?
                .checked_add(self.limits.descriptor_lifetime.as_millis() as u64)
                .ok_or_else(rejected)?,
            frame_bytes: self.limits.frame_bytes,
        };
        *current = Some(PublishedDescriptor {
            value: descriptor.clone(),
            expires: Instant::now() + self.limits.descriptor_lifetime,
        });
        Ok(descriptor)
    }
    pub fn descriptor(&self) -> io::Result<Descriptor> {
        let current = self.descriptor.lock().map_err(|_| failed())?;
        let current = current.as_ref().ok_or_else(rejected)?;
        if Instant::now() >= current.expires {
            return Err(rejected());
        }
        Ok(current.value.clone())
    }
    pub fn stats(&self) -> ServerStats {
        let (resource_accept_errors, last_resource_accept_errno) = self.resource_accept.snapshot();
        ServerStats {
            active_sessions: self.sessions.lock().map(|s| s.len()).unwrap_or(0),
            active_connections: self.limits.max_connections - self.connections.available_permits(),
            active_requests: self.limits.max_requests - self.requests.available_permits(),
            resource_accept_errors,
            last_resource_accept_errno,
        }
    }
    fn cleanup(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, session| {
                let expired = session
                    .data
                    .lock()
                    .map(|data| session.lifetime.expired(data.last_activity))
                    .unwrap_or(true);
                if expired {
                    session.lifetime.cancel();
                }
                !expired
            });
        }
    }
    fn remove_owner(&self, owner: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, s| s.owner != owner);
        }
    }
    fn authenticated_owner(&self, owner: u64) -> bool {
        self.sessions.lock().is_ok_and(|sessions| {
            sessions.values().any(|s| {
                s.owner == owner && matches!(s.lifetime.state.load(Ordering::Acquire), 1 | 3)
            })
        })
    }
    /// One owner for all listener tasks. Cancellation aborts and joins children.
    /// A second invocation on a new bound listener may share this server for rotation.
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        acceptor: TlsAcceptor,
        accepted: mpsc::Sender<AcceptedSession>,
        stop: Cancellation,
    ) -> io::Result<()> {
        let ingress = listener.local_addr()?;
        self.serve_at(listener, ingress, acceptor, accepted, stop)
            .await
    }
    /// Operator-provided advertised address for an already bound listener.
    /// Supports a wildcard/private bind behind an explicitly configured NAT;
    /// it never chooses or provisions external addresses.
    pub async fn serve_at(
        self: Arc<Self>,
        listener: TcpListener,
        ingress: SocketAddr,
        acceptor: TlsAcceptor,
        accepted: mpsc::Sender<AcceptedSession>,
        stop: Cancellation,
    ) -> io::Result<()> {
        self.serve_with_accept(ingress, acceptor, accepted, stop, || listener.accept())
            .await
    }
    async fn serve_with_accept<A, F>(
        self: Arc<Self>,
        ingress: SocketAddr,
        acceptor: TlsAcceptor,
        accepted: mpsc::Sender<AcceptedSession>,
        stop: Cancellation,
        mut accept: A,
    ) -> io::Result<()>
    where
        A: FnMut() -> F,
        F: std::future::Future<Output = io::Result<(tokio::net::TcpStream, SocketAddr)>>,
    {
        if ingress.port() == 0 || ingress.ip().is_unspecified() || ingress.ip().is_multicast() {
            return Err(rejected());
        }
        // The initial descriptor exists before the first connection is accepted.
        let initialize = { self.descriptor.lock().map_err(|_| failed())?.is_none() };
        if initialize {
            self.rotate_ingress(ingress)?;
        }
        let mut tasks = JoinSet::new();
        let mut cleanup = tokio::time::interval(Duration::from_millis(50));
        let mut retry_at: Option<Instant> = None;
        let result = loop {
            let waiting_until = retry_at;
            tokio::select! {
                biased;
                _=stop.cancelled()=>break Ok(()),
                _=cleanup.tick()=>self.cleanup(),
                Some(_)=tasks.join_next(), if !tasks.is_empty()=>{},
                _=async move {
                    if let Some(deadline)=waiting_until {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if waiting_until.is_some()=>retry_at=None,
                next=accept(), if retry_at.is_none()=> {
                    let (tcp,peer)=match next {
                        Ok(pair)=>pair,
                        Err(error) if matches!(error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted | io::ErrorKind::WouldBlock)=> {
                            // Cleanup and child completion cannot renew this deadline.
                            retry_at=Some(Instant::now()+Duration::from_millis(50));
                            continue;
                        }
                        Err(error) if resource_accept_errno(&error).is_some()=> {
                            // Fixed-size observations only: no formatting, output,
                            // allocation or new admission work while resources are scarce.
                            self.resource_accept.observe(resource_accept_errno(&error).unwrap());
                            retry_at=Some(Instant::now()+Duration::from_millis(50));
                            continue;
                        }
                        Err(error)=>break Err(error),
                    };
                    let Ok(permit)=self.connections.clone().try_acquire_owned() else {continue;};
                    let owner=rand::thread_rng().next_u64();
                    let server=self.clone();let acceptor=acceptor.clone();let accepted=accepted.clone();
                    tasks.spawn(async move {
                        let _permit=permit;let _owner=ConnectionOwner{server:server.clone(),owner};
                        let handshake=tokio::time::timeout(server.limits.request_timeout,acceptor.accept(tcp)).await;
                        let Ok(Ok(tls))=handshake else{return;};
                        if tls.get_ref().1.alpn_protocol()==Some(b"h2".as_slice()) {
                            let _=server.connection(tls,ingress,owner,peer.ip(),accepted).await;
                        } else if matches!(tls.get_ref().1.alpn_protocol(),Some(b"http/1.1")|None) {
                            let _=tokio::time::timeout(server.limits.request_timeout,server.site_h1(tls)).await;
                        }
                    });
                }
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.cleanup();
        result
    }
    async fn connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        self: Arc<Self>,
        tls: S,
        ingress: SocketAddr,
        owner: u64,
        peer_ip: IpAddr,
        accepted: mpsc::Sender<AcceptedSession>,
    ) -> io::Result<()> {
        let mut builder = h2::server::Builder::new();
        builder.max_concurrent_streams(4).max_header_list_size(8192);
        let mut connection = tokio::time::timeout(
            self.limits.request_timeout,
            builder.handshake::<_, Bytes>(tls),
        )
        .await
        .map_err(convert)?
        .map_err(convert)?;
        let anonymous_deadline = Instant::now() + self.limits.unauthenticated_timeout;
        let mut requests = JoinSet::new();
        let mut check = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                _=check.tick()=> {
                    self.cleanup();
                    if Instant::now()>=anonymous_deadline && !self.authenticated_owner(owner) {break;}
                }
                Some(_)=requests.join_next(), if !requests.is_empty()=>{},
                request=connection.accept()=> {
                    let Some(request)=request else{break;};let (request,respond)=request.map_err(convert)?;
                    let Ok(permit)=self.requests.clone().try_acquire_owned() else {drop(respond);continue;};
                    if requests.len()>=4 {drop(respond);continue;}
                    let server=self.clone();let accepted=accepted.clone();
                    requests.spawn(async move {
                        let _permit=permit;
                        let _=tokio::time::timeout(server.limits.request_timeout,server.request(request,respond,ingress,owner,peer_ip,accepted)).await;
                    });
                }
            }
        }
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        Ok(())
    }
    async fn site_h1<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        mut tls: S,
    ) -> io::Result<()> {
        let mut header = Vec::new();
        let mut byte = [0; 1];
        while header.len() < 8192 && !header.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte).await? == 0 {
                return Err(rejected());
            }
            header.push(byte[0]);
        }
        let mut root = false;
        let mut head = false;
        if header.ends_with(b"\r\n\r\n") && header.is_ascii() {
            if let Ok(text) = std::str::from_utf8(&header) {
                let mut lines = text[..text.len() - 4].split("\r\n");
                if let Some(first) = lines.next() {
                    let parts: Vec<_> = first.split(' ').collect();
                    if parts.len() == 3 {
                        head = parts[0] == "HEAD";
                        let mut hosts = 0;
                        let mut correct_host = false;
                        let mut clean = true;
                        for line in lines {
                            let Some((name, value)) = line.split_once(':') else {
                                clean = false;
                                continue;
                            };
                            if name.is_empty()
                                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                                || value.bytes().any(|b| b.is_ascii_control())
                            {
                                clean = false;
                            }
                            if name.eq_ignore_ascii_case("host") {
                                hosts += 1;
                                correct_host = value.trim() == self.settings.client.authority;
                            }
                            if name.eq_ignore_ascii_case("transfer-encoding")
                                || name.eq_ignore_ascii_case("content-length")
                                    && value.trim() != "0"
                            {
                                clean = false;
                            }
                        }
                        root = clean
                            && hosts == 1
                            && correct_host
                            && matches!(parts[0], "GET" | "HEAD")
                            && parts[1] == "/"
                            && parts[2] == "HTTP/1.1";
                    }
                }
            }
        }
        let (status, body) = if root {
            ("200 OK", self.settings.site_html.as_bytes())
        } else {
            ("404 Not Found", b"Not found\n".as_slice())
        };
        let response=format!("HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
        tls.write_all(response.as_bytes()).await?;
        if !head {
            tls.write_all(body).await?;
        }
        tls.shutdown().await
    }
    async fn request(
        &self,
        request: Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        ingress: SocketAddr,
        owner: u64,
        peer_ip: IpAddr,
        accepted: mpsc::Sender<AcceptedSession>,
    ) -> io::Result<()> {
        let admitted = self
            .credential
            .admits(&request, &self.settings.client.authority);
        let path = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_owned());
        if !admitted {
            let root = request.uri().scheme_str() == Some("https")
                && !request.headers().contains_key("host")
                && request
                    .uri()
                    .authority()
                    .is_some_and(|a| a.as_str() == self.settings.client.authority)
                && path.as_deref() == Some("/")
                && matches!(*request.method(), Method::GET | Method::HEAD);
            let head = request.method() == Method::HEAD;
            let body = if root {
                Bytes::copy_from_slice(self.settings.site_html.as_bytes())
            } else {
                Bytes::from_static(b"Not found\n")
            };
            let response = Response::builder()
                .status(if root { 200 } else { 404 })
                .header("content-type", "text/html; charset=utf-8")
                .header("content-length", body.len())
                .body(())
                .map_err(convert)?;
            let send = respond.send_response(response, head).map_err(convert)?;
            if !head {
                protocol::send(send, body).await?;
            }
            return Ok(());
        }
        let body = protocol::collect(
            request.into_body(),
            protocol::HEADER + self.limits.frame_bytes,
        )
        .await;
        let result = match body {
            Ok(body)
                if path.as_deref() == Some(self.settings.client.descriptor_path.as_str())
                    && body.is_empty() =>
            {
                self.descriptor()
                    .and_then(|d| serde_json::to_vec(&d).map(Bytes::from).map_err(convert))
                    .map(|b| (b, "application/json"))
            }
            Ok(body) => self
                .exchange(
                    body,
                    path.as_deref().unwrap_or(""),
                    ingress,
                    owner,
                    peer_ip,
                    &accepted,
                )
                .await
                .map(|b| (b, CONTENT_TYPE)),
            Err(error) => Err(error),
        };
        let (status, body, content) = match result {
            Ok((body, content)) => (200, body, content),
            Err(_) => (
                404,
                Bytes::from_static(b"Not found\n"),
                "text/html; charset=utf-8",
            ),
        };
        let response = Response::builder()
            .status(status)
            .header("content-type", content)
            .header("content-length", body.len())
            .body(())
            .map_err(convert)?;
        protocol::send(
            respond.send_response(response, false).map_err(convert)?,
            body,
        )
        .await
    }
    async fn exchange(
        &self,
        body: Bytes,
        path: &str,
        ingress: SocketAddr,
        owner: u64,
        peer_ip: IpAddr,
        accepted: &mpsc::Sender<AcceptedSession>,
    ) -> io::Result<Bytes> {
        let frame = Frame::decode(body.clone(), self.limits.frame_bytes)?;
        let digest: [u8; 32] = Sha256::digest(&body).into();
        if frame.flags == OPEN && frame.sequence == 0 && frame.ack == 0 && frame.data.is_empty() {
            let _open = self.open_lock.lock().await;
            let exists = {
                let sessions = self.sessions.lock().map_err(|_| failed())?;
                let exists = sessions.contains_key(&frame.id);
                if !exists && sessions.len() >= self.limits.max_sessions {
                    return Err(rejected());
                }
                exists
            };
            if !exists {
                let current = self.descriptor()?;
                if current.path != path
                    || current.ingress != ingress
                    || current.expires_unix_ms <= now_ms()?
                {
                    return Err(rejected());
                }
                let expires_ms = now_ms()?
                    .checked_add(self.limits.max_lifetime.as_millis() as u64)
                    .ok_or_else(rejected)?;
                if let Err(error) = self.ledger.claim(frame.id, owner, expires_ms).await {
                    // A backend can commit before its acknowledgement times
                    // out. Owner-scoped release is safe for that ambiguity.
                    let _ = self.ledger.release(frame.id, owner).await;
                    return Err(error);
                }
                let ledger_claim = ClaimedLedgerSession {
                    ledger: self.ledger.clone(),
                    id: frame.id,
                    owner,
                };
                // The backend may acknowledge an earlier claim after this ingress
                // rotates or its descriptor/session deadline expires.
                if now_ms()? >= expires_ms
                    || self.descriptor()? != current
                    || current.expires_unix_ms <= now_ms()?
                {
                    return Err(rejected());
                }
                let (application, carrier) = tokio::io::duplex(self.limits.frame_bytes * 2);
                let lifetime = Arc::new(Lifetime {
                    opened: Instant::now(),
                    state: AtomicU8::new(0),
                    completed_at_ns: AtomicU64::new(0),
                    limits: self.limits.clone(),
                });
                let application = AcceptedSession {
                    stream: ApplicationStream {
                        io: application,
                        lifetime: lifetime.clone(),
                    },
                    authentication: AuthenticationHandle(lifetime.clone()),
                    peer_ip,
                };
                accepted.try_send(application).map_err(|_| rejected())?;
                let (up, up_receive) = mpsc::channel(2);
                let (down_send, down) = mpsc::channel(2);
                let cancellation = Cancellation::default();
                let stop = cancellation.clone();
                let max = self.limits.frame_bytes;
                let worker = tokio::spawn(async move {
                    tokio::select! {_=stop.cancelled()=>{},_=prepare(carrier,up_receive,down_send,max)=>{}}
                });
                let reply = Reply {
                    id: frame.id,
                    sequence: 0,
                    fin: false,
                    data: Bytes::new(),
                }
                .encode();
                let session = Arc::new(Session {
                    _ledger_claim: ledger_claim,
                    owner,
                    ingress,
                    path: path.into(),
                    lifetime,
                    data: Mutex::new(SessionData {
                        next: 1,
                        previous_digest: digest,
                        previous_reply: reply.clone(),
                        last_activity: Instant::now(),
                        up,
                        down,
                        input_closed: false,
                        output_closed: false,
                    }),
                    exchange_lock: tokio::sync::Mutex::new(()),
                    worker,
                    cancellation,
                });
                self.sessions
                    .lock()
                    .map_err(|_| failed())?
                    .insert(frame.id, session);
                return Ok(reply);
            }
        }
        let session = self
            .sessions
            .lock()
            .map_err(|_| failed())?
            .get(&frame.id)
            .cloned()
            .ok_or_else(rejected)?;
        if session.owner != owner || session.ingress != ingress || session.path != path {
            return Err(rejected());
        }
        let _serial = session.exchange_lock.lock().await;
        let (upload, replay) = {
            let data = session.data.lock().map_err(|_| failed())?;
            if session.lifetime.expired(data.last_activity) {
                session.lifetime.cancel();
                return Err(rejected());
            }
            if frame.sequence.checked_add(1) == Some(data.next) && digest == data.previous_digest {
                (None, Some((data.next, data.previous_reply.clone())))
            } else {
                if frame.sequence != data.next
                    || frame.ack != data.next - 1
                    || frame.flags & OPEN != 0
                    || data.input_closed && (!frame.data.is_empty() || frame.flags & FIN != 0)
                {
                    return Err(rejected());
                }
                if frame.flags & CANCEL != 0 {
                    session.lifetime.cancel();
                    return Err(rejected());
                }
                (
                    if !frame.data.is_empty() || frame.flags & FIN != 0 {
                        Some(data.up.clone())
                    } else {
                        None
                    },
                    None,
                )
            }
        };
        if let Some((next, reply)) = replay {
            self.ledger.verify(frame.id, owner, next).await?;
            let data = session.data.lock().map_err(|_| failed())?;
            if session.lifetime.expired(data.last_activity)
                || data.next != next
                || data.previous_digest != digest
            {
                session.lifetime.cancel();
                return Err(rejected());
            }
            return Ok(reply);
        }
        // Reserve bounded upload capacity before committing the sequence. A
        // cancelled wait cannot partly submit an upload. Once committed, the
        // infallible permit send and cached reply prevent duplicate submission.
        let permit = match upload {
            Some(up) => Some(up.reserve_owned().await.map_err(convert)?),
            None => None,
        };
        let expected_next = {
            let data = session.data.lock().map_err(|_| failed())?;
            if session.lifetime.expired(data.last_activity) {
                session.lifetime.cancel();
                return Err(rejected());
            }
            data.next
        };
        // No ordinary mutex is held across the potentially remote transaction.
        if let Err(error) = self.ledger.advance(frame.id, owner, expected_next).await {
            session.lifetime.cancel();
            return Err(error);
        }
        let mut data = session.data.lock().map_err(|_| failed())?;
        // A remote transaction can finish after the fixed session lifetime or
        // after owner cleanup. Its committed fence must not revive local I/O.
        if session.lifetime.expired(data.last_activity) {
            session.lifetime.cancel();
            return Err(rejected());
        }
        if data.next != expected_next {
            session.lifetime.cancel();
            return Err(rejected());
        }
        // Take only output prepared before this upload. Processing the current
        // upload runs in the owned worker and cannot synthesize these bytes.
        let download = if data.output_closed {
            None
        } else {
            match data.down.try_recv() {
                Ok(d) => Some(d),
                Err(mpsc::error::TryRecvError::Empty) => None,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    session.lifetime.cancel();
                    return Err(failed());
                }
            }
        };
        let (payload, fin) =
            download.map_or((Bytes::new(), data.output_closed), |d| (d.data, d.fin));
        data.output_closed |= fin;
        let reply = Reply {
            id: frame.id,
            sequence: frame.sequence,
            fin,
            data: payload,
        }
        .encode();
        data.next = data.next.checked_add(1).ok_or_else(rejected)?;
        data.previous_digest = digest;
        data.previous_reply = reply.clone();
        data.last_activity = Instant::now();
        if let Some(permit) = permit {
            data.input_closed |= frame.flags & FIN != 0;
            permit.send(Upload {
                data: frame.data,
                fin: frame.flags & FIN != 0,
            });
        }
        Ok(reply)
    }
}
struct ConnectionOwner {
    server: Arc<Server>,
    owner: u64,
}
impl Drop for ConnectionOwner {
    fn drop(&mut self) {
        self.server.remove_owner(self.owner);
    }
}
async fn prepare(
    carrier: DuplexStream,
    mut up: mpsc::Receiver<Upload>,
    down: mpsc::Sender<Download>,
    max: usize,
) {
    let (mut read, mut write) = tokio::io::split(carrier);
    let incoming = async {
        while let Some(upload) = up.recv().await {
            if write.write_all(&upload.data).await.is_err() {
                return;
            }
            if upload.fin {
                let _ = write.shutdown().await;
                return;
            }
        }
    };
    let outgoing = async {
        let mut bytes = vec![0; max];
        loop {
            match read.read(&mut bytes).await {
                Ok(0) => {
                    let _ = down
                        .send(Download {
                            data: Bytes::new(),
                            fin: true,
                        })
                        .await;
                    return;
                }
                Ok(n) => {
                    if down
                        .send(Download {
                            data: Bytes::copy_from_slice(&bytes[..n]),
                            fin: false,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    };
    tokio::join!(incoming, outgoing);
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;

    fn authenticated() -> AuthenticationHandle {
        authenticated_with_timeout(Duration::from_millis(200))
    }

    fn authenticated_with_timeout(request_timeout: Duration) -> AuthenticationHandle {
        let auth = AuthenticationHandle(Arc::new(Lifetime {
            opened: Instant::now(),
            state: AtomicU8::new(0),
            completed_at_ns: AtomicU64::new(0),
            limits: Limits {
                request_timeout,
                max_lifetime: Duration::from_millis(300),
                ..Limits::default()
            },
        }));
        auth.0.limits.validate().unwrap();
        auth.mark_authenticated().unwrap();
        auth
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_poll_activity_cannot_renew_authenticated_max_age() {
        let auth = authenticated();
        for _ in 0..11 {
            tokio::time::advance(Duration::from_millis(25)).await;
            assert!(!auth.0.expired(Instant::now()));
        }
        tokio::time::advance(Duration::from_millis(24)).await;
        assert!(!auth.0.expired(Instant::now()));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(auth.0.expired(Instant::now()));
        assert_eq!(auth.0.state.load(Ordering::Acquire), 2);
        assert!(auth.mark_authenticated().is_err());
        assert!(auth.0.expired(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_poll_activity_cannot_renew_authenticated_application_drain() {
        let auth = authenticated();
        tokio::time::advance(Duration::from_millis(40)).await;
        auth.0.finished();
        assert_eq!(auth.0.state.load(Ordering::Acquire), 3);
        for _ in 0..7 {
            tokio::time::advance(Duration::from_millis(25)).await;
            assert!(!auth.0.expired(Instant::now()));
        }
        tokio::time::advance(Duration::from_millis(24)).await;
        assert!(!auth.0.expired(Instant::now()));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(auth.0.opened.elapsed() < auth.0.limits.max_lifetime);
        assert!(auth.0.expired(Instant::now()));
        assert_eq!(auth.0.state.load(Ordering::Acquire), 2);
        assert!(auth.mark_authenticated().is_err());
        assert!(auth.0.expired(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn application_drain_keeps_full_duration_after_fractional_completion() {
        let auth = authenticated();
        tokio::time::advance(Duration::from_micros(40_500)).await;
        auth.0.finished();
        tokio::time::advance(Duration::from_micros(199_500)).await;
        assert!(
            !auth.0.expired(Instant::now()),
            "drain rounded completion down"
        );
        tokio::time::advance(Duration::from_micros(499)).await;
        assert!(!auth.0.expired(Instant::now()));
        tokio::time::advance(Duration::from_micros(1)).await;
        assert!(auth.0.expired(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn valid_submillisecond_drain_is_not_zero() {
        let auth = authenticated_with_timeout(Duration::from_micros(500));
        tokio::time::advance(Duration::from_micros(10_250)).await;
        auth.0.finished();
        assert!(
            !auth.0.expired(Instant::now()),
            "valid drain collapsed to zero"
        );
        tokio::time::advance(Duration::from_micros(499)).await;
        assert!(!auth.0.expired(Instant::now()));
        tokio::time::advance(Duration::from_micros(1)).await;
        assert!(auth.0.expired(Instant::now()));
    }
}

#[cfg(test)]
#[path = "server_accept_tests.rs"]
mod accept_tests;

#[cfg(test)]
mod resource_observation_tests {
    use super::*;

    #[test]
    fn fixed_observations_start_absent_count_and_preserve_last_known_code() {
        let observations = ResourceAcceptObservations::default();
        assert_eq!(observations.snapshot(), (0, None));
        observations.observe(24);
        observations.observe(23);
        assert_eq!(observations.snapshot(), (2, Some(23)));
    }

    #[test]
    fn fixed_observations_saturate_without_wrapping_or_losing_last_code() {
        let observations = ResourceAcceptObservations {
            count: AtomicU64::new(u64::MAX - 1),
            last_errno: AtomicI32::new(0),
        };
        observations.observe(24);
        observations.observe(23);
        assert_eq!(observations.snapshot(), (u64::MAX, Some(23)));
    }

    #[test]
    fn unspecified_memory_failure_and_unknown_native_code_are_not_resource_retries() {
        assert_eq!(
            resource_accept_errno(&io::Error::from_raw_os_error(123_456)),
            None
        );
        assert_eq!(
            resource_accept_errno(&io::Error::new(io::ErrorKind::OutOfMemory, "fixture")),
            None
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            resource_accept_errno(&io::Error::from_raw_os_error(10_024)),
            None
        );
        #[cfg(windows)]
        assert_eq!(
            resource_accept_errno(&io::Error::from_raw_os_error(24)),
            None
        );
    }
}
