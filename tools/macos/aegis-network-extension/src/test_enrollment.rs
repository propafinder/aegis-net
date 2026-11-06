//! cfg(test)-only loopback enrollment authority for the S23 renewal tests:
//! outer TLS (the tree's outer identity, ALPN h2), one H2 POST to the
//! enrollment gRPC path per connection (aegis-server
//! `enrollment_service`: max_concurrent_streams 1), aegis-core's own
//! `enrollment_tls::Authority` inner TLS, a real `ConnectionChallenge`, the
//! device's proof verified against its CSR key, and a response chosen per
//! request. An issued receipt is remembered by request id, so a later
//! receipt-purpose request recovers it, as the authority's journal does.
//! Nothing here is reachable from a production build or names a real host.
use crate::{test_fixture::ReadyTree, test_relay::outer_acceptor};
use aegis_core::{
    h2_stream::H2Stream,
    secure_channel::{
        enrollment::{
            self,
            protocol::{self, ConnectionChallenge, ProofPurpose},
        },
        enrollment_tls::{self, Authority, AuthoritySettings},
        enrollment_wire::{
            self as wire, EnrollmentReceipt, ExchangeResponse, FailureCode, ReceiptState,
        },
        grpc_io::GrpcIo,
        registry,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, DirBuilder},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The successor's issued generation and snapshot.
pub(crate) const RENEWED_GENERATION: u64 = 8;
pub(crate) const RENEWED_SNAPSHOT: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// What the authority does with one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Issue (or, for a receipt request, return the remembered receipt).
    Issue,
    Busy,
    Unavailable,
    Rejected,
    RecoveryRequired,
    /// Issue and remember, then end the connection without the response.
    DropResponse,
    /// End the connection right after the TCP accept.
    Close,
    /// Hold the TCP connection open and never answer.
    Hang,
    /// Issue and remember, then hold the connection open without the
    /// response (a committed answer lost on a stalled path).
    Stall,
    /// v32: as `Issue`, then the receipt sent is changed by the authority's
    /// `edit` (a receipt this client must refuse).
    IssueEdited,
    /// v32: read the request, then end the connection with no answer and
    /// nothing issued (the request's outcome stays unknown to the client).
    Drop,
}

/// A pre-signed successor certificate for the tree's CSR.
#[derive(Clone)]
pub(crate) struct Successor {
    pub(crate) certificate_pem: String,
    pub(crate) fingerprint: String,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}

impl Successor {
    /// Signed now, valid for `lifetime_secs`, by the tree's device CA.
    pub(crate) fn for_tree(tree: &ReadyTree, lifetime_secs: u64) -> Self {
        Self::signed_at(tree, registry::unix_now().unwrap(), lifetime_secs)
    }

    /// Signed with `not_before`, valid for `lifetime_secs`.
    pub(crate) fn signed_at(tree: &ReadyTree, not_before: u64, lifetime_secs: u64) -> Self {
        Self::signed_by(
            tree,
            tree.device_ca_pem(),
            tree.device_ca_key_pem(),
            not_before,
            lifetime_secs,
        )
    }

    /// v32: the tree's CSR signed by the CA `ca_pem` (key `ca_key_pem`),
    /// which need not be the tree's pinned device CA.
    pub(crate) fn signed_by(
        tree: &ReadyTree,
        ca_pem: &str,
        ca_key_pem: &str,
        not_before: u64,
        lifetime_secs: u64,
    ) -> Self {
        let now = not_before;
        let issued = enrollment::sign_csr(
            tree.device_id(),
            tree.csr_pem(),
            ca_pem,
            ca_key_pem,
            now,
            lifetime_secs,
        )
        .unwrap();
        Self {
            certificate_pem: issued.certificate_pem,
            fingerprint: issued.record.certificate_sha256,
            not_before: now,
            not_after: issued.record.not_after_unix_secs,
        }
    }
}

/// One request as the authority saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) purpose: ProofPurpose,
    pub(crate) request_id: String,
    pub(crate) answer: Answer,
    /// v45: the request's operation and whether it carried an invitation.
    pub(crate) operation: protocol::Operation,
    pub(crate) invited: bool,
}

/// v45: a first-enrollment authority: it issues a fresh certificate for the
/// request's own CSR, signed by the tree's device CA, to one invitation
/// token, once (a used token is rejected for any other request).
struct Redeem {
    token: String,
    ca_pem: String,
    ca_key_pem: String,
    lifetime_secs: u64,
    /// The request id the token was spent on.
    spent: Mutex<Option<String>>,
}

type Answers = Box<dyn FnMut(usize, Option<ProofPurpose>) -> Answer + Send>;
/// v32: a check run when a request has been read, before any answer.
type Probe = Box<dyn Fn() -> bool + Send>;

struct Shared {
    redeem: Option<Redeem>,
    successor: Successor,
    device_id: String,
    profile_sha256: String,
    issued: Mutex<HashMap<String, EnrollmentReceipt>>,
    seen: Mutex<Vec<Seen>>,
    answers: Mutex<Answers>,
    // Seconds the authority's clock leads the device's.
    ahead: AtomicU64,
    // v32: how `IssueEdited` changes a receipt.
    edit: Mutex<Option<fn(&mut EnrollmentReceipt)>>,
    // v32: the request probe and its results, in request order.
    probe: Mutex<Option<Probe>>,
    probed: Mutex<Vec<bool>>,
}

pub(crate) struct TestAuthority {
    accepts: Arc<AtomicUsize>,
    shared: Arc<Shared>,
    dir: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl TestAuthority {
    /// Bind first: the ReadyTree's profile must name this address.
    pub(crate) fn bind() -> std::net::TcpListener {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }

    /// Serve every connection. `answers(index, None)` is asked at the TCP
    /// accept (only `Close` acts there); `answers(index, Some(purpose))`
    /// picks the reply to that connection's request.
    pub(crate) fn spawn(
        listener: std::net::TcpListener,
        tree: &ReadyTree,
        successor: Successor,
        answers: impl FnMut(usize, Option<ProofPurpose>) -> Answer + Send + 'static,
    ) -> Self {
        Self::spawn_with(listener, tree, successor, None, answers)
    }

    /// v45: a first-enrollment (Redeem) authority for the tree's profile
    /// and device CA, accepting `token` once and issuing certificates valid
    /// for `lifetime_secs` from its own clock.
    pub(crate) fn spawn_redeem(
        listener: std::net::TcpListener,
        tree: &ReadyTree,
        token: &str,
        lifetime_secs: u64,
        answers: impl FnMut(usize, Option<ProofPurpose>) -> Answer + Send + 'static,
    ) -> Self {
        let redeem = Redeem {
            token: token.to_owned(),
            ca_pem: tree.device_ca_pem().to_owned(),
            ca_key_pem: tree.device_ca_key_pem().to_owned(),
            lifetime_secs,
            spent: Mutex::default(),
        };
        // The renewal successor is never used by a Redeem authority.
        let unused = Successor::for_tree(tree, lifetime_secs);
        Self::spawn_with(listener, tree, unused, Some(redeem), answers)
    }

    fn spawn_with(
        listener: std::net::TcpListener,
        tree: &ReadyTree,
        successor: Successor,
        redeem: Option<Redeem>,
        answers: impl FnMut(usize, Option<ProofPurpose>) -> Answer + Send + 'static,
    ) -> Self {
        let (outer_cert, outer_key) = tree.outer_server_der();
        let outer = outer_acceptor(
            outer_cert,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(outer_key)),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "aegis-ne-test-authority-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let (cert_pem, key_pem) = tree.issuer_server_pem();
        let cert = dir.join("issuer.pem");
        let key = dir.join("issuer.key");
        for (path, bytes) in [(&cert, cert_pem), (&key, key_pem)] {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let authority = Authority::load(&AuthoritySettings { cert, key }).unwrap();
        let shared = Arc::new(Shared {
            redeem,
            successor,
            device_id: tree.device_id().to_owned(),
            profile_sha256: tree.profile_sha256().to_owned(),
            issued: Mutex::default(),
            seen: Mutex::default(),
            answers: Mutex::new(Box::new(answers)),
            ahead: AtomicU64::new(0),
            edit: Mutex::default(),
            probe: Mutex::default(),
            probed: Mutex::default(),
        });
        let accepts = Arc::new(AtomicUsize::new(0));
        let (shutdown, mut stop) = oneshot::channel::<()>();
        let (counted, served) = (accepts.clone(), shared.clone());
        let thread = thread::Builder::new()
            .name("aegis-ne-test-authority".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener).unwrap();
                    let mut tasks = Vec::new();
                    loop {
                        tokio::select! {
                            _ = &mut stop => break,
                            accepted = listener.accept() => {
                                let Ok((tcp, _)) = accepted else { continue };
                                let index = counted.fetch_add(1, Ordering::SeqCst);
                                let (outer, authority, shared) =
                                    (outer.clone(), authority.clone(), served.clone());
                                tasks.push(tokio::spawn(async move {
                                    serve(tcp, index, outer, authority, shared).await;
                                }));
                            }
                        }
                    }
                    for task in &tasks {
                        task.abort();
                    }
                });
            })
            .unwrap();
        Self {
            accepts,
            shared,
            dir,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    /// TCP connections accepted so far.
    pub(crate) fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Requests read so far.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.shared.seen.lock().unwrap().clone()
    }

    /// Run the authority's challenges `secs` ahead of the device's clock.
    pub(crate) fn set_clock_ahead(&self, secs: u64) {
        self.shared.ahead.store(secs, Ordering::SeqCst);
    }

    /// Distinct issued receipts.
    pub(crate) fn issued(&self) -> usize {
        self.shared.issued.lock().unwrap().len()
    }

    /// Remember the successor as already issued for `binding`, as an
    /// authority that committed a response its client never received.
    pub(crate) fn remember(&self, binding: protocol::RequestBinding) {
        self.remember_as(binding, &self.shared.successor);
    }

    /// v32: remember `successor` (not the spawned one) as issued for
    /// `binding`.
    pub(crate) fn remember_as(&self, binding: protocol::RequestBinding, successor: &Successor) {
        let receipt = receipt_for(successor, &self.shared.device_id, binding.clone());
        self.shared
            .issued
            .lock()
            .unwrap()
            .insert(binding.request_id, receipt);
    }

    /// v32: how `Answer::IssueEdited` changes each receipt it sends.
    pub(crate) fn edit(&self, edit: fn(&mut EnrollmentReceipt)) {
        *self.shared.edit.lock().unwrap() = Some(edit);
    }

    /// v32: run `probe` on every request read, before its answer.
    pub(crate) fn probe(&self, probe: impl Fn() -> bool + Send + 'static) {
        *self.shared.probe.lock().unwrap() = Some(Box::new(probe));
    }

    /// v32: the probe's results so far.
    pub(crate) fn probed(&self) -> Vec<bool> {
        self.shared.probed.lock().unwrap().clone()
    }
}

fn receipt_for(
    successor: &Successor,
    device_id: &str,
    binding: protocol::RequestBinding,
) -> EnrollmentReceipt {
    EnrollmentReceipt {
        version: 1,
        binding,
        device_id: device_id.into(),
        certificate_pem: successor.certificate_pem.clone(),
        certificate_sha256: successor.fingerprint.clone(),
        not_before_unix_secs: successor.not_before,
        not_after_unix_secs: successor.not_after,
        issued_generation: RENEWED_GENERATION,
        snapshot_sha256: RENEWED_SNAPSHOT.into(),
        state: ReceiptState::IssuedPendingDistribution,
    }
}

impl Drop for TestAuthority {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn drive(mut connection: h2::server::Connection<crate::test_relay::OuterTls, bytes::Bytes>) {
    while let Some(Ok(_)) = connection.accept().await {}
}

fn pick(shared: &Shared, index: usize, purpose: Option<ProofPurpose>) -> Answer {
    let mut answers = shared.answers.lock().unwrap();
    (answers)(index, purpose)
}

fn reply(
    shared: &Shared,
    request: &wire::ExchangeRequest,
    answer: Answer,
) -> Option<ExchangeResponse> {
    let failed = |code| Some(ExchangeResponse::Failed { code });
    match answer {
        Answer::Busy => failed(FailureCode::Busy),
        Answer::Unavailable => failed(FailureCode::Unavailable),
        Answer::Rejected => failed(FailureCode::Rejected),
        Answer::RecoveryRequired => failed(FailureCode::RecoveryRequired),
        Answer::Close | Answer::Hang | Answer::Drop => None,
        Answer::Issue | Answer::IssueEdited | Answer::DropResponse | Answer::Stall => {
            let mut issued = shared.issued.lock().unwrap();
            let id = request.binding.request_id.clone();
            let receipt = match (issued.get(&id), request.purpose) {
                (Some(receipt), _) => Some(receipt.clone()),
                (None, ProofPurpose::Receipt) => None,
                (None, ProofPurpose::Authorize) if shared.redeem.is_some() => {
                    let redeem = shared.redeem.as_ref().unwrap();
                    let mut spent = redeem.spent.lock().unwrap();
                    let valid = request.binding.operation == protocol::Operation::Redeem
                        && request.binding.profile_sha256 == shared.profile_sha256
                        && request.invitation.as_deref() == Some(redeem.token.as_str())
                        && spent.as_ref().is_none_or(|used| *used == id);
                    if valid {
                        let now =
                            registry::unix_now().unwrap() + shared.ahead.load(Ordering::SeqCst);
                        let signed = enrollment::sign_csr(
                            &shared.device_id,
                            &request.csr_pem,
                            &redeem.ca_pem,
                            &redeem.ca_key_pem,
                            now,
                            redeem.lifetime_secs,
                        )
                        .unwrap();
                        *spent = Some(id.clone());
                        let receipt = EnrollmentReceipt {
                            version: 1,
                            binding: request.binding.clone(),
                            device_id: shared.device_id.clone(),
                            certificate_pem: signed.certificate_pem,
                            certificate_sha256: signed.record.certificate_sha256,
                            not_before_unix_secs: now,
                            not_after_unix_secs: signed.record.not_after_unix_secs,
                            issued_generation: crate::test_fixture::ISSUED_GENERATION,
                            snapshot_sha256: crate::test_fixture::SNAPSHOT_SHA256.into(),
                            state: ReceiptState::IssuedPendingDistribution,
                        };
                        issued.insert(id, receipt.clone());
                        Some(receipt)
                    } else {
                        None
                    }
                }
                (None, ProofPurpose::Authorize) => {
                    assert_eq!(request.binding.profile_sha256, shared.profile_sha256);
                    assert_eq!(
                        request.binding.csr_sha256,
                        sha256_hex(request.csr_pem.as_bytes())
                    );
                    let receipt = receipt_for(
                        &shared.successor,
                        &shared.device_id,
                        request.binding.clone(),
                    );
                    issued.insert(id, receipt.clone());
                    Some(receipt)
                }
            };
            if matches!(answer, Answer::DropResponse | Answer::Stall) {
                return None;
            }
            let edit = *shared.edit.lock().unwrap();
            let receipt = match (receipt, edit) {
                (Some(mut receipt), Some(edit)) if answer == Answer::IssueEdited => {
                    edit(&mut receipt);
                    Some(receipt)
                }
                (receipt, _) => receipt,
            };
            match receipt {
                Some(receipt) => Some(ExchangeResponse::Issued {
                    receipt: Box::new(receipt),
                }),
                None => failed(FailureCode::Rejected),
            }
        }
    }
}

async fn serve(
    tcp: tokio::net::TcpStream,
    index: usize,
    outer: tokio_rustls::TlsAcceptor,
    authority: Authority,
    shared: Arc<Shared>,
) {
    match pick(&shared, index, None) {
        Answer::Close => {
            drop(tcp);
            return;
        }
        Answer::Hang => {
            let _held = tcp;
            std::future::pending::<()>().await;
            return;
        }
        _ => {}
    }
    let Ok(tls) = outer.accept(tcp).await else {
        return;
    };
    let Ok(mut connection) = h2::server::handshake(tls).await else {
        return;
    };
    let Some(Ok((request, mut response))) = connection.accept().await else {
        return;
    };
    assert_eq!(request.uri().path(), enrollment_tls::GRPC_PATH);
    let Ok(sender) = response.send_response(
        http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap(),
        false,
    ) else {
        return;
    };
    let driver = tokio::spawn(drive(connection));
    let carrier = GrpcIo::new(H2Stream::new(sender, request.into_body()));
    let exchange = async {
        let mut inner = authority.accept(carrier).await.ok()?;
        let now = registry::unix_now().ok()? + shared.ahead.load(Ordering::SeqCst);
        let mut challenge = ConnectionChallenge::new(now).ok()?;
        wire::write_challenge(&mut inner, &challenge.message())
            .await
            .ok()?;
        let request = wire::read_request(&mut inner).await.ok()?;
        let key = protocol::csr_public_key(&request.csr_pem).ok()?;
        let signature = request.proof_signature().ok()?;
        challenge
            .verify(&request.binding, request.purpose, &key, &signature, now)
            .ok()?;
        if let Some(probe) = shared.probe.lock().unwrap().as_ref() {
            let result = probe();
            shared.probed.lock().unwrap().push(result);
        }
        let answer = pick(&shared, index, Some(request.purpose));
        shared.seen.lock().unwrap().push(Seen {
            purpose: request.purpose,
            request_id: request.binding.request_id.clone(),
            answer,
            operation: request.binding.operation,
            invited: request.invitation.is_some(),
        });
        let response = reply(&shared, &request, answer);
        if answer == Answer::Stall {
            std::future::pending::<()>().await;
        }
        let response = response?;
        wire::write_response(&mut inner, &response).await.ok()?;
        // Let the response reach the client before the connection drops.
        tokio::time::sleep(Duration::from_millis(100)).await;
        Some(())
    };
    // Longer than a whole renewal step, so a stall outlives the client's.
    let _ = tokio::time::timeout(Duration::from_secs(25), exchange).await;
    driver.abort();
    let _ = driver.await;
}
