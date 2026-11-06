#![cfg(feature = "postgres-integration")]

use aegis_web_carrier::{PostgresSessionLedger, SessionLedger};
use std::{
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_postgres::{Client, NoTls};

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);
// The lock-timeout test intentionally holds the database-wide advisory key.
// Other cases use isolated schemas but still share that key on this server.
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn raw_connect() -> Client {
    let dsn = std::env::var("AEGIS_TEST_POSTGRES_DSN")
        .unwrap_or_else(|_| panic!("AEGIS_TEST_POSTGRES_DSN is required"));
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .unwrap_or_else(|_| {
            panic!("AEGIS_TEST_POSTGRES_DSN was set but PostgreSQL was unreachable")
        });
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn test_database() -> (Client, String) {
    let admin = raw_connect().await;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let schema = format!(
        "aegis_ledger_test_{}_{}_{}",
        std::process::id(),
        nonce,
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    );
    // This generated identifier cannot reference an existing production
    // schema. Tests never drop or mutate the application's ledger table.
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    (admin, schema)
}

async fn connect(schema: &str) -> Client {
    let client = raw_connect().await;
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    client
}

async fn cleanup(admin: Client, schema: &str) {
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

// Called through the existing listed test name in a fresh OS process. No app
// stream is transferred: this covers only the durable owner/sequence fence.
async fn cross_process_ledger_child(schema: &str) {
    assert!(generated_schema_ok(schema), "cross-process schema rejected");
    let expected: u64 = std::env::var("AEGIS_B08_CHILD_NEXT")
        .unwrap()
        .parse()
        .unwrap();
    let ledger = PostgresSessionLedger::new(
        connect(schema).await,
        2,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    assert!(ledger.verify([77; 32], 72, expected).await.is_err());
    ledger.verify([77; 32], 71, expected).await.unwrap();
    if expected > 1 {
        assert!(ledger.verify([77; 32], 71, expected - 1).await.is_err());
    }
    ledger.advance([77; 32], 71, expected).await.unwrap();
    assert!(ledger.advance([77; 32], 71, expected).await.is_err());
    println!("CROSS_PROCESS_LEDGER_CHILD_PASS");
}

fn run_ledger_child(schema: &str, expected: u64) -> std::io::Result<()> {
    struct ChildGuard(Option<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut child = ChildGuard(Some(
        Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("two_connections_fence_claim_advance_and_recover_after_reconnect")
            .arg("--nocapture")
            .env("AEGIS_B08_CHILD_SCHEMA", schema)
            .env("AEGIS_B08_CHILD_NEXT", expected.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.0.as_mut().expect("child owned").try_wait()?.is_some() {
            let output = child.0.take().expect("child owned").wait_with_output()?;
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .contains("CROSS_PROCESS_LEDGER_CHILD_PASS")
            {
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "child ledger check failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child ledger check timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

async fn connect_for_cross_process_test(
    schema: &str,
) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    if !generated_schema_ok(schema) {
        return Err(std::io::Error::other("cross-process schema rejected").into());
    }
    let dsn = std::env::var("AEGIS_TEST_POSTGRES_DSN")?;
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await?;
    Ok(client)
}

fn generated_schema_ok(schema: &str) -> bool {
    let Some(parts) = schema.strip_prefix("aegis_ledger_test_") else {
        return false;
    };
    if schema.len() > 63 {
        return false;
    }
    let mut fields = parts.split('_');
    (0..3).all(|_| {
        fields
            .next()
            .is_some_and(|field| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()))
    }) && fields.next().is_none()
}

async fn cross_process_database(
) -> Result<(Client, String), Box<dyn std::error::Error + Send + Sync>> {
    let dsn = std::env::var("AEGIS_TEST_POSTGRES_DSN")?;
    let (admin, connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let schema = format!(
        "aegis_ledger_test_{}_{}_{}",
        std::process::id(),
        nonce,
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    );
    if !generated_schema_ok(&schema) {
        return Err(std::io::Error::other("generated schema rejected").into());
    }
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await?;
    Ok((admin, schema))
}

fn expect_rejected(result: std::io::Result<()>) -> std::io::Result<()> {
    if result.is_ok() {
        Err(std::io::Error::other("ledger unexpectedly accepted"))
    } else {
        Ok(())
    }
}

async fn cross_process_owner_and_sequence_fence_survives_connection_loss() {
    let (admin, schema) = cross_process_database().await.unwrap();
    let outcome = async {
        let parent = PostgresSessionLedger::new(
            connect_for_cross_process_test(&schema).await?,
            2,
            Duration::from_secs(2),
            Duration::from_secs(3600),
        )
        .await?;
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .checked_add(60_000)
            .and_then(|ms| u64::try_from(ms).ok())
            .ok_or_else(|| std::io::Error::other("test expiry overflow"))?;
        parent.claim([77; 32], 71, expires).await?;
        let forged = format!("{schema}; DROP SCHEMA {schema} CASCADE; --");
        let rejected = tokio::task::spawn_blocking(move || run_ledger_child(&forged, 1)).await?;
        match rejected {
            Err(error) if error.to_string().contains("cross-process schema rejected") => {}
            _ => return Err(std::io::Error::other("forged child schema was not refused").into()),
        }
        parent.verify([77; 32], 71, 1).await?;
        let first_schema = schema.clone();
        tokio::task::spawn_blocking(move || run_ledger_child(&first_schema, 1)).await??;
        expect_rejected(parent.verify([77; 32], 71, 1).await)?;
        parent.verify([77; 32], 71, 2).await?;
        drop(parent);
        let second_schema = schema.clone();
        tokio::task::spawn_blocking(move || run_ledger_child(&second_schema, 2)).await??;
        let reconnected = PostgresSessionLedger::new(
            connect_for_cross_process_test(&schema).await?,
            2,
            Duration::from_secs(2),
            Duration::from_secs(3600),
        )
        .await?;
        reconnected.verify([77; 32], 71, 3).await?;
        expect_rejected(reconnected.verify([77; 32], 72, 3).await)?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup_result = admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await;
    assert!(
        cleanup_result.is_ok(),
        "disposable schema cleanup failed: {cleanup_result:?}"
    );
    outcome.unwrap();
}

fn expiry() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000
}

#[tokio::test]
async fn two_connections_fence_claim_advance_and_recover_after_reconnect() {
    if std::env::var_os("AEGIS_B08_PROCESS_CHILD").is_some() {
        run_process_child().await;
        return;
    }
    if let Ok(schema) = std::env::var("AEGIS_B08_CHILD_SCHEMA") {
        cross_process_ledger_child(&schema).await;
        return;
    }
    let _serial = TEST_LOCK.lock().await;
    let (admin, schema) = test_database().await;
    let a = PostgresSessionLedger::new(
        connect(&schema).await,
        2,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let b = PostgresSessionLedger::new(
        connect(&schema).await,
        2,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let (one, two) = tokio::join!(a.claim([1; 32], 7, expiry()), b.claim([1; 32], 8, expiry()));
    assert_ne!(one.is_ok(), two.is_ok());
    let owner = if one.is_ok() { 7 } else { 8 };
    assert!(a.claim([1; 32], owner, expiry()).await.is_err());
    assert!(a.verify([1; 32], owner + 1, 1).await.is_err());
    b.verify([1; 32], owner, 1).await.unwrap();
    let (one, two) = tokio::join!(a.advance([1; 32], owner, 1), b.advance([1; 32], owner, 1));
    assert_ne!(one.is_ok(), two.is_ok());
    assert!(a.advance([1; 32], owner, 1).await.is_err());
    drop(a);
    let reconnected = PostgresSessionLedger::new(
        connect(&schema).await,
        2,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    reconnected.verify([1; 32], owner, 2).await.unwrap();
    reconnected.claim([2; 32], 9, expiry()).await.unwrap();
    assert!(b.claim([3; 32], 10, expiry()).await.is_err());
    admin
        .execute(
            "UPDATE aegis_web_session_ledger SET expires_ms = 0 WHERE id = $1",
            &[&&[2u8; 32][..]],
        )
        .await
        .unwrap();
    assert!(b.verify([2; 32], 9, 1).await.is_err());
    b.claim([3; 32], 10, expiry()).await.unwrap();
    let rows = admin
        .query(
            "SELECT id, owner, next, expires_ms FROM aegis_web_session_ledger",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(PostgresSessionLedger::new(
        connect(&schema).await,
        3,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .is_err());
    drop(b);
    drop(reconnected);
    cleanup(admin, &schema).await;
    cross_process_owner_and_sequence_fence_survives_connection_loss().await;
    let db_cycle = std::env::var_os("AEGIS_B08_DB_CYCLE_DIR").is_some();
    tokio::time::timeout(
        Duration::from_secs(if db_cycle { 105 } else { 45 }),
        two_process_network_postgres_lifecycle(),
    )
    .await
    .expect("B08 two-process lifecycle exceeded 45-second deadline");
}

#[tokio::test]
async fn owner_release_reclaims_postgres_capacity_and_revokes_sequence() {
    let _serial = TEST_LOCK.lock().await;
    let (admin, schema) = test_database().await;
    let a = PostgresSessionLedger::new(
        connect(&schema).await,
        1,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let b = PostgresSessionLedger::new(
        connect(&schema).await,
        1,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    a.claim([41; 32], 17, expiry()).await.unwrap();
    assert!(b.claim([42; 32], 18, expiry()).await.is_err());
    assert!(b.release([41; 32], 18).await.is_err());
    a.verify([41; 32], 17, 1).await.unwrap();
    b.release([41; 32], 17).await.unwrap();
    assert!(b.claim([41; 32], 19, expiry()).await.is_err());
    assert!(a.verify([41; 32], 17, 1).await.is_err());
    assert!(a.advance([41; 32], 17, 1).await.is_err());
    b.claim([42; 32], 18, expiry()).await.unwrap();
    b.verify([42; 32], 18, 1).await.unwrap();
    drop(a);
    drop(b);
    cleanup(admin, &schema).await;
}

#[tokio::test]
async fn lock_timeout_rejects_without_creating_a_claim() {
    let _serial = TEST_LOCK.lock().await;
    let (admin, schema) = test_database().await;
    let ledger = PostgresSessionLedger::new(
        connect(&schema).await,
        2,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    admin
        .execute("SELECT pg_advisory_lock(1095069037)", &[])
        .await
        .unwrap();
    assert!(ledger.claim([4; 32], 11, expiry()).await.is_err());
    admin
        .execute("SELECT pg_advisory_unlock(1095069037)", &[])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let count: i64 = admin
        .query_one(
            "SELECT count(*) FROM aegis_web_session_ledger WHERE id = $1",
            &[&&[4u8; 32][..]],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    drop(ledger);
    cleanup(admin, &schema).await;
}

#[tokio::test]
async fn distinct_concurrent_claims_obey_shared_capacity() {
    let _serial = TEST_LOCK.lock().await;
    let (admin, schema) = test_database().await;
    let a = PostgresSessionLedger::new(
        connect(&schema).await,
        1,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let b = PostgresSessionLedger::new(
        connect(&schema).await,
        1,
        Duration::from_secs(2),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let (one, two) = tokio::join!(
        a.claim([5; 32], 12, expiry()),
        b.claim([6; 32], 13, expiry())
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let count: i64 = admin
        .query_one("SELECT count(*) FROM aegis_web_session_ledger", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    drop(a);
    drop(b);
    cleanup(admin, &schema).await;
}

fn b08_executable_digest() -> [u8; 32] {
    // The identity is immutable for this process. Hash before READY/session
    // establishment: debug executables can be large, and synchronous disk/CPU
    // work must not starve the single-thread Tokio reactor during live mTLS.
    static DIGEST: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(b08_read_executable_digest)
}

fn b08_read_executable_digest() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(std::env::current_exe().expect("test executable")).unwrap();
    let before = file.metadata().unwrap();
    let mut hash = Sha256::new();
    let mut block = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut block).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&block[..count]);
    }
    let after = file.metadata().unwrap();
    assert_eq!(
        before.len(),
        after.len(),
        "test executable changed during digest"
    );
    hash.finalize().into()
}

struct B08ProcessGuard(std::process::Child, std::path::PathBuf);
impl Drop for B08ProcessGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Generated-fixture diagnostics only; retain the child's actual
            // failure before its temporary directory and process are disposed.
            eprintln!(
                "B08 child output: {}",
                std::fs::read_to_string(&self.1).unwrap_or_default()
            );
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    eprintln!("B08 child bounded reap incomplete");
                    return;
                }
            }
        }
    }
}

struct B08SchemaGuard {
    dsn: String,
    schema: String,
    armed: bool,
}
impl B08SchemaGuard {
    async fn clear(&mut self) -> Result<(), String> {
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let (client, connection) = tokio_postgres::connect(&self.dsn, NoTls)
                .await
                .map_err(|error| error.to_string())?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
                .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .await
                .map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT count(*) FROM pg_namespace WHERE nspname=$1",
                    &[&self.schema],
                )
                .await
                .map_err(|error| error.to_string())?;
            let remaining: i64 = row.get(0);
            if remaining != 0 {
                return Err("disposable schema remains".into());
            }
            Ok::<(), String>(())
        })
        .await;
        match result {
            Ok(Ok(())) => {
                self.armed = false;
                Ok(())
            }
            Ok(Err(error)) => Err(format!("B08 schema cleanup/query failed: {error}")),
            Err(_) => Err("B08 schema cleanup deadline exceeded".into()),
        }
    }
}
impl Drop for B08SchemaGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let dsn = self.dsn.clone();
        let schema = self.schema.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let start = std::thread::Builder::new()
            .name("b08-schema-cleanup".into())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string())
                    .and_then(|runtime| {
                        runtime.block_on(async move {
                            tokio::time::timeout(Duration::from_secs(5), async {
                                let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
                                    .await
                                    .map_err(|error| error.to_string())?;
                                tokio::spawn(async move {
                                    let _ = connection.await;
                                });
                                client
                                    .batch_execute(&format!(
                                        "DROP SCHEMA IF EXISTS {schema} CASCADE"
                                    ))
                                    .await
                                    .map_err(|error| error.to_string())
                            })
                            .await
                            .map_err(|_| "cleanup deadline".to_string())?
                        })
                    });
                let _ = send.send(result);
            });
        if start.is_err() {
            eprintln!("B08 schema backup cleanup thread failed to start");
            return;
        }
        match receive.recv_timeout(Duration::from_secs(6)) {
            Ok(Ok(())) => eprintln!("B08 schema backup cleanup completed"),
            Ok(Err(error)) => eprintln!("B08 schema backup cleanup failed: {error}"),
            Err(_) => eprintln!("B08 schema backup cleanup wait exceeded 6 seconds"),
        }
    }
}

fn b08_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} missing"))
}
fn b08_private(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

async fn run_process_child() {
    use aegis_core::secure_channel::{Server as InnerServer, ServerSettings as InnerSettings};
    use aegis_web_carrier::{
        Cancellation, ClientSettings, Credential, Limits, Server, ServerSettings,
    };
    use rustls::{
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use sha2::{Digest, Sha256};
    use std::{path::PathBuf, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
    };
    use tokio_rustls::TlsAcceptor;
    use zeroize::Zeroizing;
    let executable_digest = b08_executable_digest();
    let schema = b08_env("AEGIS_B08_PROCESS_SCHEMA");
    assert!(generated_schema_ok(&schema));
    let (pg, connection) = tokio_postgres::connect(&b08_env("AEGIS_TEST_POSTGRES_DSN"), NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    pg.batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let ledger = Arc::new(
        PostgresSessionLedger::new(pg, 64, Duration::from_secs(2), Duration::from_secs(3600))
            .await
            .unwrap(),
    );
    let outer_cert = std::fs::read(b08_env("AEGIS_B08_OUTER_CERT")).unwrap();
    let outer_key = std::fs::read(b08_env("AEGIS_B08_OUTER_KEY")).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(outer_cert)],
            PrivatePkcs8KeyDer::from(outer_key).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let inner = Arc::new(
        InnerServer::load(&InnerSettings {
            cert: PathBuf::from(b08_env("AEGIS_B08_INNER_CERT")),
            key: PathBuf::from(b08_env("AEGIS_B08_INNER_KEY")),
            client_ca: PathBuf::from(b08_env("AEGIS_B08_INNER_CA")),
            allowed_client_sha256: vec![b08_env("AEGIS_B08_INNER_CLIENT_HASH")],
            device_registry: None,
            handshake_timeout_ms: 2000,
            idle_timeout_ms: 2000,
            admission: Default::default(),
        })
        .unwrap(),
    );
    let limits = Limits::default();
    let settings = ClientSettings {
        authority: "site.test".into(),
        descriptor_path: "/private/descriptor".into(),
        credential_file: PathBuf::from("/fixture/private/key"),
    };
    let bridge = Credential::from_private_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap();
    let server = Server::with_ledger(
        ServerSettings {
            client: settings,
            site_html: "<title>Site</title>".into(),
        },
        bridge,
        limits.clone(),
        ledger,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (send, mut recv) = mpsc::channel(limits.max_sessions);
    let stop = Cancellation::default();
    let task = tokio::spawn(server.clone().serve(
        listener,
        TlsAcceptor::from(Arc::new(tls)),
        send,
        stop.clone(),
    ));
    std::fs::write(b08_env("AEGIS_B08_PROCESS_READY"), address.to_string()).unwrap();
    let stop_file = PathBuf::from(b08_env("AEGIS_B08_PROCESS_STOP"));
    loop {
        tokio::select! {
            accepted=recv.recv()=> {
                let accepted=accepted.expect("accepted channel closed");
                let inner=inner.clone();
                tokio::spawn(async move {
                    let (io,authentication)=accepted.into_parts();
                    let _permit=inner.try_acquire().unwrap();
                    let (mut tls,_lease)=inner.accept_with_lease(io).await.unwrap();
                    authentication.mark_authenticated().unwrap();
                    let mut challenge=[0u8;32];
                    tls.read_exact(&mut challenge).await.unwrap();
                    let mut digest=Sha256::new();digest.update(executable_digest);digest.update(challenge);
                    tls.write_all(&digest.finalize()).await.unwrap();tls.flush().await.unwrap();
                });
            },
            _=tokio::time::sleep(Duration::from_millis(20))=>{if stop_file.exists(){break;}}
        }
    }
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

fn b08_outer_connector(cert: Vec<u8>) -> tokio_rustls::TlsConnector {
    use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert)).unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

fn b08_certificates(
    dir: &std::path::Path,
) -> (Vec<u8>, aegis_core::secure_channel::Client, String) {
    use aegis_core::secure_channel::{Client as InnerClient, ClientSettings};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use sha2::{Digest, Sha256};
    let outer = rcgen::generate_simple_self_signed(vec!["site.test".into()]).unwrap();
    let outer_der = outer.cert.der().as_ref().to_vec();
    b08_private(&dir.join("outer.der"), &outer_der);
    b08_private(&dir.join("outer.key"), &outer.key_pair.serialize_der());
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    b08_private(&dir.join("inner-ca.pem"), ca.pem().as_bytes());
    let mut pinned = String::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("allowed.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        b08_private(&dir.join(format!("{name}.pem")), cert.pem().as_bytes());
        b08_private(
            &dir.join(format!("{name}.key")),
            key.serialize_pem().as_bytes(),
        );
        if name == "allowed.test" {
            pinned = Sha256::digest(cert.der().as_ref())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
        }
    }
    let client = InnerClient::load(&ClientSettings {
        server_name: "inner.test".into(),
        server_ca: dir.join("inner-ca.pem"),
        cert: dir.join("allowed.test.pem"),
        key: dir.join("allowed.test.key"),
    })
    .unwrap();
    (outer_der, client, pinned)
}

async fn b08_spawn_server(
    dir: &std::path::Path,
    schema: &str,
    pinned: &str,
    index: u8,
) -> (B08ProcessGuard, std::net::SocketAddr, std::path::PathBuf) {
    use std::{
        process::{Command, Stdio},
        time::Instant,
    };
    let ready = dir.join(format!("server-{index}.ready"));
    let stop = dir.join(format!("server-{index}.stop"));
    let output_dir = std::env::var_os("AEGIS_B08_PROCESS_LOG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dir.to_path_buf());
    let output = output_dir.join(format!("server-{index}.output"));
    let log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap();
    let mut child = B08ProcessGuard(
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("two_connections_fence_claim_advance_and_recover_after_reconnect")
            .arg("--nocapture")
            .env("AEGIS_B08_PROCESS_CHILD", "1")
            .env("AEGIS_B08_PROCESS_SCHEMA", schema)
            .env("AEGIS_B08_PROCESS_READY", &ready)
            .env("AEGIS_B08_PROCESS_STOP", &stop)
            .env("AEGIS_B08_OUTER_CERT", dir.join("outer.der"))
            .env("AEGIS_B08_OUTER_KEY", dir.join("outer.key"))
            .env("AEGIS_B08_INNER_CERT", dir.join("inner.test.pem"))
            .env("AEGIS_B08_INNER_KEY", dir.join("inner.test.key"))
            .env("AEGIS_B08_INNER_CA", dir.join("inner-ca.pem"))
            .env("AEGIS_B08_INNER_CLIENT_HASH", pinned)
            .env_remove("AEGIS_B08_CHILD_SCHEMA")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
        output.clone(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(raw) = std::fs::read_to_string(&ready) {
            let address = raw.parse().unwrap();
            println!(
                "B08_SERVER_PROCESS_READY index={index} pid={}",
                child.0.id()
            );
            return (child, address, stop);
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "B08 child {index} exited before ready: {status}; {}",
                std::fs::read_to_string(&output).unwrap()
            );
        }
        assert!(
            Instant::now() < deadline,
            "B08 child {index} readiness deadline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn b08_stop_server(child: &mut B08ProcessGuard, stop: &std::path::Path, index: u8) {
    use std::time::Instant;
    std::fs::write(stop, b"stop").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "B08 child {index} failed: {status}");
            println!("B08_SERVER_PROCESS_STOPPED index={index}");
            return;
        }
        assert!(Instant::now() < deadline, "B08 child {index} stop deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn b08_authenticated_response(
    address: std::net::SocketAddr,
    connector: tokio_rustls::TlsConnector,
    inner: &aegis_core::secure_channel::Client,
) -> aegis_web_carrier::Descriptor {
    use aegis_web_carrier::{Client, ClientSettings, Credential, Limits};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroize::Zeroizing;
    let settings = ClientSettings {
        authority: "site.test".into(),
        descriptor_path: "/private/descriptor".into(),
        credential_file: "/fixture/private/key".into(),
    };
    let credential = Credential::from_private_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap();
    let limits = Limits::default();
    let descriptor = Client::discover(connector.clone(), address, &settings, &credential, &limits)
        .await
        .unwrap();
    let carrier = Client::connect(connector, &settings, descriptor.clone(), credential, limits)
        .await
        .unwrap();
    let mut tls = inner.connect(carrier).await.unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let challenge: [u8; 32] = rand::random();
    tls.write_all(&challenge).await.unwrap();
    tls.flush().await.unwrap();
    let mut observed = [0u8; 32];
    tls.read_exact(&mut observed).await.unwrap();
    let mut digest = Sha256::new();
    digest.update(b08_executable_digest());
    digest.update(challenge);
    assert_eq!(observed, digest.finalize().as_slice());
    drop(tls);
    descriptor
}

async fn b08_raw_open_response(
    address: std::net::SocketAddr,
    connector: tokio_rustls::TlsConnector,
    path: &str,
    id: [u8; 32],
) -> (http::StatusCode, Vec<u8>) {
    use bytes::{BufMut, BytesMut};
    use http::Request;
    use tokio::net::TcpStream;
    let tcp = TcpStream::connect(address).await.unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("site.test").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (mut send, connection) = h2::client::handshake::<_>(tls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut body = BytesMut::new();
    body.extend_from_slice(b"AWR1");
    body.extend_from_slice(&id);
    body.put_u64(0);
    body.put_u64(0);
    body.put_u8(1);
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://site.test{path}"))
        .header("content-type", "application/octet-stream")
        .header(aegis_web_carrier::KEY_HEADER, "a".repeat(64))
        .body(())
        .unwrap();
    send = send.ready().await.unwrap();
    let (response, mut stream) = send.send_request(request, false).unwrap();
    stream.send_data(body.freeze(), true).unwrap();
    let response = response.await.unwrap();
    let status = response.status();
    let mut receive = response.into_body();
    let mut reply = BytesMut::new();
    while let Some(chunk) = receive.data().await {
        let chunk = chunk.unwrap();
        receive
            .flow_control()
            .release_capacity(chunk.len())
            .unwrap();
        reply.extend_from_slice(&chunk);
    }
    driver.abort();
    let _ = driver.await;
    (status, reply.to_vec())
}

async fn b08_raw_open(
    address: std::net::SocketAddr,
    connector: tokio_rustls::TlsConnector,
    path: &str,
    id: [u8; 32],
) -> http::StatusCode {
    let (status, reply) = b08_raw_open_response(address, connector, path, id).await;
    assert_eq!(&reply[..], b"Not found\n", "private cover changed");
    status
}

async fn two_process_network_postgres_lifecycle() {
    // Complete binary identity work before starting either network process.
    let _executable_digest = b08_executable_digest();
    let (admin, schema) = test_database().await;
    drop(admin);
    let mut cleanup = B08SchemaGuard {
        dsn: b08_env("AEGIS_TEST_POSTGRES_DSN"),
        schema: schema.clone(),
        armed: true,
    };
    let directory = tempfile::tempdir().unwrap();
    let (outer_der, inner, pinned) = b08_certificates(directory.path());
    let connector = b08_outer_connector(outer_der);
    let (mut first, first_address, first_stop) =
        b08_spawn_server(directory.path(), &schema, &pinned, 1).await;
    if std::env::var_os("AEGIS_B08_TEST_ABORT_AFTER_FIRST_READY").is_some() {
        panic!("injected R3 cleanup fault after first child ready");
    }
    let _first_descriptor = tokio::time::timeout(
        Duration::from_secs(10),
        b08_authenticated_response(first_address, connector.clone(), &inner),
    )
    .await
    .unwrap();
    let db = connect(&schema).await;
    let row = db
        .query_one("SELECT id FROM aegis_web_session_ledger", &[])
        .await
        .unwrap();
    let bytes: Vec<u8> = row.get(0);
    assert_eq!(bytes.len(), 32);
    let mut old_id = [0u8; 32];
    old_id.copy_from_slice(&bytes);
    drop(db);
    let (mut second, second_address, second_stop) =
        b08_spawn_server(directory.path(), &schema, &pinned, 2).await;
    use aegis_web_carrier::{Client, ClientSettings, Credential, Limits};
    use zeroize::Zeroizing;
    let settings = ClientSettings {
        authority: "site.test".into(),
        descriptor_path: "/private/descriptor".into(),
        credential_file: "/fixture/private/key".into(),
    };
    let credential = Credential::from_private_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap();
    let descriptor = Client::discover(
        connector.clone(),
        second_address,
        &settings,
        &credential,
        &Limits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        b08_raw_open(second_address, connector.clone(), &descriptor.path, old_id).await,
        http::StatusCode::NOT_FOUND
    );
    let _fresh = b08_authenticated_response(second_address, connector.clone(), &inner).await;
    let db = connect(&schema).await;
    let count: i64 = db
        .query_one("SELECT count(*) FROM aegis_web_session_ledger", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2, "replay must not create a third ledger claim");
    drop(db);
    assert!(
        first.0.try_wait().unwrap().is_none(),
        "replica 1 must remain live"
    );
    assert!(
        second.0.try_wait().unwrap().is_none(),
        "replica 2 must remain live"
    );
    // The two children still have distinct live listeners at this boundary.
    // An optional source-bound operator can now stop its disposable PostgreSQL
    // container and require a fresh valid OPEN to receive only private cover.
    if let Some(cycle) = std::env::var_os("AEGIS_B08_DB_CYCLE_DIR") {
        let cycle = std::path::PathBuf::from(cycle);
        assert!(
            cycle.is_absolute() && cycle.is_dir(),
            "DB cycle directory required"
        );
        let outage_descriptor = Client::discover(
            connector.clone(),
            second_address,
            &settings,
            &credential,
            &Limits::default(),
        )
        .await
        .unwrap();
        let live_id: [u8; 32] = rand::random();
        let (live_status, live_reply) = b08_raw_open_response(
            second_address,
            connector.clone(),
            &outage_descriptor.path,
            live_id,
        )
        .await;
        assert_eq!(
            live_status,
            http::StatusCode::OK,
            "valid OPEN must work before DB stop"
        );
        assert_eq!(live_reply.len(), 45, "valid OPEN reply length");
        assert_eq!(&live_reply[..4], b"AWR1");
        assert_eq!(&live_reply[4..36], live_id.as_slice());
        assert!(live_reply[36..].iter().all(|byte| *byte == 0));
        b08_private(&cycle.join("ready"), b"two_replicas_ready");
        async fn wait_marker(cycle: &std::path::Path, name: &str, expected: &[u8]) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !cycle.join(name).exists() {
                assert!(
                    Instant::now() < deadline,
                    "DB cycle marker deadline: {name}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(std::fs::read(cycle.join(name)).unwrap(), expected);
        }
        wait_marker(&cycle, "stopped", b"exact_owned_postgres_stopped\n").await;
        let unavailable_id: [u8; 32] = rand::random();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(10),
                b08_raw_open(
                    second_address,
                    connector.clone(),
                    &outage_descriptor.path,
                    unavailable_id,
                )
            )
            .await
            .expect("valid OPEN must refuse before outage deadline"),
            http::StatusCode::NOT_FOUND,
            "a real PostgreSQL outage must refuse the valid new OPEN",
        );
        b08_private(&cycle.join("failclosed"), b"valid_open_refused");
        wait_marker(&cycle, "restarted", b"exact_owned_postgres_restarted\n").await;
    }
    b08_stop_server(&mut first, &first_stop, 1).await;
    drop(first);
    b08_stop_server(&mut second, &second_stop, 2).await;
    drop(second);
    cleanup
        .clear()
        .await
        .expect("B08 explicit schema cleanup/readback");
    drop(cleanup);
    println!(
        "B08_TWO_PROCESS_TLS_H2_POSTGRES_AUTH_RESTART_PASS binary_sha256={}",
        b08_executable_digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}
