//! Native owned web-response ingress with the existing device/egress policy.
use crate::{config, rate_limit::RateLimiter, session};
use aegis_core::{carrier_runtime::PrivacySettings, secure_channel};
#[cfg(unix)]
use aegis_web_carrier::PostgresSessionLedger;
use aegis_web_carrier::{Cancellation, Credential, Limits, Server, ServerSettings, SessionLedger};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Semaphore},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone, Debug, clap::Args)]
pub struct CarrierArgs {
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    relay_config: PathBuf,
    web: ServerSettings,
    privacy: Option<PrivacySettings>,
    max_sessions: usize,
    /// Rotate authenticated descriptors only after this listener is bound.
    /// This does not allocate a new IP or cloud function.
    rotate_descriptor_ms: u64,
    #[serde(default = "single_replica")]
    replicas: usize,
    #[serde(default)]
    ledger: Option<LedgerConfig>,
}

const fn single_replica() -> usize {
    1
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum LedgerConfig {
    Postgres {
        socket_directory: PathBuf,
        #[serde(default = "postgres_port")]
        port: u16,
        database: String,
        user: String,
        operation_timeout_ms: u64,
    },
}

const fn postgres_port() -> u16 {
    5432
}

fn validate_ledger_config(cfg: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=16).contains(&cfg.replicas),
        "carrier replica count rejected"
    );
    anyhow::ensure!(
        cfg.replicas == 1 || cfg.ledger.is_some(),
        "multiple carrier replicas require PostgreSQL session ledger"
    );
    if let Some(LedgerConfig::Postgres {
        socket_directory,
        port,
        database,
        user,
        operation_timeout_ms,
    }) = &cfg.ledger
    {
        anyhow::ensure!(
            cfg!(unix)
                && socket_directory.is_absolute()
                && *port != 0
                && !database.is_empty()
                && database.len() <= 63
                && !user.is_empty()
                && user.len() <= 63
                && (1..=30_000).contains(operation_timeout_ms),
            "carrier PostgreSQL ledger configuration rejected"
        );
    }
    Ok(())
}

#[cfg(unix)]
async fn postgres_ledger(
    cfg: &Config,
    limits: &Limits,
) -> anyhow::Result<Option<Arc<dyn SessionLedger>>> {
    let Some(LedgerConfig::Postgres {
        socket_directory,
        port,
        database,
        user,
        operation_timeout_ms,
    }) = &cfg.ledger
    else {
        return Ok(None);
    };
    // Check both the selected socket directory and every spelling of its
    // ancestry before letting libpq's Unix-socket client use the path.
    let trusted_directory = aegis_core::secret_file::trusted_read_parent(
        &socket_directory.join(format!(".s.PGSQL.{port}")),
    )?;
    let timeout = Duration::from_millis(*operation_timeout_ms);
    let mut database_config = tokio_postgres::Config::new();
    database_config
        .host_path(&trusted_directory)
        .port(*port)
        .dbname(database)
        .user(user);
    database_config.connect_timeout(timeout);
    let (client, connection) =
        tokio::time::timeout(timeout, database_config.connect(tokio_postgres::NoTls))
            .await
            .map_err(|_| anyhow::anyhow!("carrier PostgreSQL connection timed out"))?
            .map_err(|_| anyhow::anyhow!("carrier PostgreSQL connection rejected"))?;
    let connection_task = tokio::spawn(async move {
        if connection.await.is_err() {
            tracing::warn!("carrier PostgreSQL connection ended");
        }
    });
    let ledger = PostgresSessionLedger::new(client, cfg.max_sessions, timeout, limits.max_lifetime)
        .await
        .map_err(|_| anyhow::anyhow!("carrier PostgreSQL ledger initialization rejected"));
    match ledger {
        Ok(ledger) => Ok(Some(Arc::new(ledger))),
        Err(error) => {
            connection_task.abort();
            Err(error)
        }
    }
}

#[cfg(not(unix))]
async fn postgres_ledger(
    _cfg: &Config,
    _limits: &Limits,
) -> anyhow::Result<Option<Arc<dyn SessionLedger>>> {
    anyhow::bail!("carrier PostgreSQL Unix socket unsupported on this platform")
}

#[cfg(test)]
mod ledger_startup_tests {
    use super::*;

    fn config(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"relay_config = "/private/relay.toml"
max_sessions = 8
rotate_descriptor_ms = 60000
{extra}
[web]
site_html = "<title>Test</title>"
[web.client]
authority = "site.test"
descriptor_path = "/private/descriptor"
credential_file = "/private/admission.key"
"#
        ))
        .unwrap()
    }

    #[test]
    fn replicas_require_explicit_shared_ledger() {
        assert!(validate_ledger_config(&config("replicas = 2")).is_err());
        assert!(validate_ledger_config(&config("replicas = 1")).is_ok());
        assert!(validate_ledger_config(&config("replicas = 0")).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unavailable_postgres_refuses_startup_before_listener() {
        let missing = tempfile::tempdir().unwrap();
        let cfg = config(&format!(
            r#"replicas = 2
[ledger]
mode = "postgres"
socket_directory = "{}"
database = "aegis_carrier_test"
user = "aegis_carrier_test"
operation_timeout_ms = 200
"#,
            missing.path().display()
        ));
        validate_ledger_config(&cfg).unwrap();
        assert!(postgres_ledger(&cfg, &Limits::default()).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writable_ancestor_refuses_postgres_socket_before_connect() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let ancestor = base.path().join("writable-ancestor");
        let socket = ancestor.join("private-socket");
        std::fs::create_dir_all(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
        let cfg = config(&format!(
            r#"replicas = 2
[ledger]
mode = "postgres"
socket_directory = "{}"
database = "aegis_carrier_test"
user = "aegis_carrier_test"
operation_timeout_ms = 200
"#,
            socket.display()
        ));
        validate_ledger_config(&cfg).unwrap();
        let error = postgres_ledger(&cfg, &Limits::default())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("untrusted writes"));
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL socket configured in AEGIS_TEST_POSTGRES_SOCKET_DIR"]
    async fn two_native_runtime_replicas_share_postgres_ledger() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let socket = std::env::var("AEGIS_TEST_POSTGRES_SOCKET_DIR").unwrap();
        let port: u16 = std::env::var("AEGIS_TEST_POSTGRES_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let user = std::env::var("AEGIS_TEST_POSTGRES_USER").unwrap();
        let cfg = config(&format!(
            r#"replicas = 2
[ledger]
mode = "postgres"
socket_directory = "{socket}"
port = {port}
database = "aegis_carrier_test"
user = "{user}"
operation_timeout_ms = 2000
"#
        ));
        validate_ledger_config(&cfg).unwrap();
        let first = postgres_ledger(&cfg, &Limits::default())
            .await
            .unwrap()
            .unwrap();
        let second = postgres_ledger(&cfg, &Limits::default())
            .await
            .unwrap()
            .unwrap();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60_000;
        let id: [u8; 32] = rand::random();
        first.claim(id, 7, expires).await.unwrap();
        assert!(second.claim(id, 8, expires).await.is_err());
        second.verify(id, 7, 1).await.unwrap();
        first.advance(id, 7, 1).await.unwrap();
        assert!(second.verify(id, 7, 1).await.is_err());
        second.verify(id, 7, 2).await.unwrap();
    }
}

struct OwnedServer(JoinHandle<std::io::Result<()>>);
impl Drop for OwnedServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn run(args: &CarrierArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(any(unix, windows)),
        "carrier private custody is unsupported on this platform"
    );
    let interrupt = aegis_core::carrier_runtime::shutdown_signal()?;
    anyhow::ensure!(args.config.is_absolute(), "carrier config must be absolute");
    aegis_core::secret_file::trusted_read_parent(&args.config)?;
    let raw = aegis_core::secret_file::read_config(&args.config, 128 * 1024)?;
    let cfg: Config = toml::from_str(std::str::from_utf8(&raw)?)
        .map_err(|_| anyhow::anyhow!("carrier config rejected"))?;
    cfg.web.validate()?;
    validate_ledger_config(&cfg)?;
    anyhow::ensure!(
        cfg.relay_config.is_absolute()
            && (1..=64).contains(&cfg.max_sessions)
            && (1000..=240_000).contains(&cfg.rotate_descriptor_ms),
        "carrier runtime limits rejected"
    );
    if let Some(privacy) = &cfg.privacy {
        privacy.validate_opaque()?;
    }
    aegis_core::secret_file::trusted_read_parent(&cfg.relay_config)?;
    let relay_bytes = aegis_core::secret_file::read_config(&cfg.relay_config, 64 * 1024)?;
    let relay: config::ServerConfig = toml::from_str(std::str::from_utf8(&relay_bytes)?)
        .map_err(|_| anyhow::anyhow!("carrier relay policy rejected"))?;
    relay.validate_auth_tokens()?;
    let bind: std::net::SocketAddr = relay
        .listen
        .parse()
        .map_err(|_| anyhow::anyhow!("carrier listen must use a concrete numeric address"))?;
    anyhow::ensure!(
        !bind.ip().is_unspecified() && !bind.ip().is_multicast(),
        "carrier requires a concrete advertised listener address"
    );
    anyhow::ensure!(
        relay.auth_token.is_empty()
            && relay.legacy_auth_tokens.is_empty()
            && relay.fallback == "close"
            && !relay.bundle_endpoint.enabled
            && !relay.transport.quic_required
            && relay.transport.quic_listen.is_none()
            && relay.transport.https_bridge.is_none(),
        "opaque carrier requires exclusive device authentication and closed fallback"
    );
    let inner_settings = relay
        .transport
        .inner_tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("carrier device identity policy missing"))?;
    anyhow::ensure!(
        relay.cert.is_absolute()
            && relay.key.is_absolute()
            && inner_settings.cert.is_absolute()
            && inner_settings.key.is_absolute()
            && inner_settings.client_ca.is_absolute()
            && inner_settings
                .device_registry
                .as_ref()
                .is_none_or(|path| path.is_absolute()),
        "carrier TLS and registry paths must be absolute"
    );
    anyhow::ensure!(
        cfg.web.client.credential_file != inner_settings.key
            && cfg.web.client.credential_file != relay.key,
        "carrier admission requires a separate key"
    );
    aegis_core::secret_file::trusted_read_parent(&cfg.web.client.credential_file)?;
    let credential = Credential::from_private_bytes(aegis_core::secret_file::read(
        &cfg.web.client.credential_file,
        65,
    )?)?;
    let identity_settings = inner_settings.clone();
    let inner = tokio::task::spawn_blocking(move || {
        secure_channel::Server::load_for_startup(&identity_settings)
    })
    .await
    .map_err(|_| anyhow::anyhow!("carrier identity loader failed"))??;
    let mut watcher = inner.start_registry_watcher();
    let tls =
        tokio_rustls::TlsAcceptor::from(crate::tls::load_server_config(&relay.cert, &relay.key)?);
    let limits = Limits {
        max_sessions: cfg.max_sessions,
        ..Limits::default()
    };
    let ledger = postgres_ledger(&cfg, &limits).await?;
    let server = if let Some(ledger) = ledger {
        Server::with_ledger(cfg.web, credential, limits, ledger)?
    } else {
        Server::new(cfg.web, credential, limits)?
    };
    let listener = TcpListener::bind(bind).await?;
    let address = listener.local_addr()?;
    let cancellation = Cancellation::default();
    let (accepted_tx, mut accepted_rx) = mpsc::channel(cfg.max_sessions);
    let slots = Arc::new(Semaphore::new(cfg.max_sessions));
    let rate_limiter = RateLimiter::new(
        relay.rate_limit.max_auth_failures_per_ip,
        relay.rate_limit.ban_duration_secs,
        relay.rate_limit.enabled,
    )
    .with_operational_log(relay.logging.policy());
    let serve_server = server.clone();
    let stop = cancellation.clone();
    let mut ingress = OwnedServer(tokio::spawn(async move {
        serve_server.serve(listener, tls, accepted_tx, stop).await
    }));
    let mut sessions = JoinSet::new();
    let mut rotation = tokio::time::interval(Duration::from_millis(cfg.rotate_descriptor_ms));
    rotation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `serve` publishes the initial descriptor. Periodic rotation never changes
    // an existing authenticated stream or replays its application bytes.
    rotation.tick().await;
    tokio::pin!(interrupt);
    let result = loop {
        tokio::select! {
            result=&mut interrupt => break result.map_err(Into::into),
            result=&mut ingress.0 => break match result {Ok(result)=>result.map_err(Into::into),Err(_)=>Err(anyhow::anyhow!("carrier ingress failed"))},
            _=rotation.tick() => {
                rate_limiter.cleanup().await;
                if let Err(error)=server.rotate_ingress(address) {break Err(error.into());}
            },
            result=sessions.join_next(),if !sessions.is_empty() => {
                if let Some(Err(error))=result {if error.is_panic() {break Err(anyhow::anyhow!("device carrier worker panicked"));}}
            },
            accepted=accepted_rx.recv() => {
                let Some(accepted)=accepted else {break Err(anyhow::anyhow!("carrier admission stopped"));};
                let peer=accepted.peer_ip();
                let (stream,authentication)=accepted.into_parts();
                if rate_limiter.is_banned(peer).await {authentication.cancel();drop(stream);continue;}
                let Ok(permit)=slots.clone().try_acquire_owned() else {authentication.cancel();drop(stream);continue;};
                let inner=inner.clone();let policy=relay.target_policy.clone();
                let limiter=rate_limiter.clone();let privacy=cfg.privacy.clone();
                let operational_log=relay.logging.policy();
                sessions.spawn(async move {
                    let _permit=permit;
                    session::serve_device_carrier_with_logging(stream,inner,&policy,&limiter,Some(peer),
                        move || authentication.mark_authenticated(),privacy.as_ref(),operational_log).await
                });
            }
        }
    };
    cancellation.cancel();
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    let ingress_pending = !ingress.0.is_finished();
    let cleanup_cutoff = registry_cleanup_cutoff(tokio::time::Instant::now(), ingress_pending);
    let (ingress_timed_out, registry_cleanup) = tokio::join!(
        async {
            ingress_pending
                && tokio::time::timeout_at(cleanup_cutoff, &mut ingress.0)
                    .await
                    .is_err()
        },
        async {
            match watcher.as_mut() {
                Some(watcher) => watcher.stop_and_join_read_until(cleanup_cutoff).await,
                None => Ok(()),
            }
        }
    );
    if ingress_timed_out {
        ingress.0.abort();
        let _ = (&mut ingress.0).await;
    }
    if registry_cleanup.is_err() {
        tracing::warn!("carrier registry watcher cleanup unconfirmed");
    }
    result.and(registry_cleanup.map_err(Into::into))
}

fn registry_cleanup_cutoff(
    origin: tokio::time::Instant,
    ingress_pending: bool,
) -> tokio::time::Instant {
    // Pending ingress retains its original10s terminal cap. A completed
    // ingress had no reader cleanup interval: explicitly give only that
    // reader a new500ms cap rather than silently resetting the old10s wait.
    origin
        + if ingress_pending {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(500)
        }
}

#[cfg(test)]
mod registry_cleanup_policy_tests {
    use super::*;

    #[test]
    fn pending_ingress_keeps_original_ten_second_cleanup_origin() {
        let origin = tokio::time::Instant::now();
        let cutoff = registry_cleanup_cutoff(origin, true);
        assert_eq!(cutoff.duration_since(origin), Duration::from_secs(10));
        // Both ingress and reader receive this exact captured cutoff, not a
        // fresh interval after either branch completes or signals again.
        assert_eq!(registry_cleanup_cutoff(origin, true), cutoff);
    }

    #[test]
    fn completed_ingress_has_explicit_reader_only_half_second_cap() {
        let origin = tokio::time::Instant::now();
        let cutoff = registry_cleanup_cutoff(origin, false);
        assert_eq!(cutoff.duration_since(origin), Duration::from_millis(500));
        assert!(cutoff < origin + Duration::from_secs(10));
        assert!(cutoff < origin + Duration::from_millis(501));
    }
}
