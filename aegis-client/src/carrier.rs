//! Explicit native SOCKS entry point for the owned web-response carrier.
//! Device authentication and target opens remain the established inner protocol.
use aegis_core::{
    carrier_runtime::{shape_authenticated, PrivacySettings},
    secure_channel,
};
use aegis_web_carrier::{Client, ClientSettings, Credential, Limits};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};

#[derive(Clone, Debug, clap::Args)]
pub struct CarrierArgs {
    /// Private carrier sidecar. Paths are absolute; no admission key is a CLI argument.
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: SocketAddr,
    // Required existing install-local credentials; never an enrollment key.
    local_socks_auth_file: Option<PathBuf>,
    #[serde(skip)]
    local_auth: Option<crate::socks5::SocksAuthCfg>,
    bootstrap: SocketAddr,
    allowed_ingress_ips: Vec<IpAddr>,
    outer_ca: PathBuf,
    inner_tls: secure_channel::ClientSettings,
    web: ClientSettings,
    privacy: Option<PrivacySettings>,
    connect_timeout_ms: u64,
    idle_timeout_ms: u64,
    max_sessions: usize,
}

#[cfg(test)]
#[path = "carrier_local_auth_tests.rs"]
pub(crate) mod local_auth_tests;

fn load(path: &std::path::Path) -> anyhow::Result<(Config, Credential)> {
    anyhow::ensure!(
        cfg!(any(unix, windows)),
        "carrier private custody is unsupported on this platform"
    );
    anyhow::ensure!(
        path.is_absolute(),
        "carrier config must have an absolute path"
    );
    aegis_core::secret_file::trusted_read_parent(path)?;
    let raw = aegis_core::secret_file::read_config(path, 16 * 1024)?;
    let mut cfg: Config = toml::from_str(std::str::from_utf8(&raw)?)
        .map_err(|_| anyhow::anyhow!("carrier config rejected"))?;
    cfg.web.validate()?;
    anyhow::ensure!(
        cfg.listen.ip().is_loopback()
            && cfg.bootstrap.port() != 0
            && !cfg.bootstrap.ip().is_unspecified()
            && !cfg.bootstrap.ip().is_multicast()
            && (1..=30_000).contains(&cfg.connect_timeout_ms)
            && (1..=300_000).contains(&cfg.idle_timeout_ms)
            && (1..=64).contains(&cfg.max_sessions)
            && cfg.outer_ca.is_absolute()
            && (1..=16).contains(&cfg.allowed_ingress_ips.len())
            && cfg
                .allowed_ingress_ips
                .iter()
                .all(|ip| !ip.is_unspecified() && !ip.is_multicast())
            && cfg.inner_tls.key.is_absolute()
            && cfg.inner_tls.cert.is_absolute()
            && cfg.inner_tls.server_ca.is_absolute(),
        "carrier runtime limits rejected"
    );
    if let Some(privacy) = &cfg.privacy {
        privacy.validate_opaque()?;
    }
    let auth_path = cfg
        .local_socks_auth_file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("local SOCKS credential required"))?;
    anyhow::ensure!(
        auth_path != cfg.inner_tls.key.as_path() && auth_path != cfg.web.credential_file.as_path(),
        "local SOCKS credential must be separate"
    );
    let auth = aegis_core::local_socks_auth::LocalSocksAuth::load(auth_path)?;
    cfg.local_auth = Some(crate::socks5::SocksAuthCfg::from_local(&auth));
    anyhow::ensure!(
        cfg.web.credential_file != cfg.inner_tls.key,
        "carrier admission must use a separate key"
    );
    aegis_core::secret_file::trusted_read_parent(&cfg.web.credential_file)?;
    let credential = Credential::from_private_bytes(aegis_core::secret_file::read(
        &cfg.web.credential_file,
        65,
    )?)?;
    Ok((cfg, credential))
}

fn connector(cfg: &Config) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let roots = secure_channel::load_trust_roots(&cfg.outer_ca)?;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    tls.key_log = Arc::new(rustls::NoKeyLog);
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls)))
}

async fn session(
    mut local: TcpStream,
    cfg: Arc<Config>,
    credential: Credential,
    identity: secure_channel::Client,
    connector: tokio_rustls::TlsConnector,
) -> anyhow::Result<()> {
    let mut locally_authenticated = false;
    let established = tokio::time::timeout(Duration::from_millis(cfg.connect_timeout_ms), async {
        let auth = cfg
            .local_auth
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("local SOCKS credential required"))?;
        crate::socks5::handshake(&mut local, Some(auth)).await?;
        locally_authenticated = true;
        let target = match crate::socks5::read_client_request(&mut local).await? {
            crate::socks5::ClientRequest::Connect(target) => target,
            crate::socks5::ClientRequest::UdpAssociate => {
                crate::socks5::send_command_not_supported(&mut local).await?;
                return anyhow::Ok(None);
            }
        };
        let limits = Limits::default();
        let descriptor = Client::discover(
            connector.clone(),
            cfg.bootstrap,
            &cfg.web,
            &credential,
            &limits,
        )
        .await?;
        anyhow::ensure!(
            cfg.allowed_ingress_ips.contains(&descriptor.ingress.ip()),
            "discovered carrier ingress is not locally admitted"
        );
        let stream = Client::connect(connector, &cfg.web, descriptor, credential, limits).await?;
        // A single establishment attempt. Inner identity/open failures never replay.
        let inner = identity.connect(stream).await?;
        let mut inner = shape_authenticated(inner, cfg.privacy.as_ref())?;
        secure_channel::write_open(
            &mut inner,
            &secure_channel::OpenRequest {
                version: 1,
                host: target.host,
                port: target.port,
                transport: secure_channel::Transport::Tcp,
            },
        )
        .await?;
        anyhow::ensure!(inner.read_u8().await? == 0, "device relay rejected target");
        crate::socks5::send_success(&mut local, "0.0.0.0:0".parse()?).await?;
        Ok(Some(inner))
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("carrier establishment deadline exceeded")));
    let mut inner = match established {
        Ok(Some(inner)) => inner,
        Ok(None) => return Ok(()),
        Err(error) => {
            // RFC1929/method failures close directly, before target work.
            if !locally_authenticated {
                return Err(error);
            }
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                crate::socks5::send_general_failure(&mut local),
            )
            .await;
            return Err(error);
        }
    };
    secure_channel::copy_with_idle_timeout(
        &mut local,
        &mut inner,
        Duration::from_millis(cfg.idle_timeout_ms),
    )
    .await?;
    Ok(())
}

pub async fn run(args: &CarrierArgs) -> anyhow::Result<()> {
    let stop = aegis_core::carrier_runtime::shutdown_signal()?;
    let (cfg, credential) = load(&args.config)?;
    let connector = connector(&cfg)?;
    let identity = secure_channel::Client::load(&cfg.inner_tls)?;
    let slots = Arc::new(Semaphore::new(cfg.max_sessions));
    let listener = TcpListener::bind(cfg.listen).await?;
    let cfg = Arc::new(cfg);
    let mut tasks = JoinSet::new();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            result = &mut stop => { result?; break; }
            result = tasks.join_next(), if !tasks.is_empty() => {
                // Carrier and device errors are intentionally not logged with peer/SDP/keys.
                if let Some(Err(error)) = result { if error.is_panic() { return Err(anyhow::anyhow!("carrier worker panicked")); } }
            }
            result = listener.accept() => {
                let (stream, _) = result?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { drop(stream); continue; };
                let cfg=cfg.clone(); let identity=identity.clone();
                let credential=credential.clone(); let connector=connector.clone();
                tasks.spawn(async move { let _permit=permit; session(stream,cfg,credential,identity,connector).await });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_never_requires_a_secret_argument() {
        use clap::Parser;
        #[derive(Parser)]
        struct Args {
            #[command(flatten)]
            command: super::CarrierArgs,
        }
        assert!(Args::try_parse_from(["carrier", "--config", "/private/carrier.toml"]).is_ok());
        assert!(Args::try_parse_from(["carrier", "--admission-key", "secret"]).is_err());
    }
}
