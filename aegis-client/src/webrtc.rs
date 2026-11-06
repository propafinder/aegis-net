//! Explicit owned WebRTC ingress; signaling is verified TLS RPC, not HTTPS.
use aegis_core::{
    carrier_runtime::{shape_authenticated, PrivacySettings},
    secure_channel,
};
#[cfg(feature = "sfu-media-vp8")]
use aegis_webrtc::{
    runtime_settings::PolicySettings, sfu_livekit::SfuLiveKitClient, sfu_peer::SfuPath, Operation,
    Role, Signaling, SignalingReply, SignalingRequest,
};
use aegis_webrtc::{
    runtime_settings::RuntimeSettings, AdmissionKey, Cancellation, TlsSignalingClient,
};
use serde::Deserialize;
#[cfg(feature = "sfu-media-vp8")]
use std::net::IpAddr;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
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
pub struct Args {
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
    signaling_addr: SocketAddr,
    signaling_name: String,
    signaling_ca: PathBuf,
    signaling_key_file: PathBuf,
    inner_tls: secure_channel::ClientSettings,
    runtime: RuntimeSettings,
    privacy: Option<PrivacySettings>,
    idle_timeout_ms: u64,
    max_sessions: usize,
    #[cfg(feature = "sfu-media-vp8")]
    sfu: Option<SfuClientSettings>,
}

#[cfg(feature = "sfu-media-vp8")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SfuClientSettings {
    addr: SocketAddr,
    tls_name: String,
    ca: PathBuf,
    allowed_sfu_ips: Vec<IpAddr>,
}

#[cfg(feature = "sfu-media-vp8")]
fn valid_sfu_wss_endpoint(sfu: &SfuClientSettings) -> bool {
    // The TLS signaling endpoint and nominated ICE peer have separate trust
    // gates. A signed media grant is still required before either is used.
    sfu.addr.port() != 0 && !sfu.addr.ip().is_unspecified() && !sfu.addr.ip().is_multicast()
}

#[cfg(feature = "sfu-media-vp8")]
fn fixed_sfu_refusal_phase(phase: &str) -> &'static str {
    match phase {
        "socks_auth" => "socks_auth",
        "socks_target" => "socks_target",
        "broker_begin" => "broker_begin",
        "broker_take" => "broker_take",
        "sfu_signal" => "sfu_signal",
        "media_negotiation" => "media_negotiation",
        "device_tls" => "device_tls",
        "target_open" => "target_open",
        "active_data" => "active_data",
        "media_close" => "media_close",
        _ => "unknown",
    }
}

#[cfg(feature = "sfu-media-vp8")]
fn report_sfu_refusal(phase: &str) {
    // The CLI dispatches WebRTC before its ordinary tracing subscriber is
    // installed. Print only a fixed stage token, never an error, path, peer,
    // certificate, broker reply, media frame, or bearer value.
    let stage = fixed_sfu_refusal_phase(phase);
    eprintln!("sfu_attempt_refused phase={stage}");
    tracing::warn!(phase = stage, "sfu_attempt_refused");
}

#[cfg(test)]
#[path = "webrtc_local_auth_tests.rs"]
mod local_auth_tests;
fn private_read(path: &Path, max: usize) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    aegis_core::secret_file::trusted_read_parent(path)?;
    aegis_core::secret_file::read(path, max as u64)
}
fn load(path: &Path) -> anyhow::Result<(Config, AdmissionKey, tokio_rustls::TlsConnector)> {
    anyhow::ensure!(
        cfg!(any(unix, windows)),
        "WebRTC private custody is unsupported on this platform"
    );
    anyhow::ensure!(path.is_absolute(), "WebRTC config must be absolute");
    aegis_core::secret_file::trusted_read_parent(path)?;
    let raw = aegis_core::secret_file::read_config(path, 16384)?;
    let mut cfg: Config = toml::from_str(std::str::from_utf8(&raw)?)
        .map_err(|_| anyhow::anyhow!("WebRTC config rejected"))?;
    anyhow::ensure!(
        cfg.listen.ip().is_loopback()
            && cfg.signaling_addr.port() != 0
            && !cfg.signaling_addr.ip().is_unspecified()
            && !cfg.signaling_addr.ip().is_multicast()
            && cfg.signaling_ca.is_absolute()
            && cfg.signaling_key_file.is_absolute()
            && cfg.inner_tls.cert.is_absolute()
            && cfg.inner_tls.key.is_absolute()
            && cfg.inner_tls.server_ca.is_absolute()
            && cfg.signaling_key_file != cfg.inner_tls.key
            && cfg.runtime.bind.port() == 0
            && (1..=64).contains(&cfg.max_sessions)
            && (1..=300_000).contains(&cfg.idle_timeout_ms),
        "WebRTC native admission limits rejected"
    );
    if let Some(privacy) = &cfg.privacy {
        privacy.validate_opaque()?;
    }
    let auth_path = cfg
        .local_socks_auth_file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("local SOCKS credential required"))?;
    anyhow::ensure!(
        auth_path != cfg.inner_tls.key.as_path() && auth_path != cfg.signaling_key_file.as_path(),
        "local SOCKS credential must be separate"
    );
    let auth = aegis_core::local_socks_auth::LocalSocksAuth::load(auth_path)?;
    cfg.local_auth = Some(crate::socks5::SocksAuthCfg::from_local(&auth));
    #[cfg(feature = "sfu-media-vp8")]
    if let Some(sfu) = cfg.sfu.as_ref() {
        anyhow::ensure!(
            matches!(&cfg.runtime.ice, PolicySettings::SfuMedia)
                && (1..=30_000).contains(&cfg.runtime.connect_timeout_ms)
                && (1..=30_000).contains(&cfg.runtime.stall_timeout_ms)
                && cfg.runtime.max_lifetime_ms == 300_000
                && valid_sfu_wss_endpoint(sfu)
                && sfu.ca.is_absolute()
                && sfu.ca != cfg.inner_tls.key
                && sfu.ca != cfg.signaling_key_file
                && sfu.tls_name.len() <= 253,
            "SFU media settings rejected"
        );
        SfuPath {
            bind: cfg.runtime.bind,
            allowed_sfu_ips: sfu.allowed_sfu_ips.clone(),
        }
        .validate()?;
        let _ = rustls::pki_types::ServerName::try_from(sfu.tls_name.clone())
            .map_err(|_| anyhow::anyhow!("SFU TLS name rejected"))?;
        let _ = secure_channel::load_trust_roots(&sfu.ca)?;
    } else {
        let _ = cfg.runtime.load_with(private_read)?;
    }
    #[cfg(not(feature = "sfu-media-vp8"))]
    let _ = cfg.runtime.load_with(private_read)?;
    let raw = private_read(&cfg.signaling_key_file, 65)?;
    let text =
        std::str::from_utf8(&raw).map_err(|_| anyhow::anyhow!("signaling credential rejected"))?;
    let key = AdmissionKey::from_hex(text.strip_suffix('\n').unwrap_or(text))?;
    let name = rustls::pki_types::ServerName::try_from(cfg.signaling_name.clone())
        .map_err(|_| anyhow::anyhow!("signaling authority rejected"))?;
    let _ = name;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(secure_channel::load_trust_roots(&cfg.signaling_ca)?)
    .with_no_client_auth();
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    tls.key_log = Arc::new(rustls::NoKeyLog);
    Ok((cfg, key, tokio_rustls::TlsConnector::from(Arc::new(tls))))
}

async fn session(
    mut local: TcpStream,
    cfg: Arc<Config>,
    key: AdmissionKey,
    identity: secure_channel::Client,
    connector: tokio_rustls::TlsConnector,
    cancel: Cancellation,
) -> anyhow::Result<()> {
    #[cfg(feature = "sfu-media-vp8")]
    if cfg.sfu.is_some() {
        return session_sfu(local, cfg, key, identity, connector).await;
    }
    let mut locally_authenticated = false;
    let established = tokio::time::timeout(
        Duration::from_millis(cfg.runtime.connect_timeout_ms),
        async {
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
            // Trust verification completes before transmitting broker admission.
            let tcp = TcpStream::connect(cfg.signaling_addr).await?;
            let name = rustls::pki_types::ServerName::try_from(cfg.signaling_name.clone())?;
            let tls = connector.connect(name, tcp).await?;
            let signaling = Arc::new(TlsSignalingClient::new(tls));
            let stream =
                aegis_webrtc::connect(cfg.runtime.load_with(private_read)?, signaling, key, cancel)
                    .await?;
            // A DTLS/DataChannel connection is not device authorization.
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
        },
    )
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("WebRTC establishment deadline exceeded")));
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

#[cfg(feature = "sfu-media-vp8")]
async fn session_sfu(
    mut local: TcpStream,
    cfg: Arc<Config>,
    key: AdmissionKey,
    identity: secure_channel::Client,
    connector: tokio_rustls::TlsConnector,
) -> anyhow::Result<()> {
    let mut locally_authenticated = false;
    // Fixed stage tokens only. User target, peer, credential, broker reply,
    // SDP and bearer content must never enter a negative-run receipt.
    let mut phase = "socks_auth";
    let established = tokio::time::timeout(
        Duration::from_millis(cfg.runtime.connect_timeout_ms),
        async {
            let auth = cfg
                .local_auth
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("local SOCKS credential required"))?;
            crate::socks5::handshake(&mut local, Some(auth)).await?;
            locally_authenticated = true;
            phase = "socks_target";
            let target = match crate::socks5::read_client_request(&mut local).await? {
                crate::socks5::ClientRequest::Connect(target) => target,
                crate::socks5::ClientRequest::UdpAssociate => {
                    crate::socks5::send_command_not_supported(&mut local).await?;
                    return anyhow::Ok(None);
                }
            };
            let sfu = cfg
                .sfu
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("SFU unavailable"))?;
            // Broker TLS is verified before any admission key leaves memory.
            let tcp = TcpStream::connect(cfg.signaling_addr).await?;
            let name = rustls::pki_types::ServerName::try_from(cfg.signaling_name.clone())?;
            let tls = connector.connect(name, tcp).await?;
            let signaling = TlsSignalingClient::new(tls);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            phase = "broker_begin";
            let SignalingReply::MediaSubmitted(session) = signaling
                .exchange(
                    SignalingRequest::new(Role::Client, key.clone(), Operation::MediaBegin),
                    deadline,
                )
                .await?
            else {
                anyhow::bail!("SFU broker media begin rejected");
            };
            phase = "broker_take";
            let grant = loop {
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("SFU broker media claim expired");
                }
                match signaling
                    .exchange(
                        SignalingRequest::new(
                            Role::Client,
                            key.clone(),
                            Operation::MediaTake {
                                session,
                                claim: None,
                            },
                        ),
                        deadline,
                    )
                    .await
                {
                    Ok(SignalingReply::MediaGrant(grant)) => break grant,
                    Err(aegis_webrtc::Error::Session) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    _ => anyhow::bail!("SFU broker media grant rejected"),
                }
            };
            let (descriptor, token) = grant.into_client()?;
            phase = "sfu_signal";
            let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(secure_channel::load_trust_roots(&sfu.ca)?)
            .with_no_client_auth();
            tls_config.resumption = rustls::client::Resumption::disabled();
            tls_config.enable_early_data = false;
            tls_config.key_log = Arc::new(rustls::NoKeyLog);
            let tcp = TcpStream::connect(sfu.addr).await?;
            let name = rustls::pki_types::ServerName::try_from(sfu.tls_name.clone())?;
            let verified = tokio_rustls::TlsConnector::from(Arc::new(tls_config))
                .connect(name, tcp)
                .await?;
            let host = if sfu.addr.port() == 443 {
                sfu.tls_name.clone()
            } else {
                format!("{}:{}", sfu.tls_name, sfu.addr.port())
            };
            let media = SfuLiveKitClient::connect_verified(
                verified,
                &host,
                token,
                descriptor,
                SfuPath {
                    bind: cfg.runtime.bind,
                    allowed_sfu_ips: sfu.allowed_sfu_ips.clone(),
                },
            )
            .await?;
            phase = "media_negotiation";
            let (carrier, worker) = media.into_inner_tls_carrier().await?;
            Ok(Some((target, carrier, worker)))
        },
    )
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("SFU establishment deadline exceeded")));
    let (target, carrier, mut worker) = match established {
        Ok(Some(ready)) => ready,
        Ok(None) => return Ok(()),
        Err(error) => {
            report_sfu_refusal(phase);
            if locally_authenticated {
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    crate::socks5::send_general_failure(&mut local),
                )
                .await;
            }
            return Err(error);
        }
    };
    let result = async {
        // LiveKit room/track and media key are not target authorization.
        phase = "device_tls";
        let inner = identity.connect(carrier).await?;
        let mut inner = shape_authenticated(inner, cfg.privacy.as_ref())?;
        phase = "target_open";
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
        phase = "active_data";
        secure_channel::copy_with_idle_timeout(
            &mut local,
            &mut inner,
            Duration::from_millis(cfg.idle_timeout_ms),
        )
        .await?;
        anyhow::Ok(())
    }
    .await;
    if result.is_err() {
        report_sfu_refusal(phase);
        worker.abort();
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut worker).await;
        return result;
    }
    match tokio::time::timeout(Duration::from_secs(2), &mut worker).await {
        Ok(Ok(Ok(()))) => result,
        _ => {
            report_sfu_refusal("media_close");
            worker.abort();
            Err(anyhow::anyhow!("SFU media close unconfirmed"))
        }
    }
}
pub async fn run(args: &Args) -> anyhow::Result<()> {
    let interrupt = aegis_core::carrier_runtime::shutdown_signal()?;
    let (cfg, key, connector) = load(&args.config)?;
    let identity = secure_channel::Client::load(&cfg.inner_tls)?;
    let listener = TcpListener::bind(cfg.listen).await?;
    let slots = Arc::new(Semaphore::new(cfg.max_sessions));
    let cfg = Arc::new(cfg);
    let cancel = Cancellation::default();
    let mut tasks = JoinSet::new();
    tokio::pin!(interrupt);
    loop {
        tokio::select! {
            result=&mut interrupt=>{result?;break;},
            result=tasks.join_next(),if !tasks.is_empty()=>{
                if let Some(Err(error))=result {if error.is_panic(){return Err(anyhow::anyhow!("WebRTC worker panicked"));}}
            },
            result=listener.accept()=>{
                let (stream,_)=result?;
                let Ok(permit)=slots.clone().try_acquire_owned() else {drop(stream);continue;};
                let cfg=cfg.clone();let key=key.clone();let identity=identity.clone();
                let connector=connector.clone();let stop=cancel.clone();
                tasks.spawn(async move {let _permit=permit;session(stream,cfg,key,identity,connector,stop).await});
            }
        }
    }
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
