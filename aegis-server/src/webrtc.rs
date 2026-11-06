//! Owned WebRTC intermediary and separate verified-TLS signaling broker.
use crate::{config, rate_limit::RateLimiter, session};
use aegis_core::{carrier_runtime::PrivacySettings, secure_channel};
#[cfg(feature = "sfu-media-vp8")]
use aegis_webrtc::runtime_settings::PolicySettings;
use aegis_webrtc::{
    runtime_settings::RuntimeSettings, AdmissionKey, BrokerLimits, Cancellation, OwnedBroker,
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
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub config: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    relay_config: PathBuf,
    signaling_listen: SocketAddr,
    client_key_file: PathBuf,
    intermediary_key_file: PathBuf,
    runtime: RuntimeSettings,
    privacy: Option<PrivacySettings>,
    max_sessions: usize,
    #[cfg(feature = "sfu-media-vp8")]
    sfu: Option<SfuRunSettings>,
}

#[cfg(feature = "sfu-media-vp8")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SfuRunSettings {
    bootstrap: crate::sfu_bootstrap::SfuBootstrapSettings,
    allowed_sfu_ips: Vec<IpAddr>,
}
fn private_read(path: &Path, max: usize) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    aegis_core::secret_file::trusted_read_parent(path)?;
    aegis_core::secret_file::read(path, max as u64)
}
fn admission(path: &Path) -> anyhow::Result<AdmissionKey> {
    let raw = private_read(path, 65)?;
    let text =
        std::str::from_utf8(&raw).map_err(|_| anyhow::anyhow!("signaling credential rejected"))?;
    Ok(AdmissionKey::from_hex(
        text.strip_suffix('\n').unwrap_or(text),
    )?)
}
pub async fn run(args: &Args) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(any(unix, windows)),
        "WebRTC private custody is unsupported on this platform"
    );
    let interrupt = aegis_core::carrier_runtime::shutdown_signal()?;
    anyhow::ensure!(args.config.is_absolute(), "WebRTC config must be absolute");
    aegis_core::secret_file::trusted_read_parent(&args.config)?;
    let raw = aegis_core::secret_file::read_config(&args.config, 16384)?;
    let cfg: Config = toml::from_str(std::str::from_utf8(&raw)?)
        .map_err(|_| anyhow::anyhow!("WebRTC config rejected"))?;
    anyhow::ensure!(
        cfg.relay_config.is_absolute()
            && cfg.client_key_file.is_absolute()
            && cfg.intermediary_key_file.is_absolute()
            && cfg.client_key_file != cfg.intermediary_key_file
            && !cfg.signaling_listen.ip().is_unspecified()
            && !cfg.signaling_listen.ip().is_multicast()
            && cfg.runtime.bind.port() == 0
            && (1..=64).contains(&cfg.max_sessions),
        "WebRTC native admission limits rejected"
    );
    if let Some(privacy) = &cfg.privacy {
        privacy.validate_opaque()?;
    }
    #[cfg(feature = "sfu-media-vp8")]
    let sfu = if let Some(settings) = cfg.sfu.as_ref() {
        anyhow::ensure!(
            matches!(&cfg.runtime.ice, PolicySettings::SfuMedia)
                && (1..=30_000).contains(&cfg.runtime.connect_timeout_ms)
                && (1..=30_000).contains(&cfg.runtime.stall_timeout_ms)
                && cfg.runtime.max_lifetime_ms == 300_000,
            "SFU media runtime requires exact bounded policy"
        );
        aegis_webrtc::sfu_peer::SfuPath {
            bind: cfg.runtime.bind,
            allowed_sfu_ips: settings.allowed_sfu_ips.clone(),
        }
        .validate()?;
        Some(Arc::new(settings.bootstrap.load()?))
    } else {
        let _ = cfg.runtime.load_with(private_read)?;
        None
    };
    #[cfg(not(feature = "sfu-media-vp8"))]
    let _ = cfg.runtime.load_with(private_read)?;
    aegis_core::secret_file::trusted_read_parent(&cfg.relay_config)?;
    let relay_bytes = aegis_core::secret_file::read_config(&cfg.relay_config, 65536)?;
    let relay: config::ServerConfig = toml::from_str(std::str::from_utf8(&relay_bytes)?)
        .map_err(|_| anyhow::anyhow!("WebRTC relay policy rejected"))?;
    relay.validate_auth_tokens()?;
    anyhow::ensure!(
        relay.auth_token.is_empty()
            && relay.legacy_auth_tokens.is_empty()
            && relay.fallback == "close"
            && !relay.bundle_endpoint.enabled
            && !relay.transport.quic_required
            && relay.transport.quic_listen.is_none()
            && relay.transport.https_bridge.is_none(),
        "WebRTC requires exclusive device authentication"
    );
    let settings = relay
        .transport
        .inner_tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("WebRTC device policy missing"))?;
    #[cfg(feature = "sfu-media-vp8")]
    if let Some(media) = cfg.sfu.as_ref() {
        for protected in [
            &media.bootstrap.api_key_file,
            &media.bootstrap.api_secret_file,
            &media.bootstrap.tls_root_der_file,
        ] {
            anyhow::ensure!(
                protected != &cfg.client_key_file
                    && protected != &cfg.intermediary_key_file
                    && protected != &relay.key
                    && protected != &settings.key,
                "SFU issuer and device credentials must be separate"
            );
        }
    }
    anyhow::ensure!(
        relay.cert.is_absolute()
            && relay.key.is_absolute()
            && settings.cert.is_absolute()
            && settings.key.is_absolute()
            && settings.client_ca.is_absolute()
            && settings
                .device_registry
                .as_ref()
                .is_none_or(|p| p.is_absolute())
            && cfg.client_key_file != settings.key
            && cfg.intermediary_key_file != settings.key
            && cfg.client_key_file != relay.key
            && cfg.intermediary_key_file != relay.key,
        "WebRTC requires absolute identity paths and separate admission credentials"
    );
    let client_key = admission(&cfg.client_key_file)?;
    let intermediary_key = admission(&cfg.intermediary_key_file)?;
    let identity_settings = settings.clone();
    let inner = tokio::task::spawn_blocking(move || {
        secure_channel::Server::load_for_startup(&identity_settings)
    })
    .await
    .map_err(|_| anyhow::anyhow!("WebRTC identity loader failed"))??;
    let mut watcher = inner.start_registry_watcher();
    let tls =
        tokio_rustls::TlsAcceptor::from(crate::tls::load_server_config(&relay.cert, &relay.key)?);
    let broker = Arc::new(OwnedBroker::new(
        client_key,
        intermediary_key.clone(),
        BrokerLimits {
            max_sessions: cfg.max_sessions,
            session_ttl: Duration::from_millis(cfg.runtime.connect_timeout_ms),
        },
    )?);
    let listener = TcpListener::bind(cfg.signaling_listen).await?;
    let connections = Arc::new(Semaphore::new(cfg.max_sessions * 2));
    let cancel = Cancellation::default();
    let mut tasks = JoinSet::new();
    let mut active_devices = 0usize;
    let cfg = Arc::new(cfg);
    let limiter = RateLimiter::new(
        relay.rate_limit.max_auth_failures_per_ip,
        relay.rate_limit.ban_duration_secs,
        relay.rate_limit.enabled,
    )
    .with_operational_log(relay.logging.policy());
    let mut maintenance = tokio::time::interval(Duration::from_secs(30));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(interrupt);
    let result = loop {
        while active_devices < cfg.max_sessions {
            let cfg = cfg.clone();
            let broker = broker.clone();
            let key = intermediary_key.clone();
            let stop = cancel.clone();
            let inner = inner.clone();
            let policy = relay.target_policy.clone();
            let limiter = limiter.clone();
            let operational_log = relay.logging.policy();
            #[cfg(feature = "sfu-media-vp8")]
            let sfu = sfu.clone();
            active_devices += 1;
            tasks.spawn(async move {
                let result = async {
                    #[cfg(feature = "sfu-media-vp8")]
                    if let Some(issuer) = sfu.as_ref() {
                        let (session, claim) = broker
                            .claim_media_v1(
                                &key,
                                tokio::time::Instant::now() + Duration::from_secs(5),
                            )
                            .await?;
                        let settings = cfg.sfu.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("SFU media configuration unavailable")
                        })?;
                        let path = aegis_webrtc::sfu_peer::SfuPath {
                            bind: cfg.runtime.bind,
                            allowed_sfu_ips: settings.allowed_sfu_ips.clone(),
                        };
                        let media = crate::sfu_bootstrap::MediaTransaction::new(&broker, issuer)
                            .take_connect_media(
                                aegis_webrtc::Role::Intermediary,
                                &key,
                                session,
                                Some(claim),
                                path,
                            )
                            .await?;
                        media
                            .serve_inner_tls(
                                inner,
                                &policy,
                                &limiter,
                                cfg.privacy.as_ref(),
                                operational_log,
                            )
                            .await?;
                        return anyhow::Ok(());
                    }
                    let stream = aegis_webrtc::accept(
                        cfg.runtime.load_with(private_read)?,
                        broker,
                        key,
                        stop,
                    )
                    .await?;
                    let peer = stream.peer_ip();
                    if limiter.is_banned(peer).await {
                        return anyhow::Ok(());
                    }
                    session::serve_device_carrier_with_logging(
                        stream,
                        inner,
                        &policy,
                        &limiter,
                        Some(peer),
                        || Ok(()),
                        cfg.privacy.as_ref(),
                        operational_log,
                    )
                    .await
                }
                .await;
                (true, result)
            });
        }
        tokio::select! {
            result=&mut interrupt=>break result.map_err(Into::into),
            _=maintenance.tick()=>limiter.cleanup().await,
            result=tasks.join_next(),if !tasks.is_empty()=>match result {
                Some(Ok((device,_)))=>{if device {active_devices-=1;}},
                Some(Err(error)) if error.is_panic()=>break Err(anyhow::anyhow!("WebRTC worker panicked")),
                _=>{}
            },
            result=listener.accept()=>{
                let (tcp,_) = match result { Ok(accepted) => accepted, Err(error) => break Err(error.into()) };
                let Ok(permit)=connections.clone().try_acquire_owned() else {drop(tcp);continue;};
                let broker=broker.clone();let tls=tls.clone();
                #[cfg(feature = "sfu-media-vp8")]
                let sfu=sfu.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let result=tokio::time::timeout(Duration::from_secs(5),tls.accept(tcp)).await;
                    if let Ok(Ok(tls))=result {
                        #[cfg(feature = "sfu-media-vp8")]
                        if let Some(issuer)=sfu.as_ref() {
                            let _=broker.serve_tls_media(tls,issuer.as_ref()).await;
                        } else {
                            let _=broker.serve_tls(tls).await;
                        }
                        #[cfg(not(feature = "sfu-media-vp8"))]
                        let _=broker.serve_tls(tls).await;
                    }
                    (false,anyhow::Ok(()))
                });
            }
        }
    };
    cancel.cancel();
    // Explicit terminal policy: one new 500ms cleanup cap. This is separate
    // from the original TLS5s and broker/connect lifetime, which stay intact.
    let cleanup_cutoff = tokio::time::Instant::now() + Duration::from_millis(500);
    tasks.abort_all();
    let (tasks_cleanup, registry_cleanup) = tokio::join!(
        tokio::time::timeout_at(cleanup_cutoff, async {
            while tasks.join_next().await.is_some() {}
        }),
        async {
            match watcher.as_mut() {
                Some(watcher) => watcher.stop_and_join_read_until(cleanup_cutoff).await,
                None => Ok(()),
            }
        }
    );
    let cleanup = if tasks_cleanup.is_err() || tokio::time::Instant::now() >= cleanup_cutoff {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "WebRTC task cleanup unconfirmed",
        ))
    } else {
        registry_cleanup
    };
    if cleanup.is_err() {
        tracing::warn!("WebRTC terminal cleanup unconfirmed");
    }
    result.and(cleanup.map_err(Into::into))
}
