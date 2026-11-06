//! Explicit application-owned UDP timing control; never a TUN/capture hook.
use aegis_core::{
    carrier_runtime::PrivacySettings,
    secret_file,
    secure_channel::{
        poisson_control::{self, Profile},
        Client, ClientSettings, Server, ServerSettings,
    },
};
use serde::Deserialize;
use std::{io, net::SocketAddr, path::Path, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{timeout_at, Instant},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: SocketAddr,
    deadline_ms: u32,
    tls: Role,
    profile: Profile,
    #[serde(default)]
    authenticated_shaping: Option<PrivacySettings>,
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Role {
    Client { settings: ClientSettings },
    Server { settings: ServerSettings },
}
fn live(end: Instant) -> io::Result<()> {
    if Instant::now() >= end {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "poisson operator original deadline",
        ));
    }
    Ok(())
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "poisson control operator refused",
    )
}
pub fn run(
    config_path: &Path,
    input: Option<&Path>,
    output: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = Instant::now();
    let bytes = secret_file::read_config(config_path, 64 * 1024)?;
    let mut config: Config = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    config.profile.validate()?;
    if config.authenticated_shaping.is_some()
        || config.endpoint.port() == 0
        || config.endpoint.ip().is_unspecified()
        || config.endpoint.ip().is_multicast()
        || !(1..=60_000).contains(&config.deadline_ms)
    {
        return Err(refused().into());
    }
    let end = origin + Duration::from_millis(u64::from(config.deadline_ms));
    live(end)?;
    let base = config_path.parent().ok_or_else(refused)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match &mut config.tls {
        Role::Client { settings } => {
            if output.is_some() {
                return Err(refused().into());
            }
            live(end)?;
            let bytes = secret_file::read(
                input.ok_or_else(refused)?,
                u64::from(config.profile.timing.payload_capacity),
            )?;
            live(end)?;
            settings.resolve_paths(base);
            live(end)?;
            let client = Client::load(settings)?;
            live(end)?;
            let outcome = runtime.block_on(async {
                live(end)?;let tcp = timeout_at(end, TcpStream::connect(config.endpoint))
                    .await
                    .map_err(|_| refused())??;
                tcp.set_nodelay(true)?; live(end)?;
                Ok::<_, io::Error>(
                    poisson_control::send_once_with_ready(
                        &client,
                        &config.authenticated_shaping,
                        tcp,
                        config.profile,
                        bytes,
                        poisson_control::ApplicationControl{origin,end,ready:Some(Box::new(|ready|{println!("{}",serde_json::json!({"operation":"poisson_control","state":"application_resources_armed","starts_in_ns":ready.start.saturating_duration_since(Instant::now()).as_nanos(),"covers_for_ns":ready.covers_until.duration_since(ready.start).as_nanos(),"poisson_legitimacy_verified":false}));let _=std::io::Write::flush(&mut std::io::stdout());}))},
                    )
                    .await,
                )
            })?;
            match outcome {
                Ok(receipt) => println!("{}", serde_json::to_string(&receipt)?),
                Err(failure) => {
                    println!("{}", serde_json::to_string(&failure)?);
                    return Err(refused().into());
                }
            }
        }
        Role::Server { settings } => {
            if input.is_some() {
                return Err(refused().into());
            }
            live(end)?;
            let output = output.ok_or_else(refused)?;
            secret_file::trusted_parent(output)?;
            if output.symlink_metadata().is_ok() {
                return Err(refused().into());
            }
            live(end)?;
            settings.resolve_paths(base);
            live(end)?;
            let server = Server::load(settings)?;
            live(end)?;
            let outcome=runtime.block_on(async{
                let _watcher=server.start_registry_watcher();
                live(end)?;let listener=TcpListener::bind(config.endpoint).await?;
                live(end)?;println!("{{\"operation\":\"poisson_control\",\"state\":\"control_listening\",\"cover_armed\":false}}");
                std::io::Write::flush(&mut std::io::stdout())?;
                let(tcp,_)=timeout_at(end,listener.accept()).await.map_err(|_|refused())??;tcp.set_nodelay(true)?;live(end)?;
                Ok::<_,io::Error>(poisson_control::receive_once(&server,&config.authenticated_shaping,tcp,config.profile,origin,end).await)
            })?;
            match outcome {
                Ok(received) => {
                    secret_file::write_private_new(output, &received.payload)?;
                    println!("{}", serde_json::to_string(&received.receipt)?);
                }
                Err(failure) => {
                    println!("{}", serde_json::to_string(&failure)?);
                    return Err(refused().into());
                }
            }
        }
    }
    if Instant::now() >= end {
        return Err(refused().into());
    }
    Ok(())
}
