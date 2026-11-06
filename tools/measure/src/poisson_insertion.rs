//! Bounded explicitly owned file application source/sink. No host interception.
use aegis_core::traffic_privacy::poisson_insertion::{OwnedApplicationInput, PrivateBytes};
use aegis_core::{
    secret_file,
    secure_channel::{poisson_insertion, Client, ClientSettings, Server, ServerSettings},
    traffic_privacy::poisson_insertion::InsertionProfile,
};
use serde::Deserialize;
use std::{
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::AsyncWrite,
    net::{TcpListener, TcpStream},
    time::{timeout_at, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: std::net::SocketAddr,
    deadline_ms: u64,
    profile: InsertionProfile,
    tls: Role,
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Role {
    Client { settings: ClientSettings },
    Server { settings: ServerSettings },
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "owned insertion operator refused",
    )
}
struct PrivateBuffer {
    bytes: PrivateBytes,
    limit: usize,
}
impl AsyncWrite for PrivateBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self
            .bytes
            .len()
            .checked_add(b.len())
            .is_none_or(|n| n > self.limit)
        {
            return Poll::Ready(Err(refused()));
        }
        self.bytes.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
pub fn run(
    config_path: &Path,
    app_input: Option<&Path>,
    control_input: Option<&Path>,
    app_output: Option<&Path>,
    control_output: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = Instant::now();
    let raw = secret_file::read(config_path, 64 * 1024).map_err(|_| refused())?;
    let mut config: Config = serde_json::from_slice(&raw).map_err(|_| refused())?;
    config.profile.validate()?;
    if config.deadline_ms > 60000
        || config.deadline_ms <= config.profile.horizon_ms + config.profile.io_timeout_ms
    {
        return Err(refused().into());
    }
    let end = origin + Duration::from_millis(config.deadline_ms);
    let base = config_path.parent().ok_or_else(refused)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match &mut config.tls {
        Role::Client { settings } => {
            if app_output.is_some() || control_output.is_some() {
                return Err(refused().into());
            }
            let application = secret_file::read(
                app_input.ok_or_else(refused)?,
                config.profile.max_wire_bytes as u64,
            )
            .map_err(|_| refused())?;
            let message = secret_file::read(
                control_input.ok_or_else(refused)?,
                config.profile.capacity as u64,
            )
            .map_err(|_| refused())?;
            if message.is_empty()
                || application.len().div_ceil(config.profile.capacity) + 1
                    >= config.profile.max_records
            {
                return Err(refused().into());
            }
            settings.resolve_paths(base);
            let client = Client::load(settings).map_err(|_| refused())?;
            let receipt = runtime.block_on(async {
                let carrier = timeout_at(end, TcpStream::connect(config.endpoint))
                    .await
                    .map_err(|_| refused())?
                    .map_err(|_| refused())?;
                poisson_insertion::send_owned(
                    &client,
                    carrier,
                    OwnedApplicationInput::new(application, config.profile.max_wire_bytes)?,
                    config.profile.clone(),
                    message,
                    end,
                )
                .await
            })?;
            println!(
                "{}",
                serde_json::json!({"operation":"poisson_insertion","peer_count_ack":true,"receipt":receipt,"conditional_ideal_reference":config.profile.ideal_count_reference()?,"source_poisson_verified":false,"whole_wire_law":false,"installed_full_wide":false})
            );
        }
        Role::Server { settings } => {
            if app_input.is_some() || control_input.is_some() {
                return Err(refused().into());
            }
            let app_output = app_output.ok_or_else(refused)?;
            let control_output = control_output.ok_or_else(refused)?;
            if app_output == control_output {
                return Err(refused().into());
            }
            for path in [app_output, control_output] {
                secret_file::trusted_parent(path)?;
                if path.symlink_metadata().is_ok() {
                    return Err(refused().into());
                }
            }
            settings.resolve_paths(base);
            let server = Server::load(settings).map_err(|_| refused())?;
            let (sink, received) = runtime.block_on(async {
                let _watcher = server.start_registry_watcher();
                let exchange = async {
                    let listener = TcpListener::bind(config.endpoint)
                        .await
                        .map_err(|_| refused())?;
                    println!("{{\"operation\":\"poisson_insertion\",\"state\":\"listening\"}}");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    let (carrier, _) = listener.accept().await.map_err(|_| refused())?;
                    let sink = PrivateBuffer {
                        bytes: PrivateBytes::new(Vec::new()),
                        limit: config.profile.max_wire_bytes,
                    };
                    poisson_insertion::receive_owned(
                        &server,
                        carrier,
                        sink,
                        config.profile.clone(),
                        end,
                    )
                    .await
                };
                timeout_at(end, exchange).await.map_err(|_| refused())?
            })?;
            if Instant::now() >= end {
                return Err(refused().into());
            }
            secret_file::write_private_new(app_output, &sink.bytes)?;
            let receipt = received.receipt.clone();
            received.save_control_private_new(control_output)?;
            if Instant::now() >= end {
                return Err(refused().into());
            }
            println!(
                "{}",
                serde_json::json!({"operation":"poisson_insertion","private_outputs_saved":true,"receipt":receipt,"source_poisson_verified":false,"whole_wire_law":false,"installed_full_wide":false})
            );
        }
    }
    Ok(())
}
