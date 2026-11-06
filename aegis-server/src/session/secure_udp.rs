use aegis_core::secure_channel::datagram;
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

pub(super) async fn connect(
    host: &str,
    port: u16,
    policy: &crate::config::TargetPolicyConfig,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> io::Result<UdpSocket> {
    let addresses = crate::target_policy::resolve_allowed_targets_with_logging(
        host,
        port,
        policy,
        operational_log,
    )
    .await?;
    let mut last_error = None;
    for address in addresses {
        let binding = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        match UdpSocket::bind(binding).await {
            Ok(socket) => match socket.connect(address).await {
                Ok(()) => return Ok(socket),
                Err(error) => last_error = Some(error),
            },
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "secure UDP target unavailable")
    }))
}

pub(super) async fn copy<S: AsyncRead + AsyncWrite + Unpin>(
    inner: &mut S,
    remote: &UdpSocket,
    idle: Duration,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(inner);
    let (activity, mut changed) = tokio::sync::watch::channel(tokio::time::Instant::now());
    let to_target = async {
        while let Some(payload) = datagram::read(&mut reader).await? {
            if remote.send(&payload).await? != payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "secure UDP short send",
                ));
            }
            activity.send_replace(tokio::time::Instant::now());
        }
        io::Result::Ok(())
    };
    let to_client = async {
        let mut buffer = vec![0; 65_535];
        loop {
            let size = remote.recv(&mut buffer).await?;
            datagram::write(&mut writer, &buffer[..size]).await?;
            activity.send_replace(tokio::time::Instant::now());
        }
        #[allow(unreachable_code)]
        io::Result::Ok(())
    };
    let watchdog = async {
        loop {
            let deadline = *changed.borrow_and_update() + idle;
            tokio::select! {
                biased;
                result = changed.changed() => { result.map_err(|_| io::Error::other("secure UDP activity closed"))?; }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "secure UDP idle timeout"));
                }
            }
        }
    };
    // Separate direction futures retain partial frame reads/writes. Only
    // terminating the whole tunnel can cancel either one.
    tokio::select! { result = to_target => result, result = to_client => result, result = watchdog => result }
}
