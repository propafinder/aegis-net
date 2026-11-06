//! One explicitly owned application insertion exchange over fresh device TLS.
//! Nothing is installed, enrolled, proxied or inferred from third-party traffic.
use super::{Client, Server};
use crate::traffic_privacy::poisson_insertion::{
    self as packet, InsertionProfile, InsertionReceipt, Material, ReceivedInsertion,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{timeout_at, Instant},
};
use zeroize::Zeroizing;

fn admission(p: &InsertionProfile) -> io::Result<[u8; 36]> {
    let mut b = [0; 36];
    b[..4].copy_from_slice(b"API1");
    b[4..].copy_from_slice(&p.descriptor()?);
    Ok(b)
}
fn preflight(p: &InsertionProfile, end: Instant) -> io::Result<()> {
    p.validate()?;
    let remaining = end
        .checked_duration_since(Instant::now())
        .ok_or_else(|| packet::fail(io::ErrorKind::TimedOut, "insertion original deadline"))?;
    if remaining > Duration::from_secs(60)
        || remaining <= Duration::from_millis(p.horizon_ms + p.io_timeout_ms)
    {
        return Err(packet::fail(
            io::ErrorKind::InvalidInput,
            "insertion original budget",
        ));
    }
    Ok(())
}
fn material<F>(p: &InsertionProfile, mut export: F) -> io::Result<Material>
where
    F: FnMut(&[u8], usize, &[u8]) -> io::Result<Zeroizing<Vec<u8>>>,
{
    let ctx = p.descriptor()?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&export(b"aegis.insertion.key.v1", 32, &ctx)?);
    let mut prefix = Zeroizing::new([0; 4]);
    prefix.copy_from_slice(&export(b"aegis.insertion.prefix.v1", 4, &ctx)?);
    Ok(Material::new(key, prefix))
}
fn ack(r: &InsertionReceipt) -> [u8; 36] {
    let mut b = [0; 36];
    b[..4].copy_from_slice(b"PIA1");
    for (i, n) in [
        r.original_records,
        r.original_bytes,
        r.inserted_records,
        r.wire_records,
    ]
    .into_iter()
    .enumerate()
    {
        b[4 + i * 8..12 + i * 8].copy_from_slice(&(n as u64).to_be_bytes());
    }
    b
}
async fn bound<F, T>(end: Instant, f: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    if Instant::now() >= end {
        return Err(packet::fail(
            io::ErrorKind::TimedOut,
            "insertion exchange deadline",
        ));
    }
    let v = timeout_at(end, f)
        .await
        .map_err(|_| packet::fail(io::ErrorKind::TimedOut, "insertion exchange deadline"))?
        .map_err(|e| {
            #[cfg(test)]
            if let Some(phase) = packet::failure_phase(&e) {
                eprintln!("insertion owned phase={phase} kind={:?}", e.kind());
            }
            packet::fail(e.kind(), "insertion authenticated exchange")
        })?;
    if Instant::now() >= end {
        return Err(packet::fail(
            io::ErrorKind::TimedOut,
            "insertion exchange late result",
        ));
    }
    Ok(v)
}
/// A real non-test caller may supply its own application TCP stream as source.
/// Consumes both owned streams on error/Drop; no resumption, retries or defaults.
pub async fn send_owned<C, R>(
    client: &Client,
    carrier: C,
    source: R,
    profile: InsertionProfile,
    message: Zeroizing<Vec<u8>>,
    original_deadline: Instant,
) -> io::Result<InsertionReceipt>
where
    C: AsyncRead + AsyncWrite + Unpin + 'static,
    R: AsyncRead + Unpin + 'static,
{
    let mut rng = OsRng;
    send_owned_with_rng(
        client,
        carrier,
        source,
        profile,
        message,
        original_deadline,
        &mut rng,
    )
    .await
}

// One implementation path; the public exchange always supplies OsRng.
// Tests can pin only the random draw sequence while exercising real TLS/I/O.
async fn send_owned_with_rng<C, R, G>(
    client: &Client,
    carrier: C,
    source: R,
    profile: InsertionProfile,
    message: Zeroizing<Vec<u8>>,
    original_deadline: Instant,
    rng: &mut G,
) -> io::Result<InsertionReceipt>
where
    C: AsyncRead + AsyncWrite + Unpin + 'static,
    R: AsyncRead + Unpin + 'static,
    G: RngCore + CryptoRng,
{
    preflight(&profile, original_deadline)?;
    if message.is_empty() || message.len() > profile.capacity {
        return Err(packet::fail(
            io::ErrorKind::InvalidInput,
            "insertion control capacity",
        ));
    }
    bound(original_deadline, async move {
        let mut stream = client.connect(carrier).await?;
        if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(packet::fail(
                io::ErrorKind::PermissionDenied,
                "insertion fresh TLS13 required",
            ));
        }
        stream.write_all(&admission(&profile)?).await?;
        stream.flush().await?;
        if stream.read_u8().await? != 0xa7 {
            return Err(packet::fail(
                io::ErrorKind::InvalidData,
                "insertion profile refused",
            ));
        }
        let m = material(&profile, |label, len, context| {
            stream
                .get_ref()
                .1
                .export_keying_material(Zeroizing::new(vec![0; len]), label, Some(context))
                .map_err(|_| packet::fail(io::ErrorKind::InvalidData, "insertion exporter"))
        })?;
        let (mut stream, receipt) =
            packet::send_records(&profile, m, source, stream, message, rng, original_deadline)
                .await?;
        let mut actual = [0; 36];
        stream.read_exact(&mut actual).await?;
        if actual != ack(&receipt) {
            return Err(packet::fail(
                io::ErrorKind::InvalidData,
                "insertion peer count ACK",
            ));
        }
        Ok(receipt)
    })
    .await
}
/// Sink receives only completely authenticated original records, in FIFO order.
/// A later failure can leave an explicitly owned sink with a verified prefix;
/// this is not a successful complete exchange or a restored application.
pub async fn receive_owned<C, S>(
    server: &Server,
    carrier: C,
    sink: S,
    profile: InsertionProfile,
    original_deadline: Instant,
) -> io::Result<(S, ReceivedInsertion)>
where
    C: AsyncRead + AsyncWrite + Unpin + 'static,
    S: AsyncWrite + Unpin + 'static,
{
    preflight(&profile, original_deadline)?;
    let _permit = server.try_acquire()?;
    bound(original_deadline, async move {
        let (mut stream, lease) = server.accept_with_lease(carrier).await?;
        if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(packet::fail(
                io::ErrorKind::PermissionDenied,
                "insertion fresh TLS13 required",
            ));
        }
        let exchange = async move {
            let mut actual = [0; 36];
            stream.read_exact(&mut actual).await?;
            if actual != admission(&profile)? {
                return Err(packet::fail(
                    io::ErrorKind::InvalidData,
                    "insertion profile refused",
                ));
            }
            let receiver_horizon = Instant::now() + Duration::from_millis(profile.horizon_ms);
            stream.write_u8(0xa7).await?;
            stream.flush().await?;
            let m = material(&profile, |label, len, context| {
                stream
                    .get_ref()
                    .1
                    .export_keying_material(Zeroizing::new(vec![0; len]), label, Some(context))
                    .map_err(|_| packet::fail(io::ErrorKind::InvalidData, "insertion exporter"))
            })?;
            let (mut stream, sink, received) = packet::receive_records(
                &profile,
                m,
                stream,
                sink,
                original_deadline,
                receiver_horizon,
            )
            .await?;
            stream.write_all(&ack(&received.receipt)).await?;
            stream.flush().await?;
            Ok((sink, received))
        };
        tokio::select! {biased;error=lease.revoked()=>Err(error),result=exchange=>result}
    })
    .await
}

#[cfg(test)]
#[path = "poisson_insertion_tests.rs"]
mod tests;
