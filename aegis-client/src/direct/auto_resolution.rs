//! Route-owned DNS for Auto TCP. Only hostname-independent hybrid admissions
//! can avoid local DNS; address-specific learning remains in handle_direct.

use super::*;
use std::future::Future;
use std::io;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AutoTargetRoute {
    Direct(SocketAddr),
    RelayByName { reason_code: &'static str },
}

#[allow(clippy::too_many_arguments)]
async fn select_auto_target_route_with<F, R>(
    target: &ConnectTarget,
    dst: SocketAddr,
    brain: &Brain,
    direct: &DirectSettings,
    fallback: &DirectFallbackContext<'_>,
    direct_capable: bool,
    resolve: F,
) -> anyhow::Result<AutoTargetRoute>
where
    F: FnOnce() -> R,
    R: Future<Output = io::Result<SocketAddr>>,
{
    // Concrete broker addresses and IP literals do not need deferred DNS.
    // No unspecified hostname placeholder reaches the direct executor.
    if !dst.ip().is_unspecified() || target.host.parse::<IpAddr>().is_ok() {
        return Ok(AutoTargetRoute::Direct(dst));
    }
    if direct.hybrid_geneva {
        if let Some(route) = brain.hybrid_route_before_resolution(direct_capable).await {
            // A required relay admission is terminal if its credential/transport
            // plan is unavailable. Do not turn that refusal into local DNS/direct.
            anyhow::ensure!(
                relay::runtime_fallback_ready(fallback.relay),
                "auto_relay_policy_refused: required relay route is unavailable"
            );
            return Ok(AutoTargetRoute::RelayByName {
                reason_code: route.reason.as_str(),
            });
        }
    }
    match resolve().await {
        Ok(address) => Ok(AutoTargetRoute::Direct(address)),
        Err(source) => {
            // DNS failed before any direct dial or application send. Only Auto's
            // explicit fallback policies may try the original name remotely.
            if fallback.terminal_policy != DirectTerminalPolicy::PreserveDirectFailure
                && relay::runtime_fallback_ready(fallback.relay)
            {
                Ok(AutoTargetRoute::RelayByName {
                    reason_code: "auto_target_resolution_failed",
                })
            } else {
                Err(anyhow::Error::new(source).context("auto_target_resolution: DNS lookup failed"))
            }
        }
    }
}

async fn with_auto_relay_initial_payload<F, R>(
    mut client: TcpStream,
    direct: &DirectSettings,
    handoff: F,
) -> anyhow::Result<()>
where
    F: FnOnce(TcpStream, Option<Vec<u8>>) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    // This is ordinary client-first Auto admission, using the same budget and
    // stage vocabulary as the Direct first-read owner. An explicit server-first
    // feature needs its separately reviewed admission; None is never authority.
    let mut payload = vec![0u8; 16384];
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(direct.first_chunk_timeout_ms))
        .ok_or_else(|| {
            stage_direct_error("direct_initial_read_deadline", "invalid timeout budget")
        })?;
    let n = tokio::time::timeout_at(deadline, client.read(&mut payload))
        .await
        .map_err(|_| {
            stage_direct_error(
                "direct_initial_read_timeout",
                "client first payload did not arrive",
            )
        })?
        .context("read first chunk")?;
    payload.truncate(n);
    if payload.is_empty() {
        // EOF before genuine application bytes keeps the flow outbound-free.
        return Ok(());
    }
    handoff(client, Some(payload)).await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_auto(
    client: TcpStream,
    target: ConnectTarget,
    dst: SocketAddr,
    brain: Arc<Brain>,
    direct: &DirectSettings,
    fallback: DirectFallbackContext<'_>,
    ghost: Option<Arc<GhostLurk>>,
) -> anyhow::Result<()> {
    let raw = default_raw_engine().capabilities();
    let route = select_auto_target_route_with(
        &target,
        dst,
        &brain,
        direct,
        &fallback,
        raw.ipv4_raw_send && raw.tcp_repair_query,
        || target.resolve(),
    )
    .await?;
    match route {
        AutoTargetRoute::Direct(address) => {
            handle_direct(client, target, address, brain, direct, fallback, ghost).await
        }
        AutoTargetRoute::RelayByName { reason_code } => {
            let stack = direct
                .stack_profile
                .as_deref()
                .and_then(|value| value.parse::<StackProfileId>().ok());
            // Own actual first input before any relay handoff. The real relay
            // owner authenticates before target open and receives exactly these
            // bytes once. Its terminal returns without a direct retry.
            with_auto_relay_initial_payload(client, direct, |client, payload| async move {
                run_relay_tunnel_with_direct_handoff(
                    client,
                    fallback.relay,
                    target.host,
                    target.port,
                    dst,
                    stack,
                    direct.wire_mimicry_mode,
                    DirectRelayHandoffContext {
                        initial_payload: payload.as_deref(),
                        handoff_path: "auto_route_resolution",
                        reason_code: reason_code.to_owned(),
                        active_stall_probe_retry_attempted: Some(false),
                        surface_bias: relay::SurfaceBias::default(),
                        hybrid: None,
                    },
                )
                .await
            })
            .await
        }
    }
}

#[cfg(test)]
#[path = "auto_resolution_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "auto_relay_initial_payload_tests.rs"]
mod relay_initial_payload_tests;
