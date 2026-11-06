//! Wide UDP → MASQUE **direct** send bridge for `udp_policy = masque_direct`.
//!
//! ## Architecture (honest boundaries)
//!
//! NFQUEUE is a **verdict-only** layer (observe / policy / DROP) — per the
//! backend split it is NOT a relay, and this bridge does not turn it into one.
//! For a generic UDP flow that policy would otherwise simply DROP, the bridge
//! additionally **carries the send leg** over MASQUE direct CONNECT-UDP and
//! proves a relay-side round trip, while the original packet stays DROPped (no
//! native leak, ever).
//!
//! The MASQUE response datagram is received **at the relay** but is **not**
//! injected back to the local application: NFQUEUE cannot inject a return path
//! (that needs a raw-socket / TUN device, which would make it a relay). So the
//! bridge is honestly **send-only** — see the verdict rule in the live-proof
//! artifact (`PARTIAL_SEND_ONLY` / `BLOCKED_BY_RETURN_PATH_NOT_IMPLEMENTED`),
//! never "UDP relay PASS".
//!
//! ## Fail-closed
//!
//! If the bridge queue is saturated or the MASQUE send leg errors, the flow
//! stays fail-closed (the packet was already DROPped). There is **no** native
//! UDP fallback under any outcome.

#![cfg(target_os = "linux")]

use super::linux_nfqueue::DecodedUdp;
use crate::relay::masque;
use crate::runtime_events::RuntimeEventCode;
use crate::runtime_jsonl;
use aegis_core::RelaySettings;
use serde_json::json;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::thread::JoinHandle;

/// A 4-tuple identifying one observed UDP flow (used for once-per-tuple session
/// accounting in the drain task).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowTuple {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
}

impl FlowTuple {
    fn from_udp(u: &DecodedUdp) -> Self {
        Self {
            src: u.src,
            dst: u.dst,
            src_port: u.src_port,
            dst_port: u.dst_port,
        }
    }
}

/// One send job handed from the (synchronous) NFQUEUE consumer thread to the
/// async drain task.
struct UdpJob {
    tuple: FlowTuple,
    target_host: String,
    target_port: u16,
    payload: Vec<u8>,
}

/// Bounded so a slow MASQUE send leg can never stall the verdict loop: a full
/// queue means we hold the flow fail-closed (the packet is already DROPped)
/// rather than block packet processing.
const QUEUE_DEPTH: usize = 256;

/// Handle to the MASQUE direct UDP send bridge. Cloneable-free: owned by the
/// NFQUEUE observer for the lifetime of the enforce run; dropping it closes the
/// channel and lets the drain task exit.
pub struct WideUdpMasqueBridge {
    tx: SyncSender<UdpJob>,
    drain: Option<JoinHandle<()>>,
}

impl WideUdpMasqueBridge {
    /// Spawn the drain task. The task owns its own current-thread Tokio runtime
    /// so the bridge is independent of whether the caller runs inside an async
    /// context (the NFQUEUE consumer loop is a blocking std thread).
    pub fn spawn(settings: RelaySettings) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<UdpJob>(QUEUE_DEPTH);
        let drain = std::thread::Builder::new()
            .name("aegis-udp-masque-bridge".to_string())
            .spawn(move || drain_loop(settings, rx))?;
        Ok(Self {
            tx,
            drain: Some(drain),
        })
    }

    /// Observe a generic UDP flow that the verdict layer has DROPped and hand
    /// its payload to the MASQUE direct send leg. Always non-blocking: if the
    /// queue is full the flow stays fail-closed (the packet was already
    /// DROPped) and `wide_udp_fail_closed` is emitted — never a native
    /// fallback.
    ///
    /// `payload` is the raw UDP datagram body (extracted by
    /// [`super::linux_nfqueue::udp_payload`]).
    pub fn observe_and_forward(&self, u: &DecodedUdp, payload: Vec<u8>) {
        let tuple = FlowTuple::from_udp(u);
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideUdpFlowObserved,
            "wide udp flow observed (masque_direct send bridge)",
            json!({
                "src": tuple.src.to_string(),
                "dst": tuple.dst.to_string(),
                "src_port": tuple.src_port,
                "dst_port": tuple.dst_port,
                "udp_len": u.udp_len,
                "payload_len": payload.len(),
                "ip_version": if u.is_ipv6 { 6 } else { 4 },
                "original_verdict": "drop",
                "carry": "masque_direct_send_only",
                "no_native_fallback": true,
            }),
        );
        let job = UdpJob {
            tuple,
            target_host: tuple.dst.to_string(),
            target_port: tuple.dst_port,
            payload,
        };
        match self.tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(job)) | Err(TrySendError::Disconnected(job)) => {
                runtime_jsonl::emit(
                    "warn",
                    RuntimeEventCode::WideUdpFailClosed,
                    "wide udp flow held fail-closed (masque bridge unavailable)",
                    json!({
                        "dst": job.tuple.dst.to_string(),
                        "dst_port": job.tuple.dst_port,
                        "reason": "bridge_queue_saturated_or_closed",
                        "no_native_fallback": true,
                    }),
                );
            }
        }
    }
}

impl Drop for WideUdpMasqueBridge {
    fn drop(&mut self) {
        // `self.tx` is dropped right after this body, disconnecting the channel
        // so the drain loop's `rx.recv()` returns Err and the thread exits on
        // its own. Detach the handle (do not join — that could block teardown).
        self.drain.take();
    }
}

/// Drain loop: owns a current-thread Tokio runtime and forwards each queued
/// datagram over MASQUE direct. Single-threaded, so the per-tuple session set
/// needs no lock.
fn drain_loop(settings: RelaySettings, rx: std::sync::mpsc::Receiver<UdpJob>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            runtime_jsonl::emit(
                "warn",
                RuntimeEventCode::WideUdpFailClosed,
                "wide udp masque bridge could not start (no runtime)",
                json!({ "error": e.to_string(), "no_native_fallback": true }),
            );
            return;
        }
    };
    let mut seen: HashSet<FlowTuple> = HashSet::new();
    while let Ok(job) = rx.recv() {
        let first_for_tuple = seen.insert(job.tuple);
        if first_for_tuple {
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::WideUdpMasqueSessionStarted,
                "wide udp masque direct session started",
                json!({
                    "dst": job.tuple.dst.to_string(),
                    "dst_port": job.tuple.dst_port,
                    "transport": "masque_direct_connect_udp",
                    "through_cloudflare": false,
                }),
            );
        }
        rt.block_on(forward_one(&settings, &job));
    }
}

/// Forward a single datagram and emit the send/receive/failure events. The
/// packet is already DROPped regardless of outcome — never native.
async fn forward_one(settings: &RelaySettings, job: &UdpJob) {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideUdpMasqueDatagramSent,
        "wide udp masque direct datagram sent",
        json!({
            "dst": job.tuple.dst.to_string(),
            "dst_port": job.tuple.dst_port,
            "payload_len": job.payload.len(),
            "through_cloudflare": false,
        }),
    );
    match masque::run_masque_udp_send(settings, &job.target_host, job.target_port, &job.payload)
        .await
    {
        Ok(response) => {
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::WideUdpMasqueDatagramReceived,
                "wide udp masque direct datagram received (relay round-trip; send-only to app)",
                json!({
                    "dst": job.tuple.dst.to_string(),
                    "dst_port": job.tuple.dst_port,
                    "response_len": response.len(),
                    "delivered_to_app": false,
                    "delivery_note": "nfqueue is verdict-only; return path not injected",
                }),
            );
        }
        Err(e) => {
            runtime_jsonl::emit(
                "warn",
                RuntimeEventCode::WideUdpFlowFailed,
                "wide udp masque direct send leg failed (stays fail-closed)",
                json!({
                    "dst": job.tuple.dst.to_string(),
                    "dst_port": job.tuple.dst_port,
                    "error": e.to_string(),
                    "no_native_fallback": true,
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_udp() -> DecodedUdp {
        DecodedUdp {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 5353,
            dst_port: 53,
            udp_len: 20,
            is_ipv6: false,
        }
    }

    #[test]
    fn flow_tuple_is_derived_from_decoded_udp() {
        let u = sample_udp();
        let t = FlowTuple::from_udp(&u);
        assert_eq!(t.src, u.src);
        assert_eq!(t.dst, u.dst);
        assert_eq!(t.src_port, u.src_port);
        assert_eq!(t.dst_port, u.dst_port);
    }

    #[test]
    fn observe_and_forward_never_blocks_when_queue_saturated() {
        // A bridge whose drain never consumes: fill the queue past depth and
        // confirm observe_and_forward stays non-blocking (fail-closed), never
        // panicking or wedging the verdict loop.
        let (tx, _rx) = sync_channel::<UdpJob>(1);
        let bridge = WideUdpMasqueBridge { tx, drain: None };
        let u = sample_udp();
        // Far more than the depth; must all return promptly.
        for _ in 0..1000 {
            bridge.observe_and_forward(&u, vec![1, 2, 3, 4]);
        }
    }
}
