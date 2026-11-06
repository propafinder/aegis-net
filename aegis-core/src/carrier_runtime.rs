//! Explicit configuration for authenticated carrier experiments in native nodes.
//! No runtime setting implies measured resistance to a censor or a DP guarantee.
use crate::traffic_privacy::shaper::ShaperConfig;
use serde::{Deserialize, Serialize};
use std::{io, time::Duration};

pub(crate) const MAX_RELAY_SHAPING_CONTROL_BYTES: usize = 4096;

/// Identical explicit parameters are required at both peers. Framing is inside
/// device-authenticated TLS, and remains disabled when this section is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacySettings {
    pub payload_bytes: usize,
    pub cadence_ms: u64,
    pub buffer_bytes: usize,
    pub max_wire_bytes: u64,
    pub io_timeout_ms: u64,
    pub session_timeout_ms: u64,
    pub max_queue_delay_ms: u64,
    /// Explicit paired exponential proposal experiment. Absent preserves wire/profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poisson_pacing: Option<crate::traffic_privacy::poisson::PoissonPacing>,
    /// Finite, paired discrete-Gaussian queue epoch. Never mixed with pacing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_shaper: Option<crate::traffic_privacy::netshaper::NetShaperConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive_channel: Option<crate::traffic_privacy::adaptive_channel::AdaptiveSettings>,
    /// Enforces a declared arrival envelope. Service bounds remain conditional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrival_envelope: Option<crate::traffic_privacy::network_calculus_guard::Settings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_stream: Option<crate::traffic_privacy::cover_stream::CoverStreamSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_traps: Option<crate::traffic_privacy::bittraps::BitTrapsSettings>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "liu_present"
    )]
    pub liu_channel: Option<crate::traffic_privacy::liu_channel::LiuSettings>,
}

fn liu_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<crate::traffic_privacy::liu_channel::LiuSettings>, D::Error> {
    Deserialize::deserialize(d).map(Some)
}

impl PrivacySettings {
    /// Opaque carriers have no typed model/context/key agreement. Admit only
    /// their existing constant or exponential schedule before private custody.
    pub fn validate_opaque(&self) -> io::Result<ShaperConfig> {
        let config = self.validate()?;
        if self.net_shaper.is_some()
            || self.adaptive_channel.is_some()
            || self.cover_stream.is_some()
            || self.bit_traps.is_some()
            || self.liu_channel.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "research channel requires typed peer agreement and prepared session custody",
            ));
        }
        Ok(config)
    }

    pub fn validate(&self) -> io::Result<ShaperConfig> {
        let config = ShaperConfig {
            payload_bytes: self.payload_bytes,
            cadence: Duration::from_millis(self.cadence_ms),
            buffer_bytes: self.buffer_bytes,
            max_wire_bytes: self.max_wire_bytes,
            io_timeout: Duration::from_millis(self.io_timeout_ms),
            session_timeout: Duration::from_millis(self.session_timeout_ms),
            max_queue_delay: Duration::from_millis(self.max_queue_delay_ms),
        };
        config.validate()?;
        if let Some(liu) = &self.liu_channel {
            liu.validate()?;
        }
        // The complete typed hello must fit before any identity or connection
        // is acquired. Reserve space for both operation/version envelopes.
        let profile_bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if profile_bytes.len()
            > MAX_RELAY_SHAPING_CONTROL_BYTES - if self.liu_channel.is_some() { 512 } else { 64 }
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authenticated profile exceeds typed control envelope",
            ));
        }
        if [
            self.poisson_pacing.is_some(),
            self.net_shaper.is_some(),
            self.adaptive_channel.is_some(),
            self.cover_stream.is_some(),
            self.bit_traps.is_some(),
            self.liu_channel.is_some(),
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
            > 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "conflicting authenticated schedule owners",
            ));
        }
        if let Some(liu) = &self.liu_channel {
            liu.validate()?;
            if liu.payload_bytes() > self.payload_bytes
                || liu.buffer_bytes > self.buffer_bytes
                || liu.max_wire_bytes > self.max_wire_bytes
                || u64::from(liu.io_timeout_ms) > self.io_timeout_ms
                || u64::from(liu.session_timeout_ms) > self.session_timeout_ms
                || u64::from(liu.max_queue_delay_ms) > self.max_queue_delay_ms
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Liu model exceeds local envelope",
                ));
            }
        }
        if let Some(cover) = &self.cover_stream {
            cover.validate()?;
            if cover.buffer_bytes > self.buffer_bytes
                || cover.payload_bytes() > self.payload_bytes
                || cover.max_wire_bytes > self.max_wire_bytes
                || u64::from(cover.io_timeout_ms) > self.io_timeout_ms
                || u64::from(cover.session_timeout_ms) > self.session_timeout_ms
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cover stream exceeds local envelope",
                ));
            }
        }
        if let Some(bit) = &self.bit_traps {
            let profile = crate::traffic_privacy::bittraps::BitTrapsConfig::try_from(bit.clone())?;
            if profile.queue_capacity() > self.buffer_bytes
                || profile.release_capacity() > self.payload_bytes
                || profile.worst_wire_bytes() > self.max_wire_bytes
                || profile
                    .horizon()
                    .checked_add(Duration::from_millis(bit.io_timeout_ms))
                    .is_none_or(|span| span > Duration::from_millis(self.session_timeout_ms))
                || bit.io_timeout_ms > self.io_timeout_ms
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "BIT-TRAPS profile exceeds local envelope",
                ));
            }
        }
        if let Some(envelope) = &self.arrival_envelope {
            if self.poisson_pacing.is_some()
                || self.net_shaper.is_some()
                || self.adaptive_channel.is_some()
                || self.cover_stream.is_some()
                || self.bit_traps.is_some()
                || self.liu_channel.is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "arrival-service envelope requires the constant FIFO schedule",
                ));
            }
            envelope
                .validate_local_ceiling(
                    self.payload_bytes as u64,
                    (self.cadence_ms + self.io_timeout_ms)
                        .checked_mul(1_000_000)
                        .ok_or_else(|| io::Error::other("service period overflow"))?,
                )
                .map_err(io::Error::other)?;
            let bounds = envelope.theoretical_bounds().map_err(io::Error::other)?;
            if bounds.backlog_bytes_ceiling > self.buffer_bytes as u64
                || bounds.fifo_delay_ns_ceiling > self.max_queue_delay_ms.saturating_mul(1_000_000)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "conditional service model exceeds local queue allowance",
                ));
            }
        }
        if let Some(net) = &self.net_shaper {
            let profile =
                crate::traffic_privacy::netshaper::NetShaperProfile::try_from(net.clone())?;
            if self.poisson_pacing.is_some()
                || self.adaptive_channel.is_some()
                || profile.queue_capacity() > self.buffer_bytes
                || profile.release_capacity() > self.payload_bytes
                || profile.worst_wire_bytes() > self.max_wire_bytes
                || profile
                    .horizon()
                    .checked_add(Duration::from_millis(net.io_timeout_ms))
                    .is_none_or(|span| span > Duration::from_millis(self.session_timeout_ms))
                || profile.neighboring_window() > Duration::from_millis(self.max_queue_delay_ms)
                || net.io_timeout_ms > self.io_timeout_ms
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NetShaper profile exceeds local envelope or conflicts with another owner",
                ));
            }
        }
        if let Some(adaptive) = &self.adaptive_channel {
            adaptive.validate()?;
            if self.poisson_pacing.is_some()
                || self.net_shaper.is_some()
                || adaptive.buffer_bytes > self.buffer_bytes
                || adaptive
                    .actions
                    .iter()
                    .any(|a| usize::from(a.padded_bytes) > self.payload_bytes)
                || adaptive.max_wire_bytes > self.max_wire_bytes
                || u64::from(adaptive.io_timeout_ms) > self.io_timeout_ms
                || u64::from(adaptive.session_timeout_ms) > self.session_timeout_ms
                || u64::from(adaptive.max_queue_delay_ms) > self.max_queue_delay_ms
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "adaptive channel exceeds local envelope or conflicts with another owner",
                ));
            }
        }
        if let Some(pacing) = &self.poisson_pacing {
            pacing.validate()?;
            if self.cadence_ms != pacing.max_gap_us.div_ceil(1_000) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pacing maximum gap must match public receive envelope",
                ));
            }
        }
        Ok(config)
    }
}

pub trait ByteCarrier: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> ByteCarrier for S {}
pub type OwnedCarrier = Box<dyn ByteCarrier>;
pub use crate::traffic_privacy::worker_owner::{CleanupObservation, ShapingCleanupOwner};

/// Register termination before binding so services take the owned cleanup path.
pub fn shutdown_signal() -> io::Result<impl std::future::Future<Output = io::Result<()>>> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        #[cfg(unix)]
        {
            tokio::select! {result=tokio::signal::ctrl_c()=>result,_=terminate.recv()=>Ok(())}
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await
        }
    })
}

/// Only call after authentication; random filler is meaningful solely inside
/// encryption. The underlying owned task aborts when its stream is dropped.
pub fn shape_authenticated<S>(
    stream: S,
    privacy: Option<&PrivacySettings>,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    shape_authenticated_owned(stream, privacy, None)
}

/// Same authenticated attachment with explicit outer cancellation/join custody.
pub fn shape_authenticated_owned<S>(
    stream: S,
    privacy: Option<&PrivacySettings>,
    owner: Option<&ShapingCleanupOwner>,
) -> io::Result<OwnedCarrier>
where
    S: ByteCarrier + 'static,
{
    match privacy {
        Some(settings) => {
            let config = settings.validate_opaque()?;
            match &settings.poisson_pacing {
                Some(pacing) => Ok(Box::new(
                    crate::traffic_privacy::shaper::attach_poisson_owned(
                        stream,
                        config,
                        pacing.clone(),
                        owner,
                    )?,
                )),
                None => Ok(Box::new(
                    crate::traffic_privacy::shaper::attach_regulated_owned(
                        stream,
                        config,
                        settings.arrival_envelope.clone(),
                        owner,
                    )?,
                )),
            }
        }
        None => Ok(Box::new(stream)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn opaque_liu_refuses_before_poll_or_worker_and_drops_owned_carrier() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        struct HeldCarrier {
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for HeldCarrier {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl tokio::io::AsyncRead for HeldCarrier {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Pending
            }
        }
        impl tokio::io::AsyncWrite for HeldCarrier {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                b: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let settings: PrivacySettings = serde_json::from_value(serde_json::json!({
            "payload_bytes":2,"cadence_ms":1,"buffer_bytes":1024,"max_wire_bytes":100000,
            "io_timeout_ms":2000,"session_timeout_ms":10000,"max_queue_delay_ms":3000000,
            "liu_channel":{"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],
                "server_to_client_counts":[[3,1],[1,3]],"target_classes":[],
                "unmatched_traffic_class":0,"policy_ack_class":1,"distortion_microunits":125000,
                "optimizer_iterations":2000,"optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,
                "buffer_bytes":1024,"wire_batch_bytes":1024,"max_wire_bytes":100000,
                "io_timeout_ms":2000,"session_timeout_ms":10000,"max_queue_delay_ms":3000000}
        }))
        .unwrap();
        settings.validate().unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let held = HeldCarrier {
            polls: polls.clone(),
            drops: drops.clone(),
        };
        let error = shape_authenticated(held, Some(&settings))
            .err()
            .expect("opaque Liu must not substitute another owner");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        // Absence retains the ordinary opaque byte path.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (plain, mut peer) = tokio::io::duplex(16);
        let mut unchanged = shape_authenticated(plain, None).unwrap();
        unchanged.write_all(b"plain").await.unwrap();
        let mut b = [0; 5];
        peer.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"plain");
    }
    #[test]
    fn epoch_horizon_must_reserve_its_original_final_io_span_before_runtime() {
        let mut settings = PrivacySettings {
            payload_bytes: 64,
            cadence_ms: 10,
            buffer_bytes: 64,
            max_wire_bytes: 65536,
            io_timeout_ms: 10,
            session_timeout_ms: 160,
            max_queue_delay_ms: 200,
            poisson_pacing: None,
            net_shaper: Some(crate::traffic_privacy::netshaper::NetShaperConfig {
                slots: 16,
                cadence_ms: 10,
                window_ms: 200,
                io_timeout_ms: 10,
                queue_cap: 64,
                release_cap: 64,
                sigma_bytes: 32,
                rho_limit_n: "32".into(),
                rho_limit_d: "1".into(),
            }),
            adaptive_channel: None,
            arrival_envelope: None,
            cover_stream: None,
            bit_traps: None,
            liu_channel: None,
        };
        assert!(settings.validate().is_err());
        settings.session_timeout_ms = 180;
        settings.validate().unwrap();
        settings.net_shaper = None;
        settings.bit_traps = Some(crate::traffic_privacy::bittraps::BitTrapsSettings {
            slots: 16,
            cadence_ms: 10,
            io_timeout_ms: 10,
            queue_cap: 64,
            service: vec![(16, 1), (64, 1)],
        });
        settings.validate().unwrap();
        settings.session_timeout_ms = 160;
        assert!(settings.validate().is_err());
    }
    #[test]
    fn valid_cover_model_with_oversized_hello_refuses_before_runtime() {
        let cover = crate::traffic_privacy::cover_stream::CoverStreamSettings {
            tokens: (0..=255)
                .map(|x| {
                    let mut v = vec![0; 32];
                    v[0] = x;
                    v
                })
                .collect(),
            weights: vec![1; 256],
            conditional_model: None,
            capacity: 2,
            horizon: 64,
            max_records: 32,
            buffer_bytes: 1024,
            max_wire_bytes: 65536,
            io_timeout_ms: 100,
            session_timeout_ms: 1000,
        };
        cover.validate().unwrap();
        let settings = PrivacySettings {
            payload_bytes: 256,
            cadence_ms: 1,
            buffer_bytes: 1024,
            max_wire_bytes: 1_048_576,
            io_timeout_ms: 100,
            session_timeout_ms: 1000,
            max_queue_delay_ms: 1000,
            poisson_pacing: None,
            net_shaper: None,
            adaptive_channel: None,
            arrival_envelope: None,
            cover_stream: Some(cover),
            bit_traps: None,
            liu_channel: None,
        };
        assert!(serde_json::to_vec(&settings).unwrap().len() > MAX_RELAY_SHAPING_CONTROL_BYTES);
        assert_eq!(
            settings.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[test]
    fn invalid_privacy_budget_fails_before_runtime() {
        let settings = PrivacySettings {
            payload_bytes: 256,
            cadence_ms: 5,
            buffer_bytes: 1024,
            max_wire_bytes: 1,
            io_timeout_ms: 100,
            session_timeout_ms: 1000,
            max_queue_delay_ms: 1000,
            poisson_pacing: None,
            net_shaper: None,
            adaptive_channel: None,
            arrival_envelope: None,
            cover_stream: None,
            bit_traps: None,
            liu_channel: None,
        };
        assert!(settings.validate().is_err());
    }
}
