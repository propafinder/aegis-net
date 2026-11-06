//! Packet-level IPv4 fragmentation decoy, then normal TCP write.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, FragmentDecoyPlan, RawEngine};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct IpFragStrategy {
    pub ttl: u8,
    pub first_payload_len: usize,
    pub overlap: usize,
    pub engine: Arc<dyn RawEngine>,
}

impl Default for IpFragStrategy {
    fn default() -> Self {
        // C4: TTL sourced from LOW_DECOY_TTL_SET (seed=0 for deterministic
        // default) instead of hardcoded `ttl: 5`.
        Self {
            ttl: super::pick_low_decoy_ttl(0),
            first_payload_len: 28,
            overlap: 10,
            engine: default_raw_engine(),
        }
    }
}

#[async_trait]
impl Strategy for IpFragStrategy {
    fn id(&self) -> &'static str {
        "ip_frag"
    }

    fn requirements(&self) -> StrategyRequirements {
        StrategyRequirements {
            needs_raw_ipv4: true,
            needs_exact_tcp_seq: true,
            ipv4_only: true,
        }
    }

    async fn send_first(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        sni: Option<(usize, usize)>,
        ctx: &SendFirstContext,
    ) -> std::io::Result<()> {
        let split = preferred_split(data.len(), sni, self.first_payload_len);
        self.engine.try_send_fragmented_first_packet(
            stream,
            data,
            None,
            FragmentDecoyPlan {
                dst: ctx.dst,
                ttl: self.ttl,
                first_payload_len: split,
                overlap: self.overlap,
                strategy_id: self.id(),
            },
        )?;
        stream.write_all(data).await
    }
}

fn preferred_split(len: usize, sni: Option<(usize, usize)>, fallback: usize) -> usize {
    if len <= 1 {
        return 1;
    }
    if let Some((offset, sni_len)) = sni {
        let cut = offset.saturating_add(sni_len / 2);
        return cut.clamp(1, len - 1);
    }
    fallback.min(len - 1).max(1)
}
