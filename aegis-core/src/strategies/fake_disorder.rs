//! Packet-level disorder decoy: send tail before head with low TTL, then normal TCP write.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, RawEngine};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct FakeDisorderStrategy {
    pub ttl: u8,
    pub split_at: usize,
    pub engine: Arc<dyn RawEngine>,
}

impl Default for FakeDisorderStrategy {
    fn default() -> Self {
        // C4: TTL sourced from LOW_DECOY_TTL_SET instead of hardcoded `ttl: 5`.
        Self {
            ttl: super::pick_low_decoy_ttl(0),
            split_at: 26,
            engine: default_raw_engine(),
        }
    }
}

#[async_trait]
impl Strategy for FakeDisorderStrategy {
    fn id(&self) -> &'static str {
        "fake_disorder"
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
        let split = preferred_split(data.len(), sni, self.split_at);
        self.engine.try_send_disordered_first_packet(
            stream,
            ctx.dst,
            data,
            self.ttl,
            None,
            split,
            self.id(),
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
