//! Packet-level TTL desync: low-TTL decoy packet first, then normal TCP write.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, RawEngine};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct TtlDesyncStrategy {
    pub ttl: u8,
    pub engine: Arc<dyn RawEngine>,
}

impl Default for TtlDesyncStrategy {
    fn default() -> Self {
        // C4 (Track C anti-anomaly): TTL is picked from the named
        // LOW_DECOY_TTL_SET instead of a single hardcoded literal. Default
        // uses seed=0 so behaviour stays deterministic for tests; per-session
        // variance flows through a planner-supplied seed elsewhere.
        Self {
            ttl: super::pick_low_decoy_ttl(0),
            engine: default_raw_engine(),
        }
    }
}

#[async_trait]
impl Strategy for TtlDesyncStrategy {
    fn id(&self) -> &'static str {
        "ttl_desync"
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
        _sni: Option<(usize, usize)>,
        ctx: &SendFirstContext,
    ) -> std::io::Result<()> {
        self.engine.try_send_ttl_desync_first_packet(
            stream,
            ctx.dst,
            data,
            self.ttl,
            None,
            self.id(),
        )?;
        stream.write_all(data).await
    }
}
