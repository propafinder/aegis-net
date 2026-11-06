//! Packet-level decoy with intentionally corrupted TCP checksum.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, RawEngine};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct ChecksumTrickStrategy {
    pub ttl: u8,
    pub engine: Arc<dyn RawEngine>,
}

impl Default for ChecksumTrickStrategy {
    fn default() -> Self {
        // C4: TTL sourced from NORMAL_TTL_SET (checksum decoy wants to look
        // like a legitimate OS stack, not a low-hop decoy) instead of
        // hardcoded `ttl: 60` which locked every session to Solaris-like
        // fingerprint. Default seed=0 → first entry in the set.
        Self {
            ttl: super::pick_normal_ttl(0),
            engine: default_raw_engine(),
        }
    }
}

#[async_trait]
impl Strategy for ChecksumTrickStrategy {
    fn id(&self) -> &'static str {
        "checksum_trick"
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
        self.engine.try_send_bad_checksum_first_packet(
            stream,
            ctx.dst,
            data,
            self.ttl,
            self.id(),
        )?;
        stream.write_all(data).await
    }
}
