//! Strategy `fake_rst`: send first buffer normally, then try a decoy RST via `RawEngine`.
//!
//! On Linux, the exact TCP seq/ack path is queried through `TCP_REPAIR` /
//! `TCP_QUEUE_SEQ`, which requires `CAP_NET_ADMIN`. Raw packet send still
//! requires `CAP_NET_RAW`.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, RawEngine};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct FakeRstStrategy {
    pub engine: Arc<dyn RawEngine>,
}

impl Default for FakeRstStrategy {
    fn default() -> Self {
        Self {
            engine: default_raw_engine(),
        }
    }
}

#[async_trait]
impl Strategy for FakeRstStrategy {
    fn id(&self) -> &'static str {
        "fake_rst"
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
        // 1. Send the real data normally
        stream.write_all(data).await?;

        // A raw-dependent strategy must not degrade silently to the canonical
        // write. The caller records this strategy only if its wire effect also
        // completed.
        self.engine.try_send_fake_rst(stream, ctx.dst, self.id())?;

        Ok(())
    }
}
