//! Packet-level overlap с конфликтующими байтами через raw path.

use super::{SendFirstContext, Strategy, StrategyRequirements};
use crate::raw_engine::{default_raw_engine, OverlapDecoyPlan, RawEngine};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct OverlapStrategy {
    /// TTL для overlapping decoy packets.
    pub ttl: u8,
    /// Длина перекрытия в байтах от второго сегмента.
    pub overlap: usize,
    pub engine: Arc<dyn RawEngine>,
}

impl Default for OverlapStrategy {
    fn default() -> Self {
        Self {
            ttl: 5,
            overlap: 10,
            engine: default_raw_engine(),
        }
    }
}

#[async_trait]
impl Strategy for OverlapStrategy {
    fn id(&self) -> &'static str {
        "overlap"
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
        if data.len() < 16 {
            return stream.write_all(data).await;
        }
        let split = preferred_split(data.len(), sni);
        self.engine.try_send_overlapping_first_packet(
            stream,
            data,
            None,
            OverlapDecoyPlan {
                dst: ctx.dst,
                ttl: self.ttl,
                split_at: split,
                overlap: self.overlap,
                strategy_id: self.id(),
            },
        )?;
        // The real socket still sends the canonical payload; raw packets above
        // create the conflicting overlap that only nearer path elements should see.
        stream.write_all(data).await?;
        Ok(())
    }
}

fn preferred_split(len: usize, sni: Option<(usize, usize)>) -> usize {
    sni.and_then(|(offset, sni_len)| {
        let middle = offset + sni_len / 2;
        (middle > 0 && middle < len).then_some(middle)
    })
    .unwrap_or(len / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_split_uses_sni_midpoint_when_available() {
        assert_eq!(preferred_split(32, Some((8, 8))), 12);
    }

    #[test]
    fn preferred_split_falls_back_to_half_without_sni() {
        assert_eq!(preferred_split(32, None), 16);
    }
}
