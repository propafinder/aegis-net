//! Сегментация первого буфера с небольшим джиттером между частями.

use super::Strategy;
use crate::ghost_lurk::GhostLurk;
use async_trait::async_trait;
use rand::Rng;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

pub struct MultisplitStrategy {
    /// Ghost-LURK: задержки из профиля вместо чистого RNG.
    pub ghost: Option<Arc<GhostLurk>>,
    pub min_part: usize,
    pub max_part: usize,
}

impl Default for MultisplitStrategy {
    fn default() -> Self {
        Self {
            ghost: None,
            min_part: 8,
            max_part: 256,
        }
    }
}

#[async_trait]
impl Strategy for MultisplitStrategy {
    fn id(&self) -> &'static str {
        "multisplit"
    }

    async fn send_first(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        sni: Option<(usize, usize)>,
        _ctx: &super::SendFirstContext,
    ) -> std::io::Result<()> {
        let cuts = breakpoints(data.len(), sni, self.min_part, self.max_part);
        let mut prev = 0usize;
        for c in cuts {
            stream.write_all(&data[prev..c]).await?;
            prev = c;
            let ms = if let Some(ref g) = self.ghost {
                g.next_jitter_ms()
            } else {
                rand::thread_rng().gen_range(1..6)
            };
            sleep(Duration::from_millis(ms)).await;
        }
        stream.write_all(&data[prev..]).await?;
        Ok(())
    }
}

fn breakpoints(
    len: usize,
    sni: Option<(usize, usize)>,
    min_part: usize,
    max_part: usize,
) -> Vec<usize> {
    if len < 2 {
        return vec![];
    }
    let mut v = Vec::new();
    if let Some((o, l)) = sni {
        if l > 1 && o + l <= len {
            v.push((o + l / 2).min(len - 1).max(1));
        }
    }
    if v.is_empty() {
        let lower = min_part.max(1).min(len - 1);
        let upper = max_part.max(lower).min(len - 1);
        v.push((len / 2).clamp(lower, upper));
        if len > upper.saturating_mul(2) {
            v.push((len - upper).clamp(lower, len - 1));
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}
