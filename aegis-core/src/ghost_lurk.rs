//! Ghost-LURK: джиттер из профиля (JSON) и сглаживание по наблюдаемому IPG.
//!
//! Захват пакетов (AF_PACKET, libpcap) в дерево не тянем — метки времени можно брать из
//! `tcpdump -ttt`, tshark CSV и т.д., затем [`ipg_gaps_from_timestamps_ms`] /
//! [`GhostLurk::blend_observed_ipg_from_timestamps_ms`].

use crate::error::{AegisError, Result};
use rand::Rng;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Deserialize)]
struct GhostProfile {
    #[serde(default = "default_ipg")]
    ipg_ms: f64,
    #[serde(default = "default_min")]
    jitter_min_ms: u64,
    #[serde(default = "default_max")]
    jitter_max_ms: u64,
}

fn default_ipg() -> f64 {
    12.0
}
fn default_min() -> u64 {
    1
}
fn default_max() -> u64 {
    8
}

/// Межпакетные интервалы (мс) по возрастающим меткам времени (мс). Пустой или один элемент → пустой вектор.
pub fn ipg_gaps_from_timestamps_ms(timestamps: &[f64]) -> Vec<f64> {
    timestamps
        .windows(2)
        .filter_map(|w| {
            let d = w[1] - w[0];
            (d >= 0.0 && d.is_finite()).then_some(d)
        })
        .collect()
}

/// Среднее положительное IPG по набору интервалов (мс); для калибровки «одним числом».
pub fn mean_ipg_from_gaps_ms(gaps: &[f64]) -> Option<f64> {
    if gaps.is_empty() {
        return None;
    }
    let mut sum = 0.0f64;
    let mut n = 0usize;
    for &g in gaps {
        if g >= 0.0 && g.is_finite() {
            sum += g;
            n += 1;
        }
    }
    (n > 0).then_some(sum / n as f64)
}

/// Пассивный/эвристический профиль таймингов; нативный pcap — опционально вне процесса (см. PROGRESS.md).
pub struct GhostLurk {
    inner: Arc<RwLock<GhostProfile>>,
}

impl GhostLurk {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(GhostProfile {
                ipg_ms: default_ipg(),
                jitter_min_ms: default_min(),
                jitter_max_ms: default_max(),
            })),
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let s = fs::read_to_string(path.as_ref()).map_err(AegisError::Io)?;
        let p: GhostProfile = serde_json::from_str(&s)
            .map_err(|e| AegisError::Config(format!("ghost profile: {e}")))?;
        Ok(Self {
            inner: Arc::new(RwLock::new(p)),
        })
    }

    /// Подмешать наблюдаемый межпакетный интервал (EMA к `ipg_ms`).
    pub fn blend_observed_ipg_ms(&self, observed_ms: f64) {
        if observed_ms < 0.0 || !observed_ms.is_finite() {
            return;
        }
        if let Ok(mut g) = self.inner.write() {
            g.ipg_ms = g.ipg_ms * 0.9 + observed_ms * 0.1;
        }
    }

    /// Несколько наблюдаемых интервалов подряд (например из [`ipg_gaps_from_timestamps_ms`]): по каждому — шаг EMA.
    pub fn blend_observed_ipg_from_gaps_ms(&self, gaps_ms: &[f64]) {
        for &d in gaps_ms {
            self.blend_observed_ipg_ms(d);
        }
    }

    /// Цепочка меток времени (мс, неубывающая): сначала интервалы, затем EMA по каждому.
    pub fn blend_observed_ipg_from_timestamps_ms(&self, timestamps: &[f64]) {
        let gaps = ipg_gaps_from_timestamps_ms(timestamps);
        self.blend_observed_ipg_from_gaps_ms(&gaps);
    }

    /// Случайная задержка с учётом IPG и clamp.
    pub fn next_jitter_ms(&self) -> u64 {
        let mut rng = rand::thread_rng();
        let g = self.inner.read().ok();
        let Some(g) = g else {
            return 1;
        };
        let base = g.ipg_ms as u64;
        let j0 = g.jitter_min_ms;
        let j1 = g.jitter_max_ms.max(j0);
        rng.gen_range(j0..=j1).saturating_add(base / 4)
    }
}

impl Default for GhostLurk {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_from_timestamps() {
        assert!(ipg_gaps_from_timestamps_ms(&[]).is_empty());
        assert!(ipg_gaps_from_timestamps_ms(&[1.0]).is_empty());
        assert_eq!(
            ipg_gaps_from_timestamps_ms(&[0.0, 10.0, 25.0]),
            vec![10.0, 15.0]
        );
    }

    #[test]
    fn mean_gaps() {
        assert_eq!(mean_ipg_from_gaps_ms(&[]), None);
        assert_eq!(mean_ipg_from_gaps_ms(&[10.0, 20.0]), Some(15.0));
    }

    #[test]
    fn blend_timestamps_moves_ipg() {
        let g = GhostLurk::new();
        let before = g.inner.read().unwrap().ipg_ms;
        g.blend_observed_ipg_from_timestamps_ms(&[0.0, 100.0, 300.0]);
        let after = g.inner.read().unwrap().ipg_ms;
        assert!((after - before).abs() > f64::EPSILON);
    }

    #[test]
    fn blend_ignores_negative_observed() {
        let g = GhostLurk::new();
        let b = g.inner.read().unwrap().ipg_ms;
        g.blend_observed_ipg_ms(-5.0);
        assert_eq!(g.inner.read().unwrap().ipg_ms, b);
    }
}
