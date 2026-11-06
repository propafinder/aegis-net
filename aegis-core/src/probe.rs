//! Классификация RST и TTL (обучение Brain).

use serde::{Deserialize, Serialize};

/// Источник RST для поля `last_rst_source` в состоянии.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RstSource {
    Local,
    Remote,
    Middlebox,
    Unknown,
}

/// Эвристика: низкий TTL у RST часто указывает на близкий инъектор.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RstProbe {
    Unknown,
    PossiblyMiddlebox,
    LikelyRemote,
}

const CANONICAL_INITIAL_TTLS: [u8; 5] = [32, 60, 64, 128, 255];

/// Нормализовать наблюдаемый TTL к ближайшему типичному initial TTL.
///
/// Это не истина, а best-effort база для более устойчивой hop-эвристики:
/// один и тот же observed TTL может происходить из разных стеков, но common
/// initial TTL values всё же дают полезную привязку для runtime probing.
pub fn canonical_initial_ttl(observed_ttl: u8) -> u8 {
    CANONICAL_INITIAL_TTLS
        .into_iter()
        .find(|candidate| observed_ttl <= *candidate)
        .unwrap_or(u8::MAX)
}

/// Оценить hop distance по наблюдаемому TTL.
pub fn estimated_hops(observed_ttl: u8) -> u8 {
    canonical_initial_ttl(observed_ttl).saturating_sub(observed_ttl)
}

/// Предпочтительный decoy TTL для active probe path.
///
/// Если уже видели более близкий middlebox reset, целимся в его глубину.
/// Иначе стараемся "истечь" чуть раньше известной remote path depth.
pub fn preferred_probe_ttl(
    reference_hops: Option<u8>,
    rst_hops: Option<u8>,
    rst_source: Option<RstSource>,
    fallback: u8,
) -> u8 {
    if rst_source == Some(RstSource::Middlebox) {
        if let Some(rst_hops) = rst_hops {
            return rst_hops.max(1);
        }
    }
    reference_hops
        .map(|hops| hops.saturating_sub(1).max(1))
        .unwrap_or(fallback)
}

/// Бюджет для активного TTL probe ladder.
///
/// Чем выше confidence/packet depth и чем быстрее observer видел нужные пакеты,
/// тем больше decoy TTL candidates разрешаем проверить.
pub fn active_probe_budget(
    matched_packets: u32,
    capture_wait_cycles: u32,
    rst_source: Option<RstSource>,
) -> usize {
    if matched_packets == 0 {
        return 1;
    }
    let mut budget = match capture_wait_cycles {
        0..=4 => 4,
        5..=12 => 3,
        _ => 2,
    };
    if matched_packets == 1 {
        budget = budget.min(3);
    }
    if rst_source == Some(RstSource::Middlebox) {
        budget = budget.max(3);
    }
    budget
}

/// Построить ordered TTL ladder для active raw probing.
pub fn active_probe_ttl_candidates(
    reference_hops: Option<u8>,
    rst_hops: Option<u8>,
    rst_source: Option<RstSource>,
    budget: usize,
    fallback: u8,
) -> Vec<u8> {
    if budget <= 1 {
        return vec![fallback];
    }
    let mut candidates = Vec::new();
    if rst_source == Some(RstSource::Middlebox) {
        if let Some(rst_hops) = rst_hops {
            push_unique_ttl(&mut candidates, rst_hops.max(1));
            push_unique_ttl(&mut candidates, rst_hops.saturating_sub(1).max(1));
        }
    }
    if let Some(reference_hops) = reference_hops {
        push_unique_ttl(&mut candidates, reference_hops.saturating_sub(1).max(1));
        push_unique_ttl(&mut candidates, reference_hops.saturating_sub(2).max(1));
    }
    let mut bounded = candidates
        .into_iter()
        .take(budget.saturating_sub(1))
        .collect::<Vec<_>>();
    push_unique_ttl(&mut bounded, fallback);
    bounded
}

fn push_unique_ttl(candidates: &mut Vec<u8>, ttl: u8) {
    if !candidates.contains(&ttl) {
        candidates.push(ttl);
    }
}

impl RstProbe {
    /// `observed_ttl` — TTL из IP-заголовка (нужен raw); без него — Unknown.
    ///
    /// `reference_ttl` — observed TTL от того же destination path
    /// (`first_packet_ttl` / `syn_ack_ttl`), а не "истинный" initial TTL.
    pub fn from_ttl_pair(observed_ttl: Option<u8>, reference_ttl: u8) -> Self {
        let Some(ttl) = observed_ttl else {
            return RstProbe::Unknown;
        };
        let ttl_delta = reference_ttl.abs_diff(ttl);
        let reference_initial = canonical_initial_ttl(reference_ttl);
        let rst_initial = canonical_initial_ttl(ttl);
        let reference_hops = estimated_hops(reference_ttl);
        let rst_hops = estimated_hops(ttl);

        if (rst_initial == reference_initial && ttl_delta <= 8)
            || ttl >= reference_ttl.saturating_sub(4)
        {
            RstProbe::LikelyRemote
        } else if ttl < 32
            || ttl.saturating_add(16) < reference_ttl
            || rst_hops > reference_hops.saturating_add(8)
        {
            RstProbe::PossiblyMiddlebox
        } else {
            RstProbe::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_initial_ttl_rounds_up_to_common_defaults() {
        assert_eq!(canonical_initial_ttl(10), 32);
        assert_eq!(canonical_initial_ttl(58), 60);
        assert_eq!(canonical_initial_ttl(61), 64);
        assert_eq!(canonical_initial_ttl(120), 128);
    }

    #[test]
    fn estimated_hops_uses_canonical_initial_ttl() {
        assert_eq!(estimated_hops(58), 2);
        assert_eq!(estimated_hops(120), 8);
    }

    #[test]
    fn preferred_probe_ttl_targets_middlebox_depth_first() {
        assert_eq!(
            preferred_probe_ttl(Some(8), Some(2), Some(RstSource::Middlebox), 3),
            2
        );
    }

    #[test]
    fn preferred_probe_ttl_falls_back_to_remote_depth_when_no_middlebox_rst() {
        assert_eq!(
            preferred_probe_ttl(Some(8), Some(6), Some(RstSource::Remote), 3),
            7
        );
        assert_eq!(preferred_probe_ttl(None, None, None, 3), 3);
    }

    #[test]
    fn active_probe_budget_expands_for_fast_confident_history() {
        assert_eq!(active_probe_budget(3, 1, None), 4);
        assert_eq!(active_probe_budget(2, 8, None), 3);
        assert_eq!(active_probe_budget(1, 20, None), 2);
    }

    #[test]
    fn active_probe_budget_keeps_middlebox_ladder_available() {
        assert_eq!(active_probe_budget(1, 20, Some(RstSource::Middlebox)), 3);
        assert_eq!(active_probe_budget(0, 1, Some(RstSource::Middlebox)), 1);
    }

    #[test]
    fn active_probe_candidates_expand_middlebox_and_remote_depths() {
        assert_eq!(
            active_probe_ttl_candidates(Some(8), Some(2), Some(RstSource::Middlebox), 4, 3),
            vec![2, 1, 7, 3]
        );
    }

    #[test]
    fn active_probe_candidates_fall_back_when_budget_is_minimal() {
        assert_eq!(
            active_probe_ttl_candidates(Some(8), None, None, 1, 3),
            vec![3]
        );
    }

    #[test]
    fn rst_probe_accepts_close_ttl_as_remote() {
        assert_eq!(
            RstProbe::from_ttl_pair(Some(58), 60),
            RstProbe::LikelyRemote
        );
        assert_eq!(
            RstProbe::from_ttl_pair(Some(120), 64),
            RstProbe::LikelyRemote
        );
    }

    #[test]
    fn rst_probe_marks_far_lower_ttl_as_middlebox() {
        assert_eq!(
            RstProbe::from_ttl_pair(Some(10), 64),
            RstProbe::PossiblyMiddlebox
        );
        assert_eq!(
            RstProbe::from_ttl_pair(Some(30), 58),
            RstProbe::PossiblyMiddlebox
        );
    }
}
