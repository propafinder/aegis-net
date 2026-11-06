use serde::{Deserialize, Serialize};

use crate::state_v2::StateSnapshot;

use super::{NetworkHint, StrategyKey};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionContext {
    pub platform: String,
    pub target_class: String,
    pub network_profile: String,
    pub region_id: Option<String>,
    pub recent_failures: u64,
}

pub(super) fn decision_context_from_snapshot(
    snapshot: &StateSnapshot,
    key: &StrategyKey,
) -> DecisionContext {
    let base_hash = key.hash_key();
    let recent_failures = snapshot
        .strategy_stats
        .iter()
        .filter(|(entry_key, _)| entry_key.starts_with(&format!("{base_hash}|")))
        .map(|(_, stats)| stats.timeouts + stats.dpi_blocks + stats.freezes)
        .sum();
    DecisionContext {
        platform: current_platform().to_string(),
        target_class: format!("{:?}", key.target_class).to_ascii_lowercase(),
        network_profile: network_hint_as_str(key.network_hint).to_string(),
        region_id: snapshot
            .external_calibration
            .as_ref()
            .and_then(|calibration| {
                calibration
                    .knowledge
                    .iter()
                    .find_map(|prior| prior.region_id.clone())
            }),
        recent_failures,
    }
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn network_hint_as_str(hint: NetworkHint) -> &'static str {
    match hint {
        NetworkHint::Loopback => "loopback",
        NetworkHint::Private => "private",
        NetworkHint::Public => "public",
    }
}
