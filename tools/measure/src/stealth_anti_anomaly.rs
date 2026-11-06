use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{write_json, write_text};

const TARGET_DIRECT_PROFILES: usize = 8;
const TARGET_RELAY_PROFILES: usize = 6;
const TARGET_WS_POOL: usize = 3;
const TARGET_GRPC_POOL: usize = 3;
const TARGET_MASQUE_POOL: usize = 3;
const TARGET_DRIFT_SURFACES: usize = 8;

pub fn build_stealth_anti_anomaly_acceptance_summary(
    output_dir: &Path,
    repo_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let direct_ids = extract_catalog_ids(
        repo_root
            .join("aegis-client/src/direct/planner.rs")
            .as_path(),
        "const DIRECT_PROFILE_CATALOG",
        "family_id",
    )?;
    let relay_ids = extract_catalog_ids(
        repo_root.join("aegis-client/src/relay/policy.rs").as_path(),
        "const RELAY_SURFACE_CATALOG",
        "id",
    )?;
    let websocket_pool = extract_default_path_pool(
        repo_root.join("aegis-core/src/config_types.rs").as_path(),
        "default_websocket_path_pool",
    )?;
    let grpc_pool = extract_default_path_pool(
        repo_root.join("aegis-core/src/config_types.rs").as_path(),
        "default_grpc_path_pool",
    )?;
    let masque_pool = extract_default_path_pool(
        repo_root.join("aegis-core/src/config_types.rs").as_path(),
        "default_masque_path_pool",
    )?;
    let drift_surfaces = scan_drift_surfaces(
        repo_root
            .join("aegis-core/src/stealth_rotation.rs")
            .as_path(),
    )?;
    let phase_slot_count = scan_phase_slot_count(
        repo_root
            .join("aegis-core/src/stealth_rotation.rs")
            .as_path(),
    )?;

    let mut strategy_ttl_map = BTreeMap::new();
    for name in ["ttl_desync", "ip_frag", "fake_disorder", "checksum_trick"] {
        let (has_hardcoded, value) = count_hardcoded_ttl(
            repo_root
                .join(format!("aegis-core/src/strategies/{name}.rs"))
                .as_path(),
        )?;
        strategy_ttl_map.insert(
            name.to_string(),
            json!({
                "has_hardcoded": has_hardcoded,
                "value": value,
            }),
        );
    }
    let hardcoded_ttl_count = strategy_ttl_map
        .values()
        .filter(|item| item["has_hardcoded"].as_bool().unwrap_or(false))
        .count();

    let configurable_ttl_set_names = scan_configurable_ttl_sets(
        repo_root
            .join("aegis-core/src/strategies/ttl_sets.rs")
            .as_path(),
    )?;
    let configurable_ttl_sets = configurable_ttl_set_names.len();

    let drift_event_emitted = any_event_code_present(
        repo_root,
        &[
            "aegis-client/src/runtime_events.rs",
            "aegis-client/src/runtime_event_stream.rs",
            "aegis-client/src/direct.rs",
            "aegis-client/src/main.rs",
            "aegis-client/src/relay.rs",
        ],
        "stealth_profile_rotated",
    )?;
    let server_negotiation_emitted = any_event_code_present(
        repo_root,
        &[
            "aegis-client/src/runtime_events.rs",
            "aegis-client/src/runtime_event_stream.rs",
            "aegis-server/src/session.rs",
        ],
        "stealth_profile_negotiated",
    )?;

    let direct_diversity_pct = saturate_pct(direct_ids.len(), TARGET_DIRECT_PROFILES);
    let relay_diversity_pct = saturate_pct(relay_ids.len(), TARGET_RELAY_PROFILES);
    let catalog_diversity_score = (direct_diversity_pct + relay_diversity_pct).div_ceil(2);
    let parameter_randomization_score = saturate_pct(configurable_ttl_sets, 2);
    let drift_surfaces_pct = saturate_pct(drift_surfaces.len(), TARGET_DRIFT_SURFACES);
    let anti_correlation_score = drift_surfaces_pct.min(60);
    let intra_session_drift_score = if drift_event_emitted { 100 } else { 0 };
    let ws_pct = saturate_pct(websocket_pool.len(), TARGET_WS_POOL);
    let grpc_pct = saturate_pct(grpc_pool.len(), TARGET_GRPC_POOL);
    let masque_pct = saturate_pct(masque_pool.len(), TARGET_MASQUE_POOL);
    let path_pool_coverage_score = (ws_pct + grpc_pct + masque_pct + 1) / 3;
    let server_side_coordination_score = if server_negotiation_emitted { 100 } else { 0 };

    let dimension_scores = [
        ("catalog_diversity", catalog_diversity_score),
        ("parameter_randomization", parameter_randomization_score),
        ("anti_correlation", anti_correlation_score),
        ("intra_session_drift", intra_session_drift_score),
        ("path_pool_coverage", path_pool_coverage_score),
        ("server_side_coordination", server_side_coordination_score),
    ];
    let composite_anti_anomaly_score = (dimension_scores
        .iter()
        .map(|(_, score)| score)
        .sum::<usize>()
        + 3)
        / dimension_scores.len();

    let (verdict, status) = if composite_anti_anomaly_score >= 70 {
        ("strong", "anti_anomaly_strong")
    } else if composite_anti_anomaly_score >= 50 {
        ("medium", "anti_anomaly_medium")
    } else {
        ("weak", "anti_anomaly_weak")
    };

    let lowest_score = dimension_scores
        .iter()
        .map(|(_, score)| *score)
        .min()
        .unwrap_or(0);
    let lowest_dim = dimension_scores
        .iter()
        .find(|(_, score)| *score == lowest_score)
        .map(|(name, _)| *name)
        .unwrap_or("catalog_diversity");
    let next_action = match lowest_dim {
        "catalog_diversity" => "open_C2_catalog_expansion_relay_3_to_6",
        "parameter_randomization" => "open_C4_configurable_ttl_sets",
        "anti_correlation" => "open_nondeterministic_phase_offsets",
        "intra_session_drift" => "open_C3_intra_session_drift_timer_and_event",
        "path_pool_coverage" => "open_path_pool_expansion_per_transport",
        "server_side_coordination" => "open_C5_server_side_profile_negotiation",
        _ => "open_C2_catalog_expansion_relay_3_to_6",
    };

    let payload = json!({
        "artifact_schema": "stealth_anti_anomaly_acceptance_summary_v1",
        "producer": "build-stealth-anti-anomaly-acceptance-summary.sh",
        "scope": "repo_source_side_track_c_anti_anomaly_baseline",
        "composite_anti_anomaly_score": composite_anti_anomaly_score,
        "verdict": verdict,
        "status": status,
        "next_action": next_action,
        "dimensions": {
            "catalog_diversity": {
                "score": catalog_diversity_score,
                "direct_profile_count": direct_ids.len(),
                "direct_profile_ids": direct_ids,
                "direct_target": TARGET_DIRECT_PROFILES,
                "relay_profile_count": relay_ids.len(),
                "relay_profile_ids": relay_ids,
                "relay_target": TARGET_RELAY_PROFILES,
            },
            "parameter_randomization": {
                "score": parameter_randomization_score,
                "hardcoded_ttl_strategies": strategy_ttl_map,
                "hardcoded_ttl_count": hardcoded_ttl_count,
                "configurable_ttl_sets": configurable_ttl_sets,
                "configurable_ttl_set_names": configurable_ttl_set_names,
                "configurable_ttl_set_target": 2,
            },
            "anti_correlation": {
                "score": anti_correlation_score,
                "drift_surfaces_count": drift_surfaces.len(),
                "drift_surfaces": drift_surfaces,
                "drift_surfaces_target": TARGET_DRIFT_SURFACES,
                "phase_slot_count": phase_slot_count,
                "deterministic_offsets_cap": 60,
                "note": "Offsets are deterministic per base_epoch; cap lifts once a nondeterministic component lands.",
            },
            "intra_session_drift": {
                "score": intra_session_drift_score,
                "stealth_profile_rotated_event_emitted": drift_event_emitted,
                "target_event_code": "stealth_profile_rotated",
            },
            "path_pool_coverage": {
                "score": path_pool_coverage_score,
                "websocket_path_pool": websocket_pool,
                "grpc_path_pool": grpc_pool,
                "masque_path_pool": masque_pool,
                "websocket_target": TARGET_WS_POOL,
                "grpc_target": TARGET_GRPC_POOL,
                "masque_target": TARGET_MASQUE_POOL,
            },
            "server_side_coordination": {
                "score": server_side_coordination_score,
                "stealth_profile_negotiated_event_emitted": server_negotiation_emitted,
                "target_event_code": "stealth_profile_negotiated",
            },
        },
        "thresholds": {
            "strong_min": 70,
            "medium_min": 50,
        },
        "sources_read": [
            "aegis-client/src/direct/planner.rs",
            "aegis-client/src/relay/policy.rs",
            "aegis-core/src/config_types.rs",
            "aegis-core/src/stealth_rotation.rs",
            "aegis-core/src/strategies/ttl_desync.rs",
            "aegis-core/src/strategies/ip_frag.rs",
            "aegis-core/src/strategies/fake_disorder.rs",
            "aegis-core/src/strategies/checksum_trick.rs",
            "aegis-client/src/runtime_event_stream.rs",
        ],
    });

    write_json(
        &output_dir.join("stealth-anti-anomaly-acceptance-summary.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("stealth-anti-anomaly-acceptance-summary.md"),
        &render_markdown(&payload, &dimension_scores),
    )?;

    Ok(())
}

fn render_markdown(payload: &Value, dimension_scores: &[(&str, usize)]) -> String {
    let mut lines = vec![
        "# Stealth Anti-Anomaly Acceptance (Track C Baseline)".to_string(),
        String::new(),
        format!(
            "- Composite anti-anomaly score: `{}/100`",
            payload["composite_anti_anomaly_score"]
        ),
        format!("- Verdict: `{}`", payload["verdict"].as_str().unwrap_or("")),
        format!("- Status: `{}`", payload["status"].as_str().unwrap_or("")),
        format!(
            "- Next action: `{}`",
            payload["next_action"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Dimension Scores".to_string(),
        String::new(),
    ];

    for (dimension, score) in dimension_scores {
        lines.push(format!("- `{dimension}`: `{score}/100`"));
    }

    lines.extend([
        String::new(),
        "## Catalog Sizes".to_string(),
        String::new(),
        format!(
            "- Direct profile catalog: `{}` (target `{}`)",
            payload["dimensions"]["catalog_diversity"]["direct_profile_count"],
            TARGET_DIRECT_PROFILES
        ),
        format!(
            "- Relay surface catalog: `{}` (target `{}`)",
            payload["dimensions"]["catalog_diversity"]["relay_profile_count"],
            TARGET_RELAY_PROFILES
        ),
        format!(
            "- WebSocket path pool: `{}` (target `{}`)",
            payload["dimensions"]["path_pool_coverage"]["websocket_path_pool"]
                .as_array()
                .map_or(0, Vec::len),
            TARGET_WS_POOL
        ),
        format!(
            "- gRPC path pool: `{}` (target `{}`)",
            payload["dimensions"]["path_pool_coverage"]["grpc_path_pool"]
                .as_array()
                .map_or(0, Vec::len),
            TARGET_GRPC_POOL
        ),
        format!(
            "- MASQUE path pool: `{}` (target `{}`)",
            payload["dimensions"]["path_pool_coverage"]["masque_path_pool"]
                .as_array()
                .map_or(0, Vec::len),
            TARGET_MASQUE_POOL
        ),
        format!(
            "- Drift surfaces: `{}` (target `{}`)",
            payload["dimensions"]["anti_correlation"]["drift_surfaces_count"],
            TARGET_DRIFT_SURFACES
        ),
        format!(
            "- Phase slot count: `{}`",
            payload["dimensions"]["anti_correlation"]["phase_slot_count"]
        ),
        String::new(),
        "## Hardcoded Strategy TTLs (C4 target)".to_string(),
        String::new(),
    ]);

    if let Some(items) =
        payload["dimensions"]["parameter_randomization"]["hardcoded_ttl_strategies"].as_object()
    {
        for (name, info) in items {
            if info["has_hardcoded"].as_bool().unwrap_or(false) {
                lines.push(format!("- `{name}`: ttl=`{}` (hardcoded)", info["value"]));
            } else {
                lines.push(format!("- `{name}`: (no hardcoded ttl literal)"));
            }
        }
    }

    lines.join("\n") + "\n"
}

fn read_required_text(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Err(format!("Missing required source file: {}", path.display()).into());
    }
    Ok(std::fs::read_to_string(path)?)
}

fn extract_catalog_ids(
    path: &Path,
    anchor: &str,
    key: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = read_required_text(path)?;
    let start = text
        .find(anchor)
        .ok_or_else(|| format!("missing anchor {anchor} in {}", path.display()))?;
    let tail = &text[start..];
    let end = tail
        .find("];")
        .ok_or_else(|| format!("missing catalog terminator in {}", path.display()))?;
    Ok(extract_quoted_after_key(&tail[..end], key))
}

fn extract_default_path_pool(
    path: &Path,
    fn_name: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = read_required_text(path)?;
    let anchor = format!("fn {fn_name}() -> Vec<String>");
    let start = text
        .find(&anchor)
        .ok_or_else(|| format!("missing function {fn_name} in {}", path.display()))?;
    let body = balanced_brace_block(&text, start)
        .ok_or_else(|| format!("missing function body for {fn_name} in {}", path.display()))?;

    Ok(body
        .match_indices('"')
        .step_by(2)
        .filter_map(|(quote_start, _)| {
            let rest = &body[quote_start + 1..];
            let quote_end = rest.find('"')?;
            let value = &rest[..quote_end];
            let after = &rest[quote_end + 1..];
            after
                .trim_start()
                .starts_with(".into()")
                .then(|| value.to_string())
        })
        .collect())
}

fn count_hardcoded_ttl(path: &Path) -> Result<(bool, Option<u64>), Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Ok((false, None));
    }
    let text = read_required_text(path)?;
    let Some(index) = text.find("ttl:") else {
        return Ok((false, None));
    };
    let rest = text[index + "ttl:".len()..].trim_start();
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Ok((false, None));
    }
    Ok((true, Some(digits.parse()?)))
}

fn scan_drift_surfaces(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = read_required_text(path)?;
    let start = text
        .find("pub enum DriftSurface")
        .ok_or_else(|| format!("missing DriftSurface in {}", path.display()))?;
    let block = balanced_brace_block(&text, start)
        .ok_or_else(|| format!("missing DriftSurface body in {}", path.display()))?;
    Ok(block
        .lines()
        .map(str::trim)
        .map(|line| line.trim_end_matches(','))
        .filter(|line| {
            line.chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_uppercase())
        })
        .map(str::to_string)
        .collect())
}

fn scan_phase_slot_count(path: &Path) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    let text = read_required_text(path)?;
    let Some(index) = text.find("PHASE_SLOT_COUNT") else {
        return Ok(None);
    };
    let Some(eq_index) = text[index..].find('=') else {
        return Ok(None);
    };
    let rest = text[index + eq_index + 1..].trim_start();
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        Ok(None)
    } else {
        Ok(Some(digits.parse()?))
    }
}

fn scan_configurable_ttl_sets(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = read_required_text(path)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("pub const ") || !trimmed.contains("_TTL_SET") {
                return None;
            }
            let name = trimmed
                .trim_start_matches("pub const ")
                .split(|ch: char| ch == ':' || ch.is_whitespace())
                .next()?;
            name.ends_with("_TTL_SET").then(|| name.to_string())
        })
        .collect())
}

fn any_event_code_present(
    repo_root: &Path,
    relative_paths: &[&str],
    code: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    for relative_path in relative_paths {
        let path = repo_root.join(relative_path);
        if path.is_file() && std::fs::read_to_string(path)?.contains(code) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn extract_quoted_after_key(block: &str, key: &str) -> Vec<String> {
    let needle = format!("{key}:");
    let mut values = Vec::new();
    let mut cursor = block;
    while let Some(index) = cursor.find(&needle) {
        let after_key = &cursor[index + needle.len()..];
        let Some(open_quote) = after_key.find('"') else {
            break;
        };
        let after_open = &after_key[open_quote + 1..];
        let Some(close_quote) = after_open.find('"') else {
            break;
        };
        values.push(after_open[..close_quote].to_string());
        cursor = &after_open[close_quote + 1..];
    }
    values
}

fn balanced_brace_block(text: &str, start: usize) -> Option<&str> {
    let body_start = text[start..].find('{')? + start;
    let mut depth = 0_i64;
    for (offset, ch) in text[body_start..].char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(&text[body_start..body_start + offset + ch.len_utf8()]);
            }
        }
    }
    None
}

fn saturate_pct(value: usize, target: usize) -> usize {
    if target == 0 {
        return 0;
    }
    ((100 * value + target / 2) / target).min(100)
}
