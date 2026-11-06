use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::artifact::{write_json, write_text};

const PHASE_SLOT_COUNT: u64 = 17;
const RELAY_SAMPLE_SIZE: usize = 512;
const DIRECT_SAMPLE_SIZE: usize = 512;
const DISTRIBUTION_SIGMA_LIMIT: f64 = 3.0;

#[derive(Clone, Debug)]
struct RelaySurface {
    id: String,
    accept_language_header: Option<String>,
    cache_control_header: Option<String>,
    websocket_origin_strategy: Option<String>,
    grpc_accept_encoding_header: Option<String>,
    grpc_encoding_header: Option<String>,
    grpc_timeout_header: Option<String>,
    grpc_message_type_header: Option<String>,
    masque_alt_used_strategy: Option<String>,
}

#[derive(Clone, Debug)]
struct RelaySettings {
    server: String,
    server_name: String,
    websocket_path: String,
    websocket_path_pool: Vec<String>,
    grpc_path: String,
    grpc_path_pool: Vec<String>,
    masque_path: String,
    masque_path_pool: Vec<String>,
    drift_epoch_secs: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RelaySignature {
    profile_id: String,
    websocket_path: String,
    grpc_path: String,
    masque_path: String,
    accept_language_header: String,
    cache_control_header: String,
    websocket_origin_header: String,
    grpc_accept_encoding_header: String,
    grpc_encoding_header: String,
    grpc_timeout_header: String,
    grpc_message_type_header: String,
    masque_alt_used_header: String,
}

pub fn build_stealth_polymorphism_acceptance_summary(
    output_dir: &Path,
    config_path: &Path,
    root: &Path,
    now_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let direct_ids = extract_catalog_ids(
        &root.join("aegis-client/src/direct/planner.rs"),
        "const DIRECT_PROFILE_CATALOG",
        "family_id",
    )?;
    let relay_surfaces =
        extract_relay_surface_catalog(&root.join("aegis-client/src/relay/policy.rs"))?;
    let relay_ids = relay_surfaces
        .iter()
        .map(|surface| surface.id.clone())
        .collect::<Vec<_>>();

    let config_text = std::fs::read_to_string(config_path)?;
    let config = config_text.parse::<toml::Value>()?;
    let relay_cfg = config.get("relay");
    let relay_policy = relay_cfg.and_then(|value| value.get("policy"));

    let config_types_path = root.join("aegis-core/src/config_types.rs");
    let default_websocket_pool =
        extract_default_path_pool(&config_types_path, "default_websocket_path_pool")?;
    let default_grpc_pool =
        extract_default_path_pool(&config_types_path, "default_grpc_path_pool")?;
    let default_masque_pool =
        extract_default_path_pool(&config_types_path, "default_masque_path_pool")?;

    let relay_settings = RelaySettings {
        server: toml_str(relay_cfg, "server")
            .unwrap_or("127.0.0.1:8443")
            .to_string(),
        server_name: toml_str(relay_cfg, "server_name")
            .unwrap_or("localhost")
            .to_string(),
        websocket_path: toml_str(relay_cfg, "websocket_path")
            .unwrap_or("/aegis/ws")
            .to_string(),
        websocket_path_pool: toml_string_array(relay_cfg, "websocket_path_pool")
            .unwrap_or(default_websocket_pool),
        grpc_path: toml_str(relay_cfg, "grpc_path")
            .unwrap_or("/aegis.tunnel.v1.TunnelService/Open")
            .to_string(),
        grpc_path_pool: toml_string_array(relay_cfg, "grpc_path_pool").unwrap_or(default_grpc_pool),
        masque_path: toml_str(relay_cfg, "masque_path")
            .unwrap_or("/.well-known/masque/udp")
            .to_string(),
        masque_path_pool: toml_string_array(relay_cfg, "masque_path_pool")
            .unwrap_or(default_masque_pool),
        drift_epoch_secs: toml_int(relay_policy, "drift_epoch_secs").unwrap_or(900) as u64,
    };

    let thresholds = json!({
        "direct_variance_min_unique": direct_ids.len().min(5),
        "direct_distribution_floor": distribution_floor(DIRECT_SAMPLE_SIZE, direct_ids.len()),
        "direct_distribution_ceiling": distribution_ceiling(DIRECT_SAMPLE_SIZE, direct_ids.len()),
        "relay_variance_min_unique": relay_ids.len().min(4),
        "relay_distribution_floor": distribution_floor(RELAY_SAMPLE_SIZE, relay_ids.len()),
        "relay_distribution_ceiling": distribution_ceiling(RELAY_SAMPLE_SIZE, relay_ids.len()),
        "cross_layer_min_cardinality": 2,
    });

    let direct_stability_ok = direct_profile_family(&direct_ids, "198.51.100.42", 443, now_secs)
        == direct_profile_family(&direct_ids, "198.51.100.42", 443, now_secs + 30);
    let direct_variance_seen = sorted_set((1..33).map(|octet| {
        direct_profile_family(&direct_ids, &format!("203.0.113.{octet}"), 443, now_secs)
    }));
    let direct_variance_ok = direct_variance_seen.len()
        >= thresholds["direct_variance_min_unique"].as_u64().unwrap() as usize;
    let direct_coverage_seen = sorted_set((1..129).map(|octet| {
        direct_profile_family(&direct_ids, &format!("198.51.100.{octet}"), 443, now_secs)
    }));
    let direct_coverage_ok = direct_coverage_seen == sorted_vec(direct_ids.clone());
    let direct_counts = count_strings(
        (1..513).map(|port| direct_profile_family(&direct_ids, "198.51.100.42", port, now_secs)),
    );
    let direct_min = *direct_counts.values().min().unwrap_or(&0);
    let direct_max = *direct_counts.values().max().unwrap_or(&0);
    let direct_distribution_ok = direct_counts.len() == direct_ids.len()
        && direct_min >= thresholds["direct_distribution_floor"].as_u64().unwrap() as usize
        && direct_max <= thresholds["direct_distribution_ceiling"].as_u64().unwrap() as usize;

    let relay_stability_ok = relay_profile_signature(
        &relay_settings,
        &relay_surfaces,
        "example.org",
        443,
        now_secs,
    ) == relay_profile_signature(
        &relay_settings,
        &relay_surfaces,
        "example.org",
        443,
        now_secs + 30,
    );
    let relay_variance_seen = sorted_signature_set((1..33).map(|octet| {
        relay_profile_signature(
            &relay_settings,
            &relay_surfaces,
            &format!("edge-{octet}.example.org"),
            443,
            now_secs,
        )
    }));
    let relay_variance_ok = relay_variance_seen.len()
        >= thresholds["relay_variance_min_unique"].as_u64().unwrap() as usize;

    let relay_coverage_samples = (1..129)
        .map(|octet| {
            relay_profile_signature(
                &relay_settings,
                &relay_surfaces,
                &format!("edge-{octet}.example.org"),
                443,
                now_secs,
            )
        })
        .collect::<Vec<_>>();
    let relay_profile_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.profile_id.clone()),
    );
    let relay_websocket_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.websocket_path.clone()),
    );
    let relay_grpc_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.grpc_path.clone()),
    );
    let relay_masque_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.masque_path.clone()),
    );
    let relay_accept_language_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.accept_language_header.clone()),
    );
    let relay_cache_control_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.cache_control_header.clone()),
    );
    let relay_websocket_origin_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.websocket_origin_header.clone()),
    );
    let relay_grpc_accept_encoding_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.grpc_accept_encoding_header.clone()),
    );
    let relay_grpc_encoding_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.grpc_encoding_header.clone()),
    );
    let relay_grpc_timeout_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.grpc_timeout_header.clone()),
    );
    let relay_grpc_message_type_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.grpc_message_type_header.clone()),
    );
    let relay_masque_alt_used_seen = sorted_set(
        relay_coverage_samples
            .iter()
            .map(|item| item.masque_alt_used_header.clone()),
    );

    let expected_websocket_paths = dedupe_candidates(
        &relay_settings.websocket_path,
        &relay_settings.websocket_path_pool,
    );
    let expected_grpc_paths =
        dedupe_candidates(&relay_settings.grpc_path, &relay_settings.grpc_path_pool);
    let expected_masque_paths = dedupe_candidates(
        &relay_settings.masque_path,
        &relay_settings.masque_path_pool,
    );
    let expected_accept_languages = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| optional_or_none(&item.accept_language_header)),
    );
    let expected_cache_controls = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| optional_or_none(&item.cache_control_header)),
    );
    let expected_websocket_origins = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| resolve_websocket_origin(&relay_settings, item)),
    );
    let expected_grpc_accept_encodings = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| optional_or_none(&item.grpc_accept_encoding_header)),
    );
    let expected_grpc_encodings = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| optional_or_none(&item.grpc_encoding_header)),
    );
    let expected_grpc_timeouts = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| optional_or_none(&item.grpc_timeout_header)),
    );
    let expected_grpc_message_types = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| optional_or_none(&item.grpc_message_type_header)),
    );
    let expected_masque_alt_used = sorted_set(
        relay_surfaces
            .iter()
            .map(|item| resolve_masque_alt_used(&relay_settings, item)),
    );

    let relay_coverage_ok = relay_profile_seen == sorted_vec(relay_ids.clone())
        && same_set(&relay_websocket_seen, &expected_websocket_paths)
        && same_set(&relay_grpc_seen, &expected_grpc_paths)
        && same_set(&relay_masque_seen, &expected_masque_paths)
        && relay_accept_language_seen == expected_accept_languages
        && relay_cache_control_seen == expected_cache_controls
        && relay_websocket_origin_seen == expected_websocket_origins
        && relay_grpc_accept_encoding_seen == expected_grpc_accept_encodings
        && relay_grpc_encoding_seen == expected_grpc_encodings
        && relay_grpc_timeout_seen == expected_grpc_timeouts
        && relay_grpc_message_type_seen == expected_grpc_message_types
        && relay_masque_alt_used_seen == expected_masque_alt_used;

    let relay_counts = count_strings((1..513).map(|idx| {
        relay_profile_signature(
            &relay_settings,
            &relay_surfaces,
            &format!("edge-{idx}.example.org"),
            443,
            now_secs,
        )
        .profile_id
    }));
    let relay_min = *relay_counts.values().min().unwrap_or(&0);
    let relay_max = *relay_counts.values().max().unwrap_or(&0);
    let relay_distribution_ok = relay_counts.len() == relay_ids.len()
        && relay_min >= thresholds["relay_distribution_floor"].as_u64().unwrap() as usize
        && relay_max <= thresholds["relay_distribution_ceiling"].as_u64().unwrap() as usize;

    let mut direct_to_relay: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut relay_to_direct: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for idx in 1..257 {
        let direct_family = direct_profile_family(&direct_ids, "198.51.100.77", idx, now_secs);
        let relay_profile = relay_profile_signature(
            &relay_settings,
            &relay_surfaces,
            &format!("edge-{idx}.example.org"),
            443,
            now_secs,
        )
        .profile_id;
        direct_to_relay
            .entry(direct_family.clone())
            .or_default()
            .insert(relay_profile.clone());
        relay_to_direct
            .entry(relay_profile)
            .or_default()
            .insert(direct_family);
    }
    let direct_to_relay_min = direct_to_relay
        .values()
        .map(BTreeSet::len)
        .min()
        .unwrap_or(0);
    let relay_to_direct_min = relay_to_direct
        .values()
        .map(BTreeSet::len)
        .min()
        .unwrap_or(0);
    let cross_layer_independence_ok = direct_to_relay_min >= 2 && relay_to_direct_min >= 2;

    let checks = json!({
        "direct_window_stability": direct_stability_ok,
        "direct_sampled_variance": direct_variance_ok,
        "direct_catalog_coverage": direct_coverage_ok,
        "direct_distribution_bounds": direct_distribution_ok,
        "relay_window_stability": relay_stability_ok,
        "relay_sampled_variance": relay_variance_ok,
        "relay_catalog_and_path_coverage": relay_coverage_ok,
        "relay_distribution_bounds": relay_distribution_ok,
        "cross_layer_independence": cross_layer_independence_ok,
    });
    let all_green = checks
        .as_object()
        .unwrap()
        .values()
        .all(|value| value == true);
    let verdict = if all_green { "green" } else { "yellow" };
    let status = if all_green {
        "acceptance_green"
    } else {
        "acceptance_degraded"
    };
    let next_action = if all_green {
        "keep_long_run_acceptance_green_while_expanding_telemetry_reduction"
    } else {
        "tighten_polymorphism_distribution_and_independence_before_next_stealth_wave"
    };

    let payload = json!({
        "artifact_schema": "stealth_polymorphism_acceptance_summary_v1",
        "status": status,
        "verdict": verdict,
        "summary_scope": "repo_side_long_run_statistical_acceptance",
        "config_path": config_path.display().to_string(),
        "sample_now_secs": now_secs,
        "thresholds": thresholds,
        "checks": checks,
        "direct": {
            "catalog_ids_expected": direct_ids,
            "catalog_ids_seen": direct_coverage_seen,
            "variance_ids_seen": direct_variance_seen,
            "distribution_counts": map_counts(&direct_counts),
            "distribution_min": direct_min,
            "distribution_max": direct_max,
        },
        "relay": {
            "profile_ids_expected": relay_ids,
            "profile_ids_seen": relay_profile_seen,
            "websocket_paths_expected": expected_websocket_paths,
            "websocket_paths_seen": relay_websocket_seen,
            "grpc_paths_expected": expected_grpc_paths,
            "grpc_paths_seen": relay_grpc_seen,
            "masque_paths_expected": expected_masque_paths,
            "masque_paths_seen": relay_masque_seen,
            "accept_language_variants_expected": expected_accept_languages,
            "accept_language_variants_seen": relay_accept_language_seen,
            "cache_control_variants_expected": expected_cache_controls,
            "cache_control_variants_seen": relay_cache_control_seen,
            "websocket_origin_variants_expected": expected_websocket_origins,
            "websocket_origin_variants_seen": relay_websocket_origin_seen,
            "grpc_accept_encoding_variants_expected": expected_grpc_accept_encodings,
            "grpc_accept_encoding_variants_seen": relay_grpc_accept_encoding_seen,
            "grpc_encoding_variants_expected": expected_grpc_encodings,
            "grpc_encoding_variants_seen": relay_grpc_encoding_seen,
            "grpc_timeout_variants_expected": expected_grpc_timeouts,
            "grpc_timeout_variants_seen": relay_grpc_timeout_seen,
            "grpc_message_type_variants_expected": expected_grpc_message_types,
            "grpc_message_type_variants_seen": relay_grpc_message_type_seen,
            "masque_alt_used_variants_expected": expected_masque_alt_used,
            "masque_alt_used_variants_seen": relay_masque_alt_used_seen,
            "variance_signatures_seen": relay_variance_seen.iter().map(signature_json).collect::<Vec<_>>(),
            "distribution_counts": map_counts(&relay_counts),
            "distribution_min": relay_min,
            "distribution_max": relay_max,
            "drift_epoch_secs": relay_settings.drift_epoch_secs,
        },
        "cross_layer": {
            "direct_to_relay_min_profiles": direct_to_relay_min,
            "relay_to_direct_min_families": relay_to_direct_min,
            "direct_to_relay": set_map_json(&direct_to_relay),
            "relay_to_direct": set_map_json(&relay_to_direct),
        },
        "next_action": next_action,
    });

    write_json(
        &output_dir.join("stealth-polymorphism-acceptance-summary.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("stealth-polymorphism-acceptance-summary.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn extract_catalog_ids(
    path: &Path,
    anchor: &str,
    key: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let start = text
        .find(anchor)
        .ok_or_else(|| format!("missing anchor {anchor} in {}", path.display()))?;
    let end = text[start..]
        .find("];")
        .map(|offset| start + offset)
        .ok_or_else(|| format!("missing catalog end for {anchor} in {}", path.display()))?;
    Ok(scan_quoted_key_values(&text[start..end], key))
}

fn extract_default_path_pool(
    path: &Path,
    fn_name: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let anchor = format!("fn {fn_name}() -> Vec<String>");
    let start = text
        .find(&anchor)
        .ok_or_else(|| format!("missing default function {fn_name} in {}", path.display()))?;
    let body_start = text[start..]
        .find('{')
        .map(|offset| start + offset)
        .ok_or_else(|| format!("missing body for {fn_name} in {}", path.display()))?;
    let body_end = matching_brace_end(&text, body_start)
        .ok_or_else(|| format!("unclosed body for {fn_name} in {}", path.display()))?;
    Ok(scan_into_string_literals(&text[body_start..=body_end]))
}

fn extract_relay_surface_catalog(
    path: &Path,
) -> Result<Vec<RelaySurface>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let start = text
        .find("const RELAY_SURFACE_CATALOG")
        .ok_or_else(|| format!("missing relay surface catalog in {}", path.display()))?;
    let end = text[start..]
        .find("];")
        .map(|offset| start + offset)
        .ok_or_else(|| format!("missing relay surface catalog end in {}", path.display()))?;
    let block = &text[start..end];
    let mut surfaces = Vec::new();
    for raw in block.split("RelaySurfaceProfile {").skip(1) {
        let entry = raw
            .split_once('}')
            .map(|(entry, _)| entry)
            .ok_or("unterminated RelaySurfaceProfile entry")?;
        surfaces.push(RelaySurface {
            id: required_field(entry, "id")?,
            accept_language_header: optional_field(entry, "accept_language_header")?,
            cache_control_header: optional_field(entry, "cache_control_header")?,
            websocket_origin_strategy: optional_field(entry, "websocket_origin_strategy")?,
            grpc_accept_encoding_header: optional_field(entry, "grpc_accept_encoding_header")?,
            grpc_encoding_header: optional_field(entry, "grpc_encoding_header")?,
            grpc_timeout_header: optional_field(entry, "grpc_timeout_header")?,
            grpc_message_type_header: optional_field(entry, "grpc_message_type_header")?,
            masque_alt_used_strategy: optional_field(entry, "masque_alt_used_strategy")?,
        });
    }
    Ok(surfaces)
}

fn required_field(entry: &str, field: &str) -> Result<String, Box<dyn std::error::Error>> {
    scan_quoted_key_values(entry, field)
        .into_iter()
        .next()
        .ok_or_else(|| format!("missing relay surface field {field}").into())
}

fn optional_field(entry: &str, field: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let needle = format!("{field}:");
    let start = entry
        .find(&needle)
        .ok_or_else(|| format!("missing relay surface field {field}"))?
        + needle.len();
    let value = entry[start..].trim_start();
    if value.starts_with("None") {
        return Ok(None);
    }
    if let Some(after_prefix) = value.strip_prefix("Some(\"") {
        if let Some(end) = after_prefix.find("\")") {
            return Ok(Some(after_prefix[..end].to_string()));
        }
    }
    Err(format!("invalid optional relay surface field {field}: {value}").into())
}

fn scan_quoted_key_values(block: &str, key: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = block;
    let needle = format!("{key}:");
    while let Some(pos) = rest.find(&needle) {
        rest = &rest[pos + needle.len()..];
        if let Some(first_quote) = rest.find('"') {
            let after = &rest[first_quote + 1..];
            if let Some(second_quote) = after.find('"') {
                values.push(after[..second_quote].to_string());
                rest = &after[second_quote + 1..];
            } else {
                break;
            }
        } else {
            break;
        }
    }
    values
}

fn scan_into_string_literals(block: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = block;
    while let Some(pos) = rest.find("\"") {
        let after = &rest[pos + 1..];
        let Some(end) = after.find("\"") else {
            break;
        };
        let value = &after[..end];
        if after[end + 1..].trim_start().starts_with(".into()") {
            values.push(value.to_string());
        }
        rest = &after[end + 1..];
    }
    values
}

fn matching_brace_end(text: &str, body_start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in text[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(body_start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn toml_str<'a>(table: Option<&'a toml::Value>, key: &str) -> Option<&'a str> {
    table?.get(key)?.as_str()
}

fn toml_int(table: Option<&toml::Value>, key: &str) -> Option<i64> {
    table?.get(key)?.as_integer()
}

fn toml_string_array(table: Option<&toml::Value>, key: &str) -> Option<Vec<String>> {
    Some(
        table?
            .get(key)?
            .as_array()?
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_string)
            .collect(),
    )
}

fn dedupe_candidates(primary: &str, pool: &[String]) -> Vec<String> {
    let mut candidates = vec![primary.to_string()];
    for item in pool {
        if !item.trim().is_empty() && !candidates.contains(item) {
            candidates.push(item.clone());
        }
    }
    candidates
}

fn origin_authority(server_name: &str) -> String {
    if server_name.contains(':') && !server_name.starts_with('[') {
        format!("[{server_name}]")
    } else {
        server_name.to_string()
    }
}

fn resolve_websocket_origin(settings: &RelaySettings, surface: &RelaySurface) -> String {
    match surface.websocket_origin_strategy.as_deref() {
        Some("same_authority_https") => {
            format!("https://{}", origin_authority(&settings.server_name))
        }
        _ => "<none>".to_string(),
    }
}

fn resolve_masque_alt_used(settings: &RelaySettings, surface: &RelaySurface) -> String {
    match surface.masque_alt_used_strategy.as_deref() {
        Some("same_authority") => settings.server_name.clone(),
        _ => "<none>".to_string(),
    }
}

fn surface_slot(surface: &str) -> u64 {
    match surface {
        "DirectFingerprint" => 4,
        "RelaySession" => 7,
        "RelayWebsocketPath" => 3,
        "RelayGrpcPath" => 6,
        "RelayMasquePath" => 13,
        _ => 0,
    }
}

fn surface_phase_offset(base_epoch_secs: u64, surface: &str) -> u64 {
    if base_epoch_secs <= 1 {
        return 0;
    }
    let offset = (base_epoch_secs * surface_slot(surface)) / PHASE_SLOT_COUNT;
    offset.min(base_epoch_secs - 1)
}

fn surface_epoch(base_epoch_secs: u64, now: u64, surface: &str) -> u64 {
    let base_epoch_secs = base_epoch_secs.max(1);
    (now + surface_phase_offset(base_epoch_secs, surface)) / base_epoch_secs
}

fn sha_seed(parts: &[Vec<u8>]) -> (u64, [u8; 32]) {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut digest_array = [0u8; 32];
    digest_array.copy_from_slice(&digest);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest_array[..8]);
    (u64::from_le_bytes(first), digest_array)
}

fn direct_profile_family(direct_ids: &[String], ip_text: &str, port: u16, now: u64) -> String {
    let epoch = surface_epoch(900, now, "DirectFingerprint");
    let (_, digest) = sha_seed(&[
        b"direct-fingerprint-profile".to_vec(),
        ip_text.as_bytes().to_vec(),
        port.to_le_bytes().to_vec(),
        epoch.to_le_bytes().to_vec(),
    ]);
    direct_ids[digest[0] as usize % direct_ids.len()].clone()
}

fn session_seed(
    settings: &RelaySettings,
    host: &str,
    port: u16,
    label: &str,
    epoch_bucket: u64,
) -> u64 {
    sha_seed(&[
        label.as_bytes().to_vec(),
        epoch_bucket.to_le_bytes().to_vec(),
        settings.server.as_bytes().to_vec(),
        settings.server_name.as_bytes().to_vec(),
        host.as_bytes().to_vec(),
        port.to_le_bytes().to_vec(),
    ])
    .0
}

fn select_path(primary: &str, pool: &[String], seed: u64) -> String {
    let candidates = dedupe_candidates(primary, pool);
    candidates[seed as usize % candidates.len()].clone()
}

fn relay_profile_signature(
    settings: &RelaySettings,
    surfaces: &[RelaySurface],
    host: &str,
    port: u16,
    now: u64,
) -> RelaySignature {
    let base_epoch = settings.drift_epoch_secs;
    let profile_seed = session_seed(
        settings,
        host,
        port,
        "relay-session",
        surface_epoch(base_epoch, now, "RelaySession"),
    );
    let surface = &surfaces[profile_seed as usize % surfaces.len()];
    let websocket_path = select_path(
        &settings.websocket_path,
        &settings.websocket_path_pool,
        session_seed(
            settings,
            host,
            port,
            "relay-ws-path",
            surface_epoch(base_epoch, now, "RelayWebsocketPath"),
        ),
    );
    let grpc_path = select_path(
        &settings.grpc_path,
        &settings.grpc_path_pool,
        session_seed(
            settings,
            host,
            port,
            "relay-grpc-path",
            surface_epoch(base_epoch, now, "RelayGrpcPath"),
        ),
    );
    let masque_path = select_path(
        &settings.masque_path,
        &settings.masque_path_pool,
        session_seed(
            settings,
            host,
            port,
            "relay-masque-path",
            surface_epoch(base_epoch, now, "RelayMasquePath"),
        ),
    );
    RelaySignature {
        profile_id: surface.id.clone(),
        websocket_path,
        grpc_path,
        masque_path,
        accept_language_header: optional_or_none(&surface.accept_language_header),
        cache_control_header: optional_or_none(&surface.cache_control_header),
        websocket_origin_header: resolve_websocket_origin(settings, surface),
        grpc_accept_encoding_header: optional_or_none(&surface.grpc_accept_encoding_header),
        grpc_encoding_header: optional_or_none(&surface.grpc_encoding_header),
        grpc_timeout_header: optional_or_none(&surface.grpc_timeout_header),
        grpc_message_type_header: optional_or_none(&surface.grpc_message_type_header),
        masque_alt_used_header: resolve_masque_alt_used(settings, surface),
    }
}

fn distribution_floor(sample_size: usize, catalog_size: usize) -> usize {
    if catalog_size == 0 {
        return 0;
    }
    let sample_size = sample_size as f64;
    let probability = 1.0 / catalog_size as f64;
    let expected = sample_size * probability;
    let standard_deviation = (sample_size * probability * (1.0 - probability)).sqrt();
    (expected - DISTRIBUTION_SIGMA_LIMIT * standard_deviation)
        .floor()
        .max(0.0) as usize
}

fn distribution_ceiling(sample_size: usize, catalog_size: usize) -> usize {
    if catalog_size == 0 {
        return 0;
    }
    let sample_size = sample_size as f64;
    let probability = 1.0 / catalog_size as f64;
    let expected = sample_size * probability;
    let standard_deviation = (sample_size * probability * (1.0 - probability)).sqrt();
    (expected + DISTRIBUTION_SIGMA_LIMIT * standard_deviation).ceil() as usize
}

fn count_strings<I>(items: I) -> BTreeMap<String, usize>
where
    I: IntoIterator<Item = String>,
{
    let mut counts = BTreeMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    counts
}

fn sorted_set<I>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_vec(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

fn same_set(left: &[String], right: &[String]) -> bool {
    left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
}

fn sorted_signature_set<I>(items: I) -> Vec<RelaySignature>
where
    I: IntoIterator<Item = RelaySignature>,
{
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn optional_or_none(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "<none>".to_string())
}

fn signature_json(item: &RelaySignature) -> Value {
    json!({
        "profile_id": item.profile_id,
        "websocket_path": item.websocket_path,
        "grpc_path": item.grpc_path,
        "masque_path": item.masque_path,
        "accept_language_header": item.accept_language_header,
        "cache_control_header": item.cache_control_header,
        "websocket_origin_header": item.websocket_origin_header,
        "grpc_accept_encoding_header": item.grpc_accept_encoding_header,
        "grpc_encoding_header": item.grpc_encoding_header,
        "grpc_timeout_header": item.grpc_timeout_header,
        "grpc_message_type_header": item.grpc_message_type_header,
        "masque_alt_used_header": item.masque_alt_used_header,
    })
}

fn map_counts(counts: &BTreeMap<String, usize>) -> Value {
    Value::Object(
        counts
            .iter()
            .map(|(key, value)| (key.clone(), json!(value)))
            .collect(),
    )
}

fn set_map_json(map: &BTreeMap<String, BTreeSet<String>>) -> Value {
    Value::Object(
        map.iter()
            .map(|(key, values)| {
                (
                    key.clone(),
                    json!(values.iter().cloned().collect::<Vec<_>>()),
                )
            })
            .collect(),
    )
}

fn render_markdown(payload: &Value) -> String {
    let checks = payload.get("checks").and_then(Value::as_object).unwrap();
    let direct = payload.get("direct").unwrap();
    let relay = payload.get("relay").unwrap();
    let cross_layer = payload.get("cross_layer").unwrap();
    let mut lines = vec![
        "# Stealth Polymorphism Acceptance".to_string(),
        String::new(),
        format!("- Verdict: `{}`", payload["verdict"].as_str().unwrap()),
        format!("- Status: `{}`", payload["status"].as_str().unwrap()),
        format!("- Scope: `{}`", payload["summary_scope"].as_str().unwrap()),
        format!("- Config: `{}`", payload["config_path"].as_str().unwrap()),
        format!("- Sample now_secs: `{}`", payload["sample_now_secs"]),
        format!(
            "- Next action: `{}`",
            payload["next_action"].as_str().unwrap()
        ),
        String::new(),
        "## Checks".to_string(),
        String::new(),
    ];
    for (key, value) in checks {
        lines.push(format!(
            "- `{key}`: `{}`",
            value.as_bool().unwrap_or(false).to_string().to_lowercase()
        ));
    }
    lines.extend([
        String::new(),
        "## Direct".to_string(),
        String::new(),
        format!(
            "- Expected catalog ids: `{}`",
            join_array(&direct["catalog_ids_expected"])
        ),
        format!(
            "- Seen catalog ids: `{}`",
            join_array(&direct["catalog_ids_seen"])
        ),
        format!(
            "- Distribution min/max: `{}` / `{}`",
            direct["distribution_min"], direct["distribution_max"]
        ),
        String::new(),
        "## Relay".to_string(),
        String::new(),
        format!(
            "- Expected profile ids: `{}`",
            join_array(&relay["profile_ids_expected"])
        ),
        format!(
            "- Seen profile ids: `{}`",
            join_array(&relay["profile_ids_seen"])
        ),
        format!(
            "- WebSocket paths: `{}`",
            join_array(&relay["websocket_paths_seen"])
        ),
        format!("- gRPC paths: `{}`", join_array(&relay["grpc_paths_seen"])),
        format!(
            "- MASQUE paths: `{}`",
            join_array(&relay["masque_paths_seen"])
        ),
        format!(
            "- Accept-Language variants: `{}`",
            join_array(&relay["accept_language_variants_seen"])
        ),
        format!(
            "- Cache-Control variants: `{}`",
            join_array(&relay["cache_control_variants_seen"])
        ),
        format!(
            "- WebSocket Origin variants: `{}`",
            join_array(&relay["websocket_origin_variants_seen"])
        ),
        format!(
            "- gRPC accept-encoding variants: `{}`",
            join_array(&relay["grpc_accept_encoding_variants_seen"])
        ),
        format!(
            "- gRPC encoding variants: `{}`",
            join_array(&relay["grpc_encoding_variants_seen"])
        ),
        format!(
            "- gRPC timeout variants: `{}`",
            join_array(&relay["grpc_timeout_variants_seen"])
        ),
        format!(
            "- gRPC message-type variants: `{}`",
            join_array(&relay["grpc_message_type_variants_seen"])
        ),
        format!(
            "- MASQUE Alt-Used variants: `{}`",
            join_array(&relay["masque_alt_used_variants_seen"])
        ),
        format!(
            "- Distribution min/max: `{}` / `{}`",
            relay["distribution_min"], relay["distribution_max"]
        ),
        String::new(),
        "## Cross-Layer".to_string(),
        String::new(),
        format!(
            "- direct->relay min profiles: `{}`",
            cross_layer["direct_to_relay_min_profiles"]
        ),
        format!(
            "- relay->direct min families: `{}`",
            cross_layer["relay_to_direct_min_families"]
        ),
    ]);
    lines.join("\n") + "\n"
}

fn join_array(value: &Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{distribution_ceiling, distribution_floor};

    #[test]
    fn distribution_bounds_scale_with_catalog_size() {
        assert_eq!(distribution_floor(512, 8), 41);
        assert_eq!(distribution_ceiling(512, 8), 87);
        assert_eq!(distribution_floor(512, 18), 12);
        assert_eq!(distribution_ceiling(512, 18), 44);
    }

    #[test]
    fn distribution_bounds_handle_empty_catalog() {
        assert_eq!(distribution_floor(512, 0), 0);
        assert_eq!(distribution_ceiling(512, 0), 0);
    }
}
