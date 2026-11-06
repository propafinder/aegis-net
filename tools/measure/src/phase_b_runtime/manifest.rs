use std::path::Path;

use serde_json::{json, Value};

use crate::phase_a::{ADVERSARIAL_TARGET, WITNESS_TARGET};

use super::support::{ensure, join_strings};

pub struct PhaseBRuntimeEvidenceManifestPaths<'a> {
    pub tls_wire_json: &'a Path,
    pub relay_shape_json: &'a Path,
    pub active_probe_json: &'a Path,
    pub live_evidence_json: &'a Path,
    pub artifact_dir: Option<&'a Path>,
    pub runtime_events_jsonl: Option<&'a Path>,
    pub baseline_json: Option<&'a Path>,
}

pub fn phase_b_runtime_evidence_manifest(
    tls_wire: &Value,
    relay_shape: &Value,
    active_probe: &Value,
    live_evidence: &Value,
    paths: PhaseBRuntimeEvidenceManifestPaths<'_>,
) -> Value {
    let mut reasons = Vec::new();
    if live_evidence["status"].as_str() != Some("LIVE_EVIDENCE_READY") {
        reasons.push("phase-b-live-evidence-not-ready");
    }
    if tls_wire["status"].as_str() != Some("PASS") {
        reasons.push("phase-b-tls-wire-not-pass");
    }
    if relay_shape["status"].as_str() != Some("PASS") {
        reasons.push("phase-b-relay-shape-not-pass");
    }
    if active_probe["status"].as_str() != Some("PASS") {
        reasons.push("phase-b-active-probe-not-pass");
    }

    json!({
        "event": "phase_b_runtime_evidence_manifest",
        "schema_version": 1,
        "status": if reasons.is_empty() { "BUNDLE_READY" } else { "BUNDLE_BLOCKED" },
        "acceptance_degraded": !reasons.is_empty(),
        "reasons": reasons,
        "artifact_dir": paths.artifact_dir.map(path_string),
        "source_artifacts": {
            "baseline_json": paths.baseline_json.map(path_string),
            "runtime_events_jsonl": paths.runtime_events_jsonl.map(path_string),
        },
        "review_artifacts": {
            "tls_wire_json": path_string(paths.tls_wire_json),
            "relay_shape_json": path_string(paths.relay_shape_json),
            "active_probe_json": path_string(paths.active_probe_json),
            "live_evidence_json": path_string(paths.live_evidence_json),
        },
        "reviews": {
            "tls_wire": {
                "status": tls_wire["status"].clone(),
                "checked_events": tls_wire["checked_events"].clone(),
            },
            "relay_shape": {
                "status": relay_shape["status"].clone(),
                "checked_events": relay_shape["checked_events"].clone(),
                "require_diversity": relay_shape["require_diversity"].clone(),
            },
            "active_probe": {
                "status": active_probe["status"].clone(),
                "counts": active_probe["counts"].clone(),
            },
            "live_evidence": {
                "status": live_evidence["status"].clone(),
                "acceptance_degraded": live_evidence["acceptance_degraded"].clone(),
            },
        },
    })
}

pub fn phase_b_runtime_evidence_manifest_markdown(manifest: &Value) -> String {
    format!(
        "# Phase B Runtime Evidence Manifest\n\n\
         - Status: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Reasons: `{}`\n\
         - TLS wire: `{}` events={}\n\
         - Relay shape: `{}` events={}\n\
         - Active probe: `{}` finished={}\n\
         - Live evidence: `{}`\n",
        manifest["status"].as_str().unwrap_or("UNKNOWN"),
        manifest["acceptance_degraded"].as_bool().unwrap_or(false),
        join_strings(&manifest["reasons"]),
        manifest["reviews"]["tls_wire"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        manifest["reviews"]["tls_wire"]["checked_events"]
            .as_u64()
            .unwrap_or(0),
        manifest["reviews"]["relay_shape"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        manifest["reviews"]["relay_shape"]["checked_events"]
            .as_u64()
            .unwrap_or(0),
        manifest["reviews"]["active_probe"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        manifest["reviews"]["active_probe"]["counts"]["finished"]
            .as_u64()
            .unwrap_or(0),
        manifest["reviews"]["live_evidence"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
    )
}

pub fn phase_b_runtime_evidence_manifest_check(
    manifest: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        manifest["event"].as_str() == Some("phase_b_runtime_evidence_manifest"),
        "manifest event",
    )?;
    ensure(
        manifest["schema_version"].as_u64() == Some(1),
        "manifest schema_version",
    )?;
    ensure(
        manifest["status"].as_str() == Some("BUNDLE_READY"),
        "manifest status",
    )?;
    ensure(
        manifest["acceptance_degraded"].as_bool() == Some(false),
        "manifest acceptance_degraded",
    )?;
    ensure(
        manifest["reviews"]["tls_wire"]["status"].as_str() == Some("PASS"),
        "manifest tls wire status",
    )?;
    ensure(
        manifest["reviews"]["relay_shape"]["status"].as_str() == Some("PASS"),
        "manifest relay shape status",
    )?;
    ensure(
        manifest["reviews"]["active_probe"]["status"].as_str() == Some("PASS"),
        "manifest active probe status",
    )?;
    ensure(
        manifest["reviews"]["live_evidence"]["status"].as_str() == Some("LIVE_EVIDENCE_READY"),
        "manifest live evidence status",
    )?;
    for key in [
        "tls_wire_json",
        "relay_shape_json",
        "active_probe_json",
        "live_evidence_json",
    ] {
        let Some(path) = manifest["review_artifacts"][key].as_str() else {
            return Err(format!("contract assertion failed: missing review artifact {key}").into());
        };
        ensure(
            Path::new(path).is_file(),
            &format!("review artifact exists: {key}"),
        )?;
    }
    Ok(())
}

pub fn phase_b_master_plan_status(baseline: &Value, manifest: &Value) -> Value {
    let baseline_ready = baseline["status"].as_str() == Some("BASELINE_READY");
    let runtime_ready = manifest["status"].as_str() == Some("BUNDLE_READY");
    let mimicry_runtime_surface_ready = manifest["reviews"]["tls_wire"]["status"].as_str()
        == Some("PASS")
        && manifest["reviews"]["relay_shape"]["status"].as_str() == Some("PASS");
    let active_probe_evidence_ready =
        manifest["reviews"]["active_probe"]["status"].as_str() == Some("PASS");

    let mut reasons = Vec::new();
    if !baseline_ready {
        reasons.push("phase-b-baseline-not-ready");
    }
    if !runtime_ready {
        reasons.push("phase-b-runtime-evidence-not-ready");
    }
    if !mimicry_runtime_surface_ready {
        reasons.push("phase-b-mimicry-runtime-surface-not-ready");
    }
    if !active_probe_evidence_ready {
        reasons.push("phase-b-active-probe-evidence-not-ready");
    }

    json!({
        "event": "phase_b_master_plan_status",
        "schema_version": 1,
        "status": if reasons.is_empty() {
            "PHASE_B_RUNTIME_EVIDENCE_READY"
        } else {
            "PHASE_B_RUNTIME_EVIDENCE_BLOCKED"
        },
        "phase_b_exit_status": "EXIT_NOT_CLAIMED",
        "acceptance_degraded": !reasons.is_empty(),
        "reasons": reasons,
        "master_plan_alignment": {
            "mimicry_profiles": {
                "runtime_surface_status": if mimicry_runtime_surface_ready { "PASS" } else { "BLOCKED" },
                "score_target_status": "TRACKED_BY_BASELINE_AND_LIVE_WITNESS",
            },
            "anti_active_probing": {
                "runtime_evidence_status": if active_probe_evidence_ready { "PASS" } else { "BLOCKED" },
                "combined_testbed_score_status": "NOT_CLAIMED_IN_RUNTIME_BUNDLE",
            },
            "cross_platform_observation_parity": {
                "status": "NOT_CLAIMED_IN_RUNTIME_BUNDLE",
            },
            "phase_b_exit": {
                "status": "NOT_CLAIMED",
                "required_witness_combined_min": WITNESS_TARGET,
                "required_adversarial_pass_rate_min": ADVERSARIAL_TARGET,
            },
        },
        "baseline": {
            "status": baseline["status"].clone(),
            "witness": baseline["witness"].clone(),
            "adversarial": baseline["adversarial"].clone(),
        },
        "runtime_manifest": {
            "status": manifest["status"].clone(),
            "reviews": manifest["reviews"].clone(),
        },
    })
}

pub fn phase_b_master_plan_status_markdown(status: &Value) -> String {
    format!(
        "# Phase B Master Plan Status\n\n\
         - Status: `{}`\n\
         - Phase B exit: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Reasons: `{}`\n\
         - Mimicry runtime surface: `{}`\n\
         - Active probe runtime evidence: `{}`\n\
         - Cross-platform parity: `{}`\n",
        status["status"].as_str().unwrap_or("UNKNOWN"),
        status["phase_b_exit_status"].as_str().unwrap_or("UNKNOWN"),
        status["acceptance_degraded"].as_bool().unwrap_or(false),
        join_strings(&status["reasons"]),
        status["master_plan_alignment"]["mimicry_profiles"]["runtime_surface_status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        status["master_plan_alignment"]["anti_active_probing"]["runtime_evidence_status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        status["master_plan_alignment"]["cross_platform_observation_parity"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
    )
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
