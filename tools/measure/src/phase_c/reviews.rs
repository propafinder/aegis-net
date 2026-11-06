use serde_json::{json, Value};

pub(super) fn phase_c_multi_relay_review(evidence: Option<&Value>) -> Value {
    let Some(evidence) = evidence else {
        return phase_c_missing_review("multi_relay_pool_evidence_missing");
    };
    let status_pass = evidence["status"].as_str() == Some("PASS");
    let recovery = evidence["primary_block_recovery_median_secs"]
        .as_f64()
        .unwrap_or(f64::INFINITY);
    let mid_session_survival =
        evidence["mid_session_primary_block_survived"].as_bool() == Some(true);
    let single_relay_compatible =
        evidence["single_relay_backward_compatible"].as_bool() == Some(true);
    let observed_relay_servers = evidence["observed_relay_servers"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let mut blockers = Vec::new();
    if !status_pass {
        blockers.push("status_not_pass");
    }
    if observed_relay_servers < 2 {
        blockers.push("fewer_than_two_relay_endpoints_observed");
    }
    if recovery >= 30.0 {
        blockers.push("primary_block_recovery_median_not_below_30s");
    }
    if !mid_session_survival {
        blockers.push("mid_session_primary_block_survival_missing");
    }
    if !single_relay_compatible {
        blockers.push("single_relay_backward_compatibility_missing");
    }
    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "primary_block_recovery_median_secs": evidence["primary_block_recovery_median_secs"].clone(),
        "mid_session_primary_block_survived": mid_session_survival,
        "single_relay_backward_compatible": single_relay_compatible,
        "observed_relay_servers": evidence["observed_relay_servers"].clone(),
    })
}

pub(super) fn phase_c_bundle_mirrors_review(evidence: Option<&Value>) -> Value {
    let Some(evidence) = evidence else {
        return phase_c_missing_review("bundle_mirrors_voucher_evidence_missing");
    };
    let status_pass = evidence["status"].as_str() == Some("PASS");
    let primary_block_survives =
        evidence["primary_bundle_host_block_survives"].as_bool() == Some(true);
    let voucher = evidence["voucher_expiry_revoke_pass"].as_bool() == Some(true);
    let signed = evidence["signed_bundle_verification_preserved"].as_bool() == Some(true);
    let documented = evidence["operator_mirror_setup_documented"].as_bool() == Some(true);
    let mut blockers = Vec::new();
    if !status_pass {
        blockers.push("status_not_pass");
    }
    if !primary_block_survives {
        blockers.push("primary_bundle_host_block_survival_missing");
    }
    if !voucher {
        blockers.push("voucher_expiry_revoke_not_pass");
    }
    if !signed {
        blockers.push("signed_bundle_verification_not_preserved");
    }
    if !documented {
        blockers.push("operator_mirror_setup_not_documented");
    }
    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "primary_bundle_host_block_survives": primary_block_survives,
        "voucher_expiry_revoke_pass": voucher,
        "signed_bundle_verification_preserved": signed,
        "operator_mirror_setup_documented": documented,
    })
}

pub(super) fn phase_c_fronted_transport_review(evidence: Option<&Value>) -> Value {
    let Some(evidence) = evidence else {
        return phase_c_missing_review("cdn_fronted_transport_evidence_missing");
    };
    let status_pass = evidence["status"].as_str() == Some("PASS");
    let pass_rate = evidence["fronted_masque_pass_rate"].as_f64().unwrap_or(0.0);
    let provider_documented =
        evidence["operator_provider_constraints_documented"].as_bool() == Some(true);
    let scenario_coverage = evidence["adversarial_scenario_coverage"].as_bool() == Some(true);
    let provider_boundary = evidence["provider_boundary_evidence"].as_bool() == Some(true);
    let mut blockers = Vec::new();
    if !status_pass {
        blockers.push("status_not_pass");
    }
    if pass_rate < 0.95 {
        blockers.push("fronted_masque_pass_rate_below_0_95");
    }
    if !provider_documented {
        blockers.push("operator_provider_constraints_not_documented");
    }
    if !scenario_coverage {
        blockers.push("adversarial_scenario_coverage_missing");
    }
    if !provider_boundary {
        blockers.push("provider_boundary_evidence_missing");
    }
    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "fronted_masque_pass_rate": pass_rate,
        "operator_provider_constraints_documented": provider_documented,
        "adversarial_scenario_coverage": scenario_coverage,
        "provider_boundary_evidence": provider_boundary,
    })
}

fn phase_c_missing_review(blocker: &str) -> Value {
    json!({
        "status": "MISSING",
        "blockers": [blocker],
    })
}
