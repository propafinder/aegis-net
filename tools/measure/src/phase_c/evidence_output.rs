use serde_json::Value;

use super::support::join_strings;

pub fn phase_c_bundle_mirrors_evidence_markdown(evidence: &Value) -> String {
    format!(
        "# Phase C Bundle Mirrors Evidence\n\n\
         - Status: `{}`\n\
         - Blockers: `{}`\n\
         - Primary bundle host block survives: `{}`\n\
         - Voucher expiry/revoke pass: `{}`\n\
         - Signed bundle verification preserved: `{}`\n\
         - Operator mirror setup documented: `{}`\n",
        evidence["status"].as_str().unwrap_or("UNKNOWN"),
        join_strings(&evidence["blockers"]),
        evidence["primary_bundle_host_block_survives"]
            .as_bool()
            .unwrap_or(false),
        evidence["voucher_expiry_revoke_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["signed_bundle_verification_preserved"]
            .as_bool()
            .unwrap_or(false),
        evidence["operator_mirror_setup_documented"]
            .as_bool()
            .unwrap_or(false),
    )
}

pub fn phase_c_multi_relay_evidence_markdown(evidence: &Value) -> String {
    format!(
        "# Phase C Multi-Relay Evidence\n\n\
         - Status: `{}`\n\
         - Blockers: `{}`\n\
         - Primary block recovery median seconds: `{}`\n\
         - Mid-session primary block survived: `{}`\n\
         - Single-relay backward compatible: `{}`\n\
         - Observed relay servers: `{}`\n",
        evidence["status"].as_str().unwrap_or("UNKNOWN"),
        join_strings(&evidence["blockers"]),
        evidence["primary_block_recovery_median_secs"],
        evidence["mid_session_primary_block_survived"]
            .as_bool()
            .unwrap_or(false),
        evidence["single_relay_backward_compatible"]
            .as_bool()
            .unwrap_or(false),
        evidence["observed_relay_servers"],
    )
}
