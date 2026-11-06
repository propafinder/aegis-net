use std::{path::Path, process::Command as ProcessCommand};

use serde_json::{json, Value};

use super::{phase_d_bool, read_optional_result, result_has_pass};

pub struct PhaseDAndroidReachEvidenceInputs<'a> {
    pub vpnservice_flow_json: Option<&'a Path>,
    pub production_claim: bool,
}

pub fn phase_d_android_reach_evidence(inputs: PhaseDAndroidReachEvidenceInputs<'_>) -> Value {
    let cargo_check_status = run_phase_d_android_cargo(["check", "-p", "aegis-android-jni"]);
    let cargo_test_status = run_phase_d_android_cargo(["test", "-p", "aegis-android-jni"]);
    let rust_jni_core_compiles = cargo_check_status == "PASS" && cargo_test_status == "PASS";
    let vpnservice_basic_flow_proven =
        optional_android_vpnservice_flow(inputs.vpnservice_flow_json);

    json!({
        "rust_jni_core_compiles": rust_jni_core_compiles,
        "vpnservice_basic_flow_proven": vpnservice_basic_flow_proven,
        "production_android_claimed": inputs.production_claim,
        "checks": {
            "cargo_check_aegis_android_jni": cargo_check_status,
            "cargo_test_aegis_android_jni": cargo_test_status,
        },
        "artifacts": {
            "vpnservice_flow_json": inputs.vpnservice_flow_json,
        },
    })
}

pub(super) fn phase_d_android_reach_review(evidence: Option<&Value>) -> Value {
    let Some(evidence) = evidence else {
        return json!({
            "status": "MISSING",
            "prep_ready": false,
            "exit_ready": false,
            "overstated_claim_detected": false,
            "blockers": ["android_reach_evidence_missing"],
        });
    };
    let rust_jni = phase_d_bool(evidence, "rust_jni_core_compiles");
    let vpn_flow = phase_d_bool(evidence, "vpnservice_basic_flow_proven");
    let production_claim = phase_d_bool(evidence, "production_android_claimed");
    let prep_ready = rust_jni && !production_claim;
    let exit_ready = prep_ready && vpn_flow;
    let mut blockers = Vec::new();
    if !rust_jni {
        blockers.push("rust_jni_core_compile_not_proven");
    }
    if !vpn_flow {
        blockers.push("vpnservice_basic_flow_not_proven");
    }
    if production_claim {
        blockers.push("production_android_overclaim_detected");
    }
    json!({
        "status": if exit_ready { "PASS" } else if prep_ready { "PREP" } else { "FAIL" },
        "prep_ready": prep_ready,
        "exit_ready": exit_ready,
        "overstated_claim_detected": production_claim,
        "blockers": blockers,
    })
}

pub(super) fn optional_android_vpnservice_flow(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        result_has_pass(&value)
            && value["feature"].as_str() == Some("android_vpnservice_basic_flow")
            && value["platform"].as_str() == Some("Android")
            && value["scope"].as_str() == Some("vpnservice_poc")
            && value["vpnservice_basic_flow_proven"].as_bool() == Some(true)
            && value["tun_packet_flow_observed"].as_bool() == Some(true)
            && value["relay_session_succeeded"].as_bool() == Some(true)
            && value["production_android_claimed"].as_bool() != Some(true)
            && value["production_claim"].as_str() != Some("claimed")
    })
}

fn run_phase_d_android_cargo<const N: usize>(args: [&str; N]) -> &'static str {
    let Ok(status) = ProcessCommand::new("cargo").args(args).status() else {
        return "FAIL";
    };
    if status.success() {
        "PASS"
    } else {
        "FAIL"
    }
}
