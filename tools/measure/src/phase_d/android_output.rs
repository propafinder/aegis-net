use serde_json::Value;

pub fn phase_d_android_reach_evidence_markdown(evidence: &Value) -> String {
    format!(
        "# Phase D Android Reach Evidence\n\n\
         - Rust JNI core compiles: `{}`\n\
         - VpnService basic flow proven: `{}`\n\
         - Production Android claimed: `{}`\n\
         - cargo check: `{}`\n\
         - cargo test: `{}`\n",
        evidence["rust_jni_core_compiles"]
            .as_bool()
            .unwrap_or(false),
        evidence["vpnservice_basic_flow_proven"]
            .as_bool()
            .unwrap_or(false),
        evidence["production_android_claimed"]
            .as_bool()
            .unwrap_or(false),
        evidence["checks"]["cargo_check_aegis_android_jni"]
            .as_str()
            .unwrap_or("FAIL"),
        evidence["checks"]["cargo_test_aegis_android_jni"]
            .as_str()
            .unwrap_or("FAIL"),
    )
}
