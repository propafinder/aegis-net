//! Minimal Rust-owned Android JNI proof surface.
//!
//! This crate intentionally avoids external JNI bindings while Phase D is still
//! a proof track. The exported symbols use the JNI C ABI names Android will
//! resolve from Kotlin/Java, and the pure Rust helpers keep the contract
//! testable on non-Android hosts.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::ptr;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[repr(C)]
pub struct JniEnvOpaque {
    _private: [u8; 0],
}

#[repr(C)]
pub struct JObjectOpaque {
    _private: [u8; 0],
}

type JNIEnv = *mut JniEnvOpaque;
type JObject = *mut JObjectOpaque;
type JString = *mut c_void;
type JInt = c_int;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidReachStatus {
    pub rust_jni_core_available: bool,
    pub vpnservice_flow_available: bool,
    pub production_claim: bool,
}

impl AndroidReachStatus {
    pub fn poc_without_vpn_flow() -> Self {
        Self {
            rust_jni_core_available: true,
            vpnservice_flow_available: false,
            production_claim: false,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({
            "rust_jni_core_compiles": self.rust_jni_core_available,
            "vpnservice_basic_flow_proven": self.vpnservice_flow_available,
            "production_android_claimed": self.production_claim,
            "android_jni_version": VERSION,
        })
        .to_string()
    }
}

pub fn android_reach_status_json() -> String {
    AndroidReachStatus::poc_without_vpn_flow().to_json()
}

#[no_mangle]
pub extern "C" fn Java_org_aegis_android_AegisNative_nativeVersion(
    _env: JNIEnv,
    _class: JObject,
) -> JString {
    // The no-binding PoC cannot allocate a Java string without calling through
    // JNIEnv. Returning null keeps the symbol loadable while the Kotlin bridge
    // remains a Phase D follow-up.
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_org_aegis_android_AegisNative_nativeReachStatus(
    _env: JNIEnv,
    _class: JObject,
) -> JString {
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_org_aegis_android_AegisNative_nativeVpnServiceFlowReady(
    _env: JNIEnv,
    _class: JObject,
) -> JInt {
    0
}

#[no_mangle]
pub extern "C" fn aegis_android_reach_status_json_ptr() -> *const c_char {
    static STATUS: &[u8] = b"{\"rust_jni_core_compiles\":true,\"vpnservice_basic_flow_proven\":false,\"production_android_claimed\":false}\0";
    STATUS.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_reach_status_is_poc_not_production() {
        let status = AndroidReachStatus::poc_without_vpn_flow();
        assert!(status.rust_jni_core_available);
        assert!(!status.vpnservice_flow_available);
        assert!(!status.production_claim);
    }

    #[test]
    fn android_reach_status_json_matches_phase_d_gate_fields() {
        let value: serde_json::Value =
            serde_json::from_str(&android_reach_status_json()).expect("json");
        assert_eq!(value["rust_jni_core_compiles"], true);
        assert_eq!(value["vpnservice_basic_flow_proven"], false);
        assert_eq!(value["production_android_claimed"], false);
    }
}
