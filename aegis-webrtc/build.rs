// The optional native SFU encoder is source-pinned independently of Cargo.lock.
// Default builds never probe a native library.
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_SFU_MEDIA_VP8").is_none() {
        return;
    }
    // env-libvpx-sys otherwise permits an alternate VPX_LIB_DIR path that
    // bypasses pkg-config entirely. Keep one auditable source of native pins.
    for name in ["VPX_LIB_DIR", "VPX_INCLUDE_DIR"] {
        println!("cargo:rerun-if-env-changed={name}");
        assert!(
            std::env::var_os(name).is_none(),
            "SFU media requires pkg-config libvpx"
        );
    }
    println!("cargo:rerun-if-env-changed=VPX_VERSION");
    if let Some(version) = std::env::var_os("VPX_VERSION") {
        assert!(
            version.to_str() == Some("1.17.0"),
            "SFU media requires pinned libvpx 1.17.0"
        );
    }
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");
    let output = Command::new("pkg-config")
        .args(["--modversion", "vpx"])
        .output()
        .expect("SFU media requires pkg-config and pinned libvpx 1.17.0");
    assert!(
        output.status.success() && output.stdout == b"1.17.0\n",
        "SFU media requires pinned libvpx 1.17.0"
    );
}
