#[path = "../../scripts/lib/research_build_target.rs"]
mod research_build_target;

fn main() {
    research_build_info();
}

fn research_build_info() {
    println!("cargo:rerun-if-changed=../../scripts/lib/research_build_target.rs");
    for (input, output) in [
        ("AEGIS_BUILD_GIT_SHA", "AEGIS_RESEARCH_SOURCE_COMMIT"),
        ("AEGIS_CARGO_LOCK_SHA256", "AEGIS_RESEARCH_LOCK_SHA256"),
        ("AEGIS_BUILD_FEATURES", "AEGIS_RESEARCH_FEATURES"),
    ] {
        println!("cargo:rerun-if-env-changed={input}");
        let value = std::env::var(input).unwrap_or_else(|_| "unknown".into());
        assert!(
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b','),
            "research build directive refused"
        );
        println!("cargo:rustc-env={output}={value}");
    }
    let target = std::env::var("TARGET").expect("Cargo target");
    assert!(
        research_build_target::safe_cargo_target(&target),
        "research target refused"
    );
    println!("cargo:rustc-env=AEGIS_RESEARCH_TARGET={target}");
    let output = std::process::Command::new(std::env::var_os("RUSTC").expect("Cargo rustc"))
        .arg("--version")
        .output()
        .expect("rustc version");
    assert!(
        output.status.success() && output.stdout.len() <= 512,
        "rustc version refused"
    );
    let version = std::str::from_utf8(&output.stdout)
        .expect("rustc version UTF8")
        .trim();
    assert!(
        version.starts_with("rustc ") && version.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
        "rustc version directive refused"
    );
    println!("cargo:rustc-env=AEGIS_RESEARCH_RUSTC={version}");
}
