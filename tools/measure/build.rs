#[path = "../../scripts/lib/research_build_target.rs"]
mod research_build_target;

fn main() {
    research_build_info();
    validate_embedded_helper_sources();
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        println!("cargo:rustc-link-arg=/STACK:8388608");
    }
}

fn validate_embedded_helper_sources() {
    let builder = include_str!("../../scripts/build-release-bundle.sh").replace("\r\n", "\n");
    let declarations = builder
        .split_once("\nHELPER_SCRIPTS=(\n")
        .expect("builder helper inventory missing")
        .1
        .split_once("\n)")
        .expect("builder helper inventory end missing")
        .0;
    let mut count = 0;
    let mut seen = std::collections::BTreeSet::new();
    for line in declarations.lines() {
        let leaf = line
            .strip_prefix("  \"")
            .and_then(|value| value.strip_suffix('"'))
            .expect("invalid helper declaration");
        let components: Vec<_> = std::path::Path::new(leaf).components().collect();
        assert!(
            !components.is_empty()
                && components
                    .iter()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
                && (leaf.ends_with(".sh")
                    || leaf.ends_with(".py")
                    || leaf == "lib/aegis_auto_ufw_pins.json"),
            "unsafe helper declaration"
        );
        assert!(seen.insert(leaf), "duplicate helper declaration");
        let path = std::path::Path::new("../../scripts").join(leaf);
        let metadata = std::fs::symlink_metadata(&path).expect("missing helper source");
        assert!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && (1..=8_388_608).contains(&metadata.len()),
            "helper source must be a bounded regular file"
        );
        println!("cargo:rerun-if-changed={}", path.display());
        count += 1;
    }
    assert_eq!(count, 55, "helper inventory count changed");
    for terminal in [
        "lib/aegis_auto_terminal_witness.py",
        "lib/aegis_auto_terminal_boot_store.py",
        "lib/aegis_auto_terminal_register.py",
        "lib/aegis_auto_boot_transition.py",
    ] {
        assert!(
            seen.contains(terminal),
            "terminal helper absent from release inventory"
        );
    }
    println!("cargo:rerun-if-changed=../../scripts/build-release-bundle.sh");
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
