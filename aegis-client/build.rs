use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=AEGIS_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=AEGIS_BUILD_TIMESTAMP");
    println!("cargo:rerun-if-env-changed=AEGIS_BUILD_TARGET");
    println!("cargo:rerun-if-env-changed=AEGIS_BUILD_FEATURES");
    println!("cargo:rerun-if-env-changed=AEGIS_CARGO_LOCK_SHA256");
    if let (Ok(git_sha), Ok(build_timestamp)) = (
        std::env::var("AEGIS_BUILD_GIT_SHA"),
        std::env::var("AEGIS_BUILD_TIMESTAMP"),
    ) {
        if !git_sha.trim().is_empty() && !build_timestamp.trim().is_empty() {
            check_directive_value("AEGIS_BUILD_GIT_SHA", &git_sha);
            check_directive_value("AEGIS_BUILD_TIMESTAMP", &build_timestamp);
            println!("cargo:rustc-env=AEGIS_BUILD_GIT_SHA={git_sha}");
            println!("cargo:rustc-env=AEGIS_BUILD_TIMESTAMP={build_timestamp}");
            emit_provenance_metadata();
            return;
        }
    }
    emit_git_inputs();

    let git_sha = std::env::var("AEGIS_BUILD_GIT_SHA")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| git_output(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into()));
    let build_timestamp = std::env::var("AEGIS_BUILD_TIMESTAMP")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            git_output(&["show", "-s", "--format=%cI", "HEAD"]).unwrap_or_else(|| "unknown".into())
        });

    check_directive_value("AEGIS_BUILD_GIT_SHA", &git_sha);
    check_directive_value("AEGIS_BUILD_TIMESTAMP", &build_timestamp);
    println!("cargo:rustc-env=AEGIS_BUILD_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=AEGIS_BUILD_TIMESTAMP={build_timestamp}");
    emit_provenance_metadata();
}

fn emit_provenance_metadata() {
    let target = std::env::var("AEGIS_BUILD_TARGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("TARGET").ok())
        .unwrap_or_else(|| "unknown".into());
    let features = std::env::var("AEGIS_BUILD_FEATURES")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            let mut enabled = Vec::new();
            if std::env::var_os("CARGO_FEATURE_RAW_SOCKET").is_some() {
                enabled.push("raw-socket");
            }
            if std::env::var_os("CARGO_FEATURE_CHROME_LIKE_TLS").is_some() {
                enabled.push("chrome-like-tls");
            }
            if std::env::var_os("CARGO_FEATURE_CHROME_LIKE_QUIC").is_some() {
                enabled.push("chrome-like-quic");
            }
            if enabled.is_empty() {
                "none".into()
            } else {
                enabled.join(",")
            }
        });
    let cargo_lock_sha256 = std::env::var("AEGIS_CARGO_LOCK_SHA256")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".into());
    check_directive_value("AEGIS_BUILD_TARGET", &target);
    check_directive_value("AEGIS_BUILD_FEATURES", &features);
    check_directive_value("AEGIS_CARGO_LOCK_SHA256", &cargo_lock_sha256);
    println!("cargo:rustc-env=AEGIS_BUILD_TARGET={target}");
    println!("cargo:rustc-env=AEGIS_BUILD_FEATURES={features}");
    println!("cargo:rustc-env=AEGIS_CARGO_LOCK_SHA256={cargo_lock_sha256}");
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    Some(value.trim().to_string())
}

// Linked worktrees store .git as an indirection file. Let Git resolve its
// per-worktree HEAD and shared refs; missing rerun paths force Cargo dirty on
// every invocation, even when their intended values did not change.
fn emit_git_inputs() {
    if let Some(top) = git_output(&["rev-parse", "--show-toplevel"]) {
        let marker = std::path::Path::new(&top).join(".git");
        if marker.is_file() {
            watch_existing(&marker);
        }
    }
    if let Some(head) = git_path("HEAD") {
        watch_existing(&head);
    }
    if let Some(reference) = git_output(&["rev-parse", "--symbolic-full-name", "HEAD"]) {
        if reference.starts_with("refs/") {
            if let Some(path) = git_path(&reference) {
                if path.exists() {
                    watch_existing(&path);
                } else {
                    // A packed ref becomes loose on the next commit. Watch an
                    // existing refs ancestor so creation is detected without
                    // emitting the absent ref or scanning source/artifacts.
                    if let Some(parent) = path.ancestors().skip(1).find(|p| p.is_dir()) {
                        watch_existing(parent);
                    }
                }
            }
        }
    }
    if let Some(packed) = git_path("packed-refs") {
        watch_existing(&packed);
    }
}

fn git_path(name: &str) -> Option<std::path::PathBuf> {
    git_output(&["rev-parse", "--git-path", name]).map(std::path::PathBuf::from)
}

fn watch_existing(path: &std::path::Path) {
    if path.exists() {
        let display = path.to_string_lossy();
        check_directive_value("Git metadata path", &display);
        println!("cargo:rerun-if-changed={display}");
    }
}

fn check_directive_value(name: &str, value: &str) {
    assert!(
        !value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)),
        "invalid {name}: build metadata must not contain a directive separator"
    );
}
