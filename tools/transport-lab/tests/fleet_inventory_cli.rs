#![cfg(unix)]
//! Private-file/CLI contract using only synthetic inventory and no network.
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

const INPUT: &str = r#"{
  "artifact_schema":"aegis_fleet_dependency_inventory_v1",
  "dependencies":[{"id":1,"kind":"provider"}],
  "routes":[{"id":1,
    "provider":{"status":"known","dependency_ids":[1]},
    "dns":{"status":"not_required","dependency_ids":[]},
    "bootstrap":{"status":"unknown","dependency_ids":[]}}]
}"#;

fn private_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("inventory.json");
    fs::write(&path, INPUT).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (directory, path)
}

fn cli(path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aegis-transport-lab"))
        .arg("dependencies")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn private_cli_consumes_inventory_without_mutation_and_emits_honest_unknowns() {
    let (_directory, path) = private_fixture();
    let before = fs::read(&path).unwrap();
    let output = cli(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provenance"], "operator_declared_only");
    assert_eq!(
        report["provider_cuts"]["minimal_outage_sets"],
        serde_json::json!([[1]])
    );
    assert_eq!(
        report["bootstrap_cuts"]["status"],
        "unresolved_dependencies"
    );
    assert!(report["bootstrap_cuts"]["minimal_outage_sets"].is_null());
    assert_eq!(report["dependency_independence_verified"], false);
    assert_eq!(report["target_network_measured"], false);
    assert_eq!(report["beta_exit"], false);
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn cli_refuses_public_symlink_special_or_oversize_input_without_echoing_path() {
    use std::os::unix::fs::symlink;
    let (directory, path) = private_fixture();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let public = cli(&path);
    assert!(!public.status.success());
    assert!(public.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&public.stderr).contains(path.to_str().unwrap()));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.path().canonicalize().unwrap().join("linked.json");
    symlink(&path, &linked).unwrap();
    let symlinked = cli(&linked);
    assert!(!symlinked.status.success());
    assert!(symlinked.stdout.is_empty());
    assert!(!cli(&directory.path().canonicalize().unwrap())
        .status
        .success());
    fs::write(
        &path,
        vec![b' '; aegis_transport_lab::fleet_inventory::MAX_INPUT_BYTES + 1],
    )
    .unwrap();
    let oversized = cli(&path);
    assert!(!oversized.status.success());
    assert!(oversized.stdout.is_empty());
}

#[test]
fn cli_refuses_unknown_secret_fields_without_serializing_input_or_errors() {
    let (_directory, path) = private_fixture();
    let marker = "DO_NOT_PRINT_SYNTHETIC_CONFIG_SECRET";
    let mut input: serde_json::Value = serde_json::from_str(INPUT).unwrap();
    input["password"] = serde_json::json!(marker);
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output = cli(&path);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(path.to_str().unwrap()));
}
