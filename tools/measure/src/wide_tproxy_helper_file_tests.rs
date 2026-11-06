use super::write_tproxy_smoke_contract_artifact;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const SENTINEL: &[u8] = b"synthetic sentinel: do not overwrite\n";

struct Fixture {
    directory: tempfile::TempDir,
    helper_log: PathBuf,
    events: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let helper_log = directory.path().join("helper.log");
        let events = directory.path().join("events.jsonl");
        std::fs::write(
            &helper_log,
            "firewall_backend=nft\nwide_udp_capture_support_tier=supported_preview\nwide_udp_capture_policy=allowlist_ports\nwide_udp_capture_runtime_scope=linux_ipv4_only\n",
        )
        .unwrap();
        std::fs::write(
            &events,
            "{\"event_code\":\"direct_session_succeeded\",\"fields\":{\"target\":\"fixture.invalid\",\"port\":443}}\n",
        )
        .unwrap();
        Self {
            directory,
            helper_log,
            events,
        }
    }

    fn output(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn write(&self, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
        write_tproxy_smoke_contract_artifact(
            &self.helper_log,
            &self.events,
            output,
            "http",
            "ipv4",
            "fixture",
            "nft",
            "preview_allowlist_only",
        )
    }

    fn sentinel(&self) -> PathBuf {
        let target = self.output("sentinel");
        std::fs::write(&target, SENTINEL).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        target
    }
}

#[test]
fn actual_smoke_writer_preserves_symlink_sentinel_content_and_mode() {
    let fixture = Fixture::new();
    let target = fixture.sentinel();
    let output = fixture.output("contract.json");
    symlink(&target, &output).unwrap();
    let outcome = fixture.write(&output);
    let bytes = std::fs::read(&target).unwrap();
    let mode = std::fs::metadata(&target).unwrap().mode() & 0o777;
    eprintln!(
        "actual_writer_fixture result_ok={} sentinel_preserved={} target_mode={mode:o}",
        outcome.is_ok(),
        bytes == SENTINEL
    );
    assert_eq!(bytes, SENTINEL, "actual writer modified a symlink target");
    assert_eq!(mode, 0o600, "actual writer changed a symlink target's mode");
    assert!(outcome.is_err(), "smoke output symlink must be refused");
    assert!(std::fs::symlink_metadata(output)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn actual_smoke_writer_creates_read_shared_regular_json_and_updates_it() {
    let fixture = Fixture::new();
    let output = fixture.output("contract.json");
    fixture.write(&output).unwrap();
    let first = std::fs::read(&output).unwrap();
    assert_eq!(first.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["smoke_class"], "http_tcp");
    assert_eq!(value["firewall_backend_effective"], "nft");
    assert_eq!(value["runtime_health_status"], "healthy");
    assert_eq!(value["runtime_target_port"], 443);
    let before = std::fs::metadata(&output).unwrap();
    assert!(before.is_file());
    assert_eq!(before.nlink(), 1);
    assert_eq!(before.mode() & 0o777, 0o644);
    std::fs::write(
        &fixture.events,
        "{\"event_code\":\"direct_session_succeeded\",\"fields\":{\"target\":\"fixture.invalid\",\"port\":8443}}\n",
    )
    .unwrap();
    fixture.write(&output).unwrap();
    let updated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(updated["runtime_target_port"], 8443);
    let after = std::fs::metadata(&output).unwrap();
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.mode() & 0o777, 0o644);
}

#[test]
fn actual_smoke_writer_refuses_hardlink_without_mutating_sentinel() {
    let fixture = Fixture::new();
    let target = fixture.sentinel();
    let output = fixture.output("contract.json");
    std::fs::hard_link(&target, &output).unwrap();
    assert!(fixture.write(&output).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), SENTINEL);
    assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn actual_smoke_writer_refuses_writable_output_without_chmod_or_deletion() {
    let fixture = Fixture::new();
    let output = fixture.sentinel();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o666)).unwrap();
    let before = std::fs::metadata(&output).unwrap();
    assert!(fixture.write(&output).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), SENTINEL);
    let after = std::fs::metadata(&output).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.mode() & 0o777, 0o666);
}

#[test]
fn actual_smoke_writer_refuses_writable_parent_and_missing_parent() {
    let fixture = Fixture::new();
    let output = fixture.output("contract.json");
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(fixture.write(&output).is_err());
    assert!(!output.exists());
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let output = fixture.output("missing/contract.json");
    assert!(fixture.write(&output).is_err());
    assert!(!output.parent().unwrap().exists());
}

#[test]
fn actual_smoke_writer_refuses_dangling_symlink_and_directory() {
    let fixture = Fixture::new();
    let target = fixture.output("absent-target");
    let output = fixture.output("contract.json");
    symlink(&target, &output).unwrap();
    assert!(fixture.write(&output).is_err());
    assert!(!target.exists());
    assert!(std::fs::symlink_metadata(&output)
        .unwrap()
        .file_type()
        .is_symlink());
    let directory = fixture.output("directory-output");
    std::fs::create_dir(&directory).unwrap();
    assert!(fixture.write(&directory).is_err());
    assert!(directory.is_dir());
}
