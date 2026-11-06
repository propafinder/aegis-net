//! Genuine producer + protected StageGuard + actual before-custody dispatcher.
//! Nested under backend::actual_backend_integration_tests to reuse its actual
//! product prepare/seal helper. No mocked Header, Context, process, service or
//! network admission. These tests do not advance active custody.
use super::*;
use crate::profile_auto_transaction::receipt_store::{self, PrepareInputs};
use sha2::{Digest, Sha256};

fn payload(wrong_sha: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let tmp = tempfile::Builder::new()
        .prefix("aegis-receipt-admission-")
        .tempdir_in("/root")
        .unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = bin.join("aegis-client");
    let bytes = b"synthetic-file-data-never-executed";
    private_write(&binary, bytes);
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = if wrong_sha {
        "0".repeat(64)
    } else {
        format!("{:x}", Sha256::digest(bytes))
    };
    private_write(&tmp.path().join("bundle.manifest.json"),&serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_client_release_bundle_manifest_v2","version":"synthetic-public-source",
        "git_sha":"unknown","platform":"linux","arch":"x86_64","binaries":{"aegis-client":{"path":"bin/aegis-client","sha256":digest}}
    })).unwrap());
    let installed = tmp.path().join("install-bin").join("aegis-client");
    (tmp, binary, installed)
}
fn admit(stage: &Path, public: &Path, binary: &Path, installed: &Path) -> Result<()> {
    let mut guard = StageGuard::admit(Store::reopen(stage, 0)?)?;
    receipt_store::admit_prepare(
        &mut guard,
        PrepareInputs {
            public_payload_root: public,
            candidate_binary: binary,
            installed_binary: installed,
            source_manifest_url: None,
            source_release_channel: None,
        },
    )
}
fn before_custody(stage: &Path) -> Result<Option<String>> {
    command(CommandArgs::Verify {
        stage: stage.into(),
        phase: VerifyPhase::BeforeCustody,
    })
}
#[test]
#[ignore = "disposable root Linux actual product prepare prerequisites; no service or routing operations"]
fn actual_receipt_wrong_public_candidate_digest_refuses_before_private_admission_or_custody() {
    let (_config_tmp, stage, config) = actual_prepared(AutoMode::FullWideTun);
    let original = fs::read(config.join("aegis.toml")).unwrap();
    let (public, binary, installed) = payload(true);
    assert!(admit(&stage, public.path(), &binary, &installed).is_err());
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(guard.header.phase == Phase::Prepared);
    assert!(!guard
        .header
        .leaves
        .contains_key(Path::new("input/install-receipt/inputs.json")));
    assert!(guard.header.active_records.is_empty());
    assert_eq!(fs::read(config.join("aegis.toml")).unwrap(), original);
}
#[test]
#[ignore = "disposable root Linux actual product prepare prerequisites; no service or routing operations"]
fn actual_receipt_public_manifest_replacement_refuses_actual_before_custody_dispatch() {
    let (_config_tmp, stage, config) = actual_prepared(AutoMode::FullWideTun);
    let original = fs::read(config.join("aegis.toml")).unwrap();
    let (public, binary, installed) = payload(false);
    admit(&stage, public.path(), &binary, &installed).unwrap();
    before_custody(&stage).unwrap();
    let path = public.path().join("bundle.manifest.json");
    let bytes = fs::read(&path).unwrap();
    let replacement = public.path().join("new-manifest");
    private_write(&replacement, &bytes);
    fs::rename(replacement, path).unwrap();
    assert!(before_custody(&stage).is_err());
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(guard.header.phase == Phase::Prepared);
    assert!(guard.header.active_records.is_empty());
    assert_eq!(fs::read(config.join("aegis.toml")).unwrap(), original);
}
#[test]
#[ignore = "disposable root Linux actual product prepare prerequisites; no service or routing operations"]
fn actual_receipt_candidate_same_bytes_replacement_refuses_actual_before_custody_dispatch() {
    let (_config_tmp, stage, config) = actual_prepared(AutoMode::FullWideTun);
    let original = fs::read(config.join("aegis.toml")).unwrap();
    let (public, binary, installed) = payload(false);
    admit(&stage, public.path(), &binary, &installed).unwrap();
    before_custody(&stage).unwrap();
    let bytes = fs::read(&binary).unwrap();
    let replacement = public.path().join("new-binary");
    private_write(&replacement, &bytes);
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(replacement, &binary).unwrap();
    assert!(before_custody(&stage).is_err());
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(guard.header.phase == Phase::Prepared);
    assert!(guard.header.active_records.is_empty());
    assert_eq!(fs::read(config.join("aegis.toml")).unwrap(), original);
}
