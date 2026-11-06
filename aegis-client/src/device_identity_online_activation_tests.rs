//! Synthetic PKI proof through the actual installer activation identity gate.
//! This ignored environment-bound test forwards identity commands to an already
//! built CLI and stops before privileged metadata, services or network actions.
use super::*;
use std::{os::unix::fs::MetadataExt, process::Command};

fn full_wide_bundle(fixture: &Fixture) -> PathBuf {
    let bundle = fixture.public_bundle();
    let path = bundle.join("bundle.json");
    let mut profile: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    profile["product_mode"] = "full-wide-tun".into();
    profile["relay_server"] = "198.51.100.4:443".into();
    profile["udp"] = true.into();
    profile["enrollment"]["authority_server"] = "198.51.100.5:443".into();
    fs::write(path, serde_json::to_vec(&profile).unwrap()).unwrap();
    // Fixture-only first enrollment: establish the exact public profile before
    // any invitation use or issuance. No migration/overwrite API is introduced.
    fs::remove_file(fixture.args.identity_dir.join(PROFILE)).unwrap();
    crate::device_bundle::inspect(&crate::device_bundle::BundleInspectArgs {
        bundle_dir: bundle.clone(),
        identity_dir: Some(fixture.args.identity_dir.clone()),
        json: true,
    })
    .unwrap();
    bundle
}

#[test]
#[ignore = "requires an explicitly supplied already-built local aegis-client CLI"]
fn full_wide_activation_uses_actual_pki_recovery_before_privileged_actions() {
    let client =
        PathBuf::from(std::env::var_os("AEGIS_TEST_CLIENT_BIN").expect("AEGIS_TEST_CLIENT_BIN"));
    assert!(client.is_absolute() && client.is_file());
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let harness =
        root.join("aegis-client/tests/fixtures/full-wide-activation/activation_boundary.py");
    for scenario in ["response", "request", "none"] {
        let mut fixture = Fixture::new();
        // tempfile's directory mode follows the host umask; this environment-
        // bound harness requires its whole synthetic workspace to be private.
        fs::set_permissions(fixture._temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let wall = registry::unix_now().unwrap();
        fixture.now = wall - 120;
        let bundle = full_wide_bundle(&fixture);
        let expected_receipt = match scenario {
            "response" => Some(interrupted_with_lifetime(&fixture, 0, 3600)),
            "request" => {
                fixture.ready();
                fixture.begin(Operation::Renew, fixture.now + 60);
                None
            }
            "none" => {
                fixture.ready();
                None
            }
            _ => unreachable!(),
        };
        let wall = registry::unix_now().unwrap();
        assert!(
            fixture.now + 90 + 10 < wall,
            "strict expired predecessor margin"
        );
        if let Some(receipt) = &expected_receipt {
            assert!(
                receipt.not_before_unix_secs <= wall && wall + 60 < receipt.not_after_unix_secs
            );
        }
        // All three cases are red at the legacy ready/status boundary before
        // the installer is called. Retained state, rather than a fabricated
        // phase or relaxed expiration check, distinguishes their outcomes.
        let legacy = Command::new(&client)
            .args(["device", "status", "--identity-dir"])
            .arg(&fixture.args.identity_dir)
            .arg("--json")
            .output()
            .unwrap();
        assert!(
            !legacy.status.success(),
            "{scenario}: predecessor unexpectedly ready"
        );
        let before = fixture.snapshot();
        let key_inode = fs::metadata(fixture.args.identity_dir.join("device.key"))
            .unwrap()
            .ino();
        let expectation = match scenario {
            "response" => "ready",
            "request" => "runtime_recovery_required",
            _ => "refuse",
        };
        let outcome = Command::new("python3")
            .arg(&harness)
            .arg(root)
            .arg(&client)
            .arg(fixture._temp.path())
            .arg(&bundle)
            .arg(&fixture.args.identity_dir)
            .arg(&fixture.args.device_id)
            .arg(expectation)
            .output()
            .unwrap();
        assert!(
            outcome.status.success(),
            "{scenario}: stdout={} stderr={}",
            String::from_utf8_lossy(&outcome.stdout),
            String::from_utf8_lossy(&outcome.stderr)
        );
        println!("{}", String::from_utf8_lossy(&outcome.stdout).trim());
        assert_eq!(fixture.bytes("device.key"), before["device.key"]);
        assert_eq!(
            fs::metadata(fixture.args.identity_dir.join("device.key"))
                .unwrap()
                .ino(),
            key_inode
        );
        if let Some(receipt) = expected_receipt {
            assert_eq!(
                fixture.bytes("device.pem"),
                receipt.certificate_pem.as_bytes()
            );
            assert!(!fixture.args.identity_dir.join(REQUEST).exists());
            assert!(!fixture.args.identity_dir.join(RESPONSE).exists());
            assert_eq!(
                online_status(&fixture.args.identity_dir, wall)
                    .unwrap()
                    .state,
                "ready"
            );
        } else {
            assert_eq!(
                fixture.snapshot(),
                before,
                "{scenario}: identity was changed"
            );
        }
    }
}
