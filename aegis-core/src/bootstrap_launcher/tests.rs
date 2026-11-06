use super::*;
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::{fs, process::Command};

fn profile() -> LauncherPins {
    LauncherPins {
        schema: "aegis_client_launcher_pins_v1".into(),
        version: "v1.2.3-rc.1".into(),
        bootstrap_sha256: "a".repeat(64),
        x86_64: ManifestPins {
            manifest_sha256: "b".repeat(64),
            signature_sha256: "c".repeat(64),
        },
        aarch64: ManifestPins {
            manifest_sha256: "d".repeat(64),
            signature_sha256: "e".repeat(64),
        },
        sources: vec![
            "https://primary.example/v1.2.3-rc.1".into(),
            "https://mirror.example/v1.2.3-rc.1".into(),
        ],
    }
}

#[test]
fn rejects_missing_pins_nonversioned_or_nonpublic_sources() {
    assert!(profile().validate().is_ok());
    let mut invalid = profile();
    invalid.aarch64.signature_sha256.clear();
    assert!(invalid.validate().is_err());
    for source in [
        "https://mirror.example/latest/download",
        "http://mirror.example/v1.2.3-rc.1",
        "https://user@mirror.example/v1.2.3-rc.1",
        "https://mirror.example/v1.2.3-rc.1?query=1",
        "https://mirror.example/../v1.2.3-rc.1",
    ] {
        let mut invalid = profile();
        invalid.sources = vec![source.into()];
        assert!(invalid.validate().is_err(), "{source}");
    }
}

#[cfg(unix)]
#[test]
fn profile_load_rejects_links_writable_files_and_oversized_input() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("pins.json");
    fs::write(&path, serde_json::to_vec(&profile()).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    LauncherPins::load(&path).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(LauncherPins::load(&path).is_err());
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(LauncherPins::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let linked = temp.path().join("linked.json");
    symlink(&path, &linked).unwrap();
    assert!(LauncherPins::load(&linked).is_err());
    fs::write(&path, vec![0; 65537]).unwrap();
    assert!(LauncherPins::load(&path).is_err());
}

#[cfg(unix)]
#[test]
fn inert_launcher_verifies_each_stage_selects_arch_and_preserves_arguments() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let unsafe_temp = temp.path().join("unsafe-temp");
    fs::create_dir(&unsafe_temp).unwrap();
    fs::set_permissions(&unsafe_temp, fs::Permissions::from_mode(0o777)).unwrap();
    let downloads = temp.path().join("downloads");
    fs::create_dir(&downloads).unwrap();
    for (name, content) in [
        ("curl", "#!/bin/bash\nurl=''; output=''; while (($#)); do case \"$1\" in https://*) url=\"$1\" ;; -o) shift; output=\"$1\" ;; esac; shift; done\n[[ $url != https://primary.example/* ]] || exit 22\ncp \"$AEGIS_LAUNCHER_TEST_DOWNLOADS/${url##*/}\" \"$output\"\n"),
        ("uname", "#!/bin/bash\nif [[ $1 == -s ]]; then echo Linux; else printf '%s\\n' \"$AEGIS_LAUNCHER_TEST_ARCH\"; fi\n"),
    ] {
        let path = bin.join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let bootstrap =
        b"#!/bin/bash\nset -eu\nprintf '%s\\n' \"$@\" > \"$AEGIS_LAUNCHER_TEST_OUTPUT\"\n";
    fs::write(downloads.join("bootstrap-install.sh"), bootstrap).unwrap();
    let mut pins = profile();
    pins.bootstrap_sha256 = hex::encode(Sha256::digest(bootstrap));
    for (leaf, target) in [
        ("client-release.manifest.json", &mut pins.x86_64),
        ("client-release.manifest-aarch64.json", &mut pins.aarch64),
    ] {
        fs::write(downloads.join(leaf), leaf).unwrap();
        let signature = format!("signature-{leaf}");
        fs::write(downloads.join(format!("{leaf}.sig")), &signature).unwrap();
        target.manifest_sha256 = hex::encode(Sha256::digest(leaf));
        target.signature_sha256 = hex::encode(Sha256::digest(signature));
    }
    let marker = temp.path().join("ran.txt");
    let launcher = temp.path().join("launcher.sh");
    let url = "https://relay.example/bundle?token=a'b&value=$literal";
    let access_file = temp.path().join("client-access-url.txt");
    crate::secret_file::write_private_new(&access_file, url.as_bytes()).unwrap();
    fs::write(&launcher, pins.render_command(&access_file).unwrap()).unwrap();
    let invoke = |arch: &str| {
        Command::new("bash")
            .arg(&launcher)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("TMPDIR", &unsafe_temp)
            .env("AEGIS_LAUNCHER_TEST_ARCH", arch)
            .env("AEGIS_LAUNCHER_TEST_DOWNLOADS", &downloads)
            .env("AEGIS_LAUNCHER_TEST_OUTPUT", &marker)
            .output()
            .unwrap()
    };
    for arch in ["x86_64", "aarch64"] {
        let result = invoke(arch);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let args = fs::read_to_string(&marker).unwrap();
        assert!(args.starts_with("client\n--source\nfile://"));
        assert!(
            !args.contains(url),
            "private URL crossed actual bootstrap argv"
        );
        assert!(
            !fs::read_to_string(&launcher).unwrap().contains(url),
            "private URL crossed rendered launcher output"
        );
        assert!(args.ends_with(&format!("--bundle-url-file\n{}\n", access_file.display())));
        fs::remove_file(&marker).unwrap();
    }
    // Every untrusted stage has an independent pin. Changed bytes cannot run
    // the inert fixture, even when both mirrors return the same changed file.
    for leaf in [
        "bootstrap-install.sh",
        "client-release.manifest.json",
        "client-release.manifest.json.sig",
    ] {
        let path = downloads.join(leaf);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"changed fixture").unwrap();
        assert!(!invoke("x86_64").status.success(), "{leaf}");
        assert!(!marker.exists());
        fs::write(&path, original).unwrap();
    }
    assert!(fs::read_dir(&unsafe_temp).unwrap().next().is_none());
    assert!(!invoke("unsupported").status.success());
    assert!(!marker.exists());
}
