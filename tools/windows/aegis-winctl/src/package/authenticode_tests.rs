use super::*;
use std::ffi::OsStr;

#[test]
fn script_file_preserves_literal_arguments_and_no_inline_program() {
    let powershell = Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    let script = Path::new(r"C:\owned temp\verification.ps1");
    let package = Path::new(r"C:\kit & (literal)\package");
    let verifier = Path::new(r"C:\trusted entries\RFC3161 verifier.ps1");
    let command = command(
        powershell,
        script,
        package,
        "publisher-pin",
        verifier,
        false,
    );
    let arguments: Vec<_> = command.get_args().collect();
    assert_eq!(command.get_program(), powershell.as_os_str());
    assert_eq!(
        arguments,
        vec![
            OsStr::new("-NoLogo"),
            OsStr::new("-NoProfile"),
            OsStr::new("-NonInteractive"),
            OsStr::new("-File"),
            script.as_os_str(),
            package.as_os_str(),
            OsStr::new("publisher-pin"),
            verifier.as_os_str(),
            OsStr::new("0"),
        ]
    );
    assert!(!arguments.iter().any(|arg| *arg == OsStr::new(SCRIPT)));
    assert!(!arguments.iter().any(|arg| *arg == OsStr::new("-Command")));
}

#[test]
fn research_selection_has_only_the_original_zero_or_one_value() {
    for (research, expected) in [(false, "0"), (true, "1")] {
        let command = command(
            Path::new("powershell.exe"),
            Path::new("script.ps1"),
            Path::new("package"),
            "pin",
            Path::new("verifier.ps1"),
            research,
        );
        assert_eq!(command.get_args().last(), Some(OsStr::new(expected)));
    }
}

#[cfg(windows)]
#[test]
fn owned_script_has_private_acl_exact_bytes_and_verified_retention() {
    let script = VerificationScript::create().unwrap();
    let path = script.path.to_path_buf();
    let file = std::fs::File::open(&path).unwrap();
    aegis_core::windows_file::validate_private(&file, false).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), SCRIPT.as_bytes());
    script.lease.verify().unwrap();
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    drop(file);
    script.finish().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), SCRIPT.as_bytes());
    let retained = std::fs::File::open(&path).unwrap();
    aegis_core::windows_file::validate_private(&retained, false).unwrap();
}

#[test]
fn unsigned_install_admission_keeps_its_independent_manifest_contract() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("inert.exe");
    let mut bytes = vec![0; 128];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    std::fs::write(&executable, bytes).unwrap();
    let package = directory.path().join("kit");
    let built = super::super::build(&executable, &executable, &package, "a".repeat(40)).unwrap();
    let pin = built["manifest_sha256"].as_str().unwrap();
    assert!(super::super::verify_for_install(&package, pin, None).is_ok());
    // An optional signed-policy path does not change the original unsigned policy.
    assert!(super::super::verify_for_install(
        &package,
        pin,
        Some(&directory.path().join("absent-policy.json"))
    )
    .is_ok());
    assert!(super::super::verify_for_install(&package, &"b".repeat(64), None).is_err());
    assert!(!package.join("absent-policy.json").exists());
}
