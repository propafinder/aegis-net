//! Actual Windows CLI parsing, not a synthetic Authenticode provider.
use super::*;
use clap::Parser;

#[test]
fn install_accepts_explicit_policy_and_unsigned_default_remains_none() {
    for policy in [None, Some(r"C:\trusted policy\authenticode.json")] {
        let mut args = vec![
            "aegis-winctl",
            "client",
            "install",
            "--package",
            r"C:\kit",
            "--manifest-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--config",
            r"C:\input.toml",
            "--root",
            r"C:\new",
        ];
        if let Some(path) = policy {
            args.extend(["--authenticode-policy", path]);
        }
        let parsed = crate::Cli::try_parse_from(args).unwrap();
        let crate::TopCommand::Client(ClientArgs {
            command: ClientCommand::Install(install),
        }) = parsed.command
        else {
            panic!("wrong install command");
        };
        assert_eq!(install.authenticode.path(), policy.map(Path::new));
    }
}

#[test]
fn upgrade_accepts_explicit_policy_and_unsigned_default_remains_none() {
    for policy in [None, Some(r"C:\trusted policy\authenticode.json")] {
        let mut args = vec![
            "aegis-winctl",
            "client",
            "upgrade",
            "--root",
            r"C:\old",
            "--package",
            r"C:\kit",
            "--manifest-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--new-root",
            r"C:\new",
        ];
        if let Some(path) = policy {
            args.extend(["--authenticode-policy", path]);
        }
        let parsed = crate::Cli::try_parse_from(args).unwrap();
        let crate::TopCommand::Client(ClientArgs {
            command: ClientCommand::Upgrade { authenticode, .. },
        }) = parsed.command
        else {
            panic!("wrong upgrade command");
        };
        assert_eq!(authenticode.path(), policy.map(Path::new));
    }
}
