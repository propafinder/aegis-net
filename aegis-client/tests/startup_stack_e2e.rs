//! A real client process must enter its async runtime on the ordinary OS stack.
//! --version is a custom flag handled in run_client_inner, not clap's early exit.
// Reuse the existing tested finite direct-child/spool owner; its own ordinary
// tests are not new stack regressions and must not be added to distinct totals.
#[allow(dead_code)]
#[path = "../src/ingress/wide/ip_tunnel/tests/owned_process.rs"]
mod owned_process;
use std::{
    process::Command,
    time::{Duration, Instant},
};
#[test]
fn real_client_version_enters_async_runtime_on_default_main_stack() {
    let dir = tempfile::tempdir().expect("private owned startup test directory");
    let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-client"));
    command
        .args(["--version", "--no-runtime-events", "--forensic-safe"])
        .current_dir(dir.path())
        .env("AEGIS_NO_BANNER", "1")
        .env_remove("RUST_MIN_STACK");
    let original = Instant::now();
    let child = owned_process::HeldCommand::spawn(&mut command, dir.path())
        .expect("owned actual client startup");
    let outcome = child.finish(original + Duration::from_secs(10));
    let success = outcome.success() && !outcome.killed;
    if !success {
        // Preserve only this child's already bounded spool files. No name/PID
        // searches, global kill, native operation or foreign task removal.
        let retained = dir.keep();
        panic!("client startup refused: reason={} status={:?} reaped={} killed={} custody={} output_limit={} read_failed={} retained={}",
            outcome.reason, outcome.status, outcome.reaped, outcome.killed,
            outcome.spool_custody_confirmed, outcome.output_limit_exceeded,
            outcome.output_read_failed, retained.display());
    }
    let output = std::str::from_utf8(&outcome.stdout).expect("bounded version text");
    assert!(output.starts_with(&format!("aegis-client {} (git ", env!("CARGO_PKG_VERSION"))));
    assert!(output.contains("cargo-lock "));
    assert_eq!(output.lines().count(), 1);
    assert!(
        outcome.stderr.is_empty(),
        "version path must not emit diagnostic or failure text"
    );
}
