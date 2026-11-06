use super::run_live_command;
use std::{
    io::Write,
    path::Path,
    thread,
    time::{Duration, Instant},
};

const FIXTURE_TEST: &str = "adversarial_runner::execution::tests::subprocess_fixture";

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn fixture_command(mode: &str) -> String {
    let executable = std::env::current_exe().expect("test executable");
    format!(
        "AEGIS_PIPE_FIXTURE={} {} --exact {} --ignored --nocapture",
        quote(mode),
        quote(executable.to_str().expect("UTF-8 test executable")),
        quote(FIXTURE_TEST),
    )
}

// This is a real harmless subprocess of this test binary. Descendants terminate
// naturally after 1.4 s even when the baseline runner does not own their group.
#[test]
#[ignore = "invoked only as an isolated subprocess fixture"]
fn subprocess_fixture() {
    match std::env::var("AEGIS_PIPE_FIXTURE").as_deref() {
        Ok("bulk") => {
            let block = [b'O'; 8192];
            let mut stdout = std::io::stdout().lock();
            for _ in 0..1024 {
                stdout.write_all(&block).unwrap();
            }
            stdout.flush().unwrap();
            let block = [b'E'; 8192];
            let mut stderr = std::io::stderr().lock();
            for _ in 0..1024 {
                stderr.write_all(&block).unwrap();
            }
            stderr.flush().unwrap();
        }
        Ok("hold") => {
            std::fs::write("descendant-started", b"started").unwrap();
            thread::sleep(Duration::from_millis(450));
            std::fs::write("descendant-survived", b"survived").unwrap();
            thread::sleep(Duration::from_millis(950));
        }
        Ok("continuous") => {
            let until = Instant::now() + Duration::from_millis(1400);
            let block = [b'C'; 8192];
            let mut stdout = std::io::stdout().lock();
            while Instant::now() < until {
                if stdout.write_all(&block).is_err() {
                    break;
                }
            }
        }
        _ => panic!("fixture requires an explicit harmless mode"),
    }
}

#[test]
fn output_larger_than_pipe_capacity_completes_and_capture_is_bounded() {
    let root = tempfile::tempdir().unwrap();
    let result = run_live_command(root.path(), &fixture_command("bulk"), 2.0);
    assert!(
        !result.timed_out,
        "finite output must be drained before the deadline"
    );
    assert_eq!(result.returncode, Some(0));
    assert_eq!(result.stdout.len(), 64 * 1024);
    assert_eq!(result.stderr.len(), 64 * 1024);
    assert!(result.stdout.windows(8).any(|bytes| bytes == b"OOOOOOOO"));
    assert!(result.stderr.windows(8).any(|bytes| bytes == b"EEEEEEEE"));
    assert!(String::from_utf8_lossy(&result.stdout).contains("diagnostic output truncated"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("diagnostic output truncated"));
}

fn check_descendant_lifetime(root: &Path, command: String) {
    let started = Instant::now();
    let result = run_live_command(root, &command, 0.15);
    assert!(
        result.timed_out,
        "the original deadline includes descendant-held pipes"
    );
    assert_eq!(result.returncode, None);
    assert!(
        started.elapsed() < Duration::from_millis(750),
        "cleanup must not wait for descendant EOF indefinitely"
    );
    assert!(
        root.join("descendant-started").is_file(),
        "the real descendant must have started"
    );
    thread::sleep(Duration::from_millis(500));
    assert!(
        !root.join("descendant-survived").exists(),
        "owned descendants must stop at the deadline"
    );
}

#[test]
fn exited_shell_with_descendant_pipe_is_timed_out_and_descendant_stops() {
    let root = tempfile::tempdir().unwrap();
    check_descendant_lifetime(root.path(), format!("{} & exit 0", fixture_command("hold")));
}

#[test]
fn running_shell_timeout_stops_owned_descendant() {
    let root = tempfile::tempdir().unwrap();
    check_descendant_lifetime(root.path(), format!("{} & wait", fixture_command("hold")));
}

#[test]
fn continuously_ready_pipe_cannot_extend_original_deadline() {
    let root = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let result = run_live_command(root.path(), &fixture_command("continuous"), 0.15);
    assert!(result.timed_out);
    assert_eq!(result.returncode, None);
    assert!(started.elapsed() < Duration::from_millis(750));
    assert!(result.stdout.len() <= 64 * 1024);
}

#[test]
fn ordinary_success_and_failure_preserve_outputs_and_exit_codes() {
    let root = tempfile::tempdir().unwrap();
    for code in [0, 7] {
        let command = format!("printf 'ordinary out'; printf 'ordinary err' >&2; exit {code}");
        let result = run_live_command(root.path(), &command, 1.0);
        assert!(!result.timed_out);
        assert_eq!(result.returncode, Some(code));
        assert_eq!(result.stdout, b"ordinary out");
        assert_eq!(result.stderr, b"ordinary err");
    }
}
