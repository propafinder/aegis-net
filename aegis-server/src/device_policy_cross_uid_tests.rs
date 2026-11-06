//! Explicit privileged-container fixture; never runs in the ordinary test suite.
//! Real numeric identities and zero-capability clients cover the systemd DAC
//! boundary, without accounts, services, network interfaces or external peers.
use super::*;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

const SERVICE_UID: u32 = 23171;
const SERVICE_GID: u32 = 23171;
const OTHER_UID: u32 = 23172;
const CHILD_TEST: &str = "device_policy_status::cross_uid_tests::cross_uid_fixture_child";
const READY_MARKER: &str = "AEGIS_CROSS_UID_STATUS_READY";

fn chown(path: &Path, uid: u32, gid: u32) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path, inside the owned temporary fixture.
    assert_eq!(unsafe { libc::chown(path.as_ptr(), uid, gid) }, 0);
}

struct OwnedServer {
    child: Child,
    directory: PathBuf,
}

fn stop_owned_child(child: &mut Child, uid: u32, gid: u32, grace: Duration) {
    drop(child.stdin.take());
    let deadline = Instant::now() + grace;
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_some() {
        return;
    }
    // No CAP_KILL: adopt only this fixture child's known UID, then signal its
    // still-unreaped PID. A process ID is never used after try_wait reaps it.
    let pid = child.id() as i32;
    // SAFETY: post-fork code uses credential syscalls, kill and _exit only.
    unsafe {
        let helper = libc::fork();
        assert!(helper >= 0);
        if helper == 0 {
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                libc::_exit(1);
            }
            let result = libc::kill(pid, libc::SIGKILL);
            libc::_exit(if result == 0 { 0 } else { 1 });
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            let result = libc::waitpid(helper, &mut status, libc::WNOHANG);
            if result == helper {
                assert_eq!(status, 0);
                break;
            }
            assert!(
                result == 0 && Instant::now() < deadline,
                "fixture signal helper stalled"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        child.try_wait().unwrap().is_some(),
        "fixture child did not stop"
    );
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        stop_owned_child(
            &mut self.child,
            SERVICE_UID,
            SERVICE_GID,
            Duration::from_secs(2),
        );
        // Restore only the fixture directory for unlink without DAC override.
        chown(&self.directory, 0, 0);
    }
}

fn identity(role: &str) -> (u32, u32) {
    let uid = match role {
        "service" => SERVICE_UID,
        "group-peer" | "stalled-group" => OTHER_UID,
        _ => 0,
    };
    let gid = if role == "root-wrong-group" {
        SERVICE_GID + 1
    } else {
        SERVICE_GID
    };
    (uid, gid)
}

fn command(role: &str, directory: &Path, expected_pid: u32) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env("AEGIS_CROSS_UID_ROLE", role)
        .env("AEGIS_CROSS_UID_DIRECTORY", directory)
        .env("AEGIS_CROSS_UID_EXPECTED_PID", expected_pid.to_string())
        .stdin(if role == "service" {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let (uid, gid) = identity(role);
    // SAFETY: after fork this closure uses only setgroups/setgid/setuid,
    // prctl, capset and errno reads, with stack-allocated kernel ABI structs.
    unsafe {
        command.pre_exec(move || {
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let header = Header {
                version: 0x2008_0522, // Linux capability ABI v3.
                pid: 0,
            };
            let data = [Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

fn zero_capabilities(expected_gid: u32) {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for name in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim();
        assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0, "{name}");
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    // SAFETY: identity getters only read process credentials.
    assert_eq!(unsafe { libc::getegid() }, expected_gid);
}

fn wait_client(mut command: Command, log: &Path, role: &str) {
    let output = fs::File::create(log).unwrap();
    let mut child = command
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{}", fs::read_to_string(log).unwrap());
            return;
        }
        if Instant::now() >= deadline {
            let (uid, gid) = identity(role);
            stop_owned_child(&mut child, uid, gid, Duration::ZERO);
            panic!("cross-UID client exceeded bounded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires disposable Linux container with CAP_CHOWN, CAP_SETUID and CAP_SETGID"]
fn cross_uid_zero_cap_root_and_unprivileged_group_peer() {
    // SAFETY: geteuid only reads process credentials.
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let root = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let directory = root.path().join("service");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    chown(&directory, SERVICE_UID, SERVICE_GID);
    let log_path = root.path().join("service.log");
    let log = fs::File::create(&log_path).unwrap();
    let child = command("service", &directory, 0)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut server = OwnedServer { child, directory };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = fs::read_to_string(&log_path).unwrap();
        if text.contains(READY_MARKER) {
            break;
        }
        assert!(server.child.try_wait().unwrap().is_none(), "{text}");
        assert!(
            Instant::now() < deadline,
            "service did not become ready: {text}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    for role in ["root-query", "root-wrong-group", "group-peer"] {
        wait_client(
            command(role, &server.directory, server.child.id()),
            &root.path().join(format!("{role}.log")),
            role,
        );
    }
    // The rejected ordinary group peer must not damage the real listener.
    wait_client(
        command("root-query", &server.directory, server.child.id()),
        &root.path().join("root-after-rejection.log"),
        "root-query",
    );
    // Exercise the timeout cleanup with a different-UID process that cannot
    // be killed directly by this zero-CAP_KILL parent.
    let mut stalled = command("stalled-group", &server.directory, server.child.id())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    stop_owned_child(
        &mut stalled,
        OTHER_UID,
        SERVICE_GID,
        Duration::from_millis(20),
    );
}

#[test]
#[ignore = "subprocess fixture only; launched by the explicit cross-UID test"]
fn cross_uid_fixture_child() {
    let Ok(role) = std::env::var("AEGIS_CROSS_UID_ROLE") else {
        return;
    };
    zero_capabilities(if role == "root-wrong-group" {
        SERVICE_GID + 1
    } else {
        SERVICE_GID
    });
    if role == "stalled-group" {
        std::thread::sleep(Duration::from_secs(60));
        return;
    }
    let directory = PathBuf::from(std::env::var_os("AEGIS_CROSS_UID_DIRECTORY").unwrap());
    let path = directory.join("status.sock");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        if role == "service" {
            let (server, _) = super::tests::fixture(&directory);
            let _watcher = server.start_registry_watcher().unwrap();
            let _status = StatusServer::start(Some(&path), Some(&server)).unwrap();
            println!("{READY_MARKER}");
            std::io::stdout().flush().unwrap();
            let count = tokio::task::spawn_blocking(|| {
                use std::io::Read;
                std::io::stdin().read(&mut [0; 1]).unwrap()
            })
            .await
            .unwrap();
            assert_eq!(count, 0);
            drop(_status);
            drop(_watcher);
        } else {
            let expected_pid = std::env::var("AEGIS_CROSS_UID_EXPECTED_PID")
                .unwrap()
                .parse()
                .unwrap();
            let result = query(&path, SERVICE_UID, SERVICE_GID, expected_pid).await;
            if role == "root-query" {
                assert!(matches!(result.unwrap(), Response::Ready { .. }));
            } else {
                assert!(result.is_err(), "unexpected peer/group acknowledgement");
            }
        }
    });
}
