// Actual post-start process custody. This proves the selected service process,
// not external reachability, native routing, or leak-free capture readiness.
use super::{fail, Result};
use crate::profile_auto_install_receipt::BinaryGeneration;
use crate::profile_auto_runtime_identity::RuntimePolicy;
use crate::profile_auto_stopped_service::{self as provider, InstallLock, ManagerQuery};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
};
const LIMIT: u64 = 64 * 1024;
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(super::super::refuse())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveUnit {
    pid: i32,
    invocation: String,
    start_monotonic: u64,
    cgroup: String,
    uid: u32,
    gid: u32,
}
fn number<T: std::str::FromStr>(text: &str) -> Result<T> {
    require(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))?;
    text.parse().map_err(fail)
}
fn parse_active_for(bytes: &[u8], expected_unit: &str) -> Result<ActiveUnit> {
    require(bytes.len() <= LIMIT as usize)?;
    let text = std::str::from_utf8(bytes).map_err(fail)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or_else(super::super::refuse)?;
        require(values.insert(key, value).is_none())?;
    }
    let expected = [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "ControlGroup",
        "InvocationID",
        "ExecMainStartTimestampMonotonic",
        "User",
        "Group",
        "Type",
        "NotifyAccess",
        "StatusText",
    ];
    require(values.len() == expected.len() && expected.iter().all(|key| values.contains_key(key)))?;
    require(
        values["Id"] == expected_unit
            && values["LoadState"] == "loaded"
            && values["ActiveState"] == "active"
            && values["SubState"] == "running"
            && values["ControlPID"] == "0"
            && values["Type"] == "notify"
            && values["NotifyAccess"] == "main"
            && values["StatusText"] == "Ingress workers ready",
    )?;
    let pid: i32 = number(values["MainPID"])?;
    let start_monotonic = number(values["ExecMainStartTimestampMonotonic"])?;
    let invocation = values["InvocationID"];
    let cgroup = values["ControlGroup"];
    require(
        pid > 1
            && start_monotonic > 0
            && invocation.len() == 32
            && invocation.bytes().all(|b| b.is_ascii_hexdigit())
            && invocation.bytes().any(|b| b != b'0'),
    )?;
    require(
        cgroup.starts_with('/')
            && cgroup.len() < 4096
            && cgroup.split('/').skip(1).all(|p| {
                !p.is_empty()
                    && p != "."
                    && p != ".."
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-@".contains(&b))
            })
            && cgroup.ends_with(&format!("/{expected_unit}")),
    )?;
    let (uid, gid) =
        provider::observed_account_identity(values["User"], values["Group"]).map_err(fail)?;
    Ok(ActiveUnit {
        pid,
        invocation: invocation.into(),
        start_monotonic,
        cgroup: cgroup.into(),
        uid,
        gid,
    })
}
#[cfg(test)]
fn parse_active(bytes: &[u8]) -> Result<ActiveUnit> {
    parse_active_for(bytes, "aegis-client.service")
}
fn open_at(parent: &File, name: &str, flags: i32) -> Result<File> {
    let name = CString::new(name).map_err(fail)?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
    require(fd >= 0)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory(parent: &File, name: &str) -> Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
}
fn root() -> Result<File> {
    let path = CString::new("/").map_err(fail)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    require(fd >= 0)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn filesystem(file: &File, expected: libc::c_long) -> Result<()> {
    let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
    require(unsafe { libc::fstatfs(file.as_raw_fd(), value.as_mut_ptr()) } == 0)?;
    require(unsafe { value.assume_init() }.f_type == expected)
}
fn read(parent: &File, name: &str) -> Result<String> {
    let mut bytes = Vec::new();
    open_at(parent, name, libc::O_RDONLY | libc::O_NOFOLLOW)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    require(bytes.len() <= LIMIT as usize)?;
    String::from_utf8(bytes).map_err(fail)
}
fn start_ticks(stat: &str, pid: i32) -> Result<u64> {
    let (head, rest) = stat.rsplit_once(") ").ok_or_else(super::super::refuse)?;
    require(head.starts_with(&format!("{pid} (")))?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    require(fields.len() >= 20 && matches!(fields[0], "R" | "S" | "D"))?;
    let ticks = number(fields[19])?;
    require(ticks > 0)?;
    Ok(ticks)
}
fn process_identity(status: &str, expected: &ActiveUnit, policy: RuntimePolicy) -> Result<()> {
    require((expected.uid == 0) == (policy == RuntimePolicy::Root))?;
    for (key, wanted) in [("Uid:", expected.uid), ("Gid:", expected.gid)] {
        let lines: Vec<_> = status
            .lines()
            .filter(|line| line.starts_with(key))
            .collect();
        require(lines.len() == 1)?;
        let fields: Vec<_> = lines[0][key.len()..].split_whitespace().collect();
        require(fields.len() == 4)?;
        for field in fields {
            require(number::<u32>(field)? == wanted)?;
        }
    }
    if expected.uid != 0 {
        let lines: Vec<_> = status
            .lines()
            .filter(|line| line.starts_with("Groups:"))
            .collect();
        require(lines.len() == 1)?;
        // NSS may change between lookup and service start. The actually
        // running dedicated actor may retain only its admitted primary group;
        // an empty supplementary set grants less authority and is accepted.
        for field in lines[0]["Groups:".len()..].split_whitespace() {
            require(number::<u32>(field)? == expected.gid)?;
        }
        let scalar = |key: &str| -> Result<&str> {
            let mut lines = status.lines().filter_map(|line| line.strip_prefix(key));
            let value = lines.next().ok_or_else(super::super::refuse)?.trim();
            require(lines.next().is_none())?;
            Ok(value)
        };
        require(scalar("NoNewPrivs:")? == "1")?;
        let allowed = if policy == RuntimePolicy::DedicatedBind {
            1_u64 << 10 // CAP_NET_BIND_SERVICE
        } else {
            0
        };
        for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            let value = scalar(key)?;
            require(value.len() == 16 && value.bytes().all(|b| b.is_ascii_hexdigit()))?;
            require(u64::from_str_radix(value, 16).map_err(fail)? & !allowed == 0)?;
        }
    }
    Ok(())
}
struct Process {
    proc_root: File,
    pid_dir: File,
    pidfd: OwnedFd,
    executable: File,
    cgroup: File,
    cgroup_root: File,
    command_line: Vec<u8>,
    unit: ActiveUnit,
    runtime_policy: RuntimePolicy,
    ticks: u64,
    cgroup_identity: (u64, u64),
}
impl Process {
    fn capture(
        unit: ActiveUnit,
        binary: &BinaryGeneration,
        command_line: Vec<u8>,
        runtime_policy: RuntimePolicy,
    ) -> Result<Self> {
        let root = root()?;
        let proc_root = directory(&root, "proc")?;
        filesystem(&proc_root, libc::PROC_SUPER_MAGIC)?;
        let pid_dir = directory(&proc_root, &unit.pid.to_string())?;
        filesystem(&pid_dir, libc::PROC_SUPER_MAGIC)?;
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, unit.pid, 0) };
        require(pidfd >= 0)?;
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
        // exe is a kernel proc magic link inside the held PID directory. Its
        // readable target is authenticated by the sealed installed generation.
        let executable = open_at(&pid_dir, "exe", libc::O_RDONLY)?;
        binary.admit_running_executable(&executable).map_err(fail)?;
        let mut cgroup = root;
        for name in ["sys", "fs", "cgroup"] {
            cgroup = directory(&cgroup, name)?;
            let meta = cgroup.metadata().map_err(fail)?;
            require(meta.uid() == 0 && meta.mode() & 0o022 == 0)?;
        }
        filesystem(&cgroup, libc::CGROUP2_SUPER_MAGIC)?;
        let cgroup_root = cgroup.try_clone().map_err(fail)?;
        for name in unit
            .cgroup
            .split('/')
            .skip(1)
            .filter(|name| !name.is_empty())
        {
            cgroup = directory(&cgroup, name)?;
        }
        filesystem(&cgroup, libc::CGROUP2_SUPER_MAGIC)?;
        let meta = cgroup.metadata().map_err(fail)?;
        let ticks = start_ticks(&read(&pid_dir, "stat")?, unit.pid)?;
        let result = Self {
            proc_root,
            pid_dir,
            pidfd,
            executable,
            cgroup,
            cgroup_root,
            command_line,
            unit,
            runtime_policy,
            ticks,
            cgroup_identity: (meta.dev(), meta.ino()),
        };
        result.revalidate(binary)?;
        Ok(result)
    }
    fn revalidate(&self, binary: &BinaryGeneration) -> Result<()> {
        let mut event = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(unsafe { libc::poll(&mut event, 1, 0) } == 0 && event.revents == 0)?;
        let current = directory(&self.proc_root, &self.unit.pid.to_string())?;
        require(
            start_ticks(&read(&self.pid_dir, "stat")?, self.unit.pid)? == self.ticks
                && start_ticks(&read(&current, "stat")?, self.unit.pid)? == self.ticks,
        )?;
        process_identity(&read(&current, "status")?, &self.unit, self.runtime_policy)?;
        require(read(&current, "cgroup")? == format!("0::{}\n", self.unit.cgroup))?;
        require(read(&current, "cmdline")?.as_bytes() == self.command_line)?;
        let mut current_cgroup = self.cgroup_root.try_clone().map_err(fail)?;
        for name in self
            .unit
            .cgroup
            .split('/')
            .skip(1)
            .filter(|name| !name.is_empty())
        {
            current_cgroup = directory(&current_cgroup, name)?;
        }
        let named = current_cgroup.metadata().map_err(fail)?;
        require((named.dev(), named.ino()) == self.cgroup_identity)?;
        let members = read(&self.cgroup, "cgroup.procs")?;
        require(
            members
                .lines()
                .any(|line| line == self.unit.pid.to_string()),
        )?;
        let meta = self.cgroup.metadata().map_err(fail)?;
        require((meta.dev(), meta.ino()) == self.cgroup_identity)?;
        binary
            .admit_running_executable(&self.executable)
            .map_err(fail)?;
        binary
            .admit_running_executable(&open_at(&current, "exe", libc::O_RDONLY)?)
            .map_err(fail)
    }
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    schema: u32,
    unit_name: String,
    nonce: String,
    input_generation: String,
    planned_generation: String,
    installed_generation: String,
    policy_generation: String,
    unit: ActiveUnit,
    ticks: u64,
    cgroup_identity: (u64, u64),
}
pub(super) struct ActiveGuard {
    process: Process,
    binary: BinaryGeneration,
    evidence: Evidence,
}
impl ActiveGuard {
    pub(super) fn admit_owned_start(
        &self,
        started: &crate::profile_auto_stopped_service::pid1::CompletedStart,
    ) -> Result<()> {
        let (job, invocation) = started.facts();
        require(
            job.unit() == self.evidence.unit_name
                && job.id() > 0
                && invocation == self.evidence.unit.invocation,
        )
    }
    pub(super) fn observe_owned(
        context: &super::super::store_context::RootContext<'_>,
        lock: &InstallLock,
        started: &mut crate::profile_auto_stopped_service::pid1::OwnedStart,
    ) -> Result<Self> {
        let name = started.completed().facts().0.unit().to_owned();
        require(super::activation::private_unit_name(&name))?;
        let bytes = started.active_unit_readback().map_err(fail)?;
        let guard = Self::observe_with(context, lock, &name, &bytes)?;
        guard.admit_owned_start(started.completed())?;
        guard.revalidate_owned(context, lock, started)?;
        Ok(guard)
    }
    pub(super) fn observe(
        context: &super::super::store_context::RootContext<'_>,
        lock: &InstallLock,
    ) -> Result<Self> {
        let bytes = provider::manager_query(ManagerQuery::Active).map_err(fail)?;
        let result = Self::observe_with(context, lock, "aegis-client.service", &bytes)?;
        result.revalidate(context, lock)?;
        Ok(result)
    }
    fn observe_with(
        context: &super::super::store_context::RootContext<'_>,
        lock: &InstallLock,
        unit_name: &str,
        unit_bytes: &[u8],
    ) -> Result<Self> {
        context.admit_active_operation()?;
        lock.revalidate().map_err(fail)?;
        let policy = super::super::unit_store::verify_active_policy(context)?;
        let stage = context.stage_cell().borrow();
        let binary = super::super::receipt_store::installed_generation(&stage)?;
        let unit = parse_active_for(unit_bytes, unit_name)?;
        require(policy.runtime_identity() == (unit.uid, unit.gid))?;
        let mut command_line = super::super::receipt_store::installed_command_line(&stage)?;
        if super::activation::private_unit_name(unit_name) {
            // The transient unit executes the same protected binary/config
            // with a source-owned private launch verb and this typed PID1
            // unit. Match the kernel argv exactly, including NUL framing.
            let split = command_line
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(super::super::refuse)?
                + 1;
            let mut owned = Vec::with_capacity(command_line.len() + unit_name.len() + 20);
            owned.extend_from_slice(&command_line[..split]);
            owned.extend_from_slice(b"auto-owned-service\0");
            owned.extend_from_slice(unit_name.as_bytes());
            owned.push(0);
            owned.extend_from_slice(&command_line[split..]);
            command_line = owned;
        }
        let runtime_policy = stage
            .header
            .runtime_binding
            .as_ref()
            .ok_or_else(super::super::refuse)?
            .policy();
        let process = Process::capture(unit.clone(), &binary, command_line, runtime_policy)?;
        let evidence = Evidence {
            schema: 2,
            unit_name: unit_name.into(),
            nonce: stage.header.transaction_nonce.clone(),
            input_generation: stage.header.input_generation.clone(),
            planned_generation: stage.header.planned_generation.clone(),
            installed_generation: stage
                .header
                .leaves
                .get(std::path::Path::new(
                    "accepted/install-receipt/installed-generation.json",
                ))
                .ok_or_else(super::super::refuse)?
                .clone(),
            policy_generation: policy.generation().into(),
            unit,
            ticks: process.ticks,
            cgroup_identity: process.cgroup_identity,
        };
        drop(stage);
        let result = Self {
            process,
            binary,
            evidence,
        };
        result.process.revalidate(&result.binary)?;
        lock.revalidate().map_err(fail)?;
        Ok(result)
    }
    pub(super) fn revalidate_owned(
        &self,
        context: &super::super::store_context::RootContext<'_>,
        lock: &InstallLock,
        started: &mut crate::profile_auto_stopped_service::pid1::OwnedStart,
    ) -> Result<()> {
        self.admit_owned_start(started.completed())?;
        lock.revalidate().map_err(fail)?;
        context.admit_active_operation()?;
        let policy = super::super::unit_store::verify_active_policy(context)?;
        require(policy.generation() == self.evidence.policy_generation)?;
        self.process.revalidate(&self.binary)?;
        let bytes = started.active_unit_readback().map_err(fail)?;
        require(parse_active_for(&bytes, &self.evidence.unit_name)? == self.evidence.unit)?;
        self.process.revalidate(&self.binary)?;
        started.revalidate().map_err(fail)?;
        lock.revalidate().map_err(fail)
    }
    pub(super) fn revalidate(
        &self,
        context: &super::super::store_context::RootContext<'_>,
        lock: &InstallLock,
    ) -> Result<()> {
        lock.revalidate().map_err(fail)?;
        context.admit_active_operation()?;
        let policy = super::super::unit_store::verify_active_policy(context)?;
        require(policy.generation() == self.evidence.policy_generation)?;
        self.process.revalidate(&self.binary)?;
        let current = provider::manager_query(ManagerQuery::Active).map_err(fail)?;
        require(parse_active_for(&current, &self.evidence.unit_name)? == self.evidence.unit)?;
        self.process.revalidate(&self.binary)?;
        lock.revalidate().map_err(fail)
    }
    pub(super) fn admit_recorded(&self, bytes: &[u8]) -> Result<()> {
        let evidence: Evidence = serde_json::from_slice(bytes).map_err(fail)?;
        require(evidence == self.evidence)
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.evidence).map_err(fail)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_manager_schema_rejects_restart_transition_unknown_and_empty_epoch() {
        let good = b"Id=aegis-client.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nControlPID=0\nControlGroup=/system.slice/aegis-client.service\nInvocationID=0123456789abcdef0123456789abcdef\nExecMainStartTimestampMonotonic=1234\nUser=root\nGroup=root\nType=notify\nNotifyAccess=main\nStatusText=Ingress workers ready\n";
        assert!(parse_active(good).is_ok());
        let text = std::str::from_utf8(good).unwrap();
        let private = format!("aegis-auto@{}.service", "a".repeat(64));
        let private_reply = text.replace("aegis-client.service", &private);
        assert!(parse_active_for(private_reply.as_bytes(), &private).is_ok());
        assert!(parse_active_for(private_reply.as_bytes(), "aegis-client.service").is_err());
        for (before, after) in [
            ("SubState=running", "SubState=start"),
            ("ControlPID=0", "ControlPID=44"),
            ("MainPID=123", "MainPID=0"),
            (
                "InvocationID=0123456789abcdef0123456789abcdef",
                "InvocationID=",
            ),
            ("/system.slice/", "/system.slice/../"),
            ("Group=root", "Unknown=root"),
            ("Type=notify", "Type=simple"),
            ("NotifyAccess=main", "NotifyAccess=all"),
            ("StatusText=Ingress workers ready", "StatusText=Starting"),
        ] {
            assert!(parse_active(text.replace(before, after).as_bytes()).is_err());
        }
        assert!(parse_active(format!("{text}MainPID=123\n").as_bytes()).is_err());
    }
    #[test]
    fn actual_actor_status_refuses_foreign_supplementary_authority() {
        let unit = ActiveUnit {
            pid: 123,
            invocation: "0123456789abcdef0123456789abcdef".into(),
            start_monotonic: 1,
            cgroup: "/system.slice/aegis-client.service".into(),
            uid: 997,
            gid: 997,
        };
        let base = "Uid:\t997\t997\t997\t997\nGid:\t997\t997\t997\t997\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        let check = |text: &str| process_identity(text, &unit, RuntimePolicy::DedicatedNone);
        assert!(check(&format!("{base}Groups:\t997\n")).is_ok());
        assert!(check(&format!("{base}Groups:\t\n")).is_ok());
        for suffix in [
            "Groups:\t997 27\n",
            "Groups:\t0\n",
            "Groups:\tbad\n",
            "Groups:\t997\nGroups:\t997\n",
            "",
        ] {
            assert!(check(&format!("{base}{suffix}")).is_err());
        }
        let good = format!("{base}Groups:\t997\n");
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            for value in ["0000000000000001", "bad", "-1", "0"] {
                assert!(check(&good.replace(
                    &format!("{key}:\t0000000000000000"),
                    &format!("{key}:\t{value}")
                ))
                .is_err());
            }
            assert!(check(&format!("{good}{key}:\t0000000000000000\n")).is_err());
            assert!(check(&good.replace(&format!("{key}:\t0000000000000000\n"), "")).is_err());
        }
        assert!(check(&good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")).is_err());
        assert!(check(&format!("{good}NoNewPrivs:\t1\n")).is_err());
        assert!(check(&good.replace("NoNewPrivs:\t1\n", "")).is_err());
        let bind = good.replace("0000000000000000", "0000000000000400");
        assert!(process_identity(&bind, &unit, RuntimePolicy::DedicatedBind).is_ok());
        assert!(process_identity(
            &bind.replace("0000000000000400", "0000000000001400"),
            &unit,
            RuntimePolicy::DedicatedBind
        )
        .is_err());
        assert!(process_identity(&good, &unit, RuntimePolicy::Root).is_err());
    }
    #[test]
    #[ignore = "requires disposable root Linux with cgroup2 and admitted actual running executable"]
    fn actual_proc_fd_custody_binds_running_binary_and_exact_command_line() {
        use crate::profile_auto_install_receipt::CapturedBinary;
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "never silently skip native custody"
        );
        let executable = std::env::current_exe().unwrap();
        let captured = CapturedBinary::capture(&executable, 0, true).unwrap();
        let generation: BinaryGeneration =
            serde_json::from_slice(&captured.generation_bytes().unwrap()).unwrap();
        let proc_root = directory(&root().unwrap(), "proc").unwrap();
        let pid = unsafe { libc::getpid() };
        let pid_dir = directory(&proc_root, &pid.to_string()).unwrap();
        let group = read(&pid_dir, "cgroup").unwrap();
        let cgroup = group
            .strip_prefix("0::")
            .unwrap()
            .strip_suffix('\n')
            .unwrap();
        let unit = ActiveUnit {
            pid,
            invocation: "proc-only-fixture".into(),
            start_monotonic: 1,
            cgroup: cgroup.into(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        let argv = read(&pid_dir, "cmdline").unwrap().into_bytes();
        let held =
            Process::capture(unit.clone(), &generation, argv.clone(), RuntimePolicy::Root).unwrap();
        held.revalidate(&generation).unwrap();
        let mut changed = argv;
        changed.extend_from_slice(b"unadmitted-argument\0");
        assert!(Process::capture(unit, &generation, changed, RuntimePolicy::Root).is_err());
        captured.revalidate().unwrap();
        // This covers actual low-level process/FD custody only. It neither
        // constructs ActiveGuard nor claims a systemd installation/READY proof.
    }
    #[test]
    fn proc_start_identity_requires_same_pid_nonterminal_state_and_positive_tick() {
        let tail = vec!["0"; 18].join(" ");
        assert_eq!(
            start_ticks(&format!("42 (space and ) name) S {tail} 12 0"), 42).unwrap(),
            12
        );
        assert!(start_ticks(&format!("42 (x) Z {tail} 12 0"), 42).is_err());
        assert!(start_ticks(&format!("42 (x) S {tail} 0 0"), 42).is_err());
        assert!(start_ticks(&format!("42 (x) S {tail} 12 0"), 43).is_err());
    }
}
