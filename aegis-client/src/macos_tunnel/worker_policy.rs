//! Dedicated-worker PF phase consumer. Source-staged: no installed CLI caller.
//! Native pfctl parsing, socket lookup and live bilateral isolation still require
//! a separate VM acceptance. Successful command dispatch is not that proof.
use super::super::{
    worker_accounts::{self, VerifiedAccount},
    worker_launch::{
        CaptureAdmission, ConfirmedWorkerExit, OwnedNetworkWorker, PreparedIdentityEvent,
    },
};
use super::{
    admitted_runtime_root, ensure_no_active_receipt, field, full_routes, output, pf_input,
    pf_rendered, physical_signature, protected_root, read_journal, remove_capture_routes,
    require_empty_state_table, require_receipt_owner, root_vm, valid_name, Exclusion, Journal,
    ANCHOR, BASE, JOURNAL, PF_CONFIG,
};
use aegis_core::tunnel_policy::{ANCHOR_V4, CLIENT_V4, CLIENT_V6};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
};
const MAX_PINS: usize = 32;
const LOCK: &str = "/var/db/aegis-macos-utun/policy.lock";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    BootstrapAuthority,
    RelayEgress,
    CaptureActive,
    RetainedGuard,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    endpoint: SocketAddr,
    interface: String,
    gateway: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerBinding {
    pid: u32,
    generation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerReceipt {
    account: String,
    uid: u32,
    gid: u32,
    phase: Phase,
    binding: Option<WorkerBinding>,
    exit_confirmed: bool,
    authority: Vec<Pin>,
    relay: Vec<Pin>,
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "dedicated worker policy admission rejected; reconciliation required",
    )
}
fn valid_identity(account: &str, uid: u32, gid: u32) -> bool {
    account.starts_with("_aegis_")
        && (8..=64).contains(&account.len())
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && ![0, 65534, u32::MAX - 1, u32::MAX].contains(&uid)
        && ![0, 65534, u32::MAX - 1, u32::MAX].contains(&gid)
}
fn physical_interface(interface: &str) -> bool {
    // This VM experiment admits Ethernet interfaces only. Other adapters and
    // tunnel/bridge names require separate native classification/acceptance.
    interface.len() <= 15
        && interface
            .strip_prefix("en")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}
fn valid_endpoint(endpoint: SocketAddr) -> bool {
    endpoint.port() != 0
        && !endpoint.ip().is_unspecified()
        && !endpoint.ip().is_loopback()
        && !endpoint.ip().is_multicast()
        && !matches!(endpoint.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        && !matches!(endpoint, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
}
fn valid_gateway(gateway: &str, interface: &str) -> bool {
    let (ip, scope) = gateway
        .split_once('%')
        .map_or((gateway, None), |(i, s)| (i, Some(s)));
    ip.parse::<IpAddr>().is_ok() && scope.is_none_or(|scope| scope == interface)
}
impl WorkerReceipt {
    pub(super) fn validate(&self) -> io::Result<()> {
        if !valid_identity(&self.account, self.uid, self.gid) {
            return Err(denied());
        }
        if self
            .binding
            .as_ref()
            .is_some_and(|b| b.pid == 0 || !super::valid_supervisor_owner(&b.generation))
            || self.exit_confirmed && self.binding.is_none()
            || matches!(self.phase, Phase::RelayEgress | Phase::CaptureActive)
                && self.binding.is_none()
        {
            return Err(denied());
        }
        for pins in [&self.authority, &self.relay] {
            if pins.is_empty() || pins.len() > MAX_PINS {
                return Err(denied());
            }
            for (index, pin) in pins.iter().enumerate() {
                if !valid_endpoint(pin.endpoint)
                    || !physical_interface(&pin.interface)
                    || !valid_gateway(&pin.gateway, &pin.interface)
                    || pins[..index].iter().any(|old| old.endpoint == pin.endpoint)
                {
                    return Err(denied());
                }
            }
        }
        // A host exclusion has a single physical gateway. Inconsistent route
        // observations for the same address cannot become an ambiguous rule.
        for a in &self.authority {
            for r in &self.relay {
                if a.endpoint.ip() == r.endpoint.ip()
                    && (a.interface != r.interface || a.gateway != r.gateway)
                {
                    return Err(denied());
                }
            }
        }
        Ok(())
    }
    pub(super) fn rollback_admitted(&self) -> bool {
        self.phase == Phase::RetainedGuard && self.exit_confirmed && self.binding.is_some()
    }
    fn matches(&self, account: &VerifiedAccount) -> bool {
        self.account == account.name && (self.uid, self.gid) == account.admission.ids()
    }
}
fn fresh_account(account: &VerifiedAccount) -> io::Result<()> {
    let current = worker_accounts::discover(&account.name)?;
    if current.name != account.name || current.admission.ids() != account.admission.ids() {
        return Err(denied());
    }
    Ok(())
}
fn pins(endpoints: &[SocketAddr]) -> io::Result<Vec<Pin>> {
    if endpoints.is_empty() || endpoints.len() > MAX_PINS {
        return Err(denied());
    }
    let mut result = Vec::new();
    for endpoint in endpoints {
        if !valid_endpoint(*endpoint) || result.iter().any(|p: &Pin| p.endpoint == *endpoint) {
            return Err(denied());
        }
        let route = super::route(endpoint.ip())?;
        let interface = field(&route, "interface:").ok_or_else(denied)?;
        let gateway = field(&route, "gateway:").ok_or_else(denied)?;
        if !physical_interface(interface) || !valid_gateway(gateway, interface) {
            return Err(denied());
        }
        result.push(Pin {
            endpoint: *endpoint,
            interface: interface.into(),
            gateway: gateway.into(),
        });
    }
    Ok(result)
}
fn rules(interface: &str, worker: &WorkerReceipt) -> io::Result<String> {
    worker.validate()?;
    if interface.len() > 15
        || !interface
            .strip_prefix("utun")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(denied());
    }
    let mut result = String::from("pass quick on lo0 all no state\n");
    if worker.phase == Phase::CaptureActive {
        result.push_str(&format!("pass quick on {interface} all no state\n"));
    }
    let active: &[Pin] = match worker.phase {
        Phase::BootstrapAuthority => &worker.authority,
        Phase::RelayEgress | Phase::CaptureActive => &worker.relay,
        Phase::RetainedGuard => &[],
    };
    for pin in active {
        let family = if pin.endpoint.is_ipv6() {
            "inet6"
        } else {
            "inet"
        };
        result.push_str(&format!("pass out quick on {} {family} proto tcp from any to {} port {} user = {} flags any no state\n", pin.interface, pin.endpoint.ip(), pin.endpoint.port(), worker.uid));
        result.push_str(&format!("pass in quick on {} {family} proto tcp from {} port {} to any user = {} flags any no state\n", pin.interface, pin.endpoint.ip(), pin.endpoint.port(), worker.uid));
    }
    // These link-local control packets have no TCP/UDP socket UID. They never
    // grant DNS/application UDP or general ICMP forwarding. No rule may create
    // an incoming state that subsequently skips the outgoing UID check.
    result.push_str("pass out quick inet6 proto icmp6 to { fe80::/10, ff02::/16 } icmp6-type { neighbrsol, neighbradv, routersol } no state\npass in quick inet6 proto icmp6 from fe80::/10 to { fe80::/10, ff02::/16 } icmp6-type { neighbrsol, neighbradv, routeradv } no state\nblock drop quick all\n");
    Ok(result)
}
fn active_root(root: &str) -> bool {
    let mut filter = Vec::new();
    for line in root.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("scrub-anchor ") {
            if line != "scrub-anchor \"com.apple/*\" all fragment reassemble" {
                return false;
            }
        } else {
            filter.push(line);
        }
    }
    matches!(
        filter.as_slice(),
        [
            "anchor \"aegis.utun\" quick all",
            "anchor \"com.apple/*\" all"
        ] | [
            "anchor \"aegis.utun\" all quick",
            "anchor \"com.apple/*\" all"
        ]
    )
}
fn empty_apple_anchors(text: &str, translation: bool) -> bool {
    let mut depth = 0usize;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line == "}" {
            let Some(next) = depth.checked_sub(1) else {
                return false;
            };
            depth = next;
            continue;
        }
        let (line, opened) = line
            .strip_suffix('{')
            .map_or((line, false), |line| (line.trim(), true));
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 && fields.len() != 5 {
            return false;
        }
        let Some(name) = fields[1]
            .strip_prefix('"')
            .and_then(|name| name.strip_suffix('"'))
        else {
            return false;
        };
        if !name.starts_with("com.apple/")
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/.*_-".contains(&b))
            || fields[2] != "all"
        {
            return false;
        }
        if translation {
            if !["nat-anchor", "rdr-anchor"].contains(&fields[0]) || fields.len() != 3 {
                return false;
            }
        } else if fields[0] == "scrub-anchor" {
            if fields.len() != 5 || fields[3..] != ["fragment", "reassemble"] {
                return false;
            }
        } else if fields[0] != "anchor" || fields.len() != 3 {
            return false;
        }
        if opened {
            depth += 1;
        }
        if depth > 32 {
            return false;
        }
    }
    depth == 0
}
fn require_stateless_environment() -> io::Result<()> {
    // PF can create states for translation or stateful TCP normalization even
    // when a filter pass has no state. Do not guess about nested Apple rules.
    if !empty_apple_anchors(&output("/sbin/pfctl", &["-a", "*", "-sn"])?, true)
        || !empty_apple_anchors(
            &output("/sbin/pfctl", &["-a", "com.apple/*", "-sr"])?,
            false,
        )
    {
        return Err(denied());
    }
    require_empty_state_table()
}
fn current_guard() -> io::Result<()> {
    if !active_root(&output("/sbin/pfctl", &["-sr"])?)
        || !output("/sbin/pfctl", &["-s", "info"])?.contains("Status: Enabled")
    {
        return Err(denied());
    }
    require_stateless_environment()
}
fn native_address(text: &str) -> bool {
    let (ip, prefix) = text
        .split_once('/')
        .map_or((text, None), |(a, p)| (a, Some(p)));
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return text == "any";
    };
    prefix.is_none_or(|p| {
        p.parse::<u8>()
            .is_ok_and(|p| p <= if ip.is_ipv6() { 128 } else { 32 })
    })
}
/// Only the simple printer grammar used by our generated rules is understood.
/// Unknown counters, anchors, tables, flags, rule options or diagnostics refuse.
/// No vendor hostname/service/user-name normalization is guessed here.
fn native_rule(fields: &[&str]) -> bool {
    if fields == ["block", "drop", "quick", "all"] {
        return true;
    }
    let Some(fields) = fields.strip_suffix(&["no", "state"]) else {
        return false;
    };
    let flags_any = fields.ends_with(&["flags", "any"]);
    let fields = fields.strip_suffix(&["flags", "any"]).unwrap_or(fields);
    if let ["pass", "quick", "on", interface, "all"] = fields {
        return *interface == "lo0"
            || interface
                .strip_prefix("utun")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    }
    if fields.len() == 18
        && fields[0] == "pass"
        && ["in", "out"].contains(&fields[1])
        && fields[2] == "quick"
        && fields[3] == "on"
        && physical_interface(fields[4])
        && ["inet", "inet6"].contains(&fields[5])
        && fields[6..8] == ["proto", "tcp"]
        && fields[8] == "from"
        && fields[10] == "to"
        && fields[12..14] == ["port", "="]
        && fields[14].parse::<u16>().is_ok_and(|p| p > 0)
        && fields[15..17] == ["user", "="]
        && fields[17].parse::<u32>().is_ok()
        && native_address(fields[9])
        && native_address(fields[11])
    {
        return true;
    }
    // Inbound rules place the remote port after the source, before `to`.
    if fields.len() == 18
        && fields[0] == "pass"
        && fields[1] == "in"
        && fields[2] == "quick"
        && fields[3] == "on"
        && physical_interface(fields[4])
        && ["inet", "inet6"].contains(&fields[5])
        && fields[6..8] == ["proto", "tcp"]
        && fields[8] == "from"
        && fields[10..12] == ["port", "="]
        && fields[12].parse::<u16>().is_ok_and(|p| p > 0)
        && fields[13] == "to"
        && fields[15..17] == ["user", "="]
        && fields[17].parse::<u32>().is_ok()
        && native_address(fields[9])
        && native_address(fields[14])
    {
        return true;
    }
    if flags_any {
        return false;
    }
    fields.len() == 12
        && fields[0] == "pass"
        && ["in", "out"].contains(&fields[1])
        && fields[2..5] == ["quick", "inet6", "proto"]
        && ["icmp6", "ipv6-icmp"].contains(&fields[5])
        && fields[6] == "from"
        && fields[8] == "to"
        && native_address(fields[7])
        && native_address(fields[9])
        && fields[10] == "icmp6-type"
        && [
            "neighbrsol",
            "neighbradv",
            "routersol",
            "routeradv",
            "133",
            "134",
            "135",
            "136",
        ]
        .contains(&fields[11])
}
fn native_anchor(text: &str) -> io::Result<Vec<String>> {
    if text.is_empty()
        || text.len() > 262144
        || !text.is_ascii()
        || text
            .bytes()
            .any(|b| b.is_ascii_control() && !b"\n\r\t".contains(&b))
    {
        return Err(denied());
    }
    let mut result = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.len() > 2048 || result.len() >= 256 {
            return Err(denied());
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if !native_rule(&fields) {
            return Err(denied());
        }
        result.push(fields.join(" "));
    }
    if result.is_empty()
        || result
            .last()
            .is_none_or(|line| line != "block drop quick all")
    {
        return Err(denied());
    }
    Ok(result)
}
fn require_anchor_pair(expected: &str, actual: &str) -> io::Result<()> {
    if native_anchor(expected)? != native_anchor(actual)? {
        return Err(denied());
    }
    Ok(())
}
fn confirm_anchor(expected_rules: &str) -> io::Result<()> {
    let expected = pf_rendered(expected_rules)?;
    let actual = output("/sbin/pfctl", &["-a", ANCHOR, "-sr"])?;
    require_anchor_pair(&expected, &actual)
}
fn current_phase_guard(expected_rules: &str) -> io::Result<()> {
    current_guard()?;
    confirm_anchor(expected_rules)
}
fn phase_allowed(current: Phase, next: Phase) -> bool {
    matches!(
        (current, next),
        (Phase::BootstrapAuthority, Phase::RelayEgress)
            | (Phase::RelayEgress, Phase::CaptureActive)
            | (_, Phase::RetainedGuard)
    )
}

/// Nonblocking flock serializes this source's cooperating cross-process PF,
/// journal and rollback callers. It is not a kernel transaction or root lockout.
pub(super) struct MutationLock(File);
impl MutationLock {
    pub(super) fn acquire(create: bool) -> io::Result<Self> {
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(LOCK)
        };
        let file = if create {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(LOCK)
            {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => open()?,
                Err(e) => return Err(e),
            }
        } else {
            open()?
        };
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 {
            return Err(denied());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "owned policy mutation already active",
            ));
        }
        Ok(Self(file))
    }
}
impl Drop for MutationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn store(journal: &Journal) -> io::Result<()> {
    let temporary = format!(
        "{BASE}/policy-{}.tmp",
        hex::encode(rand::random::<[u8; 16]>())
    );
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, journal).map_err(io::Error::other)?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, JOURNAL)?;
        File::open(BASE)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
fn base() -> io::Result<()> {
    match fs::create_dir(BASE) {
        Ok(()) => fs::set_permissions(BASE, fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(BASE)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(denied());
    }
    Ok(())
}

trait PhaseBackend {
    fn confirm(&mut self, expected_rules: &str) -> io::Result<()>;
    fn dry_run(&mut self, rules: &str) -> io::Result<()>;
    fn load(&mut self, rules: &str) -> io::Result<()>;
    fn persist(&mut self, journal: &Journal) -> io::Result<()>;
}
struct SystemBackend;
impl PhaseBackend for SystemBackend {
    fn confirm(&mut self, expected_rules: &str) -> io::Result<()> {
        current_phase_guard(expected_rules)
    }
    fn dry_run(&mut self, rules: &str) -> io::Result<()> {
        pf_input(&["-n", "-o", "none", "-a", ANCHOR, "-f", "-"], rules)
    }
    fn load(&mut self, rules: &str) -> io::Result<()> {
        pf_input(&["-o", "none", "-a", ANCHOR, "-f", "-"], rules)
    }
    fn persist(&mut self, journal: &Journal) -> io::Result<()> {
        store(journal)
    }
}
/// Shared actual publication ordering, injectable only for source regression.
/// A failed/unknown load is treated as potentially applied. Restriction is
/// confirmed and persisted before the original error can be returned; failure
/// of recovery reports INCOMPLETE and never says rollback succeeded.
fn publish_phase(
    journal: &mut Journal,
    next: Phase,
    binding: Option<WorkerBinding>,
    mut permission: impl FnMut() -> io::Result<()>,
    backend: &mut impl PhaseBackend,
) -> io::Result<()> {
    let mut attempt = journal.clone();
    let worker = attempt.worker.as_mut().ok_or_else(denied)?;
    if !phase_allowed(worker.phase, next) || worker.exit_confirmed && next != Phase::RetainedGuard {
        return Err(denied());
    }
    if next == Phase::RelayEgress {
        let binding = binding.ok_or_else(denied)?;
        if worker.exit_confirmed || worker.binding.as_ref() != Some(&binding) {
            return Err(denied());
        }
        worker.binding = Some(binding);
    } else if binding.is_some() {
        return Err(denied());
    }
    worker.phase = next;
    let requested = rules(
        &attempt.interface,
        attempt.worker.as_ref().ok_or_else(denied)?,
    )?;
    let current = rules(
        &journal.interface,
        journal.worker.as_ref().ok_or_else(denied)?,
    )?;
    backend.confirm(&current)?;
    backend.dry_run(&requested)?;
    backend.confirm(&current)?;
    permission()?;
    let result = (|| {
        backend.load(&requested)?;
        backend.confirm(&requested)?;
        permission()?;
        backend.persist(&attempt)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            *journal = attempt;
            Ok(())
        }
        Err(original) => {
            let mut retained = journal.clone();
            retained.worker.as_mut().ok_or_else(denied)?.phase = Phase::RetainedGuard;
            let restrictive = rules(
                &retained.interface,
                retained.worker.as_ref().ok_or_else(denied)?,
            )?;
            let recovery = (|| {
                backend.dry_run(&restrictive)?;
                backend.load(&restrictive)?;
                backend.confirm(&restrictive)?;
                backend.persist(&retained)?;
                Ok::<(), io::Error>(())
            })();
            if recovery.is_err() {
                return Err(io::Error::other("INCOMPLETE: worker phase restriction or receipt confirmation failed; retain owned guard and reconcile"));
            }
            *journal = retained;
            Err(original)
        }
    }
}

fn require_current_receipt(cached: &Journal, current: &Journal, owner: &str) -> io::Result<()> {
    require_receipt_owner(cached.supervisor_owner.as_deref(), owner)?;
    require_receipt_owner(current.supervisor_owner.as_deref(), owner)?;
    if cached != current {
        return Err(denied());
    }
    Ok(())
}

pub(in crate::macos_tunnel) struct WorkerPolicy {
    journal: Journal,
}
impl WorkerPolicy {
    /// Only native discovery can supply this account. Numeric IPs are supplied
    /// by the validated public runtime profile; this API does not infer names.
    pub(in crate::macos_tunnel) fn prepare_worker(
        interface: &str,
        service: &str,
        account: &VerifiedAccount,
        owner: &str,
        authority: &[SocketAddr],
        relay: &[SocketAddr],
    ) -> io::Result<Self> {
        require_receipt_owner(Some(owner), owner)?;
        if !valid_name(service) {
            return Err(denied());
        }
        fresh_account(account)?;
        root_vm()?;
        ensure_no_active_receipt()?;
        let (uid, gid) = account.admission.ids();
        let worker = WorkerReceipt {
            account: account.name.clone(),
            uid,
            gid,
            phase: Phase::BootstrapAuthority,
            binding: None,
            exit_confirmed: false,
            authority: pins(authority)?,
            relay: pins(relay)?,
        };
        let guard = rules(interface, &worker)?;
        let routes = output("/usr/sbin/netstat", &["-rn"])?;
        if routes.lines().any(|l| {
            l.split_whitespace().next().is_some_and(|v| {
                [
                    "0/1",
                    "0.0.0.0/1",
                    "128.0/1",
                    "128.0.0.0/1",
                    "::/1",
                    "8000::/1",
                ]
                .contains(&v)
            })
        }) {
            return Err(denied());
        }
        let config = fs::read_to_string(PF_CONFIG)?;
        let protected = protected_root(&config)?;
        let runtime_root = output("/sbin/pfctl", &["-sr"])?;
        if runtime_root.trim().is_empty() || !admitted_runtime_root(&runtime_root) {
            return Err(denied());
        }
        require_stateless_environment()?;
        let socks = output(
            "/usr/sbin/networksetup",
            &["-getsocksfirewallproxy", service],
        )?;
        let socks_enabled = match field(&socks, "Enabled:") {
            Some("Yes") => true,
            Some("No") => false,
            _ => return Err(denied()),
        };
        for command in ["-getwebproxy", "-getsecurewebproxy", "-getautoproxyurl"] {
            if field(
                &output("/usr/sbin/networksetup", &[command, service])?,
                "Enabled:",
            ) != Some("No")
            {
                return Err(denied());
            }
        }
        let dns = output("/usr/sbin/networksetup", &["-getdnsservers", service])?;
        let dns = if dns.contains("aren't any DNS Servers") {
            vec![]
        } else {
            dns.lines()
                .map(str::trim)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        if dns.len() > 16 || dns.iter().any(|v| v.parse::<IpAddr>().is_err()) {
            return Err(denied());
        }
        let mut exclusions = Vec::new();
        for pin in worker.authority.iter().chain(worker.relay.iter()) {
            if exclusions
                .iter()
                .any(|v: &Exclusion| v.ip == pin.endpoint.ip())
            {
                continue;
            }
            let physical = super::route(pin.endpoint.ip())?;
            if field(&physical, "interface:") != Some(&pin.interface)
                || field(&physical, "gateway:") != Some(&pin.gateway)
            {
                return Err(denied());
            }
            exclusions.push(Exclusion {
                ip: pin.endpoint.ip(),
                gateway: pin.gateway.clone(),
                created: !field(&physical, "flags:").is_some_and(|f| f.contains("HOST")),
            });
        }
        pf_input(&["-n", "-o", "none", "-a", ANCHOR, "-f", "-"], &guard)?;
        pf_input(&["-n", "-f", "-"], &protected)?;
        base()?;
        let _lock = MutationLock::acquire(true)?;
        ensure_no_active_receipt()?;
        fresh_account(account)?;
        require_stateless_environment()?;
        let journal = Journal {
            schema: "aegis_macos_utun_vm_v1".into(),
            supervisor_owner: Some(owner.into()),
            interface: interface.into(),
            service: service.into(),
            dns,
            pf_sha256: hex::encode(Sha256::digest(config.as_bytes())),
            exclusions,
            physical_default: physical_signature()?,
            socks_enabled,
            worker: Some(worker),
        };
        let mut receipt = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(JOURNAL)?;
        serde_json::to_writer(&mut receipt, &journal).map_err(io::Error::other)?;
        receipt.sync_all()?;
        let setup = (|| {
            pf_input(&["-o", "none", "-a", ANCHOR, "-f", "-"], &guard)?;
            pf_input(&["-f", "-"], &protected)?;
            output("/sbin/pfctl", &["-e"]).or_else(|error| {
                if output("/sbin/pfctl", &["-s", "info"])?.contains("Status: Enabled") {
                    Ok(String::new())
                } else {
                    Err(error)
                }
            })?;
            current_phase_guard(&guard)?;
            // No utun routes/DNS change in bootstrap. Exclusion routes are owned
            // separately and never grant physical permission without a UID rule.
            for e in &journal.exclusions {
                if e.created {
                    output(
                        "/sbin/route",
                        &[
                            "-n",
                            "add",
                            if e.ip.is_ipv6() { "-inet6" } else { "-inet" },
                            "-host",
                            &e.ip.to_string(),
                            &e.gateway,
                        ],
                    )?;
                }
            }
            Self {
                journal: journal.clone(),
            }
            .check_routes()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(original) = setup {
            // Worker has not been launched and capture routes were not added.
            // Remove attempted authority allowance even if native publication
            // only partly succeeded; unknown confirmation remains INCOMPLETE.
            let mut retained = journal.clone();
            retained.worker.as_mut().ok_or_else(denied)?.phase = Phase::RetainedGuard;
            let restriction = (|| {
                let guard = rules(interface, retained.worker.as_ref().ok_or_else(denied)?)?;
                pf_input(&["-o", "none", "-a", ANCHOR, "-f", "-"], &guard)?;
                current_phase_guard(&guard)?;
                store(&retained)
            })();
            if restriction.is_err() {
                return Err(io::Error::other("INCOMPLETE: bootstrap guard restriction could not be confirmed; retain receipt and reconcile"));
            }
            return Err(original);
        }
        Ok(Self { journal })
    }
    pub(in crate::macos_tunnel) fn routable_ips(&self) -> Vec<IpAddr> {
        self.journal.exclusions.iter().map(|e| e.ip).collect()
    }
    pub(in crate::macos_tunnel) fn check_physical_route(&self) -> io::Result<()> {
        self.check_routes()
    }
    fn owned(&self, owner: &str) -> io::Result<Journal> {
        require_receipt_owner(self.journal.supervisor_owner.as_deref(), owner)?;
        let current = read_journal()?;
        require_receipt_owner(current.supervisor_owner.as_deref(), owner)?;
        require_current_receipt(&self.journal, &current, owner)?;
        Ok(current)
    }
    fn check_routes(&self) -> io::Result<()> {
        if physical_signature()? != self.journal.physical_default {
            return Err(denied());
        }
        let worker = self.journal.worker.as_ref().ok_or_else(denied)?;
        for pin in worker.authority.iter().chain(worker.relay.iter()) {
            let route = super::route(pin.endpoint.ip())?;
            if field(&route, "interface:") != Some(&pin.interface)
                || field(&route, "gateway:") != Some(&pin.gateway)
            {
                return Err(denied());
            }
        }
        Ok(())
    }
    fn checked_account(
        &self,
        account: &VerifiedAccount,
        worker: &OwnedNetworkWorker,
    ) -> io::Result<()> {
        if !self.journal.worker.as_ref().is_some_and(|w| {
            w.matches(account)
                && !w.exit_confirmed
                && w.binding.as_ref().is_some_and(|binding| {
                    binding.pid == worker.id() && binding.generation == worker.generation_nonce()
                })
        }) || !worker.matches_account(account)
        {
            return Err(denied());
        }
        fresh_account(account)
    }
    fn apply_phase(
        &mut self,
        owner: &str,
        next: Phase,
        binding: Option<WorkerBinding>,
        permission: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut journal = self.owned(owner)?;
        if hex::encode(Sha256::digest(fs::read(PF_CONFIG)?)) != journal.pf_sha256 {
            return Err(denied());
        }
        let result = publish_phase(&mut journal, next, binding, permission, &mut SystemBackend);
        // publish_phase changes the in-memory receipt only after a confirmed
        // successful persist (either requested phase or restrictive recovery).
        self.journal = journal;
        result
    }
    /// Register exact ownership immediately after a successful launch, before
    /// interpreting identity or ACK phases. Missing registration stays unknown.
    pub(in crate::macos_tunnel) fn bind_worker(
        &mut self,
        owner: &str,
        account: &VerifiedAccount,
        worker: &OwnedNetworkWorker,
    ) -> io::Result<()> {
        self.owned(owner)?;
        let _lock = MutationLock::acquire(false)?;
        let mut journal = self.owned(owner)?;
        fresh_account(account)?;
        let current = journal.worker.as_mut().ok_or_else(denied)?;
        if current.phase != Phase::BootstrapAuthority
            || current.binding.is_some()
            || current.exit_confirmed
            || !current.matches(account)
            || !worker.matches_account(account)
            || worker.id() == 0
            || !super::valid_supervisor_owner(worker.generation_nonce())
        {
            return Err(denied());
        }
        current.binding = Some(WorkerBinding {
            pid: worker.id(),
            generation: worker.generation_nonce().into(),
        });
        store(&journal)?;
        self.journal = journal;
        Ok(())
    }
    /// Only a token constructed from the exact owned Child's successful native
    /// reap may admit rollback. Interface/PID absence is never an exit proof.
    pub(in crate::macos_tunnel) fn confirm_worker_exit(
        &mut self,
        owner: &str,
        account: &VerifiedAccount,
        exit: &ConfirmedWorkerExit,
    ) -> io::Result<()> {
        self.owned(owner)?;
        let _lock = MutationLock::acquire(false)?;
        let mut journal = self.owned(owner)?;
        let current = journal.worker.as_mut().ok_or_else(denied)?;
        let binding = current.binding.as_ref().ok_or_else(denied)?;
        if !current.matches(account)
            || !exit.matches_account(account)
            || !exit.matches_binding(binding.pid, &binding.generation)
        {
            return Err(denied());
        }
        current.exit_confirmed = true;
        store(&journal)?;
        self.journal = journal;
        Ok(())
    }
    pub(in crate::macos_tunnel) fn authorize_relay(
        &mut self,
        owner: &str,
        account: &VerifiedAccount,
        event: &PreparedIdentityEvent,
        worker: &mut OwnedNetworkWorker,
    ) -> io::Result<()> {
        self.owned(owner)?;
        let _lock = MutationLock::acquire(false)?;
        self.owned(owner)?;
        self.checked_account(account, worker)?;
        self.check_routes()?;
        if !event.is_current_for(worker)? {
            return Err(denied());
        }
        self.apply_phase(
            owner,
            Phase::RelayEgress,
            Some(WorkerBinding {
                pid: worker.id(),
                generation: worker.generation_nonce().into(),
            }),
            || {
                if event.is_current_for(worker)? {
                    Ok(())
                } else {
                    Err(denied())
                }
            },
        )
    }
    pub(in crate::macos_tunnel) fn activate_capture(
        &mut self,
        owner: &str,
        account: &VerifiedAccount,
        grant: &CaptureAdmission,
        worker: &mut OwnedNetworkWorker,
    ) -> io::Result<()> {
        self.owned(owner)?;
        let _lock = MutationLock::acquire(false)?;
        self.owned(owner)?;
        self.checked_account(account, worker)?;
        self.check_routes()?;
        if !grant.is_current_for(worker)? {
            return Err(denied());
        }
        let result = (|| {
            self.apply_phase(owner, Phase::CaptureActive, None, || {
                if grant.is_current_for(worker)? {
                    Ok(())
                } else {
                    Err(denied())
                }
            })?;
            output(
                "/sbin/ifconfig",
                &[
                    &self.journal.interface,
                    "inet",
                    &CLIENT_V4.to_string(),
                    &ANCHOR_V4.to_string(),
                    "mtu",
                    "1280",
                    "up",
                ],
            )?;
            output(
                "/sbin/ifconfig",
                &[
                    &self.journal.interface,
                    "inet6",
                    &format!("{CLIENT_V6}/128"),
                ],
            )?;
            output(
                "/usr/sbin/networksetup",
                &["-setsocksfirewallproxystate", &self.journal.service, "off"],
            )?;
            output(
                "/usr/sbin/networksetup",
                &["-setdnsservers", &self.journal.service, "9.9.9.9"],
            )?;
            if output(
                "/usr/sbin/networksetup",
                &["-getdnsservers", &self.journal.service],
            )?
            .trim()
                != "9.9.9.9"
            {
                return Err(denied());
            }
            for prefix in full_routes() {
                if !grant.is_current_for(worker)? {
                    return Err(denied());
                }
                output(
                    "/sbin/route",
                    &[
                        "-n",
                        "add",
                        if prefix.contains(':') {
                            "-inet6"
                        } else {
                            "-inet"
                        },
                        "-net",
                        prefix,
                        "-interface",
                        &self.journal.interface,
                    ],
                )?;
            }
            for ip in ["1.1.1.1", "2001:4860:4860::8888"] {
                if field(&super::route(ip.parse().unwrap())?, "interface:")
                    != Some(&self.journal.interface)
                {
                    return Err(denied());
                }
            }
            self.check_routes()?;
            current_phase_guard(&rules(
                &self.journal.interface,
                self.journal.worker.as_ref().ok_or_else(denied)?,
            )?)?;
            if !grant.is_current_for(worker)? {
                return Err(denied());
            }
            Ok(())
        })();
        if result.is_err() {
            // Guard restriction precedes route removal. If either cannot be
            // confirmed, caller must report INCOMPLETE and retain the receipt.
            self.apply_phase(owner, Phase::RetainedGuard, None, || Ok(()))?;
            remove_capture_routes(&self.journal)?;
        }
        result
    }
    pub(in crate::macos_tunnel) fn check_capture(
        &self,
        owner: &str,
        account: &VerifiedAccount,
        grant: &CaptureAdmission,
        worker: &mut OwnedNetworkWorker,
    ) -> io::Result<()> {
        self.owned(owner)?;
        self.checked_account(account, worker)?;
        if self
            .journal
            .worker
            .as_ref()
            .is_none_or(|w| w.phase != Phase::CaptureActive)
        {
            return Err(denied());
        }
        self.check_routes()?;
        current_phase_guard(&rules(
            &self.journal.interface,
            self.journal.worker.as_ref().ok_or_else(denied)?,
        )?)?;
        if !grant.is_current_for(worker)? {
            return Err(denied());
        }
        Ok(())
    }
    pub(in crate::macos_tunnel) fn retain_guard(&mut self, owner: &str) -> io::Result<()> {
        self.owned(owner)?;
        let _lock = MutationLock::acquire(false)?;
        self.apply_phase(owner, Phase::RetainedGuard, None, || Ok(()))?;
        remove_capture_routes(&self.journal)
    }
}
#[cfg(test)]
#[path = "worker_policy_tests.rs"]
mod tests;
