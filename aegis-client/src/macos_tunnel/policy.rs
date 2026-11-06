//! VM-only guarded system policy. Refuses custom PF root rules and existing
//! journals. A published receipt records attempted policy setup, not proof that
//! a guard was installed; failures require explicit confirmation/reconciliation.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::net::SocketAddr;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[allow(dead_code)]
#[path = "worker_policy.rs"]
mod worker_policy;
#[allow(unused_imports)]
pub(super) use worker_policy::WorkerPolicy;

const BASE: &str = "/var/db/aegis-macos-utun";
const JOURNAL: &str = "/var/db/aegis-macos-utun/policy.json";
const ANCHOR: &str = "aegis.utun";
const PF_CONFIG: &str = "/etc/pf.conf";
const ROOT_ANCHOR: &str = "anchor \"com.apple/*\"";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Exclusion {
    ip: IpAddr,
    gateway: String,
    created: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Journal {
    schema: String,
    /// Optional for direct/manual VM entry and older receipts. Automated
    /// supervisors may roll back only the receipt carrying their own nonce.
    #[serde(default)]
    supervisor_owner: Option<String>,
    interface: String,
    service: String,
    dns: Vec<String>,
    pf_sha256: String,
    exclusions: Vec<Exclusion>,
    physical_default: String,
    socks_enabled: bool,
    #[serde(default)]
    worker: Option<worker_policy::WorkerReceipt>,
}
fn wait_bounded(child: &mut std::process::Child) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system policy command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn output(binary: &str, args: &[&str]) -> io::Result<String> {
    let mut child = Command::new(binary)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(262145).read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = wait_bounded(&mut child);
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("policy output reader failed"))??;
    if !status?.success() {
        return Err(io::Error::other(format!("{binary} failed")));
    }
    if bytes.len() > 262144 {
        return Err(io::Error::other("policy output limit exceeded"));
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}
fn pf_input(args: &[&str], input: &str) -> io::Result<()> {
    let mut child = Command::new("/sbin/pfctl")
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let status = wait_bounded(&mut child);
    writer
        .join()
        .map_err(|_| io::Error::other("PF input writer failed"))??;
    if !status?.success() {
        return Err(io::Error::other("PF transaction failed"));
    }
    Ok(())
}
/// Parse-only native printer output; does not load rules. Captured output and
/// pipe input are bounded. Native subprocess/reaping remain cooperative.
fn pf_rendered(input: &str) -> io::Result<String> {
    if input.is_empty() || input.len() > 32768 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PF expected rules limit",
        ));
    }
    let mut child = Command::new("/sbin/pfctl")
        .args(["-n", "-v", "-o", "none", "-a", ANCHOR, "-f", "-"])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let input = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(262145).read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = wait_bounded(&mut child);
    let written = writer
        .join()
        .map_err(|_| io::Error::other("PF expected writer failed"))?;
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("PF expected reader failed"))??;
    written?;
    if !status?.success() || bytes.len() > 262144 {
        return Err(io::Error::other("PF expected parse/readback refused"));
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}
fn valid_name(value: &str) -> bool {
    !value.starts_with('-')
        && !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b))
}
fn valid_supervisor_owner(owner: &str) -> bool {
    owner.len() == 32
        && owner
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Public ownership tag, not a credential. Only canonical supervisor nonces
/// may enter the automated disconnect path; there is no empty/manual fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptOwner(String);

impl std::str::FromStr for ReceiptOwner {
    type Err = io::Error;

    fn from_str(owner: &str) -> io::Result<Self> {
        require_receipt_owner(Some(owner), owner)?;
        Ok(Self(owner.to_owned()))
    }
}

impl ReceiptOwner {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

fn require_receipt_owner(stored: Option<&str>, expected: &str) -> io::Result<()> {
    if !valid_supervisor_owner(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid VM supervisor receipt owner",
        ));
    }
    if stored != Some(expected) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "policy receipt does not belong to this supervisor; guard retained",
        ));
    }
    Ok(())
}
pub(super) fn ensure_no_active_receipt() -> io::Result<()> {
    // Reject a dangling symlink too; exists()/try_exists() follow it and would
    // mistake that pre-existing journal name for an available receipt slot.
    match fs::symlink_metadata(JOURNAL) {
        Ok(_) => Err(io::Error::other(
            "a policy receipt already exists; explicit reconciliation required",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
fn admitted_runtime_root(root: &str) -> bool {
    root.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .all(|line| {
            line == "anchor \"com.apple/*\" all"
                || line == "scrub-anchor \"com.apple/*\" all fragment reassemble"
        })
}
fn admitted_state_table(states: &str) -> bool {
    states.trim().is_empty()
}
fn require_empty_state_table() -> io::Result<()> {
    // Root-rule admission alone does not prove that older floating states are
    // absent. Keep their contents private and refuse rather than destroy states
    // that may belong to another service.
    if !admitted_state_table(&output("/sbin/pfctl", &["-ss"])?) {
        return Err(io::Error::other(
            "PF state table is not empty; separate reconciliation required before capture",
        ));
    }
    Ok(())
}
pub(super) fn root_vm() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mac system policy requires root",
        ));
    }
    if !output("/usr/sbin/sysctl", &["-n", "hw.model"])?
        .trim()
        .starts_with("VirtualMac")
    {
        return Err(io::Error::other(
            "experimental packet policy is restricted to a macOS VM",
        ));
    }
    Ok(())
}
fn route(ip: IpAddr) -> io::Result<String> {
    output(
        "/sbin/route",
        &[
            "-n",
            "get",
            if ip.is_ipv6() { "-inet6" } else { "-inet" },
            &ip.to_string(),
        ],
    )
}
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
}
fn full_routes() -> [&'static str; 4] {
    ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
}
fn protected_root(config: &str) -> io::Result<String> {
    if config.lines().filter(|l| l.trim() == ROOT_ANCHOR).count() != 1 {
        return Err(io::Error::other(
            "unsupported PF configuration: standard Apple filter anchor required",
        ));
    }
    for line in config
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if line.starts_with("anchor ") && line != ROOT_ANCHOR
            || line.starts_with("pass ")
            || line.starts_with("block ")
            || line.starts_with("set skip") && line != "set skip on lo0"
        {
            return Err(io::Error::other(
                "custom PF filter/skip configuration requires separate acceptance",
            ));
        }
    }
    Ok(config.replace(
        ROOT_ANCHOR,
        &format!("anchor \"{ANCHOR}\" quick\n{ROOT_ANCHOR}"),
    ))
}
fn read_journal() -> io::Result<Journal> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(JOURNAL)?;
    let meta = file.metadata()?;
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.nlink() != 1 || meta.len() > 65536 {
        return Err(io::Error::other("unsafe policy receipt"));
    }
    let j: Journal = serde_json::from_reader(file).map_err(io::Error::other)?;
    if let Some(worker) = &j.worker {
        worker.validate()?;
    }
    if j.schema != "aegis_macos_utun_vm_v1"
        || j.supervisor_owner
            .as_deref()
            .is_some_and(|owner| !valid_supervisor_owner(owner))
        || !valid_name(&j.service)
        || !j
            .interface
            .strip_prefix("utun")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(io::Error::other("invalid policy receipt"));
    }
    Ok(j)
}
// Historical admission helpers may test this refusal, but cannot obtain a
// generic policy owner or activate native policy alongside WorkerPolicy.
#[cfg(test)]
pub(super) fn refuse_generic_policy(
    _interface: &str,
    _service: &str,
    _pins: &[SocketAddr],
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "generic macOS PF pins are disabled; dedicated owned worker policy is required",
    ))
}
fn default_rows(table: &str) -> io::Result<String> {
    let mut interface_column = None;
    let mut rows = Vec::new();
    for line in table.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"Destination") {
            interface_column = fields.iter().position(|v| *v == "Netif");
        }
        if fields.first() == Some(&"default") {
            let column =
                interface_column.ok_or_else(|| io::Error::other("route table header absent"))?;
            let gateway = fields
                .get(1)
                .ok_or_else(|| io::Error::other("route gateway absent"))?;
            let interface = fields
                .get(column)
                .ok_or_else(|| io::Error::other("route interface absent"))?;
            if interface.starts_with("utun") {
                return Err(io::Error::other("existing VPN default route not admitted"));
            }
            rows.push(format!("{gateway}|{interface}"));
        }
    }
    rows.sort();
    if rows.is_empty() {
        return Err(io::Error::other("physical default routes absent"));
    }
    Ok(rows.join("\n"))
}
fn physical_signature() -> io::Result<String> {
    default_rows(&output("/usr/sbin/netstat", &["-rn"])?)
}
fn remove_capture_routes(j: &Journal) -> io::Result<()> {
    for prefix in full_routes() {
        let ip: IpAddr = prefix.split('/').next().unwrap().parse().unwrap();
        if route(ip)
            .ok()
            .and_then(|v| field(&v, "interface:").map(str::to_owned))
            .as_deref()
            == Some(&j.interface)
        {
            output(
                "/sbin/route",
                &[
                    "-n",
                    "delete",
                    if ip.is_ipv6() { "-inet6" } else { "-inet" },
                    "-net",
                    prefix,
                    "-interface",
                    &j.interface,
                ],
            )?;
        }
    }
    Ok(())
}
pub(super) fn disconnect() -> io::Result<()> {
    disconnect_with_owner(None)
}
pub(super) fn disconnect_owned(owner: &str) -> io::Result<()> {
    // Do not let an invalid expected owner degenerate into manual/global
    // disconnect, including when no tagged receipt is available.
    require_receipt_owner(Some(owner), owner)?;
    disconnect_with_owner(Some(owner))
}
fn disconnect_with_owner(owner: Option<&str>) -> io::Result<()> {
    root_vm()?;
    let mut j = read_journal()?;
    if let Some(owner) = owner {
        // This check precedes every rollback mutation and configuration read.
        // Missing/other tags require the explicit operator disconnect instead.
        require_receipt_owner(j.supervisor_owner.as_deref(), owner)?;
    }
    let _lock = if j.worker.is_some() {
        Some(worker_policy::MutationLock::acquire(false)?)
    } else {
        None
    };
    if _lock.is_some() {
        let snapshot = j.clone();
        j = read_journal()?;
        if j != snapshot {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker receipt changed before rollback lock; retry reconciliation",
            ));
        }
        if let Some(owner) = owner {
            require_receipt_owner(j.supervisor_owner.as_deref(), owner)?;
        }
    }
    if j.worker
        .as_ref()
        .is_some_and(|worker| !worker.rollback_admitted())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owned worker exit or retained guard is unconfirmed; policy receipt retained",
        ));
    }
    let config = fs::read_to_string(PF_CONFIG)?;
    if hex::encode(Sha256::digest(config.as_bytes())) != j.pf_sha256 {
        return Err(io::Error::other(
            "PF source changed; explicit reconciliation required",
        ));
    }
    // Do not dismantle a live packet worker behind its back.
    if output("/sbin/ifconfig", &[&j.interface]).is_ok() {
        return Err(io::Error::other("stop the packet worker before disconnect"));
    }
    remove_capture_routes(&j)?;
    let mut dns = vec!["-setdnsservers", j.service.as_str()];
    if j.dns.is_empty() {
        dns.push("Empty");
    } else {
        dns.extend(j.dns.iter().map(String::as_str));
    }
    output("/usr/sbin/networksetup", &dns)?;
    let socks = output(
        "/usr/sbin/networksetup",
        &["-getsocksfirewallproxy", &j.service],
    )?;
    let current_socks = field(&socks, "Enabled:");
    if current_socks != Some("No") && !(j.socks_enabled && current_socks == Some("Yes")) {
        return Err(io::Error::other(
            "system SOCKS state changed; manual reconciliation required",
        ));
    }
    if j.socks_enabled && current_socks == Some("No") {
        output(
            "/usr/sbin/networksetup",
            &["-setsocksfirewallproxystate", &j.service, "on"],
        )?;
    }

    for exclusion in &j.exclusions {
        if exclusion.created {
            let current = route(exclusion.ip)?;
            if field(&current, "gateway:") == Some(&exclusion.gateway)
                && field(&current, "flags:").is_some_and(|f| f.contains("HOST"))
            {
                output(
                    "/sbin/route",
                    &[
                        "-n",
                        "delete",
                        if exclusion.ip.is_ipv6() {
                            "-inet6"
                        } else {
                            "-inet"
                        },
                        "-host",
                        &exclusion.ip.to_string(),
                        &exclusion.gateway,
                    ],
                )?;
            }
        }
    }
    pf_input(&["-f", "-"], &config)?;
    pf_input(&["-a", ANCHOR, "-f", "-"], "")?;
    // Keep PF enabled: never disable a global firewall owned by other services.
    fs::rename(
        JOURNAL,
        format!(
            "{BASE}/disconnected-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos()
        ),
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_disconnect_owner_rejects_malformed_input_before_native_admission() {
        for invalid in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
            " 0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef\n",
        ] {
            assert_eq!(
                invalid.parse::<ReceiptOwner>().unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            // The existing native entry point also refuses malformed input
            // before root/VM checks, receipt reads or any system-policy command.
            assert_eq!(
                disconnect_owned(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn typed_disconnect_owner_preserves_exact_foreign_and_missing_receipt_refusal() {
        let owner: ReceiptOwner = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(owner.as_str(), "0123456789abcdef0123456789abcdef");
        // This is the same gate used by disconnect_with_owner before its
        // first PF/DNS/route mutation; a typed valid input cannot grant a
        // missing or differently tagged receipt automated ownership.
        for stored in [None, Some("fedcba9876543210fedcba9876543210")] {
            assert_eq!(
                require_receipt_owner(stored, owner.as_str())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert!(require_receipt_owner(Some(owner.as_str()), owner.as_str()).is_ok());
    }

    #[test]
    fn automated_rollback_requires_the_exact_valid_receipt_owner() {
        let owner = "0123456789abcdef0123456789abcdef";
        let other = "fedcba9876543210fedcba9876543210";
        assert!(require_receipt_owner(Some(owner), owner).is_ok());
        assert_eq!(
            require_receipt_owner(None, owner).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            require_receipt_owner(Some(other), owner)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        for invalid in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(!valid_supervisor_owner(invalid));
            assert_eq!(
                require_receipt_owner(Some(invalid), invalid)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
    #[test]
    fn legacy_receipt_remains_readable_without_granting_automated_ownership() {
        let legacy: Journal = serde_json::from_value(serde_json::json!({
            "schema": "aegis_macos_utun_vm_v1",
            "interface": "utun12",
            "service": "Ethernet",
            "dns": [],
            "pf_sha256": "0".repeat(64),
            "exclusions": [],
            "physical_default": "192.0.2.1|en0",
            "socks_enabled": false,
        }))
        .unwrap();
        assert!(legacy.supervisor_owner.is_none());
        assert!(require_receipt_owner(
            legacy.supervisor_owner.as_deref(),
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }
    #[test]
    fn admits_stock_apple_scrub_but_rejects_custom_runtime_rules() {
        let stock =
            "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
        assert!(admitted_runtime_root(stock));
        assert!(admitted_runtime_root("anchor \"com.apple/*\" all\n"));
        assert!(!admitted_runtime_root(&format!("{stock}pass out all\n")));
        assert!(!admitted_runtime_root(
            &stock.replace("com.apple/*", "other/*")
        ));
        assert!(!admitted_runtime_root(
            &stock.replace("fragment reassemble", "no-df")
        ));
    }
    #[test]
    fn state_admission_requires_an_empty_table_even_for_a_stock_root() {
        assert!(admitted_runtime_root("anchor \"com.apple/*\" all\n"));
        assert!(admitted_state_table(""));
        assert!(admitted_state_table(" \t\n"));
        // Admission cares only about emptiness, never a guess about which
        // private address/flow belongs to another application or service.
        assert!(!admitted_state_table(
            "all tcp 192.0.2.1:12345 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED\n"
        ));
        assert!(!admitted_state_table(
            "all udp 192.0.2.1:12345 -> 198.51.100.1:53 MULTIPLE:MULTIPLE\n"
        ));
    }
    #[test]
    fn generic_policy_refuses_before_native_commands_even_with_valid_pins() {
        assert_eq!(
            refuse_generic_policy("utun12", "Ethernet", &["192.0.2.9:443".parse().unwrap()])
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[test]
    fn default_signature_ignores_capture_but_detects_gateway_change() {
        let before = "Destination Gateway Flags Netif Expire\ndefault 192.168.1.1 UGSc en0\n";
        let after = format!("{before}0/1 198.19.255.2 USc utun9\n");
        assert_eq!(default_rows(before).unwrap(), default_rows(&after).unwrap());
        assert_ne!(
            default_rows(before).unwrap(),
            default_rows(&before.replace("192.168.1.1", "192.168.2.1")).unwrap()
        );
        assert!(default_rows(&before.replace("en0", "utun9")).is_err());
    }
    #[test]
    fn rejects_custom_filter_or_skip() {
        assert!(protected_root("set skip on en0\nanchor \"com.apple/*\"\n").is_err());
        assert!(protected_root("pass out all\nanchor \"com.apple/*\"\n").is_err());
        assert!(protected_root("anchor \"com.apple/*\"\n")
            .unwrap()
            .starts_with("anchor \"aegis.utun\" quick"));
    }
}
