//! Read-only, bounded current network-manager administrative attestation.
//! This proves a current protected service binding, never per-frame authorization.
#[cfg(any(target_os = "linux", test))]
use sha2::{Digest, Sha256};
use std::io;
#[cfg(any(target_os = "linux", test))]
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExpectedManagerBinding {
    pub schema: String,
    pub boot_id: String,
    pub state_sha256: String,
    pub path: String,
    pub inode: String,
    pub invocation: String,
    pin: Option<ManagerPin>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagerPin {
    ifindex: u32,
    dhcp4_server: Option<String>,
    dhcp6_server: Option<String>,
}
struct RequiredNullableString(Option<String>);
impl<'de> serde::Deserialize<'de> for RequiredNullableString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NullableStringVisitor;
        impl serde::de::Visitor<'_> for NullableStringVisitor {
            type Value = RequiredNullableString;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or explicit null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(None))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(Some(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(RequiredNullableString(Some(value)))
            }
        }
        deserializer.deserialize_any(NullableStringVisitor)
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingV1Wire {
    schema: String,
    boot_id: String,
    state_sha256: String,
    path: String,
    inode: String,
    invocation: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingV2Wire {
    schema: String,
    boot_id: String,
    state_sha256: String,
    path: String,
    inode: String,
    invocation: String,
    ifindex: u32,
    dhcp4_server: RequiredNullableString,
    dhcp6_server: RequiredNullableString,
}
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum BindingWire {
    V1(BindingV1Wire),
    V2(BindingV2Wire),
}
impl<'de> serde::Deserialize<'de> for ExpectedManagerBinding {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = <BindingWire as serde::Deserialize>::deserialize(deserializer)?;
        let (base, pin) = match wire {
            BindingWire::V1(value) => {
                if value.schema != "aegis_device_guard_binding_v1" {
                    return Err(serde::de::Error::custom("manager V1 schema mismatch"));
                }
                (value, None)
            }
            BindingWire::V2(value) => {
                if value.schema != "aegis_device_guard_binding_v2" {
                    return Err(serde::de::Error::custom("manager V2 schema mismatch"));
                }
                let pin = ManagerPin {
                    ifindex: value.ifindex,
                    dhcp4_server: value.dhcp4_server.0,
                    dhcp6_server: value.dhcp6_server.0,
                };
                (
                    BindingV1Wire {
                        schema: value.schema,
                        boot_id: value.boot_id,
                        state_sha256: value.state_sha256,
                        path: value.path,
                        inode: value.inode,
                        invocation: value.invocation,
                    },
                    Some(pin),
                )
            }
        };
        Ok(Self {
            schema: base.schema,
            boot_id: base.boot_id,
            state_sha256: base.state_sha256,
            path: base.path,
            inode: base.inode,
            invocation: base.invocation,
            pin,
        })
    }
}
impl serde::Serialize for ExpectedManagerBinding {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(if self.pin.is_some() { 9 } else { 6 }))?;
        map.serialize_entry("schema", &self.schema)?;
        map.serialize_entry("boot_id", &self.boot_id)?;
        map.serialize_entry("state_sha256", &self.state_sha256)?;
        map.serialize_entry("path", &self.path)?;
        map.serialize_entry("inode", &self.inode)?;
        map.serialize_entry("invocation", &self.invocation)?;
        if let Some(pin) = &self.pin {
            map.serialize_entry("ifindex", &pin.ifindex)?;
            map.serialize_entry("dhcp4_server", &pin.dhcp4_server)?;
            map.serialize_entry("dhcp6_server", &pin.dhcp6_server)?;
        }
        map.end()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ManagerProof {
    unit: String,
    binding: ExpectedManagerBinding,
    digest: String,
}
impl ManagerProof {
    pub(super) fn unit(&self) -> &str {
        &self.unit
    }
    pub(super) fn binding(&self) -> &ExpectedManagerBinding {
        &self.binding
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
}
#[cfg(any(target_os = "linux", test))]
fn refuse(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, text)
}
#[cfg(any(target_os = "linux", test))]
fn ensure(ok: bool, text: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(refuse(text))
    }
}
#[cfg(any(target_os = "linux", test))]
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
#[cfg(any(target_os = "linux", test))]
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['\n', '\r', '\0', ' ', '\\'])
        && !path.split('/').any(|s| s == ".." || s == ".")
}

#[cfg(any(target_os = "linux", test))]
fn digest_opened(
    mut reader: impl std::io::Read,
    deadline: std::time::Instant,
) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 32768];
    let mut bytes = 0u64;
    loop {
        ensure(
            std::time::Instant::now() < deadline,
            "role file hashing deadline",
        )?;
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        ensure(bytes <= 67108864, "role file hash bound")?;
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(any(target_os = "linux", test))]
const KEYS: &[&str] = &[
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
    "FragmentPath",
    "DropInPaths",
    "ExecStart",
    "NeedDaemonReload",
    "User",
    "DynamicUser",
];
#[cfg(any(target_os = "linux", test))]
fn parse_unit(bytes: &[u8]) -> io::Result<BTreeMap<String, String>> {
    ensure(bytes.len() <= 32768, "unit readback bound")?;
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("unit readback encoding"))?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| refuse("unit property frame"))?;
        ensure(
            KEYS.contains(&k)
                && !v.contains('\0')
                && map.insert(k.to_owned(), v.to_owned()).is_none(),
            "duplicate or unknown unit property",
        )?;
    }
    ensure(map.len() == KEYS.len(), "incomplete unit properties")?;
    Ok(map)
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Process {
    pid: u32,
    start: u64,
    executable: PathBuf,
    executable_sha256: String,
    executable_device: u64,
    executable_inode: u64,
    argv: Vec<String>,
    cgroup: String,
    uids: [u32; 4],
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    unit: BTreeMap<String, String>,
    process: Process,
    boot: String,
    cgroup_inode: u64,
    cgroup_device: u64,
    files: BTreeMap<PathBuf, String>,
    systemctl_sha256: String,
    account: Account,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Account {
    name: String,
    uid: u32,
    row_sha256: String,
    passwd_sha256: String,
    passwd_device: u64,
    passwd_inode: u64,
}
#[cfg(any(target_os = "linux", test))]
fn configured_account<'a>(name: &str, unit: &'a BTreeMap<String, String>) -> io::Result<&'a str> {
    ensure(
        get(unit, "DynamicUser")? == "no",
        "dynamic manager account refused",
    )?;
    match get(unit, "User")? {
        "" | "root" => Ok("root"),
        "systemd-network" if name == "systemd-networkd.service" => Ok("systemd-network"),
        _ => Err(refuse(
            "manager account is not an allowed loaded unit account",
        )),
    }
}
#[cfg(any(target_os = "linux", test))]
fn local_account(bytes: &[u8], name: &str) -> io::Result<(u32, String)> {
    ensure(
        bytes.len() <= 65536 && !bytes.contains(&0),
        "local passwd bound/frame",
    )?;
    ensure(
        matches!(name, "root" | "systemd-network"),
        "unknown manager local account",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("local passwd encoding"))?;
    let mut rows = Vec::new();
    for row in text.lines() {
        let fields: Vec<_> = row.split(':').collect();
        ensure(
            fields.len() == 7 && !fields[0].is_empty() && !fields[0].contains(char::is_whitespace),
            "local passwd row frame",
        )?;
        let number = |raw: &str| -> io::Result<u32> {
            ensure(
                !raw.is_empty() && raw.bytes().all(|x| x.is_ascii_digit()),
                "local passwd numeric identity",
            )?;
            let value: u32 = raw
                .parse()
                .map_err(|_| refuse("local passwd UID/GID range"))?;
            ensure(
                value.to_string() == raw,
                "noncanonical local passwd identity",
            )?;
            Ok(value)
        };
        let uid = number(fields[2])?;
        let _gid = number(fields[3])?;
        rows.push((fields[0], uid, row));
    }
    let selected: Vec<_> = rows.iter().filter(|r| r.0 == name).collect();
    ensure(
        selected.len() == 1,
        "absent or duplicate local manager account",
    )?;
    let uid = selected[0].1;
    ensure(
        (name == "root" && uid == 0) || (name == "systemd-network" && uid > 0),
        "manager local account UID refused",
    )?;
    ensure(
        rows.iter().filter(|r| r.1 == uid).count() == 1,
        "ambiguous local manager numeric UID",
    )?;
    Ok((uid, hex::encode(Sha256::digest(selected[0].2.as_bytes()))))
}
#[cfg(any(target_os = "linux", test))]
fn process_uids(bytes: &str) -> io::Result<[u32; 4]> {
    let rows: Vec<_> = bytes
        .lines()
        .filter_map(|row| row.strip_prefix("Uid:"))
        .collect();
    ensure(rows.len() == 1, "process UID row ambiguity")?;
    let values: Vec<_> = rows[0].split_whitespace().collect();
    ensure(values.len() == 4, "process UID tuple frame")?;
    let mut result = [0; 4];
    for (slot, raw) in result.iter_mut().zip(values) {
        ensure(
            !raw.is_empty() && raw.bytes().all(|x| x.is_ascii_digit()),
            "process UID numeric frame",
        )?;
        *slot = raw.parse().map_err(|_| refuse("process UID range"))?;
        ensure(slot.to_string() == raw, "process UID canonical frame")?;
    }
    Ok(result)
}
#[cfg(any(target_os = "linux", test))]
fn get<'a>(u: &'a BTreeMap<String, String>, k: &str) -> io::Result<&'a str> {
    u.get(k)
        .map(String::as_str)
        .ok_or_else(|| refuse("missing manager unit field"))
}
#[cfg(any(target_os = "linux", test))]
fn pid(u: &BTreeMap<String, String>, k: &str) -> io::Result<u32> {
    let s = get(u, k)?;
    ensure(
        !s.is_empty() && s.bytes().all(|x| x.is_ascii_digit()),
        "manager PID schema",
    )?;
    s.parse().map_err(|_| refuse("manager PID range"))
}
#[cfg(any(target_os = "linux", test))]
fn binding_schema(unit: &str, b: &ExpectedManagerBinding, state: &str) -> io::Result<()> {
    ensure(
        matches!(unit, "NetworkManager.service" | "systemd-networkd.service"),
        "unknown manager unit",
    )?;
    let pin_valid = match (&*b.schema, &b.pin) {
        ("aegis_device_guard_binding_v1", None) => true,
        ("aegis_device_guard_binding_v2", Some(pin)) => {
            pin.ifindex > 0
                && pin.dhcp4_server.as_deref().is_none_or(|value| {
                    value.parse::<std::net::Ipv4Addr>().is_ok_and(|address| {
                        address.to_string() == value
                            && !address.is_unspecified()
                            && !address.is_multicast()
                            && !address.is_loopback()
                            && !address.is_link_local()
                    })
                })
                && pin.dhcp6_server.as_deref().is_none_or(|value| {
                    value.parse::<std::net::Ipv6Addr>().is_ok_and(|address| {
                        address.to_string() == value
                            && !address.is_unspecified()
                            && !address.is_multicast()
                            && !address.is_loopback()
                    })
                })
        }
        _ => false,
    };
    let boot = &b.boot_id;
    ensure(
        pin_valid
            && hex(state, 64)
            && b.state_sha256 == state
            && boot.len() == 36
            && [8, 13, 18, 23].iter().all(|i| boot.as_bytes()[*i] == b'-')
            && hex(&boot.replace('-', ""), 32)
            && !b.path.is_empty()
            && b.path.len() <= 4096
            && b.path
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.@:/-".contains(&c))
            && b.path
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..")
            && b.path.rsplit('/').next() == Some(unit)
            && hex(&b.invocation, 32)
            && b.inode.parse::<u64>().is_ok_and(|n| n > 0)
            && b.inode.bytes().all(|x| x.is_ascii_digit()),
        "manager binding schema or state refused",
    )
}
#[cfg(any(target_os = "linux", test))]
fn file_paths(u: &BTreeMap<String, String>) -> io::Result<Vec<PathBuf>> {
    let fragment = get(u, "FragmentPath")?;
    ensure(safe_path(fragment), "manager fragment path refused")?;
    let mut paths = vec![PathBuf::from(fragment)];
    for p in get(u, "DropInPaths")?.split_whitespace() {
        ensure(
            safe_path(p) && !paths.iter().any(|v| v == std::path::Path::new(p)),
            "duplicate or unsafe manager drop-in",
        )?;
        paths.push(p.into());
    }
    ensure(paths.len() <= 33, "manager drop-in bound")?;
    Ok(paths)
}
#[cfg(any(target_os = "linux", test))]
fn validate(unit: &str, b: &ExpectedManagerBinding, state: &str, s: &Snapshot) -> io::Result<()> {
    binding_schema(unit, b, state)?;
    let u = &s.unit;
    let account_name = configured_account(unit, u)?;
    ensure(
        s.account.name == account_name
            && ((account_name == "root" && s.account.uid == 0)
                || (account_name == "systemd-network" && s.account.uid > 0))
            && hex(&s.account.row_sha256, 64)
            && hex(&s.account.passwd_sha256, 64)
            && s.account.passwd_device > 0
            && s.account.passwd_inode > 0,
        "manager configured local account proof refused",
    )?;
    ensure(
        get(u, "LoadState")? == "loaded"
            && get(u, "ActiveState")? == "active"
            && get(u, "SubState")? == "running"
            && get(u, "NeedDaemonReload")? == "no"
            && pid(u, "ControlPID")? == 0
            && pid(u, "MainPID")? > 0
            && pid(u, "MainPID")? == s.process.pid
            && get(u, "ControlGroup")? == format!("/{}", b.path)
            && get(u, "InvocationID")? == b.invocation
            && s.boot == b.boot_id
            && s.cgroup_inode.to_string() == b.inode
            && s.cgroup_device > 0
            && s.process.start > 0
            && s.process.uids == [s.account.uid; 4]
            && s.process.cgroup == format!("/{}", b.path)
            && s.process.executable.to_str().is_some_and(safe_path)
            && hex(&s.process.executable_sha256, 64)
            && hex(&s.systemctl_sha256, 64)
            && s.process.executable_inode > 0
            && s.process.executable_device > 0,
        "manager is not the exact current active bound role",
    )?;
    let paths = file_paths(u)?;
    ensure(
        s.files.len() == paths.len()
            && paths
                .iter()
                .all(|p| s.files.get(p).is_some_and(|h| hex(h, 64))),
        "manager unit file inventory or hash refused",
    )
}
#[cfg(any(target_os = "linux", test))]
fn validate_pair(
    unit: &str,
    b: &ExpectedManagerBinding,
    state: &str,
    first: &Snapshot,
    last: &Snapshot,
) -> io::Result<ManagerProof> {
    validate(unit, b, state, first)?;
    validate(unit, b, state, last)?;
    ensure(
        first == last,
        "manager changed between complete observations",
    )?;
    // Digest public administrative metadata, not manager command-line bytes.
    let value = serde_json::json!({"unit":unit,"binding":b,"pid":last.process.pid,"start_ticks":last.process.start,"executable_path":last.process.executable,
 "executable_sha256":last.process.executable_sha256,"executable_device":last.process.executable_device,"executable_inode":last.process.executable_inode,
 "unit_properties_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&last.unit).map_err(|_|refuse("unit digest encoding"))?)),
 "files":last.files,"systemctl_sha256":last.systemctl_sha256,"cgroup_device":last.cgroup_device,
 "account":{"name":last.account.name,"uid":last.account.uid,"row_sha256":last.account.row_sha256,"passwd_sha256":last.account.passwd_sha256,"passwd_device":last.account.passwd_device,"passwd_inode":last.account.passwd_inode},"process_uids":last.process.uids});
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&value).map_err(|_| refuse("manager digest encoding"))?,
    ));
    Ok(ManagerProof {
        unit: unit.into(),
        binding: b.clone(),
        digest,
    })
}
#[cfg(any(target_os = "linux", test))]
fn directory_identity_matches(before: (u64, u64), opened: (u64, u64), after: (u64, u64)) -> bool {
    before.0 > 0 && before.1 > 0 && before == opened && opened == after
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        io::Read,
        os::unix::{fs::MetadataExt, io::AsRawFd, process::CommandExt},
        path::Path,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    fn live(deadline: Instant) -> io::Result<()> {
        ensure(Instant::now() < deadline, "role attestation deadline")
    }
    fn protected_hash(path: &Path, deadline: Instant) -> io::Result<String> {
        live(deadline)?;
        ensure(
            fs::canonicalize(path)? == path,
            "role pin must be canonical",
        )?;
        for ancestor in path.ancestors().skip(1) {
            let m = fs::symlink_metadata(ancestor)?;
            ensure(
                m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
                "manager file ancestor not root protected",
            )?;
        }
        let meta = fs::symlink_metadata(path)?;
        ensure(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == 0
                && meta.mode() & 0o022 == 0
                && meta.len() <= 67108864,
            "role file is not protected regular root file",
        )?;
        let mut f = fs::File::open(path)?;
        let opened = f.metadata()?;
        ensure(
            meta.dev() == opened.dev() && meta.ino() == opened.ino(),
            "role file replaced while opening",
        )?;
        let digest = digest_opened(&mut f, deadline)?;
        let after = f.metadata()?;
        ensure(
            meta.dev() == after.dev()
                && meta.ino() == after.ino()
                && meta.len() == after.len()
                && meta.mtime() == after.mtime()
                && meta.mtime_nsec() == after.mtime_nsec()
                && after.uid() == 0
                && after.mode() & 0o022 == 0
                && after.is_file(),
            "role file changed while hashing",
        )?;
        Ok(digest)
    }
    fn read(path: &Path, limit: u64, deadline: Instant) -> io::Result<Vec<u8>> {
        live(deadline)?;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
        ensure(bytes.len() as u64 <= limit, "role metadata bound")?;
        live(deadline)?;
        Ok(bytes)
    }
    fn text(path: &Path, limit: u64, deadline: Instant) -> io::Result<String> {
        String::from_utf8(read(path, limit, deadline)?)
            .map_err(|_| refuse("role metadata encoding"))
    }
    fn process(pid: u32, deadline: Instant) -> io::Result<Process> {
        ensure(pid > 0, "role PID absent")?;
        let base = PathBuf::from(format!("/proc/{pid}"));
        let stat = text(&base.join("stat"), 8192, deadline)?;
        let end = stat.rfind(')').ok_or_else(|| refuse("role stat frame"))?;
        let start = stat[end + 1..]
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| refuse("role stat missing ticks"))?
            .parse()
            .map_err(|_| refuse("role ticks type"))?;
        let uid = text(&base.join("status"), 16384, deadline)?;
        let uids = process_uids(&uid)?;
        let cg = text(&base.join("cgroup"), 8192, deadline)?;
        let groups: Vec<_> = cg.lines().filter_map(|l| l.strip_prefix("0::")).collect();
        ensure(groups.len() == 1, "unified process cgroup absent")?;
        let exe = fs::read_link(base.join("exe"))?;
        ensure(
            fs::canonicalize(&exe)? == exe,
            "process executable path is not canonical",
        )?;
        let target = fs::symlink_metadata(&exe)?;
        let mut executable_fd = fs::File::open(base.join("exe"))?;
        let metadata = executable_fd.metadata()?;
        ensure(
            target.is_file()
                && !target.file_type().is_symlink()
                && metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.len() <= 67108864
                && target.dev() == metadata.dev()
                && target.ino() == metadata.ino(),
            "process executable fd differs from protected canonical target",
        )?;
        let digest = digest_opened(&mut executable_fd, deadline)?;
        let after = executable_fd.metadata()?;
        let target_after = fs::symlink_metadata(&exe)?;
        let proc_after = fs::metadata(base.join("exe"))?;
        ensure(
            after.uid() == 0
                && after.mode() & 0o022 == 0
                && target_after.uid() == 0
                && target_after.mode() & 0o022 == 0
                && !target_after.file_type().is_symlink()
                && target_after.is_file()
                && after.dev() == metadata.dev()
                && after.ino() == metadata.ino()
                && after.len() == metadata.len()
                && after.mtime() == metadata.mtime()
                && after.mtime_nsec() == metadata.mtime_nsec()
                && target_after.dev() == metadata.dev()
                && target_after.ino() == metadata.ino()
                && proc_after.dev() == metadata.dev()
                && proc_after.ino() == metadata.ino(),
            "process executable identity changed while hashing opened fd",
        )?;
        let raw = read(&base.join("cmdline"), 16384, deadline)?;
        ensure(raw.ends_with(&[0]), "role argv frame")?;
        let argv = raw[..raw.len() - 1]
            .split(|x| *x == 0)
            .map(|b| String::from_utf8(b.to_vec()).map_err(|_| refuse("role argv encoding")))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Process {
            pid,
            start,
            executable: exe,
            executable_sha256: digest,
            executable_device: metadata.dev(),
            executable_inode: metadata.ino(),
            argv,
            cgroup: groups[0].to_owned(),
            uids,
        })
    }
    fn unit(name: &str, deadline: Instant) -> io::Result<(BTreeMap<String, String>, String)> {
        let binary = Path::new("/usr/bin/systemctl");
        let pin = protected_hash(binary, deadline)?;
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new(binary);
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                    || libc::getppid() != parent
                {
                    return Err(refuse("manager helper caller identity changed"));
                }
                Ok(())
            });
        }
        let mut child = command
            .arg("show")
            .arg(name)
            .arg(format!("--property={}", KEYS.join(",")))
            .arg("--no-pager")
            .env("LC_ALL", "C")
            .env("SYSTEMD_PAGER", "")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let result = (|| -> io::Result<_> {
            let mut output = child
                .stdout
                .take()
                .ok_or_else(|| refuse("unit pipe absent"))?;
            let fd = output.as_raw_fd();
            let old = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            ensure(
                old >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, old | libc::O_NONBLOCK) } == 0,
                "unit pipe nonblocking failed",
            )?;
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                live(deadline)?;
                match output.read(&mut buffer) {
                    Ok(0) => {}
                    Ok(n) => {
                        bytes.extend_from_slice(&buffer[..n]);
                        ensure(bytes.len() <= 32768, "unit output bound")?
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if let Some(status) = child.try_wait()? {
                    ensure(status.success(), "systemctl did not confirm unit")?;
                    loop {
                        match output.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                bytes.extend_from_slice(&buffer[..n]);
                                ensure(bytes.len() <= 32768, "unit output bound")?
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        }
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            ensure(
                protected_hash(binary, deadline)? == pin,
                "systemctl changed during readback",
            )?;
            Ok((parse_unit(&bytes)?, pin))
        })();
        if result.is_err() {
            let _ = child.kill();
            let until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < until {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        result
    }

    fn account(
        name: &str,
        unit: &BTreeMap<String, String>,
        deadline: Instant,
    ) -> io::Result<Account> {
        let name = configured_account(name, unit)?;
        let path = Path::new("/etc/passwd");
        let before = fs::symlink_metadata(path)?;
        ensure(before.len() <= 65536, "local account metadata bound")?;
        let pinned = protected_hash(path, deadline)?;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let opened = file.metadata()?;
        ensure(
            opened.is_file()
                && opened.uid() == 0
                && opened.mode() & 0o022 == 0
                && (opened.dev(), opened.ino()) == (before.dev(), before.ino()),
            "local passwd protected FD identity",
        )?;
        let mut bytes = Vec::new();
        (&mut file).take(65537).read_to_end(&mut bytes)?;
        live(deadline)?;
        ensure(
            bytes.len() <= 65536
                && bytes.len() as u64 == opened.len()
                && hex::encode(Sha256::digest(&bytes)) == pinned,
            "local passwd changed during opened read",
        )?;
        let after = file.metadata()?;
        let final_path = fs::symlink_metadata(path)?;
        ensure(
            after.is_file()
                && final_path.is_file()
                && !final_path.file_type().is_symlink()
                && after.uid() == 0
                && final_path.uid() == 0
                && after.mode() & 0o022 == 0
                && final_path.mode() & 0o022 == 0
                && (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec(),
                ) == (
                    opened.dev(),
                    opened.ino(),
                    opened.len(),
                    opened.mtime(),
                    opened.mtime_nsec(),
                    opened.ctime(),
                    opened.ctime_nsec(),
                )
                && (
                    final_path.dev(),
                    final_path.ino(),
                    final_path.len(),
                    final_path.mtime(),
                    final_path.mtime_nsec(),
                    final_path.ctime(),
                    final_path.ctime_nsec(),
                ) == (
                    opened.dev(),
                    opened.ino(),
                    opened.len(),
                    opened.mtime(),
                    opened.mtime_nsec(),
                    opened.ctime(),
                    opened.ctime_nsec(),
                ),
            "local passwd file replacement or drift",
        )?;
        let (uid, row_sha256) = local_account(&bytes, name)?;
        Ok(Account {
            name: name.into(),
            uid,
            row_sha256,
            passwd_sha256: pinned,
            passwd_device: opened.dev(),
            passwd_inode: opened.ino(),
        })
    }
    fn snapshot(name: &str, expected_path: &str, deadline: Instant) -> io::Result<Snapshot> {
        let (unit, systemctl_sha256) = unit(name, deadline)?;
        let account = account(name, &unit, deadline)?;
        let role = process(pid(&unit, "MainPID")?, deadline)?;
        let cg = get(&unit, "ControlGroup")?;
        ensure(cg == format!("/{expected_path}"), "foreign manager cgroup")?;
        let path = Path::new("/sys/fs/cgroup").join(cg.trim_start_matches('/'));
        ensure(
            fs::canonicalize(&path)? == path,
            "manager cgroup not canonical",
        )?;
        let m = fs::symlink_metadata(&path)?;
        ensure(
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0,
            "manager cgroup unowned",
        )?;
        let cgroup_fd = fs::File::open(&path)?;
        let opened = cgroup_fd.metadata()?;
        ensure(
            opened.is_dir()
                && opened.uid() == 0
                && (opened.dev(), opened.ino()) == (m.dev(), m.ino()),
            "manager cgroup directory replaced at open",
        )?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        ensure(
            unsafe { libc::fstatfs(cgroup_fd.as_raw_fd(), &mut stat) } == 0
                && stat.f_type as u64 == 0x63677270,
            "manager cgroup opened filesystem is not cgroup2",
        )?;
        let mut files = BTreeMap::new();
        for p in file_paths(&unit)? {
            files.insert(p.clone(), protected_hash(&p, deadline)?);
        }
        // Executable path ancestry protection is independently checked, in addition to opened proc-exe FD identity.
        ensure(
            protected_hash(&role.executable, deadline)? == role.executable_sha256,
            "manager executable differs from current protected disk",
        )?;
        let after = fs::symlink_metadata(&path)?;
        ensure(
            after.is_dir()
                && after.uid() == 0
                && !after.file_type().is_symlink()
                && directory_identity_matches(
                    (m.dev(), m.ino()),
                    (opened.dev(), opened.ino()),
                    (after.dev(), after.ino()),
                ),
            "manager cgroup directory identity changed while observing",
        )?;
        Ok(Snapshot {
            unit,
            process: role,
            boot: text(Path::new("/proc/sys/kernel/random/boot_id"), 64, deadline)?
                .trim()
                .into(),
            cgroup_inode: m.ino(),
            cgroup_device: m.dev(),
            files,
            systemctl_sha256,
            account,
        })
    }
    fn pidfd_live(fd: &fs::File) -> io::Result<()> {
        let mut p = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        ensure(
            unsafe { libc::poll(&mut p, 1, 0) } == 0 && p.revents == 0,
            "manager pidfd terminal or unavailable",
        )
    }
    pub(super) fn attest(
        name: &str,
        b: &ExpectedManagerBinding,
        state: &str,
    ) -> io::Result<ManagerProof> {
        binding_schema(name, b, state)?;
        ensure(
            unsafe { libc::geteuid() } == 0,
            "manager proof requires root",
        )?;
        // Reserve100ms for bounded owned helper cleanup within the three-second total budget.
        let deadline = Instant::now() + Duration::from_millis(2900);
        let (initial, initial_tool) = unit(name, deadline)?;
        let initial_pid = pid(&initial, "MainPID")?;
        ensure(initial_pid > 0, "manager PID absent")?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, initial_pid, 0) } as i32;
        ensure(fd >= 0, "manager pidfd open refused")?;
        use std::os::fd::FromRawFd;
        let owned = unsafe { fs::File::from_raw_fd(fd) };
        pidfd_live(&owned)?;
        let first = snapshot(name, &b.path, deadline)?;
        ensure(
            first.unit == initial && first.systemctl_sha256 == initial_tool,
            "manager unit changed after pidfd open",
        )?;
        pidfd_live(&owned)?;
        let last = snapshot(name, &b.path, deadline)?;
        pidfd_live(&owned)?;
        live(deadline)?;
        validate_pair(name, b, state, &first, &last)
    }
}
pub(super) fn attest_current_manager(
    unit: &str,
    binding: &ExpectedManagerBinding,
    accepted_state_sha256: &str,
) -> io::Result<ManagerProof> {
    #[cfg(target_os = "linux")]
    {
        linux::attest(unit, binding, accepted_state_sha256)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (unit, binding, accepted_state_sha256);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "manager attestation requires Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> (ExpectedManagerBinding, Snapshot) {
        let b = ExpectedManagerBinding {
            schema: "aegis_device_guard_binding_v1".into(),
            boot_id: "00112233-4455-6677-8899-aabbccddeeff".into(),
            state_sha256: "a".repeat(64),
            path: format!("system.slice/{name}"),
            inode: "1234".into(),
            invocation: "b".repeat(32),
            pin: None,
        };
        let mut unit: BTreeMap<String, String> = KEYS
            .iter()
            .map(|k| (k.to_string(), String::new()))
            .collect();
        for (k, v) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NeedDaemonReload", "no"),
            ("User", "root"),
            ("DynamicUser", "no"),
            ("MainPID", "100"),
            ("ControlPID", "0"),
            ("FragmentPath", "/usr/lib/systemd/system/manager.service"),
            (
                "DropInPaths",
                "/etc/systemd/system/manager.service.d/test.conf",
            ),
            ("ExecStart", "opaque unit command metadata"),
        ] {
            unit.insert(k.into(), v.into());
        }
        unit.insert("ControlGroup".into(), format!("/{}", b.path));
        unit.insert("InvocationID".into(), b.invocation.clone());
        let process = Process {
            pid: 100,
            start: 200,
            executable: "/usr/bin/manager".into(),
            executable_sha256: "c".repeat(64),
            executable_device: 1,
            executable_inode: 2,
            argv: vec!["manager".into()],
            cgroup: format!("/{}", b.path),
            uids: [0; 4],
        };
        let files = BTreeMap::from([
            (
                "/usr/lib/systemd/system/manager.service".into(),
                "d".repeat(64),
            ),
            (
                "/etc/systemd/system/manager.service.d/test.conf".into(),
                "e".repeat(64),
            ),
        ]);
        let s = Snapshot {
            unit,
            process,
            boot: b.boot_id.clone(),
            cgroup_inode: 1234,
            cgroup_device: 3,
            files,
            systemctl_sha256: "f".repeat(64),
            account: Account {
                name: "root".into(),
                uid: 0,
                row_sha256: "1".repeat(64),
                passwd_sha256: "2".repeat(64),
                passwd_device: 1,
                passwd_inode: 100,
            },
        };
        (b, s)
    }
    #[test]
    fn both_whitelisted_managers_prove_current_identity() {
        for name in ["NetworkManager.service", "systemd-networkd.service"] {
            let (b, s) = fixture(name);
            let proof = validate_pair(name, &b, &b.state_sha256, &s, &s).unwrap();
            assert_eq!(proof.unit(), name);
            assert_eq!(proof.binding(), &b);
            assert!(hex(proof.digest(), 64));
        }
    }
    #[test]
    fn unknown_role_and_cross_manager_receipt_refused() {
        let (b, s) = fixture("NetworkManager.service");
        assert!(validate_pair("foreign.service", &b, &b.state_sha256, &s, &s).is_err());
        assert!(validate_pair("systemd-networkd.service", &b, &b.state_sha256, &s, &s).is_err());
    }
    #[test]
    fn stale_boot_state_inode_invocation_refused() {
        let (b, s) = fixture("NetworkManager.service");
        for part in 0..4 {
            let mut x = s.clone();
            match part {
                0 => x.boot = "10112233-4455-6677-8899-aabbccddeeff".into(),
                1 => x.cgroup_inode = 999,
                2 => {
                    x.unit.insert("InvocationID".into(), "0".repeat(32));
                }
                _ => {
                    x.process.cgroup = "/system.slice/foreign.service".into();
                }
            }
            assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &x, &x).is_err());
        }
        assert!(validate_pair("NetworkManager.service", &b, &"0".repeat(64), &s, &s).is_err());
    }
    #[test]
    fn inactive_activating_control_and_reloaded_units_refused() {
        let (b, s) = fixture("NetworkManager.service");
        for (k, v) in [
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("ControlPID", "200"),
            ("MainPID", "0"),
            ("NeedDaemonReload", "yes"),
            ("LoadState", "not-found"),
        ] {
            let mut x = s.clone();
            x.unit.insert(k.into(), v.into());
            assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &x, &x).is_err());
        }
    }
    #[test]
    fn pid_ticks_executable_identity_change_refused() {
        let (b, s) = fixture("NetworkManager.service");
        for part in 0..5 {
            let mut x = s.clone();
            match part {
                0 => x.process.pid = 101,
                1 => x.process.start = 201,
                2 => x.process.executable_inode = 22,
                3 => x.process.executable_device = 5,
                _ => x.process.executable_sha256 = "0".repeat(64),
            }
            assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &s, &x).is_err());
        }
    }
    #[test]
    fn complete_unit_and_dropin_inventory_must_stay_pinned() {
        let (b, s) = fixture("NetworkManager.service");
        for part in 0..3 {
            let mut x = s.clone();
            match part {
                0 => {
                    x.files.remove(&PathBuf::from(
                        "/etc/systemd/system/manager.service.d/test.conf",
                    ));
                }
                1 => {
                    x.files.insert(
                        "/etc/systemd/system/manager.service.d/test.conf".into(),
                        "0".repeat(64),
                    );
                }
                _ => {
                    x.unit
                        .insert("ExecStart".into(), "different opaque command".into());
                }
            }
            assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &s, &x).is_err());
        }
    }
    #[test]
    fn duplicate_unknown_and_wrong_type_binding_refused() {
        let (b, _) = fixture("NetworkManager.service");
        let text = serde_json::to_string(&b).unwrap();
        let mut v = serde_json::to_value(&b).unwrap();
        v["inode"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<ExpectedManagerBinding>(v).is_err());
        let dup = text.replacen("{", "{\"schema\":\"aegis_device_guard_binding_v1\",", 1);
        assert!(serde_json::from_str::<ExpectedManagerBinding>(&dup).is_err());
        let mut v = serde_json::to_value(b).unwrap();
        v["foreign"] = true.into();
        assert!(serde_json::from_value::<ExpectedManagerBinding>(v).is_err());
    }
    #[test]
    fn strict_v2_binding_retains_lease_pins_in_administrative_proof() {
        let (legacy, snapshot) = fixture("NetworkManager.service");
        let mut value = serde_json::to_value(&legacy).unwrap();
        value["schema"] = "aegis_device_guard_binding_v2".into();
        value["ifindex"] = 3.into();
        value["dhcp4_server"] = "10.77.0.1".into();
        value["dhcp6_server"] = "fd00:77::1".into();
        let parsed: ExpectedManagerBinding = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        let proof = validate_pair(
            "NetworkManager.service",
            &parsed,
            &parsed.state_sha256,
            &snapshot,
            &snapshot,
        )
        .unwrap();
        assert_eq!(proof.binding(), &parsed);
        for (field, changed) in [
            ("ifindex", serde_json::json!(4)),
            ("dhcp4_server", serde_json::json!("10.77.0.2")),
            ("dhcp6_server", serde_json::json!("fd00:77::2")),
        ] {
            let mut altered = value.clone();
            altered[field] = changed;
            let binding: ExpectedManagerBinding = serde_json::from_value(altered).unwrap();
            let other = validate_pair(
                "NetworkManager.service",
                &binding,
                &binding.state_sha256,
                &snapshot,
                &snapshot,
            )
            .unwrap();
            assert_ne!(other.digest(), proof.digest());
            assert_ne!(other.binding(), proof.binding());
        }
        for (field, changed) in [
            ("ifindex", serde_json::json!(0)),
            ("dhcp4_server", serde_json::json!("127.0.0.1")),
            ("dhcp4_server", serde_json::json!("169.254.1.2")),
            ("dhcp6_server", serde_json::json!("ff02::1:2")),
            ("dhcp6_server", serde_json::json!("FD00:77::1")),
        ] {
            let mut altered = value.clone();
            altered[field] = changed;
            if let Ok(binding) = serde_json::from_value::<ExpectedManagerBinding>(altered) {
                assert!(
                    binding_schema("NetworkManager.service", &binding, &binding.state_sha256)
                        .is_err()
                );
            }
        }
        for field in ["ifindex", "dhcp4_server", "dhcp6_server"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ExpectedManagerBinding>(missing).is_err());
        }
        let mut null_pin = value.clone();
        null_pin["dhcp4_server"] = serde_json::Value::Null;
        null_pin["dhcp6_server"] = serde_json::Value::Null;
        let null_binding: ExpectedManagerBinding = serde_json::from_value(null_pin).unwrap();
        assert!(binding_schema(
            "NetworkManager.service",
            &null_binding,
            &null_binding.state_sha256
        )
        .is_ok());
        let duplicate = serde_json::to_string(&value)
            .unwrap()
            .replacen("{", "{\"ifindex\":3,", 1);
        assert!(serde_json::from_str::<ExpectedManagerBinding>(&duplicate).is_err());
        let mut unknown = value.clone();
        unknown["foreign"] = true.into();
        assert!(serde_json::from_value::<ExpectedManagerBinding>(unknown).is_err());
        let mut downgrade = value;
        downgrade["schema"] = "aegis_device_guard_binding_v1".into();
        assert!(serde_json::from_value::<ExpectedManagerBinding>(downgrade).is_err());
    }
    #[test]
    fn nonroot_and_falsy_numeric_identity_refused() {
        let (b, s) = fixture("NetworkManager.service");
        for part in 0..3 {
            let mut x = s.clone();
            match part {
                0 => x.process.uids = [1000; 4],
                1 => x.process.start = 0,
                _ => x.cgroup_device = 0,
            }
            assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &x, &x).is_err());
        }
    }
    #[test]
    fn manager_pid_schema_cannot_parse_boolean_or_negative() {
        let (b, s) = fixture("NetworkManager.service");
        for raw in ["true", "-1", "", "4294967296"] {
            let mut x = s.clone();
            x.unit.insert("MainPID".into(), raw.into());
            assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &x, &x).is_err());
        }
    }
    #[test]
    fn samecount_foreign_dropin_and_duplicate_path_refused() {
        let (b, s) = fixture("NetworkManager.service");
        for raw in ["/etc/systemd/system/manager.service.d/foreign.conf","/etc/systemd/system/manager.service.d/test.conf /etc/systemd/system/manager.service.d/test.conf"] {let mut x=s.clone();x.unit.insert("DropInPaths".into(),raw.into());assert!(validate_pair("NetworkManager.service",&b,&b.state_sha256,&x,&x).is_err());}
    }
    #[test]
    fn exact_original_custom_slice_binding_supported() {
        for path in [
            "custom.slice/nested.slice/NetworkManager.service",
            "NetworkManager.service",
        ] {
            let (mut b, mut snapshot) = fixture("NetworkManager.service");
            b.path = path.into();
            snapshot
                .unit
                .insert("ControlGroup".into(), format!("/{path}"));
            snapshot.process.cgroup = format!("/{path}");
            assert!(validate_pair(
                "NetworkManager.service",
                &b,
                &b.state_sha256,
                &snapshot,
                &snapshot
            )
            .is_ok());
        }
    }
    #[test]
    fn custom_slice_cannot_adopt_foreign_unit_or_unsafe_path() {
        let (b, snapshot) = fixture("NetworkManager.service");
        for path in [
            "custom.slice/foreign.service",
            "custom.slice/NetworkManager.service/",
            "/custom.slice/NetworkManager.service",
            "custom.slice//NetworkManager.service",
            "./NetworkManager.service",
            "../NetworkManager.service",
            "custom.slice/../NetworkManager.service",
            "custom slice/NetworkManager.service",
            "custom.slice/NetworkManager.service\n",
        ] {
            let mut b = b.clone();
            let mut snapshot = snapshot.clone();
            b.path = path.into();
            snapshot
                .unit
                .insert("ControlGroup".into(), format!("/{path}"));
            snapshot.process.cgroup = format!("/{path}");
            assert!(
                validate_pair(
                    "NetworkManager.service",
                    &b,
                    &b.state_sha256,
                    &snapshot,
                    &snapshot
                )
                .is_err(),
                "{path}"
            );
        }
        let (mut b, mut snapshot) = fixture("NetworkManager.service");
        b.path = "custom.slice/NetworkManager.service".into();
        snapshot.process.cgroup = format!("/{}", b.path);
        // A safe receipt is still refused if the live unit remains at a different exact path.
        assert!(validate_pair(
            "NetworkManager.service",
            &b,
            &b.state_sha256,
            &snapshot,
            &snapshot
        )
        .is_err());
    }
    #[test]
    fn cgroup_directory_fd_cannot_adopt_samepath_replacement() {
        assert!(directory_identity_matches((1, 2), (1, 2), (1, 2)));
        for (a, b, c) in [
            ((1, 2), (1, 3), (1, 3)),
            ((1, 2), (1, 2), (2, 2)),
            ((1, 2), (1, 2), (1, 3)),
            ((0, 2), (0, 2), (0, 2)),
            ((1, 0), (1, 0), (1, 0)),
        ] {
            assert!(!directory_identity_matches(a, b, c));
        }
    }
    fn networkd_fixture() -> (ExpectedManagerBinding, Snapshot) {
        let (b, mut s) = fixture("systemd-networkd.service");
        s.unit.insert("User".into(), "systemd-network".into());
        s.account.name = "systemd-network".into();
        s.account.uid = 192;
        s.process.uids = [192; 4];
        (b, s)
    }
    #[test]
    fn qualified_loaded_networkd_account_is_supported_without_root_process_claim() {
        let (b, s) = networkd_fixture();
        assert!(validate_pair("systemd-networkd.service", &b, &b.state_sha256, &s, &s).is_ok());
        let (_, mut root) = fixture("systemd-networkd.service");
        root.unit.insert("User".into(), String::new());
        assert!(validate_pair(
            "systemd-networkd.service",
            &b,
            &b.state_sha256,
            &root,
            &root
        )
        .is_ok());
    }
    #[test]
    fn loaded_user_dynamic_account_and_manager_cross_role_refused() {
        let (b, s) = networkd_fixture();
        for (key, value) in [
            ("User", "nobody"),
            ("User", "192"),
            ("User", "root"),
            ("DynamicUser", "yes"),
            ("DynamicUser", ""),
        ] {
            let mut x = s.clone();
            x.unit.insert(key.into(), value.into());
            assert!(
                validate_pair("systemd-networkd.service", &b, &b.state_sha256, &x, &x).is_err()
            );
        }
        let (b, mut x) = fixture("NetworkManager.service");
        x.unit.insert("User".into(), "systemd-network".into());
        x.account.name = "systemd-network".into();
        x.account.uid = 192;
        x.process.uids = [192; 4];
        assert!(validate_pair("NetworkManager.service", &b, &b.state_sha256, &x, &x).is_err());
    }
    #[test]
    fn all_real_effective_saved_filesystem_process_uids_must_match_qualified_account() {
        let (b, s) = networkd_fixture();
        for slot in 0..4 {
            let mut x = s.clone();
            x.process.uids[slot] = 0;
            assert!(
                validate_pair("systemd-networkd.service", &b, &b.state_sha256, &x, &x).is_err()
            );
        }
        let mut x = s.clone();
        x.process.uids = [193; 4];
        assert!(validate_pair("systemd-networkd.service", &b, &b.state_sha256, &x, &x).is_err());
    }
    #[test]
    fn actual_passwd_rows_resolve_only_unique_qualified_local_user_and_uid() {
        let passwd = b"root:x:0:0:root:/root:/bin/bash\nsystemd-network:x:192:192:Network:/:/usr/sbin/nologin\n";
        assert_eq!(local_account(passwd, "root").unwrap().0, 0);
        let (uid, digest) = local_account(passwd, "systemd-network").unwrap();
        assert_eq!(uid, 192);
        assert!(hex(&digest, 64));
        for bytes in [
            b"root:x:0:0:r:/:/bin/bash\n".as_slice(),
            b"systemd-network:x:192:192:n:/:/bin/false\nsystemd-network:x:193:193:n:/:/bin/false\n"
                .as_slice(),
            b"systemd-network:x:192:192:n:/:/bin/false\nforeign:x:192:192:n:/:/bin/false\n"
                .as_slice(),
            b"systemd-network:x:0:0:n:/:/bin/false\n".as_slice(),
            b"systemd-network:x:0192:192:n:/:/bin/false\n".as_slice(),
            b"systemd-network:x:true:192:n:/:/bin/false\n".as_slice(),
            b"systemd-network:x:4294967296:192:n:/:/bin/false\n".as_slice(),
            b"systemd-network:x:192:192:n:/:/bin/false\0".as_slice(),
        ] {
            assert!(local_account(bytes, "systemd-network").is_err());
        }
        assert!(local_account(passwd, "nobody").is_err());
        assert!(local_account(b"root:x:1:0:r:/:/bin/bash\n", "root").is_err());
    }
    #[test]
    fn passwd_file_row_and_identity_drift_are_part_of_complete_pair_proof() {
        let (b, s) = networkd_fixture();
        for slot in 0..6 {
            let mut last = s.clone();
            match slot {
                0 => last.account.uid = 193,
                1 => last.account.name = "root".into(),
                2 => last.account.passwd_sha256 = "0".repeat(64),
                3 => last.account.row_sha256 = "0".repeat(64),
                4 => last.account.passwd_inode += 1,
                _ => last.account.passwd_device += 1,
            }
            assert!(
                validate_pair("systemd-networkd.service", &b, &b.state_sha256, &s, &last).is_err()
            );
        }
        let mut root = s.clone();
        root.account.uid = 0;
        root.process.uids = [0; 4];
        assert!(validate_pair(
            "systemd-networkd.service",
            &b,
            &b.state_sha256,
            &root,
            &root
        )
        .is_err());
    }
    #[test]
    fn uid_status_parser_rejects_ambiguous_non_numeric_or_incomplete_frames() {
        assert_eq!(
            process_uids("Name:\tnetworkd\nUid:\t192\t192\t192\t192\n").unwrap(),
            [192; 4]
        );
        for text in [
            "Uid: 192 192 192\n",
            "Uid: 192 192 192 192 192\n",
            "Uid: 192 192 192 192\nUid: 0 0 0 0\n",
            "Uid: true 192 192 192\n",
            "Uid: -1 192 192 192\n",
            "Uid: 0192 192 192 192\n",
            "Uid: 4294967296 192 192 192\n",
        ] {
            assert!(process_uids(text).is_err());
        }
    }
    #[test]
    fn account_metadata_must_have_protected_hash_and_nonzero_file_identity() {
        let (b, s) = networkd_fixture();
        for slot in 0..4 {
            let mut x = s.clone();
            match slot {
                0 => x.account.passwd_sha256 = "not-a-hash".into(),
                1 => x.account.row_sha256 = String::new(),
                2 => x.account.passwd_device = 0,
                _ => x.account.passwd_inode = 0,
            };
            assert!(
                validate_pair("systemd-networkd.service", &b, &b.state_sha256, &x, &x).is_err()
            );
        }
    }
}
