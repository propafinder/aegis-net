//! Explicit selected-profile removal primitives. No kernel or filesystem I/O.
//! A removal is authorized by exact archived ownership, never observed names.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

fn refuse() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "selected teardown ownership refused",
    )
}
fn need(v: bool) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(refuse())
    }
}
fn hexadecimal(s: &str, size: usize) -> bool {
    s.len() == size
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePin {
    pub device: u64,
    pub inode: u64,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
}
impl FilePin {
    pub fn validate(&self) -> io::Result<()> {
        need(
            self.inode != 0
                && hexadecimal(&self.sha256, 64)
                && self.size <= 18 * 1048576
                && self.mode & 0o022 == 0
                && self.mode <= 0o777,
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Intent,
    ArchiveCommitted,
    NativeQuiet,
    DropInRemoved,
    PayloadRemoved,
    GateRemoved,
    Complete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownRecord {
    pub schema: String,
    pub token: String,
    pub source: String,
    pub phase: Phase,
    pub profile_sha256: String,
    pub directory_manifest_sha256: String,
    pub archive_device: u64,
    pub archive_inode: u64,
    pub archive_manifest_sha256: Option<String>,
    pub original_inet_digest: String,
    pub initial_original_inet_digest: String,
    pub initial_manager_identity_sha256: Option<String>,
    pub initial_manager_binding_sha256: Option<String>,
    pub selected_netdev_digest: String,
    pub owned_files: BTreeMap<String, FilePin>,
}
impl TeardownRecord {
    pub fn validate(&self) -> io::Result<()> {
        need(
            self.schema == "aegis_selected_teardown_v1"
                && hexadecimal(&self.token, 32)
                && hexadecimal(&self.source, 40)
                && hexadecimal(&self.profile_sha256, 64)
                && hexadecimal(&self.directory_manifest_sha256, 64)
                && self.archive_inode != 0
                && hexadecimal(&self.original_inet_digest, 64)
                && hexadecimal(&self.initial_original_inet_digest, 64)
                && hexadecimal(&self.selected_netdev_digest, 64),
        )?;
        match (
            &self.initial_manager_identity_sha256,
            &self.initial_manager_binding_sha256,
        ) {
            (None, None) => need(self.initial_original_inet_digest == self.original_inet_digest)?,
            (Some(role), Some(binding)) => need(
                hexadecimal(role, 64)
                    && hexadecimal(binding, 64)
                    && self.initial_original_inet_digest != self.original_inet_digest,
            )?,
            _ => return Err(refuse()),
        }
        need(!self.owned_files.is_empty() && self.owned_files.len() <= 8500)?;
        for (name, pin) in &self.owned_files {
            need(
                name.starts_with('/')
                    && name.len() <= 512
                    && !name.split('/').any(|s| s == "." || s == ".."),
            )?;
            pin.validate()?;
        }
        need(
            self.phase == Phase::Intent
                || self
                    .archive_manifest_sha256
                    .as_deref()
                    .is_some_and(|s| hexadecimal(s, 64)),
        )
    }
    pub fn advance(&self, phase: Phase, archive: Option<&str>) -> io::Result<Self> {
        self.validate()?;
        let next = match self.phase {
            Phase::Intent => Phase::ArchiveCommitted,
            Phase::ArchiveCommitted => Phase::NativeQuiet,
            Phase::NativeQuiet => Phase::DropInRemoved,
            Phase::DropInRemoved => Phase::PayloadRemoved,
            Phase::PayloadRemoved => Phase::GateRemoved,
            Phase::GateRemoved => Phase::Complete,
            Phase::Complete => return Err(refuse()),
        };
        need(phase == next)?;
        let mut row = self.clone();
        row.phase = phase;
        if self.phase == Phase::Intent {
            let hash = archive.ok_or_else(refuse)?;
            need(hexadecimal(hash, 64))?;
            row.archive_manifest_sha256 = Some(hash.into());
        } else {
            need(archive.is_none() || archive == self.archive_manifest_sha256.as_deref())?;
        }
        row.validate()?;
        Ok(row)
    }
}

/// Trusted v2 state has no script evaluation or private keys. The unbound block
/// keeps exact local management replies/ND, but no client or DHCP-role admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceBlockPolicy {
    pub uplink: String,
    pub manager: String,
    pub dhcp4: bool,
    pub dhcp6: bool,
    pub capture_interface: String,
    pub redirect_capture: bool,
    pub management_ports: Vec<u16>,
}
impl DeviceBlockPolicy {
    pub fn from_state(text: &str) -> io::Result<Self> {
        need(text.len() <= 65536 && !text.contains(['\r', '\0']))?;
        let mut fields = BTreeMap::new();
        for line in text.lines().filter(|s| !s.is_empty()) {
            let (key, value) = line.split_once('=').ok_or_else(refuse)?;
            need(fields.insert(key, value).is_none())?;
        }
        let required = [
            "schema",
            "armed",
            "service",
            "uplink",
            "manager",
            "capture_interface",
            "management_address_policy",
            "management_ports",
            "dhcp4",
            "dhcp6",
            "initramfs_network",
        ];
        need(required.iter().all(|k| fields.contains_key(k)))?;
        need(
            fields
                .get("capture_profile")
                .copied()
                .is_none_or(|profile| {
                    profile == "full-wide-tun" || profile == "wide-redirect-safe"
                }),
        )?;
        need(
            fields["schema"] == "aegis_device_guard_v2"
                && fields["armed"] == "1"
                && fields["service"] == "aegis-client.service"
                && fields["capture_interface"] == "aegis-tun0"
                && fields["management_address_policy"] == "current_local"
                && fields["initramfs_network"] == "absent_verified"
                && ["0", "1"].contains(&fields["dhcp4"])
                && ["0", "1"].contains(&fields["dhcp6"]),
        )?;
        need(["NetworkManager.service", "systemd-networkd.service"].contains(&fields["manager"]))?;
        match (
            fields.get("foreign_policy"),
            fields.get("ufw_integrity_sha256"),
        ) {
            (None, None) => {}
            (Some(class), Some(sha)) => need(
                *class == "filter_only"
                    && sha.len() == 64
                    && sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            )?,
            _ => return Err(refuse()),
        }
        let nm = [
            "manager_connection_uuid",
            "manager_ipv4_method",
            "manager_ipv6_method",
        ];
        need(fields.keys().all(|key| {
            required.contains(key)
                || *key == "capture_profile"
                || *key == "foreign_policy"
                || *key == "ufw_integrity_sha256"
                || (fields["manager"] == "NetworkManager.service" && nm.contains(key))
        }))?;
        if fields["manager"] == "NetworkManager.service" {
            need(nm.iter().all(|k| fields.contains_key(k)))?;
            let uuid = fields["manager_connection_uuid"];
            need(
                uuid.len() == 36
                    && uuid.bytes().enumerate().all(|(i, c)| {
                        if [8, 13, 18, 23].contains(&i) {
                            c == b'-'
                        } else {
                            c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                        }
                    }),
            )?;
            need(
                ["auto", "manual"].contains(&fields["manager_ipv4_method"])
                    && ["auto", "dhcp", "manual", "disabled", "ignore", "link-local"]
                        .contains(&fields["manager_ipv6_method"]),
            )?;
            need((fields["manager_ipv4_method"] == "auto") == (fields["dhcp4"] == "1"))?;
            need(
                ["auto", "dhcp"].contains(&fields["manager_ipv6_method"])
                    == (fields["dhcp6"] == "1"),
            )?;
        }
        let uplink = fields["uplink"];
        need(
            !uplink.is_empty()
                && uplink.len() <= 15
                && uplink.as_bytes()[0].is_ascii_alphanumeric()
                && uplink != "lo"
                && uplink != "aegis-tun0"
                && uplink
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        )?;
        let mut ports = vec![];
        let mut seen = BTreeSet::new();
        if !fields["management_ports"].is_empty() {
            for part in fields["management_ports"].split(',') {
                let p = part.parse::<u16>().map_err(|_| refuse())?;
                need(p != 0 && p.to_string() == part && seen.insert(p) && ports.len() < 8)?;
                ports.push(p);
            }
        }
        Ok(Self {
            uplink: uplink.into(),
            manager: fields["manager"].into(),
            dhcp4: fields["dhcp4"] == "1",
            dhcp6: fields["dhcp6"] == "1",
            capture_interface: "aegis-tun0".into(),
            redirect_capture: fields.get("capture_profile").copied() == Some("wide-redirect-safe"),
            management_ports: ports,
        })
    }
    pub fn expected(&self) -> Value {
        let table = "aegis_device_guard";
        let meta = |k: &str| json!({"meta":{"key":k}});
        let payload = |p: &str, f: &str| json!({"payload":{"protocol":p,"field":f}});
        let ct = |key: &str| json!({"ct":{"key":key}});
        let cmp =
            |left: Value, right: Value| json!({"match":{"left":left,"right":right,"op":"=="}});
        let chain = |name: &str, hook: &str, priority: i32, policy: &str| json!({"chain":{"family":"inet","table":table,"name":name,"type":"filter","hook":hook,"prio":priority,"policy":policy}});
        let rule = |chain: &str, expr: Vec<Value>| json!({"rule":{"family":"inet","table":table,"chain":chain,"expr":expr}});
        let mut rows = vec![
            json!({"table":{"family":"inet","name":table}}),
            chain("incoming", "prerouting", -190, "accept"),
            chain("output", "output", 10, "drop"),
            chain("forward", "forward", 10, "drop"),
        ];
        rows.push(rule(
            "output",
            vec![
                cmp(meta("oifname"), json!("lo")),
                json!({"counter":null}),
                json!({"accept":null}),
            ],
        ));
        if !self.redirect_capture {
            rows.push(rule(
                "output",
                vec![
                    cmp(meta("oifname"), json!(self.capture_interface)),
                    json!({"counter":null}),
                    json!({"accept":null}),
                ],
            ));
        }
        for port in &self.management_ports {
            rows.push(rule(
                "incoming",
                vec![
                    cmp(meta("iifname"), json!(self.uplink)),
                    cmp(
                        json!({"fib":{"result":"type","flags":["daddr"]}}),
                        json!("local"),
                    ),
                    cmp(meta("l4proto"), json!(6)),
                    cmp(payload("tcp", "dport"), json!(port)),
                    cmp(ct("direction"), json!("original")),
                    cmp(ct("state"), json!({"set":["new","established"]})),
                    json!({"mangle":{"key":ct("mark"),"value":0xa3610002u32}}),
                ],
            ));
            rows.push(rule(
                "output",
                vec![
                    cmp(meta("oifname"), json!(self.uplink)),
                    cmp(meta("l4proto"), json!(6)),
                    cmp(ct("direction"), json!("reply")),
                    cmp(ct("mark"), json!(0xa3610002u32)),
                    cmp(
                        json!({"ct":{"key":"proto-dst","dir":"original"}}),
                        json!(port),
                    ),
                    cmp(payload("tcp", "sport"), json!(port)),
                    json!({"counter":null}),
                    json!({"accept":null}),
                ],
            ));
        }
        rows.push(rule("output",vec![cmp(meta("oifname"),json!(self.uplink)),cmp(meta("nfproto"),json!("ipv6")),cmp(payload("ip6","hoplimit"),json!(255)),cmp(payload("ip6","daddr"),json!({"set":[{"prefix":{"addr":"fe80::","len":10}},{"prefix":{"addr":"ff02::","len":16}}]})),cmp(meta("l4proto"),json!(58)),cmp(payload("icmpv6","type"),json!({"set":[133,135,136]})),json!({"counter":null}),json!({"accept":null})]));
        rows.push(rule(
            "output",
            vec![json!({"counter":null}), json!({"drop":null})],
        ));
        rows.push(rule(
            "forward",
            vec![json!({"counter":null}), json!({"drop":null})],
        ));
        json!({"nftables":rows})
    }
    /// Exact initial manager recipe from the original guarded renderer. This
    /// pure recipe does not attest a role; callers need an independent fresh proof.
    pub fn expected_manager(&self, binding: &OriginalGuardBinding) -> io::Result<Value> {
        validate_original_unit_binding(
            &serde_json::to_vec(binding)?,
            &binding.state_sha256,
            &self.manager,
        )?;
        let marker = format!(
            "aegis-v2-{}",
            hex::encode(Sha256::digest(serde_json::to_vec(&[
                binding.boot_id.as_str(),
                binding.state_sha256.as_str(),
                "manager",
                binding.path.as_str(),
                binding.inode.as_str(),
                binding.invocation.as_str()
            ])?))
        );
        let meta = |key: &str| json!({"meta":{"key":key}});
        let payload = |field: &str| json!({"payload":{"protocol":"udp","field":field}});
        let cmp =
            |left: Value, right: Value| json!({"match":{"left":left,"right":right,"op":"=="}});
        let mut value = self.expected();
        let rows = value["nftables"].as_array_mut().ok_or_else(refuse)?;
        let mut grants = vec![];
        for (selected, family, sport, dport) in
            [(self.dhcp4, "ipv4", 68, 67), (self.dhcp6, "ipv6", 546, 547)]
        {
            if selected {
                grants.push(json!({"rule":{"family":"inet","table":"aegis_device_guard","chain":"output","expr":[cmp(meta("oifname"),json!(self.uplink)),cmp(meta("nfproto"),json!(family)),cmp(meta("l4proto"),json!(17)),cmp(payload("sport"),json!(sport)),cmp(payload("dport"),json!(dport)),cmp(json!({"socket":{"key":"cgroupv2","level":binding.path.split('/').count()}}),json!(binding.path)),{"counter":null},{"accept":null}],"comment":marker}}));
            }
        }
        let at = rows.len().checked_sub(3).ok_or_else(refuse)?;
        rows.splice(at..at, grants);
        Ok(value)
    }
    pub fn verify_manager(
        &self,
        actual: &Value,
        binding: &OriginalGuardBinding,
    ) -> io::Result<[u8; 32]> {
        let expected = canonical_inet(&self.expected_manager(binding)?)?;
        need(canonical_inet(actual)? == expected)?;
        Ok(Sha256::digest(serde_json::to_vec(&expected)?).into())
    }
    pub fn block_transaction(&self) -> Value {
        let mut rows = vec![
            json!({"add":{"table":{"family":"inet","name":"aegis_device_guard"}}}),
            json!({"flush":{"table":{"family":"inet","name":"aegis_device_guard"}}}),
        ];
        for row in self.expected()["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
        {
            rows.push(json!({"add":row}));
        }
        json!({"nftables":rows})
    }
    pub fn verify(&self, actual: &Value) -> io::Result<[u8; 32]> {
        let expected = canonical_inet(&self.expected())?;
        need(canonical_inet(actual)? == expected)?;
        Ok(Sha256::digest(serde_json::to_vec(&expected)?).into())
    }
}
fn canonical_inet(value: &Value) -> io::Result<Value> {
    let root = value.as_object().ok_or_else(refuse)?;
    need(root.len() == 1)?;
    let rows = root
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(refuse)?;
    need(rows.len() <= 40)?;
    let mut objects = vec![];
    let mut incoming = vec![];
    let mut output = vec![];
    let mut forward = vec![];
    let mut meta_seen = false;
    for row in rows {
        let object = row.as_object().ok_or_else(refuse)?;
        need(object.len() == 1)?;
        let (kind, body) = object.iter().next().ok_or_else(refuse)?;
        if kind == "metainfo" {
            need(!meta_seen && body.is_object())?;
            meta_seen = true;
            continue;
        }
        need(["table", "chain", "rule"].contains(&kind.as_str()))?;
        let mut body = body.as_object().ok_or_else(refuse)?.clone();
        if let Some(handle) = body.remove("handle") {
            need(handle.as_u64().is_some())?;
        }
        if kind == "rule" {
            let expr = body
                .get_mut("expr")
                .and_then(Value::as_array_mut)
                .ok_or_else(refuse)?;
            for item in expr {
                if let Some(counter) = item.get_mut("counter") {
                    if !counter.is_null() {
                        let c = counter.as_object().ok_or_else(refuse)?;
                        need(
                            c.len() == 2
                                && c.get("packets").and_then(Value::as_u64).is_some()
                                && c.get("bytes").and_then(Value::as_u64).is_some(),
                        )?;
                        *counter = Value::Null;
                    }
                }
            }
        }
        let clean = json!({kind:body});
        if kind == "rule" {
            match clean["rule"]["chain"].as_str() {
                Some("incoming") => incoming.push(clean),
                Some("output") => output.push(clean),
                Some("forward") => forward.push(clean),
                _ => return Err(refuse()),
            }
        } else {
            objects.push(clean)
        }
    }
    need(objects.len() == 4)?;
    objects.sort_by_key(Value::to_string);
    objects.extend(incoming);
    objects.extend(output);
    objects.extend(forward);
    Ok(Value::Array(objects))
}
/// The helper hashes Bash command-substitution output: remove trailing LF
/// bytes only, while the accepted raw file SHA/inode remain separate pins.
pub fn original_guard_state_digest(raw: &[u8]) -> String {
    let end = raw.iter().rposition(|b| *b != b'\n').map_or(0, |i| i + 1);
    hex::encode(Sha256::digest(&raw[..end]))
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalGuardBinding {
    pub schema: String,
    pub boot_id: String,
    pub state_sha256: String,
    pub path: String,
    pub inode: String,
    pub invocation: String,
}
pub fn parse_original_binding(
    bytes: &[u8],
    state_sha: &str,
    expected_path: &str,
) -> io::Result<OriginalGuardBinding> {
    validate_original_binding(bytes, state_sha, expected_path)?;
    serde_json::from_value(super::recovery::parse_unique_public_metadata(bytes)?)
        .map_err(|_| refuse())
}
/// The original renderer derives its cgroup level from the complete receipt
/// path. Permit only an exact safe relative path ending in the supported role.
pub fn validate_original_unit_binding(
    bytes: &[u8],
    state_sha: &str,
    unit: &str,
) -> io::Result<OriginalGuardBinding> {
    need(
        [
            "aegis-client.service",
            "NetworkManager.service",
            "systemd-networkd.service",
        ]
        .contains(&unit),
    )?;
    let value = super::recovery::parse_unique_public_metadata(bytes)?;
    let path = value["path"].as_str().ok_or_else(refuse)?;
    need(
        !path.is_empty()
            && path.len() <= 4096
            && path.split('/').all(|part| {
                !part.is_empty()
                    && ![".", ".."].contains(&part)
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:@-".contains(&b))
            })
            && path.rsplit('/').next() == Some(unit),
    )?;
    parse_original_binding(bytes, state_sha, path)
}
/// Strict public original guard-binding archive schema. This is evidence only;
/// it never grants initial bound-policy adoption or live manager authority.
pub fn validate_original_binding(
    bytes: &[u8],
    state_sha: &str,
    expected_path: &str,
) -> io::Result<()> {
    let v = super::recovery::parse_unique_public_metadata(bytes)?;
    let o = v.as_object().ok_or_else(refuse)?;
    need(
        o.len() == 6
            && o.keys().all(|k| {
                [
                    "schema",
                    "boot_id",
                    "state_sha256",
                    "path",
                    "inode",
                    "invocation",
                ]
                .contains(&k.as_str())
            }),
    )?;
    need(
        v["schema"] == "aegis_device_guard_binding_v1"
            && v["state_sha256"] == state_sha
            && v["path"] == expected_path
            && hexadecimal(state_sha, 64),
    )?;
    let boot = v["boot_id"].as_str().ok_or_else(refuse)?;
    need(
        boot.len() == 36
            && boot.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            }),
    )?;
    let inode = v["inode"].as_str().ok_or_else(refuse)?;
    let n = inode.parse::<u64>().map_err(|_| refuse())?;
    need(
        n > 0
            && n.to_string() == inode
            && v["invocation"].as_str().is_some_and(|i| hexadecimal(i, 32)),
    )
}
/// Only the exact public receipt schema may be included in the ownership archive.
pub fn validate_recovery_receipt(v: &Value, name: &str, source: &str) -> io::Result<()> {
    let o = v.as_object().ok_or_else(refuse)?;
    let fields = [
        "schema",
        "instance",
        "source_commit",
        "journal_sha256",
        "status",
        "old_process_absent",
        "all_recorded_socket_inodes_absent",
        "recorded_tun_absent",
        "owned_table_absent",
        "removed_exact_table",
        "kernel_installed_guard_acceptance",
    ];
    need(o.len() == fields.len() && o.keys().all(|k| fields.contains(&k.as_str())))?;
    let token = o
        .get("instance")
        .and_then(Value::as_str)
        .ok_or_else(refuse)?;
    let digest = o
        .get("journal_sha256")
        .and_then(Value::as_str)
        .ok_or_else(refuse)?;
    need(
        token.len() == 8
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let stamp = name
        .strip_prefix(&format!("{token}-"))
        .and_then(|n| n.strip_suffix(".json"))
        .ok_or_else(refuse)?;
    need(
        !stamp.is_empty()
            && stamp.len() <= 39
            && stamp.bytes().all(|b| b.is_ascii_digit())
            && stamp.parse::<u128>().is_ok(),
    )?;
    need(
        v["schema"] == "aegis_relay_geneva_owned_recovery_v1"
            && v["source_commit"] == source
            && v["status"] == "PASS_OWNED_RECOVERY_ONLY",
    )?;
    for k in [
        "old_process_absent",
        "all_recorded_socket_inodes_absent",
        "recorded_tun_absent",
        "owned_table_absent",
    ] {
        need(v[k].as_bool() == Some(true))?;
    }
    need(
        v["removed_exact_table"].as_bool().is_some()
            && v["kernel_installed_guard_acceptance"].as_bool() == Some(false),
    )
}
/// Complete typed table inventory. A malformed/error row is never absence.
pub fn exact_table_present(value: &Value, family: &str, name: &str) -> io::Result<bool> {
    let root = value.as_object().ok_or_else(refuse)?;
    need(root.len() == 1)?;
    let rows = root
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(refuse)?;
    need(rows.len() <= 65536)?;
    let mut names = BTreeSet::new();
    let mut meta_seen = false;
    let mut found = false;
    for row in rows {
        let obj = row.as_object().ok_or_else(refuse)?;
        need(obj.len() == 1)?;
        if let Some(info) = obj.get("metainfo") {
            need(!meta_seen && info.is_object())?;
            meta_seen = true;
            continue;
        }
        let t = obj
            .get("table")
            .and_then(Value::as_object)
            .ok_or_else(refuse)?;
        need(
            t.keys()
                .all(|k| ["family", "name", "handle", "flags", "comment"].contains(&k.as_str())),
        )?;
        let f = t.get("family").and_then(Value::as_str).ok_or_else(refuse)?;
        let n = t.get("name").and_then(Value::as_str).ok_or_else(refuse)?;
        need(
            ["ip", "ip6", "inet", "arp", "bridge", "netdev"].contains(&f)
                && !n.is_empty()
                && n.len() <= 128
                && names.insert((f.to_string(), n.to_string())),
        )?;
        if n == name {
            need(f == family)?;
            found = true;
        }
    }
    Ok(found)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> DeviceBlockPolicy {
        DeviceBlockPolicy::from_state("schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\nuplink=eth0\nmanager=systemd-networkd.service\ncapture_interface=aegis-tun0\nmanagement_address_policy=current_local\nmanagement_ports=22,443\ndhcp4=1\ndhcp6=0\ninitramfs_network=absent_verified\n").unwrap()
    }
    #[test]
    fn original_state_hash_matches_pinned_actual_bash_lf_only_oracle() {
        let raw = br#"{"schema":"aegis_device_guard_v2","public_fixture_only":true}"#;
        let expected = "26c8c52d2bc0c6984145e84f108b906030f425d05e37c7a7122d753ec425e6b6";
        for extra in [b"".as_slice(), b"\n", b"\n\n"] {
            let mut bytes = raw.to_vec();
            bytes.extend_from_slice(extra);
            assert_eq!(original_guard_state_digest(&bytes), expected);
        }
        let mut cr = raw.to_vec();
        cr.extend_from_slice(b"\r\n");
        assert_ne!(original_guard_state_digest(&cr), expected);
        let mut space = raw.to_vec();
        space.extend_from_slice(b" \n");
        assert_ne!(original_guard_state_digest(&space), expected);
        assert_ne!(
            hex::encode(Sha256::digest([raw.as_slice(), b"\n"].concat())),
            expected
        );
    }
    #[test]
    fn exact_manager_recipe_matches_original_marker_and_refuses_same_count_drift() {
        let binding = OriginalGuardBinding {
            schema: "aegis_device_guard_binding_v1".into(),
            boot_id: "00112233-4455-6677-8899-aabbccddeeff".into(),
            state_sha256: "26c8c52d2bc0c6984145e84f108b906030f425d05e37c7a7122d753ec425e6b6".into(),
            path: "system.slice/systemd-networkd.service".into(),
            inode: "1234".into(),
            invocation: "b".repeat(32),
        };
        for (d4, d6, count) in [
            (false, false, 0),
            (true, false, 1),
            (false, true, 1),
            (true, true, 2),
        ] {
            let mut p = policy();
            p.uplink = "enp1s0".into();
            p.dhcp4 = d4;
            p.dhcp6 = d6;
            let actual = p.expected_manager(&binding).unwrap();
            assert!(p.verify_manager(&actual, &binding).is_ok());
            let grants = actual["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["rule"]["comment"].as_str().is_some())
                .collect::<Vec<_>>();
            assert_eq!(grants.len(), count);
            for r in &grants {
                assert_eq!(
                    r["rule"]["comment"],
                    "aegis-v2-464d5c45b9d04edafd0b46f07075b298bdaa47c7bfbbaeb9d9d30f2e48cabf03"
                );
                assert_eq!(r["rule"]["expr"][5]["match"]["left"]["socket"]["level"], 2);
            }
            if count > 0 {
                assert!(p.verify(&actual).is_err());
                let index = actual["nftables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|r| r["rule"]["comment"].as_str().is_some())
                    .unwrap();
                for field in ["comment", "port", "role", "extra"] {
                    let mut bad = actual.clone();
                    match field {
                        "comment" => bad["nftables"][index]["rule"]["comment"] = json!("foreign"),
                        "port" => {
                            bad["nftables"][index]["rule"]["expr"][4]["match"]["right"] = json!(443)
                        }
                        "role" => {
                            bad["nftables"][index]["rule"]["expr"][5]["match"]["right"] =
                                json!("system.slice/foreign.service")
                        }
                        _ => {
                            bad["nftables"].as_array_mut().unwrap().push(json!({"rule":{"family":"inet","table":"aegis_device_guard","chain":"output","expr":[{"accept":null}]}}));
                        }
                    }
                    assert!(p.verify_manager(&bad, &binding).is_err());
                }
            }
        }
    }
    #[test]
    fn actual_original_bash_oracle_binds_dhcp_recipe_and_lf_hash() {
        // Public inert fixture is output of the two exact original Bash functions,
        // not a kernel readback or installed-policy acceptance fixture.
        let oracle: Value =
            serde_json::from_str(include_str!("original_guard_recipe_fixture.json")).unwrap();
        assert_eq!(
            oracle["oracle_receipt_sha256"],
            "50fee33bef4fade789515a6340dae21b56944d053a7305fc6acf2a9260dfa554"
        );
        assert_eq!(
            oracle["source_helper_sha256"],
            "2b110772e3dc74bc6fd2bde2f58a44e3e667447a0005c171359e27223f3a9a54"
        );
        let raw = b"{\"schema\":\"aegis_device_guard_v2\",\"public_fixture_only\":true}\n";
        for (name, d4, d6) in [
            ("unbound", false, false),
            ("dhcp4_manager_bound", true, false),
            ("dhcp6_manager_bound", false, true),
            ("both_manager_bound", true, true),
            ("static_manager_bound", false, false),
        ] {
            let fixture = &oracle["fixtures"][name];
            assert_eq!(original_guard_state_digest(raw), fixture["state_sha256"]);
            let binding = OriginalGuardBinding {
                schema: "aegis_device_guard_binding_v1".into(),
                boot_id: "00112233-4455-6677-8899-aabbccddeeff".into(),
                state_sha256: fixture["state_sha256"].as_str().unwrap().into(),
                path: "system.slice/systemd-networkd.service".into(),
                inode: "1234".into(),
                invocation: "b".repeat(32),
            };
            let mut p = policy();
            p.uplink = "enp1s0".into();
            p.dhcp4 = d4;
            p.dhcp6 = d6;
            let actual = p.expected_manager(&binding).unwrap();
            let rows = actual["nftables"].as_array().unwrap();
            let grants = rows
                .iter()
                .filter(|r| r["rule"]["comment"].is_string())
                .collect::<Vec<_>>();
            let bash_grants = fixture["rules"]
                .as_str()
                .unwrap()
                .lines()
                .filter(|l| l.contains(" socket cgroupv2 "))
                .collect::<Vec<_>>();
            assert_eq!(grants.len(), bash_grants.len());
            for (r, line) in grants.iter().zip(bash_grants) {
                let expr = r["rule"]["expr"].as_array().unwrap();
                let family = expr[1]["match"]["right"].as_str().unwrap();
                let sport = expr[3]["match"]["right"].as_u64().unwrap();
                let dport = expr[4]["match"]["right"].as_u64().unwrap();
                assert_eq!(r["rule"]["comment"], fixture["manager_marker"]);
                assert_eq!(line,format!("add rule inet aegis_device_guard output oifname \"enp1s0\" meta nfproto {family} udp sport {sport} udp dport {dport} socket cgroupv2 level 2 \"{}\" counter accept comment \"{}\"",binding.path,r["rule"]["comment"].as_str().unwrap()));
                assert_eq!(expr[2]["match"]["right"], 17);
            }
            let mut no_grants = actual.clone();
            no_grants["nftables"]
                .as_array_mut()
                .unwrap()
                .retain(|r| !r["rule"]["comment"].is_string());
            assert_eq!(no_grants, p.expected());
        }
    }
    #[test]
    fn manager_cgroup_path_and_level_remain_exact_for_supported_slices() {
        let mut p = policy();
        p.dhcp6 = true;
        let mut binding = OriginalGuardBinding {
            schema: "aegis_device_guard_binding_v1".into(),
            boot_id: "00112233-4455-6677-8899-aabbccddeeff".into(),
            state_sha256: "b".repeat(64),
            path: "network.slice/network-managed.slice/systemd-networkd.service".into(),
            inode: "1234".into(),
            invocation: "c".repeat(32),
        };
        for path in [
            "network.slice/network-managed.slice/systemd-networkd.service",
            "systemd-networkd.service",
        ] {
            binding.path = path.into();
            let actual = p.expected_manager(&binding).unwrap();
            for r in actual["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["rule"]["comment"].is_string())
            {
                assert_eq!(r["rule"]["expr"][5]["match"]["right"], path);
                assert_eq!(
                    r["rule"]["expr"][5]["match"]["left"]["socket"]["level"],
                    path.split('/').count()
                );
            }
            assert!(p.verify_manager(&actual, &binding).is_ok());
        }
        for path in [
            "/systemd-networkd.service",
            "a//systemd-networkd.service",
            "a/../systemd-networkd.service",
            "a/./systemd-networkd.service",
            "a/systemd-networkd.service/",
            "a/foreign.service",
            "a/NetworkManager.service",
            "a space/systemd-networkd.service",
        ] {
            binding.path = path.into();
            assert!(p.expected_manager(&binding).is_err());
        }
    }
    #[test]
    fn original_binding_public_schema_refuses_extra_duplicate_and_wrong_state() {
        let v = json!({"schema":"aegis_device_guard_binding_v1","boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","state_sha256":"b".repeat(64),"path":"system.slice/aegis-client.service","inode":"123","invocation":"c".repeat(32)});
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(validate_original_binding(
            &bytes,
            &"b".repeat(64),
            "system.slice/aegis-client.service"
        )
        .is_ok());
        let mut x = v.clone();
        x["secret"] = json!("refuse");
        assert!(validate_original_binding(
            &serde_json::to_vec(&x).unwrap(),
            &"b".repeat(64),
            "system.slice/aegis-client.service"
        )
        .is_err());
        assert!(validate_original_binding(
            &bytes,
            &"d".repeat(64),
            "system.slice/aegis-client.service"
        )
        .is_err());
        let x = String::from_utf8(bytes)
            .unwrap()
            .replacen("{", "{\"inode\":\"123\",", 1);
        assert!(validate_original_binding(
            x.as_bytes(),
            &"b".repeat(64),
            "system.slice/aegis-client.service"
        )
        .is_err());
    }
    #[test]
    fn inventory_errors_duplicates_wrong_family_never_absence() {
        assert!(!exact_table_present(&json!({"nftables":[]}), "ip", "own").unwrap());
        assert!(exact_table_present(
            &json!({"nftables":[{"table":{"family":"ip","name":"own"}}]}),
            "ip",
            "own"
        )
        .unwrap());
        for v in [
            json!({"error":"failed"}),
            json!({"nftables":[{"error":"failed"}]}),
            json!({"nftables":[{"table":{"family":"inet","name":"own"}}]}),
            json!({"nftables":[{"table":{"family":"ip","name":"own"}},{"table":{"family":"ip","name":"own"}}]}),
        ] {
            assert!(exact_table_present(&v, "ip", "own").is_err());
        }
    }
    #[test]
    fn receipt_archive_refuses_secret_extra_or_fabricated_scope() {
        let v = json!({"schema":"aegis_relay_geneva_owned_recovery_v1","instance":"abcdef12","source_commit":"b".repeat(40),"journal_sha256":"c".repeat(64),"status":"PASS_OWNED_RECOVERY_ONLY","old_process_absent":true,"all_recorded_socket_inodes_absent":true,"recorded_tun_absent":true,"owned_table_absent":true,"removed_exact_table":false,"kernel_installed_guard_acceptance":false});
        assert!(validate_recovery_receipt(&v, "abcdef12-123.json", &"b".repeat(40)).is_ok());
        for k in ["token", "private_key", "unknown"] {
            let mut x = v.clone();
            x[k] = json!("not admissible");
            assert!(validate_recovery_receipt(&x, "abcdef12-123.json", &"b".repeat(40)).is_err());
        }
        let mut x = v.clone();
        x["old_process_absent"] = json!("true");
        assert!(validate_recovery_receipt(&x, "abcdef12-123.json", &"b".repeat(40)).is_err());
        assert!(validate_recovery_receipt(&v, "different-123.json", &"b".repeat(40)).is_err());
    }
    #[test]
    fn complete_inet_block_and_same_count_grant_drift() {
        let p = policy();
        let a = p.expected();
        assert!(p.verify(&a).is_ok());
        let mut b = a.clone();
        b["nftables"][1]["chain"]["prio"] = json!(0);
        assert!(p.verify(&b).is_err());
        let mut b = a;
        b["nftables"][4]["rule"]["expr"][0] =
            json!({"match":{"left":{"meta":{"key":"mark"}},"right":42,"op":"=="}});
        assert!(p.verify(&b).is_err());
    }
    #[test]
    fn extra_or_reordered_rule_refused_counters_only_normalized() {
        let p = policy();
        let mut a = p.expected();
        a["nftables"][4]["rule"]["expr"][1] = json!({"counter":{"packets":5,"bytes":40}});
        assert!(p.verify(&a).is_ok());
        let row = a["nftables"][4].clone();
        a["nftables"].as_array_mut().unwrap().push(row);
        assert!(p.verify(&a).is_err());
        let mut a = p.expected();
        a["nftables"].as_array_mut().unwrap().swap(4, 5);
        assert!(p.verify(&a).is_err());
    }
    #[test]
    fn state_duplicates_disarm_unknown_and_code_refused() {
        let valid="schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\nuplink=eth0\nmanager=systemd-networkd.service\ncapture_interface=aegis-tun0\nmanagement_address_policy=current_local\nmanagement_ports=22\ndhcp4=0\ndhcp6=0\ninitramfs_network=absent_verified\n";
        assert!(DeviceBlockPolicy::from_state(valid).is_ok());
        let full =
            DeviceBlockPolicy::from_state(&format!("{valid}capture_profile=full-wide-tun\n"))
                .unwrap();
        let redirect =
            DeviceBlockPolicy::from_state(&format!("{valid}capture_profile=wide-redirect-safe\n"))
                .unwrap();
        assert_eq!(
            full.expected(),
            DeviceBlockPolicy::from_state(valid).unwrap().expected()
        );
        assert!(redirect.redirect_capture);
        assert_eq!(
            redirect.expected()["nftables"].as_array().unwrap().len() + 1,
            full.expected()["nftables"].as_array().unwrap().len()
        );
        assert!(redirect.verify(&full.expected()).is_err());
        for text in [
            format!("{valid}armed=1\n"),
            valid.replace("armed=1", "armed=0"),
            valid.replace("eth0", "eth0;sh"),
            format!("{valid}unknown=x\n"),
            format!("{valid}capture_profile=unknown\n"),
            format!("{valid}capture_profile=\n"),
            format!("{valid}capture_profile=wide-redirect-safe\ncapture_profile=full-wide-tun\n"),
        ] {
            assert!(DeviceBlockPolicy::from_state(&text).is_err());
        }
    }
    #[test]
    fn foreign_policy_state_requires_exact_optional_pair() {
        let valid="schema=aegis_device_guard_v2\narmed=1\nservice=aegis-client.service\nuplink=eth0\nmanager=systemd-networkd.service\ncapture_interface=aegis-tun0\nmanagement_address_policy=current_local\nmanagement_ports=22\ndhcp4=0\ndhcp6=0\ninitramfs_network=absent_verified\n";
        let pair = format!(
            "foreign_policy=filter_only\nufw_integrity_sha256={}\n",
            "a".repeat(64)
        );
        assert!(DeviceBlockPolicy::from_state(&format!("{valid}{pair}")).is_ok());
        for suffix in [
            "foreign_policy=filter_only\n".to_string(),
            format!("ufw_integrity_sha256={}\n", "a".repeat(64)),
            pair.replace("filter_only", "unknown"),
            pair.replace(&"a".repeat(64), &"A".repeat(64)),
            pair.replace(&"a".repeat(64), &"a".repeat(63)),
            format!("{pair}foreign_policy=filter_only\n"),
        ] {
            assert!(DeviceBlockPolicy::from_state(&format!("{valid}{suffix}")).is_err());
        }
    }

    #[test]
    fn durable_phase_cannot_skip_archive_or_change_owned_hash() {
        let mut r = TeardownRecord {
            schema: "aegis_selected_teardown_v1".into(),
            token: "a".repeat(32),
            source: "b".repeat(40),
            phase: Phase::Intent,
            profile_sha256: "c".repeat(64),
            directory_manifest_sha256: "a".repeat(64),
            archive_device: 1,
            archive_inode: 2,
            archive_manifest_sha256: None,
            original_inet_digest: "d".repeat(64),
            initial_original_inet_digest: "d".repeat(64),
            initial_manager_identity_sha256: None,
            initial_manager_binding_sha256: None,
            selected_netdev_digest: "e".repeat(64),
            owned_files: BTreeMap::from([(
                "/exact".into(),
                FilePin {
                    device: 1,
                    inode: 2,
                    sha256: "f".repeat(64),
                    size: 4,
                    mode: 0o600,
                },
            )]),
        };
        assert!(r
            .advance(Phase::PayloadRemoved, Some(&"a".repeat(64)))
            .is_err());
        assert!(r.advance(Phase::ArchiveCommitted, None).is_err());
        r = r
            .advance(Phase::ArchiveCommitted, Some(&"a".repeat(64)))
            .unwrap();
        assert!(r
            .advance(Phase::NativeQuiet, Some(&"b".repeat(64)))
            .is_err());
        for phase in [
            Phase::NativeQuiet,
            Phase::DropInRemoved,
            Phase::PayloadRemoved,
            Phase::GateRemoved,
            Phase::Complete,
        ] {
            r = r.advance(phase, None).unwrap();
        }
        assert!(r.advance(Phase::Complete, None).is_err());
    }
}
