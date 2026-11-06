//! Explicit selected-service guard contract. Pure public data; no kernel I/O.
//! The existing default persistent guard has no dependency on this module.
//! Raw link-header matches preserve deliberate IPv4 version/length/checksum
//! changes. Bound admission is still only marked local-to-relay TCP traffic.
use super::RelayOuterGenevaSettings;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io,
    net::{Ipv4Addr, SocketAddrV4},
};

pub const TABLE: &str = "aegis_relay_geneva_device_guard";
const SCHEMA: &str = "aegis_relay_geneva_installed_guard_v1";
const MAX_ROWS: usize = 196;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicGuardPolicy {
    pub schema: String,
    pub source_commit: String,
    pub interface: String,
    pub local_address: Ipv4Addr,
    pub socket_mark: u32,
    pub relay_endpoints: Vec<SocketAddrV4>,
    pub device_guard_state_sha256: String,
}

/// Constructed only after fresh existing guard role/PID/invocation readback.
/// A caller must not use an unverified on-disk binding as this authorization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentClientBinding {
    pub boot_id: String,
    pub invocation_id: String,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
}

/// Opaque permission for native mark-reservation inspection. It applies to
/// exactly the complete table validated below, never a prefix or other object.
#[derive(Clone, Debug)]
pub struct InstalledGuardProof {
    table_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    source_commit: String,
    interface: String,
    socket_mark: u32,
}
impl InstalledGuardProof {
    pub fn table_name(&self) -> &'static str {
        TABLE
    }
    pub fn table_family(&self) -> &'static str {
        "netdev"
    }
    pub fn policy_sha256(&self) -> [u8; 32] {
        self.policy_sha256
    }
    pub fn table_sha256(&self) -> [u8; 32] {
        self.table_sha256
    }
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub fn interface(&self) -> &str {
        &self.interface
    }
    pub fn socket_mark(&self) -> u32 {
        self.socket_mark
    }
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "selected installed guard contract refused",
    )
}
fn need(ok: bool) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(refused())
    }
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unicast(a: Ipv4Addr) -> bool {
    !a.is_unspecified() && !a.is_multicast() && !a.is_broadcast() && !a.is_loopback()
}
impl PublicGuardPolicy {
    fn validate_public(&self) -> io::Result<()> {
        need(
            self.schema == SCHEMA
                && hex(&self.source_commit, 40)
                && hex(&self.device_guard_state_sha256, 64),
        )?;
        need(
            !self.interface.is_empty()
                && self.interface.len() <= 15
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && self.socket_mark != 0
                && unicast(self.local_address),
        )?;
        need(!self.relay_endpoints.is_empty() && self.relay_endpoints.len() <= 16)?;
        let mut seen = BTreeSet::new();
        for endpoint in &self.relay_endpoints {
            need(
                unicast(*endpoint.ip())
                    && *endpoint.ip() != self.local_address
                    && endpoint.port() != 0
                    && seen.insert(*endpoint),
            )?;
        }
        Ok(())
    }
    pub fn validate(
        &self,
        source: &str,
        request: &RelayOuterGenevaSettings,
        endpoints: &[SocketAddrV4],
    ) -> io::Result<()> {
        self.validate_public()?;
        need(hex(source, 40) && self.source_commit == source)?;
        need(
            hex(&self.device_guard_state_sha256, 64)
                && self.interface == request.interface
                && self.socket_mark == request.socket_mark
                && self.local_address == request.local_address,
        )?;
        need(
            !self.interface.is_empty()
                && self.interface.len() <= 15
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && self.socket_mark != 0
                && unicast(self.local_address),
        )?;
        need(!endpoints.is_empty() && endpoints.len() <= 16 && self.relay_endpoints == endpoints)?;
        let mut seen = BTreeSet::new();
        for e in endpoints {
            need(
                unicast(*e.ip())
                    && *e.ip() != self.local_address
                    && e.port() != 0
                    && seen.insert(*e),
            )?;
        }
        Ok(())
    }
    pub fn digest(&self) -> io::Result<[u8; 32]> {
        self.validate_public()?;
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|_| refused())?).into())
    }
}
fn binding_digest(binding: Option<&CurrentClientBinding>) -> io::Result<String> {
    let Some(b) = binding else {
        return Ok("blocked".into());
    };
    need(
        b.boot_id.len() == 36
            && b.boot_id.bytes().enumerate().all(|(i, v)| {
                if [8, 13, 18, 23].contains(&i) {
                    v == b'-'
                } else {
                    v.is_ascii_digit() || (b'a'..=b'f').contains(&v)
                }
            }),
    )?;
    need(
        hex(&b.invocation_id, 32)
            && b.cgroup_inode != 0
            && b.cgroup_path.starts_with('/')
            && b.cgroup_path != "/"
            && b.cgroup_path.len() <= 256
            && !b.cgroup_path.ends_with('/')
            && !b.cgroup_path.contains("//"),
    )?;
    need(
        b.cgroup_path
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"_.@:/-".contains(&v))
            && !b.cgroup_path.split('/').any(|x| x == "." || x == ".."),
    )?;
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&json!([
            b.boot_id,
            b.invocation_id,
            b.cgroup_path,
            b.cgroup_inode
        ]))
        .map_err(|_| refused())?,
    )))
}
/// Packet layout offsets are bytes; the libnftables JSON ABI is BITS.
/// Narrow byte types make conversion to u32 bits total (no wrapping).
fn raw_bytes(offset: u16, len: u8) -> Value {
    let offset_bits = u32::from(offset) * 8;
    let length_bits = u32::from(len) * 8;
    json!({"payload":{"base":"ll","offset":offset_bits,"len":length_bits}})
}
fn cmp(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
fn mark(p: &PublicGuardPolicy) -> Value {
    cmp(json!({"meta":{"key":"mark"}}), json!(p.socket_mark))
}
fn masked(left: Value, mask: u32) -> Value {
    json!({"&":[left,mask]})
}
fn rule(expr: Vec<Value>) -> Value {
    json!({"rule":{"family":"netdev","table":TABLE,"chain":"egress","expr":expr}})
}
/// Complete expected gate. No counters, anonymous sets, routes or tc/qdisc.
/// Existing root-owned guard transactions must append this table update in the
/// SAME nft transaction as role revocation; then signal and await the exact
/// bound client and native worker before declaring the terminal drain barrier.
pub fn expected(
    policy: &PublicGuardPolicy,
    binding: Option<&CurrentClientBinding>,
) -> io::Result<Value> {
    let digest = policy.digest()?;
    let binding = binding_digest(binding)?;
    let stamp = hex::encode(Sha256::digest(
        [digest.as_slice(), binding.as_bytes()].concat(),
    ));
    let mut rows = vec![
        json!({"table":{"family":"netdev","name":TABLE,"comment":format!("aegis-relay-guard:{stamp}")}}),
        json!({"chain":{"family":"netdev","table":TABLE,"name":"egress","type":"filter","hook":"egress","prio":10,"dev":policy.interface,"policy":"accept"}}),
    ];
    if binding != "blocked" {
        for endpoint in &policy.relay_endpoints {
            let common = vec![
                mark(policy),
                cmp(raw_bytes(12, 2), json!(0x0800)),
                cmp(raw_bytes(23, 1), json!(6)),
                cmp(raw_bytes(26, 4), json!(u32::from(policy.local_address))),
                cmp(raw_bytes(30, 4), json!(u32::from(*endpoint.ip()))),
            ];
            // Noninitial fragments have no ports; all originate from a whole
            // batch already checked against the registered native relay tuple.
            let mut fragments = common.clone();
            fragments
                .push(json!({"match":{"op":"!=","left":masked(raw_bytes(20,2),0x1fff),"right":0}}));
            fragments.push(json!({"accept":null}));
            rows.push(rule(fragments));
            for ihl in 5..=15 {
                let mut full = common.clone();
                full.push(cmp(masked(raw_bytes(14, 1), 15), json!(ihl)));
                full.push(cmp(masked(raw_bytes(20, 2), 0x1fff), json!(0)));
                full.push(cmp(raw_bytes(14 + ihl * 4 + 2, 2), json!(endpoint.port())));
                full.push(json!({"accept":null}));
                rows.push(rule(full));
            }
        }
    }
    rows.push(rule(vec![mark(policy), json!({"drop":null})]));
    need(rows.len() <= MAX_ROWS)?;
    Ok(json!({"nftables":rows}))
}
/// Creation or replacement commands to append to the original guard's atomic
/// transaction. Replacement is allowed only after exact owned table validation.
pub fn transaction(
    policy: &PublicGuardPolicy,
    binding: Option<&CurrentClientBinding>,
    replace_owned: bool,
) -> io::Result<Value> {
    let mut expected = expected(policy, binding)?;
    let mut rows = Vec::new();
    if replace_owned {
        rows.push(json!({"delete":{"table":{"family":"netdev","name":TABLE}}}));
    }
    for object in expected["nftables"].as_array_mut().ok_or_else(refused)? {
        let kind = if object.get("rule").is_some() {
            "add"
        } else {
            "create"
        };
        rows.push(json!({kind:object.take()}));
    }
    Ok(json!({"nftables":rows}))
}
/// Text form appended to the EXISTING inet guard batch, not applied separately.
/// It is rendered from the same typed JSON ABI expression tree validated above.
/// No caller-supplied nft tokens or filenames are interpolated as syntax.
pub fn transaction_text(
    policy: &PublicGuardPolicy,
    binding: Option<&CurrentClientBinding>,
    replace_owned: bool,
) -> io::Result<String> {
    use std::fmt::Write;
    fn number(v: &Value) -> io::Result<u64> {
        v.as_u64().ok_or_else(refused)
    }
    fn operand(v: &Value) -> io::Result<String> {
        if v.get("meta") == Some(&json!({"key":"mark"})) {
            return Ok("meta mark".into());
        }
        if let Some(p) = v.get("payload").and_then(Value::as_object) {
            need(p.len() == 3 && p.get("base") == Some(&json!("ll")))?;
            return Ok(format!(
                "@ll,{},{}",
                number(&p["offset"])?,
                number(&p["len"])?
            ));
        }
        if let Some(pair) = v.get("&").and_then(Value::as_array) {
            need(pair.len() == 2)?;
            return Ok(format!(
                "{} & 0x{:x}",
                operand(&pair[0])?,
                number(&pair[1])?
            ));
        }
        Err(refused())
    }
    let tx = transaction(policy, binding, replace_owned)?;
    let mut text = String::new();
    for command in tx["nftables"].as_array().ok_or_else(refused)? {
        if command.get("delete").is_some() {
            writeln!(text, "delete table netdev {TABLE}").map_err(|_| refused())?;
            continue;
        }
        let object = command
            .get("create")
            .or_else(|| command.get("add"))
            .ok_or_else(refused)?;
        if let Some(table) = object.get("table") {
            let comment = table["comment"].as_str().ok_or_else(refused)?;
            need(
                comment
                    .strip_prefix("aegis-relay-guard:")
                    .is_some_and(|s| hex(s, 64)),
            )?;
            writeln!(
                text,
                "create table netdev {TABLE} {{ comment \"{comment}\"; }}"
            )
            .map_err(|_| refused())?;
        } else if object.get("chain").is_some() {
            writeln!(text,"create chain netdev {TABLE} egress {{ type filter hook egress device \"{}\" priority 10; policy accept; }}",policy.interface).map_err(|_|refused())?;
        } else if let Some(rule) = object.get("rule") {
            write!(text, "add rule netdev {TABLE} egress").map_err(|_| refused())?;
            for expr in rule["expr"].as_array().ok_or_else(refused)? {
                if let Some(m) = expr.get("match") {
                    let op = m["op"].as_str().ok_or_else(refused)?;
                    need(["==", "!="].contains(&op))?;
                    write!(
                        text,
                        " {} {op} 0x{:x}",
                        operand(&m["left"])?,
                        number(&m["right"])?
                    )
                    .map_err(|_| refused())?;
                } else if expr.get("accept") == Some(&Value::Null) {
                    text.push_str(" accept");
                } else if expr.get("drop") == Some(&Value::Null) {
                    text.push_str(" drop");
                } else {
                    return Err(refused());
                }
            }
            text.push('\n');
        } else {
            return Err(refused());
        }
    }
    need(text.len() <= 262144)?;
    Ok(text)
}
fn canonical(actual: &Value) -> io::Result<Value> {
    let map = actual.as_object().ok_or_else(refused)?;
    need(map.len() == 1)?;
    let mut rows = Vec::new();
    let input_rows = map
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    need(input_rows.len() <= MAX_ROWS + 1)?;
    for row in map
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(refused)?
    {
        let obj = row.as_object().ok_or_else(refused)?;
        need(obj.len() == 1)?;
        if let Some(meta) = obj.get("metainfo") {
            need(meta.is_object())?;
            continue;
        }
        let mut row = row.clone();
        let (key, body) = row
            .as_object_mut()
            .ok_or_else(refused)?
            .iter_mut()
            .next()
            .ok_or_else(refused)?;
        need(["table", "chain", "rule"].contains(&key.as_str()))?;
        let body = body.as_object_mut().ok_or_else(refused)?;
        if let Some(handle) = body.remove("handle") {
            need(handle.as_u64().is_some())?;
        }
        rows.push(row);
        need(rows.len() <= MAX_ROWS)?;
    }
    // Object order may differ, rule order may NEVER differ.
    let mut objects = rows
        .iter()
        .filter(|r| r.get("rule").is_none())
        .cloned()
        .collect::<Vec<_>>();
    objects.sort_by_key(|r| r.to_string());
    objects.extend(rows.into_iter().filter(|r| r.get("rule").is_some()));
    Ok(json!({"nftables":objects}))
}
/// Caller first validates policy against trusted source/request/endpoints and
/// proves root-owned file provenance plus fresh role binding. This function
/// proves complete kernel table semantics; it does not fabricate that evidence.
/// Digest the exact normalized table snapshot already read by the native
/// driver. This is not authorization; only verify_observation creates a proof.
/// Prove presence/absence from a typed complete `nft list tables` inventory.
/// A same-name wrong-family table, duplicate or malformed row is never absence.
pub fn selected_table_present(inventory: &Value) -> io::Result<bool> {
    let object = inventory.as_object().ok_or_else(refused)?;
    need(object.len() == 1)?;
    let rows = object
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    need(rows.len() <= 8192)?;
    let mut found = false;
    for row in rows {
        let fields = row.as_object().ok_or_else(refused)?;
        need(fields.len() == 1)?;
        if let Some(meta) = fields.get("metainfo") {
            need(meta.is_object())?;
            continue;
        }
        let table = fields
            .get("table")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        let name = table
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        let family = table
            .get("family")
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        need(
            !name.is_empty()
                && name.len() <= 255
                && ["ip", "ip6", "inet", "arp", "bridge", "netdev"].contains(&family),
        )?;
        if name == TABLE {
            need(family == "netdev" && !found)?;
            found = true;
        }
    }
    Ok(found)
}

pub fn canonical_table_digest(actual: &Value) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(&canonical(actual)?).map_err(|_| refused())?).into())
}

pub fn verify_observation(
    actual: &Value,
    policy: &PublicGuardPolicy,
    binding: Option<&CurrentClientBinding>,
    source: &str,
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
) -> io::Result<InstalledGuardProof> {
    policy.validate(source, request, endpoints)?;
    let observed = canonical(actual)?;
    need(observed == canonical(&expected(policy, binding)?)?)?;
    Ok(InstalledGuardProof {
        table_sha256: Sha256::digest(serde_json::to_vec(&observed).map_err(|_| refused())?).into(),
        policy_sha256: policy.digest()?,
        source_commit: source.into(),
        interface: policy.interface.clone(),
        socket_mark: policy.socket_mark,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn complete_inventory_absence_refuses_wrong_family_duplicate_and_malformed_rows() {
        use super::{selected_table_present, TABLE};
        assert!(!selected_table_present(&serde_json::json!({"nftables":[{"metainfo":{"version":"1.1"}},{"table":{"family":"inet","name":"aegis_device_guard","handle":3}}]})).unwrap());
        let table = serde_json::json!({"table":{"family":"netdev","name":TABLE,"handle":1}});
        assert!(selected_table_present(&serde_json::json!({"nftables":[table.clone()]})).unwrap());
        for bad in [
            serde_json::json!({"nftables":[{"table":{"family":"ip","name":TABLE}}]}),
            serde_json::json!({"nftables":[table.clone(),table]}),
            serde_json::json!({"nftables":[{"error":"query failed"}]}),
            serde_json::json!({"nftables":[{"table":{"name":TABLE}}]}),
            serde_json::json!({"nftables":[{"metainfo":null}]}),
            serde_json::json!({"nftables":[],"error":"truncated"}),
        ] {
            assert!(selected_table_present(&bad).is_err(), "{bad}");
        }
    }

    use super::*;
    fn inputs() -> (
        PublicGuardPolicy,
        RelayOuterGenevaSettings,
        Vec<SocketAddrV4>,
        CurrentClientBinding,
    ) {
        let endpoints = vec!["192.0.2.3:24443".parse().unwrap()];
        let p = PublicGuardPolicy {
            schema: SCHEMA.into(),
            source_commit: "a".repeat(40),
            interface: "client0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            socket_mark: 0x5a71,
            relay_endpoints: endpoints.clone(),
            device_guard_state_sha256: "b".repeat(64),
        };
        let r = RelayOuterGenevaSettings {
            strategy: "[IP:ttl:64]-drop-|".into(),
            interface: p.interface.clone(),
            local_address: p.local_address,
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            outbound_queue: 431,
            inbound_queue: 432,
            socket_mark: p.socket_mark,
            max_duration_secs: 24,
        };
        let b = CurrentClientBinding {
            boot_id: "00000000-0000-0000-0000-000000000000".into(),
            invocation_id: "c".repeat(32),
            cgroup_path: "/system.slice/aegis-client.service".into(),
            cgroup_inode: 42,
        };
        (p, r, endpoints, b)
    }
    #[test]
    fn raw_payload_json_uses_primary_abi_bit_units_for_real_fields() {
        let (p, _, _, b) = inputs();
        let table = expected(&p, Some(&b)).unwrap();
        let fragments = &table["nftables"][2]["rule"]["expr"];
        // Literal ABI expectations, independent of the renderer/helper.
        assert_eq!(
            fragments[1]["match"]["left"],
            json!({"payload":{"base":"ll","offset":96,"len":16}})
        );
        assert_eq!(
            fragments[2]["match"]["left"],
            json!({"payload":{"base":"ll","offset":184,"len":8}})
        );
        assert_eq!(
            fragments[3]["match"]["left"],
            json!({"payload":{"base":"ll","offset":208,"len":32}})
        );
        assert_eq!(
            fragments[4]["match"]["left"],
            json!({"payload":{"base":"ll","offset":240,"len":32}})
        );
        assert_eq!(
            fragments[5]["match"]["left"]["&"][0],
            json!({"payload":{"base":"ll","offset":160,"len":16}})
        );
        let ihl5 = &table["nftables"][3]["rule"]["expr"];
        assert_eq!(
            ihl5[5]["match"]["left"]["&"][0],
            json!({"payload":{"base":"ll","offset":112,"len":8}})
        );
        assert_eq!(
            ihl5[7]["match"]["left"],
            json!({"payload":{"base":"ll","offset":288,"len":16}})
        );
        let ihl15 = &table["nftables"][13]["rule"]["expr"];
        assert_eq!(
            ihl15[7]["match"]["left"],
            json!({"payload":{"base":"ll","offset":608,"len":16}})
        );
    }
    #[test]
    fn historical_byte_unit_table_is_refused_even_with_matching_object_count() {
        let (p, r, e, b) = inputs();
        let mut old = expected(&p, Some(&b)).unwrap();
        fn regress(v: &mut Value) {
            match v {
                Value::Object(map) => {
                    if let Some(body) = map.get_mut("payload").and_then(Value::as_object_mut) {
                        for key in ["offset", "len"] {
                            let bits = body[key].as_u64().unwrap();
                            body.insert(key.into(), json!(bits / 8));
                        }
                    }
                    for child in map.values_mut() {
                        regress(child);
                    }
                }
                Value::Array(rows) => {
                    for row in rows {
                        regress(row);
                    }
                }
                _ => {}
            }
        }
        regress(&mut old);
        assert!(verify_observation(&old, &p, Some(&b), &p.source_commit, &r, &e).is_err());
    }
    #[test]
    fn text_batch_keeps_same_real_bit_abi_and_no_generic_token_inputs() {
        let (p, _, _, b) = inputs();
        let script = transaction_text(&p, Some(&b), true).unwrap();
        assert!(script.starts_with(
            "delete table netdev aegis_relay_geneva_device_guard\ncreate table netdev"
        ));
        assert!(script.contains("@ll,96,16 == 0x800"));
        assert!(script.contains("@ll,208,32 == 0xc0000202"));
        assert!(script.contains("@ll,112,8 & 0xf == 0x5"));
        assert!(script.contains("@ll,288,16 == 0x5f7b"));
        let mut invalid = p;
        invalid.interface = "client0; accept".into();
        assert!(transaction_text(&invalid, None, false).is_err());
    }
    #[test]
    fn exact_block_and_bound_gate_differ_and_cannot_inherit_permission() {
        let (p, r, e, b) = inputs();
        let blocked = expected(&p, None).unwrap();
        let bound = expected(&p, Some(&b)).unwrap();
        assert_eq!(blocked["nftables"].as_array().unwrap().len(), 3);
        assert!(verify_observation(&blocked, &p, None, &p.source_commit, &r, &e).is_ok());
        assert!(verify_observation(&blocked, &p, Some(&b), &p.source_commit, &r, &e).is_err());
        assert!(verify_observation(&bound, &p, None, &p.source_commit, &r, &e).is_err());
    }
    #[test]
    fn same_count_mark_interface_endpoint_or_order_drift_refused() {
        let (p, r, e, b) = inputs();
        let bound = expected(&p, Some(&b)).unwrap();
        for index in [0, 1, 2, 14] {
            let mut drift = bound.clone();
            let body = drift["nftables"][index]
                .as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap();
            body["foreign"] = json!(true);
            assert!(verify_observation(&drift, &p, Some(&b), &p.source_commit, &r, &e).is_err());
        }
        let mut drift = bound.clone();
        drift["nftables"].as_array_mut().unwrap().swap(2, 3);
        assert!(verify_observation(&drift, &p, Some(&b), &p.source_commit, &r, &e).is_err());
    }
    #[test]
    fn source_request_and_relay_membership_are_independent_pins() {
        let (p, r, e, b) = inputs();
        let actual = expected(&p, Some(&b)).unwrap();
        assert!(verify_observation(&actual, &p, Some(&b), &"f".repeat(40), &r, &e).is_err());
        let mut other = r.clone();
        other.socket_mark += 1;
        assert!(verify_observation(&actual, &p, Some(&b), &p.source_commit, &other, &e).is_err());
        assert!(verify_observation(
            &actual,
            &p,
            Some(&b),
            &p.source_commit,
            &r,
            &["192.0.2.4:24443".parse().unwrap()]
        )
        .is_err());
    }
    #[test]
    fn duplicate_fields_extra_objects_and_fake_binding_fail_closed() {
        let (p, r, e, mut b) = inputs();
        b.invocation_id = "not-an-invocation".into();
        assert!(expected(&p, Some(&b)).is_err());
        let mut actual = expected(&p, None).unwrap();
        actual["nftables"]
            .as_array_mut()
            .unwrap()
            .push(json!({"set":{"name":"foreign"}}));
        assert!(verify_observation(&actual, &p, None, &p.source_commit, &r, &e).is_err());
        let text = serde_json::to_string(&p).unwrap().replacen(
            "\"schema\":",
            "\"schema\":\"duplicate\",\"schema\":",
            1,
        );
        assert!(serde_json::from_str::<PublicGuardPolicy>(&text).is_err());
    }
    #[test]
    fn atomic_commands_recreate_only_the_exact_verified_table() {
        let (p, _, _, b) = inputs();
        let tx = transaction(&p, Some(&b), true).unwrap();
        let rows = tx["nftables"].as_array().unwrap();
        assert_eq!(
            rows[0],
            json!({"delete":{"table":{"family":"netdev","name":TABLE}}})
        );
        assert!(rows[1].get("create").unwrap().get("table").is_some());
        assert!(rows[3].get("add").unwrap().get("rule").is_some());
    }
}
