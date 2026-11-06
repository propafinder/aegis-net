//! Strict reconstruction of public native journal intent. No kernel or file I/O.
//! A privileged adapter must independently prove old process/socket/TUN absence,
//! exact current namespace and complete nft semantics before any deletion.
use super::{RelayFlowPin, RelayOuterGenevaSettings};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{Ipv4Addr, SocketAddrV4},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicRequest {
    pub interface: String,
    pub local_address: Ipv4Addr,
    pub local_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
    pub socket_mark: u32,
    pub outbound_queue: u16,
    pub inbound_queue: u16,
    pub max_duration_secs: u16,
}
impl From<&RelayOuterGenevaSettings> for PublicRequest {
    fn from(r: &RelayOuterGenevaSettings) -> Self {
        Self {
            interface: r.interface.clone(),
            local_address: r.local_address,
            local_mac: r.local_mac,
            next_hop_mac: r.next_hop_mac,
            socket_mark: r.socket_mark,
            outbound_queue: r.outbound_queue,
            inbound_queue: r.inbound_queue,
            max_duration_secs: r.max_duration_secs,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub network_namespace_inode: u64,
    pub network_namespace_device: u64,
    pub service_invocation_id: Option<String>,
    pub unified_cgroup: String,
    pub service_profile_measured: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupIntent {
    pub schema: String,
    pub instance: String,
    pub process_identity: ProcessIdentity,
    pub table: String,
    pub tun: String,
    pub request_public: PublicRequest,
    pub endpoints_public: Vec<SocketAddrV4>,
    pub owned_flows: u64,
    pub strategy_sha256: String,
    pub executable_sha256: String,
    pub source_stamp: String,
    pub controlled_native_acceptance: bool,
}
/// Caller-owned trusted candidate/config; never derived from the journal.
pub struct RecoveryTrust<'a> {
    pub source: &'a str,
    pub executable_sha256: &'a str,
    pub request: &'a RelayOuterGenevaSettings,
    pub endpoints: &'a [SocketAddrV4],
    pub boot_id: &'a str,
    pub network_namespace_inode: u64,
    pub network_namespace_device: u64,
    pub cgroup_path: &'a str,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicTuple {
    local: Ipv4Addr,
    relay: Ipv4Addr,
    local_port: u16,
    relay_port: u16,
}
impl PublicTuple {
    fn pin(self) -> RelayFlowPin {
        RelayFlowPin {
            local: self.local,
            relay: self.relay,
            local_port: self.local_port,
            relay_port: self.relay_port,
        }
    }
}
#[derive(Clone, Debug)]
pub struct RecoveryPlan {
    pub intent: SetupIntent,
    /// All historical inodes must be absent; even an inode reused by an unrelated
    /// current socket causes refusal, never a kill or ownership adoption.
    pub socket_inodes: BTreeSet<u64>,
    /// Only unresolved arm intents may exist in the exact observed kernel set.
    pub unresolved_flows: Vec<RelayFlowPin>,
    pub terminal_quiesced_recorded: bool,
    pub journal_sha256: [u8; 32],
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "owned relay recovery intent refused",
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
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn typed<T: for<'de> Deserialize<'de>>(v: Value) -> io::Result<T> {
    serde_json::from_value(v).map_err(|_| refused())
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, v)| {
            if [8, 13, 18, 23].contains(&i) {
                v == b'-'
            } else {
                v.is_ascii_digit() || (b'a'..=b'f').contains(&v)
            }
        })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arm {
    token: u64,
    socket_inode: u64,
    tuple: PublicTuple,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmed {
    token: u64,
    socket_inode: u64,
    tuple: PublicTuple,
    presence: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retire {
    token: u64,
    socket_inode: u64,
    tuple: PublicTuple,
    element_presence: Option<bool>,
    kernel_inode_proof_pending: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delete {
    token: u64,
    socket_inode: u64,
    tuple: PublicTuple,
    last_socket_inode_absent: bool,
    element_presence: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    token: u64,
    socket_inode: u64,
    tuple: PublicTuple,
    last_socket_inode_absent: bool,
    tuple_element_removed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Quiesced {
    owned_flows: u64,
    worker_terminal: bool,
    table_removed: bool,
}
#[derive(Clone, Copy)]
struct Flow {
    inode: u64,
    tuple: PublicTuple,
    retiring: bool,
}

/// Records are exact bytes in contiguous decimal filename order. No gaps,
/// duplicate keys or partial records can become a usable recovery plan.
pub fn reconstruct(
    records: &[(String, Vec<u8>)],
    trust: &RecoveryTrust<'_>,
) -> io::Result<RecoveryPlan> {
    need(!records.is_empty() && records.len() <= 8200)?;
    let mut total = 0usize;
    let mut digest = Sha256::new();
    let mut decoded = Vec::new();
    for (index, (name, bytes)) in records.iter().enumerate() {
        total = total.checked_add(bytes.len()).ok_or_else(refused)?;
        need(bytes.len() <= 65536 && total <= 18 * 1048576)?;
        let prefix = format!("{index:08}_");
        let phase = name
            .strip_prefix(&prefix)
            .and_then(|n| n.strip_suffix(".json"))
            .ok_or_else(refused)?;
        need(
            !phase.is_empty()
                && phase
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'_'),
        )?;
        // Standard Value accepts duplicate keys. The custom visitor below
        // rejects them recursively before typed schema parsing.
        let value = parse_unique_public_metadata(bytes)?;
        need(value.is_object())?;
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        decoded.push((phase.to_string(), value));
    }
    need(decoded[0].0 == "setup_intent")?;
    let intent: SetupIntent = typed(decoded[0].1.clone())?;
    need(
        intent.schema == "aegis_relay_geneva_native_intent_v1"
            && hex(&intent.instance, 8)
            && intent.table == format!("aegis_rg_{}", intent.instance)
            && intent.tun == format!("agv{}", intent.instance)
            && intent.owned_flows == 0
            && !intent.controlled_native_acceptance
            && hex(trust.source, 40)
            && intent.source_stamp == trust.source
            && hex(trust.executable_sha256, 64)
            && intent.executable_sha256 == trust.executable_sha256
            && intent.strategy_sha256
                == hex::encode(Sha256::digest(trust.request.strategy.as_bytes()))
            && intent.request_public == PublicRequest::from(trust.request),
    )?;
    let mut endpoints = trust.endpoints.to_vec();
    endpoints.sort_unstable();
    endpoints.dedup();
    need(!endpoints.is_empty() && endpoints.len() <= 16 && endpoints == intent.endpoints_public)?;
    let p = &intent.process_identity;
    need(
        uuid(&p.boot_id)
            && p.boot_id == trust.boot_id
            && p.pid > 0
            && p.start_ticks > 0
            && p.network_namespace_inode > 0
            && p.network_namespace_inode == trust.network_namespace_inode
            && p.network_namespace_device == trust.network_namespace_device
            && p.unified_cgroup == format!("0::{}", trust.cgroup_path)
            && trust.cgroup_path.starts_with('/')
            && trust.cgroup_path != "/"
            && p.service_invocation_id
                .as_deref()
                .is_some_and(|s| hex(s, 32)),
    )?;
    let mut flows: BTreeMap<u64, Flow> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut seen_tuples = BTreeSet::new();
    let mut socket_inodes = BTreeSet::new();
    let mut terminal = false;
    for (phase, value) in decoded.into_iter().skip(1) {
        need(!terminal)?;
        match phase.as_str() {
            "flow_arm_intent" => {
                let row: Arm = typed(value)?;
                need(
                    row.token > 0
                        && row.socket_inode > 0
                        && seen.insert(row.token)
                        && seen.len() <= 1024
                        && flows.len() < 128
                        && row.tuple.local == trust.request.local_address
                        && row.tuple.local_port != 0
                        && endpoints
                            .contains(&SocketAddrV4::new(row.tuple.relay, row.tuple.relay_port))
                        && seen_tuples.insert((
                            row.tuple.local,
                            row.tuple.local_port,
                            row.tuple.relay,
                            row.tuple.relay_port,
                        )),
                )?;
                socket_inodes.insert(row.socket_inode);
                flows.insert(
                    row.token,
                    Flow {
                        inode: row.socket_inode,
                        tuple: row.tuple,
                        retiring: false,
                    },
                );
            }
            "flow_arm_confirmed" => {
                let row: Confirmed = typed(value)?;
                let f = flows.get(&row.token).ok_or_else(refused)?;
                need(
                    row.presence
                        && !f.retiring
                        && f.inode == row.socket_inode
                        && f.tuple == row.tuple,
                )?;
            }
            "flow_retire_intent" => {
                let row: Retire = typed(value)?;
                let f = flows.get_mut(&row.token).ok_or_else(refused)?;
                need(
                    row.kernel_inode_proof_pending
                        && f.inode == row.socket_inode
                        && f.tuple == row.tuple,
                )?;
                let _ = row.element_presence;
                f.retiring = true;
            }
            "flow_delete_intent" => {
                let row: Delete = typed(value)?;
                let f = flows.get_mut(&row.token).ok_or_else(refused)?;
                need(
                    row.last_socket_inode_absent
                        && row.element_presence.is_none()
                        && f.retiring
                        && f.inode == row.socket_inode
                        && f.tuple == row.tuple,
                )?;
            }
            "flow_retired" => {
                let row: Retired = typed(value)?;
                let f = flows.get(&row.token).ok_or_else(refused)?;
                // A tuple can already be absent; then there is no delete_intent.
                need(
                    row.last_socket_inode_absent
                        && row.tuple_element_removed
                        && f.retiring
                        && f.inode == row.socket_inode
                        && f.tuple == row.tuple,
                )?;
                flows.remove(&row.token);
            }
            "quiesced" => {
                let row: Quiesced = typed(value)?;
                need(
                    row.owned_flows == 0
                        && row.worker_terminal
                        && row.table_removed
                        && flows.is_empty(),
                )?;
                terminal = true;
            }
            "rules_arm_intent" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Rules {
                    table: String,
                    script_sha256: String,
                }
                let row: Rules = typed(value)?;
                need(row.table == intent.table && hex(&row.script_sha256, 64))?;
            }
            // These do not establish ownership or absence. Their truth never
            // substitutes for privileged adapter's fresh kernel checks.
            "native_command_failed"
            | "setup_failed"
            | "worker_terminal"
            | "readiness_failed"
            | "ready"
            | "fail_closed"
            | "linger_failed"
            | "worker_failed" => {}
            "runtime_fault"
            | "owned_nft_epoch"
            | "owned_nft_delete_epoch"
            | "route_epoch_refreshed"
            | "installed_guard_authorized" => {}
            _ => return Err(refused()),
        }
    }
    Ok(RecoveryPlan {
        intent,
        socket_inodes,
        unresolved_flows: flows.values().map(|f| f.tuple.pin()).collect(),
        terminal_quiesced_recorded: terminal,
        journal_sha256: digest.finalize().into(),
    })
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Err(E::custom("floating JSON refused"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut rows = Vec::new();
                while let Some(UniqueValue(v)) = seq.next_element()? {
                    rows.push(v);
                }
                Ok(UniqueValue(Value::Array(rows)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut rows = serde_json::Map::new();
                while let Some((k, UniqueValue(v))) = map.next_entry::<String, UniqueValue>()? {
                    if rows.insert(k, v).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueValue(Value::Object(rows)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub fn parse_unique_public_metadata(bytes: &[u8]) -> io::Result<Value> {
    parse_unique_public_metadata_bounded(bytes, 65536)
}
/// Larger public teardown archives use the same duplicate-key/type parser, with
/// a fixed upper ceiling. Ordinary profile and journal bounds are unchanged.
pub fn parse_unique_public_metadata_bounded(bytes: &[u8], maximum: usize) -> io::Result<Value> {
    need(maximum <= 2 * 1048576 && bytes.len() <= maximum)?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let UniqueValue(value) = UniqueValue::deserialize(&mut decoder).map_err(|_| refused())?;
    decoder.end().map_err(|_| refused())?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BOOT: &str = "00000000-0000-0000-0000-000000000001";
    type Fixture = (
        RelayOuterGenevaSettings,
        Vec<SocketAddrV4>,
        Vec<(String, Vec<u8>)>,
    );
    fn input() -> Fixture {
        let request = RelayOuterGenevaSettings {
            strategy: "[IP:ttl:64]-drop-|".into(),
            interface: "client0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            socket_mark: 23153,
            outbound_queue: 431,
            inbound_queue: 432,
            max_duration_secs: 24,
        };
        let endpoints = vec!["192.0.2.3:24443".parse().unwrap()];
        let setup = json!({"schema":"aegis_relay_geneva_native_intent_v1","instance":"1234abcd","table":"aegis_rg_1234abcd","tun":"agv1234abcd","process_identity":{"boot_id":BOOT,"pid":42,"start_ticks":123,"network_namespace_inode":456,"network_namespace_device":789,"service_invocation_id":"cccccccccccccccccccccccccccccccc","unified_cgroup":"0::/system.slice/aegis-client.service","service_profile_measured":false},"request_public":PublicRequest::from(&request),"endpoints_public":endpoints,"owned_flows":0,"strategy_sha256":hex::encode(Sha256::digest(request.strategy.as_bytes())),"executable_sha256":EXE,"source_stamp":SOURCE,"controlled_native_acceptance":false});
        (
            request,
            endpoints,
            vec![(
                "00000000_setup_intent.json".into(),
                serde_json::to_vec(&setup).unwrap(),
            )],
        )
    }
    fn trust<'a>(
        request: &'a RelayOuterGenevaSettings,
        endpoints: &'a [SocketAddrV4],
    ) -> RecoveryTrust<'a> {
        RecoveryTrust {
            source: SOURCE,
            executable_sha256: EXE,
            request,
            endpoints,
            boot_id: BOOT,
            network_namespace_inode: 456,
            network_namespace_device: 789,
            cgroup_path: "/system.slice/aegis-client.service",
        }
    }
    fn append(records: &mut Vec<(String, Vec<u8>)>, phase: &str, value: Value) {
        records.push((
            format!("{:08}_{phase}.json", records.len()),
            serde_json::to_vec(&value).unwrap(),
        ));
    }
    fn tuple() -> Value {
        json!({"local":"192.0.2.2","relay":"192.0.2.3","local_port":45555,"relay_port":24443})
    }
    fn arm(records: &mut Vec<(String, Vec<u8>)>) {
        append(
            records,
            "flow_arm_intent",
            json!({"token":1,"socket_inode":555,"tuple":tuple()}),
        );
    }
    #[test]
    fn interrupted_arm_retains_only_owned_unresolved_tuple_and_inode() {
        let (r, e, mut rows) = input();
        arm(&mut rows);
        let plan = reconstruct(&rows, &trust(&r, &e)).unwrap();
        assert_eq!(plan.unresolved_flows.len(), 1);
        assert_eq!(plan.unresolved_flows[0].local_port, 45555);
        assert_eq!(plan.socket_inodes, BTreeSet::from([555]));
        assert!(!plan.terminal_quiesced_recorded);
    }
    #[test]
    fn retired_inode_still_requires_fresh_absence_and_quiesced_is_not_kernel_proof() {
        let (r, e, mut rows) = input();
        arm(&mut rows);
        append(
            &mut rows,
            "flow_retire_intent",
            json!({"token":1,"socket_inode":555,"tuple":tuple(),"element_presence":null,"kernel_inode_proof_pending":true}),
        );
        append(
            &mut rows,
            "flow_retired",
            json!({"token":1,"socket_inode":555,"tuple":tuple(),"last_socket_inode_absent":true,"tuple_element_removed":true}),
        );
        append(
            &mut rows,
            "quiesced",
            json!({"owned_flows":0,"worker_terminal":true,"table_removed":true}),
        );
        let p = reconstruct(&rows, &trust(&r, &e)).unwrap();
        assert!(p.unresolved_flows.is_empty());
        assert!(p.socket_inodes.contains(&555));
        assert!(p.terminal_quiesced_recorded);
    }
    #[test]
    fn duplicate_partial_missing_or_reordered_record_refused() {
        let (r, e, rows) = input();
        let t = trust(&r, &e);
        let mut bad = rows.clone();
        bad[0].1 = b"{\"schema\":\"a\",\"schema\":\"b\"}".to_vec();
        assert!(reconstruct(&bad, &t).is_err());
        bad[0].1 = b"{".to_vec();
        assert!(reconstruct(&bad, &t).is_err());
        bad = rows.clone();
        bad[0].0 = "00000001_setup_intent.json".into();
        assert!(reconstruct(&bad, &t).is_err());
        bad = rows.clone();
        append(&mut bad, "setup_intent", json!({}));
        assert!(reconstruct(&bad, &t).is_err());
    }
    #[test]
    fn trust_source_config_namespace_and_executable_are_independent() {
        let (r, e, rows) = input();
        let mut t = trust(&r, &e);
        t.source = "dddddddddddddddddddddddddddddddddddddddd";
        assert!(reconstruct(&rows, &t).is_err());
        t = trust(&r, &e);
        t.executable_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        assert!(reconstruct(&rows, &t).is_err());
        t = trust(&r, &e);
        t.network_namespace_inode += 1;
        assert!(reconstruct(&rows, &t).is_err());
        let mut other = r.clone();
        other.socket_mark += 1;
        assert!(reconstruct(&rows, &trust(&other, &e)).is_err());
    }
    #[test]
    fn foreign_tuple_or_inode_in_followup_does_not_get_adopted() {
        let (r, e, mut rows) = input();
        arm(&mut rows);
        append(
            &mut rows,
            "flow_arm_confirmed",
            json!({"token":1,"socket_inode":999,"tuple":tuple(),"presence":true}),
        );
        assert!(reconstruct(&rows, &trust(&r, &e)).is_err());
        let (r, e, mut rows) = input();
        let mut foreign = tuple();
        foreign["relay"] = json!("192.0.2.4");
        append(
            &mut rows,
            "flow_arm_intent",
            json!({"token":1,"socket_inode":555,"tuple":foreign}),
        );
        assert!(reconstruct(&rows, &trust(&r, &e)).is_err());
    }
    #[test]
    fn false_retirement_and_quiescence_and_tuple_reuse_refused() {
        let (r, e, mut rows) = input();
        arm(&mut rows);
        append(
            &mut rows,
            "quiesced",
            json!({"owned_flows":0,"worker_terminal":true,"table_removed":true}),
        );
        assert!(reconstruct(&rows, &trust(&r, &e)).is_err());
        let (r, e, mut rows) = input();
        arm(&mut rows);
        append(
            &mut rows,
            "flow_retire_intent",
            json!({"token":1,"socket_inode":555,"tuple":tuple(),"element_presence":true,"kernel_inode_proof_pending":true}),
        );
        append(
            &mut rows,
            "flow_retired",
            json!({"token":1,"socket_inode":555,"tuple":tuple(),"last_socket_inode_absent":false,"tuple_element_removed":true}),
        );
        assert!(reconstruct(&rows, &trust(&r, &e)).is_err());
        rows.pop();
        append(
            &mut rows,
            "flow_retired",
            json!({"token":1,"socket_inode":555,"tuple":tuple(),"last_socket_inode_absent":true,"tuple_element_removed":true}),
        );
        append(
            &mut rows,
            "flow_arm_intent",
            json!({"token":2,"socket_inode":556,"tuple":tuple()}),
        );
        assert!(reconstruct(&rows, &trust(&r, &e)).is_err());
    }
}
