//! Pure, bounded nftables JSON policy. This module performs no I/O to the kernel.
//! Schema: libnftables-json(5), shipped by Netfilter. Native observations must use
//! numeric protocol/priority output. Only object handles and standalone metainfo
//! are non-policy metadata; rule/expression order and every other field matter.
use super::{RelayFlowPin, RelayOuterGenevaSettings};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io, net::Ipv4Addr};

const MAX_FLOWS: usize = 128;
fn refuse() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "relay Geneva nft policy refused",
    )
}
fn ensure(ok: bool) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(refuse())
    }
}
fn names(table: &str, tun: &str, r: &RelayOuterGenevaSettings) -> io::Result<()> {
    let token = table.strip_prefix("aegis_rg_").ok_or_else(refuse)?;
    ensure(token.len() == 8 && token.bytes().all(|b| b.is_ascii_hexdigit()))?;
    ensure(tun == format!("agv{token}"))?;
    ensure(
        !r.interface.is_empty()
            && r.interface.len() <= 15
            && r.interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            && r.interface != tun
            && r.socket_mark != 0
            && r.outbound_queue != r.inbound_queue,
    )?;
    ensure(valid_ip(r.local_address))
}
fn valid_ip(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() && !ip.is_loopback()
}
fn meta(key: &str) -> Value {
    json!({"meta":{"key":key}})
}
fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload":{"protocol":protocol,"field":field}})
}
fn cmp(left: Value, right: Value, op: &str) -> Value {
    json!({"match":{"left":left,"right":right,"op":op}})
}
fn tuple(out: bool) -> Value {
    let (src, sport, dst, dport) = if out {
        ("daddr", "dport", "saddr", "sport")
    } else {
        ("saddr", "sport", "daddr", "dport")
    };
    json!({"concat":[payload("ip",src),payload("tcp",sport),payload("ip",dst),payload("tcp",dport)]})
}
fn flow_key(f: &RelayFlowPin) -> (u32, u16, u32, u16) {
    (
        u32::from(f.relay),
        f.relay_port,
        u32::from(f.local),
        f.local_port,
    )
}
fn checked_flows(flows: &[RelayFlowPin]) -> io::Result<Vec<RelayFlowPin>> {
    ensure(flows.len() <= MAX_FLOWS)?;
    let mut seen = BTreeSet::new();
    for f in flows {
        ensure(
            valid_ip(f.local)
                && valid_ip(f.relay)
                && f.local != f.relay
                && f.local_port != 0
                && f.relay_port != 0
                && seen.insert(flow_key(f)),
        )?;
    }
    let mut out = flows.to_vec();
    out.sort_by_key(flow_key);
    Ok(out)
}
fn elements(flows: &[RelayFlowPin]) -> Value {
    Value::Array(
        flows
            .iter()
            .map(|f| {
                json!({"concat":[f.relay.to_string(), f.relay_port,
        f.local.to_string(),f.local_port]})
            })
            .collect(),
    )
}
fn expected(
    table: &str,
    tun: &str,
    r: &RelayOuterGenevaSettings,
    flows: &[RelayFlowPin],
) -> io::Result<Value> {
    names(table, tun, r)?;
    let flows = checked_flows(flows)?;
    ensure(flows.iter().all(|f| f.local == r.local_address))?;
    let chain = |name, hook, prio| {
        json!({"chain":{"family":"ip","table":table,"name":name,
        "type":"filter","hook":hook,"prio":prio,"policy":"accept"}})
    };
    let rule =
        |chain, expr| json!({"rule":{"family":"ip","table":table,"chain":chain,"expr":expr}});
    Ok(json!({"nftables":[
        {"table":{"family":"ip","name":table}},
        {"set":{"family":"ip","table":table,"name":"flows",
            "type":["ipv4_addr","inet_service","ipv4_addr","inet_service"],"elem":elements(&flows)}},
        chain("out","postrouting",300),chain("input","input",-10),
        rule("out",json!([
            cmp(meta("mark"),json!(r.socket_mark),"=="),
            cmp(meta("oifname"),json!(r.interface),"=="),
            cmp(payload("ip","saddr"),json!(r.local_address.to_string()),"=="),
            cmp(payload("ip","protocol"),json!(6),"=="),
            cmp(tuple(true),json!("@flows"),"=="),{"queue":{"num":r.outbound_queue}}])),
        rule("out",json!([cmp(meta("mark"),json!(r.socket_mark),"=="),{"drop":null}])),
        rule("input",json!([
            cmp(meta("iifname"),json!(r.interface),"=="),
            cmp(payload("ip","protocol"),json!(6),"=="),
            cmp(tuple(false),json!("@flows"),"=="),
            {"mangle":{"key":meta("mark"),"value":r.socket_mark}},
            {"queue":{"num":r.inbound_queue}}])),
        rule("input",json!([cmp(meta("iifname"),json!(tun),"!="),
            cmp(meta("mark"),json!(r.socket_mark),"=="),{"drop":null}]))]}))
}
/// Atomic create commands; CREATE refuses an already existing owned namespace.
pub(super) fn render(table: &str, tun: &str, r: &RelayOuterGenevaSettings) -> io::Result<Vec<u8>> {
    let mut value = expected(table, tun, r, &[])?;
    for obj in value["nftables"].as_array_mut().ok_or_else(refuse)? {
        if let Some(set) = obj.get_mut("set").and_then(Value::as_object_mut) {
            set.remove("elem");
        }
        let command = if obj.get("rule").is_some() {
            "add"
        } else {
            "create"
        };
        *obj = json!({command:obj.take()});
    }
    serde_json::to_vec(&value).map_err(|_| refuse())
}
fn entries(value: &Value) -> io::Result<&Vec<Value>> {
    let root = value.as_object().ok_or_else(refuse)?;
    ensure(root.len() == 1)?;
    let rows = root
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(refuse)?;
    ensure(rows.len() <= 9)?;
    Ok(rows)
}
fn parse_elements(value: Option<&Value>) -> io::Result<Vec<RelayFlowPin>> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    // The schema permits a single expression as well as an array of expressions.
    let singleton;
    let rows = if let Some(a) = value.as_array() {
        a
    } else {
        singleton = vec![value.clone()];
        &singleton
    };
    ensure(rows.len() <= MAX_FLOWS)?;
    let mut flows = vec![];
    for row in rows {
        let obj = row.as_object().ok_or_else(refuse)?;
        ensure(obj.len() == 1)?;
        let t = obj
            .get("concat")
            .and_then(Value::as_array)
            .ok_or_else(refuse)?;
        ensure(t.len() == 4)?;
        let ip = |v: &Value| -> io::Result<Ipv4Addr> {
            let s = v.as_str().ok_or_else(refuse)?;
            let ip = s.parse::<Ipv4Addr>().map_err(|_| refuse())?;
            ensure(ip.to_string() == s)?;
            Ok(ip)
        };
        let port = |v: &Value| -> io::Result<u16> {
            let n = v.as_u64().ok_or_else(refuse)?;
            u16::try_from(n).map_err(|_| refuse())
        };
        flows.push(RelayFlowPin {
            relay: ip(&t[0])?,
            relay_port: port(&t[1])?,
            local: ip(&t[2])?,
            local_port: port(&t[3])?,
        });
    }
    checked_flows(&flows)
}
/// Strictly parsed observations, NOT permission to adopt those flows. The caller
/// must check every row against its pre-recorded owned add/delete intents.
pub(super) fn observed_flows(actual: &Value) -> io::Result<Vec<RelayFlowPin>> {
    let mut found = None;
    for obj in entries(actual)? {
        let map = obj.as_object().ok_or_else(refuse)?;
        ensure(map.len() == 1)?;
        if let Some(set) = map.get("set") {
            let set = set.as_object().ok_or_else(refuse)?;
            ensure(
                found.is_none()
                    && set.get("family") == Some(&json!("ip"))
                    && set.get("name") == Some(&json!("flows"))
                    && set.get("type")
                        == Some(&json!([
                            "ipv4_addr",
                            "inet_service",
                            "ipv4_addr",
                            "inet_service"
                        ])),
            )?;
            found = Some(parse_elements(set.get("elem"))?);
        }
    }
    found.ok_or_else(refuse)
}
fn canonical(value: &Value) -> io::Result<Value> {
    let mut objects = vec![];
    let mut rules_out = vec![];
    let mut rules_input = vec![];
    let mut meta_seen = false;
    for entry in entries(value)? {
        let map = entry.as_object().ok_or_else(refuse)?;
        ensure(map.len() == 1)?;
        if let Some(m) = map.get("metainfo") {
            ensure(!meta_seen && m.is_object())?;
            meta_seen = true;
            continue;
        }
        let (kind, body) = map.iter().next().ok_or_else(refuse)?;
        ensure(matches!(kind.as_str(), "table" | "set" | "chain" | "rule"))?;
        let mut body = body.as_object().ok_or_else(refuse)?.clone();
        if let Some(handle) = body.remove("handle") {
            ensure(handle.as_u64().is_some())?;
        }
        if kind == "set" {
            let flows = parse_elements(body.get("elem"))?;
            body.insert("elem".into(), elements(&flows));
        }
        let clean = json!({kind:body});
        if kind == "rule" {
            match clean["rule"]["chain"].as_str() {
                Some("out") => rules_out.push(clean),
                Some("input") => rules_input.push(clean),
                _ => return Err(refuse()),
            }
        } else {
            objects.push(clean);
        }
    }
    ensure(objects.len() == 4 && rules_out.len() == 2 && rules_input.len() == 2)?;
    // Independent named objects may be listed in a different order. Rule order
    // within each chain is never normalized because it affects packet policy.
    objects.sort_by_key(Value::to_string);
    objects.extend(rules_out);
    objects.extend(rules_input);
    Ok(Value::Array(objects))
}
/// nftables 1.0.9 delinearization removes the redundant IPv4 protocol
/// dependency before an exact TCP-typed concatenation. Build only that observed
/// complete alternate from OUR expected policy; never strip actual predicates.
/// Keep render unchanged, including its explicit kernel protocol match.
fn tcp_dependency_elided_listing(mut value: Value) -> io::Result<Value> {
    for (rule, index, outbound) in [(4, 3, true), (6, 1, false)] {
        let expressions = value["nftables"][rule]["rule"]["expr"]
            .as_array_mut()
            .ok_or_else(refuse)?;
        ensure(
            expressions.get(index) == Some(&cmp(payload("ip", "protocol"), json!(6), "=="))
                && expressions.get(index + 1) == Some(&cmp(tuple(outbound), json!("@flows"), "==")),
        )?;
        expressions.remove(index);
    }
    Ok(value)
}

/// Compare all policy semantics and the exact known owned flow set. A drift or
/// unsupported format fails closed; only exact verified policy gets a digest.
pub(super) fn validate(
    actual: &Value,
    table: &str,
    tun: &str,
    r: &RelayOuterGenevaSettings,
    flows: &[RelayFlowPin],
) -> io::Result<[u8; 32]> {
    let expected_value = expected(table, tun, r, flows)?;
    let expected = canonical(&expected_value)?;
    let actual = canonical(actual)?;
    if actual != expected {
        let observed_listing = canonical(&tcp_dependency_elided_listing(expected_value)?)?;
        ensure(actual == observed_listing)?;
    }
    Ok(Sha256::digest(serde_json::to_vec(&expected).map_err(|_| refuse())?).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TABLE: &str = "aegis_rg_abcdef01";
    const TUN: &str = "agvabcdef01";
    fn request() -> RelayOuterGenevaSettings {
        RelayOuterGenevaSettings {
            strategy: "\\/".into(),
            interface: "eth0".into(),
            local_address: "192.0.2.1".parse().unwrap(),
            local_mac: [2, 0, 0, 0, 0, 1],
            next_hop_mac: [2, 0, 0, 0, 0, 2],
            outbound_queue: 101,
            inbound_queue: 102,
            socket_mark: 123,
            max_duration_secs: 120,
        }
    }
    fn flow(port: u16) -> RelayFlowPin {
        RelayFlowPin {
            local: "192.0.2.1".parse().unwrap(),
            relay: "198.51.100.2".parse().unwrap(),
            local_port: port,
            relay_port: 443,
        }
    }
    fn valid(flows: &[RelayFlowPin]) -> Value {
        expected(TABLE, TUN, &request(), flows).unwrap()
    }
    fn accepted(v: &Value, flows: &[RelayFlowPin]) -> bool {
        validate(v, TABLE, TUN, &request(), flows).is_ok()
    }
    #[test]
    fn exact_full_policy_and_flow_set() {
        let f = [flow(2345), flow(3456)];
        let v = valid(&f);
        assert!(accepted(&v, &f));
        assert_eq!(observed_flows(&v).unwrap(), f);
        assert!(!accepted(&v, &f[..1]));
        assert!(accepted(&valid(&[]), &[]));
    }
    #[test]
    fn metadata_and_unordered_elements_only() {
        let f = [flow(2345), flow(3456)];
        let mut v = valid(&f);
        let digest = validate(&v, TABLE, TUN, &request(), &f).unwrap();
        for obj in v["nftables"].as_array_mut().unwrap() {
            obj.as_object_mut().unwrap().values_mut().next().unwrap()["handle"] = json!(42);
        }
        v["nftables"][1]["set"]["elem"]
            .as_array_mut()
            .unwrap()
            .reverse();
        v["nftables"]
            .as_array_mut()
            .unwrap()
            .insert(0, json!({"metainfo":{"json_schema_version":1}}));
        assert_eq!(validate(&v, TABLE, TUN, &request(), &f).unwrap(), digest);
        v["nftables"][5]["rule"]["comment"] = json!("foreign");
        assert!(!accepted(&v, &f));
    }
    #[test]
    fn same_count_policy_drift_refused() {
        let original = valid(&[flow(2345)]);
        let mutations = [
            ("/nftables/4/rule/expr/0/match/right", json!(124)),
            ("/nftables/4/rule/expr/1/match/right", json!("eth1")),
            ("/nftables/4/rule/expr/3/match/right", json!(17)),
            ("/nftables/4/rule/expr/5/queue/num", json!(102)),
            ("/nftables/6/rule/expr/3/mangle/value", json!(0)),
            ("/nftables/7/rule/expr/0/match/right", json!("foreign")),
            ("/nftables/2/chain/prio", json!(299)),
            ("/nftables/3/chain/policy", json!("drop")),
            ("/nftables/1/set/type/1", json!("mark")),
            ("/nftables/1/set/elem/0/concat/1", json!(444)),
        ];
        for (path, value) in mutations {
            let mut v = original.clone();
            *v.pointer_mut(path).unwrap() = value;
            assert!(!accepted(&v, &[flow(2345)]), "{path}");
        }
    }
    #[test]
    fn bypass_extra_expression_and_rule_order_refused() {
        let mut v = valid(&[]);
        v["nftables"][4]["rule"]["expr"][5]["queue"]["flags"] = json!(["bypass"]);
        assert!(!accepted(&v, &[]));
        let mut v = valid(&[]);
        v["nftables"][4]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .push(json!({"accept":null}));
        assert!(!accepted(&v, &[]));
        let mut v = valid(&[]);
        v["nftables"].as_array_mut().unwrap().swap(4, 5);
        assert!(!accepted(&v, &[]));
        let mut v = valid(&[]);
        v["nftables"][6]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .swap(3, 4);
        assert!(!accepted(&v, &[]));
    }
    #[test]
    fn typed_elements_reject_foreign_duplicate_lease_or_range() {
        let original = valid(&[flow(2345)]);
        for bad in [
            json!({"concat":["198.51.100.2",true,"192.0.2.1",2345]}),
            json!({"concat":["198.51.100.2",443,"192.0.2.1",0]}),
            json!({"concat":["198.51.100.2",443,"192.0.2.1",2345],"timeout":100}),
            json!({"range":[1,2]}),
            json!({"concat":["198.51.100.2",443,"192.0.2.1",65536]}),
        ] {
            let mut v = original.clone();
            v["nftables"][1]["set"]["elem"] = json!([bad]);
            assert!(observed_flows(&v).is_err());
            assert!(!accepted(&v, &[flow(2345)]));
        }
        let mut v = original;
        let e = v["nftables"][1]["set"]["elem"][0].clone();
        v["nftables"][1]["set"]["elem"]
            .as_array_mut()
            .unwrap()
            .push(e);
        assert!(observed_flows(&v).is_err());
    }
    #[test]
    fn empty_set_and_single_expression_schema() {
        let mut v = valid(&[]);
        v["nftables"][1]["set"]
            .as_object_mut()
            .unwrap()
            .remove("elem");
        assert!(accepted(&v, &[]));
        let mut v = valid(&[flow(2345)]);
        v["nftables"][1]["set"]["elem"] = v["nftables"][1]["set"]["elem"][0].clone();
        assert!(accepted(&v, &[flow(2345)]));
    }
    #[test]
    fn ownership_bounds_and_extra_objects_refused() {
        assert!(render("other", TUN, &request()).is_err());
        assert!(render(TABLE, "foreign", &request()).is_err());
        let mut r = request();
        r.interface = TUN.into();
        assert!(render(TABLE, TUN, &r).is_err());
        let f = vec![flow(2345); 129];
        assert!(expected(TABLE, TUN, &request(), &f).is_err());
        let mut v = valid(&[]);
        v["nftables"]
            .as_array_mut()
            .unwrap()
            .push(json!({"set":{"name":"foreign"}}));
        assert!(!accepted(&v, &[]));
        let mut v = valid(&[]);
        v["nftables"][0]["table"]["flags"] = json!(["dormant"]);
        assert!(!accepted(&v, &[]));
    }
    #[test]
    fn renderer_atomic_create_exact_no_bypass() {
        let v: Value = serde_json::from_slice(&render(TABLE, TUN, &request()).unwrap()).unwrap();
        assert_eq!(v["nftables"].as_array().unwrap().len(), 8);
        let readback = json!({"nftables":v["nftables"].as_array().unwrap().iter().map(|x| {
            let commands=x.as_object().unwrap();
            assert_eq!(commands.len(),1);
            let (command,object)=commands.iter().next().unwrap();
            assert_eq!(command,if object.get("rule").is_some() { "add" } else { "create" });
            object.clone()
        }).collect::<Vec<_>>()});
        assert!(accepted(&readback, &[]));
        assert!(!v.to_string().contains("bypass"));
    }
    fn observed_nft_109() -> Value {
        serde_json::from_slice(include_bytes!(
            "test-fixtures/nft-tcp-dependency-elided-1.0.9.json"
        ))
        .unwrap()
    }
    fn measured_request() -> RelayOuterGenevaSettings {
        RelayOuterGenevaSettings {
            interface: "client0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            outbound_queue: 431,
            inbound_queue: 432,
            socket_mark: 23153,
            max_duration_secs: 24,
            ..request()
        }
    }
    fn measured_accepted(value: &Value) -> bool {
        validate(
            value,
            "aegis_rg_db7a1403",
            "agvdb7a1403",
            &measured_request(),
            &[],
        )
        .is_ok()
    }
    // Actual CI37161677318 / artifact11287144937, public readback only. Raw
    // SHA256 fb0f379d12a42006e3741d3115ece5c416b7366c655bdf0be285ad11f6cbb4db.
    // This reproduces JSON ABI compatibility, not a new native runtime pass.
    #[test]
    fn actual_nft_109_tcp_dependency_elision_is_exact_expected_policy() {
        let value = observed_nft_109();
        assert!(observed_flows(&value).unwrap().is_empty());
        let expected =
            expected("aegis_rg_db7a1403", "agvdb7a1403", &measured_request(), &[]).unwrap();
        assert_ne!(canonical(&value).unwrap(), canonical(&expected).unwrap());
        assert_eq!(
            canonical(&value).unwrap(),
            canonical(&tcp_dependency_elided_listing(expected.clone()).unwrap()).unwrap()
        );
        assert!(measured_accepted(&value));
        assert_eq!(
            validate(
                &value,
                "aegis_rg_db7a1403",
                "agvdb7a1403",
                &measured_request(),
                &[]
            )
            .unwrap(),
            validate(
                &expected,
                "aegis_rg_db7a1403",
                "agvdb7a1403",
                &measured_request(),
                &[]
            )
            .unwrap()
        );
        let script = render("aegis_rg_db7a1403", "agvdb7a1403", &measured_request()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(script)),
            "99db4ab2553fa2ca02ea2b280e4c7afb8858c5e3c6d1b23ee47096e75d83e4b7"
        );
    }
    #[test]
    fn elided_listing_missing_or_non_tcp_tuple_cannot_grant_queue() {
        for rule in [5, 7] {
            // actual fixture includes initial metainfo row
            for protocol in ["udp", "th", "ip"] {
                let mut value = observed_nft_109();
                let index = if rule == 5 { 3 } else { 1 };
                value["nftables"][rule]["rule"]["expr"][index]["match"]["left"]["concat"][1]
                    ["payload"]["protocol"] = json!(protocol);
                assert!(!measured_accepted(&value), "{rule} {protocol}");
            }
            let mut value = observed_nft_109();
            let index = if rule == 5 { 3 } else { 1 };
            value["nftables"][rule]["rule"]["expr"]
                .as_array_mut()
                .unwrap()
                .remove(index);
            assert!(!measured_accepted(&value));
        }
    }
    #[test]
    fn elided_listing_wrong_or_moved_protocol_predicate_is_never_stripped() {
        for rule in [5, 7] {
            let index = if rule == 5 { 3 } else { 1 };
            let mut value = observed_nft_109();
            value["nftables"][rule]["rule"]["expr"]
                .as_array_mut()
                .unwrap()
                .insert(index, cmp(payload("ip", "protocol"), json!(17), "=="));
            assert!(!measured_accepted(&value));
            let mut value = observed_nft_109();
            value["nftables"][rule]["rule"]["expr"]
                .as_array_mut()
                .unwrap()
                .insert(0, cmp(payload("ip", "protocol"), json!(6), "=="));
            assert!(!measured_accepted(&value));
        }
    }
    #[test]
    fn elided_listing_complete_policy_drift_and_unknown_objects_refused() {
        for (path, bad) in [
            ("/nftables/5/rule/expr/4/queue/num", json!(432)),
            ("/nftables/7/rule/expr/3/queue/num", json!(431)),
            ("/nftables/5/rule/expr/1/match/right", json!("eth0")),
            ("/nftables/7/rule/expr/2/mangle/value", json!(0)),
            ("/nftables/8/rule/expr/0/match/right", json!("foreign")),
            ("/nftables/1/table/name", json!("aegis_rg_abcdef01")),
            ("/nftables/3/chain/prio", json!(299)),
        ] {
            let mut value = observed_nft_109();
            *value.pointer_mut(path).unwrap() = bad;
            assert!(!measured_accepted(&value), "{path}");
        }
        let mut value = observed_nft_109();
        value["nftables"][5]["rule"]["expr"][4]["queue"]["flags"] = json!(["bypass"]);
        assert!(!measured_accepted(&value));
        let mut value = observed_nft_109();
        value["nftables"][5]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .push(json!({"accept":null}));
        assert!(!measured_accepted(&value));
        let mut value = observed_nft_109();
        value["nftables"].as_array_mut().unwrap().swap(5, 6);
        assert!(!measured_accepted(&value));
        let mut value = observed_nft_109();
        value["nftables"][5]["rule"]["expr"][3]["match"]["left"]["concat"]
            .as_array_mut()
            .unwrap()
            .swap(1, 3);
        assert!(!measured_accepted(&value));
        let mut value = observed_nft_109();
        value["nftables"][0] =
            json!({"counter":{"family":"ip","table":"aegis_rg_db7a1403","name":"unknown"}});
        assert!(!measured_accepted(&value));
    }
    #[test]
    fn elided_listing_stale_owned_flow_cannot_be_adopted() {
        let mut value = observed_nft_109();
        value["nftables"][2]["set"]["elem"] =
            json!([{"concat":["192.0.2.3",24443,"192.0.2.2",42001]}]);
        assert_eq!(observed_flows(&value).unwrap().len(), 1);
        assert!(!measured_accepted(&value));
    }
}
