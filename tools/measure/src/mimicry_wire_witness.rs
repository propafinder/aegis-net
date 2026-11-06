use std::{collections::BTreeMap, fs, path::Path, process::Command as ProcessCommand};

use serde_json::{json, Value};

use crate::artifact::write_json;

const TSHARK_FIELDS: &[&str] = &[
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.dsfield",
    "ip.id",
    "ip.flags.df",
    "ip.frag_offset",
    "ip.flags.mf",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.window_size_value",
    "tcp.options.mss_val",
    "tcp.options.wscale.shift",
    "tcp.options.sack_perm",
    "tcp.options.timestamp.tsval",
    "tcp.options.timestamp.tsecr",
    "tcp.seq_raw",
];

#[derive(Clone, Debug)]
struct RuntimeCandidate {
    target: String,
    port: i64,
    runtime_slice: String,
    runtime_event_code: Option<String>,
    runtime_ts_unix_ms: i64,
    planned_ttl_preface: Option<i64>,
}

#[derive(Clone, Debug)]
struct Packet {
    ts_unix_ms: i64,
    ip_dst: Option<String>,
    ttl: Option<i64>,
    tos: Option<i64>,
    ip_id: Option<i64>,
    dont_fragment: Option<bool>,
    tcp_srcport: Option<i64>,
    tcp_dstport: Option<i64>,
    syn: bool,
    tcp_len: i64,
    window_preface: Option<i64>,
    mss: Option<i64>,
    window_scale: Option<i64>,
    sack_permitted: Option<bool>,
    timestamp_tsval: Option<i64>,
}

pub fn build_mimicry_wire_witness_summary(
    pcap: &Path,
    runtime_events: &Path,
    output: &Path,
    tshark_bin: &str,
    window_ms: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_records = parse_jsonl_lenient(runtime_events)?;
    let active_records = active_runtime_candidates(&runtime_records);
    let packets = tshark_packet_rows(pcap, tshark_bin)?;
    let mut witness_records = Vec::new();

    for runtime_record in &active_records {
        let flow_packets = best_flow_packets_for_runtime(runtime_record, &packets, window_ms);
        if flow_packets.is_empty() {
            continue;
        }
        let preface_packet = flow_packets
            .iter()
            .find(|packet| packet.tcp_len > 0 && packet.ttl.unwrap_or(0) > 10)
            .or_else(|| flow_packets.iter().find(|packet| packet.tcp_len > 0))
            .unwrap_or(&flow_packets[0]);
        let capture_window = json!({
            "start_unix_ms": flow_packets.iter().map(|packet| packet.ts_unix_ms).min().unwrap_or(0),
            "end_unix_ms": flow_packets.iter().map(|packet| packet.ts_unix_ms).max().unwrap_or(0),
        });
        witness_records.push(json!({
            "target": runtime_record.target,
            "port": runtime_record.port,
            "runtime_slice": runtime_record.runtime_slice,
            "runtime_event_code": runtime_record.runtime_event_code,
            "capture_window": capture_window,
            "ttl_preface": preface_packet.ttl,
            "window_preface": preface_packet.window_preface,
            "ipv4_header_shaping": {
                "tos": preface_packet.tos,
                "ip_id": preface_packet.ip_id,
                "dont_fragment": preface_packet.dont_fragment,
            },
            "negotiated_options": negotiated_options_from_packets(&flow_packets),
            "fragment_choreography": {
                "first_payload_len": Value::Null,
                "disorder_split_at": Value::Null,
                "overlap": Value::Null,
            },
            "packet_count_considered": flow_packets.len(),
        }));
    }

    let payload = json!({
        "artifact_schema": "wire_mimicry_independent_witness_summary_v1",
        "producer": "build-mimicry-wire-witness-summary.sh",
        "pcap_path": pcap.display().to_string(),
        "runtime_events_jsonl": runtime_events.display().to_string(),
        "witness_window_ms": window_ms,
        "active_runtime_records_seen": active_records.len(),
        "capture_backed_records_seen": witness_records.len(),
        "hostile_path_capture_ready": !witness_records.is_empty(),
        "records": witness_records,
    });
    write_json(output, &payload)?;
    Ok(())
}

fn parse_jsonl_lenient(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for raw_line in fs::read_to_string(path)?.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            records.push(value);
        }
    }
    Ok(records)
}

fn active_runtime_candidates(records: &[Value]) -> Vec<RuntimeCandidate> {
    records
        .iter()
        .filter_map(|record| {
            let fields = record.get("fields")?.as_object()?;
            if fields
                .get("mimicry_capability_wire_active")
                .and_then(Value::as_bool)
                != Some(true)
            {
                return None;
            }
            let runtime_slice = fields
                .get("mimicry_capability_wire_runtime_slice")?
                .as_str()?;
            if runtime_slice.is_empty() {
                return None;
            }
            let target = fields.get("target")?.as_str()?.to_string();
            let port = fields.get("port")?.as_i64()?;
            let runtime_ts_unix_ms = record.get("ts_unix_ms")?.as_i64()?;
            Some(RuntimeCandidate {
                target,
                port,
                runtime_slice: runtime_slice.to_string(),
                runtime_event_code: record
                    .get("event_code")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                runtime_ts_unix_ms,
                planned_ttl_preface: fields
                    .get("mimicry_capability_wire_ttl_preface")
                    .and_then(Value::as_i64),
            })
        })
        .collect()
}

fn tshark_packet_rows(
    pcap: &Path,
    tshark_bin: &str,
) -> Result<Vec<Packet>, Box<dyn std::error::Error>> {
    let mut command = ProcessCommand::new(tshark_bin);
    command.args([
        "-r",
        &pcap.display().to_string(),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]);
    for field in TSHARK_FIELDS {
        command.args(["-e", field]);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("tshark failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    let mut packets = Vec::new();
    for raw_line in stdout.lines() {
        let mut parts = raw_line.split('\t').collect::<Vec<_>>();
        parts.resize(TSHARK_FIELDS.len(), "");
        let row = TSHARK_FIELDS
            .iter()
            .copied()
            .zip(parts)
            .collect::<BTreeMap<_, _>>();
        let Some(ts_epoch) = parse_float(row["frame.time_epoch"]) else {
            continue;
        };
        packets.push(Packet {
            ts_unix_ms: (ts_epoch * 1000.0) as i64,
            ip_dst: string_or_none(row["ip.dst"]),
            ttl: parse_int(row["ip.ttl"]),
            tos: parse_int(row["ip.dsfield"]),
            ip_id: parse_int(row["ip.id"]),
            dont_fragment: parse_bool(row["ip.flags.df"]),
            tcp_srcport: parse_int(row["tcp.srcport"]),
            tcp_dstport: parse_int(row["tcp.dstport"]),
            syn: parse_bool(row["tcp.flags.syn"]).unwrap_or(false),
            tcp_len: parse_int(row["tcp.len"]).unwrap_or(0),
            window_preface: parse_int(row["tcp.window_size_value"]),
            mss: parse_int(row["tcp.options.mss_val"]),
            window_scale: parse_int(row["tcp.options.wscale.shift"]),
            sack_permitted: parse_bool(row["tcp.options.sack_perm"]),
            timestamp_tsval: parse_int(row["tcp.options.timestamp.tsval"]),
        });
    }
    Ok(packets)
}

fn packet_matches_target(runtime_record: &RuntimeCandidate, packet: &Packet) -> bool {
    if packet.tcp_dstport != Some(runtime_record.port) {
        return false;
    }
    let target = runtime_record.target.trim();
    if !target.is_empty()
        && target
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | ':'))
    {
        return packet.ip_dst.as_deref() == Some(target);
    }
    true
}

fn candidate_packets_for_runtime<'a>(
    runtime_record: &RuntimeCandidate,
    packets: &'a [Packet],
    window_ms: i64,
) -> Vec<&'a Packet> {
    let start_unix_ms = runtime_record.runtime_ts_unix_ms - window_ms;
    let end_unix_ms = runtime_record.runtime_ts_unix_ms + window_ms;
    packets
        .iter()
        .filter(|packet| {
            start_unix_ms <= packet.ts_unix_ms
                && packet.ts_unix_ms <= end_unix_ms
                && packet_matches_target(runtime_record, packet)
        })
        .collect()
}

fn best_flow_packets_for_runtime(
    runtime_record: &RuntimeCandidate,
    packets: &[Packet],
    window_ms: i64,
) -> Vec<Packet> {
    let matching = candidate_packets_for_runtime(runtime_record, packets, window_ms);
    if matching.is_empty() {
        return Vec::new();
    }
    let mut flows: BTreeMap<i64, Vec<Packet>> = BTreeMap::new();
    for packet in &matching {
        if let Some(srcport) = packet.tcp_srcport {
            flows.entry(srcport).or_default().push((*packet).clone());
        }
    }
    if flows.is_empty() {
        return matching.into_iter().cloned().collect();
    }

    let preface_flows = flows
        .iter()
        .filter(|(_, flow_packets)| flow_has_preface(runtime_record, flow_packets))
        .map(|(srcport, flow_packets)| (*srcport, flow_packets.clone()))
        .collect::<BTreeMap<_, _>>();
    let candidate_flows = if preface_flows.is_empty() {
        &flows
    } else {
        &preface_flows
    };

    let event_code = runtime_record.runtime_event_code.as_deref().unwrap_or("");
    let mut best_srcport = None;
    let mut best_score = i64::MAX;
    for (srcport, flow_packets) in candidate_flows {
        let score =
            if event_code.contains("session_succeeded") || event_code.contains("session_failed") {
                let last_ts = flow_packets
                    .iter()
                    .map(|packet| packet.ts_unix_ms)
                    .max()
                    .unwrap_or(0);
                (runtime_record.runtime_ts_unix_ms - last_ts).abs()
            } else {
                let first_ts = flow_packets
                    .iter()
                    .map(|packet| packet.ts_unix_ms)
                    .min()
                    .unwrap_or(0);
                (first_ts - runtime_record.runtime_ts_unix_ms).abs()
            };
        if score < best_score {
            best_score = score;
            best_srcport = Some(*srcport);
        }
    }
    best_srcport
        .and_then(|srcport| flows.get(&srcport).cloned())
        .unwrap_or_else(|| matching.into_iter().cloned().collect())
}

fn flow_has_preface(runtime_record: &RuntimeCandidate, flow_packets: &[Packet]) -> bool {
    flow_packets.iter().any(|packet| {
        if packet.tcp_len <= 0 {
            return false;
        }
        let ttl = packet.ttl.unwrap_or(0);
        if let Some(planned_ttl) = runtime_record.planned_ttl_preface {
            ttl == planned_ttl
        } else {
            10 < ttl && ttl < 64
        }
    })
}

fn negotiated_options_from_packets(packets: &[Packet]) -> Value {
    for packet in packets {
        if packet.mss.is_some()
            || packet.window_scale.is_some()
            || packet.sack_permitted.is_some()
            || packet.timestamp_tsval.is_some()
        {
            let timestamp_mode = if packet.timestamp_tsval.is_some() {
                if packet.syn {
                    Some("syn_timestamp_offer_layout20")
                } else {
                    Some("timestamp_option_observed")
                }
            } else {
                None
            };
            return json!({
                "mss": packet.mss,
                "window_scale": packet.window_scale,
                "sack_permitted": packet.sack_permitted,
                "timestamp_mode": timestamp_mode,
            });
        }
    }
    json!({
        "mss": Value::Null,
        "window_scale": Value::Null,
        "sack_permitted": Value::Null,
        "timestamp_mode": Value::Null,
    })
}

fn parse_int(value: &str) -> Option<i64> {
    let text = value.trim();
    if text.is_empty() || text == "0x" {
        return None;
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    text.parse::<f64>().ok().map(|value| value as i64)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn parse_float(value: &str) -> Option<f64> {
    value.trim().parse().ok()
}

fn string_or_none(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
