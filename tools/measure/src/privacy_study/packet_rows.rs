//! Strict private packet-field export ingestion, not a PCAP decoder.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

pub(super) const HEADER: &str = "timestamp_unix_us\tframe_length_bytes\tcaptured_length_bytes\tsrc_ip\tdst_ip\tprotocol\tsrc_port\tdst_port";
const MAX_ROW_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(super) struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Flow {
    pub protocol: Protocol,
    pub client: Endpoint,
    pub peer: Endpoint,
}

type Key = (Protocol, Endpoint, Endpoint);
fn key(protocol: Protocol, first: Endpoint, second: Endpoint) -> Key {
    if first <= second {
        (protocol, first, second)
    } else {
        (protocol, second, first)
    }
}

impl Flow {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.client.port == 0
            || self.peer.port == 0
            || self.client == self.peer
            || self.client.ip.is_ipv4() != self.peer.ip.is_ipv4()
        {
            return Err("invalid explicit trial flow tuple");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct Selection {
    pub flow: Flow,
    pub started_us: u64,
    pub finished_us: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(super) struct TrialStats {
    pub selected_wire_frame_bytes: u64,
    pub selected_packet_rows: u64,
    pub outgoing_wire_frame_bytes: u64,
    pub incoming_wire_frame_bytes: u64,
}

struct Window {
    started: u64,
    finished: u64,
    trial: usize,
}

pub(super) fn extract(
    bytes: &[u8],
    selections: &[Selection],
    capture_started_us: u64,
    capture_finished_exclusive_us: u64,
    remaining_rows: &mut usize,
) -> Result<(Vec<TrialStats>, usize), &'static str> {
    let mut windows: BTreeMap<Key, Vec<Window>> = BTreeMap::new();
    for (trial, selected) in selections.iter().enumerate() {
        selected.flow.validate()?;
        if selected.started_us < capture_started_us
            || selected.finished_us > capture_finished_exclusive_us
            || selected.started_us >= selected.finished_us
        {
            return Err("trial window is outside declared complete capture interval");
        }
        windows
            .entry(key(
                selected.flow.protocol,
                selected.flow.client,
                selected.flow.peer,
            ))
            .or_default()
            .push(Window {
                started: selected.started_us,
                finished: selected.finished_us,
                trial,
            });
    }
    for group in windows.values_mut() {
        group.sort_unstable_by_key(|window| window.started);
        if group
            .windows(2)
            .any(|pair| pair[0].finished > pair[1].started)
        {
            return Err("ambiguous overlapping trial flow windows");
        }
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "packet export must be UTF-8 TSV")?;
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err("packet export header must match version 1");
    }
    let mut stats = vec![TrialStats::default(); selections.len()];
    let mut previous_timestamp = None;
    let mut rows = 0usize;
    for line in lines {
        if line.is_empty() || line.len() > MAX_ROW_BYTES || line.contains('\r') {
            return Err("invalid bounded packet export row");
        }
        *remaining_rows = remaining_rows
            .checked_sub(1)
            .ok_or("combined packet row budget exceeded")?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 8 {
            return Err("packet export row has wrong field count");
        }
        let number = |value: &str| -> Result<u64, &'static str> {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid integer packet field");
            }
            value.parse().map_err(|_| "integer packet field overflow")
        };
        let timestamp = number(fields[0])?;
        let length = number(fields[1])?;
        let captured = number(fields[2])?;
        if timestamp < capture_started_us || timestamp >= capture_finished_exclusive_us {
            return Err("packet timestamp is outside declared complete capture interval");
        }
        if previous_timestamp.is_some_and(|previous| previous > timestamp) {
            return Err("packet export timestamps must preserve nondecreasing capture order");
        }
        previous_timestamp = Some(timestamp);
        if !(1..=65_535).contains(&length) || captured != length {
            return Err("packet export is truncated or frame length is outside budget");
        }
        let protocol = match fields[5] {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => return Err("packet export protocol must be tcp or udp"),
        };
        let source = Endpoint {
            ip: fields[3].parse().map_err(|_| "invalid packet IP address")?,
            port: u16::try_from(number(fields[6])?).map_err(|_| "packet port is outside budget")?,
        };
        let destination = Endpoint {
            ip: fields[4].parse().map_err(|_| "invalid packet IP address")?,
            port: u16::try_from(number(fields[7])?).map_err(|_| "packet port is outside budget")?,
        };
        Flow {
            protocol,
            client: source,
            peer: destination,
        }
        .validate()?;
        rows += 1;
        let Some(group) = windows.get(&key(protocol, source, destination)) else {
            continue;
        };
        let after = group.partition_point(|window| window.started <= timestamp);
        let Some(window) = after.checked_sub(1).map(|index| &group[index]) else {
            continue;
        };
        if timestamp >= window.finished {
            continue;
        }
        let selected = &mut stats[window.trial];
        selected.selected_wire_frame_bytes = selected
            .selected_wire_frame_bytes
            .checked_add(length)
            .ok_or("selected wire byte budget overflow")?;
        selected.selected_packet_rows += 1;
        if source == selections[window.trial].flow.client {
            selected.outgoing_wire_frame_bytes += length;
        } else {
            selected.incoming_wire_frame_bytes += length;
        }
    }
    if rows == 0 || stats.iter().any(|trial| trial.selected_packet_rows == 0) {
        return Err("packet export or selected trial has no packet rows");
    }
    Ok((stats, rows))
}
