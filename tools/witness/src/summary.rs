//! Aggregation helpers for witness JSONL events.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::report::WitnessEvent;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessSummary {
    pub schema_version: u8,
    pub groups: Vec<WitnessSummaryGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessSummaryGroup {
    pub label: String,
    pub total_records: usize,
    pub tls_client_hello_records: usize,
    pub ja3_present_avg: f32,
    pub alpn_match_avg: f32,
    pub sni_structure_avg: f32,
    pub extension_structure_avg: f32,
    pub combined_avg: f32,
}

#[derive(Debug, Default)]
struct Accumulator {
    total_records: usize,
    tls_client_hello_records: usize,
    ja3_present_sum: f32,
    alpn_match_sum: f32,
    sni_structure_sum: f32,
    extension_structure_sum: f32,
    combined_sum: f32,
}

pub fn summarize_events(events: &[WitnessEvent]) -> WitnessSummary {
    let mut groups = BTreeMap::<String, Accumulator>::new();
    for event in events {
        let group = groups.entry(event.label.clone()).or_default();
        group.total_records += 1;
        if event.classification.is_tls_client_hello {
            group.tls_client_hello_records += 1;
        }
        group.ja3_present_sum += event.score.ja3_present;
        group.alpn_match_sum += event.score.alpn_match;
        group.sni_structure_sum += event.score.sni_structure;
        group.extension_structure_sum += event.score.extension_structure;
        group.combined_sum += event.score.combined;
    }

    WitnessSummary {
        schema_version: 1,
        groups: groups
            .into_iter()
            .map(|(label, acc)| acc.into_group(label))
            .collect(),
    }
}

impl Accumulator {
    fn into_group(self, label: String) -> WitnessSummaryGroup {
        let denom = self.total_records.max(1) as f32;
        WitnessSummaryGroup {
            label,
            total_records: self.total_records,
            tls_client_hello_records: self.tls_client_hello_records,
            ja3_present_avg: self.ja3_present_sum / denom,
            alpn_match_avg: self.alpn_match_sum / denom,
            sni_structure_avg: self.sni_structure_sum / denom,
            extension_structure_avg: self.extension_structure_sum / denom,
            combined_avg: self.combined_sum / denom,
        }
    }
}

impl WitnessSummary {
    pub fn to_markdown_table(&self) -> String {
        let mut out = String::from(
            "| Label | Records | TLS ClientHello | JA3 | ALPN | SNI | Extensions | Combined |\n\
             |---|---:|---:|---:|---:|---:|---:|---:|\n",
        );
        for group in &self.groups {
            out.push_str(&format!(
                "| {} | {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} |\n",
                escape_table_cell(&group.label),
                group.total_records,
                group.tls_client_hello_records,
                group.ja3_present_avg,
                group.alpn_match_avg,
                group.sni_structure_avg,
                group.extension_structure_avg,
                group.combined_avg,
            ));
        }
        out
    }
}

fn escape_table_cell(value: &str) -> String {
    value.replace('|', "\\|")
}
