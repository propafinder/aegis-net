use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenBins {
    pub schema_version: u8,
    pub statistic: String,
    pub units: String,
    pub frozen_unix_ms: u64,
    pub training_units_sha256: String,
    pub upper_exclusive_edges: Vec<u64>,
}

impl FrozenBins {
    pub fn validate(&self, training_units_sha256: &str) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.statistic != "selected_captured_wire_frame_bytes"
            || self.units != "bytes"
            || self.frozen_unix_ms == 0
            || self.training_units_sha256 != training_units_sha256
            || !(1..=255).contains(&self.upper_exclusive_edges.len())
            || self.upper_exclusive_edges[0] == 0
            || self
                .upper_exclusive_edges
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("invalid frozen scalar bins or training declaration binding");
        }
        Ok(())
    }

    pub fn feature(&self, selected_wire_frame_bytes: u64) -> usize {
        self.upper_exclusive_edges
            .partition_point(|edge| selected_wire_frame_bytes >= *edge)
    }
}
