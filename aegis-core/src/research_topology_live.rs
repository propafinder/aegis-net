//! Conditional admission against an operator-declared dependency graph.
//! This only narrows an already admitted pool. It never discovers nodes, proves
//! reachability, authorizes a target or substitutes for transport policy.
use super::{Graph, GraphInput, Interdependent, ModelError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_LIVE_NODES: usize = 32;
pub const MAX_LIVE_EDGES: usize = 128;
pub const MAX_LIVE_ENDPOINTS: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveDependencyPolicy {
    pub a: GraphInput,
    pub b: GraphInput,
    pub dependency_pairs: Vec<[u32; 2]>,
    /// Exactly one unique A node per numeric endpoint, in public pool order.
    pub endpoint_nodes: Vec<u32>,
    /// The operator requires both anchors to survive the declared cascade.
    pub anchor_a: u32,
    pub anchor_b: u32,
    #[serde(default)]
    pub unavailable_a: Vec<u32>,
    #[serde(default)]
    pub unavailable_b: Vec<u32>,
}

impl LiveDependencyPolicy {
    pub fn validate(&self, endpoint_count: usize) -> Result<(), ModelError> {
        self.checked_system(endpoint_count).map(|_| ())
    }

    fn checked_system(&self, endpoint_count: usize) -> Result<Interdependent, ModelError> {
        if !(2..=MAX_LIVE_ENDPOINTS).contains(&endpoint_count)
            || self.endpoint_nodes.len() != endpoint_count
            || [self.a.nodes.len(), self.b.nodes.len()]
                .into_iter()
                .any(|n| n == 0 || n > MAX_LIVE_NODES)
            || [self.a.edges.len(), self.b.edges.len()]
                .into_iter()
                .any(|n| n > MAX_LIVE_EDGES)
            || self.dependency_pairs.len() > MAX_LIVE_NODES
        {
            return Err(ModelError("live dependency bounds"));
        }
        let a = Graph::new(self.a.clone())?;
        let b = Graph::new(self.b.clone())?;
        if !a.nodes().contains(&self.anchor_a) || !b.nodes().contains(&self.anchor_b) {
            return Err(ModelError("unknown live dependency anchor"));
        }
        let mut mapped = BTreeSet::new();
        for &node in &self.endpoint_nodes {
            if !a.nodes().contains(&node) || !mapped.insert(node) {
                return Err(ModelError("unknown/duplicate live endpoint node"));
            }
        }
        // Verify declared failures independently, before merging observed pool
        // exclusions; merging must not hide malformed duplicate declarations.
        a.survivors(&self.unavailable_a)?;
        b.survivors(&self.unavailable_b)?;
        Interdependent::new(a, b, &self.dependency_pairs)
    }

    /// `eligible` must already reflect authorization, transport hard blocks and
    /// the caller's bounded pre-auth outage state. Output preserves its order.
    /// An excluded endpoint is removed from the declared graph, then the same
    /// bounded connectivity/dependency fixed point used by the analysis runs.
    pub fn admit(
        &self,
        endpoint_count: usize,
        eligible: &[usize],
    ) -> Result<Vec<usize>, ModelError> {
        let system = self.checked_system(endpoint_count)?;
        if eligible.len() > endpoint_count {
            return Err(ModelError("live eligibility count"));
        }
        let mut permitted = BTreeSet::new();
        for &index in eligible {
            if index >= endpoint_count || !permitted.insert(index) {
                return Err(ModelError("unknown/duplicate eligible endpoint"));
            }
        }
        let mut failed_a: BTreeSet<_> = self.unavailable_a.iter().copied().collect();
        for (index, &node) in self.endpoint_nodes.iter().enumerate() {
            if !permitted.contains(&index) {
                failed_a.insert(node);
            }
        }
        let report = system.cascade(
            &failed_a.into_iter().collect::<Vec<_>>(),
            &self.unavailable_b,
        )?;
        if !report.final_a.largest_component.contains(&self.anchor_a)
            || !report.final_b.largest_component.contains(&self.anchor_b)
        {
            return Ok(Vec::new());
        }
        Ok(eligible
            .iter()
            .copied()
            .filter(|&index| {
                report
                    .final_a
                    .largest_component
                    .contains(&self.endpoint_nodes[index])
            })
            .collect())
    }
}

#[cfg(test)]
#[path = "research_topology_live_tests.rs"]
mod tests;
