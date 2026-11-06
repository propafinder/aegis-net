//! Bounded Albert/Buldyrev algorithms shared by analysis and opt-in relay
//! dependency admission. Graphs are operator assumptions, never discovered fleet
//! facts or measured Internet reachability.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

pub const MAX_NODES: usize = 128;
pub const MAX_EDGES: usize = 4096;
pub const MAX_CAUSES: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid bounded topology: {0}")]
pub struct ModelError(pub &'static str);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphInput {
    pub nodes: Vec<u32>,
    pub edges: Vec<[u32; 2]>,
}

#[derive(Clone, Debug)]
pub struct Graph {
    ids: Vec<u32>,
    adjacent: Vec<Vec<usize>>,
}

impl Graph {
    pub fn new(mut input: GraphInput) -> Result<Self, ModelError> {
        if input.nodes.is_empty() || input.nodes.len() > MAX_NODES || input.edges.len() > MAX_EDGES
        {
            return Err(ModelError("node/edge limits"));
        }
        input.nodes.sort_unstable();
        if input.nodes.windows(2).any(|w| w[0] == w[1]) {
            return Err(ModelError("duplicate node ID"));
        }
        let mut adjacent = vec![Vec::new(); input.nodes.len()];
        let mut edges = BTreeSet::new();
        for [a, b] in input.edges {
            let x = input
                .nodes
                .binary_search(&a)
                .map_err(|_| ModelError("unknown edge endpoint"))?;
            let y = input
                .nodes
                .binary_search(&b)
                .map_err(|_| ModelError("unknown edge endpoint"))?;
            if x == y || !edges.insert((x.min(y), x.max(y))) {
                return Err(ModelError("self/duplicate undirected edge"));
            }
            adjacent[x].push(y);
            adjacent[y].push(x);
        }
        for neighbors in &mut adjacent {
            neighbors.sort_unstable();
        }
        Ok(Self {
            ids: input.nodes,
            adjacent,
        })
    }
    pub fn nodes(&self) -> &[u32] {
        &self.ids
    }
    pub fn input(&self) -> GraphInput {
        GraphInput {
            nodes: self.ids.clone(),
            edges: self
                .adjacent
                .iter()
                .enumerate()
                .flat_map(|(a, ns)| {
                    ns.iter()
                        .filter(move |&&b| a < b)
                        .map(move |&b| [self.ids[a], self.ids[b]])
                })
                .collect(),
        }
    }
    fn survivors(&self, failed: &[u32]) -> Result<Vec<bool>, ModelError> {
        if failed.len() > self.ids.len() {
            return Err(ModelError("failure count"));
        }
        let mut alive = vec![true; self.ids.len()];
        for id in failed {
            let i = self
                .ids
                .binary_search(id)
                .map_err(|_| ModelError("unknown failed ID"))?;
            if !alive[i] {
                return Err(ModelError("duplicate failed ID"));
            }
            alive[i] = false;
        }
        Ok(alive)
    }
    fn components(&self, alive: &[bool]) -> Vec<Vec<usize>> {
        let mut visited = vec![false; self.ids.len()];
        let mut components = Vec::new();
        for start in 0..self.ids.len() {
            if !alive[start] || visited[start] {
                continue;
            }
            let mut stack = vec![start];
            visited[start] = true;
            let mut component = Vec::new();
            while let Some(i) = stack.pop() {
                component.push(i);
                for &j in &self.adjacent[i] {
                    if alive[j] && !visited[j] {
                        visited[j] = true;
                        stack.push(j);
                    }
                }
            }
            component.sort_unstable();
            components.push(component);
        }
        components.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        components
    }
    fn keep_largest(&self, alive: &mut [bool]) {
        let components = self.components(alive);
        let mut keep = vec![false; alive.len()];
        if let Some(largest) = components.first() {
            for &i in largest {
                keep[i] = true;
            }
        }
        alive.copy_from_slice(&keep);
    }
    fn live_ids(&self, alive: &[bool]) -> Vec<u32> {
        self.ids
            .iter()
            .zip(alive)
            .filter_map(|(&id, &live)| live.then_some(id))
            .collect()
    }
    fn metrics(&self, alive: &[bool]) -> Metrics {
        let components = self.components(alive);
        let largest_component = components
            .first()
            .map_or_else(Vec::new, |v| v.iter().map(|&i| self.ids[i]).collect());
        let sizes: Vec<_> = components.iter().map(Vec::len).collect();
        let mut reachable_ordered_pairs = 0u64;
        let mut distance_sum = 0u64;
        let mut inverse_sum = 0.0;
        for start in 0..self.ids.len() {
            if !alive[start] {
                continue;
            }
            let mut distance = vec![usize::MAX; self.ids.len()];
            let mut queue = VecDeque::from([start]);
            distance[start] = 0;
            while let Some(i) = queue.pop_front() {
                for &j in &self.adjacent[i] {
                    if alive[j] && distance[j] == usize::MAX {
                        distance[j] = distance[i] + 1;
                        queue.push_back(j);
                    }
                }
            }
            for d in distance.into_iter().filter(|&d| d > 0 && d != usize::MAX) {
                reachable_ordered_pairs += 1;
                distance_sum += d as u64;
                inverse_sum += 1.0 / d as f64;
            }
        }
        let denominator = self.ids.len() * self.ids.len().saturating_sub(1);
        Metrics {
            surviving_nodes: alive.iter().filter(|&&v| v).count(),
            largest_fraction_of_original: largest_component.len() as f64 / self.ids.len() as f64,
            largest_component,
            component_sizes: sizes.clone(),
            mean_nonlargest_component_size: (sizes.len() > 1)
                .then(|| sizes[1..].iter().sum::<usize>() as f64 / (sizes.len() - 1) as f64),
            reachable_ordered_pairs,
            mean_reachable_distance: (reachable_ordered_pairs > 0)
                .then(|| distance_sum as f64 / reachable_ordered_pairs as f64),
            global_efficiency_original_denominator: if denominator == 0 {
                0.0
            } else {
                inverse_sum / denominator as f64
            },
        }
    }
    pub fn measure(&self, failed: &[u32]) -> Result<Metrics, ModelError> {
        Ok(self.metrics(&self.survivors(failed)?))
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Metrics {
    pub surviving_nodes: usize,
    pub largest_component: Vec<u32>,
    pub largest_fraction_of_original: f64,
    pub component_sizes: Vec<usize>,
    pub mean_nonlargest_component_size: Option<f64>,
    pub reachable_ordered_pairs: u64,
    /// Albert calls the mean shortest-path length a diameter. Here unreachable
    /// pairs are excluded and the pair count is exposed, rather than hidden.
    pub mean_reachable_distance: Option<f64>,
    /// Additional engineering metric, not a claimed Albert paper formula.
    pub global_efficiency_original_denominator: f64,
}

/// Reproducible simulation randomness only, never cryptographic randomness.
struct Seeded(u64);
impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> Result<u64, ModelError> {
        if n == 0 {
            return Err(ModelError("zero random range"));
        }
        let threshold = n.wrapping_neg() % n;
        for _ in 0..128 {
            let x = self.next();
            if x >= threshold {
                return Ok(x % n);
            }
        }
        Err(ModelError("simulation rejection bound"))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    Random,
    InitialDegree,
    AdaptiveDegree,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct AttackStep {
    pub removed: Option<u32>,
    pub metrics: Metrics,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct AttackReport {
    pub mode: AttackMode,
    pub seed: u64,
    pub steps: Vec<AttackStep>,
}
pub fn attack(
    graph: &Graph,
    mode: AttackMode,
    removals: usize,
    seed: u64,
) -> Result<AttackReport, ModelError> {
    if removals > graph.ids.len() {
        return Err(ModelError("attack count"));
    }
    let mut rng = Seeded(seed);
    let mut alive = vec![true; graph.ids.len()];
    let mut order: Vec<_> = (0..alive.len()).collect();
    match mode {
        AttackMode::Random => {
            for i in (1..order.len()).rev() {
                let j = rng.below((i + 1) as u64)? as usize;
                order.swap(i, j);
            }
        }
        AttackMode::InitialDegree => order.sort_by(|&a, &b| {
            graph.adjacent[b]
                .len()
                .cmp(&graph.adjacent[a].len())
                .then(a.cmp(&b))
        }),
        AttackMode::AdaptiveDegree => {}
    }
    let mut steps = vec![AttackStep {
        removed: None,
        metrics: graph.metrics(&alive),
    }];
    for &ordered in order.iter().take(removals) {
        let i = if mode == AttackMode::AdaptiveDegree {
            (0..alive.len())
                .filter(|&i| alive[i])
                .max_by(|&a, &b| {
                    let degree = |i: usize| graph.adjacent[i].iter().filter(|&&j| alive[j]).count();
                    degree(a).cmp(&degree(b)).then(b.cmp(&a))
                })
                .ok_or(ModelError("no attack node"))?
        } else {
            ordered
        };
        alive[i] = false;
        steps.push(AttackStep {
            removed: Some(graph.ids[i]),
            metrics: graph.metrics(&alive),
        });
    }
    Ok(AttackReport { mode, seed, steps })
}

pub fn erdos_renyi(
    nodes: usize,
    probability_numerator: u32,
    probability_denominator: u32,
    seed: u64,
) -> Result<Graph, ModelError> {
    if nodes == 0
        || nodes > MAX_NODES
        || probability_denominator == 0
        || probability_denominator > 1_000_000
        || probability_numerator > probability_denominator
    {
        return Err(ModelError("ER parameters"));
    }
    let mut rng = Seeded(seed);
    let mut edges = Vec::new();
    for a in 0..nodes {
        for b in a + 1..nodes {
            if rng.below(probability_denominator as u64)? < probability_numerator as u64 {
                edges.push([a as u32, b as u32]);
            }
        }
    }
    Graph::new(GraphInput {
        nodes: (0..nodes as u32).collect(),
        edges,
    })
}
/// Clique seed of m+1; m distinct existing endpoints per new node, sampled
/// proportionally to current degree, without replacement within that step.
pub fn preferential_attachment(nodes: usize, m: usize, seed: u64) -> Result<Graph, ModelError> {
    if nodes == 0 || nodes > MAX_NODES || m == 0 || m >= nodes {
        return Err(ModelError("PA parameters"));
    }
    let mut rng = Seeded(seed);
    let mut degree = vec![0u64; nodes];
    let mut edges = Vec::new();
    for a in 0..=m {
        for b in a + 1..=m {
            edges.push([a as u32, b as u32]);
            degree[a] += 1;
            degree[b] += 1;
        }
    }
    for new in m + 1..nodes {
        let mut chosen = BTreeSet::new();
        for _ in 0..m {
            let total: u64 = (0..new)
                .filter(|i| !chosen.contains(i))
                .map(|i| degree[i])
                .sum();
            let mut sample = rng.below(total)?;
            let mut target = None;
            for (i, &d) in degree.iter().enumerate().take(new) {
                if chosen.contains(&i) {
                    continue;
                }
                if sample < d {
                    target = Some(i);
                    break;
                }
                sample -= d;
            }
            let target = target.ok_or(ModelError("PA endpoint"))?;
            chosen.insert(target);
            edges.push([new as u32, target as u32]);
            degree[new] += 1;
            degree[target] += 1;
        }
    }
    Graph::new(GraphInput {
        nodes: (0..nodes as u32).collect(),
        edges,
    })
}

#[derive(Clone, Debug)]
pub struct Interdependent {
    a: Graph,
    b: Graph,
    a_to_b: Vec<usize>,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct CascadeStage {
    pub layer: char,
    pub removed_by_connectivity: Vec<u32>,
    pub removed_by_dependency: Vec<u32>,
    pub surviving_a: Vec<u32>,
    pub surviving_b: Vec<u32>,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct CascadeReport {
    pub initial_a: Vec<u32>,
    pub initial_b: Vec<u32>,
    pub stages: Vec<CascadeStage>,
    pub final_a: Metrics,
    pub final_b: Metrics,
    pub fixed_point: bool,
}
impl Interdependent {
    /// Exactly the symmetric one-to-one dependency variant: every vertex in A
    /// is paired with one unique B vertex. Not an inferred infrastructure map.
    pub fn new(a: Graph, b: Graph, pairs: &[[u32; 2]]) -> Result<Self, ModelError> {
        if a.ids.len() != b.ids.len() || pairs.len() != a.ids.len() {
            return Err(ModelError(
                "complete equal-size dependency bijection required",
            ));
        }
        let mut map = vec![usize::MAX; a.ids.len()];
        let mut used = BTreeSet::new();
        for &[x, y] in pairs {
            let i = a
                .ids
                .binary_search(&x)
                .map_err(|_| ModelError("unknown dependency A ID"))?;
            let j = b
                .ids
                .binary_search(&y)
                .map_err(|_| ModelError("unknown dependency B ID"))?;
            if map[i] != usize::MAX || !used.insert(j) {
                return Err(ModelError("duplicate dependency endpoint"));
            }
            map[i] = j;
        }
        Ok(Self { a, b, a_to_b: map })
    }
    fn propagate(&self, a: &mut [bool], b: &mut [bool]) {
        for (i, &j) in self.a_to_b.iter().enumerate() {
            let live = a[i] && b[j];
            a[i] = live;
            b[j] = live;
        }
    }
    pub fn cascade(&self, failed_a: &[u32], failed_b: &[u32]) -> Result<CascadeReport, ModelError> {
        let mut a = self.a.survivors(failed_a)?;
        let mut b = self.b.survivors(failed_b)?;
        self.propagate(&mut a, &mut b);
        let initial_a = self.a.live_ids(&a);
        let initial_b = self.b.live_ids(&b);
        let mut stages = Vec::new();
        for _ in 0..=self.a.ids.len() {
            let before_cycle = (a.clone(), b.clone());
            for layer in ['A', 'B'] {
                let before = if layer == 'A' { a.clone() } else { b.clone() };
                if layer == 'A' {
                    self.a.keep_largest(&mut a);
                } else {
                    self.b.keep_largest(&mut b);
                }
                let current = if layer == 'A' { &a } else { &b };
                let graph = if layer == 'A' { &self.a } else { &self.b };
                let removed_by_connectivity = graph
                    .ids
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &id)| (before[i] && !current[i]).then_some(id))
                    .collect();
                let opposite_before = if layer == 'A' { b.clone() } else { a.clone() };
                self.propagate(&mut a, &mut b);
                let opposite = if layer == 'A' { &b } else { &a };
                let opposite_graph = if layer == 'A' { &self.b } else { &self.a };
                let removed_by_dependency = opposite_graph
                    .ids
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &id)| (opposite_before[i] && !opposite[i]).then_some(id))
                    .collect();
                stages.push(CascadeStage {
                    layer,
                    removed_by_connectivity,
                    removed_by_dependency,
                    surviving_a: self.a.live_ids(&a),
                    surviving_b: self.b.live_ids(&b),
                });
            }
            if before_cycle == (a.clone(), b.clone()) {
                return Ok(CascadeReport {
                    initial_a,
                    initial_b,
                    stages,
                    final_a: self.a.metrics(&a),
                    final_b: self.b.metrics(&b),
                    fixed_point: true,
                });
            }
        }
        Err(ModelError("cascade monotonic bound"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provenance {
    Synthetic { label: String },
    ObservedInput { evidence_sha256: String },
}
impl Provenance {
    fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Synthetic { label }
                if !label.is_empty()
                    && label.len() <= 64
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
            {
                Ok(())
            }
            Self::ObservedInput { evidence_sha256 }
                if evidence_sha256.len() == 64
                    && evidence_sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
            {
                Ok(())
            }
            _ => Err(ModelError("provenance syntax")),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonCause {
    pub id: u32,
    pub failed_a: Vec<u32>,
    pub failed_b: Vec<u32>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub provenance: Provenance,
    pub a: GraphInput,
    pub b: GraphInput,
    pub dependency_pairs: Vec<[u32; 2]>,
    pub failed_a: Vec<u32>,
    pub failed_b: Vec<u32>,
    pub common_causes: Vec<CommonCause>,
    pub attack_removals: usize,
    pub seed: u64,
}
#[derive(Debug, Serialize)]
pub struct Analysis {
    pub schema: &'static str,
    pub provenance: Provenance,
    pub evidence_authenticated: bool,
    pub target_network_measured: bool,
    pub beta_exit: bool,
    pub attacks: Vec<AttackReport>,
    pub initial_cascade: CascadeReport,
    pub common_cause_cascades: BTreeMap<u32, CascadeReport>,
}
pub fn analyze(request: Request) -> Result<Analysis, ModelError> {
    if request.schema != "aegis_topology_papers_v1" || request.common_causes.len() > MAX_CAUSES {
        return Err(ModelError("schema/cause limit"));
    }
    request.provenance.validate()?;
    let a = Graph::new(request.a)?;
    let b = Graph::new(request.b)?;
    let system = Interdependent::new(a.clone(), b, &request.dependency_pairs)?;
    let initial_cascade = system.cascade(&request.failed_a, &request.failed_b)?;
    let mut common_cause_cascades = BTreeMap::new();
    for cause in request.common_causes {
        if cause.failed_a.is_empty() && cause.failed_b.is_empty() {
            return Err(ModelError("empty common cause"));
        }
        if common_cause_cascades
            .insert(cause.id, system.cascade(&cause.failed_a, &cause.failed_b)?)
            .is_some()
        {
            return Err(ModelError("duplicate cause ID"));
        }
    }
    let attacks = [
        AttackMode::Random,
        AttackMode::InitialDegree,
        AttackMode::AdaptiveDegree,
    ]
    .into_iter()
    .map(|mode| attack(&a, mode, request.attack_removals, request.seed))
    .collect::<Result<Vec<_>, _>>()?;
    Ok(Analysis {
        schema: "aegis_topology_papers_report_v1",
        provenance: request.provenance,
        evidence_authenticated: false,
        target_network_measured: false,
        beta_exit: false,
        attacks,
        initial_cascade,
        common_cause_cascades,
    })
}

#[cfg(test)]
#[path = "research_topology_tests.rs"]
mod tests;

#[path = "research_topology_live.rs"]
mod live;
pub use live::LiveDependencyPolicy;
