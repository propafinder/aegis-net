//! Offline consumer of operator-declared, pseudonymous dependency inventories.
//! Unknown dependencies never become invented nodes or an independence verdict.
use crate::dependency_cuts::{self, Dependency, FailureKind, Route, Topology};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, collections::BTreeSet, path::Path};
use thiserror::Error;

pub const MAX_INPUT_BYTES: usize = 65_536;
const INVENTORY_SCHEMA: &str = "aegis_fleet_dependency_inventory_v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InventoryError {
    #[error("inventory exceeds the input byte budget")]
    InputBudget,
    #[error("inventory JSON or schema is invalid")]
    InvalidJson,
    #[error("inventory graph exceeds the node, route or edge budget")]
    GraphBudget,
    #[error("inventory dependency declarations are inconsistent")]
    InvalidGraph,
    #[error("inventory requires a bounded private regular file in trusted ancestry")]
    PrivateInput,
    #[error("finite dependency analysis failed")]
    Analysis,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Provider,
    Dns,
    Controller,
    Broker,
    Sfu,
}

impl Kind {
    fn failure_kind(self) -> FailureKind {
        match self {
            Self::Provider => FailureKind::Provider,
            Self::Dns => FailureKind::Dns,
            Self::Controller => FailureKind::Controller,
            Self::Broker => FailureKind::Broker,
            Self::Sfu => FailureKind::Sfu,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Provider,
    Dns,
    Bootstrap,
}

impl Category {
    fn contains(self, kind: Kind) -> bool {
        match self {
            Self::Provider => kind == Kind::Provider,
            Self::Dns => kind == Kind::Dns,
            Self::Bootstrap => matches!(kind, Kind::Controller | Kind::Broker | Kind::Sfu),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Knowledge {
    Known,
    Unknown,
    NotRequired,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    status: Knowledge,
    dependency_ids: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryDependency {
    id: u8,
    kind: Kind,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRoute {
    id: u8,
    provider: Declaration,
    dns: Declaration,
    bootstrap: Declaration,
}

impl InventoryRoute {
    fn declarations(&self) -> [(Category, &Declaration); 3] {
        [
            (Category::Provider, &self.provider),
            (Category::Dns, &self.dns),
            (Category::Bootstrap, &self.bootstrap),
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    artifact_schema: String,
    dependencies: Vec<InventoryDependency>,
    routes: Vec<InventoryRoute>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UnknownDependency {
    pub route_id: u8,
    pub category: Category,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NotRequiredDeclaration {
    pub route_id: u8,
    pub category: Category,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CutStatus {
    ComputedFromDeclarations,
    UnresolvedDependencies,
    CutBudgetExceeded,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CutReport {
    pub status: CutStatus,
    /// All other dependencies are assumed available for this finite calculation.
    /// None means no result; Some([]) means no cut within the selected family.
    pub minimal_outage_sets: Option<Vec<Vec<u8>>>,
    pub selected_known_dependency_count: usize,
    pub nonempty_subset_budget: usize,
}

#[derive(Debug, Serialize)]
pub struct InventoryReport {
    pub artifact_schema: &'static str,
    pub scope: &'static str,
    pub input_sha256: String,
    pub provenance: &'static str,
    pub semantics: &'static str,
    pub dependency_count: usize,
    pub route_count: usize,
    pub declarations_complete: bool,
    pub unknown_dependencies: Vec<UnknownDependency>,
    pub declared_not_required: Vec<NotRequiredDeclaration>,
    pub provider_cuts: CutReport,
    pub dns_cuts: CutReport,
    pub bootstrap_cuts: CutReport,
    pub all_dependency_cuts: CutReport,
    pub dependency_independence_verified: bool,
    pub fleet_reliability_measured: bool,
    pub target_network_measured: bool,
    pub beta_exit: bool,
}

impl Inventory {
    fn validate(&self) -> Result<(), InventoryError> {
        if self.artifact_schema != INVENTORY_SCHEMA {
            return Err(InventoryError::InvalidJson);
        }
        if self.dependencies.len() > dependency_cuts::MAX_NODES
            || self.routes.is_empty()
            || self.routes.len() > dependency_cuts::MAX_ROUTES
            || self.routes.iter().any(|route| {
                route
                    .declarations()
                    .iter()
                    .map(|(_, declaration)| declaration.dependency_ids.len())
                    .sum::<usize>()
                    > dependency_cuts::MAX_NODES
            })
        {
            return Err(InventoryError::GraphBudget);
        }
        let dependencies: BTreeMap<_, _> = self
            .dependencies
            .iter()
            .map(|dependency| (dependency.id, dependency.kind))
            .collect();
        let route_ids: BTreeSet<_> = self.routes.iter().map(|route| route.id).collect();
        if dependencies.len() != self.dependencies.len()
            || dependencies.contains_key(&0)
            || route_ids.len() != self.routes.len()
            || route_ids.contains(&0)
        {
            return Err(InventoryError::InvalidGraph);
        }
        let mut referenced = BTreeSet::new();
        for route in &self.routes {
            let mut route_dependencies = BTreeSet::new();
            for (category, declaration) in route.declarations() {
                match declaration.status {
                    Knowledge::Known if declaration.dependency_ids.is_empty() => {
                        return Err(InventoryError::InvalidGraph);
                    }
                    Knowledge::NotRequired
                        if category == Category::Provider
                            || !declaration.dependency_ids.is_empty() =>
                    {
                        return Err(InventoryError::InvalidGraph);
                    }
                    _ => {}
                }
                for id in &declaration.dependency_ids {
                    if !dependencies
                        .get(id)
                        .is_some_and(|kind| category.contains(*kind))
                        || !route_dependencies.insert(*id)
                    {
                        return Err(InventoryError::InvalidGraph);
                    }
                    referenced.insert(*id);
                }
            }
        }
        // Unreferenced nodes cannot silently inflate or alter a cut family.
        if referenced.len() != dependencies.len() {
            return Err(InventoryError::InvalidGraph);
        }
        Ok(())
    }

    fn cuts(&self, categories: &[Category]) -> Result<CutReport, InventoryError> {
        let dependencies: Vec<_> = self
            .dependencies
            .iter()
            .filter(|dependency| categories.iter().any(|c| c.contains(dependency.kind)))
            .map(|dependency| Dependency {
                id: dependency.id,
                kind: dependency.kind.failure_kind(),
            })
            .collect();
        let mut report = CutReport {
            status: CutStatus::UnresolvedDependencies,
            minimal_outage_sets: None,
            selected_known_dependency_count: dependencies.len(),
            nonempty_subset_budget: (1 << dependency_cuts::MAX_CUT_DEPENDENCIES) - 1,
        };
        if self.routes.iter().any(|route| {
            route.declarations().iter().any(|(category, declaration)| {
                categories.contains(category) && declaration.status == Knowledge::Unknown
            })
        }) {
            return Ok(report);
        }
        if dependencies.len() > dependency_cuts::MAX_CUT_DEPENDENCIES {
            report.status = CutStatus::CutBudgetExceeded;
            return Ok(report);
        }
        let routes: Vec<_> = self
            .routes
            .iter()
            .map(|route| Route {
                id: route.id,
                dependencies: route
                    .declarations()
                    .iter()
                    .filter(|(category, _)| categories.contains(category))
                    .flat_map(|(_, declaration)| declaration.dependency_ids.iter().copied())
                    .collect(),
            })
            .collect();
        report.status = CutStatus::ComputedFromDeclarations;
        // A route explicitly not requiring this family survives every failure
        // in the family. Do not invent a sentinel node to force a model cut.
        if routes.iter().any(|route| route.dependencies.is_empty()) {
            report.minimal_outage_sets = Some(Vec::new());
            return Ok(report);
        }
        let kinds = [
            FailureKind::Provider,
            FailureKind::Dns,
            FailureKind::Controller,
            FailureKind::Broker,
            FailureKind::Sfu,
        ];
        report.minimal_outage_sets = Some(
            Topology::new(dependencies, routes)
                .and_then(|topology| topology.minimal_cuts(&kinds))
                .map_err(|_| InventoryError::Analysis)?,
        );
        Ok(report)
    }
}

/// Parse bounded JSON with strict fields, then consume the existing cut model.
/// Only numeric pseudonyms and a hash leave the input; there are no endpoints,
/// provider names, credential fields, probes, probability or independence claims.
pub fn analyze_json(bytes: &[u8]) -> Result<InventoryReport, InventoryError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(InventoryError::InputBudget);
    }
    let inventory: Inventory =
        serde_json::from_slice(bytes).map_err(|_| InventoryError::InvalidJson)?;
    inventory.validate()?;
    let mut unknown_dependencies = Vec::new();
    let mut declared_not_required = Vec::new();
    let mut ordered_routes: Vec<_> = inventory.routes.iter().collect();
    ordered_routes.sort_by_key(|route| route.id);
    for route in ordered_routes {
        for (category, declaration) in route.declarations() {
            if declaration.status == Knowledge::Unknown {
                unknown_dependencies.push(UnknownDependency {
                    route_id: route.id,
                    category,
                });
            }
            if declaration.status == Knowledge::NotRequired {
                declared_not_required.push(NotRequiredDeclaration {
                    route_id: route.id,
                    category,
                });
            }
        }
    }
    Ok(InventoryReport {
        artifact_schema: "aegis_fleet_dependency_cuts_v1",
        scope: "offline_declared_dependency_inventory",
        input_sha256: format!("{:x}", Sha256::digest(bytes)),
        provenance: "operator_declared_only",
        semantics: "alternative_routes_OR_each_route_dependencies_AND_unselected_available",
        dependency_count: inventory.dependencies.len(),
        route_count: inventory.routes.len(),
        declarations_complete: unknown_dependencies.is_empty(),
        unknown_dependencies,
        declared_not_required,
        provider_cuts: inventory.cuts(&[Category::Provider])?,
        dns_cuts: inventory.cuts(&[Category::Dns])?,
        bootstrap_cuts: inventory.cuts(&[Category::Bootstrap])?,
        all_dependency_cuts: inventory.cuts(&[
            Category::Provider,
            Category::Dns,
            Category::Bootstrap,
        ])?,
        dependency_independence_verified: false,
        fleet_reliability_measured: false,
        target_network_measured: false,
        beta_exit: false,
    })
}

/// Reuse the product's bounded descriptor/permission reader. Paths and raw
/// parser/OS errors are intentionally absent from returned diagnostic messages.
pub fn analyze_private_file(path: &Path) -> Result<InventoryReport, InventoryError> {
    let parent = aegis_core::secret_file::trusted_read_parent(path)
        .map_err(|_| InventoryError::PrivateInput)?;
    let leaf = path.file_name().ok_or(InventoryError::PrivateInput)?;
    let bytes = aegis_core::secret_file::read(&parent.join(leaf), MAX_INPUT_BYTES as u64)
        .map_err(|_| InventoryError::PrivateInput)?;
    analyze_json(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn known(ids: &[u8]) -> Value {
        json!({"status":"known", "dependency_ids":ids})
    }

    fn unknown(ids: &[u8]) -> Value {
        json!({"status":"unknown", "dependency_ids":ids})
    }

    fn not_required() -> Value {
        json!({"status":"not_required", "dependency_ids":[]})
    }

    fn route(id: u8, provider: Value, dns: Value, bootstrap: Value) -> Value {
        json!({"id":id, "provider":provider, "dns":dns, "bootstrap":bootstrap})
    }

    fn fixture(shared_provider: bool) -> Value {
        let mut inventory = json!({
            "artifact_schema":INVENTORY_SCHEMA,
            "dependencies":[
                {"id":1,"kind":"provider"},
                {"id":2,"kind":"provider"},
                {"id":3,"kind":"dns"},
                {"id":4,"kind":"controller"},
                {"id":5,"kind":"broker"},
                {"id":6,"kind":"sfu"}
            ],
            "routes":[
                route(10, known(&[1]), known(&[3]), known(&[4,5,6])),
                route(20, known(&[2]), known(&[3]), known(&[4,5,6]))
            ]
        });
        if shared_provider {
            inventory["dependencies"].as_array_mut().unwrap().remove(1);
            inventory["routes"][1]["provider"] = known(&[1]);
        }
        inventory
    }

    fn analyze(value: &Value) -> Result<InventoryReport, InventoryError> {
        analyze_json(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn distinct_declared_providers_still_have_shared_dns_and_bootstrap_cuts() {
        let report = analyze(&fixture(false)).unwrap();
        assert!(report.declarations_complete);
        assert_eq!(
            report.provider_cuts.minimal_outage_sets,
            Some(vec![vec![1, 2]])
        );
        assert_eq!(report.dns_cuts.minimal_outage_sets, Some(vec![vec![3]]));
        assert_eq!(
            report.bootstrap_cuts.minimal_outage_sets,
            Some(vec![vec![4], vec![5], vec![6]])
        );
        assert_eq!(
            report.all_dependency_cuts.minimal_outage_sets,
            Some(vec![vec![3], vec![4], vec![5], vec![6], vec![1, 2]])
        );
        assert!(!report.dependency_independence_verified);
        assert!(!report.fleet_reliability_measured);
        assert!(!report.target_network_measured);
        assert!(!report.beta_exit);
    }

    #[test]
    fn shared_provider_is_one_outage_cut_and_order_does_not_change_cuts() {
        let mut input = fixture(true);
        let first = analyze(&input).unwrap();
        assert_eq!(first.provider_cuts.minimal_outage_sets, Some(vec![vec![1]]));
        input["dependencies"].as_array_mut().unwrap().reverse();
        input["routes"].as_array_mut().unwrap().reverse();
        input["routes"][0]["bootstrap"]["dependency_ids"] = json!([6, 5, 4]);
        let second = analyze(&input).unwrap();
        assert_eq!(first.all_dependency_cuts, second.all_dependency_cuts);
        assert_eq!(first.unknown_dependencies, second.unknown_dependencies);
        // Hash binds exact input bytes, not a guessed canonical topology.
        assert_ne!(first.input_sha256, second.input_sha256);
    }

    #[test]
    fn unresolved_category_does_not_become_a_fake_cut_or_independence_verdict() {
        let mut input = fixture(false);
        input["routes"][0]["provider"] = unknown(&[1]);
        input["routes"][1]["dns"] = unknown(&[3]);
        let report = analyze(&input).unwrap();
        assert!(!report.declarations_complete);
        assert_eq!(
            report.provider_cuts.status,
            CutStatus::UnresolvedDependencies
        );
        assert_eq!(report.provider_cuts.minimal_outage_sets, None);
        assert_eq!(report.dns_cuts.minimal_outage_sets, None);
        assert_eq!(report.all_dependency_cuts.minimal_outage_sets, None);
        assert_eq!(
            report.bootstrap_cuts.minimal_outage_sets,
            Some(vec![vec![4], vec![5], vec![6]])
        );
        assert_eq!(
            report.unknown_dependencies,
            vec![
                UnknownDependency {
                    route_id: 10,
                    category: Category::Provider
                },
                UnknownDependency {
                    route_id: 20,
                    category: Category::Dns
                }
            ]
        );
        assert!(!report.dependency_independence_verified);
    }

    #[test]
    fn wholly_unknown_inventory_is_accepted_without_inventing_nodes() {
        let input = json!({
            "artifact_schema":INVENTORY_SCHEMA,
            "dependencies":[],
            "routes":[route(1, unknown(&[]), unknown(&[]), unknown(&[]))]
        });
        let report = analyze(&input).unwrap();
        assert_eq!(report.dependency_count, 0);
        assert_eq!(report.unknown_dependencies.len(), 3);
        for cut in [
            report.provider_cuts,
            report.dns_cuts,
            report.bootstrap_cuts,
            report.all_dependency_cuts,
        ] {
            assert_eq!(cut.status, CutStatus::UnresolvedDependencies);
            assert_eq!(cut.minimal_outage_sets, None);
        }
    }

    #[test]
    fn explicit_not_required_is_retained_and_empty_cuts_are_not_unknown() {
        let input = json!({
            "artifact_schema":INVENTORY_SCHEMA,
            "dependencies":[{"id":1,"kind":"provider"}, {"id":2,"kind":"dns"}],
            "routes":[
                route(1, known(&[1]), known(&[2]), not_required()),
                route(2, known(&[1]), not_required(), not_required())
            ]
        });
        let report = analyze(&input).unwrap();
        assert!(report.declarations_complete);
        assert_eq!(report.dns_cuts.minimal_outage_sets, Some(vec![]));
        assert_eq!(
            report.bootstrap_cuts.status,
            CutStatus::ComputedFromDeclarations
        );
        assert_eq!(report.bootstrap_cuts.minimal_outage_sets, Some(vec![]));
        assert_eq!(
            report.all_dependency_cuts.minimal_outage_sets,
            Some(vec![vec![1]])
        );
        assert_eq!(report.declared_not_required.len(), 3);
        assert!(!report.dependency_independence_verified);
    }

    #[test]
    fn malformed_or_incomplete_schema_diagnostics_do_not_echo_input() {
        let synthetic_marker = "DO_NOT_ECHO_SYNTHETIC_PRIVATE_INPUT";
        let mut input = fixture(false);
        input["routes"][0]["password"] = json!(synthetic_marker);
        assert_eq!(analyze(&input).unwrap_err(), InventoryError::InvalidJson);
        assert!(!analyze(&input)
            .unwrap_err()
            .to_string()
            .contains(synthetic_marker));
        input = fixture(false);
        input["routes"][0].as_object_mut().unwrap().remove("dns");
        assert_eq!(analyze(&input).unwrap_err(), InventoryError::InvalidJson);
        input = fixture(false);
        input["artifact_schema"] = json!("future_schema");
        assert_eq!(analyze(&input).unwrap_err(), InventoryError::InvalidJson);
        for invalid in [
            "{",
            "{} {}",
            "{\"artifact_schema\":\"x\",\"artifact_schema\":\"y\"}",
            "{\"artifact_schema\":1}",
        ] {
            assert_eq!(
                analyze_json(invalid.as_bytes()).unwrap_err(),
                InventoryError::InvalidJson
            );
        }
    }

    #[test]
    fn inconsistent_graph_is_rejected_before_analysis() {
        for mutation in 0..11 {
            let mut input = fixture(false);
            match mutation {
                0 => input["dependencies"][1]["id"] = json!(1),
                1 => input["routes"][1]["id"] = json!(10),
                2 => input["routes"][0]["provider"] = known(&[99]),
                3 => input["routes"][0]["provider"] = known(&[3]),
                4 => input["routes"][0]["provider"] = known(&[]),
                5 => input["routes"][0]["bootstrap"] = known(&[4, 4]),
                6 => {
                    input["routes"][0]["dns"] =
                        json!({"status":"not_required", "dependency_ids":[3]})
                }
                7 => input["routes"][0]["provider"] = not_required(),
                8 => input["dependencies"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":7,"kind":"provider"})),
                9 => input["routes"][0]["id"] = json!(0),
                10 => input["dependencies"][0]["id"] = json!(0),
                _ => unreachable!(),
            }
            assert_eq!(
                analyze(&input).unwrap_err(),
                InventoryError::InvalidGraph,
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn input_and_graph_budgets_refuse_before_cut_enumeration() {
        assert_eq!(
            analyze_json(&vec![b' '; MAX_INPUT_BYTES + 1]).unwrap_err(),
            InventoryError::InputBudget
        );
        for mutation in 0..4 {
            let mut input = fixture(false);
            match mutation {
                0 => input["dependencies"] = json!(vec![json!({"id":1,"kind":"provider"}); 17]),
                1 => input["routes"] = json!(vec![input["routes"][0].clone(); 17]),
                2 => input["routes"][0]["provider"]["dependency_ids"] = json!(vec![1; 17]),
                3 => input["routes"] = json!([]),
                _ => unreachable!(),
            }
            assert_eq!(analyze(&input).unwrap_err(), InventoryError::GraphBudget);
        }
        // The exact byte cap is permitted. Whitespace cannot enlarge the model.
        let mut exact = serde_json::to_vec(&fixture(false)).unwrap();
        exact.resize(MAX_INPUT_BYTES, b' ');
        assert!(analyze_json(&exact).is_ok());
    }

    #[test]
    fn cut_budget_is_explicit_and_other_families_still_work() {
        let input = json!({
            "artifact_schema":INVENTORY_SCHEMA,
            "dependencies":(1..=9).map(|id| json!({"id":id,"kind":"provider"})).collect::<Vec<_>>(),
            "routes":[route(1, known(&(1..=9).collect::<Vec<_>>()), not_required(), not_required())]
        });
        let report = analyze(&input).unwrap();
        assert!(report.declarations_complete);
        assert_eq!(report.provider_cuts.status, CutStatus::CutBudgetExceeded);
        assert_eq!(report.provider_cuts.minimal_outage_sets, None);
        assert_eq!(report.provider_cuts.selected_known_dependency_count, 9);
        assert_eq!(
            report.all_dependency_cuts.status,
            CutStatus::CutBudgetExceeded
        );
        assert_eq!(report.dns_cuts.minimal_outage_sets, Some(vec![]));
        assert_eq!(report.bootstrap_cuts.minimal_outage_sets, Some(vec![]));

        let mut within = input;
        within["dependencies"].as_array_mut().unwrap().pop();
        within["routes"][0]["provider"] = known(&(1..=8).collect::<Vec<_>>());
        let report = analyze(&within).unwrap();
        assert_eq!(
            report.provider_cuts.status,
            CutStatus::ComputedFromDeclarations
        );
        assert_eq!(report.provider_cuts.nonempty_subset_budget, 255);
        assert_eq!(report.provider_cuts.minimal_outage_sets.unwrap().len(), 8);
    }
}
