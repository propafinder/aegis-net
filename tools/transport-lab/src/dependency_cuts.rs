//! Finite, deterministic availability model: alternatives are OR; each route is AND.
//! No network observations, probabilities, scale laws, or critical thresholds.
use serde::Serialize;
use std::collections::BTreeSet;
use thiserror::Error;

pub const MAX_NODES: usize = 16;
pub const MAX_ROUTES: usize = 16;
pub const MAX_CUT_DEPENDENCIES: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Provider,
    Dns,
    Controller,
    Broker,
    Sfu,
}
#[derive(Clone, Debug, Serialize)]
pub struct Dependency {
    pub id: u8,
    pub kind: FailureKind,
}
#[derive(Clone, Debug, Serialize)]
pub struct Route {
    pub id: u8,
    pub dependencies: Vec<u8>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Topology {
    dependencies: Vec<Dependency>,
    routes: Vec<Route>,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Availability {
    pub available: bool,
    pub surviving_routes: Vec<u8>,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("require 1..=16 dependencies and routes, and bounded route dependencies")]
    Bounds,
    #[error("duplicate identifier/reference, empty route, or unknown dependency")]
    InvalidGraph,
    #[error("failure input contains unknown/duplicate dependency or exceeds bound")]
    InvalidFailure,
    #[error("cut enumeration permits at most five kinds and eight selected dependencies")]
    CutBound,
}
impl Topology {
    pub fn new(
        mut dependencies: Vec<Dependency>,
        mut routes: Vec<Route>,
    ) -> Result<Self, ModelError> {
        if dependencies.is_empty()
            || dependencies.len() > MAX_NODES
            || routes.is_empty()
            || routes.len() > MAX_ROUTES
            || routes.iter().any(|r| r.dependencies.len() > MAX_NODES)
        {
            return Err(ModelError::Bounds);
        }
        let ids: BTreeSet<_> = dependencies.iter().map(|d| d.id).collect();
        let route_ids: BTreeSet<_> = routes.iter().map(|r| r.id).collect();
        if ids.len() != dependencies.len()
            || route_ids.len() != routes.len()
            || routes.iter().any(|r| {
                r.dependencies.is_empty()
                    || r.dependencies
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != r.dependencies.len()
                    || r.dependencies.iter().any(|id| !ids.contains(id))
            })
        {
            return Err(ModelError::InvalidGraph);
        }
        dependencies.sort_by_key(|d| d.id);
        routes.sort_by_key(|r| r.id);
        for route in &mut routes {
            route.dependencies.sort_unstable();
        }
        Ok(Self {
            dependencies,
            routes,
        })
    }
    fn survives(&self, failed: &[u8]) -> Vec<u8> {
        self.routes
            .iter()
            .filter(|r| r.dependencies.iter().all(|d| !failed.contains(d)))
            .map(|r| r.id)
            .collect()
    }
    pub fn availability(&self, failed: &[u8]) -> Result<Availability, ModelError> {
        if failed.len() > MAX_NODES
            || failed.iter().copied().collect::<BTreeSet<_>>().len() != failed.len()
            || failed
                .iter()
                .any(|id| !self.dependencies.iter().any(|d| d.id == *id))
        {
            return Err(ModelError::InvalidFailure);
        }
        let surviving_routes = self.survives(failed);
        Ok(Availability {
            available: !surviving_routes.is_empty(),
            surviving_routes,
        })
    }
    /// Enumerate inclusion-minimal outage sets within selected kinds. Unselected
    /// dependencies remain available; an empty selection has no outage cuts.
    /// At most 255 nonempty subsets, sorted by cardinality then numeric IDs.
    pub fn minimal_cuts(&self, kinds: &[FailureKind]) -> Result<Vec<Vec<u8>>, ModelError> {
        if kinds.len() > 5 {
            return Err(ModelError::CutBound);
        }
        let ids: Vec<_> = self
            .dependencies
            .iter()
            .filter(|d| kinds.contains(&d.kind))
            .map(|d| d.id)
            .collect();
        if ids.len() > MAX_CUT_DEPENDENCIES {
            return Err(ModelError::CutBound);
        }
        let mut cuts = Vec::new();
        for mask in 1usize..(1usize << ids.len()) {
            let cut: Vec<_> = ids
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, id)| *id)
                .collect();
            if !self.survives(&cut).is_empty() {
                continue;
            }
            // Monotone AND/OR availability: testing every immediate subset suffices.
            if (0..cut.len()).all(|removed| {
                let subset: Vec<_> = cut
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != removed)
                    .map(|(_, id)| *id)
                    .collect();
                !self.survives(&subset).is_empty()
            }) {
                cuts.push(cut);
            }
        }
        cuts.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
        Ok(cuts)
    }
    pub fn provider_cuts(&self) -> Result<Vec<Vec<u8>>, ModelError> {
        self.minimal_cuts(&[FailureKind::Provider])
    }
}
fn fixture(shared_provider: bool, independent_bootstrap: bool) -> Result<Topology, ModelError> {
    use FailureKind::*;
    let (kinds, paths): (Vec<_>, Vec<Vec<u8>>) = if shared_provider {
        (
            vec![Provider, Dns, Controller, Broker, Sfu],
            vec![vec![1, 2, 3, 4, 5]; 3],
        )
    } else if independent_bootstrap {
        (
            vec![Provider, Provider, Dns, Controller, Dns, Controller],
            vec![vec![1, 3, 4], vec![2, 5, 6]],
        )
    } else {
        (
            vec![Provider, Provider, Provider, Dns, Controller, Broker, Sfu],
            vec![
                vec![1, 4, 5, 6, 7],
                vec![2, 4, 5, 6, 7],
                vec![3, 4, 5, 6, 7],
            ],
        )
    };
    Topology::new(
        kinds
            .into_iter()
            .enumerate()
            .map(|(i, kind)| Dependency {
                id: i as u8 + 1,
                kind,
            })
            .collect(),
        paths
            .into_iter()
            .enumerate()
            .map(|(i, dependencies)| Route {
                id: i as u8 + 1,
                dependencies,
            })
            .collect(),
    )
}
/// Fictitious topologies only. Dependency IDs do not identify actual providers.
pub fn demo() -> Result<serde_json::Value, ModelError> {
    use FailureKind::*;
    let all = [Provider, Dns, Controller, Broker, Sfu];
    let shared = fixture(true, false)?;
    let bootstrap = fixture(false, false)?;
    let independent = fixture(false, true)?;
    let base = Topology::new(
        independent.dependencies.clone(),
        vec![independent.routes[0].clone()],
    )?;
    let shared_alternative = Topology::new(
        independent.dependencies.clone(),
        vec![
            independent.routes[0].clone(),
            Route {
                id: 2,
                dependencies: vec![2, 3, 4],
            },
        ],
    )?;
    Ok(serde_json::json!({
        "scope": "fictitious_bounded_boolean_dependency_model",
        "semantics": "alternative_routes_OR_each_route_dependencies_AND",
        "three_bridges_one_provider": {
            "topology": shared, "provider_cuts": shared.provider_cuts()?,
            "provider_failure": shared.availability(&[1])?,
            "shared_failure": "all_three_bridge_routes_fail_when_provider_1_fails"
        },
        "distinct_providers_shared_bootstrap": {
            "topology": bootstrap, "provider_cuts": bootstrap.provider_cuts()?,
            "all_dependency_cuts": bootstrap.minimal_cuts(&all)?,
            "shared_dns_failure": bootstrap.availability(&[4])?
        },
        "independent_alternative": {
            "topology": independent, "provider_cuts": independent.provider_cuts()?,
            "all_dependency_cuts": independent.minimal_cuts(&all)?,
            "first_route_dns_failure": independent.availability(&[3])?
        },
        "same_dns_failure_when_adding_alternative": {
            "failed_dependencies": [3],
            "single_route": base.availability(&[3])?,
            "alternative_shares_bootstrap": shared_alternative.availability(&[3])?,
            "alternative_has_independent_bootstrap": independent.availability(&[3])?
        },
        "interpretation": "provider_diversity_does_not_remove_shared_bootstrap_cuts",
        "fleet_reliability_measured": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use FailureKind::*;
    #[test]
    fn shared_provider_cut() {
        let t = fixture(true, false).unwrap();
        assert_eq!(t.availability(&[]).unwrap().surviving_routes, vec![1, 2, 3]);
        assert_eq!(t.provider_cuts().unwrap(), vec![vec![1]]);
        assert!(!t.availability(&[1]).unwrap().available);
        assert_eq!(
            demo().unwrap()["three_bridges_one_provider"]["provider_failure"]["available"],
            false
        );
    }
    #[test]
    fn shared_bootstrap_cuts_distinct_providers() {
        let t = fixture(false, false).unwrap();
        assert_eq!(t.provider_cuts().unwrap(), vec![vec![1, 2, 3]]);
        assert_eq!(
            t.minimal_cuts(&[Provider, Dns, Controller, Broker, Sfu])
                .unwrap(),
            vec![vec![4], vec![5], vec![6], vec![7], vec![1, 2, 3]]
        );
        assert_eq!(t.availability(&[1]).unwrap().surviving_routes, vec![2, 3]);
        assert!(!t.availability(&[5]).unwrap().available);
    }
    #[test]
    fn fully_independent_alternative() {
        let t = fixture(false, true).unwrap();
        let base = Topology::new(t.dependencies.clone(), vec![t.routes[0].clone()]).unwrap();
        let shared = Topology::new(
            t.dependencies.clone(),
            vec![
                t.routes[0].clone(),
                Route {
                    id: 2,
                    dependencies: vec![2, 3, 4],
                },
            ],
        )
        .unwrap();
        assert!(!base.availability(&[3]).unwrap().available);
        assert!(!shared.availability(&[3]).unwrap().available);
        assert_eq!(t.availability(&[3]).unwrap().surviving_routes, vec![2]);
        assert!(!t.availability(&[3, 5]).unwrap().available);
        assert_eq!(t.provider_cuts().unwrap(), vec![vec![1, 2]]);
    }
    #[test]
    fn duplicates_and_bounded_invalid_graphs() {
        let nodes = vec![Dependency {
            id: 1,
            kind: Provider,
        }];
        let route = Route {
            id: 1,
            dependencies: vec![1],
        };
        for deps in [vec![], vec![1, 1], vec![2]] {
            assert_eq!(
                Topology::new(
                    nodes.clone(),
                    vec![Route {
                        id: 1,
                        dependencies: deps
                    }]
                )
                .unwrap_err(),
                ModelError::InvalidGraph
            );
        }
        assert_eq!(
            Topology::new(vec![nodes[0].clone(); 2], vec![route.clone()]).unwrap_err(),
            ModelError::InvalidGraph
        );
        assert_eq!(
            Topology::new(nodes.clone(), vec![route.clone(); 2]).unwrap_err(),
            ModelError::InvalidGraph
        );
        assert_eq!(
            Topology::new(nodes.clone(), vec![route.clone(); 17]).unwrap_err(),
            ModelError::Bounds
        );
        assert_eq!(
            Topology::new(vec![nodes[0].clone(); 17], vec![route.clone()]).unwrap_err(),
            ModelError::Bounds
        );
        let t = Topology::new(nodes, vec![route]).unwrap();
        for failed in [vec![1, 1], vec![2], vec![1; 17]] {
            assert_eq!(
                t.availability(&failed).unwrap_err(),
                ModelError::InvalidFailure
            );
        }
        let many = Topology::new(
            (1..=9)
                .map(|id| Dependency { id, kind: Provider })
                .collect(),
            vec![Route {
                id: 1,
                dependencies: (1..=9).collect(),
            }],
        )
        .unwrap();
        assert_eq!(many.provider_cuts().unwrap_err(), ModelError::CutBound);
        assert_eq!(
            t.minimal_cuts(&[Provider; 6]).unwrap_err(),
            ModelError::CutBound
        );
    }
    #[test]
    fn deterministic_cutset_stable_order() {
        let t = fixture(false, true).unwrap();
        let mut nodes = t.dependencies.clone();
        nodes.reverse();
        let mut routes = t.routes.clone();
        routes.reverse();
        for r in &mut routes {
            r.dependencies.reverse();
        }
        let reordered = Topology::new(nodes, routes).unwrap();
        let expected = vec![
            vec![1, 2],
            vec![1, 5],
            vec![1, 6],
            vec![2, 3],
            vec![2, 4],
            vec![3, 5],
            vec![3, 6],
            vec![4, 5],
            vec![4, 6],
        ];
        assert_eq!(
            t.minimal_cuts(&[Provider, Dns, Controller]).unwrap(),
            expected
        );
        assert_eq!(
            reordered
                .minimal_cuts(&[Controller, Provider, Dns])
                .unwrap(),
            expected
        );
        assert_eq!(
            reordered.availability(&[]).unwrap().surviving_routes,
            vec![1, 2]
        );
        assert!(t.minimal_cuts(&[]).unwrap().is_empty());
    }
}
