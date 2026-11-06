use super::*;

fn graph(n: u32, edges: &[[u32; 2]]) -> Graph {
    Graph::new(GraphInput {
        nodes: (0..n).collect(),
        edges: edges.to_vec(),
    })
    .unwrap()
}
fn pairs(n: u32) -> Vec<[u32; 2]> {
    (0..n).map(|i| [i, i]).collect()
}
fn path(n: u32) -> Graph {
    graph(n, &(1..n).map(|i| [i - 1, i]).collect::<Vec<_>>())
}

#[test]
fn canonical_ids_edges_and_bad_graph_refusals() {
    let x = Graph::new(GraphInput {
        nodes: vec![9, 3, 7],
        edges: vec![[9, 7], [3, 7]],
    })
    .unwrap();
    assert_eq!(x.nodes(), &[3, 7, 9]);
    assert_eq!(x.input().edges, vec![[3, 7], [7, 9]]);
    for input in [
        GraphInput {
            nodes: vec![],
            edges: vec![],
        },
        GraphInput {
            nodes: vec![1, 1],
            edges: vec![],
        },
        GraphInput {
            nodes: vec![1],
            edges: vec![[1, 1]],
        },
        GraphInput {
            nodes: vec![1, 2],
            edges: vec![[1, 3]],
        },
        GraphInput {
            nodes: vec![1, 2],
            edges: vec![[1, 2], [2, 1]],
        },
    ] {
        assert!(Graph::new(input).is_err());
    }
    assert!(Graph::new(GraphInput {
        nodes: (0..129).collect(),
        edges: vec![]
    })
    .is_err());
    assert!(Graph::new(GraphInput {
        nodes: vec![1],
        edges: vec![[1, 1]; MAX_EDGES + 1]
    })
    .is_err());
}

#[test]
fn path_metrics_include_reachability_and_original_efficiency_denominator() {
    let g = path(3);
    let m = g.measure(&[]).unwrap();
    assert_eq!(m.reachable_ordered_pairs, 6);
    assert_eq!(m.mean_reachable_distance, Some(4.0 / 3.0));
    assert!((m.global_efficiency_original_denominator - 5.0 / 6.0).abs() < 1e-14);
    let m = g.measure(&[1]).unwrap();
    assert_eq!(m.largest_component, vec![0]);
    assert_eq!(m.component_sizes, vec![1, 1]);
    assert_eq!(m.mean_nonlargest_component_size, Some(1.0));
    assert_eq!(m.mean_reachable_distance, None);
    assert_eq!(m.global_efficiency_original_denominator, 0.0);
    assert_eq!(m.largest_fraction_of_original, 1.0 / 3.0);
    assert!(g.measure(&[1, 1]).is_err());
    assert!(g.measure(&[8]).is_err());
}

#[test]
fn complete_singleton_and_empty_survivor_conventions() {
    let g = erdos_renyi(6, 1, 1, 99).unwrap();
    let m = g.measure(&[0, 1]).unwrap();
    assert_eq!(m.global_efficiency_original_denominator, 12.0 / 30.0);
    assert_eq!(m.mean_reachable_distance, Some(1.0));
    assert_eq!(
        g.measure(&(0..6).collect::<Vec<_>>())
            .unwrap()
            .component_sizes,
        Vec::<usize>::new()
    );
    let m = graph(1, &[]).measure(&[]).unwrap();
    assert_eq!(m.largest_component, vec![0]);
    assert_eq!(m.global_efficiency_original_denominator, 0.0);
    assert_eq!(m.mean_reachable_distance, None);
}

#[test]
fn star_target_attack_has_causal_damage_and_random_can_remove_leaf() {
    let g = graph(8, &(1..8).map(|i| [0, i]).collect::<Vec<_>>());
    let targeted = attack(&g, AttackMode::InitialDegree, 1, 0).unwrap();
    assert_eq!(targeted.steps[1].removed, Some(0));
    assert_eq!(targeted.steps[1].metrics.component_sizes, vec![1; 7]);
    let leaf = (0..100)
        .map(|seed| attack(&g, AttackMode::Random, 1, seed).unwrap())
        .find(|r| r.steps[1].removed != Some(0))
        .unwrap();
    assert_eq!(leaf.steps[1].metrics.largest_component.len(), 7);
    assert!(
        leaf.steps[1].metrics.global_efficiency_original_denominator
            > targeted.steps[1]
                .metrics
                .global_efficiency_original_denominator
    );
}

#[test]
fn degree_policies_are_distinct_with_stable_id_ties() {
    // Original degrees: 0=4,1=3,2=2,3=2,4=1,5=2.
    // After removing0, vertex1 loses one edge and ties vertex5 at2;
    // after removing1, adaptive ties3 and5 at1, selecting3, while the
    // initial degree policy still selects2, now isolated.
    let g = graph(6, &[[0, 1], [0, 2], [0, 3], [0, 4], [1, 2], [1, 5], [3, 5]]);
    let original = attack(&g, AttackMode::InitialDegree, 3, 0).unwrap();
    let adaptive = attack(&g, AttackMode::AdaptiveDegree, 3, 0).unwrap();
    assert_eq!(
        original
            .steps
            .iter()
            .filter_map(|s| s.removed)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        adaptive
            .steps
            .iter()
            .filter_map(|s| s.removed)
            .collect::<Vec<_>>(),
        vec![0, 1, 3]
    );
    assert!(attack(&g, AttackMode::Random, 7, 1).is_err());
}

#[test]
fn seeded_permutation_is_repeatable_complete_without_replacement() {
    let g = path(12);
    let a = attack(&g, AttackMode::Random, 12, 123456).unwrap();
    let b = attack(&g, AttackMode::Random, 12, 123456).unwrap();
    assert_eq!(a, b);
    let ids: BTreeSet<_> = a.steps.iter().filter_map(|s| s.removed).collect();
    assert_eq!(ids, (0..12).collect());
    assert_ne!(
        a.steps.iter().filter_map(|s| s.removed).collect::<Vec<_>>(),
        attack(&g, AttackMode::Random, 12, 123457)
            .unwrap()
            .steps
            .iter()
            .filter_map(|s| s.removed)
            .collect::<Vec<_>>()
    );
    assert!(a
        .steps
        .windows(2)
        .all(|s| s[1].metrics.surviving_nodes + 1 == s[0].metrics.surviving_nodes));
}

#[test]
fn generator_probability_extremes_and_exact_attachment_edge_count() {
    assert!(erdos_renyi(7, 0, 10, 1).unwrap().input().edges.is_empty());
    assert_eq!(erdos_renyi(7, 10, 10, 1).unwrap().input().edges.len(), 21);
    assert!(erdos_renyi(128, 1, 1, 1).is_err()); // 8128 > explicit4096 budget.
    for (n, num, den) in [
        (0, 1, 1),
        (129, 1, 1),
        (2, 1, 0),
        (2, 2, 1),
        (2, 1, 1_000_001),
    ] {
        assert!(erdos_renyi(n, num, den, 0).is_err());
    }
    for m in 1..5 {
        let g = preferential_attachment(32, m, 55).unwrap();
        assert_eq!(g.input().edges.len(), m * (m + 1) / 2 + (32 - m - 1) * m);
        assert_eq!(g.measure(&[]).unwrap().largest_component.len(), 32);
    }
    assert!(preferential_attachment(5, 0, 0).is_err());
    assert!(preferential_attachment(5, 5, 0).is_err());
    assert_eq!(
        preferential_attachment(20, 2, 123).unwrap().input().edges,
        preferential_attachment(20, 2, 123).unwrap().input().edges
    );
    assert_eq!(
        erdos_renyi(20, 1, 5, 123).unwrap().input().edges,
        erdos_renyi(20, 1, 5, 123).unwrap().input().edges
    );
}

#[test]
fn splitmix64_fixed_reference_sequence() {
    let mut r = Seeded(0);
    assert_eq!(r.next(), 0xe220a8397b1dcdaf);
    assert_eq!(r.next(), 0x6e789e6aa1b965f4);
    assert!(r.below(0).is_err());
    assert_eq!(r.below(1).unwrap(), 0);
}

#[test]
fn dependency_requires_complete_explicit_bijection_and_known_ids() {
    let a = path(3);
    let b = path(3);
    for p in [
        vec![],
        vec![[0, 0], [1, 1]],
        vec![[0, 0], [1, 0], [2, 2]],
        vec![[0, 0], [0, 1], [2, 2]],
        vec![[0, 0], [1, 1], [2, 9]],
    ] {
        assert!(Interdependent::new(a.clone(), b.clone(), &p).is_err());
    }
    assert!(Interdependent::new(a.clone(), path(4), &pairs(3)).is_err());
    let b = Graph::new(GraphInput {
        nodes: vec![10, 20, 30],
        edges: vec![[10, 20], [20, 30]],
    })
    .unwrap();
    let s = Interdependent::new(a, b, &[[0, 30], [1, 20], [2, 10]]).unwrap();
    let r = s.cascade(&[0], &[]).unwrap();
    assert_eq!(r.initial_b, vec![10, 20]);
    assert_eq!(r.final_b.largest_component, vec![10, 20]);
}

#[test]
fn actual_alternating_cascade_exceeds_one_connectivity_pass() {
    let a = path(6);
    let b = graph(6, &[[0, 2], [2, 4], [4, 1], [1, 3], [3, 5]]);
    assert_eq!(a.measure(&[2]).unwrap().largest_component.len(), 3);
    assert_eq!(b.measure(&[2]).unwrap().largest_component.len(), 4);
    let r = Interdependent::new(a, b, &pairs(6))
        .unwrap()
        .cascade(&[2], &[])
        .unwrap();
    assert_eq!(r.initial_a, vec![0, 1, 3, 4, 5]);
    assert_eq!(r.stages[0].removed_by_connectivity, vec![0, 1]);
    assert_eq!(r.stages[0].removed_by_dependency, vec![0, 1]);
    assert_eq!(r.stages[1].removed_by_connectivity, vec![4]);
    assert_eq!(r.stages[1].removed_by_dependency, vec![4]);
    assert_eq!(r.stages[2].removed_by_connectivity, vec![5]);
    assert_eq!(r.stages[2].removed_by_dependency, vec![5]);
    assert_eq!(r.final_a.largest_component, vec![3]);
    assert_eq!(r.final_b.largest_component, vec![3]);
    assert!(r.fixed_point);
    // Singleton is preserved; no invented finite cutoff labels it empty.
    assert_eq!(r.final_a.largest_fraction_of_original, 1.0 / 6.0);
}

#[test]
fn no_failure_and_complete_failure_fixed_points() {
    let s = Interdependent::new(path(8), path(8), &pairs(8)).unwrap();
    let r = s.cascade(&[], &[]).unwrap();
    assert_eq!(r.stages.len(), 2);
    assert_eq!(r.final_a.surviving_nodes, 8);
    let r = s.cascade(&(0..8).collect::<Vec<_>>(), &[]).unwrap();
    assert_eq!(r.stages.len(), 2);
    assert_eq!(r.final_a.surviving_nodes, 0);
    assert_eq!(r.final_b.surviving_nodes, 0);
    assert!(s.cascade(&[99], &[]).is_err());
    assert!(s.cascade(&[], &[1, 1]).is_err());
}

#[test]
fn finite_largest_component_tie_is_canonical_not_input_order() {
    let g = Graph::new(GraphInput {
        nodes: vec![40, 30, 20, 10],
        edges: vec![[30, 40], [20, 10]],
    })
    .unwrap();
    let s = Interdependent::new(g.clone(), g, &[[40, 40], [30, 30], [20, 20], [10, 10]]).unwrap();
    assert_eq!(
        s.cascade(&[], &[]).unwrap().final_a.largest_component,
        vec![10, 20]
    );
}

#[test]
fn generated_cascades_monotone_bounded_and_connected_at_fixed_point() {
    for seed in 0..64 {
        let s = Interdependent::new(
            erdos_renyi(12, 1, 4, seed).unwrap(),
            erdos_renyi(12, 1, 4, seed + 100).unwrap(),
            &pairs(12),
        )
        .unwrap();
        let r = s.cascade(&[seed as u32 % 12], &[]).unwrap();
        assert!(r.stages.len() <= 26);
        let mut previous = (r.initial_a.clone(), r.initial_b.clone());
        for stage in &r.stages {
            assert!(stage.surviving_a.iter().all(|v| previous.0.contains(v)));
            assert!(stage.surviving_b.iter().all(|v| previous.1.contains(v)));
            assert_eq!(stage.surviving_a, stage.surviving_b);
            previous = (stage.surviving_a.clone(), stage.surviving_b.clone());
        }
        assert!(r.final_a.component_sizes.len() <= 1);
        assert!(r.final_b.component_sizes.len() <= 1);
        assert!(r.fixed_point);
    }
}

fn request() -> Request {
    Request {
        schema: "aegis_topology_papers_v1".into(),
        provenance: Provenance::Synthetic {
            label: "cascade-control".into(),
        },
        a: path(6).input(),
        b: graph(6, &[[0, 2], [2, 4], [4, 1], [1, 3], [3, 5]]).input(),
        dependency_pairs: pairs(6),
        failed_a: vec![],
        failed_b: vec![],
        common_causes: vec![CommonCause {
            id: 17,
            failed_a: vec![2],
            failed_b: vec![],
        }],
        attack_removals: 2,
        seed: 27,
    }
}

#[test]
fn explicit_common_cause_causes_cascade_without_provider_inference() {
    let r = analyze(request()).unwrap();
    assert_eq!(r.initial_cascade.final_a.surviving_nodes, 6);
    assert_eq!(r.common_cause_cascades[&17].final_a.surviving_nodes, 1);
    assert!(!r.evidence_authenticated && !r.target_network_measured && !r.beta_exit);
    assert_eq!(r.attacks.len(), 3);
    let mut q = request();
    q.provenance = Provenance::ObservedInput {
        evidence_sha256: "ab".repeat(32),
    };
    let r = analyze(q).unwrap();
    assert!(!r.evidence_authenticated && !r.target_network_measured);
}

#[test]
fn malformed_request_cause_provenance_and_json_refusals() {
    let mut q = request();
    q.schema = "unknown".into();
    assert!(analyze(q).is_err());
    let mut q = request();
    q.common_causes.push(q.common_causes[0].clone());
    assert!(analyze(q).is_err());
    let mut q = request();
    q.common_causes[0].failed_a.clear();
    assert!(analyze(q).is_err());
    let mut q = request();
    q.common_causes[0].failed_b = vec![99];
    assert!(analyze(q).is_err());
    let mut q = request();
    q.common_causes = vec![
        CommonCause {
            id: 1,
            failed_a: vec![1],
            failed_b: vec![]
        };
        17
    ];
    assert!(analyze(q).is_err());
    let mut q = request();
    q.provenance = Provenance::ObservedInput {
        evidence_sha256: "AB".repeat(32),
    };
    assert!(analyze(q).is_err());
    let mut q = request();
    q.provenance = Provenance::Synthetic {
        label: "user secret text".into(),
    };
    assert!(analyze(q).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Request>(value).is_err());
    let round: Request = serde_json::from_value(serde_json::to_value(request()).unwrap()).unwrap();
    assert!(analyze(round).is_ok());
}
