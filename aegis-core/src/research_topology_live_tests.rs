use super::*;

fn policy() -> LiveDependencyPolicy {
    let graph = GraphInput {
        nodes: vec![0, 1, 2],
        edges: vec![[0, 1], [1, 2]],
    };
    LiveDependencyPolicy {
        a: graph.clone(),
        b: graph,
        dependency_pairs: vec![[0, 0], [1, 1], [2, 2]],
        endpoint_nodes: vec![0, 2],
        anchor_a: 1,
        anchor_b: 1,
        unavailable_a: Vec::new(),
        unavailable_b: Vec::new(),
    }
}

#[test]
fn declared_cascade_only_narrows_eligible_pool_and_preserves_order() {
    let p = policy();
    assert_eq!(p.admit(2, &[1, 0]).unwrap(), [1, 0]);
    assert_eq!(p.admit(2, &[1]).unwrap(), [1]);
    assert_eq!(p.admit(2, &[0]).unwrap(), [0]);
    assert!(p.admit(2, &[]).unwrap().is_empty());
}

#[test]
fn shared_dependency_outage_and_fixed_point_can_deny_entire_pool() {
    let mut p = policy();
    p.unavailable_b = vec![1];
    assert!(p.admit(2, &[0, 1]).unwrap().is_empty());
    p.unavailable_b = vec![0];
    assert_eq!(p.admit(2, &[0, 1]).unwrap(), [1]);
    // Direct exclusion and declared failure refer to the same A node without
    // counting it twice; malformed declarations still fail separately.
    p.unavailable_a = vec![0];
    assert_eq!(p.admit(2, &[1]).unwrap(), [1]);
}

#[test]
fn pin_order_changes_endpoint_mapping_and_no_unknown_arm_is_created() {
    let mut p = policy();
    p.unavailable_a = vec![0];
    assert_eq!(p.admit(2, &[0, 1]).unwrap(), [1]);
    p.endpoint_nodes.swap(0, 1);
    assert_eq!(p.admit(2, &[0, 1]).unwrap(), [0]);
    assert!(p.admit(2, &[2]).is_err());
    assert!(p.admit(2, &[0, 0]).is_err());
}

#[test]
fn malformed_graph_bijection_anchor_failures_mapping_and_bounds_refuse() {
    let p = policy();
    let mut cases = Vec::new();
    let mut q = p.clone();
    q.a.nodes.push(2);
    cases.push(q);
    let mut q = p.clone();
    q.a.edges.push([0, 9]);
    cases.push(q);
    let mut q = p.clone();
    q.dependency_pairs[1][1] = 0;
    cases.push(q);
    let mut q = p.clone();
    q.anchor_a = 9;
    cases.push(q);
    let mut q = p.clone();
    q.anchor_b = 9;
    cases.push(q);
    let mut q = p.clone();
    q.endpoint_nodes[1] = 0;
    cases.push(q);
    let mut q = p.clone();
    q.endpoint_nodes[1] = 9;
    cases.push(q);
    let mut q = p.clone();
    q.unavailable_a = vec![0, 0];
    cases.push(q);
    let mut q = p.clone();
    q.unavailable_b = vec![9];
    cases.push(q);
    let mut q = p.clone();
    q.b.nodes = (0..33).collect();
    cases.push(q);
    let mut q = p.clone();
    q.a.edges = vec![[0, 1]; 129];
    cases.push(q);
    for q in cases {
        assert!(q.validate(2).is_err());
    }
    assert!(p.validate(1).is_err());
    assert!(p.validate(17).is_err());
    assert!(p.validate(3).is_err());
}

#[test]
fn typed_public_policy_roundtrip_and_unknown_nested_keys_refuse() {
    let p = policy();
    let bytes = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        serde_json::from_slice::<LiveDependencyPolicy>(&bytes).unwrap(),
        p
    );
    let mut value = serde_json::to_value(&p).unwrap();
    value["network_measured"] = serde_json::json!(true);
    assert!(serde_json::from_value::<LiveDependencyPolicy>(value).is_err());
    let mut value = serde_json::to_value(&p).unwrap();
    value["a"]["discover"] = serde_json::json!(true);
    assert!(serde_json::from_value::<LiveDependencyPolicy>(value).is_err());
}
