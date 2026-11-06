//! Durable public guard transitions. An adapter persists intent BEFORE emitting
//! a kernel batch; only a fresh complete readback can commit active authority.
//! Both exact old/new tables remain recognizable after an interrupted command.
use super::{
    installed_guard::{
        transaction_text, verify_observation, CurrentClientBinding, PublicGuardPolicy,
    },
    RelayOuterGenevaSettings,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io, net::SocketAddrV4};

/// Administrative authorization is checked against the native driver's exact
/// observed table snapshot. A proof never permits a same-name replacement.
/// Later guard changes are terminal NFT events, not an untransformed fallback.
pub trait InstalledGuardAuthorization: Send + Sync {
    fn verify(
        &self,
        request: &RelayOuterGenevaSettings,
        endpoints: &[SocketAddrV4],
        actual_guard: &Value,
    ) -> io::Result<super::installed_guard::InstalledGuardProof>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedGuardState {
    pub schema: String,
    pub policy_sha256: String,
    pub active_binding: Option<CurrentClientBinding>,
    pub table_present: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardTransitionIntent {
    pub schema: String,
    pub policy_sha256: String,
    pub committed_base: OwnedGuardState,
    pub previous: OwnedGuardState,
    pub proposed_binding: Option<CurrentClientBinding>,
}
pub struct PreparedTransition {
    pub intent: GuardTransitionIntent,
    pub nft_script: String,
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "selected installed guard transition refused",
    )
}
fn need(v: bool) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(refused())
    }
}
fn state_valid(s: &OwnedGuardState, p: &PublicGuardPolicy) -> io::Result<()> {
    need(
        s.schema == "aegis_relay_geneva_guard_state_v1"
            && s.policy_sha256 == hex::encode(p.digest()?),
    )?;
    need(s.table_present || s.active_binding.is_none())?;
    super::installed_guard::expected(p, s.active_binding.as_ref())?;
    Ok(())
}

/// Read-only verification of the retained selected state against the complete
/// current kernel table and a separately attested current or stopped binding.
/// This does not prepare a transition, persist state, or authorize a new bind.
pub fn verify_current(
    policy: &PublicGuardPolicy,
    state: &OwnedGuardState,
    actual: &Value,
    current_binding: Option<&CurrentClientBinding>,
    source: &str,
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
) -> io::Result<super::installed_guard::InstalledGuardProof> {
    state_valid(state, policy)?;
    need(state.table_present && state.active_binding.as_ref() == current_binding)?;
    verify_observation(actual, policy, current_binding, source, request, endpoints)
}
fn observed_matches(
    actual: Option<&Value>,
    s: &OwnedGuardState,
    p: &PublicGuardPolicy,
    source: &str,
    r: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
) -> bool {
    match (actual, s.table_present) {
        (None, false) => true,
        (Some(v), true) => {
            verify_observation(v, p, s.active_binding.as_ref(), source, r, endpoints).is_ok()
        }
        _ => false,
    }
}
/// No root-owned state is invented from kernel output. An absent initial state
/// may only create a blocked table; initial bound admission is never permitted.
// Keep the independent trust context explicit at this administrative boundary;
// no argument is inferred from a pending record or observed kernel output.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    policy: &PublicGuardPolicy,
    state: Option<&OwnedGuardState>,
    pending: Option<&GuardTransitionIntent>,
    observed: Option<&Value>,
    proposed: Option<&CurrentClientBinding>,
    source: &str,
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
) -> io::Result<PreparedTransition> {
    policy.validate(source, request, endpoints)?;
    let empty = OwnedGuardState {
        schema: "aegis_relay_geneva_guard_state_v1".into(),
        policy_sha256: hex::encode(policy.digest()?),
        active_binding: None,
        table_present: false,
    };
    let current = state.unwrap_or(&empty);
    state_valid(current, policy)?;
    need(state.is_some() || proposed.is_none())?;
    let mut previous = current.clone();
    if let Some(intent) = pending {
        need(
            intent.schema == "aegis_relay_geneva_guard_transition_v1"
                && intent.policy_sha256 == hex::encode(policy.digest()?),
        )?;
        state_valid(&intent.previous, policy)?;
        state_valid(&intent.committed_base, policy)?;
        let after = OwnedGuardState {
            schema: empty.schema.clone(),
            policy_sha256: empty.policy_sha256.clone(),
            active_binding: intent.proposed_binding.clone(),
            table_present: true,
        };
        state_valid(&after, policy)?;
        // A crash can occur after committing the new state but before removing
        // intent, or while replacing a previous failed transition's intent.
        need(
            serde_json::to_value(current)? == serde_json::to_value(&intent.committed_base)?
                || serde_json::to_value(current)? == serde_json::to_value(&after)?,
        )?;
        if observed.is_none() {
            // Reboot can remove volatile kernel state while both durable state
            // and pending intent survive. Absence never grants a bound role;
            // create only a fresh restrictive table without a delete command.
            need(proposed.is_none())?;
            previous = empty.clone();
        } else if observed_matches(observed, &after, policy, source, request, endpoints) {
            previous = after;
        } else {
            need(observed_matches(
                observed,
                &intent.previous,
                policy,
                source,
                request,
                endpoints,
            ))?;
            previous = intent.previous.clone();
        }
    } else if observed.is_none() {
        need(proposed.is_none())?;
        previous = empty.clone();
    } else {
        need(observed_matches(
            observed, current, policy, source, request, endpoints,
        ))?;
    }
    super::installed_guard::expected(policy, proposed)?;
    let intent = GuardTransitionIntent {
        schema: "aegis_relay_geneva_guard_transition_v1".into(),
        policy_sha256: empty.policy_sha256.clone(),
        committed_base: current.clone(),
        previous,
        proposed_binding: proposed.cloned(),
    };
    let nft_script = transaction_text(policy, proposed, intent.previous.table_present)?;
    Ok(PreparedTransition { intent, nft_script })
}
/// Only after this result is durably written may the adapter remove pending
/// intent. No receipt alone establishes a current process/cgroup binding.
pub fn finish(
    policy: &PublicGuardPolicy,
    intent: &GuardTransitionIntent,
    observed: &Value,
    source: &str,
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
) -> io::Result<OwnedGuardState> {
    need(
        intent.schema == "aegis_relay_geneva_guard_transition_v1"
            && intent.policy_sha256 == hex::encode(policy.digest()?),
    )?;
    state_valid(&intent.previous, policy)?;
    state_valid(&intent.committed_base, policy)?;
    verify_observation(
        observed,
        policy,
        intent.proposed_binding.as_ref(),
        source,
        request,
        endpoints,
    )?;
    Ok(OwnedGuardState {
        schema: "aegis_relay_geneva_guard_state_v1".into(),
        policy_sha256: intent.policy_sha256.clone(),
        active_binding: intent.proposed_binding.clone(),
        table_present: true,
    })
}

#[cfg(test)]
mod tests {
    use super::super::installed_guard::expected;
    use super::*;
    fn fixture() -> (
        PublicGuardPolicy,
        RelayOuterGenevaSettings,
        Vec<SocketAddrV4>,
        CurrentClientBinding,
    ) {
        let p = PublicGuardPolicy {
            schema: "aegis_relay_geneva_installed_guard_v1".into(),
            source_commit: "a".repeat(40),
            interface: "client0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            socket_mark: 23153,
            relay_endpoints: vec!["192.0.2.3:24443".parse().unwrap()],
            device_guard_state_sha256: "b".repeat(64),
        };
        let r = RelayOuterGenevaSettings {
            strategy: "[IP:ttl:64]-drop-|".into(),
            interface: p.interface.clone(),
            local_address: p.local_address,
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            outbound_queue: 431,
            inbound_queue: 432,
            socket_mark: p.socket_mark,
            max_duration_secs: 24,
        };
        let b = CurrentClientBinding {
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            invocation_id: "c".repeat(32),
            cgroup_path: "/system.slice/aegis-client.service".into(),
            cgroup_inode: 42,
        };
        let e = p.relay_endpoints.clone();
        (p, r, e, b)
    }
    #[test]
    fn current_verification_requires_retained_state_current_binding_and_full_table() {
        let (p, r, e, b) = fixture();
        for binding in [None, Some(&b)] {
            let state = OwnedGuardState {
                schema: "aegis_relay_geneva_guard_state_v1".into(),
                policy_sha256: hex::encode(p.digest().unwrap()),
                active_binding: binding.cloned(),
                table_present: true,
            };
            let actual = expected(&p, binding).unwrap();
            let state_before = serde_json::to_vec(&state).unwrap();
            let actual_before = serde_json::to_vec(&actual).unwrap();
            let proof =
                verify_current(&p, &state, &actual, binding, &p.source_commit, &r, &e).unwrap();
            assert_eq!(proof.policy_sha256(), p.digest().unwrap());
            // Verification has no transition/persistence mutation, including
            // when the same caller observes a blocked or active table.
            assert_eq!(serde_json::to_vec(&state).unwrap(), state_before);
            assert_eq!(serde_json::to_vec(&actual).unwrap(), actual_before);
            let opposite = if binding.is_some() { None } else { Some(&b) };
            assert!(
                verify_current(&p, &state, &actual, opposite, &p.source_commit, &r, &e).is_err()
            );
            assert!(verify_current(
                &p,
                &state,
                &expected(&p, opposite).unwrap(),
                binding,
                &p.source_commit,
                &r,
                &e,
            )
            .is_err());
        }
    }

    #[test]
    fn current_verification_refuses_stale_policy_missing_table_and_foreign_source() {
        let (p, r, e, _) = fixture();
        let state = OwnedGuardState {
            schema: "aegis_relay_geneva_guard_state_v1".into(),
            policy_sha256: hex::encode(p.digest().unwrap()),
            active_binding: None,
            table_present: true,
        };
        let actual = expected(&p, None).unwrap();
        for index in 0..3 {
            let mut changed = state.clone();
            match index {
                0 => changed.policy_sha256 = "f".repeat(64),
                1 => changed.table_present = false,
                _ => changed.schema = "claimed_pass".into(),
            }
            assert!(verify_current(&p, &changed, &actual, None, &p.source_commit, &r, &e).is_err());
        }
        assert!(verify_current(&p, &state, &actual, None, &"f".repeat(40), &r, &e).is_err());
        let mut changed = actual.clone();
        changed["nftables"].as_array_mut().unwrap().pop();
        assert!(verify_current(&p, &state, &changed, None, &p.source_commit, &r, &e).is_err());
    }

    #[test]
    fn current_verification_refuses_replaced_boot_invocation_and_cgroup_identity() {
        let (p, r, e, b) = fixture();
        let state = OwnedGuardState {
            schema: "aegis_relay_geneva_guard_state_v1".into(),
            policy_sha256: hex::encode(p.digest().unwrap()),
            active_binding: Some(b.clone()),
            table_present: true,
        };
        let actual = expected(&p, Some(&b)).unwrap();
        for index in 0..4 {
            let mut changed = b.clone();
            match index {
                0 => changed.boot_id = "00000000-0000-0000-0000-000000000002".into(),
                1 => changed.invocation_id = "d".repeat(32),
                2 => changed.cgroup_path = "/system.slice/foreign.service".into(),
                _ => changed.cgroup_inode += 1,
            }
            assert!(verify_current(
                &p,
                &state,
                &actual,
                Some(&changed),
                &p.source_commit,
                &r,
                &e
            )
            .is_err());
        }
    }

    #[test]
    fn initial_create_must_be_blocked_and_exact_readback_committed() {
        let (p, r, e, b) = fixture();
        assert!(prepare(&p, None, None, None, Some(&b), &p.source_commit, &r, &e).is_err());
        let q = prepare(&p, None, None, None, None, &p.source_commit, &r, &e).unwrap();
        let blocked = expected(&p, None).unwrap();
        let state = finish(&p, &q.intent, &blocked, &p.source_commit, &r, &e).unwrap();
        assert!(state.table_present);
        assert!(state.active_binding.is_none());
        assert!(finish(
            &p,
            &q.intent,
            &expected(&p, Some(&b)).unwrap(),
            &p.source_commit,
            &r,
            &e
        )
        .is_err());
    }
    #[test]
    fn interrupted_bind_can_recognize_exact_old_or_new_and_withdraw_both() {
        let (p, r, e, b) = fixture();
        let blocked = expected(&p, None).unwrap();
        let q = prepare(&p, None, None, None, None, &p.source_commit, &r, &e).unwrap();
        let state = finish(&p, &q.intent, &blocked, &p.source_commit, &r, &e).unwrap();
        let bind = prepare(
            &p,
            Some(&state),
            None,
            Some(&blocked),
            Some(&b),
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        for observed in [blocked, expected(&p, Some(&b)).unwrap()] {
            let block = prepare(
                &p,
                Some(&state),
                Some(&bind.intent),
                Some(&observed),
                None,
                &p.source_commit,
                &r,
                &e,
            )
            .unwrap();
            assert!(block.intent.proposed_binding.is_none());
            assert!(block.nft_script.starts_with("delete table netdev"));
        }
    }
    #[test]
    fn second_interruption_retains_original_committed_base_until_verified_finish() {
        let (p, r, e, b) = fixture();
        let blocked = expected(&p, None).unwrap();
        let first = prepare(&p, None, None, None, None, &p.source_commit, &r, &e).unwrap();
        let committed = finish(&p, &first.intent, &blocked, &p.source_commit, &r, &e).unwrap();
        let bind = prepare(
            &p,
            Some(&committed),
            None,
            Some(&blocked),
            Some(&b),
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        let bound = expected(&p, Some(&b)).unwrap();
        // Kernel bind succeeded, but its state write did not. Then a block
        // attempt replaced intent and also died before either kernel/commit.
        let block = prepare(
            &p,
            Some(&committed),
            Some(&bind.intent),
            Some(&bound),
            None,
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        let again = prepare(
            &p,
            Some(&committed),
            Some(&block.intent),
            Some(&bound),
            None,
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        assert!(again.intent.previous.active_binding.is_some());
        assert!(again.intent.committed_base.active_binding.is_none());
        assert!(finish(&p, &again.intent, &bound, &p.source_commit, &r, &e).is_err());
        let ended = finish(&p, &again.intent, &blocked, &p.source_commit, &r, &e).unwrap();
        assert!(ended.active_binding.is_none());
        assert!(ended.table_present);
    }
    #[test]
    fn durable_state_after_reboot_can_only_create_fresh_block_without_adopting_binding() {
        let (p, r, e, binding) = fixture();
        let first = prepare(&p, None, None, None, None, &p.source_commit, &r, &e).unwrap();
        let blocked = expected(&p, None).unwrap();
        let committed = finish(&p, &first.intent, &blocked, &p.source_commit, &r, &e).unwrap();
        let bind = prepare(
            &p,
            Some(&committed),
            None,
            Some(&blocked),
            Some(&binding),
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        let active = finish(
            &p,
            &bind.intent,
            &expected(&p, Some(&binding)).unwrap(),
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        // Both durable blocked and bound state survive, volatile table does not.
        for state in [&committed, &active] {
            let q = prepare(&p, Some(state), None, None, None, &p.source_commit, &r, &e).unwrap();
            assert!(!q.intent.previous.table_present);
            assert!(q.intent.previous.active_binding.is_none());
            assert_eq!(
                serde_json::to_value(&q.intent.committed_base).unwrap(),
                serde_json::to_value(state).unwrap()
            );
            assert!(q.nft_script.starts_with("create table netdev"));
            assert!(!q.nft_script.contains("delete table"));
            assert!(prepare(
                &p,
                Some(state),
                None,
                None,
                Some(&binding),
                &p.source_commit,
                &r,
                &e
            )
            .is_err());
            assert!(finish(
                &p,
                &q.intent,
                &expected(&p, Some(&binding)).unwrap(),
                &p.source_commit,
                &r,
                &e
            )
            .is_err());
            assert!(finish(&p, &q.intent, &blocked, &p.source_commit, &r, &e)
                .unwrap()
                .active_binding
                .is_none());
        }
        // A valid interrupted prior bind is retained in history, never reused
        // as permission after absence. A malformed old intent still refuses.
        let q = prepare(
            &p,
            Some(&committed),
            Some(&bind.intent),
            None,
            None,
            &p.source_commit,
            &r,
            &e,
        )
        .unwrap();
        assert!(!q.intent.previous.table_present);
        let mut foreign = bind.intent;
        foreign.policy_sha256 = "f".repeat(64);
        assert!(prepare(
            &p,
            Some(&committed),
            Some(&foreign),
            None,
            None,
            &p.source_commit,
            &r,
            &e
        )
        .is_err());
    }

    #[test]
    fn unknown_matching_count_or_absent_recorded_table_cannot_be_adopted() {
        let (p, r, e, _) = fixture();
        let actual = expected(&p, None).unwrap();
        assert!(prepare(
            &p,
            None,
            None,
            Some(&actual),
            None,
            &p.source_commit,
            &r,
            &e
        )
        .is_err());
        let q = prepare(&p, None, None, None, None, &p.source_commit, &r, &e).unwrap();
        let state = finish(&p, &q.intent, &actual, &p.source_commit, &r, &e).unwrap();
        assert!(prepare(
            &p,
            Some(&state),
            None,
            None,
            Some(&fixture().3),
            &p.source_commit,
            &r,
            &e
        )
        .is_err());
        let mut foreign = actual;
        foreign["nftables"][2]["rule"]["expr"][0]["match"]["right"] = serde_json::json!(1);
        assert!(prepare(
            &p,
            Some(&state),
            None,
            Some(&foreign),
            None,
            &p.source_commit,
            &r,
            &e
        )
        .is_err());
    }
}
