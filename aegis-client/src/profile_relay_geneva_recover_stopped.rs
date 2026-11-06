//! Independent administrative recovery of exact stopped selected owners.
//! The service-prestart cgroup path remains a separate command and contract.
use super::*;

// This is a retained-data check, not an authority constructor. Native role,
// complete INET/NETDEV observations and exact journal ownership are still needed.
fn blocked_state(policy: &PublicGuardPolicy, bytes: &[u8]) -> io::Result<OwnedGuardState> {
    let state: OwnedGuardState =
        serde_json::from_value(parse_unique_public_metadata(bytes)?).map_err(|_| refused())?;
    need(
        state.schema == "aegis_relay_geneva_guard_state_v1"
            && state.policy_sha256 == hex::encode(policy.digest()?)
            && state.table_present
            && state.active_binding.is_none(),
    )?;
    Ok(state)
}

#[cfg(target_os = "linux")]
pub(super) fn run() -> io::Result<String> {
    use aegis_core::relay_geneva::{
        linux::recovery::teardown as native, operation_deadline, teardown::DeviceBlockPolicy,
        teardown_storage as store,
    };
    operation_deadline::check()?;
    absent(&Path::new(DIR).join(TEARDOWN))?;
    let i = input()?;
    let request = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    let state_file = store::open_public(&Path::new(DIR).join(STATE), 65536)?;
    blocked_state(&i.profile.policy, &state_file.bytes)?;
    let device_file = store::open_public(Path::new(DEVICE_STATE), 65536)?;
    need(device_file.pin.sha256 == i.profile.policy.device_guard_state_sha256)?;
    let device_text = std::str::from_utf8(&device_file.bytes).map_err(|_| refused())?;
    let inet = DeviceBlockPolicy::from_state(device_text)?;
    let current = || -> io::Result<()> {
        operation_deadline::check()?;
        stable(&i)?;
        store::unchanged(&state_file)?;
        store::unchanged(&device_file)?;
        absent(&Path::new(DIR).join(INTENT))?;
        absent(&Path::new(DIR).join(TEARDOWN))?;
        crate::profile_relay_geneva_role::verify_installable(&i.profile.role)?;
        operation_deadline::check()
    };
    current()?;
    let lease = native::GuardLease::acquire()?;
    // Independent administrative recovery may not inherit the prestart role's
    // INET admission. An already complete original block is mandatory.
    let initial_inet = lease.verify_inet(&inet)?;
    let before = verify_current(&i, true)?;
    current()?;
    let receipts = native::recover_stopped(
        &lease,
        request,
        &i.endpoints,
        &i.profile.policy,
        &inet,
        &i.profile.role.executable_sha256,
        current,
    )?;
    native::quiet(request, &i.endpoints, &i.profile.role.executable_sha256)?;
    current()?;
    need(lease.verify_inet(&inet)? == initial_inet)?;
    let after = verify_current(&i, true)?;
    need(
        before.proof.table_sha256() == after.proof.table_sha256()
            && before.proof.policy_sha256() == after.proof.policy_sha256(),
    )?;
    native::quiet(request, &i.endpoints, &i.profile.role.executable_sha256)?;
    need(lease.verify_inet(&inet)? == initial_inet)?;
    current()?;
    let output = serde_json::to_string(&json!({
        "schema":"aegis_relay_geneva_stopped_recovery_command_v1",
        "source":source()?, "profile_sha256":hex::encode(i.profile_bytes_sha256),
        "policy_sha256":hex::encode(after.proof.policy_sha256()),
        "table_sha256":hex::encode(after.proof.table_sha256()),
        "original_inet_sha256":hex::encode(initial_inet), "owned_receipts":receipts,
        "original_inet_guard_armed_blocked":true,
        "complete_selected_kernel_readback_verified":true,
        "owned_native_owners_quiet":true,
        "physical_capture_verified":false, "installed_lifecycle_acceptance":false
    }))
    .map_err(|_| refused())?;
    operation_deadline::check()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::relay_geneva::{installed_guard::expected, RelayOuterGenevaSettings};
    fn fixture() -> (PublicGuardPolicy, RelayOuterGenevaSettings, OwnedGuardState) {
        let policy = PublicGuardPolicy {
            schema: "aegis_relay_geneva_installed_guard_v1".into(),
            source_commit: "a".repeat(40),
            interface: "client0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            socket_mark: 23153,
            relay_endpoints: vec!["192.0.2.3:24443".parse().unwrap()],
            device_guard_state_sha256: "b".repeat(64),
        };
        let request = RelayOuterGenevaSettings {
            strategy: "[IP:ttl:64]-drop-|".into(),
            interface: policy.interface.clone(),
            local_address: policy.local_address,
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            outbound_queue: 431,
            inbound_queue: 432,
            socket_mark: policy.socket_mark,
            max_duration_secs: 24,
        };
        let state = OwnedGuardState {
            schema: "aegis_relay_geneva_guard_state_v1".into(),
            policy_sha256: hex::encode(policy.digest().unwrap()),
            active_binding: None,
            table_present: true,
        };
        (policy, request, state)
    }
    #[test]
    fn exact_blocked_state_and_complete_real_policy_have_a_valid_pure_readback() {
        let (policy, request, state) = fixture();
        let bytes = serde_json::to_vec(&state).unwrap();
        let retained = blocked_state(&policy, &bytes).unwrap();
        let proof = installed_profile::verify_current(
            &policy,
            &retained,
            &expected(&policy, None).unwrap(),
            None,
            &policy.source_commit,
            &request,
            &policy.relay_endpoints,
        )
        .unwrap();
        assert_eq!(proof.policy_sha256(), policy.digest().unwrap());
        assert_eq!(serde_json::to_vec(&retained).unwrap(), bytes);
        // This pure schema/kernel fixture does not mint a native role or grant.
    }
    #[test]
    fn retained_state_refuses_pending_authority_missing_table_stale_policy_and_duplicates() {
        let (policy, _, state) = fixture();
        for index in 0..4 {
            let mut changed = state.clone();
            match index {
                0 => changed.table_present = false,
                1 => changed.policy_sha256 = "f".repeat(64),
                2 => changed.schema = "claimed_pass".into(),
                _ => {
                    changed.active_binding = Some(CurrentClientBinding {
                        boot_id: "00000000-0000-0000-0000-000000000001".into(),
                        invocation_id: "c".repeat(32),
                        cgroup_path: "/system.slice/aegis-client.service".into(),
                        cgroup_inode: 42,
                    })
                }
            }
            assert!(blocked_state(&policy, &serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let raw = serde_json::to_string(&state).unwrap();
        let duplicate = raw.replacen("{", "{\"table_present\":true,", 1);
        assert!(blocked_state(&policy, duplicate.as_bytes()).is_err());
    }
    #[test]
    fn blocked_metadata_cannot_authorize_foreign_source_or_partial_native_rules() {
        let (policy, request, state) = fixture();
        let retained = blocked_state(&policy, &serde_json::to_vec(&state).unwrap()).unwrap();
        let exact = expected(&policy, None).unwrap();
        assert!(installed_profile::verify_current(
            &policy,
            &retained,
            &exact,
            None,
            &"f".repeat(40),
            &request,
            &policy.relay_endpoints
        )
        .is_err());
        let mut partial = exact;
        partial["nftables"].as_array_mut().unwrap().pop();
        assert!(installed_profile::verify_current(
            &policy,
            &retained,
            &partial,
            None,
            &policy.source_commit,
            &request,
            &policy.relay_endpoints
        )
        .is_err());
    }
}
