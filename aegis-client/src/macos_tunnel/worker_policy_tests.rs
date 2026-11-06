//! Renderer/receipt/phase tests. Numeric identities are syntax fixtures, never
//! fake VerifiedAccount values or claims of native socket ownership/PF proof.
use super::*;
fn sample() -> WorkerReceipt {
    WorkerReceipt {
        account: "_aegis_fixture".into(),
        uid: 50123,
        gid: 50124,
        phase: Phase::BootstrapAuthority,
        binding: None,
        exit_confirmed: false,
        authority: vec![Pin {
            endpoint: "192.0.2.10:9443".parse().unwrap(),
            interface: "en0".into(),
            gateway: "192.0.2.1".into(),
        }],
        relay: vec![Pin {
            endpoint: "[2001:db8::20]:8443".parse().unwrap(),
            interface: "en1".into(),
            gateway: "fe80::1%en1".into(),
        }],
    }
}
#[test]
fn bootstrap_render_is_exact_uid_tcp_authority_only_in_both_directions() {
    let text = rules("utun12", &sample()).unwrap();
    assert!(text.contains("pass out quick on en0 inet proto tcp from any to 192.0.2.10 port 9443 user = 50123 flags any no state\n"));
    assert!(text.contains("pass in quick on en0 inet proto tcp from 192.0.2.10 port 9443 to any user = 50123 flags any no state\n"));
    assert!(!text.contains("2001:db8::20"));
    assert!(!text.contains("utun12"));
    assert!(!text.contains("udp"));
    assert!(!text.contains("user root"));
    assert!(!text.contains("user nobody"));
    assert!(text.ends_with("block drop quick all\n"));
    assert!(text
        .lines()
        .filter(|l| l.starts_with("pass "))
        .all(|l| l.ends_with("no state")));
}
#[test]
fn relay_render_replaces_authority_before_capture_and_never_unions_pins() {
    let mut receipt = sample();
    receipt.phase = Phase::RelayEgress;
    receipt.binding = Some(WorkerBinding {
        pid: 1234,
        generation: "0".repeat(32),
    });
    let text = rules("utun12", &receipt).unwrap();
    assert!(!text.contains("192.0.2.10"));
    assert!(!text.contains("utun12"));
    assert!(text.contains("pass out quick on en1 inet6 proto tcp from any to 2001:db8::20 port 8443 user = 50123 flags any no state\n"));
    assert!(text.contains("pass in quick on en1 inet6 proto tcp from 2001:db8::20 port 8443 to any user = 50123 flags any no state\n"));
    receipt.phase = Phase::CaptureActive;
    let capture = rules("utun12", &receipt).unwrap();
    assert_eq!(
        capture.lines().nth(1),
        Some("pass quick on utun12 all no state")
    );
    assert!(!capture.contains("192.0.2.10"));
    receipt.phase = Phase::RetainedGuard;
    let closed = rules("utun12", &receipt).unwrap();
    assert!(!closed.contains("proto tcp"));
    assert!(!closed.contains("utun12"));
    assert!(closed.starts_with("pass quick on lo0 all no state\n"));
}
#[test]
fn all_pass_rules_remain_stateless_in_all_phases_and_final_block_is_bilateral() {
    for phase in [
        Phase::BootstrapAuthority,
        Phase::RelayEgress,
        Phase::CaptureActive,
        Phase::RetainedGuard,
    ] {
        let mut receipt = sample();
        receipt.phase = phase;
        if matches!(phase, Phase::RelayEgress | Phase::CaptureActive) {
            receipt.binding = Some(WorkerBinding {
                pid: 1234,
                generation: "0".repeat(32),
            });
        }
        let text = rules("utun12", &receipt).unwrap();
        assert!(text
            .lines()
            .filter(|l| l.starts_with("pass "))
            .all(|l| l.ends_with("no state")));
        assert!(!text.contains("keep state"));
        assert!(!text.contains("block drop out"));
        for line in text.lines().filter(|l| l.contains("proto tcp")) {
            assert!(line.contains("user = 50123 flags any no state"));
            assert!(line.contains("port 9443") || line.contains("port 8443"));
        }
    }
}
#[test]
fn phase_machine_cannot_skip_authentication_or_reopen_a_retained_guard() {
    assert!(phase_allowed(Phase::BootstrapAuthority, Phase::RelayEgress));
    assert!(phase_allowed(Phase::RelayEgress, Phase::CaptureActive));
    assert!(!phase_allowed(
        Phase::BootstrapAuthority,
        Phase::CaptureActive
    ));
    assert!(!phase_allowed(
        Phase::CaptureActive,
        Phase::BootstrapAuthority
    ));
    assert!(!phase_allowed(Phase::CaptureActive, Phase::RelayEgress));
    assert!(!phase_allowed(Phase::RetainedGuard, Phase::RelayEgress));
    for phase in [
        Phase::BootstrapAuthority,
        Phase::RelayEgress,
        Phase::CaptureActive,
        Phase::RetainedGuard,
    ] {
        assert!(phase_allowed(phase, Phase::RetainedGuard));
    }
}
#[test]
fn unknown_or_missing_phase_and_unknown_receipt_fields_are_refused() {
    let value = serde_json::to_value(sample()).unwrap();
    let mut unknown = value.clone();
    unknown["phase"] = "declared_ready".into();
    assert!(serde_json::from_value::<WorkerReceipt>(unknown).is_err());
    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("phase");
    assert!(serde_json::from_value::<WorkerReceipt>(missing).is_err());
    let mut extra = value;
    extra["all_process_pins"] = true.into();
    assert!(serde_json::from_value::<WorkerReceipt>(extra).is_err());
}
#[test]
fn generic_unknown_identity_and_unbounded_duplicate_or_injected_pins_refuse() {
    for id in [0, 65534, u32::MAX - 1, u32::MAX] {
        let mut receipt = sample();
        receipt.uid = id;
        assert!(rules("utun12", &receipt).is_err());
        receipt = sample();
        receipt.gid = id;
        assert!(receipt.validate().is_err());
    }
    for name in ["", "root", "nobody", "_aegis_", "_aegis_good\npass all"] {
        let mut receipt = sample();
        receipt.account = name.into();
        assert!(receipt.validate().is_err());
    }
    for interface in [
        "utun0",
        "lo0",
        "bridge0",
        "ipsec0",
        "tap0",
        "en0\npass all",
        "-e",
        "",
        "en01234567890123456",
    ] {
        let mut receipt = sample();
        receipt.authority[0].interface = interface.into();
        assert!(receipt.validate().is_err());
    }
    for endpoint in [
        "127.0.0.1:443",
        "0.0.0.0:443",
        "192.0.2.10:0",
        "224.0.0.1:443",
        "255.255.255.255:443",
        "[::1]:443",
        "[ff02::1]:443",
    ] {
        let mut receipt = sample();
        receipt.authority[0].endpoint = endpoint.parse().unwrap();
        assert!(receipt.validate().is_err());
    }
    let mut receipt = sample();
    receipt.authority.push(receipt.authority[0].clone());
    assert!(receipt.validate().is_err());
    receipt = sample();
    receipt.authority = vec![];
    assert!(receipt.validate().is_err());
    receipt = sample();
    receipt.authority = vec![receipt.authority[0].clone(); MAX_PINS + 1];
    assert!(receipt.validate().is_err());
    assert!(rules("utun1\npass all", &sample()).is_err());
}
#[test]
fn authority_and_relay_same_address_cannot_disagree_on_physical_route() {
    let mut receipt = sample();
    receipt.relay[0].endpoint = "192.0.2.10:8443".parse().unwrap();
    assert!(receipt.validate().is_err());
    receipt.relay[0].interface = "en0".into();
    receipt.relay[0].gateway = "192.0.2.1".into();
    assert!(receipt.validate().is_ok());
    receipt.relay[0].gateway = "192.0.2.1%en1".into();
    assert!(receipt.validate().is_err());
}
#[test]
fn active_runtime_guard_requires_first_quick_anchor_and_known_stock_root() {
    for guard in [
        "anchor \"aegis.utun\" quick all",
        "anchor \"aegis.utun\" all quick",
    ] {
        assert!(active_root(&format!("scrub-anchor \"com.apple/*\" all fragment reassemble\n{guard}\nanchor \"com.apple/*\" all\n")));
    }
    assert!(!active_root(""));
    assert!(!active_root(
        "anchor \"aegis.utun\" all\nanchor \"com.apple/*\" all\n"
    ));
    assert!(!active_root(
        "anchor \"com.apple/*\" all\nanchor \"aegis.utun\" quick all\n"
    ));
    assert!(!active_root(
        "anchor \"aegis.utun\" quick all\npass in all keep state\nanchor \"com.apple/*\" all\n"
    ));
    assert!(!active_root("anchor \"aegis.utun\" quick all\n"));
}
#[test]
fn owned_foreign_or_changed_phase_receipts_refuse_before_lock_or_commands() {
    let owner = "0123456789abcdef0123456789abcdef";
    let journal = Journal {
        schema: "aegis_macos_utun_vm_v1".into(),
        supervisor_owner: Some(owner.into()),
        interface: "utun12".into(),
        service: "Ethernet".into(),
        dns: vec![],
        pf_sha256: "0".repeat(64),
        exclusions: vec![],
        physical_default: "192.0.2.1|en0".into(),
        socks_enabled: false,
        worker: Some(sample()),
    };
    let policy = WorkerPolicy { journal };
    // This mismatched owner returns before JOURNAL, LOCK or any native command.
    assert_eq!(
        policy
            .owned("fedcba9876543210fedcba9876543210")
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn relay_and_capture_receipts_require_bound_worker_generation() {
    for phase in [Phase::RelayEgress, Phase::CaptureActive] {
        let mut receipt = sample();
        receipt.phase = phase;
        assert!(receipt.validate().is_err());
        receipt.binding = Some(WorkerBinding {
            pid: 1234,
            generation: "0".repeat(32),
        });
        assert!(receipt.validate().is_ok());
        receipt.binding.as_mut().unwrap().pid = 0;
        assert!(receipt.validate().is_err());
        receipt.binding.as_mut().unwrap().pid = 1234;
        receipt.binding.as_mut().unwrap().generation = "declared-ready".into();
        assert!(receipt.validate().is_err());
    }
    let mut bootstrap = sample();
    bootstrap.binding = Some(WorkerBinding {
        pid: 1234,
        generation: "0".repeat(32),
    });
    assert!(bootstrap.validate().is_ok());
    assert!(!bootstrap.rollback_admitted());
}

#[test]
fn recursive_translation_and_normalization_require_empty_known_apple_anchors() {
    assert!(empty_apple_anchors("", true));
    assert!(empty_apple_anchors(
        "nat-anchor \"com.apple/*\" all {\n}\nrdr-anchor \"com.apple/*\" all\n",
        true
    ));
    assert!(empty_apple_anchors("scrub-anchor \"com.apple/*\" all fragment reassemble {\n}\nanchor \"com.apple/100.internet/*\" all\n",false));
    for source in [
        "nat on en0 from any to any -> (en0)",
        "rdr pass on en0 proto tcp to any port 443 -> 127.0.0.1 port 8443",
        "binat on en0 from 192.0.2.1 to any -> 198.51.100.1",
        "nat-anchor \"foreign/*\" all",
        "nat-anchor \"com.apple/*\" all {\n",
        "}",
    ] {
        assert!(!empty_apple_anchors(source, true));
    }
    for source in [
        "scrub all reassemble tcp",
        "scrub-anchor \"com.apple/*\" all reassemble tcp",
        "pass in all keep state",
        "anchor \"foreign/*\" all",
        "scrub-anchor \"com.apple/*\" all no-df",
    ] {
        assert!(!empty_apple_anchors(source, false));
    }
}
fn journal() -> Journal {
    Journal {
        schema: "aegis_macos_utun_vm_v1".into(),
        supervisor_owner: Some("0123456789abcdef0123456789abcdef".into()),
        interface: "utun12".into(),
        service: "Ethernet".into(),
        dns: vec![],
        pf_sha256: "0".repeat(64),
        exclusions: vec![],
        physical_default: "192.0.2.1|en0".into(),
        socks_enabled: false,
        worker: Some({
            let mut worker = sample();
            worker.binding = binding();
            worker
        }),
    }
}
#[test]
fn owner_and_all_receipt_fields_must_match_before_mutation_lock() {
    let cached = journal();
    let owner = cached.supervisor_owner.as_deref().unwrap();
    assert!(require_current_receipt(&cached, &cached, owner).is_ok());
    let mut other = cached.clone();
    other.worker.as_mut().unwrap().phase = Phase::RetainedGuard;
    assert!(require_current_receipt(&cached, &other, owner).is_err());
    other = cached.clone();
    other.dns = vec!["192.0.2.53".into()];
    assert!(require_current_receipt(&cached, &other, owner).is_err());
    other = cached.clone();
    other.socks_enabled = true;
    assert!(require_current_receipt(&cached, &other, owner).is_err());
    other = cached.clone();
    other.exclusions.push(Exclusion {
        ip: "192.0.2.10".parse().unwrap(),
        gateway: "192.0.2.1".into(),
        created: true,
    });
    assert!(require_current_receipt(&cached, &other, owner).is_err());
    other = cached.clone();
    other.supervisor_owner = None;
    assert!(require_current_receipt(&cached, &other, owner).is_err());
}
#[derive(Default)]
struct PublicationFixture {
    loads: Vec<String>,
    confirms: usize,
    expected_confirmations: Vec<String>,
    stored: Vec<Phase>,
    fail_confirmation_after_load: bool,
    fail_first_store: bool,
    fail_first_load: bool,
    fail_retained_store: bool,
    fail_restriction: bool,
}
impl PhaseBackend for PublicationFixture {
    fn confirm(&mut self, expected_rules: &str) -> io::Result<()> {
        self.confirms += 1;
        self.expected_confirmations.push(expected_rules.into());
        if self.fail_confirmation_after_load && self.loads.len() == 1 {
            Err(denied())
        } else {
            Ok(())
        }
    }
    fn dry_run(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn load(&mut self, rules: &str) -> io::Result<()> {
        self.loads.push(rules.into());
        if self.fail_first_load {
            self.fail_first_load = false;
            return Err(denied());
        }
        if self.fail_restriction && !rules.contains("proto tcp") {
            Err(denied())
        } else {
            Ok(())
        }
    }
    fn persist(&mut self, journal: &Journal) -> io::Result<()> {
        if self.fail_retained_store
            && journal.worker.as_ref().unwrap().phase == Phase::RetainedGuard
        {
            return Err(denied());
        }
        if self.fail_first_store && self.stored.is_empty() {
            self.fail_first_store = false;
            return Err(denied());
        }
        self.stored.push(journal.worker.as_ref().unwrap().phase);
        Ok(())
    }
}
fn binding() -> Option<WorkerBinding> {
    Some(WorkerBinding {
        pid: 1234,
        generation: "0".repeat(32),
    })
}
#[test]
fn postload_confirmation_or_store_failure_publishes_restrictive_receipt() {
    for store in [false, true] {
        let mut receipt = journal();
        let mut backend = PublicationFixture {
            fail_confirmation_after_load: !store,
            fail_first_store: store,
            ..Default::default()
        };
        assert!(publish_phase(
            &mut receipt,
            Phase::RelayEgress,
            binding(),
            || Ok(()),
            &mut backend
        )
        .is_err());
        assert_eq!(receipt.worker.as_ref().unwrap().phase, Phase::RetainedGuard);
        assert_eq!(backend.loads.len(), 2);
        assert!(backend.loads[0].contains("2001:db8::20"));
        assert!(!backend.loads[1].contains("proto tcp"));
        assert!(!backend.loads[1].contains("utun12"));
        assert_eq!(backend.stored, vec![Phase::RetainedGuard]);
    }
}
#[test]
fn permission_expiring_after_load_restricts_and_preload_refusal_does_not_load() {
    let mut receipt = journal();
    let mut backend = PublicationFixture::default();
    let mut calls = 0;
    assert!(publish_phase(
        &mut receipt,
        Phase::RelayEgress,
        binding(),
        || {
            calls += 1;
            if calls == 2 {
                Err(denied())
            } else {
                Ok(())
            }
        },
        &mut backend
    )
    .is_err());
    assert_eq!(receipt.worker.as_ref().unwrap().phase, Phase::RetainedGuard);
    assert_eq!(backend.loads.len(), 2);
    let mut receipt = journal();
    let before = receipt.clone();
    let mut backend = PublicationFixture::default();
    assert!(publish_phase(
        &mut receipt,
        Phase::RelayEgress,
        binding(),
        || Err(denied()),
        &mut backend
    )
    .is_err());
    assert!(receipt == before);
    assert!(backend.loads.is_empty());
    assert!(backend.stored.is_empty());
}
#[test]
fn failed_restrictive_recovery_remains_incomplete_and_never_records_success() {
    let mut receipt = journal();
    let original = receipt.clone();
    let mut backend = PublicationFixture {
        fail_first_store: true,
        fail_restriction: true,
        ..Default::default()
    };
    let error = publish_phase(
        &mut receipt,
        Phase::RelayEgress,
        binding(),
        || Ok(()),
        &mut backend,
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("INCOMPLETE:"));
    assert!(receipt == original);
    assert!(backend.stored.is_empty());
    assert_eq!(backend.loads.len(), 2);
}
#[test]
fn skipped_phase_does_not_touch_backend_and_valid_publication_binds_generation() {
    let mut receipt = journal();
    let mut backend = PublicationFixture::default();
    assert!(publish_phase(
        &mut receipt,
        Phase::CaptureActive,
        None,
        || Ok(()),
        &mut backend
    )
    .is_err());
    assert_eq!(backend.confirms, 0);
    assert!(backend.loads.is_empty());
    publish_phase(
        &mut receipt,
        Phase::RelayEgress,
        binding(),
        || Ok(()),
        &mut backend,
    )
    .unwrap();
    let worker = receipt.worker.as_ref().unwrap();
    assert_eq!(worker.phase, Phase::RelayEgress);
    assert_eq!(worker.binding.as_ref().unwrap().pid, 1234);
    assert_eq!(backend.stored, vec![Phase::RelayEgress]);
}

#[test]
fn independent_rollback_needs_retained_phase_and_confirmed_bound_exit() {
    let mut receipt = sample();
    assert!(!receipt.rollback_admitted());
    receipt.phase = Phase::RetainedGuard;
    assert!(!receipt.rollback_admitted());
    receipt.exit_confirmed = true;
    assert!(receipt.validate().is_err());
    assert!(!receipt.rollback_admitted());
    receipt.binding = binding();
    assert!(receipt.validate().is_ok());
    assert!(receipt.rollback_admitted());
    receipt.phase = Phase::RelayEgress;
    assert!(!receipt.rollback_admitted());
    receipt.phase = Phase::CaptureActive;
    assert!(!receipt.rollback_admitted());
}
#[test]
fn a_confirmed_exit_cannot_reopen_any_egress_or_capture_phase() {
    for (phase, next, bind) in [
        (Phase::BootstrapAuthority, Phase::RelayEgress, binding()),
        (Phase::RelayEgress, Phase::CaptureActive, None),
    ] {
        let mut receipt = journal();
        let worker = receipt.worker.as_mut().unwrap();
        worker.phase = phase;
        worker.exit_confirmed = true;
        let mut backend = PublicationFixture::default();
        assert!(publish_phase(&mut receipt, next, bind, || Ok(()), &mut backend).is_err());
        assert!(backend.loads.is_empty());
        assert_eq!(backend.confirms, 0);
    }
}

#[test]
fn a_failed_requested_load_is_treated_as_potentially_applied_and_restricted() {
    let mut receipt = journal();
    let mut backend = PublicationFixture {
        fail_first_load: true,
        ..Default::default()
    };
    assert!(publish_phase(
        &mut receipt,
        Phase::RelayEgress,
        binding(),
        || Ok(()),
        &mut backend
    )
    .is_err());
    assert_eq!(backend.loads.len(), 2);
    assert!(backend.loads[0].contains("proto tcp"));
    assert!(!backend.loads[1].contains("proto tcp"));
    assert_eq!(receipt.worker.as_ref().unwrap().phase, Phase::RetainedGuard);
    assert_eq!(backend.stored, vec![Phase::RetainedGuard]);
}
#[test]
fn failed_restrictive_persist_does_not_claim_a_clean_recovery_receipt() {
    let mut receipt = journal();
    let original = receipt.clone();
    let mut backend = PublicationFixture {
        fail_confirmation_after_load: true,
        fail_retained_store: true,
        ..Default::default()
    };
    let error = publish_phase(
        &mut receipt,
        Phase::RelayEgress,
        binding(),
        || Ok(()),
        &mut backend,
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("INCOMPLETE:"));
    assert!(receipt == original);
    assert!(backend.stored.is_empty());
    assert_eq!(backend.loads.len(), 2);
    assert!(!backend.loads[1].contains("proto tcp"));
}

// Shapes follow primary upstream PF print_rule/print_ugid/print_fromto (numeric
// port equality, flags-any may be omitted with no state, one expanded ICMP rule).
// These are source fixtures, not an observed Darwin pfctl output or live policy.
fn printed_anchor() -> String {
    [
        "pass quick on lo0 all no state",
        "pass out quick on en0 inet proto tcp from any to 192.0.2.10 port = 9443 user = 50123 no state",
        "pass in quick on en0 inet proto tcp from 192.0.2.10 port = 9443 to any user = 50123 no state",
        "pass out quick inet6 proto ipv6-icmp from any to fe80::/10 icmp6-type neighbrsol no state",
        "pass in quick inet6 proto ipv6-icmp from fe80::/10 to ff02::/16 icmp6-type routeradv no state",
        "block drop quick all",
    ].join("\n")
}
#[test]
fn paired_native_printer_readback_preserves_order_and_only_normalizes_whitespace() {
    let expected = printed_anchor();
    let padded = expected.replace(' ', "\t ");
    require_anchor_pair(&expected, &format!("\n{padded}\n")).unwrap();
    let mut reordered: Vec<_> = expected.lines().collect();
    reordered.swap(1, 2);
    assert!(require_anchor_pair(&expected, &reordered.join("\n")).is_err());
    assert!(require_anchor_pair(&expected, &format!("{expected}\n{expected}")).is_err());
}
#[test]
fn actual_anchor_uid_pin_flags_state_direction_or_nested_anchor_change_refuses() {
    let expected = printed_anchor();
    for actual in [
        expected.replace("50123", "0"),
        expected.replace("192.0.2.10", "192.0.2.20"),
        expected.replace("9443", "9444"),
        expected.replace("en0", "en1"),
        expected.replace("no state", "keep state"),
        expected.replace("no state", "flags S/SA no state"),
        expected.replace("pass out quick", "pass in quick"),
        expected.replace("block drop quick all", "anchor \"foreign\" all"),
        expected.replace("user = 50123 ", ""),
    ] {
        assert!(require_anchor_pair(&expected, &actual).is_err());
    }
    assert!(require_anchor_pair(&expected, &expected.replace("block drop quick all", "")).is_err());
}
#[test]
fn native_readback_refuses_unknown_printer_lines_and_bounded_or_truncated_output() {
    let expected = printed_anchor();
    for unexpected in [
        "@0 pass quick on lo0 all no state",
        "[ Evaluations: 0 ]",
        "table <x> persist",
        "scrub all",
        "warning: custom syntax",
        "pass quick on lo0 all route-to en0 no state",
    ] {
        assert!(require_anchor_pair(
            &format!("{unexpected}\n{expected}"),
            &format!("{unexpected}\n{expected}")
        )
        .is_err());
    }
    for bad in [
        String::new(),
        "x".repeat(262145),
        "pass\0 quick on lo0 all no state\nblock drop quick all".into(),
        expected.replace("neighbrsol", "unknown_type"),
        expected.replace("50123", "worker_name"),
    ] {
        assert!(native_anchor(&bad).is_err());
    }
    let many = format!(
        "{}block drop quick all",
        "pass quick on lo0 all no state\n".repeat(256)
    );
    assert!(native_anchor(&many).is_err());
}
#[test]
fn expected_phase_is_confirmed_before_load_then_requested_or_retained_after_load() {
    for failed in [false, true] {
        let mut receipt = journal();
        let current = rules("utun12", receipt.worker.as_ref().unwrap()).unwrap();
        let mut backend = PublicationFixture {
            fail_first_store: failed,
            ..Default::default()
        };
        let result = publish_phase(
            &mut receipt,
            Phase::RelayEgress,
            binding(),
            || Ok(()),
            &mut backend,
        );
        assert_eq!(result.is_err(), failed);
        assert_eq!(backend.expected_confirmations[0], current);
        assert_eq!(backend.expected_confirmations[1], current);
        assert!(backend.expected_confirmations[2].contains("2001:db8::20"));
        assert!(!backend.expected_confirmations[2].contains("192.0.2.10"));
        if failed {
            assert_eq!(backend.expected_confirmations.len(), 4);
            assert!(!backend.expected_confirmations[3].contains("proto tcp"));
            assert!(!backend.expected_confirmations[3].contains("utun12"));
        } else {
            assert_eq!(backend.expected_confirmations.len(), 3);
        }
    }
}
#[test]
fn capture_and_retained_native_readback_cannot_reuse_prior_bootstrap_rules() {
    let bootstrap = printed_anchor();
    let relay = bootstrap
        .replace("en0 inet", "en1 inet6")
        .replace("192.0.2.10", "2001:db8::20")
        .replace("9443", "8443");
    let capture = relay.replace(
        "pass quick on lo0 all no state",
        "pass quick on lo0 all no state\npass quick on utun12 all no state",
    );
    let retained: String = bootstrap
        .lines()
        .filter(|l| !l.contains("proto tcp"))
        .collect::<Vec<_>>()
        .join("\n");
    require_anchor_pair(&relay, &relay).unwrap();
    require_anchor_pair(&capture, &capture).unwrap();
    require_anchor_pair(&retained, &retained).unwrap();
    assert!(require_anchor_pair(&relay, &bootstrap).is_err());
    assert!(require_anchor_pair(&capture, &relay).is_err());
    assert!(require_anchor_pair(&retained, &relay).is_err());
}

#[test]
fn native_printer_known_optional_any_flags_are_understood_but_not_erased_in_comparison() {
    let expected = printed_anchor();
    let flags = expected.replace("no state", "flags any no state");
    // ICMP cannot have TCP flags; use only the generic/TCP lines.
    assert!(native_anchor(&flags).is_err());
    let flags = flags
        .lines()
        .map(|l| {
            if l.contains("proto ipv6-icmp") {
                l.replace("flags any ", "")
            } else {
                l.into()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    require_anchor_pair(&flags, &flags).unwrap();
    assert!(require_anchor_pair(&expected, &flags).is_err());
}
