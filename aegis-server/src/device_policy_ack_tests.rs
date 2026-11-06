use super::*;
use aegis_core::secure_channel::registry::RuntimePolicyStatus;

fn unit() -> UnitIdentity {
    unit_identity(b"MainPID=42\nActiveState=active\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nFragmentPath=/etc/systemd/system/aegis-server.service\nDropInPaths=/etc/systemd/system/aegis-server.service.d/policy.conf\nControlGroup=/system.slice/aegis-server.service\n").unwrap()
}

fn expected() -> SyncReceipt {
    SyncReceipt {
        event_code: "device_policy_durable_apply",
        acknowledgement: "disk_only",
        generation: 3,
        snapshot_sha256: "a".repeat(64),
        issued_at_unix_secs: 100,
        expires_at_unix_secs: 200,
    }
}

fn response() -> Response {
    Response::Ready {
        policy: RuntimePolicyStatus {
            generation: 3,
            snapshot_sha256: "a".repeat(64),
            issued_at_unix_secs: 100,
            expires_at_unix_secs: 200,
            policy_remaining_ms: 40_000,
            effective_valid_for_ms: 2500,
        },
        process: ProcessIdentity {
            pid: 42,
            process_start_ticks: Some(99),
            version: "0.3.50".into(),
            build_git: "b".repeat(40),
            build_target: "aarch64-unknown-linux-gnu".into(),
            cargo_lock_sha256: "c".repeat(64),
        },
    }
}

#[test]
fn disk_and_live_acknowledgements_are_distinct_and_response_delay_reduces_validity() {
    let ack = matches_live(&expected(), response(), &unit(), Some(99), 500).unwrap();
    assert_eq!(ack.acknowledgement, "live_process");
    assert_eq!(ack.effective_valid_for_ms, 2000);
    assert_eq!(expected().acknowledgement, "disk_only");
    assert!(matches_live(&expected(), response(), &unit(), Some(99), 2500).is_err());
    assert!(matches_live(&expected(), Response::Unavailable, &unit(), Some(99), 0).is_err());
}

#[test]
fn exact_generation_digest_deadline_and_process_identity_are_required() {
    let baseline = expected();
    let changes: Vec<fn(&mut RuntimePolicyStatus, &mut ProcessIdentity)> = vec![
        |p, _| p.generation -= 1,
        |p, _| p.generation += 1,
        |p, _| p.snapshot_sha256 = "d".repeat(64),
        |p, _| p.issued_at_unix_secs += 1,
        |p, _| p.expires_at_unix_secs += 1,
        |p, _| p.effective_valid_for_ms = 0,
        |p, _| p.effective_valid_for_ms = 3001,
        |p, _| p.policy_remaining_ms = 2000,
        |_, p| p.pid += 1,
        |_, p| p.process_start_ticks = Some(100),
        |_, p| p.build_git = "malformed\nfield".into(),
    ];
    for change in changes {
        let Response::Ready {
            mut policy,
            mut process,
        } = response()
        else {
            unreachable!()
        };
        change(&mut policy, &mut process);
        assert!(matches_live(
            &baseline,
            Response::Ready { policy, process },
            &unit(),
            Some(99),
            0
        )
        .is_err());
    }
}

#[test]
fn systemd_input_is_bounded_exact_active_identity_not_an_arbitrary_command() {
    let valid = "MainPID=42\nActiveState=active\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nFragmentPath=/etc/systemd/system/aegis-server.service\nDropInPaths=\nControlGroup=/system.slice/aegis-server.service\n";
    assert!(unit_identity(valid.as_bytes()).is_ok());
    for input in [
        valid.replace("MainPID=42", "MainPID=0"),
        valid.replace("ActiveState=active", "ActiveState=activating"),
        valid.replace(
            "InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "InvocationID=x",
        ),
        valid.replace(
            "FragmentPath=/etc/systemd/system/aegis-server.service",
            "FragmentPath=/tmp/../x",
        ),
        valid.replace("DropInPaths=", "DropInPaths=/tmp/hello\\x20world"),
        valid.replace(
            "ControlGroup=/system.slice/aegis-server.service",
            "ControlGroup=/",
        ),
        valid.replace(
            "ControlGroup=/system.slice/aegis-server.service",
            "ControlGroup=/system.slice/../other",
        ),
        format!("{valid}MainPID=43\n"),
        format!("{valid}Unexpected=forbidden\n"),
        valid.repeat(200),
        "MainPID=42\n".into(),
    ] {
        assert!(
            unit_identity(input.as_bytes()).is_err(),
            "invalid unit identity accepted"
        );
    }
    let mut restarted = unit();
    restarted.invocation = "b".repeat(32);
    assert_ne!(
        unit(),
        restarted,
        "same PID in a new systemd invocation is not the same owner"
    );
}

#[test]
fn opt_in_config_has_strict_path_and_timeout_bounds() {
    for (path, seconds, valid) in [
        ("/run/aegis/status.sock", 1, true),
        ("/run/aegis/status.sock", 10, true),
        ("/run/aegis/status.sock", 0, false),
        ("/run/aegis/status.sock", 11, false),
        ("relative.sock", 1, false),
        ("/run/aegis/../other", 1, false),
    ] {
        assert_eq!(
            RuntimeAckConfig {
                service_unit: default_service_unit(),
                socket: path.into(),
                service_uid: 123,
                service_gid: 123,
                timeout_secs: seconds
            }
            .validate()
            .is_ok(),
            valid
        );
    }
    assert!(serde_json::from_str::<RuntimeAckConfig>(r#"{"socket":"/run/aegis/status.sock","service_uid":123,"service_gid":123,"timeout_secs":1,"unit":"attacker.service"}"#).is_err());
}

#[test]
fn named_rollout_service_is_explicit_bounded_and_cannot_select_other_units() {
    let base = serde_json::json!({"socket":"/run/aegis/status.sock","service_uid":123,"service_gid":123,"timeout_secs":1});
    let default: RuntimeAckConfig = serde_json::from_value(base.clone()).unwrap();
    assert_eq!(default.service_unit, "aegis-server.service");
    for (name, valid) in [
        ("aegis-server-v3.service", true),
        ("aegis-server-blue-1.service", true),
        ("aegis-server-.service", false),
        ("aegis-server@other.service", false),
        ("sshd.service", false),
        ("aegis-server-x/service.service", false),
        ("aegis-server-x.service --user", false),
        ("../aegis-server.service", false),
    ] {
        let mut value = base.clone();
        value["service_unit"] = name.into();
        let config: RuntimeAckConfig = serde_json::from_value(value).unwrap();
        assert_eq!(config.validate().is_ok(), valid, "{name}");
    }
}
