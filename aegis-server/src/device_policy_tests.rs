use super::*;
use aegis_core::secure_channel::registry::{DeviceRecord, InvitationPurpose, InvitationRecord};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn directory() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().canonicalize().unwrap().join(name)
}

fn private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn snapshot(at: u64, ttl: u64) -> DeviceRegistry {
    let mut value = DeviceRegistry::new(at, ttl).unwrap();
    for (name, digit) in [("neighbor", 'a'), ("device", 'b')] {
        value.devices.push(DeviceRecord {
            device_id: name.into(),
            certificate_sha256: digit.to_string().repeat(64),
            not_after_unix_secs: at + 5000,
            revoked: false,
        });
    }
    value.invitations.push(InvitationRecord {
        device_id: "invited".into(),
        token_sha256: "c".repeat(64),
        expires_unix_secs: at + 100,
        consumed: false,
        purpose: InvitationPurpose::Enroll,
    });
    value
}

fn fixture_config(dir: &tempfile::TempDir) -> SyncConfig {
    let key = path(dir, "node-key");
    private(&key, b"synthetic-not-a-real-private-key");
    let hosts = path(dir, "known_hosts");
    private(
        &hosts,
        format!("{HOST_ALIAS} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture\n").as_bytes(),
    );
    SyncConfig {
        schema: "aegis_device_policy_ssh_v1".into(),
        registry: path(dir, "replica.json"),
        authority_host: "authority.example.invalid".into(),
        authority_port: 22,
        authority_user: "aegis-policy-read".into(),
        identity_file: key,
        known_hosts_file: hosts,
        timeout_secs: 15,
        runtime_ack: None,
    }
}

#[test]
fn export_is_canonical_read_only_and_never_refreshes() {
    let dir = directory();
    let registry = path(&dir, "authority.json");
    let value = snapshot(100, 900);
    registry::publish_snapshot(&registry, &value).unwrap();
    let before = fs::read(&registry).unwrap();
    let floor = fs::read(registry::floor_path(&registry)).unwrap();
    let bytes = export(&registry, 110).unwrap();
    assert_eq!(bytes, canonical(&value).unwrap());
    let decoded = decode(&bytes, 110).unwrap();
    assert_eq!(decoded.devices[0].device_id, "device");
    assert_eq!(decoded.invitations[0].token_sha256, "c".repeat(64));
    assert_eq!(decoded.validity, value.validity);
    assert_eq!(fs::read(&registry).unwrap(), before);
    assert_eq!(fs::read(registry::floor_path(&registry)).unwrap(), floor);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn export_refuses_pending_and_writer_lock_even_with_old_healthy_pair() {
    let dir = directory();
    let registry = path(&dir, "authority.json");
    registry::publish_snapshot(&registry, &snapshot(100, 900)).unwrap();
    let transaction = registry::RegistryTransaction::begin(&registry).unwrap();
    assert_eq!(
        export(&registry, 110).unwrap_err(),
        PolicyError::RegistryUnavailable
    );
    drop(transaction);
    let mut pending = snapshot(100, 900);
    pending.generation = 2;
    private(
        &registry::pending_path(&registry),
        &canonical(&pending).unwrap(),
    );
    assert_eq!(
        export(&registry, 110).unwrap_err(),
        PolicyError::RegistryUnavailable
    );
    assert_eq!(DeviceRegistry::load(&registry).unwrap().generation, 1);
}

#[tokio::test]
async fn health_waits_for_bounded_registry_publication_overlap() {
    let dir = directory();
    let registry = path(&dir, "replica.json");
    let expected = snapshot(100, 900);
    registry::publish_snapshot(&registry, &expected).unwrap();
    let transaction = registry::RegistryTransaction::begin(&registry).unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(transaction);
    });

    let started = std::time::Instant::now();
    let observed = load_health_snapshot(
        &registry,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    release.await.unwrap();

    assert_eq!(observed.generation, expected.generation);
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn health_fails_closed_when_publication_exceeds_its_budget() {
    let dir = directory();
    let registry = path(&dir, "replica.json");
    registry::publish_snapshot(&registry, &snapshot(100, 900)).unwrap();
    let _transaction = registry::RegistryTransaction::begin(&registry).unwrap();

    let started = std::time::Instant::now();
    assert_eq!(
        load_health_snapshot(
            &registry,
            tokio::time::Instant::now() + Duration::from_millis(150),
        )
        .await
        .unwrap_err(),
        PolicyError::RegistryUnavailable
    );
    assert!(started.elapsed() >= Duration::from_millis(125));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn health_does_not_retry_invalid_registry_state() {
    let dir = directory();
    let registry = path(&dir, "replica.json");
    private(&registry, b"not-json");
    private(&registry::floor_path(&registry), b"not-json");
    private(&path(&dir, "replica.json.lock"), b"");

    let started = std::time::Instant::now();
    assert_eq!(
        load_health_snapshot(
            &registry,
            tokio::time::Instant::now() + Duration::from_secs(2)
        )
        .await
        .unwrap_err(),
        PolicyError::RegistryUnavailable
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn health_does_not_retry_durable_issuance_recovery_barrier() {
    let dir = directory();
    let registry = path(&dir, "replica.json");
    registry::publish_snapshot(&registry, &snapshot(100, 900)).unwrap();
    private(
        &registry::issuance_pending_path(&registry),
        b"recovery-required",
    );

    let started = std::time::Instant::now();
    assert_eq!(
        load_health_snapshot(
            &registry,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap_err(),
        PolicyError::RegistryUnavailable
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn expired_future_legacy_partial_invalid_and_noncanonical_policy_reject() {
    let original = snapshot(100, 10);
    let bytes = canonical(&original).unwrap();
    assert_eq!(
        decode(&bytes, 110).unwrap_err(),
        PolicyError::InvalidValidity
    );
    assert_eq!(
        decode(&bytes, 99).unwrap_err(),
        PolicyError::InvalidValidity
    );
    assert_eq!(
        decode(&canonical(&DeviceRegistry::default()).unwrap(), 105).unwrap_err(),
        PolicyError::InvalidValidity
    );
    assert_eq!(
        decode(&bytes[..bytes.len() - 1], 105).unwrap_err(),
        PolicyError::InvalidSnapshot
    );
    assert_eq!(
        decode(b"not-json", 105).unwrap_err(),
        PolicyError::InvalidSnapshot
    );
    assert_eq!(
        decode(&serde_json::to_vec_pretty(&original).unwrap(), 105).unwrap_err(),
        PolicyError::NonCanonical
    );
    let mut invalid = serde_json::to_value(&original).unwrap();
    invalid["devices"][0]["revoked"] = serde_json::json!("no");
    assert_eq!(
        decode(&serde_json::to_vec(&invalid).unwrap(), 105).unwrap_err(),
        PolicyError::InvalidSnapshot
    );
    let mut injected = serde_json::to_value(&original).unwrap();
    injected["private_key"] = serde_json::json!("PRIVATE MATERIAL MUST NEVER BE DELIVERED");
    assert_eq!(
        decode(&serde_json::to_vec(&injected).unwrap(), 105).unwrap_err(),
        PolicyError::InvalidSnapshot
    );
    assert_eq!(
        decode(&vec![b'x'; MAX_REGISTRY_BYTES as usize + 1], 105).unwrap_err(),
        PolicyError::OutputTooLarge
    );
}

#[test]
fn failed_inputs_leave_floor_and_snapshot_unchanged_and_valid_newer_applies() {
    let dir = directory();
    let target = path(&dir, "replica.json");
    let initial = snapshot(100, 60);
    apply(&target, &canonical(&initial).unwrap(), 110).unwrap();
    let unchanged = (
        fs::read(&target).unwrap(),
        fs::read(registry::floor_path(&target)).unwrap(),
    );
    let mut wrong = initial.clone();
    wrong.devices[0].revoked = true;
    assert_eq!(
        apply(&target, &canonical(&wrong).unwrap(), 110).unwrap_err(),
        PolicyError::ApplyFailed
    );
    let mut expired = initial.clone();
    expired.generation = 2;
    assert_eq!(
        apply(&target, &canonical(&expired).unwrap(), 160).unwrap_err(),
        PolicyError::InvalidValidity
    );
    assert_eq!(
        (
            fs::read(&target).unwrap(),
            fs::read(registry::floor_path(&target)).unwrap()
        ),
        unchanged
    );
    assert!(!registry::pending_path(&target).exists());
    let mut newer = initial.clone();
    newer.refresh_validity(155, 60).unwrap();
    newer.devices[0].revoked = true;
    let result = apply(&target, &canonical(&newer).unwrap(), 161).unwrap();
    assert_eq!(result.generation, 2);
    assert_eq!(result.event_code, "device_policy_durable_apply");
    assert_eq!(result.acknowledgement, "disk_only");
    assert_eq!(result.expires_at_unix_secs, 215);
    assert!(DeviceRegistry::load(&target).unwrap().devices[1].revoked);
    assert_eq!(
        apply(&target, &canonical(&initial).unwrap(), 110).unwrap_err(),
        PolicyError::ApplyFailed
    );
}

#[test]
fn same_snapshot_does_not_extend_validity_or_rewrite_the_floor() {
    use std::os::unix::fs::MetadataExt;
    let dir = directory();
    let target = path(&dir, "replica.json");
    let initial = snapshot(100, 30);
    let bytes = canonical(&initial).unwrap();
    apply(&target, &bytes, 101).unwrap();
    let floor = registry::floor_path(&target);
    let before = (
        fs::metadata(&target).unwrap().ino(),
        fs::metadata(&floor).unwrap().ino(),
    );
    let result = apply(&target, &bytes, 129).unwrap();
    assert_eq!(result.expires_at_unix_secs, 130);
    assert_eq!(
        (
            fs::metadata(&target).unwrap().ino(),
            fs::metadata(&floor).unwrap().ino()
        ),
        before
    );
    assert_eq!(
        apply(&target, &bytes, 130).unwrap_err(),
        PolicyError::InvalidValidity
    );
    assert_eq!(
        DeviceRegistry::load(&target).unwrap().validity,
        initial.validity
    );
}

#[test]
fn exact_pending_recovery_works_before_and_after_floor_without_discard() {
    for after_floor in [false, true] {
        let dir = directory();
        let target = path(&dir, "replica.json");
        let authority = path(&dir, "authority.json");
        let original = snapshot(100, 60);
        apply(&target, &canonical(&original).unwrap(), 110).unwrap();
        let mut next = original.clone();
        next.refresh_validity(120, 60).unwrap();
        next.devices[0].revoked = true;
        registry::publish_snapshot(&authority, &next).unwrap();
        // Synthetic fault cut only: preserve the exact core-generated snapshot
        // and floor; no production code manufactures or discards sidecars.
        let pending = registry::pending_path(&target);
        private(&pending, &fs::read(&authority).unwrap());
        if after_floor {
            private(
                &registry::floor_path(&target),
                &fs::read(registry::floor_path(&authority)).unwrap(),
            );
        }
        let floor_before = fs::read(registry::floor_path(&target)).unwrap();
        let pending_before = fs::read(&pending).unwrap();
        let mut unrelated = next.clone();
        unrelated.refresh_validity(121, 60).unwrap();
        assert_eq!(
            apply(&target, &canonical(&unrelated).unwrap(), 122).unwrap_err(),
            PolicyError::ApplyFailed
        );
        assert_eq!(fs::read(&pending).unwrap(), pending_before);
        assert_eq!(
            fs::read(registry::floor_path(&target)).unwrap(),
            floor_before
        );
        apply(&target, &canonical(&next).unwrap(), 122).unwrap();
        assert!(!pending.exists());
        assert_eq!(DeviceRegistry::load(&target).unwrap().generation, 2);
        assert_eq!(
            DeviceRegistry::load(&target).unwrap().validity,
            next.validity
        );
    }
}

#[test]
fn forced_export_accepts_only_exact_protocol_command() {
    for command in [
        None,
        Some(""),
        Some("sh"),
        Some("aegis-device-policy-v1\n"),
        Some("aegis-device-policy-v1; id"),
        Some("scp -f registry.json"),
    ] {
        assert_eq!(
            validate_original_command(command).unwrap_err(),
            PolicyError::UnexpectedSshCommand
        );
    }
    validate_original_command(Some(REMOTE_COMMAND)).unwrap();
}

#[test]
fn ssh_config_guards_files_pin_and_option_injection() {
    let dir = directory();
    let mut config = fixture_config(&dir);
    config.validate().unwrap();
    for bad in [
        "-oProxyCommand=sh",
        "host\nother",
        "user@host",
        "a b",
        "..",
        "",
    ] {
        config.authority_host = bad.into();
        assert!(config.validate().is_err());
    }
    config.authority_host = "2001:db8::1".into();
    config.validate().unwrap();
    config.authority_user = "-oProxyCommand".into();
    assert!(config.validate().is_err());
    config.authority_user = "readonly".into();
    let original_key = config.identity_file.clone();
    for bad in [
        "/root/%h-key",
        "/root/${KEY}",
        "/root/key name",
        "/root/key\nfile",
    ] {
        config.identity_file = PathBuf::from(bad);
        assert_eq!(config.validate().unwrap_err(), PolicyError::InvalidConfig);
    }
    config.identity_file = original_key;
    fs::set_permissions(&config.identity_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(config.validate().unwrap_err(), PolicyError::UnsafeInput);
    fs::set_permissions(&config.identity_file, fs::Permissions::from_mode(0o600)).unwrap();
    let real = config.identity_file.clone();
    config.identity_file = path(&dir, "link");
    std::os::unix::fs::symlink(&real, &config.identity_file).unwrap();
    assert_eq!(config.validate().unwrap_err(), PolicyError::UnsafeInput);
    config.identity_file = real;
    private(&config.known_hosts_file, b"* ssh-ed25519 AAAA");
    assert_eq!(config.validate().unwrap_err(), PolicyError::InvalidConfig);
}

#[test]
fn ssh_argv_uses_fixed_program_no_inherited_env_and_one_exact_authority() {
    let dir = directory();
    let config = fixture_config(&dir);
    let command = config.command();
    let command = command.as_std();
    assert_eq!(command.get_program(), SSH);
    let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
    for option in [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "VerifyHostKeyDNS=no",
        "UpdateHostKeys=no",
        "HostKeyAlgorithms=ssh-ed25519",
        "NumberOfPasswordPrompts=0",
        "ProxyCommand=none",
        "PermitLocalCommand=no",
        "ClearAllForwardings=yes",
    ] {
        assert!(args.contains(&option), "{option}");
    }
    assert!(args
        .contains(&format!("UserKnownHostsFile={}", config.known_hosts_file.display()).as_str()));
    assert_eq!(
        &args[args.len() - 3..],
        ["--", config.authority_host.as_str(), REMOTE_COMMAND]
    );
    let env: Vec<_> = command
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|s| s.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert_eq!(env.len(), 2);
    assert!(!env.iter().any(|(k, _)| k == "SSH_AUTH_SOCK"));
}

fn python(code: &str) -> Command {
    let mut command = Command::new("python3");
    command.args(["-c", code]);
    command
}

fn shell(code: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", code]);
    command
}

#[tokio::test]
async fn child_environment_contains_only_explicit_values() {
    let dir = directory();
    let config = fixture_config(&dir);
    // Command.env_clear must affect the executed process, not merely the
    // explicit-environment iterator used by the argv shape check above.
    let mut command = shell("env");
    command.env("SSH_AUTH_SOCK", "synthetic-must-not-inherit");
    // The synthetic shell executes this fixed script and ignores SSH argv.
    let command = config.configure_command(command);
    let output = receive(command, Duration::from_secs(10)).await.unwrap();
    let environment = String::from_utf8(output).unwrap();
    assert!(!environment.contains("SSH_AUTH_SOCK"));
    for line in environment.lines() {
        assert!(
            line.starts_with("PATH=")
                || line == "LC_ALL=C"
                || line.starts_with("PWD=")
                || line.starts_with("SHLVL=")
                || line.starts_with("_="),
            "unexpected inherited variable name"
        );
    }
}

#[tokio::test]
async fn actual_openssh_accepts_the_pinned_configuration_without_connecting() {
    let dir = directory();
    let config = fixture_config(&dir);
    let mut command = Command::new(SSH);
    command.arg("-G");
    let bytes = receive(config.configure_command(command), Duration::from_secs(10))
        .await
        .unwrap();
    let output = String::from_utf8(bytes).unwrap();
    for required in [
        "hostkeyalgorithms ssh-ed25519",
        "stricthostkeychecking true",
        "identityagent none",
        "updatehostkeys false",
        "verifyhostkeydns false",
        "globalknownhostsfile /dev/null",
        "hostkeyalias aegis-device-policy-authority",
    ] {
        assert!(
            output.lines().any(|line| line == required),
            "missing effective SSH option: {required}"
        );
    }
    assert!(output
        .lines()
        .any(|line| line == format!("userknownhostsfile {}", config.known_hosts_file.display())));
}

#[tokio::test]
async fn transport_bounds_timeout_partial_output_and_exit_status() {
    assert_eq!(
        receive(shell("printf partial;exit 3"), Duration::from_secs(10))
            .await
            .unwrap_err(),
        PolicyError::TransportFailed
    );
    assert_eq!(
        receive(
            shell("printf partial;exec sleep 10"),
            Duration::from_millis(500)
        )
        .await
        .unwrap_err(),
        PolicyError::Timeout
    );
    assert_eq!(
        receive(
            python("import sys;sys.stdout.buffer.write(b'x'*(4194304+1));sys.stdout.flush()"),
            Duration::from_secs(10)
        )
        .await
        .unwrap_err(),
        PolicyError::OutputTooLarge
    );
    let bytes = receive(shell("printf '{}'"), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(
        decode(&bytes, 100).unwrap_err(),
        PolicyError::InvalidSnapshot
    );
    let before = std::time::Instant::now();
    let value = receive(
        python("import sys;sys.stderr.write('sensitive-error'*100000);sys.stdout.write('ok')"),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(value, b"ok");
    assert!(before.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn timeout_stops_owned_descendant_before_returning() {
    let dir = directory();
    let marker = path(&dir, "descendant-wrote");
    let ready = path(&dir, "descendant-created");
    // Paths are generated private tempfile paths, never remote/operator text.
    let source = format!(
        "(sleep 1;printf leaked > '{}') & printf ready > '{}';wait",
        marker.display(),
        ready.display()
    );
    assert_eq!(
        receive(shell(&source), Duration::from_millis(500))
            .await
            .unwrap_err(),
        PolicyError::Timeout
    );
    assert_eq!(
        fs::read(&ready).unwrap(),
        b"ready",
        "fixture must fork before timeout"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        !marker.exists(),
        "timed-out descendant escaped the owned process group"
    );
}

#[tokio::test]
async fn completed_leader_stops_remaining_group_before_reap() {
    for exit_code in [0, 7] {
        let dir = directory();
        let marker = path(&dir, "descendant-wrote");
        let ready = path(&dir, "descendant-created");
        // Redirect the descendant's stdout so EOF arrives before its delayed
        // write. A leader-only wait/reap would leave that writer alive.
        let source = format!(
            "(sleep 1;printf leaked > '{}') >/dev/null & printf ready > '{}';printf complete;exit {exit_code}",
            marker.display(),
            ready.display()
        );
        let result = receive(shell(&source), Duration::from_secs(10)).await;
        if exit_code == 0 {
            assert_eq!(result.unwrap(), b"complete");
        } else {
            assert_eq!(result.unwrap_err(), PolicyError::TransportFailed);
        }
        assert_eq!(fs::read(&ready).unwrap(), b"ready");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            !marker.exists(),
            "descendant survived leader exit {exit_code}"
        );
    }
}

#[tokio::test]
async fn cancellation_stops_owned_group_without_waiting_for_transfer_timeout() {
    let dir = directory();
    let marker = path(&dir, "descendant-wrote");
    let ready = path(&dir, "descendant-created");
    let source = format!(
        "(sleep 1;printf leaked > '{}') & printf ready > '{}';wait",
        marker.display(),
        ready.display()
    );
    let command = shell(&source);
    let transfer = tokio::spawn(receive(command, Duration::from_secs(10)));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture must fork before cancellation");
    transfer.abort();
    assert!(transfer.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        !marker.exists(),
        "cancelled transfer left a descendant running"
    );
}
