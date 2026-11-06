//! Explicit stopped selected teardown. No active owner is signalled or killed.
use super::*;
use aegis_core::relay_geneva::{
    linux::recovery::teardown as native,
    teardown::{DeviceBlockPolicy, Phase, TeardownRecord},
    teardown_storage::{self as store, Archive, DirectoryPin, OpenedPublicFile},
};
use std::{
    collections::BTreeMap,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub(super) const HISTORY: &str = "/var/lib/aegis-relay-geneva-history";
pub(super) const NATIVE: &str = "/run/aegis-relay-geneva";
pub(super) const ORIGINAL_BINDINGS: [&str; 2] = [
    "/var/lib/aegis-install/client/device-guard.conf.client-binding",
    "/var/lib/aegis-install/client/device-guard.conf.manager-binding",
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    token: String,
    source: String,
    initial_record_sha256: String,
    profile_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Directories {
    schema: String,
    source: String,
    directories: BTreeMap<PathBuf, DirectoryPin>,
}
fn json_bytes<T: Serialize>(v: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| refused())
}
fn text(bytes: Vec<u8>) -> io::Result<String> {
    String::from_utf8(bytes).map_err(|_| refused())
}
fn request(i: &Input) -> io::Result<&aegis_core::relay_geneva::RelayOuterGenevaSettings> {
    i.config.relay.outer_geneva.as_ref().ok_or_else(refused)
}
pub(super) fn inactive(i: &Input, drop_removed: bool) -> io::Result<()> {
    let mut role = i.profile.role.clone();
    if drop_removed {
        need(
            role.drop_in_paths_to_sha256
                .remove(Path::new(DROP_IN))
                .is_some(),
        )?;
    }
    crate::profile_relay_geneva_role::verify_installable(&role)
}
pub(super) fn same_input(i: &Input, raw: &str) -> io::Result<()> {
    let current = input_profile(raw.into(), false)?;
    need(
        current.profile_bytes_sha256 == i.profile_bytes_sha256
            && current.endpoints == i.endpoints
            && current.profile.role.config_sha256 == i.profile.role.config_sha256,
    )
}
fn exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
struct ManagerContext {
    file: OpenedPublicFile,
    binding: aegis_core::relay_geneva::teardown::OriginalGuardBinding,
    expected: crate::profile_relay_geneva_manager::ExpectedManagerBinding,
    proof: crate::profile_relay_geneva_manager::ManagerProof,
    state_sha: String,
    unit: String,
}
impl ManagerContext {
    fn current(&self, i: &Input, raw: &str) -> io::Result<()> {
        same_input(i, raw)?;
        store::unchanged(&self.file)?;
        need(
            aegis_core::relay_geneva::teardown::original_guard_state_digest(
                crate::profile::read_install_metadata(Path::new(DEVICE_STATE))?.as_bytes(),
            ) == self.state_sha,
        )?;
        let now = crate::profile_relay_geneva_manager::attest_current_manager(
            &self.unit,
            &self.expected,
            &self.state_sha,
        )?;
        need(now == self.proof && now.binding() == &self.expected && now.unit() == self.unit)
    }
}
fn initial_context(
    i: &Input,
    raw: &str,
    lease: &native::GuardLease,
    inet: &DeviceBlockPolicy,
) -> io::Result<([u8; 32], Option<ManagerContext>)> {
    let actual = lease.observe_inet()?;
    if let Ok(digest) = inet.verify(&actual) {
        return Ok((digest, None));
    }
    let file = store::open_public(Path::new(ORIGINAL_BINDINGS[1]), 65536)?;
    let state_sha = aegis_core::relay_geneva::teardown::original_guard_state_digest(
        crate::profile::read_install_metadata(Path::new(DEVICE_STATE))?.as_bytes(),
    );
    let binding = aegis_core::relay_geneva::teardown::validate_original_unit_binding(
        &file.bytes,
        &state_sha,
        &inet.manager,
    )?;
    let expected = serde_json::from_value(parse_unique_public_metadata(&file.bytes)?)
        .map_err(|_| refused())?;
    let proof = crate::profile_relay_geneva_manager::attest_current_manager(
        &inet.manager,
        &expected,
        &state_sha,
    )?;
    let context = ManagerContext {
        file,
        binding,
        expected,
        proof,
        state_sha,
        unit: inet.manager.clone(),
    };
    let digest = inet.verify_manager(&actual, &context.binding)?;
    context.current(i, raw)?;
    let (again, bound) = lease.verify_initial(inet, Some(&context.binding))?;
    need(bound && digest == again)?;
    Ok((digest, Some(context)))
}
fn capture(i: &Input) -> io::Result<(BTreeMap<String, OpenedPublicFile>, Directories)> {
    let mut files = BTreeMap::new();
    let mut dirs = BTreeMap::new();
    for path in [
        Path::new(DIR).join(PROFILE),
        Path::new(DIR).join(STATE),
        Path::new(DIR).join(INSTALL_INTENT),
        RECOVERY_HELPER.into(),
        DROP_IN.into(),
        DEVICE_STATE.into(),
    ] {
        let file = store::open_public(&path, 65536)?;
        files.insert(path.to_str().ok_or_else(refused)?.into(), file);
    }
    for (index, path) in ORIGINAL_BINDINGS.iter().enumerate() {
        if exists(Path::new(path))? {
            let f = store::open_public(Path::new(path), 65536)?;
            let inet = DeviceBlockPolicy::from_state(&crate::profile::read_install_metadata(
                Path::new(DEVICE_STATE),
            )?)?;
            let unit = if index == 0 {
                "aegis-client.service"
            } else {
                &inet.manager
            };
            aegis_core::relay_geneva::teardown::validate_original_unit_binding(
                &f.bytes,
                &aegis_core::relay_geneva::teardown::original_guard_state_digest(
                    crate::profile::read_install_metadata(Path::new(DEVICE_STATE))?.as_bytes(),
                ),
                unit,
            )?;
            files.insert((*path).into(), f);
        }
    }
    let history = Path::new(DIR).join("relay-geneva-history");
    if exists(&history)? {
        dirs.insert(history.clone(), store::directory_pin(&history)?);
        for entry in std::fs::read_dir(&history)? {
            let path = entry?.path();
            let f = store::open_public(&path, 65536)?;
            let expected = format!("{}.json", f.pin.sha256);
            need(path.file_name().and_then(|n| n.to_str()) == Some(expected.as_str()))?;
            let row = parse_unique_public_metadata(&f.bytes)?;
            match row.get("schema").and_then(Value::as_str) {
                Some("aegis_relay_geneva_installed_profile_v1") => {
                    let _: InstalledProfile = serde_json::from_value(row).map_err(|_| refused())?;
                }
                Some("aegis_relay_geneva_install_intent_v1") => {
                    let _: InstallIntent = serde_json::from_value(row).map_err(|_| refused())?;
                }
                Some("aegis_relay_geneva_guard_state_v1") => {
                    let _: OwnedGuardState = serde_json::from_value(row).map_err(|_| refused())?;
                }
                Some("aegis_relay_geneva_guard_transition_v1") => {
                    let _: GuardTransitionIntent =
                        serde_json::from_value(row).map_err(|_| refused())?;
                }
                _ => return Err(refused()),
            }
            files.insert(path.to_str().ok_or_else(refused)?.into(), f);
            need(files.len() <= 8500)?;
        }
    }
    let native_paths =
        native::public_paths(request(i)?, &i.endpoints, &i.profile.role.executable_sha256)?;
    if exists(Path::new(NATIVE))? {
        dirs.insert(NATIVE.into(), store::directory_pin(Path::new(NATIVE))?);
        for entry in std::fs::read_dir(NATIVE)? {
            let path = entry?.path();
            dirs.insert(path.clone(), store::directory_pin(&path)?);
            let token = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(refused)?;
            need(
                token == "recovery-receipts"
                    || (token.len() == 8
                        && token
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))),
            )?;
            let actual = std::fs::read_dir(&path)?
                .map(|e| e.map(|e| e.path()))
                .collect::<io::Result<Vec<_>>>()?;
            need(actual.iter().all(|p| native_paths.contains(p)))?;
        }
        for path in native_paths {
            let f = store::open_public(&path, 1048576)?;
            files.insert(path.to_str().ok_or_else(refused)?.into(), f);
            need(files.len() <= 8500)?;
        }
    }
    Ok((
        files,
        Directories {
            schema: "aegis_selected_teardown_directories_v1".into(),
            source: source()?.into(),
            directories: dirs,
        },
    ))
}
fn systemctl(args: &[&str]) -> io::Result<()> {
    let executable = std::fs::canonicalize("/usr/bin/systemctl")?;
    let pin = store::open_public(&executable, 18 * 1048576)?;
    need(pin.pin.mode & 0o111 != 0)?;
    let parent = unsafe { libc::getpid() };
    let mut cmd = Command::new(&executable);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::other("teardown helper parent changed"));
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                need(status.success())?;
                break;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(refused());
            }
        }
    }
    store::unchanged(&pin)
}
fn load_phases(archive: &Archive, marker: &Marker) -> io::Result<(usize, TeardownRecord)> {
    let mut rows = vec![];
    for entry in std::fs::read_dir(&archive.directory)? {
        let p = entry?.path();
        let name = p.file_name().and_then(|v| v.to_str()).ok_or_else(refused)?;
        if name.ends_with("-phase.json") {
            let index = name.strip_suffix("-phase.json").ok_or_else(refused)?;
            need(index.len() == 8 && index.bytes().all(|b| b.is_ascii_digit()))?;
            rows.push((index.parse::<usize>().map_err(|_| refused())?, p));
        }
    }
    rows.sort_by_key(|(index, _)| *index);
    need(!rows.is_empty() && rows.len() <= 7)?;
    let mut previous: Option<TeardownRecord> = None;
    for (position, (index, path)) in rows.into_iter().enumerate() {
        need(index == position)?;
        let f = store::open_public(&path, 2 * 1048576)?;
        let r: TeardownRecord = serde_json::from_value(
            aegis_core::relay_geneva::recovery::parse_unique_public_metadata_bounded(
                &f.bytes,
                2 * 1048576,
            )?,
        )
        .map_err(|_| refused())?;
        r.validate()?;
        need(
            r.source == source()?
                && r.source == marker.source
                && r.token == marker.token
                && r.profile_sha256 == marker.profile_sha256,
        )?;
        if let Some(old) = previous.as_ref() {
            let expected: TeardownRecord =
                old.advance(r.phase, r.archive_manifest_sha256.as_deref())?;
            need(expected == r)?;
        } else {
            need(r.phase == Phase::Intent && f.pin.sha256 == marker.initial_record_sha256)?;
        }
        previous = Some(r);
    }
    let r = previous.ok_or_else(refused)?;
    Ok((r.phase as usize, r))
}
fn archive_files(
    archive: &Archive,
    row: &TeardownRecord,
) -> io::Result<BTreeMap<PathBuf, Vec<u8>>> {
    let snapshot = archive
        .verified_snapshot_pinned(row.archive_manifest_sha256.as_deref().ok_or_else(refused)?)?;
    need(
        row.archive_manifest_sha256.as_deref() == Some(snapshot.manifest_sha256.as_str())
            && snapshot.manifest.files == row.owned_files
            && snapshot.manifest.source == row.source
            && snapshot.manifest.token == row.token,
    )?;
    Ok(snapshot
        .files
        .into_iter()
        .map(|(name, file)| (PathBuf::from(name), file.bytes))
        .collect())
}
fn verify_archive(archive: &Archive, row: &TeardownRecord) -> io::Result<()> {
    let snapshot = archive
        .verified_snapshot_pinned(row.archive_manifest_sha256.as_deref().ok_or_else(refused)?)?;
    let digest = snapshot.manifest_sha256;
    let manifest = snapshot.manifest;
    need(
        row.archive_manifest_sha256.as_deref() == Some(digest.as_str())
            && manifest.files == row.owned_files
            && manifest.source == row.source
            && manifest.token == row.token,
    )
}
fn verify_marker(archive: &Archive, marker: &Marker) -> io::Result<()> {
    archive.verify_extra("teardown-marker.json", &json_bytes(marker)?)
}

fn validate_remaining(row: &TeardownRecord, archive: &Archive) -> io::Result<()> {
    verify_archive(archive, row)?;
    for (path, pin) in &row.owned_files {
        if exists(Path::new(path))? {
            need(store::open_public(Path::new(path), 18 * 1048576)?.pin == *pin)?;
        } else {
            let allowed = if path == DROP_IN {
                row.phase >= Phase::NativeQuiet
            } else if path == DEVICE_STATE || ORIGINAL_BINDINGS.contains(&path.as_str()) {
                false
            } else {
                row.phase >= Phase::DropInRemoved
            };
            need(allowed)?;
        }
    }
    Ok(())
}
fn advance(
    archive: &Archive,
    index: &mut usize,
    row: &mut TeardownRecord,
    phase: Phase,
    hash: Option<&str>,
) -> io::Result<()> {
    let next = row.advance(phase, hash)?;
    *index += 1;
    archive.append(*index, &next)?;
    *row = next;
    Ok(())
}
fn remove_one(path: &Path, pin: &aegis_core::relay_geneva::teardown::FilePin) -> io::Result<()> {
    if exists(path)? {
        let f = store::open_public(path, 18 * 1048576)?;
        need(f.pin == *pin)?;
        store::remove_exact(&f)?;
    }
    Ok(())
}
fn run_owned(archive: &Archive, marker: &Marker) -> io::Result<()> {
    verify_marker(archive, marker)?;
    let live_marker = store::open_public(&Path::new(DIR).join(TEARDOWN), 65536)?;
    need(live_marker.bytes == json_bytes(marker)?)?;
    let (mut index, mut row) = load_phases(archive, marker)?;
    let apin = archive.identity()?;
    need(apin.device == row.archive_device && apin.inode == row.archive_inode)?;
    if row.phase == Phase::Intent {
        let raw = crate::profile::read_install_metadata(&Path::new(DIR).join(PROFILE))?;
        let initial = input_profile(raw.clone(), true)?;
        inactive(&initial, false)?;
        need(hex::encode(initial.profile_bytes_sha256) == row.profile_sha256)?;
        let (files, dirs) = capture(&initial)?;
        need(
            files
                .iter()
                .map(|(n, f)| (n.clone(), f.pin.clone()))
                .collect::<BTreeMap<_, _>>()
                == row.owned_files,
        )?;
        let expected_dirs = json_bytes(&dirs)?;
        need(
            store::open_public(&archive.directory.join("directories.json"), 2 * 1048576)?.bytes
                == expected_dirs,
        )?;
        let lease = native::GuardLease::acquire()?;
        inactive(&initial, false)?;
        lease.selected_block(
            &initial.profile.policy,
            request(&initial)?,
            &initial.endpoints,
        )?;
        let inet = DeviceBlockPolicy::from_state(&crate::profile::read_install_metadata(
            Path::new(DEVICE_STATE),
        )?)?;
        need(hex::encode(inet.verify(&inet.expected())?) == row.original_inet_digest)?;
        let (current_digest, manager) = initial_context(&initial, &raw, &lease, &inet)?;
        if let Some(manager) = manager.as_ref() {
            need(
                hex::encode(current_digest) == row.initial_original_inet_digest
                    && row.initial_manager_identity_sha256.as_deref()
                        == Some(manager.proof.digest())
                    && row.initial_manager_binding_sha256.as_deref()
                        == Some(manager.file.pin.sha256.as_str()),
            )?;
        } else {
            need(hex::encode(current_digest) == row.original_inet_digest)?;
        }
        lease.revoke_inet_initial(&inet, manager.as_ref().map(|m| &m.binding), || {
            manager
                .as_ref()
                .ok_or_else(refused)?
                .current(&initial, &raw)
        })?;

        same_input(&initial, &raw)?;
        let hash = archive.copy(&row.token, &row.source, &files)?;
        advance(
            archive,
            &mut index,
            &mut row,
            Phase::ArchiveCommitted,
            Some(&hash),
        )?;
    }
    verify_archive(archive, &row)?;
    let raw = text(archive.original(&Path::new(DIR).join(PROFILE))?)?;
    let i = input_profile(raw.clone(), false)?;
    let r = request(&i)?;
    need(
        row.selected_netdev_digest
            == hex::encode(
                aegis_core::relay_geneva::installed_guard::canonical_table_digest(
                    &aegis_core::relay_geneva::installed_guard::expected(&i.profile.policy, None)?,
                )?,
            ),
    )?;
    let inet = DeviceBlockPolicy::from_state(&text(archive.original(Path::new(DEVICE_STATE))?)?)?;
    let state: OwnedGuardState = serde_json::from_value(parse_unique_public_metadata(
        &archive.original(&Path::new(DIR).join(STATE))?,
    )?)
    .map_err(|_| refused())?;
    need(
        state.schema == "aegis_relay_geneva_guard_state_v1"
            && state.policy_sha256 == hex::encode(i.profile.policy.digest()?)
            && state.table_present
            && state.active_binding.is_none(),
    )?;
    let dirf = store::open_public(&archive.directory.join("directories.json"), 2 * 1048576)?;
    need(dirf.pin.sha256 == row.directory_manifest_sha256)?;
    let dirs: Directories = serde_json::from_value(
        aegis_core::relay_geneva::recovery::parse_unique_public_metadata_bounded(
            &dirf.bytes,
            2 * 1048576,
        )?,
    )
    .map_err(|_| refused())?;
    need(dirs.schema == "aegis_selected_teardown_directories_v1" && dirs.source == source()?)?;
    let lease = native::GuardLease::acquire()?;
    same_input(&i, &raw)?;
    validate_remaining(&row, archive)?;
    if row.phase == Phase::NativeQuiet && !exists(Path::new(DROP_IN))? {
        systemctl(&["daemon-reload"])?;
    }
    inactive(&i, !exists(Path::new(DROP_IN))?)?;
    need(hex::encode(lease.verify_inet(&inet)?) == row.original_inet_digest)?;
    let saved = archive_files(archive, &row)?;
    if row.phase == Phase::ArchiveCommitted {
        lease.selected_block(&i.profile.policy, r, &i.endpoints)?;
        let proof = native::recover_stopped(
            &lease,
            r,
            &i.endpoints,
            &i.profile.policy,
            &inet,
            &i.profile.role.executable_sha256,
            || {
                same_input(&i, &raw)?;
                inactive(&i, false)
            },
        )?;
        let proofname = format!(
            "native-quiet-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| refused())?
                .as_nanos()
        );
        archive.write_extra(&proofname, &json_bytes(&proof)?)?;
        advance(archive, &mut index, &mut row, Phase::NativeQuiet, None)?;
    }
    native::quiet_archived(r, &i.endpoints, &i.profile.role.executable_sha256, &saved)?;
    if row.phase == Phase::NativeQuiet {
        same_input(&i, &raw)?;
        inactive(&i, !exists(Path::new(DROP_IN))?)?;
        lease.verify_inet(&inet)?;
        lease.selected_block(&i.profile.policy, r, &i.endpoints)?;
        validate_remaining(&row, archive)?;
        systemctl(&["disable", "aegis-client.service"])?;
        remove_one(
            Path::new(DROP_IN),
            row.owned_files.get(DROP_IN).ok_or_else(refused)?,
        )?;
        systemctl(&["daemon-reload"])?;
        inactive(&i, true)?;
        advance(archive, &mut index, &mut row, Phase::DropInRemoved, None)?;
    }
    if row.phase == Phase::DropInRemoved {
        same_input(&i, &raw)?;
        inactive(&i, true)?;
        lease.verify_inet(&inet)?;
        lease.selected_block(&i.profile.policy, r, &i.endpoints)?;
        native::quiet_archived(r, &i.endpoints, &i.profile.role.executable_sha256, &saved)?;
        validate_remaining(&row, archive)?;
        for (path, pin) in &row.owned_files {
            if path == DEVICE_STATE || path == DROP_IN || ORIGINAL_BINDINGS.contains(&path.as_str())
            {
                continue;
            }
            same_input(&i, &raw)?;
            inactive(&i, true)?;
            lease.verify_inet(&inet)?;
            remove_one(Path::new(path), pin)?;
        }
        let mut ordered = dirs.directories.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        for (path, pin) in ordered {
            if exists(path)? {
                store::remove_empty_exact(path, pin)?;
            }
        }
        advance(archive, &mut index, &mut row, Phase::PayloadRemoved, None)?;
    }
    if row.phase == Phase::PayloadRemoved {
        verify_archive(archive, &row)?;
        same_input(&i, &raw)?;
        inactive(&i, true)?;
        for path in [PROFILE, STATE, INSTALL_INTENT] {
            absent(&Path::new(DIR).join(path))?;
        }
        absent(Path::new(RECOVERY_HELPER))?;
        absent(Path::new(DROP_IN))?;
        absent(Path::new(NATIVE))?;
        native::quiet_archived(r, &i.endpoints, &i.profile.role.executable_sha256, &saved)?;
        if native::super_selected_exists()? {
            lease.delete_selected_last(&i.profile.policy, r, &i.endpoints, &inet, || {
                same_input(&i, &raw)?;
                inactive(&i, true)?;
                verify_marker(archive, marker)?;
                verify_archive(archive, &row)?;
                native::quiet_archived(r, &i.endpoints, &i.profile.role.executable_sha256, &saved)
            })?;
        }
        lease.verify_inet(&inet)?;
        advance(archive, &mut index, &mut row, Phase::GateRemoved, None)?;
    }
    if row.phase == Phase::GateRemoved {
        same_input(&i, &raw)?;
        inactive(&i, true)?;
        need(!native::super_selected_exists()?)?;
        lease.verify_inet(&inet)?;
        native::quiet_archived(r, &i.endpoints, &i.profile.role.executable_sha256, &saved)?;
        verify_archive(archive, &row)?;
        advance(archive, &mut index, &mut row, Phase::Complete, None)?;
    }
    need(row.phase == Phase::Complete)?;
    need(!native::super_selected_exists()?)?;
    lease.verify_inet(&inet)?;
    inactive(&i, true)?;
    let markerfile = store::open_public(&Path::new(DIR).join(TEARDOWN), 65536)?;
    let m: Marker = serde_json::from_value(parse_unique_public_metadata(&markerfile.bytes)?)
        .map_err(|_| refused())?;
    need(
        markerfile.pin == live_marker.pin
            && markerfile.bytes == json_bytes(marker)?
            && m.token == marker.token
            && m.initial_record_sha256 == marker.initial_record_sha256,
    )?;
    store::remove_exact(&markerfile)?;
    println!(
        "{}",
        json!({"schema":"aegis_selected_teardown_terminal_v1","status":"PASS_OWNED_SOURCE_OPERATION_ONLY","archive":archive.directory,"original_inet_guard_armed_blocked":true,"selected_profile_admission_absent":true,"installed_lifecycle_acceptance":false,"physical_quiet_capture_verified":false})
    );
    Ok(())
}
/// Re-read the complete retained chain. This returns metadata, never authority.
pub(super) fn completed_record(archive: &Archive, token: &str) -> io::Result<TeardownRecord> {
    let first = store::open_public(&archive.directory.join("00000000-phase.json"), 2 * 1048576)?;
    let row: TeardownRecord = serde_json::from_value(
        aegis_core::relay_geneva::recovery::parse_unique_public_metadata_bounded(
            &first.bytes,
            2 * 1048576,
        )?,
    )
    .map_err(|_| refused())?;
    row.validate()?;
    need(row.source == source()? && row.token == token)?;
    let marker = Marker {
        schema: "aegis_selected_teardown_marker_v1".into(),
        token: token.into(),
        source: source()?.into(),
        initial_record_sha256: first.pin.sha256,
        profile_sha256: row.profile_sha256,
    };
    let (_, last) = load_phases(archive, &marker)?;
    let ap = archive.identity()?;
    super::verify_teardown::completed_metadata(&last, source()?, token, ap.device, ap.inode)?;
    verify_marker(archive, &marker)?;
    verify_archive(archive, &last)?;
    Ok(last)
}

pub(super) fn run(resume_token: Option<&str>) -> io::Result<()> {
    let markerpath = Path::new(DIR).join(TEARDOWN);
    if !exists(&markerpath)? {
        if let Some(token) = resume_token {
            let archive = Archive::existing(Path::new(HISTORY), token)?;
            let first =
                store::open_public(&archive.directory.join("00000000-phase.json"), 2 * 1048576)?;
            let row: TeardownRecord = serde_json::from_value(
                aegis_core::relay_geneva::recovery::parse_unique_public_metadata_bounded(
                    &first.bytes,
                    2 * 1048576,
                )?,
            )
            .map_err(|_| refused())?;
            row.validate()?;
            need(row.source == source()? && row.token == token)?;
            let marker = Marker {
                schema: "aegis_selected_teardown_marker_v1".into(),
                token: token.into(),
                source: source()?.into(),
                initial_record_sha256: first.pin.sha256,
                profile_sha256: row.profile_sha256,
            };
            let (_, last) = load_phases(&archive, &marker)?;
            let ap = archive.identity()?;
            need(
                last.phase == Phase::Complete
                    && ap.device == last.archive_device
                    && ap.inode == last.archive_inode,
            )?;
            verify_marker(&archive, &marker)?;
            verify_archive(&archive, &last)?;
            println!(
                "{}",
                json!({"schema":"aegis_selected_teardown_historical_resume_v1","status":"ALREADY_COMPLETED_RECORD_ONLY","archive":archive.directory,"source":source()?,"fresh_kernel_or_unit_acceptance":false,"installed_lifecycle_acceptance":false})
            );
            return Ok(());
        }
    }
    let (archive, marker) = if exists(&markerpath)? {
        let marker: Marker = serde_json::from_value(parse_unique_public_metadata(
            crate::profile::read_install_metadata(&markerpath)?.as_bytes(),
        )?)
        .map_err(|_| refused())?;
        need(
            marker.schema == "aegis_selected_teardown_marker_v1"
                && marker.source == source()?
                && resume_token.is_none_or(|t| t == marker.token),
        )?;
        (
            Archive::existing(Path::new(HISTORY), &marker.token)?,
            marker,
        )
    } else {
        let raw = crate::profile::read_install_metadata(&Path::new(DIR).join(PROFILE))?;
        let i = input_profile(raw.clone(), true)?;
        inactive(&i, false)?;
        need(optional::<GuardTransitionIntent>(INTENT)?.is_none())?;
        let intent: InstallIntent = read(INSTALL_INTENT)?;
        need(
            intent.schema == "aegis_relay_geneva_install_intent_v1"
                && intent.source == source()?
                && intent.manifest_sha256 == hex::encode(i.profile_bytes_sha256)
                && intent.recovery_helper_sha256 == i.profile.recovery_helper_sha256
                && i.profile
                    .role
                    .drop_in_paths_to_sha256
                    .get(Path::new(DROP_IN))
                    == Some(&intent.drop_in_sha256)
                && intent.drop_in_path == DROP_IN
                && intent.helper_path == RECOVERY_HELPER
                && intent.initial_service_stopped
                && intent.initial_files_absent,
        )?;
        let state: OwnedGuardState = read(STATE)?;
        need(
            state.schema == "aegis_relay_geneva_guard_state_v1"
                && state.policy_sha256 == hex::encode(i.profile.policy.digest()?)
                && state.table_present
                && state.active_binding.is_none(),
        )?;
        let r = request(&i)?;
        let inet = DeviceBlockPolicy::from_state(&crate::profile::read_install_metadata(
            Path::new(DEVICE_STATE),
        )?)?;
        let lease = native::GuardLease::acquire()?;
        inactive(&i, false)?;
        lease.selected_block(&i.profile.policy, r, &i.endpoints)?;
        let (initial_original_inet_digest, manager_context) =
            initial_context(&i, &raw, &lease, &inet)?;
        let original_inet_digest = inet.verify(&inet.expected())?;
        let token = format!("{:032x}", rand::random::<u128>());
        let archive = Archive::create(Path::new(HISTORY), &token)?;
        let setup = (|| -> io::Result<Marker> {
            let (files, dirs) = capture(&i)?;
            let dirsbytes = json_bytes(&dirs)?;
            let archivepin = archive.identity()?;
            let row = TeardownRecord {
                schema: "aegis_selected_teardown_v1".into(),
                token: token.clone(),
                source: source()?.into(),
                phase: Phase::Intent,
                profile_sha256: hex::encode(i.profile_bytes_sha256),
                directory_manifest_sha256: hex::encode(Sha256::digest(&dirsbytes)),
                archive_device: archivepin.device,
                archive_inode: archivepin.inode,
                archive_manifest_sha256: None,
                original_inet_digest: hex::encode(original_inet_digest),
                initial_original_inet_digest: hex::encode(initial_original_inet_digest),
                initial_manager_identity_sha256: manager_context
                    .as_ref()
                    .map(|m| m.proof.digest().to_owned()),
                initial_manager_binding_sha256: manager_context
                    .as_ref()
                    .map(|m| m.file.pin.sha256.clone()),
                selected_netdev_digest: hex::encode(
                    aegis_core::relay_geneva::installed_guard::canonical_table_digest(
                        &aegis_core::relay_geneva::installed_guard::expected(
                            &i.profile.policy,
                            None,
                        )?,
                    )?,
                ),
                owned_files: files
                    .iter()
                    .map(|(n, f)| (n.clone(), f.pin.clone()))
                    .collect(),
            };
            archive.write_extra("directories.json", &dirsbytes)?;
            archive.append(0, &row)?;
            let initial =
                store::open_public(&archive.directory.join("00000000-phase.json"), 2 * 1048576)?;
            let marker = Marker {
                schema: "aegis_selected_teardown_marker_v1".into(),
                token,
                source: source()?.into(),
                initial_record_sha256: initial.pin.sha256,
                profile_sha256: row.profile_sha256.clone(),
            };
            let markerbytes = json_bytes(&marker)?;
            archive.write_extra("teardown-marker.json", &markerbytes)?;
            crate::profile::write_relay_geneva_record(TEARDOWN, &text(markerbytes)?)?;
            Ok(marker)
        })();
        let marker = match setup {
            Ok(marker) => marker,
            Err(e) => {
                let stamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| refused())?
                    .as_nanos();
                archive.write_extra(&format!("setup-failure-{stamp}.json"), &json_bytes(&json!({"schema":"aegis_selected_teardown_setup_failure_v1","status":"FAIL_BEFORE_SELECTED_MUTATION","source":source()?,"archive":archive.directory,"selected_resources_retained":true,"installed_lifecycle_acceptance":false}))?)?;
                return Err(e);
            }
        };
        drop(lease);
        (archive, marker)
    };
    let result = run_owned(&archive, &marker);
    if result.is_err() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused())?
            .as_nanos();
        let failure = json!({"schema":"aegis_selected_teardown_failure_v1","status":"FAIL_OWNED_TEARDOWN_PENDING","source":source()?,"token":marker.token,"original_and_selected_guard_state_requires_fresh_inspection":true,"installed_lifecycle_acceptance":false});
        archive.write_extra(&format!("failure-{stamp}.json"), &json_bytes(&failure)?)?;
    }
    result
}
