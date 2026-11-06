//! Guarded Linux administrative AUTO transaction backend.
//! Selected bytes are captured/rendered once; later phases retain protected stage
//! generations and publication receipts. This includes unit publication/reload
//! and observation of an already active service; installer integration is pending.
use super::{
    authority::{Manifest, ReferenceBinding, SourceBinding, StageGuard},
    digest,
    durable::Store,
    AutoMode, Header, Leaves, Phase, Result, MAX_STAGE,
};
use crate::profile_auto_capture::InputRole;
use crate::profile_auto_prepare::{self as prepare, PreparedInputs, Role};
use crate::profile_auto_publication::linux as publisher;
use crate::profile_auto_render::PreparedRender;
use crate::profile_auto_transaction_cli::{
    CommandArgs, InspectField, PrepareArgs, ServiceUser, VerifyPhase,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[path = "profile_auto_activation.rs"]
mod activation;
#[path = "profile_auto_active_service.rs"]
mod active_service;

fn fail<T>(_: T) -> String {
    super::refuse()
}
const CAPTURE_FAILURE_PREFIX: &str = "AUTO authenticated capture refusal:";
const BEGIN_CAPTURE_STEP_PREFIX: &str = "AUTO begin capture step:";
const BEGIN_CAPTURE_STEPS: &[&str] = &[
    "stage_reopen",
    "stage_admit",
    "recipe_restore",
    "installed_facts",
    "publication_verify",
    "policy_prepare",
    "manager_identity",
    "terminal_configure",
    "terminal_recover_incomplete",
    "terminal_prepare",
    "guard_handoff",
    "launch_register",
    "pid1_start",
    "launch_prove",
    "launch_record",
    "capture_precheck",
    "capture_ready",
    "capture_revalidate",
    "capture_mark",
    "terminal_activate",
];
const BIND_RUNTIME_STEP_PREFIX: &str = "AUTO bind runtime step:";
/// Closed BindRuntimeService refusal coordinates (worker, handler,
/// unit_store::prepare_policy and the policy compiler). The installer
/// coordinator admits exactly this list.
const BIND_RUNTIME_STEPS: &[&str] = &[
    "worker_pin_before",
    "dispatch",
    "worker_pin_after",
    "bind_stage_state",
    "bind_originals",
    "bind_settings",
    "bind_runtime_policy",
    "bind_resolve",
    "bind_reference_owner",
    "bind_service_user",
    "bind_account_generation",
    "bind_header_persist",
    "bind_resolve_again",
    "bind_binding_equal",
    "bind_account_generation_again",
    "policy_stage_current",
    "policy_stage_state",
    "policy_binding",
    "policy_inputs",
    "policy_inputs_record",
    "policy_templates",
    "policy_namespace",
    "policy_original_leaves",
    "policy_dropins_capture",
    "policy_render",
    "policy_runtime_mode",
    "policy_first_arm",
    "policy_recipe_build",
    "policy_postflight",
    "policy_recipe_write",
    "policy_compile_template",
    "policy_compile_identity_mode",
    "policy_compile_dropin_bounds",
    "policy_compile_boot_gate",
    "policy_compile_unit_template",
    "policy_compile_unit_render",
    "policy_compile_fulltun_dropin_name",
    "policy_compile_first_arm_dropins",
    "policy_compile_guard_hook_missing",
    "policy_compile_guard_hook_unrecognized",
    "policy_compile_fulltun_unit_shape",
    "policy_compile_first_arm_entry",
    "policy_compile_other",
];

/// Only the generic refusal is typed. Every classified worker error
/// (recovery, owner, projection, reload) keeps its exact text and reason.
fn bind_runtime_step_error(step: &'static str, error: String) -> String {
    debug_assert!(BIND_RUNTIME_STEPS.contains(&step));
    if error == super::refuse() && BIND_RUNTIME_STEPS.contains(&step) {
        format!("{BIND_RUNTIME_STEP_PREFIX}{step}")
    } else {
        error
    }
}

fn bind_runtime_step_response(error: &str) -> Option<serde_json::Value> {
    let step = error.strip_prefix(BIND_RUNTIME_STEP_PREFIX)?;
    if !BIND_RUNTIME_STEPS.contains(&step) {
        return None;
    }
    Some(serde_json::json!({"status":"error","reason":"phase_refused","bind_runtime_step":step}))
}

fn capture_failure_diagnostic(error: &str) -> Option<serde_json::Value> {
    let mut fields = error.strip_prefix(CAPTURE_FAILURE_PREFIX)?.split(':');
    let reason = fields.next()?;
    let source = fields.next()?;
    let line_text = fields.next()?;
    if fields.next().is_some()
        || !matches!(
            reason,
            "refused"
                | "timeout"
                | "os_error"
                | "value_error"
                | "subprocess_error"
                | "runtime_error"
                | "unexpected_exception"
        )
        || !matches!(
            source,
            "unknown"
                | "guardian"
                | "witness"
                | "topology"
                | "rollback"
                | "policy"
                | "endpoint"
                | "capture"
                | "capture_topology"
        )
    {
        return None;
    }
    let line = line_text.parse::<u32>().ok()?;
    if line.to_string() != line_text
        || !((source == "unknown" && line == 0)
            || (source != "unknown" && (1..=10_000).contains(&line)))
    {
        return None;
    }
    Some(serde_json::json!({"reason":reason,"source":source,"line":line}))
}

fn begin_capture_step_error(step: &'static str, error: String) -> String {
    debug_assert!(BEGIN_CAPTURE_STEPS.contains(&step));
    if step == "capture_ready" {
        if let Some(coordinate) = capture_failure_diagnostic(&error) {
            return format!(
                "{BEGIN_CAPTURE_STEP_PREFIX}{step}:capture:{}:{}:{}",
                coordinate["reason"].as_str().unwrap_or("unknown"),
                coordinate["source"].as_str().unwrap_or("unknown"),
                coordinate["line"].as_u64().unwrap_or(0),
            );
        }
    }
    if step == "pid1_start" {
        if let Some(diagnostic) =
            crate::profile_auto_stopped_service::pid1::start_failure_diagnostic(&error)
        {
            return format!(
                "{BEGIN_CAPTURE_STEP_PREFIX}{step}:pid1:{}:{}:{}",
                diagnostic["phase"].as_str().unwrap_or("unknown"),
                diagnostic["cause"].as_str().unwrap_or("unknown"),
                diagnostic["errno"].as_u64().unwrap_or(0),
            );
        }
    }
    let reason = match error.as_str() {
        ACTIVATION_RECOVERY_REQUIRED => "native_recovery_required",
        ACTIVATION_OWNER_UNAVAILABLE => "activation_owner_unavailable",
        PROJECTION_SEMANTICS_CHANGED => "projection_semantics_changed",
        _ => "phase_refused",
    };
    format!("{BEGIN_CAPTURE_STEP_PREFIX}{step}:{reason}")
}

fn begin_capture_step_response(error: &str) -> Option<serde_json::Value> {
    let fields: Vec<&str> = error
        .strip_prefix(BEGIN_CAPTURE_STEP_PREFIX)?
        .split(':')
        .collect();
    let step = *fields.first()?;
    if !BEGIN_CAPTURE_STEPS.contains(&step) {
        return None;
    }
    let mut value = match fields.as_slice() {
        [_, "phase_refused"] => serde_json::json!({"status":"error","reason":"phase_refused"}),
        [_, "native_recovery_required"] => {
            serde_json::json!({"status":"error","reason":"native_recovery_required"})
        }
        [_, "activation_owner_unavailable"] => {
            serde_json::json!({"status":"error","reason":"activation_owner_unavailable"})
        }
        [_, "projection_semantics_changed"] => {
            serde_json::json!({"status":"error","reason":"projection_semantics_changed"})
        }
        [_, "capture", reason, source, line] if step == "capture_ready" => {
            let nested = format!("{CAPTURE_FAILURE_PREFIX}{reason}:{source}:{line}");
            let coordinate = capture_failure_diagnostic(&nested)?;
            serde_json::json!({"status":"error","reason":"phase_refused",
                               "capture_refusal":coordinate})
        }
        [_, "pid1", phase, cause, errno] if step == "pid1_start" => {
            let nested = format!("AUTO PID1 start requires recovery:{phase}:{cause}:{errno}");
            let diagnostic =
                crate::profile_auto_stopped_service::pid1::start_failure_diagnostic(&nested)?;
            serde_json::json!({"status":"error","reason":"native_recovery_required",
                               "diagnostic":diagnostic})
        }
        _ => return None,
    };
    value["begin_capture_step"] = serde_json::json!(step);
    Some(value)
}

fn worker_pin_failure(step: &'static str, command: &CommandArgs) -> String {
    debug_assert!(matches!(step, "worker_pin_before" | "worker_pin_after"));
    let refusal = super::refuse();
    if matches!(
        command,
        CommandArgs::BindRuntimeService { .. } | CommandArgs::BeginCapture { .. }
    ) {
        bind_runtime_step_error(step, refusal)
    } else {
        refusal
    }
}
fn key(role: Role) -> String {
    match role {
        Role::Config => "config".into(),
        Role::StateTarget => "state".into(),
        Role::StateSource => "prior-state".into(),
        Role::AdministratorMetadata => "metadata".into(),
        Role::BundleMain => "bundle-main".into(),
        Role::BundleCa => "bundle-ca".into(),
        Role::BundleSupplementary => "bundle-supplementary".into(),
        Role::BundleMasque => "bundle-masque".into(),
        Role::Reference(i) => format!("reference-{i}"),
    }
}
fn role_name(role: Role) -> String {
    if matches!(role, Role::Reference(_)) {
        "reference".into()
    } else {
        key(role)
    }
}
fn mode(s: &str) -> Result<AutoMode> {
    match s {
        "socks-only" => Ok(AutoMode::SocksOnly),
        "wide-redirect-safe" => Ok(AutoMode::WideRedirectSafe),
        "full-wide-tun" => Ok(AutoMode::FullWideTun),
        _ => Err(super::refuse()),
    }
}
fn insert(
    files: &mut BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    path: PathBuf,
    bytes: Vec<u8>,
) -> Result<()> {
    if !super::relative(&path)
        || bytes.len() > super::leaf_bound(&path)
        || files.insert(path, Zeroizing::new(bytes)).is_some()
    {
        return Err(super::refuse());
    }
    Ok(())
}
/// The second bounded recipe is reserved before any custody/native action so a
/// final whole-document DNS-format projection cannot predictably exhaust stage.
fn check_aggregate(files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>, recipe_len: usize) -> Result<()> {
    let total = files
        .values()
        .try_fold(recipe_len, |sum, b| sum.checked_add(b.len()))
        .ok_or_else(super::refuse)?;
    if files.len() > super::MAX_LEAVES || total > MAX_STAGE {
        return Err(super::refuse());
    }
    Ok(())
}
pub(super) fn seal(
    parent: &Path,
    prepared: &PreparedInputs,
    service_uid: u32,
    operator_uid: u32,
    bundle: Option<PathBuf>,
    runtime_events: &Path,
    handoff: Option<(
        &crate::profile_auto_stopped_service::InstallLock,
        &Path,
        &Path,
        &Path,
        Option<&str>,
    )>,
) -> Result<PathBuf> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(super::refuse());
    }
    prepared.revalidate_originals().map_err(fail)?;
    let mut files = BTreeMap::new();
    let mut old = Leaves::new();
    let mut accepted = Leaves::new();
    for (side, trees, leaves) in [
        ("input", &prepared.raw, &mut old),
        ("accepted", &prepared.accepted, &mut accepted),
    ] {
        for (role, tree) in trees {
            let name = key(*role);
            for (leaf, bytes) in &tree.files {
                let logical = PathBuf::from(&name).join(leaf);
                leaves.insert(logical, bytes.to_vec())?;
                insert(
                    &mut files,
                    PathBuf::from(format!("{side}/payload/{name}")).join(leaf),
                    bytes.to_vec(),
                )?;
            }
            insert(
                &mut files,
                PathBuf::from(format!("{side}/directories/{name}.json")),
                serde_json::to_vec(&tree.directories).map_err(fail)?,
            )?;
        }
    }
    let mut sources = Vec::new();
    for (role, record) in &prepared.original_generations {
        let generation_leaf = PathBuf::from(format!("input/generations/{}.json", key(*role)));
        insert(
            &mut files,
            generation_leaf.clone(),
            serde_json::to_vec(record).map_err(fail)?,
        )?;
        let witness = if matches!(
            role,
            Role::Config | Role::StateTarget | Role::AdministratorMetadata
        ) && record.kind() == 0
        {
            // Publication metadata belongs to the SAME admitted original
            // capture. Root snapshot checks surround this inspection; an
            // absent original has no witness and keeps its absence proof.
            prepared.revalidate_originals().map_err(fail)?;
            let target = publisher::Target::open(record.original_source()).map_err(fail)?;
            let generation = target.inspect().map_err(fail)?.ok_or_else(super::refuse)?;
            prepared.revalidate_originals().map_err(fail)?;
            let leaf = PathBuf::from(format!("input/publication-witnesses/{}.json", key(*role)));
            insert(
                &mut files,
                leaf.clone(),
                generation.witness().map_err(fail)?,
            )?;
            Some(leaf)
        } else {
            None
        };
        sources.push(SourceBinding {
            role: role_name(*role),
            original_path: record.original_source().to_path_buf(),
            generation_leaf,
            publication_witness_leaf: witness,
        });
    }
    let mut references = Vec::new();
    for (role, source) in &prepared.original_reference_map {
        let Role::Reference(index) = role else {
            return Err(super::refuse());
        };
        let record = prepared
            .original_generations
            .get(role)
            .ok_or_else(super::refuse)?;
        let raw = prepared.raw.get(role).ok_or_else(super::refuse)?;
        if raw.files.len() != 1 {
            return Err(super::refuse());
        }
        let bytes = raw.files.values().next().ok_or_else(super::refuse)?;
        let stage_bytes = PathBuf::from(format!("input/references/{index:04}/bytes"));
        insert(&mut files, stage_bytes.clone(), bytes.to_vec())?;
        let expected_uid = match record.role() {
            InputRole::PrivateCredential { expected_uid } => Some(expected_uid),
            _ => None,
        };
        references.push(ReferenceBinding {
            stage_bytes,
            generation_leaf: PathBuf::from(format!("input/generations/{}.json", key(*role))),
            original_path: source.clone(),
            final_path: prepared
                .final_reference_map
                .get(role)
                .ok_or_else(super::refuse)?
                .clone(),
            expected_uid,
        });
    }
    // BTree role order preserves numeric references; fixed staging indexes are
    // checked by Manifest admission and not caller-selected filenames.
    if let Some(tree) = prepared.raw.get(&Role::StateSource) {
        if tree.files.len() == 1 {
            insert(
                &mut files,
                "input/prior-state/bytes".into(),
                tree.files
                    .values()
                    .next()
                    .ok_or_else(super::refuse)?
                    .to_vec(),
            )?;
        }
    }
    let recipe = prepared.rendered.export_private_recipe().map_err(fail)?;
    let recipe_len = recipe.len();
    insert(
        &mut files,
        "accepted/render-recipe.json".into(),
        recipe.to_vec(),
    )?;
    let manifest = Manifest {
        schema: 1,
        config_root: prepared.targets.config.clone(),
        state_dir: prepared.targets.state.clone(),
        metadata_dir: prepared.targets.metadata.clone(),
        service_uid,
        operator_uid,
        logical_bundle: if prepared.is_upgrade { None } else { bundle },
        render_context: prepared.rendered.context.clone(),
        sources,
        references,
    };
    insert(
        &mut files,
        "input/authority.json".into(),
        serde_json::to_vec(&manifest).map_err(fail)?,
    )?;
    check_aggregate(&files, recipe_len)?;
    let header = Header {
        protocol: super::PROTOCOL.into(),
        administrator_uid: 0,
        config_root: prepared.targets.config.clone(),
        state_dir: prepared.targets.state.clone(),
        metadata_dir: prepared.targets.metadata.clone(),
        phase: Phase::Prepared,
        transaction_nonce: hex::encode(rand::random::<[u8; 16]>()),
        current_records: BTreeMap::new(),
        active_records: BTreeMap::new(),
        pending: None,
        mode: mode(&prepared.mode)?,
        plan: prepared.plan.clone(),
        old_unit_namespace: None,
        new_unit_namespace: None,
        runtime_events: runtime_events.to_path_buf(),
        unit_policy_recipe: None,
        unit_records: BTreeMap::new(),
        unit_role_records: BTreeMap::new(),
        unit_pending: None,
        unit_forward_transitions: BTreeMap::new(),
        unit_restorations: BTreeMap::new(),
        unit_restored_manager: None,
        runtime_binding: None,
        installed_receipt_recipe: None,
        service_uid: None,
        service_gid: None,
        state_records: BTreeMap::new(),
        namespace_records: BTreeMap::new(),
        service_was_active: None,
        capture_started: false,
        leaves: files.iter().map(|(p, b)| (p.clone(), digest(b))).collect(),
        input_generation: old.generation(b"aegis-auto-original-v1\0"),
        accepted_generation: accepted.generation(b"aegis-auto-accepted-v1\0"),
        planned_generation: accepted.generation(b"aegis-auto-accepted-v1\0"),
        render_recipe: "accepted/render-recipe.json".into(),
    };
    manifest.validate(&header)?;
    header.validate(0)?;
    if serde_json::to_vec(&header).map_err(fail)?.len() > 1024 * 1024 {
        return Err(super::refuse());
    }
    prepared.revalidate_originals().map_err(fail)?;
    let store = if let Some((lock, handoff_path, candidate, public_root, boot_sha)) = handoff {
        Store::create_with_handoff(
            parent,
            0,
            lock,
            handoff_path,
            candidate,
            public_root,
            boot_sha,
        )?
    } else {
        Store::create(parent, 0)?
    };
    for (p, b) in &files {
        store.write_new(p, b)?;
    }
    store.save_header(&header)?;
    // All old receipts survive a failed admission. No active installation has
    // been stopped or changed by this unique stage creation.
    let stage = StageGuard::admit(store)?;
    stage.revalidate_originals()?;
    let _verified = PreparedRender::restore_private_recipe(&stage).map_err(fail)?;
    Ok(stage.store.path().to_path_buf())
}

pub(super) fn inspect(stage: &StageGuard, field: InspectField) -> Result<String> {
    let result = match field {
        InspectField::RuntimeServicePolicy => {
            let rendered = PreparedRender::restore_private_recipe(stage).map_err(fail)?;
            let settings: aegis_core::Settings =
                toml::from_str(&rendered.config.bytes).map_err(fail)?;
            let policy =
                crate::profile_auto_runtime_identity::runtime_policy(stage.header.mode, &settings)
                    .map_err(fail)?;
            match policy {
                crate::profile_auto_runtime_identity::RuntimePolicy::Root => "root",
                crate::profile_auto_runtime_identity::RuntimePolicy::DedicatedNone => {
                    "dedicated-none"
                }
                crate::profile_auto_runtime_identity::RuntimePolicy::DedicatedBind => {
                    "dedicated-bind"
                }
            }
            .into()
        }
        InspectField::RuntimeEventsPath => runtime_events_scalar(&stage.header.runtime_events)?,
        InspectField::ProductMode => stage.header.mode.name().to_owned(),
        InspectField::UdpPolicy => stage.header.plan["profile"]["udp_policy"]
            .as_str()
            .ok_or_else(super::refuse)?
            .into(),
        InspectField::DnsPolicy => stage.header.plan["profile"]["dns_policy"]
            .as_str()
            .ok_or_else(super::refuse)?
            .into(),
        InspectField::Ipv6Policy => stage.header.plan["profile"]["ipv6_policy"]
            .as_str()
            .ok_or_else(super::refuse)?
            .into(),
        InspectField::LeakRisk => stage.header.plan["profile"]["leak_risk"]
            .as_str()
            .ok_or_else(super::refuse)?
            .into(),
        InspectField::PlanPath => stage
            .store
            .path()
            .join("accepted/payload/metadata/auto-install-plan.json")
            .to_str()
            .ok_or_else(super::refuse)?
            .into(),
    };
    Ok(result)
}

fn resolved_runtime_events(
    requested: &Path,
    policy: crate::profile_auto_runtime_identity::RuntimePolicy,
) -> PathBuf {
    use crate::profile_auto_runtime_identity::RuntimePolicy;
    if requested != Path::new("/var/lib/aegis-client-logs/runtime/runtime-events.jsonl") {
        return requested.to_path_buf();
    }
    // Resolve the installer alias before the prepared header/handoff is
    // completed. A root runtime never takes ownership of the service log.
    PathBuf::from(match policy {
        RuntimePolicy::Root => "/var/lib/aegis-client-logs/root/runtime-events.jsonl",
        RuntimePolicy::DedicatedNone | RuntimePolicy::DedicatedBind => {
            "/var/lib/aegis-client-logs/service/runtime-events.jsonl"
        }
    })
}

fn runtime_events_scalar(path: &Path) -> Result<String> {
    let value = path.to_str().ok_or_else(super::refuse)?;
    if !crate::profile_auto_transaction_cli::fixed_runtime_events(value) {
        return Err(super::refuse());
    }
    Ok(value.to_owned())
}

pub(super) fn prepare(
    args: PrepareArgs,
    lock: Option<&crate::profile_auto_stopped_service::InstallLock>,
) -> Result<PathBuf> {
    let handoff = args.prepare_handoff.as_deref();
    if handoff.is_some() != lock.is_some()
        || handoff
            .is_some_and(|p| p != Path::new("/var/lib/aegis-auto/control/prepare-current.json"))
    {
        return Err(super::refuse());
    }
    if let Some(lock) = lock {
        lock.revalidate().map_err(fail)?;
        super::installer_v2_generation::verify_prepare_source(
            &args.public_payload_root,
            &args.candidate_binary,
            lock,
        )?;
    }
    if args.boot_successor && lock.is_none() {
        return Err(super::refuse());
    }
    let boot_sha = if args.boot_successor {
        Some(
            super::installer_v2_generation::verified_boot_prepare_intent(
                &args.public_payload_root,
                &args.candidate_binary,
                lock.ok_or_else(super::refuse)?,
            )?,
        )
    } else {
        None
    };
    let (request, admission) = super::prepare_admission::prepare_request(&args)?;
    let service_uid = request.service_uid;
    let operator_uid = request.operator_uid;
    let bundle = request.bundle.clone();
    let prepared = prepare::prepare(request).map_err(fail)?;
    admission.revalidate_after_prepare(&prepared)?;
    let runtime_events = if args.runtime_events
        == Path::new("/var/lib/aegis-client-logs/runtime/runtime-events.jsonl")
    {
        let settings: aegis_core::Settings =
            toml::from_str(&prepared.rendered.config.bytes).map_err(fail)?;
        let policy =
            crate::profile_auto_runtime_identity::runtime_policy(mode(&prepared.mode)?, &settings)
                .map_err(fail)?;
        resolved_runtime_events(&args.runtime_events, policy)
    } else {
        args.runtime_events.clone()
    };
    let path = seal(
        &args.staging_parent,
        &prepared,
        service_uid,
        operator_uid,
        bundle,
        &runtime_events,
        lock.zip(handoff).map(|(lock, handoff)| {
            (
                lock,
                handoff,
                args.candidate_binary.as_path(),
                args.public_payload_root.as_path(),
                boot_sha.as_deref(),
            )
        }),
    )?;
    let mut stage = StageGuard::admit(Store::reopen(&path, 0)?)?;
    super::receipt_store::admit_prepare(
        &mut stage,
        super::receipt_store::PrepareInputs {
            public_payload_root: &args.public_payload_root,
            candidate_binary: &args.candidate_binary,
            installed_binary: &args.installed_binary,
            source_manifest_url: args.source_manifest_url.as_deref(),
            source_release_channel: args.source_release_channel.as_deref(),
        },
    )?;
    if let (Some(lock), Some(handoff)) = (lock, handoff) {
        Store::complete_handoff(&stage, lock, handoff)?;
        lock.revalidate().map_err(fail)?;
    }
    Ok(path)
}
fn stage_path(args: &CommandArgs) -> &Path {
    match args {
        CommandArgs::BindRuntimeService { stage, .. }
        | CommandArgs::Inspect { stage, .. }
        | CommandArgs::Verify { stage, .. }
        | CommandArgs::CommitCustody { stage, .. }
        | CommandArgs::CommitState { stage }
        | CommandArgs::CommitConfig { stage }
        | CommandArgs::SealInstallReceipt { stage }
        | CommandArgs::PublishServicePolicy { stage }
        | CommandArgs::ReloadServicePolicy { stage }
        | CommandArgs::PublishMetadata { stage }
        | CommandArgs::BeginCapture { stage }
        | CommandArgs::Finalize { stage }
        | CommandArgs::Rollback { stage, .. } => stage,
    }
}
fn service_identity(user: ServiceUser) -> Result<(u32, u32)> {
    let identity =
        crate::profile_auto_runtime_identity::resolve_custody_identity(user).map_err(fail)?;
    Ok((identity.uid(), identity.gid()))
}
pub(super) fn command(args: CommandArgs) -> Result<Option<String>> {
    // Direct entry may inspect/admit read-only facts; mutations belong to the
    // one worker retaining the actual exclusive install lock across phases.
    if !matches!(
        args,
        CommandArgs::Inspect { .. }
            | CommandArgs::Verify {
                phase: VerifyPhase::BeforeCustody,
                ..
            }
    ) {
        return Err(super::refuse());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(super::refuse());
    }
    let stage = StageGuard::admit(Store::reopen(stage_path(&args), 0)?)?;
    // Direct inspection has no mutating authority. Still admit the exact
    // protected render recipe before reading any stage-dependent fact.
    let _rendered = PreparedRender::restore_private_recipe(&stage).map_err(fail)?;
    match args {
        CommandArgs::Inspect { field, .. } => inspect(&stage, field).map(Some),
        CommandArgs::Verify {
            phase: VerifyPhase::BeforeCustody,
            ..
        } => {
            if stage.header.phase != Phase::Prepared || stage.header.pending.is_some() {
                return Err(super::refuse());
            }
            stage.revalidate_originals()?;
            super::receipt_store::revalidate_inputs(&stage)?;
            Ok(None)
        }
        _ => Err(super::refuse()),
    }
}
// Direct command dispatch cannot own a systemd start. The original worker
// enters `activation::Session` for BeginCapture/Finalize and keeps its stage,
// installation, manager, and native fences until terminal handling. READY
// alone never grants this path; direct callers still fail before mutation.
const ACTIVATION_OWNER_UNAVAILABLE: &str = "AUTO finalization requires transaction-owned systemd job, invocation and enablement compensation; private stage retained";
const ACTIVATION_RECOVERY_REQUIRED: &str =
    "AUTO activation marker or stage admission uncertain; private stage retained for recovery";
const PROJECTION_SEMANTICS_CHANGED: &str =
    "AUTO formatter changed complete accepted configuration semantics; no projection receipt";
fn admit_worker_stage(stage: &Path) -> Result<StageGuard> {
    let store =
        Store::reopen_for_worker(stage, 0).map_err(|_| ACTIVATION_RECOVERY_REQUIRED.to_owned())?;
    StageGuard::admit(store).map_err(|_| ACTIVATION_RECOVERY_REQUIRED.to_owned())
}
fn require_activation_authority(args: &CommandArgs) -> Result<()> {
    match args {
        CommandArgs::BeginCapture { .. } => Err("AUTO native capture requires actual native capture/guard readiness; private stage retained".into()),
        CommandArgs::Finalize { .. } => Err(ACTIVATION_OWNER_UNAVAILABLE.into()),
        _ => Ok(()),
    }
}

fn command_with_lock(
    args: CommandArgs,
    lock: &crate::profile_auto_stopped_service::InstallLock,
) -> Result<Option<String>> {
    // The mutating dispatcher cannot be called without a real retained
    // InstallLock. Recovery takes precedence over activation refusal.
    Store::marker_preflight_for_worker(stage_path(&args), 0)
        .map_err(|_| ACTIVATION_RECOVERY_REQUIRED.to_owned())?;
    require_activation_authority(&args)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(super::refuse());
    }
    // Reprove the exact worker-owned flock before every stage admission.
    lock.revalidate().map_err(fail)?;
    let mut stage = admit_worker_stage(stage_path(&args))?;
    // A complete private render recipe must be admitted before ANY active
    // mutation, even inspect-independent commands. Restore never reparses or
    // reopens an original selected secret generation.
    let mut rendered = PreparedRender::restore_private_recipe(&stage).map_err(fail)?;
    if let CommandArgs::Inspect { field, .. } = args {
        return inspect(&stage, field).map(Some);
    }
    if let CommandArgs::Verify {
        phase: VerifyPhase::BeforeCustody,
        ..
    } = args
    {
        if stage.header.phase != Phase::Prepared || stage.header.pending.is_some() {
            return Err(super::refuse());
        }
        stage.revalidate_originals()?;
        super::receipt_store::revalidate_inputs(&stage)?;
        return Ok(None);
    }
    // Keep the whole worker command, including unit/dropin publication and
    // receipt persistence, outside the recovery-only activation seal. The
    // per-publisher leases below narrow this further for direct typed callers.
    let _publication_lease = stage.publication_lease().map_err(fail)?;
    if let CommandArgs::BindRuntimeService { service_user, .. } = &args {
        // Each step names the next check; a generic refusal leaves only that
        // closed coordinate in the bounded worker response.
        let mut step: &'static str = "bind_stage_state";
        let bound: Result<()> = (|| {
            if stage.header.phase != Phase::Prepared
                || stage.header.pending.is_some()
                || stage.header.runtime_binding.is_some()
                || stage.header.service_uid.is_some()
            {
                return Err(super::refuse());
            }
            step = "bind_originals";
            stage.revalidate_originals()?;
            step = "bind_settings";
            let settings: aegis_core::Settings =
                toml::from_str(&rendered.config.bytes).map_err(fail)?;
            step = "bind_runtime_policy";
            let policy =
                crate::profile_auto_runtime_identity::runtime_policy(stage.header.mode, &settings)
                    .map_err(fail)?;
            step = "bind_resolve";
            let binding = crate::profile_auto_runtime_identity::resolve_runtime_binding(
                *service_user,
                policy,
            )
            .map_err(fail)?;
            // External private sources cannot be silently chowned or reinterpreted
            // as readable by a different final actor. Internal copies get fresh attrs.
            step = "bind_reference_owner";
            for reference in &stage.manifest.references {
                if reference.expected_uid.is_some()
                    && !reference.final_path.starts_with(&stage.header.config_root)
                    && reference.expected_uid != Some(binding.identity().uid())
                {
                    return Err(super::refuse());
                }
            }
            step = "bind_service_user";
            if binding.identity().user() != *service_user {
                return Err(super::refuse());
            }
            step = "bind_account_generation";
            binding.revalidate_local_generation().map_err(fail)?;
            step = "bind_header_persist";
            stage.header.runtime_binding = Some(binding);
            stage.persist_header()?;
            // A separately resolved object avoids aliasing the mutable protected
            // StageGuard. Both positive account observations must agree exactly;
            // serialization is used only to compare private already-admitted facts.
            step = "bind_resolve_again";
            let policy_binding = crate::profile_auto_runtime_identity::resolve_runtime_binding(
                *service_user,
                policy,
            )
            .map_err(fail)?;
            step = "bind_binding_equal";
            if serde_json::to_vec(&policy_binding).map_err(fail)?
                != serde_json::to_vec(
                    stage
                        .header
                        .runtime_binding
                        .as_ref()
                        .ok_or_else(super::refuse)?,
                )
                .map_err(fail)?
            {
                return Err(super::refuse());
            }
            step = "bind_account_generation_again";
            policy_binding.revalidate_local_generation().map_err(fail)?;
            super::unit_store::prepare_policy(&mut stage, lock, &policy_binding, &mut step)
        })();
        return bound
            .map(|()| None)
            .map_err(|error| bind_runtime_step_error(step, error));
    }
    if let CommandArgs::CommitCustody {
        service_user,
        was_active,
        ..
    } = &args
    {
        if stage.header.phase != Phase::Prepared || stage.header.pending.is_some() {
            return Err(super::refuse());
        }
        stage
            .header
            .runtime_binding
            .as_ref()
            .ok_or_else(super::refuse)?
            .revalidate_local_generation()
            .map_err(fail)?;
        let namespace = super::unit_binding::read(&stage, false)?;
        if namespace.is_absent() && (*service_user != ServiceUser::Root || *was_active) {
            return Err(super::refuse());
        }
        let (uid, gid) = service_identity(*service_user)?;
        // Bind actual resolved local service identity before the first owned
        // publication. It cannot be overwritten by a subsequent command.
        if stage.header.service_uid.is_some()
            || stage.header.service_gid.is_some()
            || stage.header.service_was_active.is_some()
        {
            return Err(super::refuse());
        }
        stage.header.service_uid = Some(uid);
        stage.header.service_gid = Some(gid);
        stage.header.service_was_active = Some(*was_active);
        stage.persist_header()?;
    }
    if let CommandArgs::SealInstallReceipt { .. } = args {
        super::receipt_store::seal(&mut stage)?;
        return Ok(None);
    }
    let prepared_operation = match &args {
        CommandArgs::PublishMetadata { .. } => {
            Some(crate::profile_auto_stopped_service::PreparedOperation::PublishMetadata)
        }
        CommandArgs::Rollback { .. } => {
            Some(crate::profile_auto_stopped_service::PreparedOperation::StaticRollback)
        }
        CommandArgs::Verify {
            phase: VerifyPhase::BeforeActivation,
            ..
        } => Some(crate::profile_auto_stopped_service::PreparedOperation::BeforeActivation),
        _ => None,
    };
    let unit_operation = match &args {
        CommandArgs::PublishServicePolicy { .. } => {
            Some(super::store_context::UnitOperation::Publish)
        }
        CommandArgs::ReloadServicePolicy { .. } => {
            Some(super::store_context::UnitOperation::Reload)
        }
        CommandArgs::Rollback { .. } => {
            // Protected source-side intent admission chooses a recovery purpose.
            // Rollback itself never authorizes publishing a final base unit.
            if stage.header.new_unit_namespace.is_some() {
                super::unit_store::admit_accepted_manager_restoration_entry(&stage)?;
                Some(super::store_context::UnitOperation::RestoreAcceptedManager)
            } else if super::unit_store::admitted_pending_publication(&stage)?.is_some() {
                Some(super::store_context::UnitOperation::RecoverPendingPublish)
            } else {
                Some(super::store_context::UnitOperation::Rollback)
            }
        }
        _ => None,
    };
    let state_reader = super::v2_state_reader::PublishedState;
    let context = super::store_context::RootContext::from_stage_with_lock(
        stage,
        &state_reader,
        Some(lock),
        prepared_operation,
        unit_operation,
    )
    .map_err(fail)?;
    let publication =
        crate::profile_auto_runtime_publication::linux::RuntimePublication::new(&context);
    match args {
        CommandArgs::BindRuntimeService { .. } => unreachable!("binding handled before context"),
        CommandArgs::CommitCustody { .. } => context
            .stopped_phase(|| publication.commit_custody())
            .map_err(fail)?,
        CommandArgs::CommitState { .. } => context
            .stopped_phase(|| {
                crate::profile_auto_runtime_state::linux::RuntimeState::new(&context).commit()
            })
            .map_err(fail)?,
        CommandArgs::CommitConfig { .. } => context
            .stopped_phase(|| publication.commit_config())
            .map_err(fail)?,
        CommandArgs::SealInstallReceipt { .. } => unreachable!("receipt sealed before context"),
        CommandArgs::PublishServicePolicy { .. } => {
            super::unit_store::publish_policy(&context)?;
        }
        CommandArgs::ReloadServicePolicy { .. } => {
            super::unit_store::reload_and_accept_policy(&context)?;
        }
        CommandArgs::PublishMetadata { .. } => context
            .stopped_phase(|| publication.publish_metadata())
            .map_err(fail)?,
        CommandArgs::Verify {
            phase: VerifyPhase::PublishedConfig,
            ..
        } => {
            let view = publication.published_view().map_err(fail)?;
            rendered.verify_published_tree(&view).map_err(fail)?;
        }
        CommandArgs::Verify {
            phase: VerifyPhase::BeforeActivation,
            ..
        } => {
            context
                .stopped_phase(|| {
                    publication.verify_final_runtime_config()?;
                    let view = publication.published_view()?;
                    rendered.verify_published_tree(&view)?;
                    crate::profile_auto_runtime_state::linux::RuntimeState::new(&context)
                        .verify_before_activation()?;
                    super::receipt_store::verify_activation(&context.stage_cell().borrow())
                        .map_err(|_| "Administrative AUTO activation refused")?;
                    Ok(())
                })
                .map_err(fail)?;
        }
        CommandArgs::BeginCapture { .. } => {
            // Defense in depth if dispatch is later refactored: never fall
            // back to treating main-service READY as native capture proof.
            return Err(super::refuse());
        }
        CommandArgs::Finalize { .. } => {
            let mode = context.stage_cell().borrow().header.mode;
            // A recognized main READY notification certifies local workers,
            // not ownership/readiness of the separate installed native capture.
            // No protected actual capture/guard receipt exists in this cohort.
            if mode != AutoMode::SocksOnly {
                return Err("AUTO wide finalization requires actual native capture/guard readiness; private stage retained".into());
            }
            {
                let g = context.stage_cell().borrow();
                if !matches!(g.header.phase, Phase::Metadata | Phase::Finalized)
                    || g.header.pending.is_some()
                    || g.header.unit_pending.is_some()
                    || g.header.capture_started
                {
                    return Err(super::refuse());
                }
            }
            let guard = active_service::ActiveGuard::observe(&context, lock)?;
            {
                let g = context.stage_cell().borrow();
                if g.header.phase == Phase::Finalized {
                    admit_active_evidence(&g, &guard)?;
                    rendered
                        .verify_published_tree(&publication.published_view().map_err(fail)?)
                        .map_err(fail)?;
                    guard.revalidate(&context, lock)?;
                    return Ok(None);
                }
            }
            let already_projected = {
                let g = context.stage_cell().borrow();
                g.header
                    .active_records
                    .get("config")
                    .and_then(|p| g.header.current_records.get(p))
                    .is_some_and(|s| s.phase == "projection")
            };
            if already_projected {
                {
                    let g = context.stage_cell().borrow();
                    if g.header.render_recipe != Path::new("accepted/final-render-recipe.json") {
                        return Err(super::refuse());
                    }
                }
                let view = publication.published_view().map_err(fail)?;
                rendered.verify_published_tree(&view).map_err(fail)?;
            } else {
                publication
                    .finalize_projection(&mut rendered)
                    .map_err(|error| {
                        if error == "auto_render_dns_projection_semantics_changed" {
                            PROJECTION_SEMANTICS_CHANGED.to_owned()
                        } else {
                            fail(error)
                        }
                    })?;
            }
            guard.revalidate(&context, lock)?;
            let mut g = context.stage_cell().borrow_mut();
            persist_active_evidence(&mut g, &guard)?;
            if mode == AutoMode::SocksOnly {
                let recipe = rendered.export_private_recipe().map_err(fail)?;
                let leaf = PathBuf::from("accepted/final-render-recipe.json");
                g.store.write_new(&leaf, &recipe)?;
                g.header.leaves.insert(leaf.clone(), digest(&recipe));
                g.header.render_recipe = leaf;
            } else if g.header.render_recipe != Path::new("accepted/final-render-recipe.json") {
                return Err(super::refuse());
            }
            g.header.phase = Phase::Finalized;
            g.persist_header()?;
        }
        CommandArgs::Rollback {
            capture_started, ..
        } => {
            {
                let mut g = context.stage_cell().borrow_mut();
                if capture_started || g.header.capture_started {
                    g.header.capture_started = true;
                    g.header.phase = Phase::NativeRecoveryRequired;
                    g.persist_header()?;
                    return Err("AUTO capture requires separately authorized native recovery; private stage retained".into());
                }
            }
            let manager_pending = context.stage_cell().borrow().header.unit_pending.as_deref()
                == Some(Path::new(
                    "receipts/unit-target/restore-manager-intent.json",
                ));
            if manager_pending {
                // A typed completed receipt may converge its Header pointer;
                // an attempt without the receipt never replays daemon-reload.
                super::unit_store::restore_manager_and_accept(&context)?;
            } else if context.stage_cell().borrow().header.unit_pending.is_some() {
                // Even the first own rename may leave no committed role record.
                // Actual typed pending topology must be resolved before choosing
                // the rollback actor epoch; unsupported cases remain refused.
                if let Some(completion) = super::unit_store::recover_pending_policy(&context)? {
                    context
                        .finish_publication_recovery_for_rollback(completion)
                        .map_err(fail)?;
                }
            }
            if !context
                .stage_cell()
                .borrow()
                .header
                .unit_role_records
                .is_empty()
            {
                if context
                    .stage_cell()
                    .borrow()
                    .header
                    .unit_restored_manager
                    .is_none()
                {
                    super::unit_store::rollback_policy(&context)?;
                }
                if context
                    .stage_cell()
                    .borrow()
                    .header
                    .new_unit_namespace
                    .is_some()
                {
                    super::unit_store::restore_manager_and_accept(&context)?;
                }
            }
            let pending_role = context
                .stage_cell()
                .borrow()
                .header
                .pending
                .as_ref()
                .map(|(_, s)| s.role.clone());
            if let Some(role) = pending_role {
                let withdrawal = context
                    .stage_cell()
                    .borrow()
                    .header
                    .pending
                    .as_ref()
                    .is_some_and(|(p, _)| {
                        p.file_name() == Some(std::ffi::OsStr::new("withdrawal-intent.json"))
                    });
                if withdrawal {
                    context
                        .stopped_phase(|| {
                            context
                                .stage_cell()
                                .borrow_mut()
                                .recover_pending_withdrawal(&role)
                                .map_err(|_| "Administrative AUTO withdrawal recovery refused")
                        })
                        .map_err(fail)?;
                } else {
                    context
                        .stopped_phase(|| {
                            publication.recover_pending(if role == "config" {
                                Role::Config
                            } else if role == "state" {
                                Role::StateTarget
                            } else if role == "metadata" {
                                Role::AdministratorMetadata
                            } else {
                                return Err("Administrative AUTO pending role refused");
                            })
                        })
                        .map_err(fail)?;
                }
            }
            let state_status = {
                let g = context.stage_cell().borrow();
                g.header
                    .active_records
                    .get("state")
                    .and_then(|p| g.header.current_records.get(p))
                    .map(|s| s.phase.clone())
            };
            if let Some(state_phase) = state_status {
                context.stopped_phase(|| {
                    if state_phase=="rollback" {
                        // Completed protected rollback is verified, not swapped a
                        // second time. A foreign/replaced generation still refuses.
                        let admitted=crate::profile_auto_runtime_publication::linux::Context::authenticated_current_receipt(&context,Role::StateTarget)?;
                        let target=crate::profile_auto_publication::linux::Target::open(crate::profile_auto_runtime_publication::linux::Context::sealed_target(&context,Role::StateTarget)?)?;
                        crate::profile_auto_publication::linux::reopen_own_receipt(&target,&admitted)?;
                        Ok(())
                    } else if state_phase=="state" {
                        crate::profile_auto_runtime_state::linux::RuntimeState::new(&context).rollback()
                    } else {Err("Administrative AUTO state rollback refused")}
                }).map_err(fail)?;
            }
            if context
                .stage_cell()
                .borrow()
                .header
                .active_records
                .contains_key("metadata")
            {
                context
                    .stopped_phase(|| publication.rollback_role(Role::AdministratorMetadata))
                    .map_err(fail)?;
            }
            if context
                .stage_cell()
                .borrow()
                .header
                .active_records
                .contains_key("config")
            {
                context
                    .stopped_phase(|| publication.rollback_role(Role::Config))
                    .map_err(fail)?;
            }
            context
                .stopped_phase(|| {
                    context
                        .stage_cell()
                        .borrow()
                        .verify_completed_withdrawals()
                        .map_err(|_| {
                            "Administrative AUTO completed withdrawal verification refused"
                        })
                })
                .map_err(fail)?;
            let mut g = context.stage_cell().borrow_mut();
            g.header.phase = Phase::RolledBack;
            g.persist_header()?;
        }
        CommandArgs::Inspect { .. }
        | CommandArgs::Verify {
            phase: VerifyPhase::BeforeCustody,
            ..
        } => return Err(super::refuse()),
    }
    Ok(None)
}
fn active_evidence_leaf(stage: &StageGuard) -> Result<Option<PathBuf>> {
    let leaves: Vec<_> = stage
        .header
        .leaves
        .keys()
        .filter(|leaf| leaf.starts_with("records/active-service"))
        .cloned()
        .collect();
    if leaves.len() > 1 {
        return Err(super::refuse());
    }
    Ok(leaves.into_iter().next())
}
fn admit_active_evidence(stage: &StageGuard, guard: &active_service::ActiveGuard) -> Result<()> {
    let leaf = active_evidence_leaf(stage)?.ok_or_else(super::refuse)?;
    let bytes = stage.store.read(&leaf)?;
    if stage.header.leaves.get(&leaf) != Some(&digest(&bytes)) {
        return Err(super::refuse());
    }
    guard.admit_recorded(&bytes)
}
fn persist_active_evidence(
    stage: &mut StageGuard,
    guard: &active_service::ActiveGuard,
) -> Result<()> {
    if active_evidence_leaf(stage)?.is_some() {
        return admit_active_evidence(stage, guard);
    }
    // A failure before header commit leaves an unadmitted orphan. Retry names
    // are unique; never overwrite or adopt it based on its current pathname.
    let unique: [u8; 16] = rand::random();
    let leaf = PathBuf::from(format!(
        "records/active-service/{}.json",
        hex::encode(unique)
    ));
    let bytes = guard.bytes()?;
    stage.store.write_new(&leaf, &bytes)?;
    stage.header.leaves.insert(leaf, digest(&bytes));
    Ok(())
}

/// Called only inside the retained owner's exact post-marker write scope.
/// The live manager connection and independently observed process must agree
/// on the invocation both before and after projection publication.
fn preflight_owned_projection(
    context: &super::store_context::RootContext<'_>,
    rendered: &PreparedRender,
) -> Result<()> {
    if rendered.context.mode == crate::profile_auto_render::SelectedMode::SocksOnly {
        return Ok(());
    }
    {
        let stage = context.stage_cell().borrow();
        if stage.header.phase != Phase::Metadata
            || !stage.header.capture_started
            || stage.header.pending.is_some()
            || stage.header.unit_pending.is_some()
        {
            return Err(super::refuse());
        }
    }
    let publication =
        crate::profile_auto_runtime_publication::linux::RuntimePublication::new(context);
    publication.preflight_projection(rendered).map_err(|error| {
        if error == "auto_render_dns_projection_semantics_changed" {
            PROJECTION_SEMANTICS_CHANGED.to_owned()
        } else {
            fail(error)
        }
    })
}

fn finalize_owned_projection(
    context: &super::store_context::RootContext<'_>,
    rendered: &mut PreparedRender,
    lock: &crate::profile_auto_stopped_service::InstallLock,
    started: &mut crate::profile_auto_stopped_service::pid1::OwnedStart,
) -> Result<()> {
    started.revalidate().map_err(fail)?;
    let guard = active_service::ActiveGuard::observe_owned(context, lock, started)?;
    guard.admit_owned_start(started.completed())?;
    {
        let stage = context.stage_cell().borrow();
        if stage.header.phase != Phase::Metadata
            || stage.header.pending.is_some()
            || stage.header.unit_pending.is_some()
        {
            return Err(super::refuse());
        }
    }
    let publication =
        crate::profile_auto_runtime_publication::linux::RuntimePublication::new(context);
    publication.finalize_projection(rendered).map_err(|error| {
        if error == "auto_render_dns_projection_semantics_changed" {
            PROJECTION_SEMANTICS_CHANGED.to_owned()
        } else {
            fail(error)
        }
    })?;
    guard.revalidate_owned(context, lock, started)?;
    started.revalidate().map_err(fail)?;
    guard.admit_owned_start(started.completed())?;
    let mut stage = context.stage_cell().borrow_mut();
    persist_active_evidence(&mut stage, &guard)?;
    if stage.header.mode == AutoMode::SocksOnly {
        let recipe = rendered.export_private_recipe().map_err(fail)?;
        let leaf = PathBuf::from("accepted/final-render-recipe.json");
        stage.store.write_new(&leaf, &recipe)?;
        stage.header.leaves.insert(leaf.clone(), digest(&recipe));
        stage.header.render_recipe = leaf;
    } else if stage.header.render_recipe != Path::new("accepted/final-render-recipe.json") {
        return Err(super::refuse());
    }
    stage.header.phase = Phase::Finalized;
    stage.persist_header()
}

/// Closed diagnostic coordinates for the existing finalized Stop operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalizedStopPhase {
    InstallLock,
    UnitPin,
    UnitPinPreflight,
    StageReopen,
    Prelocks,
    ReadScope,
    StageAdmit,
    Context,
    InstalledFacts,
    Mode,
    OwnerBind,
    Pid1Stop,
    FinishSocks,
    GuardianAnchor,
    GuardianInverse,
    FinishWide,
    UnitPinPostflight,
}

impl FinalizedStopPhase {
    fn label(self) -> &'static str {
        match self {
            Self::InstallLock => "install_lock",
            Self::UnitPin => "unit_pin",
            Self::UnitPinPreflight => "unit_pin_preflight",
            Self::StageReopen => "stage_reopen",
            Self::Prelocks => "prelocks",
            Self::ReadScope => "read_scope",
            Self::StageAdmit => "stage_admit",
            Self::Context => "context",
            Self::InstalledFacts => "installed_facts",
            Self::Mode => "mode",
            Self::OwnerBind => "owner_bind",
            Self::Pid1Stop => "pid1_stop",
            Self::FinishSocks => "finish_socks",
            Self::GuardianAnchor => "guardian_anchor",
            Self::GuardianInverse => "guardian_inverse",
            Self::FinishWide => "finish_wide",
            Self::UnitPinPostflight => "unit_pin_postflight",
        }
    }
}

fn finalized_stop_failure_marker(phase: FinalizedStopPhase) -> String {
    format!("AUTO_NATIVE_STOP_DIAGNOSTIC phase={}", phase.label())
}

/// Fresh, one-use inverse for an already Finalized AUTO stage. The caller is
/// the installed administrative worker with its original InstallLock; saved
/// terminal JSON is only matched against fresh protected source and PID1.
pub(super) fn stop_finalized_stage(
    stage_path: &Path,
    lock: &crate::profile_auto_stopped_service::InstallLock,
    required_mode: Option<AutoMode>,
) -> Result<()> {
    use super::{durable::FreshStopPrelocks, owner_installed::ProtectedInstalledFacts};
    let mut phase = FinalizedStopPhase::InstallLock;
    let result: Result<()> = (|| {
        lock.revalidate().map_err(fail)?;
        // Keep the fixed unit resident during repeated accepted-policy readbacks.
        phase = FinalizedStopPhase::UnitPin;
        let mut fixed_unit_pin = crate::profile_auto_stopped_service::pid1::FixedUnitPin::acquire()
            .map_err(fail)?
            .ok_or_else(super::refuse)?;
        phase = FinalizedStopPhase::UnitPinPreflight;
        fixed_unit_pin.revalidate().map_err(fail)?;
        phase = FinalizedStopPhase::StageReopen;
        let store = Store::reopen_for_worker(stage_path, 0).map_err(fail)?;
        phase = FinalizedStopPhase::Prelocks;
        let prelocks = FreshStopPrelocks::acquire(store, lock).map_err(fail)?;
        phase = FinalizedStopPhase::ReadScope;
        let read_scope = prelocks.enter_read_scope().map_err(fail)?;
        phase = FinalizedStopPhase::StageAdmit;
        let (stage, fences) = prelocks.admit().map_err(fail)?;
        let state = super::v2_state_reader::PublishedState;
        phase = FinalizedStopPhase::Context;
        let context = super::store_context::RootContext::from_stage_with_lock(
            stage,
            &state,
            Some(lock),
            None,
            None,
        )
        .map_err(fail)?;
        let mode = context.stage_cell().borrow().header.mode;
        phase = FinalizedStopPhase::InstalledFacts;
        let installed = ProtectedInstalledFacts::capture(&context, lock)?;
        phase = FinalizedStopPhase::Mode;
        if required_mode.is_some_and(|required| required != mode) {
            return Err(super::refuse());
        }
        phase = FinalizedStopPhase::OwnerBind;
        let mut owner = super::durable::FreshFinalizedStop::bind(
            &context, &installed, lock, fences, read_scope,
        )?;
        phase = FinalizedStopPhase::Pid1Stop;
        let completed =
            crate::profile_auto_stopped_service::pid1::stop_finalized(&mut owner).map_err(fail)?;
        match mode {
            AutoMode::SocksOnly => {
                phase = FinalizedStopPhase::FinishSocks;
                owner.finish_socks(&completed)?;
            }
            AutoMode::WideRedirectSafe | AutoMode::FullWideTun => {
                phase = FinalizedStopPhase::GuardianAnchor;
                let mut inverse = {
                    let anchor = owner.guard_anchor()?;
                    phase = FinalizedStopPhase::GuardianInverse;
                    crate::profile_auto_guardian::GuardDenyLease::acquire_stop_inverse(&anchor)
                        .map_err(fail)?
                };
                phase = FinalizedStopPhase::FinishWide;
                owner.finish_wide(&completed, &mut inverse)?;
            }
        }
        phase = FinalizedStopPhase::UnitPinPostflight;
        fixed_unit_pin.revalidate().map_err(fail)
    })();
    if result.is_err() {
        eprintln!("{}", finalized_stop_failure_marker(phase));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_log_alias_uses_separate_policy_directories() {
        use crate::profile_auto_runtime_identity::RuntimePolicy;
        let alias = Path::new("/var/lib/aegis-client-logs/runtime/runtime-events.jsonl");
        for (policy, expected) in [
            (
                RuntimePolicy::Root,
                "/var/lib/aegis-client-logs/root/runtime-events.jsonl",
            ),
            (
                RuntimePolicy::DedicatedNone,
                "/var/lib/aegis-client-logs/service/runtime-events.jsonl",
            ),
            (
                RuntimePolicy::DedicatedBind,
                "/var/lib/aegis-client-logs/service/runtime-events.jsonl",
            ),
        ] {
            let resolved = resolved_runtime_events(alias, policy);
            assert_eq!(resolved, Path::new(expected));
            assert_eq!(runtime_events_scalar(&resolved).unwrap(), expected);
            for existing in [
                "/dev/null",
                "/var/log/aegis-client/runtime/runtime-events.jsonl",
                "/run/private-native-events.jsonl",
            ] {
                assert_eq!(
                    resolved_runtime_events(Path::new(existing), policy),
                    Path::new(existing)
                );
            }
        }
        for unbound in [alias, Path::new("/tmp/foreign-log"), Path::new("relative")] {
            assert!(runtime_events_scalar(unbound).is_err());
        }
    }
    #[test]
    fn direct_mutator_refuses_before_stage_lookup() {
        let error = command(CommandArgs::CommitState {
            stage: PathBuf::from("/no-such-stage-for-unleased-mutation"),
        })
        .unwrap_err();
        assert_eq!(error, super::super::refuse());
    }
    #[test]
    fn finalize_requires_owned_job_before_any_stage_or_manager_lookup() {
        // The path need not exist: the actual command dispatch refuses before
        // its stage lookup, even without an InstallLock. The worker separately
        // admits its stage before accepting commands.
        let args = CommandArgs::Finalize {
            stage: PathBuf::from("/no-such-stage-for-unowned-activation"),
        };
        let error = require_activation_authority(&args).unwrap_err();
        assert!(error.contains("transaction-owned systemd job"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&worker_phase_failure(&error).unwrap())
                .unwrap()["reason"],
            "activation_owner_unavailable"
        );
    }
    #[test]
    fn three_mode_schema_and_unknown_refusal() {
        for m in ["socks-only", "wide-redirect-safe", "full-wide-tun"] {
            assert!(mode(m).is_ok());
        }
        assert!(mode("full-wide-hybrid-geneva").is_err());
    }
    #[test]
    fn ordinary_payload_limit_is_not_widened_by_recipe_exception() {
        let mut values = BTreeMap::new();
        assert!(insert(
            &mut values,
            "input/payload/config/huge".into(),
            vec![0; super::super::MAX_LEAF + 1]
        )
        .is_err());
        assert_eq!(
            super::super::leaf_bound(Path::new("accepted/render-recipe.json")),
            96 * 1024 * 1024
        );
        assert_eq!(
            super::super::leaf_bound(Path::new("input/render-recipe.json")),
            16 * 1024 * 1024
        );
    }
    #[test]
    fn final_recipe_space_is_reserved_before_custody() {
        let values = BTreeMap::new();
        assert!(check_aggregate(&values, MAX_STAGE).is_ok());
        assert!(check_aggregate(&values, MAX_STAGE + 1).is_err());
    }
}

#[cfg(test)]
#[path = "profile_auto_backend_integration_tests.rs"]
mod actual_backend_integration_tests;
#[cfg(test)]
#[path = "profile_auto_worker_successor_tests.rs"]
mod worker_successor_tests;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    command: Vec<String>,
}
pub(super) fn worker(stage: &Path) -> Result<()> {
    use std::time::{Duration, Instant};
    if unsafe { libc::geteuid() } != 0 {
        return Err(super::refuse());
    }
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire().map_err(fail)?;
    // Keep the original inactive fixed unit resident across every staged
    // publication and the admitted manager reload. Without a held PID 1
    // reference, a fresh LoadUnit may GC/reload a partially published
    // drop-in and silently switch the old stopped actor's User/Group.
    let mut fixed_unit_pin =
        crate::profile_auto_stopped_service::pid1::FixedUnitPin::acquire().map_err(fail)?;
    if let Some(pin) = fixed_unit_pin.as_mut() {
        pin.revalidate().map_err(fail)?;
    }
    let published_state = super::v2_state_reader::PublishedState;
    let mut activation: Option<activation::Session<'_>> = None;
    let started = Instant::now();
    let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(super::refuse());
    }
    // Acquire before admission; every phase reconstructs protected authority
    // while borrowing this same held lock. EOF/error leaves durable receipts.
    let mut admitted = match admit_worker_stage(stage) {
        Ok(admitted) => admitted,
        Err(error) => {
            if let Ok(response) = worker_phase_failure(&error) {
                let _ = write_worker_response(&response, started);
            }
            return Err(error);
        }
    };
    if admitted.header.phase == Phase::Prepared {
        admitted.revalidate_originals()?;
        super::unit_binding::admit_original(&mut admitted, &lock)?;
    }
    // The per-stage OFD flock must be released before dispatch reopens it on
    // another descriptor. The distinct global InstallLock remains worker-owned.
    drop(admitted);
    // Reentry after own publication admits immutable stage/owned receipts;
    // original path identities are legitimately retired, never blindly reread.
    write_worker_response(b"{\"status\":\"ready\"}\n", started)?;
    let outcome = (|| -> Result<()> {
        for _ in 0..128 {
            let mut line = Vec::new();
            loop {
                let remaining = Duration::from_secs(900)
                    .checked_sub(started.elapsed())
                    .ok_or_else(super::refuse)?;
                let timeout = remaining
                    .min(Duration::from_secs(30))
                    .as_millis()
                    .min(i32::MAX as u128) as i32;
                let mut poll = libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
                if ready < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                if ready <= 0 {
                    return Err(super::refuse());
                }
                let mut byte = 0u8;
                let n = unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) };
                if n == 0 {
                    // A terminal command returns after its own acknowledged reply.
                    // EOF here means the coordinator abandoned a nonterminal stage;
                    // dropping the install lock must never look like completion.
                    if line.is_empty() {
                        if activation.is_some() {
                            return Err(ACTIVATION_RECOVERY_REQUIRED.into());
                        }
                        // Bind the refusal to the current protected phase. A
                        // replaced or corrupt stage cannot receive a clean
                        // coordinator-disconnect acknowledgement.
                        let abandoned = admit_worker_stage(stage)?;
                        if matches!(abandoned.header.phase, Phase::Finalized | Phase::RolledBack) {
                            return Err(super::refuse());
                        }
                        drop(abandoned);
                        if let Ok(response) = worker_phase_failure(
                            "AUTO worker coordinator disconnected before terminal phase",
                        ) {
                            let _ = write_worker_response(&response, started);
                        }
                    }
                    return Err(super::refuse());
                }
                if n != 1 {
                    return Err(super::refuse());
                }
                if byte == b'\n' {
                    break;
                }
                if line.len() >= 16384 {
                    return Err(super::refuse());
                }
                line.push(byte);
            }
            let request: WorkerRequest = serde_json::from_slice(&line).map_err(fail)?;
            if request.command.is_empty() || request.command.iter().any(|v| v == "--stage") {
                return Err(super::refuse());
            }
            let mut words = vec![
                request.command[0].clone(),
                "--stage".into(),
                stage.to_str().ok_or_else(super::refuse)?.into(),
            ];
            words.extend(request.command.into_iter().skip(1));
            let crate::profile_auto_transaction_cli::Parsed::Command(args) =
                crate::profile_auto_transaction_cli::parse(&words)?
            else {
                return Err(super::refuse());
            };
            let reload_command = matches!(&args, CommandArgs::ReloadServicePolicy { .. });
            let bind_command = matches!(&args, CommandArgs::BindRuntimeService { .. });
            let bind_step = |step: &'static str, error: String| {
                if bind_command {
                    bind_runtime_step_error(step, error)
                } else {
                    error
                }
            };
            // Preserve the closed diagnostic before dispatch consumes the command.
            let pin_after_error = worker_pin_failure("worker_pin_after", &args);
            let pin_before: Result<()> = if let Some(pin) = fixed_unit_pin.as_mut() {
                pin.revalidate().map_err(|_| {
                    if reload_command {
                        "reload_worker_before".to_owned()
                    } else {
                        worker_pin_failure("worker_pin_before", &args)
                    }
                })
            } else {
                Ok(())
            };
            let getter = if let CommandArgs::Inspect { field, .. } = &args {
                Some(*field)
            } else {
                None
            };
            let terminal = matches!(
                &args,
                CommandArgs::Finalize { .. } | CommandArgs::Rollback { .. }
            );
            let value = match pin_before
                .and_then(|_| match args {
                    CommandArgs::BeginCapture { .. } if activation.is_none() => {
                        activation::Session::start(stage, &lock, &published_state, true).map(
                            |session| {
                                activation = Some(session);
                                None
                            },
                        )
                    }
                    CommandArgs::Finalize { .. } => {
                        let session = if let Some(session) = activation.take() {
                            Ok(session)
                        } else {
                            activation::Session::start(stage, &lock, &published_state, false)
                        };
                        session.and_then(|session| session.finalize(&lock).map(|()| None))
                    }
                    args if activation.is_some() => {
                        let _ = args;
                        Err(ACTIVATION_RECOVERY_REQUIRED.into())
                    }
                    args => {
                        command_with_lock(args, &lock).map_err(|error| bind_step("dispatch", error))
                    }
                })
                .and_then(|value| {
                    if let Some(pin) = fixed_unit_pin.as_mut() {
                        pin.revalidate().map_err(|_| {
                            if reload_command {
                                "reload_worker_after".to_owned()
                            } else {
                                pin_after_error.clone()
                            }
                        })?;
                    }
                    Ok(value)
                }) {
                Ok(value) => value,
                Err(error) => {
                    // A rejected phase can follow a durable partial publication.
                    // Keep the worker's original failure and give its supervisor a
                    // bounded response to retain alongside the private receipts.
                    // Only fixed, non-secret reasons cross the worker pipe.
                    if let Ok(response) = worker_phase_failure_closed(&error, reload_command) {
                        let _ = write_worker_response(&response, started);
                    }
                    return Err(error);
                }
            };
            if let (Some(field), Some(value)) = (getter, value.as_ref()) {
                crate::profile_auto_transaction_cli::inspect_scalar(field, stage, value)?;
            } else if value.is_some() {
                return Err(super::refuse());
            }
            let response = serde_json::to_vec(&serde_json::json!({"status":"ok","value":value}))
                .map_err(fail)?;
            if response.len() > 8192 {
                return Err(super::refuse());
            }
            let mut framed = response;
            framed.push(b'\n');
            write_worker_response(&framed, started)?;
            if terminal {
                return Ok(());
            }
        }
        Err(super::refuse())
    })();
    if let Some(session) = activation.take() {
        // All parser, transport, timeout and coordinator failures flow through
        // this exact inverse while the original lock and session still live.
        session
            .compensate_abandon(&lock)
            .map_err(|_| ACTIVATION_RECOVERY_REQUIRED.to_owned())?;
    }
    outcome
}

fn worker_phase_failure(error: &str) -> Result<Vec<u8>> {
    worker_phase_failure_closed(error, false)
}
fn worker_phase_failure_closed(error: &str, reload_command: bool) -> Result<Vec<u8>> {
    if !reload_command {
        if let Some(value) =
            bind_runtime_step_response(error).or_else(|| begin_capture_step_response(error))
        {
            let mut response = serde_json::to_vec(&value).map_err(fail)?;
            response.push(b'\n');
            if response.len() > 8193 {
                return Err(super::refuse());
            }
            return Ok(response);
        }
    }
    let reason = match error {
        ACTIVATION_RECOVERY_REQUIRED => "native_recovery_required",
        ACTIVATION_OWNER_UNAVAILABLE => "activation_owner_unavailable",
        PROJECTION_SEMANTICS_CHANGED => "projection_semantics_changed",
        "AUTO native capture requires actual native capture/guard readiness; private stage retained"
        | "AUTO wide finalization requires actual native capture/guard readiness; private stage retained" => {
            "native_capture_guard_not_ready"
        }
        "AUTO capture requires separately authorized native recovery; private stage retained" => {
            "native_recovery_required"
        }
        "AUTO worker coordinator disconnected before terminal phase" => "coordinator_disconnected",
        _ => "phase_refused",
    };
    let diagnostic = crate::profile_auto_stopped_service::pid1::start_failure_diagnostic(error);
    let capture_refusal = if reload_command {
        None
    } else {
        capture_failure_diagnostic(error)
    };
    let mut value = serde_json::json!({"status":"error","reason":reason});
    if reload_command && reason == "phase_refused" && diagnostic.is_none() {
        value["reload_failure"] = serde_json::json!(if reload_failure_label(error) {
            error
        } else {
            "reload_dispatch"
        });
    }
    if let Some(diagnostic) = diagnostic {
        value["reason"] = serde_json::json!("native_recovery_required");
        value["diagnostic"] = diagnostic;
    }
    if let Some(capture_refusal) = capture_refusal {
        value["capture_refusal"] = capture_refusal;
    }
    let mut response = serde_json::to_vec(&value).map_err(fail)?;
    response.push(b'\n');
    if response.len() > 8193 {
        return Err(super::refuse());
    }
    Ok(response)
}

fn reload_failure_label(error: &str) -> bool {
    matches!(
        error,
        "reload_worker_before"
            | "reload_worker_after"
            | "reload_dispatch"
            | "reload_stage"
            | "reload_committed_policy"
            | "reload_recorded_namespace"
            | "reload_intent"
            | "reload_native_unknown"
            | "reload_receipt_validation"
            | "reload_receipt_write"
            | "reload_namespace_commit"
    ) || crate::profile_auto_stopped_service::reload_failure_label(error)
}

fn write_worker_response(bytes: &[u8], started: std::time::Instant) -> Result<()> {
    use std::time::{Duration, Instant};
    if bytes.len() > 8193 {
        return Err(super::refuse());
    }
    let idle = Instant::now();
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = Duration::from_secs(900)
            .checked_sub(started.elapsed())
            .ok_or_else(super::refuse)?;
        let write_remaining = Duration::from_secs(30)
            .checked_sub(idle.elapsed())
            .ok_or_else(super::refuse)?;
        let timeout = remaining
            .min(write_remaining)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: libc::STDOUT_FILENO,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if ready <= 0 {
            return Err(super::refuse());
        }
        let written = unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if written < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        if written <= 0 {
            return Err(super::refuse());
        }
        offset += written as usize;
    }
    Ok(())
}

#[cfg(test)]
mod worker_protocol_tests {
    use super::{
        begin_capture_step_error, begin_capture_step_response, bind_runtime_step_error,
        bind_runtime_step_response, capture_failure_diagnostic, reload_failure_label,
        worker_phase_failure, worker_phase_failure_closed, worker_pin_failure, CommandArgs,
        PathBuf, WorkerRequest, ACTIVATION_OWNER_UNAVAILABLE, ACTIVATION_RECOVERY_REQUIRED,
        BIND_RUNTIME_STEPS, PROJECTION_SEMANTICS_CHANGED,
    };

    fn response_value(bytes: Vec<u8>) -> serde_json::Value {
        assert!(bytes.len() <= 8193 && bytes.ends_with(b"\n"));
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn bind_runtime_step_types_only_a_generic_refusal_with_a_closed_code() {
        let generic = super::super::refuse();
        for step in BIND_RUNTIME_STEPS {
            let encoded = bind_runtime_step_error(step, generic.clone());
            assert_ne!(encoded, generic);
            assert_eq!(
                bind_runtime_step_response(&encoded).unwrap(),
                serde_json::json!({"status":"error","reason":"phase_refused",
                                   "bind_runtime_step":step})
            );
            let response = worker_phase_failure(&encoded).unwrap();
            assert!(!response
                .windows(b"Administrative".len())
                .any(|w| w == b"Administrative"));
            assert_eq!(
                response_value(response),
                serde_json::json!({"status":"error","reason":"phase_refused",
                                   "bind_runtime_step":step})
            );
            // A reload command never carries a bind coordinate.
            assert!(
                response_value(worker_phase_failure_closed(&encoded, true).unwrap())
                    .get("bind_runtime_step")
                    .is_none()
            );
        }
        let mut unique = BIND_RUNTIME_STEPS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!((unique.len(), BIND_RUNTIME_STEPS.len()), (43, 43));
    }

    #[test]
    fn bind_runtime_step_keeps_every_classified_error_and_refuses_open_codes() {
        for error in [
            ACTIVATION_RECOVERY_REQUIRED,
            ACTIVATION_OWNER_UNAVAILABLE,
            PROJECTION_SEMANTICS_CHANGED,
            "AUTO PID1 start requires recovery:post_submit:deny_lease:0",
            "AUTO authenticated capture refusal:os_error:endpoint:412",
            "reload_worker_before",
            "private credential: example-secret",
        ] {
            for step in ["dispatch", "bind_header_persist", "policy_compile_other"] {
                let kept = bind_runtime_step_error(step, error.to_owned());
                assert_eq!(kept, error);
                assert_eq!(
                    response_value(worker_phase_failure(&kept).unwrap()),
                    response_value(worker_phase_failure(error).unwrap())
                );
            }
        }
        for open in [
            "AUTO bind runtime step:",
            "AUTO bind runtime step:private",
            "AUTO bind runtime step:dispatch:private",
            "AUTO bind runtime step:policy_compile_guard_hook_unrecognized ",
            "AUTO bind runtime step:begin_capture",
        ] {
            assert!(bind_runtime_step_response(open).is_none());
            assert_eq!(
                response_value(worker_phase_failure(open).unwrap()),
                serde_json::json!({"status":"error","reason":"phase_refused"})
            );
        }
        // Every compiler coordinate is a listed step, and the list names no
        // compiler coordinate the compiler cannot return.
        let compiled: Vec<&str> = BIND_RUNTIME_STEPS
            .iter()
            .copied()
            .filter(|step| step.starts_with("policy_compile_"))
            .collect();
        assert_eq!(
            compiled,
            crate::profile_auto_unit_policy::linux::COMPILE_REFUSAL_CODES
        );
    }

    #[test]
    fn begin_capture_step_contains_no_raw_error_and_retains_closed_failure_class() {
        let encoded = begin_capture_step_error("launch_register", "private credential".into());
        assert!(!encoded.contains("private credential"));
        assert_eq!(
            begin_capture_step_response(&encoded).unwrap(),
            serde_json::json!({"status":"error","reason":"phase_refused",
                               "begin_capture_step":"launch_register"})
        );
        let recovery =
            begin_capture_step_error("launch_prove", ACTIVATION_RECOVERY_REQUIRED.into());
        assert_eq!(
            begin_capture_step_response(&recovery).unwrap()["reason"],
            "native_recovery_required"
        );
        let capture = begin_capture_step_error(
            "capture_ready",
            "AUTO authenticated capture refusal:os_error:endpoint:412".into(),
        );
        assert_eq!(
            begin_capture_step_response(&capture).unwrap(),
            serde_json::json!({"status":"error","reason":"phase_refused",
                               "begin_capture_step":"capture_ready",
                               "capture_refusal":{"reason":"os_error","source":"endpoint","line":412}})
        );
        let pid1 = begin_capture_step_error(
            "pid1_start",
            "AUTO PID1 start requires recovery:job_signal_budget:permission:0".into(),
        );
        assert_eq!(
            begin_capture_step_response(&pid1).unwrap()["diagnostic"],
            serde_json::json!({"phase":"job_signal_budget","cause":"permission","errno":0})
        );
        for bad in [
            "AUTO begin capture step:private:phase_refused",
            "AUTO begin capture step:capture_ready:capture:os_error:private:412",
            "AUTO begin capture step:capture_ready:capture:os_error:endpoint:0412",
            "AUTO begin capture step:launch_record:capture:os_error:endpoint:412",
            "AUTO begin capture step:pid1_start:pid1:private:permission:0",
            "AUTO begin capture step:launch_record:pid1:job_signal_budget:permission:0",
        ] {
            assert!(begin_capture_step_response(bad).is_none());
        }
    }

    #[test]
    fn terminal_registrar_failures_cross_the_actual_worker_response_boundary() {
        for step in [
            "terminal_configure",
            "terminal_recover_incomplete",
            "terminal_prepare",
            "terminal_activate",
        ] {
            let private = begin_capture_step_error(step, "private credential".into());
            let encoded = worker_phase_failure_closed(&private, false).unwrap();
            assert!(!encoded
                .windows(b"private credential".len())
                .any(|w| w == b"private credential"));
            assert_eq!(
                response_value(encoded),
                serde_json::json!({"status":"error","reason":"phase_refused",
                                   "begin_capture_step":step})
            );
            let recovery = begin_capture_step_error(step, ACTIVATION_RECOVERY_REQUIRED.into());
            assert_eq!(
                response_value(worker_phase_failure_closed(&recovery, false).unwrap()),
                serde_json::json!({"status":"error","reason":"native_recovery_required",
                                   "begin_capture_step":step})
            );
        }
        assert!(begin_capture_step_response(
            "AUTO begin capture step:terminal_foreign:phase_refused"
        )
        .is_none());
    }

    #[test]
    fn begin_capture_pin_refusal_has_only_the_closed_pin_coordinate() {
        let begin = CommandArgs::BeginCapture {
            stage: PathBuf::from("/run/aegis-test-stage"),
        };
        for step in ["worker_pin_before", "worker_pin_after"] {
            let encoded = worker_pin_failure(step, &begin);
            let response = worker_phase_failure_closed(&encoded, false).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"status":"error","reason":"phase_refused",
                                  "bind_runtime_step":step})
            );
            assert!(begin_capture_step_response(&encoded).is_none());
        }
        let finalize = CommandArgs::Finalize {
            stage: PathBuf::from("/run/aegis-test-stage"),
        };
        let encoded = worker_pin_failure("worker_pin_before", &finalize);
        let response = worker_phase_failure_closed(&encoded, false).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"status":"error","reason":"phase_refused"})
        );
    }

    #[test]
    fn authenticated_capture_refusal_response_is_bounded_and_closed() {
        let coordinate = "AUTO authenticated capture refusal:os_error:endpoint:412";
        assert_eq!(
            capture_failure_diagnostic(coordinate).unwrap(),
            serde_json::json!({"reason":"os_error","source":"endpoint","line":412})
        );
        let response: serde_json::Value =
            serde_json::from_slice(&worker_phase_failure(coordinate).unwrap()).unwrap();
        assert_eq!(
            response,
            serde_json::json!({
                "status":"error", "reason":"phase_refused",
                "capture_refusal":{"reason":"os_error","source":"endpoint","line":412}
            })
        );
        let reload: serde_json::Value =
            serde_json::from_slice(&worker_phase_failure_closed(coordinate, true).unwrap())
                .unwrap();
        assert!(reload.get("capture_refusal").is_none());
        for bad in [
            "AUTO authenticated capture refusal:os_error:endpoint:0",
            "AUTO authenticated capture refusal:os_error:unknown:412",
            "AUTO authenticated capture refusal:os_error:endpoint:10001",
            "AUTO authenticated capture refusal:os_error:endpoint:0412",
            "AUTO authenticated capture refusal:os_error:private:412",
            "AUTO authenticated capture refusal:os_error:endpoint:412:private",
        ] {
            assert!(capture_failure_diagnostic(bad).is_none());
            let response: serde_json::Value =
                serde_json::from_slice(&worker_phase_failure(bad).unwrap()).unwrap();
            assert_eq!(
                response,
                serde_json::json!({"status":"error","reason":"phase_refused"})
            );
        }
    }
    #[test]
    fn worker_requests_reject_unknown_authority_fields_and_non_command_payloads() {
        let valid: WorkerRequest = serde_json::from_str(
            r#"{"command":["bind-runtime-service","--service-user","aegis"]}"#,
        )
        .unwrap();
        assert_eq!(valid.command.len(), 3);
        for bad in [
            r#"{"command":["commit-state"],"uid":997}"#,
            r#"{"command":["commit-state"],"pid":1}"#,
            r#"{"command":["commit-state"],"hash":"claimed"}"#,
            r#"{"command":"commit-state"}"#,
        ] {
            assert!(serde_json::from_str::<WorkerRequest>(bad).is_err());
        }
    }
    #[test]
    fn refused_phase_response_retains_only_fixed_reason() {
        let wide = worker_phase_failure(
            "AUTO wide finalization requires actual native capture/guard readiness; private stage retained",
        )
        .unwrap();
        assert!(wide.len() <= 8193 && wide.ends_with(b"\n"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wide).unwrap(),
            serde_json::json!({"status":"error","reason":"native_capture_guard_not_ready"})
        );
        let arbitrary = worker_phase_failure("private credential: example-secret").unwrap();
        assert!(!arbitrary
            .windows(b"example-secret".len())
            .any(|w| w == &b"example-secret"[..]));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&arbitrary).unwrap(),
            serde_json::json!({"status":"error","reason":"phase_refused"})
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &worker_phase_failure(PROJECTION_SEMANTICS_CHANGED).unwrap()
            )
            .unwrap(),
            serde_json::json!({"status":"error","reason":"projection_semantics_changed"})
        );
        let recovery = worker_phase_failure(
            "AUTO capture requires separately authorized native recovery; private stage retained",
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&recovery).unwrap(),
            serde_json::json!({"status":"error","reason":"native_recovery_required"})
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &worker_phase_failure(ACTIVATION_RECOVERY_REQUIRED).unwrap()
            )
            .unwrap(),
            serde_json::json!({"status":"error","reason":"native_recovery_required"})
        );
        let disconnected =
            worker_phase_failure("AUTO worker coordinator disconnected before terminal phase")
                .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&disconnected).unwrap(),
            serde_json::json!({"status":"error","reason":"coordinator_disconnected"})
        );
    }
    #[test]
    fn reload_failure_is_closed_and_command_scoped() {
        for label in [
            "reload_worker_before",
            "reload_native_fixed_command",
            "reload_native_fixed_executable",
            "reload_native_fixed_spawn",
            "reload_native_fixed_pipes",
            "reload_native_fixed_wait",
            "reload_native_fixed_drain",
            "reload_native_fixed_stderr",
            "reload_native_fixed_cleanup",
            "reload_native_fixed_exit",
            "reload_native_fixed_readback",
            "reload_native_fixed_stdout",
            "reload_second_pid1_final",
            "reload_namespace_commit",
        ] {
            assert!(reload_failure_label(label));
            let expected = serde_json::json!({"status":"error","reason":"phase_refused",
                                              "reload_failure":label});
            let actual: serde_json::Value =
                serde_json::from_slice(&worker_phase_failure_closed(label, true).unwrap()).unwrap();
            assert_eq!(actual, expected);
            let ordinary: serde_json::Value =
                serde_json::from_slice(&worker_phase_failure_closed(label, false).unwrap())
                    .unwrap();
            assert_eq!(
                ordinary,
                serde_json::json!({"status":"error","reason":"phase_refused"})
            );
        }
        for unknown in [
            "reload_third_pid1_final",
            "reload_second_raw_error",
            "reload_native_fixed_command: secret",
        ] {
            assert!(!reload_failure_label(unknown));
            let value: serde_json::Value =
                serde_json::from_slice(&worker_phase_failure_closed(unknown, true).unwrap())
                    .unwrap();
            assert_eq!(
                value,
                serde_json::json!({"status":"error","reason":"phase_refused",
                                               "reload_failure":"reload_dispatch"})
            );
        }
        for error in [
            ACTIVATION_RECOVERY_REQUIRED,
            "AUTO PID1 start requires recovery:post_submit:deny_lease:0",
        ] {
            let value: serde_json::Value =
                serde_json::from_slice(&worker_phase_failure_closed(error, true).unwrap()).unwrap();
            assert_eq!(value["reason"], "native_recovery_required");
            assert!(value.get("reload_failure").is_none());
        }
    }
}
