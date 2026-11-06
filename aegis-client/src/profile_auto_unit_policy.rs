//! Private AUTO v2 managed systemd policy producer.
//! Fixed singleton leaves only; never exchanges a systemd parent directory.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        ffi::CString,
        fs::{self, File},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::{MetadataExt, PermissionsExt},
        },
        path::{Component, Path, PathBuf},
    };
    type Result<T> = std::result::Result<T, &'static str>;
    const REFUSED: &str = "AUTO managed unit policy refused";
    const LIMIT: usize = 64 * 1024;
    const UNIT: &str = include_str!("../../packaging/systemd/aegis-client.service");
    const ENVIRONMENT: &str = include_str!("../../packaging/env/aegis-client.env.example");
    const DEVICE_GUARD_DROPIN: &str = "30-device-egress-guard.conf";
    const V2_BOOT_GATE_DROPIN: &str = "00-v2-boot-gate.conf";
    // V2 owns private transient activation; the fixed service always refuses.
    // This condition is false before, during and after marker publication.
    const V2_BOOT_GATE_BYTES: &str = "[Unit]\nConditionPathExists=!/\n";
    const DEVICE_GUARD_STATE: &str = "/var/lib/aegis-install/client/device-guard.conf";
    const DEVICE_GUARD_HELPER: &str = "/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh";
    const V2_BOOT_INTERLOCK: &str = "ConditionPathExists=!/";
    // Each compile check refuses with its own fixed text so the worker can
    // report a closed BindRuntimeService coordinate. No caller compares
    // these texts; every other compile refusal stays REFUSED ("other").
    const COMPILE_TEMPLATE: &str = "AUTO managed unit policy refused: template";
    const COMPILE_IDENTITY_MODE: &str = "AUTO managed unit policy refused: identity mode";
    const COMPILE_DROPIN_BOUNDS: &str = "AUTO managed unit policy refused: drop-in bounds";
    const COMPILE_BOOT_GATE: &str = "AUTO managed unit policy refused: boot gate";
    const COMPILE_UNIT_TEMPLATE: &str = "AUTO managed unit policy refused: unit template";
    const COMPILE_UNIT_RENDER: &str = "AUTO managed unit policy refused: unit render";
    const COMPILE_FULLTUN_DROPIN_NAME: &str =
        "AUTO managed unit policy refused: full-tun drop-in name";
    const COMPILE_FIRST_ARM_DROPINS: &str = "AUTO managed unit policy refused: first-arm drop-ins";
    const COMPILE_GUARD_HOOK_MISSING: &str = "AUTO managed unit policy refused: guard hook missing";
    const COMPILE_GUARD_HOOK_UNRECOGNIZED: &str =
        "AUTO managed unit policy refused: guard hook unrecognized";
    const COMPILE_FULLTUN_UNIT_SHAPE: &str =
        "AUTO managed unit policy refused: full-tun unit shape";
    const COMPILE_FIRST_ARM_ENTRY: &str = "AUTO managed unit policy refused: first-arm entry";
    /// The closed coordinates refusal_code() can return, in its order.
    pub(crate) const COMPILE_REFUSAL_CODES: [&str; 13] = [
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
    /// Closed coordinate for a compile()/compile_first_arm() refusal.
    pub(crate) fn refusal_code(error: &str) -> &'static str {
        match error {
            COMPILE_TEMPLATE => COMPILE_REFUSAL_CODES[0],
            COMPILE_IDENTITY_MODE => COMPILE_REFUSAL_CODES[1],
            COMPILE_DROPIN_BOUNDS => COMPILE_REFUSAL_CODES[2],
            COMPILE_BOOT_GATE => COMPILE_REFUSAL_CODES[3],
            COMPILE_UNIT_TEMPLATE => COMPILE_REFUSAL_CODES[4],
            COMPILE_UNIT_RENDER => COMPILE_REFUSAL_CODES[5],
            COMPILE_FULLTUN_DROPIN_NAME => COMPILE_REFUSAL_CODES[6],
            COMPILE_FIRST_ARM_DROPINS => COMPILE_REFUSAL_CODES[7],
            COMPILE_GUARD_HOOK_MISSING => COMPILE_REFUSAL_CODES[8],
            COMPILE_GUARD_HOOK_UNRECOGNIZED => COMPILE_REFUSAL_CODES[9],
            COMPILE_FULLTUN_UNIT_SHAPE => COMPILE_REFUSAL_CODES[10],
            COMPILE_FIRST_ARM_ENTRY => COMPILE_REFUSAL_CODES[11],
            _ => COMPILE_REFUSAL_CODES[12],
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) enum LeafRole {
        BaseUnit,
        Environment,
    }
    impl LeafRole {
        fn name(self) -> &'static str {
            match self {
                Self::BaseUnit => "aegis-client.service",
                Self::Environment => "aegis-client",
            }
        }
        fn stage(self) -> &'static str {
            match self {
                Self::BaseUnit => "prepared-unit",
                Self::Environment => "prepared-environment",
            }
        }
        pub(crate) fn parent(self) -> &'static Path {
            Path::new(match self {
                Self::BaseUnit => "/etc/systemd/system",
                Self::Environment => "/etc/default",
            })
        }
        fn backup(self) -> &'static str {
            match self {
                Self::BaseUnit => "rollback-unit",
                Self::Environment => "rollback-environment",
            }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) enum RuntimeUser {
        Root,
        Aegis,
        AegisSvc,
    }
    impl RuntimeUser {
        fn name(self) -> &'static str {
            match self {
                Self::Root => "root",
                Self::Aegis => "aegis",
                Self::AegisSvc => "aegis-svc",
            }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Policy {
        Root,
        DedicatedNone,
        DedicatedBind,
    }
    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) enum Mode {
        Socks,
        Redirect,
        FullTun,
    }
    // Construct only from accepted sealed render and protected account binding.
    pub(crate) struct CompilerInputs {
        pub(crate) mode: Mode,
        pub(crate) policy: Policy,
        pub(crate) user: RuntimeUser,
        pub(crate) binary: PathBuf,
        pub(crate) config: PathBuf,
        pub(crate) state: PathBuf,
        pub(crate) events: PathBuf,
    }
    pub(crate) struct CompiledPolicy {
        pub(crate) unit: Vec<u8>,
        pub(crate) environment: Vec<u8>,
        pub(crate) dropins: BTreeMap<PathBuf, Vec<u8>>,
        pub(crate) transient: TransientPolicy,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct TransientPolicy {
        mode: Mode,
        user: RuntimeUser,
        binary: String,
        config: String,
        state: String,
        events: String,
        guard_timeout: Option<u32>,
    }
    /// Values are minted only from the compiler's protected source inputs.
    /// The PID 1 transport maps these variants to exact D-Bus signatures;
    /// no caller supplies a free-form property, command, or unit name.
    pub(crate) enum TransientProperty {
        String(&'static str, String),
        Bool(&'static str, bool),
        U32(&'static str, u32),
        U64(&'static str, u64),
        StringArray(&'static str, Vec<String>),
        Exec(&'static str, Vec<Vec<String>>),
    }
    impl CompiledPolicy {
        pub(crate) fn transient_policy(&self) -> TransientPolicy {
            self.transient.clone()
        }
    }
    impl TransientPolicy {
        pub(crate) fn bind_unit(
            &self,
            unit: &crate::profile_auto_stopped_service::pid1::PrivateUnit,
        ) -> Result<Vec<TransientProperty>> {
            private_unit_namespace_unshadowed(unit.name())?;
            let mut environment = vec!["RUST_LOG=info".into()];
            let mut after = vec!["network-online.target".into()];
            let mut requires = Vec::new();
            if self.mode != Mode::Socks {
                environment.push(format!("AEGIS_DEVICE_GUARD_STATE={DEVICE_GUARD_STATE}"));
                requires.push("aegis-auto-guardian.service".into());
                after.push("aegis-auto-guardian.service".into());
                let token = unit
                    .name()
                    .strip_prefix("aegis-auto@")
                    .and_then(|name| name.strip_suffix(".service"))
                    .ok_or(REFUSED)?;
                if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(REFUSED);
                }
                let terminal_b = format!("aegis-auto-terminal-b@{token}.service");
                requires.push(terminal_b.clone());
                after.push(terminal_b);
                requires.push("aegis-device-egress-guard.service".into());
                after.push("aegis-device-egress-guard.service".into());
            }
            let mut values = vec![
                TransientProperty::String("Description", "AEGIS private AUTO runtime".into()),
                // Instances otherwise inherit systemd's per-template slice;
                // every held actor binds the exact direct system.slice cgroup.
                TransientProperty::String("Slice", "system.slice".into()),
                TransientProperty::StringArray("After", after),
                TransientProperty::StringArray("Wants", vec!["network-online.target".into()]),
                TransientProperty::String("Type", "notify".into()),
                TransientProperty::String("NotifyAccess", "main".into()),
                TransientProperty::String("Restart", "no".into()),
                TransientProperty::String("CollectMode", "inactive".into()),
                TransientProperty::String("WorkingDirectory", self.state.clone()),
                TransientProperty::StringArray("Environment", environment),
                TransientProperty::Exec(
                    "ExecStart",
                    vec![vec![
                        self.binary.clone(),
                        "auto-owned-service".into(),
                        unit.name().to_owned(),
                        "--config".into(),
                        self.config.clone(),
                        "--runtime-events-jsonl".into(),
                        self.events.clone(),
                    ]],
                ),
                TransientProperty::String("User", self.user.name().into()),
                TransientProperty::String("Group", self.user.name().into()),
                TransientProperty::U64("LimitNOFILE", 65_536),
                TransientProperty::U32("UMask", 0o077),
                TransientProperty::Bool("NoNewPrivileges", true),
                TransientProperty::Bool("PrivateTmp", true),
                TransientProperty::String("ProtectSystem", "full".into()),
                TransientProperty::String("ProtectHome", "yes".into()),
                TransientProperty::Bool("ProtectControlGroups", true),
                TransientProperty::Bool("ProtectKernelModules", true),
                TransientProperty::Bool("ProtectKernelTunables", true),
                TransientProperty::Bool("LockPersonality", true),
                TransientProperty::Bool("RestrictRealtime", true),
                TransientProperty::Bool("RestrictSUIDSGID", true),
                TransientProperty::StringArray("SystemCallArchitectures", vec!["native".into()]),
            ];
            if !requires.is_empty() {
                values.push(TransientProperty::StringArray("Requires", requires));
            }
            if self.mode == Mode::Redirect {
                // The main redirect client is the dedicated account, while
                // PID 1 runs the installed guard BIND and STOP control hooks
                // as root so they can authenticate their ControlPID.
                values.push(TransientProperty::Bool("PermissionsStartOnly", true));
            }
            let (bounding, ambient) = match self.mode {
                Mode::FullTun => ((1u64 << 10) | (1u64 << 12) | (1u64 << 13), 0),
                Mode::Redirect => (1u64 << 10, 1u64 << 10),
                Mode::Socks => (0, 0),
            };
            values.push(TransientProperty::U64("CapabilityBoundingSet", bounding));
            values.push(TransientProperty::U64("AmbientCapabilities", ambient));
            let mut writable = vec![self.state.clone()];
            if self.events != "/dev/null" {
                let event_dir = Path::new(&self.events).parent().ok_or(REFUSED)?;
                let event_dir = event_dir.to_str().ok_or(REFUSED)?.to_owned();
                if !writable.contains(&event_dir) {
                    writable.push(event_dir);
                }
            }
            values.push(TransientProperty::StringArray("ReadWritePaths", writable));
            if self.mode != Mode::Socks {
                values.extend([
                    TransientProperty::U64("TimeoutStopUSec", 15_000_000),
                    TransientProperty::Exec(
                        "ExecStop",
                        vec![vec![
                            self.binary.clone(),
                            "auto-stop-service-clean".into(),
                            unit.name().to_owned(),
                        ]],
                    ),
                    TransientProperty::Exec(
                        "ExecStopPost",
                        vec![vec![
                            self.binary.clone(),
                            "auto-stop-service".into(),
                            unit.name().to_owned(),
                        ]],
                    ),
                ]);
                values.push(TransientProperty::Exec(
                    "ExecStartPre",
                    vec![vec![
                        self.binary.clone(),
                        "auto-bind-service".into(),
                        unit.name().to_owned(),
                    ]],
                ));
            }
            if self.mode == Mode::FullTun {
                let timeout = self.guard_timeout.ok_or(REFUSED)?;
                values.push(TransientProperty::U64(
                    "TimeoutStartUSec",
                    u64::from(timeout) * 1_000_000,
                ));
            }
            Ok(values)
        }
    }
    fn private_unit_namespace_unshadowed(unit: &str) -> Result<()> {
        // PID 1 merges drop-ins even for transient services. They may add
        // ExecStartPre or override our fixed hooks before the first readback,
        // so refuse any applicable foreign source before StartTransientUnit.
        if !unit.starts_with("aegis-auto@")
            || !unit.ends_with(".service")
            || unit.len() != "aegis-auto@".len() + 64 + ".service".len()
            || !unit["aegis-auto@".len()..unit.len() - ".service".len()]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        let paths = crate::profile_auto_stopped_service::manager_query(
            crate::profile_auto_stopped_service::ManagerQuery::SearchPaths,
        )
        .map_err(|_| REFUSED)?;
        let roots = private_lookup_paths(&paths)?;
        let token = &unit["aegis-auto@".len()..unit.len() - ".service".len()];
        let applicable = [
            "aegis-.service".to_owned(),
            "aegis-@.service".to_owned(),
            format!("aegis-@{token}.service"),
            "aegis-auto@.service".to_owned(),
            unit.to_owned(),
        ];
        let mut names = ["d", "wants", "requires", "upholds"]
            .into_iter()
            .map(|suffix| format!("service.{suffix}"))
            .collect::<Vec<_>>();
        for base in &applicable {
            names.push(base.clone());
            for suffix in ["d", "wants", "requires", "upholds"] {
                names.push(format!("{base}.{suffix}"));
            }
        }
        for root in roots {
            let base = root.as_path();
            let meta = match fs::metadata(base) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(REFUSED),
            };
            if !meta.is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
                return Err(REFUSED);
            }
            for name in &names {
                match fs::symlink_metadata(base.join(name)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(REFUSED),
                }
            }
        }
        Ok(())
    }
    fn private_lookup_paths(paths: &[u8]) -> Result<Vec<PathBuf>> {
        if paths.len() > 8192 || paths.iter().any(|b| b.is_ascii_control() && *b != b'\n') {
            return Err(REFUSED);
        }
        let paths = std::str::from_utf8(paths).map_err(|_| REFUSED)?;
        let mut version = None;
        let mut unit_paths = None;
        for line in paths.lines() {
            let (key, value) = line.split_once('=').ok_or(REFUSED)?;
            match key {
                "Version" if version.is_none() => version = Some(value),
                "UnitPath" if unit_paths.is_none() => unit_paths = Some(value),
                _ => return Err(REFUSED),
            }
        }
        if !crate::profile_auto_unit_namespace::admitted_manager_version(version.ok_or(REFUSED)?) {
            return Err(REFUSED);
        }
        let roots: Vec<_> = unit_paths
            .ok_or(REFUSED)?
            .split_whitespace()
            .map(PathBuf::from)
            .collect();
        if roots.is_empty()
            || roots.len() > 32
            || roots
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != roots.len()
        {
            return Err(REFUSED);
        }
        for root in &roots {
            let base = root.as_path();
            if !base.is_absolute()
                || base.components().any(|component| {
                    !matches!(component, Component::RootDir | Component::Normal(_))
                })
                || ![
                    "/etc/systemd",
                    "/run/systemd",
                    "/usr/lib/systemd",
                    "/usr/local/lib/systemd",
                ]
                .iter()
                .any(|prefix| base.starts_with(prefix) && base != Path::new(prefix))
            {
                return Err(REFUSED);
            }
        }
        Ok(roots)
    }
    fn quote(path: &Path, exec: bool) -> Result<String> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path
                .components()
                .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        {
            return Err(REFUSED);
        }
        let value = path.to_str().ok_or(REFUSED)?;
        if value.len() > 4096 || value.bytes().any(|b| b < 32 || b == 127) {
            return Err(REFUSED);
        }
        let mut out = String::from("\"");
        for c in value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '%' => out.push_str("%%"),
                '$' if exec => out.push_str("$$"),
                other => out.push(other),
            }
        }
        out.push('"');
        Ok(out)
    }
    // WorkingDirectory= parses one scalar path, including literal spaces and
    // quotes; ExecStart= and ReadWritePaths= use their own list grammars.
    fn scalar_path(path: &Path) -> Result<String> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(REFUSED);
        }
        let value = path.to_str().ok_or(REFUSED)?;
        if value.len() > 4096
            || value.bytes().any(|b| b < 32 || b == 127)
            || value
                .as_bytes()
                .last()
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'\\')
        {
            return Err(REFUSED);
        }
        Ok(value.replace('%', "%%"))
    }
    // The After= values of every client guard hook install.sh has written,
    // oldest first: from 8d2cd08d, and since d0b9bc24 (UFW ordering). Only
    // these exact generations are admitted; the newest must stay byte-equal
    // to the install.sh heredoc (see the tests).
    const INSTALLER_GUARD_AFTER: [&str; 2] = [
        "aegis-device-egress-guard.service",
        "aegis-device-egress-guard.service ufw.service",
    ];
    fn installer_device_guard_dropin(timeout: u32, after: &str) -> String {
        format!("[Unit]\nRequires=aegis-device-egress-guard.service\nAfter={after}\n[Service]\nType=notify\nNotifyAccess=main\nTimeoutStartSec={timeout}\nEnvironment=AEGIS_DEVICE_GUARD_STATE={DEVICE_GUARD_STATE}\nExecStartPre=/bin/bash {DEVICE_GUARD_HELPER} bind\nExecStartPost=/bin/bash {DEVICE_GUARD_HELPER} capture-bind-legacy\nExecStopPost=/bin/bash {DEVICE_GUARD_HELPER} block\n")
    }
    fn prior_installer_device_guard_dropin(timeout: u32, after: &str) -> String {
        format!("[Unit]\nRequires=aegis-device-egress-guard.service\nAfter={after}\n[Service]\nType=notify\nNotifyAccess=main\nTimeoutStartSec={timeout}\nEnvironment=AEGIS_DEVICE_GUARD_STATE={DEVICE_GUARD_STATE}\nExecStartPre=/bin/bash {DEVICE_GUARD_HELPER} bind\nExecStopPost=/bin/bash {DEVICE_GUARD_HELPER} block\n")
    }
    /// True only for the exact bytes one shipped installer generation writes
    /// for this exact startup timeout; no prefix, pattern or other timeout.
    fn installer_guard_hook(original: &[u8], timeout: u32) -> bool {
        matches!(timeout, 60 | 180)
            && INSTALLER_GUARD_AFTER.iter().any(|after| {
                original == installer_device_guard_dropin(timeout, after).as_bytes()
                    || original == prior_installer_device_guard_dropin(timeout, after).as_bytes()
            })
    }
    #[cfg(test)]
    fn old_device_guard_dropin(timeout: u32) -> String {
        prior_installer_device_guard_dropin(timeout, INSTALLER_GUARD_AFTER[0])
    }
    // The After= values of every owned AUTO guard hook this compiler has
    // published, oldest first: the original owned hook, and since Option B
    // the installer's ufw.service ordering kept. Publication writes only the
    // newest; an older generation is admitted only at its exact bytes for the
    // same timeout and the same protected binary.
    const OWNED_GUARD_AFTER: [&str; 2] = [
        "aegis-device-egress-guard.service",
        "aegis-device-egress-guard.service ufw.service",
    ];
    fn owned_device_guard_dropin_after(timeout: u32, binary: &Path, after: &str) -> Result<String> {
        Ok(format!("[Unit]\nRequires=aegis-device-egress-guard.service\nAfter={after}\n[Service]\nType=notify\nNotifyAccess=main\nTimeoutStartSec={timeout}\nEnvironment=AEGIS_DEVICE_GUARD_STATE={DEVICE_GUARD_STATE}\nExecStartPre={} auto-bind-service %n\n",quote(binary,true)?))
    }
    fn owned_device_guard_dropin(timeout: u32, binary: &Path) -> Result<String> {
        owned_device_guard_dropin_after(
            timeout,
            binary,
            OWNED_GUARD_AFTER[OWNED_GUARD_AFTER.len() - 1],
        )
    }
    /// Every owned generation for this exact timeout and binary, oldest first.
    fn owned_guard_generations(timeout: u32, binary: &Path) -> Result<Vec<String>> {
        OWNED_GUARD_AFTER
            .iter()
            .map(|after| owned_device_guard_dropin_after(timeout, binary, after))
            .collect()
    }
    /// True only for the exact bytes of one owned generation at this exact
    /// startup timeout and protected binary; no prefix, pattern or other timeout.
    fn owned_guard_hook(original: &[u8], timeout: u32, binary: &Path) -> Result<bool> {
        Ok(matches!(timeout, 60 | 180)
            && owned_guard_generations(timeout, binary)?
                .iter()
                .any(|generation| original == generation.as_bytes()))
    }
    /// Accepts only the exact installed guard hook transition for the
    /// protected binary and timeout already bound into this compiled policy.
    pub(crate) fn verify_owned_guard_transition(
        compiled: &CompiledPolicy,
        original: &[u8],
    ) -> Result<()> {
        if compiled.transient.mode != Mode::FullTun {
            return Err(REFUSED);
        }
        let timeout = compiled.transient.guard_timeout.ok_or(REFUSED)?;
        if !matches!(timeout, 60 | 180) {
            return Err(REFUSED);
        }
        let binary = Path::new(&compiled.transient.binary);
        let owned = owned_device_guard_dropin(timeout, binary)?;
        if compiled
            .dropins
            .get(Path::new(DEVICE_GUARD_DROPIN))
            .map(Vec::as_slice)
            != Some(owned.as_bytes())
            || (!installer_guard_hook(original, timeout)
                && !owned_guard_hook(original, timeout, binary)?)
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    pub(crate) fn compile(
        input: &CompilerInputs,
        captured_unit: &[u8],
        captured_env: &[u8],
        old_dropins: &BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<CompiledPolicy> {
        compile_inner(input, captured_unit, captured_env, old_dropins, false)
    }
    /// This entry point is used only after unit_store authenticates the
    /// captured, source-bound first-arm receipt and current installed guard.
    /// A fresh unit namespace has no client drop-ins to carry the older guard
    /// hook, so the compiler creates the same owned hook from that authority.
    pub(crate) fn compile_first_arm(
        input: &CompilerInputs,
        captured_unit: &[u8],
        captured_env: &[u8],
        old_dropins: &BTreeMap<PathBuf, Vec<u8>>,
        _admission: &crate::profile_auto_transaction::VerifiedFirstArm,
    ) -> Result<CompiledPolicy> {
        if input.mode != Mode::FullTun
            || !old_dropins.is_empty()
                && (old_dropins.len() != 1
                    || old_dropins
                        .get(Path::new(V2_BOOT_GATE_DROPIN))
                        .map(Vec::as_slice)
                        != Some(V2_BOOT_GATE_BYTES.as_bytes()))
        {
            return Err(COMPILE_FIRST_ARM_ENTRY);
        }
        compile_inner(input, captured_unit, captured_env, old_dropins, true)
    }
    fn compile_inner(
        input: &CompilerInputs,
        captured_unit: &[u8],
        captured_env: &[u8],
        old_dropins: &BTreeMap<PathBuf, Vec<u8>>,
        fresh_first_arm: bool,
    ) -> Result<CompiledPolicy> {
        if captured_unit != UNIT.as_bytes() || captured_env != ENVIRONMENT.as_bytes() {
            return Err(COMPILE_TEMPLATE);
        }
        if (input.policy == Policy::Root) != (input.user == RuntimeUser::Root)
            || (input.mode == Mode::FullTun && input.policy != Policy::Root)
            || (input.mode == Mode::Redirect && input.policy != Policy::DedicatedBind)
        {
            return Err(COMPILE_IDENTITY_MODE);
        }
        if old_dropins.len() > 128
            || old_dropins.iter().any(|(p, b)| {
                p.is_absolute()
                    || p.components().any(|c| !matches!(c, Component::Normal(_)))
                    || b.len() > LIMIT
            })
        {
            return Err(COMPILE_DROPIN_BOUNDS);
        }
        if old_dropins
            .get(Path::new(V2_BOOT_GATE_DROPIN))
            .is_some_and(|bytes| bytes != V2_BOOT_GATE_BYTES.as_bytes())
        {
            return Err(COMPILE_BOOT_GATE);
        }
        let mut dropins = old_dropins.clone();
        let mut guard_timeout = None;
        dropins.remove(Path::new("10-dedicated-uid.conf"));
        dropins.remove(Path::new("20-ipv6-tun.conf"));
        if UNIT.matches("Type=simple\n").count() != 1 || UNIT.contains("NotifyAccess=") {
            return Err(COMPILE_UNIT_TEMPLATE);
        }
        let mut unit = UNIT
            .replacen("[Unit]\n", &format!("[Unit]\n{V2_BOOT_INTERLOCK}\n"), 1)
            .replace("Type=simple\n", "Type=notify\nNotifyAccess=main\n")
            .replace("__AEGIS_CLIENT_ENV_FILE__", "/etc/default/aegis-client")
            .replace(
                "WorkingDirectory=__AEGIS_CLIENT_STATE_DIR__",
                &format!("WorkingDirectory={}", scalar_path(&input.state)?),
            )
            .replace(
                "ReadWritePaths=__AEGIS_CLIENT_STATE_DIR__",
                &format!("ReadWritePaths={}", quote(&input.state, false)?),
            )
            .replace("__AEGIS_CLIENT_BIN__", &quote(&input.binary, true)?)
            .replace("__AEGIS_CLIENT_CONFIG__", &quote(&input.config, true)?)
            .replace(
                "__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__",
                &quote(&input.events, true)?,
            );
        if unit.contains("__AEGIS_")
            || unit.len() > LIMIT
            || unit.matches(V2_BOOT_INTERLOCK).count() != 1
        {
            return Err(COMPILE_UNIT_RENDER);
        }
        match input.policy {
            Policy::Root if input.mode == Mode::FullTun => {
                // The ordinary installed v2 guard drop-in acquires its own
                // guard flock in ExecStartPre/ExecStopPost. The AUTO owner
                // retains that exact flock through PID 1's StartUnit job, so
                // those hooks would deadlock. The captured root-owned
                // namespace may contain our rendered replacement. Its exact
                // bytes establish a recognized current policy, not who wrote
                // it. Admit only a shipped installer generation or that
                // byte-exact variant for this protected installed binary;
                // unknown or stale-binary hooks still refuse.
                // No retained Aegis-owned drop-in may add a later lifecycle
                // hook or override Type/Restart after our fixed base unit.
                // The two older AUTO leaves are removed above; every other
                // name must be the exact installed guard variant below.
                if old_dropins.keys().any(|name| {
                    name != Path::new(DEVICE_GUARD_DROPIN)
                        && name != Path::new(V2_BOOT_GATE_DROPIN)
                        && name != Path::new("10-dedicated-uid.conf")
                        && name != Path::new("20-ipv6-tun.conf")
                }) {
                    return Err(COMPILE_FULLTUN_DROPIN_NAME);
                }
                let rendered = [60u32, 180]
                    .into_iter()
                    .map(|seconds| Ok((seconds, owned_guard_generations(seconds, &input.binary)?)))
                    .collect::<Result<Vec<_>>>()?;
                let timeout = if fresh_first_arm {
                    if !old_dropins.is_empty()
                        && (old_dropins.len() != 1
                            || old_dropins
                                .get(Path::new(V2_BOOT_GATE_DROPIN))
                                .map(Vec::as_slice)
                                != Some(V2_BOOT_GATE_BYTES.as_bytes()))
                    {
                        return Err(COMPILE_FIRST_ARM_DROPINS);
                    }
                    60
                } else {
                    let original_guard = old_dropins
                        .get(Path::new(DEVICE_GUARD_DROPIN))
                        .ok_or(COMPILE_GUARD_HOOK_MISSING)?;
                    rendered
                        .iter()
                        .find(|(seconds, owned)| {
                            installer_guard_hook(original_guard, *seconds)
                                || owned.iter().any(|generation| {
                                    original_guard.as_slice() == generation.as_bytes()
                                })
                        })
                        .map(|(seconds, _)| *seconds)
                        .ok_or(COMPILE_GUARD_HOOK_UNRECOGNIZED)?
                };
                dropins.insert(
                    DEVICE_GUARD_DROPIN.into(),
                    owned_device_guard_dropin(timeout, &input.binary)?.into_bytes(),
                );
                guard_timeout = Some(timeout);
                // The executable is the exact installed binary admitted by
                // the protected payload receipt.  The hidden command sends
                // only a fixed STOP_BEGIN request to the installed guardian;
                // no shell or route-changing argv is emitted by systemd.
                // Guardian retains the pre-effect intent until the service
                // cgroup is empty after ExecStopPost has exited.
                if unit.matches("[Unit]\n").count() != 1
                    || unit.matches("[Service]\n").count() != 1
                    || unit.contains("ExecStop=")
                    || unit.contains("ExecStopPost=")
                    || unit.contains("TimeoutStopSec=")
                    || unit.matches("Restart=on-failure\n").count() != 1
                {
                    return Err(COMPILE_FULLTUN_UNIT_SHAPE);
                }
                unit = unit.replace(
                    "[Unit]\n",
                    "[Unit]\nRequires=aegis-auto-guardian.service\nAfter=aegis-auto-guardian.service\n",
                );
                unit = unit.replace(
                    "[Service]\n",
                    &format!(
                        "[Service]\nExecStop={} auto-stop-service-clean %n\nExecStopPost={} auto-stop-service %n\nTimeoutStopSec=15s\n",
                        quote(&input.binary, true)?,
                        quote(&input.binary, true)?
                    ),
                );
                // An unexpected exit must not create a new service invocation
                // outside the original AUTO owner and one-use PID 1 ticket.
                unit = unit.replace("Restart=on-failure\n", "Restart=no\n");
            }
            Policy::Root => {}
            policy => {
                let cap = if policy == Policy::DedicatedBind {
                    "CAP_NET_BIND_SERVICE"
                } else {
                    ""
                };
                let events_dir = if input.events == Path::new("/dev/null") {
                    String::new()
                } else {
                    format!(" {}", quote(input.events.parent().ok_or(REFUSED)?, false)?)
                };
                let text=format!("# AUTO-owned dedicated runtime policy.\n[Service]\nUser={}\nGroup={}\nNoNewPrivileges=true\nAmbientCapabilities=\nAmbientCapabilities={}\nCapabilityBoundingSet=\nCapabilityBoundingSet={}\nReadWritePaths={}{}\n",input.user.name(),input.user.name(),cap,cap,quote(&input.state,false)?,events_dir);
                dropins.insert("10-dedicated-uid.conf".into(), text.into_bytes());
            }
        }
        if unit.len() > LIMIT || unit.contains("__AEGIS_") {
            return Err(COMPILE_UNIT_RENDER);
        }
        Ok(CompiledPolicy {
            unit: unit.into_bytes(),
            environment: ENVIRONMENT.as_bytes().to_vec(),
            dropins,
            transient: TransientPolicy {
                mode: input.mode,
                user: input.user,
                binary: input.binary.to_str().ok_or(REFUSED)?.to_owned(),
                config: input.config.to_str().ok_or(REFUSED)?.to_owned(),
                state: input.state.to_str().ok_or(REFUSED)?.to_owned(),
                events: input.events.to_str().ok_or(REFUSED)?.to_owned(),
                guard_timeout,
            },
        })
    }
    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Node {
        dev: u64,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        len: i64,
        mtime: i64,
        mtime_ns: i64,
        ctime: i64,
        ctime_ns: i64,
    }
    fn node(fd: i32) -> Result<Node> {
        let mut s: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut s) } != 0 {
            return Err(REFUSED);
        }
        #[allow(clippy::useless_conversion)]
        let links = u64::from(s.st_nlink);
        Ok(Node {
            dev: s.st_dev,
            ino: s.st_ino,
            mode: s.st_mode,
            uid: s.st_uid,
            gid: s.st_gid,
            links,
            len: s.st_size,
            mtime: s.st_mtime,
            mtime_ns: s.st_mtime_nsec,
            ctime: s.st_ctime,
            ctime_ns: s.st_ctime_nsec,
        })
    }
    fn inode(a: &Node, b: &Node) -> bool {
        a.dev == b.dev
            && a.ino == b.ino
            && a.mode == b.mode
            && a.uid == b.uid
            && a.gid == b.gid
            && a.links == b.links
            && a.len == b.len
            && a.mtime == b.mtime
            && a.mtime_ns == b.mtime_ns
    }
    fn c(s: &str) -> Result<CString> {
        CString::new(s).map_err(|_| REFUSED)
    }
    fn owned(fd: i32) -> Result<OwnedFd> {
        if fd < 0 {
            Err(REFUSED)
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
    fn hash(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }
    fn read(parent: &OwnedFd, name: &str) -> Result<Option<(Node, Vec<u8>)>> {
        let name = c(name)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(REFUSED)
            };
        }
        let fd = owned(raw)?;
        let before = node(fd.as_raw_fd())?;
        if before.mode & libc::S_IFMT != libc::S_IFREG
            || before.uid != 0
            || before.links != 1
            || before.len < 0
            || before.len as usize > LIMIT
            || before.mode & 0o022 != 0
        {
            return Err(REFUSED);
        }
        let mut bytes = Vec::new();
        let mut file = File::from(fd);
        (&mut file)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        if node(file.as_raw_fd())? != before {
            return Err(REFUSED);
        }
        // Independently reopen same leaf, compare generation after bounded read.
        let again = owned(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        if bytes.len() != before.len as usize || node(again.as_raw_fd())? != before {
            return Err(REFUSED);
        }
        Ok(Some((before, bytes)))
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Original {
        pub(crate) node: Option<Node>,
        pub(crate) digest: Option<[u8; 32]>,
    }
    pub(crate) struct Targets {
        pub(crate) parent: OwnedFd,
        pub(crate) stage: OwnedFd,
    }
    /// Prepare-only. Caller must independently admit this held parent as the
    /// provider's fixed namespace role, surrounding capture with its guards.
    /// This is not a pathname, JSON, or standalone CLI authority constructor.
    pub(crate) fn capture_original_leaf(parent: &OwnedFd, role: LeafRole) -> Result<Original> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(REFUSED);
        }
        let n = node(parent.as_raw_fd())?;
        if n.mode & libc::S_IFMT != libc::S_IFDIR || n.uid != 0 || n.mode & 0o022 != 0 {
            return Err(REFUSED);
        }
        match read(parent, role.name())? {
            None => Ok(Original {
                node: None,
                digest: None,
            }),
            Some((n, b)) => Ok(Original {
                node: Some(n),
                digest: Some(hash(&b)),
            }),
        }
    }

    #[derive(Clone, Copy)]
    pub(crate) enum Mutation {
        StageCreate,
        StageLink,
        Publish,
        Rollback,
        RecoverReadback,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Intent {
        pub(crate) role: LeafRole,
        pub(crate) epoch: [u8; 32],
        original: Original,
        prepared: Node,
        digest: [u8; 32],
        parent: Node,
        stage: Node,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Receipt {
        intent: Intent,
        published: Node,
        displaced: Option<Node>,
    }
    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct OriginalNamespaceMetadata {
        pub(crate) device: u64,
        pub(crate) inode: u64,
        pub(crate) uid: u32,
        pub(crate) gid: u32,
        pub(crate) mode: u32,
        pub(crate) links: u64,
        pub(crate) size: i64,
        pub(crate) mtime_sec: i64,
        pub(crate) mtime_nsec: i64,
        pub(crate) ctime_sec: i64,
        pub(crate) ctime_nsec: i64,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct OriginalNamespaceWitness {
        pub(crate) role: LeafRole,
        pub(crate) metadata: Option<OriginalNamespaceMetadata>,
        pub(crate) sha256: Option<[u8; 32]>,
    }
    impl Original {
        // Observation only: the coordinator must bind this to the sealed role
        // namespace before admitting the captured original.
        pub(crate) fn namespace_witness(&self, role: LeafRole) -> OriginalNamespaceWitness {
            OriginalNamespaceWitness {
                role,
                sha256: self.digest,
                metadata: self.node.as_ref().map(|n| OriginalNamespaceMetadata {
                    device: n.dev,
                    inode: n.ino,
                    uid: n.uid,
                    gid: n.gid,
                    mode: n.mode,
                    links: n.links,
                    size: n.len,
                    mtime_sec: n.mtime,
                    mtime_nsec: n.mtime_ns,
                    ctime_sec: n.ctime,
                    ctime_nsec: n.ctime_ns,
                }),
            }
        }
    }
    impl Receipt {
        // Read-only source fields from the authenticated actual intent. Caller
        // must run verify(context,self) before comparing to opaque NamespaceRecord.
        pub(crate) fn original_namespace_witness(&self) -> OriginalNamespaceWitness {
            self.intent.original.namespace_witness(self.intent.role)
        }
        pub(crate) fn publication_epoch(&self) -> [u8; 32] {
            self.intent.epoch
        }
        pub(crate) fn intent(&self) -> &Intent {
            &self.intent
        }
        pub(crate) fn role(&self) -> LeafRole {
            self.intent.role
        }
    }

    // No default/mock authority. RootContext must bind fixed role namespace,
    // held global InstallLock, original generation and provider stop proof.
    pub(crate) trait Context {
        fn epoch(&self) -> Result<[u8; 32]>;
        fn held_targets(&self, role: LeafRole) -> Result<Targets>;
        fn original(&self, role: LeafRole) -> Result<Original>;
        fn accepted_bytes(&self, role: LeafRole) -> Result<Vec<u8>>;
        fn original_guard(&self, role: LeafRole, original: &Original) -> Result<()>;
        fn stopped_mutation(
            &self,
            role: LeafRole,
            epoch: &[u8; 32],
            operation: Mutation,
            actual: &mut dyn FnMut() -> Result<()>,
        ) -> Result<()>;
        fn stage_prepared(&self, intent: &Intent) -> Result<()>;
        fn persist_intent(&self, intent: &Intent) -> Result<()>;
        fn admit_intent(&self, intent: &Intent) -> Result<()>;
        /// Exact durable source retained after completed pending publication.
        fn admit_durable_publication_intent(&self, intent: &Intent) -> Result<()>;
        fn commit_receipt(&self, receipt: &Receipt) -> Result<()>;
        fn admit_receipt(&self, receipt: &Receipt) -> Result<()>;
        fn persist_rollback_intent(&self, receipt: &Receipt, epoch: &[u8; 32]) -> Result<()>;
        fn admit_rollback_intent(&self, receipt: &Receipt, epoch: &[u8; 32]) -> Result<()>;
        fn commit_rollback(&self, receipt: &RestorationReceipt) -> Result<()>;
        fn admit_restoration(&self, receipt: &RestorationReceipt) -> Result<()>;
        /// Durable source/predecessor admission remains valid after the completed
        /// restoration transition clears the live pending-intent pointer.
        fn admit_restoration_source(&self, receipt: &RestorationReceipt) -> Result<()>;
    }

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RestorationReceipt {
        forward: Receipt,
        rollback_epoch: [u8; 32],
        restored: Option<Node>,
        retired_new: Node,
        parent: Node,
        stage: Node,
    }
    impl RestorationReceipt {
        pub(crate) fn forward_receipt(&self) -> &Receipt {
            &self.forward
        }
        pub(crate) fn role(&self) -> LeafRole {
            self.forward.role()
        }
        pub(crate) fn rollback_epoch(&self) -> [u8; 32] {
            self.rollback_epoch
        }
        pub(crate) fn restored_namespace_witness(&self) -> OriginalNamespaceWitness {
            OriginalNamespaceWitness {
                role: self.role(),
                sha256: self.forward.intent.original.digest,
                metadata: self.restored.as_ref().map(|n| OriginalNamespaceMetadata {
                    device: n.dev,
                    inode: n.ino,
                    uid: n.uid,
                    gid: n.gid,
                    mode: n.mode,
                    links: n.links,
                    size: n.len,
                    mtime_sec: n.mtime,
                    mtime_nsec: n.mtime_ns,
                    ctime_sec: n.ctime,
                    ctime_nsec: n.ctime_ns,
                }),
            }
        }
    }
    pub(crate) enum RollbackRecovery {
        NotApplied,
        Completed(Box<RestorationReceipt>),
    }

    fn directories(t: &Targets) -> Result<(Node, Node)> {
        let parent = node(t.parent.as_raw_fd())?;
        let stage = node(t.stage.as_raw_fd())?;
        if parent.mode & libc::S_IFMT != libc::S_IFDIR
            || parent.uid != 0
            || parent.mode & 0o022 != 0
            || stage.mode & libc::S_IFMT != libc::S_IFDIR
            || stage.uid != 0
            || stage.mode & 0o777 != 0o700
            || stage.dev != parent.dev
            || stage.ino == parent.ino
        {
            return Err(REFUSED);
        }
        Ok((parent, stage))
    }
    fn original_now(t: &Targets, role: LeafRole, expected: &Original) -> Result<()> {
        match (
            read(&t.parent, role.name())?,
            &expected.node,
            &expected.digest,
        ) {
            (None, None, None) => Ok(()),
            (Some((n, b)), Some(old), Some(d)) if &n == old && hash(&b) == *d => Ok(()),
            _ => Err(REFUSED),
        }
    }
    pub(crate) fn publish<C: Context>(context: &C, role: LeafRole) -> Result<Receipt> {
        let accepted = context.accepted_bytes(role)?;
        let bytes = accepted.as_slice();
        if unsafe { libc::geteuid() } != 0
            || bytes.is_empty()
            || bytes.len() > LIMIT
            || std::str::from_utf8(bytes).is_err()
        {
            return Err(REFUSED);
        }
        let epoch = context.epoch()?;
        let t = context.held_targets(role)?;
        let (parent, stage) = directories(&t)?;
        let original = context.original(role)?;
        context.original_guard(role, &original)?;
        original_now(&t, role, &original)?;
        let mut fresh = None;
        context.stopped_mutation(role, &epoch, Mutation::StageCreate, &mut || {
            let fd = owned(unsafe {
                libc::openat(
                    t.stage.as_raw_fd(),
                    c(".")?.as_ptr(),
                    libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(|_| REFUSED)?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0
                || unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
            {
                return Err(REFUSED);
            }
            file.sync_all().map_err(|_| REFUSED)?;
            fresh = Some(file);
            Ok(())
        })?;
        let fresh = fresh.ok_or(REFUSED)?;
        let prepared = node(fresh.as_raw_fd())?;
        if prepared.uid != 0
            || prepared.gid != 0
            || prepared.mode & 0o777 != 0o644
            || prepared.len != bytes.len() as i64
            || prepared.links != 0
        {
            return Err(REFUSED);
        }
        let intent = Intent {
            role,
            epoch,
            original,
            prepared,
            digest: hash(bytes),
            parent,
            stage,
        };
        context.stage_prepared(&intent)?;
        context.stopped_mutation(role, &epoch, Mutation::StageLink, &mut || {
            if unsafe {
                libc::linkat(
                    fresh.as_raw_fd(),
                    c("")?.as_ptr(),
                    t.stage.as_raw_fd(),
                    c(role.stage())?.as_ptr(),
                    libc::AT_EMPTY_PATH,
                )
            } != 0
            {
                return Err(REFUSED);
            }
            if unsafe { libc::fsync(t.stage.as_raw_fd()) } != 0 {
                return Err(REFUSED);
            }
            Ok(())
        })?;
        context.persist_intent(&intent)?;
        let mut committed = None;
        context.stopped_mutation(role, &epoch, Mutation::Publish, &mut || {
            context.original_guard(role, &intent.original)?;
            original_now(&t, role, &intent.original)?;
            let staged = read(&t.stage, role.stage())?.ok_or(REFUSED)?;
            let current = node(fresh.as_raw_fd())?;
            let mut expected = intent.prepared.clone();
            expected.links = 1;
            if staged.0 != current
                || hash(&staged.1) != intent.digest
                || !inode(&current, &expected)
            {
                return Err(REFUSED);
            }
            let flags = if intent.original.node.is_some() {
                libc::RENAME_EXCHANGE
            } else {
                libc::RENAME_NOREPLACE
            };
            if unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    t.stage.as_raw_fd(),
                    c(role.stage())?.as_ptr(),
                    t.parent.as_raw_fd(),
                    c(role.name())?.as_ptr(),
                    flags,
                )
            } != 0
            {
                return Err(REFUSED);
            }
            if unsafe { libc::fsync(t.parent.as_raw_fd()) } != 0
                || unsafe { libc::fsync(t.stage.as_raw_fd()) } != 0
            {
                return Err(REFUSED);
            }
            let current = read(&t.parent, role.name())?.ok_or(REFUSED)?;
            let actual = node(fresh.as_raw_fd())?;
            if current.0 != actual || hash(&current.1) != intent.digest {
                return Err(REFUSED);
            }
            let displaced = match &intent.original.node {
                None => {
                    if read(&t.stage, role.stage())?.is_some() {
                        return Err(REFUSED);
                    }
                    None
                }
                Some(old) => {
                    let (saved, bytes) = read(&t.stage, role.stage())?.ok_or(REFUSED)?;
                    if !inode(old, &saved) || Some(hash(&bytes)) != intent.original.digest {
                        return Err(REFUSED);
                    }
                    Some(saved)
                }
            };
            let receipt = Receipt {
                intent: intent.clone(),
                published: actual,
                displaced,
            };
            context.commit_receipt(&receipt)?;
            committed = Some(receipt);
            Ok(())
        })?;
        let receipt = committed.ok_or(REFUSED)?;
        verify(context, &receipt)?;
        Ok(receipt)
    }
    pub(crate) fn verify<C: Context>(context: &C, receipt: &Receipt) -> Result<()> {
        context.admit_receipt(receipt)?;
        let accepted = context.accepted_bytes(receipt.intent.role)?;
        if hash(&accepted) != receipt.intent.digest {
            return Err(REFUSED);
        }
        let t = context.held_targets(receipt.intent.role)?;
        let (parent, stage) = directories(&t)?;
        // Directory times change with our entries. Fixed inode/ownership remain.
        if parent.dev != receipt.intent.parent.dev
            || parent.ino != receipt.intent.parent.ino
            || stage.dev != receipt.intent.stage.dev
            || stage.ino != receipt.intent.stage.ino
        {
            return Err(REFUSED);
        }
        let (n, b) = read(&t.parent, receipt.intent.role.name())?.ok_or(REFUSED)?;
        if n != receipt.published || hash(&b) != receipt.intent.digest {
            return Err(REFUSED);
        }
        Ok(())
    }
    pub(crate) fn rollback<C: Context>(
        context: &C,
        receipt: &Receipt,
    ) -> Result<RestorationReceipt> {
        verify(context, receipt)?;
        let t = context.held_targets(receipt.intent.role)?;
        let role = receipt.intent.role;
        let epoch = context.epoch()?;
        context.persist_rollback_intent(receipt, &epoch)?;
        let mut restored = None;
        context.stopped_mutation(role, &epoch, Mutation::Rollback, &mut || {
            verify(context, receipt)?;
            match &receipt.displaced {
                Some(old) => {
                    let (n, b) = read(&t.stage, role.stage())?.ok_or(REFUSED)?;
                    if &n != old || Some(hash(&b)) != receipt.intent.original.digest {
                        return Err(REFUSED);
                    }
                    if unsafe {
                        libc::syscall(
                            libc::SYS_renameat2,
                            t.stage.as_raw_fd(),
                            c(role.stage())?.as_ptr(),
                            t.parent.as_raw_fd(),
                            c(role.name())?.as_ptr(),
                            libc::RENAME_EXCHANGE,
                        )
                    } != 0
                    {
                        return Err(REFUSED);
                    }
                }
                None => {
                    if unsafe {
                        libc::syscall(
                            libc::SYS_renameat2,
                            t.parent.as_raw_fd(),
                            c(role.name())?.as_ptr(),
                            t.stage.as_raw_fd(),
                            c(role.backup())?.as_ptr(),
                            libc::RENAME_NOREPLACE,
                        )
                    } != 0
                    {
                        return Err(REFUSED);
                    }
                }
            }
            if unsafe { libc::fsync(t.parent.as_raw_fd()) } != 0
                || unsafe { libc::fsync(t.stage.as_raw_fd()) } != 0
            {
                return Err(REFUSED);
            }
            let restoration = restoration_readback(context, receipt, &epoch, &t)?;
            context.commit_rollback(&restoration)?;
            restored = Some(restoration);
            Ok(())
        })?;
        let restoration = restored.ok_or(REFUSED)?;
        verify_restoration(context, &restoration)?;
        Ok(restoration)
    }
    fn restoration_readback<C: Context>(
        context: &C,
        forward: &Receipt,
        epoch: &[u8; 32],
        t: &Targets,
    ) -> Result<RestorationReceipt> {
        context.admit_rollback_intent(forward, epoch)?;
        observed_restoration_readback(context, forward, epoch, t)
    }
    fn observed_restoration_readback<C: Context>(
        context: &C,
        forward: &Receipt,
        epoch: &[u8; 32],
        t: &Targets,
    ) -> Result<RestorationReceipt> {
        if context.epoch()? != *epoch {
            return Err(REFUSED);
        }
        intent_anchors(t, &forward.intent)?;
        let value = read(&t.parent, forward.role().name())?;
        if !original_matches(value.as_ref(), &forward.intent.original) {
            return Err(REFUSED);
        }
        let name = if forward.intent.original.node.is_some() {
            forward.role().stage()
        } else {
            forward.role().backup()
        };
        let (retired, bytes) = read(&t.stage, name)?.ok_or(REFUSED)?;
        if !inode(&retired, &forward.published) || hash(&bytes) != forward.intent.digest {
            return Err(REFUSED);
        }
        let (parent, stage) = directories(t)?;
        Ok(RestorationReceipt {
            forward: forward.clone(),
            rollback_epoch: *epoch,
            restored: value.map(|(n, _)| n),
            retired_new: retired,
            parent,
            stage,
        })
    }
    pub(crate) fn verify_restoration<C: Context>(
        context: &C,
        receipt: &RestorationReceipt,
    ) -> Result<()> {
        context.admit_receipt(&receipt.forward)?;
        context.admit_restoration(receipt)?;
        context.admit_restoration_source(receipt)?;
        let t = context.held_targets(receipt.role())?;
        let actual =
            observed_restoration_readback(context, &receipt.forward, &receipt.rollback_epoch, &t)?;
        if actual.restored != receipt.restored
            || actual.retired_new != receipt.retired_new
            || (
                actual.parent.dev,
                actual.parent.ino,
                actual.parent.mode,
                actual.parent.uid,
                actual.parent.gid,
            ) != (
                receipt.parent.dev,
                receipt.parent.ino,
                receipt.parent.mode,
                receipt.parent.uid,
                receipt.parent.gid,
            )
            || (
                actual.stage.dev,
                actual.stage.ino,
                actual.stage.mode,
                actual.stage.uid,
                actual.stage.gid,
            ) != (
                receipt.stage.dev,
                receipt.stage.ino,
                receipt.stage.mode,
                receipt.stage.uid,
                receipt.stage.gid,
            )
        {
            return Err(REFUSED);
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum PendingSingletonOutcome {
        NotApplied,
        Completed,
    }
    enum PendingSingletonClaim {
        Publish(Intent),
        Restore(Receipt, [u8; 32]),
    }
    /// Opaque actual held-target proof, never deserialized from claimant JSON.
    pub(crate) struct PendingSingletonReadback {
        claim: PendingSingletonClaim,
        targets: Targets,
        target: Option<(Node, Vec<u8>)>,
        staged: Option<(Node, Vec<u8>)>,
        backup: Option<(Node, Vec<u8>)>,
        outcome: PendingSingletonOutcome,
    }
    impl PendingSingletonReadback {
        /// Only this opaque actual completed BaseUnit publication may cross
        /// the recovery-purpose final-base gate. Enum/purpose alone is no proof.
        pub(crate) fn require_completed_base<C: Context>(&self, context: &C) -> Result<()> {
            if !matches!(&self.claim,PendingSingletonClaim::Publish(i) if i.role==LeafRole::BaseUnit)
                || self.outcome != PendingSingletonOutcome::Completed
            {
                return Err(REFUSED);
            }
            self.revalidate(context)
        }
        pub(crate) fn role(&self) -> LeafRole {
            match &self.claim {
                PendingSingletonClaim::Publish(i) => i.role,
                PendingSingletonClaim::Restore(r, _) => r.role(),
            }
        }
        pub(crate) fn outcome(&self) -> PendingSingletonOutcome {
            self.outcome
        }
        pub(crate) fn target_witness(&self) -> OriginalNamespaceWitness {
            // Reuse the established lossless Node -> namespace metadata
            // conversion. This observed target comes only from the opaque held
            // readback capability; the conversion itself grants no authority.
            Original {
                node: self.target.as_ref().map(|(n, _)| n.clone()),
                digest: self.target.as_ref().map(|(_, b)| hash(b)),
            }
            .namespace_witness(self.role())
        }
        pub(crate) fn revalidate<C: Context>(&self, context: &C) -> Result<()> {
            self.revalidate_source(context, false)
        }
        pub(crate) fn revalidate_recovered_publication<C: Context>(
            &self,
            context: &C,
        ) -> Result<()> {
            if !matches!(&self.claim, PendingSingletonClaim::Publish(_)) {
                return Err(REFUSED);
            }
            self.revalidate_source(context, true)
        }
        fn revalidate_source<C: Context>(&self, context: &C, durable: bool) -> Result<()> {
            let intent = match &self.claim {
                PendingSingletonClaim::Publish(i) => {
                    if durable {
                        context.admit_durable_publication_intent(i)?;
                    } else {
                        context.admit_intent(i)?;
                    }
                    if context.epoch()? != i.epoch
                        || hash(&context.accepted_bytes(i.role)?) != i.digest
                    {
                        return Err(REFUSED);
                    }
                    i
                }
                PendingSingletonClaim::Restore(r, e) => {
                    context.admit_rollback_intent(r, e)?;
                    if context.epoch()? != *e {
                        return Err(REFUSED);
                    }
                    &r.intent
                }
            };
            intent_anchors(&self.targets, intent)?;
            let fresh = context.held_targets(self.role())?;
            intent_anchors(&fresh, intent)?;
            if read(&self.targets.parent, self.role().name())? != self.target
                || read(&self.targets.stage, self.role().stage())? != self.staged
                || read(&self.targets.stage, self.role().backup())? != self.backup
            {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    pub(crate) fn pending_publish_readback<C: Context>(
        context: &C,
        intent: &Intent,
    ) -> Result<PendingSingletonReadback> {
        context.admit_intent(intent)?;
        if context.epoch()? != intent.epoch
            || hash(&context.accepted_bytes(intent.role)?) != intent.digest
        {
            return Err(REFUSED);
        }
        let targets = context.held_targets(intent.role)?;
        intent_anchors(&targets, intent)?;
        let target = read(&targets.parent, intent.role.name())?;
        let staged = read(&targets.stage, intent.role.stage())?;
        let backup = read(&targets.stage, intent.role.backup())?;
        let outcome = if original_exact(target.as_ref(), &intent.original)
            && staged
                .as_ref()
                .is_some_and(|(n, b)| prepared_matches(n, b, intent))
        {
            PendingSingletonOutcome::NotApplied
        } else if target
            .as_ref()
            .is_some_and(|(n, b)| prepared_matches(n, b, intent))
            && original_matches(staged.as_ref(), &intent.original)
        {
            PendingSingletonOutcome::Completed
        } else {
            return Err(REFUSED);
        };
        let proof = PendingSingletonReadback {
            claim: PendingSingletonClaim::Publish(intent.clone()),
            targets,
            target,
            staged,
            backup,
            outcome,
        };
        proof.revalidate(context)?;
        Ok(proof)
    }
    pub(crate) fn pending_restore_readback<C: Context>(
        context: &C,
        receipt: &Receipt,
        epoch: &[u8; 32],
    ) -> Result<PendingSingletonReadback> {
        context.admit_rollback_intent(receipt, epoch)?;
        if context.epoch()? != *epoch {
            return Err(REFUSED);
        }
        let targets = context.held_targets(receipt.role())?;
        intent_anchors(&targets, &receipt.intent)?;
        let target = read(&targets.parent, receipt.role().name())?;
        let staged = read(&targets.stage, receipt.role().stage())?;
        let backup = read(&targets.stage, receipt.role().backup())?;
        let known_prior = match (&receipt.displaced, staged.as_ref()) {
            (Some(old), Some((n, b))) => {
                old == n && Some(hash(b)) == receipt.intent.original.digest
            }
            (None, None) => backup.is_none(),
            _ => false,
        };
        let outcome = if target
            .as_ref()
            .is_some_and(|(n, b)| n == &receipt.published && hash(b) == receipt.intent.digest)
            && known_prior
        {
            PendingSingletonOutcome::NotApplied
        } else {
            let retired = if receipt.intent.original.node.is_some() {
                staged.as_ref()
            } else {
                backup.as_ref()
            };
            if !original_matches(target.as_ref(), &receipt.intent.original)
                || !retired.is_some_and(|(n, b)| {
                    inode(n, &receipt.published) && hash(b) == receipt.intent.digest
                })
            {
                return Err(REFUSED);
            }
            PendingSingletonOutcome::Completed
        };
        let proof = PendingSingletonReadback {
            claim: PendingSingletonClaim::Restore(receipt.clone(), *epoch),
            targets,
            target,
            staged,
            backup,
            outcome,
        };
        proof.revalidate(context)?;
        Ok(proof)
    }
    pub(crate) enum Recovery {
        NotApplied,
        Completed,
    }
    fn intent_anchors(t: &Targets, i: &Intent) -> Result<()> {
        let (p, s) = directories(t)?;
        if (p.dev, p.ino, p.uid, p.gid, p.mode)
            != (
                i.parent.dev,
                i.parent.ino,
                i.parent.uid,
                i.parent.gid,
                i.parent.mode,
            )
            || (s.dev, s.ino, s.uid, s.gid, s.mode)
                != (
                    i.stage.dev,
                    i.stage.ino,
                    i.stage.uid,
                    i.stage.gid,
                    i.stage.mode,
                )
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    fn prepared_matches(n: &Node, b: &[u8], i: &Intent) -> bool {
        let mut expected = i.prepared.clone();
        expected.links = 1;
        inode(n, &expected) && hash(b) == i.digest
    }
    fn original_exact(value: Option<&(Node, Vec<u8>)>, o: &Original) -> bool {
        match (value, &o.node, o.digest) {
            (None, None, None) => true,
            (Some((n, b)), Some(old), Some(d)) => n == old && hash(b) == d,
            _ => false,
        }
    }
    fn original_matches(value: Option<&(Node, Vec<u8>)>, o: &Original) -> bool {
        match (value, &o.node, o.digest) {
            (None, None, None) => true,
            (Some((n, b)), Some(old), Some(d)) => inode(n, old) && hash(b) == d,
            _ => false,
        }
    }
    /// Classifies only exact kernel outcomes of an authenticated pending intent.
    /// A NotApplied result retains staged evidence and does not mark rollback.
    pub(crate) fn recover_pending_publish<C: Context>(
        context: &C,
        intent: &Intent,
    ) -> Result<Recovery> {
        context.admit_intent(intent)?;
        if context.epoch()? != intent.epoch
            || hash(&context.accepted_bytes(intent.role)?) != intent.digest
        {
            return Err(REFUSED);
        }
        let t = context.held_targets(intent.role)?;
        intent_anchors(&t, intent)?;
        let target = read(&t.parent, intent.role.name())?;
        let staged = read(&t.stage, intent.role.stage())?;
        if original_exact(target.as_ref(), &intent.original)
            && staged
                .as_ref()
                .is_some_and(|(n, b)| prepared_matches(n, b, intent))
        {
            return Ok(Recovery::NotApplied);
        }
        let (published, bytes) = target.ok_or(REFUSED)?;
        if !prepared_matches(&published, &bytes, intent)
            || !original_matches(staged.as_ref(), &intent.original)
        {
            return Err(REFUSED);
        }
        let receipt = Receipt {
            intent: intent.clone(),
            published,
            displaced: staged.map(|(n, _)| n),
        };
        context.stopped_mutation(
            intent.role,
            &intent.epoch,
            Mutation::RecoverReadback,
            &mut || {
                intent_anchors(&t, intent)?;
                let again = read(&t.parent, intent.role.name())?.ok_or(REFUSED)?;
                if again.0 != receipt.published || hash(&again.1) != intent.digest {
                    return Err(REFUSED);
                }
                context.commit_receipt(&receipt)
            },
        )?;
        verify(context, &receipt)?;
        Ok(Recovery::Completed)
    }
    pub(crate) fn recover_pending_rollback<C: Context>(
        context: &C,
        receipt: &Receipt,
        epoch: &[u8; 32],
    ) -> Result<RollbackRecovery> {
        context.admit_rollback_intent(receipt, epoch)?;
        if context.epoch()? != *epoch {
            return Err(REFUSED);
        }
        let t = context.held_targets(receipt.role())?;
        intent_anchors(&t, &receipt.intent)?;
        let target = read(&t.parent, receipt.role().name())?;
        if target
            .as_ref()
            .is_some_and(|(n, b)| n == &receipt.published && hash(b) == receipt.intent.digest)
        {
            let prior = read(&t.stage, receipt.role().stage())?;
            let known_backup = match (&receipt.displaced, prior.as_ref()) {
                (Some(old), Some((n, b))) => {
                    old == n && Some(hash(b)) == receipt.intent.original.digest
                }
                (None, None) => read(&t.stage, receipt.role().backup())?.is_none(),
                _ => false,
            };
            if known_backup {
                return Ok(RollbackRecovery::NotApplied);
            }
            return Err(REFUSED);
        }
        if !original_matches(target.as_ref(), &receipt.intent.original) {
            return Err(REFUSED);
        }
        let displaced = read(
            &t.stage,
            if receipt.intent.original.node.is_some() {
                receipt.role().stage()
            } else {
                receipt.role().backup()
            },
        )?
        .ok_or(REFUSED)?;
        if !inode(&displaced.0, &receipt.published) || hash(&displaced.1) != receipt.intent.digest {
            return Err(REFUSED);
        }
        let mut restored = None;
        context.stopped_mutation(
            receipt.role(),
            epoch,
            Mutation::RecoverReadback,
            &mut || {
                let actual = restoration_readback(context, receipt, epoch, &t)?;
                context.commit_rollback(&actual)?;
                restored = Some(actual);
                Ok(())
            },
        )?;
        let restoration = restored.ok_or(REFUSED)?;
        verify_restoration(context, &restoration)?;
        Ok(RollbackRecovery::Completed(Box::new(restoration)))
    }

    // The Aegis-only directory is the sole tree publication target. RootContext
    // supplies its captured files/empty directories and guarded generation.
    // Global/vendor/service.d drop-ins are never targets here.
    pub(crate) trait DropinContext {
        fn epoch(&self) -> Result<[u8; 32]>;
        fn original_generation(
            &self,
        ) -> Result<Option<crate::profile_auto_publication::linux::Generation>>;
        fn capture_guard(
            &self,
        ) -> Result<Box<dyn crate::profile_auto_publication::linux::CaptureGuard + '_>>;
        fn stopped_mutation(
            &self,
            epoch: &[u8; 32],
            actual: &mut dyn FnMut() -> Result<()>,
        ) -> Result<()>;
        fn persist_stage(
            &self,
            stage: &crate::profile_auto_publication::linux::StageReceipt,
        ) -> Result<()>;
        fn persist_intent(
            &self,
            intent: &crate::profile_auto_publication::linux::PublicationIntent,
        ) -> Result<()>;
        fn commit_receipt(
            &self,
            receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
        ) -> Result<()>;
        fn admit_receipt(
            &self,
            receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
        ) -> Result<()>;
        fn current_receipt_guard(
            &self,
            receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
        ) -> Result<Box<dyn crate::profile_auto_publication::linux::CaptureGuard + '_>>;
        fn original_absence_authority(
            &self,
        ) -> Result<Box<dyn crate::profile_auto_publication::linux::OwnAbsenceChainAuthority + '_>>;
        fn persist_withdrawal(
            &self,
            intent: &crate::profile_auto_publication::linux::WithdrawalIntent,
        ) -> Result<()>;
        fn commit_rollback(
            &self,
            forward: &crate::profile_auto_publication::linux::PublicationReceipt,
            receipt: &DropinRollback,
        ) -> Result<()>;
        fn admit_rollback(
            &self,
            forward: &crate::profile_auto_publication::linux::PublicationReceipt,
            receipt: &DropinRollback,
        ) -> Result<()>;
    }
    const DROPINS: &str = "/etc/systemd/system/aegis-client.service.d";
    fn dropin_publication_policy(
        dropins: &BTreeMap<PathBuf, Vec<u8>>,
    ) -> crate::profile_auto_publication::linux::ConfigPolicy {
        use crate::profile_auto_publication::linux as fs;
        fs::ConfigPolicy {
            runtime_uid: 0,
            runtime_gid: 0,
            root_policy: true,
            leaves: dropins
                .keys()
                .cloned()
                .map(|path| {
                    let role = if [
                        V2_BOOT_GATE_DROPIN,
                        "10-dedicated-uid.conf",
                        DEVICE_GUARD_DROPIN,
                    ]
                    .iter()
                    .any(|owned| path == Path::new(owned))
                    {
                        fs::ConfigLeafRole::SystemdDropin
                    } else {
                        fs::ConfigLeafRole::Public
                    };
                    (path, role)
                })
                .collect(),
        }
    }
    pub(crate) fn publish_dropins<C: DropinContext>(
        context: &C,
        compiled: &CompiledPolicy,
        captured_directories: &std::collections::BTreeSet<PathBuf>,
    ) -> Result<crate::profile_auto_publication::linux::PublicationReceipt> {
        use crate::profile_auto_publication::linux as fs;
        if unsafe { libc::geteuid() } != 0 {
            return Err(REFUSED);
        }
        let epoch = context.epoch()?;
        let guard = context.capture_guard()?;
        let tree = fs::CapturedTree::new(compiled.dropins.clone(), captured_directories.clone())?;
        let policy = dropin_publication_policy(&compiled.dropins);
        let mut expected = context.original_generation()?;
        let mut target = Some(fs::Target::open(Path::new(DROPINS))?);
        let mut prepared = None;
        context.stopped_mutation(&epoch, &mut || {
            prepared = Some(fs::Prepared::build_runtime_config_captured(
                target.take().ok_or(REFUSED)?,
                expected.take(),
                &tree,
                &policy,
                |stage| context.persist_stage(stage),
                guard.as_ref(),
            )?);
            Ok(())
        })?;
        let mut actual = None;
        context.stopped_mutation(&epoch, &mut || {
            let receipt = prepared
                .take()
                .ok_or(REFUSED)?
                .publish_captured(|intent| context.persist_intent(intent), guard.as_ref())?;
            revalidate_dropin_publication(compiled, captured_directories, &receipt)?;
            context.commit_receipt(&receipt)?;
            actual = Some(receipt);
            Ok(())
        })?;
        let receipt = actual.ok_or(REFUSED)?;
        verify_dropins(context, compiled, captured_directories, &receipt)?;
        Ok(receipt)
    }
    pub(crate) fn verify_dropins<C: DropinContext>(
        context: &C,
        compiled: &CompiledPolicy,
        directories: &std::collections::BTreeSet<PathBuf>,
        receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
    ) -> Result<()> {
        context.admit_receipt(receipt)?;
        revalidate_dropin_publication(compiled, directories, receipt)
    }
    fn revalidate_dropin_publication(
        compiled: &CompiledPolicy,
        directories: &std::collections::BTreeSet<PathBuf>,
        receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
    ) -> Result<()> {
        use crate::profile_auto_publication::linux as fs;
        let target = fs::Target::open(Path::new(DROPINS))?;
        let policy = dropin_publication_policy(&compiled.dropins);
        fs::verify_runtime_config_policy(&target, receipt, &policy)?;
        if fs::current_leaf_names(&target, receipt)? != compiled.dropins.keys().cloned().collect()
            || fs::current_directory_names(&target, receipt)? != *directories
        {
            return Err(REFUSED);
        }
        for (path, bytes) in &compiled.dropins {
            if fs::read_current_leaf(&target, receipt, path)?.as_slice() != bytes.as_slice() {
                return Err(REFUSED);
            }
        }
        fs::revalidate_current_receipt(&target, receipt)
    }
    pub(crate) enum DropinRollback {
        // Restores the actual displaced original inode/attributes through a
        // distinct retained policy; never reconstructs/normalizes its tree.
        RetainedOriginal(crate::profile_auto_publication::linux::PublicationReceipt),
        OriginalAbsence(crate::profile_auto_publication::linux::WithdrawalReceipt),
    }
    pub(crate) fn rollback_dropins<C: DropinContext>(
        context: &C,
        receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
    ) -> Result<DropinRollback> {
        use crate::profile_auto_publication::linux as fs;
        context.admit_receipt(receipt)?;
        let mut target = Some(fs::Target::open(Path::new(DROPINS))?);
        let epoch = context.epoch()?;
        let original_existed = context.original_generation()?.is_some();
        let mut result = None;
        if original_existed {
            let guard = context.current_receipt_guard(receipt)?;
            context.stopped_mutation(&epoch, &mut || {
                result = Some(DropinRollback::RetainedOriginal(
                    restore_retained_dropin_target(
                        target.take().ok_or(REFUSED)?,
                        receipt,
                        |intent| context.persist_intent(intent),
                        guard.as_ref(),
                    )?,
                ));
                let restoration = result.as_ref().ok_or(REFUSED)?;
                revalidate_dropin_restoration(receipt, restoration)?;
                context.commit_rollback(receipt, restoration)
            })?;
        } else {
            let authority = context.original_absence_authority()?;
            context.stopped_mutation(&epoch, &mut || {
                result = Some(DropinRollback::OriginalAbsence(
                    fs::restore_original_absence_after_own_chain(
                        target.as_ref().ok_or(REFUSED)?,
                        receipt,
                        authority.as_ref(),
                        |intent| context.persist_withdrawal(intent),
                    )?,
                ));
                let restoration = result.as_ref().ok_or(REFUSED)?;
                revalidate_dropin_restoration(receipt, restoration)?;
                context.commit_rollback(receipt, restoration)
            })?;
        }
        let result = result.ok_or(REFUSED)?;
        verify_dropin_restoration(context, receipt, &result)?;
        Ok(result)
    }

    /// Requires the authenticated rollback record plus exact filesystem proof;
    /// the enum or forward publication receipt alone is not restoration authority.
    pub(crate) fn verify_dropin_restoration<C: DropinContext>(
        context: &C,
        forward: &crate::profile_auto_publication::linux::PublicationReceipt,
        restored: &DropinRollback,
    ) -> Result<()> {
        context.admit_receipt(forward)?;
        context.admit_rollback(forward, restored)?;
        revalidate_dropin_restoration(forward, restored)
    }
    fn revalidate_dropin_restoration(
        forward: &crate::profile_auto_publication::linux::PublicationReceipt,
        restored: &DropinRollback,
    ) -> Result<()> {
        use crate::profile_auto_publication::linux as fs;
        let target = fs::Target::open(Path::new(DROPINS))?;
        match restored {
            DropinRollback::RetainedOriginal(receipt) => {
                fs::validate_retained_restore_predecessor(forward, receipt)?;
                fs::revalidate_current_receipt(&target, receipt)
            }
            DropinRollback::OriginalAbsence(receipt) => {
                fs::validate_withdrawal_predecessor(forward, receipt)?;
                fs::revalidate_withdrawal(&target, receipt)
            }
        }
    }

    fn restore_retained_dropin_target(
        target: crate::profile_auto_publication::linux::Target,
        receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
        persist: impl FnMut(&crate::profile_auto_publication::linux::PublicationIntent) -> Result<()>,
        guard: &(impl crate::profile_auto_publication::linux::CaptureGuard + ?Sized),
    ) -> Result<crate::profile_auto_publication::linux::PublicationReceipt> {
        crate::profile_auto_publication::linux::restore_retained_original_tree(
            target, receipt, persist, guard,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn owned_systemd_dropins_use_public_role_only_for_exact_names() {
            use crate::profile_auto_publication::linux::ConfigLeafRole;
            let leaves = BTreeMap::from([
                (
                    PathBuf::from(V2_BOOT_GATE_DROPIN),
                    V2_BOOT_GATE_BYTES.as_bytes().to_vec(),
                ),
                (
                    PathBuf::from("10-dedicated-uid.conf"),
                    b"[Service]\nUser=aegis\n".to_vec(),
                ),
                (
                    PathBuf::from(DEVICE_GUARD_DROPIN),
                    b"[Unit]\nAfter=ufw.service\n".to_vec(),
                ),
                (
                    PathBuf::from("99-foreign.conf"),
                    b"[Service]\nEnvironment=local\n".to_vec(),
                ),
            ]);
            let policy = dropin_publication_policy(&leaves);
            for owned in [
                V2_BOOT_GATE_DROPIN,
                "10-dedicated-uid.conf",
                DEVICE_GUARD_DROPIN,
            ] {
                assert!(policy.leaves[Path::new(owned)] == ConfigLeafRole::SystemdDropin);
            }
            assert!(policy.leaves[Path::new("99-foreign.conf")] == ConfigLeafRole::Public);
            assert!(policy.root_policy && policy.runtime_uid == 0 && policy.runtime_gid == 0);
        }
        #[test]
        fn transient_lookup_profiles_reject_unknown_or_ambiguous_managers() {
            for version in ["255.4-1ubuntu8.12", "259 (259.5-0ubuntu3.4)"] {
                let response = format!("UnitPath=/run/systemd/transient /etc/systemd/system /usr/lib/systemd/system\nVersion={version}\n");
                assert_eq!(private_lookup_paths(response.as_bytes()).unwrap().len(), 3);
                for roots in [
                    "",
                    "/tmp/system",
                    "/etc/systemd/../system",
                    "/etc/systemd/system /etc/systemd/system",
                ] {
                    assert!(private_lookup_paths(
                        format!("Version={version}\nUnitPath={roots}\n").as_bytes()
                    )
                    .is_err());
                }
                assert!(
                    private_lookup_paths(format!("{response}Version={version}\n").as_bytes())
                        .is_err()
                );
                assert!(private_lookup_paths(format!("{response}Unknown=x\n").as_bytes()).is_err());
            }
            for version in [
                "254", "256", "257", "258", "260", "2590", "v259", "259\t", "259\r", "259\0",
            ] {
                assert!(
                    private_lookup_paths(
                        format!("Version={version}\nUnitPath=/etc/systemd/system\n").as_bytes()
                    )
                    .is_err(),
                    "{version:?}"
                );
            }
        }
        fn input() -> CompilerInputs {
            CompilerInputs {
                mode: Mode::Socks,
                policy: Policy::DedicatedNone,
                user: RuntimeUser::Aegis,
                binary: "/usr/local/bin/aegis-client".into(),
                config: "/etc/aegis/client/aegis.toml".into(),
                state: "/var/lib/aegis-client".into(),
                events: "/dev/null".into(),
            }
        }
        #[test]
        fn compiler_closed_user_mode_and_control_injection_refuse() {
            let mut i = input();
            i.mode = Mode::FullTun;
            assert!(compile(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
            i = input();
            i.binary = "/usr/bin/client\nExecStart=/bin/false".into();
            assert!(compile(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
        }
        #[test]
        fn fresh_full_tun_requires_separate_first_arm_entry_and_absent_dropins() {
            let mut i = input();
            i.mode = Mode::FullTun;
            i.policy = Policy::Root;
            i.user = RuntimeUser::Root;
            assert!(compile(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
            let admission = crate::profile_auto_transaction::VerifiedFirstArm::test_only();
            let fresh = compile_first_arm(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new(),
                &admission,
            )
            .unwrap();
            assert_eq!(fresh.transient.guard_timeout, Some(60));
            assert_eq!(
                fresh.dropins[Path::new(DEVICE_GUARD_DROPIN)],
                owned_device_guard_dropin(60, &i.binary).unwrap().as_bytes()
            );
            let early_gate = BTreeMap::from([(
                PathBuf::from(V2_BOOT_GATE_DROPIN),
                V2_BOOT_GATE_BYTES.as_bytes().to_vec(),
            )]);
            let guarded = compile_first_arm(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &early_gate,
                &admission,
            )
            .unwrap();
            assert_eq!(
                guarded.dropins[Path::new(V2_BOOT_GATE_DROPIN)],
                V2_BOOT_GATE_BYTES.as_bytes()
            );
            let foreign_gate = BTreeMap::from([(
                PathBuf::from(V2_BOOT_GATE_DROPIN),
                b"[Unit]\nConditionPathExists=/tmp/foreign\n".to_vec(),
            )]);
            assert!(compile_first_arm(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &foreign_gate,
                &admission,
            )
            .is_err());
            assert!(compile_first_arm(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::from([(PathBuf::from("99-foreign.conf"), b"[Service]\n".to_vec())]),
                &admission,
            )
            .is_err());
            i.mode = Mode::Redirect;
            assert!(compile_first_arm(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new(),
                &admission,
            )
            .is_err());
        }
        #[test]
        fn compiler_preserves_unmanaged_dropins_and_safe_argument_boundaries() {
            let mut i = input();
            i.binary = "/opt/aegis folder/client%name$\"x".into();
            let prior =
                BTreeMap::from([(PathBuf::from("99-owner.conf"), b"# owner policy\n".to_vec())]);
            let p = compile(&i, UNIT.as_bytes(), ENVIRONMENT.as_bytes(), &prior).unwrap();
            assert_eq!(
                p.dropins[Path::new("99-owner.conf")],
                prior[Path::new("99-owner.conf")]
            );
            let s = String::from_utf8(p.unit).unwrap();
            assert!(s.contains("client%%name$$\\\"x\" --config"));
            assert!(!s.contains("User="));
        }
        #[test]
        fn compiler_uses_scalar_path_grammar_only_for_working_directory() {
            let mut i = input();
            i.state = "/var/lib/aegis state/%unit\"$owned".into();
            let compiled = compile(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new(),
            )
            .unwrap();
            let unit = String::from_utf8(compiled.unit).unwrap();
            assert!(unit.contains("EnvironmentFile=-/etc/default/aegis-client\n"));
            assert!(unit.contains("WorkingDirectory=/var/lib/aegis state/%%unit\"$owned\n"));
            assert!(unit.contains("ReadWritePaths=\"/var/lib/aegis state/%%unit\\\"$owned\"\n"));
            i.state = "/var/lib/aegis-state ".into();
            assert!(compile(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
            i.state = "/var/lib/aegis-state\\".into();
            assert!(compile(
                &i,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
        }
        #[test]
        fn compiler_exact_source_templates_and_admitted_modes() {
            for (mode, policy, user) in [
                (Mode::Socks, Policy::DedicatedNone, RuntimeUser::Aegis),
                (Mode::Redirect, Policy::DedicatedBind, RuntimeUser::AegisSvc),
            ] {
                let mut i = input();
                i.mode = mode;
                i.policy = policy;
                i.user = user;
                let p = compile(
                    &i,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &BTreeMap::new(),
                )
                .unwrap();
                assert_eq!(p.environment, ENVIRONMENT.as_bytes());
                assert!(!p.dropins.contains_key(Path::new("20-ipv6-tun.conf")));
                assert_eq!(
                    String::from_utf8(p.unit)
                        .unwrap()
                        .matches(V2_BOOT_INTERLOCK)
                        .count(),
                    1
                );
            }
            let mut full_tun = input();
            full_tun.mode = Mode::FullTun;
            full_tun.policy = Policy::Root;
            full_tun.user = RuntimeUser::Root;
            let guard_dropin = BTreeMap::from([(
                PathBuf::from(DEVICE_GUARD_DROPIN),
                old_device_guard_dropin(60).into_bytes(),
            )]);
            let compiled = compile(
                &full_tun,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &guard_dropin,
            )
            .unwrap();
            verify_owned_guard_transition(&compiled, &guard_dropin[Path::new(DEVICE_GUARD_DROPIN)])
                .unwrap();
            let mut changed_guard = guard_dropin[Path::new(DEVICE_GUARD_DROPIN)].clone();
            changed_guard.push(b' ');
            assert!(verify_owned_guard_transition(&compiled, &changed_guard).is_err());
            let unit = String::from_utf8(compiled.unit).unwrap();
            assert_eq!(unit.matches(V2_BOOT_INTERLOCK).count(), 1);
            assert!(unit.contains("Requires=aegis-auto-guardian.service\n"));
            assert!(unit.contains("After=aegis-auto-guardian.service\n"));
            assert!(unit
                .contains("ExecStop=\"/usr/local/bin/aegis-client\" auto-stop-service-clean %n\n"));
            assert!(unit
                .contains("ExecStopPost=\"/usr/local/bin/aegis-client\" auto-stop-service %n\n"));
            assert!(unit.contains("TimeoutStopSec=15s\n"));
            assert!(unit.contains("Restart=no\n"));
            let guard = String::from_utf8(compiled.dropins[Path::new(DEVICE_GUARD_DROPIN)].clone())
                .unwrap();
            assert!(guard
                .contains("ExecStartPre=\"/usr/local/bin/aegis-client\" auto-bind-service %n\n"));
            assert!(!guard.contains("ExecStopPost="));
            assert!(!guard.contains("/bin/bash"));
            let online_guard = BTreeMap::from([(
                PathBuf::from(DEVICE_GUARD_DROPIN),
                old_device_guard_dropin(180).into_bytes(),
            )]);
            assert!(compile(
                &full_tun,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &online_guard,
            )
            .is_ok());
            for seconds in [60u32, 180] {
                let owned_bytes = owned_device_guard_dropin(seconds, &full_tun.binary)
                    .unwrap()
                    .into_bytes();
                let prior_owned = BTreeMap::from([
                    (PathBuf::from(DEVICE_GUARD_DROPIN), owned_bytes.clone()),
                    (
                        PathBuf::from("10-dedicated-uid.conf"),
                        b"[Service]\nUser=aegis-svc\n".to_vec(),
                    ),
                ]);
                let continued = compile(
                    &full_tun,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &prior_owned,
                )
                .unwrap();
                verify_owned_guard_transition(&continued, &owned_bytes).unwrap();
                assert_eq!(
                    continued.dropins[Path::new(DEVICE_GUARD_DROPIN)],
                    owned_bytes
                );
                assert!(!continued
                    .dropins
                    .contains_key(Path::new("10-dedicated-uid.conf")));
                let original_binary = full_tun.binary.clone();
                full_tun.binary = "/usr/local/bin/aegis-client-replaced".into();
                assert!(compile(
                    &full_tun,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &prior_owned,
                )
                .is_err());
                full_tun.binary = original_binary;
                let mut modified = prior_owned;
                modified
                    .get_mut(Path::new(DEVICE_GUARD_DROPIN))
                    .unwrap()
                    .push(b' ');
                assert!(compile(
                    &full_tun,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &modified,
                )
                .is_err());
            }
            let foreign_guard = BTreeMap::from([(
                PathBuf::from(DEVICE_GUARD_DROPIN),
                b"[Service]\nExecStartPre=/bin/false\n".to_vec(),
            )]);
            assert!(compile(
                &full_tun,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &foreign_guard,
            )
            .is_err());
            let extra_lifecycle = BTreeMap::from([
                (
                    PathBuf::from(DEVICE_GUARD_DROPIN),
                    old_device_guard_dropin(60).into_bytes(),
                ),
                (
                    PathBuf::from("99-admin.conf"),
                    b"[Service]\nExecStartPre=/bin/false\n".to_vec(),
                ),
            ]);
            assert!(compile(
                &full_tun,
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &extra_lifecycle,
            )
            .is_err());
            assert!(!unit.contains("/bin/sh"));
            assert!(!unit.contains("ip route"));
            assert!(compile(
                &input(),
                b"[Service]\nExecStart=/bin/false\n",
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
        }

        /// The owned hook every earlier compiler published (Option B keeps
        /// the installer's ufw.service ordering in the newest one).
        fn previous_owned_dropin(timeout: u32, binary: &Path) -> Vec<u8> {
            owned_device_guard_dropin_after(timeout, binary, OWNED_GUARD_AFTER[0])
                .unwrap()
                .into_bytes()
        }

        #[test]
        fn owned_guard_hook_keeps_ufw_ordering_and_admits_only_the_previous_owned_bytes() {
            let mut full_tun = input();
            full_tun.mode = Mode::FullTun;
            full_tun.policy = Policy::Root;
            full_tun.user = RuntimeUser::Root;
            let binary = full_tun.binary.clone();
            for seconds in [60u32, 180] {
                let newest = owned_device_guard_dropin(seconds, &binary)
                    .unwrap()
                    .into_bytes();
                let previous = previous_owned_dropin(seconds, &binary);
                let text = String::from_utf8(newest.clone()).unwrap();
                assert!(text.contains("\nAfter=aegis-device-egress-guard.service ufw.service\n"));
                assert_eq!(newest.len(), previous.len() + " ufw.service".len());
                // Re-entry from the previous owned generation publishes only
                // the newest bytes and passes the publication check.
                let prior =
                    BTreeMap::from([(PathBuf::from(DEVICE_GUARD_DROPIN), previous.clone())]);
                let compiled =
                    compile(&full_tun, UNIT.as_bytes(), ENVIRONMENT.as_bytes(), &prior).unwrap();
                assert_eq!(compiled.transient.guard_timeout, Some(seconds));
                assert_eq!(compiled.dropins[Path::new(DEVICE_GUARD_DROPIN)], newest);
                verify_owned_guard_transition(&compiled, &previous).unwrap();
                verify_owned_guard_transition(&compiled, &newest).unwrap();
                // Stale binary, space variants and cross-timeout bytes refuse.
                let stale =
                    previous_owned_dropin(seconds, Path::new("/usr/local/bin/aegis-client-old"));
                let mut appended = previous.clone();
                appended.push(b' ');
                let trailing = String::from_utf8(newest.clone())
                    .unwrap()
                    .replace("ufw.service\n", "ufw.service \n")
                    .into_bytes();
                let doubled = String::from_utf8(newest.clone())
                    .unwrap()
                    .replace(".service ufw", ".service  ufw")
                    .into_bytes();
                let other = previous_owned_dropin(if seconds == 60 { 180 } else { 60 }, &binary);
                for refused in [&stale, &appended, &trailing, &doubled] {
                    let bytes =
                        BTreeMap::from([(PathBuf::from(DEVICE_GUARD_DROPIN), refused.clone())]);
                    assert!(
                        compile(&full_tun, UNIT.as_bytes(), ENVIRONMENT.as_bytes(), &bytes)
                            .is_err()
                    );
                    assert!(verify_owned_guard_transition(&compiled, refused).is_err());
                }
                assert!(verify_owned_guard_transition(&compiled, &other).is_err());
                for generation in owned_guard_generations(seconds, &binary).unwrap() {
                    assert!(owned_guard_hook(generation.as_bytes(), seconds, &binary).unwrap());
                    assert!(!owned_guard_hook(generation.as_bytes(), 61, &binary).unwrap());
                }
            }
            assert_eq!(OWNED_GUARD_AFTER.last(), INSTALLER_GUARD_AFTER.last());
        }

        /// install.sh itself, read at compile time: the shipped installer
        /// bytes, never a Rust-side copy of its template.
        const INSTALL_SH: &str = include_str!("../../install.sh");
        /// The current client guard hook, including late capture binding.
        const INSTALL_SH_GUARD_SHA256: [(u32, &str); 2] = [
            (
                60,
                "794607b6b65db845792780bfa35be2ed291923f3e63c74fa81ef293619892c5c",
            ),
            (
                180,
                "6563b6a6715a9c93437b02dad2fb15a327c58ac90d50c79e893c657e5f8dbfea",
            ),
        ];
        /// The hook install.sh wrote before d0b9bc24 (105fbb87, native39 39/39).
        const PRE_UFW_GUARD_SHA256: [(u32, &str); 2] = [
            (
                60,
                "9bc83b8e51b70c7fff7b792f29476946f6e54fc5e4eda9c7395edbda3928c008",
            ),
            (
                180,
                "9a3ce13d900d42a328f16dce26621f055e6258c51b0abce46cf3f8d9407b7b11",
            ),
        ];

        fn sha256_hex(bytes: &[u8]) -> String {
            hex::encode(Sha256::digest(bytes))
        }

        fn exactly_one<'a>(found: Vec<&'a str>, what: &str) -> &'a str {
            assert_eq!(found.len(), 1, "install.sh must contain exactly one {what}");
            found[0]
        }

        /// Renders the client guard drop-in exactly as install.sh writes it.
        /// The state path, the helper path, the startup timeouts and the one
        /// heredoc (selected by its target path) are all read from install.sh.
        fn install_sh_guard_dropins() -> Vec<(u32, Vec<u8>)> {
            let start = INSTALL_SH
                .find("\ninstall_device_egress_guard_units() {\n")
                .expect("install.sh guard function");
            let function = &INSTALL_SH[start + 1..];
            let function = &function[..function.find("\n}\n").expect("guard function end")];
            let lines: Vec<&str> = function.lines().collect();
            let state = exactly_one(
                lines
                    .iter()
                    .filter_map(|line| {
                        line.trim()
                            .strip_prefix("[[ \"$state\" == ")?
                            .strip_suffix(" &&")
                    })
                    .collect(),
                "state path check",
            );
            let library = exactly_one(
                lines
                    .iter()
                    .filter_map(|line| {
                        line.trim()
                            .strip_prefix("\"$AEGIS_WIDE_LIB_DIR\" == ")?
                            .strip_suffix(" ]] || {")
                    })
                    .collect(),
                "helper directory check",
            );
            let helper_name = exactly_one(
                function
                    .split("helper=\"${AEGIS_WIDE_LIB_DIR}/")
                    .skip(1)
                    .map(|rest| rest.split('"').next().unwrap_or_default())
                    .collect(),
                "helper assignment",
            );
            let helper = format!("{library}/{helper_name}");
            let mut timeouts: Vec<u32> = function
                .split("startup_timeout=")
                .skip(1)
                .map(|rest| {
                    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                    digits.parse().expect("numeric install.sh startup timeout")
                })
                .collect();
            timeouts.sort_unstable();
            timeouts.dedup();
            let target = "\"${SYSTEMD_DIR}/aegis-client.service.d/30-device-egress-guard.conf\"";
            assert_eq!(
                INSTALL_SH
                    .lines()
                    .filter(|line| line.contains(target) && line.contains("<<EOF"))
                    .count(),
                1
            );
            let header = exactly_one(
                lines
                    .iter()
                    .copied()
                    .filter(|line| line.contains(target) && line.contains("<<EOF"))
                    .collect(),
                "client guard heredoc",
            );
            let first = lines.iter().position(|line| *line == header).unwrap() + 1;
            let length = lines[first..]
                .iter()
                .position(|line| *line == "EOF")
                .expect("client guard heredoc end");
            let template: String = lines[first..first + length]
                .iter()
                .map(|line| format!("{line}\n"))
                .collect();
            timeouts
                .into_iter()
                .map(|timeout| {
                    let rendered = template
                        .replace("${state}", state)
                        .replace("${helper}", &helper)
                        .replace("${startup_timeout}", &timeout.to_string());
                    assert!(
                        !rendered.contains(['$', '\\', '`']),
                        "unexpected install.sh expansion"
                    );
                    (timeout, rendered.into_bytes())
                })
                .collect()
        }

        fn full_tun_input() -> CompilerInputs {
            let mut full_tun = input();
            full_tun.mode = Mode::FullTun;
            full_tun.policy = Policy::Root;
            full_tun.user = RuntimeUser::Root;
            full_tun
        }

        fn guard_only(bytes: &[u8]) -> BTreeMap<PathBuf, Vec<u8>> {
            BTreeMap::from([(PathBuf::from(DEVICE_GUARD_DROPIN), bytes.to_vec())])
        }

        #[test]
        fn install_sh_guard_hook_compiles_at_each_installer_timeout() {
            let full_tun = full_tun_input();
            let rendered = install_sh_guard_dropins();
            assert_eq!(rendered.len(), 2);
            for (timeout, bytes) in rendered {
                // The r16 #36 input: the fresh installer hook, refused before.
                let compiled = compile(
                    &full_tun,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &guard_only(&bytes),
                )
                .expect("install.sh guard hook refused by the full-tun compiler");
                assert_eq!(compiled.transient.guard_timeout, Some(timeout));
                assert_eq!(
                    compiled.dropins[Path::new(DEVICE_GUARD_DROPIN)],
                    owned_device_guard_dropin(timeout, &full_tun.binary)
                        .unwrap()
                        .as_bytes()
                );
                verify_owned_guard_transition(&compiled, &bytes)
                    .expect("install.sh guard hook refused at publication");
                // The exact r16 order: a dedicated wide-redirect-safe policy
                // carries the hook unchanged, then full-wide-tun re-enters.
                let mut wide = input();
                wide.mode = Mode::Redirect;
                wide.policy = Policy::DedicatedBind;
                wide.user = RuntimeUser::AegisSvc;
                let after_wide = compile(
                    &wide,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &guard_only(&bytes),
                )
                .unwrap();
                assert_eq!(after_wide.dropins[Path::new(DEVICE_GUARD_DROPIN)], bytes);
                assert!(after_wide
                    .dropins
                    .contains_key(Path::new("10-dedicated-uid.conf")));
                let reentry = compile(
                    &full_tun,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &after_wide.dropins,
                )
                .expect("full-tun re-entry after wide refused");
                assert_eq!(reentry.transient.guard_timeout, Some(timeout));
                assert!(!reentry
                    .dropins
                    .contains_key(Path::new("10-dedicated-uid.conf")));
                assert_eq!(
                    reentry.dropins[Path::new(DEVICE_GUARD_DROPIN)],
                    compiled.dropins[Path::new(DEVICE_GUARD_DROPIN)]
                );
                verify_owned_guard_transition(&reentry, &bytes).unwrap();
            }
        }

        #[test]
        fn install_sh_guard_hook_refuses_one_byte_and_cross_timeout_changes() {
            let full_tun = full_tun_input();
            let rendered = install_sh_guard_dropins();
            let mut compiled = Vec::new();
            for (timeout, bytes) in &rendered {
                let policy = compile(
                    &full_tun,
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &guard_only(bytes),
                )
                .expect("install.sh guard hook refused by the full-tun compiler");
                let text = String::from_utf8(bytes.clone()).unwrap();
                let mut appended = bytes.clone();
                appended.push(b' ');
                for changed in [
                    appended,
                    text.replacen(
                        &format!("TimeoutStartSec={timeout}\n"),
                        "TimeoutStartSec=61\n",
                        1,
                    )
                    .into_bytes(),
                    text.replacen(" ufw.service\n", " ufw.service \n", 1)
                        .into_bytes(),
                ] {
                    assert_ne!(&changed, bytes);
                    assert!(compile(
                        &full_tun,
                        UNIT.as_bytes(),
                        ENVIRONMENT.as_bytes(),
                        &guard_only(&changed),
                    )
                    .is_err());
                    assert!(verify_owned_guard_transition(&policy, &changed).is_err());
                }
                compiled.push((*timeout, policy));
            }
            // Publication is keyed on the compiled timeout, never any timeout.
            let [(short, short_policy), (long, long_policy)] = compiled.as_slice() else {
                panic!("two installer timeouts required");
            };
            assert_eq!((*short, *long), (60, 180));
            assert!(verify_owned_guard_transition(short_policy, &rendered[1].1).is_err());
            assert!(verify_owned_guard_transition(long_policy, &rendered[0].1).is_err());
        }

        #[test]
        fn installer_guard_generations_are_exactly_the_shipped_install_sh_bytes() {
            let rendered = install_sh_guard_dropins();
            let newest = INSTALLER_GUARD_AFTER[INSTALLER_GUARD_AFTER.len() - 1];
            assert_eq!(
                rendered
                    .iter()
                    .map(|(seconds, _)| *seconds)
                    .collect::<Vec<_>>(),
                [60, 180]
            );
            for ((timeout, bytes), (pinned_timeout, pinned)) in
                rendered.iter().zip(INSTALL_SH_GUARD_SHA256)
            {
                assert_eq!(*timeout, pinned_timeout);
                assert_eq!(sha256_hex(bytes), pinned);
                assert_eq!(
                    bytes.as_slice(),
                    installer_device_guard_dropin(*timeout, newest).as_bytes()
                );
                assert!(installer_guard_hook(bytes, *timeout));
                for other in [0, 59, 61, 120, 179, 181] {
                    assert!(!installer_guard_hook(bytes, other));
                }
            }
            for (timeout, pinned) in PRE_UFW_GUARD_SHA256 {
                let bytes = old_device_guard_dropin(timeout).into_bytes();
                assert_eq!(sha256_hex(&bytes), pinned);
                assert!(installer_guard_hook(&bytes, timeout));
                assert!(compile(
                    &full_tun_input(),
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &guard_only(&bytes),
                )
                .is_ok());
            }
            for timeout in [60, 180] {
                let generations: Vec<String> = INSTALLER_GUARD_AFTER
                    .iter()
                    .map(|after| {
                        sha256_hex(installer_device_guard_dropin(timeout, after).as_bytes())
                    })
                    .collect();
                assert_eq!(generations.len(), 2);
                assert_ne!(generations[0], generations[1]);
            }
            assert!(!installer_guard_hook(
                installer_device_guard_dropin(61, newest).as_bytes(),
                61
            ));
        }

        #[test]
        fn compile_refusals_carry_closed_bind_runtime_codes() {
            fn code(result: Result<CompiledPolicy>) -> &'static str {
                refusal_code(result.err().expect("compile refusal required"))
            }
            let full_tun = full_tun_input();
            let ufw = install_sh_guard_dropins().remove(0).1;
            let mut changed = ufw.clone();
            changed.push(b' ');
            let compile_with = |i: &CompilerInputs, dropins: BTreeMap<PathBuf, Vec<u8>>| {
                compile(i, UNIT.as_bytes(), ENVIRONMENT.as_bytes(), &dropins)
            };
            assert_eq!(
                code(compile(
                    &input(),
                    b"[Service]\n",
                    ENVIRONMENT.as_bytes(),
                    &BTreeMap::new()
                )),
                "policy_compile_template"
            );
            let mut mismatched = full_tun_input();
            mismatched.policy = Policy::DedicatedNone;
            assert_eq!(
                code(compile_with(&mismatched, guard_only(&ufw))),
                "policy_compile_identity_mode"
            );
            assert_eq!(
                code(compile_with(
                    &full_tun,
                    BTreeMap::from([(PathBuf::from("/etc/absolute.conf"), Vec::new())])
                )),
                "policy_compile_dropin_bounds"
            );
            assert_eq!(
                code(compile_with(
                    &full_tun,
                    BTreeMap::from([(
                        PathBuf::from(V2_BOOT_GATE_DROPIN),
                        b"[Unit]\nConditionPathExists=/tmp\n".to_vec()
                    )])
                )),
                "policy_compile_boot_gate"
            );
            let mut placeholder = input();
            placeholder.binary = "/usr/local/bin/__AEGIS_CLIENT_BIN__".into();
            assert_eq!(
                code(compile_with(&placeholder, BTreeMap::new())),
                "policy_compile_unit_render"
            );
            let mut foreign = guard_only(&ufw);
            foreign.insert("99-admin.conf".into(), b"[Service]\n".to_vec());
            assert_eq!(
                code(compile_with(&full_tun, foreign)),
                "policy_compile_fulltun_dropin_name"
            );
            assert_eq!(
                code(compile_with(
                    &full_tun,
                    BTreeMap::from([(
                        PathBuf::from("10-dedicated-uid.conf"),
                        b"[Service]\n".to_vec()
                    )])
                )),
                "policy_compile_guard_hook_missing"
            );
            assert_eq!(
                code(compile_with(&full_tun, guard_only(&changed))),
                "policy_compile_guard_hook_unrecognized"
            );
            let admission = crate::profile_auto_transaction::VerifiedFirstArm::test_only();
            assert_eq!(
                code(compile_first_arm(
                    &input(),
                    UNIT.as_bytes(),
                    ENVIRONMENT.as_bytes(),
                    &BTreeMap::new(),
                    &admission
                )),
                "policy_compile_first_arm_entry"
            );
            let mut trailing = input();
            trailing.state = "/var/lib/aegis-state ".into();
            assert_eq!(
                code(compile_with(&trailing, BTreeMap::new())),
                "policy_compile_other"
            );
            for (text, expected) in [
                (COMPILE_TEMPLATE, 0),
                (COMPILE_IDENTITY_MODE, 1),
                (COMPILE_DROPIN_BOUNDS, 2),
                (COMPILE_BOOT_GATE, 3),
                (COMPILE_UNIT_TEMPLATE, 4),
                (COMPILE_UNIT_RENDER, 5),
                (COMPILE_FULLTUN_DROPIN_NAME, 6),
                (COMPILE_FIRST_ARM_DROPINS, 7),
                (COMPILE_GUARD_HOOK_MISSING, 8),
                (COMPILE_GUARD_HOOK_UNRECOGNIZED, 9),
                (COMPILE_FULLTUN_UNIT_SHAPE, 10),
                (COMPILE_FIRST_ARM_ENTRY, 11),
                (REFUSED, 12),
                ("private /etc/aegis path", 12),
            ] {
                assert_eq!(refusal_code(text), COMPILE_REFUSAL_CODES[expected]);
            }
            let mut unique = COMPILE_REFUSAL_CODES.to_vec();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), COMPILE_REFUSAL_CODES.len());
        }

        #[test]
        fn compiler_notify_readiness_is_closed_and_source_bound() {
            let p = compile(
                &input(),
                UNIT.as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new(),
            )
            .unwrap();
            let text = std::str::from_utf8(&p.unit).unwrap();
            assert_eq!(text.matches("Type=notify\n").count(), 1);
            assert_eq!(text.matches("NotifyAccess=main\n").count(), 1);
            assert!(!text.contains("Type=simple"));
            assert!(compile(
                &input(),
                UNIT.replace("Type=simple", "Type=notify").as_bytes(),
                ENVIRONMENT.as_bytes(),
                &BTreeMap::new()
            )
            .is_err());
        }
        struct KernelFixture {
            root: PathBuf,
            parent: PathBuf,
            stage: PathBuf,
            epoch: std::cell::Cell<[u8; 32]>,
            original: Original,
            receipts: std::cell::RefCell<Vec<Vec<u8>>>,
            intents: std::cell::RefCell<usize>,
            intent_bytes: std::cell::RefCell<Vec<Vec<u8>>>,
            publication_pending: std::cell::Cell<bool>,
            rollback_bytes: std::cell::RefCell<Vec<Vec<u8>>>,
            rollback_pending: std::cell::Cell<bool>,
            restoration_bytes: std::cell::RefCell<Vec<Vec<u8>>>,
            fail_commit: std::cell::Cell<bool>,
            fail_rollback_commit: std::cell::Cell<bool>,
            block_publish: std::cell::Cell<bool>,
            active_mutation: std::cell::Cell<Option<Mutation>>,
        }
        impl Drop for KernelFixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
        fn open_dir(p: &Path) -> OwnedFd {
            use std::os::unix::ffi::OsStrExt;
            let name = CString::new(p.as_os_str().as_bytes()).unwrap();
            owned(unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })
            .unwrap()
        }
        impl KernelFixture {
            fn new(existing: bool) -> Self {
                use std::os::unix::fs::PermissionsExt;
                let root = std::env::temp_dir().join(format!(
                    ".aegis-unit-fixture-{:032x}",
                    rand::random::<u128>()
                ));
                std::fs::create_dir(&root).unwrap();
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                let parent = root.join("systemd");
                let stage = root.join("stage");
                for p in [&parent, &stage] {
                    std::fs::create_dir(p).unwrap();
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
                std::fs::write(parent.join("unrelated.service"), b"unrelated-unit").unwrap();
                if existing {
                    std::fs::write(parent.join(LeafRole::BaseUnit.name()), b"captured-old-unit")
                        .unwrap();
                    std::fs::set_permissions(
                        parent.join(LeafRole::BaseUnit.name()),
                        std::fs::Permissions::from_mode(0o644),
                    )
                    .unwrap();
                }
                let original = match read(&open_dir(&parent), LeafRole::BaseUnit.name()).unwrap() {
                    None => Original {
                        node: None,
                        digest: None,
                    },
                    Some((n, b)) => Original {
                        node: Some(n),
                        digest: Some(hash(&b)),
                    },
                };
                Self {
                    root,
                    parent,
                    stage,
                    epoch: std::cell::Cell::new([7; 32]),
                    original,
                    receipts: std::cell::RefCell::new(Vec::new()),
                    intents: std::cell::RefCell::new(0),
                    intent_bytes: std::cell::RefCell::new(Vec::new()),
                    publication_pending: std::cell::Cell::new(false),
                    rollback_bytes: std::cell::RefCell::new(Vec::new()),
                    rollback_pending: std::cell::Cell::new(false),
                    restoration_bytes: std::cell::RefCell::new(Vec::new()),
                    fail_commit: std::cell::Cell::new(false),
                    fail_rollback_commit: std::cell::Cell::new(false),
                    block_publish: std::cell::Cell::new(false),
                    active_mutation: std::cell::Cell::new(None),
                }
            }
        }
        // Only the primitive fixture uses this authority: real local descriptors,
        // persistent receipt identity and epoch rejection. It does NOT model
        // systemd/cgroup/provider acceptance or claim runtime unit installation.
        impl Context for KernelFixture {
            fn epoch(&self) -> Result<[u8; 32]> {
                Ok(self.epoch.get())
            }
            fn held_targets(&self, _: LeafRole) -> Result<Targets> {
                Ok(Targets {
                    parent: open_dir(&self.parent),
                    stage: open_dir(&self.stage),
                })
            }
            fn original(&self, _: LeafRole) -> Result<Original> {
                Ok(self.original.clone())
            }
            fn accepted_bytes(&self, _: LeafRole) -> Result<Vec<u8>> {
                Ok(b"new-owned-unit".to_vec())
            }
            fn original_guard(&self, _: LeafRole, o: &Original) -> Result<()> {
                if serde_json::to_vec(o).unwrap() == serde_json::to_vec(&self.original).unwrap() {
                    Ok(())
                } else {
                    Err(REFUSED)
                }
            }
            fn stopped_mutation(
                &self,
                _: LeafRole,
                e: &[u8; 32],
                m: Mutation,
                f: &mut dyn FnMut() -> Result<()>,
            ) -> Result<()> {
                if *e != self.epoch.get()
                    || (self.block_publish.get() && matches!(m, Mutation::Publish))
                {
                    return Err(REFUSED);
                }
                let previous = self.active_mutation.replace(Some(m));
                let outcome = f();
                self.active_mutation.set(previous);
                outcome
            }
            fn stage_prepared(&self, _: &Intent) -> Result<()> {
                Ok(())
            }
            fn persist_intent(&self, i: &Intent) -> Result<()> {
                *self.intents.borrow_mut() += 1;
                self.intent_bytes
                    .borrow_mut()
                    .push(serde_json::to_vec(i).unwrap());
                self.publication_pending.set(true);
                Ok(())
            }
            fn admit_durable_publication_intent(&self, i: &Intent) -> Result<()> {
                if self.publication_pending.get()
                    || self.epoch.get() != i.epoch
                    || !self
                        .intent_bytes
                        .borrow()
                        .contains(&serde_json::to_vec(i).unwrap())
                {
                    return Err(REFUSED);
                }
                Ok(())
            }
            fn admit_intent(&self, i: &Intent) -> Result<()> {
                if !self.publication_pending.get() {
                    return Err(REFUSED);
                }
                if self
                    .intent_bytes
                    .borrow()
                    .contains(&serde_json::to_vec(i).unwrap())
                {
                    Ok(())
                } else {
                    Err(REFUSED)
                }
            }
            fn commit_receipt(&self, r: &Receipt) -> Result<()> {
                if !matches!(
                    self.active_mutation.get(),
                    Some(Mutation::Publish | Mutation::RecoverReadback)
                ) || self.fail_commit.get()
                {
                    return Err(REFUSED);
                }
                self.receipts
                    .borrow_mut()
                    .push(serde_json::to_vec(r).unwrap());
                self.publication_pending.set(false);
                Ok(())
            }
            fn admit_receipt(&self, r: &Receipt) -> Result<()> {
                if self
                    .receipts
                    .borrow()
                    .contains(&serde_json::to_vec(r).unwrap())
                {
                    Ok(())
                } else {
                    Err(REFUSED)
                }
            }
            fn persist_rollback_intent(&self, r: &Receipt, e: &[u8; 32]) -> Result<()> {
                self.admit_receipt(r)?;
                self.rollback_bytes
                    .borrow_mut()
                    .push(serde_json::to_vec(&(r, e)).unwrap());
                self.rollback_pending.set(true);
                Ok(())
            }
            fn admit_rollback_intent(&self, r: &Receipt, e: &[u8; 32]) -> Result<()> {
                if !self.rollback_pending.get() {
                    return Err(REFUSED);
                }
                if self
                    .rollback_bytes
                    .borrow()
                    .contains(&serde_json::to_vec(&(r, e)).unwrap())
                {
                    Ok(())
                } else {
                    Err(REFUSED)
                }
            }
            fn commit_rollback(&self, r: &RestorationReceipt) -> Result<()> {
                if !matches!(
                    self.active_mutation.get(),
                    Some(Mutation::Rollback | Mutation::RecoverReadback)
                ) || self.fail_rollback_commit.get()
                {
                    return Err(REFUSED);
                }
                self.restoration_bytes
                    .borrow_mut()
                    .push(serde_json::to_vec(r).unwrap());
                self.rollback_pending.set(false);
                Ok(())
            }
            fn admit_restoration_source(&self, r: &RestorationReceipt) -> Result<()> {
                self.admit_receipt(r.forward_receipt())?;
                self.admit_restoration(r)?;
                if r.rollback_epoch() != self.epoch.get()
                    || !self.rollback_bytes.borrow().contains(
                        &serde_json::to_vec(&(r.forward_receipt(), r.rollback_epoch())).unwrap(),
                    )
                {
                    return Err(REFUSED);
                }
                Ok(())
            }
            fn admit_restoration(&self, r: &RestorationReceipt) -> Result<()> {
                if self
                    .restoration_bytes
                    .borrow()
                    .contains(&serde_json::to_vec(r).unwrap())
                {
                    Ok(())
                } else {
                    Err(REFUSED)
                }
            }
        }
        #[test]
        #[ignore = "actual disposable root Linux filesystem primitive only; no systemd service"]
        fn actual_unit_leaf_exchange_absence_rollback_preserves_old_inode_and_other_units() {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            for existing in [false, true] {
                let f = KernelFixture::new(existing);
                let original = f.original.node.clone();
                let r = publish(&f, LeafRole::BaseUnit).unwrap();
                assert_eq!(
                    std::fs::read(f.parent.join("unrelated.service")).unwrap(),
                    b"unrelated-unit"
                );
                assert_eq!(*f.intents.borrow(), 1);
                verify(&f, &r).unwrap();
                // A replay outside the admitted mutation is not a history commit.
                assert!(f.commit_receipt(&r).is_err());
                assert_eq!(r.published.mode & 0o777, 0o644);
                assert_eq!((r.published.uid, r.published.gid), (0, 0));
                assert_eq!(r.published.links, 1);
                let restoration = rollback(&f, &r).unwrap();
                verify_restoration(&f, &restoration).unwrap();
                assert!(f.commit_rollback(&restoration).is_err());
                assert_eq!(
                    restoration.restored_namespace_witness().metadata.is_some(),
                    existing
                );
                assert_eq!(
                    restoration.forward_receipt().publication_epoch(),
                    r.publication_epoch()
                );
                match original {
                    None => assert!(!f.parent.join(LeafRole::BaseUnit.name()).exists()),
                    Some(old) => {
                        let (n, b) = read(&open_dir(&f.parent), LeafRole::BaseUnit.name())
                            .unwrap()
                            .unwrap();
                        assert_eq!((old.dev, old.ino), (n.dev, n.ino));
                        assert_eq!(b, b"captured-old-unit");
                    }
                }
            }
        }
        #[test]
        #[ignore = "actual disposable root Linux filesystem primitive only; no systemd service"]
        fn actual_unit_fifo_symlink_hardlink_and_substitution_refuse_without_victim_write() {
            use std::os::unix::{
                ffi::OsStrExt,
                fs::{symlink, PermissionsExt},
            };
            assert_eq!(unsafe { libc::geteuid() }, 0);
            for kind in [0, 1, 2] {
                let f = KernelFixture::new(false);
                let path = f.parent.join(LeafRole::BaseUnit.name());
                let victim = f.root.join("victim");
                std::fs::write(&victim, b"victim-original").unwrap();
                std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
                match kind {
                    0 => {
                        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    }
                    1 => symlink(&victim, &path).unwrap(),
                    _ => std::fs::hard_link(&victim, &path).unwrap(),
                }
                assert!(publish(&f, LeafRole::BaseUnit).is_err());
                assert_eq!(std::fs::read(&victim).unwrap(), b"victim-original");
                assert_eq!(*f.intents.borrow(), 0);
            }
            let f = KernelFixture::new(true);
            let r = publish(&f, LeafRole::BaseUnit).unwrap();
            std::fs::remove_file(f.parent.join(LeafRole::BaseUnit.name())).unwrap();
            std::fs::write(f.parent.join(LeafRole::BaseUnit.name()), b"foreign").unwrap();
            assert!(rollback(&f, &r).is_err());
            assert_eq!(
                std::fs::read(f.parent.join(LeafRole::BaseUnit.name())).unwrap(),
                b"foreign"
            );
        }
        #[test]
        #[ignore = "actual disposable root Linux filesystem primitive only; no systemd service"]
        fn actual_unit_changed_epoch_prevents_mutation_and_receipt_replay() {
            struct Changed<'a>(&'a KernelFixture);
            impl Context for Changed<'_> {
                fn epoch(&self) -> Result<[u8; 32]> {
                    Ok(self.0.epoch.get())
                }
                fn held_targets(&self, r: LeafRole) -> Result<Targets> {
                    self.0.held_targets(r)
                }
                fn original(&self, r: LeafRole) -> Result<Original> {
                    self.0.original(r)
                }
                fn accepted_bytes(&self, r: LeafRole) -> Result<Vec<u8>> {
                    self.0.accepted_bytes(r)
                }
                fn original_guard(&self, r: LeafRole, o: &Original) -> Result<()> {
                    self.0.original_guard(r, o)
                }
                fn stopped_mutation(
                    &self,
                    r: LeafRole,
                    e: &[u8; 32],
                    m: Mutation,
                    f: &mut dyn FnMut() -> Result<()>,
                ) -> Result<()> {
                    self.0.epoch.set([9; 32]);
                    self.0.stopped_mutation(r, e, m, f)
                }
                fn stage_prepared(&self, i: &Intent) -> Result<()> {
                    self.0.stage_prepared(i)
                }
                fn persist_intent(&self, i: &Intent) -> Result<()> {
                    self.0.persist_intent(i)
                }
                fn admit_intent(&self, i: &Intent) -> Result<()> {
                    self.0.admit_intent(i)
                }
                fn admit_durable_publication_intent(&self, i: &Intent) -> Result<()> {
                    self.0.admit_durable_publication_intent(i)
                }
                fn commit_receipt(&self, r: &Receipt) -> Result<()> {
                    self.0.commit_receipt(r)
                }
                fn admit_receipt(&self, r: &Receipt) -> Result<()> {
                    self.0.admit_receipt(r)
                }
                fn persist_rollback_intent(&self, r: &Receipt, e: &[u8; 32]) -> Result<()> {
                    self.0.persist_rollback_intent(r, e)
                }
                fn admit_rollback_intent(&self, r: &Receipt, e: &[u8; 32]) -> Result<()> {
                    self.0.admit_rollback_intent(r, e)
                }
                fn commit_rollback(&self, r: &RestorationReceipt) -> Result<()> {
                    self.0.commit_rollback(r)
                }
                fn admit_restoration(&self, r: &RestorationReceipt) -> Result<()> {
                    self.0.admit_restoration(r)
                }
                fn admit_restoration_source(&self, r: &RestorationReceipt) -> Result<()> {
                    self.0.admit_restoration_source(r)
                }
            }
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let mut alias = KernelFixture::new(false);
            alias.stage = alias.parent.clone();
            assert!(publish(&alias, LeafRole::BaseUnit).is_err());
            assert_eq!(*alias.intents.borrow(), 0);
            assert!(!alias.parent.join(LeafRole::BaseUnit.name()).exists());
            let f = KernelFixture::new(true);
            assert!(publish(&Changed(&f), LeafRole::BaseUnit).is_err());
            assert_eq!(
                std::fs::read(f.parent.join(LeafRole::BaseUnit.name())).unwrap(),
                b"captured-old-unit"
            );
            assert_eq!(*f.intents.borrow(), 0);
            let g = KernelFixture::new(true);
            let r = publish(&g, LeafRole::BaseUnit).unwrap();
            assert!(verify(&f, &r).is_err());
            let restored = rollback(&g, &r).unwrap();
            verify_restoration(&g, &restored).unwrap();
            std::fs::remove_file(g.parent.join(LeafRole::BaseUnit.name())).unwrap();
            std::fs::write(
                g.parent.join(LeafRole::BaseUnit.name()),
                b"foreign-after-restoration",
            )
            .unwrap();
            assert!(verify_restoration(&g, &restored).is_err());
            assert_eq!(
                std::fs::read(g.parent.join(LeafRole::BaseUnit.name())).unwrap(),
                b"foreign-after-restoration"
            );
        }

        #[test]
        #[ignore = "actual disposable root Linux retained-dropin inode/heterogeneous metadata; no global systemd writes"]
        fn actual_dropin_retained_inode_and_heterogeneous_original_attrs_are_restored() {
            use crate::profile_auto_publication::linux as fs;
            use std::{
                collections::BTreeSet,
                os::unix::fs::{MetadataExt, PermissionsExt},
            };
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let f = KernelFixture::new(false);
            let path = f.root.join("owned-dropins");
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let empty = path.join("empty");
            std::fs::create_dir(&empty).unwrap();
            std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o750)).unwrap();
            let original_file = path.join("99-owner.conf");
            std::fs::write(&original_file, b"# owner original").unwrap();
            std::fs::set_permissions(&original_file, std::fs::Permissions::from_mode(0o440))
                .unwrap();
            use std::os::unix::ffi::OsStrExt;
            for item in [&empty, &original_file] {
                let name = CString::new(item.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::chown(name.as_ptr(), 0, 41) }, 0);
            }
            let before_root = std::fs::metadata(&path).unwrap();
            let before_file = std::fs::metadata(&original_file).unwrap();
            let before_empty = std::fs::metadata(&empty).unwrap();
            let expected = fs::Target::open(&path).unwrap().inspect().unwrap().unwrap();
            struct Guard {
                path: PathBuf,
                generation: fs::Generation,
            }
            impl fs::CaptureGuard for Guard {
                fn validate_captured_generation(
                    &self,
                    target: &Path,
                    expected: Option<&fs::Generation>,
                ) -> Result<()> {
                    if target != self.path
                        || expected.ok_or(REFUSED)?.digest()? != self.generation.digest()?
                    {
                        return Err(REFUSED);
                    }
                    Ok(())
                }
            }
            let guard = Guard {
                path: path.clone(),
                generation: expected.clone(),
            };
            let files = BTreeMap::from([
                (PathBuf::from("99-owner.conf"), b"# owner original".to_vec()),
                (
                    PathBuf::from("10-dedicated-uid.conf"),
                    b"[Service]\nUser=aegis\n".to_vec(),
                ),
            ]);
            let policy = fs::ConfigPolicy {
                runtime_uid: 0,
                runtime_gid: 0,
                root_policy: true,
                leaves: files
                    .keys()
                    .cloned()
                    .map(|p| (p, fs::ConfigLeafRole::Public))
                    .collect(),
            };
            let tree =
                fs::CapturedTree::new(files, BTreeSet::from([PathBuf::from("empty")])).unwrap();
            let current = fs::Prepared::build_runtime_config_captured(
                fs::Target::open(&path).unwrap(),
                Some(expected),
                &tree,
                &policy,
                |_| Ok(()),
                &guard,
            )
            .unwrap()
            .publish_captured(|_| Ok(()), &guard)
            .unwrap();
            fs::verify_runtime_config_policy(&fs::Target::open(&path).unwrap(), &current, &policy)
                .unwrap();
            let owned = Guard {
                path: path.clone(),
                generation: current.generation().clone(),
            };
            let restored = restore_retained_dropin_target(
                fs::Target::open(&path).unwrap(),
                &current,
                |_| Ok(()),
                &owned,
            )
            .unwrap();
            fs::validate_retained_restore_predecessor(&current, &restored).unwrap();
            assert!(fs::validate_retained_restore_predecessor(&restored, &current).is_err());
            assert!(fs::validate_retained_restore_predecessor(&current, &current).is_err());
            fs::revalidate_current_receipt(&fs::Target::open(&path).unwrap(), &restored).unwrap();
            let after_root = std::fs::metadata(&path).unwrap();
            let after_file = std::fs::metadata(&original_file).unwrap();
            let after_empty = std::fs::metadata(&empty).unwrap();
            for (before, after) in [
                (&before_root, &after_root),
                (&before_file, &after_file),
                (&before_empty, &after_empty),
            ] {
                assert_eq!(
                    (
                        before.dev(),
                        before.ino(),
                        before.uid(),
                        before.gid(),
                        before.mode(),
                        before.nlink()
                    ),
                    (
                        after.dev(),
                        after.ino(),
                        after.uid(),
                        after.gid(),
                        after.mode(),
                        after.nlink()
                    )
                );
            }
            assert_eq!(std::fs::read(&original_file).unwrap(), b"# owner original");
            assert!(!path.join("10-dedicated-uid.conf").exists());
            assert_eq!(
                std::fs::read(f.parent.join("unrelated.service")).unwrap(),
                b"unrelated-unit"
            );
        }

        #[test]
        #[ignore = "Actual root Linux completed BaseUnit recovery gate; not a manager or Store acceptance"]
        fn actual_completed_base_recovery_capability_refuses_before_and_changed_epoch() {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let before = KernelFixture::new(true);
            before.block_publish.set(true);
            assert!(publish(&before, LeafRole::BaseUnit).is_err());
            let i: Intent = serde_json::from_slice(&before.intent_bytes.borrow()[0]).unwrap();
            let proof = pending_publish_readback(&before, &i).unwrap();
            assert!(proof.require_completed_base(&before).is_err());
            let completed = KernelFixture::new(true);
            completed.fail_commit.set(true);
            assert!(publish(&completed, LeafRole::BaseUnit).is_err());
            let i: Intent = serde_json::from_slice(&completed.intent_bytes.borrow()[0]).unwrap();
            let proof = pending_publish_readback(&completed, &i).unwrap();
            proof.require_completed_base(&completed).unwrap();
            completed.epoch.set([17; 32]);
            assert!(proof.require_completed_base(&completed).is_err());
        }
        #[test]
        #[ignore = "Actual disposable root Linux held pending singleton readback; no provider/Store acceptance"]
        fn actual_pending_singleton_readback_holds_target_and_refuses_changed_bytes() {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            for before in [true, false] {
                let f = KernelFixture::new(true);
                f.block_publish.set(before);
                f.fail_commit.set(!before);
                assert!(publish(&f, LeafRole::BaseUnit).is_err());
                let i: Intent = serde_json::from_slice(&f.intent_bytes.borrow()[0]).unwrap();
                let proof = pending_publish_readback(&f, &i).unwrap();
                assert_eq!(
                    proof.outcome(),
                    if before {
                        PendingSingletonOutcome::NotApplied
                    } else {
                        PendingSingletonOutcome::Completed
                    }
                );
                proof.revalidate(&f).unwrap();
                // Independent actual filesystem metadata verifies the complete
                // observation contract, including nanoseconds and full mode.
                use std::os::unix::fs::MetadataExt;
                let actual = std::fs::metadata(f.parent.join(LeafRole::BaseUnit.name())).unwrap();
                let witness = proof.target_witness();
                let observed = witness.metadata.unwrap();
                assert_eq!(
                    (
                        observed.device,
                        observed.inode,
                        observed.uid,
                        observed.gid,
                        observed.mode,
                        observed.links,
                        observed.size
                    ),
                    (
                        actual.dev(),
                        actual.ino(),
                        actual.uid(),
                        actual.gid(),
                        actual.mode(),
                        actual.nlink(),
                        i64::try_from(actual.size()).unwrap()
                    )
                );
                assert_eq!(
                    (
                        observed.mtime_sec,
                        observed.mtime_nsec,
                        observed.ctime_sec,
                        observed.ctime_nsec
                    ),
                    (
                        actual.mtime(),
                        actual.mtime_nsec(),
                        actual.ctime(),
                        actual.ctime_nsec()
                    )
                );
                assert_eq!(
                    witness.sha256,
                    Some(hash(
                        &std::fs::read(f.parent.join(LeafRole::BaseUnit.name())).unwrap()
                    ))
                );
                std::fs::write(
                    f.parent.join(LeafRole::BaseUnit.name()),
                    b"foreign changed unit",
                )
                .unwrap();
                assert!(proof.revalidate(&f).is_err());
            }
        }
        #[test]
        #[ignore = "requires disposable root Linux; actual singleton FD/syscall fixture"]
        fn actual_publication_recovery_completion_retains_durable_source_and_held_snapshot() {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "never silently skip native fixture"
            );
            for completed in [true, false] {
                let fixture = KernelFixture::new(true);
                fixture.fail_commit.set(completed);
                fixture.block_publish.set(!completed);
                assert!(publish(&fixture, LeafRole::BaseUnit).is_err());
                let intent: Intent =
                    serde_json::from_slice(&fixture.intent_bytes.borrow()[0]).unwrap();
                let proof = pending_publish_readback(&fixture, &intent).unwrap();
                if completed {
                    fixture.fail_commit.set(false);
                    assert!(matches!(
                        recover_pending_publish(&fixture, &intent).unwrap(),
                        Recovery::Completed
                    ));
                } else {
                    assert!(matches!(
                        recover_pending_publish(&fixture, &intent).unwrap(),
                        Recovery::NotApplied
                    ));
                    fixture.publication_pending.set(false); // model durable pending retirement
                }
                assert!(proof.revalidate(&fixture).is_err());
                proof.revalidate_recovered_publication(&fixture).unwrap();
                fixture.epoch.set([8; 32]);
                assert!(proof.revalidate_recovered_publication(&fixture).is_err());
                fixture.epoch.set([7; 32]);
                let source = fixture.intent_bytes.borrow_mut().pop().unwrap();
                assert!(proof.revalidate_recovered_publication(&fixture).is_err());
                fixture.intent_bytes.borrow_mut().push(source);
                std::fs::write(
                    fixture.parent.join(LeafRole::BaseUnit.name()),
                    b"foreign post-recovery target",
                )
                .unwrap();
                assert!(proof.revalidate_recovered_publication(&fixture).is_err());
            }
            // Genuine kernel file/FD operations with a fixture journal; this is
            // not a real protected RootContext or installed manager acceptance.
        }
        #[test]
        #[ignore = "requires disposable root Linux; actual singleton FD/syscall fixture"]
        fn actual_completed_restoration_verifies_after_pending_clear_and_preserves_source_binding()
        {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "never silently skip native fixture"
            );
            for existed in [true, false] {
                let fixture = KernelFixture::new(existed);
                let forward = publish(&fixture, LeafRole::BaseUnit).unwrap();
                let restored = rollback(&fixture, &forward).unwrap();
                assert!(!fixture.rollback_pending.get());
                assert!(fixture
                    .admit_rollback_intent(&forward, &restored.rollback_epoch())
                    .is_err());
                verify_restoration(&fixture, &restored).unwrap();
                let source = fixture.rollback_bytes.borrow_mut().pop().unwrap();
                assert!(verify_restoration(&fixture, &restored).is_err());
                fixture.rollback_bytes.borrow_mut().push(source);
                fixture.epoch.set([8; 32]);
                assert!(verify_restoration(&fixture, &restored).is_err());
                fixture.epoch.set([7; 32]);
                std::fs::write(
                    fixture.parent.join(LeafRole::BaseUnit.name()),
                    b"foreign after completed rollback",
                )
                .unwrap();
                assert!(verify_restoration(&fixture, &restored).is_err());
            }
            // Actual private filesystem/held-FD operations with fixture journal;
            // no live manager, protected Store or installed lifecycle is claimed.
        }
        #[test]
        #[ignore = "actual disposable root Linux pending singleton kernel outcomes; no systemd/provider acceptance"]
        fn actual_singleton_pending_publish_and_original_absence_rollback_recover_only_owned_outcomes(
        ) {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let before = KernelFixture::new(true);
            before.block_publish.set(true);
            assert!(publish(&before, LeafRole::BaseUnit).is_err());
            let i: Intent = serde_json::from_slice(&before.intent_bytes.borrow()[0]).unwrap();
            assert!(matches!(
                recover_pending_publish(&before, &i).unwrap(),
                Recovery::NotApplied
            ));
            assert_eq!(
                std::fs::read(before.parent.join(LeafRole::BaseUnit.name())).unwrap(),
                b"captured-old-unit"
            );
            for existed in [false, true] {
                let f = KernelFixture::new(existed);
                f.fail_commit.set(true);
                assert!(publish(&f, LeafRole::BaseUnit).is_err());
                let i: Intent = serde_json::from_slice(&f.intent_bytes.borrow()[0]).unwrap();
                f.fail_commit.set(false);
                assert!(matches!(
                    recover_pending_publish(&f, &i).unwrap(),
                    Recovery::Completed
                ));
                let r: Receipt = serde_json::from_slice(&f.receipts.borrow()[0]).unwrap();
                f.fail_rollback_commit.set(true);
                assert!(rollback(&f, &r).is_err());
                f.fail_rollback_commit.set(false);
                let restoration = match recover_pending_rollback(&f, &r, &f.epoch.get()).unwrap() {
                    RollbackRecovery::Completed(r) => r,
                    RollbackRecovery::NotApplied => {
                        panic!("actual completed rollback cannot claim not-applied")
                    }
                };
                verify_restoration(&f, &restoration).unwrap();
                assert_eq!(
                    restoration.restored_namespace_witness().metadata.is_some(),
                    existed
                );
                if existed {
                    assert_eq!(
                        std::fs::read(f.parent.join(LeafRole::BaseUnit.name())).unwrap(),
                        b"captured-old-unit"
                    );
                } else {
                    assert!(!f.parent.join(LeafRole::BaseUnit.name()).exists());
                }
                assert_eq!(
                    std::fs::read(f.parent.join("unrelated.service")).unwrap(),
                    b"unrelated-unit"
                );
            }
            let foreign = KernelFixture::new(false);
            foreign.fail_commit.set(true);
            assert!(publish(&foreign, LeafRole::BaseUnit).is_err());
            let i: Intent = serde_json::from_slice(&foreign.intent_bytes.borrow()[0]).unwrap();
            std::fs::remove_file(foreign.parent.join(LeafRole::BaseUnit.name())).unwrap();
            std::fs::write(
                foreign.parent.join(LeafRole::BaseUnit.name()),
                b"foreign-unit",
            )
            .unwrap();
            foreign.fail_commit.set(false);
            assert!(recover_pending_publish(&foreign, &i).is_err());
            assert!(foreign.receipts.borrow().is_empty());
            assert_eq!(
                std::fs::read(foreign.parent.join(LeafRole::BaseUnit.name())).unwrap(),
                b"foreign-unit"
            );
        }
    }
}
