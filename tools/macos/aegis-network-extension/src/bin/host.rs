// v39 menu-bar app (AppKit glue; its model and flows are in the library).
#[cfg(target_os = "macos")]
#[path = "host/appkit.rs"]
mod appkit;
#[cfg(target_os = "macos")]
#[path = "host/menu_app.rs"]
mod menu_app;

#[cfg(target_os = "macos")]
mod native {
    use aegis_network_extension::host_lifecycle::{
        parse_host_args, protocol_flags_text, save_refusal_may_be_durable, ActivationTracker,
        DeactivationTracker, HostCommand, OwnedVerb, ProfileLine, ReplacementDecision, ResultClaim,
        ACTIVATION_TIMEOUT_SECS, DEACTIVATION_TIMEOUT_SECS, EXIT_USAGE, UNAVAILABLE, USAGE,
    };
    use objc2::runtime::ProtocolObject;
    use objc2::{define_class, msg_send, rc::Retained, AnyThread};
    use objc2_foundation::NSError;
    use objc2_foundation::{NSObject, NSObjectProtocol, NSString};
    use objc2_system_extensions::{
        OSSystemExtensionErrorDomain, OSSystemExtensionManager, OSSystemExtensionProperties,
        OSSystemExtensionReplacementAction, OSSystemExtensionRequest,
        OSSystemExtensionRequestDelegate, OSSystemExtensionRequestResult,
    };
    use std::sync::{Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    /// The single activation request of this process. Delegate callbacks
    /// arrive on the main queue; the lock only makes the shared state sound.
    static ACTIVATION: Mutex<Option<ActivationTracker>> = Mutex::new(None);

    fn activation() -> MutexGuard<'static, Option<ActivationTracker>> {
        ACTIVATION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The single deactivation request of this process (S21). A process
    /// installs at most one of `ACTIVATION` and `DEACTIVATION`.
    static DEACTIVATION: Mutex<Option<DeactivationTracker>> = Mutex::new(None);

    fn deactivation() -> MutexGuard<'static, Option<DeactivationTracker>> {
        DEACTIVATION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn stop_if_settled(settled: bool) {
        if settled {
            unsafe { CFRunLoopStop(CFRunLoopGetMain()) };
        }
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[name = "AegisSystemExtensionApprovalDelegate"]
        struct ApprovalDelegate;
        unsafe impl NSObjectProtocol for ApprovalDelegate {}
        unsafe impl OSSystemExtensionRequestDelegate for ApprovalDelegate {
            #[unsafe(method(requestNeedsUserApproval:))]
            fn needs_approval(&self, _request: &OSSystemExtensionRequest) {
                eprintln!(
                    "System Settings approval required; no automatic approval. Waiting at most {ACTIVATION_TIMEOUT_SECS}s."
                );
                if let Some(t) = activation().as_mut() {
                    t.needs_user_approval();
                }
                if let Some(t) = deactivation().as_mut() {
                    t.needs_user_approval();
                }
            }
            #[unsafe(method(request:didFinishWithResult:))]
            fn finish(
                &self,
                _request: &OSSystemExtensionRequest,
                result: OSSystemExtensionRequestResult,
            ) {
                let deactivating = deactivation().as_mut().map(|t| t.finished(result.0));
                let settled = match deactivating {
                    Some(settled) => {
                        eprintln!("Deactivation request finished.");
                        settled
                    }
                    None => {
                        eprintln!("Activation request finished; tunnel readiness is separate.");
                        activation().as_mut().is_some_and(|t| t.finished(result.0))
                    }
                };
                stop_if_settled(settled);
            }
            #[unsafe(method(request:didFailWithError:))]
            fn failure(&self, _request: &OSSystemExtensionRequest, error: &NSError) {
                let domain = error.domain();
                let sysext = unsafe { &*domain == OSSystemExtensionErrorDomain };
                let (name, code) = (domain.to_string(), error.code());
                let deactivating = deactivation()
                    .as_mut()
                    .map(|t| t.failed(sysext, &name, code));
                let settled = match deactivating {
                    Some(settled) => {
                        eprintln!("Deactivation request failed.");
                        settled
                    }
                    None => {
                        eprintln!("Activation request failed.");
                        activation()
                            .as_mut()
                            .is_some_and(|t| t.failed(sysext, &name, code))
                    }
                };
                stop_if_settled(settled);
            }
            #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
            fn replace(
                &self,
                _request: &OSSystemExtensionRequest,
                existing: &OSSystemExtensionProperties,
                incoming: &OSSystemExtensionProperties,
            ) -> OSSystemExtensionReplacementAction {
                let (existing_id, existing_version, incoming_id, incoming_version) = unsafe {
                    (
                        existing.bundleIdentifier().to_string(),
                        existing.bundleVersion().to_string(),
                        incoming.bundleIdentifier().to_string(),
                        incoming.bundleVersion().to_string(),
                    )
                };
                // Replace only with a numerically newer CFBundleVersion of
                // this provider; equal, lower, malformed, foreign or an
                // untracked request cancels.
                let decision = activation().as_mut().map(|t| {
                    t.replacement(
                        &existing_id,
                        &existing_version,
                        &incoming_id,
                        &incoming_version,
                    )
                });
                match decision {
                    Some(ReplacementDecision::Replace) => {
                        eprintln!("Replacing the active extension with a newer CFBundleVersion.");
                        OSSystemExtensionReplacementAction::Replace
                    }
                    Some(ReplacementDecision::Cancel(reason)) => {
                        eprintln!("Replacement cancelled: {reason}.");
                        OSSystemExtensionReplacementAction::Cancel
                    }
                    None => OSSystemExtensionReplacementAction::Cancel,
                }
            }
        }
    );

    #[repr(C)]
    struct OpaqueRunLoop {
        _private: [u8; 0],
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFRunLoopDefaultMode: *const std::ffi::c_void;
        fn CFRunLoopRun();
        fn CFRunLoopGetMain() -> *mut OpaqueRunLoop;
        fn CFRunLoopStop(rl: *mut OpaqueRunLoop);
        fn CFRunLoopRunInMode(
            mode: *const std::ffi::c_void,
            seconds: f64,
            return_after_source_handled: u8,
        ) -> i32;
    }
    /// `kCFRunLoopRunFinished`: the mode has no sources or timers.
    const RUN_LOOP_FINISHED: i32 = 1;

    /// The one result (stdout line and exit code) of this process's bounded
    /// profile or XPC verb.
    static RESULT: ResultClaim = ResultClaim::new();

    /// A completion prints and exits only after claiming the result.
    /// When the watchdog claimed it first, the completion prints nothing and
    /// waits for the watchdog's exit.
    fn claim_result() {
        if !RESULT.claim() {
            loop {
                std::thread::park();
            }
        }
    }

    /// Every profile verb is bounded by its operation's one deadline (30 s
    /// from `Operation::begin`, terms query included); on expiry a dispatched
    /// preference change is an unknown result, never success. A completion
    /// that already claimed the result keeps it: the watchdog then prints
    /// nothing.
    fn watchdog(operation: &aegis_network_extension::manager::Operation, stdout_line: String) {
        let owner = operation.clone();
        std::thread::spawn(move || {
            std::thread::sleep(owner.remaining());
            owner.cancel();
            if !RESULT.claim() {
                return;
            }
            println!("{stdout_line}");
            eprintln!("profile operation expired; pending result unknown");
            std::process::exit(2);
        });
    }

    fn run_profile_loop() -> ! {
        unsafe { CFRunLoopRun() };
        // Every completion exits; a returning run loop is never a result.
        eprintln!("run loop returned without a profile result");
        std::process::exit(2);
    }

    /// S16a: the held tree's public terms from the provider, bounded like
    /// any XPC verb (10 s, and never past the verb's own deadline), before
    /// any profile preference is touched. The requested relay must be the
    /// held signed relay host; DNS and MTU are the provider's. No host-side
    /// `Aegis/` tree is read.
    fn provider_policy(
        relay: std::net::IpAddr,
        operation: &aegis_network_extension::manager::Operation,
    ) -> Result<
        (
            aegis_network_extension::profile_terms::ProfileTerms,
            aegis_network_extension::policy::FullWide,
        ),
        aegis_network_extension::profile_terms::TermsFailure,
    > {
        use aegis_network_extension::{
            profile_terms::{host_policy, TermsFailure},
            provider_xpc::{query_provider, Verb},
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(query_provider(Verb::ProfileTerms));
        });
        match receiver.recv_timeout(Duration::from_secs(10).min(operation.remaining())) {
            Ok(reply) => host_policy(reply, relay),
            Err(_) => Err(TermsFailure::Timeout),
        }
    }

    fn run_save_or_owned(command: HostCommand) -> ! {
        use aegis_network_extension::{
            configuration::PROVIDER_ID,
            manager::{
                self, fresh_owner_generation, Action, Operation, OwnedTarget, ProfileIntent,
                SaveMode,
            },
        };
        use std::sync::Arc;
        // One deadline for the whole verb: the terms query and the
        // preference operation both spend from it.
        let operation = Operation::begin();
        let save_mode = match command {
            HostCommand::SaveProfile {
                replace_existing: true,
                ..
            } => Some(SaveMode::ReplaceExisting),
            HostCommand::SaveProfile { .. } => Some(SaveMode::New),
            _ => None,
        };
        let save = save_mode.is_some();
        let (generation, relay, action) = match command {
            HostCommand::SaveProfile { relay, .. } => (fresh_owner_generation(), relay, None),
            HostCommand::Owned {
                verb,
                owner_generation,
                relay,
                window,
            } => (
                owner_generation,
                relay,
                Some(match verb {
                    OwnedVerb::Connect => Action::Connect(window),
                    OwnedVerb::Disconnect => Action::Disconnect,
                    OwnedVerb::Status => Action::Status,
                    OwnedVerb::RepairRuntime => Action::RepairRuntime,
                }),
            ),
            _ => unreachable!("only save/owned verbs reach this path"),
        };
        // A save, connect or repair needs the provider's admitted terms. A
        // disconnect or status read does not: it matches the saved profile's
        // own typed intent, so a stop never depends on provider XPC or on
        // the held tree (S16a). Nothing is saved before the terms are
        // admitted, so a refusal here is a known-unsaved result.
        let mut profile_sha256 = None;
        let target = if action.is_none_or(Action::needs_terms) {
            let (terms, policy) = match provider_policy(relay, &operation) {
                Ok(admitted) => admitted,
                Err(failure) => {
                    if save {
                        println!("owner_generation={generation} saved=false");
                    }
                    eprintln!("owner_generation={generation} {}", failure.code());
                    std::process::exit(failure.exit());
                }
            };
            profile_sha256 = Some(terms.profile_sha256);
            OwnedTarget::Terms(ProfileIntent {
                provider_id: PROVIDER_ID.into(),
                owner_generation: generation.clone(),
                policy,
            })
        } else {
            OwnedTarget::Saved {
                provider_id: PROVIDER_ID.into(),
                owner_generation: generation.clone(),
                relay,
            }
        };
        // A save may be durable before any result is known, so its owner
        // generation reaches stdout on every outcome, expiry included.
        watchdog(
            &operation,
            if save {
                format!("owner_generation={generation} saved=unknown")
            } else {
                format!("owner_generation={generation} result=unknown")
            },
        );
        let digest = profile_sha256
            .map(|digest| format!(" profile_sha256={digest}"))
            .unwrap_or_default();
        let owned_completion = |generation: String, digest: String| -> manager::Completion {
            Arc::new(move |result| {
                claim_result();
                match result {
                    Ok(status) => {
                        println!(
                            "owner_generation={generation}{digest} native_vpn_status={} native_acceptance=false",
                            status.0
                        );
                        std::process::exit(0);
                    }
                    Err(code) => {
                        eprintln!("owner_generation={generation} {code}");
                        std::process::exit(2);
                    }
                }
            })
        };
        let save_completion = |generation: String, digest: String| -> manager::SaveCompletion {
            Arc::new(move |result| {
                claim_result();
                match result {
                    Ok(report) => {
                        println!(
                            "owner_generation={generation} saved=true{digest} native_vpn_status={} native_acceptance=false",
                            report.status.0
                        );
                        if report.replaced {
                            eprintln!("owner_generation={generation} replaced_existing_profile");
                        }
                        std::process::exit(0);
                    }
                    Err(failure) => {
                        let saved = if save_refusal_may_be_durable(failure.code) {
                            "unknown"
                        } else {
                            "false"
                        };
                        println!("owner_generation={generation} saved={saved}");
                        eprintln!("owner_generation={generation} {}", failure.code);
                        if let Some(line) = failure.reloaded_line(&generation) {
                            eprintln!("{line}");
                        }
                        std::process::exit(2);
                    }
                }
            })
        };
        match (save_mode, action, target) {
            (Some(mode), None, OwnedTarget::Terms(intent)) => {
                manager::save_profile(intent, mode, operation, save_completion(generation, digest))
            }
            (Some(_), _, _) | (None, None, _) => {
                unreachable!("a save always has terms and no owned action")
            }
            (None, Some(action), target) => manager::act_owned(
                target,
                action,
                operation,
                owned_completion(generation, digest),
            ),
        }
        run_profile_loop();
    }

    fn run_list() -> ! {
        use aegis_network_extension::manager::{list_provider, ListCompletion, Operation};
        use std::sync::Arc;
        let operation = Operation::begin();
        watchdog(&operation, "profiles=unknown".into());
        let completion: ListCompletion = Arc::new(|result| {
            claim_result();
            match result {
                Ok(profiles) => {
                    for (index, p) in profiles.iter().enumerate() {
                        let line = ProfileLine {
                            index,
                            owner_generation: p.owner_generation.clone(),
                            scutil_service_id: p.scutil_service_id.clone(),
                            intent_valid: p.intent_valid,
                            enabled: p.enabled,
                            on_demand_enabled: p.on_demand_enabled,
                            native_vpn_status: p.status.0,
                        };
                        println!("{}", line.format());
                        // Diagnosis only, on stderr so the stable stdout line
                        // format the harness parses is unchanged.
                        eprintln!(
                            "profile_diag index={index} intent_error={} {}",
                            p.intent_error.unwrap_or("none"),
                            protocol_flags_text(p.flags)
                        );
                    }
                    println!("profiles={} native_acceptance=false", profiles.len());
                    std::process::exit(0);
                }
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(2);
                }
            }
        });
        list_provider(operation, completion);
        run_profile_loop();
    }

    fn run_emergency_stop() -> ! {
        use aegis_network_extension::manager::{emergency_stop, Operation, StopCompletion};
        use std::sync::Arc;
        let operation = Operation::begin();
        watchdog(&operation, "emergency_stop_requested=unknown".into());
        let completion: StopCompletion = Arc::new(|result| {
            claim_result();
            match result {
                Ok(stopped) => {
                    for (index, s) in stopped.iter().enumerate() {
                        println!(
                        "stop_requested index={index} owner_generation={} native_vpn_status_before={} on_demand_enabled={}",
                        s.owner_generation.as_deref().unwrap_or(UNAVAILABLE),
                        s.status_before.0,
                        s.on_demand_enabled
                    );
                        if s.on_demand_enabled {
                            eprintln!("on-demand is enabled for profile {index} and may restart the tunnel; run --remove-profile");
                        }
                    }
                    // A stop request is not an observed disconnect.
                    println!(
                        "emergency_stop_requested={} disconnected=unknown",
                        stopped.len()
                    );
                    std::process::exit(0);
                }
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(2);
                }
            }
        });
        emergency_stop(operation, completion);
        run_profile_loop();
    }

    fn run_remove() -> ! {
        use aegis_network_extension::manager::{
            remove_provider_profiles, Operation, RemovalCompletion,
        };
        use std::sync::Arc;
        let operation = Operation::begin();
        watchdog(&operation, "profiles_removed=unknown".into());
        let completion: RemovalCompletion = Arc::new(|result| {
            claim_result();
            match result {
                Ok(report) => {
                    println!(
                    "profiles_found={} profiles_removed={} removal_failed={} profiles_remaining={}",
                    report.found, report.removed, report.failed, report.remaining
                );
                    std::process::exit(if report.complete() { 0 } else { 2 });
                }
                Err(code) => {
                    println!("profiles_removed=unknown");
                    eprintln!("{code}");
                    std::process::exit(2);
                }
            }
        });
        remove_provider_profiles(operation, completion);
        run_profile_loop();
    }

    /// One bounded `--ping`/`--status`/`--profile-terms`/`--forget-identity` exchange with the
    /// installed provider; `--forget-identity` and `--renew` first need an
    /// administrator's password at the system prompt (67 without it, nothing
    /// sent). Exit 0 with one JSON line; 65 for a provider
    /// refusal or malformed reply (v30: and a closed `--identity-gate`); 69
    /// when the service is unavailable or its signer is refused; 74 when a
    /// forget left key material it should have removed; 75 when no reply
    /// arrives within the budget.
    fn run_xpc(verb: aegis_network_extension::provider_xpc::Verb) -> ! {
        use aegis_network_extension::{
            identity_import::authorization::IdentityChange,
            provider_xpc::{query_provider, query_provider_authorized, Verb},
        };
        if verb.requires_authorization() {
            // `--forget-identity` / `--renew`: an administrator approves
            // this one request before anything is sent.
            let change = if verb == Verb::Renew {
                IdentityChange::Renew
            } else {
                IdentityChange::Forget
            };
            let approval = authorize_or_exit(None, &change);
            start_xpc_watchdog(None);
            finish_xpc(query_provider_authorized(verb, approval))
        }
        start_xpc_watchdog(None);
        let started = std::time::Instant::now();
        let reply = query_provider(verb);
        // v31: `--status` and `--ping` also show a renewal that needs
        // attention (failing, deferred beside the armed guard, expired), on
        // stderr, within what is left of the XPC bound.
        if aegis_network_extension::host_lifecycle::renewal_line_wanted(verb, &reply) {
            if let Some(line) = renewal_line_within(RENEWAL_LINE_BOUND, started) {
                eprintln!("{line}");
            }
        }
        finish_xpc(reply)
    }

    /// v31: the most the renewal line may add, and the margin it leaves
    /// before the 10 s XPC watchdog.
    const RENEWAL_LINE_BOUND: Duration = Duration::from_secs(3);
    const XPC_WATCHDOG_MARGIN: Duration = Duration::from_secs(9);

    /// v31: one bounded `cert-status` query for the renewal line; nothing
    /// when it is slow, refused or healthy.
    fn renewal_line_within(bound: Duration, started: std::time::Instant) -> Option<String> {
        use aegis_network_extension::{
            host_lifecycle::renewal_line,
            provider_xpc::{query_provider, Verb},
        };
        let budget = bound.min(XPC_WATCHDOG_MARGIN.saturating_sub(started.elapsed()));
        if budget.is_zero() {
            return None;
        }
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sent.send(renewal_line(&query_provider(Verb::CertStatus)));
        });
        received.recv_timeout(budget).ok().flatten()
    }

    /// Set once the administrator prompt has been answered (or refused);
    /// the prompt watchdog exits only while it is still open.
    static PROMPT: ResultClaim = ResultClaim::new();

    /// Wait for one administrator prompt (`acquire`), bounded by
    /// `PROMPT_TIMEOUT_SECS`. On a refusal, a cancellation or no answer,
    /// `refused` prints the verb's stdout line, the code goes to stderr and
    /// the host exits `EXIT_AUTHORIZATION_REFUSED`; nothing has been sent or
    /// changed. The caller writes its banner first.
    fn prompt_or_exit<T>(
        timeout_code: &'static str,
        refused: impl Fn(&'static str) + Copy + Send + 'static,
        acquire: impl FnOnce() -> Result<T, &'static str>,
    ) -> T {
        use aegis_network_extension::{
            host_lifecycle::EXIT_AUTHORIZATION_REFUSED,
            identity_import::authorization::PROMPT_TIMEOUT_SECS,
        };
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(PROMPT_TIMEOUT_SECS));
            if !PROMPT.claim() {
                return;
            }
            refused(timeout_code);
            eprintln!("{timeout_code}");
            std::process::exit(EXIT_AUTHORIZATION_REFUSED);
        });
        let acquired = acquire();
        if !PROMPT.claim() {
            // The prompt watchdog is exiting.
            loop {
                std::thread::park();
            }
        }
        match acquired {
            Ok(approved) => approved,
            Err(code) => {
                refused(code);
                eprintln!("{code}");
                std::process::exit(EXIT_AUTHORIZATION_REFUSED);
            }
        }
    }

    /// Ask for the administrator's approval of one identity change
    /// (`identity_import::authorization`, v30: a password-only prompt that
    /// names `change`, then the proof for the provider). The system prompt
    /// is bounded by `PROMPT_TIMEOUT_SECS`; nothing has been sent when it is
    /// refused, cancelled or unanswered. `refused_line` is printed first on
    /// stdout (`--import`'s not-sent line). Exit `EXIT_AUTHORIZATION_REFUSED`.
    fn authorize_or_exit(
        refused_line: Option<&'static str>,
        change: &aegis_network_extension::identity_import::authorization::IdentityChange,
    ) -> aegis_network_extension::identity_import::authorization::IdentityApproval {
        use aegis_network_extension::identity_import::authorization::{
            approve_identity_change, PROMPT_TIMEOUT_SECS,
        };
        eprintln!(
            "administrator approval required for this identity change; answer the system prompt (at most {PROMPT_TIMEOUT_SECS}s)"
        );
        prompt_or_exit(
            "identity_authorization_timeout",
            move |_| {
                if let Some(line) = refused_line {
                    println!("{line}");
                }
            },
            || approve_identity_change(change),
        )
    }

    /// v26: `--disable-filter` and `--remove-filter` weaken the leak guard,
    /// so an administrator approves each at the system prompt
    /// (`approve_filter_weakening`, its own right) before NEFilterManager is
    /// touched. Refused: one `filter_result=authorization_refused
    /// exit_code=67` line, the code on stderr, nothing changed.
    fn approve_filter_or_exit() {
        use aegis_network_extension::{
            host_lifecycle::FilterOutcome,
            identity_import::authorization::{approve_filter_weakening, PROMPT_TIMEOUT_SECS},
        };
        eprintln!(
            "administrator approval required for this leak-guard change; answer the system prompt (at most {PROMPT_TIMEOUT_SECS}s)"
        );
        prompt_or_exit(
            "filter_authorization_timeout",
            |code| {
                println!(
                    "{} filter_changed=false",
                    FilterOutcome::AuthorizationRefused(code).prefix()
                )
            },
            approve_filter_weakening,
        )
    }

    /// `--import DIR [--remove-source]` (S15): admit `DIR` (canonical, 0700,
    /// the caller's, no link, only import members), send it in one bounded
    /// request and compare the provider's committed manifest with every
    /// sent path, length and digest (the provider-rewritten bridge
    /// sidecar: presence only). Only an exact match, and only with
    /// `--remove-source`, removes `DIR`. An administrator approves the
    /// import at the system prompt before it is sent (67 without it). One
    /// stdout line of codes and counts; exit codes in `host_lifecycle` (0,
    /// 65, 66, 67, 69, 73, 74, 75, 76, 77).
    fn run_import(dir: &std::path::Path, remove_source: bool) -> ! {
        use aegis_network_extension::{
            host_import::{
                conclude_import, record_import_attempt, SourceTree, JOURNAL_REFUSED,
                JOURNAL_REFUSED_LINE, SOURCE_REFUSED_LINE, TIMEOUT_LINE,
            },
            host_lifecycle::EXIT_IMPORT_SOURCE_REFUSED,
            provider_xpc::query_provider_import,
        };
        let source = match SourceTree::open(dir) {
            Ok(source) => source,
            Err(code) => {
                println!("{SOURCE_REFUSED_LINE}");
                eprintln!("{code}");
                std::process::exit(EXIT_IMPORT_SOURCE_REFUSED);
            }
        };
        // Recorded before anything is sent: an uninstall resume marker
        // written earlier no longer stands once key material may be back.
        let home = std::env::var_os("HOME").filter(|home| std::path::Path::new(home).is_absolute());
        if home.is_none_or(|home| record_import_attempt(std::path::Path::new(&home)).is_err()) {
            println!("{JOURNAL_REFUSED_LINE}");
            eprintln!("{JOURNAL_REFUSED}");
            std::process::exit(EXIT_IMPORT_SOURCE_REFUSED);
        }
        // Nothing has been sent if the administrator does not approve.
        let change =
            aegis_network_extension::identity_import::authorization::IdentityChange::import_of(dir);
        let approval = authorize_or_exit(Some(SOURCE_REFUSED_LINE), &change);
        start_xpc_watchdog(Some(TIMEOUT_LINE));
        let reply = query_provider_import(source.payload(), approval);
        // Claimed before any removal: a reply after the deadline removes
        // nothing, and the watchdog cannot exit during a removal.
        claim_result();
        let outcome = conclude_import(&source, reply, remove_source);
        println!("{}", outcome.stdout);
        if let Some(code) = &outcome.stderr {
            eprintln!("{code}");
        }
        std::process::exit(outcome.exit);
    }

    /// v45: one bounded provider query (10 s) for the join's precheck.
    fn bounded_query(
        verb: aegis_network_extension::provider_xpc::Verb,
    ) -> Result<aegis_network_extension::provider_xpc::Reply, (i32, &'static str)> {
        use aegis_network_extension::{
            host_lifecycle::{xpc_error_exit, EXIT_XPC_REFUSED, EXIT_XPC_TIMEOUT},
            provider_xpc::{query_provider, Reply},
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(query_provider(verb));
        });
        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(Reply::Refused(_))) => Err((EXIT_XPC_REFUSED, "provider_refused")),
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(code)) => Err((xpc_error_exit(code), code)),
            Err(_) => Err((EXIT_XPC_TIMEOUT, "xpc_timeout")),
        }
    }

    /// v45: what the provider says before a join: identity presence, the
    /// session phase and, when it answers, the certificate's state.
    fn provider_view() -> Result<
        aegis_network_extension::host_enroll::ProviderView,
        aegis_network_extension::host_enroll::Failure,
    > {
        use aegis_network_extension::{
            host_enroll::{Failure, ProviderView},
            provider_xpc::{Reply, Verb},
        };
        let provider = |(exit, code)| Failure::Provider(exit, code);
        let identity_present = match bounded_query(Verb::Ping).map_err(provider)? {
            Reply::Ping(ping) => ping.identity_present,
            _ => return Err(Failure::Provider(65, "reply_verb_mismatch")),
        };
        let (session_phase, session_refusal) =
            match bounded_query(Verb::Status).map_err(provider)? {
                Reply::Status(status) => (status.session_phase, status.session_refusal),
                _ => return Err(Failure::Provider(65, "reply_verb_mismatch")),
            };
        let (cert_state, not_after) = match bounded_query(Verb::CertStatus) {
            Ok(Reply::CertStatus(report)) => (Some(report.state), report.not_after),
            _ => (None, None),
        };
        Ok(ProviderView {
            identity_present,
            session_phase,
            session_refusal,
            cert_state,
            not_after,
        })
    }

    /// v45 `--enroll FILE [--remove-source] [--replace-identity]`
    /// (`host_enroll`): admit the package, ask the provider, stage and
    /// redeem the invitation in a private staging tree, then import that
    /// tree exactly as `--import DIR --remove-source` does (administrator
    /// prompt, one bounded request, exact manifest check, staging removed
    /// only on an exact commit). With `--remove-source` the package file
    /// goes after a commit. One `enroll_result=` stdout line; progress
    /// (`enroll_progress=`) and at most one code on stderr; exit codes in
    /// `host_lifecycle` (0, 40-46, 65-77).
    fn run_enroll(path: &std::path::Path, remove_source: bool, replace_identity: bool) -> ! {
        use aegis_network_extension::{
            host_enroll::{self, Failure, APPROVAL_REFUSED_LINE, IMPORT_UNKNOWN_LINE, PROGRESS},
            host_import::{conclude_import, record_import_attempt, SourceTree, JOURNAL_REFUSED},
            host_lifecycle::EXIT_IMPORT_SOURCE_REFUSED,
            identity_import::authorization::IdentityChange,
            invite_package::{read_package, remove_package},
            menu_l10n::{self, Lang},
            provider_xpc::query_provider_import,
        };
        fn fail(failure: Failure) -> ! {
            println!("{}", failure.line());
            eprintln!("{}", failure.code());
            std::process::exit(failure.exit());
        }
        let progress = |step: &str| eprintln!("{PROGRESS}{step}");
        let (package, source) =
            read_package(path).unwrap_or_else(|code| fail(Failure::Package(code)));
        progress("checking");
        let view = provider_view().unwrap_or_else(|failure| fail(failure));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if let Err(failure) = host_enroll::precheck(&view, replace_identity, now) {
            fail(failure);
        }
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .filter(|home| home.is_absolute())
            .unwrap_or_else(|| fail(Failure::Local("enroll_home_unset")));
        let root = host_enroll::staging_root(&home).unwrap_or_else(|failure| fail(failure));
        let staged = host_enroll::stage(&package, &root, &mut |step| progress(step))
            .unwrap_or_else(|failure| fail(failure));
        let not_sent = |code: &str| -> ! {
            println!(
                "enroll_result=failed stage=import redeem={} import=not_sent staging=kept invite=kept",
                staged.redeemed.token()
            );
            eprintln!("{code}");
            std::process::exit(EXIT_IMPORT_SOURCE_REFUSED);
        };
        let tree = SourceTree::open(&staged.dir).unwrap_or_else(|code| not_sent(code));
        // What is sent is exactly this package's issued identity.
        if let Err(code) = host_enroll::admit_payload(&package, &staged, tree.payload()) {
            not_sent(code);
        }
        // Recorded before anything is sent, as `--import` does.
        if record_import_attempt(&home).is_err() {
            not_sent(JOURNAL_REFUSED);
        }
        progress("approving");
        let change = IdentityChange::join_of(
            package.device_id(),
            menu_l10n::system() == Lang::Ru,
            view.identity_present,
        );
        let approval = authorize_or_exit(Some(APPROVAL_REFUSED_LINE), &change);
        progress("importing");
        start_xpc_watchdog(Some(IMPORT_UNKNOWN_LINE));
        let reply = query_provider_import(tree.payload(), approval);
        // Claimed before any removal, as `--import` does.
        claim_result();
        let outcome = conclude_import(&tree, reply, true);
        drop(tree);
        if host_enroll::import_committed(&outcome) {
            // Other joins that never got a certificate are moot now.
            host_enroll::sweep_unissued(&root);
        }
        let invite = if host_enroll::import_committed(&outcome) && remove_source {
            match remove_package(path, &source) {
                Ok(()) => "removed",
                Err(_) => "remove_failed",
            }
        } else {
            "kept"
        };
        drop(package);
        println!(
            "{}",
            host_enroll::import_line(staged.redeemed, &outcome, invite)
        );
        if let Some(code) = &outcome.stderr {
            eprintln!("{code}");
        } else if invite == "remove_failed" {
            eprintln!("invite_not_removed");
        }
        std::process::exit(outcome.exit);
    }

    fn start_xpc_watchdog(stdout_line: Option<&'static str>) {
        use aegis_network_extension::host_lifecycle::EXIT_XPC_TIMEOUT;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(10));
            if !RESULT.claim() {
                return;
            }
            if let Some(line) = stdout_line {
                println!("{line}");
            }
            eprintln!("xpc_timeout");
            std::process::exit(EXIT_XPC_TIMEOUT);
        });
    }

    fn finish_xpc(reply: Result<aegis_network_extension::provider_xpc::Reply, &'static str>) -> ! {
        use aegis_network_extension::{
            host_lifecycle::{xpc_error_exit, xpc_reply_exit, EXIT_XPC_REFUSED},
            provider_xpc::{encode_reply, Reply},
        };
        claim_result();
        match reply {
            Ok(Reply::Refused(code)) => {
                eprintln!("provider_refused {code}");
                std::process::exit(EXIT_XPC_REFUSED);
            }
            Ok(reply) => match encode_reply(&reply) {
                Ok(bytes) => {
                    println!("{}", String::from_utf8_lossy(&bytes));
                    // v30: the identity gate's summary line, and what
                    // closes it on stderr.
                    if let Reply::IdentityGate(report) = &reply {
                        println!("{}", report.line());
                        if let Some(blocker) = report.blocker() {
                            eprintln!("identity_gate_closed {blocker}");
                        }
                    }
                    std::process::exit(xpc_reply_exit(&reply));
                }
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(EXIT_XPC_REFUSED);
                }
            },
            Err(code) => {
                eprintln!("{code}");
                std::process::exit(xpc_error_exit(code));
            }
        }
    }

    /// S20b: the filter verbs' watchdog. A dispatched save or removal whose
    /// result did not arrive in time is unknown, never success.
    fn filter_watchdog(operation: &aegis_network_extension::manager::Operation) {
        use aegis_network_extension::host_lifecycle::FilterOutcome;
        let owner = operation.clone();
        std::thread::spawn(move || {
            std::thread::sleep(owner.remaining());
            owner.cancel();
            if !RESULT.claim() {
                return;
            }
            println!("{} result=unknown", FilterOutcome::Timeout.prefix());
            eprintln!("filter operation expired; pending result unknown");
            std::process::exit(FilterOutcome::Timeout.exit());
        });
    }

    /// The one `filter_result=` stdout line (and, for `--filter-status`, the
    /// provider's decoded reply on a second line) and the outcome's exit.
    fn finish_filter(
        outcome: aegis_network_extension::host_lifecycle::FilterOutcome,
        fields: &str,
        reply: Option<String>,
    ) -> ! {
        claim_result();
        println!("{} {fields}", outcome.prefix());
        if let Some(reply) = reply {
            println!("{reply}");
        }
        if let Some(detail) = outcome.detail() {
            eprintln!("{detail}");
        }
        std::process::exit(outcome.exit());
    }

    /// The provider's `filter-status`, bounded like any XPC verb (10 s and
    /// never past the verb's own deadline).
    fn filter_attachment(
        operation: &aegis_network_extension::manager::Operation,
    ) -> aegis_network_extension::host_lifecycle::FilterAttachment {
        use aegis_network_extension::{
            host_lifecycle::{xpc_error_exit, FilterAttachment, EXIT_XPC_REFUSED},
            provider_xpc::{query_provider, Reply, Verb},
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(query_provider(Verb::FilterStatus));
        });
        match receiver.recv_timeout(Duration::from_secs(10).min(operation.remaining())) {
            Ok(Ok(Reply::FilterStatus(report))) => FilterAttachment::Report(report),
            Ok(Ok(Reply::Refused(code))) => FilterAttachment::Refused(code),
            Ok(Ok(_)) => FilterAttachment::Refused("reply_verb_mismatch".into()),
            Ok(Err(code)) if xpc_error_exit(code) == EXIT_XPC_REFUSED => {
                FilterAttachment::Refused(code.into())
            }
            Ok(Err(code)) => FilterAttachment::Unavailable(code),
            Err(_) => FilterAttachment::Unavailable("xpc_timeout"),
        }
    }

    /// S20b `--filter-status`, `--enable-filter`, `--disable-filter` and
    /// `--remove-filter`: one bounded NEFilterManager operation (30 s; 120 s
    /// for an enable, which may wait for the user's answer to macOS's
    /// "would like to filter network content" alert). Exit codes and the
    /// result line are in `host_lifecycle` (`FilterOutcome`).
    fn run_filter(command: HostCommand) -> ! {
        use aegis_network_extension::{
            filter_manager::{disable_filter, enable_filter, read_filter, remove_filter},
            host_lifecycle::{
                attachment_fields, disable_outcome, enable_outcome, filter_failure, remove_outcome,
                status_outcome, FilterAttachment, FilterOutcome, FILTER_ENABLE_SECS,
                FILTER_VERB_SECS,
            },
            manager::Operation,
            provider_xpc::{encode_reply, Reply},
        };
        use std::sync::Arc;
        // v26: before the verb's own bound starts, so the prompt's wait
        // never eats into the NEFilterManager operation.
        if aegis_network_extension::host_lifecycle::filter_requires_authorization(&command) {
            approve_filter_or_exit();
        }
        let budget = if command == HostCommand::EnableFilter {
            FILTER_ENABLE_SECS
        } else {
            FILTER_VERB_SECS
        };
        let operation = Operation::with_budget(Duration::from_secs(budget));
        filter_watchdog(&operation);
        match command {
            HostCommand::FilterStatus => {
                let bound = operation.clone();
                read_filter(
                    operation,
                    Arc::new(move |result| match result {
                        Ok(readback) => {
                            // The provider is asked only about an exact,
                            // enabled configuration.
                            let attachment = (enable_outcome(&readback) == FilterOutcome::Ok)
                                .then(|| filter_attachment(&bound));
                            let outcome = attachment.as_ref().map_or_else(
                                || enable_outcome(&readback),
                                |a| status_outcome(&readback, a),
                            );
                            let reply = match &attachment {
                                Some(FilterAttachment::Report(report)) => {
                                    encode_reply(&Reply::FilterStatus(report.clone()))
                                        .ok()
                                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                                }
                                _ => None,
                            };
                            let fields = format!(
                                "{} {}",
                                readback.fields(),
                                attachment_fields(attachment.as_ref())
                            );
                            finish_filter(outcome, &fields, reply)
                        }
                        Err(code) => {
                            finish_filter(filter_failure(code), "configured=unknown", None)
                        }
                    }),
                );
            }
            HostCommand::EnableFilter => enable_filter(
                operation,
                Arc::new(|result| match result {
                    Ok(readback) => {
                        finish_filter(enable_outcome(&readback), &readback.fields(), None)
                    }
                    Err(code) => finish_filter(filter_failure(code), "filter_saved=unknown", None),
                }),
            ),
            HostCommand::DisableFilter => disable_filter(
                operation,
                Arc::new(|result| match result {
                    Ok(readback) => {
                        finish_filter(disable_outcome(&readback), &readback.fields(), None)
                    }
                    Err(code) => finish_filter(filter_failure(code), "filter_saved=unknown", None),
                }),
            ),
            HostCommand::RemoveFilter => remove_filter(
                operation,
                Arc::new(|result| match result {
                    Ok((found, after)) => finish_filter(
                        remove_outcome(&after),
                        &format!(
                            "filter_found={} filter_remaining={}",
                            u8::from(found),
                            u8::from(after.configured)
                        ),
                        None,
                    ),
                    Err(code) => {
                        finish_filter(filter_failure(code), "filter_removed=unknown", None)
                    }
                }),
            ),
            _ => unreachable!("only filter verbs reach this path"),
        }
        run_profile_loop();
    }

    /// Explicit user-operated activation request for this provider only. The
    /// run loop stops on the finish or failure callback and the host gives up
    /// after `ACTIVATION_TIMEOUT_SECS`. Exit codes are in `host_lifecycle`.
    fn run_activation() -> ! {
        use aegis_network_extension::configuration::PROVIDER_ID;
        if objc2::MainThreadMarker::new().is_none() {
            eprintln!("main_thread_required");
            std::process::exit(EXIT_USAGE);
        }
        *activation() = Some(ActivationTracker::default());
        let id = NSString::from_str(PROVIDER_ID);
        // The request's delegate is weak; both stay alive until exit.
        let delegate: Retained<ApprovalDelegate> =
            unsafe { msg_send![ApprovalDelegate::alloc(), init] };
        let request = unsafe {
            OSSystemExtensionRequest::activationRequestForExtension_queue(
                &id,
                dispatch2::DispatchQueue::main(),
            )
        };
        unsafe {
            request.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            OSSystemExtensionManager::sharedManager().submitRequest(&request);
        }
        wait_for_request(
            ACTIVATION_TIMEOUT_SECS,
            || activation().as_ref().is_some_and(|t| t.outcome().is_some()),
            || {
                if let Some(t) = activation().as_mut() {
                    t.timed_out();
                }
            },
        );
        let (line, code) = {
            let guard = activation();
            let t = guard.as_ref().expect("activation tracker installed");
            (t.report_line(), t.exit_code())
        };
        println!("{line}");
        drop((delegate, request));
        std::process::exit(code);
    }

    /// Runs the main run loop in slices until the request settles or
    /// `timeout_secs` pass; on expiry `expire` settles it as a timeout.
    fn wait_for_request(timeout_secs: u64, settled: impl Fn() -> bool, expire: impl Fn()) {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if settled() {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                expire();
                break;
            }
            let slice = remaining.min(Duration::from_secs(1)).as_secs_f64();
            if unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, slice, 0) } == RUN_LOOP_FINISHED {
                // The main run loop services the main queue, so an empty mode
                // is unexpected; wait out the slice instead of spinning.
                std::thread::sleep(Duration::from_secs_f64(slice));
            }
        }
    }

    /// S21: explicit user-operated deactivation request for this provider
    /// only, bounded like an activation (`DEACTIVATION_TIMEOUT_SECS`). The
    /// run loop stops on the finish or failure callback. One
    /// `deactivation_result=` stdout line; exit codes in `host_lifecycle`.
    fn run_deactivation() -> ! {
        use aegis_network_extension::configuration::PROVIDER_ID;
        if objc2::MainThreadMarker::new().is_none() {
            eprintln!("main_thread_required");
            std::process::exit(EXIT_USAGE);
        }
        *deactivation() = Some(DeactivationTracker::default());
        let id = NSString::from_str(PROVIDER_ID);
        // The request's delegate is weak; both stay alive until exit.
        let delegate: Retained<ApprovalDelegate> =
            unsafe { msg_send![ApprovalDelegate::alloc(), init] };
        let request = unsafe {
            OSSystemExtensionRequest::deactivationRequestForExtension_queue(
                &id,
                dispatch2::DispatchQueue::main(),
            )
        };
        unsafe {
            request.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            OSSystemExtensionManager::sharedManager().submitRequest(&request);
        }
        wait_for_request(
            DEACTIVATION_TIMEOUT_SECS,
            || {
                deactivation()
                    .as_ref()
                    .is_some_and(|t| t.outcome().is_some())
            },
            || {
                if let Some(t) = deactivation().as_mut() {
                    t.timed_out();
                }
            },
        );
        let (line, code) = {
            let guard = deactivation();
            let t = guard.as_ref().expect("deactivation tracker installed");
            (t.report_line(), t.exit_code())
        };
        println!("{line}");
        drop((delegate, request));
        std::process::exit(code);
    }

    pub fn run() {
        let args: Vec<_> = std::env::args().collect();
        // v39: opened from Finder (no verb, not a terminal) it is the
        // menu-bar app, which runs these same verbs as children. A terminal
        // start without a verb keeps the usage error below.
        let stdin_is_terminal = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
        if aegis_network_extension::menu_model::launched_as_app(&args, stdin_is_terminal) {
            crate::menu_app::run();
        }
        let command = match parse_host_args(&args) {
            Ok(command) => command,
            Err(code) => {
                eprintln!("{code}\n{USAGE}");
                std::process::exit(EXIT_USAGE);
            }
        };
        match command {
            HostCommand::Xpc(verb) => run_xpc(verb),
            HostCommand::Import { dir, remove_source } => run_import(&dir, remove_source),
            HostCommand::Enroll {
                path,
                remove_source,
                replace_identity,
            } => run_enroll(&path, remove_source, replace_identity),
            HostCommand::RequestActivation => run_activation(),
            HostCommand::Deactivate => run_deactivation(),
            HostCommand::List => run_list(),
            HostCommand::RemoveProfile => run_remove(),
            HostCommand::EmergencyStop => run_emergency_stop(),
            command @ (HostCommand::FilterStatus
            | HostCommand::EnableFilter
            | HostCommand::DisableFilter
            | HostCommand::RemoveFilter) => run_filter(command),
            command @ (HostCommand::SaveProfile { .. } | HostCommand::Owned { .. }) => {
                run_save_or_owned(command)
            }
        }
    }
}
#[cfg(target_os = "macos")]
fn main() {
    native::run();
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS containing app requires macOS");
    std::process::exit(2);
}
