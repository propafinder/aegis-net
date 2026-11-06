use super::*;
use sha2::{Digest, Sha256};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const CHILD: &str = "AEGIS_FORENSIC_BUILD_TEST_CHILD";
const ROOT: &str = "AEGIS_FORENSIC_BUILD_TEST_ROOT";
const TEST_NAME: &str = "runtime_event_stream::forensic_build_tests::compiled_forensic_sink_ignores_explicit_path_and_preserves_existing_log";

#[tokio::test]
async fn compiled_forensic_sink_ignores_explicit_path_and_preserves_existing_log() {
    if let Some(case) = std::env::var_os(CHILD) {
        let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
        let existing = case == "existing";
        let log = if existing {
            root.join("existing-events.jsonl")
        } else {
            root.join("missing-log-parent/events.jsonl")
        };
        let state = if existing {
            root.join("existing-state.json")
        } else {
            root.join("missing-state-parent/state.json")
        };
        let state_digest = Sha256::digest(state.as_os_str().to_string_lossy().as_bytes());
        let sidecar = state
            .parent()
            .unwrap()
            .join(format!(".{}.seed", hex::encode(&state_digest[..6])));
        let log_bytes = b"existing synthetic log must remain unchanged\n";
        let mut old_state = aegis_core::StateSnapshot::default();
        old_state
            .strategy_stats
            .insert("previous-destination|direct".into(), Default::default());
        let state_bytes = serde_json::to_vec(&old_state).unwrap();
        let sidecar_bytes = b"existing synthetic sidecar must remain unchanged";
        if existing {
            std::fs::write(&log, log_bytes).unwrap();
            std::fs::write(&state, &state_bytes).unwrap();
            std::fs::write(&sidecar, sidecar_bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // A regression that opens the sink would also change its mode.
                std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
        }
        let original_log_permissions =
            existing.then(|| std::fs::metadata(&log).unwrap().permissions());
        set_forensic_redact(false);
        set_private_logs(false);
        assert!(!forensic_redact_enabled());
        assert!(!private_logs_enabled());
        assert!(
            GLOBAL_STREAM.get().is_none(),
            "fresh child must not have a prior global sink"
        );
        // Runtime flags deliberately request diagnostics. The compiled branch
        // itself must prevent an explicit path from constructing the sink.
        init(Some(log.clone())).unwrap();
        assert!(matches!(GLOBAL_STREAM.get(), Some(None)));
        emit(
            "info",
            RuntimeEventCode::BrainSelectOrderExplained,
            "synthetic diagnostic",
            json!({"target":"synthetic.example.invalid"}),
        );
        emit_raw(
            "info",
            "synthetic_forensic_raw",
            "synthetic raw diagnostic",
            json!({"target":"synthetic.example.invalid"}),
        );
        emit_external_calibration_applied(&ExternalCalibrationSnapshot {
            schema_version: 1,
            source: "synthetic_public_calibration".into(),
            ..Default::default()
        });
        emit_knowledge_prior_applied(&ExternalKnowledgePrior {
            target_class: "https_ws".into(),
            region_id: None,
            score: 0.5,
            confidence: 0.5,
            hard_excluded: false,
            fail_closed: false,
            generated_at_unix_ms: None,
        });

        let settings = aegis_core::config_types::DirectSettings {
            state_path: state.clone(),
            persist_state: true,
            ..Default::default()
        };
        // False runtime forensic flag plus explicit Direct consent isolates the
        // compiled forensic_safe decision in the real state-store loader too.
        let store = crate::brain_state::load_runtime(&settings, aegis_core::Mode::Direct, false)
            .await
            .unwrap();
        assert!(store.snapshot().await.strategy_stats.is_empty());
        store
            .update(|snapshot| {
                snapshot
                    .strategy_stats
                    .insert("current-destination|direct".into(), Default::default());
            })
            .await;
        store.flush().await.unwrap();
        if existing {
            assert_eq!(std::fs::read(&log).unwrap(), log_bytes);
            assert_eq!(std::fs::read(&state).unwrap(), state_bytes);
            assert_eq!(std::fs::read(&sidecar).unwrap(), sidecar_bytes);
            let permissions = std::fs::metadata(&log).unwrap().permissions();
            assert_eq!(
                permissions.readonly(),
                original_log_permissions.as_ref().unwrap().readonly()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(permissions.mode(), original_log_permissions.unwrap().mode());
            }
            assert_eq!(
                std::fs::read_dir(&root).unwrap().count(),
                3,
                "no new state/key/log sidecars"
            );
        } else {
            assert!(!log.exists());
            assert!(!state.exists());
            assert!(!sidecar.exists());
            assert_eq!(
                std::fs::read_dir(&root).unwrap().count(),
                0,
                "no new parent directories or sidecars"
            );
        }
        return;
    }

    for case in ["missing", "existing"] {
        let fixture = TempDir::new().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--test-threads=1"])
            .env(CHILD, case)
            .env(ROOT, fixture.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("compiled forensic fixture child timed out: {case}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "compiled forensic child failed ({case}): {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "child must execute the exact compiled fixture"
        );
    }
}
