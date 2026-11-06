//! Read-only service checkpoints. Never reboot, restart a service, or turn a
//! post-boot snapshot into a claim about unobserved early-boot packets.
use super::*;

const FILETIME_TICKS_PER_MILLISECOND: u64 = 10_000;
const SAME_BOOT_TOLERANCE_TICKS: u64 = 5_000 * FILETIME_TICKS_PER_MILLISECOND;

#[derive(Args)]
pub(super) struct RebootArgs {
    #[command(subcommand)]
    command: RebootCommand,
}
#[derive(Subcommand)]
enum RebootCommand {
    Prepare {
        #[arg(long)]
        root: PathBuf,
        /// New private checkpoint directory on the Windows test machine.
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
    },
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Boot {
    boot_ticks: u64,
    machine: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: u32,
    root: PathBuf,
    manifest_sha256: String,
    config_sha256: String,
    service_name: String,
    boot: Boot,
}

fn boot() -> Result<Boot, WinctlError> {
    use windows::{
        core::PWSTR,
        Win32::System::{
            SystemInformation::{GetSystemTimePreciseAsFileTime, GetTickCount64},
            WindowsProgramming::GetComputerNameW,
        },
    };

    // Derive the boot instant entirely through bounded, in-process Win32 calls.
    // Get-CimInstance can block indefinitely while the WMI service is loaded.
    let now = unsafe { GetSystemTimePreciseAsFileTime() };
    let now_ticks = ((now.dwHighDateTime as u64) << 32) | now.dwLowDateTime as u64;
    let uptime_ticks = unsafe { GetTickCount64() }
        .checked_mul(FILETIME_TICKS_PER_MILLISECOND)
        .ok_or_else(|| invalid("boot uptime overflow"))?;
    let boot_ticks = now_ticks
        .checked_sub(uptime_ticks)
        .ok_or_else(|| invalid("boot identity unavailable"))?;

    let mut name = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    unsafe { GetComputerNameW(PWSTR(name.as_mut_ptr()), &mut name_len) }
        .map_err(|_| invalid("computer name unavailable"))?;
    let machine = String::from_utf16(&name[..name_len as usize])
        .map_err(|_| invalid("computer name is not valid UTF-16"))?;
    let result = Boot {
        boot_ticks,
        machine,
    };
    if result.boot_ticks == 0 || result.machine.is_empty() {
        return Err(invalid("boot identity incomplete"));
    }
    Ok(result)
}

fn same_boot(left: &Boot, right: &Boot) -> bool {
    left.machine == right.machine
        && left.boot_ticks.abs_diff(right.boot_ticks) <= SAME_BOOT_TOLERANCE_TICKS
}

fn snapshot(root: &Path) -> Result<(Checkpoint, Value), WinctlError> {
    let receipt = verify_installed(root)?;
    if !receipt.service || !receipt.system_tunnel {
        return Err(invalid(
            "reboot checkpoint requires an installed system-tunnel service",
        ));
    }
    let diagnostic = operator::doctor(root)?;
    let raw =
        aegis_core::secret_file::read_config(&root.join("config/aegis.toml"), 4 * 1024 * 1024)?;
    Ok((
        Checkpoint {
            schema: 1,
            root: root.canonicalize()?,
            manifest_sha256: receipt.manifest_sha256,
            config_sha256: package::hash(&raw),
            service_name: receipt.service_name,
            boot: boot()?,
        },
        diagnostic,
    ))
}

fn compare(before: &Checkpoint, after: &Checkpoint) -> Result<(), WinctlError> {
    if before.schema != 1
        || before.root != after.root
        || before.manifest_sha256 != after.manifest_sha256
        || before.config_sha256 != after.config_sha256
        || before.service_name != after.service_name
        || before.boot.machine != after.boot.machine
    {
        return Err(invalid(
            "checkpoint machine, installation or configuration changed",
        ));
    }
    if same_boot(&before.boot, &after.boot)
        || after.boot.boot_ticks
            <= before
                .boot
                .boot_ticks
                .saturating_add(SAME_BOOT_TOLERANCE_TICKS)
    {
        return Err(invalid("a later Windows boot has not been observed"));
    }
    Ok(())
}

pub(super) fn run(args: RebootArgs) -> Result<Value, WinctlError> {
    match args.command {
        RebootCommand::Prepare { root, output } => prepare(&root, &output),
        RebootCommand::Verify { root, checkpoint } => verify(&root, &checkpoint),
    }
}
pub(super) fn prepare(root: &Path, output: &Path) -> Result<Value, WinctlError> {
    validate_root(output)?;
    if output.exists() {
        return Err(invalid("checkpoint output already exists"));
    }
    let (record, diagnostic) = snapshot(root)?;
    if diagnostic["service"]["state"] != "RUNNING"
        || diagnostic["tunnel"]["adapter_present"] != true
    {
        return Err(invalid(
            "start the installed tunnel before recording the checkpoint",
        ));
    }
    write_checkpoint(output, &record)?;
    Ok(
        json!({"ok":true,"checkpoint":output,"status":"awaiting_manual_reboot","network_mutated":false,
        "reboot_performed":false,"service":diagnostic["service"],"tunnel":diagnostic["tunnel"]}),
    )
}

fn write_checkpoint(output: &Path, record: &Checkpoint) -> Result<(), WinctlError> {
    windows_file::trusted_system_directory(
        output
            .parent()
            .ok_or_else(|| invalid("checkpoint parent missing"))?,
    )?;
    // Administrator preparation and SYSTEM observation are different accounts.
    // Use the service ACL, not an ACL owned/writable by the preparing user.
    windows_file::create_private_directory(output, true, false)?;
    windows_file::write_private_new(
        &output.join("checkpoint.json"),
        &serde_json::to_vec_pretty(record)?,
        true,
    )?;
    Ok(())
}
pub(super) fn verify(root: &Path, checkpoint: &Path) -> Result<Value, WinctlError> {
    let before = read_checkpoint(checkpoint)?;
    let (after, diagnostic) = snapshot(root)?;
    compare(&before, &after)?;
    let tunnel = &diagnostic["tunnel"];
    let protection = &tunnel["protection"];
    let restored = diagnostic["service"]["state"] == "RUNNING"
        && tunnel["adapter_present"] == true
        && tunnel["full_capture"] == true
        && tunnel["kill_switch_configured"] == true
        && tunnel["system_dns_configured"] == true
        && protection["owned_by_installation"] == true
        && protection["persistent_blocks"] == 4
        && protection["boot_blocks"] == 2
        && protection["live_interface_permits"] == 6
        && protection["disabled_filters"] == 0;
    if !restored {
        return Err(invalid(
            "later boot observed but full tunnel service/protection state is incomplete",
        ));
    }
    Ok(
        json!({"ok":true,"status":"post_boot_service_state_verified","reboot_observed":true,
        "network_mutated":false,"service":diagnostic["service"],"tunnel":tunnel,
        "early_boot_packet_capture_verified":false,"authenticated_relay_egress_verified":false,
        "full_acceptance":false}),
    )
}

fn read_checkpoint(checkpoint: &Path) -> Result<Checkpoint, WinctlError> {
    windows_file::trusted_system_directory(checkpoint)?;
    let raw = aegis_core::secret_file::read_config(&checkpoint.join("checkpoint.json"), 65536)?;
    Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(ticks: u64) -> Checkpoint {
        Checkpoint {
            schema: 1,
            root: PathBuf::from("C:/fixture"),
            manifest_sha256: "a".repeat(64),
            config_sha256: "b".repeat(64),
            service_name: "fixture".into(),
            boot: Boot {
                boot_ticks: ticks,
                machine: "fixture".into(),
            },
        }
    }
    #[test]
    fn same_boot_and_changed_identity_cannot_pass() {
        let later = 10 + SAME_BOOT_TOLERANCE_TICKS + 1;
        assert!(compare(&record(10), &record(10)).is_err());
        assert!(compare(&record(10), &record(9)).is_err());
        assert!(compare(&record(10), &record(later)).is_ok());
        let mut after = record(later);
        after.config_sha256 = "c".repeat(64);
        assert!(compare(&record(10), &after).is_err());
        let mut after = record(later);
        after.boot.machine = "another".into();
        assert!(compare(&record(10), &after).is_err());
        let mut after = record(later);
        after.root = PathBuf::from("C:/another");
        assert!(compare(&record(10), &after).is_err());
    }

    #[test]
    fn boot_estimate_tolerates_only_small_clock_sampling_drift() {
        assert!(same_boot(
            &record(100).boot,
            &record(100 + SAME_BOOT_TOLERANCE_TICKS).boot
        ));
        assert!(!same_boot(
            &record(100).boot,
            &record(101 + SAME_BOOT_TOLERANCE_TICKS).boot
        ));
    }
    #[test]
    fn actual_boot_identity_is_stable_between_queries() {
        assert!(same_boot(&boot().unwrap(), &boot().unwrap()));
    }

    #[test]
    #[ignore = "explicit administrator/SYSTEM cross-account checkpoint fixture; no network mutation"]
    fn checkpoint_cross_account() {
        let output = PathBuf::from(std::env::var_os("AEGIS_TEST_REBOOT_CHECKPOINT").unwrap());
        let role = std::env::var("AEGIS_TEST_REBOOT_ROLE").unwrap();
        let current = windows_file::current_sid().unwrap();
        match role.as_str() {
            "write" => {
                assert_ne!(current, "S-1-5-18", "writer must be a different principal");
                write_checkpoint(&output, &record(10)).unwrap();
            }
            "read" => {
                assert_eq!(current, "S-1-5-18", "reader must actually be SYSTEM");
                let before = read_checkpoint(&output).unwrap();
                assert!(compare(&before, &record(10)).is_err());
                compare(&before, &record(11 + SAME_BOOT_TOLERANCE_TICKS)).unwrap();
                windows_file::trusted_system_directory(&output).unwrap();
            }
            _ => panic!("unknown checkpoint test role"),
        }
    }

    #[test]
    fn checkpoint_rejects_user_writable_parent_before_creation() {
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("checkpoint");
        assert!(write_checkpoint(&output, &record(10)).is_err());
        assert!(!output.exists());
    }
}
