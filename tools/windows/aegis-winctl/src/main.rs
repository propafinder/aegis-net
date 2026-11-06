use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(windows)]
mod install;
#[cfg(any(windows, test))]
mod install_payload;
mod package;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod tunnel;

fn main() {
    let cli = Cli::parse();
    let result = run(cli);
    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        Err(err) => {
            let payload = json!({
                "ok": false,
                "error": err.to_string(),
            });
            eprintln!("{}", serde_json::to_string_pretty(&payload).unwrap());
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Error)]
enum WinctlError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("command failed: {program} {args:?} exit={code:?}")]
    CommandFailed {
        program: String,
        args: Vec<String>,
        code: Option<i32>,
    },
    #[error("artifact validation failed: {0}")]
    ArtifactValidation(String),
}

#[derive(Parser)]
#[command(name = "aegis-winctl")]
#[command(about = "AEGIS Windows Rust-first control plane")]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    Package(package::PackageArgs),
    #[cfg(windows)]
    Client(install::ClientArgs),
    #[cfg(windows)]
    Tunnel(tunnel::TunnelArgs),
    Service(ServiceArgs),
    Wfp(WfpArgs),
    Proof(ProofArgs),
    Artifact(ArtifactArgs),
}

#[derive(Args)]
struct ServiceArgs {
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Subcommand)]
enum ServiceCommand {
    Status(ServiceNameArg),
    Install(ServiceInstallArgs),
    Start(ServiceNameArg),
    Stop(ServiceNameArg),
    Uninstall(ServiceNameArg),
}

#[derive(Args)]
struct ServiceNameArg {
    #[arg(long, default_value = "AegisClient")]
    service_name: String,
}

#[derive(Args)]
struct ServiceInstallArgs {
    #[arg(long, default_value = "AegisClient")]
    service_name: String,
    #[arg(long, default_value = "AEGIS Client")]
    display_name: String,
    #[arg(long)]
    bin_path: String,
    #[arg(long, default_value = "demand")]
    start: String,
    /// Full system tunnel requires LocalSystem and SCM crash recovery.
    #[arg(long)]
    system_tunnel: bool,
}

#[derive(Args)]
struct WfpArgs {
    #[command(subcommand)]
    command: WfpCommand,
}

#[derive(Subcommand)]
enum WfpCommand {
    Status(WfpToolArg),
    Cleanup(WfpToolArg),
    InstallControlledTcp(WfpInstallControlledTcpArgs),
    InstallControlledTcpAllowlist(WfpInstallControlledTcpAllowlistArgs),
    UdpFeasibility,
}

#[derive(Args)]
struct WfpToolArg {
    #[arg(long, default_value = "target/debug/aegis-wfpctl.exe")]
    controller: PathBuf,
}

#[derive(Args)]
struct WfpInstallControlledTcpArgs {
    #[arg(long, default_value = "target/debug/aegis-wfpctl.exe")]
    controller: PathBuf,
    #[arg(long)]
    target_ip: String,
    #[arg(long)]
    target_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    redirect_ip: String,
    #[arg(long, default_value_t = 18080)]
    redirect_port: u16,
    #[arg(long)]
    listener_pid: u32,
}

#[derive(Args)]
struct WfpInstallControlledTcpAllowlistArgs {
    #[arg(long, default_value = "target/debug/aegis-wfpctl.exe")]
    controller: PathBuf,
    #[arg(long = "target", required = true)]
    targets: Vec<String>,
    #[arg(long = "relay-exclusion")]
    relay_exclusions: Vec<String>,
    #[arg(long, default_value_t = 18080)]
    redirect_port: u16,
    #[arg(long)]
    listener_pid: u32,
    #[arg(long)]
    apply: bool,
}

#[derive(Args)]
struct ProofArgs {
    #[command(subcommand)]
    command: ProofCommand,
}

#[derive(Subcommand)]
enum ProofCommand {
    ServiceReboot(ServiceRebootArgs),
    Policy(PolicyArgs),
    TcpAllowlistPlan(TcpAllowlistPlanArgs),
}

#[derive(Args)]
struct ServiceRebootArgs {
    #[command(subcommand)]
    command: ServiceRebootCommand,
}

#[derive(Subcommand)]
enum ServiceRebootCommand {
    Prepare(ServiceRebootCommon),
    VerifyAfterReboot(ServiceRebootCommon),
}

#[derive(Args, Clone)]
struct ServiceRebootCommon {
    #[arg(long)]
    artifact_dir: PathBuf,
    #[arg(long, default_value = "AegisClient")]
    service_name: String,
    #[arg(long, default_value = "api.ipify.org")]
    target_host: String,
    #[arg(long, default_value = "auto")]
    target_scheme: String,
    #[arg(long, default_value_t = 443)]
    target_port: u16,
    #[arg(long, value_parser = parse_expected_relay_egress_ip)]
    expected_relay_egress_ip: String,
    #[arg(long, default_value = "target/debug/aegis-wfpctl.exe")]
    wfp_controller: PathBuf,
    #[arg(long, default_value_t = 18080)]
    redirect_port: u16,
    #[arg(long)]
    relay_egress_log: Option<PathBuf>,
}

#[derive(Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand)]
enum PolicyCommand {
    Dns(PolicyProofArgs),
    Udp(PolicyProofArgs),
    Ipv6(PolicyProofArgs),
}

#[derive(Args, Clone)]
struct PolicyProofArgs {
    #[arg(long)]
    artifact_dir: PathBuf,
}

#[derive(Args, Clone)]
struct TcpAllowlistPlanArgs {
    #[arg(long)]
    artifact_dir: PathBuf,
    #[arg(long = "target", required = true)]
    targets: Vec<String>,
    #[arg(long = "relay-exclusion")]
    relay_exclusions: Vec<String>,
    #[arg(long, default_value_t = 18080)]
    redirect_port: u16,
    #[arg(long)]
    listener_pid: Option<u32>,
}

#[derive(Args)]
struct ArtifactArgs {
    #[command(subcommand)]
    command: ArtifactCommand,
}

#[derive(Subcommand)]
enum ArtifactCommand {
    Validate(ArtifactDirArg),
    WriteResult(WriteResultArgs),
    Redact(RedactArgs),
}

#[derive(Args)]
struct ArtifactDirArg {
    #[arg(long)]
    artifact_dir: PathBuf,
}

#[derive(Args)]
struct WriteResultArgs {
    #[arg(long)]
    artifact_dir: PathBuf,
    #[arg(long)]
    status: String,
    #[arg(long)]
    verdict: String,
    #[arg(long)]
    blocker: Option<String>,
}

#[derive(Args)]
struct RedactArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

fn run(cli: Cli) -> Result<Value, WinctlError> {
    match cli.command {
        TopCommand::Package(args) => package::run(args),
        #[cfg(windows)]
        TopCommand::Client(args) => install::run(args),
        #[cfg(windows)]
        TopCommand::Tunnel(args) => tunnel::run(args),
        TopCommand::Service(args) => run_service(args),
        TopCommand::Wfp(args) => run_wfp(args),
        TopCommand::Proof(args) => run_proof(args),
        TopCommand::Artifact(args) => run_artifact(args),
    }
}

#[cfg(windows)]
fn run_service(args: ServiceArgs) -> Result<Value, WinctlError> {
    service::run(args.command)
}

#[cfg(not(windows))]
fn run_service(args: ServiceArgs) -> Result<Value, WinctlError> {
    match args.command {
        ServiceCommand::Status(arg) => Ok(json!({
            "ok": true,
            "service": query_service(&arg.service_name)?,
        })),
        ServiceCommand::Install(arg) => {
            run_checked(
                "sc.exe",
                &[
                    "create",
                    &arg.service_name,
                    "binPath=",
                    &arg.bin_path,
                    "DisplayName=",
                    &arg.display_name,
                    "start=",
                    &arg.start,
                ],
            )?;
            Ok(json!({"ok": true, "service_name": arg.service_name, "action": "install"}))
        }
        ServiceCommand::Start(arg) => {
            run_checked("sc.exe", &["start", &arg.service_name])?;
            Ok(json!({"ok": true, "service_name": arg.service_name, "action": "start"}))
        }
        ServiceCommand::Stop(arg) => {
            run_checked("sc.exe", &["stop", &arg.service_name])?;
            Ok(json!({"ok": true, "service_name": arg.service_name, "action": "stop"}))
        }
        ServiceCommand::Uninstall(arg) => {
            run_checked("sc.exe", &["delete", &arg.service_name])?;
            Ok(json!({"ok": true, "service_name": arg.service_name, "action": "uninstall"}))
        }
    }
}

fn run_wfp(args: WfpArgs) -> Result<Value, WinctlError> {
    match args.command {
        WfpCommand::Status(arg) => Ok(json!({
            "ok": true,
            "controller": arg.controller,
            "present": arg.controller.exists(),
        })),
        WfpCommand::Cleanup(arg) => {
            if !arg.controller.exists() {
                return Ok(json!({
                    "ok": true,
                    "action": "cleanup",
                    "cleanup": "CONTROLLER_NOT_PRESENT",
                    "controller": arg.controller,
                }));
            }
            let controller = arg.controller.to_string_lossy().to_string();
            run_checked(&controller, &["cleanup"])?;
            Ok(json!({"ok": true, "action": "cleanup", "cleanup": "PASS"}))
        }
        WfpCommand::InstallControlledTcp(arg) => {
            if arg.redirect_ip != "127.0.0.1"
                || arg.redirect_port == 0
                || arg.listener_pid == 0
                || arg.target_port == 0
            {
                return Err(WinctlError::ArtifactValidation(
                    "WFP requires 127.0.0.1, nonzero ports and listener PID".into(),
                ));
            }
            validate_target_ipv4(
                arg.target_ip
                    .parse()
                    .map_err(|_| WinctlError::ArtifactValidation("target must be IPv4".into()))?,
            )?;
            if !arg.controller.exists() {
                return Err(WinctlError::ArtifactValidation(format!(
                    "WFP controller not found: {}",
                    arg.controller.display()
                )));
            }
            let controller = arg.controller.to_string_lossy().to_string();
            let target_port = arg.target_port.to_string();
            let redirect_port = arg.redirect_port.to_string();
            let listener_pid = arg.listener_pid.to_string();
            run_checked(
                &controller,
                &[
                    "install",
                    &arg.target_ip,
                    &target_port,
                    &redirect_port,
                    &listener_pid,
                ],
            )?;
            Ok(json!({
                "ok": true,
                "action": "install-controlled-tcp",
                "target": format!("{}:{}", arg.target_ip, arg.target_port),
                "redirect": format!("{}:{}", arg.redirect_ip, arg.redirect_port),
                "listener_pid": arg.listener_pid,
            }))
        }
        WfpCommand::InstallControlledTcpAllowlist(arg) => {
            let plan = tcp_allowlist_apply_plan(&arg)?;
            if !arg.apply {
                return Ok(json!({
                    "ok": true,
                    "action": "install-controlled-tcp-allowlist",
                    "status": "DRY_RUN_REQUIRES_APPLY",
                    "applies_wfp_state": false,
                    "controller": arg.controller,
                    "redirect_port": arg.redirect_port,
                    "listener_pid": arg.listener_pid,
                    "targets": plan,
                }));
            }
            if !arg.controller.exists() {
                return Err(WinctlError::ArtifactValidation(format!(
                    "WFP controller not found: {}",
                    arg.controller.display()
                )));
            }
            let controller = arg.controller.to_string_lossy().to_string();
            run_checked(&controller, &["cleanup"])?;
            for target in &plan {
                let ip = target["resolved_ipv4"].as_str().unwrap_or_default();
                let port = target["port"].as_u64().unwrap_or_default().to_string();
                let redirect_port = arg.redirect_port.to_string();
                let listener_pid = arg.listener_pid.to_string();
                if let Err(error) = run_checked(
                    &controller,
                    &["install", ip, &port, &redirect_port, &listener_pid],
                ) {
                    // A partially applied list must not be reported as success.
                    // Surface cleanup failure too, so the operator knows state
                    // may remain installed.
                    if let Err(cleanup) = run_checked(&controller, &["cleanup"]) {
                        return Err(WinctlError::ArtifactValidation(format!(
                            "allowlist apply failed: {error}; cleanup failed: {cleanup}"
                        )));
                    }
                    return Err(error);
                }
            }
            Ok(json!({
                "ok": true,
                "action": "install-controlled-tcp-allowlist",
                "status": "APPLIED",
                "applies_wfp_state": true,
                "controller": arg.controller,
                "redirect_port": arg.redirect_port,
                "listener_pid": arg.listener_pid,
                "targets": plan,
            }))
        }
        WfpCommand::UdpFeasibility => Ok(json!({
            "ok": true,
            "feature": "windows_wfp_controlled_dns_udp_next_scope",
            "status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER",
            "verdict": "BLOCKED",
            "blocker": "current AEGIS WFP proof path installs ALE_CONNECT_REDIRECT_V4 with IPPROTO_TCP only; controlled DNS/UDP needs a UDP-capable WFP layer and driver callout changes",
            "wfp_layer_current": "ALE_CONNECT_REDIRECT_V4",
            "wfp_protocol_current": "IPPROTO_TCP",
            "udp_redirect_supported_by_current_code": false,
            "dns_udp_53_redirect_supported_by_current_layer": false,
            "new_wfp_layer_needed": true,
            "callout_driver_needed": true,
            "controlled_target_only": true,
            "controlled_udp_or_dns_captured": false,
            "dns_capture_claimed": false,
            "udp_capture_claimed": false,
            "ipv6_capture_claimed": false,
            "broad_capture_claim": "not_claimed",
            "production_driver_claim": "not_claimed",
        })),
    }
}

fn run_proof(args: ProofArgs) -> Result<Value, WinctlError> {
    match args.command {
        ProofCommand::ServiceReboot(args) => match args.command {
            ServiceRebootCommand::Prepare(common) => service_reboot_prepare(common),
            ServiceRebootCommand::VerifyAfterReboot(common) => service_reboot_verify(common),
        },
        ProofCommand::Policy(args) => run_policy_proof(args),
        ProofCommand::TcpAllowlistPlan(args) => write_tcp_allowlist_plan(args),
    }
}

fn run_policy_proof(args: PolicyArgs) -> Result<Value, WinctlError> {
    match args.command {
        PolicyCommand::Dns(arg) => write_policy_proof(WindowsPolicyLane::Dns, arg),
        PolicyCommand::Udp(arg) => write_policy_proof(WindowsPolicyLane::Udp, arg),
        PolicyCommand::Ipv6(arg) => write_policy_proof(WindowsPolicyLane::Ipv6, arg),
    }
}

fn run_artifact(args: ArtifactArgs) -> Result<Value, WinctlError> {
    match args.command {
        ArtifactCommand::Validate(arg) => validate_artifact(&arg.artifact_dir),
        ArtifactCommand::WriteResult(arg) => {
            fs::create_dir_all(&arg.artifact_dir)?;
            let result = base_result(&ServiceRebootCommon {
                artifact_dir: arg.artifact_dir.clone(),
                service_name: "AegisClient".to_string(),
                target_host: "api.ipify.org".to_string(),
                target_scheme: "auto".to_string(),
                target_port: 443,
                expected_relay_egress_ip: String::new(),
                wfp_controller: PathBuf::from("target/debug/aegis-wfpctl.exe"),
                redirect_port: 18080,
                relay_egress_log: None,
            })
            .with_status(&arg.status)
            .with_verdict(&arg.verdict)
            .with_blocker(arg.blocker.unwrap_or_default());
            write_result_json(&arg.artifact_dir, &result)?;
            Ok(json!({"ok": true, "artifact_dir": arg.artifact_dir, "result": result}))
        }
        ArtifactCommand::Redact(arg) => {
            let input = fs::read_to_string(arg.input)?;
            let redacted = redact_text(&input);
            fs::write(&arg.output, redacted)?;
            Ok(json!({"ok": true, "output": arg.output}))
        }
    }
}

fn service_reboot_prepare(common: ServiceRebootCommon) -> Result<Value, WinctlError> {
    fs::create_dir_all(&common.artifact_dir)?;
    write_commands(&common)?;
    write_environment(&common, "prepare")?;
    if !is_elevated() {
        let result = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::Prepare,
            elevated: false,
            marker_present: false,
            reboot_performed: false,
            service_exists: false,
            service_started_after_reboot: false,
            runtime_events_restarted: false,
            wfp_driver_started_after_reboot: false,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        })
        .to_result(
            &common,
            &ServiceRebootEvidence {
                mode: ServiceRebootMode::Prepare,
                elevated: false,
                marker_present: false,
                reboot_performed: false,
                service_exists: false,
                service_started_after_reboot: false,
                runtime_events_restarted: false,
                wfp_driver_started_after_reboot: false,
                wfp_reconfigured_after_reboot: false,
                controlled_tcp_wfp_proof_after_reboot: false,
                relay_egress_after_reboot: false,
                cleanup: CleanupStatus::NotRun,
            },
        );
        write_result_json(&common.artifact_dir, &result)?;
        write_readme(&common.artifact_dir, &result)?;
        return Ok(json!({"ok": true, "result": result}));
    }

    let service = query_service(&common.service_name).unwrap_or_else(|_| json!({"exists": false}));
    let marker = json!({
        "prepared_at_unix": unix_now(),
        "computer": std::env::var("COMPUTERNAME").unwrap_or_default(),
        "service": service,
        "target_host": common.target_host,
        "target_scheme": normalized_target_scheme(&common).unwrap_or_else(|_| "invalid".to_string()),
        "target_port": common.target_port,
        "expected_relay_egress_ip": common.expected_relay_egress_ip,
        "wfp_controller": common.wfp_controller,
        "redirect_port": common.redirect_port,
    });
    fs::write(
        marker_path(&common.artifact_dir),
        serde_json::to_string_pretty(&marker)?,
    )?;
    fs::write(
        common.artifact_dir.join("manual-reboot-instructions.txt"),
        format!(
            "Manual operator step required:\n1. Reboot this Windows host.\n2. After login/elevation, run:\n   aegis-winctl proof service-reboot verify-after-reboot --artifact-dir {} --service-name {} --target-host {} --target-scheme {} --target-port {} --expected-relay-egress-ip {} --wfp-controller {} --redirect-port {}\nNo reboot is performed automatically.\n",
            common.artifact_dir.display(),
            common.service_name,
            common.target_host,
            common.target_scheme,
            common.target_port,
            common.expected_relay_egress_ip,
            common.wfp_controller.display(),
            common.redirect_port
        ),
    )?;
    let evidence = ServiceRebootEvidence {
        mode: ServiceRebootMode::Prepare,
        elevated: true,
        marker_present: true,
        reboot_performed: false,
        service_exists: service
            .get("exists")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        service_started_after_reboot: false,
        runtime_events_restarted: false,
        wfp_driver_started_after_reboot: false,
        wfp_reconfigured_after_reboot: false,
        controlled_tcp_wfp_proof_after_reboot: false,
        relay_egress_after_reboot: false,
        cleanup: CleanupStatus::NotRun,
    };
    let result = classify_service_reboot(evidence.clone()).to_result(&common, &evidence);
    write_result_json(&common.artifact_dir, &result)?;
    write_readme(&common.artifact_dir, &result)?;
    Ok(json!({"ok": true, "result": result}))
}

fn service_reboot_verify(common: ServiceRebootCommon) -> Result<Value, WinctlError> {
    fs::create_dir_all(&common.artifact_dir)?;
    write_commands(&common)?;
    write_environment(&common, "verify-after-reboot")?;
    if !is_elevated() {
        let result = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::VerifyAfterReboot,
            elevated: false,
            marker_present: marker_path(&common.artifact_dir).exists(),
            reboot_performed: false,
            service_exists: false,
            service_started_after_reboot: false,
            runtime_events_restarted: false,
            wfp_driver_started_after_reboot: false,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        })
        .to_result(
            &common,
            &ServiceRebootEvidence {
                mode: ServiceRebootMode::VerifyAfterReboot,
                elevated: false,
                marker_present: marker_path(&common.artifact_dir).exists(),
                reboot_performed: false,
                service_exists: false,
                service_started_after_reboot: false,
                runtime_events_restarted: false,
                wfp_driver_started_after_reboot: false,
                wfp_reconfigured_after_reboot: false,
                controlled_tcp_wfp_proof_after_reboot: false,
                relay_egress_after_reboot: false,
                cleanup: CleanupStatus::NotRun,
            },
        );
        write_result_json(&common.artifact_dir, &result)?;
        write_readme(&common.artifact_dir, &result)?;
        return Ok(json!({"ok": true, "result": result}));
    }

    let marker_present = marker_path(&common.artifact_dir).exists();
    let mut service =
        query_service(&common.service_name).unwrap_or_else(|_| json!({"exists": false}));
    if service
        .get("exists")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !service
            .get("state")
            .and_then(Value::as_str)
            .is_some_and(|state| state.eq_ignore_ascii_case("RUNNING"))
    {
        let _ = run_checked("sc.exe", &["start", &common.service_name]);
        service = query_service(&common.service_name).unwrap_or_else(|_| json!({"exists": false}));
    }
    fs::write(
        common.artifact_dir.join("service-after-reboot.json"),
        serde_json::to_string_pretty(&service)?,
    )?;
    let service_started = service
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case("RUNNING"));
    let service_exists = service
        .get("exists")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reboot_performed = marker_present && reboot_was_performed(&common.artifact_dir)?;
    let service_pid = service
        .get("process_id")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let wfp_driver_started = start_wfp_driver_after_reboot(&common)?;
    let wfp_reconfigured =
        if service_exists && service_started && service_pid > 0 && wfp_driver_started {
            reconfigure_wfp_after_reboot(&common, service_pid as u32)?
        } else {
            false
        };
    let runtime_events_restarted =
        Path::new(r"C:\ProgramData\AEGIS\state\runtime-events.jsonl").exists();
    let relay_egress_body = if wfp_reconfigured {
        run_relay_egress_probe(&common)?
    } else {
        String::new()
    };
    let relay_egress = relay_egress_body.contains(&common.expected_relay_egress_ip);
    let cleanup = cleanup_wfp(&common);
    let evidence = ServiceRebootEvidence {
        mode: ServiceRebootMode::VerifyAfterReboot,
        elevated: true,
        marker_present,
        reboot_performed,
        service_exists,
        service_started_after_reboot: service_started,
        runtime_events_restarted,
        wfp_driver_started_after_reboot: wfp_driver_started,
        wfp_reconfigured_after_reboot: wfp_reconfigured,
        controlled_tcp_wfp_proof_after_reboot: relay_egress,
        relay_egress_after_reboot: relay_egress,
        cleanup,
    };
    let result = classify_service_reboot(evidence.clone()).to_result(&common, &evidence);
    write_result_json(&common.artifact_dir, &result)?;
    write_readme(&common.artifact_dir, &result)?;
    Ok(json!({"ok": true, "result": result}))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceRebootMode {
    Prepare,
    VerifyAfterReboot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStatus {
    Pass,
    NotRun,
    ControllerNotPresent,
    Warn,
}

#[derive(Clone, Debug)]
struct ServiceRebootEvidence {
    mode: ServiceRebootMode,
    elevated: bool,
    marker_present: bool,
    reboot_performed: bool,
    service_exists: bool,
    service_started_after_reboot: bool,
    runtime_events_restarted: bool,
    wfp_driver_started_after_reboot: bool,
    wfp_reconfigured_after_reboot: bool,
    controlled_tcp_wfp_proof_after_reboot: bool,
    relay_egress_after_reboot: bool,
    cleanup: CleanupStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Classification {
    status: &'static str,
    verdict: &'static str,
    blocker: &'static str,
}

fn classify_service_reboot(evidence: ServiceRebootEvidence) -> Classification {
    if !evidence.elevated {
        return Classification {
            status: "BLOCKED_BY_NON_ELEVATED_TERMINAL",
            verdict: "BLOCKED",
            blocker: "elevated Windows terminal is required",
        };
    }
    match evidence.mode {
        ServiceRebootMode::Prepare => Classification {
            status: "BLOCKED_BY_REBOOT_NOT_PERFORMED",
            verdict: "BLOCKED",
            blocker: "manual reboot required before verify-after-reboot",
        },
        ServiceRebootMode::VerifyAfterReboot => {
            if !evidence.marker_present {
                return Classification {
                    status: "BLOCKED_BY_PREPARE_MARKER_MISSING",
                    verdict: "BLOCKED",
                    blocker: "pre-reboot marker is missing; run prepare before reboot",
                };
            }
            if !evidence.reboot_performed {
                return Classification {
                    status: "BLOCKED_BY_REBOOT_NOT_PERFORMED",
                    verdict: "BLOCKED",
                    blocker: "current boot time is not after the pre-reboot marker",
                };
            }
            if !evidence.service_exists {
                return Classification {
                    status: "BLOCKED_BY_SERVICE_MISSING",
                    verdict: "BLOCKED",
                    blocker: "AegisClient service is not installed",
                };
            }
            if !evidence.service_started_after_reboot {
                return Classification {
                    status: "BLOCKED_BY_SERVICE_START_FAILED",
                    verdict: "BLOCKED",
                    blocker: "AegisClient service is not running after start attempt",
                };
            }
            if !evidence.wfp_driver_started_after_reboot {
                return Classification {
                    status: "BLOCKED_BY_WFP_DRIVER_START_FAILED",
                    verdict: "BLOCKED",
                    blocker: "AegisWfp driver service is not running after start attempt",
                };
            }
            if !evidence.wfp_reconfigured_after_reboot {
                return Classification {
                    status: "BLOCKED_BY_WFP_RECONFIGURE_FAILED",
                    verdict: "BLOCKED",
                    blocker: "WFP was not reconfigured for the post-reboot service PID",
                };
            }
            if !evidence.controlled_tcp_wfp_proof_after_reboot
                || !evidence.relay_egress_after_reboot
            {
                return Classification {
                    status: "BLOCKED_BY_RELAY_EGRESS_FAILED",
                    verdict: "BLOCKED",
                    blocker: "controlled TCP WFP relay egress proof did not pass after reboot",
                };
            }
            if evidence.cleanup != CleanupStatus::Pass {
                return Classification {
                    status: "CLEANUP_FAILED",
                    verdict: "FAIL",
                    blocker: "cleanup did not remove AEGIS-owned proof state cleanly",
                };
            }
            if evidence.service_started_after_reboot
                && evidence.runtime_events_restarted
                && evidence.wfp_reconfigured_after_reboot
                && evidence.controlled_tcp_wfp_proof_after_reboot
                && evidence.relay_egress_after_reboot
                && evidence.cleanup == CleanupStatus::Pass
            {
                Classification {
                    status: "PASS",
                    verdict: "PASS",
                    blocker: "",
                }
            } else {
                Classification {
                    status: "FAIL",
                    verdict: "FAIL",
                    blocker: "post-reboot service/WFP/relay evidence is incomplete",
                }
            }
        }
    }
}

impl Classification {
    fn to_result(
        &self,
        common: &ServiceRebootCommon,
        evidence: &ServiceRebootEvidence,
    ) -> ServiceRebootResult {
        let mut result = base_result(common)
            .with_status(self.status)
            .with_verdict(self.verdict)
            .with_blocker(self.blocker);
        result.fields.insert(
            "mode".to_string(),
            json!(match evidence.mode {
                ServiceRebootMode::Prepare => "prepare",
                ServiceRebootMode::VerifyAfterReboot => "verify-after-reboot",
            }),
        );
        result
            .fields
            .insert("administrator_shell".to_string(), json!(evidence.elevated));
        result.fields.insert(
            "prepare_marker_present".to_string(),
            json!(evidence.marker_present),
        );
        result.fields.insert(
            "reboot_verified".to_string(),
            json!(evidence.marker_present && evidence.reboot_performed),
        );
        result
            .fields
            .insert("service_exists".to_string(), json!(evidence.service_exists));
        result.fields.insert(
            "service_started_after_reboot".to_string(),
            json!(evidence.service_started_after_reboot),
        );
        result.fields.insert(
            "runtime_events_restarted".to_string(),
            json!(evidence.runtime_events_restarted),
        );
        result.fields.insert(
            "wfp_driver_started_after_reboot".to_string(),
            json!(evidence.wfp_driver_started_after_reboot),
        );
        result.fields.insert(
            "wfp_reconfigured_after_reboot".to_string(),
            json!(evidence.wfp_reconfigured_after_reboot),
        );
        result.fields.insert(
            "controlled_tcp_wfp_proof_after_reboot".to_string(),
            json!(evidence.controlled_tcp_wfp_proof_after_reboot),
        );
        result.fields.insert(
            "relay_egress_after_reboot".to_string(),
            json!(evidence.relay_egress_after_reboot),
        );
        result.fields.insert(
            "cleanup".to_string(),
            json!(match evidence.cleanup {
                CleanupStatus::Pass => "PASS",
                CleanupStatus::NotRun => "NOT_RUN",
                CleanupStatus::ControllerNotPresent => "CONTROLLER_NOT_PRESENT",
                CleanupStatus::Warn => "WARN",
            }),
        );
        result
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PolicyProofResult {
    schema_version: u8,
    feature: String,
    platform: String,
    scope: String,
    status: String,
    verdict: String,
    blocker: String,
    broad_capture_claim: String,
    dns_capture_claim: String,
    udp_capture_claim: String,
    ipv6_capture_claim: String,
    production_driver_claim: String,
    policy_lane: String,
    policy: String,
    current_wfp_layer: String,
    current_wfp_protocol: String,
    capture_supported_by_current_code: bool,
    leak_prevention_proven: bool,
    live_capture_artifact_claimed: bool,
    next_required_proof: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsPolicyLane {
    Dns,
    Udp,
    Ipv6,
}

impl WindowsPolicyLane {
    fn code(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Udp => "udp",
            Self::Ipv6 => "ipv6",
        }
    }

    fn feature(self) -> &'static str {
        match self {
            Self::Dns => "windows_wide_dns_policy_proof",
            Self::Udp => "windows_wide_udp_policy_proof",
            Self::Ipv6 => "windows_wide_ipv6_policy_proof",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Dns => "controlled_wfp_tcp_dns_boundary",
            Self::Udp => "controlled_wfp_tcp_udp_boundary",
            Self::Ipv6 => "controlled_wfp_ipv4_tcp_ipv6_boundary",
        }
    }

    fn blocker(self) -> &'static str {
        match self {
            Self::Dns => "current AEGIS Windows WFP proof path redirects IPv4 TCP ALE connect flows only; DNS UDP/53 capture or fail-closed DNS blocking requires a separate UDP/DNS WFP policy proof",
            Self::Udp => "current AEGIS Windows WFP proof path redirects IPv4 TCP ALE connect flows only; UDP capture requires a UDP-capable WFP layer and driver/control-plane changes",
            Self::Ipv6 => "current AEGIS Windows WFP proof path is controlled IPv4 TCP only; IPv6 capture or fail-closed IPv6 blocking requires a separate IPv6 policy proof",
        }
    }

    fn next_required_proof(self) -> &'static str {
        match self {
            Self::Dns => "add a Windows DNS policy proof that either captures DNS through an explicit UDP/DNS WFP path or proves fail-closed DNS blocking while controlled TCP WFP is active",
            Self::Udp => "add a Windows UDP policy proof that either captures a controlled UDP target or proves explicit UDP blocking while controlled TCP WFP is active",
            Self::Ipv6 => "add a Windows IPv6 policy proof that either captures controlled IPv6 TCP or proves explicit IPv6 blocking while controlled TCP WFP is active",
        }
    }
}

fn policy_proof_result(lane: WindowsPolicyLane) -> PolicyProofResult {
    PolicyProofResult {
        schema_version: 1,
        feature: lane.feature().to_string(),
        platform: "Windows".to_string(),
        scope: lane.scope().to_string(),
        status: "POLICY_NOT_CLAIMED_BY_CURRENT_TCP_MVP".to_string(),
        verdict: "PARTIAL".to_string(),
        blocker: lane.blocker().to_string(),
        broad_capture_claim: "not_claimed".to_string(),
        dns_capture_claim: "not_claimed".to_string(),
        udp_capture_claim: "not_claimed".to_string(),
        ipv6_capture_claim: "not_claimed".to_string(),
        production_driver_claim: "not_claimed".to_string(),
        policy_lane: lane.code().to_string(),
        policy: "not_claimed".to_string(),
        current_wfp_layer: "ALE_CONNECT_REDIRECT_V4".to_string(),
        current_wfp_protocol: "IPPROTO_TCP".to_string(),
        capture_supported_by_current_code: false,
        leak_prevention_proven: false,
        live_capture_artifact_claimed: false,
        next_required_proof: lane.next_required_proof().to_string(),
    }
}

fn write_policy_proof(
    lane: WindowsPolicyLane,
    args: PolicyProofArgs,
) -> Result<Value, WinctlError> {
    fs::create_dir_all(&args.artifact_dir)?;
    let result = policy_proof_result(lane);
    fs::write(
        args.artifact_dir.join("result.json"),
        serde_json::to_string_pretty(&result)? + "\n",
    )?;
    fs::write(
        args.artifact_dir.join("README.md"),
        format!(
            "# Windows Wide {} Policy Proof\n\nVerdict: `{}`\n\nStatus: `{}`\n\nThis artifact records an explicit policy boundary for the current controlled Windows WFP TCP MVP. It does not claim broad Windows wide, {}, production driver readiness, or leak prevention.\n",
            lane.code().to_ascii_uppercase(),
            result.verdict,
            result.status,
            lane_claim_phrase(lane)
        ),
    )?;
    fs::write(
        args.artifact_dir.join("commands.txt"),
        format!(
            "aegis-winctl proof policy {} --artifact-dir {}\n",
            lane.code(),
            args.artifact_dir.display()
        ),
    )?;
    fs::write(
        args.artifact_dir.join("environment.txt"),
        format!(
            "timestamp_unix={}\ncomputer={}\nuser={}\npolicy_lane={}\nadministrator_shell={}\nartifact={}\n",
            unix_now(),
            std::env::var("COMPUTERNAME").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default(),
            lane.code(),
            is_elevated(),
            args.artifact_dir.display()
        ),
    )?;
    Ok(json!({
        "ok": true,
        "artifact_dir": args.artifact_dir,
        "result": result,
    }))
}

fn lane_claim_phrase(lane: WindowsPolicyLane) -> &'static str {
    match lane {
        WindowsPolicyLane::Dns => "DNS capture",
        WindowsPolicyLane::Udp => "UDP capture",
        WindowsPolicyLane::Ipv6 => "IPv6 capture",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TcpAllowlistPlanResult {
    schema_version: u8,
    feature: String,
    platform: String,
    scope: String,
    status: String,
    verdict: String,
    blocker: String,
    broad_capture_claim: String,
    dns_capture_claim: String,
    udp_capture_claim: String,
    ipv6_capture_claim: String,
    production_driver_claim: String,
    target_count: usize,
    targets: Vec<TcpAllowlistEntry>,
    relay_exclusions: Vec<TcpAllowlistEntry>,
    redirect_port: u16,
    listener_pid: Option<u32>,
    applies_wfp_state: bool,
    cleanup_required_before_apply: bool,
    current_controller_limit: String,
    current_driver_config_model: String,
    multi_filter_driver_change_required: bool,
    multi_target_apply_implemented: bool,
    multi_target_apply_live_proven: bool,
    next_required_proof: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct TcpAllowlistEntry {
    host: String,
    port: u16,
}

fn write_tcp_allowlist_plan(args: TcpAllowlistPlanArgs) -> Result<Value, WinctlError> {
    fs::create_dir_all(&args.artifact_dir)?;
    let result = tcp_allowlist_plan_result(&args)?;
    fs::write(
        args.artifact_dir.join("result.json"),
        serde_json::to_string_pretty(&result)? + "\n",
    )?;
    fs::write(
        args.artifact_dir.join("README.md"),
        format!(
            "# Windows Wide TCP Allowlist Plan\n\nVerdict: `{}`\n\nStatus: `{}`\n\nThis artifact is a dry-run plan only. It does not apply WFP state and does not claim broad Windows wide, DNS, UDP, IPv6, or production driver support.\n",
            result.verdict, result.status
        ),
    )?;
    fs::write(
        args.artifact_dir.join("commands.txt"),
        tcp_allowlist_plan_command(&args),
    )?;
    fs::write(
        args.artifact_dir.join("environment.txt"),
        format!(
            "timestamp_unix={}\ncomputer={}\nuser={}\nadministrator_shell={}\nartifact={}\n",
            unix_now(),
            std::env::var("COMPUTERNAME").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default(),
            is_elevated(),
            args.artifact_dir.display()
        ),
    )?;
    Ok(json!({
        "ok": true,
        "artifact_dir": args.artifact_dir,
        "result": result,
    }))
}

fn tcp_allowlist_plan_result(
    args: &TcpAllowlistPlanArgs,
) -> Result<TcpAllowlistPlanResult, WinctlError> {
    let targets = parse_allowlist_entries(&args.targets)?;
    let relay_exclusions = parse_allowlist_entries(&args.relay_exclusions)?;
    Ok(TcpAllowlistPlanResult {
        schema_version: 1,
        feature: "windows_wide_tcp_allowlist_plan".to_string(),
        platform: "Windows".to_string(),
        scope: "controlled_tcp_allowlist_dry_run".to_string(),
        status: "PLAN_ONLY_MULTI_TARGET_APPLY_NOT_LIVE_PROVEN".to_string(),
        verdict: "PARTIAL".to_string(),
        blocker: "aegis-winctl multi-target apply command exists but has not yet been live-proven with relay egress and cleanup matrix".to_string(),
        broad_capture_claim: "not_claimed".to_string(),
        dns_capture_claim: "not_claimed".to_string(),
        udp_capture_claim: "not_claimed".to_string(),
        ipv6_capture_claim: "not_claimed".to_string(),
        production_driver_claim: "not_claimed".to_string(),
        target_count: targets.len(),
        targets,
        relay_exclusions,
        redirect_port: args.redirect_port,
        listener_pid: args.listener_pid,
        applies_wfp_state: false,
        cleanup_required_before_apply: true,
        current_controller_limit: "one controlled IPv4 TCP target per aegis-wfpctl install; allowlists use repeated dynamic installs".to_string(),
        current_driver_config_model:
            "kernel callout reads per-filter provider context; aegis-wfpctl install creates one dynamic filter/provider-context per controlled target".to_string(),
        multi_filter_driver_change_required: false,
        multi_target_apply_implemented: true,
        multi_target_apply_live_proven: false,
        next_required_proof: "run aegis-winctl multi-target apply with explicit relay exclusions, prove relay egress for every target, and prove cleanup matrix before any broader TCP claim".to_string(),
    })
}

fn parse_allowlist_entries(raw: &[String]) -> Result<Vec<TcpAllowlistEntry>, WinctlError> {
    raw.iter()
        .map(|entry| parse_allowlist_entry(entry))
        .collect()
}

fn parse_allowlist_entry(raw: &str) -> Result<TcpAllowlistEntry, WinctlError> {
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(WinctlError::ArtifactValidation(format!(
            "target must be host:port, got {raw}"
        )));
    };
    if host.trim().is_empty()
        || host != host.trim()
        || host.contains(':')
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
    {
        return Err(WinctlError::ArtifactValidation(format!(
            "target host is empty: {raw}"
        )));
    }
    let port = port.parse::<u16>().map_err(|_| {
        WinctlError::ArtifactValidation(format!("target port must be u16, got {raw}"))
    })?;
    if port == 0 {
        return Err(WinctlError::ArtifactValidation(
            "target port must be nonzero".into(),
        ));
    }
    Ok(TcpAllowlistEntry {
        host: host.to_string(),
        port,
    })
}

fn tcp_allowlist_apply_plan(
    args: &WfpInstallControlledTcpAllowlistArgs,
) -> Result<Vec<Value>, WinctlError> {
    if args.targets.is_empty()
        || args.targets.len() > 64
        || args.redirect_port == 0
        || args.listener_pid == 0
    {
        return Err(WinctlError::ArtifactValidation(
            "allowlist requires 1-64 targets, nonzero redirect port and listener PID".into(),
        ));
    }
    let targets = parse_allowlist_entries(&args.targets)?;
    let relay_exclusions = parse_allowlist_entries(&args.relay_exclusions)?;
    let mut excluded = std::collections::BTreeSet::new();
    for exclusion in &relay_exclusions {
        for address in (exclusion.host.as_str(), exclusion.port).to_socket_addrs()? {
            if let std::net::IpAddr::V4(ip) = address.ip() {
                excluded.insert((ip, exclusion.port));
            }
        }
    }
    let mut planned = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for target in targets {
        if relay_exclusions.contains(&target) {
            return Err(WinctlError::ArtifactValidation(format!(
                "target {}:{} is also listed as a relay exclusion",
                target.host, target.port
            )));
        }
        let mut addresses = std::collections::BTreeSet::new();
        for address in (target.host.as_str(), target.port).to_socket_addrs()? {
            if let std::net::IpAddr::V4(ip) = address.ip() {
                addresses.insert(ip);
            }
        }
        if addresses.is_empty() {
            return Err(WinctlError::ArtifactValidation(
                "target has no IPv4 address".into(),
            ));
        }
        for resolved in addresses {
            validate_target_ipv4(resolved)?;
            if excluded.contains(&(resolved, target.port)) {
                return Err(WinctlError::ArtifactValidation(
                    "resolved target overlaps a relay exclusion".into(),
                ));
            }
            if !seen.insert((resolved, target.port)) {
                continue;
            }
            if seen.len() > 64 {
                return Err(WinctlError::ArtifactValidation(
                    "resolved allowlist exceeds 64 tuples".into(),
                ));
            }
            planned.push(json!({
            "host": target.host,
            "port": target.port,
            "resolved_ipv4": resolved.to_string(),
            "redirect": format!("127.0.0.1:{}", args.redirect_port),
            "listener_pid": args.listener_pid,
            }));
        }
    }
    Ok(planned)
}

fn validate_target_ipv4(ip: Ipv4Addr) -> Result<(), WinctlError> {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local()
    {
        return Err(WinctlError::ArtifactValidation(
            "WFP target must be unicast IPv4 outside loopback/link-local".into(),
        ));
    }
    Ok(())
}

fn tcp_allowlist_plan_command(args: &TcpAllowlistPlanArgs) -> String {
    let mut parts = vec![
        "aegis-winctl proof tcp-allowlist-plan".to_string(),
        format!("--artifact-dir {}", args.artifact_dir.display()),
    ];
    for target in &args.targets {
        parts.push(format!("--target {target}"));
    }
    for exclusion in &args.relay_exclusions {
        parts.push(format!("--relay-exclusion {exclusion}"));
    }
    parts.push(format!("--redirect-port {}", args.redirect_port));
    if let Some(listener_pid) = args.listener_pid {
        parts.push(format!("--listener-pid {listener_pid}"));
    }
    parts.join(" ") + "\n"
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServiceRebootResult {
    schema_version: u8,
    feature: String,
    platform: String,
    scope: String,
    service_name: String,
    target_host: String,
    target_scheme: String,
    target_port: u16,
    expected_relay_egress_ip: String,
    status: String,
    verdict: String,
    blocker: String,
    broad_capture_claim: String,
    dns_capture_claim: String,
    udp_capture_claim: String,
    ipv6_capture_claim: String,
    production_driver_claim: String,
    #[serde(flatten)]
    fields: BTreeMap<String, Value>,
}

impl ServiceRebootResult {
    fn with_status(mut self, status: &str) -> Self {
        self.status = status.to_string();
        self
    }

    fn with_verdict(mut self, verdict: &str) -> Self {
        self.verdict = verdict.to_string();
        self
    }

    fn with_blocker(mut self, blocker: impl Into<String>) -> Self {
        self.blocker = blocker.into();
        self
    }
}

fn parse_expected_relay_egress_ip(value: &str) -> Result<String, String> {
    value
        .parse::<std::net::IpAddr>()
        .map(|_| value.to_owned())
        .map_err(|_| "Expected relay egress must be an explicit IP address".to_owned())
}

fn base_result(common: &ServiceRebootCommon) -> ServiceRebootResult {
    ServiceRebootResult {
        schema_version: 1,
        feature: "windows_wide_service_reboot_persistence_proof".to_string(),
        platform: "Windows".to_string(),
        scope: "controlled_wfp_service_reboot".to_string(),
        service_name: common.service_name.clone(),
        target_host: common.target_host.clone(),
        target_scheme: normalized_target_scheme(common).unwrap_or_else(|_| "invalid".to_string()),
        target_port: common.target_port,
        expected_relay_egress_ip: common.expected_relay_egress_ip.clone(),
        status: "FAIL".to_string(),
        verdict: "FAIL".to_string(),
        blocker: String::new(),
        broad_capture_claim: "not_claimed".to_string(),
        dns_capture_claim: "not_claimed".to_string(),
        udp_capture_claim: "not_claimed".to_string(),
        ipv6_capture_claim: "not_claimed".to_string(),
        production_driver_claim: "not_claimed".to_string(),
        fields: BTreeMap::new(),
    }
}

fn write_result_json(dir: &Path, result: &ServiceRebootResult) -> Result<(), WinctlError> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join("result.json"),
        serde_json::to_string_pretty(result)? + "\n",
    )?;
    Ok(())
}

fn write_readme(dir: &Path, result: &ServiceRebootResult) -> Result<(), WinctlError> {
    fs::write(
        dir.join("README.md"),
        format!(
            "# Windows Wide Service Reboot Persistence Proof\n\nVerdict: `{}`\n\nStatus: `{}`\n\nThis Rust-first proof is controlled TCP only and does not claim broad Windows wide, DNS, UDP, IPv6, or production driver support.\n",
            result.verdict, result.status
        ),
    )?;
    Ok(())
}

fn write_commands(common: &ServiceRebootCommon) -> Result<(), WinctlError> {
    fs::write(
        common.artifact_dir.join("commands.txt"),
        format!(
            "aegis-winctl proof service-reboot prepare --artifact-dir {} --service-name {} --target-host {} --target-scheme {} --target-port {} --expected-relay-egress-ip {} --wfp-controller {} --redirect-port {}\noperator manually reboots Windows host\naegis-winctl proof service-reboot verify-after-reboot --artifact-dir {} --service-name {} --target-host {} --target-scheme {} --target-port {} --expected-relay-egress-ip {} --wfp-controller {} --redirect-port {}\n",
            common.artifact_dir.display(),
            common.service_name,
            common.target_host,
            common.target_scheme,
            common.target_port,
            common.expected_relay_egress_ip,
            common.wfp_controller.display(),
            common.redirect_port,
            common.artifact_dir.display(),
            common.service_name,
            common.target_host,
            common.target_scheme,
            common.target_port,
            common.expected_relay_egress_ip,
            common.wfp_controller.display(),
            common.redirect_port,
        ),
    )?;
    Ok(())
}

fn write_environment(common: &ServiceRebootCommon, mode: &str) -> Result<(), WinctlError> {
    fs::write(
        common.artifact_dir.join("environment.txt"),
        format!(
            "timestamp_unix={}\ncomputer={}\nuser={}\nmode={}\nadministrator_shell={}\nservice_name={}\ntarget_scheme={}\nartifact={}\n",
            unix_now(),
            std::env::var("COMPUTERNAME").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default(),
            mode,
            is_elevated(),
            common.service_name,
            normalized_target_scheme(common).unwrap_or_else(|_| "invalid".to_string()),
            common.artifact_dir.display()
        ),
    )?;
    Ok(())
}

fn marker_path(dir: &Path) -> PathBuf {
    dir.join("pre-reboot-marker.json")
}

fn reboot_was_performed(artifact_dir: &Path) -> Result<bool, WinctlError> {
    let marker = fs::read_to_string(marker_path(artifact_dir))?;
    let marker: Value = serde_json::from_str(&marker)?;
    let Some(prepared_at_unix) = marker.get("prepared_at_unix").and_then(Value::as_u64) else {
        return Ok(false);
    };
    Ok(system_boot_unix().is_some_and(|boot_unix| boot_unix > prepared_at_unix))
}

fn reconfigure_wfp_after_reboot(
    common: &ServiceRebootCommon,
    service_pid: u32,
) -> Result<bool, WinctlError> {
    let log_path = common
        .artifact_dir
        .join("wfp-reconfigured-after-reboot.log");
    if !common.wfp_controller.exists() {
        fs::write(
            &log_path,
            format!(
                "status=CONTROLLER_NOT_PRESENT\ncontroller={}\n",
                common.wfp_controller.display()
            ),
        )?;
        return Ok(false);
    }

    let target_ip = resolve_ipv4_target(&common.target_host, common.target_port)?;
    let controller = common.wfp_controller.to_string_lossy().to_string();
    let target_port = common.target_port.to_string();
    let redirect_port = common.redirect_port.to_string();
    let service_pid = service_pid.to_string();

    let _ = Command::new(&controller).arg("cleanup").output();
    let _ = Command::new(&controller).arg("clear-logs").output();
    let output = Command::new(&controller)
        .args([
            "install",
            &target_ip.to_string(),
            &target_port,
            &redirect_port,
            &service_pid,
        ])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    fs::write(
        &log_path,
        format!(
            "controller={}\ntarget={}:{}\nredirect=127.0.0.1:{}\nservice_pid={}\nexit_code={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}\n",
            common.wfp_controller.display(),
            target_ip,
            common.target_port,
            common.redirect_port,
            service_pid,
            output.status.code(),
            stdout.trim(),
            stderr.trim()
        ),
    )?;
    Ok(output.status.success())
}

fn start_wfp_driver_after_reboot(common: &ServiceRebootCommon) -> Result<bool, WinctlError> {
    let log_path = common.artifact_dir.join("wfp-driver-after-reboot.log");
    let before = Command::new("sc.exe")
        .args(["query", "AegisWfp"])
        .output()?;
    let before_stdout = String::from_utf8_lossy(&before.stdout);
    let before_stderr = String::from_utf8_lossy(&before.stderr);
    let before_running = before_stdout
        .lines()
        .any(|line| line.contains("STATE") && line.contains("RUNNING"));

    let start = if before_running {
        None
    } else {
        Some(
            Command::new("sc.exe")
                .args(["start", "AegisWfp"])
                .output()?,
        )
    };

    let after = Command::new("sc.exe")
        .args(["query", "AegisWfp"])
        .output()?;
    let after_stdout = String::from_utf8_lossy(&after.stdout);
    let after_stderr = String::from_utf8_lossy(&after.stderr);
    let after_running = after_stdout
        .lines()
        .any(|line| line.contains("STATE") && line.contains("RUNNING"));

    let mut log = format!(
        "service=AegisWfp\nbefore_exit_code={:?}\n--- before stdout ---\n{}\n--- before stderr ---\n{}\n",
        before.status.code(),
        before_stdout.trim(),
        before_stderr.trim()
    );
    if let Some(start) = start {
        log.push_str(&format!(
            "\nstart_exit_code={:?}\n--- start stdout ---\n{}\n--- start stderr ---\n{}\n",
            start.status.code(),
            String::from_utf8_lossy(&start.stdout).trim(),
            String::from_utf8_lossy(&start.stderr).trim()
        ));
    } else {
        log.push_str("\nstart_skipped=already_running\n");
    }
    log.push_str(&format!(
        "\nafter_exit_code={:?}\n--- after stdout ---\n{}\n--- after stderr ---\n{}\n",
        after.status.code(),
        after_stdout.trim(),
        after_stderr.trim()
    ));
    fs::write(log_path, log)?;
    Ok(after_running)
}

fn run_relay_egress_probe(common: &ServiceRebootCommon) -> Result<String, WinctlError> {
    if let Some(path) = &common.relay_egress_log {
        if path.exists() {
            return Ok(fs::read_to_string(path)?);
        }
    }

    let target_ip = resolve_ipv4_target(&common.target_host, common.target_port)?;
    let resolve_arg = format!(
        "{}:{}:{}",
        common.target_host, common.target_port, target_ip
    );
    let url = relay_probe_url(common)?;
    let output = Command::new("curl.exe")
        .args([
            "-4",
            "-sS",
            "--noproxy",
            "*",
            "--max-time",
            "30",
            "--resolve",
            &resolve_arg,
            &url,
        ])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    fs::write(
        common.artifact_dir.join("relay-egress-after-reboot.log"),
        format!(
            "url={}\nresolve={}\nexit_code={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}\n",
            url,
            resolve_arg,
            output.status.code(),
            stdout,
            stderr
        ),
    )?;
    Ok(stdout)
}

fn normalized_target_scheme(common: &ServiceRebootCommon) -> Result<String, WinctlError> {
    match common.target_scheme.to_ascii_lowercase().as_str() {
        "auto" => {
            if common.target_port == 80 {
                Ok("http".to_string())
            } else {
                Ok("https".to_string())
            }
        }
        "http" => Ok("http".to_string()),
        "https" => Ok("https".to_string()),
        other => Err(WinctlError::ArtifactValidation(format!(
            "unsupported target scheme: {other}; expected auto, http, or https"
        ))),
    }
}

fn relay_probe_url(common: &ServiceRebootCommon) -> Result<String, WinctlError> {
    let scheme = normalized_target_scheme(common)?;
    let default_port = (scheme == "http" && common.target_port == 80)
        || (scheme == "https" && common.target_port == 443);
    if default_port {
        Ok(format!("{}://{}/", scheme, common.target_host))
    } else {
        Ok(format!(
            "{}://{}:{}/",
            scheme, common.target_host, common.target_port
        ))
    }
}

fn resolve_ipv4_target(host: &str, port: u16) -> Result<Ipv4Addr, WinctlError> {
    (host, port)
        .to_socket_addrs()?
        .find_map(|addr| match addr {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            std::net::SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            WinctlError::ArtifactValidation(format!("no IPv4 address resolved for {host}:{port}"))
        })
}

#[cfg(windows)]
fn system_boot_unix() -> Option<u64> {
    use windows::Win32::System::SystemInformation::GetTickCount64;

    let uptime_secs = unsafe { GetTickCount64() / 1000 };
    unix_now().checked_sub(uptime_secs)
}

#[cfg(not(windows))]
fn system_boot_unix() -> Option<u64> {
    None
}

fn cleanup_wfp(common: &ServiceRebootCommon) -> CleanupStatus {
    if !common.wfp_controller.exists() {
        return CleanupStatus::ControllerNotPresent;
    }
    let controller = common.wfp_controller.to_string_lossy().to_string();
    match run_checked(&controller, &["cleanup"]) {
        Ok(()) => CleanupStatus::Pass,
        Err(_) => CleanupStatus::Warn,
    }
}

fn validate_artifact(dir: &Path) -> Result<Value, WinctlError> {
    let result_path = dir.join("result.json");
    if !result_path.exists() {
        return Err(WinctlError::ArtifactValidation(format!(
            "missing {}",
            result_path.display()
        )));
    }
    let result: Value = serde_json::from_str(&fs::read_to_string(&result_path)?)?;
    for key in [
        "feature",
        "platform",
        "scope",
        "status",
        "verdict",
        "broad_capture_claim",
        "dns_capture_claim",
        "udp_capture_claim",
        "ipv6_capture_claim",
    ] {
        if result.get(key).is_none() {
            return Err(WinctlError::ArtifactValidation(format!(
                "missing result.json key {key}"
            )));
        }
    }
    Ok(json!({"ok": true, "artifact_dir": dir, "result": result}))
}

fn redact_text(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("auth_token")
                || lower.contains("authorization: bearer")
                || lower.contains("private key")
            {
                "<redacted>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[cfg(windows)]
fn query_service(service_name: &str) -> Result<Value, WinctlError> {
    service::query(service_name)
}

#[cfg(not(windows))]
fn query_service(service_name: &str) -> Result<Value, WinctlError> {
    let output = Command::new("sc.exe")
        .args(["queryex", service_name])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Ok(json!({
            "name": service_name,
            "exists": false,
            "stdout": stdout.trim(),
            "stderr": stderr.trim(),
        }));
    }
    Ok(parse_sc_query(service_name, &stdout))
}

#[cfg(any(not(windows), test))]
fn parse_sc_query(service_name: &str, text: &str) -> Value {
    let mut state = None;
    let mut pid = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("STATE") {
            if let Some(status) = rest.split(':').nth(1) {
                let parts: Vec<&str> = status.split_whitespace().collect();
                if parts.len() >= 2 {
                    state = Some(parts[1].to_string());
                }
            }
        }
        if let Some(rest) = trimmed.strip_prefix("PID") {
            if let Some(raw) = rest.split(':').nth(1) {
                pid = raw.trim().parse::<u32>().ok();
            }
        }
    }
    json!({
        "name": service_name,
        "exists": true,
        "state": state.unwrap_or_else(|| "UNKNOWN".to_string()),
        "process_id": pid.unwrap_or(0),
    })
}

fn run_checked(program: &str, args: &[&str]) -> Result<(), WinctlError> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(WinctlError::CommandFailed {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            code: status.code(),
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(windows)]
fn is_elevated() -> bool {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin().as_bool() }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_rejects_zero_ports_wildcards_and_local_capture() {
        for raw in ["host:0", "host:65536", "::1:443", "a b:443", ":443"] {
            assert!(parse_allowlist_entry(raw).is_err());
        }
        for ip in ["0.0.0.0", "127.0.0.2", "224.0.0.1", "169.254.1.1"] {
            assert!(validate_target_ipv4(ip.parse().unwrap()).is_err());
        }
    }

    #[test]
    fn allowlist_deduplicates_and_requires_listener_pid() {
        let mut args = WfpInstallControlledTcpAllowlistArgs {
            controller: "unused".into(),
            targets: vec!["203.0.113.1:443".into(); 2],
            relay_exclusions: vec![],
            redirect_port: 18080,
            listener_pid: 42,
            apply: false,
        };
        assert_eq!(tcp_allowlist_apply_plan(&args).unwrap().len(), 1);
        args.listener_pid = 0;
        assert!(tcp_allowlist_apply_plan(&args).is_err());
    }

    #[test]
    fn classifies_non_elevated_as_blocked() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::Prepare,
            elevated: false,
            marker_present: false,
            reboot_performed: false,
            service_exists: false,
            service_started_after_reboot: false,
            runtime_events_restarted: false,
            wfp_driver_started_after_reboot: false,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        });
        assert_eq!(verdict.status, "BLOCKED_BY_NON_ELEVATED_TERMINAL");
        assert_eq!(verdict.verdict, "BLOCKED");
    }

    #[test]
    fn classifies_prepare_as_reboot_not_performed() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::Prepare,
            elevated: true,
            marker_present: true,
            reboot_performed: false,
            service_exists: true,
            service_started_after_reboot: false,
            runtime_events_restarted: false,
            wfp_driver_started_after_reboot: false,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        });
        assert_eq!(verdict.status, "BLOCKED_BY_REBOOT_NOT_PERFORMED");
    }

    #[test]
    fn classifies_verify_without_marker_as_reboot_not_performed() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::VerifyAfterReboot,
            elevated: true,
            marker_present: false,
            reboot_performed: false,
            service_exists: true,
            service_started_after_reboot: true,
            runtime_events_restarted: true,
            wfp_driver_started_after_reboot: true,
            wfp_reconfigured_after_reboot: true,
            controlled_tcp_wfp_proof_after_reboot: true,
            relay_egress_after_reboot: true,
            cleanup: CleanupStatus::Pass,
        });
        assert_eq!(verdict.status, "BLOCKED_BY_PREPARE_MARKER_MISSING");
    }

    #[test]
    fn classifies_verify_without_service_as_service_missing() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::VerifyAfterReboot,
            elevated: true,
            marker_present: true,
            reboot_performed: true,
            service_exists: false,
            service_started_after_reboot: false,
            runtime_events_restarted: false,
            wfp_driver_started_after_reboot: false,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        });
        assert_eq!(verdict.status, "BLOCKED_BY_SERVICE_MISSING");
        assert_eq!(verdict.verdict, "BLOCKED");
    }

    #[test]
    fn classifies_verify_without_wfp_reconfigure_as_blocked() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::VerifyAfterReboot,
            elevated: true,
            marker_present: true,
            reboot_performed: true,
            service_exists: true,
            service_started_after_reboot: true,
            runtime_events_restarted: true,
            wfp_driver_started_after_reboot: true,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        });
        assert_eq!(verdict.status, "BLOCKED_BY_WFP_RECONFIGURE_FAILED");
        assert_eq!(verdict.verdict, "BLOCKED");
    }

    #[test]
    fn classifies_verify_without_wfp_driver_start_as_blocked() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::VerifyAfterReboot,
            elevated: true,
            marker_present: true,
            reboot_performed: true,
            service_exists: true,
            service_started_after_reboot: true,
            runtime_events_restarted: true,
            wfp_driver_started_after_reboot: false,
            wfp_reconfigured_after_reboot: false,
            controlled_tcp_wfp_proof_after_reboot: false,
            relay_egress_after_reboot: false,
            cleanup: CleanupStatus::NotRun,
        });
        assert_eq!(verdict.status, "BLOCKED_BY_WFP_DRIVER_START_FAILED");
        assert_eq!(verdict.verdict, "BLOCKED");
    }

    #[test]
    fn classifies_complete_verify_as_pass() {
        let verdict = classify_service_reboot(ServiceRebootEvidence {
            mode: ServiceRebootMode::VerifyAfterReboot,
            elevated: true,
            marker_present: true,
            reboot_performed: true,
            service_exists: true,
            service_started_after_reboot: true,
            runtime_events_restarted: true,
            wfp_driver_started_after_reboot: true,
            wfp_reconfigured_after_reboot: true,
            controlled_tcp_wfp_proof_after_reboot: true,
            relay_egress_after_reboot: true,
            cleanup: CleanupStatus::Pass,
        });
        assert_eq!(verdict.status, "PASS");
        assert_eq!(verdict.verdict, "PASS");
    }

    #[test]
    fn redacts_sensitive_lines() {
        let redacted = redact_text("safe\npassword = hunter2\nauth_token = abc\n");
        assert!(redacted.contains("safe"));
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("abc"));
    }

    #[test]
    fn parses_sc_query_state_and_pid() {
        let parsed = parse_sc_query(
            "AegisClient",
            "SERVICE_NAME: AegisClient\n        STATE              : 4  RUNNING\n        PID                : 1234\n",
        );
        assert_eq!(parsed["state"], "RUNNING");
        assert_eq!(parsed["process_id"], 1234);
    }

    #[test]
    fn relay_probe_url_auto_uses_http_for_port_80() {
        let common = test_service_reboot_common("auto", 80);
        assert_eq!(relay_probe_url(&common).unwrap(), "http://api.ipify.org/");
    }

    #[test]
    fn relay_probe_url_auto_uses_https_for_port_443() {
        let common = test_service_reboot_common("auto", 443);
        assert_eq!(relay_probe_url(&common).unwrap(), "https://api.ipify.org/");
    }

    #[test]
    fn relay_probe_url_keeps_explicit_http_non_default_port() {
        let common = test_service_reboot_common("http", 8080);
        assert_eq!(
            relay_probe_url(&common).unwrap(),
            "http://api.ipify.org:8080/"
        );
    }

    #[test]
    fn dns_policy_result_does_not_claim_capture_or_leak_prevention() {
        let result = policy_proof_result(WindowsPolicyLane::Dns);
        assert_eq!(result.feature, "windows_wide_dns_policy_proof");
        assert_eq!(result.verdict, "PARTIAL");
        assert_eq!(result.dns_capture_claim, "not_claimed");
        assert_eq!(result.udp_capture_claim, "not_claimed");
        assert_eq!(result.ipv6_capture_claim, "not_claimed");
        assert!(!result.capture_supported_by_current_code);
        assert!(!result.leak_prevention_proven);
        assert!(!result.live_capture_artifact_claimed);
    }

    #[test]
    fn ipv6_policy_result_records_ipv4_tcp_boundary() {
        let result = policy_proof_result(WindowsPolicyLane::Ipv6);
        assert_eq!(result.scope, "controlled_wfp_ipv4_tcp_ipv6_boundary");
        assert_eq!(result.current_wfp_layer, "ALE_CONNECT_REDIRECT_V4");
        assert_eq!(result.current_wfp_protocol, "IPPROTO_TCP");
        assert!(result.blocker.contains("controlled IPv4 TCP only"));
    }

    #[test]
    fn parses_tcp_allowlist_entry() {
        let entry = parse_allowlist_entry("api.ipify.org:443").expect("parse entry");
        assert_eq!(entry.host, "api.ipify.org");
        assert_eq!(entry.port, 443);
    }

    #[test]
    fn tcp_allowlist_plan_is_dry_run_only() {
        let args = TcpAllowlistPlanArgs {
            artifact_dir: PathBuf::from("artifact"),
            targets: vec![
                "api.ipify.org:443".to_string(),
                "example.com:80".to_string(),
            ],
            relay_exclusions: vec!["198.51.100.22:8443".to_string()],
            redirect_port: 18080,
            listener_pid: Some(1234),
        };
        let result = tcp_allowlist_plan_result(&args).expect("plan result");
        assert_eq!(result.target_count, 2);
        assert_eq!(result.broad_capture_claim, "not_claimed");
        assert!(!result.applies_wfp_state);
        assert!(result.cleanup_required_before_apply);
        assert_eq!(
            result.current_controller_limit,
            "one controlled IPv4 TCP target per aegis-wfpctl install; allowlists use repeated dynamic installs"
        );
        assert!(!result.multi_filter_driver_change_required);
        assert!(result.multi_target_apply_implemented);
        assert!(!result.multi_target_apply_live_proven);
        assert!(result
            .current_driver_config_model
            .contains("per-filter provider context"));
    }

    #[test]
    fn tcp_allowlist_apply_plan_resolves_numeric_targets() {
        let args = WfpInstallControlledTcpAllowlistArgs {
            controller: PathBuf::from("aegis-wfpctl.exe"),
            targets: vec![
                "203.0.113.10:443".to_string(),
                "203.0.113.20:80".to_string(),
            ],
            relay_exclusions: vec!["198.51.100.22:8443".to_string()],
            redirect_port: 18080,
            listener_pid: 4321,
            apply: false,
        };
        let plan = tcp_allowlist_apply_plan(&args).expect("apply plan");
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0]["resolved_ipv4"], "203.0.113.10");
        assert_eq!(plan[0]["redirect"], "127.0.0.1:18080");
    }

    #[test]
    fn tcp_allowlist_apply_plan_rejects_relay_exclusion_target() {
        let args = WfpInstallControlledTcpAllowlistArgs {
            controller: PathBuf::from("aegis-wfpctl.exe"),
            targets: vec!["198.51.100.22:8443".to_string()],
            relay_exclusions: vec!["198.51.100.22:8443".to_string()],
            redirect_port: 18080,
            listener_pid: 4321,
            apply: false,
        };
        let err = tcp_allowlist_apply_plan(&args).expect_err("relay exclusion rejected");
        assert!(err.to_string().contains("relay exclusion"));
    }

    fn test_service_reboot_common(target_scheme: &str, target_port: u16) -> ServiceRebootCommon {
        ServiceRebootCommon {
            artifact_dir: PathBuf::from("artifact"),
            service_name: "AegisClient".to_string(),
            target_host: "api.ipify.org".to_string(),
            target_scheme: target_scheme.to_string(),
            target_port,
            expected_relay_egress_ip: "192.0.2.81".to_string(),
            wfp_controller: PathBuf::from("target/debug/aegis-wfpctl.exe"),
            redirect_port: 18080,
            relay_egress_log: None,
        }
    }

    fn parse_explicit_egress_common(verb: &str, expected: &str) -> ServiceRebootCommon {
        let parsed = Cli::try_parse_from([
            "aegis-winctl",
            "proof",
            "service-reboot",
            verb,
            "--artifact-dir",
            "audit23-unused-artifact",
            "--expected-relay-egress-ip",
            expected,
        ])
        .unwrap();
        let TopCommand::Proof(ProofArgs {
            command: ProofCommand::ServiceReboot(ServiceRebootArgs { command }),
        }) = parsed.command
        else {
            panic!("wrong proof owner");
        };
        let common = match command {
            ServiceRebootCommand::Prepare(common)
            | ServiceRebootCommand::VerifyAfterReboot(common) => common,
        };
        assert_eq!(common.expected_relay_egress_ip, expected);
        assert_eq!(
            serde_json::to_value(base_result(&common)).unwrap()["expected_relay_egress_ip"],
            expected
        );
        common
    }

    fn explicit_egress_validity_control(verb: &str) {
        parse_explicit_egress_common(verb, "192.0.2.81");
        parse_explicit_egress_common(verb, "2001:db8::81");
    }

    #[test]
    fn service_reboot_prepare_refuses_missing_explicit_egress_at_real_cli() {
        explicit_egress_validity_control("prepare");
        eprintln!("AUDIT23_CLI_VALIDITY case=prepare_missing controls=2 result=true");
        let parsed = Cli::try_parse_from([
            "aegis-winctl",
            "proof",
            "service-reboot",
            "prepare",
            "--artifact-dir",
            "audit23-unused-artifact",
        ]);
        assert!(
            matches!(parsed, Err(ref error) if error.kind() == clap::error::ErrorKind::MissingRequiredArgument),
            "missing explicit egress was admitted"
        );
    }

    #[test]
    fn service_reboot_verify_refuses_missing_explicit_egress_at_real_cli() {
        explicit_egress_validity_control("verify-after-reboot");
        eprintln!("AUDIT23_CLI_VALIDITY case=verify_missing controls=2 result=true");
        let parsed = Cli::try_parse_from([
            "aegis-winctl",
            "proof",
            "service-reboot",
            "verify-after-reboot",
            "--artifact-dir",
            "audit23-unused-artifact",
        ]);
        assert!(
            matches!(parsed, Err(ref error) if error.kind() == clap::error::ErrorKind::MissingRequiredArgument),
            "missing explicit egress was admitted"
        );
    }

    #[test]
    fn service_reboot_refuses_malformed_explicit_egress_at_real_cli() {
        for verb in ["prepare", "verify-after-reboot"] {
            explicit_egress_validity_control(verb);
            eprintln!("AUDIT23_CLI_VALIDITY case=malformed controls=2 result=true");
            for invalid in [
                "",
                "relay.example.invalid",
                "not-an-ip",
                "192.0.2.999",
                "127",
                " 192.0.2.81",
            ] {
                let parsed = Cli::try_parse_from([
                    "aegis-winctl",
                    "proof",
                    "service-reboot",
                    verb,
                    "--artifact-dir",
                    "audit23-unused-artifact",
                    "--expected-relay-egress-ip",
                    invalid,
                ]);
                assert!(
                    matches!(parsed, Err(ref error) if error.kind() == clap::error::ErrorKind::ValueValidation),
                    "malformed explicit egress was admitted"
                );
            }
        }
    }

    #[test]
    fn service_reboot_preserves_two_explicit_egress_identities_at_real_cli() {
        for verb in ["prepare", "verify-after-reboot"] {
            for expected in ["192.0.2.81", "198.51.100.82", "2001:db8::81"] {
                parse_explicit_egress_common(verb, expected);
            }
        }
    }
}
