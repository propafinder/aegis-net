use super::{service, ServiceCommand, ServiceNameArg, WinctlError};
use aegis_core::windows_tunnel::{firewall, lifecycle};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;
#[derive(Args)]
pub(super) struct TunnelArgs {
    #[command(subcommand)]
    command: TunnelCommand,
}
#[derive(Subcommand)]
enum TunnelCommand {
    Status,
    /// Stop the explicitly named service, restore only journaled routes, then
    /// remove AEGIS protection. Foreground clients must be stopped first.
    Disconnect {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        service_name: Option<String>,
    },
    /// Repair a crashed session while retaining persistent network protection.
    Recover {
        #[arg(long)]
        config: PathBuf,
    },
}
pub(super) fn run(args: TunnelArgs) -> Result<Value, WinctlError> {
    match args.command {
        TunnelCommand::Status => Ok(
            json!({"ok":true,"persistent_filter_count":firewall::status()?,"protection":firewall::inspect(None)?,"filter_presence_is_not_relay_health":true}),
        ),
        TunnelCommand::Disconnect {
            config,
            service_name,
        } => {
            if let Some(service_name) = service_name {
                if service::query(&service_name)?["exists"] == true {
                    service::run(ServiceCommand::Stop(ServiceNameArg { service_name }))?;
                }
            }
            let _exclusive = lifecycle::Exclusive::acquire()?;
            let count = lifecycle::recover_routes(&lifecycle::journal_path(&config))?;
            firewall::disconnect()?;
            Ok(json!({"ok":true,"disconnected":true,"recovered_routes":count}))
        }
        TunnelCommand::Recover { config } => {
            let _exclusive = lifecycle::Exclusive::acquire()?;
            let count = lifecycle::recover_routes(&lifecycle::journal_path(&config))?;
            Ok(
                json!({"ok":true,"recovered_routes":count,"persistent_filter_count":firewall::status()?}),
            )
        }
    }
}
