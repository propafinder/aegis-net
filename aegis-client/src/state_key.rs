//! Explicit local state-key maintenance. No credential bytes enter CLI output.
use aegis_core::state_secret::{key_store_status, migrate_key_store, StateKeyStore};
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Args, Clone, Debug)]
pub struct StateKeyArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Clone, Debug)]
enum Action {
    /// Report the selected backend and any adjacent key copy, without reading secrets.
    Status {
        /// Use the exact expanded state_path from the client config.
        #[arg(long)]
        state_path: PathBuf,
    },
    /// Move a file key into an external store. Stop all clients using this state first.
    /// Run as the service identity; older binaries do not understand the new policy.
    Migrate {
        /// Use the exact expanded state_path from the client config.
        #[arg(long)]
        state_path: PathBuf,
        /// systemd-credential requires a preprovisioned matching aegis-state-key.
        #[arg(long, value_enum)]
        to: Backend,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Backend {
    OsKeyring,
    SystemdCredential,
}

pub fn run(args: &StateKeyArgs) -> anyhow::Result<()> {
    let status = match &args.action {
        Action::Status { state_path } => {
            key_store_status(&crate::config::expand_tilde(state_path))?
        }
        Action::Migrate { state_path, to } => migrate_key_store(
            &crate::config::expand_tilde(state_path),
            match to {
                Backend::OsKeyring => StateKeyStore::OsKeyring,
                Backend::SystemdCredential => StateKeyStore::SystemdCredential,
            },
        )?,
    };
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}
