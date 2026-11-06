//! Restricted delivered research entry point. Full build/host operators are not registered.
mod brain_outcome_replay;
mod poisson_control;
mod poisson_insertion;
mod privacy_frontier;
mod privacy_pcap;
mod privacy_study;
mod private_control;
mod research_build_info;
mod research_command;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-measure",
    version,
    about = "AEGIS private research operators"
)]
struct Cli {
    #[command(subcommand)]
    command: research_command::ResearchCommand,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().skip(1).any(|arg| {
        arg == std::ffi::OsStr::new("--bundle-url")
            || arg
                .to_str()
                .is_some_and(|arg| arg.starts_with("--bundle-url="))
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Inline bundle URLs are no longer accepted. Use --bundle-url-file with an opaque private record path, or --bundle with an archive path.",
        ).into());
    }
    research_command::run(Cli::parse().command)
}
