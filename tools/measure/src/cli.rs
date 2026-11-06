use clap::Parser;

mod command;

pub use command::Command;

#[derive(Debug, Parser)]
#[command(version, about = "AEGIS measurement artifact helpers")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
