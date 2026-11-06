//! The fixed delivered action surface, shared with the full build-side tool.
use std::path::PathBuf;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum ResearchCommand {
    /// Content-free exact-built private research tool producer snapshot.
    ResearchBuildInfo,
    /// Paired timing control over explicitly application-owned UDP resources.
    PoissonControl {
        #[arg(long)]
        config_json: PathBuf,
        #[arg(long)]
        input_file: Option<PathBuf>,
        #[arg(long)]
        output_file: Option<PathBuf>,
    },
    /// Explicit application-owned Poisson insertion exchange, no native traffic.
    PoissonInsertion {
        #[arg(long)]
        config_json: PathBuf,
        #[arg(long)]
        application_input: Option<PathBuf>,
        #[arg(long)]
        control_input: Option<PathBuf>,
        #[arg(long)]
        application_output: Option<PathBuf>,
        #[arg(long)]
        control_output: Option<PathBuf>,
    },
    /// One authorized TLS control exchange; no installed traffic-mode activation.
    PrivateControl {
        #[arg(long)]
        config_json: PathBuf,
        #[arg(long)]
        input_file: Option<PathBuf>,
        #[arg(long)]
        output_file: Option<PathBuf>,
    },
    /// Export a strictly supported private classic PCAP trial to assembler TSV.
    PrivacyPcapExport {
        #[arg(long)]
        input_pcap: PathBuf,
        #[arg(long)]
        output_tsv: PathBuf,
    },
    /// Assemble paired finite-bin samples from private retained packet-field exports.
    PrivacyStudyAssemble {
        #[arg(long)]
        input_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Replay private native direct outcome events without applying a route policy.
    BrainOutcomeReplay {
        #[arg(long)]
        input_jsonl: PathBuf,
        #[arg(long)]
        provenance_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Estimate a finite-alphabet empirical privacy/cost frontier from measured input.
    PrivacyFrontier {
        #[arg(long)]
        input_json: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
}

pub fn run(command: ResearchCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ResearchCommand::ResearchBuildInfo => crate::research_build_info::emit(
            "aegis-measure",
            crate::research_build_info::MEASURE_CAPABILITIES,
        ),
        ResearchCommand::PoissonControl {
            config_json,
            input_file,
            output_file,
        } => {
            crate::poisson_control::run(&config_json, input_file.as_deref(), output_file.as_deref())
        }
        ResearchCommand::PoissonInsertion {
            config_json,
            application_input,
            control_input,
            application_output,
            control_output,
        } => crate::poisson_insertion::run(
            &config_json,
            application_input.as_deref(),
            control_input.as_deref(),
            application_output.as_deref(),
            control_output.as_deref(),
        ),
        ResearchCommand::PrivateControl {
            config_json,
            input_file,
            output_file,
        } => {
            crate::private_control::run(&config_json, input_file.as_deref(), output_file.as_deref())
        }
        ResearchCommand::PrivacyPcapExport {
            input_pcap,
            output_tsv,
        } => {
            use std::io::Write;
            let summary = crate::privacy_pcap::run(&input_pcap, &output_tsv)?;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &summary)?;
            stdout.write_all(b"\n")?;
            Ok(())
        }
        ResearchCommand::PrivacyStudyAssemble {
            input_json,
            output_json,
        } => {
            crate::privacy_study::run(&input_json, &output_json)?;
            Ok(())
        }
        ResearchCommand::BrainOutcomeReplay {
            input_jsonl,
            provenance_json,
            output_json,
        } => crate::brain_outcome_replay::run(&input_jsonl, &provenance_json, &output_json)
            .map_err(Into::into),
        ResearchCommand::PrivacyFrontier {
            input_json,
            output_json,
        } => {
            use std::io::{Read, Write};
            const MAX_INPUT: u64 = 16 * 1024 * 1024;
            let file = std::fs::File::open(&input_json)?;
            if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_INPUT {
                return Err("privacy input must be a regular file of at most 16 MiB".into());
            }
            let mut input = Vec::new();
            file.take(MAX_INPUT + 1).read_to_end(&mut input)?;
            if input.len() as u64 > MAX_INPUT {
                return Err("privacy input exceeded its read budget".into());
            }
            let value = serde_json::from_slice(&input)?;
            let report = crate::privacy_frontier::privacy_frontier_report(&value)?;
            // Never erase an earlier attempt or follow a pre-existing output symlink.
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output_json)?;
            serde_json::to_writer_pretty(&mut output, &report)?;
            output.write_all(b"\n")?;
            output.sync_all()?;
            Ok(())
        }
    }
}
