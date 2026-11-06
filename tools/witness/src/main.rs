use std::{fs::OpenOptions, io::Write, path::PathBuf};

use clap::Parser;

use aegis_witness::{
    capture::{select_source, CapturedRecord},
    classify_tls::classify_tls_record,
    fixture::client_hello_with_sni_alpn,
    report::WitnessEvent,
    score::score_tls_classification,
    summary::summarize_events,
};

#[derive(Debug, Parser)]
#[command(version, about = "AEGIS witness classifier")]
struct Args {
    /// Hex-encoded TLS record to classify.
    #[arg(long, conflicts_with_all = ["input_file", "input_pcap", "stdin", "interface", "fixture_clienthello_hostname", "summarize_jsonl"])]
    input_hex: Option<String>,

    /// Raw TLS record file to classify.
    #[arg(long, conflicts_with_all = ["input_hex", "input_pcap", "stdin", "interface", "fixture_clienthello_hostname", "summarize_jsonl"])]
    input_file: Option<PathBuf>,

    /// Classic PCAP: single complete TLS records in Ethernet/Raw IPv4 TCP.
    /// Unsupported, empty, fragmented, or multi-segment input is refused.
    #[arg(long, conflicts_with_all = ["input_hex", "input_file", "stdin", "interface", "fixture_clienthello_hostname", "summarize_jsonl"])]
    input_pcap: Option<PathBuf>,

    /// Read raw TLS record bytes from stdin.
    #[arg(long, conflicts_with_all = ["input_hex", "input_file", "input_pcap", "interface", "fixture_clienthello_hostname", "summarize_jsonl"])]
    stdin: bool,

    /// Reserved for live capture; currently returns an explicit unsupported error.
    #[arg(long, conflicts_with_all = ["input_hex", "input_file", "input_pcap", "stdin", "fixture_clienthello_hostname", "summarize_jsonl"])]
    interface: Option<String>,

    /// Generate and classify a Rust-native TLS ClientHello fixture.
    #[arg(long, conflicts_with_all = ["input_hex", "input_file", "input_pcap", "stdin", "interface", "summarize_jsonl"])]
    fixture_clienthello_hostname: Option<String>,

    /// Summarize an existing witness JSONL stream without classifying new input.
    #[arg(long, conflicts_with_all = ["input_hex", "input_file", "input_pcap", "stdin", "interface", "fixture_clienthello_hostname", "output_jsonl"])]
    summarize_jsonl: Option<PathBuf>,

    /// ALPN used with --fixture-clienthello-hostname.
    #[arg(long, default_value = "h2")]
    fixture_clienthello_alpn: String,

    /// Optional JSONL output path. Defaults to stdout.
    #[arg(long)]
    output_jsonl: Option<PathBuf>,

    /// Optional JSON summary output path.
    #[arg(long)]
    summary_json: Option<PathBuf>,

    /// Optional Markdown summary table output path.
    #[arg(long)]
    summary_markdown: Option<PathBuf>,

    /// Optional operator label copied into the JSONL event.
    #[arg(long, default_value = "unlabeled")]
    label: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if let Some(path) = args.summarize_jsonl.as_deref() {
        let events = read_witness_jsonl(path)?;
        write_summary_outputs(&events, args.summary_json, args.summary_markdown)?;
        return Ok(());
    }

    let records = if let Some(hostname) = args.fixture_clienthello_hostname.as_deref() {
        vec![CapturedRecord {
            label_suffix: None,
            bytes: client_hello_with_sni_alpn(hostname, &args.fixture_clienthello_alpn)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?,
        }]
    } else {
        let source = select_source(
            args.input_hex,
            args.input_file,
            args.input_pcap,
            args.stdin,
            args.interface,
        )?;
        source.read_records()?
    };
    let events = records
        .into_iter()
        .map(|record| event_for_record(&args.label, record))
        .collect::<Vec<_>>();

    if let Some(path) = args.output_jsonl {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        for event in &events {
            writeln!(file, "{}", serde_json::to_string(&event)?)?;
        }
    } else {
        for event in &events {
            println!("{}", serde_json::to_string(&event)?);
        }
    }

    write_summary_outputs(&events, args.summary_json, args.summary_markdown)?;

    Ok(())
}

fn read_witness_jsonl(
    path: &std::path::Path,
) -> Result<Vec<WitnessEvent>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    for (index, line) in std::fs::read_to_string(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<WitnessEvent>(line).map_err(|err| {
            format!(
                "{}:{} invalid witness JSONL: {err}",
                path.display(),
                index + 1
            )
        })?;
        events.push(event);
    }
    Ok(events)
}

fn write_summary_outputs(
    events: &[WitnessEvent],
    summary_json: Option<PathBuf>,
    summary_markdown: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = summary_json {
        let summary = summarize_events(events);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        writeln!(file, "{}", serde_json::to_string_pretty(&summary)?)?;
    }

    if let Some(path) = summary_markdown {
        let summary = summarize_events(events);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        write!(file, "{}", summary.to_markdown_table())?;
    }
    Ok(())
}

fn event_for_record(label: &str, record: aegis_witness::capture::CapturedRecord) -> WitnessEvent {
    let classification = classify_tls_record(&record.bytes);
    let score = score_tls_classification(&classification);
    WitnessEvent::new(
        label.to_string(),
        record.label_suffix,
        classification,
        score,
    )
}
