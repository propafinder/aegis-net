use std::{
    collections::BTreeSet,
    fs,
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aegis_witness::{
    classify_tls::{classify_tls_record, TlsWitnessClassification},
    score::score_tls_classification,
};
use clap::Parser;
use serde_json::{json, Value};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Capture and compare AEGIS vs Chrome TLS ClientHello fingerprints"
)]
struct Args {
    /// Output artifact directory.
    #[arg(long)]
    output_dir: PathBuf,
    /// Hostname used for SNI and Chrome navigation.
    #[arg(long, default_value = "example.com")]
    host: String,
    /// Single ALPN value requested from the AEGIS probe.
    #[arg(long, default_value = "h2,http/1.1")]
    alpn: String,
    /// AEGIS relay TLS backend under measurement.
    #[arg(long, default_value = "chrome_like_experimental")]
    aegis_backend: String,
    /// Repository root used for the internal cargo-run probe.
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    /// Chrome/Chromium binary path. If omitted, common local paths are probed.
    #[arg(long)]
    chrome_bin: Option<PathBuf>,
    /// tshark binary path.
    #[arg(long, default_value = "tshark")]
    tshark_bin: PathBuf,
    /// Capture timeout for each probe.
    #[arg(long, default_value_t = 60_000)]
    timeout_ms: u64,
}

#[derive(Debug)]
struct CapturedHello {
    label: &'static str,
    raw_path: PathBuf,
    pcap_path: PathBuf,
    classification: TlsWitnessClassification,
    tshark: Value,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    fs::create_dir_all(&args.output_dir)?;

    let timeout = Duration::from_millis(args.timeout_ms);
    let aegis = capture_aegis_clienthello(&args, timeout)?;
    let chrome = capture_chrome_clienthello(&args, timeout)?;
    let comparison = compare(&aegis, &chrome);
    let verdict = verdict_for(&comparison);
    let not_claimed = not_claimed_for(&comparison);

    let result = json!({
        "schema_version": 1,
        "artifact": "chrome-like-tls-clienthello-local-compare",
        "verdict": verdict,
        "browser_identical_claimed": false,
        "host": args.host,
        "alpn": args.alpn,
        "aegis_backend": args.aegis_backend,
        "captures": {
            "aegis": capture_json(&aegis),
            "chrome": capture_json(&chrome),
        },
        "comparison": comparison,
        "not_claimed": not_claimed,
    });

    write_json(&args.output_dir.join("result.json"), &result)?;
    write_readme(&args.output_dir, verdict)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn capture_aegis_clienthello(
    args: &Args,
    timeout: Duration,
) -> Result<CapturedHello, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    let child = Command::new("cargo")
        .current_dir(&args.repo_root)
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("aegis-client")
        .arg("--features")
        .arg("chrome-like-tls")
        .arg("--")
        .arg("tls-probe")
        .arg("--addr")
        .arg(addr.to_string())
        .arg("--server-name")
        .arg(&args.host)
        .arg("--backend")
        .arg(&args.aegis_backend)
        .arg("--alpn")
        .arg(&args.alpn)
        .arg("--json")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    capture_from_listener(
        "aegis",
        child,
        listener,
        timeout,
        &args.output_dir,
        &args.tshark_bin,
    )
}

fn capture_chrome_clienthello(
    args: &Args,
    timeout: Duration,
) -> Result<CapturedHello, Box<dyn std::error::Error>> {
    let chrome_bin = chrome_bin(args.chrome_bin.as_deref())?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    let user_data_dir = temp_profile_dir("aegis-chrome-clienthello");
    fs::create_dir_all(&user_data_dir)?;
    let url = format!("https://{}:{}/", args.host, addr.port());
    let host_rule = format!("MAP {} 127.0.0.1,EXCLUDE localhost", args.host);
    let child = Command::new(chrome_bin)
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--disable-quic")
        .arg("--disable-background-networking")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--ignore-certificate-errors")
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--host-resolver-rules={host_rule}"))
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let capture = capture_from_listener(
        "chrome",
        child,
        listener,
        timeout,
        &args.output_dir,
        &args.tshark_bin,
    );
    let _ = fs::remove_dir_all(user_data_dir);
    capture
}

fn capture_from_listener(
    label: &'static str,
    mut child: Child,
    listener: TcpListener,
    timeout: Duration,
    output_dir: &Path,
    tshark_bin: &Path,
) -> Result<CapturedHello, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let record = loop {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(timeout_left(deadline)))?;
                break read_tls_record(&mut stream)?;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if let Some(status) = child.try_wait()? {
                    return Err(format!("{label} probe exited before ClientHello: {status}").into());
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{label} ClientHello capture timed out").into());
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(Box::new(err)),
        }
    };

    let _ = child.kill();
    let _ = child.wait();

    let raw_path = output_dir.join(format!("{label}-clienthello.raw"));
    let pcap_path = output_dir.join(format!("{label}-clienthello.pcap"));
    fs::write(&raw_path, &record)?;
    fs::write(&pcap_path, synthetic_pcap(&record))?;
    let classification = classify_tls_record(&record);
    let tshark = tshark_fields(&pcap_path, tshark_bin);

    Ok(CapturedHello {
        label,
        raw_path,
        pcap_path,
        classification,
        tshark,
    })
}

fn read_tls_record(stream: &mut std::net::TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    let mut record = header.to_vec();
    record.extend_from_slice(&body);
    Ok(record)
}

fn timeout_left(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::from_millis(1))
}

fn chrome_bin(explicit: Option<&Path>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let mac = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if mac.exists() {
        return Ok(mac);
    }
    Ok(PathBuf::from("google-chrome"))
}

fn temp_profile_dir(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}", std::process::id()))
}

fn tshark_fields(pcap_path: &Path, tshark_bin: &Path) -> Value {
    let output = Command::new(tshark_bin)
        .arg("-r")
        .arg(pcap_path)
        .arg("-d")
        .arg("tcp.port==443,tls")
        .arg("-Y")
        .arg("tls.handshake.type==1")
        .arg("-T")
        .arg("fields")
        .arg("-e")
        .arg("tls.handshake.ja3")
        .arg("-e")
        .arg("tls.handshake.ja3_full")
        .arg("-e")
        .arg("tls.handshake.ja4")
        .arg("-e")
        .arg("tls.handshake.ja4_r")
        .arg("-e")
        .arg("tls.handshake.extensions_server_name")
        .arg("-e")
        .arg("tls.handshake.extensions_alpn_str")
        .output();

    let Ok(output) = output else {
        return json!({"available": false, "error": "failed to execute tshark"});
    };
    if !output.status.success() {
        return json!({
            "available": false,
            "status": output.status.code(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or_default();
    let fields = line.split('\t').collect::<Vec<_>>();
    json!({
        "available": true,
        "ja3": field(&fields, 0),
        "ja3_full": field(&fields, 1),
        "ja4": field(&fields, 2),
        "ja4_r": field(&fields, 3),
        "sni": field(&fields, 4),
        "alpn": field(&fields, 5),
    })
}

fn field(fields: &[&str], index: usize) -> Value {
    fields
        .get(index)
        .filter(|value| !value.is_empty())
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
}

fn compare(aegis: &CapturedHello, chrome: &CapturedHello) -> Value {
    let aegis_tshark = &aegis.tshark;
    let chrome_tshark = &chrome.tshark;
    let aegis_ciphers_no_grease = without_grease(&aegis.classification.cipher_suites);
    let chrome_ciphers_no_grease = without_grease(&chrome.classification.cipher_suites);
    let aegis_extensions_no_grease = without_grease(&aegis.classification.extension_types);
    let chrome_extensions_no_grease = without_grease(&chrome.classification.extension_types);
    let aegis_groups_no_grease = without_grease(&aegis.classification.supported_groups);
    let chrome_groups_no_grease = without_grease(&chrome.classification.supported_groups);
    json!({
        "ja3_equal": aegis.classification.ja3 == chrome.classification.ja3,
        "ja3_md5_equal": aegis.classification.ja3_md5 == chrome.classification.ja3_md5,
        "ja4_equal": optional_equal(aegis_tshark.get("ja4"), chrome_tshark.get("ja4")),
        "ja4_r_equal": optional_equal(aegis_tshark.get("ja4_r"), chrome_tshark.get("ja4_r")),
        "cipher_suites_equal": aegis.classification.cipher_suites == chrome.classification.cipher_suites,
        "cipher_suites_without_grease_equal": aegis_ciphers_no_grease == chrome_ciphers_no_grease,
        "extension_types_equal": aegis.classification.extension_types == chrome.classification.extension_types,
        "extension_types_without_grease_order_equal": aegis_extensions_no_grease == chrome_extensions_no_grease,
        "extension_types_without_grease_set_equal": set_of(&aegis_extensions_no_grease) == set_of(&chrome_extensions_no_grease),
        "supported_groups_equal": aegis.classification.supported_groups == chrome.classification.supported_groups,
        "supported_groups_without_grease_equal": aegis_groups_no_grease == chrome_groups_no_grease,
        "alpn_equal": aegis.classification.alpn == chrome.classification.alpn,
        "sni_equal": aegis.classification.sni == chrome.classification.sni,
    })
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !aegis_fingerprint::grease::is_grease_value(*value))
        .collect()
}

fn set_of(values: &[u16]) -> BTreeSet<u16> {
    values.iter().copied().collect()
}

fn optional_equal(left: Option<&Value>, right: Option<&Value>) -> Value {
    match (left, right) {
        (Some(Value::String(a)), Some(Value::String(b))) => json!(a == b),
        (Some(Value::Null), _) | (_, Some(Value::Null)) | (None, _) | (_, None) => Value::Null,
        (Some(a), Some(b)) => json!(a == b),
    }
}

fn verdict_for(comparison: &Value) -> &'static str {
    let ja3_equal = comparison
        .get("ja3_equal")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ja4_equal = comparison.get("ja4_equal").and_then(Value::as_bool);
    if ja3_equal && ja4_equal == Some(true) {
        "MEASURED_JA3_JA4_MATCH_NO_BROWSER_IDENTICAL_CLAIM"
    } else {
        "MEASURED_MISMATCH"
    }
}

fn not_claimed_for(comparison: &Value) -> Vec<&'static str> {
    let mut claims = vec!["NOT_CLAIMED: browser-identical TLS"];
    if !comparison
        .get("ja3_equal")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        claims.push("NOT_CLAIMED: Chrome JA3 parity");
    }
    if comparison.get("ja4_equal").and_then(Value::as_bool) != Some(true) {
        claims.push("NOT_CLAIMED: Chrome JA4 parity");
    }
    claims.push("NOT_CLAIMED: universal anti-DPI");
    claims.push("NOT_CLAIMED: state-level ML traffic-analysis resistance");
    claims
}

fn capture_json(capture: &CapturedHello) -> Value {
    json!({
        "label": capture.label,
        "raw_path": capture.raw_path,
        "pcap_path": capture.pcap_path,
        "classification": capture.classification,
        "score": score_tls_classification(&capture.classification),
        "tshark": capture.tshark,
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::File::create(path)?;
    writeln!(file, "{}", serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn write_readme(output_dir: &Path, verdict: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = format!(
        "# Chrome-like TLS ClientHello Local Compare\n\n\
         Verdict: `{verdict}`.\n\n\
         This artifact captures a real AEGIS relay TLS ClientHello and a real Chrome ClientHello \
         against a local TCP listener, writes raw records and synthetic pcaps, and compares JA3/JA4 \
         evidence. It does not claim browser-identical TLS, universal bypass, or ML resistance.\n"
    );
    fs::write(output_dir.join("README.md"), text)?;
    Ok(())
}

fn synthetic_pcap(tls_record: &[u8]) -> Vec<u8> {
    let frame = ethernet_ipv4_tcp_frame(tls_record);
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(&frame);
    out
}

fn ethernet_ipv4_tcp_frame(payload: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[10, 0, 0, 10]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 20]);
    let ip_sum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&53_100u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
    tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x18;
    tcp[14..16].copy_from_slice(&64_240u16.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&ip[12..16]);
    pseudo.extend_from_slice(&ip[16..20]);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    pseudo.extend_from_slice(payload);
    let tcp_sum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
    frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame.extend_from_slice(payload);
    frame
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (u32::from(chunk[0])) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
