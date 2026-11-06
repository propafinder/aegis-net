use std::net::Ipv4Addr;

use aegis_witness::{
    capture::{select_source, InputSource},
    pcap::parse_pcap,
    tcp::extract_tcp_ipv4_payload,
};

fn client_hello_with_sni(hostname: &str) -> Vec<u8> {
    let host = hostname.as_bytes();
    let mut sni_inner = Vec::new();
    sni_inner.push(0x00);
    sni_inner.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_inner.extend_from_slice(host);

    let mut sni_value = Vec::new();
    sni_value.extend_from_slice(&(sni_inner.len() as u16).to_be_bytes());
    sni_value.extend_from_slice(&sni_inner);

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    sni_ext.extend_from_slice(&(sni_value.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_value);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    let mut handshake = vec![
        0x01,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn ethernet_ipv4_tcp(payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&443u16.to_be_bytes());
    tcp.extend_from_slice(&53100u16.to_be_bytes());
    tcp.extend_from_slice(&1u32.to_be_bytes());
    tcp.extend_from_slice(&1u32.to_be_bytes());
    tcp.push(5u8 << 4);
    tcp.push(0x18);
    tcp.extend_from_slice(&4096u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let total_len = 20 + tcp.len();
    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    ip.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
    eth.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

fn pcap_with_packet(packet: &[u8]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    pcap.extend_from_slice(packet);
    pcap
}

#[test]
fn parses_classic_pcap_and_extracts_tcp_payload() {
    let hello = client_hello_with_sni("relay.example");
    let packet = ethernet_ipv4_tcp(&hello);
    let pcap = pcap_with_packet(&packet);
    let parsed = parse_pcap(&pcap).expect("pcap");

    assert_eq!(parsed.link_type, 1);
    assert_eq!(parsed.packets.len(), 1);

    let tcp = extract_tcp_ipv4_payload(parsed.link_type, &parsed.packets[0].data).expect("tcp");
    assert_eq!(tcp.src_addr, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(tcp.dst_addr, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(tcp.payload, hello);
}

#[test]
fn capture_source_selects_pcap_file() {
    let source =
        select_source(None, None, Some("capture.pcap".into()), false, None).expect("source");

    assert_eq!(source, InputSource::PcapFile("capture.pcap".into()));
}

// These are synthetic parser controls, not independent capture evidence.
struct OwnedPcapFixture {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl OwnedPcapFixture {
    fn new(bytes: &[u8]) -> Self {
        use std::io::Write;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("aegis-witness-pcap-{}-{id}", std::process::id()));
        std::fs::create_dir(&dir).expect("fresh owned fixture directory");
        let path = dir.join("input.pcap");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("fresh fixture file");
        file.write_all(bytes).expect("fixture bytes");
        Self { dir, path }
    }

    fn records(
        &self,
    ) -> Result<Vec<aegis_witness::capture::CapturedRecord>, aegis_witness::capture::CaptureError>
    {
        InputSource::PcapFile(self.path.clone()).read_records()
    }
}

impl Drop for OwnedPcapFixture {
    fn drop(&mut self) {
        // Remove only known owned leaves; no recursive cleanup of ambient paths.
        for name in ["input.pcap", "events.jsonl", "summary.json", "summary.md"] {
            let _ = std::fs::remove_file(self.dir.join(name));
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn pcap_with_packets(link_type: u32, packets: &[Vec<u8>]) -> Vec<u8> {
    let mut pcap = pcap_with_packet(&[]);
    pcap.truncate(24);
    pcap[20..24].copy_from_slice(&link_type.to_le_bytes());
    for packet in packets {
        pcap.extend_from_slice(&[0; 8]);
        pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        pcap.extend_from_slice(packet);
    }
    pcap
}

fn ipv6_ethernet_packet() -> Vec<u8> {
    let mut packet = vec![0; 14 + 40];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    packet
}

fn assert_pcap_refuses(link_type: u32, packets: &[Vec<u8>], reason: &str) {
    let fixture = OwnedPcapFixture::new(&pcap_with_packets(link_type, packets));
    let error = fixture
        .records()
        .expect_err("unsupported input must not become a TLS-negative or empty success");
    assert_eq!(
        error.to_string(),
        reason,
        "unexpected complete refusal cause"
    );
}

#[test]
fn audit68_complete_single_payload_retains_existing_classification() {
    let hello = client_hello_with_sni("relay.example");
    let fixture = OwnedPcapFixture::new(&pcap_with_packets(1, &[ethernet_ipv4_tcp(&hello)]));
    let records = fixture.records().expect("supported complete payload");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].bytes, hello);
    assert!(
        aegis_witness::classify_tls::classify_tls_record(&records[0].bytes).is_tls_client_hello
    );
}

#[test]
fn audit68_empty_and_ack_only_captures_are_distinct_refusals() {
    assert_pcap_refuses(1, &[], "PCAP input contains no packets");
    assert_pcap_refuses(
        1,
        &[ethernet_ipv4_tcp(&[])],
        "PCAP input contains no supported nonempty TCP payloads",
    );
}

#[test]
fn audit68_unsupported_sll2_and_ipv6_do_not_become_empty_success() {
    assert_pcap_refuses(
        276,
        &[],
        "failed to decode PCAP packet: unsupported PCAP link type 276",
    );
    assert_pcap_refuses(
        276,
        &[vec![0; 20]],
        "failed to decode PCAP packet: unsupported PCAP link type 276",
    );
    assert_pcap_refuses(
        1,
        &[ipv6_ethernet_packet()],
        "failed to decode PCAP packet: IPv6 PCAP payloads are unsupported",
    );
    let mut raw_v6 = vec![0; 40];
    raw_v6[0] = 0x60;
    assert_pcap_refuses(
        101,
        &[raw_v6],
        "failed to decode PCAP packet: IPv6 PCAP payloads are unsupported",
    );
}

#[test]
fn audit68_mixed_supported_and_ipv6_refuses_whole_input() {
    let hello = client_hello_with_sni("relay.example");
    assert_pcap_refuses(
        1,
        &[ethernet_ipv4_tcp(&hello), ipv6_ethernet_packet()],
        "failed to decode PCAP packet: IPv6 PCAP payloads are unsupported",
    );
}

#[test]
fn audit68_split_handshake_and_out_of_order_segments_refuse_reassembly() {
    let hello = client_hello_with_sni("relay.example");
    let split = hello.len() / 2;
    let first = ethernet_ipv4_tcp(&hello[..split]);
    let mut last = ethernet_ipv4_tcp(&hello[split..]);
    last[38..42].copy_from_slice(&(1 + split as u32).to_be_bytes());
    assert_pcap_refuses(
        1,
        &[first.clone(), last.clone()],
        "TCP stream reassembly is unsupported (second payload at packet 1)",
    );
    assert_pcap_refuses(
        1,
        &[last, first],
        "TCP stream reassembly is unsupported (second payload at packet 1)",
    );
}

#[test]
fn audit68_retransmit_refuses_duplicate_packet_classification() {
    let hello = client_hello_with_sni("relay.example");
    let packet = ethernet_ipv4_tcp(&hello);
    assert_pcap_refuses(
        1,
        &[packet.clone(), packet],
        "TCP stream reassembly is unsupported (second payload at packet 1)",
    );
}

#[test]
fn audit68_incomplete_coalesced_and_opaque_payloads_are_not_tls_negatives() {
    let hello = client_hello_with_sni("relay.example");
    assert_pcap_refuses(1, &[ethernet_ipv4_tcp(&hello[..hello.len() - 1])], "PCAP packet 0 requires unsupported TLS framing: split, truncated, or coalesced TLS records");
    let mut coalesced = hello.clone();
    coalesced.extend_from_slice(&hello);
    assert_pcap_refuses(1, &[ethernet_ipv4_tcp(&coalesced)], "PCAP packet 0 requires unsupported TLS framing: split, truncated, or coalesced TLS records");
    assert_pcap_refuses(1, &[ethernet_ipv4_tcp(b"GET / HTTP/1.1\r\n\r\n")], "PCAP packet 0 requires unsupported TLS framing: payload is not a complete supported TLS record");
}

#[test]
fn audit68_tls_handshake_fragmentation_refuses_complete_record_false_negative() {
    let mut fragmented = client_hello_with_sni("relay.example");
    fragmented.pop();
    let record_len = (fragmented.len() - 5) as u16;
    fragmented[3..5].copy_from_slice(&record_len.to_be_bytes());
    assert_pcap_refuses(
        1,
        &[ethernet_ipv4_tcp(&fragmented)],
        "PCAP packet 0 requires unsupported TLS framing: split or coalesced TLS handshake messages",
    );
}

#[test]
fn audit68_ipv4_more_fragments_and_later_fragment_are_refused() {
    let hello = client_hello_with_sni("relay.example");
    let mut first_fragment = ethernet_ipv4_tcp(&hello);
    first_fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    let mut later_fragment = ethernet_ipv4_tcp(&hello);
    later_fragment[20..22].copy_from_slice(&1u16.to_be_bytes());
    assert_pcap_refuses(
        1,
        &[first_fragment],
        "failed to decode PCAP packet: IPv4 fragmentation is unsupported",
    );
    assert_pcap_refuses(
        1,
        &[later_fragment],
        "failed to decode PCAP packet: IPv4 fragmentation is unsupported",
    );
}

#[test]
fn audit68_truncated_supported_frames_refuse_instead_of_disappearing() {
    assert_pcap_refuses(
        1,
        &[vec![0; 13]],
        "failed to decode PCAP packet: malformed PCAP frame: short Ethernet header",
    );
    let hello = client_hello_with_sni("relay.example");
    let mut truncated = ethernet_ipv4_tcp(&hello);
    truncated.pop();
    assert_pcap_refuses(
        1,
        &[truncated],
        "failed to decode PCAP packet: malformed PCAP frame: invalid IPv4 total length",
    );
}

#[test]
fn audit68_independent_directional_flows_remain_supported() {
    let hello = client_hello_with_sni("relay.example");
    let first = ethernet_ipv4_tcp(&hello);
    let mut second = ethernet_ipv4_tcp(&hello);
    second[34..36].copy_from_slice(&444u16.to_be_bytes());
    let fixture = OwnedPcapFixture::new(&pcap_with_packets(1, &[first, second]));
    assert_eq!(
        fixture
            .records()
            .expect("two distinct directional flows")
            .len(),
        2
    );
}

fn assert_cli_refusal_preserves_outputs(existing: bool) {
    use std::io::Write;
    let fixture = OwnedPcapFixture::new(&pcap_with_packets(276, &[vec![0; 20]]));
    let names = ["events.jsonl", "summary.json", "summary.md"];
    let mut previous_metadata = Vec::new();
    if existing {
        for name in names {
            let path = fixture.dir.join(name);
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .expect("fresh owned sentinel");
            file.write_all(b"existing-private-evidence\n")
                .expect("sentinel bytes");
            drop(file);
            previous_metadata
                .push(std::fs::symlink_metadata(path).expect("owned sentinel metadata"));
        }
    }

    // Cargo selects the actual package binary for this integration test. This
    // is not a PATH substitute or a test-only emulator of the CLI authority.
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_aegis-witness"))
        .canonicalize()
        .expect("actual Cargo-provided witness executable");
    let expected_name = format!("aegis-witness{}", std::env::consts::EXE_SUFFIX);
    assert_eq!(
        executable.file_name().and_then(|name| name.to_str()),
        Some(expected_name.as_str())
    );
    assert!(std::fs::symlink_metadata(&executable)
        .expect("executable metadata")
        .file_type()
        .is_file());
    let executable_before = std::fs::read(&executable).expect("actual executable bytes");
    assert!(
        !executable_before.is_empty(),
        "actual binary must not be empty"
    );

    let child = std::process::Command::new(&executable)
        .arg("--input-pcap")
        .arg(&fixture.path)
        .arg("--output-jsonl")
        .arg(fixture.dir.join(names[0]))
        .arg("--summary-json")
        .arg(fixture.dir.join(names[1]))
        .arg("--summary-markdown")
        .arg(fixture.dir.join(names[2]))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start actual witness CLI");
    let child_pid = child.id();
    // wait_with_output waits for and reaps this direct child. It is not a
    // process-tree custody or native capture acceptance claim.
    let output = child
        .wait_with_output()
        .expect("wait and reap actual witness CLI");
    assert_eq!(
        output.status.code(),
        Some(1),
        "exact PCAP refusal exit status"
    );
    // main returns Result<(), Box<dyn Error>>; CaptureError and the nested
    // TcpPayloadError derive Debug. Their SLL2 cause is this exact stderr.
    assert_eq!(
        output.stderr.as_slice(),
        b"Error: PcapDecode(UnsupportedLinkType(276))\n",
        "exact PCAP refusal cause"
    );
    assert!(
        output.stdout.is_empty(),
        "refusal must not emit partial classification"
    );
    assert!(
        std::fs::read(&executable).expect("executable bytes after wait") == executable_before,
        "Cargo-provided executable bytes must remain unchanged"
    );

    for (index, name) in names.iter().enumerate() {
        let path = fixture.dir.join(name);
        if existing {
            let metadata = std::fs::symlink_metadata(&path).expect("sentinel retained");
            assert!(
                metadata.file_type().is_file(),
                "sentinel must stay a regular file"
            );
            assert_eq!(
                std::fs::read(&path).expect("sentinel bytes retained"),
                b"existing-private-evidence\n"
            );
            let previous = &previous_metadata[index];
            assert_eq!(metadata.len(), previous.len());
            assert_eq!(
                metadata.modified().expect("sentinel mtime"),
                previous.modified().expect("original mtime")
            );
            assert_eq!(
                metadata.permissions().readonly(),
                previous.permissions().readonly()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(
                    (metadata.dev(), metadata.ino()),
                    (previous.dev(), previous.ino()),
                    "owned output object identity must remain unchanged"
                );
            }
        } else {
            assert!(
                matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "refusal must not create any output leaf, including a dangling symlink"
            );
        }
    }
    // A runtime receipt from the genuine subprocess, emitted only after the
    // exact status/cause/byte/metadata checks above. The supervisor owns the
    // enclosing run; this receipt covers only this direct child's completed wait.
    eprintln!(
        "AUDIT68_CLI_REFUSAL_RECEIPT {}",
        serde_json::json!({
            "schema": "aegis.audit68.cli-refusal-control.v1",
            "cargo_executable_name": expected_name,
            "executable_bytes_before": executable_before.len(),
            "executable_bytes_unchanged_after_wait": true,
            "child_pid": child_pid,
            "direct_child_wait_returned": true,
            "exit_code": output.status.code(),
            "stderr_exact_sll2_cause": true,
            "stdout_bytes": output.stdout.len(),
            "existing_output_case": existing,
            "output_leaves_checked": names.len(),
            "output_bytes_and_metadata_preserved": existing,
            "unix_output_object_identity_checked": existing && cfg!(unix),
            "late_mixed_frame_cli_control": false,
            "independent_capture_acceptance": false
        })
    );
}

#[test]
fn audit68_cli_refusal_creates_no_outputs() {
    assert_cli_refusal_preserves_outputs(false);
}

#[test]
fn audit68_cli_refusal_preserves_existing_outputs() {
    assert_cli_refusal_preserves_outputs(true);
}
