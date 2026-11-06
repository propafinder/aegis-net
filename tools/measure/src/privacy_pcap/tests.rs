use super::*;

fn ip_packet(v6: bool, udp: bool, length: usize, reverse: bool) -> Vec<u8> {
    let header = if v6 { 40 } else { 20 };
    let mut packet = vec![0; length];
    let (source, destination) = if reverse { (2, 1) } else { (1, 2) };
    if v6 {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
        packet[6] = if udp { 17 } else { 6 };
        packet[8..24].copy_from_slice(
            &format!("2001:db8::{source}")
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[24..40].copy_from_slice(
            &format!("2001:db8::{destination}")
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
    } else {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[9] = if udp { 17 } else { 6 };
        packet[12..16].copy_from_slice(&[192, 0, 2, source]);
        packet[16..20].copy_from_slice(&[192, 0, 2, destination]);
    }
    let (source_port, destination_port) = if reverse {
        (8443u16, 12000u16)
    } else {
        (12000, 8443)
    };
    packet[header..header + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[header + 2..header + 4].copy_from_slice(&destination_port.to_be_bytes());
    if udp {
        packet[header + 4..header + 6].copy_from_slice(&((length - header) as u16).to_be_bytes());
    } else {
        packet[header + 12] = 0x50;
    }
    packet
}
fn ethernet(ip: &[u8], tags: usize) -> Vec<u8> {
    let mut frame = vec![0; 12];
    for _ in 0..tags {
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
    }
    frame.extend_from_slice(&(if ip[0] >> 4 == 4 { 0x0800u16 } else { 0x86dd }).to_be_bytes());
    frame.extend_from_slice(ip);
    frame
}
fn u16_bytes(endian: Endian, value: u16) -> [u8; 2] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}
fn u32_bytes(endian: Endian, value: u32) -> [u8; 4] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}
fn pcap(endian: Endian, nanos: bool, link: u32, records: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&u32_bytes(
        endian,
        if nanos { 0xa1b23c4d } else { 0xa1b2c3d4 },
    ));
    data.extend_from_slice(&u16_bytes(endian, 2));
    data.extend_from_slice(&u16_bytes(endian, 4));
    data.extend_from_slice(&u32_bytes(endian, 0));
    data.extend_from_slice(&u32_bytes(endian, 0));
    // Real capture defaults can exceed the accepted individual frame length.
    data.extend_from_slice(&u32_bytes(endian, 262144));
    data.extend_from_slice(&u32_bytes(endian, link));
    for (sec, fraction, frame) in records {
        data.extend_from_slice(&u32_bytes(endian, *sec));
        data.extend_from_slice(&u32_bytes(endian, *fraction));
        data.extend_from_slice(&u32_bytes(endian, frame.len() as u32));
        data.extend_from_slice(&u32_bytes(endian, frame.len() as u32));
        data.extend_from_slice(frame);
    }
    data
}
fn export(data: &[u8]) -> Result<Converted, &'static str> {
    convert(data, MAX_OUTPUT, MAX_RECORDS)
}

#[test]
fn endian_and_exact_time_resolution_preserve_identical_rows_and_content_bindings() {
    let frame = ip_packet(false, false, 50, false);
    let mut expected = None;
    for endian in [Endian::Little, Endian::Big] {
        for nanos in [false, true] {
            let input = pcap(
                endian,
                nanos,
                101,
                &[(1, if nanos { 123_000 } else { 123 }, frame.clone())],
            );
            let result = export(&input).unwrap();
            let text = std::str::from_utf8(&result.tsv).unwrap();
            assert!(text.starts_with(crate::privacy_study::PACKET_ROWS_V1_HEADER));
            assert!(text.contains("\n1000123\t50\t50\t192.0.2.1\t192.0.2.2\ttcp\t12000\t8443\n"));
            assert_eq!(result.summary["input_pcap_sha256"], digest(&input));
            assert_eq!(result.summary["output_tsv_sha256"], digest(&result.tsv));
            if let Some(expected) = &expected {
                assert_eq!(&result.tsv, expected);
            } else {
                expected = Some(result.tsv);
            }
            let summary = result.summary.to_string();
            assert!(!summary.contains("192.0.2."));
            assert_eq!(result.summary["capture_origin_verified"], false);
            assert_eq!(result.summary["complete_capture_interval_verified"], false);
        }
    }
}

#[test]
fn both_ip_families_and_transports_support_vlan_and_full_record_length_with_padding() {
    for v6 in [false, true] {
        for udp in [false, true] {
            for tags in 0..=2 {
                let raw = ip_packet(v6, udp, if v6 { 64 } else { 40 }, true);
                let mut frame = ethernet(&raw, tags);
                frame.extend_from_slice(&[0; 5]);
                let result =
                    export(&pcap(Endian::Little, false, 1, &[(2, 3, frame.clone())])).unwrap();
                let row = std::str::from_utf8(&result.tsv)
                    .unwrap()
                    .lines()
                    .nth(1)
                    .unwrap();
                let fields: Vec<_> = row.split('\t').collect();
                assert_eq!(fields[1], frame.len().to_string());
                assert_eq!(fields[2], fields[1]);
                assert_eq!(fields[5], if udp { "udp" } else { "tcp" });
                assert_eq!((fields[6], fields[7]), ("8443", "12000"));
                assert_eq!(result.summary["declared_frame_bytes"], frame.len());
                assert_eq!(result.summary["physical_wire_frame_size_verified"], false);
            }
        }
    }
}

#[test]
fn invalid_header_link_flags_empty_and_partial_record_are_whole_input_refusals() {
    let valid = pcap(
        Endian::Little,
        false,
        101,
        &[(1, 0, ip_packet(false, false, 50, false))],
    );
    for cut in [0, 4, 23, 25, 39, valid.len() - 1] {
        assert!(export(&valid[..cut]).is_err());
    }
    for (offset, replacement) in [(0, 0u32), (16, 0), (20, 276), (20, 101 | (1 << 26))] {
        let mut input = valid.clone();
        input[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(export(&input).is_err());
    }
    let mut input = valid.clone();
    input[4] = 3;
    assert!(export(&input).is_err());
    let mut input = valid.clone();
    input.push(0);
    assert!(export(&input).is_err());
    assert!(export(&pcap(Endian::Big, false, 101, &[])).is_err());
    let mut input = valid;
    // Record original/captured length disagreement is never silently repaired.
    input[36..40].copy_from_slice(&49u32.to_le_bytes());
    assert!(export(&input).is_err());
}

#[test]
fn invalid_fraction_precision_snapshots_and_timestamp_order_are_refused_without_rounding() {
    let frame = ip_packet(false, true, 40, false);
    for (nanos, fraction) in [(false, 1_000_000), (true, 1_000_000_000), (true, 1001)] {
        assert!(export(&pcap(
            Endian::Big,
            nanos,
            101,
            &[(1, fraction, frame.clone())]
        ))
        .is_err());
    }
    let mut input = pcap(Endian::Little, false, 101, &[(1, 0, frame.clone())]);
    input[16..20].copy_from_slice(&39u32.to_le_bytes());
    assert!(export(&input).is_err());
    let input = pcap(
        Endian::Little,
        false,
        101,
        &[(1, 2, frame.clone()), (1, 1, frame.clone())],
    );
    assert!(export(&input).is_err());
    let input = pcap(
        Endian::Little,
        false,
        101,
        &[(1, 2, frame.clone()), (1, 2, frame)],
    );
    let result = export(&input).unwrap();
    assert_eq!(result.summary["rows_emitted"], 2);
    assert_eq!(result.summary["first_observed_packet_unix_us"], 1000002);
    assert_eq!(result.summary["last_observed_packet_unix_us"], 1000002);
}

#[test]
fn fragments_extensions_and_unsupported_protocols_are_not_skipped() {
    for flags in [0x2000u16, 1, 0x8000] {
        let mut frame = ip_packet(false, false, 50, false);
        frame[6..8].copy_from_slice(&flags.to_be_bytes());
        assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
    }
    let mut df = ip_packet(false, false, 50, false);
    df[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, df)])).is_ok());
    for protocol in [0, 43, 44, 58, 59, 60] {
        let mut frame = ip_packet(true, false, 64, false);
        frame[6] = protocol;
        assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
    }
    let good = ethernet(&ip_packet(false, false, 50, false), 0);
    let mut arp = good.clone();
    arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    assert!(export(&pcap(
        Endian::Little,
        false,
        1,
        &[(1, 0, good), (1, 1, arp)]
    ))
    .is_err());
    let nested = ethernet(&ip_packet(false, false, 50, false), 3);
    assert!(export(&pcap(Endian::Little, false, 1, &[(1, 0, nested)])).is_err());
}

#[test]
fn ip_transport_internal_lengths_and_endpoints_refuse_malformed_complete_records() {
    let valid = ip_packet(false, false, 50, false);
    for (offset, value) in [(0, 0x44), (9, 1), (32, 0x40), (32, 0xf0)] {
        let mut frame = valid.clone();
        frame[offset] = value;
        assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
    }
    for length in [19u16, 51] {
        let mut frame = valid.clone();
        frame[2..4].copy_from_slice(&length.to_be_bytes());
        assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
    }
    let mut udp = ip_packet(false, true, 40, false);
    udp[24..26].copy_from_slice(&8u16.to_be_bytes());
    assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, udp)])).is_err());
    let mut frame = valid.clone();
    frame[20..22].fill(0);
    assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
    let mut frame = valid;
    frame.push(0);
    assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
    let mut frame = ip_packet(true, true, 64, false);
    frame[4..6].fill(0);
    assert!(export(&pcap(Endian::Little, false, 101, &[(1, 0, frame)])).is_err());
}

#[test]
fn cumulative_byte_and_record_budgets_apply_before_any_output_file_is_created() {
    let input = pcap(
        Endian::Little,
        false,
        101,
        &[
            (1, 1, ip_packet(false, false, 50, false)),
            (1, 2, ip_packet(true, true, 64, true)),
        ],
    );
    let baseline = export(&input).unwrap();
    let exact = convert(&input, baseline.tsv.len(), 2).unwrap();
    assert_eq!(exact.tsv, baseline.tsv);
    assert!(convert(&input, baseline.tsv.len() - 1, 2).is_err());
    assert!(convert(&input, MAX_OUTPUT, 1).is_err());
    assert!(convert(&input, MAX_OUTPUT + 1, 2).is_err());
    assert!(convert(&input, MAX_OUTPUT, MAX_RECORDS + 1).is_err());
    let oversized = vec![0; MAX_INPUT + 1];
    assert!(export(&oversized).is_err());
}

fn private_directory() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "aegis-synthetic-pcap-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}
#[test]
fn native_private_consumer_hashes_output_and_preserves_existing_attempts_without_path_echo() {
    let directory = private_directory();
    let input = directory.join("input.pcap");
    let output = directory.join("new.tsv");
    let data = pcap(
        Endian::Little,
        false,
        101,
        &[(1, 2, ip_packet(false, false, 50, false))],
    );
    aegis_core::secret_file::write_private_new(&input, &data).unwrap();
    let report = run(&input, &output).unwrap();
    let out = aegis_core::secret_file::read(&output, MAX_OUTPUT as u64).unwrap();
    assert_eq!(report["input_pcap_sha256"], digest(&data));
    assert_eq!(report["output_tsv_sha256"], digest(&out));
    assert!(!report.to_string().contains(directory.to_str().unwrap()));
    assert!(!report.to_string().contains("192.0.2."));
    assert!(run(&input, &output).is_err());
    assert_eq!(
        &**aegis_core::secret_file::read(&output, MAX_OUTPUT as u64).unwrap(),
        &**out
    );
    let bad = directory.join("bad.pcap");
    aegis_core::secret_file::write_private_new(&bad, &data[..data.len() - 1]).unwrap();
    let refused = directory.join("refused.tsv");
    let error = run(&bad, &refused).unwrap_err();
    assert!(!error.contains(directory.to_str().unwrap()));
    assert!(!refused.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn private_descriptor_reader_and_create_new_writer_refuse_links_public_files_and_writable_ancestry()
{
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = private_directory();
    let input = directory.join("input.pcap");
    let output = directory.join("new.tsv");
    let data = pcap(
        Endian::Little,
        false,
        101,
        &[(1, 2, ip_packet(false, false, 50, false))],
    );
    aegis_core::secret_file::write_private_new(&input, &data).unwrap();
    let link = directory.join("link.pcap");
    symlink(&input, &link).unwrap();
    assert!(run(&link, &output).is_err());
    assert!(!output.exists());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(run(&input, &output).is_err());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&input, &output).unwrap();
    assert!(run(&input, &output).is_err());
    assert_eq!(std::fs::read(&input).unwrap(), data);
    std::fs::remove_file(&output).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(run(&input, &output).is_err());
    assert!(!output.exists());
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
