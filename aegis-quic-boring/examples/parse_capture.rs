//! Parse a QUIC Initial capture and print its ClientHello fingerprint.
//!
//! Input format: a sequence of `u32` big-endian length prefixes, each followed
//! by one raw UDP payload. That is what the capture helper in
//! `tests/chrome_live_ja4.rs` records, so an operator can fingerprint any
//! browser (or a suspicious client) offline:
//!
//! ```text
//! cargo run -p aegis-quic-boring --example parse_capture -- capture.bin
//! ```

use aegis_quic_boring::fingerprint::clienthello::parse;
use aegis_quic_boring::fingerprint::initial_packet::{decode_client_initial, CryptoStream};
use aegis_quic_boring::fingerprint::ja4::{compute, Transport};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/chrome_quic_pkts.bin".to_string());
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));

    let mut stream = CryptoStream::new();
    let mut pos = 0;
    let mut decoded = 0usize;
    while pos + 4 <= raw.len() {
        let len = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;
        let Some(datagram) = raw.get(pos..pos + len) else {
            break;
        };
        pos += len;
        if let Ok(pkt) = decode_client_initial(datagram) {
            decoded += 1;
            stream.push_packet(&pkt);
        }
    }

    let Some(msg) = stream.complete_message() else {
        eprintln!("no complete ClientHello ({decoded} Initial packets decoded)");
        std::process::exit(1);
    };
    let hello = parse(msg).expect("parse ClientHello");
    let ja4 = compute(&hello, Transport::Quic);

    println!("JA4      = {ja4}");
    println!("  sni      = {:?}", hello.server_name);
    println!("  ciphers  = {:04x?}", hello.cipher_suites);
    println!("  exts     = {:04x?}", hello.extensions);
    println!("  groups   = {:04x?}", hello.supported_groups);
    println!("  sigalgs  = {:04x?}", hello.signature_algorithms);
    println!("  alpn     = {:?}", hello.alpn);
}
