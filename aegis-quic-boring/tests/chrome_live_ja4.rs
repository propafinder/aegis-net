//! Measure a **live Chrome** QUIC ClientHello and diff it against ours.
//!
//! No packet capture and no root: Chrome is pointed at a local UDP socket with
//! `--origin-to-force-quic-on`, and its Initial packet is decrypted with the
//! RFC 9001 Initial keys derived from the DCID it puts in the clear. The
//! handshake then dies (we never answer) — the ClientHello is all we need.
//!
//! Ignored by default because it needs Chrome installed; run with:
//! `cargo test -p aegis-quic-boring --features boring --test chrome_live_ja4 -- --ignored --nocapture`

#![cfg(feature = "boring")]

use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use aegis_quic_boring::config::ctx::Trust;
use aegis_quic_boring::fingerprint::clienthello::{parse, ClientHello};
use aegis_quic_boring::fingerprint::initial_packet::{decode_client_initial, CryptoStream};
use aegis_quic_boring::fingerprint::ja4::{compute, Ja4, Transport};
use aegis_quic_boring::session::client_config::ChromeQuicClientConfig;
use quinn_proto::crypto::ClientConfig;
use quinn_proto::transport_parameters::TransportParameters;

const CHROMIUM_BROWSER_CANDIDATES: &[&str] = &[
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
];

fn chrome_binary() -> Option<&'static str> {
    CHROMIUM_BROWSER_CANDIDATES
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).exists())
}

/// Chrome's QUIC ClientHello, captured off a local UDP socket.
fn capture_chrome_hello(chrome: &str) -> ClientHello {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind capture socket");
    let port = socket.local_addr().unwrap().port();
    socket
        .set_read_timeout(Some(Duration::from_secs(25)))
        .unwrap();

    let profile = tempfile::Builder::new()
        .prefix("aegis-chrome-ja4-")
        .tempdir()
        .unwrap();

    let mut command = Command::new(chrome);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child: Child = command
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--disable-background-networking",
            "--enable-quic",
            &format!("--user-data-dir={}", profile.path().display()),
            &format!("--origin-to-force-quic-on=127.0.0.1:{port}"),
            "--ignore-certificate-errors",
            &format!("https://127.0.0.1:{port}/"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Chrome");

    // The hello spans several Initial packets, so keep reading until the
    // CRYPTO stream holds a complete handshake message.
    let mut buf = vec![0u8; 2048];
    let mut stream = CryptoStream::new();
    let mut hello_bytes = None;
    let mut decoded_packets = 0usize;

    while let Ok((len, _)) = socket.recv_from(&mut buf) {
        // Use the datagram's real length: `buf` keeps bytes from earlier reads
        // past `len`, and feeding those to the decoder is how a capture test
        // turns flaky.
        let Ok(pkt) = decode_client_initial(&buf[..len]) else {
            continue;
        };
        decoded_packets += 1;
        stream.push_packet(&pkt);
        if let Some(msg) = stream.complete_message() {
            hello_bytes = Some(msg.to_vec());
            break;
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let bytes = hello_bytes.unwrap_or_else(|| {
        panic!("no complete ClientHello from Chrome ({decoded_packets} Initial packets decoded)")
    });
    parse(&bytes).expect("parse Chrome's ClientHello")
}

/// Our own QUIC ClientHello.
fn our_hello() -> ClientHello {
    let config = Arc::new(
        ChromeQuicClientConfig::new(vec![b"h3".to_vec()], Trust::System).expect("build config"),
    );
    let encoded: &[u8] = &[0x04, 0x02, 0x43, 0xe8];
    let params = TransportParameters::read(quinn_proto::Side::Server, &mut &encoded[..]).unwrap();
    // Same destination form as the capture: a literal IP, so neither side
    // sends SNI and the fingerprints are directly comparable.
    let mut session = config.start_session(1, "127.0.0.1", &params).unwrap();
    let mut buf = Vec::new();
    session.write_handshake(&mut buf);
    parse(&buf).expect("parse our ClientHello")
}

fn report(label: &str, hello: &ClientHello, ja4: &Ja4) {
    println!("--- {label} ---");
    println!("  JA4      = {ja4}");
    println!("  ciphers  = {}", ja4.cipher_input);
    println!("  ext+sig  = {}", ja4.extension_input);
    println!("  groups   = {:04x?}", hello.supported_groups);
    println!("  alpn     = {:?}", hello.alpn);
    println!("  raw ciphers = {:04x?}", hello.cipher_suites);
    println!("  raw exts    = {:04x?}", hello.extensions);
}

#[test]
#[ignore = "requires a local Chrome install"]
fn quic_ja4_matches_live_chrome() {
    let Some(chrome) = chrome_binary() else {
        panic!("no Chromium-family browser found in {CHROMIUM_BROWSER_CANDIDATES:?}");
    };

    let chrome_hello = capture_chrome_hello(chrome);
    let ours = our_hello();

    let chrome_ja4 = compute(&chrome_hello, Transport::Quic);
    let our_ja4 = compute(&ours, Transport::Quic);

    report("live Chromium-family browser", &chrome_hello, &chrome_ja4);
    report("AEGIS", &ours, &our_ja4);

    assert_eq!(
        our_ja4.cipher_input, chrome_ja4.cipher_input,
        "cipher list differs from live Chrome"
    );
    assert_eq!(
        our_ja4.extension_input, chrome_ja4.extension_input,
        "extension/sigalg list differs from live Chrome"
    );
    assert_eq!(
        our_ja4.to_string(),
        chrome_ja4.to_string(),
        "JA4 differs from live Chrome"
    );

    // JA4 filters GREASE, so compare the raw lists too: a byte-level classifier
    // sees values JA4 hides.
    assert_eq!(
        ours.cipher_suites, chrome_hello.cipher_suites,
        "raw cipher list (GREASE included) differs from live Chrome"
    );
    assert_eq!(
        ours.supported_groups, chrome_hello.supported_groups,
        "raw supported_groups (GREASE included) differs from live Chrome"
    );
    assert_eq!(
        ours.signature_algorithms, chrome_hello.signature_algorithms,
        "signature algorithms differ from live Chrome"
    );
    let mut our_exts = ours.extensions.clone();
    let mut chrome_exts = chrome_hello.extensions.clone();
    our_exts.sort_unstable();
    chrome_exts.sort_unstable();
    assert_eq!(
        our_exts, chrome_exts,
        "extension set (GREASE included, order ignored) differs from live Chrome"
    );
}
