//! Кодек Relay: roundtrip и негативные кейсы.

use aegis_core::relay::{
    decode_relay_request, decode_relay_response, encode_relay_request, encode_relay_response,
    RelayRequest, RelayStatus,
};

#[test]
fn relay_request_roundtrip_variants() {
    let cases = vec![
        RelayRequest {
            auth: vec![],
            host: "a".into(),
            port: 1,
        },
        RelayRequest {
            auth: b"secret-token-xyz".to_vec(),
            host: "example.com".into(),
            port: 443,
        },
        RelayRequest {
            auth: vec![0xff; 256],
            host: "тест.example".into(),
            port: 65535,
        },
    ];
    for req in cases {
        let bytes = encode_relay_request(&req);
        let got = decode_relay_request(&bytes).expect("decode");
        assert_eq!(got.auth, req.auth);
        assert_eq!(got.host, req.host);
        assert_eq!(got.port, req.port);
    }
}

#[test]
fn relay_response_roundtrip() {
    for (st, msg) in [
        (RelayStatus::Ok, None),
        (RelayStatus::AuthFailed, Some("bad")),
        (RelayStatus::BadTarget, Some("nxdomain")),
    ] {
        let b = encode_relay_response(st, msg);
        let (g, m) = decode_relay_response(&b).expect("decode resp");
        assert_eq!(g as u8, st as u8);
        assert_eq!(m, msg.unwrap_or(""));
    }
}

#[test]
fn relay_reject_bad_magic() {
    let mut b = encode_relay_request(&RelayRequest {
        auth: vec![],
        host: "x".into(),
        port: 80,
    });
    b[0] = 0xff;
    assert!(decode_relay_request(&b).is_err());
}
