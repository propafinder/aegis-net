//! Контракт видимости: магия AEG1 не является TLS record header; в relay она уходит
//! только в TLS application data (после handshake), не в открытом виде как первые байты TCP.

use aegis_core::relay::{encode_relay_request, RelayRequest, RELAY_REQ_MAGIC};

#[test]
fn relay_magic_is_not_tls_record_type() {
    let f = encode_relay_request(&RelayRequest {
        auth: vec![b'x'; 8],
        host: "example.com".into(),
        port: 443,
    });
    assert_eq!(&f[..4], RELAY_REQ_MAGIC);
    // TLS record: handshake 0x16, change_cipher_spec 0x14, alert 0x15, application 0x17
    assert_ne!(f[0], 0x16);
    assert_ne!(f[0], 0x17);
}
