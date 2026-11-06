#[path = "src/preface.rs"]
mod preface;

fn main() {
    println!("cargo:rerun-if-changed=chrome-stable.toml");
    println!("cargo:rerun-if-changed=fixtures/h2-connection-preface.hex");
    println!("cargo:rerun-if-changed=src/preface.rs");
    let text = std::fs::read_to_string("chrome-stable.toml").expect("read chrome profile");
    let value: toml::Value = toml::from_str(&text).expect("chrome profile toml");
    let table = value.as_table().expect("chrome profile table");
    for key in [
        "schema",
        "measured_chrome",
        "measured_on",
        "user_agent",
        "tls",
        "quic",
        "http2",
    ] {
        assert!(table.contains_key(key), "chrome profile missing {key}");
    }
    assert_eq!(table["schema"].as_integer(), Some(1), "schema must be 1");
    let http2 = table["http2"].as_table().expect("http2 table");
    let window = u32::try_from(
        http2["connection_window_increment"]
            .as_integer()
            .expect("connection window"),
    )
    .expect("connection window fits u32");
    let settings = http2["settings"]
        .as_array()
        .expect("http2 settings")
        .iter()
        .map(|item| {
            let item = item.as_table().expect("setting");
            let id = u16::try_from(item["id"].as_integer().expect("setting id"))
                .expect("setting id fits u16");
            let value = u32::try_from(item["value"].as_integer().expect("setting value"))
                .expect("setting value fits u32");
            (id, value)
        })
        .collect::<Vec<_>>();
    assert!(!settings.is_empty(), "http2 settings are empty");
    let encoded = preface::connection_preface(&settings, window);
    let fixture = std::fs::read_to_string("fixtures/h2-connection-preface.hex").expect("fixture");
    let fixture = decode_hex(fixture.trim());
    assert_eq!(
        encoded, fixture,
        "HTTP/2 preface fixture does not match chrome-stable.toml"
    );
    let tls = table["tls"].as_table().expect("tls table");
    let quic = table["quic"].as_table().expect("quic table");
    assert!(tls["grease"].as_bool().is_some());
    assert!(quic["grease"].as_bool().is_some());
    assert!(!quic["ocsp_stapling"].as_bool().expect("quic ocsp flag"));
    assert!(!quic["signed_cert_timestamps"]
        .as_bool()
        .expect("quic sct flag"));
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}
