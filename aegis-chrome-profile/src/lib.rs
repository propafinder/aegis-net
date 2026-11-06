//! One versioned Chrome stable profile.
//!
//! TCP TLS, QUIC and HTTP/2 read [`chrome_stable`]. The file is
//! `chrome-stable.toml` next to this crate. `build.rs` rejects a profile
//! whose HTTP/2 preface does not match `fixtures/h2-connection-preface.hex`.

use std::sync::OnceLock;

use serde::Deserialize;

mod preface;

const PROFILE_TEXT: &str = include_str!("../chrome-stable.toml");
const PREFACE_HEX: &str = include_str!("../fixtures/h2-connection-preface.hex");

/// The checked-in Chrome stable profile. Panics if the file failed validation;
/// `build.rs` rejects that file before this can run in a normal build.
pub fn chrome_stable() -> &'static ChromeProfile {
    static PROFILE: OnceLock<ChromeProfile> = OnceLock::new();
    PROFILE.get_or_init(|| {
        ChromeProfile::parse(PROFILE_TEXT).expect("chrome-stable.toml failed validation")
    })
}

/// User-Agent for the host OS, taken from the profile.
pub fn user_agent() -> &'static str {
    let profile = chrome_stable();
    if cfg!(target_os = "windows") {
        profile.user_agent.windows.as_str()
    } else if cfg!(target_os = "macos") {
        profile.user_agent.macos.as_str()
    } else {
        profile.user_agent.linux.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromeProfile {
    pub schema: u32,
    pub measured_chrome: String,
    pub measured_on: String,
    pub user_agent: UserAgent,
    pub tls: TlsProfile,
    pub quic: QuicProfile,
    pub http2: Http2Profile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgent {
    pub major: u32,
    pub windows: String,
    pub macos: String,
    pub linux: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsProfile {
    pub grease: bool,
    pub permute_extensions: bool,
    pub ech_grease: bool,
    pub ocsp_stapling: bool,
    pub signed_cert_timestamps: bool,
    pub alps_new_codepoint: bool,
    pub tls13_ciphers: Vec<String>,
    pub tls12_ciphers: Vec<String>,
    pub groups: Vec<String>,
    pub signature_algorithms: Vec<u16>,
    pub cert_compression: Vec<String>,
    pub alpn_http11: Vec<String>,
    pub alpn_h2: Vec<String>,
    pub alpn_h2_http11: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicProfile {
    pub grease: bool,
    pub permute_extensions: bool,
    pub ech_grease: bool,
    pub ocsp_stapling: bool,
    pub signed_cert_timestamps: bool,
    pub alps_new_codepoint: bool,
    pub tls13_ciphers: Vec<String>,
    pub groups: Vec<String>,
    pub signature_algorithms: Vec<u16>,
    pub cert_compression: Vec<String>,
    pub alpn: Vec<String>,
    pub transport: QuicTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct QuicTransport {
    #[serde(default)]
    pub apply: bool,
    #[serde(default)]
    pub initial_max_data: Option<u64>,
    #[serde(default)]
    pub initial_max_stream_data: Option<u64>,
    #[serde(default)]
    pub initial_max_streams_bidi: Option<u64>,
    #[serde(default)]
    pub initial_max_streams_uni: Option<u64>,
    #[serde(default)]
    pub max_idle_timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_ack_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Profile {
    pub connection_window_increment: u32,
    pub pseudo_header_order: Vec<String>,
    pub header_order: Vec<String>,
    pub headers_priority: Option<HeadersPriority>,
    pub settings: Vec<Http2Setting>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersPriority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Setting {
    pub id: u16,
    pub value: u32,
}

impl ChromeProfile {
    pub fn parse(text: &str) -> Result<Self, String> {
        let raw: RawProfile = toml::from_str(text).map_err(|err| err.to_string())?;
        if raw.schema != 1 {
            return Err(format!("unsupported chrome profile schema {}", raw.schema));
        }
        if raw.measured_chrome.is_empty() || raw.measured_on.is_empty() {
            return Err("measured_chrome and measured_on are required".into());
        }
        let user_agent = validate_user_agent(raw.user_agent)?;
        let tls = validate_tls(raw.tls)?;
        let quic = validate_quic(raw.quic)?;
        let http2 = validate_http2(raw.http2)?;
        let profile = Self {
            schema: raw.schema,
            measured_chrome: raw.measured_chrome,
            measured_on: raw.measured_on,
            user_agent,
            tls,
            quic,
            http2,
        };
        let encoded = profile.http2_preface();
        let fixture = decode_hex(PREFACE_HEX.trim())?;
        if encoded != fixture {
            return Err(
                "HTTP/2 preface fixture does not match the profile settings and window".into(),
            );
        }
        Ok(profile)
    }

    pub fn http2_preface(&self) -> Vec<u8> {
        let settings: Vec<(u16, u32)> = self
            .http2
            .settings
            .iter()
            .map(|setting| (setting.id, setting.value))
            .collect();
        preface::connection_preface(&settings, self.http2.connection_window_increment)
    }
}

impl TlsProfile {
    pub fn tls13_cipher_string(&self) -> String {
        self.tls13_ciphers.join(":")
    }

    pub fn tls12_cipher_string(&self) -> String {
        self.tls12_ciphers.join(":")
    }

    pub fn groups_string(&self) -> String {
        self.groups.join(":")
    }

    pub fn wire(&self, protocols: &[String]) -> Vec<Vec<u8>> {
        protocols
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect()
    }
}

impl QuicProfile {
    pub fn tls13_cipher_string(&self) -> String {
        self.tls13_ciphers.join(":")
    }

    pub fn groups_string(&self) -> String {
        self.groups.join(":")
    }

    pub fn alpn_wire(&self) -> Vec<Vec<u8>> {
        self.alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect()
    }
}

fn validate_user_agent(raw: RawUserAgent) -> Result<UserAgent, String> {
    for (label, value) in [
        ("windows", raw.windows.as_str()),
        ("macos", raw.macos.as_str()),
        ("linux", raw.linux.as_str()),
    ] {
        let token = format!("Chrome/{}.0.0.0", raw.major);
        if !value.contains(&token) || !value.contains("AppleWebKit/537.36") {
            return Err(format!("{label} user agent is not Chrome/{}", raw.major));
        }
    }
    if raw.major < 131 {
        return Err("user agent major predates the X25519MLKEM768 ClientHello".into());
    }
    Ok(UserAgent {
        major: raw.major,
        windows: raw.windows,
        macos: raw.macos,
        linux: raw.linux,
    })
}

fn validate_tls(raw: RawTls) -> Result<TlsProfile, String> {
    require_nonempty("tls13_ciphers", &raw.tls13_ciphers)?;
    require_nonempty("tls12_ciphers", &raw.tls12_ciphers)?;
    require_nonempty("groups", &raw.groups)?;
    for name in raw.tls13_ciphers.iter().chain(raw.tls12_ciphers.iter()) {
        cipher_id(name)?;
    }
    for name in &raw.groups {
        group_id(name)?;
    }
    if raw.cert_compression.iter().any(|name| name != "brotli") {
        return Err("only brotli certificate compression is implemented".into());
    }
    Ok(TlsProfile {
        grease: raw.grease,
        permute_extensions: raw.permute_extensions,
        ech_grease: raw.ech_grease,
        ocsp_stapling: raw.ocsp_stapling,
        signed_cert_timestamps: raw.signed_cert_timestamps,
        alps_new_codepoint: raw.alps_new_codepoint,
        tls13_ciphers: raw.tls13_ciphers,
        tls12_ciphers: raw.tls12_ciphers,
        groups: raw.groups,
        signature_algorithms: parse_sigalgs(&raw.signature_algorithms)?,
        cert_compression: raw.cert_compression,
        alpn_http11: require_nonempty("alpn_http11", &raw.alpn_http11)?,
        alpn_h2: require_nonempty("alpn_h2", &raw.alpn_h2)?,
        alpn_h2_http11: require_nonempty("alpn_h2_http11", &raw.alpn_h2_http11)?,
    })
}

fn validate_quic(raw: RawQuic) -> Result<QuicProfile, String> {
    require_nonempty("quic tls13_ciphers", &raw.tls13_ciphers)?;
    require_nonempty("quic groups", &raw.groups)?;
    for name in &raw.tls13_ciphers {
        cipher_id(name)?;
    }
    for name in &raw.groups {
        group_id(name)?;
    }
    if raw.cert_compression.iter().any(|name| name != "brotli") {
        return Err("only brotli certificate compression is implemented".into());
    }
    if raw.alpn != ["h3"] {
        return Err("quic alpn must be h3".into());
    }
    Ok(QuicProfile {
        grease: raw.grease,
        permute_extensions: raw.permute_extensions,
        ech_grease: raw.ech_grease,
        ocsp_stapling: raw.ocsp_stapling,
        signed_cert_timestamps: raw.signed_cert_timestamps,
        alps_new_codepoint: raw.alps_new_codepoint,
        tls13_ciphers: raw.tls13_ciphers,
        groups: raw.groups,
        signature_algorithms: parse_sigalgs(&raw.signature_algorithms)?,
        cert_compression: raw.cert_compression,
        alpn: raw.alpn,
        transport: raw.transport,
    })
}

fn validate_http2(raw: RawHttp2) -> Result<Http2Profile, String> {
    if raw.settings.is_empty() {
        return Err("http2 settings are empty".into());
    }
    let mut seen = Vec::new();
    for setting in &raw.settings {
        if !matches!(setting.id, 1..=6) {
            return Err(format!(
                "HTTP/2 setting id {} is not emitted by the client builder",
                setting.id
            ));
        }
        if seen.contains(&setting.id) {
            return Err(format!("duplicate HTTP/2 setting id {}", setting.id));
        }
        seen.push(setting.id);
        if setting.id == 2 && setting.value > 1 {
            return Err("ENABLE_PUSH must be 0 or 1".into());
        }
    }
    if raw.pseudo_header_order
        != [":method", ":authority", ":scheme", ":path"]
            .map(str::to_string)
            .to_vec()
    {
        return Err(
            "pseudo-header order is applied by the vendored h2 patch and must stay :method, :authority, :scheme, :path"
                .into(),
        );
    }
    if raw.header_order.is_empty() {
        return Err("http2 header_order is empty".into());
    }
    // The vendored h2 always sets the PRIORITY flag, so the profile must
    // record what it sends; a missing table is not a default.
    let Some(priority) = &raw.headers_priority else {
        return Err("http2.headers_priority is required".into());
    };
    if priority.dependency > 0x7fff_ffff {
        return Err("HEADERS priority dependency does not fit in 31 bits".into());
    }
    let settings = raw
        .settings
        .into_iter()
        .map(|setting| Http2Setting {
            id: setting.id,
            value: setting.value,
        })
        .collect();
    Ok(Http2Profile {
        connection_window_increment: raw.connection_window_increment,
        pseudo_header_order: raw.pseudo_header_order,
        header_order: raw.header_order,
        headers_priority: raw.headers_priority,
        settings,
    })
}

fn require_nonempty(label: &str, values: &[String]) -> Result<Vec<String>, String> {
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err(format!("{label} is empty"));
    }
    Ok(values.to_vec())
}

fn parse_sigalgs(values: &[String]) -> Result<Vec<u16>, String> {
    if values.is_empty() {
        return Err("signature algorithms are empty".into());
    }
    values
        .iter()
        .map(|value| {
            let hex = value
                .strip_prefix("0x")
                .ok_or_else(|| format!("signature algorithm {value} is not 0xNNNN"))?;
            let id = u16::from_str_radix(hex, 16)
                .map_err(|_| format!("signature algorithm {value} is not 0xNNNN"))?;
            let [hi, lo] = id.to_be_bytes();
            if hi == lo && (hi & 0x0f) == 0x0a {
                return Err(format!("signature algorithm {value} is GREASE"));
            }
            Ok(id)
        })
        .collect()
}

pub fn cipher_id(name: &str) -> Result<u16, String> {
    Ok(match name {
        "TLS_AES_128_GCM_SHA256" => 0x1301,
        "TLS_AES_256_GCM_SHA384" => 0x1302,
        "TLS_CHACHA20_POLY1305_SHA256" => 0x1303,
        "ECDHE-ECDSA-AES128-GCM-SHA256" => 0xc02b,
        "ECDHE-RSA-AES128-GCM-SHA256" => 0xc02f,
        "ECDHE-ECDSA-AES256-GCM-SHA384" => 0xc02c,
        "ECDHE-RSA-AES256-GCM-SHA384" => 0xc030,
        "ECDHE-ECDSA-CHACHA20-POLY1305" => 0xcca9,
        "ECDHE-RSA-CHACHA20-POLY1305" => 0xcca8,
        "ECDHE-RSA-AES128-SHA" => 0xc013,
        "ECDHE-RSA-AES256-SHA" => 0xc014,
        "AES128-GCM-SHA256" => 0x009c,
        "AES256-GCM-SHA384" => 0x009d,
        "AES128-SHA" => 0x002f,
        "AES256-SHA" => 0x0035,
        other => return Err(format!("unknown cipher {other}")),
    })
}

pub fn group_id(name: &str) -> Result<u16, String> {
    Ok(match name {
        "X25519MLKEM768" => 0x11ec,
        "X25519" => 0x001d,
        "P-256" => 0x0017,
        "P-384" => 0x0018,
        "P-521" => 0x0019,
        other => return Err(format!("unknown group {other}")),
    })
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("preface fixture hex has an odd length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| "preface fixture is not hex".to_string())
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    schema: u32,
    measured_chrome: String,
    measured_on: String,
    user_agent: RawUserAgent,
    tls: RawTls,
    quic: RawQuic,
    http2: RawHttp2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUserAgent {
    major: u32,
    windows: String,
    macos: String,
    linux: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    grease: bool,
    permute_extensions: bool,
    ech_grease: bool,
    ocsp_stapling: bool,
    signed_cert_timestamps: bool,
    alps_new_codepoint: bool,
    tls13_ciphers: Vec<String>,
    tls12_ciphers: Vec<String>,
    groups: Vec<String>,
    signature_algorithms: Vec<String>,
    cert_compression: Vec<String>,
    alpn_http11: Vec<String>,
    alpn_h2: Vec<String>,
    alpn_h2_http11: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuic {
    grease: bool,
    permute_extensions: bool,
    ech_grease: bool,
    ocsp_stapling: bool,
    signed_cert_timestamps: bool,
    alps_new_codepoint: bool,
    tls13_ciphers: Vec<String>,
    groups: Vec<String>,
    signature_algorithms: Vec<String>,
    cert_compression: Vec<String>,
    alpn: Vec<String>,
    #[serde(default)]
    transport: QuicTransport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHttp2 {
    connection_window_increment: u32,
    pseudo_header_order: Vec<String>,
    header_order: Vec<String>,
    #[serde(default)]
    headers_priority: Option<HeadersPriority>,
    settings: Vec<RawSetting>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSetting {
    id: u16,
    value: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_profile_parses_and_matches_the_preface_fixture() {
        let profile = ChromeProfile::parse(PROFILE_TEXT).unwrap();
        assert_eq!(profile.schema, 1);
        assert_eq!(profile.tls.signature_algorithms[0], 0x0904);
        assert!(!profile.quic.grease);
        assert!(!profile.quic.ocsp_stapling);
        assert!(!profile.quic.signed_cert_timestamps);
        assert_eq!(profile.http2.connection_window_increment, 15_663_105);
        assert_eq!(
            profile.http2_preface(),
            decode_hex(PREFACE_HEX.trim()).unwrap()
        );
    }

    #[test]
    fn empty_cipher_list_is_rejected() {
        let mut text = PROFILE_TEXT.to_string();
        text = text.replace(
            "tls13_ciphers = [\"TLS_AES_128_GCM_SHA256\", \"TLS_AES_256_GCM_SHA384\", \"TLS_CHACHA20_POLY1305_SHA256\"]",
            "tls13_ciphers = []",
        );
        assert!(ChromeProfile::parse(&text).is_err());
    }

    /// A misspelled key must fail, not fall back to a serde default. Every
    /// table is covered, including the optional QUIC transport block and the
    /// HEADERS priority, whose absence or typo would otherwise be silent.
    #[test]
    fn unknown_keys_are_rejected_in_every_table() {
        let edits = [
            ("schema = 1\n", "schema = 1\nschemaa = 1\n"),
            ("major = 157\n", "major = 157\nmajorr = 157\n"),
            ("[tls]\n", "[tls]\ngreese = true\n"),
            ("[quic]\n", "[quic]\nalpn_h3 = [\"h3\"]\n"),
            ("apply = false\n", "apply = false\ninitial_max_dta = 1\n"),
            ("exclusive = true\n", "exclusive = true\nwieght = 1\n"),
            ("[http2]\n", "[http2]\nwindow_increment = 1\n"),
            ("id = 1\n", "id = 1\nvaleu = 1\n"),
        ];
        for (from, to) in edits {
            assert_eq!(
                PROFILE_TEXT.matches(from).count(),
                1,
                "fixture anchor {from:?}"
            );
            let text = PROFILE_TEXT.replacen(from, to, 1);
            assert!(
                ChromeProfile::parse(&text).is_err(),
                "unknown key accepted: {to:?}"
            );
        }
        let table = "[http2.headers_priority]\n";
        let start = PROFILE_TEXT.find(table).expect("priority table");
        let end = start + PROFILE_TEXT[start..].find("\n\n").expect("table end") + 2;
        let without = format!("{}{}", &PROFILE_TEXT[..start], &PROFILE_TEXT[end..]);
        assert!(
            ChromeProfile::parse(&without).is_err(),
            "a profile without the HEADERS priority h2 sends was accepted"
        );
    }
}
