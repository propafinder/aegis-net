//! Клиентский [JA3](https://github.com/salesforce/ja3) и серверный **JA3S**: строки отпечатков и MD5 (hex).

use super::tls::{
    client_hello_payload, extension_value_in_client_hello_body, parse_client_hello_core,
    parse_ec_point_formats_list, parse_server_hello_core, parse_supported_groups_list,
    ClientHelloCore,
};

fn join_u16_hyphen(vals: &[u16]) -> String {
    vals.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8_hyphen(vals: &[u8]) -> String {
    vals.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn collect_supported_groups_and_ecpf(ch: &[u8]) -> Option<(Vec<u16>, Vec<u8>)> {
    let curves = match extension_value_in_client_hello_body(ch, 10) {
        None => Vec::new(),
        Some(ed) => parse_supported_groups_list(ed)?,
    };
    let points = match extension_value_in_client_hello_body(ch, 11) {
        None => Vec::new(),
        Some(ed) => parse_ec_point_formats_list(ed)?,
    };
    Some((curves, points))
}

fn build_ja3_string(core: &ClientHelloCore, curves: &[u16], points: &[u8]) -> String {
    let ver = u32::from(core.legacy_version);
    format!(
        "{},{},{},{},{}",
        ver,
        join_u16_hyphen(&core.cipher_suites),
        join_u16_hyphen(&core.extension_types),
        join_u16_hyphen(curves),
        join_u8_hyphen(points),
    )
}

/// Строка JA3 (до MD5): `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats` (десятичные числа, списки через `-`).
pub fn ja3_client_fingerprint_string(buf: &[u8]) -> Option<String> {
    let core = parse_client_hello_core(buf)?;
    let ch = client_hello_payload(buf)?;
    let (curves, points) = collect_supported_groups_and_ecpf(ch)?;
    Some(build_ja3_string(&core, &curves, &points))
}

/// MD5 от [`ja3_client_fingerprint_string`] — 32 символа hex (нижний регистр), как в инструментах JA3.
pub fn ja3_client_md5_hex(buf: &[u8]) -> Option<String> {
    let s = ja3_client_fingerprint_string(buf)?;
    let d = md5::compute(s.as_bytes());
    Some(hex::encode(d.as_slice()))
}

/// Строка JA3S (до MD5): `SSLVersion,Cipher,Extensions` (десятичные, расширения через `-`).
pub fn ja3s_server_fingerprint_string(buf: &[u8]) -> Option<String> {
    let sh = parse_server_hello_core(buf)?;
    let ver = u32::from(sh.legacy_version);
    let cipher = u32::from(sh.cipher_suite);
    let exts = join_u16_hyphen(&sh.extension_types);
    Some(format!("{},{},{}", ver, cipher, exts))
}

/// MD5 от [`ja3s_server_fingerprint_string`].
pub fn ja3s_server_md5_hex(buf: &[u8]) -> Option<String> {
    let s = ja3s_server_fingerprint_string(buf)?;
    let d = md5::compute(s.as_bytes());
    Some(hex::encode(d.as_slice()))
}
