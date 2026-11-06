//! Разбор ClientHello: SNI (все `host_name` в списке), точечная подмена без сдвига длины.
//!
//! Структурный разбор шифров и типов расширений; ALPN / signature_algorithms — см. [`super::tls::client_hello_alpn_protocols`] и т.д.

/// Снимок полей, нужных для правок буфера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloView {
    /// Первое имя в SNI (совместимость с одним hostname).
    pub sni: Option<String>,
    /// Диапазон первого hostname в исходном `buf`.
    pub sni_hostname_range: Option<(usize, usize)>,
    /// Все `host_name` (type 0) в списке SNI, по порядку.
    pub sni_hostnames: Vec<(usize, usize)>,
}

/// Разобрать первую TLS-запись как ClientHello с SNI (минимально).
pub fn parse_client_hello(buf: &[u8]) -> Option<TlsClientHelloView> {
    use super::tls::sni_all_hostname_ranges;
    let ranges = sni_all_hostname_ranges(buf)?;
    let range = *ranges.first()?;
    let sni = std::str::from_utf8(buf.get(range.0..range.0 + range.1)?)
        .ok()
        .map(str::to_string);
    Some(TlsClientHelloView {
        sni,
        sni_hostname_range: Some(range),
        sni_hostnames: ranges,
    })
}

/// Подменить SNI **без изменения длины** (иначе нужно пересобирать расширения).
pub fn patch_sni_same_length(
    buf: &mut [u8],
    range: (usize, usize),
    new_sni: &str,
) -> Result<(), &'static str> {
    if new_sni.len() != range.1 {
        return Err("SNI length mismatch: use same-length hostname or tls_modify");
    }
    let slice = buf
        .get_mut(range.0..range.0 + range.1)
        .ok_or("range out of bounds")?;
    slice.copy_from_slice(new_sni.as_bytes());
    Ok(())
}

pub use super::ja3::{
    ja3_client_fingerprint_string, ja3_client_md5_hex, ja3s_server_fingerprint_string,
    ja3s_server_md5_hex,
};
pub use super::tls::{
    client_hello_alpn_protocols, client_hello_ec_point_formats,
    client_hello_encrypted_client_hello_inner, client_hello_encrypted_client_hello_outer,
    client_hello_extension_value, client_hello_key_share, client_hello_pre_shared_key_identities,
    client_hello_psk_key_exchange_modes, client_hello_signature_algorithms,
    client_hello_supported_groups, client_hello_supported_versions, parse_alpn_protocol_names,
    parse_client_hello_core, parse_ec_point_formats_list, parse_encrypted_client_hello,
    parse_encrypted_client_hello_inner, parse_key_share_client_hello,
    parse_pre_shared_key_identities, parse_psk_key_exchange_modes, parse_server_hello_core,
    parse_signature_algorithms_list, parse_supported_groups_list, parse_supported_versions_list,
    ClientHelloCore, EchClientOuter, KeyShareEntry, ServerHelloCore,
    TLS_EXT_ENCRYPTED_CLIENT_HELLO, TLS_EXT_PRE_SHARED_KEY, TLS_EXT_PSK_KEY_EXCHANGE_MODES,
};
