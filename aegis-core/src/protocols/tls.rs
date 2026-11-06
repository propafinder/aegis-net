//! Минимальный разбор TLS ClientHello / ServerHello: SNI, ядро рукопожатия, расширения — JA3 / JA3S.

/// Проверка: первая TLS-запись — Handshake ClientHello.
pub fn is_likely_tls_client_hello(buf: &[u8]) -> bool {
    if buf.len() < 5 + 4 + 2 {
        return false;
    }
    buf[0] == 22 && buf[5] == 1
}

/// Проверка: первая TLS-запись — Handshake ServerHello.
pub fn is_likely_tls_server_hello(buf: &[u8]) -> bool {
    if buf.len() < 5 + 4 {
        return false;
    }
    buf[0] == 22 && buf[5] == 2
}

/// Все вхождения `host_name` (type 0) в расширении SNI: абсолютные `[start, start+len)` в `buf`.
pub fn sni_all_hostname_ranges(buf: &[u8]) -> Option<Vec<(usize, usize)>> {
    let hs_len = u24(buf.get(6..9)?) as usize;
    let body_start = 9usize;
    let ch = buf.get(body_start..body_start + hs_len)?;
    let (ext_rel_start, ext_len) = extensions_list_range_in_client_hello(ch)?;
    let ext = ch.get(ext_rel_start..ext_rel_start + ext_len)?;
    let mut o = 0usize;
    while o + 4 <= ext.len() {
        let et = u16::from_be_bytes([ext[o], ext[o + 1]]);
        let elen = u16::from_be_bytes([ext[o + 2], ext[o + 3]]) as usize;
        o += 4;
        if o + elen > ext.len() {
            break;
        }
        if et == 0 {
            let ed = &ext[o..o + elen];
            let abs_val_start = body_start + ext_rel_start + o;
            let v = collect_sni_hostnames_from_value(abs_val_start, ed);
            return if v.is_empty() { None } else { Some(v) };
        }
        o += elen;
    }
    None
}

/// Диапазон **первого** hostname в SNI.
///
/// Returns `(start, len)` — NOT `(start, end)`. Slice it as
/// `buf[start..start + len]`. A caller that read the second element as an end
/// offset sliced `buf[start..len]` and panicked on every real ClientHello
/// (`panic = "abort"` in this workspace, so the process died); the contract is
/// spelled out here so that mistake cannot be made silently again.
pub fn sni_hostname_range(buf: &[u8]) -> Option<(usize, usize)> {
    sni_all_hostname_ranges(buf).and_then(|v| v.first().copied())
}

pub(crate) fn u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

/// Типы расширений по порядку в срезе данных расширений (как в TLS `Extension` list).
pub(crate) fn extension_types_from_list_bytes(ext_data: &[u8]) -> Option<Vec<u16>> {
    let mut types = Vec::new();
    let mut o = 0usize;
    while o + 4 <= ext_data.len() {
        let et = u16::from_be_bytes([ext_data[o], ext_data[o + 1]]);
        let elen = u16::from_be_bytes([ext_data[o + 2], ext_data[o + 3]]) as usize;
        o += 4;
        if o + elen > ext_data.len() {
            return None;
        }
        types.push(et);
        o += elen;
    }
    (o == ext_data.len()).then_some(types)
}

/// Значение **первого** расширения с типом `ext_type` в теле ClientHello (`ch`).
pub fn extension_value_in_client_hello_body(ch: &[u8], ext_type: u16) -> Option<&[u8]> {
    let (ext_rel_start, ext_len) = extensions_list_range_in_client_hello(ch)?;
    let ext = ch.get(ext_rel_start..ext_rel_start + ext_len)?;
    let mut o = 0usize;
    while o + 4 <= ext.len() {
        let et = u16::from_be_bytes([ext[o], ext[o + 1]]);
        let elen = u16::from_be_bytes([ext[o + 2], ext[o + 3]]) as usize;
        o += 4;
        if o + elen > ext.len() {
            return None;
        }
        if et == ext_type {
            return Some(&ext[o..o + elen]);
        }
        o += elen;
    }
    None
}

/// Значение расширения в **первой** TLS-записи ClientHello (`buf`).
pub fn client_hello_extension_value(buf: &[u8], ext_type: u16) -> Option<&[u8]> {
    let ch = client_hello_payload(buf)?;
    extension_value_in_client_hello_body(ch, ext_type)
}

/// RFC 7301: тело расширения ALPN (`ExtensionType` 16) → список имён протоколов.
pub fn parse_alpn_protocol_names(ext_value: &[u8]) -> Option<Vec<String>> {
    if ext_value.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext_value[0], ext_value[1]]) as usize;
    if ext_value.len() < 2 + list_len {
        return None;
    }
    let list = &ext_value[2..2 + list_len];
    let mut out = Vec::new();
    let mut o = 0usize;
    while o < list.len() {
        let n = list[o] as usize;
        o += 1;
        if o + n > list.len() {
            return None;
        }
        let name = std::str::from_utf8(&list[o..o + n]).ok()?;
        out.push(name.to_string());
        o += n;
    }
    Some(out)
}

/// RFC 5246 / 8446: тело расширения `signature_algorithms` (13) → список `SignatureAndHashAlgorithm` (u16).
pub fn parse_signature_algorithms_list(ext_value: &[u8]) -> Option<Vec<u16>> {
    if ext_value.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext_value[0], ext_value[1]]) as usize;
    if ext_value.len() < 2 + list_len || !list_len.is_multiple_of(2) {
        return None;
    }
    let mut v = Vec::with_capacity(list_len / 2);
    for i in (0..list_len).step_by(2) {
        v.push(u16::from_be_bytes([ext_value[2 + i], ext_value[2 + i + 1]]));
    }
    Some(v)
}

/// ALPN из ClientHello (расширение 16).
pub fn client_hello_alpn_protocols(buf: &[u8]) -> Option<Vec<String>> {
    let raw = client_hello_extension_value(buf, 16)?;
    parse_alpn_protocol_names(raw)
}

/// Подписи из ClientHello (расширение 13).
pub fn client_hello_signature_algorithms(buf: &[u8]) -> Option<Vec<u16>> {
    let raw = client_hello_extension_value(buf, 13)?;
    parse_signature_algorithms_list(raw)
}

/// RFC 7919 / 8446: `supported_groups` (расширение 10) — список именованных групп (u16).
pub fn parse_supported_groups_list(ext_value: &[u8]) -> Option<Vec<u16>> {
    if ext_value.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext_value[0], ext_value[1]]) as usize;
    if ext_value.len() < 2 + list_len || !list_len.is_multiple_of(2) {
        return None;
    }
    let mut v = Vec::with_capacity(list_len / 2);
    for i in (0..list_len).step_by(2) {
        v.push(u16::from_be_bytes([ext_value[2 + i], ext_value[2 + i + 1]]));
    }
    Some(v)
}

/// RFC 4492 / 8446: `ec_point_formats` (расширение 11).
pub fn parse_ec_point_formats_list(ext_value: &[u8]) -> Option<Vec<u8>> {
    if ext_value.is_empty() {
        return None;
    }
    let n = ext_value[0] as usize;
    if ext_value.len() < 1 + n {
        return None;
    }
    Some(ext_value[1..1 + n].to_vec())
}

/// RFC 8446: `supported_versions` (расширение 43) в ClientHello — список `SupportedVersion` (u16).
pub fn parse_supported_versions_list(ext_value: &[u8]) -> Option<Vec<u16>> {
    if ext_value.is_empty() {
        return None;
    }
    let n = ext_value[0] as usize;
    if !(2..=254).contains(&n) || ext_value.len() != 1 + n || !n.is_multiple_of(2) {
        return None;
    }
    let mut v = Vec::with_capacity(n / 2);
    for i in (0..n).step_by(2) {
        v.push(u16::from_be_bytes([ext_value[1 + i], ext_value[1 + i + 1]]));
    }
    Some(v)
}

/// Группы из ClientHello (расширение 10).
pub fn client_hello_supported_groups(buf: &[u8]) -> Option<Vec<u16>> {
    let raw = client_hello_extension_value(buf, 10)?;
    parse_supported_groups_list(raw)
}

/// Форматы точки EC из ClientHello (расширение 11).
pub fn client_hello_ec_point_formats(buf: &[u8]) -> Option<Vec<u8>> {
    let raw = client_hello_extension_value(buf, 11)?;
    parse_ec_point_formats_list(raw)
}

/// Поддерживаемые версии TLS из ClientHello (расширение 43, TLS 1.3).
pub fn client_hello_supported_versions(buf: &[u8]) -> Option<Vec<u16>> {
    let raw = client_hello_extension_value(buf, 43)?;
    parse_supported_versions_list(raw)
}

/// Одна запись `KeyShare` в ClientHello (RFC 8446): группа + opaque `key_exchange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

/// RFC 8446: расширение `key_share` (51) в ClientHello — список `KeyShareEntry`.
pub fn parse_key_share_client_hello(ext_value: &[u8]) -> Option<Vec<KeyShareEntry>> {
    if ext_value.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext_value[0], ext_value[1]]) as usize;
    if ext_value.len() < 2 + list_len {
        return None;
    }
    let list = &ext_value[2..2 + list_len];
    let mut out = Vec::new();
    let mut o = 0usize;
    while o < list.len() {
        if o + 4 > list.len() {
            return None;
        }
        let group = u16::from_be_bytes([list[o], list[o + 1]]);
        o += 2;
        let ke_len = u16::from_be_bytes([list[o], list[o + 1]]) as usize;
        o += 2;
        if ke_len < 1 || o + ke_len > list.len() {
            return None;
        }
        let key_exchange = list[o..o + ke_len].to_vec();
        o += ke_len;
        out.push(KeyShareEntry {
            group,
            key_exchange,
        });
    }
    Some(out)
}

/// Записи `key_share` из ClientHello (расширение 51).
pub fn client_hello_key_share(buf: &[u8]) -> Option<Vec<KeyShareEntry>> {
    let raw = client_hello_extension_value(buf, 51)?;
    parse_key_share_client_hello(raw)
}

// IANA TLS ExtensionTypes — фрагмент (TLS 1.3 / ECH).
/// `pre_shared_key` (RFC 8446).
pub const TLS_EXT_PRE_SHARED_KEY: u16 = 41;
/// `psk_key_exchange_modes` (RFC 8446).
pub const TLS_EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
/// `encrypted_client_hello` (RFC 9849).
pub const TLS_EXT_ENCRYPTED_CLIENT_HELLO: u16 = 65037;

/// RFC 8446: тело `psk_key_exchange_modes` — список байтов режимов (`psk_ke` / `psk_dhe_ke`).
pub fn parse_psk_key_exchange_modes(ext_value: &[u8]) -> Option<Vec<u8>> {
    if ext_value.is_empty() {
        return None;
    }
    let n = ext_value[0] as usize;
    if n < 1 || ext_value.len() != 1 + n {
        return None;
    }
    Some(ext_value[1..1 + n].to_vec())
}

/// Режимы PSK из ClientHello (расширение 45).
pub fn client_hello_psk_key_exchange_modes(buf: &[u8]) -> Option<Vec<u8>> {
    let raw = client_hello_extension_value(buf, TLS_EXT_PSK_KEY_EXCHANGE_MODES)?;
    parse_psk_key_exchange_modes(raw)
}

/// RFC 8446 `OfferedPsks`: разбор только **идентификаторов** (opaque identity на каждый PskIdentity); binders проверяются по длине всего расширения.
pub fn parse_pre_shared_key_identities(ext_value: &[u8]) -> Option<Vec<Vec<u8>>> {
    if ext_value.len() < 2 {
        return None;
    }
    let identities_len = u16::from_be_bytes([ext_value[0], ext_value[1]]) as usize;
    if identities_len < 7 || ext_value.len() < 2 + identities_len + 2 {
        return None;
    }
    let id_blob = &ext_value[2..2 + identities_len];
    let mut out = Vec::new();
    let mut o = 0usize;
    while o < id_blob.len() {
        if o + 2 > id_blob.len() {
            return None;
        }
        let id_len = u16::from_be_bytes([id_blob[o], id_blob[o + 1]]) as usize;
        o += 2;
        if id_len < 1 || o + id_len + 4 > id_blob.len() {
            return None;
        }
        out.push(id_blob[o..o + id_len].to_vec());
        o += id_len + 4; // obfuscated_ticket_age
    }
    if o != id_blob.len() {
        return None;
    }
    let binders_pos = 2 + identities_len;
    let binders_len =
        u16::from_be_bytes([ext_value[binders_pos], ext_value[binders_pos + 1]]) as usize;
    if binders_len < 33 || ext_value.len() != binders_pos + 2 + binders_len {
        return None;
    }
    Some(out)
}

/// Идентификаторы PSK из ClientHello (расширение 41).
pub fn client_hello_pre_shared_key_identities(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    let raw = client_hello_extension_value(buf, TLS_EXT_PRE_SHARED_KEY)?;
    parse_pre_shared_key_identities(raw)
}

/// RFC 9849: вариант **outer** — после `ECHClientHello.type == outer (0)` идут `HpkeSymmetricCipherSuite`, `config_id`, `enc`, `payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchClientOuter {
    pub kdf_id: u16,
    pub aead_id: u16,
    pub config_id: u8,
    pub enc: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Разбор `encrypted_client_hello` для **outer** (тип 0). Вариант **inner** (тип 1) — см. [`parse_encrypted_client_hello_inner`].
pub fn parse_encrypted_client_hello(ext_value: &[u8]) -> Option<EchClientOuter> {
    if ext_value.is_empty() || ext_value[0] != 0 {
        return None;
    }
    let mut o = 1usize;
    if o + 4 > ext_value.len() {
        return None;
    }
    let kdf_id = u16::from_be_bytes([ext_value[o], ext_value[o + 1]]);
    let aead_id = u16::from_be_bytes([ext_value[o + 2], ext_value[o + 3]]);
    o += 4;
    if o >= ext_value.len() {
        return None;
    }
    let config_id = ext_value[o];
    o += 1;
    if o + 2 > ext_value.len() {
        return None;
    }
    let enc_len = u16::from_be_bytes([ext_value[o], ext_value[o + 1]]) as usize;
    o += 2;
    if o + enc_len > ext_value.len() {
        return None;
    }
    let enc = ext_value[o..o + enc_len].to_vec();
    o += enc_len;
    if o + 2 > ext_value.len() {
        return None;
    }
    let plen = u16::from_be_bytes([ext_value[o], ext_value[o + 1]]) as usize;
    o += 2;
    if plen < 1 || o + plen != ext_value.len() {
        return None;
    }
    let payload = ext_value[o..o + plen].to_vec();
    Some(EchClientOuter {
        kdf_id,
        aead_id,
        config_id,
        enc,
        payload,
    })
}

/// RFC 9849: вариант **inner** — только байт типа `1`, поле `Empty` (без данных).
pub fn parse_encrypted_client_hello_inner(ext_value: &[u8]) -> Option<()> {
    (ext_value.len() == 1 && ext_value[0] == 1).then_some(())
}

/// ECH (outer) из ClientHello, расширение 65037.
pub fn client_hello_encrypted_client_hello_outer(buf: &[u8]) -> Option<EchClientOuter> {
    let raw = client_hello_extension_value(buf, TLS_EXT_ENCRYPTED_CLIENT_HELLO)?;
    parse_encrypted_client_hello(raw)
}

/// ECH (inner) из ClientHello, расширение 65037.
pub fn client_hello_encrypted_client_hello_inner(buf: &[u8]) -> Option<()> {
    let raw = client_hello_extension_value(buf, TLS_EXT_ENCRYPTED_CLIENT_HELLO)?;
    parse_encrypted_client_hello_inner(raw)
}

/// Разобранное ядро ClientHello (без глубокого разбора значений расширений). Порядок элементов — как в wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloCore {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    /// Типы расширений по порядку (как в пакете).
    pub extension_types: Vec<u16>,
}

/// Тело handshake ClientHello после заголовка TLS Record (тип 22, версия записи, длина) и `Handshake` (type=1, u24 len).
pub(crate) fn client_hello_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 9 {
        return None;
    }
    if buf[0] != 22 || buf[5] != 1 {
        return None;
    }
    let hs_len = u24(buf.get(6..9)?) as usize;
    buf.get(9..9 + hs_len)
}

fn parse_client_hello_body(ch: &[u8]) -> Option<ClientHelloCore> {
    if ch.len() < 2 + 32 + 1 {
        return None;
    }
    let mut o = 0usize;
    let legacy_version = u16::from_be_bytes([ch[o], ch[o + 1]]);
    o += 2 + 32;
    let sid_len = ch[o] as usize;
    o += 1;
    if o + sid_len > ch.len() {
        return None;
    }
    o += sid_len;
    if o + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[o], ch[o + 1]]) as usize;
    o += 2;
    if !cs_len.is_multiple_of(2) || o + cs_len > ch.len() {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for i in (0..cs_len).step_by(2) {
        cipher_suites.push(u16::from_be_bytes([ch[o + i], ch[o + i + 1]]));
    }
    o += cs_len;
    if o >= ch.len() {
        return None;
    }
    let comp_len = ch[o] as usize;
    o += 1;
    if o + comp_len > ch.len() {
        return None;
    }
    let compression_methods = ch[o..o + comp_len].to_vec();
    o += comp_len;

    let extension_types = if o >= ch.len() {
        vec![]
    } else {
        if o + 2 > ch.len() {
            return None;
        }
        let ext_total = u16::from_be_bytes([ch[o], ch[o + 1]]) as usize;
        o += 2;
        if o + ext_total > ch.len() {
            return None;
        }
        let ext_data = &ch[o..o + ext_total];
        extension_types_from_list_bytes(ext_data)?
    };

    Some(ClientHelloCore {
        legacy_version,
        cipher_suites,
        compression_methods,
        extension_types,
    })
}

/// Разбор первой записи TLS: ClientHello → версия, списки шифров / сжатий / **типов** расширений (без SNI как строки).
pub fn parse_client_hello_core(buf: &[u8]) -> Option<ClientHelloCore> {
    let ch = client_hello_payload(buf)?;
    parse_client_hello_body(ch)
}

/// Ядро ServerHello: одна cipher suite и порядок типов расширений.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloCore {
    pub legacy_version: u16,
    pub cipher_suite: u16,
    pub extension_types: Vec<u16>,
}

/// Тело TLS Handshake ServerHello (после заголовка записи).
pub(crate) fn server_hello_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 9 {
        return None;
    }
    if buf[0] != 22 || buf[5] != 2 {
        return None;
    }
    let hs_len = u24(buf.get(6..9)?) as usize;
    buf.get(9..9 + hs_len)
}

fn parse_server_hello_body(sh: &[u8]) -> Option<ServerHelloCore> {
    if sh.len() < 2 + 32 + 1 + 2 + 1 {
        return None;
    }
    let mut o = 0usize;
    let legacy_version = u16::from_be_bytes([sh[o], sh[o + 1]]);
    o += 2 + 32;
    let sid_len = sh[o] as usize;
    o += 1;
    if o + sid_len > sh.len() {
        return None;
    }
    o += sid_len;
    if o + 2 + 1 > sh.len() {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([sh[o], sh[o + 1]]);
    o += 2;
    o += 1; // compression method

    let extension_types = if o >= sh.len() {
        vec![]
    } else {
        if o + 2 > sh.len() {
            return None;
        }
        let ext_total = u16::from_be_bytes([sh[o], sh[o + 1]]) as usize;
        o += 2;
        if o + ext_total > sh.len() {
            return None;
        }
        extension_types_from_list_bytes(&sh[o..o + ext_total])?
    };

    Some(ServerHelloCore {
        legacy_version,
        cipher_suite,
        extension_types,
    })
}

/// Разбор первой записи TLS: ServerHello.
pub fn parse_server_hello_core(buf: &[u8]) -> Option<ServerHelloCore> {
    let sh = server_hello_payload(buf)?;
    parse_server_hello_body(sh)
}

/// Диапазон списка расширений относительно начала **тела** ClientHello (`ch`).
pub(crate) fn extensions_list_range_in_client_hello(ch: &[u8]) -> Option<(usize, usize)> {
    if ch.len() < 2 + 32 + 1 {
        return None;
    }
    let mut o = 2 + 32;
    let sid_len = *ch.get(o)? as usize;
    o += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*ch.get(o)?, *ch.get(o + 1)?]) as usize;
    o += 2 + cs_len;
    let comp_len = *ch.get(o)? as usize;
    o += 1 + comp_len;
    let ext_len = u16::from_be_bytes([*ch.get(o)?, *ch.get(o + 1)?]) as usize;
    o += 2;
    Some((o, ext_len))
}

fn collect_sni_hostnames_from_value(abs_val_start: usize, ed: &[u8]) -> Vec<(usize, usize)> {
    if ed.len() < 2 {
        return vec![];
    }
    let list_len = u16::from_be_bytes([ed[0], ed[1]]) as usize;
    if ed.len() < 2 + list_len {
        return vec![];
    }
    let list = &ed[2..2 + list_len];
    let mut o = 0usize;
    let mut out = Vec::new();
    while o + 3 <= list.len() {
        let nt = list[o];
        let nl = u16::from_be_bytes([list[o + 1], list[o + 2]]) as usize;
        if o + 3 + nl > list.len() {
            break;
        }
        if nt == 0 {
            out.push((abs_val_start + 2 + o + 3, nl));
        }
        o += 3 + nl;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // AUDIT REPRO (H1): crafted ClientHello body with cs_len running past the
    // buffer end must NOT panic. `extensions_list_range_in_client_hello` uses a
    // raw `ch[o]` at the compression-methods length after advancing `o` by the
    // attacker-controlled cipher-suites length. If this test panics with
    // "index out of bounds", the OOB is CONFIRMED reachable on origin/main.
    #[test]
    fn audit_h1_client_hello_oob_does_not_panic() {
        let mut ch = vec![0x03, 0x03]; // legacy_version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session_id length = 0
        ch.extend_from_slice(&0xFFFFu16.to_be_bytes()); // cipher_suites length = 65535 (lies)
                                                        // buffer ends here: len = 37
        let r = extensions_list_range_in_client_hello(&ch);
        // A correctly-bounded parser returns None on truncated input.
        assert!(r.is_none(), "expected None on truncated hello, got {r:?}");
    }

    #[test]
    fn not_tls() {
        assert!(!is_likely_tls_client_hello(&[]));
    }

    #[test]
    fn parse_alpn_http11() {
        let mut v = vec![0u8, 9, 8];
        v.extend_from_slice(b"http/1.1");
        let names = parse_alpn_protocol_names(&v).expect("alpn");
        assert_eq!(names, vec!["http/1.1".to_string()]);
    }

    #[test]
    fn parse_sigalgs_two() {
        let v = [0u8, 4, 0x04, 0x01, 0x04, 0x03];
        assert_eq!(
            parse_signature_algorithms_list(&v).expect("sig"),
            vec![0x0401, 0x0403]
        );
    }

    #[test]
    fn parse_supported_versions_tls13_tls12() {
        // длина 4 байта: 0x0304 (TLS 1.3), 0x0303 (TLS 1.2)
        let v = [4u8, 0x03, 0x04, 0x03, 0x03];
        assert_eq!(
            parse_supported_versions_list(&v).expect("sv"),
            vec![0x0304, 0x0303]
        );
    }

    #[test]
    fn parse_key_share_x25519_single() {
        // список 36 байт: группа x25519 (0x001d), длина ключа 32, 32 нуля
        let mut v = vec![0u8, 36];
        v.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]);
        v.extend_from_slice(&[0u8; 32]);
        let e = parse_key_share_client_hello(&v).expect("ks");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].group, 0x001d);
        assert_eq!(e[0].key_exchange.len(), 32);
    }

    #[test]
    fn parse_psk_ke_modes_two() {
        let v = [2u8, 1, 2];
        assert_eq!(parse_psk_key_exchange_modes(&v).expect("m"), vec![1u8, 2]);
    }

    #[test]
    fn parse_offered_psks_one_identity() {
        // identities: 8 байт (>=7); один identity len=2 + age; binders: 33 байта (один binder 32+1)
        let mut v = vec![0u8, 8];
        v.extend_from_slice(&[0x00, 0x02, 0xab, 0xcd, 0, 0, 0, 0]);
        v.extend_from_slice(&[0u8, 33]);
        v.push(32u8);
        v.extend_from_slice(&[0u8; 32]);
        let ids = parse_pre_shared_key_identities(&v).expect("psk");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], vec![0xabu8, 0xcd]);
    }

    #[test]
    fn parse_ech_outer_minimal() {
        // RFC 9849 outer: cipher_suite (kdf+aead), uint8 config_id, enc, payload
        let mut v = vec![0u8];
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        v.push(0x42);
        v.extend_from_slice(&[0x00, 0x02, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x00, 0x02, 0xcc, 0xdd]);
        let o = parse_encrypted_client_hello(&v).expect("ech");
        assert_eq!(o.kdf_id, 0x0001);
        assert_eq!(o.aead_id, 0x0002);
        assert_eq!(o.config_id, 0x42);
        assert_eq!(o.enc, vec![0xaa, 0xbb]);
        assert_eq!(o.payload, vec![0xcc, 0xdd]);
    }

    #[test]
    fn parse_ech_outer_empty_enc() {
        let mut v = vec![0u8];
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        v.push(0x01);
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(&[0x00, 0x01, 0xef]);
        let o = parse_encrypted_client_hello(&v).expect("ech");
        assert!(o.enc.is_empty());
        assert_eq!(o.payload, vec![0xefu8]);
    }

    #[test]
    fn parse_ech_inner_empty() {
        assert!(parse_encrypted_client_hello_inner(&[1]).is_some());
        assert!(parse_encrypted_client_hello_inner(&[1, 0]).is_none());
        assert!(parse_encrypted_client_hello_inner(&[0]).is_none());
    }
}
