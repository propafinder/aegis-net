//! Pinned ECH policy shared by profile validation and actual relay TLS.
//! This supplies neither credentials nor online/capture admission.
//!
//! Rotation model (CDN-fronted profiles, carrier program stage D2):
//! the device profile pins one ECHConfigList and therefore its `public_name`
//! (for Cloudflare, `cloudflare-ech.com`). CDN keys rotate frequently. When
//! the edge cannot decrypt a stale config it completes the *outer* handshake,
//! authenticated for that pinned public name under the profile's explicit
//! outer CA, and returns `retry_configs` (RFC 9849 section 6.1.6). Rustls
//! surfaces them only after that authentication, as the handshake error. This
//! module admits such retry configs only when every config keeps a pinned
//! public name and at least one is usable, and caches them in memory for the
//! same outer authority and pinned list. No credentials, H2 bytes, device
//! identity or enrollment material are sent on a rejected handshake; a retry
//! that is rejected again fails closed and clears the rotation.
use aegis_core::RelaySettings;
use anyhow::Context;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Retry configs older than this are dropped; the next stale handshake
/// re-learns them through the same authenticated path.
pub const MAX_ROTATION_AGE: Duration = Duration::from_secs(6 * 60 * 60);

/// Authenticated ECH rejection from AWS-LC, with the retry list BoringSSL
/// returned after the outer handshake. Display never includes the bytes.
#[derive(Debug)]
pub struct AuthenticatedEchRetry {
    pub retry_configs: Option<Vec<u8>>,
}

impl std::fmt::Display for AuthenticatedEchRetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay rejected encrypted client hello")
    }
}

impl std::error::Error for AuthenticatedEchRetry {}
const MAX_ROTATIONS: usize = 64;
const MAX_LIST_BYTES: usize = 16 * 1024;

pub fn require_accepted_ech(
    settings: &RelaySettings,
    status: rustls::client::EchStatus,
) -> anyhow::Result<()> {
    if settings.ech_config_list.is_some() || settings.ech_config_list_base64.is_some() {
        anyhow::ensure!(
            status == rustls::client::EchStatus::Accepted,
            "required ECH was not accepted by the relay (status={status:?})"
        );
    }
    Ok(())
}

/// The exact pinned ECHConfigList bytes, or `None` when ECH is not requested.
fn pinned_list(settings: &RelaySettings) -> anyhow::Result<Option<Vec<u8>>> {
    anyhow::ensure!(
        settings.ech_config_list.is_none() || settings.ech_config_list_base64.is_none(),
        "ECH file and inline config are mutually exclusive"
    );
    if let Some(encoded) = settings.ech_config_list_base64.as_deref() {
        inline_ech_config(encoded)?;
        return Ok(Some(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| anyhow::anyhow!("inline ECHConfigList encoding invalid"))?,
        ));
    }
    let Some(path) = settings.ech_config_list.as_deref() else {
        return Ok(None);
    };
    let bytes = aegis_core::secret_file::read_config(path, 64 * 1024)
        .context("read pinned ECHConfigList")?;
    anyhow::ensure!(!bytes.is_empty(), "pinned ECHConfigList is empty");
    Ok(Some(bytes.to_vec()))
}

fn ech_config(bytes: Vec<u8>) -> anyhow::Result<rustls::client::EchConfig> {
    rustls::client::EchConfig::new(
        rustls::pki_types::EchConfigListBytes::from(bytes),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .map_err(|_| anyhow::anyhow!("ECHConfigList has no usable supported config"))
}

pub fn pinned_ech_mode(
    settings: &RelaySettings,
) -> anyhow::Result<Option<rustls::client::EchMode>> {
    Ok(pinned_ech_mode_with_token(settings)?.0)
}

/// Return the exact learned generation used to prepare the ECH mode. A held
/// pool compares these across pins before admitting a coherent snapshot.
pub fn pinned_ech_mode_with_token(
    settings: &RelaySettings,
) -> anyhow::Result<(Option<rustls::client::EchMode>, Option<RotationToken>)> {
    let Some(pinned) = pinned_list(settings)? else {
        return Ok((None, None));
    };
    // Validate the pin itself even when an authenticated rotation is used.
    ech_config(pinned.clone()).context("validate pinned ECHConfigList")?;
    let (list, token) = rotation(settings, &pinned)
        .map(|(list, token)| (list, Some(token)))
        .unwrap_or((pinned, None));
    Ok((Some(ech_config(list)?.into()), token))
}

/// Bytes the AWS-LC Chrome stack offers: a learned rotation when one is
/// cached, otherwise the pinned list. `None` when ECH is not configured.
///
/// AWS-LC sends a plain ClientHello, with the inner name as SNI, when no
/// ECHConfig in the list is one it can use; only the post-handshake
/// `SSL_ech_accepted` check would then fail the connection. Rustls admits
/// more KEMs than AWS-LC, so its validation alone does not prevent that.
/// A list AWS-LC cannot offer is refused here, before any network I/O.
pub fn effective_ech_config_list(settings: &RelaySettings) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(pinned) = pinned_list(settings)? else {
        return Ok(None);
    };
    ech_config(pinned.clone()).context("validate pinned ECHConfigList")?;
    let list = rotation(settings, &pinned)
        .map(|(list, _)| list)
        .unwrap_or(pinned);
    anyhow::ensure!(
        aws_lc_offers_ech(&list),
        "ECHConfigList has no config the AWS-LC client offers \
         (DHKEM X25519 with HKDF-SHA256); use tls_backend=rustls for this list"
    );
    Ok(Some(list))
}

/// Whether AWS-LC 0.44's ECH client selects a config from `list`
/// (`ssl_select_ech_config`): version 0xfe0d, a 32-byte DHKEM(X25519,
/// HKDF-SHA256) key, a cipher suite with HKDF-SHA256 and AES-128-GCM,
/// AES-256-GCM or ChaCha20-Poly1305, an LDH public name whose last label is
/// not numeric, and no mandatory extension. Malformed input is `false`.
fn aws_lc_offers_ech(list: &[u8]) -> bool {
    fn usable(contents: &mut &[u8]) -> anyhow::Result<bool> {
        take(contents, 1)?; // config_id
        let kem = u16_at(contents)?;
        let key_length = u16_at(contents)? as usize;
        take(contents, key_length)?;
        let suites_length = u16_at(contents)? as usize;
        let mut suites = take(contents, suites_length)?;
        take(contents, 1)?; // maximum_name_length
        let name_length = take(contents, 1)?[0] as usize;
        let name = take(contents, name_length)?;
        let extensions_length = u16_at(contents)? as usize;
        let mut extensions = take(contents, extensions_length)?;
        anyhow::ensure!(contents.is_empty(), "trailing ECHConfig bytes");
        let mut suite_ok = false;
        while !suites.is_empty() {
            let kdf = u16_at(&mut suites)?;
            let aead = u16_at(&mut suites)?;
            suite_ok |= kdf == 0x0001 && matches!(aead, 0x0001..=0x0003);
        }
        let mut mandatory = false;
        while !extensions.is_empty() {
            let kind = u16_at(&mut extensions)?;
            let length = u16_at(&mut extensions)? as usize;
            take(&mut extensions, length)?;
            mandatory |= kind & 0x8000 != 0;
        }
        Ok(kem == 0x0020 && key_length == 32 && suite_ok && !mandatory && ldh_public_name(name))
    }
    let mut input = list;
    let Ok(total) = u16_at(&mut input) else {
        return false;
    };
    if total as usize != input.len() || total == 0 {
        return false;
    }
    let mut found = false;
    while !input.is_empty() {
        let (Ok(version), Ok(length)) = (u16_at(&mut input), u16_at(&mut input)) else {
            return false;
        };
        let Ok(mut contents) = take(&mut input, length as usize) else {
            return false;
        };
        if version == 0xfe0d {
            match usable(&mut contents) {
                Ok(ok) => found |= ok,
                Err(_) => return false,
            }
        }
    }
    found
}

/// AWS-LC's `ssl_is_valid_ech_public_name`.
fn ldh_public_name(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let labels: Vec<&[u8]> = name.split(|byte| *byte == b'.').collect();
    let ldh = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-')
            && label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    });
    let last = labels.last().copied().unwrap_or_default();
    let decimal = last.iter().all(u8::is_ascii_digit);
    let hex = last.len() >= 2
        && last[0] == b'0'
        && matches!(last[1], b'x' | b'X')
        && last[2..].iter().all(u8::is_ascii_hexdigit);
    ldh && !decimal && !hex
}

/// Build from the signed list only, ignoring an in-memory learned rotation.
/// A held provider uses this to retain an immutable fail-closed rollback
/// connector even when a previous session already learned a CDN key.
pub fn original_pinned_ech_mode(
    settings: &RelaySettings,
) -> anyhow::Result<Option<rustls::client::EchMode>> {
    pinned_list(settings)?
        .map(|list| ech_config(list).map(Into::into))
        .transpose()
}

/// Validate public inline bytes before profile pinning, output, or network I/O.
/// Errors never contain the caller's encoded configuration.
pub fn inline_ech_config(encoded: &str) -> anyhow::Result<rustls::client::EchConfig> {
    anyhow::ensure!(
        !encoded.is_empty() && encoded.len() <= 21848,
        "inline ECHConfigList is empty or exceeds its size bound"
    );
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("inline ECHConfigList encoding invalid"))?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_LIST_BYTES,
        "inline ECHConfigList is empty or exceeds its size bound"
    );
    ech_config(bytes)
        .map_err(|_| anyhow::anyhow!("inline ECHConfigList has no usable supported config"))
}

/// Public facts about one ECHConfig, parsed without any key material.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EchConfigSummary {
    pub version: u16,
    /// Present only for the RFC 9849 version (0xfe0d).
    pub config_id: Option<u8>,
    pub kem_id: Option<u16>,
    pub public_name: Option<String>,
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> anyhow::Result<&'a [u8]> {
    anyhow::ensure!(input.len() >= length, "truncated ECHConfigList");
    let (head, tail) = input.split_at(length);
    *input = tail;
    Ok(head)
}

fn u16_at(input: &mut &[u8]) -> anyhow::Result<u16> {
    let bytes = take(input, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Parse an ECHConfigList (u16-prefixed vector of ECHConfig) structurally.
pub fn ech_config_summaries(list: &[u8]) -> anyhow::Result<Vec<EchConfigSummary>> {
    anyhow::ensure!(
        !list.is_empty() && list.len() <= MAX_LIST_BYTES,
        "ECHConfigList is empty or exceeds its size bound"
    );
    let mut input = list;
    let total = u16_at(&mut input)? as usize;
    anyhow::ensure!(
        total == input.len() && total > 0,
        "ECHConfigList length mismatch"
    );
    let mut summaries = Vec::new();
    while !input.is_empty() {
        let version = u16_at(&mut input)?;
        let length = u16_at(&mut input)? as usize;
        let mut contents = take(&mut input, length)?;
        if version != 0xfe0d {
            summaries.push(EchConfigSummary {
                version,
                config_id: None,
                kem_id: None,
                public_name: None,
            });
            continue;
        }
        let config_id = take(&mut contents, 1)?[0];
        let kem_id = u16_at(&mut contents)?;
        let key_length = u16_at(&mut contents)? as usize;
        take(&mut contents, key_length)?;
        let suites_length = u16_at(&mut contents)? as usize;
        anyhow::ensure!(
            suites_length >= 4 && suites_length.is_multiple_of(4),
            "invalid ECH cipher suite vector"
        );
        take(&mut contents, suites_length)?;
        take(&mut contents, 1)?; // maximum_name_length
        let name_length = take(&mut contents, 1)?[0] as usize;
        let name = take(&mut contents, name_length)?;
        let name = std::str::from_utf8(name).context("ECH public_name encoding")?;
        anyhow::ensure!(
            matches!(
                rustls::pki_types::ServerName::try_from(name.to_owned()),
                Ok(rustls::pki_types::ServerName::DnsName(_))
            ),
            "ECH public_name is not a DNS name"
        );
        let extensions_length = u16_at(&mut contents)? as usize;
        take(&mut contents, extensions_length)?;
        anyhow::ensure!(contents.is_empty(), "trailing ECHConfig bytes");
        summaries.push(EchConfigSummary {
            version,
            config_id: Some(config_id),
            kem_id: Some(kem_id),
            public_name: Some(name.to_ascii_lowercase()),
        });
    }
    Ok(summaries)
}

fn public_names(list: &[u8]) -> anyhow::Result<Vec<String>> {
    Ok(ech_config_summaries(list)?
        .into_iter()
        .filter_map(|summary| summary.public_name)
        .collect())
}

type RotationKey = (String, [u8; 32]);

/// Exact held-provider rotation scope. A same-name direct route without ECH
/// has no scope and must never inherit a fronted route's learned config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRotationScope(RotationKey);

pub fn held_rotation_scope(settings: &RelaySettings) -> anyhow::Result<Option<HeldRotationScope>> {
    anyhow::ensure!(
        settings.ech_config_list.is_none(),
        "held ECH scope cannot reopen a file"
    );
    Ok(pinned_list(settings)?
        .as_deref()
        .map(|pinned| HeldRotationScope(rotation_key(settings, pinned))))
}
type Rotations = Mutex<HashMap<RotationKey, (Vec<u8>, Instant, RotationToken)>>;

/// Identity of one learned rotation, for conditional rollback after a local
/// connector-build failure. It carries no ECH config or private material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationToken(u64);

static NEXT_ROTATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn rotations() -> &'static Rotations {
    static ROTATIONS: OnceLock<Rotations> = OnceLock::new();
    ROTATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn rotation_key(settings: &RelaySettings, pinned: &[u8]) -> RotationKey {
    (
        settings.server_name.to_ascii_lowercase(),
        Sha256::digest(pinned).into(),
    )
}

fn rotation(settings: &RelaySettings, pinned: &[u8]) -> Option<(Vec<u8>, RotationToken)> {
    let mut map = rotations().lock().unwrap_or_else(|e| e.into_inner());
    let key = rotation_key(settings, pinned);
    match map.get(&key) {
        Some((list, captured, token)) if captured.elapsed() < MAX_ROTATION_AGE => {
            Some((list.clone(), *token))
        }
        Some(_) => {
            map.remove(&key);
            None
        }
        None => None,
    }
}

/// Whether the current connector uses an authenticated rotation for this pin.
pub fn has_rotation(settings: &RelaySettings) -> bool {
    pinned_list(settings)
        .ok()
        .flatten()
        .and_then(|pinned| rotation(settings, &pinned))
        .is_some()
}

/// Drop a learned rotation (after a retry was itself rejected).
pub fn forget_rotation(settings: &RelaySettings) {
    if let Ok(Some(pinned)) = pinned_list(settings) {
        rotations()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&rotation_key(settings, &pinned));
    }
}

/// Forget only this caller's learned generation; another pool may have
/// published a newer authenticated rejection meanwhile.
pub fn forget_rotation_if_current(settings: &RelaySettings, token: RotationToken) {
    if let Ok(Some(pinned)) = pinned_list(settings) {
        let mut map = rotations().lock().unwrap_or_else(|e| e.into_inner());
        let key = rotation_key(settings, &pinned);
        if map
            .get(&key)
            .is_some_and(|(_, _, current)| *current == token)
        {
            map.remove(&key);
        }
    }
}

/// Whether the named authority still has exactly the caller's generation.
pub fn rotation_is_current(settings: &RelaySettings, token: RotationToken) -> bool {
    let Ok(Some(pinned)) = pinned_list(settings) else {
        return false;
    };
    let map = rotations().lock().unwrap_or_else(|e| e.into_inner());
    map.get(&rotation_key(settings, &pinned))
        .is_some_and(|(_, captured, current)| {
            captured.elapsed() < MAX_ROTATION_AGE && *current == token
        })
}

/// The retry configs carried by an authenticated ECH rejection, if any.
fn rejection_retry_list(error: &(dyn std::error::Error + 'static)) -> Option<Option<Vec<u8>>> {
    use rustls::internal::msgs::codec::Codec;
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(cause) = current {
        if let Some(retry) = cause.downcast_ref::<AuthenticatedEchRetry>() {
            return Some(
                retry
                    .retry_configs
                    .clone()
                    .filter(|configs| !configs.is_empty()),
            );
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if let Some(retry) = io
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<AuthenticatedEchRetry>())
            {
                return Some(
                    retry
                        .retry_configs
                        .clone()
                        .filter(|configs| !configs.is_empty()),
                );
            }
        }
        let rustls_error = cause.downcast_ref::<rustls::Error>().or_else(|| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(|io| io.get_ref())
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        });
        if let Some(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
        )) = rustls_error
        {
            return Some(configs.as_ref().filter(|c| !c.is_empty()).map(|configs| {
                let mut bytes = Vec::new();
                configs.encode(&mut bytes);
                bytes
            }));
        }
        current = cause.source();
    }
    None
}

/// Outcome of inspecting a failed outer TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchRejection {
    /// Not an ECH rejection: handle the error normally.
    NotEch,
    /// Rejected with authenticated, admitted retry configs: one fresh dial may
    /// use them (they are now cached for this authority and pin).
    RetryAdmitted,
    /// Rejected without usable or admissible retry configs: fail closed.
    Refused,
}

/// Inspect a TLS handshake error. Only retry configs from an authenticated
/// rejection whose every config keeps a pinned public name are admitted.
pub fn record_rejection(
    settings: &RelaySettings,
    error: &(dyn std::error::Error + 'static),
) -> EchRejection {
    record_rejection_with_token(settings, error).0
}

/// The same authenticated admission as [`record_rejection`], exposing the
/// generation only to a held connector owner that can publish atomically.
pub fn record_rejection_with_token(
    settings: &RelaySettings,
    error: &(dyn std::error::Error + 'static),
) -> (EchRejection, Option<RotationToken>) {
    let Some(retry) = rejection_retry_list(error) else {
        return (EchRejection::NotEch, None);
    };
    let Some(retry) = retry else {
        return (EchRejection::Refused, None);
    };
    let admitted = (|| -> anyhow::Result<RotationToken> {
        let pinned = pinned_list(settings)?.context("ECH rejection without a pinned list")?;
        anyhow::ensure!(retry.len() <= MAX_LIST_BYTES, "retry configs exceed bound");
        let pinned_names = public_names(&pinned)?;
        let retry_names = public_names(&retry)?;
        anyhow::ensure!(
            !retry_names.is_empty() && retry_names.iter().all(|name| pinned_names.contains(name)),
            "retry configs change the pinned ECH public name"
        );
        ech_config(retry.clone())?;
        let mut map = rotations().lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_ROTATIONS {
            map.retain(|_, (_, captured, _)| captured.elapsed() < MAX_ROTATION_AGE);
            if map.len() >= MAX_ROTATIONS {
                map.clear();
            }
        }
        let token = RotationToken(NEXT_ROTATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        map.insert(
            rotation_key(settings, &pinned),
            (retry, Instant::now(), token),
        );
        Ok(token)
    })();
    match admitted {
        Ok(token) => (EchRejection::RetryAdmitted, Some(token)),
        Err(_) => (EchRejection::Refused, None),
    }
}

/// Extract the ECHConfigList from one DNS HTTPS (SVCB, RFC 9460) record.
///
/// Accepts the presentation form printed by `dig +short HTTPS name`
/// (`1 . alpn="h3,h2" ... ech=BASE64`) or the RFC 3597 generic form
/// (`\# LEN HEX...`) returned by some resolvers and DNS-over-HTTPS JSON.
/// The result is only an operator input for a pinned device profile: DNS is
/// not authenticated here, so the operator must verify it with a live
/// handshake before pinning, and the device never fetches DNS for ECH.
pub fn ech_config_from_https_record(record: &str) -> anyhow::Result<Vec<u8>> {
    let record = record.trim();
    anyhow::ensure!(record.len() <= 64 * 1024, "HTTPS record too large");
    if let Some(generic) = record.strip_prefix("\\#") {
        let mut parts = generic.split_whitespace();
        let length: usize = parts
            .next()
            .context("generic RDATA length missing")?
            .parse()
            .context("generic RDATA length")?;
        let hex: String = parts.collect();
        let rdata = hex::decode(hex).context("generic RDATA hex")?;
        anyhow::ensure!(rdata.len() == length, "generic RDATA length mismatch");
        return ech_config_from_https_rdata(&rdata);
    }
    let token = record
        .split_whitespace()
        .find_map(|token| token.strip_prefix("ech="))
        .context("HTTPS record has no ech parameter")?;
    let token = token.trim_matches('"');
    let list = base64::engine::general_purpose::STANDARD
        .decode(token)
        .context("ech parameter is not base64")?;
    ech_config_summaries(&list)?;
    Ok(list)
}

/// Extract the `ech` SvcParam (key 5) from binary HTTPS/SVCB RDATA.
pub fn ech_config_from_https_rdata(rdata: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut input = rdata;
    let priority = u16_at(&mut input)?;
    anyhow::ensure!(priority != 0, "AliasMode HTTPS record carries no ECH");
    // Uncompressed TargetName (RFC 9460 forbids compression here).
    loop {
        let length = take(&mut input, 1)?[0] as usize;
        anyhow::ensure!(length < 64, "invalid TargetName label");
        if length == 0 {
            break;
        }
        take(&mut input, length)?;
    }
    let mut previous = None;
    let mut ech = None;
    while !input.is_empty() {
        let key = u16_at(&mut input)?;
        anyhow::ensure!(
            previous.is_none_or(|p| key > p),
            "SvcParams are not in strictly increasing key order"
        );
        previous = Some(key);
        let length = u16_at(&mut input)? as usize;
        let value = take(&mut input, length)?;
        if key == 5 {
            ech = Some(value.to_vec());
        }
    }
    let list = ech.context("HTTPS record has no ech SvcParam")?;
    ech_config_summaries(&list)?;
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn synthetic_list(entries: &[(u8, &str)]) -> Vec<u8> {
        let mut configs = Vec::new();
        for (config_id, public_name) in entries {
            // X25519/HKDF-SHA256, AES-128-GCM; a structurally valid public key.
            let mut contents = vec![*config_id, 0, 32, 0, 32, 9];
            contents.extend([0; 31]);
            contents.extend([0, 4, 0, 1, 0, 1, 0]);
            contents.push(public_name.len() as u8);
            contents.extend(public_name.as_bytes());
            contents.extend([0, 0]);
            configs.extend([0xfe, 0x0d]);
            configs.extend((contents.len() as u16).to_be_bytes());
            configs.extend(contents);
        }
        let mut list = (configs.len() as u16).to_be_bytes().to_vec();
        list.extend(configs);
        list
    }

    #[test]
    fn summaries_report_public_names_and_refuse_malformed_lists() {
        let list = synthetic_list(&[(7, "cover.example"), (8, "cover.example")]);
        let summaries = ech_config_summaries(&list).unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].config_id, Some(7));
        assert_eq!(summaries[1].public_name.as_deref(), Some("cover.example"));
        let mut truncated = list.clone();
        truncated.pop();
        assert!(ech_config_summaries(&truncated).is_err());
        let mut wrong_total = list.clone();
        wrong_total[1] ^= 1;
        assert!(ech_config_summaries(&wrong_total).is_err());
        assert!(ech_config_summaries(&[]).is_err());
        assert!(ech_config_summaries(&synthetic_list(&[(1, "not a name")])).is_err());
    }

    fn config_with(
        kem: u16,
        key: usize,
        suites: &[(u16, u16)],
        name: &str,
        ext: &[u16],
    ) -> Vec<u8> {
        let mut contents = vec![5];
        contents.extend(kem.to_be_bytes());
        contents.extend((key as u16).to_be_bytes());
        contents.extend(vec![9; key]);
        contents.extend(((suites.len() * 4) as u16).to_be_bytes());
        for (kdf, aead) in suites {
            contents.extend(kdf.to_be_bytes());
            contents.extend(aead.to_be_bytes());
        }
        contents.push(0);
        contents.push(name.len() as u8);
        contents.extend(name.as_bytes());
        contents.extend(((ext.len() * 4) as u16).to_be_bytes());
        for kind in ext {
            contents.extend(kind.to_be_bytes());
            contents.extend([0, 0]);
        }
        let mut config = vec![0xfe, 0x0d];
        config.extend((contents.len() as u16).to_be_bytes());
        config.extend(contents);
        config
    }

    fn list_of(configs: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = configs.concat();
        let mut list = (body.len() as u16).to_be_bytes().to_vec();
        list.extend(body);
        list
    }

    #[test]
    fn aws_lc_offerability_mirrors_its_ech_client_selection() {
        let x25519 = config_with(0x0020, 32, &[(1, 1)], "cover.example", &[]);
        let p256 = config_with(0x0010, 65, &[(1, 1)], "cover.example", &[]);
        assert!(aws_lc_offers_ech(&synthetic_list(&[(1, "cover.example")])));
        assert!(aws_lc_offers_ech(&list_of(std::slice::from_ref(&x25519))));
        // Rustls accepts P-256; AWS-LC skips it and would send a plain hello.
        ech_config(list_of(std::slice::from_ref(&p256))).expect("rustls admits P-256");
        assert!(!aws_lc_offers_ech(&list_of(std::slice::from_ref(&p256))));
        assert!(aws_lc_offers_ech(&list_of(&[p256.clone(), x25519.clone()])));
        for (kdf, aead) in [(2, 1), (1, 0xffff), (3, 3)] {
            let only = config_with(0x0020, 32, &[(kdf, aead)], "cover.example", &[]);
            assert!(!aws_lc_offers_ech(&list_of(&[only])), "{kdf:#x}/{aead:#x}");
        }
        let chacha = config_with(0x0020, 32, &[(2, 1), (1, 3)], "cover.example", &[]);
        assert!(aws_lc_offers_ech(&list_of(&[chacha])));
        let mandatory = config_with(0x0020, 32, &[(1, 1)], "cover.example", &[0x8001]);
        assert!(!aws_lc_offers_ech(&list_of(&[mandatory])));
        let optional = config_with(0x0020, 32, &[(1, 1)], "cover.example", &[0x0001]);
        assert!(aws_lc_offers_ech(&list_of(&[optional])));
        assert!(!aws_lc_offers_ech(&list_of(&[config_with(
            0x0020,
            31,
            &[(1, 1)],
            "cover.example",
            &[]
        )])));
        for name in [
            "cover.123",
            "cover.0x1f",
            "-cover.example",
            "cover..example",
            "a_b.example",
        ] {
            let config = config_with(0x0020, 32, &[(1, 1)], name, &[]);
            assert!(!aws_lc_offers_ech(&list_of(&[config])), "{name}");
        }
        let mut truncated = list_of(std::slice::from_ref(&x25519));
        truncated.pop();
        assert!(!aws_lc_offers_ech(&truncated));
        assert!(!aws_lc_offers_ech(&[]));
    }

    #[test]
    fn effective_list_refuses_a_pin_aws_lc_cannot_offer() {
        let p256 = list_of(&[config_with(0x0010, 65, &[(1, 1)], "cover.example", &[])]);
        let settings = RelaySettings {
            server_name: "relay.example".into(),
            ech_config_list_base64: Some(base64::engine::general_purpose::STANDARD.encode(&p256)),
            ..RelaySettings::default()
        };
        assert!(
            pinned_ech_mode(&settings).unwrap().is_some(),
            "rustls path keeps it"
        );
        assert!(effective_ech_config_list(&settings).is_err());
        let usable = synthetic_list(&[(1, "cover.example")]);
        let settings = RelaySettings {
            server_name: "relay.example".into(),
            ech_config_list_base64: Some(base64::engine::general_purpose::STANDARD.encode(&usable)),
            ..RelaySettings::default()
        };
        assert_eq!(effective_ech_config_list(&settings).unwrap(), Some(usable));
    }

    fn https_rdata(list: &[u8], extra_after: bool) -> Vec<u8> {
        let mut rdata = vec![0, 1, 0]; // priority 1, TargetName "."
        rdata.extend([0, 1, 0, 3, 2, b'h', b'2']); // alpn=h2
        rdata.extend([0, 5]);
        rdata.extend((list.len() as u16).to_be_bytes());
        rdata.extend(list);
        if extra_after {
            rdata.extend([0, 4, 0, 4, 192, 0, 2, 1]); // ipv4hint out of order
        }
        rdata
    }

    #[test]
    fn https_record_presentation_and_generic_forms_yield_the_same_list() {
        let list = synthetic_list(&[(3, "cloudflare-ech.com")]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&list);
        let presentation =
            format!("1 . alpn=\"h3,h2\" ipv4hint=192.0.2.1 ech={encoded} ipv6hint=2001:db8::1");
        assert_eq!(ech_config_from_https_record(&presentation).unwrap(), list);
        let quoted = format!("1 . ech=\"{encoded}\"");
        assert_eq!(ech_config_from_https_record(&quoted).unwrap(), list);
        let rdata = https_rdata(&list, false);
        let generic = format!("\\# {} {}", rdata.len(), hex::encode(&rdata));
        assert_eq!(ech_config_from_https_record(&generic).unwrap(), list);
        // Out-of-order keys, AliasMode, missing ech and length lies are refused.
        assert!(ech_config_from_https_rdata(&https_rdata(&list, true)).is_err());
        let mut alias = rdata.clone();
        alias[1] = 0;
        assert!(ech_config_from_https_rdata(&alias).is_err());
        assert!(ech_config_from_https_record("1 . alpn=h2").is_err());
        let lying = format!("\\# {} {}", rdata.len() + 1, hex::encode(&rdata));
        assert!(ech_config_from_https_record(&lying).is_err());
    }

    #[test]
    fn non_ech_errors_are_not_rotations() {
        let settings = RelaySettings {
            server_name: "relay.example".into(),
            ech_config_list_base64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(synthetic_list(&[(1, "cover.example")])),
            ),
            ..RelaySettings::default()
        };
        let error = std::io::Error::other("connection reset");
        assert_eq!(record_rejection(&settings, &error), EchRejection::NotEch);
        let rejected = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(None),
            ),
        );
        assert_eq!(
            record_rejection(&settings, &rejected),
            EchRejection::Refused
        );
        assert!(!has_rotation(&settings));
    }
}
