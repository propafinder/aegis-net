use crate::rejected;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::{
    fmt, io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const KEY_HEADER: &str = "x-aegis-bridge-key";
pub const CONTENT_TYPE: &str = "application/octet-stream";

fn valid_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && matches!(
            rustls::pki_types::ServerName::try_from(value.to_owned()),
            Ok(rustls::pki_types::ServerName::DnsName(_))
        )
}
fn valid_path(value: &str) -> bool {
    value.len() > 1
        && value.len() <= 256
        && value.starts_with('/')
        && !value.contains("//")
        && !value.split('/').any(|part| matches!(part, "." | ".."))
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
}
fn clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}
pub(crate) fn now_ms() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| rejected())?
            .as_millis(),
    )
    .map_err(|_| rejected())
}

/// Deterministic private identity-directory sidecar, independent of the device key.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub authority: String,
    pub descriptor_path: String,
    pub credential_file: PathBuf,
}
impl ClientSettings {
    pub fn validate(&self) -> io::Result<()> {
        if !valid_authority(&self.authority)
            || !valid_path(&self.descriptor_path)
            || !clean_absolute(&self.credential_file)
        {
            return Err(rejected());
        }
        Ok(())
    }
    /// The caller must supply the platform's trusted-owner/private-ACL reader.
    /// Both the sidecar and key are read through that reader before any dial.
    pub fn load_with(
        path: &Path,
        mut private_read: impl FnMut(&Path, usize) -> io::Result<Zeroizing<Vec<u8>>>,
    ) -> io::Result<(Self, Credential)> {
        if !clean_absolute(path) {
            return Err(rejected());
        }
        let bytes = private_read(path, 4096)?;
        if bytes.len() > 4096 {
            return Err(rejected());
        }
        let settings: Self = toml::from_str(std::str::from_utf8(&bytes).map_err(|_| rejected())?)
            .map_err(|_| rejected())?;
        settings.validate()?;
        let key = Credential::from_private_bytes(private_read(&settings.credential_file, 65)?)?;
        Ok((settings, key))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub client: ClientSettings,
    /// Explicit public inline HTML; never a filesystem path.
    pub site_html: String,
}
impl ServerSettings {
    pub fn validate(&self) -> io::Result<()> {
        self.client.validate()?;
        if self.site_html.is_empty() || self.site_html.len() > 64 * 1024 {
            return Err(rejected());
        }
        Ok(())
    }
}

/// Redacted admission key, distinct from inner device authentication.
#[derive(Clone)]
pub struct Credential(std::sync::Arc<Zeroizing<[u8; 64]>>);
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential([redacted])")
    }
}
impl Credential {
    pub fn from_private_bytes(raw: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        let value = raw.strip_suffix(b"\n").unwrap_or(&raw);
        if value.len() != 64
            || value.iter().all(|b| *b == b'0')
            || value
                .iter()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
        {
            return Err(rejected());
        }
        let mut bytes = Zeroizing::new([0; 64]);
        bytes.copy_from_slice(value);
        Ok(Self(std::sync::Arc::new(bytes)))
    }
    pub fn header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_bytes(self.0.as_slice()).expect("validated key");
        value.set_sensitive(true);
        value
    }
    pub(crate) fn admits<T>(&self, request: &http::Request<T>, authority: &str) -> bool {
        request.method() == http::Method::POST
            && request.uri().scheme_str() == Some("https")
            && request
                .uri()
                .authority()
                .is_some_and(|a| a.as_str() == authority)
            && !request.headers().contains_key("host")
            && request.headers().get_all("content-type").iter().count() == 1
            && request
                .headers()
                .get("content-type")
                .is_some_and(|h| h == CONTENT_TYPE)
            && request.headers().get_all(KEY_HEADER).iter().count() == 1
            && request.headers().get(KEY_HEADER).is_some_and(|h| {
                h.as_bytes().len() == 64 && bool::from(self.0.as_slice().ct_eq(h.as_bytes()))
            })
    }
}

/// Delivered only through verified HTTPS with exact admission; contains no key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub authority: String,
    pub ingress: SocketAddr,
    pub path: String,
    pub generation: u64,
    pub expires_unix_ms: u64,
    pub frame_bytes: usize,
}
impl Descriptor {
    pub fn validate(&self, settings: &ClientSettings, limits: &Limits) -> io::Result<()> {
        settings.validate()?;
        limits.validate()?;
        let now = now_ms()?;
        if self.version != 1
            || self.authority != settings.authority
            || !valid_path(&self.path)
            || self.path == settings.descriptor_path
            || self.ingress.port() == 0
            || self.ingress.ip().is_unspecified()
            || self.ingress.ip().is_multicast()
            || self.generation == 0
            || self.expires_unix_ms <= now
            || self.expires_unix_ms - now > 600_000
            || self.frame_bytes == 0
            || self.frame_bytes > limits.frame_bytes
        {
            return Err(rejected());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub frame_bytes: usize,
    pub max_sessions: usize,
    pub max_connections: usize,
    pub max_requests: usize,
    pub request_timeout: Duration,
    pub poll_interval: Duration,
    pub unauthenticated_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub descriptor_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 16 * 1024,
            max_sessions: 64,
            max_connections: 32,
            max_requests: 128,
            request_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(20),
            unauthenticated_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600),
            descriptor_lifetime: Duration::from_secs(300),
        }
    }
}
impl Limits {
    pub fn validate(&self) -> io::Result<()> {
        if self.frame_bytes == 0
            || self.frame_bytes > 32 * 1024
            || self.max_sessions == 0
            || self.max_sessions > 1024
            || self.max_connections == 0
            || self.max_connections > 1024
            || self.max_requests == 0
            || self.max_requests > 4096
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(30)
            || self.poll_interval < Duration::from_millis(1)
            || self.poll_interval > Duration::from_secs(1)
            || self.unauthenticated_timeout.is_zero()
            || self.unauthenticated_timeout > Duration::from_secs(10)
            || self.idle_timeout.is_zero()
            || self.idle_timeout > Duration::from_secs(300)
            || self.max_lifetime.is_zero()
            || self.max_lifetime > Duration::from_secs(3600)
            || self.descriptor_lifetime.is_zero()
            || self.descriptor_lifetime > Duration::from_secs(600)
        {
            return Err(rejected());
        }
        Ok(())
    }
}
