//! An opt-in HTTPS carrier admission gate, never a replacement for inner TLS.
//! The credential is carried only inside verified outer TLS. This protocol
//! does not claim browser fingerprint equivalence or allowlist reachability.
use http::{header::HeaderValue, Request};
use serde::{Deserialize, Serialize};
use std::{
    fmt, io,
    path::{Component, Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const KEY_HEADER: &str = "x-aegis-bridge-key";
pub const SIDECAR: &str = "https-bridge.toml";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Traffic,
    Enrollment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub authority: String,
    pub path: String,
    pub enrollment_path: String,
    pub credential_file: PathBuf,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "HTTPS bridge policy rejected")
}

pub fn clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

pub(crate) fn valid_authority(value: &str) -> bool {
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

pub(crate) fn valid_path(value: &str) -> bool {
    value.len() > 1
        && value.len() <= 256
        && value.starts_with('/')
        && !value.contains("//")
        && !value.split('/').any(|part| matches!(part, "." | ".."))
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
}

impl ClientSettings {
    pub fn validate(&self) -> io::Result<()> {
        if !cfg!(any(unix, windows)) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTPS bridge requires enforced private-file custody",
            ));
        }
        if !valid_authority(&self.authority)
            || !valid_path(&self.path)
            || !valid_path(&self.enrollment_path)
            || self.path == self.enrollment_path
            || !clean_absolute(&self.credential_file)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn validate_authority(&self, authority: &str) -> io::Result<()> {
        self.validate()?;
        if self.authority != authority {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn path(&self, purpose: Purpose) -> &str {
        match purpose {
            Purpose::Traffic => &self.path,
            Purpose::Enrollment => &self.enrollment_path,
        }
    }
    pub fn load_credential(&self) -> io::Result<Credential> {
        self.validate()?;
        Credential::load(&self.credential_file)
    }
}

/// No serialization or exposed Debug representation of the key bytes.
pub struct Credential(Zeroizing<[u8; 64]>);
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential([redacted])")
    }
}
impl Credential {
    fn load(path: &Path) -> io::Result<Self> {
        crate::secret_file::trusted_read_parent(path).map_err(|_| invalid())?;
        let raw = crate::secret_file::read(path, 65).map_err(|_| invalid())?;
        let bytes = raw.strip_suffix(b"\n").unwrap_or(&raw);
        Self::from_captured_bytes(bytes)
    }

    /// Prepare the existing carrier credential from a caller-held private
    /// snapshot. The caller must retain and validate its file custody; this
    /// constructor never reopens `ClientSettings::credential_file`.
    pub fn from_captured_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 64
            || bytes
                .iter()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
            || bytes.iter().all(|b| *b == b'0')
        {
            return Err(invalid());
        }
        let mut key = Zeroizing::new([0; 64]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
    pub fn header_value(&self) -> HeaderValue {
        let mut value =
            HeaderValue::from_bytes(&*self.0).expect("validated hexadecimal credential");
        value.set_sensitive(true);
        value
    }
    fn accepts(&self, value: &[u8]) -> bool {
        value.len() == 64 && bool::from(self.0.as_slice().ct_eq(value))
    }
    /// Load a 64-hex private admission key with the same owner-only custody
    /// checks as the bridge credential. Used by the CDN-fronted origin gate.
    pub fn load_private(path: &Path) -> io::Result<Self> {
        if !clean_absolute(path) {
            return Err(invalid());
        }
        Self::load(path)
    }
    pub(crate) fn accepts_value(&self, value: &[u8]) -> bool {
        self.accepts(value)
    }
    pub(crate) fn same_secret(&self, other: &Self) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub carrier: ClientSettings,
    /// Explicit public content, not a path to a possibly private file.
    pub site_html: String,
}
impl ServerSettings {
    pub fn validate(&self) -> io::Result<()> {
        self.carrier.validate()?;
        if self.site_html.is_empty() || self.site_html.len() > 64 * 1024 {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Loaded once before binding. All rejected routes get the same public reply.
#[derive(Debug)]
pub struct Gate {
    settings: ServerSettings,
    credential: Credential,
}
impl Gate {
    pub fn load(settings: &ServerSettings) -> io::Result<Self> {
        settings.validate()?;
        Ok(Self {
            settings: settings.clone(),
            credential: settings.carrier.load_credential()?,
        })
    }
    pub fn admits<T>(&self, request: &Request<T>, purpose: Purpose) -> bool {
        let headers = request.headers();
        request.method() == http::Method::POST
            && request.uri().scheme_str() == Some("https")
            && request
                .uri()
                .authority()
                .is_some_and(|a| a.as_str() == self.settings.carrier.authority)
            && request
                .uri()
                .path_and_query()
                .is_some_and(|p| p.as_str() == self.settings.carrier.path(purpose))
            && !headers.contains_key("host")
            && headers.get_all("content-type").iter().count() == 1
            && headers
                .get("content-type")
                .is_some_and(|v| v == "application/grpc")
            && headers.get_all(KEY_HEADER).iter().count() == 1
            && headers
                .get(KEY_HEADER)
                .is_some_and(|v| self.credential.accepts(v.as_bytes()))
    }
    pub fn site<T>(&self, request: &Request<T>) -> PublicResponse<'_> {
        if request.uri().scheme_str() != Some("https") || request.headers().contains_key("host") {
            return self.public_response(request.method().as_str(), None, None);
        }
        let authority = request.uri().authority().map(|a| a.as_str());
        self.public_response(
            request.method().as_str(),
            authority,
            request.uri().path_and_query().map(|p| p.as_str()),
        )
    }
    pub fn public_response(
        &self,
        method: &str,
        authority: Option<&str>,
        path: Option<&str>,
    ) -> PublicResponse<'_> {
        let root = matches!(method, "GET" | "HEAD")
            && authority == Some(self.settings.carrier.authority.as_str())
            && path == Some("/");
        PublicResponse {
            status: if root { 200 } else { 404 },
            body: if root {
                self.settings.site_html.as_bytes()
            } else {
                b"Not found\n"
            },
            head: method == "HEAD",
        }
    }
}
pub struct PublicResponse<'a> {
    pub status: u16,
    pub body: &'a [u8],
    pub head: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_credential_is_independent_of_mutated_source() {
        let mut captured = Zeroizing::new([b'a'; 64]);
        let prepared = Credential::from_captured_bytes(captured.as_slice()).unwrap();
        captured.fill(b'b');
        let header = prepared.header_value();
        assert!(header.is_sensitive());
        assert_eq!(header.as_bytes(), &[b'a'; 64]);
        assert!(Credential::from_captured_bytes(&[b'0'; 64]).is_err());
        assert!(Credential::from_captured_bytes(&[b'A'; 64]).is_err());
        assert!(Credential::from_captured_bytes(&[b'a'; 63]).is_err());
    }
    fn settings(path: PathBuf) -> ClientSettings {
        ClientSettings {
            authority: "bridge.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: path,
        }
    }
    #[test]
    fn bridge_policy_refuses_authority_confusion_and_unbounded_routes() {
        let base = settings(std::env::temp_dir().join("key"));
        assert!(base.validate().is_ok());
        for value in ["other.test", "bridge.test:443", "Bridge.test"] {
            assert!(base.validate_authority(value).is_err());
        }
        for path in ["/", "//stream", "/a/../b", "/a?b", "/a%2fb"] {
            let mut s = base.clone();
            s.path = path.into();
            assert!(s.validate().is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn gate_is_exact_role_bound_and_secret_debug_is_redacted() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        file.write_all(&[b'a'; 64]).unwrap();
        let cfg = ServerSettings {
            carrier: settings(file.path().to_owned()),
            site_html: "<!doctype html><title>Site</title>".into(),
        };
        let gate = Gate::load(&cfg).unwrap();
        let credential = cfg.carrier.load_credential().unwrap();
        assert!(credential.header_value().is_sensitive());
        assert!(!format!("{credential:?}").contains(&"a".repeat(64)));
        let request = || {
            Request::builder()
                .method("POST")
                .uri("https://bridge.test/private/stream")
                .header("content-type", "application/grpc")
                .header(KEY_HEADER, credential.header_value())
                .body(())
                .unwrap()
        };
        assert!(gate.admits(&request(), Purpose::Traffic));
        assert!(!gate.admits(&request(), Purpose::Enrollment));
        let mut wrong = request();
        wrong
            .headers_mut()
            .append(KEY_HEADER, credential.header_value());
        assert!(!gate.admits(&wrong, Purpose::Traffic));
        let mut wrong = request();
        wrong
            .headers_mut()
            .append("content-type", HeaderValue::from_static("application/grpc"));
        assert!(!gate.admits(&wrong, Purpose::Traffic));
        for uri in [
            "https://other.test/private/stream",
            "https://bridge.test/private/stream?x",
            "http://bridge.test/private/stream",
            "https://bridge.test/tunnel.v1.Channel/Connect",
        ] {
            let mut r = request();
            *r.uri_mut() = uri.parse().unwrap();
            assert!(!gate.admits(&r, Purpose::Traffic));
            assert_eq!(gate.site(&r).status, 404);
        }
        let root = Request::builder()
            .uri("https://bridge.test/")
            .body(())
            .unwrap();
        assert_eq!(gate.site(&root).status, 200);
    }
    #[cfg(unix)]
    #[test]
    fn credential_refuses_public_files_symlinks_and_malformed_bytes() {
        use std::{
            io::Write,
            os::unix::fs::{symlink, PermissionsExt},
        };
        let directory = tempfile::tempdir().unwrap();
        let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        file.write_all(&[b'a'; 64]).unwrap();
        let cfg = settings(file.path().to_owned());
        assert!(cfg.load_credential().is_ok());
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(cfg.load_credential().is_err());
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let alias = directory.path().join("alias");
        symlink(file.path(), &alias).unwrap();
        assert!(settings(alias).load_credential().is_err());
        for bytes in [
            vec![b'0'; 64],
            vec![b'a'; 66],
            vec![b'A'; 64],
            vec![b'a'; 63],
        ] {
            std::fs::write(file.path(), bytes).unwrap();
            assert!(cfg.load_credential().is_err());
        }
    }
}
