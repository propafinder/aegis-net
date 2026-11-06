//! Origin admission for a CDN-fronted, device-enrolled relay.
//!
//! The terminating CDN (for example Cloudflare with gRPC enabled) forwards
//! client gRPC streams to the origin over its own HTTP/2 connection and adds a
//! private origin-pull header through an operator-owned request transform.
//! The device never holds that header value: it authenticates end to end with
//! the separate inner device mTLS. This gate only decides whether an HTTP/2
//! request arrived through the configured CDN path; it never replaces inner
//! TLS, device authorization, target policy or enrollment proof.
//!
//! A request that fails any check receives the ordinary public decoy; no
//! inner TLS byte, enrollment forwarder or target is reached.
use crate::https_bridge::Credential;
use http::Request;
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr, path::PathBuf};

/// Header injected by the CDN request transform on the CDN-to-origin leg only.
pub const ORIGIN_KEY_HEADER: &str = "x-aegis-origin-key";

/// The fixed enrollment route (`secure_channel::enrollment_tls::GRPC_PATH`),
/// repeated here because that module is behind the `device-enrollment`
/// feature; a test pins the two values together.
pub const ENROLLMENT_PATH: &str = "/enrollment.v1.Authority/Exchange";

/// Which fixed enrolled route a fronted request is allowed to reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// `secure_channel::GRPC_PATH`: inner device TLS, then TCP/UDP opens.
    Traffic,
    /// `secure_channel::enrollment_tls::GRPC_PATH`: opaque forward to the
    /// separate enrollment authority (same public authority and port 443).
    Enrollment,
}

/// Optional same-port enrollment forwarding ("variant B"). The relay never
/// holds the issuer key; it pipes the opaque enrollment gRPC stream to the
/// separately configured authority listener, whose outer TLS it verifies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentForwardSettings {
    /// Authority listener, normally loopback on the same host.
    pub authority_address: SocketAddr,
    /// DNS name in the authority's outer certificate.
    pub server_name: String,
    /// Public CA that issued the authority's outer certificate.
    pub ca: PathBuf,
    /// Simultaneous forwarded enrollment streams. Defaults to 8.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
}

fn default_max_concurrent() -> usize {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Public edge authority the CDN forwards (`:authority`/Host).
    pub authority: String,
    /// Private 64-hex origin-pull key, the value the CDN transform injects.
    pub credential_file: PathBuf,
    /// Optional second key accepted during an origin-key rotation.
    #[serde(default)]
    pub next_credential_file: Option<PathBuf>,
    #[serde(default)]
    pub enrollment_forward: Option<EnrollmentForwardSettings>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').count() >= 2
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

impl Settings {
    pub fn validate(&self) -> io::Result<()> {
        if !cfg!(any(unix, windows)) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fronted origin requires enforced private-file custody",
            ));
        }
        if !valid_dns_name(&self.authority) {
            return Err(invalid(
                "fronted origin authority must be a lowercase DNS name",
            ));
        }
        if !crate::https_bridge::clean_absolute(&self.credential_file)
            || self
                .next_credential_file
                .as_deref()
                .is_some_and(|next| !crate::https_bridge::clean_absolute(next))
            || self.next_credential_file.as_ref() == Some(&self.credential_file)
        {
            return Err(invalid(
                "fronted origin credentials must be distinct clean absolute paths",
            ));
        }
        if let Some(forward) = &self.enrollment_forward {
            if !valid_dns_name(&forward.server_name)
                || !crate::https_bridge::clean_absolute(&forward.ca)
                || forward.authority_address.port() == 0
                || forward.authority_address.ip().is_unspecified()
                || forward.authority_address.ip().is_multicast()
                || !(1..=64).contains(&forward.max_concurrent)
            {
                return Err(invalid("fronted enrollment forward settings rejected"));
            }
        }
        Ok(())
    }

    /// Every private path this configuration reads, for key-separation checks.
    pub fn credential_paths(&self) -> impl Iterator<Item = &std::path::Path> {
        std::iter::once(self.credential_file.as_path()).chain(self.next_credential_file.as_deref())
    }
}

/// Loaded once before binding. Key bytes never appear in Debug output.
#[derive(Debug)]
pub struct Gate {
    authority: String,
    keys: Vec<Credential>,
    enrollment: bool,
}

impl Gate {
    pub fn load(settings: &Settings) -> io::Result<Self> {
        settings.validate()?;
        let mut keys = Vec::with_capacity(2);
        for path in settings.credential_paths() {
            keys.push(
                Credential::load_private(path)
                    .map_err(|_| invalid("fronted origin credential rejected"))?,
            );
        }
        if keys.len() == 2 && keys[0].same_secret(&keys[1]) {
            return Err(invalid("fronted origin rotation keys must differ"));
        }
        Ok(Self {
            authority: settings.authority.clone(),
            keys,
            enrollment: settings.enrollment_forward.is_some(),
        })
    }

    /// Classify one HTTP/2 request. `None` means: answer with the decoy and
    /// never touch inner TLS, the authority or a target.
    pub fn route<T>(&self, request: &Request<T>) -> Option<Route> {
        let headers = request.headers();
        let uri = request.uri();
        let authority_ok = uri
            .authority()
            .is_some_and(|authority| authority.as_str() == self.authority)
            && match headers.get_all(http::header::HOST).iter().count() {
                0 => true,
                1 => headers
                    .get(http::header::HOST)
                    .is_some_and(|host| host.as_bytes() == self.authority.as_bytes()),
                _ => false,
            };
        let key_ok = headers.get_all(ORIGIN_KEY_HEADER).iter().count() == 1
            && headers.get(ORIGIN_KEY_HEADER).is_some_and(|value| {
                // Evaluate every configured key so the comparison count does
                // not depend on which key (if any) matched.
                self.keys.iter().fold(false, |accepted, key| {
                    key.accepts_value(value.as_bytes()) | accepted
                })
            });
        let shape_ok = request.method() == http::Method::POST
            && uri.scheme_str() == Some("https")
            && headers.get_all(http::header::CONTENT_TYPE).iter().count() == 1
            && headers
                .get(http::header::CONTENT_TYPE)
                .is_some_and(|value| value == "application/grpc");
        if !(authority_ok && key_ok && shape_ok) {
            return None;
        }
        match uri.path_and_query().map(|path| path.as_str()) {
            Some(crate::secure_channel::GRPC_PATH) => Some(Route::Traffic),
            Some(ENROLLMENT_PATH) if self.enrollment => Some(Route::Enrollment),
            _ => None,
        }
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn key_file(dir: &std::path::Path, name: &str, byte: u8) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, [byte; 64]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn settings(dir: &std::path::Path) -> Settings {
        Settings {
            authority: "relay.example.test".into(),
            credential_file: key_file(dir, "origin.key", b'a'),
            next_credential_file: None,
            enrollment_forward: None,
        }
    }

    fn request(path: &str, key: &[u8]) -> Request<()> {
        Request::builder()
            .method("POST")
            .uri(format!("https://relay.example.test{path}"))
            .header("content-type", "application/grpc")
            .header(
                ORIGIN_KEY_HEADER,
                http::HeaderValue::from_bytes(key).unwrap(),
            )
            .body(())
            .unwrap()
    }

    #[test]
    fn exact_cdn_injected_key_admits_only_the_fixed_enrolled_routes() {
        let dir = tempfile::tempdir().unwrap();
        let gate = Gate::load(&settings(dir.path())).unwrap();
        let traffic = crate::secure_channel::GRPC_PATH;
        let enroll = ENROLLMENT_PATH;
        assert_eq!(
            gate.route(&request(traffic, &[b'a'; 64])),
            Some(Route::Traffic)
        );
        // Enrollment is reachable only when the forwarder is configured.
        assert_eq!(gate.route(&request(enroll, &[b'a'; 64])), None);
        for (path, key) in [
            (traffic, [b'b'; 64].as_slice()),
            (traffic, [b'a'; 63].as_slice()),
            ("/", [b'a'; 64].as_slice()),
            ("/tunnel.v1.Channel/Connect?x=1", [b'a'; 64].as_slice()),
            ("/bundle", [b'a'; 64].as_slice()),
        ] {
            assert_eq!(gate.route(&request(path, key)), None, "{path}");
        }
        let mut missing = request(traffic, &[b'a'; 64]);
        missing.headers_mut().remove(ORIGIN_KEY_HEADER);
        assert_eq!(
            gate.route(&missing),
            None,
            "direct origin hit without the CDN key"
        );
        let mut doubled = request(traffic, &[b'a'; 64]);
        doubled.headers_mut().append(
            ORIGIN_KEY_HEADER,
            http::HeaderValue::from_bytes(&[b'a'; 64]).unwrap(),
        );
        assert_eq!(gate.route(&doubled), None);
        let mut get = request(traffic, &[b'a'; 64]);
        *get.method_mut() = http::Method::GET;
        assert_eq!(gate.route(&get), None);
        let mut websocket = request(traffic, &[b'a'; 64]);
        *websocket.method_mut() = http::Method::CONNECT;
        assert_eq!(
            gate.route(&websocket),
            None,
            "no RFC 8441 or CONNECT tunnel"
        );
        let mut other_type = request(traffic, &[b'a'; 64]);
        other_type
            .headers_mut()
            .insert("content-type", "application/grpc+proto".parse().unwrap());
        assert_eq!(gate.route(&other_type), None);
        let mut other_authority = request(traffic, &[b'a'; 64]);
        *other_authority.uri_mut() = format!("https://origin.example.test{traffic}")
            .parse()
            .unwrap();
        assert_eq!(gate.route(&other_authority), None);
        let mut host = request(traffic, &[b'a'; 64]);
        host.headers_mut()
            .insert("host", "relay.example.test".parse().unwrap());
        assert_eq!(
            gate.route(&host),
            Some(Route::Traffic),
            "CDN may add matching Host"
        );
        host.headers_mut()
            .insert("host", "other.example.test".parse().unwrap());
        assert_eq!(gate.route(&host), None, "conflicting Host is refused");
        assert!(!format!("{gate:?}").contains(&"a".repeat(64)));
    }

    #[test]
    fn rotation_key_and_enrollment_forward_are_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = settings(dir.path());
        cfg.next_credential_file = Some(key_file(dir.path(), "next.key", b'c'));
        cfg.enrollment_forward = Some(EnrollmentForwardSettings {
            authority_address: "127.0.0.1:9445".parse().unwrap(),
            server_name: "enroll.example.test".into(),
            ca: dir.path().join("authority-ca.pem"),
            max_concurrent: 8,
        });
        let gate = Gate::load(&cfg).unwrap();
        let enroll = ENROLLMENT_PATH;
        assert_eq!(
            gate.route(&request(enroll, &[b'a'; 64])),
            Some(Route::Enrollment)
        );
        assert_eq!(
            gate.route(&request(enroll, &[b'c'; 64])),
            Some(Route::Enrollment)
        );
        assert_eq!(gate.route(&request(enroll, &[b'd'; 64])), None);

        let same = Settings {
            next_credential_file: Some(key_file(dir.path(), "same.key", b'a')),
            ..cfg.clone()
        };
        assert!(Gate::load(&same).is_err(), "rotation keys must differ");
        for authority in ["Relay.example.test", "relay", "relay.example.test:443", ""] {
            let mut bad = cfg.clone();
            bad.authority = authority.into();
            assert!(bad.validate().is_err(), "{authority}");
        }
        let mut bad = cfg.clone();
        bad.enrollment_forward.as_mut().unwrap().authority_address =
            "0.0.0.0:9445".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = cfg.clone();
        bad.enrollment_forward.as_mut().unwrap().max_concurrent = 0;
        assert!(bad.validate().is_err());
        let mut bad = cfg;
        bad.next_credential_file = Some(bad.credential_file.clone());
        assert!(bad.validate().is_err());
    }

    #[cfg(feature = "device-enrollment")]
    #[test]
    fn enrollment_route_matches_the_authority_path() {
        assert_eq!(
            ENROLLMENT_PATH,
            crate::secure_channel::enrollment_tls::GRPC_PATH
        );
    }

    #[test]
    fn origin_key_custody_refuses_public_or_malformed_files() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = settings(dir.path());
        std::fs::set_permissions(&cfg.credential_file, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(Gate::load(&cfg).is_err());
        std::fs::set_permissions(&cfg.credential_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::write(&cfg.credential_file, [b'0'; 64]).unwrap();
        assert!(Gate::load(&cfg).is_err());
    }
}
