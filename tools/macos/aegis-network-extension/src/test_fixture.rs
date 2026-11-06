//! cfg(test)-only ready App Group tree. Every key is generated per fixture;
//! nothing here is reachable from a production build or names a real relay.
use crate::{bound_relay_policy::BoundRelayPolicy, policy::FullWide};
use aegis_client::{online_expectation::OnlineExpectation, public_profile_file::MEMBERS};
use aegis_core::secure_channel::{
    enrollment::{self, protocol},
    enrollment_wire::{EnrollmentReceipt, ReceiptState},
    registry,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio_rustls::rustls::pki_types as rustls_der;

/// The device id the fixture's record, CSR and certificate name.
pub(crate) const DEVICE_ID: &str = "fixture-device-1";
/// The issued fixture's Redeem receipt generation and snapshot: the floor
/// the Store reports and every ACK must meet.
pub(crate) const ISSUED_GENERATION: u64 = 7;
pub(crate) const SNAPSHOT_SHA256: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
/// The signed bundle's `macos_packet.dns_upstream`.
pub(crate) const DNS_UPSTREAM: &str = "198.19.255.2:53";
const OWNER_GENERATION: &str = "fixture-generation-1";
const OUTER_NAME: &str = "localhost";
const INNER_NAME: &str = "inner.test";
/// The profile's enrollment inner TLS name (`enrollment.inner_server_name`).
pub(crate) const ISSUER_NAME: &str = "issuer.test";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn private_dir(path: &Path) {
    DirBuilder::new().mode(0o700).create(path).unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

pub(crate) fn signing_ca() -> (rcgen::Certificate, KeyPair) {
    signing_ca_until(None)
}

/// v32: a signing CA whose `notAfter` is `not_after` (Unix seconds; None:
/// rcgen's default).
pub(crate) fn signing_ca_until(not_after: Option<u64>) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    if let Some(not_after) = not_after {
        params.not_after =
            rcgen::date_time_ymd(1970, 1, 1) + std::time::Duration::from_secs(not_after);
    }
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    (params.self_signed(&key).unwrap(), key)
}

/// Fixture root under the canonical per-user temp directory. A world-writable
/// sticky root such as /private/tmp is refused: other UIDs may populate it.
fn fixture_root() -> PathBuf {
    let temp = std::env::temp_dir().canonicalize().unwrap();
    let meta = std::fs::metadata(&temp).unwrap();
    assert!(
        !temp.starts_with("/private/tmp")
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0,
        "fixture temp root must be the private per-user directory"
    );
    let root = temp.join(format!(
        "aegis-ne-fixture-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    private_dir(&root);
    root
}

/// A complete ready `<root>/Aegis` tree whose signed bundle names `relay`.
/// Construction panics unless the production bundle validator admits the
/// written bundle, so a tree cannot pass a test the real path would refuse.
/// Dropping it removes the tree; callers must drop Store owners first.
pub(crate) struct ReadyTree {
    root: PathBuf,
    /// The `Aegis` directory: `root/Aegis`, or `root` itself for
    /// `ReadyTree::installed`.
    aegis: PathBuf,
    /// Left in place on drop (`ReadyTree::keep`).
    kept: bool,
    relay: SocketAddr,
    /// v40: every pin of the signed pool, the primary (`relay`) first.
    pins: Vec<SocketAddr>,
    profile_sha256: String,
    online: OnlineExpectation,
    policy: FullWide,
    outer: CertifiedKey,
    inner_ca: rcgen::Certificate,
    inner_ca_key: KeyPair,
    device_ca_pem: String,
    device_ca_key_pem: String,
    csr_pem: String,
    certificate_pem: String,
    not_before: u64,
    device_id: &'static str,
}

/// S23: when and for how long the fixture's certificate is issued, and the
/// enrollment authority its signed profile names.
#[derive(Clone, Copy)]
pub(crate) struct Issuance {
    pub(crate) authority: SocketAddr,
    /// None: now.
    pub(crate) not_before: Option<u64>,
    pub(crate) lifetime_secs: u64,
    /// v32: the device id (`DEVICE_ID` by default).
    pub(crate) device_id: &'static str,
    /// v32: the device CA's `notAfter` (None: rcgen's default).
    pub(crate) ca_not_after: Option<u64>,
}

impl Default for Issuance {
    fn default() -> Self {
        Self {
            authority: "127.0.0.1:8443".parse().unwrap(),
            not_before: None,
            lifetime_secs: 24 * 3600,
            device_id: DEVICE_ID,
            ca_not_after: None,
        }
    }
}

impl ReadyTree {
    /// The issued fixture: a Redeem `online-completed.json` receipt is
    /// persisted, so the Store reports an issuance floor (generation 7) for
    /// the device certificate. Only an issued identity is admitted (S22).
    pub(crate) fn new(relay: SocketAddr) -> Self {
        Self::build(relay, true, None, Issuance::default(), &[])
    }

    /// S23: the issued fixture with its certificate issued at `not_before`
    /// for `lifetime_secs`, and `authority` as the profile's enrollment
    /// authority (`enrollment.authority_server`).
    pub(crate) fn renewable(
        relay: SocketAddr,
        authority: SocketAddr,
        not_before: u64,
        lifetime_secs: u64,
    ) -> Self {
        Self::build(
            relay,
            true,
            None,
            Issuance {
                authority,
                not_before: Some(not_before),
                lifetime_secs,
                ..Issuance::default()
            },
            &[],
        )
    }

    /// v40 (CP-D3 M1): the issued fixture whose signed v4 pool is `relay`
    /// (the primary) and then `more`, every pin with the fixture's outer
    /// name, so one outer identity serves every pin; a pool of two or more
    /// pins carries the default carrier failover policy.
    pub(crate) fn pooled(relay: SocketAddr, more: &[SocketAddr]) -> Self {
        Self::build(relay, true, None, Issuance::default(), more)
    }

    /// v40: `pooled` with `issuance` (another enrollment authority, such as
    /// one of the pins: variant B through the fronted 443).
    pub(crate) fn pooled_as(relay: SocketAddr, more: &[SocketAddr], issuance: Issuance) -> Self {
        Self::build(relay, true, None, issuance, more)
    }

    /// v32: `renewable` with every `Issuance` field given (another device
    /// id, a device CA ending at a given instant).
    pub(crate) fn issued_as(relay: SocketAddr, issuance: Issuance) -> Self {
        Self::build(relay, true, None, issuance, &[])
    }

    /// B-06 S15: the issued fixture written as the `Aegis` directory
    /// `aegis` itself (0700, created here; it must not exist), the import
    /// source of the later installed run. `aegis` must be absolute and its
    /// parent a canonical directory of the caller that no other user can
    /// write. Removed on drop unless `keep` is called.
    pub(crate) fn installed(aegis: &Path, relay: SocketAddr) -> Self {
        assert!(
            aegis.is_absolute(),
            "installed fixture dir must be absolute"
        );
        let parent = aegis.parent().expect("installed fixture dir has a parent");
        assert_eq!(
            parent.canonicalize().unwrap(),
            parent,
            "installed fixture parent must be canonical"
        );
        let meta = std::fs::symlink_metadata(parent).unwrap();
        assert!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
            "installed fixture parent must be the caller's and not group/other writable"
        );
        assert!(
            std::fs::symlink_metadata(aegis).is_err(),
            "installed fixture dir must not exist"
        );
        Self::build(
            relay,
            true,
            Some(aegis.to_owned()),
            Issuance::default(),
            &[],
        )
    }

    /// Leave the tree in place when dropped.
    pub(crate) fn keep(mut self) {
        self.kept = true;
    }

    /// The `Aegis` directory (the import source).
    pub(crate) fn aegis(&self) -> &Path {
        &self.aegis
    }

    /// Relay-side fixture material for the installed run, never part of an
    /// import: the outer and inner server identities this bundle trusts
    /// and the device CA a relay requires of clients. Written as fresh 0600
    /// files into a new 0700 `dir`.
    pub(crate) fn write_relay_material(&self, dir: &Path) {
        private_dir(dir);
        let (outer_cert, outer_key) = self.outer_server_pem();
        let (inner_cert, inner_key) = self.inner_server_pem();
        for (leaf, text) in [
            ("outer-server.pem", outer_cert.as_str()),
            ("outer-server.key", outer_key.as_str()),
            ("inner-server.pem", inner_cert.as_str()),
            ("inner-server.key", inner_key.as_str()),
            ("device-ca.pem", self.device_ca_pem()),
        ] {
            private_file(&dir.join(leaf), text.as_bytes());
        }
    }

    /// The same issued fixture, named where a test relies on the receipt.
    pub(crate) fn with_online_completed(relay: SocketAddr) -> Self {
        Self::build(relay, true, None, Issuance::default(), &[])
    }

    /// A ready identity the Store admits offline, with no completion
    /// receipt: the provider capture and import must refuse it (S22).
    pub(crate) fn unissued(relay: SocketAddr) -> Self {
        Self::build(relay, false, None, Issuance::default(), &[])
    }

    fn build(
        relay: SocketAddr,
        completed: bool,
        installed: Option<PathBuf>,
        issuance: Issuance,
        more: &[SocketAddr],
    ) -> Self {
        // A signed full-wide profile pins an IPv4 relay endpoint.
        assert!(relay.is_ipv4(), "fixture relay must be IPv4");
        let dns: Vec<IpAddr> = vec![
            "198.19.255.2".parse().unwrap(),
            "fd00:ae61::2".parse().unwrap(),
        ];
        let policy = FullWide::new(relay.ip(), dns.clone(), 1280)
            .or_else(|_| FullWide::for_test_loopback(relay.ip(), dns.clone(), 1280))
            .unwrap();
        let outer = rcgen::generate_simple_self_signed(vec![OUTER_NAME.into()]).unwrap();
        let (inner_ca, inner_ca_key) = signing_ca();
        let (device_ca, device_ca_key) = signing_ca_until(issuance.ca_not_after);
        let device_id = issuance.device_id;
        let pins: Vec<SocketAddr> = std::iter::once(relay).chain(more.iter().copied()).collect();
        let device_ca_pem = device_ca.pem();
        let held_device_ca_pem = device_ca_pem.clone();
        let profile = json!({
            "schema":"aegis_device_bundle_v4", "product_mode":"full-wide-tun", "udp":true,
            "relay_server":relay.to_string(), "outer_server_name":OUTER_NAME,
            "inner_server_name":INNER_NAME,
            "relay_endpoints":pins.iter().map(|pin| json!({"server":pin.to_string(),"server_name":OUTER_NAME})).collect::<Vec<_>>(),
            "enrollment":{"protocol":"aegis-enrollment-v1",
                "authority_server":issuance.authority.to_string(),
                "outer_server_name":OUTER_NAME, "inner_server_name":ISSUER_NAME,
                "automatic_renewal":true, "renewal_policy":"same-key-v1"},
            "macos_packet":{"mtu":1280, "dns_servers":dns, "dns_upstream":DNS_UPSTREAM,
                "max_flows":64, "idle_ms":30_000}
        });
        let public: [Vec<u8>; 4] = [
            serde_json::to_vec(&profile).unwrap(),
            outer.cert.pem().into_bytes(),
            inner_ca.pem().into_bytes(),
            device_ca_pem.clone().into_bytes(),
        ];
        // Refuse before anything is created, so a refused relay leaks no tree.
        aegis_client::device_bundle_profile::validate_profile(&public[0])
            .expect("production profile validator refused the fixture relay");
        let (root, aegis) = match installed {
            Some(aegis) => (aegis.clone(), aegis),
            None => {
                let root = fixture_root();
                let aegis = root.join("Aegis");
                (root, aegis)
            }
        };
        let bundle = aegis.join("bundle");
        let identity = aegis.join("identity");
        for dir in [&aegis, &bundle, &identity] {
            private_dir(dir);
        }
        for (member, bytes) in MEMBERS.into_iter().zip(&public) {
            private_file(&bundle.join(member), bytes);
        }
        let profile_sha256 = aegis_client::public_profile_file::profile_digest_bytes(&public);

        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let key_pem = key.serialize_pem();
        let csr = enrollment::csr_for_key(device_id, &key_pem).unwrap();
        let now = issuance
            .not_before
            .unwrap_or_else(|| registry::unix_now().unwrap());
        let issued = enrollment::sign_csr(
            device_id,
            &csr,
            &device_ca_pem,
            &device_ca_key.serialize_pem(),
            now,
            issuance.lifetime_secs,
        )
        .unwrap();
        let certificate_pem = issued.certificate_pem.clone();
        let fingerprint = issued.record.certificate_sha256.clone();
        let record = json!({
            "version":1, "device_id":device_id, "phase":"ready",
            "device_ca_sha256":sha256_hex(device_ca_pem.as_bytes()),
            "certificate_sha256":fingerprint,
        });
        for (leaf, bytes) in [
            (".lock", Vec::new()),
            ("identity.json", serde_json::to_vec(&record).unwrap()),
            ("device.key", key_pem.into_bytes()),
            ("device.csr", csr.clone().into_bytes()),
            ("device.pem", issued.certificate_pem.clone().into_bytes()),
            ("device-ca.pem", device_ca_pem.into_bytes()),
            ("bundle-profile.sha256", profile_sha256.clone().into_bytes()),
        ] {
            private_file(&identity.join(leaf), &bytes);
        }
        let (issued_generation, snapshot_sha256) = if completed {
            let receipt = EnrollmentReceipt {
                version: 1,
                binding: protocol::RequestBinding {
                    operation: protocol::Operation::Redeem,
                    request_id: "d".repeat(64),
                    profile_sha256: profile_sha256.clone(),
                    csr_sha256: sha256_hex(csr.as_bytes()),
                    predecessor_sha256: None,
                },
                device_id: device_id.into(),
                certificate_pem: issued.certificate_pem,
                certificate_sha256: fingerprint.clone(),
                not_before_unix_secs: now,
                not_after_unix_secs: issued.record.not_after_unix_secs,
                issued_generation: ISSUED_GENERATION,
                snapshot_sha256: SNAPSHOT_SHA256.into(),
                state: ReceiptState::IssuedPendingDistribution,
            };
            let saved = json!({"version":1, "receipt":receipt, "predecessor_certificate_pem":null});
            private_file(
                &identity.join("online-completed.json"),
                &serde_json::to_vec(&saved).unwrap(),
            );
            (Some(ISSUED_GENERATION), Some(SNAPSHOT_SHA256.into()))
        } else {
            (None, None)
        };
        let online = OnlineExpectation {
            certificate_sha256: fingerprint,
            not_after_unix_secs: issued.record.not_after_unix_secs,
            issued_generation,
            snapshot_sha256,
        };
        // No runtime record: the provider derives its binding from this tree.
        let admitted = BoundRelayPolicy::from_snapshot(public, None, &bundle, &identity)
            .expect("production bundle validator refused the fixture bundle");
        assert_eq!(
            admitted
                .settings()
                .relay
                .server
                .parse::<SocketAddr>()
                .unwrap(),
            relay
        );
        Self {
            root,
            aegis,
            kept: false,
            relay,
            pins,
            profile_sha256,
            online,
            policy,
            outer,
            inner_ca,
            inner_ca_key,
            device_ca_pem: held_device_ca_pem,
            device_ca_key_pem: device_ca_key.serialize_pem(),
            csr_pem: csr,
            certificate_pem,
            not_before: now,
            device_id,
        }
    }

    /// The App Group container: pass to `capture_test_root`.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn identity_dir(&self) -> PathBuf {
        self.aegis.join("identity")
    }
    /// v40: every pin of the signed pool, the primary first.
    pub(crate) fn pins(&self) -> &[SocketAddr] {
        &self.pins
    }
    pub(crate) fn relay(&self) -> SocketAddr {
        self.relay
    }
    pub(crate) fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }
    /// Values the protected Store must report for this tree.
    pub(crate) fn online(&self) -> &OnlineExpectation {
        &self.online
    }
    pub(crate) fn generation(&self) -> &str {
        OWNER_GENERATION
    }
    /// Saved manager policy whose relay, DNS and MTU the signed bundle names.
    pub(crate) fn policy(&self) -> &FullWide {
        &self.policy
    }
    /// Outer TLS server identity trusted by the bundle's outer-ca.pem.
    pub(crate) fn outer_server_pem(&self) -> (String, String) {
        (self.outer.cert.pem(), self.outer.key_pair.serialize_pem())
    }
    /// The same outer identity as DER, for a rustls acceptor.
    pub(crate) fn outer_server_der(&self) -> (rustls_der::CertificateDer<'static>, Vec<u8>) {
        (
            self.outer.cert.der().clone(),
            self.outer.key_pair.serialize_der(),
        )
    }
    /// CA that issued the device certificate; a relay requires it of clients.
    pub(crate) fn device_ca_pem(&self) -> &str {
        &self.device_ca_pem
    }
    /// The fixture's device id, as its record and receipt name it.
    pub(crate) fn device_id(&self) -> &'static str {
        self.device_id
    }
    /// Put `bytes` at `identity/<leaf>` as a fresh private file: a new leaf,
    /// or an atomic rename over the existing one.
    pub(crate) fn write_identity_file(&self, leaf: &str, bytes: &[u8]) {
        let staged = self.identity_dir().join(format!("{leaf}.fixture-next"));
        private_file(&staged, bytes);
        std::fs::rename(staged, self.identity_dir().join(leaf)).unwrap();
    }
    /// Replace the saved Redeem receipt's issued generation on disk, as a
    /// renewal would. Atomic rename of a private file; the Store must notice.
    pub(crate) fn rewrite_issued_generation(&self, generation: u64) {
        let path = self.identity_dir().join("online-completed.json");
        let mut saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        saved["receipt"]["issued_generation"] = json!(generation);
        let staged = self.identity_dir().join("online-completed.json.next");
        private_file(&staged, &serde_json::to_vec(&saved).unwrap());
        std::fs::rename(staged, path).unwrap();
    }
    /// S23: the device CA's private key, for a loopback enrollment
    /// authority that issues successors.
    pub(crate) fn device_ca_key_pem(&self) -> &str {
        &self.device_ca_key_pem
    }
    /// The device CSR (immutable: renewal is same-key).
    pub(crate) fn csr_pem(&self) -> &str {
        &self.csr_pem
    }
    /// The installed certificate as first written, and its `not_before`.
    pub(crate) fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }
    pub(crate) fn not_before(&self) -> u64 {
        self.not_before
    }
    /// Enrollment inner TLS identity for `issuer.test`, issued by
    /// inner-ca.pem (the profile's `enrollment.inner_server_name`).
    pub(crate) fn issuer_server_pem(&self) -> (String, String) {
        self.server_pem(ISSUER_NAME)
    }
    /// Inner TLS server identity for `inner.test` issued by inner-ca.pem.
    pub(crate) fn inner_server_pem(&self) -> (String, String) {
        self.server_pem(INNER_NAME)
    }
    fn server_pem(&self, name: &str) -> (String, String) {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let cert = params
            .signed_by(&key, &self.inner_ca, &self.inner_ca_key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

impl Drop for ReadyTree {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

mod tests {
    use super::*;
    use crate::{app_group::CapturedAppGroupInputs, local_identity::CapturedLocalIdentity};
    use aegis_client::{
        protected_identity_store::ProtectedIdentityStore,
        protected_online_expectation::ProtectedOnlineExpectation,
    };

    fn same(actual: &OnlineExpectation, expected: &OnlineExpectation) -> bool {
        actual.certificate_sha256 == expected.certificate_sha256
            && actual.not_after_unix_secs == expected.not_after_unix_secs
            && actual.issued_generation == expected.issued_generation
            && actual.snapshot_sha256 == expected.snapshot_sha256
    }

    #[test]
    fn test_fixture_is_private_and_admitted_by_protected_store() {
        let temp = std::env::temp_dir().canonicalize().unwrap();
        for tree in [
            ReadyTree::unissued("127.0.0.1:443".parse().unwrap()),
            ReadyTree::with_online_completed("127.0.0.1:8443".parse().unwrap()),
        ] {
            assert!(tree.root().starts_with(&temp));
            assert!(!tree.root().starts_with("/private/tmp"));
            assert_eq!(
                std::fs::metadata(tree.root()).unwrap().mode() & 0o7777,
                0o700
            );
            assert_eq!(tree.policy().relay(), tree.relay().ip());
            let store = ProtectedOnlineExpectation::open_existing(
                &tree.identity_dir(),
                tree.profile_sha256(),
            )
            .unwrap();
            let observed = store.expectation_at(registry::unix_now().unwrap()).unwrap();
            assert!(same(&observed, tree.online()));
            assert!(ProtectedIdentityStore::open_existing(&tree.identity_dir()).is_err());
            drop(store);
            // With no lock held, only the profile pin can refuse this digest.
            let wrong_profile =
                ProtectedOnlineExpectation::open_existing(&tree.identity_dir(), &"e".repeat(64))
                    .unwrap();
            assert!(wrong_profile
                .expectation_at(registry::unix_now().unwrap())
                .is_err());
            drop(wrong_profile);
            let (outer_cert, outer_key) = tree.outer_server_pem();
            let (inner_cert, inner_key) = tree.inner_server_pem();
            for pem in [&outer_cert, &inner_cert] {
                aegis_client::device_bundle_profile::validate_ca(pem.as_bytes()).unwrap();
            }
            assert!(outer_key.contains("PRIVATE KEY") && inner_key.contains("PRIVATE KEY"));
        }
        for tree in [
            ReadyTree::new("127.0.0.1:443".parse().unwrap()),
            ReadyTree::with_online_completed("127.0.0.1:443".parse().unwrap()),
        ] {
            assert_eq!(tree.online().issued_generation, Some(7));
            assert!(tree.identity_dir().join("online-completed.json").exists());
        }
        let unissued = ReadyTree::unissued("127.0.0.1:443".parse().unwrap());
        assert_eq!(unissued.online().issued_generation, None);
        assert!(!unissued
            .identity_dir()
            .join("online-completed.json")
            .exists());
    }

    #[test]
    fn test_fixture_refuses_relays_no_signed_bundle_can_carry() {
        for relay in [
            "[::1]:8443",
            "198.18.0.1:443",
            "198.19.0.1:443",
            "192.0.2.1:0",
        ] {
            let relay: SocketAddr = relay.parse().unwrap();
            let built = std::panic::catch_unwind(|| ReadyTree::new(relay));
            assert!(built.is_err(), "fixture admitted relay {relay}");
        }
    }

    #[test]
    fn test_fixture_local_identity_over_test_root_derives_runtime_and_prepares_crypto() {
        use crate::local_identity::PreparedLocalSession;
        for tree in [
            ReadyTree::new("127.0.0.1:443".parse().unwrap()),
            ReadyTree::with_online_completed("127.0.0.1:443".parse().unwrap()),
        ] {
            assert!(!tree.root().join("Aegis/runtime.json").exists());
            let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
            let identity = CapturedLocalIdentity::from_claim(inputs).unwrap();
            // The admitted identity holds the one Store lock.
            assert!(ProtectedIdentityStore::open_existing(&tree.identity_dir()).is_err());
            let mut prepared: PreparedLocalSession = identity.prepare_crypto().unwrap();
            assert_eq!(prepared.pinned_peer().unwrap(), tree.relay());
            let saved = crate::configuration::SavedProviderIntent {
                generation: tree.generation().into(),
                policy: tree.policy().clone(),
            };
            let (bound, online) = prepared.derive_runtime(&saved).unwrap();
            assert!(same(&online, tree.online()));
            let again = prepared.bind_runtime_for_test(&bound, &saved).unwrap();
            assert!(same(&again, tree.online()));
            let other = crate::configuration::SavedProviderIntent {
                generation: "other-generation".into(),
                policy: tree.policy().clone(),
            };
            assert!(prepared.bind_runtime_for_test(&bound, &other).is_err());
            drop(bound);
            drop(prepared);
            ProtectedIdentityStore::open_existing(&tree.identity_dir()).unwrap();
        }
    }
}
