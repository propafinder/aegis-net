use super::*;
use aegis_core::secure_channel::{enrollment, enrollment_tls, registry::RegistryTransaction};
use aegis_server::{enrollment_service, enrollment_store::IssuerConfig};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use tokio::sync::oneshot;

struct Fixture {
    _dir: tempfile::TempDir,
    identity: PathBuf,
    bundle: PathBuf,
    invitation: PathBuf,
    relay_address: std::net::SocketAddr,
    /// CDN-like edge listener pinned in a fronted profile (relay and
    /// authority both reached through it on one public authority).
    edge_address: Option<std::net::SocketAddr>,
    config: enrollment_service::AuthorityConfig,
}

impl Fixture {
    async fn new() -> Self {
        Self::new_with_bridge(false).await
    }
    async fn new_with_bridge(bridge_enabled: bool) -> Self {
        Self::new_with_policy(bridge_enabled, false).await
    }
    async fn new_with_policy(bridge_enabled: bool, full_wide: bool) -> Self {
        Self::new_with_research_policy(bridge_enabled, full_wide, None, None).await
    }
    async fn new_with_research_policy(
        bridge_enabled: bool,
        full_wide: bool,
        shaping: Option<aegis_core::carrier_runtime::PrivacySettings>,
        privacy_plan: Option<aegis_core::traffic_privacy::plan::PrivacyPlan>,
    ) -> Self {
        Self::build(bridge_enabled, full_wide, shaping, privacy_plan, false).await
    }
    /// A device profile whose relay and enrollment authority are both the
    /// CDN-like edge (`front.test`), as with Cloudflare fronting.
    async fn new_fronted() -> Self {
        Self::build(false, false, None, None, true).await
    }
    async fn build(
        bridge_enabled: bool,
        full_wide: bool,
        shaping: Option<aegis_core::carrier_runtime::PrivacySettings>,
        privacy_plan: Option<aegis_core::traffic_privacy::plan::PrivacyPlan>,
        fronted: bool,
    ) -> Self {
        #[cfg(target_os = "macos")]
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let relay_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let edge_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let edge_address = fronted.then(|| edge_listener.local_addr().unwrap());
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_path = path.join("ca.pem");
        let ca_key_path = path.join("ca.key");
        enrollment::write_private_new(&ca_path, ca.pem().as_bytes()).unwrap();
        enrollment::write_private_new(&ca_key_path, ca_key.serialize_pem().as_bytes()).unwrap();
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut leaf = CertificateParams::new(vec![
            "front.test".into(),
            "enroll.test".into(),
            "relay.test".into(),
            "origin.test".into(),
        ])
        .unwrap();
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let cert = path.join("authority.pem");
        let key = path.join("authority.key");
        enrollment::write_private_new(&cert, leaf.pem().as_bytes()).unwrap();
        enrollment::write_private_new(&key, leaf_key.serialize_pem().as_bytes()).unwrap();
        let source = path.join("profile.json");
        let mut public_profile = serde_json::json!({
            "schema":"aegis_device_bundle_v3","product_mode":if full_wide {"full-wide-tun"} else {"socks-only"},
            "relay_server":edge_address.unwrap_or(relay_address).to_string(),
            "outer_server_name":if bridge_enabled || fronted {"front.test"} else {"relay.test"},
            "inner_server_name":"origin.test","udp":bridge_enabled || full_wide || fronted,
            "enrollment":{"protocol":"aegis-enrollment-v1",
                // Variant B: the authority is reached on the same public
                // authority and port as the tunnel, through the edge.
                "authority_server":edge_address.unwrap_or(listen).to_string(),
                "outer_server_name":"front.test","inner_server_name":"enroll.test",
                "automatic_renewal":true,"renewal_policy":"same-key-v1"}
        });
        // Admit the exact public research policy before the four-member digest
        // is bound to the identity and authority. Never mutate installed policy.
        if let Some(shaping) = shaping {
            public_profile["authenticated_shaping"] = serde_json::to_value(shaping).unwrap();
        }
        if let Some(plan) = privacy_plan {
            public_profile["privacy_plan"] = serde_json::to_value(plan).unwrap();
        }
        fs::write(&source, serde_json::to_vec(&public_profile).unwrap()).unwrap();
        let bundle = path.join("bundle");
        crate::device_bundle::create(&crate::device_bundle::BundleCreateArgs {
            bundle_dir: bundle.clone(),
            profile: source,
            outer_ca: ca_path.clone(),
            inner_ca: ca_path.clone(),
            device_ca: ca_path.clone(),
        })
        .unwrap();
        let identity = path.join("identity");
        crate::device_identity::run_device(&crate::device_identity::DeviceArgs {
            action: crate::device_identity::DeviceAction::Prepare(
                crate::device_identity::PrepareArgs {
                    device_id: "device-a".into(),
                    identity_dir: identity.clone(),
                    device_ca: ca_path.clone(),
                },
            ),
        })
        .await
        .unwrap();
        crate::device_bundle::inspect(&crate::device_bundle::BundleInspectArgs {
            bundle_dir: bundle.clone(),
            identity_dir: Some(identity.clone()),
            json: false,
        })
        .unwrap();
        let https_bridge = if bridge_enabled {
            let carrier = aegis_core::https_bridge::ClientSettings {
                authority: "front.test".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
                credential_file: identity.join("bridge-credential"),
            };
            enrollment::write_private_new(&carrier.credential_file, &[b'a'; 64]).unwrap();
            enrollment::write_private_new(
                &identity.join(aegis_core::https_bridge::SIDECAR),
                toml::to_string(&carrier).unwrap().as_bytes(),
            )
            .unwrap();
            Some(aegis_core::https_bridge::ServerSettings {
                carrier,
                site_html: "<!doctype html><title>Public site</title>".into(),
            })
        } else {
            None
        };
        let registry = path.join("registry.json");
        let invitation = path.join("invitation");
        aegis_server::devices::initialize(&registry).unwrap();
        aegis_server::devices::invite(
            &registry,
            "device-a",
            &invitation,
            300,
            registry::unix_now().unwrap(),
        )
        .unwrap();
        let digest = OnlineProfile::load(&bundle, &identity)
            .unwrap()
            .digest()
            .to_owned();
        drop(listener);
        drop(relay_listener);
        drop(edge_listener);
        Self {
            identity,
            bundle,
            invitation,
            relay_address,
            edge_address,
            config: enrollment_service::AuthorityConfig {
                https_bridge,
                listen,
                outer_cert: cert.clone(),
                outer_key: key.clone(),
                inner_tls: enrollment_tls::AuthoritySettings { cert, key },
                issuer: IssuerConfig {
                    registry,
                    ca_cert: ca_path,
                    ca_key: ca_key_path,
                    profile_sha256: digest,
                    lifetime_secs: 90,
                    max_receipts: 16,
                    max_receipt_bytes_total: 1048576,
                    receipt_grace_secs: 60,
                    receipt_namespace: None,
                },
            },
            _dir: dir,
        }
    }
    fn material(&self, invitation: bool) -> RequestMaterial {
        store::begin_online_request(
            &self.identity,
            Operation::Redeem,
            &self.config.issuer.profile_sha256,
            invitation.then_some(self.invitation.as_path()),
            registry::unix_now().unwrap(),
        )
        .unwrap()
    }
    fn profile(&self) -> OnlineProfile {
        OnlineProfile::load(&self.bundle, &self.identity).unwrap()
    }
    fn key(&self) -> (u64, Vec<u8>) {
        let path = self.identity.join("device.key");
        let stat = fs::metadata(&path).unwrap();
        assert_eq!(stat.mode() & 0o777, 0o600);
        assert_eq!(stat.nlink(), 1);
        (stat.ino(), fs::read(path).unwrap())
    }
    async fn server(&self) -> Server {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let config = self.config.clone();
        let task = tokio::spawn(enrollment_service::run_with_shutdown(
            config,
            Some(ready_tx),
            async {
                let _ = stopped.await;
            },
        ));
        let ready = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ready, self.config.listen);
        Server {
            stop: Some(stop),
            task,
        }
    }
    async fn install_due_predecessor(&self) {
        let now = registry::unix_now().unwrap();
        let issued = enrollment::sign_csr(
            "device-a",
            &fs::read_to_string(self.identity.join("device.csr")).unwrap(),
            &fs::read_to_string(&self.config.issuer.ca_cert).unwrap(),
            &fs::read_to_string(&self.config.issuer.ca_key).unwrap(),
            now - 125,
            180,
        )
        .unwrap();
        let certificate = self._dir.path().join("predecessor.pem");
        enrollment::write_private_new(&certificate, issued.certificate_pem.as_bytes()).unwrap();
        let transaction = RegistryTransaction::begin(&self.config.issuer.registry).unwrap();
        let mut data = transaction.load().unwrap();
        data.devices.push(issued.record);
        data.invitations[0].consumed = true;
        data.generation += 1;
        data.refresh_validity(now, 900).unwrap();
        transaction
            .save(&self.config.issuer.registry, &data, false)
            .unwrap();
        drop(transaction);
        crate::device_identity::run_device(&crate::device_identity::DeviceArgs {
            action: crate::device_identity::DeviceAction::Complete(
                crate::device_identity::CompleteArgs {
                    identity_dir: self.identity.clone(),
                    certificate,
                    device_ca: self.config.issuer.ca_cert.clone(),
                },
            ),
        })
        .await
        .unwrap();
        assert!(
            store::online_status(&self.identity, now)
                .unwrap()
                .renewal_due
        );
    }

    fn settings(&self) -> aegis_core::Settings {
        let dir = self._dir.path().join("config");
        fs::create_dir(&dir).unwrap();
        fs::copy(self.bundle.join("outer-ca.pem"), dir.join("ca.pem")).unwrap();
        fs::copy(self.bundle.join("inner-ca.pem"), dir.join("inner-ca.pem")).unwrap();
        let output = dir.join("client.toml");
        crate::device_bundle::render(&crate::device_bundle::BundleRenderArgs {
            bundle_dir: self.bundle.clone(),
            identity_dir: self.identity.clone(),
            config_dir: dir,
            output: output.clone(),
            relay_geneva_request: None,
            relay_geneva_request_sha256: None,
            relay_geneva_profile_manifest: None,
            relay_geneva_profile_sha256: None,
            validate_only: false,
        })
        .unwrap();
        crate::config::load_config(output).unwrap()
    }

    async fn relay(&self, registry: &std::path::Path) -> Server {
        self.relay_with_shaping(registry, None).await
    }

    async fn relay_with_shaping(
        &self,
        registry: &std::path::Path,
        shaping: Option<aegis_core::carrier_runtime::PrivacySettings>,
    ) -> Server {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg: aegis_server::config::ServerConfig =
            serde_json::from_value(serde_json::json!({
                "listen":self.relay_address.to_string(),
                "cert":self.config.outer_cert,"key":self.config.outer_key,"auth_token":"",
                "target_policy":{"profile":"full_vpn_egress"},
                "transport":{"quic_required":false,"inner_tls":{
                    "cert":self.config.outer_cert,"key":self.config.outer_key,
                    "client_ca":self.config.issuer.ca_cert,"device_registry":registry,
                    "handshake_timeout_ms":3000,"idle_timeout_ms":3000
                }}
            }))
            .unwrap();
        cfg.transport.https_bridge = self.config.https_bridge.clone();
        cfg.transport.authenticated_shaping = shaping;
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let mut task = tokio::spawn(aegis_server::run_server_with_shutdown(
            cfg,
            Some(ready_tx),
            async {
                let _ = stopped.await;
            },
        ));
        if tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .is_err()
        {
            panic!("synthetic relay startup failed: {:?}", (&mut task).await);
        }
        Server {
            stop: Some(stop),
            task,
        }
    }
}

struct Server {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl Server {
    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn actual_authority_redeem_completes_same_key_and_not_due_renew_never_connects() {
    let f = Fixture::new().await;
    let key = f.key();
    let server = f.server().await;
    redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone()),
    })
    .await
    .unwrap();
    server.stop().await;
    assert_eq!(f.key(), key);
    assert!(!f.identity.join("online-request.json").exists());
    assert!(
        f.invitation.exists(),
        "caller invitation is not our managed copy"
    );
    let status = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    assert_eq!(status.state, "ready");
    assert!(!status.renewal_due && !status.pending);
    renew(&RenewArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        if_due: true,
    })
    .await
    .unwrap();
    assert_eq!(f.key(), key);
}

#[tokio::test]
async fn lost_committed_response_recovers_exact_certificate_without_reissuing() {
    let f = Fixture::new().await;
    let key = f.key();
    let server = f.server().await;
    let first = f.material(true);
    let response = exchange(&f.identity, &f.profile(), &first, ProofPurpose::Authorize)
        .await
        .unwrap();
    let ExchangeResponse::Issued { receipt } = response else {
        panic!("issuance failed")
    };
    // Simulate delivery lost before local persistence: only the issuer committed.
    let registry_before = fs::read(&f.config.issuer.registry).unwrap();
    assert!(!f.identity.join("device.pem").exists());
    let resumed = f.material(false);
    assert!(resumed.resume);
    assert_eq!(first.binding, resumed.binding);
    let completion = perform(&f.identity, &f.profile(), &resumed).await.unwrap();
    assert_eq!(completion.certificate_sha256, receipt.certificate_sha256);
    assert_eq!(
        fs::read_to_string(f.identity.join("device.pem")).unwrap(),
        receipt.certificate_pem
    );
    assert_eq!(
        fs::read(&f.config.issuer.registry).unwrap(),
        registry_before
    );
    assert_eq!(f.key(), key);
    server.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_invitation_recovers_old_issuance_without_reading_new_token() {
    let f = Fixture::new().await;
    let key = f.key();
    let server = f.server().await;
    let first = f.material(true);
    let response = exchange(&f.identity, &f.profile(), &first, ProofPurpose::Authorize)
        .await
        .unwrap();
    let ExchangeResponse::Issued { receipt } = response else {
        panic!("old issue failed")
    };
    let registry_before = fs::read(&f.config.issuer.registry).unwrap();
    let missing_new_token = f.identity.parent().unwrap().join("missing-new-invitation");
    let missing_journal = f
        .identity
        .parent()
        .unwrap()
        .join("missing-recovery/out.json");
    refresh_redeem_invitation(&RefreshRedeemInvitationArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        new_invitation_file: missing_new_token.clone(),
        recovery_out: missing_journal.clone(),
    })
    .await
    .unwrap();
    assert!(!missing_new_token.exists() && !missing_journal.exists());
    assert_eq!(f.key(), key);
    assert_eq!(
        fs::read(&f.config.issuer.registry).unwrap(),
        registry_before
    );
    assert_eq!(
        fs::read_to_string(f.identity.join("device.pem")).unwrap(),
        receipt.certificate_pem
    );
    server.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_invitation_transport_failure_keeps_exact_pending_and_key() {
    let f = Fixture::new().await;
    let first = f.material(true);
    let before_request = fs::read(f.identity.join("online-request.json")).unwrap();
    let key = f.key();
    let recovery = tempfile::tempdir_in(f.identity.parent().unwrap().parent().unwrap()).unwrap();
    fs::set_permissions(recovery.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let next = recovery.path().join("new-token");
    enrollment::write_private_new(&next, &[b'e'; 64]).unwrap();
    let journal = recovery.path().join("old-request.json");
    // No authority listener exists. Receipt cannot be classified as Rejected.
    assert!(refresh_redeem_invitation(&RefreshRedeemInvitationArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        new_invitation_file: next,
        recovery_out: journal.clone(),
    })
    .await
    .is_err());
    assert!(!journal.exists());
    assert_eq!(
        fs::read(f.identity.join("online-request.json")).unwrap(),
        before_request
    );
    assert_eq!(f.key(), key);
    assert_eq!(f.material(false).binding, first.binding);
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_invitation_busy_unavailable_and_ambiguous_refuse_all_local_mutation() {
    let f = Fixture::new().await;
    f.material(true);
    let snapshot = store::prepare_refresh(&f.identity, &f.config.issuer.profile_sha256).unwrap();
    let before = fs::read(f.identity.join("online-request.json")).unwrap();
    let recovery = tempfile::tempdir_in(f.identity.parent().unwrap().parent().unwrap()).unwrap();
    fs::set_permissions(recovery.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let next = recovery.path().join("new-token");
    enrollment::write_private_new(&next, &[b'e'; 64]).unwrap();
    let journal = recovery.path().join("old-request.json");
    let args = RefreshRedeemInvitationArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        new_invitation_file: next,
        recovery_out: journal.clone(),
    };
    for response in [
        Ok(ExchangeResponse::Failed {
            code: FailureCode::Busy,
        }),
        Ok(ExchangeResponse::Failed {
            code: FailureCode::Unavailable,
        }),
        Ok(ExchangeResponse::Failed {
            code: FailureCode::RecoveryRequired,
        }),
        Err(anyhow::anyhow!("synthetic transport ambiguity")),
    ] {
        assert!(
            refresh_after_receipt(&args, &f.profile(), &snapshot, response)
                .await
                .is_err()
        );
        assert_eq!(
            fs::read(f.identity.join("online-request.json")).unwrap(),
            before
        );
        assert!(!journal.exists());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_invitation_uses_new_operator_token_with_same_key_and_request_id() {
    let f = Fixture::new().await;
    let first = f.material(true);
    let key = f.key();
    let now = registry::unix_now().unwrap();
    // Model expiry of the old invitation before a normal new operator issue.
    let transaction = RegistryTransaction::begin(&f.config.issuer.registry).unwrap();
    let mut registry = transaction.load().unwrap();
    registry.invitations[0].expires_unix_secs = now - 1;
    registry.generation += 1;
    registry.refresh_validity(now, 900).unwrap();
    transaction
        .save(&f.config.issuer.registry, &registry, false)
        .unwrap();
    drop(transaction);
    let recovery = tempfile::tempdir_in(f.identity.parent().unwrap().parent().unwrap()).unwrap();
    fs::set_permissions(recovery.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let next = recovery.path().join("new-token");
    aegis_server::devices::invite(&f.config.issuer.registry, "device-a", &next, 300, now).unwrap();
    let journal = recovery.path().join("old-request.json");
    let server = f.server().await;
    let outcome = refresh_redeem_invitation(&RefreshRedeemInvitationArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        new_invitation_file: next,
        recovery_out: journal.clone(),
    })
    .await;
    if let Err(error) = outcome {
        panic!(
            "refresh positive failure: {error:?}; journal_exists={}",
            journal.exists()
        );
    }
    assert_eq!(f.key(), key);
    assert!(journal.exists());
    let old: serde_json::Value = serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
    let old_pending: serde_json::Value =
        serde_json::from_slice(&hex::decode(old["old_pending_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(
        old_pending["binding"]["request_id"],
        first.binding.request_id.as_str()
    );
    let status = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    assert_eq!(status.state, "ready");
    assert!(!status.pending);
    server.stop().await;
}

#[tokio::test]
async fn unavailable_authority_retains_request_then_resume_receipt_falls_back_to_authorize() {
    let f = Fixture::new().await;
    let key = f.key();
    let first = f.material(true);
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        perform(&f.identity, &f.profile(), &first)
    )
    .await
    .unwrap()
    .is_err());
    let resumed = f.material(false);
    assert_eq!(first.binding, resumed.binding);
    let server = f.server().await;
    let completion = perform(&f.identity, &f.profile(), &resumed).await.unwrap();
    assert!(completion.certificate_valid_now);
    assert_eq!(f.key(), key);
    server.stop().await;
}

#[tokio::test]
async fn actual_due_renewal_extends_certificate_with_same_key_and_no_invitation() {
    let f = Fixture::new().await;
    f.install_due_predecessor().await;
    let before = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    let key = f.key();
    let old_certificate = fs::read(f.identity.join("device.pem")).unwrap();
    let server = f.server().await;
    renew(&RenewArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        if_due: true,
    })
    .await
    .unwrap();
    let after = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    assert!(after.not_after_unix_secs > before.not_after_unix_secs);
    assert!(!after.pending && !after.renewal_due);
    assert_ne!(
        fs::read(f.identity.join("device.pem")).unwrap(),
        old_certificate
    );
    assert_eq!(f.key(), key);
    server.stop().await;
}

#[tokio::test]
async fn profile_change_refuses_before_pending_state_or_network() {
    let f = Fixture::new().await;
    let before = fs::read(&f.config.issuer.registry).unwrap();
    let path = f.bundle.join("bundle.json");
    let mut profile: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    profile["enrollment"]["inner_server_name"] = "replacement.test".into();
    fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
    assert!(redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone())
    })
    .await
    .is_err());
    assert!(!f.identity.join("online-request.json").exists());
    assert_eq!(fs::read(&f.config.issuer.registry).unwrap(), before);
}

#[path = "device_renewal_tests.rs"]
mod renewal;

#[path = "device_enrollment_fronted_tests.rs"]
mod fronted;

#[cfg(target_os = "macos")]
#[path = "macos_worker_runtime_online_tests.rs"]
mod macos_worker_runtime;
