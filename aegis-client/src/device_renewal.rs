//! Installed online identities renew only while ingress is stopped. A due
//! monitor requests process restart; startup recovers/renews and requires a
//! live targetless relay ACK before capture and readiness can proceed.
use crate::{device_bundle::online::OnlineProfile, device_identity::store};
use aegis_client::{
    observed_policy_ack::ObservedPolicyAck,
    online_ack_observation::{observe_policy_ack, ObservationFailure},
    online_expectation::OnlineExpectation,
    online_renewal_plan::{after_protected_status, RenewalPlan},
    online_session_observation::OnlineSessionObservation,
};
use aegis_core::{
    secure_channel::{enrollment::protocol::Operation, registry},
    Settings,
};
use anyhow::{ensure, Context, Result};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

struct Prepared {
    bundle: PathBuf,
    identity: PathBuf,
    profile: OnlineProfile,
    settings: Settings,
    expected: OnlineExpectation,
}

/// Read-only config validation. A pending transaction remains for explicit
/// startup recovery; this function neither repairs it nor opens a connection.
pub(crate) fn validate(bundle: Option<&Path>, settings: &Settings) -> Result<()> {
    if let Some(bundle) = bundle {
        let _ = OnlineProfile::for_runtime(bundle, settings)?;
    }
    Ok(())
}

pub(crate) struct Supervisor {
    prepared: Option<Prepared>,
    session: Option<OnlineSessionObservation>,
}

impl Supervisor {
    pub(crate) async fn start(bundle: Option<&Path>, settings: &Settings) -> Result<Self> {
        let Some(bundle) = bundle else {
            return Ok(Self {
                prepared: None,
                session: None,
            });
        };
        PreparedIdentity::prepare(bundle, settings, true)
            .await?
            .confirm()
            .await
    }

    pub(crate) async fn confirm_before_ready(&self) -> Result<()> {
        if let Some(prepared) = &self.prepared {
            let confirmed = prepared.confirm().await?;
            // Lock acquisition can outlive the authenticated grant. Do not
            // publish a now-expired result or attach it to another issuance.
            self.session
                .as_ref()
                .context("online acknowledgement owner missing")?
                .replace_observed(confirmed, prepared.expected.binding())?;
        }
        Ok(())
    }

    /// Final synchronous readiness boundary. Local checks after the awaited
    /// ACK cannot inherit an expired grant or a changed on-disk issuance.
    pub(crate) fn ensure_confirmation_current(&self) -> Result<()> {
        let Some(prepared) = &self.prepared else {
            return Ok(());
        };
        self.session
            .as_ref()
            .context("online acknowledgement owner missing")?
            .ensure_current(prepared.expected.binding())
    }

    #[cfg(all(test, unix))]
    pub(crate) fn retained_ack_deadline_for_test(&self) -> Result<Option<tokio::time::Instant>> {
        let Some(prepared) = &self.prepared else {
            return Ok(None);
        };
        Ok(Some(
            self.session
                .as_ref()
                .context("missing retained ACK")?
                .valid_until_checked(prepared.expected.binding())?,
        ))
    }

    pub(crate) async fn failure(&mut self) -> &'static str {
        match self.session.as_mut() {
            Some(session) => session.failure().await,
            None => std::future::pending().await,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) async fn stop_monitor_and_join(&mut self) -> Result<()> {
        if let Some(session) = self.session.as_mut() {
            session.stop_and_join().await?;
        }
        Ok(())
    }
}

/// A validated stopped-ingress identity. Issuance/recovery is complete, but
/// this type provides no capture authorization or live relay confirmation.
pub(crate) struct PreparedIdentity(Prepared);
impl PreparedIdentity {
    pub(crate) async fn prepare(
        bundle: &Path,
        settings: &Settings,
        renewal_allowed: bool,
    ) -> Result<Self> {
        let (profile, identity) = OnlineProfile::for_runtime(bundle, settings)?;
        if !renewal_allowed {
            let status = store::online_status(&identity, registry::unix_now()?)?;
            after_protected_status(false, status.pending, status.renewal_due)
                .map_err(anyhow::Error::msg)?;
        }
        if renewal_allowed {
            if let Some(completed) =
                store::resume_online_response(&identity, registry::unix_now()?)?
            {
                ensure!(
                    completed.certificate_valid_now,
                    "recovered device certificate expired"
                );
            }
        }
        let status = store::online_status(&identity, registry::unix_now()?)?;
        if after_protected_status(renewal_allowed, status.pending, status.renewal_due)
            .map_err(anyhow::Error::msg)?
            == RenewalPlan::Renew
        {
            let material = store::begin_online_request(
                &identity,
                Operation::Renew,
                profile.digest(),
                None,
                registry::unix_now()?,
            )?;
            let completed =
                crate::device_enrollment::perform(&identity, &profile, &material).await?;
            ensure!(
                completed.certificate_valid_now,
                "renewed device certificate expired"
            );
        }
        let expected =
            store::online_expectation(&identity, profile.digest(), registry::unix_now()?)?;
        let prepared = Prepared {
            bundle: bundle.to_owned(),
            identity,
            profile,
            settings: settings.clone(),
            expected,
        };
        Ok(Self(prepared))
    }
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn fingerprint(&self) -> &str {
        &self.0.expected.certificate_sha256
    }
    pub(crate) async fn confirm(self) -> Result<Supervisor> {
        let prepared = self.0;
        let acknowledgement = prepared.confirm().await?;
        // The monitor has no network or key-generation path. Its task belongs
        // to this client process and is aborted on every startup/exit path.
        let directory = prepared.identity.clone();
        let digest = prepared.profile.digest().to_owned();
        let expected = OnlineExpectation {
            certificate_sha256: prepared.expected.certificate_sha256.clone(),
            not_after_unix_secs: prepared.expected.not_after_unix_secs,
            issued_generation: prepared.expected.issued_generation,
            snapshot_sha256: prepared.expected.snapshot_sha256.clone(),
        };
        Ok(Supervisor {
            prepared: Some(prepared),
            session: Some(OnlineSessionObservation::new(acknowledgement, move || {
                monitor(&directory, &digest, &expected)
            })),
        })
    }
}

impl Prepared {
    async fn confirm(&self) -> Result<ObservedPolicyAck> {
        // Revalidate path/config/pin after any local recovery and immediately
        // before readiness. No changed profile can inherit the previous ACK.
        let (profile, identity) = OnlineProfile::for_runtime(&self.bundle, &self.settings)?;
        ensure!(
            identity == self.identity && profile.digest() == self.profile.digest(),
            "online profile changed during startup"
        );
        let mut last_error = anyhow::anyhow!("no live relay policy acknowledgement attempted");
        for attempt in 0..3 {
            let observation =
                observe_policy_ack(
                    &self.expected,
                    || {
                        ensure!(
                            monitor_at(
                                &self.identity,
                                self.profile.digest(),
                                &self.expected.certificate_sha256,
                                registry::unix_now()?,
                            )
                            .is_none(),
                            "device renewal or recovery became due before readiness"
                        );
                        store::online_expectation(
                            &self.identity,
                            self.profile.digest(),
                            registry::unix_now()?,
                        )
                    },
                    |current| async move {
                        crate::relay::policy_ack(&self.settings.relay, &current).await
                    },
                )
                .await;
            match observation {
                Ok(confirmed) => return Ok(confirmed),
                Err(ObservationFailure::Ack(error)) => last_error = error,
                Err(error) => return Err(terminal_observation_error(error)),
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_secs(attempt + 1)).await;
            }
        }
        // Keep the final transport/authentication/ACK cause for the explicit
        // diagnostic mode. Default and forensic-safe log boundaries still
        // reduce this chain to closed error codes; ingress remains stopped.
        Err(last_error
            .context("live relay policy has not confirmed this device; ingress remains blocked"))
    }
}

fn terminal_observation_error(failure: ObservationFailure) -> anyhow::Error {
    match failure {
        ObservationFailure::BeforeRead(error)
        | ObservationFailure::Ack(error)
        | ObservationFailure::After(error) => error,
        ObservationFailure::BeforeChanged(error) => {
            error.context("device identity changed during startup")
        }
        ObservationFailure::AfterChanged(error) => {
            error.context("device identity changed during policy acknowledgement")
        }
    }
}

fn monitor(directory: &Path, digest: &str, expected: &OnlineExpectation) -> Option<&'static str> {
    match registry::unix_now() {
        Ok(now) => monitor_issuance_at(directory, digest, expected, now),
        Err(_) => Some("device renewal clock became invalid"),
    }
}

fn monitor_issuance_at(
    directory: &Path,
    digest: &str,
    expected: &OnlineExpectation,
    now: u64,
) -> Option<&'static str> {
    if let Some(reason) = monitor_at(directory, digest, &expected.certificate_sha256, now) {
        return Some(reason);
    }
    match store::online_expectation(directory, digest, now) {
        Ok(current) if expected.ensure_same_issuance(&current).is_ok() => None,
        Ok(_) => Some("device issuance changed; authenticated restart required"),
        Err(_) => Some("device identity or renewal state became invalid"),
    }
}

pub(crate) fn monitor_at(
    directory: &Path,
    digest: &str,
    fingerprint: &str,
    now: u64,
) -> Option<&'static str> {
    let check = || -> Result<Option<&'static str>> {
        let status = store::online_status(directory, now)?;
        if status.pending || status.renewal_due {
            return Ok(Some("device renewal requires restart before issuance"));
        }
        let expected = store::online_expectation(directory, digest, now)?;
        if expected.certificate_sha256 != fingerprint {
            return Ok(Some(
                "device certificate changed; authenticated restart required",
            ));
        }
        Ok(None)
    };
    check().unwrap_or(Some("device identity or renewal state became invalid"))
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    fn issuance(generation: Option<u64>, snapshot: Option<&str>) -> OnlineExpectation {
        OnlineExpectation {
            certificate_sha256: "same-certificate".into(),
            not_after_unix_secs: 10_000,
            issued_generation: generation,
            snapshot_sha256: snapshot.map(str::to_owned),
        }
    }

    #[test]
    fn post_ack_changed_issuance_preserves_diagnostic_context() {
        let changed = terminal_observation_error(ObservationFailure::AfterChanged(
            anyhow::anyhow!("online issuance changed; authenticated restart required"),
        ));
        assert_eq!(
            changed.to_string(),
            "device identity changed during policy acknowledgement"
        );
        let expired = terminal_observation_error(ObservationFailure::After(anyhow::anyhow!(
            "policy acknowledgement expired before readiness"
        )));
        assert_eq!(
            expired.to_string(),
            "policy acknowledgement expired before readiness"
        );
    }

    #[test]
    fn readiness_ack_cannot_cross_same_certificate_issuance_generations() {
        let prepared = issuance(Some(7), Some("snapshot-seven"));
        assert!(prepared
            .ensure_same_issuance(&issuance(Some(7), Some("snapshot-seven")))
            .is_ok());
        for changed in [
            issuance(Some(8), Some("snapshot-seven")),
            issuance(Some(7), Some("snapshot-eight")),
            issuance(None, None),
        ] {
            assert!(prepared.ensure_same_issuance(&changed).is_err());
        }
    }

    #[test]
    fn offline_prepared_identity_cannot_inherit_a_new_online_ack_floor() {
        let prepared = issuance(None, None);
        assert!(prepared.ensure_same_issuance(&issuance(None, None)).is_ok());
        assert!(prepared
            .ensure_same_issuance(&issuance(Some(1), Some("online")))
            .is_err());
    }

    #[test]
    fn readiness_ack_cannot_inherit_changed_certificate_or_expiry() {
        let prepared = issuance(Some(7), Some("snapshot-seven"));
        let mut current = issuance(Some(7), Some("snapshot-seven"));
        current.certificate_sha256 = "replacement-certificate".into();
        assert!(prepared.ensure_same_issuance(&current).is_err());
        current.certificate_sha256 = prepared.certificate_sha256.clone();
        current.not_after_unix_secs += 1;
        assert!(prepared.ensure_same_issuance(&current).is_err());
    }

    #[test]
    fn retained_live_ack_rejects_same_certificate_issuance_change() {
        // The library tests the exact expiry boundary with an injected clock.
        // This integration check uses a long live deadline so scheduler delay
        // cannot convert its positive issuance assertion into a timing test.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
        let retained = ObservedPolicyAck::retain_observed(
            issuance(Some(7), Some("snapshot-seven")).binding(),
            deadline,
        )
        .unwrap();
        assert!(retained
            .ensure_current(issuance(Some(7), Some("snapshot-seven")).binding())
            .is_ok());
        assert!(retained
            .ensure_current(issuance(Some(8), Some("snapshot-seven")).binding())
            .is_err());
        assert!(retained
            .ensure_current(issuance(Some(7), Some("snapshot-eight")).binding())
            .is_err());
        assert!(retained
            .ensure_current(issuance(None, None).binding())
            .is_err());
    }

    #[test]
    fn windows_tunnel_requires_a_valid_online_profile() {
        let settings = Settings {
            windows_tunnel: Some(Default::default()),
            ..Default::default()
        };
        let error = validate(Some(Path::new("not-a-bundle")), &settings).unwrap_err();
        assert!(error.to_string().contains("absolute directory"));
        assert!(validate(None, &settings).is_ok());
    }
}
