//! One completed operator-profile training owner per server runtime/keyring.
//! Not a request cache: no remote input can insert, refresh, or launch training.
use super::*;
use crate::traffic_privacy::{adaptive_channel, liu_channel};
use std::time::Duration;

enum PublicTraining {
    Adaptive(adaptive_channel::PreparedChannel),
    Liu(liu_channel::PreparedChannel),
}

/// Same-build, process-resident completed public numerical model only.
/// Private fields prevent session state or forged descriptors from becoming a
/// reuse key. The entire ordered profile must match, not just a hash.
pub struct ServerTraining {
    profile: PrivacySettings,
    numerical: PublicTraining,
}
impl ServerTraining {
    /// Call once for trusted local configuration BEFORE binding listeners.
    /// Failure blocks readiness. The existing 4/32 budget and actual optimizer
    /// bodies govern this work; no session/accept clock exists or is renewed.
    pub async fn prepare(profile: &PrivacySettings) -> io::Result<Option<Self>> {
        let timeout_ms = if let Some(settings) = &profile.adaptive_channel {
            settings.optimizer_timeout_ms
        } else if let Some(settings) = &profile.liu_channel {
            settings.optimizer_timeout_ms
        } else {
            profile.validate()?;
            return Ok(None);
        };
        let startup_origin = Instant::now();
        let startup_deadline = startup_origin
            .checked_add(Duration::from_millis(u64::from(timeout_ms)))
            .ok_or_else(rejected)?;
        profile.validate()?;
        within_establishment(startup_deadline, async {
            let numerical = if let Some(settings) = &profile.adaptive_channel {
                PublicTraining::Adaptive(
                    adaptive_channel::prepare(settings.clone(), startup_deadline).await?,
                )
            } else if let Some(settings) = &profile.liu_channel {
                PublicTraining::Liu(liu_channel::prepare(settings.clone(), startup_deadline).await?)
            } else {
                return Err(rejected());
            };
            Ok(Some(Self {
                profile: profile.clone(),
                numerical,
            }))
        })
        .await
    }
    pub(super) fn check_profile(&self, profile: &PrivacySettings) -> io::Result<()> {
        if profile != &self.profile {
            return Err(rejected());
        }
        Ok(())
    }
    pub(super) fn adaptive(
        &self,
        profile: &PrivacySettings,
    ) -> io::Result<adaptive_channel::PreparedChannel> {
        self.check_profile(profile)?;
        match &self.numerical {
            PublicTraining::Adaptive(prepared) => Ok(prepared.clone()),
            _ => Err(rejected()),
        }
    }
    pub(super) fn liu(
        &self,
        profile: &PrivacySettings,
    ) -> io::Result<liu_channel::PreparedChannel> {
        self.check_profile(profile)?;
        match &self.numerical {
            PublicTraining::Liu(prepared) => Ok(prepared.reuse_public_training()),
            _ => Err(rejected()),
        }
    }
}
