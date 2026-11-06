//! Containing-host publication of one exact local runtime record after the
//! manager preference has been saved, reloaded and parsed into typed intent.
//! Publication is not a relay ACK, packet permit or installed acceptance.

use crate::{
    app_group::CapturedHostAppGroupInputs,
    configuration::{SavedProviderIntent, PROVIDER_ID},
    local_identity::public_profile_digest,
    manager::ProfileIntent,
    runtime_binding,
};
use aegis_client::{
    online_expectation::OnlineExpectation, protected_online_expectation::ProtectedOnlineExpectation,
};
use aegis_core::secure_channel::registry;
use std::io;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "host runtime publication refused",
    )
}

pub(crate) struct HostRuntimePublisher {
    inputs: CapturedHostAppGroupInputs,
    online: ProtectedOnlineExpectation<'static>,
    initial: OnlineExpectation,
    profile_sha256: String,
}

impl HostRuntimePublisher {
    pub(crate) fn capture() -> io::Result<Self> {
        let mut inputs = CapturedHostAppGroupInputs::capture_claim()?;
        let (online, initial, profile_sha256) =
            inputs.with_portable_paths(|bundle, identity| {
                let profile_sha256 = public_profile_digest(bundle)?;
                let online = ProtectedOnlineExpectation::open_existing(identity, &profile_sha256)
                    .map_err(|_| refused())?;
                let initial = online
                    .expectation_at(registry::unix_now().map_err(|_| refused())?)
                    .map_err(|_| refused())?;
                Ok((online, initial, profile_sha256))
            })?;
        Ok(Self {
            inputs,
            online,
            initial,
            profile_sha256,
        })
    }

    /// The saved intent must come from the actual reloaded native manager.
    /// The held Store lock spans render, fsync, atomic rename and postcheck.
    pub(crate) fn publish(&mut self, saved: &SavedProviderIntent) -> io::Result<()> {
        self.inputs.revalidate()?;
        let bundle = self.inputs.bundle_path();
        let profile_sha256 = self.profile_sha256.clone();
        let online = &self.online;
        let initial = &self.initial;
        let recheck = || {
            if public_profile_digest(&bundle)? != profile_sha256 {
                return Err(refused());
            }
            let current = online
                .expectation_at(registry::unix_now().map_err(|_| refused())?)
                .map_err(|_| refused())?;
            initial
                .ensure_same_issuance(&current)
                .map_err(|_| refused())?;
            Ok(current)
        };
        let current = recheck()?;
        let intent = ProfileIntent {
            provider_id: PROVIDER_ID.into(),
            owner_generation: saved.generation.clone(),
            policy: saved.policy.clone(),
        };
        let bytes = runtime_binding::render_for_host(&intent, &profile_sha256, &current)?;
        self.inputs
            .publish_runtime(&bytes, || recheck().map(|_| ()))
    }
}
