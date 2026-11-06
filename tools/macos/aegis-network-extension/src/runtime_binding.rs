//! Provider runtime binding and the host-only runtime document.
//!
//! The sandboxed root provider cannot read a `runtime.json` published by the
//! console-user host: the two roles resolve different App Group containers.
//! The provider therefore derives its binding itself from the saved manager
//! intent, the held admitted bundle and the held protected Store issuance, and
//! never opens a runtime record. Every relay, DNS and MTU value the saved
//! (host-written, console-user) intent names must equal the held signed
//! bundle's terms; the profile digest must equal both the held identity's and
//! the held signed policy's; issuance comes only from the held Store. The
//! owner generation is the one field nothing signed can authorize: it is an
//! opaque, well-formed identifier pinned for the life of one session.
//!
//! The host still renders the exact document (`render_for_host`) for its own
//! container. Neither value is a relay ACK, packet permit or capture grant.

use crate::{configuration::PROVIDER_ID, manager::ProfileIntent, policy::FullWide};
use aegis_client::online_expectation::OnlineExpectation;
use aegis_core::secure_channel::enrollment::protocol;
use serde_json::{json, Value};
use std::{io, net::IpAddr};

const MAX_RUNTIME: u64 = 4096;
const SCHEMA: &str = "aegis-ne-runtime-v1";

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "runtime identity binding refused",
    )
}

fn checked_inputs(
    generation: &str,
    profile_sha256: &str,
    online: &OnlineExpectation,
) -> io::Result<()> {
    if generation.is_empty()
        || generation.len() > 128
        || generation.chars().any(char::is_control)
        || online.not_after_unix_secs == 0
        || online.issued_generation.is_some() != online.snapshot_sha256.is_some()
    {
        return Err(refused());
    }
    protocol::digest(profile_sha256).map_err(|_| refused())?;
    protocol::digest(&online.certificate_sha256).map_err(|_| refused())?;
    if let Some(snapshot) = online.snapshot_sha256.as_deref() {
        protocol::digest(snapshot).map_err(|_| refused())?;
    }
    Ok(())
}

fn expected_document(
    generation: &str,
    policy: &FullWide,
    profile_sha256: &str,
    online: &OnlineExpectation,
) -> io::Result<Value> {
    checked_inputs(generation, profile_sha256, online)?;
    Ok(json!({
        "schema": SCHEMA,
        "owner_generation": generation,
        "relay": policy.relay().to_string(),
        "dns": policy.dns().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "mtu": policy.mtu(),
        "profile_sha256": profile_sha256,
        "certificate_sha256": online.certificate_sha256,
        "not_after_unix_secs": online.not_after_unix_secs,
        "issued_generation": online.issued_generation,
        "snapshot_sha256": online.snapshot_sha256,
    }))
}

/// Render the sole accepted encoding for a containing host's exact saved
/// profile. The host must acquire its values from a separately protected local
/// identity check and publish the bytes transactionally in its App Group.
/// No provider path reads these bytes.
pub fn render_for_host(
    intent: &ProfileIntent,
    profile_sha256: &str,
    online: &OnlineExpectation,
) -> io::Result<Vec<u8>> {
    if intent.provider_id != PROVIDER_ID {
        return Err(refused());
    }
    let value = expected_document(
        &intent.owner_generation,
        &intent.policy,
        profile_sha256,
        online,
    )?;
    let bytes = serde_json::to_vec(&value).map_err(|_| refused())?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RUNTIME {
        return Err(refused());
    }
    Ok(bytes)
}

/// The runtime terms a held, admitted signed bundle authorizes. Construct it
/// only from the retained `BoundRelayPolicy` of the same App Group claim.
pub(crate) struct SignedRuntimeTerms<'a> {
    pub(crate) relay: IpAddr,
    pub(crate) dns: &'a [IpAddr],
    pub(crate) mtu: u16,
    pub(crate) profile_sha256: &'a str,
}

/// The provider's own runtime binding. Each field is either taken from the
/// held tree/Store or cross-checked against the held signed terms.
#[must_use = "retain the derived binding and compare every later derivation"]
pub(crate) struct DerivedRuntimeBinding {
    generation: String,
    policy: FullWide,
    profile_sha256: String,
    certificate_sha256: String,
    not_after_unix_secs: u64,
    issued_generation: Option<u64>,
    snapshot_sha256: Option<String>,
}

/// Derive the binding from the saved intent, the held signed terms, the held
/// identity's profile digest and the held Store issuance. A saved relay, DNS
/// list or MTU the signed bundle does not name, a digest that differs from the
/// signed policy's own, a malformed generation or issuance, or an identity
/// without an issued generation and snapshot (S22) is refused.
pub(crate) fn derive(
    generation: &str,
    policy: &FullWide,
    signed: &SignedRuntimeTerms<'_>,
    profile_sha256: &str,
    online: &OnlineExpectation,
) -> io::Result<DerivedRuntimeBinding> {
    checked_inputs(generation, profile_sha256, online)?;
    // S22: the provider binds only an issued identity, never an offline one.
    // `checked_inputs` already requires the snapshot exactly with a generation.
    if online.issued_generation.is_none() {
        return Err(refused());
    }
    if policy.relay() != signed.relay
        || policy.dns() != signed.dns
        || policy.mtu() != signed.mtu
        || profile_sha256 != signed.profile_sha256
    {
        return Err(refused());
    }
    Ok(DerivedRuntimeBinding {
        generation: generation.to_owned(),
        policy: policy.clone(),
        profile_sha256: profile_sha256.to_owned(),
        certificate_sha256: online.certificate_sha256.clone(),
        not_after_unix_secs: online.not_after_unix_secs,
        issued_generation: online.issued_generation,
        snapshot_sha256: online.snapshot_sha256.clone(),
    })
}

impl DerivedRuntimeBinding {
    /// Require a later derivation to be the exact retained binding: the same
    /// generation, relay, DNS, MTU, profile digest and full issuance.
    pub(crate) fn ensure_same(&self, current: &Self) -> io::Result<()> {
        if self.generation != current.generation
            || self.policy != current.policy
            || self.profile_sha256 != current.profile_sha256
            || self.certificate_sha256 != current.certificate_sha256
            || self.not_after_unix_secs != current.not_after_unix_secs
            || self.issued_generation != current.issued_generation
            || self.snapshot_sha256 != current.snapshot_sha256
        {
            return Err(refused());
        }
        Ok(())
    }

    /// The host document these exact values would render, for consistency
    /// tests between the two roles only.
    #[cfg(test)]
    fn host_document(&self) -> io::Result<Value> {
        expected_document(
            &self.generation,
            &self.policy,
            &self.profile_sha256,
            &OnlineExpectation {
                certificate_sha256: self.certificate_sha256.clone(),
                not_after_unix_secs: self.not_after_unix_secs,
                issued_generation: self.issued_generation,
                snapshot_sha256: self.snapshot_sha256.clone(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn fixture() -> (ProfileIntent, OnlineExpectation) {
        let policy = FullWide::new(
            "192.0.2.5".parse().unwrap(),
            vec![
                "198.19.255.2".parse().unwrap(),
                "fd00:ae61::2".parse().unwrap(),
            ],
            1280,
        )
        .unwrap();
        (
            ProfileIntent {
                provider_id: "dev.aegis.macos.PacketTunnel".into(),
                owner_generation: "generation-1".into(),
                policy,
            },
            OnlineExpectation {
                certificate_sha256: "a".repeat(64),
                not_after_unix_secs: 12345,
                issued_generation: Some(7),
                snapshot_sha256: Some("b".repeat(64)),
            },
        )
    }

    fn signed(policy: &FullWide) -> SignedRuntimeTerms<'_> {
        SignedRuntimeTerms {
            relay: policy.relay(),
            dns: policy.dns(),
            mtu: policy.mtu(),
            profile_sha256: PROFILE,
        }
    }

    fn policy(relay: &str, dns: &[&str], mtu: u16) -> FullWide {
        FullWide::new(
            relay.parse().unwrap(),
            dns.iter().map(|d| d.parse().unwrap()).collect(),
            mtu,
        )
        .unwrap()
    }

    #[test]
    fn derived_binding_refuses_changed_generation_relay_dns_mtu_profile_and_issuance() {
        let (intent, online) = fixture();
        let held = signed(&intent.policy);
        let bound = derive(
            &intent.owner_generation,
            &intent.policy,
            &held,
            PROFILE,
            &online,
        )
        .unwrap();
        // The identical derivation is the same binding.
        bound
            .ensure_same(
                &derive(
                    &intent.owner_generation,
                    &intent.policy,
                    &held,
                    PROFILE,
                    &online,
                )
                .unwrap(),
            )
            .unwrap();
        // A changed generation derives, but is never the retained binding.
        let other = derive("generation-2", &intent.policy, &held, PROFILE, &online).unwrap();
        assert!(bound.ensure_same(&other).is_err());
        // A changed relay, DNS list or MTU is refused against the same signed
        // terms, and differs from the binding when signed terms moved with it.
        for changed in [
            policy("192.0.2.6", &["198.19.255.2", "fd00:ae61::2"], 1280),
            policy("192.0.2.5", &["198.19.255.2"], 1280),
            policy("192.0.2.5", &["fd00:ae61::2", "198.19.255.2"], 1280),
            policy("192.0.2.5", &["198.19.255.2", "fd00:ae61::2"], 1400),
        ] {
            assert!(derive("generation-1", &changed, &held, PROFILE, &online).is_err());
            let moved = derive(
                "generation-1",
                &changed,
                &signed(&changed),
                PROFILE,
                &online,
            )
            .unwrap();
            assert!(bound.ensure_same(&moved).is_err());
        }
        // A changed profile digest is refused against the signed digest, and
        // differs from the binding when the signed digest moved with it.
        let other_profile = "d".repeat(64);
        assert!(derive(
            "generation-1",
            &intent.policy,
            &held,
            &other_profile,
            &online
        )
        .is_err());
        let moved = SignedRuntimeTerms {
            profile_sha256: &other_profile,
            ..signed(&intent.policy)
        };
        let moved = derive(
            "generation-1",
            &intent.policy,
            &moved,
            &other_profile,
            &online,
        )
        .unwrap();
        assert!(bound.ensure_same(&moved).is_err());
        // Every issuance field is part of the binding.
        let mut changed = Vec::new();
        let mut next = online.clone();
        next.issued_generation = Some(8);
        changed.push(next);
        next = online.clone();
        next.certificate_sha256 = "e".repeat(64);
        changed.push(next);
        next = online.clone();
        next.not_after_unix_secs += 1;
        changed.push(next);
        next = online.clone();
        next.snapshot_sha256 = Some("f".repeat(64));
        changed.push(next);
        for next in changed {
            let current = derive("generation-1", &intent.policy, &held, PROFILE, &next).unwrap();
            assert!(bound.ensure_same(&current).is_err());
        }
    }

    #[test]
    fn derived_binding_refuses_malformed_generation_digests_and_incoherent_issuance() {
        let (intent, online) = fixture();
        let held = signed(&intent.policy);
        for generation in [String::new(), "x".repeat(129), "line\nbreak".into()] {
            assert!(derive(&generation, &intent.policy, &held, PROFILE, &online).is_err());
        }
        assert!(derive(&"x".repeat(128), &intent.policy, &held, PROFILE, &online).is_ok());
        let upper = "C".repeat(64);
        let upper_held = SignedRuntimeTerms {
            profile_sha256: &upper,
            ..signed(&intent.policy)
        };
        assert!(derive("g", &intent.policy, &upper_held, &upper, &online).is_err());
        let mut bad = online.clone();
        bad.snapshot_sha256 = None;
        assert!(derive("g", &intent.policy, &held, PROFILE, &bad).is_err());
        bad = online.clone();
        bad.not_after_unix_secs = 0;
        assert!(derive("g", &intent.policy, &held, PROFILE, &bad).is_err());
        bad = online.clone();
        bad.certificate_sha256 = "a".repeat(63);
        assert!(derive("g", &intent.policy, &held, PROFILE, &bad).is_err());
        bad = online;
        bad.snapshot_sha256 = Some("short".into());
        assert!(derive("g", &intent.policy, &held, PROFILE, &bad).is_err());
    }

    #[test]
    fn derived_binding_refuses_an_identity_without_issuance() {
        let (intent, online) = fixture();
        let held = signed(&intent.policy);
        // An offline identity (no completion receipt) is coherent, and the
        // host may still render it, but the provider never binds it.
        let mut offline = online.clone();
        offline.issued_generation = None;
        offline.snapshot_sha256 = None;
        assert!(render_for_host(&intent, PROFILE, &offline).is_ok());
        assert!(derive("g", &intent.policy, &held, PROFILE, &offline).is_err());
        // Either half missing alone is refused too.
        let mut half = online.clone();
        half.issued_generation = None;
        assert!(derive("g", &intent.policy, &held, PROFILE, &half).is_err());
        half = online.clone();
        half.snapshot_sha256 = None;
        assert!(derive("g", &intent.policy, &held, PROFILE, &half).is_err());
        assert!(derive("g", &intent.policy, &held, PROFILE, &online).is_ok());
    }

    #[test]
    fn host_document_names_exactly_the_provider_derived_binding() {
        let (intent, online) = fixture();
        let bytes = render_for_host(&intent, PROFILE, &online).unwrap();
        let bound = derive(
            &intent.owner_generation,
            &intent.policy,
            &signed(&intent.policy),
            PROFILE,
            &online,
        )
        .unwrap();
        let rendered: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rendered, bound.host_document().unwrap());
        // The host encoding stays canonical and bounded.
        assert_eq!(serde_json::to_vec(&rendered).unwrap(), bytes);
        assert!(bytes.len() as u64 <= MAX_RUNTIME);
    }

    #[test]
    fn host_renderer_refuses_alien_provider_and_incoherent_issuance() {
        let (mut intent, mut online) = fixture();
        let profile = "c".repeat(64);
        intent.provider_id = "dev.aegis.macos.Other".into();
        assert!(render_for_host(&intent, &profile, &online).is_err());
        intent.provider_id = PROVIDER_ID.into();
        online.snapshot_sha256 = None;
        assert!(render_for_host(&intent, &profile, &online).is_err());
        online.issued_generation = None;
        online.certificate_sha256 = "A".repeat(64);
        assert!(render_for_host(&intent, &profile, &online).is_err());
    }
}
