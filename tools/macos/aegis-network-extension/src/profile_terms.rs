//! B-06 S16a: the public profile terms of the provider's held identity tree.
//!
//! Since S14 the identity and bundle live only in the root provider's own
//! App Group container; the console-user host has no `Aegis/` tree to read.
//! The host therefore asks the provider (`profile-terms` over the S10 XPC
//! channel) for the public values a saved manager profile must name: the
//! signed numeric relay endpoint, the signed `macos_packet` DNS list and MTU
//! and the digest of the four public bundle files.
//!
//! The provider answers only from a fresh capture of its held tree, checked
//! by the same validators a start uses up to the Store: the descriptor
//! custody and S22 identity checks of `CapturedAppGroupInputs`, then
//! `BoundRelayPolicy::capture` and its signed runtime terms. The reply never
//! carries key material, a certificate, a bridge secret or a file path; no
//! Store is opened. The owner generation is not a term: nothing in the held
//! tree names one, so the host mints it when it saves a profile.
//!
//! Terms are not a relay ACK, packet permit, credential grant or start.

use crate::{
    app_group::{custody_refusal_code, CapturedAppGroupInputs},
    bound_relay_policy::BoundRelayPolicy,
    host_lifecycle::{xpc_error_exit, EXIT_XPC_REFUSED, EXIT_XPC_TIMEOUT},
    identity_import::is_sha256_hex,
    policy::FullWide,
    provider_xpc::Reply,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

/// A refused held policy or signed-term inconsistency. Custody refusals keep
/// their own stable codes (`custody_refusal_code`).
pub const TERMS_REFUSED: &str = "profile_terms_refused";
/// The requested `RELAY_IP` is not the held signed relay host.
pub const RELAY_MISMATCH: &str = "profile_relay_mismatch";

/// The public terms of the held tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileTerms {
    /// The signed numeric relay endpoint (`relay_server`).
    pub relay: SocketAddr,
    /// The signed `macos_packet.dns_servers`, in order.
    pub dns: Vec<IpAddr>,
    /// The signed `macos_packet.mtu`.
    pub mtu: u16,
    /// Digest of the four public bundle files (lowercase hex).
    pub profile_sha256: String,
}

impl ProfileTerms {
    /// The full-wide manager policy these terms authorize. A relay or DNS
    /// value no saved profile may carry, a port 0 or a malformed digest is
    /// refused, on either side of the channel.
    pub fn policy(&self) -> Result<FullWide, &'static str> {
        if self.relay.port() == 0 || !is_sha256_hex(&self.profile_sha256) {
            return Err(TERMS_REFUSED);
        }
        FullWide::new(self.relay.ip(), self.dns.clone(), self.mtu).map_err(|_| TERMS_REFUSED)
    }
}

/// The provider's terms over one capture `inputs`: the held signed bundle's
/// policy (`BoundRelayPolicy::capture` revalidates every held descriptor
/// after reading) and its signed runtime terms, whose relay host is parsed
/// from the same signed `relay_server`. Only retained values are read after
/// that revalidation.
pub(crate) fn held_terms(
    inputs: &mut CapturedAppGroupInputs,
) -> Result<ProfileTerms, &'static str> {
    let refused = |error: io::Error| custody_or(&error, TERMS_REFUSED);
    let policy = BoundRelayPolicy::capture(inputs).map_err(refused)?;
    let relay: SocketAddr = policy
        .settings()
        .relay
        .server
        .parse()
        .map_err(|_| TERMS_REFUSED)?;
    let signed = policy.signed_runtime_terms().map_err(refused)?;
    let terms = ProfileTerms {
        relay,
        dns: signed.dns.to_vec(),
        mtu: signed.mtu,
        profile_sha256: signed.profile_sha256.to_owned(),
    };
    terms.policy()?;
    Ok(terms)
}

/// A custody refusal's own code, else `fallback`.
fn custody_or(error: &io::Error, fallback: &'static str) -> &'static str {
    match custody_refusal_code(error) {
        "provider_app_group_custody_refused" => fallback,
        code => code,
    }
}

/// The provider responder's terms: one fresh `capture`, dropped (with its
/// tree lease) before the reply is sent.
pub(crate) fn provider_terms(
    capture: impl FnOnce() -> io::Result<CapturedAppGroupInputs>,
) -> Result<ProfileTerms, &'static str> {
    let mut inputs = capture().map_err(|error| custody_refusal_code(&error))?;
    held_terms(&mut inputs)
}

/// Why the host could not admit terms for a profile verb.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TermsFailure {
    /// No reply within the XPC budget.
    Timeout,
    /// No decoded reply (`provider_xpc` host-side code).
    Xpc(&'static str),
    /// The provider refused (no identity, custody, policy).
    Refused(String),
    /// The reply decoded but is not a `profile-terms` reply.
    Unexpected,
    /// The requested relay is not the held signed relay.
    RelayMismatch,
}

impl TermsFailure {
    pub fn code(&self) -> &str {
        match self {
            Self::Timeout => "xpc_timeout",
            Self::Xpc(code) => code,
            Self::Refused(code) => code,
            Self::Unexpected => "reply_verb_mismatch",
            Self::RelayMismatch => RELAY_MISMATCH,
        }
    }
    /// Exit codes of `--ping` for channel failures; a relay mismatch is a
    /// profile refusal (2), like every other profile-verb refusal.
    pub fn exit(&self) -> i32 {
        match self {
            Self::Timeout => EXIT_XPC_TIMEOUT,
            Self::Xpc(code) => xpc_error_exit(code),
            Self::Refused(_) | Self::Unexpected => EXIT_XPC_REFUSED,
            Self::RelayMismatch => 2,
        }
    }
}

/// Host admission of one `profile-terms` reply for `--save-profile`,
/// `--connect` and `--repair-runtime` (a disconnect or status read needs no
/// terms; `manager::OwnedTarget::Saved`): the operator's `RELAY_IP` must be the held signed relay
/// host, and the returned terms must form a full-wide policy. The returned
/// policy's DNS and MTU are the provider's, never a host default.
pub fn host_policy(
    reply: Result<Reply, &'static str>,
    requested_relay: IpAddr,
) -> Result<(ProfileTerms, FullWide), TermsFailure> {
    let terms = match reply.map_err(TermsFailure::Xpc)? {
        Reply::ProfileTerms(terms) => terms,
        Reply::Refused(code) => return Err(TermsFailure::Refused(code)),
        _ => return Err(TermsFailure::Unexpected),
    };
    if terms.relay.ip() != requested_relay {
        return Err(TermsFailure::RelayMismatch);
    }
    let policy = terms
        .policy()
        .map_err(|code| TermsFailure::Refused(code.into()))?;
    Ok((terms, policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity_import::tests::TempContainer, test_fixture::ReadyTree};

    fn fixture_relay() -> SocketAddr {
        "192.0.2.10:443".parse().unwrap()
    }

    fn capture(dir: &std::path::Path) -> io::Result<CapturedAppGroupInputs> {
        CapturedAppGroupInputs::capture_test_root(dir)
    }

    #[test]
    fn profile_terms_of_a_held_fixture_are_exactly_its_signed_public_terms() {
        let tree = ReadyTree::new(fixture_relay());
        let terms = provider_terms(|| capture(tree.root())).unwrap();
        assert_eq!(
            terms,
            ProfileTerms {
                relay: tree.relay(),
                dns: tree.policy().dns().to_vec(),
                mtu: tree.policy().mtu(),
                profile_sha256: tree.profile_sha256().to_owned(),
            }
        );
        assert_eq!(&terms.policy().unwrap(), tree.policy());
    }

    #[test]
    fn profile_terms_refuse_without_an_issued_identity_or_tree() {
        let empty = TempContainer::new();
        assert_eq!(
            provider_terms(|| capture(empty.path())),
            Err(crate::app_group::AEGIS_TREE_MISSING)
        );
        let unissued = ReadyTree::unissued(fixture_relay());
        assert_eq!(
            provider_terms(|| capture(unissued.root())),
            Err("file_missing:online-completed.json")
        );
        let tree = ReadyTree::new(fixture_relay());
        std::fs::remove_file(tree.identity_dir().join("device.key")).unwrap();
        assert_eq!(
            provider_terms(|| capture(tree.root())),
            Err("file_missing:device.key")
        );
    }

    #[test]
    fn profile_terms_refuse_a_loopback_relay_no_profile_may_save() {
        // The fixture admits 127.0.0.1 for loopback relay tests; a saved
        // full-wide profile never may.
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        assert_eq!(provider_terms(|| capture(tree.root())), Err(TERMS_REFUSED));
    }

    fn terms() -> ProfileTerms {
        ProfileTerms {
            relay: fixture_relay(),
            dns: vec![
                "198.19.255.2".parse().unwrap(),
                "fd00:ae61::2".parse().unwrap(),
            ],
            mtu: 1280,
            profile_sha256: "c".repeat(64),
        }
    }

    #[test]
    fn host_policy_refuses_a_relay_mismatch_and_takes_provider_dns_and_mtu() {
        let requested: IpAddr = "192.0.2.10".parse().unwrap();
        let (admitted, policy) = host_policy(Ok(Reply::ProfileTerms(terms())), requested).unwrap();
        assert_eq!(admitted, terms());
        assert_eq!(policy.relay(), requested);
        assert_eq!(policy.dns(), terms().dns.as_slice());
        assert_eq!(policy.mtu(), 1280);
        for other in ["192.0.2.11", "2001:db8::10", "198.51.100.10"] {
            let failure =
                host_policy(Ok(Reply::ProfileTerms(terms())), other.parse().unwrap()).unwrap_err();
            assert_eq!(failure, TermsFailure::RelayMismatch, "{other}");
            assert_eq!(failure.code(), RELAY_MISMATCH);
            assert_eq!(failure.exit(), 2);
        }
        // Provider refusal, channel failure and a reply for another verb.
        let refused = host_policy(Ok(Reply::Refused("aegis_tree_missing".into())), requested);
        assert_eq!(
            refused,
            Err(TermsFailure::Refused("aegis_tree_missing".into()))
        );
        assert_eq!(refused.unwrap_err().exit(), EXIT_XPC_REFUSED);
        let unavailable = host_policy(Err("service_unavailable"), requested).unwrap_err();
        assert_eq!(
            unavailable.exit(),
            crate::host_lifecycle::EXIT_XPC_UNAVAILABLE
        );
        let status = Reply::Status(crate::provider_xpc::StatusReport {
            session_phase: "none".into(),
            session_refusal: None,
        });
        assert_eq!(
            host_policy(Ok(status), requested),
            Err(TermsFailure::Unexpected)
        );
        assert_eq!(TermsFailure::Timeout.exit(), EXIT_XPC_TIMEOUT);
    }

    #[test]
    fn host_policy_refuses_terms_no_full_wide_profile_may_carry() {
        let requested: IpAddr = "192.0.2.10".parse().unwrap();
        let mut bad = Vec::new();
        let mut next = terms();
        next.relay.set_port(0);
        bad.push(next);
        next = terms();
        next.dns = Vec::new();
        bad.push(next);
        next = terms();
        next.dns.push("192.0.2.53".parse().unwrap());
        bad.push(next);
        next = terms();
        next.mtu = 1279;
        bad.push(next);
        next = terms();
        next.profile_sha256 = "C".repeat(64);
        bad.push(next);
        next = terms();
        next.profile_sha256 = "c".repeat(63);
        bad.push(next);
        for terms in bad {
            assert_eq!(
                host_policy(Ok(Reply::ProfileTerms(terms.clone())), requested),
                Err(TermsFailure::Refused(TERMS_REFUSED.into())),
                "{terms:?}"
            );
        }
        // A loopback relay matches its own request yet is never saveable.
        let mut loopback = terms();
        loopback.relay = "127.0.0.1:443".parse().unwrap();
        assert_eq!(
            host_policy(
                Ok(Reply::ProfileTerms(loopback)),
                "127.0.0.1".parse().unwrap()
            ),
            Err(TermsFailure::Refused(TERMS_REFUSED.into()))
        );
    }
}
