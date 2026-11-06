//! Offline pre-network admission model; no ICE driver, probe, socket, or cover proof.
//! Trust/readiness are caller attestations, not signature or reachability checks.
//! Filter raw offers here before giving anything to a future ICE dial/probe driver.
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub const MAX_DESCRIPTOR_TTL_MS: u64 = 60_000;
pub const MAX_CANDIDATES: usize = 64;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CandidateKind {
    Host,
    Srflx,
    Relay,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Mode {
    PeerIce,
    TurnRelayOnly,
    OwnedServiceOnly,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum EndpointKind {
    Turn,
    OwnedSfu,
    OwnedApi,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Payload {
    DataChannel,
    Media,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum WireProtocol {
    SctpOverDtls,
    Srtp,
}
/// Numeric inventory handles; never an address, invitation, SDP, or credential.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EndpointId(pub u32);
/// TURN allocation binding must be established externally, not inferred from
/// `typ relay` or a candidate address. Raw candidate kinds alone grant no route.
pub struct Candidate {
    pub kind: CandidateKind,
    pub via_endpoint: Option<EndpointId>,
}
#[derive(Clone, Copy)]
pub struct Lease {
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub trusted: bool,
    pub ready: bool,
    pub provider: u32,
}
#[derive(Clone, Copy)]
pub struct EndpointDescriptor {
    pub id: EndpointId,
    pub kind: EndpointKind,
    pub lease: Lease,
    /// Existing verified readiness input; this function never performs a probe.
    pub reachable: bool,
    pub payload_path_ready: bool,
    pub ready_payload: Payload,
}
pub struct Policy {
    pub mode: Mode,
    pub allow_direct: bool,
    pub allowed_endpoint: Option<EndpointId>,
}
#[derive(Debug, Error, Serialize, PartialEq, Eq)]
pub enum Refusal {
    #[error("too many candidate offers")]
    CandidateLimit,
    #[error("broker or descriptor trust/TTL/readiness refused")]
    InvalidLease,
    #[error("explicit allowed endpoint required")]
    MissingEndpoint,
    #[error("endpoint is not explicitly allowed")]
    EndpointMismatch,
    #[error("endpoint class is incompatible with requested route")]
    WrongEndpointKind,
    #[error("mediated payload path is unavailable")]
    PathUnavailable,
    #[error("no candidate admitted under requested mode")]
    NoCandidate,
}
/// Aggregate fixture receipt: contains no endpoint/provider handles or raw offers.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Admission {
    pub scope: &'static str,
    pub mode: Mode,
    pub endpoint_kind: Option<EndpointKind>,
    pub admitted_host: usize,
    pub admitted_srflx: usize,
    pub admitted_relay: usize,
    pub rejected_direct: usize,
    pub rejected_relay: usize,
    pub bootstrap_required: bool,
    pub route_provider_required: bool,
    pub shared_bootstrap_route_provider: bool,
    pub wire_protocol: WireProtocol,
    pub video_cover_proven: bool,
}
fn validate_lease(lease: Lease, now_ms: u64) -> Result<(), Refusal> {
    let ttl = lease.expires_at_ms.checked_sub(lease.issued_at_ms);
    if !lease.trusted
        || !lease.ready
        || lease.issued_at_ms > now_ms
        || lease.expires_at_ms <= now_ms
        || !ttl.is_some_and(|v| v > 0 && v <= MAX_DESCRIPTOR_TTL_MS)
    {
        return Err(Refusal::InvalidLease);
    }
    Ok(())
}
/// Call before *any* connectivity check. Failure has no lower-mode retry path.
/// OwnedServiceOnly uses its separate service endpoint, admitting zero ICE offers:
/// a TURN relay candidate cannot stand in for an SFU/API forwarding path.
pub fn admit(
    policy: &Policy,
    broker: Lease,
    endpoint: Option<EndpointDescriptor>,
    offers: &[Candidate],
    payload: Payload,
    now_ms: u64,
) -> Result<Admission, Refusal> {
    if offers.len() > MAX_CANDIDATES {
        return Err(Refusal::CandidateLimit);
    }
    validate_lease(broker, now_ms)?;
    let mediated = policy.mode != Mode::PeerIce;
    let selected = if mediated {
        let allowed = policy.allowed_endpoint.ok_or(Refusal::MissingEndpoint)?;
        let e = endpoint.ok_or(Refusal::MissingEndpoint)?;
        if e.id != allowed {
            return Err(Refusal::EndpointMismatch);
        }
        validate_lease(e.lease, now_ms)?;
        let correct = match policy.mode {
            Mode::TurnRelayOnly => e.kind == EndpointKind::Turn,
            Mode::OwnedServiceOnly => e.kind != EndpointKind::Turn,
            Mode::PeerIce => false,
        };
        if !correct {
            return Err(Refusal::WrongEndpointKind);
        }
        if !e.reachable || !e.payload_path_ready || e.ready_payload != payload {
            return Err(Refusal::PathUnavailable);
        }
        Some(e)
    } else {
        None
    };
    let mut a = Admission {
        scope: "modeled_pre_network_admission_only",
        mode: policy.mode,
        endpoint_kind: selected.map(|e| e.kind),
        admitted_host: 0,
        admitted_srflx: 0,
        admitted_relay: 0,
        rejected_direct: 0,
        rejected_relay: 0,
        bootstrap_required: true,
        route_provider_required: mediated,
        shared_bootstrap_route_provider: selected
            .is_some_and(|e| e.lease.provider == broker.provider),
        wire_protocol: match payload {
            Payload::DataChannel => WireProtocol::SctpOverDtls,
            Payload::Media => WireProtocol::Srtp,
        },
        video_cover_proven: false,
    };
    for offer in offers {
        match offer.kind {
            CandidateKind::Host if !mediated && policy.allow_direct => a.admitted_host += 1,
            CandidateKind::Srflx if !mediated && policy.allow_direct => a.admitted_srflx += 1,
            CandidateKind::Host | CandidateKind::Srflx => a.rejected_direct += 1,
            CandidateKind::Relay
                if policy.mode == Mode::TurnRelayOnly
                    && offer.via_endpoint == selected.map(|e| e.id) =>
            {
                a.admitted_relay += 1
            }
            CandidateKind::Relay => a.rejected_relay += 1,
        }
    }
    if policy.mode != Mode::OwnedServiceOnly
        && a.admitted_host + a.admitted_srflx + a.admitted_relay == 0
    {
        return Err(Refusal::NoCandidate);
    }
    Ok(a)
}
#[cfg(test)]
mod tests {
    use super::*;
    const OFFERS: [CandidateKind; 3] = [
        CandidateKind::Host,
        CandidateKind::Srflx,
        CandidateKind::Relay,
    ];
    fn lease() -> Lease {
        Lease {
            issued_at_ms: 0,
            expires_at_ms: 100,
            trusted: true,
            ready: true,
            provider: 7,
        }
    }
    fn endpoint(kind: EndpointKind) -> EndpointDescriptor {
        EndpointDescriptor {
            id: EndpointId(1),
            kind,
            lease: lease(),
            reachable: true,
            payload_path_ready: true,
            ready_payload: Payload::DataChannel,
        }
    }
    fn policy(mode: Mode) -> Policy {
        Policy {
            mode,
            allow_direct: false,
            allowed_endpoint: Some(EndpointId(1)),
        }
    }
    fn run(
        p: &Policy,
        e: Option<EndpointDescriptor>,
        offers: &[CandidateKind],
    ) -> Result<Admission, Refusal> {
        admit(p, lease(), e, &candidates(offers), Payload::DataChannel, 1)
    }
    fn candidates(kinds: &[CandidateKind]) -> Vec<Candidate> {
        kinds
            .iter()
            .map(|kind| Candidate {
                kind: *kind,
                via_endpoint: Some(EndpointId(1)),
            })
            .collect()
    }
    #[test]
    fn service_rejects_every_direct_offer_in_all_six_orders() {
        for (i, first) in OFFERS.iter().enumerate() {
            for (j, second) in OFFERS.iter().enumerate() {
                if i == j {
                    continue;
                }
                let k = 3 - i - j;
                let a = run(
                    &policy(Mode::OwnedServiceOnly),
                    Some(endpoint(EndpointKind::OwnedSfu)),
                    &[*first, *second, OFFERS[k]],
                )
                .unwrap();
                assert_eq!(
                    (
                        a.admitted_host,
                        a.admitted_srflx,
                        a.admitted_relay,
                        a.rejected_direct,
                        a.rejected_relay
                    ),
                    (0, 0, 0, 2, 1)
                );
            }
        }
    }
    #[test]
    fn peer_mode_requires_explicit_direct_permission() {
        let mut p = policy(Mode::PeerIce);
        assert_eq!(run(&p, None, &OFFERS), Err(Refusal::NoCandidate));
        p.allow_direct = true;
        let a = run(&p, None, &OFFERS).unwrap();
        assert_eq!(
            (a.admitted_host, a.admitted_srflx, a.rejected_relay),
            (1, 1, 1)
        );
    }
    #[test]
    fn missing_expired_untrusted_and_overlong_service_refuse() {
        let mut p = policy(Mode::OwnedServiceOnly);
        assert_eq!(run(&p, None, &OFFERS), Err(Refusal::MissingEndpoint));
        p.allowed_endpoint = None;
        assert_eq!(
            run(&p, Some(endpoint(EndpointKind::OwnedApi)), &OFFERS),
            Err(Refusal::MissingEndpoint)
        );
        p.allowed_endpoint = Some(EndpointId(2));
        assert_eq!(
            run(&p, Some(endpoint(EndpointKind::OwnedApi)), &OFFERS),
            Err(Refusal::EndpointMismatch)
        );
        for (trusted, issued, expires) in [
            (false, 0, 100),
            (true, 0, 1),
            (true, 0, 60_001),
            (true, 2, 100),
            (true, 10, 9),
        ] {
            let mut e = endpoint(EndpointKind::OwnedApi);
            e.lease.trusted = trusted;
            e.lease.issued_at_ms = issued;
            e.lease.expires_at_ms = expires;
            assert_eq!(
                run(&policy(Mode::OwnedServiceOnly), Some(e), &OFFERS),
                Err(Refusal::InvalidLease)
            );
        }
    }
    #[test]
    fn failed_broker_or_service_never_downgrades_despite_direct_offers() {
        let p = policy(Mode::OwnedServiceOnly);
        let mut e = endpoint(EndpointKind::OwnedSfu);
        e.payload_path_ready = false;
        assert_eq!(run(&p, Some(e), &OFFERS), Err(Refusal::PathUnavailable));
        e.payload_path_ready = true;
        e.reachable = false;
        assert_eq!(run(&p, Some(e), &OFFERS), Err(Refusal::PathUnavailable));
        for ready in [false, true] {
            let mut b = lease();
            b.ready = ready;
            b.expires_at_ms = if ready { 1 } else { 100 };
            assert_eq!(
                admit(
                    &p,
                    b,
                    Some(endpoint(EndpointKind::OwnedSfu)),
                    &candidates(&OFFERS),
                    Payload::Media,
                    1
                ),
                Err(Refusal::InvalidLease)
            );
        }
    }
    #[test]
    fn turn_is_distinct_and_mediated_direct_flag_cannot_override_filter() {
        let mut p = policy(Mode::TurnRelayOnly);
        p.allow_direct = true;
        let a = run(&p, Some(endpoint(EndpointKind::Turn)), &OFFERS).unwrap();
        assert_eq!((a.admitted_relay, a.rejected_direct), (1, 2));
        assert_eq!(
            run(&p, Some(endpoint(EndpointKind::OwnedSfu)), &OFFERS),
            Err(Refusal::WrongEndpointKind)
        );
        assert_eq!(
            run(
                &policy(Mode::OwnedServiceOnly),
                Some(endpoint(EndpointKind::Turn)),
                &OFFERS
            ),
            Err(Refusal::WrongEndpointKind)
        );
        let unbound = Candidate {
            kind: CandidateKind::Relay,
            via_endpoint: Some(EndpointId(2)),
        };
        assert_eq!(
            admit(
                &p,
                lease(),
                Some(endpoint(EndpointKind::Turn)),
                &[unbound],
                Payload::DataChannel,
                1
            ),
            Err(Refusal::NoCandidate)
        );
    }
    #[test]
    fn typed_parsing_bounds_redaction_dependency_and_media_distinction() {
        assert_eq!(
            serde_json::from_str::<Vec<CandidateKind>>(r#"["host","srflx","relay"]"#).unwrap(),
            OFFERS
        );
        assert!(serde_json::from_str::<CandidateKind>(r#""unknown""#).is_err());
        let p = policy(Mode::OwnedServiceOnly);
        let e = endpoint(EndpointKind::OwnedApi);
        assert_eq!(
            run(&p, Some(e), &[CandidateKind::Host; MAX_CANDIDATES + 1]),
            Err(Refusal::CandidateLimit)
        );
        let a = run(&p, Some(e), &OFFERS).unwrap();
        assert_eq!(
            admit(&p, lease(), Some(e), &[], Payload::Media, 1),
            Err(Refusal::PathUnavailable)
        );
        let mut media_endpoint = e;
        media_endpoint.ready_payload = Payload::Media;
        let m = admit(&p, lease(), Some(media_endpoint), &[], Payload::Media, 1).unwrap();
        assert_eq!(
            (a.wire_protocol, m.wire_protocol),
            (WireProtocol::SctpOverDtls, WireProtocol::Srtp)
        );
        assert!(!a.video_cover_proven && !m.video_cover_proven);
        assert!(
            a.bootstrap_required && a.route_provider_required && a.shared_bootstrap_route_provider
        );
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains("issued_at")
                && !json.contains("expires_at")
                && !json.contains("endpoint_id")
        );
    }
}
