//! Relay-only policy around the original live Geneva program.
//!
//! This layer has no socket/rule/interface I/O. It validates every output before
//! exposing any batch to a driver. Failure poisons the session; a caller must
//! close its relay socket, never retry with an untransformed image.
use aegis_geneva::{
    live::{program::Program, wire},
    packet::model::Direction,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};

pub use aegis_geneva::packet::model::Direction as RelayPacketDirection;

/// Explicit controlled backend request, never an implicit default. Endpoints
/// remain separate from the SNI and target; driver resources are bounded.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayOuterGenevaSettings {
    pub strategy: String,
    pub interface: String,
    pub local_address: Ipv4Addr,
    pub local_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
    pub outbound_queue: u16,
    pub inbound_queue: u16,
    pub socket_mark: u32,
    pub max_duration_secs: u16,
}
impl crate::Settings {
    pub fn validate_relay_outer_geneva(&self) -> Result<(), String> {
        self.validate_relay_outer_geneva_policy(cfg!(target_os = "linux"))
    }
    fn validate_relay_outer_geneva_policy(&self, platform_supported: bool) -> Result<(), String> {
        let Some(request) = &self.relay.outer_geneva else {
            return Ok(());
        };
        if !platform_supported {
            return Err("relay.outer_geneva requires Linux".into());
        }
        if !matches!(self.mode, crate::Mode::Relay)
            || self.direct.hybrid_geneva
            || self.ingress.primary != crate::IngressPrimary::Wide
            || !self.ingress.wide.enabled
            || self.ingress.allow_fallback
            || !matches!(
                self.ingress.wide.platform_backend,
                crate::WidePlatformBackend::LinuxRedirect | crate::WidePlatformBackend::LinuxTproxy
            )
        {
            return Err(
                "relay.outer_geneva requires relay-only wide ingress without fallback".into(),
            );
        }
        // A relay reply must reach its owned INPUT queue before any application
        // TPROXY interception. The existing TPROXY helper scopes PREROUTING by
        // interface; all-interface or same-link capture would intercept replies
        // first, and the addressless reinjection TUN must never be its scope.
        if self.ingress.wide.platform_backend == crate::WidePlatformBackend::LinuxTproxy
            && !self
                .ingress
                .wide
                .prerouting_interface
                .as_deref()
                .is_some_and(|capture| {
                    !capture.is_empty()
                        && capture != request.interface
                        && !capture.starts_with("agv")
                        && capture.len() <= 15
                        && capture
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
        {
            return Err(
                "relay.outer_geneva requires TPROXY capture on a separate explicit interface"
                    .into(),
            );
        }
        if self.relay.endpoints.len() >= 16 {
            return Err("relay.outer_geneva endpoint resource bound exceeded".into());
        }
        if self.relay.inner_tls.is_none()
            || self.relay.ca_cert.is_none()
            || self.relay.transport_priority != [crate::TunnelTransportFamily::GrpcStream]
            || !matches!(
                self.relay.udp_transport_priority.as_deref(),
                Some([] | [crate::TunnelTransportFamily::GrpcDatagram])
            )
        {
            return Err("relay.outer_geneva requires authenticated inner TLS over IPv4 TCP carriers; QUIC is unsupported".into());
        }
        self.relay.validate_inner_tls_transport()?;
        if request.interface.is_empty()
            || request.interface.len() > 15
            || !request
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || request.socket_mark == 0
            || request.socket_mark & self.ingress.wide.default_mark != 0
            || request.outbound_queue == request.inbound_queue
            || request.max_duration_secs == 0
            || request.max_duration_secs > 3600
            || request.local_address.is_unspecified()
            || request.local_address.is_loopback()
            || request.local_address.is_multicast()
            || request.local_address.is_broadcast()
            || [request.local_mac, request.next_hop_mac]
                .iter()
                .any(|mac| *mac == [0; 6] || mac[0] & 1 != 0)
        {
            return Err("relay.outer_geneva ownership or resource binding is invalid".into());
        }
        Program::parse(&request.strategy)
            .map_err(|_| "relay.outer_geneva strategy refused".to_string())?;
        for endpoint in std::iter::once(self.relay.server.as_str())
            .chain(self.relay.endpoints.iter().map(|e| e.server.as_str()))
        {
            let SocketAddr::V4(address) = endpoint.parse::<SocketAddr>().map_err(|_| {
                "relay.outer_geneva requires explicit IPv4 relay endpoints".to_string()
            })?
            else {
                return Err("relay.outer_geneva IPv6 relay is unsupported".into());
            };
            if address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_loopback()
                || address.ip().is_multicast()
                || address.ip().is_broadcast()
                || *address.ip() == request.local_address
            {
                return Err("relay.outer_geneva relay endpoint refused".into());
            }
        }
        Ok(())
    }
}

/// A single already registered, kernel-observed local TCP/relay tuple.
/// It contains no application destination, DNS name or authentication material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayFlowPin {
    pub local: Ipv4Addr,
    pub relay: Ipv4Addr,
    pub local_port: u16,
    pub relay_port: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayGenevaError {
    #[error("invalid relay tuple or strategy")]
    Configuration,
    #[error("packet is outside the registered relay TCP tuple")]
    Ownership,
    #[error("Geneva packet batch refused")]
    Program,
    #[error("relay Geneva session has failed closed")]
    Closed,
}

/// Complete validated ordered batch. There is no partial-result accessor.
/// An empty batch deliberately drops the queued original.
#[derive(Debug)]
pub struct RelayPacketBatch(Vec<Vec<u8>>);
impl RelayPacketBatch {
    pub fn frames(&self) -> &[Vec<u8>] {
        &self.0
    }
    pub fn into_frames(self) -> Vec<Vec<u8>> {
        self.0
    }
}

pub struct RelayGenevaProgram {
    program: Program,
    pin: RelayFlowPin,
    digest: [u8; 32],
    closed: bool,
}
impl RelayGenevaProgram {
    pub fn new(text: &str, pin: RelayFlowPin) -> Result<Self, RelayGenevaError> {
        if pin.local.is_unspecified()
            || pin.relay.is_unspecified()
            || pin.local.is_loopback()
            || pin.relay.is_loopback()
            || pin.local.is_multicast()
            || pin.relay.is_multicast()
            || pin.local.is_broadcast()
            || pin.relay.is_broadcast()
            || pin.local == pin.relay
            || pin.local_port == 0
            || pin.relay_port == 0
        {
            return Err(RelayGenevaError::Configuration);
        }
        let program = Program::parse(text).map_err(|_| RelayGenevaError::Configuration)?;
        Ok(Self {
            program,
            pin,
            digest: Sha256::digest(text.as_bytes()).into(),
            closed: false,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    pub fn close(&mut self) {
        self.closed = true;
    }
    pub fn execute<R: Rng + ?Sized>(
        &mut self,
        frame: &[u8],
        direction: Direction,
        rng: &mut R,
    ) -> Result<RelayPacketBatch, RelayGenevaError> {
        if self.closed {
            return Err(RelayGenevaError::Closed);
        }
        let result = self.execute_inner(frame, direction, rng);
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    fn execute_inner<R: Rng + ?Sized>(
        &mut self,
        frame: &[u8],
        direction: Direction,
        rng: &mut R,
    ) -> Result<RelayPacketBatch, RelayGenevaError> {
        // Only a complete original TCP datagram enters a program. Fragmented
        // inputs cannot authenticate their port and are refused by the driver.
        check_tuple(frame, self.pin, direction, false)?;
        let batch = self
            .program
            .execute(frame, direction, rng)
            .map_err(|_| RelayGenevaError::Program)?;
        let bytes = batch
            .iter()
            .try_fold(0usize, |sum, f| sum.checked_add(f.len()))
            .ok_or(RelayGenevaError::Program)?;
        if batch.len() > wire::MAX_OUTPUTS || bytes > wire::MAX_BATCH_BYTES {
            return Err(RelayGenevaError::Program);
        }
        for output in &batch {
            check_tuple(output, self.pin, direction, true)?;
        }
        Ok(RelayPacketBatch(batch))
    }
}

fn check_tuple(
    frame: &[u8],
    pin: RelayFlowPin,
    direction: Direction,
    generated: bool,
) -> Result<(), RelayGenevaError> {
    if frame.len() < 34
        || frame.len() > wire::MAX_FRAME
        || frame[12..14] != [8, 0]
        || frame[23] != 6
    {
        return Err(RelayGenevaError::Ownership);
    }
    let (src, dst, sport, dport) = match direction {
        Direction::Outbound => (pin.local, pin.relay, pin.local_port, pin.relay_port),
        Direction::Inbound => (pin.relay, pin.local, pin.relay_port, pin.local_port),
    };
    if frame[26..30] != src.octets() || frame[30..34] != dst.octets() {
        return Err(RelayGenevaError::Ownership);
    }
    // Generated explicit version/length/checksum corruption is retained. Header
    // placement still has to be representable to verify the pinned TCP ports.
    let ihl = usize::from(frame[14] & 15) * 4;
    if ihl < 20 || 14 + ihl > frame.len() {
        return Err(RelayGenevaError::Ownership);
    }
    let fragment = u16::from_be_bytes([frame[20], frame[21]]);
    if !generated && (frame[14] >> 4 != 4 || fragment & 0x3fff != 0) {
        return Err(RelayGenevaError::Ownership);
    }
    // A non-initial fragment has no ports. Its addresses/protocol are still
    // pinned; only the pure program can create it from this verified original.
    if generated && fragment & 0x1fff != 0 {
        return Ok(());
    }
    let body = frame
        .get(14 + ihl..14 + ihl + 4)
        .ok_or(RelayGenevaError::Ownership)?;
    if body[0..2] != sport.to_be_bytes() || body[2..4] != dport.to_be_bytes() {
        return Err(RelayGenevaError::Ownership);
    }
    Ok(())
}

#[cfg(test)]
#[path = "relay_geneva_dns_tests.rs"]
mod dns_trigger_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    fn pin() -> RelayFlowPin {
        RelayFlowPin {
            local: Ipv4Addr::new(192, 0, 2, 2),
            relay: Ipv4Addr::new(192, 0, 2, 3),
            local_port: 1234,
            relay_port: 443,
        }
    }
    fn frame() -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20 + 16];
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&56u16.to_be_bytes());
        f[22] = 64;
        f[23] = 6;
        f[26..30].copy_from_slice(&pin().local.octets());
        f[30..34].copy_from_slice(&pin().relay.octets());
        f[34..36].copy_from_slice(&1234u16.to_be_bytes());
        f[36..38].copy_from_slice(&443u16.to_be_bytes());
        f[46] = 0x50;
        f[47] = 0x18;
        f[54..].copy_from_slice(b"encrypted-bytes!");
        f
    }
    fn run(text: &str) -> Result<RelayPacketBatch, RelayGenevaError> {
        RelayGenevaProgram::new(text, pin()).unwrap().execute(
            &frame(),
            Direction::Outbound,
            &mut StdRng::seed_from_u64(1),
        )
    }
    #[test]
    fn actual_duplicate_identity_and_drop_preserve_order() {
        let f = frame();
        assert_eq!(
            run("[IP:ttl:64]-duplicate(,)-|").unwrap().frames(),
            &[f.clone(), f]
        );
        assert!(run("[IP:ttl:64]-drop-|").unwrap().frames().is_empty());
    }
    #[test]
    fn actual_overlap_reverse_and_ip_fragments_stay_pinned() {
        let tcp = run("[IP:ttl:64]-fragment{TCP:3:False:2}(,)-|").unwrap();
        assert_eq!(tcp.frames().len(), 2);
        assert_eq!(&tcp.frames()[0][54..], b"rypted-bytes!");
        assert_eq!(
            run("[IP:ttl:64]-fragment{IP:1:True}(,)-|")
                .unwrap()
                .frames()
                .len(),
            2
        );
    }
    #[test]
    fn whole_batch_address_or_port_escape_is_terminal() {
        for text in [
            "[IP:ttl:64]-duplicate(,tamper{IP:dst:replace:203.0.113.9}())-|",
            "[IP:ttl:64]-duplicate(,tamper{TCP:dport:replace:80}())-|",
        ] {
            let mut p = RelayGenevaProgram::new(text, pin()).unwrap();
            assert_eq!(
                p.execute(&frame(), Direction::Outbound, &mut StdRng::seed_from_u64(1))
                    .unwrap_err(),
                RelayGenevaError::Ownership
            );
            assert!(p.is_closed());
            assert_eq!(
                p.execute(&frame(), Direction::Outbound, &mut StdRng::seed_from_u64(1))
                    .unwrap_err(),
                RelayGenevaError::Closed
            );
        }
    }
    #[test]
    fn foreign_input_never_reaches_program_and_inbound_is_exact() {
        let mut p = RelayGenevaProgram::new("", pin()).unwrap();
        let mut f = frame();
        f[30..34].copy_from_slice(&[203, 0, 113, 9]);
        assert!(p
            .execute(&f, Direction::Outbound, &mut StdRng::seed_from_u64(1))
            .is_err());
        let mut p = RelayGenevaProgram::new("", pin()).unwrap();
        let mut f = frame();
        f[26..30].copy_from_slice(&pin().relay.octets());
        f[30..34].copy_from_slice(&pin().local.octets());
        f[34..36].copy_from_slice(&443u16.to_be_bytes());
        f[36..38].copy_from_slice(&1234u16.to_be_bytes());
        assert_eq!(
            p.execute(&f, Direction::Inbound, &mut StdRng::seed_from_u64(1))
                .unwrap()
                .frames(),
            &[f]
        );
    }
    #[test]
    fn explicit_bad_checksums_are_not_repaired_by_policy() {
        let out = run("[IP:ttl:64]-tamper{IP:chksum:replace:17}()-|").unwrap();
        assert_eq!(&out.frames()[0][24..26], &17u16.to_be_bytes());
        let out = run("[IP:ttl:64]-tamper{TCP:chksum:replace:19}()-|").unwrap();
        assert_eq!(&out.frames()[0][50..52], &19u16.to_be_bytes());
    }
}

pub mod installed_guard;
pub mod installed_profile;
pub mod operation_deadline;
pub mod queue;
pub mod recovery;

#[cfg(any(target_os = "linux", test))]
mod linux_policy;
pub mod stream;
pub mod teardown;
#[cfg(unix)]
pub mod teardown_storage;
pub use stream::{RelayProtectedTcp, RelaySocketGuard};

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(test)]
mod policy_tests {
    use super::*;
    fn selected() -> crate::Settings {
        let mut s = crate::Settings {
            mode: crate::Mode::Relay,
            ..Default::default()
        };
        s.ingress.allow_fallback = false;
        s.ingress.wide.enabled = true;
        s.ingress.wide.platform_backend = crate::WidePlatformBackend::LinuxRedirect;
        s.relay.server = "192.0.2.3:443".into();
        s.relay.ca_cert = Some("public-ca.pem".into());
        s.relay.transport_priority = vec![crate::TunnelTransportFamily::GrpcStream];
        s.relay.udp_transport_priority = Some(vec![crate::TunnelTransportFamily::GrpcDatagram]);
        s.relay.tls_backend = crate::RelayTlsBackend::Rustls;
        s.relay.inner_tls = Some(crate::secure_channel::ClientSettings {
            server_name: "relay.test".into(),
            server_ca: "inner-ca.pem".into(),
            cert: "identity.pem".into(),
            key: "identity.key".into(),
        });
        s.relay.outer_geneva = Some(RelayOuterGenevaSettings {
            strategy: "[IP:ttl:64]-duplicate(,)-|".into(),
            interface: "eth0".into(),
            local_address: Ipv4Addr::new(192, 0, 2, 2),
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            outbound_queue: 414,
            inbound_queue: 415,
            socket_mark: 0xae9,
            max_duration_secs: 900,
        });
        s
    }
    #[test]
    fn absence_preserves_existing_profile_and_platform_refusal_is_early() {
        crate::Settings::default()
            .validate_relay_outer_geneva()
            .unwrap();
        selected().validate_relay_outer_geneva_policy(true).unwrap();
        assert!(selected()
            .validate_relay_outer_geneva_policy(false)
            .is_err());
    }
    #[test]
    fn no_direct_auto_fallback_plaintext_quic_or_ipv6_selected() {
        let base = selected();
        for mode in [crate::Mode::Direct, crate::Mode::Auto] {
            let mut s = base.clone();
            s.mode = mode;
            assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        }
        for backend in [
            crate::WidePlatformBackend::Auto,
            crate::WidePlatformBackend::LinuxNfqueueObserver,
        ] {
            let mut s = base.clone();
            s.ingress.wide.platform_backend = backend;
            assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        }
        let mut s = base.clone();
        s.ingress.allow_fallback = true;
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.inner_tls = None;
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.transport_priority = vec![crate::TunnelTransportFamily::MasqueDerived];
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.udp_transport_priority = Some(vec![crate::TunnelTransportFamily::MasqueDerived]);
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.server = "[::1]:443".into();
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.server = "lookup.example:443".into();
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base;
        s.direct.hybrid_geneva = true;
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
    }
    #[test]
    fn tproxy_scope_cannot_recapture_relay_replies_or_reinjection() {
        let mut s = selected();
        s.ingress.wide.platform_backend = crate::WidePlatformBackend::LinuxTproxy;
        for capture in [None, Some("eth0"), Some("agv12345678"), Some("../lan0")] {
            s.ingress.wide.prerouting_interface = capture.map(str::to_owned);
            assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        }
        s.ingress.wide.prerouting_interface = Some("lan0".into());
        assert!(s.validate_relay_outer_geneva_policy(true).is_ok());
        s.relay.server = "127.0.0.1:443".into();
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
    }
    #[test]
    fn ownership_and_resource_inputs_are_typed_bounded_and_not_shell_fragments() {
        let base = selected();
        for name in ["", "eth0;touch /tmp/x", "../eth0", "overlong-interface"] {
            let mut s = base.clone();
            s.relay.outer_geneva.as_mut().unwrap().interface = name.into();
            assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        }
        let mut overlap = base.clone();
        overlap.ingress.wide.default_mark = 1;
        assert!(overlap.validate_relay_outer_geneva_policy(true).is_err());
        overlap.relay.outer_geneva.as_mut().unwrap().socket_mark = 2;
        assert!(overlap.validate_relay_outer_geneva_policy(true).is_ok());
        let mut s = base.clone();
        s.relay.outer_geneva.as_mut().unwrap().socket_mark = 0;
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.outer_geneva.as_mut().unwrap().max_duration_secs = 3601;
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base.clone();
        s.relay.outer_geneva.as_mut().unwrap().inbound_queue = 414;
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
        let mut s = base;
        s.relay.outer_geneva.as_mut().unwrap().strategy = "[IP:ttl:64]-exec{arbitrary}()-|".into();
        assert!(s.validate_relay_outer_geneva_policy(true).is_err());
    }
}
