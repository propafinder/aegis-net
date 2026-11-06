use crate::{Error, Result};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use webrtc::peer_connection::{
    RTCIceCandidate, RTCIceCandidateType, RTCIceServer, RTCIceTransportPolicy,
};
use zeroize::Zeroizing;

/// Explicit, numeric TURN endpoint. No discovery, DNS, implicit public servers
/// or automatic fallback to direct candidates is performed by this crate.
pub struct TurnServer {
    endpoint: SocketAddr,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl TurnServer {
    pub fn udp(endpoint: SocketAddr, username: String, password: String) -> Result<Self> {
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
            || username.is_empty()
            || username.len() > 256
            || password.is_empty()
            || password.len() > 256
            || username.chars().any(char::is_control)
            || password.chars().any(char::is_control)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            endpoint,
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
        })
    }

    pub(crate) fn rtc(&self) -> RTCIceServer {
        RTCIceServer {
            urls: vec![format!("turn:{}?transport=udp", self.endpoint)],
            username: self.username.to_string(),
            credential: self.password.to_string(),
        }
    }
}

impl fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TurnServer([redacted])")
    }
}

/// A direct intermediary is an explicit privacy tradeoff. RelayOnly never
/// falls back to host/srflx candidates, including on TURN outage.
#[derive(Debug)]
pub enum IcePolicy {
    Loopback,
    DirectIntermediary {
        allowed_peer_ips: Vec<IpAddr>,
    },
    RelayOnly {
        servers: Vec<TurnServer>,
        allowed_relay_ips: Vec<IpAddr>,
    },
    /// A media-call adapter has a different wire contract. Refuse it before
    /// creating a socket rather than substitute P2P or TURN DataChannels.
    SfuMedia,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEvidence {
    pub local_type: &'static str,
    pub remote_type: &'static str,
    pub relay_only: bool,
    pub nominated_pair_checked: bool,
    pub peer_address_allowed: bool,
    pub media_session_verified: bool,
}

fn kind(candidate: &RTCIceCandidate) -> &'static str {
    match candidate.typ {
        RTCIceCandidateType::Host => "host",
        RTCIceCandidateType::Srflx => "srflx",
        RTCIceCandidateType::Prflx => "prflx",
        RTCIceCandidateType::Relay => "relay",
        _ => "unknown",
    }
}

impl IcePolicy {
    pub(crate) fn validate(&self, bind: SocketAddr) -> Result<()> {
        if bind.ip().is_multicast() || bind.ip().is_unspecified() {
            return Err(Error::Configuration);
        }
        match self {
            Self::SfuMedia => Err(Error::UnsupportedSfu),
            Self::Loopback if !bind.ip().is_loopback() => Err(Error::Configuration),
            Self::Loopback => Ok(()),
            Self::DirectIntermediary { allowed_peer_ips } => check_ips(allowed_peer_ips),
            Self::RelayOnly {
                servers,
                allowed_relay_ips,
            } => {
                if servers.is_empty() || servers.len() > 4 {
                    return Err(Error::Configuration);
                }
                check_ips(allowed_relay_ips)
            }
        }
    }

    pub(crate) fn rtc(&self) -> (RTCIceTransportPolicy, Vec<RTCIceServer>) {
        match self {
            Self::RelayOnly { servers, .. } => (
                RTCIceTransportPolicy::Relay,
                servers.iter().map(TurnServer::rtc).collect(),
            ),
            _ => (RTCIceTransportPolicy::All, vec![]),
        }
    }

    /// Reject candidate disclosure/dials before applying remote SDP. This is a
    /// strict native-Rust contract: numeric UDP candidates only, at most 16.
    pub(crate) fn check_sdp(&self, sdp: &str) -> Result<()> {
        let mut count = 0;
        for line in sdp.lines().filter(|line| line.starts_with("a=candidate:")) {
            count += 1;
            if count > 16 {
                return Err(Error::Path);
            }
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.len() < 8 || !fields[2].eq_ignore_ascii_case("udp") || fields[6] != "typ" {
                return Err(Error::Path);
            }
            let ip: IpAddr = fields[4].parse().map_err(|_| Error::Path)?;
            let port: u16 = fields[5].parse().map_err(|_| Error::Path)?;
            if port == 0 {
                return Err(Error::Path);
            }
            let allowed = match self {
                Self::Loopback => ip.is_loopback(),
                Self::DirectIntermediary { allowed_peer_ips } => allowed_peer_ips.contains(&ip),
                Self::RelayOnly {
                    allowed_relay_ips, ..
                } => fields[7] == "relay" && allowed_relay_ips.contains(&ip),
                Self::SfuMedia => false,
            };
            if !allowed {
                return Err(Error::Path);
            }
        }
        if count == 0 {
            return Err(Error::Path);
        }
        Ok(())
    }

    pub(crate) fn check_local_sdp(&self, sdp: &str, bind: SocketAddr) -> Result<()> {
        match self {
            Self::DirectIntermediary { .. } => Self::DirectIntermediary {
                allowed_peer_ips: vec![bind.ip()],
            }
            .check_sdp(sdp),
            _ => self.check_sdp(sdp),
        }
    }

    pub(crate) fn selected(
        &self,
        local: &RTCIceCandidate,
        remote: &RTCIceCandidate,
        bind: SocketAddr,
    ) -> Result<PathEvidence> {
        let local_ip: IpAddr = local.address.parse().map_err(|_| Error::Path)?;
        let remote_ip: IpAddr = remote.address.parse().map_err(|_| Error::Path)?;
        let relay_only = matches!(self, Self::RelayOnly { .. });
        let allowed = match self {
            Self::Loopback => local_ip.is_loopback() && remote_ip.is_loopback(),
            Self::DirectIntermediary { allowed_peer_ips } => {
                local_ip == bind.ip() && allowed_peer_ips.contains(&remote_ip)
            }
            Self::RelayOnly {
                allowed_relay_ips, ..
            } => {
                local.typ == RTCIceCandidateType::Relay
                    && remote.typ == RTCIceCandidateType::Relay
                    && allowed_relay_ips.contains(&local_ip)
                    && allowed_relay_ips.contains(&remote_ip)
            }
            Self::SfuMedia => return Err(Error::UnsupportedSfu),
        };
        if !allowed {
            return Err(Error::Path);
        }
        Ok(PathEvidence {
            local_type: kind(local),
            remote_type: kind(remote),
            relay_only,
            nominated_pair_checked: true,
            peer_address_allowed: true,
            media_session_verified: false,
        })
    }
}

fn check_ips(ips: &[IpAddr]) -> Result<()> {
    if ips.is_empty()
        || ips.len() > 16
        || ips
            .iter()
            .any(|ip| ip.is_unspecified() || ip.is_multicast())
    {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
