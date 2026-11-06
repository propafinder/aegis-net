//! Addressing a single header field, e.g. `TCP:flags` or `IP:ttl`.
//!
//! Geneva strategies name fields as `PROTO:field`, both in triggers (match on
//! a field's value) and in `tamper` actions (overwrite one). Keeping the
//! addressing in its own module means the set of reachable fields is one
//! reviewable list rather than string matching scattered across the engine.

use crate::error::{Error, Result};

/// The protocol layer a field lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Ip,
    Tcp,
    Udp,
}

impl Proto {
    pub fn parse(text: &str) -> Result<Self> {
        match text.to_ascii_uppercase().as_str() {
            "IP" => Ok(Proto::Ip),
            "TCP" => Ok(Proto::Tcp),
            "UDP" => Ok(Proto::Udp),
            other => Err(Error::Syntax(format!("unknown protocol {other}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Ip => "IP",
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

/// A field within a protocol header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    // IP
    Ttl,
    IpFlags,
    IpId,
    IpChecksum,
    // TCP
    TcpFlags,
    Seq,
    Ack,
    Window,
    TcpChecksum,
    DataOffset,
    IpVersion,
    IpIhl,
    IpTos,
    IpLength,
    IpFragment,
    IpProtocol,
    IpSource,
    IpDestination,
    TcpSource,
    TcpDestination,
    TcpReserved,
    TcpUrgent,
    UdpSource,
    UdpDestination,
    UdpLength,
    UdpChecksum,
}

impl Field {
    pub fn proto(self) -> Proto {
        match self {
            Field::Ttl | Field::IpFlags | Field::IpId | Field::IpChecksum => Proto::Ip,
            Field::IpVersion => Proto::Ip,
            Field::IpIhl => Proto::Ip,
            Field::IpTos => Proto::Ip,
            Field::IpLength => Proto::Ip,
            Field::IpFragment => Proto::Ip,
            Field::IpProtocol => Proto::Ip,
            Field::IpSource => Proto::Ip,
            Field::IpDestination => Proto::Ip,
            Field::TcpSource => Proto::Tcp,
            Field::TcpDestination => Proto::Tcp,
            Field::TcpReserved => Proto::Tcp,
            Field::TcpUrgent => Proto::Tcp,
            Field::UdpSource => Proto::Udp,
            Field::UdpDestination => Proto::Udp,
            Field::UdpLength => Proto::Udp,
            Field::UdpChecksum => Proto::Udp,
            _ => Proto::Tcp,
        }
    }

    pub fn parse(proto: Proto, name: &str) -> Result<Self> {
        let lower = name.to_ascii_lowercase();
        let field = match (proto, lower.as_str()) {
            (Proto::Ip, "ttl") => Field::Ttl,
            (Proto::Ip, "flags") => Field::IpFlags,
            (Proto::Ip, "id") => Field::IpId,
            (Proto::Ip, "chksum") | (Proto::Ip, "checksum") => Field::IpChecksum,
            (Proto::Tcp, "flags") => Field::TcpFlags,
            (Proto::Tcp, "seq") => Field::Seq,
            (Proto::Tcp, "ack") => Field::Ack,
            (Proto::Tcp, "window") => Field::Window,
            (Proto::Tcp, "chksum") | (Proto::Tcp, "checksum") => Field::TcpChecksum,
            (Proto::Tcp, "dataofs") | (Proto::Tcp, "offset") => Field::DataOffset,
            (Proto::Ip, "version") => Field::IpVersion,
            (Proto::Ip, "ihl") => Field::IpIhl,
            (Proto::Ip, "tos") => Field::IpTos,
            (Proto::Ip, "len") => Field::IpLength,
            (Proto::Ip, "frag") => Field::IpFragment,
            (Proto::Ip, "proto") => Field::IpProtocol,
            (Proto::Ip, "src") => Field::IpSource,
            (Proto::Ip, "dst") => Field::IpDestination,
            (Proto::Tcp, "sport") => Field::TcpSource,
            (Proto::Tcp, "dport") => Field::TcpDestination,
            (Proto::Tcp, "reserved") => Field::TcpReserved,
            (Proto::Tcp, "urgptr") => Field::TcpUrgent,
            (Proto::Udp, "sport") => Field::UdpSource,
            (Proto::Udp, "dport") => Field::UdpDestination,
            (Proto::Udp, "len") => Field::UdpLength,
            (Proto::Udp, "chksum") => Field::UdpChecksum,
            _ => {
                return Err(Error::UnknownField {
                    proto: proto.as_str().to_string(),
                    field: name.to_string(),
                })
            }
        };
        Ok(field)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Field::Ttl => "ttl",
            Field::IpFlags => "flags",
            Field::IpId => "id",
            Field::IpChecksum => "chksum",
            Field::TcpFlags => "flags",
            Field::Seq => "seq",
            Field::Ack => "ack",
            Field::Window => "window",
            Field::TcpChecksum => "chksum",
            Field::DataOffset => "dataofs",
            Field::IpVersion => "version",
            Field::IpIhl => "ihl",
            Field::IpTos => "tos",
            Field::IpLength => "len",
            Field::IpFragment => "frag",
            Field::IpProtocol => "proto",
            Field::IpSource => "src",
            Field::IpDestination => "dst",
            Field::TcpSource => "sport",
            Field::TcpDestination => "dport",
            Field::TcpReserved => "reserved",
            Field::TcpUrgent => "urgptr",
            Field::UdpSource => "sport",
            Field::UdpDestination => "dport",
            Field::UdpLength => "len",
            Field::UdpChecksum => "chksum",
        }
    }

    /// Wire width of extended numeric fields. Absent layers remain absent.
    pub fn wire_mask(self) -> Option<u32> {
        match self {
            Field::IpVersion => Some(15),
            Field::IpIhl => Some(15),
            Field::IpTos => Some(255),
            Field::IpLength => Some(65535),
            Field::IpFragment => Some(8191),
            Field::IpProtocol => Some(255),
            Field::IpSource => Some(4294967295),
            Field::IpDestination => Some(4294967295),
            Field::TcpSource => Some(65535),
            Field::TcpDestination => Some(65535),
            Field::TcpReserved => Some(7),
            Field::TcpUrgent => Some(65535),
            Field::UdpSource => Some(65535),
            Field::UdpDestination => Some(65535),
            Field::UdpLength => Some(65535),
            Field::UdpChecksum => Some(65535),
            _ => None,
        }
    }

    /// Every field the historical offline mutation may pick from.
    pub const ALL: &'static [Field] = &[
        Field::Ttl,
        Field::IpFlags,
        Field::IpId,
        Field::IpChecksum,
        Field::TcpFlags,
        Field::Seq,
        Field::Ack,
        Field::Window,
        Field::TcpChecksum,
        Field::DataOffset,
    ];
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.proto().as_str(), self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_qualified_names() {
        assert_eq!(Field::parse(Proto::Tcp, "flags").unwrap(), Field::TcpFlags);
        assert_eq!(Field::parse(Proto::Ip, "flags").unwrap(), Field::IpFlags);
        assert_eq!(Field::parse(Proto::Ip, "TTL").unwrap(), Field::Ttl);
    }

    #[test]
    fn same_name_in_two_layers_stays_distinct() {
        assert_ne!(
            Field::parse(Proto::Ip, "flags").unwrap(),
            Field::parse(Proto::Tcp, "flags").unwrap()
        );
    }

    #[test]
    fn rejects_unknown_field_and_proto() {
        assert!(Field::parse(Proto::Tcp, "nonesuch").is_err());
        assert_eq!(Proto::parse("UDP").unwrap(), Proto::Udp);
        assert!(Proto::parse("DNS").is_err());
    }

    #[test]
    fn display_round_trips_through_parse() {
        for field in Field::ALL {
            let text = field.to_string();
            let (proto, name) = text.split_once(':').unwrap();
            let parsed = Field::parse(Proto::parse(proto).unwrap(), name).unwrap();
            assert_eq!(parsed, *field, "{text}");
        }
    }

    #[test]
    fn every_field_reports_its_own_layer() {
        assert_eq!(Field::Ttl.proto(), Proto::Ip);
        assert_eq!(Field::Seq.proto(), Proto::Tcp);
    }
}
