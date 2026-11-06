use std::net::SocketAddr;

#[derive(Debug, Clone, Copy)]
pub(crate) enum OriginalDestinationMethod {
    ConfiguredControlledTarget,
    WfpRedirectContext,
}

impl OriginalDestinationMethod {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ConfiguredControlledTarget => "configured_controlled_target",
            Self::WfpRedirectContext => "wfp_redirect_context",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OriginalDestination {
    pub(crate) addr: SocketAddr,
    pub(crate) method: OriginalDestinationMethod,
}

pub(crate) fn configured_controlled_target(addr: SocketAddr) -> OriginalDestination {
    OriginalDestination {
        addr,
        method: OriginalDestinationMethod::ConfiguredControlledTarget,
    }
}

#[cfg(windows)]
pub(crate) fn query_wfp_redirect_context(
    stream: &tokio::net::TcpStream,
) -> std::io::Result<OriginalDestination> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKADDR_STORAGE,
        SOCKET_ERROR,
    };

    let socket = stream.as_raw_socket() as usize;
    let mut context = vec![0u8; size_of::<SOCKADDR_STORAGE>() * 2];
    let mut bytes_returned = 0u32;
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            std::ptr::null(),
            0,
            context.as_mut_ptr().cast(),
            context.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }

    if bytes_returned as usize > context.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WFP context length exceeds buffer",
        ));
    }

    parse_ipv4_sockaddr(&context[..bytes_returned as usize]).map(|addr| OriginalDestination {
        addr,
        method: OriginalDestinationMethod::WfpRedirectContext,
    })
}

#[cfg(windows)]
fn parse_ipv4_sockaddr(bytes: &[u8]) -> std::io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    if bytes.len() < 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("WFP redirect context too small: {} bytes", bytes.len()),
        ));
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != AF_INET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("WFP redirect context family is {family}, expected AF_INET"),
        ));
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    if port == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_loopback()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WFP context destination rejected",
        ));
    }
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr_from_wfp_context() {
        let bytes = [2, 0, 0, 80, 198, 51, 100, 63, 0, 0, 0, 0, 0, 0, 0, 0];
        let parsed = parse_ipv4_sockaddr(&bytes).expect("parse");
        assert_eq!(
            parsed,
            "198.51.100.63:80".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn rejects_truncated_wrong_family_and_zero_port_context() {
        assert!(parse_ipv4_sockaddr(&[2, 0, 0, 80, 1, 1, 1, 1]).is_err());
        assert!(parse_ipv4_sockaddr(&[0; 16]).is_err());
        let mut bytes = [0; 16];
        bytes[0] = 2;
        bytes[4..8].copy_from_slice(&[203, 0, 113, 1]);
        assert!(parse_ipv4_sockaddr(&bytes).is_err());
    }
}
