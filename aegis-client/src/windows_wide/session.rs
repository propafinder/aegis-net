use crate::socks5::ConnectTarget;
use crate::windows_wide::original_dst::OriginalDestination;

#[derive(Debug, Clone)]
pub(crate) struct WindowsWideSessionTarget {
    pub(crate) target: ConnectTarget,
    pub(crate) original_dst: OriginalDestination,
}

impl WindowsWideSessionTarget {
    pub(crate) fn from_original_dst(
        original_dst: OriginalDestination,
        controlled_target_host: Option<String>,
    ) -> Self {
        Self {
            target: ConnectTarget {
                host: controlled_target_host.unwrap_or_else(|| original_dst.addr.ip().to_string()),
                port: original_dst.addr.port(),
            },
            original_dst,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_wide::original_dst::{OriginalDestination, OriginalDestinationMethod};

    #[test]
    fn session_target_defaults_to_original_destination_ip() {
        let original_dst = OriginalDestination {
            addr: "203.0.113.10:443".parse().expect("addr"),
            method: OriginalDestinationMethod::WfpRedirectContext,
        };
        let target = WindowsWideSessionTarget::from_original_dst(original_dst, None);
        assert_eq!(target.target.host, "203.0.113.10");
        assert_eq!(target.target.port, 443);
    }

    #[test]
    fn session_target_uses_explicit_controlled_hostname_override() {
        let original_dst = OriginalDestination {
            addr: "203.0.113.10:443".parse().expect("addr"),
            method: OriginalDestinationMethod::WfpRedirectContext,
        };
        let target = WindowsWideSessionTarget::from_original_dst(
            original_dst,
            Some("api.ipify.org".to_string()),
        );
        assert_eq!(target.target.host, "api.ipify.org");
        assert_eq!(target.target.port, 443);
        assert_eq!(target.original_dst.addr, original_dst.addr);
    }
}
