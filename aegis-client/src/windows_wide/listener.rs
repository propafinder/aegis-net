use crate::windows_wide::{events, original_dst, session::WindowsWideSessionTarget};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

pub(crate) struct WindowsWideAcceptedFlow {
    pub(crate) client: TcpStream,
    pub(crate) peer: SocketAddr,
    pub(crate) session_target: WindowsWideSessionTarget,
}

pub(crate) struct WindowsWideListener {
    listener: TcpListener,
    controlled_target: Option<SocketAddr>,
    controlled_target_host: Option<String>,
}

impl WindowsWideListener {
    pub(crate) async fn bind(
        listen: SocketAddr,
        controlled_target: Option<SocketAddr>,
        controlled_target_host: Option<String>,
    ) -> io::Result<Self> {
        if controlled_target_host.is_some() && controlled_target.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controlled_tcp_target_host requires one explicit controlled_tcp_target",
            ));
        }
        if let Some(host) = controlled_target_host.as_deref() {
            if host.len() > 253
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid controlled target hostname",
                ));
            }
        }
        if let Some(controlled_target) = controlled_target {
            if !controlled_target.is_ipv4() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Windows WFP ALE controlled TCP proof requires an IPv4 target, got {controlled_target}"
                    ),
                ));
            }
        }
        if !listen.is_ipv4() || !listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Windows WFP ALE listener must bind loopback, got {listen}"),
            ));
        }
        let listener = TcpListener::bind(listen).await?;
        let actual_listen = listener.local_addr()?;
        events::backend_started(actual_listen);
        Ok(Self {
            listener,
            controlled_target,
            controlled_target_host,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) async fn accept(&self) -> io::Result<WindowsWideAcceptedFlow> {
        let (client, peer) = self.listener.accept().await?;
        let redirected_to = self.local_addr()?;
        events::flow_accepted(peer, redirected_to);
        let original_dst = match original_dst::query_wfp_redirect_context(&client) {
            Ok(original_dst) => original_dst,
            Err(err) => {
                events::original_dst_dynamic_lookup_failed(&err);
                match self.controlled_target {
                    Some(controlled_target) => {
                        original_dst::configured_controlled_target(controlled_target)
                    }
                    None => return Err(err),
                }
            }
        };
        events::original_dst_resolved(original_dst.addr, original_dst.method.as_str());
        // An explicit hostname belongs to one tuple only. Never rewrite other
        // destinations recovered from a multi-target WFP filter set.
        let host_override = self
            .controlled_target_host
            .clone()
            .filter(|_| self.controlled_target == Some(original_dst.addr));
        Ok(WindowsWideAcceptedFlow {
            client,
            peer,
            session_target: WindowsWideSessionTarget::from_original_dst(
                original_dst,
                host_override,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn hostname_override_requires_one_tuple_and_valid_dns_name() {
        let listen = "127.0.0.1:0".parse().unwrap();
        assert!(
            WindowsWideListener::bind(listen, None, Some("example.test".into()))
                .await
                .is_err()
        );
        let target = Some("203.0.113.1:443".parse().unwrap());
        for host in ["", "a b", "https://example.test", "-bad.test", "bad..test"] {
            assert!(WindowsWideListener::bind(listen, target, Some(host.into()))
                .await
                .is_err());
        }
    }
    #[tokio::test]
    async fn dynamic_listener_rejects_nonredirected_connections() {
        let listener = WindowsWideListener::bind("127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        let _stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        assert!(listener.accept().await.is_err());
    }
    #[tokio::test]
    async fn controlled_proof_fallback_keeps_explicit_hostname() {
        let listener = WindowsWideListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            Some("203.0.113.1:443".parse().unwrap()),
            Some("example.test".into()),
        )
        .await
        .unwrap();
        let _stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let flow = listener.accept().await.unwrap();
        assert_eq!(flow.session_target.target.host, "example.test");
        assert_eq!(flow.session_target.target.port, 443);
    }
}
