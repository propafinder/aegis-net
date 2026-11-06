use crate::ingress::{
    IngressBackend, IngressBackendRuntimeStatus, IngressKind, IngressResponse,
    IngressSessionIntent, IngressTransport, TcpConnectIntent,
};
use crate::windows_wide::listener::WindowsWideListener;
use aegis_core::{WideIngressSettings, WidePlatformBackend};
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;

pub struct WindowsWidePrimaryBackend {
    listener: WindowsWideListener,
    settings: WideIngressSettings,
}

impl WindowsWidePrimaryBackend {
    pub async fn bind(settings: WideIngressSettings) -> io::Result<Self> {
        if !Self::supports_platform(&settings) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Windows WFP ALE controlled TCP listener requires enabled backend=windows_wfp_ale (backend={:?}, listen={})",
                    settings.platform_backend, settings.listen
                ),
            ));
        }
        let controlled_target = settings.controlled_tcp_target;
        let controlled_target_host = settings.controlled_tcp_target_host.clone();
        let listener =
            WindowsWideListener::bind(settings.listen, controlled_target, controlled_target_host)
                .await?;
        let mut settings = settings;
        settings.listen = listener.local_addr()?;
        tracing::info!(
            backend = "wide_primary_windows_wfp_ale",
            listen = %settings.listen,
            controlled_target = ?controlled_target,
            controlled_target_host = ?settings.controlled_tcp_target_host,
            "Windows WFP ALE controlled TCP listener started"
        );
        Ok(Self { listener, settings })
    }

    pub fn supports_platform(settings: &WideIngressSettings) -> bool {
        if !settings.enabled {
            return false;
        }
        matches!(
            settings.platform_backend,
            WidePlatformBackend::WindowsWfpAle
        )
    }
}

#[async_trait]
impl IngressBackend for WindowsWidePrimaryBackend {
    fn id(&self) -> &'static str {
        "wide_primary_windows"
    }

    fn kind(&self) -> IngressKind {
        IngressKind::WidePrimary
    }

    fn is_available(&self) -> bool {
        Self::supports_platform(&self.settings)
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        Some(self.settings.listen)
    }

    fn runtime_status(&self) -> IngressBackendRuntimeStatus {
        IngressBackendRuntimeStatus {
            wide_backend_current_stage: Some("windows_wfp_controlled_tcp_listener"),
            wide_backend_scope_target: Some("controlled_ipv4_tcp_only"),
            wide_backend_reason_code: Some("wfp_redirect_context_preferred"),
            ..IngressBackendRuntimeStatus::default()
        }
    }

    async fn accept(&self) -> io::Result<IngressSessionIntent> {
        let flow = self.listener.accept().await?;
        let target = flow.session_target.target;
        tracing::info!(
            backend = "wide_primary_windows_wfp_ale",
            peer = %flow.peer,
            target_host = %target.host,
            target_port = target.port,
            original_dst_method = %flow.session_target.original_dst.method.as_str(),
            listen = %self.settings.listen,
            "Windows WFP ALE controlled TCP accepted redirected stream"
        );
        Ok(IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: flow.peer,
            transport: IngressTransport::TcpConnect(TcpConnectIntent {
                client: flow.client,
                target,
                response: IngressResponse::None,
                target_lease: None,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::WidePlatformBackend;

    #[test]
    fn windows_backend_is_not_reported_supported_until_adapter_exists() {
        let settings = WideIngressSettings::default();
        assert!(!WindowsWidePrimaryBackend::supports_platform(&settings));
    }

    #[test]
    fn windows_backend_still_rejects_explicit_backend_mode_without_adapter() {
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::Windivert,
            ..WideIngressSettings::default()
        };
        assert!(!WindowsWidePrimaryBackend::supports_platform(&settings));
    }

    #[test]
    fn windows_wfp_mvp_backend_supports_dynamic_original_dst_mode() {
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::WindowsWfpAle,
            ..WideIngressSettings::default()
        };
        assert!(WindowsWidePrimaryBackend::supports_platform(&settings));
    }

    #[test]
    fn windows_wfp_mvp_backend_requires_explicit_controlled_target() {
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::WindowsWfpAle,
            controlled_tcp_target: Some("93.184.216.34:80".parse().expect("target")),
            ..WideIngressSettings::default()
        };
        assert!(WindowsWidePrimaryBackend::supports_platform(&settings));
    }
}
