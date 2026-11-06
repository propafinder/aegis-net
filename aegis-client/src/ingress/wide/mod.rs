#[cfg(any(target_os = "linux", all(test, unix)))]
mod ancillary;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod forward_gate;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub(crate) mod macos_utun;
#[cfg(target_os = "windows")]
mod windows;

// The Linux socket listener uses the shared fake-IP allocator/parser. Other
// packet backends use packet_engine::dns directly; resolver tests keep this
// listener module available on every test host.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod dns_preview;
#[cfg(any(target_os = "macos", windows))]
pub(crate) mod ip_tunnel;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) mod linux_nfqueue;
#[cfg(target_os = "linux")]
pub(crate) mod nfqueue_lifecycle;
#[cfg(target_os = "linux")]
pub(crate) mod nfqueue_proto;
#[cfg(target_os = "linux")]
pub(crate) mod nfqueue_socket;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) mod packet_engine_services;
#[cfg(any(target_os = "linux", test))]
mod tcp_stream_pump;
#[cfg(target_os = "linux")]
pub(crate) mod tun_route_policy;
#[cfg(target_os = "linux")]
pub(crate) mod tun_smoltcp;
#[cfg(target_os = "linux")]
pub(crate) mod tun_smoltcp_adapter;
#[cfg(target_os = "linux")]
pub(crate) mod tun_smoltcp_engine;
#[cfg(any(target_os = "linux", test))]
mod udp_conntrack;
#[cfg(any(target_os = "linux", test))]
mod udp_conntrack_lookup;
#[cfg(target_os = "linux")]
pub(crate) mod udp_masque_bridge;
#[cfg(target_os = "linux")]
pub(crate) mod udp_redirect_proxy;

use super::{IngressBackend, IngressBackendRuntimeStatus, IngressKind, IngressSessionIntent};
use aegis_core::{RelaySettings, WideIngressSettings};
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use linux::LinuxWidePrimaryBackend;
#[cfg(target_os = "macos")]
use macos::MacosWidePrimaryBackend;
#[cfg(target_os = "windows")]
use windows::WindowsWidePrimaryBackend;

pub struct WidePrimaryBackend {
    settings: WideIngressSettings,
    #[cfg(target_os = "linux")]
    linux: Option<LinuxWidePrimaryBackend>,
    #[cfg(target_os = "macos")]
    macos: Option<MacosWidePrimaryBackend>,
    #[cfg(target_os = "windows")]
    windows: Option<WindowsWidePrimaryBackend>,
}

impl WidePrimaryBackend {
    #[cfg(target_os = "linux")]
    pub(crate) fn fake_ip_map(&self) -> Option<std::sync::Arc<dns_preview::FakeIpMap>> {
        self.linux
            .as_ref()
            .and_then(LinuxWidePrimaryBackend::fake_ip_map)
    }

    #[cfg(test)]
    pub async fn bind(settings: WideIngressSettings) -> io::Result<Self> {
        Self::bind_with_relay(settings, None).await
    }

    pub async fn bind_with_relay(
        settings: WideIngressSettings,
        relay: Option<RelaySettings>,
    ) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        let _ = &relay;
        if !Self::supports_platform(&settings) {
            return Err(unsupported_bind_error(&settings));
        }
        #[cfg(target_os = "linux")]
        {
            Self::bind_with_relay_gated(settings, relay, None).await
        }

        #[cfg(target_os = "macos")]
        {
            let macos = MacosWidePrimaryBackend::bind(settings.clone()).await?;
            let mut settings = settings;
            settings.listen = macos.listen_addr();
            Ok(Self {
                settings,
                macos: Some(macos),
            })
        }

        #[cfg(target_os = "windows")]
        {
            let windows = Some(WindowsWidePrimaryBackend::bind(settings.clone()).await?);
            Ok(Self { settings, windows })
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(unsupported_bind_error(&settings))
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn bind_with_relay_gated(
        settings: WideIngressSettings,
        relay: Option<RelaySettings>,
        gate: Option<forward_gate::ForwardGate>,
    ) -> io::Result<Self> {
        if !Self::supports_platform(&settings) {
            return Err(unsupported_bind_error(&settings));
        }
        let linux =
            LinuxWidePrimaryBackend::bind_with_relay_gated(settings.clone(), relay, gate).await?;
        let mut settings = settings;
        settings.listen = linux.listen_addr();
        Ok(Self {
            settings,
            linux: Some(linux),
        })
    }

    pub fn supports_platform(settings: &WideIngressSettings) -> bool {
        if !settings.enabled {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            LinuxWidePrimaryBackend::supports_platform(settings)
        }

        #[cfg(target_os = "macos")]
        {
            MacosWidePrimaryBackend::supports_platform(settings)
        }

        #[cfg(target_os = "windows")]
        {
            WindowsWidePrimaryBackend::supports_platform(settings)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    pub fn supports_platform_family(settings: &WideIngressSettings) -> bool {
        if !settings.enabled {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            matches!(
                settings.platform_backend,
                aegis_core::WidePlatformBackend::Auto
                    | aegis_core::WidePlatformBackend::LinuxRedirect
                    | aegis_core::WidePlatformBackend::LinuxTproxy
                    | aegis_core::WidePlatformBackend::LinuxNfqueueObserver
            )
        }

        #[cfg(target_os = "macos")]
        {
            matches!(
                settings.platform_backend,
                aegis_core::WidePlatformBackend::Auto | aegis_core::WidePlatformBackend::MacosPf
            )
        }

        #[cfg(target_os = "windows")]
        {
            matches!(
                settings.platform_backend,
                aegis_core::WidePlatformBackend::Auto
                    | aegis_core::WidePlatformBackend::Windivert
                    | aegis_core::WidePlatformBackend::WindowsWfpAle
            )
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }
}

fn unsupported_bind_error(settings: &WideIngressSettings) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "wide ingress backend is not implemented for this platform yet (backend={:?}, listen={})",
            settings.platform_backend, settings.listen
        ),
    )
}

#[async_trait]
impl IngressBackend for WidePrimaryBackend {
    async fn failure(&self) -> &'static str {
        #[cfg(target_os = "linux")]
        if let Some(linux) = &self.linux {
            return linux.failure().await;
        }
        std::future::pending().await
    }

    async fn shutdown(&self) {
        #[cfg(target_os = "linux")]
        if let Some(linux) = self.linux.as_ref() {
            linux.shutdown().await;
        }
    }

    fn id(&self) -> &'static str {
        "wide_primary"
    }

    fn runtime_id(&self) -> &'static str {
        #[cfg(target_os = "linux")]
        if let Some(backend) = &self.linux {
            return backend.id();
        }
        #[cfg(target_os = "macos")]
        if let Some(backend) = &self.macos {
            return backend.id();
        }
        #[cfg(target_os = "windows")]
        if let Some(backend) = &self.windows {
            return backend.id();
        }
        self.id()
    }

    fn kind(&self) -> IngressKind {
        IngressKind::WidePrimary
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.linux
                .as_ref()
                .is_some_and(|linux| linux.is_available())
        }
        #[cfg(target_os = "macos")]
        {
            self.macos.is_some()
        }
        #[cfg(target_os = "windows")]
        {
            self.windows.is_some()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self::supports_platform(&self.settings)
        }
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        Some(self.settings.listen)
    }

    fn runtime_status(&self) -> IngressBackendRuntimeStatus {
        #[cfg(target_os = "linux")]
        if let Some(backend) = &self.linux {
            return backend.runtime_status();
        }
        #[cfg(target_os = "macos")]
        if let Some(backend) = &self.macos {
            return backend.runtime_status();
        }
        #[cfg(target_os = "windows")]
        if let Some(backend) = &self.windows {
            return backend.runtime_status();
        }
        IngressBackendRuntimeStatus::default()
    }

    async fn accept(&self) -> io::Result<IngressSessionIntent> {
        #[cfg(target_os = "linux")]
        if let Some(backend) = &self.linux {
            return backend.accept().await;
        }
        #[cfg(target_os = "macos")]
        if let Some(backend) = &self.macos {
            return backend.accept().await;
        }
        #[cfg(target_os = "windows")]
        if let Some(backend) = &self.windows {
            return backend.accept().await;
        }

        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "wide ingress backend is not implemented for this platform yet (backend={:?}, listen={})",
                self.settings.platform_backend,
                self.settings.listen
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::WidePlatformBackend;

    #[test]
    fn disabled_wide_backend_is_not_supported() {
        let settings = WideIngressSettings {
            enabled: false,
            ..WideIngressSettings::default()
        };
        assert!(!WidePrimaryBackend::supports_platform(&settings));
        assert!(!WidePrimaryBackend::supports_platform_family(&settings));
    }

    #[test]
    fn family_support_tracks_current_os_backend_enum() {
        let mut settings = WideIngressSettings::default();
        #[cfg(target_os = "linux")]
        {
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::LinuxRedirect;
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::LinuxTproxy;
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::MacosPf;
            assert!(!WidePrimaryBackend::supports_platform_family(&settings));
        }
        #[cfg(target_os = "macos")]
        {
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::MacosPf;
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::Windivert;
            assert!(!WidePrimaryBackend::supports_platform_family(&settings));
        }
        #[cfg(target_os = "windows")]
        {
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::Windivert;
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::WindowsWfpAle;
            assert!(WidePrimaryBackend::supports_platform_family(&settings));
            settings.platform_backend = WidePlatformBackend::LinuxRedirect;
            assert!(!WidePrimaryBackend::supports_platform_family(&settings));
        }
    }

    #[tokio::test]
    async fn bind_rejects_unsupported_runtime_path() {
        let mut settings = WideIngressSettings::default();
        #[cfg(target_os = "linux")]
        {
            settings.platform_backend = WidePlatformBackend::MacosPf;
        }
        #[cfg(target_os = "macos")]
        {
            settings.platform_backend = WidePlatformBackend::Auto;
        }
        #[cfg(target_os = "windows")]
        {
            settings.platform_backend = WidePlatformBackend::Auto;
        }

        let result = WidePrimaryBackend::bind(settings).await;
        assert!(result.is_err(), "unsupported bind unexpectedly succeeded");
        let err = result.err().expect("unsupported bind error");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err
            .to_string()
            .contains("wide ingress backend is not implemented"));
    }
}
