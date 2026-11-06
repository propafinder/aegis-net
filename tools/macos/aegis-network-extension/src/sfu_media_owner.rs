//! Feature-gated, one-flow SFU media owner. Broker and SFU sockets are bound
//! to the current physical interface; every remote ICE tuple is inserted in
//! the current leak arm before the backend sees its SDP or trickle.
use crate::{
    app_group::CapturedSfuSnapshot,
    carrier_io::{own, InnerCarrier},
    establish_limit::EstablishPermit,
    provider_session_body::{EpochPins, UdpMediaLease},
    relay_socket::{bind_ice_udp, connect_bound, physical_source_for_peer, RelayInterface},
};
use aegis_core::{
    carrier_program::SfuDeclaration,
    secure_channel::{self, OpenRequest, Transport},
};
use aegis_webrtc::sfu_peer::{MediaTaskOwner, MediaTaskScope};
use aegis_webrtc::{
    sfu_livekit::{MediaPump, SfuLiveKitClient},
    sfu_peer::{CandidateAuthorizer, SfuPath, UdpSocketBinder},
    AdmissionKey, Operation, Role, Signaling, SignalingReply, SignalingRequest, TlsSignalingClient,
};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::AsyncReadExt;
use tokio::sync::OwnedSemaphorePermit;
use tokio_rustls::{rustls, TlsConnector};

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "SFU media owner refused")
}

fn connector(ca: &[u8]) -> io::Result<TlsConnector> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca) {
        roots
            .add(certificate.map_err(|_| refused())?)
            .map_err(|_| refused())?;
    }
    if roots.is_empty() {
        return Err(refused());
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| refused())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    config.key_log = Arc::new(rustls::NoKeyLog);
    Ok(TlsConnector::from(Arc::new(config)))
}

/// The extra WorkGate permit and exact candidate leases stay alive through
/// the last scoped WebRTC reactor or peer-close task, including cancellation
/// of the flow that originally opened the media peer.
struct MediaLeaseAnchor {
    _leases: Arc<Mutex<Vec<UdpMediaLease<'static>>>>,
    _gate: OwnedSemaphorePermit,
}

pub(crate) struct MediaTaskLifetime {
    owner: MediaTaskOwner,
    scope: MediaTaskScope,
    leases: Arc<Mutex<Vec<UdpMediaLease<'static>>>>,
}

pub(crate) fn task_lifetime(
    gate: &crate::held_relay_services::WorkGate,
) -> io::Result<MediaTaskLifetime> {
    let leases = Arc::new(Mutex::new(Vec::new()));
    let anchor = Arc::new(MediaLeaseAnchor {
        _leases: leases.clone(),
        _gate: gate.admit()?,
    });
    let (owner, scope) = MediaTaskOwner::new(anchor);
    Ok(MediaTaskLifetime {
        owner,
        scope,
        leases,
    })
}

pub(crate) struct MediaTerminal {
    pump: Option<MediaPump>,
    owner: Option<MediaTaskOwner>,
}

impl Future for MediaTerminal {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let polled = {
            let Some(pump) = self.pump.as_mut() else {
                return Poll::Ready(());
            };
            pump.as_mut().poll(cx)
        };
        match polled {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                drop(self.pump.take());
                drop(self.owner.take());
                Poll::Ready(())
            }
        }
    }
}

impl Drop for MediaTerminal {
    fn drop(&mut self) {
        drop(self.pump.take());
        drop(self.owner.take());
    }
}

pub(crate) struct SfuFlow {
    pub(crate) inner: InnerCarrier,
    pub(crate) terminal: MediaTerminal,
}

/// One strictly bounded media target from one fresh broker grant. The
/// provider calls this only after the ordinary inner-device Policy ACK and
/// holds the returned flow under its WorkGate for the complete copy lifetime.
#[allow(clippy::too_many_arguments)] // Every explicit owner/input is security-significant.
pub(crate) async fn open_target(
    signed: &SfuDeclaration,
    private: &CapturedSfuSnapshot,
    interface: &RelayInterface,
    pins: &EpochPins,
    generation: u64,
    inner_client: &secure_channel::Client,
    transport: Transport,
    (host, port): (String, u16),
    permit: &mut EstablishPermit,
    deadline: tokio::time::Instant,
    lifetime: MediaTaskLifetime,
) -> io::Result<SfuFlow> {
    let MediaTaskLifetime {
        owner,
        scope,
        leases,
    } = lifetime;
    if host.is_empty()
        || port == 0
        || pins.generation() != generation
        || pins.get().as_ref() != Some(interface)
        || !crate::leak_guard::LEAK_GUARD.guarding_now()
    {
        return Err(refused());
    }
    let (broker_ca, media_ca) = crate::sfu_media_custody::admit_public_roots(
        &private.broker_ca,
        &private.media_ca,
        signed,
    )?;
    let broker_key = std::str::from_utf8(private.broker_key.as_slice()).map_err(|_| refused())?;
    let key = AdmissionKey::from_hex(broker_key).map_err(|_| refused())?;
    // Choose the route's source for this exact signed media peer. A source-only
    // UDP probe sends no media datagram and closes before the ICE backend
    // receives its separately authorized candidate sockets.
    let source = physical_source_for_peer(signed.media, interface)?;
    // The broker is distinct from both signed relay and media TCP pins.
    // Amend only this exact signed tuple under the current arm, and withdraw
    // it immediately after the one-use grant transaction.
    let broker_lease = pins
        .authorize_web_ingress(generation, signed.broker)
        .ok_or_else(refused)?;
    let broker_tcp = tokio::time::timeout_at(deadline, connect_bound(signed.broker, interface))
        .await
        .map_err(|_| refused())??;
    if broker_tcp.peer_addr()? != signed.broker {
        return Err(refused());
    }
    let broker_name = rustls::pki_types::ServerName::try_from(signed.broker_tls_name.clone())
        .map_err(|_| refused())?;
    let broker_tls = tokio::time::timeout_at(
        deadline,
        connector(&broker_ca)?.connect(broker_name, broker_tcp),
    )
    .await
    .map_err(|_| refused())?
    .map_err(|_| refused())?;
    let signaling = TlsSignalingClient::new(broker_tls);
    let SignalingReply::MediaSubmitted(session) = signaling
        .exchange(
            SignalingRequest::new(Role::Client, key.clone(), Operation::MediaBegin),
            deadline,
        )
        .await
        .map_err(|_| refused())?
    else {
        return Err(refused());
    };
    let grant = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(refused());
        }
        match signaling
            .exchange(
                SignalingRequest::new(
                    Role::Client,
                    key.clone(),
                    Operation::MediaTake {
                        session,
                        claim: None,
                    },
                ),
                deadline,
            )
            .await
        {
            Ok(SignalingReply::MediaGrant(grant)) => break grant,
            Err(aegis_webrtc::Error::Session) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
            _ => return Err(refused()),
        }
    };
    let (descriptor, token) = grant.into_client().map_err(|_| refused())?;
    drop(signaling);
    drop(broker_lease);
    let media_tcp = tokio::time::timeout_at(deadline, connect_bound(signed.media, interface))
        .await
        .map_err(|_| refused())??;
    if media_tcp.peer_addr()? != signed.media {
        return Err(refused());
    }
    let media_name = rustls::pki_types::ServerName::try_from(signed.media_tls_name.clone())
        .map_err(|_| refused())?;
    let media_tls = tokio::time::timeout_at(
        deadline,
        connector(&media_ca)?.connect(media_name, media_tcp),
    )
    .await
    .map_err(|_| refused())?
    .map_err(|_| refused())?;
    let candidate_authorizer: CandidateAuthorizer = {
        let pins = pins.clone();
        let interface = interface.clone();
        let allowed = signed.allowed_media_ips.clone();
        let leases = leases.clone();
        Arc::new(move |candidates: &[SocketAddr]| {
            if candidates
                .iter()
                .any(|candidate| !allowed.contains(&candidate.ip()))
            {
                return Err(aegis_webrtc::Error::Path);
            }
            let admitted = pins
                .authorize_udp_media(generation, &interface, candidates)
                .ok_or(aegis_webrtc::Error::Path)?;
            leases
                .lock()
                .map_err(|_| aegis_webrtc::Error::Path)?
                .extend(admitted);
            Ok(())
        })
    };
    let socket_binder: UdpSocketBinder = {
        let pins = pins.clone();
        let interface = interface.clone();
        Arc::new(move |socket| {
            if pins.generation() != generation
                || pins.get().as_ref() != Some(&interface)
                || !crate::leak_guard::LEAK_GUARD.guarding_now()
            {
                return Err(refused());
            }
            bind_ice_udp(socket, &interface, source)
        })
    };
    let path = SfuPath {
        bind: SocketAddr::new(source, 0),
        allowed_sfu_ips: signed.allowed_media_ips.clone(),
    };
    let host_header = if signed.media.port() == 443 {
        signed.media_tls_name.clone()
    } else {
        format!("{}:{}", signed.media_tls_name, signed.media.port())
    };
    let media = tokio::time::timeout_at(
        deadline,
        SfuLiveKitClient::connect_verified_with_network_scoped(
            media_tls,
            &host_header,
            token,
            descriptor,
            path,
            Some(candidate_authorizer),
            Some(socket_binder),
            Some(scope),
        ),
    )
    .await
    .map_err(|_| refused())?
    .map_err(|_| refused())?;
    let (carrier, pump) =
        tokio::time::timeout_at(deadline, media.into_inner_tls_carrier_unspawned())
            .await
            .map_err(|_| refused())?
            .map_err(|_| refused())?;
    let mut terminal = MediaTerminal {
        pump: Some(pump),
        owner: Some(owner),
    };
    let mut inner = tokio::select! {
        ready = inner_client.connect(own(carrier)) => ready.map_err(|_| refused())?,
        () = &mut terminal => return Err(refused()),
        () = tokio::time::sleep_until(deadline) => return Err(refused()),
    };
    let request = OpenRequest {
        transport,
        version: 1,
        host,
        port,
    };
    tokio::select! {
        written = secure_channel::write_open(&mut inner, &request) => written.map_err(|_| refused())?,
        () = &mut terminal => return Err(refused()),
        () = tokio::time::sleep_until(deadline) => return Err(refused()),
    }
    permit.request_written();
    let status = tokio::select! {
        status = inner.read_u8() => status.map_err(|_| refused())?,
        () = &mut terminal => return Err(refused()),
        () = tokio::time::sleep_until(deadline) => return Err(refused()),
    };
    if status != 0 {
        return Err(refused());
    }
    Ok(SfuFlow { inner, terminal })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn media_scope_keeps_work_gate_permit_until_all_holders_drop() {
        let gate = crate::held_relay_services::WorkGate::new();
        let MediaTaskLifetime {
            owner,
            scope,
            leases,
        } = task_lifetime(&gate).unwrap();
        assert_eq!(gate.flows(), 1);
        drop(owner);
        drop(leases);
        assert_eq!(gate.flows(), 1);
        drop(scope);
        assert!(gate.drained());
    }

    #[tokio::test]
    async fn media_terminal_drops_pump_before_last_gate_owner() {
        struct PumpDrop(Arc<crate::held_relay_services::WorkGate>);
        impl Drop for PumpDrop {
            fn drop(&mut self) {
                assert_eq!(self.0.flows(), 1);
            }
        }

        let gate = crate::held_relay_services::WorkGate::new();
        let MediaTaskLifetime {
            owner,
            scope,
            leases,
        } = task_lifetime(&gate).unwrap();
        drop(scope);
        drop(leases);
        let marker = PumpDrop(gate.clone());
        let pump: MediaPump = Box::pin(async move {
            let _marker = marker;
            std::future::pending::<aegis_webrtc::Result<()>>().await
        });
        let terminal = MediaTerminal {
            pump: Some(pump),
            owner: Some(owner),
        };
        assert_eq!(gate.flows(), 1);
        drop(terminal);
        assert!(gate.drained());
    }

    #[tokio::test]
    async fn completed_media_pump_releases_its_owner_after_secret_drop() {
        struct PumpDrop(Arc<crate::held_relay_services::WorkGate>);
        impl Drop for PumpDrop {
            fn drop(&mut self) {
                assert_eq!(self.0.flows(), 1);
            }
        }

        let gate = crate::held_relay_services::WorkGate::new();
        let MediaTaskLifetime {
            owner,
            scope,
            leases,
        } = task_lifetime(&gate).unwrap();
        drop(scope);
        drop(leases);
        let marker = PumpDrop(gate.clone());
        let pump: MediaPump = Box::pin(async move {
            drop(marker);
            Ok(())
        });
        MediaTerminal {
            pump: Some(pump),
            owner: Some(owner),
        }
        .await;
        assert!(gate.drained());
    }
}
