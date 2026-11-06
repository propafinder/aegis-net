//! Actual existing binary relay/event owner adapter. No admission/ready flag;
//! this changes neither transport selection nor TLS/lease/renewal policy.
use aegis_client::{
    packet_engine::services::{EngineEvent, EventSink, RelayServices, RelayWork},
    relay_runtime_types::{ConnectTarget, UdpPacket},
};
use aegis_core::RelaySettings;
use tokio::{net::TcpStream, sync::mpsc};
pub(crate) struct ClientRelayServices;
impl EventSink for ClientRelayServices {
    fn emit(
        &self,
        level: &'static str,
        event: EngineEvent,
        message: &'static str,
        fields: serde_json::Value,
    ) {
        use crate::runtime_events::RuntimeEventCode as Existing;
        let code = match event {
            EngineEvent::WideTunSmoltcpTcpFlowEstablished => {
                Existing::WideTunSmoltcpTcpFlowEstablished
            }
            EngineEvent::WideNfqueueBackendError => Existing::WideNfqueueBackendError,
            EngineEvent::Ipv6UdpSessionCreated => Existing::Ipv6UdpSessionCreated,
            EngineEvent::Ipv6UdpResponseDelivered => Existing::Ipv6UdpResponseDelivered,
            EngineEvent::DnsFakeIpAssigned => Existing::DnsFakeIpAssigned,
            EngineEvent::DnsFakeIpMappingHit => Existing::DnsFakeIpMappingHit,
        };
        crate::runtime_event_stream::emit(level, code, message, fields);
    }
}
impl RelayServices for ClientRelayServices {
    fn tcp<'a>(
        &'a self,
        local: TcpStream,
        settings: &'a RelaySettings,
        host: String,
        port: u16,
    ) -> RelayWork<'a, ()> {
        Box::pin(crate::relay::run_relay_tunnel(
            local, settings, host, port, None, None, None,
        ))
    }
    fn udp_once<'a>(
        &'a self,
        settings: &'a RelaySettings,
        target: ConnectTarget,
        payload: &'a [u8],
    ) -> RelayWork<'a, Vec<u8>> {
        Box::pin(crate::relay::run_relay_udp_datagram_once(
            settings, target, payload,
        ))
    }
    fn udp_flow<'a>(
        &'a self,
        settings: &'a RelaySettings,
        host: &'a str,
        port: u16,
        outbound: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<UdpPacket>,
    ) -> RelayWork<'a, ()> {
        Box::pin(crate::relay::run_relay_udp_flow(
            settings, host, port, outbound, incoming,
        ))
    }
}
