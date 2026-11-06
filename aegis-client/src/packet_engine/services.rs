//! Mechanics-only transport service boundary. Implementations must retain their
//! actual admitted configuration, trust/identity/renewal owner for the session.
//! This trait neither grants credentials nor makes a NetworkExtension ready.
use crate::relay_runtime_types::{ConnectTarget, UdpPacket};
use aegis_core::RelaySettings;
use serde_json::Value;
use std::{future::Future, pin::Pin};
use tokio::{net::TcpStream, sync::mpsc};
pub type RelayWork<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;
#[derive(Clone, Copy)]
pub enum EngineEvent {
    WideTunSmoltcpTcpFlowEstablished,
    WideNfqueueBackendError,
    Ipv6UdpSessionCreated,
    Ipv6UdpResponseDelivered,
    DnsFakeIpAssigned,
    DnsFakeIpMappingHit,
}
pub trait EventSink: Send + Sync {
    fn emit(&self, level: &'static str, event: EngineEvent, message: &'static str, fields: Value);
}
pub trait RelayServices: EventSink {
    fn tcp<'a>(
        &'a self,
        local: TcpStream,
        settings: &'a RelaySettings,
        host: String,
        port: u16,
    ) -> RelayWork<'a, ()>;
    fn udp_once<'a>(
        &'a self,
        settings: &'a RelaySettings,
        target: ConnectTarget,
        payload: &'a [u8],
    ) -> RelayWork<'a, Vec<u8>>;
    fn udp_flow<'a>(
        &'a self,
        settings: &'a RelaySettings,
        host: &'a str,
        port: u16,
        outbound: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<UdpPacket>,
    ) -> RelayWork<'a, ()>;
}
