//! Binary compatibility facade for the shared actual packet engine.
#[cfg(test)]
mod fragments;
#[cfg(test)]
mod tests;
pub use aegis_client::packet_engine_io::{PacketIo, TunnelStats};
#[cfg(all(test, windows))]
use aegis_core::tunnel_policy::{ANCHOR_V4, ANCHOR_V6};
use aegis_core::RelaySettings;
#[cfg(test)]
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
#[cfg(test)]
use std::{collections::VecDeque, sync::atomic::Ordering, time::Instant};
use std::{
    io,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn run(
    device: &mut impl PacketIo,
    settings: RelaySettings,
    stop: Arc<AtomicBool>,
    max_flows: usize,
    idle: Duration,
    mtu: usize,
    dns_upstream: std::net::SocketAddr,
) -> io::Result<TunnelStats> {
    run_ready(
        device,
        settings,
        stop,
        max_flows,
        idle,
        mtu,
        dns_upstream,
        || {},
    )
}
#[allow(clippy::too_many_arguments)]
pub fn run_ready(
    device: &mut impl PacketIo,
    settings: RelaySettings,
    stop: Arc<AtomicBool>,
    max_flows: usize,
    idle: Duration,
    mtu: usize,
    dns_upstream: std::net::SocketAddr,
    ready: impl FnOnce(),
) -> io::Result<TunnelStats> {
    aegis_client::packet_engine::run_ready_with_services(
        device,
        settings,
        Arc::new(super::packet_engine_services::ClientRelayServices),
        stop,
        max_flows,
        idle,
        mtu,
        dns_upstream,
        ready,
    )
}

#[cfg(test)]
const MAX_PACKET_QUEUE: usize = 512;
#[cfg(test)]
include!("../../packet_engine/phy_body.rs");
