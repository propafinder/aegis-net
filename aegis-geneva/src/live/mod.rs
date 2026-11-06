//! Pure, bounded execution over Ethernet/IPv4 wire images.
//! Socket I/O is confined to the opt-in `aegis-geneva-bridge` executable.
pub(super) mod dns;
pub(super) mod options;
pub mod program;
pub(super) mod values;
pub mod wire;

#[cfg(all(feature = "live-linux", unix))]
pub mod input;
