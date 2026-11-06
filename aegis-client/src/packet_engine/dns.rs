//! Actual shared fake-IP allocator and parser, without OS DNS listener ownership.
#[cfg(any(target_os = "linux", test))]
use aegis_core::{RelaySettings, TunnelTransportFamily, WideIngressSettings};
use serde_json::json;
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
include!("dns_core_body.rs");

#[cfg(test)]
impl FakeIpMap {
    /// Every binding was last used `by` earlier than it was (use order kept).
    pub(crate) fn idle_for_test(&self, by: Duration) {
        let mut inner = self.inner.lock().expect("dns_preview map lock");
        for mapping in inner.by_ip.values_mut() {
            mapping.last_used = mapping
                .last_used
                .checked_sub(by)
                .expect("test clock far enough from its origin");
        }
    }

    /// How many leases hold `ip`'s binding, read under a map lock the caller
    /// already holds.
    fn holders_for_test(inner: &FakeIpMapInner, ip: Ipv4Addr) -> usize {
        inner.by_ip[&u32::from(ip)]
            .lease
            .as_ref()
            .map_or(0, |(_, core)| core.strong_count())
    }
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
