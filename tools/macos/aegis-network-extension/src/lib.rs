//! Private product scaffold. No signing, installation or live acceptance claim.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod apple;
pub mod bridge;
pub mod policy;

// B-06 S20b leak guard: the packet filter's pure verdict and the
// process-global gate the tunnel provider arms (no Apple dependency).
pub mod leak_guard;

// B-06 S20b: the NEFilterPacketProvider beside the packet tunnel provider.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod filter_provider;

// B-06 S20b host side: NEFilterManager enable, readback and removal.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod filter_manager;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod configuration;

// Staged public-consistency codec; no runtime caller until child protocol review.
#[cfg(all(target_os = "macos", feature = "apple"))]
#[allow(dead_code)]
pub(crate) mod intent_wire;

// Bounded untrusted frame codec for a future authenticated child XPC channel.
#[cfg(all(target_os = "macos", feature = "apple"))]
#[allow(dead_code)]
pub(crate) mod packet_frame;

// Inert, bounded XPC packet ingress proposal. No runtime caller or Store grant.
#[cfg(all(target_os = "macos", feature = "apple"))]
#[allow(dead_code)]
pub(crate) mod packet_transport;

pub mod engine;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod manager;

// B-06 S11 host verbs, replacement rule and bounded activation outcome.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod host_lifecycle;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod app_group;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod web_response_custody;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod sfu_media_custody;

#[cfg(all(target_os = "macos", feature = "sfu-media-vp8"))]
pub(crate) mod sfu_media_owner;

// Opt-in held H3 transport. The default Apple build retains its QUIC refusal.
#[cfg(all(target_os = "macos", feature = "enrolled-quic"))]
pub(crate) mod quic_carrier;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod bound_relay_policy;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod prepared_crypto;

// All outer wire routes must hand their owned byte stream to enrolled TLS.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod carrier_io;

// B-06 S16f relay sockets bound to the physical egress interface.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod relay_socket;

// B-06 S16g session-wide relay channel establishment limiter.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod establish_limit;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod held_relay_services;

// B-06 v40 (CP-D3 M1): the signed profile's carrier pool (one held outer
// connector per pin), aegis-core's carrier failover controller and the
// access network key from the system path monitor (RAM only).
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod carrier_failover;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod carrier_network;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod carrier_pool;

// B-06 S16i-1 per-flow outcome instrumentation.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod flow_log;

// B-06 S16h pooled outer sessions for flows; no runtime caller until the
// flow path moves onto the pool.
#[cfg(all(target_os = "macos", feature = "apple"))]
#[allow(dead_code)]
pub(crate) mod flow_pool;

// B-06 v34: the adaptive receive window of a pooled flow's stream.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod stream_window;

// B-06 S16l: the session's persistent ACK connection.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod ack_conn;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod provider_session;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod provider_session_body;

// B-06 S17 failure policy: recoverable loss reasserts and rebuilds.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod session_rebuild;

// B-06 S18 sleep/wake and physical path changes: re-ACK, re-pin, rebuild.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod path_watch;

// S22 provider-side identity custody over held bytes.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod identity_custody;

// B-06 S23 provider-epoch certificate renewal: due monitor, the step before
// each capture, the Store journal and the enrollment exchange.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod identity_renewal;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod renewal_exchange;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod renewal_journal;

// S14 identity import/forget payload, authorization and provider commit.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod identity_import;

// S15 host import client: source admission, echo check, source removal.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod host_import;

// v45 one-step join: the `.aegis-invite` package, the host's staging and
// Redeem journal, and `--enroll` (stage, redeem, then the S15 import).
#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod enroll_journal;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod host_enroll;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod invite_package;

// v45 menu language: English base, Russian from the system language.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod menu_l10n;

// v39 menu-bar app (source only): its pure state model, the masked
// diagnostics report and the sequences of existing host CLI verbs it runs.
// The AppKit glue lives in `bin/host/` only, so neither this library nor the
// provider links AppKit.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod menu_diagnostics;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod menu_flow;
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod menu_model;

// S16a public profile terms of the provider's held tree, for the host's
// profile verbs.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod profile_terms;

// Authenticated host<->provider channel: ping/status diagnostics and the
// S14 identity verbs.
#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod provider_xpc;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod store_last_thread;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod store_scoped_packet;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod store_scoped_observation;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod local_identity;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub mod runtime_binding;

#[cfg(all(target_os = "macos", feature = "apple"))]
pub(crate) mod host_runtime_publication;

// Unsigned lib-test App Group tree; absent from every non-test build.
#[cfg(all(test, target_os = "macos", feature = "apple"))]
pub(crate) mod test_fixture;

// Loopback outer-H2/inner-TLS/PolicyAck relay for lib tests only.
#[cfg(all(test, target_os = "macos", feature = "apple"))]
pub(crate) mod test_relay;

// B-06 S16h-1 loopback latency link (RTT/2 each way) for lib tests only.
#[cfg(all(test, target_os = "macos", feature = "apple"))]
pub(crate) mod test_link;

// B-06 S16b fixture relay for the bounded installed window; lib tests only.
#[cfg(all(test, target_os = "macos", feature = "apple"))]
pub(crate) mod fixture_relay;

// B-06 S23 loopback enrollment authority; lib tests only.
#[cfg(all(test, target_os = "macos", feature = "apple"))]
pub(crate) mod test_enrollment;

#[cfg(feature = "client-engine")]
pub mod packet_engine;

/// Lib tests only: a global allocator that counts this thread's
/// allocations, so S20b can show the per-packet path never allocates.
#[cfg(test)]
pub(crate) mod test_alloc {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    }

    fn counted() {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get().wrapping_add(1)));
    }

    pub(crate) struct Counting;

    // SAFETY: every call forwards to the system allocator unchanged.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            counted();
            System.alloc(layout)
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            counted();
            System.alloc_zeroed(layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            counted();
            System.realloc(ptr, layout, size)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout)
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    /// Allocations made on the calling thread so far.
    pub(crate) fn allocations() -> u64 {
        ALLOCATIONS.with(Cell::get)
    }
}
