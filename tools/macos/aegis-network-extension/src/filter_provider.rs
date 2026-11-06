//! B-06 S20b: the NEFilterPacketProvider of the PacketTunnel system
//! extension (`NEProviderClasses` key `com.apple.networkextension.filter-packet`).
//!
//! Both providers of a system extension are instantiated in one process,
//! so the handler reads the same process-global gate the tunnel provider
//! arms (`leak_guard::LEAK_GUARD`); no IPC, file or lock sits between them.
//! The handler block captures nothing, may run on several threads at once
//! and does no allocation, logging or Objective-C messaging per packet:
//! `nw_interface_get_name` is a C getter of the interface object Apple
//! passes for the call.
//!
//! objc2-network-extension 0.3.2 does not bind `packetHandler` (it has no
//! `nw_interface_t`), so the setter is sent with `msg_send!` and the
//! Network.framework getter is declared here.
//!
//! v27 (S20f): the same call also counts each drop by the interface class
//! of that name and by direction, and writes it to the wait-free drop ring
//! (`leak_guard::DropRing`); both stay allocation and lock free, and the
//! verdict never depends on them. The name is reduced to an address-free
//! interface code (`en7`, or a hash) before anything keeps it.
use crate::leak_guard::{self, ATTACHMENT, COUNTERS, LEAK_GUARD};
use block2::{DynBlock, RcBlock};
use objc2::{define_class, msg_send, ClassType};
use objc2_foundation::{NSError, NSObjectProtocol};
use objc2_network_extension::{
    NEFilterPacketContext, NEFilterPacketProvider, NEFilterPacketProviderVerdict,
    NEProviderStopReason, NETrafficDirection,
};
use std::ffi::{c_char, c_void, CStr};

#[link(name = "Network", kind = "framework")]
extern "C" {
    /// `const char *nw_interface_get_name(nw_interface_t interface)`; the
    /// name lives as long as the interface object.
    fn nw_interface_get_name(interface: *mut c_void) -> *const c_char;
}

/// `NEFilterPacketHandler`: (context, nw_interface_t, direction, bytes,
/// length) -> verdict.
type PacketHandler = dyn Fn(
    *mut NEFilterPacketContext,
    *mut c_void,
    NETrafficDirection,
    *const c_void,
    usize,
) -> NEFilterPacketProviderVerdict;

/// The interface name Apple passes, as bytes; `None` when absent.
///
/// # Safety
/// `interface` is null or the `nw_interface_t` of the current call.
unsafe fn interface_name<'a>(interface: *mut c_void) -> Option<&'a [u8]> {
    if interface.is_null() {
        return None;
    }
    let name = unsafe { nw_interface_get_name(interface) };
    (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }.to_bytes())
}

/// One packet's verdict. A null or empty packet is judged as an empty
/// frame (Drop while guarding, Allow while Open).
///
/// # Safety
/// `bytes` is null or valid for `length` bytes for the call, and
/// `interface` as for `interface_name`.
unsafe fn handle(
    interface: *mut c_void,
    direction: NETrafficDirection,
    bytes: *const c_void,
    length: usize,
) -> NEFilterPacketProviderVerdict {
    let packet: &[u8] = if bytes.is_null() || length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(bytes.cast(), length) }
    };
    let name = unsafe { interface_name(interface) };
    let verdict = leak_guard::filter_packet(&LEAK_GUARD, &COUNTERS, name, direction.0, packet);
    NEFilterPacketProviderVerdict(verdict.raw())
}

fn install_packet_handler(provider: &AegisFilterPacketProvider) {
    let handler: RcBlock<PacketHandler> = RcBlock::new(
        |_context: *mut NEFilterPacketContext,
         interface: *mut c_void,
         direction: NETrafficDirection,
         bytes: *const c_void,
         length: usize| {
            // A panic must never unwind into NetworkExtension: it drops.
            std::panic::catch_unwind(|| unsafe { handle(interface, direction, bytes, length) })
                .unwrap_or(NEFilterPacketProviderVerdict::Drop)
        },
    );
    // `packetHandler` is a copy property: NetworkExtension keeps its own
    // copy, and this reference may drop afterwards.
    let handler: &DynBlock<PacketHandler> = &handler;
    unsafe {
        let _: () = msg_send![provider, setPacketHandler: handler];
    }
}

define_class!(
    #[unsafe(super(NEFilterPacketProvider))]
    #[name = "AegisFilterPacketProvider"]
    pub struct AegisFilterPacketProvider;
    unsafe impl NSObjectProtocol for AegisFilterPacketProvider {}
    impl AegisFilterPacketProvider {
        #[unsafe(method(startFilterWithCompletionHandler:))]
        fn start_filter(&self, completion: &DynBlock<dyn Fn(*mut NSError)>) {
            install_packet_handler(self);
            let pid = std::process::id() as i32;
            ATTACHMENT.attach(pid);
            crate::apple::log_fields("filter", &["started", &format!("pid:{pid}")]);
            completion.call((std::ptr::null_mut(),));
        }
        #[unsafe(method(stopFilterWithReason:completionHandler:))]
        fn stop_filter(&self, reason: NEProviderStopReason, completion: &DynBlock<dyn Fn()>) {
            // v26: counted, so a tunnel epoch guarded since before this
            // stop fails closed on its next drain tick (apple.rs).
            ATTACHMENT.detach();
            let guarding = LEAK_GUARD.snapshot().0.mode == leak_guard::Mode::Guarding;
            crate::apple::log_fields(
                "filter",
                &[
                    "stopped",
                    &format!("reason:{}", reason.0),
                    &format!("stops:{}", ATTACHMENT.stops()),
                    &format!("guarding:{guarding}"),
                ],
            );
            completion.call(());
        }
    }
);

/// Register the class with the Objective-C runtime before
/// `startSystemExtensionMode`, as the tunnel provider's is.
pub(crate) fn register_class() {
    let _ = AegisFilterPacketProvider::class();
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::runtime::AnyClass;

    #[test]
    fn the_filter_class_registers_as_a_packet_provider_with_both_callbacks() {
        register_class();
        let class = AnyClass::get(c"AegisFilterPacketProvider").expect("registered");
        assert_eq!(
            class.superclass().map(AnyClass::name),
            Some(c"NEFilterPacketProvider")
        );
        for selector in [
            objc2::sel!(startFilterWithCompletionHandler:),
            objc2::sel!(stopFilterWithReason:completionHandler:),
            objc2::sel!(setPacketHandler:),
        ] {
            assert!(class.responds_to(selector), "{selector:?}");
        }
    }

    #[test]
    fn the_native_handler_judges_through_the_shared_gate() {
        // Open (nothing armed in this test process's gate unless another
        // test armed it): any packet is allowed, a null one included.
        let frame = [0u8; 20];
        let open = unsafe {
            handle(
                std::ptr::null_mut(),
                NETrafficDirection::Outbound,
                frame.as_ptr().cast(),
                frame.len(),
            )
        };
        let null = unsafe {
            handle(
                std::ptr::null_mut(),
                NETrafficDirection::Inbound,
                std::ptr::null(),
                0,
            )
        };
        if LEAK_GUARD.snapshot().0.mode == leak_guard::Mode::Open {
            assert_eq!(open, NEFilterPacketProviderVerdict::Allow);
            assert_eq!(null, NEFilterPacketProviderVerdict::Allow);
        }
        assert_eq!(unsafe { interface_name(std::ptr::null_mut()) }, None);
        assert_eq!(
            NEFilterPacketProviderVerdict(leak_guard::Verdict::Drop.raw()),
            NEFilterPacketProviderVerdict::Drop
        );
        assert_eq!(
            NEFilterPacketProviderVerdict(leak_guard::Verdict::Allow.raw()),
            NEFilterPacketProviderVerdict::Allow
        );
        assert_eq!(NETrafficDirection::Outbound.0, 2);
        assert_eq!(NETrafficDirection::Inbound.0, 1);
    }
}
