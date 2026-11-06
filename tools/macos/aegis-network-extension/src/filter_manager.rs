//! B-06 S20b host side: the app's one NEFilterManager configuration, a
//! packet filter served by the PacketTunnel system extension's
//! `AegisFilterPacketProvider`.
//!
//! Every call needs the main thread, is bounded by its `Operation` and
//! reports the reloaded configuration (`host_lifecycle::FilterReadback`),
//! never only the save's own error. The first save of a configuration makes
//! macOS ask the user to allow AEGIS to filter network content; nothing
//! here answers that alert. The decisions on a readback (`enable_outcome`,
//! `status_outcome`, exit codes) are in `host_lifecycle`.
use crate::{
    configuration::PROVIDER_ID,
    host_lifecycle::{filter_error_code, FilterReadback, FILTER_DESCRIPTION},
    manager::Operation,
};
use block2::RcBlock;
use objc2::rc::Retained;
use objc2_foundation::{NSError, NSString};
use objc2_network_extension::{
    NEFilterErrorDomain, NEFilterManager, NEFilterManagerGrade, NEFilterProviderConfiguration,
};
use std::{rc::Rc, sync::Arc};

/// One verb's result: the reloaded configuration, or a stable code.
pub type FilterCompletion = Arc<dyn Fn(Result<FilterReadback, &'static str>)>;
/// `--remove-filter`: whether a configuration was found, and the reload.
pub type RemoveCompletion = Arc<dyn Fn(Result<(bool, FilterReadback), &'static str>)>;

/// The stable code of a completion's error; `None` for success.
fn error_code(error: *mut NSError) -> Option<&'static str> {
    if error.is_null() {
        return None;
    }
    let error = unsafe { &*error };
    let filter_domain = unsafe { &*error.domain() == NEFilterErrorDomain };
    Some(filter_error_code(filter_domain, error.code()))
}

/// The configuration `manager` holds now, as plain fields.
fn readback(manager: &NEFilterManager) -> FilterReadback {
    unsafe {
        let config = manager.providerConfiguration();
        FilterReadback {
            configured: config.is_some(),
            enabled: manager.isEnabled(),
            filter_packets: config.as_ref().is_some_and(|c| c.filterPackets()),
            filter_sockets: config.as_ref().is_some_and(|c| c.filterSockets()),
            packet_bundle_id: config
                .as_ref()
                .and_then(|c| c.filterPacketProviderBundleIdentifier())
                .map(|id| id.to_string()),
            data_bundle_id: config
                .as_ref()
                .and_then(|c| c.filterDataProviderBundleIdentifier())
                .map(|id| id.to_string()),
            server_address_set: config.as_ref().is_some_and(|c| c.serverAddress().is_some()),
            organization_set: config.as_ref().is_some_and(|c| c.organization().is_some()),
            grade: manager.grade().0,
            description: manager.localizedDescription().map(|d| d.to_string()),
        }
    }
}

/// The reviewed configuration: packets only, this provider, nothing else.
fn reviewed_configuration() -> Retained<NEFilterProviderConfiguration> {
    unsafe {
        let config = NEFilterProviderConfiguration::new();
        config.setFilterPackets(true);
        config.setFilterSockets(false);
        config.setFilterPacketProviderBundleIdentifier(Some(&NSString::from_str(PROVIDER_ID)));
        config.setFilterDataProviderBundleIdentifier(None);
        config.setServerAddress(None);
        config.setOrganization(None);
        config
    }
}

fn shared() -> Retained<NEFilterManager> {
    unsafe { NEFilterManager::sharedManager() }
}

/// Load the preferences, then `then` on the main thread with the manager.
fn load(
    operation: Operation,
    failed: Rc<dyn Fn(&'static str)>,
    then: impl Fn(Retained<NEFilterManager>, Operation) + 'static,
) {
    if objc2::MainThreadMarker::new().is_none() {
        failed("main_thread_required");
        return;
    }
    let manager = shared();
    let held = manager.clone();
    let loaded = RcBlock::new(move |error: *mut NSError| {
        if let Err(code) = operation.check() {
            failed(code);
            return;
        }
        if let Some(code) = error_code(error) {
            failed(code);
            return;
        }
        then(held.clone(), operation.clone());
    });
    unsafe { manager.loadFromPreferencesWithCompletionHandler(&loaded) };
}

/// Save, then reload and report the reloaded configuration.
fn save_and_reload(
    manager: Retained<NEFilterManager>,
    operation: Operation,
    done: FilterCompletion,
) {
    let saved = RcBlock::new(move |error: *mut NSError| {
        if let Err(code) = operation.check() {
            done(Err(code));
            return;
        }
        if let Some(code) = error_code(error) {
            done(Err(code));
            return;
        }
        let reload_done = done.clone();
        let failed: Rc<dyn Fn(&'static str)> = Rc::new(move |code| reload_done(Err(code)));
        let done = done.clone();
        load(operation.clone(), failed, move |manager, _| {
            done(Ok(readback(&manager)))
        });
    });
    unsafe { manager.saveToPreferencesWithCompletionHandler(&saved) };
}

/// `--filter-status`: the configuration as macOS holds it.
pub fn read_filter(operation: Operation, done: FilterCompletion) {
    let failed_done = done.clone();
    let failed: Rc<dyn Fn(&'static str)> = Rc::new(move |code| failed_done(Err(code)));
    load(operation, failed, move |manager, _| {
        done(Ok(readback(&manager)))
    });
}

/// `--enable-filter`: save the reviewed packet-filter configuration,
/// enabled, and report its reload.
pub fn enable_filter(operation: Operation, done: FilterCompletion) {
    let failed_done = done.clone();
    let failed: Rc<dyn Fn(&'static str)> = Rc::new(move |code| failed_done(Err(code)));
    load(operation, failed, move |manager, operation| {
        unsafe {
            manager.setProviderConfiguration(Some(&reviewed_configuration()));
            manager.setLocalizedDescription(Some(&NSString::from_str(FILTER_DESCRIPTION)));
            manager.setGrade(NEFilterManagerGrade::Firewall);
            manager.setEnabled(true);
        }
        save_and_reload(manager, operation, done.clone());
    });
}

/// `--disable-filter`: keep the configuration, enabled=false. Nothing to
/// disable is reported by the reload (not configured).
pub fn disable_filter(operation: Operation, done: FilterCompletion) {
    let failed_done = done.clone();
    let failed: Rc<dyn Fn(&'static str)> = Rc::new(move |code| failed_done(Err(code)));
    load(operation, failed, move |manager, operation| {
        if unsafe { manager.providerConfiguration() }.is_none() {
            done(Ok(readback(&manager)));
            return;
        }
        unsafe { manager.setEnabled(false) };
        save_and_reload(manager, operation, done.clone());
    });
}

/// `--remove-filter`: removeFromPreferences when a configuration exists,
/// then reload; the caller requires the reload to hold none.
pub fn remove_filter(operation: Operation, done: RemoveCompletion) {
    let failed_done = done.clone();
    let failed: Rc<dyn Fn(&'static str)> = Rc::new(move |code| failed_done(Err(code)));
    load(operation, failed, move |manager, operation| {
        let found = unsafe { manager.providerConfiguration() }.is_some();
        if !found {
            done(Ok((false, readback(&manager))));
            return;
        }
        let done = done.clone();
        let removed = RcBlock::new(move |error: *mut NSError| {
            if let Err(code) = operation.check() {
                done(Err(code));
                return;
            }
            if let Some(code) = error_code(error) {
                done(Err(code));
                return;
            }
            let reload_done = done.clone();
            let failed: Rc<dyn Fn(&'static str)> = Rc::new(move |code| reload_done(Err(code)));
            let done = done.clone();
            load(operation.clone(), failed, move |manager, _| {
                done(Ok((true, readback(&manager))))
            });
        });
        unsafe { manager.removeFromPreferencesWithCompletionHandler(&removed) };
    });
}
