//! Construct explicit full-wide manager intent. Caller must independently
//! admit an approved extension/identity, save preferences, reload and observe
//! the exact manager. This function does not save or start the VPN.
use crate::policy::FullWide;
use objc2::{msg_send, rc::Retained, AnyThread};
use objc2_foundation::NSString;
use objc2_network_extension::{NETunnelProviderManager, NETunnelProviderProtocol};
pub const PROVIDER_ID: &str = "dev.aegis.macos.PacketTunnel";

pub(crate) struct SavedProviderIntent {
    pub(crate) generation: String,
    pub(crate) policy: FullWide,
}
impl SavedProviderIntent {
    // Staged for the signed child protocol; not a factory admission.
    #[allow(dead_code)]
    pub(crate) fn canonical_public_wire(&self) -> Result<Vec<u8>, &'static str> {
        crate::intent_wire::encode_public_intent(&self.generation, &self.policy)
    }
    pub(crate) fn matches_returned_owner(&self, generation: &str, policy: &FullWide) -> bool {
        self.generation == generation && self.policy == *policy
    }
}

// The manager intent is not an authentication grant. It must nevertheless be
// the exact full-wide intent that the provider will apply before a future
// admitted factory is allowed to construct any packet or credential owner.
pub(crate) fn provider_shape_matches(protocol: &NETunnelProviderProtocol) -> bool {
    unsafe {
        protocol
            .providerBundleIdentifier()
            .is_some_and(|id| id.to_string() == PROVIDER_ID)
            && protocol.includeAllNetworks()
            && !protocol.excludeLocalNetworks()
            && !protocol.excludeAPNs()
            && !protocol.excludeCellularServices()
            && !protocol.excludeDeviceCommunication()
            && !protocol.enforceRoutes()
    }
}
pub(crate) fn provider_intent_matches(
    protocol: &NETunnelProviderProtocol,
    policy: &FullWide,
) -> bool {
    provider_shape_matches(protocol)
        && unsafe {
            protocol
                .serverAddress()
                .is_some_and(|address| address.to_string() == policy.relay().to_string())
        }
}

// This is a consistency check on the persisted manager request, not a
// credential or permission grant. Reject malformed saved intent before a
// future factory is allowed to create a packet/credential owner.
pub(crate) fn saved_provider_intent(
    protocol: &NETunnelProviderProtocol,
) -> Result<SavedProviderIntent, &'static str> {
    if !provider_shape_matches(protocol) {
        return Err("provider_shape_mismatch");
    }
    let config =
        unsafe { protocol.providerConfiguration() }.ok_or("saved_provider_intent_absent")?;
    if config.len() != 5 {
        return Err("saved_provider_intent_shape");
    }
    let value = |key: &str| -> Result<String, &'static str> {
        config
            .objectForKey(&NSString::from_str(key))
            .and_then(|item| item.downcast::<NSString>().ok())
            .map(|item| item.to_string())
            .ok_or("saved_provider_intent_value")
    };
    if value("schema")? != "aegis-ne-profile-v1" {
        return Err("saved_provider_intent_schema");
    }
    let generation = value("owner_generation")?;
    if generation.is_empty() || generation.len() > 128 || generation.chars().any(char::is_control) {
        return Err("saved_provider_intent_generation");
    }
    let relay = value("relay")?
        .parse()
        .map_err(|_| "saved_provider_intent_relay")?;
    let dns_text = value("dns")?;
    let dns = dns_text
        .split(',')
        .map(|part| part.parse().map_err(|_| "saved_provider_intent_dns"))
        .collect::<Result<Vec<_>, _>>()?;
    let mtu = value("mtu")?
        .parse()
        .map_err(|_| "saved_provider_intent_mtu")?;
    let policy = FullWide::new(relay, dns, mtu)?;
    if !provider_intent_matches(protocol, &policy)
        || value("relay")? != policy.relay().to_string()
        || value("dns")?
            != policy
                .dns()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        || value("mtu")? != policy.mtu().to_string()
    {
        return Err("saved_provider_intent_mismatch");
    }
    Ok(SavedProviderIntent { generation, policy })
}
/// The `localizedDescription` every saved AEGIS profile carries.
pub const LOCALIZED_DESCRIPTION: &str = "AEGIS full-wide";

/// The six protocol flags `provider_shape_matches` compares, in this order:
/// includeAllNetworks, excludeLocalNetworks, excludeAPNs,
/// excludeCellularServices, excludeDeviceCommunication, enforceRoutes.
pub const FULLWIDE_FLAGS: [bool; 6] = [true, false, false, false, false, false];

/// The six flags of `protocol` as the system (or a fresh object) reports
/// them, in `FULLWIDE_FLAGS` order. Diagnostic and verification input only.
pub fn protocol_flags(protocol: &NETunnelProviderProtocol) -> [bool; 6] {
    unsafe {
        [
            protocol.includeAllNetworks(),
            protocol.excludeLocalNetworks(),
            protocol.excludeAPNs(),
            protocol.excludeCellularServices(),
            protocol.excludeDeviceCommunication(),
            protocol.enforceRoutes(),
        ]
    }
}

/// A fresh full-wide protocol for `provider_id`: the relay as server address,
/// includeAllNetworks, no exclusions and no enforceRoutes. It carries no
/// `providerConfiguration`; the caller sets one before attaching it.
pub fn fullwide_protocol(
    provider_id: &str,
    policy: &FullWide,
) -> Result<Retained<NETunnelProviderProtocol>, &'static str> {
    if provider_id != PROVIDER_ID {
        return Err("invalid_provider_identifier");
    }
    unsafe {
        let protocol: Retained<NETunnelProviderProtocol> =
            msg_send![NETunnelProviderProtocol::alloc(), init];
        protocol.setProviderBundleIdentifier(Some(&NSString::from_str(provider_id)));
        protocol.setServerAddress(Some(&NSString::from_str(&policy.relay().to_string())));
        protocol.setIncludeAllNetworks(true);
        protocol.setExcludeLocalNetworks(false);
        protocol.setExcludeAPNs(false);
        protocol.setExcludeCellularServices(false);
        protocol.setExcludeDeviceCommunication(false);
        // includeAllNetworks supersedes enforceRoutes; never claim both.
        protocol.setEnforceRoutes(false);
        Ok(protocol)
    }
}

pub fn fullwide_manager(
    provider_id: &str,
    policy: &FullWide,
) -> Result<Retained<NETunnelProviderManager>, &'static str> {
    let protocol = fullwide_protocol(provider_id, policy)?;
    unsafe {
        let manager: Retained<NETunnelProviderManager> =
            msg_send![NETunnelProviderManager::alloc(), init];
        manager.setProtocolConfiguration(Some(&protocol));
        manager.setLocalizedDescription(Some(&NSString::from_str(LOCALIZED_DESCRIPTION)));
        manager.setEnabled(false); // approval/custody then explicit enable is separate
        Ok(manager)
    }
}

/// B-06 v35: how one tunnel start's pooled streams receive. Chosen per
/// start ([`WINDOW_POLICY_OPTION`]), never saved. v36: the fixed window
/// unless the owner's `--connect ... --window-policy adaptive` asked for the
/// v35 window (a QA arm; v36-load-acceptance.md, outcome `fixed`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WindowMode {
    /// The v35 stream window (`stream_window::WindowPolicy`). v36: only on
    /// request, `--window-policy adaptive` (the treatment arm of a later
    /// A/B); no product start asks for it.
    Adaptive,
    /// v33's fixed 128 KiB stream window, with v35's measurements,
    /// placement and telemetry. v36: the product default, and every start
    /// that carries no start option (on-demand and System Settings starts).
    #[default]
    Fixed,
}

impl WindowMode {
    /// Its `pool_policy mode:` token.
    pub fn code(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::Fixed => "fixed",
        }
    }

    /// v36: the mode a start-option or `--window-policy` value names
    /// (exactly `adaptive` or `fixed`), else none.
    pub fn from_value(value: &str) -> Option<Self> {
        match value {
            WINDOW_POLICY_ADAPTIVE => Some(Self::Adaptive),
            WINDOW_POLICY_FIXED => Some(Self::Fixed),
            _ => None,
        }
    }
}

/// The one start-option key the provider examines (`startTunnelWithOptions`).
/// v36: absent for the product default (fixed), [`WINDOW_POLICY_ADAPTIVE`]
/// for the v35 window; [`WINDOW_POLICY_FIXED`] stays accepted.
pub const WINDOW_POLICY_OPTION: &str = "aegis_window_policy";
/// A value [`WINDOW_POLICY_OPTION`] accepts: v33's fixed window (v36: the
/// default anyway).
pub const WINDOW_POLICY_FIXED: &str = "fixed";
/// v36: the other value [`WINDOW_POLICY_OPTION`] accepts: the v35 window.
pub const WINDOW_POLICY_ADAPTIVE: &str = "adaptive";

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::runtime::AnyObject;
    use objc2_foundation::NSDictionary;
    use std::net::IpAddr;

    fn saved(protocol: &NETunnelProviderProtocol, fields: &[(&str, &str)]) {
        let keys: Vec<_> = fields
            .iter()
            .map(|(key, _)| NSString::from_str(key))
            .collect();
        let values: Vec<_> = fields
            .iter()
            .map(|(_, value)| NSString::from_str(value))
            .collect();
        let objects: Vec<&AnyObject> = values.iter().map(|value| &**value as &AnyObject).collect();
        let dictionary =
            NSDictionary::from_slices(&keys.iter().map(|key| &**key).collect::<Vec<_>>(), &objects);
        unsafe { protocol.setProviderConfiguration(Some(&dictionary)) };
    }

    #[test]
    fn native_saved_intent_precedes_factory_and_refuses_mutation() {
        let policy = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["2001:db8::53".parse().unwrap()],
            1280,
        )
        .unwrap();
        let manager = fullwide_manager(PROVIDER_ID, &policy).unwrap();
        let protocol = unsafe { manager.protocolConfiguration() }
            .unwrap()
            .downcast::<NETunnelProviderProtocol>()
            .unwrap();
        let baseline = [
            ("schema", "aegis-ne-profile-v1"),
            ("owner_generation", "generation-1"),
            ("relay", "192.0.2.1"),
            ("dns", "2001:db8::53"),
            ("mtu", "1280"),
        ];
        assert!(saved_provider_intent(&protocol).is_err());
        saved(&protocol, &baseline);
        let parsed = saved_provider_intent(&protocol).unwrap();
        assert_eq!(parsed.policy, policy);
        assert_eq!(parsed.generation, "generation-1");
        let wire = parsed.canonical_public_wire().unwrap();
        let decoded = crate::intent_wire::decode_public_intent(&wire).unwrap();
        assert_eq!(decoded.generation, parsed.generation);
        assert_eq!(decoded.policy, parsed.policy);
        assert!(parsed.matches_returned_owner("generation-1", &policy));
        assert!(!parsed.matches_returned_owner("stale-generation", &policy));
        let other_policy = FullWide::new(
            "192.0.2.2".parse().unwrap(),
            vec!["2001:db8::53".parse().unwrap()],
            1280,
        )
        .unwrap();
        assert!(!parsed.matches_returned_owner("generation-1", &other_policy));
        for (index, bad) in [
            "unknown-schema",
            "",
            "192.0.2.2",
            "::ffff:127.0.0.1",
            "1279",
        ]
        .into_iter()
        .enumerate()
        {
            let mut fields = baseline;
            fields[index].1 = bad;
            saved(&protocol, &fields);
            assert!(saved_provider_intent(&protocol).is_err(), "field {index}");
        }
        saved(&protocol, &baseline);
        unsafe { protocol.setServerAddress(Some(&NSString::from_str("192.0.2.2"))) };
        assert!(saved_provider_intent(&protocol).is_err());
        unsafe { protocol.setServerAddress(Some(&NSString::from_str("192.0.2.1"))) };
        let mut extra = baseline.to_vec();
        extra.push(("unexpected", "value"));
        saved(&protocol, &extra);
        assert!(saved_provider_intent(&protocol).is_err());
    }

    /// S16d: the flag constant the save path verifies against is exactly the
    /// shape `provider_shape_matches` requires, flag for flag.
    #[test]
    fn native_fullwide_flags_constant_is_the_provider_shape() {
        let policy = FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["2001:db8::53".parse().unwrap()],
            1280,
        )
        .unwrap();
        assert!(fullwide_protocol("dev.aegis.macos.Other", &policy).is_err());
        let protocol = fullwide_protocol(PROVIDER_ID, &policy).unwrap();
        assert_eq!(protocol_flags(&protocol), FULLWIDE_FLAGS);
        assert!(provider_shape_matches(&protocol));
        assert!(unsafe { protocol.providerConfiguration() }.is_none());
        let set = |index: usize, value: bool| unsafe {
            match index {
                0 => protocol.setIncludeAllNetworks(value),
                1 => protocol.setExcludeLocalNetworks(value),
                2 => protocol.setExcludeAPNs(value),
                3 => protocol.setExcludeCellularServices(value),
                4 => protocol.setExcludeDeviceCommunication(value),
                _ => protocol.setEnforceRoutes(value),
            }
        };
        for index in 0..6 {
            set(index, !FULLWIDE_FLAGS[index]);
            let mut expected = FULLWIDE_FLAGS;
            expected[index] = !expected[index];
            assert_eq!(protocol_flags(&protocol), expected, "flag {index}");
            assert!(!provider_shape_matches(&protocol), "flag {index}");
            set(index, FULLWIDE_FLAGS[index]);
            assert!(provider_shape_matches(&protocol), "flag {index}");
        }
    }

    #[test]
    fn native_manager_intent_refuses_wrong_provider_relay_and_route_exceptions() {
        let relay: IpAddr = "192.0.2.1".parse().unwrap();
        let policy = FullWide::new(relay, vec!["2001:db8::53".parse().unwrap()], 1280).unwrap();
        assert!(fullwide_manager("dev.aegis.macos.Other", &policy).is_err());
        let manager = fullwide_manager(PROVIDER_ID, &policy).unwrap();
        let protocol = unsafe { manager.protocolConfiguration() }
            .unwrap()
            .downcast::<NETunnelProviderProtocol>()
            .unwrap();
        assert!(provider_intent_matches(&protocol, &policy));
        unsafe { protocol.setServerAddress(Some(&NSString::from_str("192.0.2.2"))) };
        assert!(!provider_intent_matches(&protocol, &policy));
        unsafe { protocol.setServerAddress(Some(&NSString::from_str("192.0.2.1"))) };
        unsafe { protocol.setExcludeAPNs(true) };
        assert!(!provider_intent_matches(&protocol, &policy));
        unsafe { protocol.setExcludeAPNs(false) };
        unsafe { protocol.setIncludeAllNetworks(false) };
        assert!(!provider_intent_matches(&protocol, &policy));
    }

    /// T27 (v36, outcome `fixed`): the product default is v33's fixed
    /// window; only the exact values `adaptive` and `fixed` name a mode.
    #[test]
    fn the_default_window_mode_is_fixed_and_only_two_values_name_a_mode() {
        assert_eq!(WindowMode::default(), WindowMode::Fixed);
        assert_eq!(WindowMode::default().code(), "fixed");
        assert_eq!(
            WindowMode::from_value(WINDOW_POLICY_ADAPTIVE),
            Some(WindowMode::Adaptive)
        );
        assert_eq!(
            WindowMode::from_value(WINDOW_POLICY_FIXED),
            Some(WindowMode::Fixed)
        );
        for mode in [WindowMode::Adaptive, WindowMode::Fixed] {
            assert_eq!(WindowMode::from_value(mode.code()), Some(mode));
        }
        for other in ["", "ADAPTIVE", "Fixed", "fixed ", " adaptive", "v33", "v35"] {
            assert_eq!(WindowMode::from_value(other), None, "{other:?}");
        }
    }
}
