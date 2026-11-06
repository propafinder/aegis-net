//! Route vocabulary for the opt-in Geneva hybrid product path.
//!
//! Strategy identifiers (for example `geneva`) and relay transport identifiers
//! (for example `grpc_stream`) are implementation details.  This module names
//! the product route selected for each protocol/address-family pair, its access
//! network visibility, and the terminal action when that route fails.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridRouteFamily {
    DirectGeneva,
    RelayGrpc,
    RelayMasque,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessNetworkVisibility {
    /// The access network sees the real destination address.
    DestinationVisible,
    /// The access network sees a relay endpoint, not the final destination.
    RelayEndpointVisible,
    /// No outbound route is permitted.
    NoEgress,
}

impl HybridRouteFamily {
    pub const fn access_network_visibility(self) -> AccessNetworkVisibility {
        match self {
            Self::DirectGeneva => AccessNetworkVisibility::DestinationVisible,
            Self::RelayGrpc | Self::RelayMasque => AccessNetworkVisibility::RelayEndpointVisible,
            Self::Block => AccessNetworkVisibility::NoEgress,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalFailureAction {
    /// Hand off while replaying the buffered application payload is provably
    /// safe. A runtime that has already attempted canonical application bytes
    /// must override this to `Block` rather than duplicate the flow.
    RelayGrpc,
    Block,
}

impl TerminalFailureAction {
    pub const fn route_family(self) -> HybridRouteFamily {
        match self {
            Self::RelayGrpc => HybridRouteFamily::RelayGrpc,
            Self::Block => HybridRouteFamily::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HybridRouteDecision {
    pub primary: HybridRouteFamily,
    pub access_network_visibility: AccessNetworkVisibility,
    pub terminal_failure_action: TerminalFailureAction,
}

/// Resolve the product route independently from concrete strategy and
/// transport identifiers.
pub const fn resolve_hybrid_geneva_route(
    protocol: FlowProtocol,
    address_family: AddressFamily,
) -> HybridRouteDecision {
    let (primary, terminal_failure_action) = match (protocol, address_family) {
        (FlowProtocol::Tcp, AddressFamily::Ipv4) => (
            HybridRouteFamily::DirectGeneva,
            TerminalFailureAction::RelayGrpc,
        ),
        (FlowProtocol::Tcp, AddressFamily::Ipv6) => {
            (HybridRouteFamily::RelayGrpc, TerminalFailureAction::Block)
        }
        (FlowProtocol::Udp, AddressFamily::Ipv4 | AddressFamily::Ipv6) => {
            (HybridRouteFamily::RelayMasque, TerminalFailureAction::Block)
        }
    };
    HybridRouteDecision {
        primary,
        access_network_visibility: primary.access_network_visibility(),
        terminal_failure_action,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridGenevaPolicyRequirements {
    /// The exact authenticated gRPC transport plan is configured. This does
    /// not claim that the endpoint is currently reachable or that deployment
    /// fronting has been proven on the wire.
    pub grpc_relay_configured: bool,
    /// A direct MASQUE endpoint and its transport plan are configured. Live
    /// health remains a separate deployment/runtime gate.
    pub masque_relay_configured: bool,
    pub passthrough_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridGenevaPolicyError {
    PassthroughForbidden,
    GrpcRelayRequired,
    MasqueRelayRequired,
}

impl std::fmt::Display for HybridGenevaPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PassthroughForbidden => {
                "hybrid Geneva policy forbids native passthrough after capture"
            }
            Self::GrpcRelayRequired => {
                "hybrid Geneva policy requires an authenticated gRPC relay fallback configuration"
            }
            Self::MasqueRelayRequired => {
                "hybrid Geneva policy requires a configured MASQUE relay for UDP"
            }
        })
    }
}

impl std::error::Error for HybridGenevaPolicyError {}

impl HybridGenevaPolicyRequirements {
    pub fn validate(self) -> Result<(), HybridGenevaPolicyError> {
        if self.passthrough_enabled {
            return Err(HybridGenevaPolicyError::PassthroughForbidden);
        }
        if !self.grpc_relay_configured {
            return Err(HybridGenevaPolicyError::GrpcRelayRequired);
        }
        if !self.masque_relay_configured {
            return Err(HybridGenevaPolicyError::MasqueRelayRequired);
        }
        Ok(())
    }
}

/// Typed terminal classification for the direct executor.
///
/// The first three values are planning/capability failures.  They are eligible
/// for immediate relay handoff in an explicit fallback mode and must not run an
/// active stall probe.  The remaining values preserve the existing runtime
/// classification behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectTerminalReason {
    NoExecutableStrategy,
    UnsupportedAddressFamily,
    MissingRawCapability,
    ClassifiedDirectFailure,
    StrategiesExhausted,
}

impl DirectTerminalReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoExecutableStrategy => "no_executable_strategy",
            Self::UnsupportedAddressFamily => "unsupported_address_family",
            Self::MissingRawCapability => "missing_raw_capability",
            Self::ClassifiedDirectFailure => "classified_direct_failure",
            Self::StrategiesExhausted => "strategies_exhausted",
        }
    }

    pub const fn requires_immediate_relay_handoff(self) -> bool {
        matches!(
            self,
            Self::NoExecutableStrategy
                | Self::UnsupportedAddressFamily
                | Self::MissingRawCapability
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_route_matrix_is_total_and_fail_closed() {
        let tcp4 = resolve_hybrid_geneva_route(FlowProtocol::Tcp, AddressFamily::Ipv4);
        assert_eq!(tcp4.primary, HybridRouteFamily::DirectGeneva);
        assert_eq!(
            tcp4.access_network_visibility,
            AccessNetworkVisibility::DestinationVisible
        );
        assert_eq!(
            tcp4.terminal_failure_action,
            TerminalFailureAction::RelayGrpc
        );

        let tcp6 = resolve_hybrid_geneva_route(FlowProtocol::Tcp, AddressFamily::Ipv6);
        assert_eq!(tcp6.primary, HybridRouteFamily::RelayGrpc);
        assert_eq!(tcp6.terminal_failure_action, TerminalFailureAction::Block);

        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let udp = resolve_hybrid_geneva_route(FlowProtocol::Udp, family);
            assert_eq!(udp.primary, HybridRouteFamily::RelayMasque);
            assert_eq!(udp.terminal_failure_action, TerminalFailureAction::Block);
        }
    }

    #[test]
    fn every_route_family_has_an_explicit_visibility_class() {
        assert_eq!(
            HybridRouteFamily::DirectGeneva.access_network_visibility(),
            AccessNetworkVisibility::DestinationVisible
        );
        assert_eq!(
            HybridRouteFamily::RelayGrpc.access_network_visibility(),
            AccessNetworkVisibility::RelayEndpointVisible
        );
        assert_eq!(
            HybridRouteFamily::RelayMasque.access_network_visibility(),
            AccessNetworkVisibility::RelayEndpointVisible
        );
        assert_eq!(
            HybridRouteFamily::Block.access_network_visibility(),
            AccessNetworkVisibility::NoEgress
        );
    }

    #[test]
    fn hybrid_policy_rejects_passthrough_and_missing_relays() {
        let valid = HybridGenevaPolicyRequirements {
            grpc_relay_configured: true,
            masque_relay_configured: true,
            passthrough_enabled: false,
        };
        assert_eq!(valid.validate(), Ok(()));

        assert_eq!(
            HybridGenevaPolicyRequirements {
                passthrough_enabled: true,
                ..valid
            }
            .validate(),
            Err(HybridGenevaPolicyError::PassthroughForbidden)
        );
        assert_eq!(
            HybridGenevaPolicyRequirements {
                grpc_relay_configured: false,
                ..valid
            }
            .validate(),
            Err(HybridGenevaPolicyError::GrpcRelayRequired)
        );
        assert_eq!(
            HybridGenevaPolicyRequirements {
                masque_relay_configured: false,
                ..valid
            }
            .validate(),
            Err(HybridGenevaPolicyError::MasqueRelayRequired)
        );
    }
}
