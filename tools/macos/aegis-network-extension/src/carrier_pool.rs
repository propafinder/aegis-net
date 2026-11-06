//! B-06 v40 (CP-D3 M1): the signed profile's ordered carrier pool.
//!
//! A v4 device profile names 1 to 16 numeric relay pins, the primary first
//! (for example a direct HTTP/2 relay, then CDN edge pins of the fronted
//! enrolled carrier, D1). Before any async work the session's held crypto
//! preloads one held outer connector per pin: the same rustls policy, held
//! outer CA bytes and pinned ECH for every pin, with that pin's own TLS name
//! (`relay_settings_for_endpoint`, which also drops the pool policy, so each
//! attempt is admitted exactly as a single carrier is). No path is reopened
//! and no DNS is resolved: every pin is a numeric address and port.
//!
//! A session dials exactly one pin, its selected carrier
//! ([`crate::prepared_crypto::PreparedCryptoInputs::select_carrier`]); the
//! leak guard arms the whole pool, every exact pin and nothing else
//! ([`HeldCarriers::pins`]).
//!
//! D2 (ECH over the fronted carrier): when an edge rejects the pinned ECH
//! config with authenticated retry configs (a rotated CDN key), aegis-client's
//! `ech_policy::record_rejection` admits them only if every retry config keeps
//! a pinned public name. [`HeldCarriers::ech_rejected`] then rebuilds the
//! held connector of every pin with that TLS name from the held CA (now with
//! the admitted configs), so the caller redials exactly once; a second
//! rejection is refused and [`HeldCarriers::forget_rotation`] returns every
//! such pin to its pinned list (fail closed, never a loop, never a weaker
//! check).
use aegis_client::relay_endpoint_policy::{
    effective_relay_endpoints, endpoint_runtime_ready, relay_settings_for_endpoint,
};
use aegis_core::RelaySettings;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError, RwLock},
};
use tokio_rustls::TlsConnector;

/// aegis-core's carrier pool bound, which the leak guard's set matches.
pub(crate) const MAX_PINS: usize = aegis_core::brain::carrier_failover::MAX_CARRIERS;
const _: () = assert!(MAX_PINS == crate::leak_guard::MAX_RELAY_PINS);

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "prepared crypto refused")
}

/// A pin a provider may dial: a port and a unicast address. Loopback stays
/// admissible here only because the signed full-wide policy refuses it for
/// the saved relay (`policy::FullWide::new`), and lib tests use it.
fn admissible_pin(pin: SocketAddr) -> bool {
    let ip = pin.ip();
    pin.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

/// One pin of the pool and its held outer connector.
pub(crate) struct HeldCarrier {
    peer: SocketAddr,
    relay: RelaySettings,
    rotation_scope: Option<aegis_client::ech_policy::HeldRotationScope>,
    index: usize,
    connectors: Arc<RwLock<Vec<TlsConnector>>>,
}

impl HeldCarrier {
    /// The exact numeric pin.
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// This pin's single-carrier relay settings: the signed profile's
    /// settings with this pin's address and TLS name and no pool policy.
    pub(crate) fn relay(&self) -> &RelaySettings {
        &self.relay
    }

    /// The held outer connector (an `Arc` clone).
    pub(crate) fn connector(&self) -> TlsConnector {
        self.connectors
            .read()
            .unwrap_or_else(PoisonError::into_inner)[self.index]
            .clone()
    }
}

/// What a failed outer handshake means for the ECH rotation (D2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EchRedial {
    /// Not an ECH rejection: judge the error as before.
    NotEch,
    /// Authenticated retry configs were admitted and the connectors of the
    /// pin's TLS name rebuilt: redial exactly once.
    Redial,
    /// An ECH rejection without admissible retry configs: fail closed.
    Refused,
}

/// The profile's pool, in profile order (`[0]` is the primary).
pub(crate) struct HeldCarriers {
    carriers: Vec<HeldCarrier>,
    connectors: Arc<RwLock<Vec<TlsConnector>>>,
    pinned_connectors: Vec<TlsConnector>,
    rotation_lock: Mutex<()>,
    active_rotation: Mutex<Vec<Option<aegis_client::ech_policy::RotationToken>>>,
}

impl HeldCarriers {
    /// Admit the signed relay `settings` and preload one held connector per
    /// pin from `outer_ca`. Refused: an outer Geneva shape, an endpoint
    /// bandit or authenticated shaping (none has a provider owner); a pool
    /// that is empty, longer than [`MAX_PINS`] or does not begin with the
    /// primary; a pin that is not a numeric admissible address and port; a
    /// repeated pin; a pin whose connector cannot be built.
    pub(crate) fn from_held(settings: &RelaySettings, outer_ca: &[u8]) -> io::Result<Self> {
        if settings.outer_geneva.is_some()
            || settings.endpoint_bandit.is_some()
            || settings.authenticated_shaping.is_some()
            || settings.endpoints.is_empty()
            || settings.endpoints.len() > MAX_PINS
            || settings.endpoints[0].server != settings.server
            || settings.endpoints[0].server_name != settings.server_name
        {
            return Err(refused());
        }
        let mut carriers: Vec<HeldCarrier> = Vec::with_capacity(settings.endpoints.len());
        let mut pinned_connectors = Vec::with_capacity(settings.endpoints.len());
        let mut current_connectors = Vec::with_capacity(settings.endpoints.len());
        let mut active_rotation = Vec::with_capacity(settings.endpoints.len());
        let connectors = Arc::new(RwLock::new(Vec::new()));
        for endpoint in effective_relay_endpoints(settings) {
            if !endpoint_runtime_ready(&endpoint) {
                return Err(refused());
            }
            let peer: SocketAddr = endpoint.server.parse().map_err(|_| refused())?;
            if !admissible_pin(peer) || carriers.iter().any(|held| held.peer == peer) {
                return Err(refused());
            }
            let relay = relay_settings_for_endpoint(settings, &endpoint);
            let rotation_scope =
                aegis_client::ech_policy::held_rotation_scope(&relay).map_err(|_| refused())?;
            let (connector, rotation) =
                aegis_client::prepared_outer_tls::explicit_h2_connector_from_pem_with_rotation(
                    &relay, outer_ca,
                )
                .map_err(|_| refused())?;
            // The cached generation can change while this pool is prepared.
            // Only pins with the same signed ECH list and TLS authority
            // share a generation. A direct route may have the same SNI but
            // intentionally no ECH under fronted_only.
            if carriers.iter().any(|prior| {
                rotation_scope.is_some()
                    && prior.rotation_scope == rotation_scope
                    && active_rotation[prior.index] != rotation
            }) {
                return Err(refused());
            }
            let index = carriers.len();
            current_connectors.push(connector);
            active_rotation.push(rotation);
            pinned_connectors.push(if rotation.is_some() {
                aegis_client::prepared_outer_tls::explicit_h2_connector_from_pem_pinned(
                    &relay, outer_ca,
                )
                .map_err(|_| refused())?
            } else {
                // Both modes used the signed list; preserve the exact Arc
                // rather than manufacturing a different equivalent config.
                current_connectors[index].clone()
            });
            carriers.push(HeldCarrier {
                peer,
                relay,
                rotation_scope,
                index,
                connectors: connectors.clone(),
            });
        }
        *connectors.write().unwrap_or_else(PoisonError::into_inner) = current_connectors;
        Ok(Self {
            carriers,
            connectors,
            pinned_connectors,
            rotation_lock: Mutex::new(()),
            active_rotation: Mutex::new(active_rotation),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.carriers.len()
    }

    pub(crate) fn get(&self, index: usize) -> Option<&HeldCarrier> {
        self.carriers.get(index)
    }

    pub(crate) fn index_of(&self, carrier: &HeldCarrier) -> Option<usize> {
        self.carriers
            .iter()
            .position(|held| std::ptr::eq(held, carrier))
    }

    /// The primary pin (the profile's `relay_server`).
    pub(crate) fn primary(&self) -> &HeldCarrier {
        &self.carriers[0]
    }

    /// Every exact pin, in profile order: what the leak guard arms.
    pub(crate) fn pins(&self) -> Vec<SocketAddr> {
        self.carriers.iter().map(HeldCarrier::peer).collect()
    }

    /// Pins with the exact same signed ECH authority and list. A same-name
    /// direct pin without ECH is intentionally excluded.
    fn same_rotation_scope(&self, index: usize) -> impl Iterator<Item = &HeldCarrier> {
        let scope = self
            .carriers
            .get(index)
            .and_then(|held| held.rotation_scope.clone());
        self.carriers
            .iter()
            .filter(move |held| scope.is_some() && held.rotation_scope == scope)
    }

    /// Publish one complete connector generation. A dial already holding an
    /// older connector may finish its authenticated handshake, but a new dial
    /// cannot observe only some pins of a rotated TLS name.
    fn publish(&self, generation: Vec<TlsConnector>) {
        *self
            .connectors
            .write()
            .unwrap_or_else(PoisonError::into_inner) = generation;
    }

    fn restore_pinned_name(&self, index: usize) {
        let indices: Vec<usize> = self
            .same_rotation_scope(index)
            .map(|held| held.index)
            .collect();
        let mut generation = self
            .connectors
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for index in indices {
            generation[index] = self.pinned_connectors[index].clone();
        }
        self.publish(generation);
        let mut active = self
            .active_rotation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for carrier in self.same_rotation_scope(index) {
            active[carrier.index] = None;
        }
    }

    /// D2: inspect pin `index`'s failed outer handshake. Admitted retry
    /// configs rebuild the connector of every pin with that TLS name.
    pub(crate) fn ech_rejected(
        &self,
        index: usize,
        error: &(dyn std::error::Error + 'static),
        outer_ca: &[u8],
    ) -> EchRedial {
        use aegis_client::ech_policy::{record_rejection_with_token, EchRejection};
        let Some(held) = self.carriers.get(index) else {
            return EchRedial::NotEch;
        };
        let _rotation = self
            .rotation_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (rejection, token) = record_rejection_with_token(&held.relay, error);
        match rejection {
            EchRejection::NotEch => EchRedial::NotEch,
            EchRejection::Refused => EchRedial::Refused,
            EchRejection::RetryAdmitted => {
                let Some(token) = token else {
                    return EchRedial::Refused;
                };
                let mut generation = self
                    .connectors
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                for carrier in self.same_rotation_scope(index) {
                    let Ok(connector) =
                        aegis_client::prepared_outer_tls::explicit_h2_connector_from_pem(
                            &carrier.relay,
                            outer_ca,
                        )
                    else {
                        aegis_client::ech_policy::forget_rotation_if_current(&held.relay, token);
                        self.restore_pinned_name(index);
                        return EchRedial::Refused;
                    };
                    generation[carrier.index] = connector;
                }
                if !aegis_client::ech_policy::rotation_is_current(&held.relay, token) {
                    self.restore_pinned_name(index);
                    return EchRedial::Refused;
                }
                self.publish(generation);
                let mut active = self
                    .active_rotation
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                for carrier in self.same_rotation_scope(index) {
                    active[carrier.index] = Some(token);
                }
                EchRedial::Redial
            }
        }
    }

    /// D2: the redial with admitted retry configs was itself refused: drop
    /// the rotation and return every pin of that TLS name to its pinned
    /// list.
    pub(crate) fn forget_rotation(&self, index: usize, _outer_ca: &[u8]) {
        let Some(held) = self.carriers.get(index) else {
            return;
        };
        let _rotation = self
            .rotation_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(token) = self
            .active_rotation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)[index]
        {
            aegis_client::ech_policy::forget_rotation_if_current(&held.relay, token);
        }
        self.restore_pinned_name(index);
    }

    /// Whether pin `index` dials with an admitted rotation now.
    #[cfg(test)]
    pub(crate) fn has_rotation(&self, index: usize) -> bool {
        self.carriers
            .get(index)
            .is_some_and(|held| aegis_client::ech_policy::has_rotation(&held.relay))
    }
}

#[cfg(test)]
#[path = "carrier_pool_tests.rs"]
mod tests;
