//! TCP pre-authentication fairness keyed only by the kernel's socket peer IP.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

const MAX_TRACKED_PEERS: usize = 4096;

#[derive(Clone)]
pub(crate) struct SocketAdmissionLimiter {
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
    maximum: usize,
}

pub(crate) struct SocketAdmissionPermit {
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
}

impl SocketAdmissionLimiter {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            maximum,
        }
    }

    pub(crate) fn try_acquire(&self, peer: IpAddr) -> Option<SocketAdmissionPermit> {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if !peers.contains_key(&peer) && peers.len() >= MAX_TRACKED_PEERS {
            return None;
        }
        let count = peers.entry(peer).or_default();
        if *count >= self.maximum {
            return None;
        }
        *count += 1;
        Some(SocketAdmissionPermit {
            peers: self.peers.clone(),
            peer,
        })
    }
}

impl Drop for SocketAdmissionPermit {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = peers.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&self.peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_preauth_socket_quota_reclaims_peer_counts_and_preserves_other_peers() {
        let limiter = SocketAdmissionLimiter::new(2);
        let first = "192.0.2.1".parse().unwrap();
        let second = "192.0.2.2".parse().unwrap();
        let one = limiter.try_acquire(first).unwrap();
        let two = limiter.try_acquire(first).unwrap();
        assert!(limiter.try_acquire(first).is_none());
        let other = limiter.try_acquire(second).unwrap();
        drop(one);
        assert!(limiter.try_acquire(first).is_some());
        drop(two);
        drop(other);
        assert!(limiter.peers.lock().unwrap().is_empty());
    }

    #[test]
    fn relay_preauth_socket_quota_bounds_map_cardinality() {
        let limiter = SocketAdmissionLimiter::new(1);
        let held = (0..MAX_TRACKED_PEERS)
            .map(|index| {
                limiter
                    .try_acquire(IpAddr::V4((0xc0000000 + index as u32).into()))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(limiter
            .try_acquire("198.51.100.1".parse().unwrap())
            .is_none());
        assert_eq!(limiter.peers.lock().unwrap().len(), MAX_TRACKED_PEERS);
        drop(held);
        assert!(limiter.peers.lock().unwrap().is_empty());
        assert!(limiter
            .try_acquire("198.51.100.1".parse().unwrap())
            .is_some());
    }

    #[test]
    fn relay_preauth_socket_proof_releases_quota_once_for_all_request_clones() {
        let limiter = SocketAdmissionLimiter::new(1);
        let peer = "192.0.2.1".parse().unwrap();
        let budget = super::super::AdmissionBudget::new(std::time::Duration::from_secs(1))
            .with_socket_permit(limiter.try_acquire(peer).unwrap());
        let request = budget.clone();
        assert!(limiter.try_acquire(peer).is_none());
        request.authenticated().unwrap();
        let next = limiter.try_acquire(peer).unwrap();
        budget.authenticated().unwrap();
        assert!(
            limiter.try_acquire(peer).is_none(),
            "proof cannot release another socket's slot"
        );
        drop(next);
        assert!(limiter.try_acquire(peer).is_some());
    }
}
