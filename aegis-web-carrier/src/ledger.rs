//! Atomic session fencing for an optional shared store. Implementations must
//! make each operation linearizable for one session ID. Claims survive an
//! instance crash until expiry, but a known closed session releases active
//! capacity while its ID remains a bounded tombstone until expiry.
use crate::rejected;
use std::{collections::HashMap, future::Future, io, pin::Pin, sync::Mutex};

pub type LedgerFuture<'a> = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

/// An external implementation may use a Firestore transaction or equivalent
/// compare-and-set. It must reject unavailable/ambiguous outcomes, stale
/// owners, expired claims, and duplicate advances. This is a fencing contract,
/// not a way to migrate the in-process application stream to another instance.
pub trait SessionLedger: Send + Sync {
    fn claim<'a>(&'a self, id: [u8; 32], owner: u64, expires_ms: u64) -> LedgerFuture<'a>;
    fn verify<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a>;
    fn advance<'a>(&'a self, id: [u8; 32], owner: u64, expected_next: u64) -> LedgerFuture<'a>;
    /// Retire only this owner's active claim. The ID remains fenced until its
    /// original expiry; a stale owner cannot free another session's capacity.
    fn release<'a>(&'a self, id: [u8; 32], owner: u64) -> LedgerFuture<'a>;
}

/// Local implementation used by the standalone carrier. Sharing one instance
/// among two `Server`s exercises the contract but is not durable service state.
pub struct InMemorySessionLedger {
    claims: Mutex<HashMap<[u8; 32], Claim>>,
    max_claims: usize,
}

const MAX_RETAINED_IDS: usize = 1_048_576;

impl Default for InMemorySessionLedger {
    fn default() -> Self {
        Self {
            claims: Mutex::new(HashMap::new()),
            max_claims: 4096,
        }
    }
}

impl InMemorySessionLedger {
    /// A full ledger rejects new sessions until old claims expire.
    pub fn with_capacity(max_claims: usize) -> io::Result<Self> {
        if max_claims == 0 {
            return Err(rejected());
        }
        Ok(Self {
            claims: Mutex::new(HashMap::new()),
            max_claims,
        })
    }
}

#[derive(Clone, Copy)]
struct Claim {
    owner: u64,
    next: u64,
    expires_ms: u64,
    released: bool,
}

impl SessionLedger for InMemorySessionLedger {
    fn claim<'a>(&'a self, id: [u8; 32], owner: u64, expires_ms: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            let now = crate::settings::now_ms()?;
            if expires_ms <= now {
                return Err(rejected());
            }
            let mut claims = self.claims.lock().map_err(|_| rejected())?;
            claims.retain(|_, claim| claim.expires_ms > now);
            if claims.contains_key(&id)
                || claims.len() >= MAX_RETAINED_IDS
                || claims.values().filter(|claim| !claim.released).count() >= self.max_claims
            {
                return Err(rejected());
            }
            claims.insert(
                id,
                Claim {
                    owner,
                    next: 1,
                    expires_ms,
                    released: false,
                },
            );
            Ok(())
        })
    }

    fn verify<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            let now = crate::settings::now_ms()?;
            let claims = self.claims.lock().map_err(|_| rejected())?;
            match claims.get(&id) {
                Some(claim)
                    if claim.owner == owner
                        && claim.next == next
                        && claim.expires_ms > now
                        && !claim.released =>
                {
                    Ok(())
                }
                _ => Err(rejected()),
            }
        })
    }

    fn advance<'a>(&'a self, id: [u8; 32], owner: u64, expected_next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            let now = crate::settings::now_ms()?;
            let mut claims = self.claims.lock().map_err(|_| rejected())?;
            match claims.get_mut(&id) {
                Some(claim)
                    if claim.owner == owner
                        && claim.next == expected_next
                        && claim.expires_ms > now
                        && !claim.released =>
                {
                    claim.next = expected_next.checked_add(1).ok_or_else(rejected)?;
                    Ok(())
                }
                _ => Err(rejected()),
            }
        })
    }

    fn release<'a>(&'a self, id: [u8; 32], owner: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            let mut claims = self.claims.lock().map_err(|_| rejected())?;
            match claims.get_mut(&id) {
                Some(claim) if claim.owner == owner && !claim.released => {
                    claim.released = true;
                    Ok(())
                }
                _ => Err(rejected()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_claims_refuse_new_ids_and_sequence_replay() {
        let ledger = InMemorySessionLedger::with_capacity(1).unwrap();
        let expires = crate::settings::now_ms().unwrap() + 60_000;
        ledger.claim([1; 32], 7, expires).await.unwrap();
        assert!(ledger.claim([1; 32], 8, expires).await.is_err());
        assert!(ledger.claim([2; 32], 8, expires).await.is_err());
        ledger.verify([1; 32], 7, 1).await.unwrap();
        ledger.advance([1; 32], 7, 1).await.unwrap();
        assert!(ledger.advance([1; 32], 7, 1).await.is_err());
        assert!(ledger.verify([1; 32], 8, 2).await.is_err());
        ledger.verify([1; 32], 7, 2).await.unwrap();
    }

    #[tokio::test]
    async fn owner_release_reclaims_capacity_and_revokes_sequence() {
        let ledger = InMemorySessionLedger::with_capacity(1).unwrap();
        let expires = crate::settings::now_ms().unwrap() + 60_000;
        ledger.claim([1; 32], 7, expires).await.unwrap();
        ledger.release([1; 32], 7).await.unwrap();
        assert!(ledger.claim([1; 32], 9, expires).await.is_err());
        assert!(ledger.verify([1; 32], 7, 1).await.is_err());
        assert!(ledger.advance([1; 32], 7, 1).await.is_err());
        ledger.claim([2; 32], 8, expires).await.unwrap();
        assert!(ledger.release([2; 32], 7).await.is_err());
        ledger.verify([2; 32], 8, 1).await.unwrap();
    }
}
