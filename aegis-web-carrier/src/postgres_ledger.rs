//! Durable session fencing using a dedicated PostgreSQL database. The table
//! contains only random session IDs, owner tokens, sequence numbers and expiry.
use crate::{rejected, LedgerFuture, SessionLedger};
use std::{io, time::Duration};
use tokio::sync::Mutex;
use tokio_postgres::Client;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS aegis_web_session_ledger (\
    id BYTEA PRIMARY KEY CHECK (octet_length(id) = 32), \
    owner BYTEA NOT NULL CHECK (octet_length(owner) = 8), \
    next BIGINT NOT NULL CHECK (next > 0), \
    expires_ms BIGINT NOT NULL, \
    released BOOLEAN NOT NULL DEFAULT FALSE)";
const CONFIG_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS aegis_web_session_ledger_config (\
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), \
    max_claims BIGINT NOT NULL, max_ttl_ms BIGINT NOT NULL)";
const CLOCK_MS: &str = "(extract(epoch from clock_timestamp()) * 1000)::bigint";
const MAX_RETAINED_IDS: i64 = 1_048_576;

/// A dedicated database must be shared by all carrier replicas. Callers own
/// the client's connection task and should use TLS for a remote database.
pub struct PostgresSessionLedger {
    client: Mutex<Client>,
    max_claims: i64,
    operation_timeout: Duration,
    max_ttl_ms: i64,
}

impl PostgresSessionLedger {
    /// Initializes the schema. A lost or ambiguous operation always rejects;
    /// retrying a claim can then only encounter the earlier committed claim.
    pub async fn new(
        client: Client,
        max_claims: usize,
        operation_timeout: Duration,
        max_ttl: Duration,
    ) -> io::Result<Self> {
        let max_claims = i64::try_from(max_claims).map_err(|_| rejected())?;
        let max_ttl_ms = i64::try_from(max_ttl.as_millis()).map_err(|_| rejected())?;
        if max_claims == 0
            || max_claims > 1_048_576
            || operation_timeout.is_zero()
            || operation_timeout > Duration::from_secs(30)
            || max_ttl_ms == 0
            || max_ttl_ms > 3_600_000
        {
            return Err(rejected());
        }
        tokio::time::timeout(operation_timeout, client.batch_execute(SCHEMA))
            .await
            .map_err(|_| rejected())?
            .map_err(|_| rejected())?;
        tokio::time::timeout(
            operation_timeout,
            client.batch_execute("ALTER TABLE aegis_web_session_ledger ADD COLUMN IF NOT EXISTS released BOOLEAN NOT NULL DEFAULT FALSE"),
        )
        .await
        .map_err(|_| rejected())?
        .map_err(|_| rejected())?;
        tokio::time::timeout(operation_timeout, client.batch_execute(CONFIG_SCHEMA))
            .await
            .map_err(|_| rejected())?
            .map_err(|_| rejected())?;
        tokio::time::timeout(
            operation_timeout,
            client.execute(
                "INSERT INTO aegis_web_session_ledger_config (singleton, max_claims, max_ttl_ms) VALUES (TRUE, $1, $2) ON CONFLICT (singleton) DO NOTHING",
                &[&max_claims, &max_ttl_ms],
            ),
        )
        .await
        .map_err(|_| rejected())?
        .map_err(|_| rejected())?;
        let row = tokio::time::timeout(
            operation_timeout,
            client.query_one(
                "SELECT max_claims, max_ttl_ms FROM aegis_web_session_ledger_config WHERE singleton = TRUE",
                &[],
            ),
        )
        .await
        .map_err(|_| rejected())?
        .map_err(|_| rejected())?;
        if row.get::<_, i64>(0) != max_claims || row.get::<_, i64>(1) != max_ttl_ms {
            return Err(rejected());
        }
        Ok(Self {
            client: Mutex::new(client),
            max_claims,
            operation_timeout,
            max_ttl_ms,
        })
    }

    async fn claim_inner(&self, id: [u8; 32], owner: u64, expires_ms: u64) -> io::Result<()> {
        let expiry = i64::try_from(expires_ms).map_err(|_| rejected())?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(|_| rejected())?;
        // All claimers in this dedicated database serialize capacity and
        // cleanup, including claimers attached to a different replica.
        transaction
            .execute("SELECT pg_advisory_xact_lock(1095069037)", &[])
            .await
            .map_err(|_| rejected())?;
        transaction
            .execute(
                &format!("DELETE FROM aegis_web_session_ledger WHERE expires_ms <= {CLOCK_MS}"),
                &[],
            )
            .await
            .map_err(|_| rejected())?;
        let row = transaction
            .query_one(
                &format!("SELECT {CLOCK_MS}, count(*) FILTER (WHERE NOT released), count(*) FROM aegis_web_session_ledger"),
                &[],
            )
            .await
            .map_err(|_| rejected())?;
        let db_now: i64 = row.get(0);
        let count: i64 = row.get(1);
        let retained: i64 = row.get(2);
        // The source clock may differ slightly from PostgreSQL. A bounded
        // margin allows that skew while the database enforces actual expiry.
        if expiry <= db_now
            || expiry.saturating_sub(db_now) > self.max_ttl_ms.saturating_add(30_000)
            || count >= self.max_claims
            || retained >= MAX_RETAINED_IDS
        {
            return Err(rejected());
        }
        transaction
            .execute(
                "INSERT INTO aegis_web_session_ledger (id, owner, next, expires_ms) VALUES ($1, $2, 1, $3)",
                &[&&id[..], &&owner.to_be_bytes()[..], &expiry],
            )
            .await
            .map_err(|_| rejected())?;
        transaction.commit().await.map_err(|_| rejected())
    }

    async fn verify_inner(&self, id: [u8; 32], owner: u64, next: u64) -> io::Result<()> {
        let next = i64::try_from(next).map_err(|_| rejected())?;
        let client = self.client.lock().await;
        let row = client
            .query_opt(
                &format!("SELECT 1 FROM aegis_web_session_ledger WHERE id = $1 AND owner = $2 AND next = $3 AND expires_ms > {CLOCK_MS} AND NOT released"),
                &[&&id[..], &&owner.to_be_bytes()[..], &next],
            )
            .await
            .map_err(|_| rejected())?;
        if row.is_some() {
            Ok(())
        } else {
            Err(rejected())
        }
    }

    async fn advance_inner(&self, id: [u8; 32], owner: u64, expected_next: u64) -> io::Result<()> {
        let next = i64::try_from(expected_next).map_err(|_| rejected())?;
        if next == i64::MAX {
            return Err(rejected());
        }
        let client = self.client.lock().await;
        let changed = client
            .execute(
                &format!("UPDATE aegis_web_session_ledger SET next = next + 1 WHERE id = $1 AND owner = $2 AND next = $3 AND expires_ms > {CLOCK_MS} AND NOT released"),
                &[&&id[..], &&owner.to_be_bytes()[..], &next],
            )
            .await
            .map_err(|_| rejected())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(rejected())
        }
    }

    async fn release_inner(&self, id: [u8; 32], owner: u64) -> io::Result<()> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(|_| rejected())?;
        transaction
            .execute("SELECT pg_advisory_xact_lock(1095069037)", &[])
            .await
            .map_err(|_| rejected())?;
        let changed = transaction
            .execute(
                "UPDATE aegis_web_session_ledger SET released = TRUE WHERE id = $1 AND owner = $2 AND NOT released",
                &[&&id[..], &&owner.to_be_bytes()[..]],
            )
            .await
            .map_err(|_| rejected())?;
        if changed != 1 {
            return Err(rejected());
        }
        transaction.commit().await.map_err(|_| rejected())
    }
}

impl SessionLedger for PostgresSessionLedger {
    fn claim<'a>(&'a self, id: [u8; 32], owner: u64, expires_ms: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(
                self.operation_timeout,
                self.claim_inner(id, owner, expires_ms),
            )
            .await
            .map_err(|_| rejected())?
        })
    }

    fn verify<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(self.operation_timeout, self.verify_inner(id, owner, next))
                .await
                .map_err(|_| rejected())?
        })
    }

    fn advance<'a>(&'a self, id: [u8; 32], owner: u64, expected_next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(
                self.operation_timeout,
                self.advance_inner(id, owner, expected_next),
            )
            .await
            .map_err(|_| rejected())?
        })
    }

    fn release<'a>(&'a self, id: [u8; 32], owner: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(self.operation_timeout, self.release_inner(id, owner))
                .await
                .map_err(|_| rejected())?
        })
    }
}
