//! Owned HTTPS deferred request/reply bytes. Admission never grants egress.
//! Feed every accepted stream into the existing device mTLS and lease handler.
//! This is not Huma wire compatibility or a browser-unobservability claim.
mod client;
mod ledger;
mod postgres_ledger;
mod protocol;
mod server;
mod settings;

pub use client::{Client, WebStream};
pub use ledger::{InMemorySessionLedger, LedgerFuture, SessionLedger};
pub use postgres_ledger::PostgresSessionLedger;
pub use server::{AcceptedSession, ApplicationStream, AuthenticationHandle, Server, ServerStats};
pub use settings::{ClientSettings, Credential, Descriptor, Limits, ServerSettings, KEY_HEADER};

use std::{io, sync::Arc};
use tokio::sync::watch;

fn rejected() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "web carrier rejected")
}
fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "web carrier ended")
}
fn convert(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    // Deliberately do not include request headers, identifiers or credentials.
    let _ = error;
    failed()
}

/// Explicit cancellation shared with owned server and client tasks.
#[derive(Clone)]
pub struct Cancellation(Arc<watch::Sender<bool>>);
impl Default for Cancellation {
    fn default() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }
}
impl Cancellation {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    pub(crate) async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow_and_update() {
                return;
            }
        }
    }
}
