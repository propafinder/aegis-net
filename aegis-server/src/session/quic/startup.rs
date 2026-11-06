//! Internal startup reports contain static phases and typed I/O kinds only.
//! They never format the original error, credentials, paths or listener address.
use std::{fmt, io};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Phase {
    Policy,
    Address,
    Tls,
    Transport,
    UdpBind,
    Endpoint,
    Unreported,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Address => "address",
            Self::Tls => "tls",
            Self::Transport => "transport",
            Self::UdpBind => "udp_bind",
            Self::Endpoint => "endpoint",
            Self::Unreported => "unreported",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Failure {
    phase: Phase,
    io_kind: Option<io::ErrorKind>,
}

impl Failure {
    pub(crate) fn unreported() -> Self {
        Self {
            phase: Phase::Unreported,
            io_kind: None,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "phase={} io_kind={:?}", self.phase.label(), self.io_kind)
    }
}

pub(crate) enum Readiness {
    Unit(oneshot::Sender<()>),
    Report(oneshot::Sender<Result<(), Failure>>),
}

pub(super) struct Reporter(Option<Readiness>);

impl Reporter {
    pub(super) fn new(ready: Option<Readiness>) -> Self {
        Self(ready)
    }

    pub(super) fn check<T>(
        &mut self,
        result: anyhow::Result<T>,
        phase: Phase,
    ) -> anyhow::Result<T> {
        result.inspect_err(|error| {
            let failure = Failure {
                phase,
                io_kind: error.downcast_ref::<io::Error>().map(io::Error::kind),
            };
            // Unit callers retain their original closed-channel failure API.
            // No task wait, retry, fallback or new startup clock is introduced.
            if let Some(Readiness::Report(sender)) = self.0.take() {
                let _ = sender.send(Err(failure));
            }
        })
    }

    pub(super) fn success(mut self) {
        match self.0.take() {
            Some(Readiness::Unit(sender)) => {
                let _ = sender.send(());
            }
            Some(Readiness::Report(sender)) => {
                let _ = sender.send(Ok(()));
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn report_preserves_original_error_identity_and_omits_private_error_text() {
        let (tx, rx) = oneshot::channel();
        let mut reporter = Reporter::new(Some(Readiness::Report(tx)));
        let error = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private-path-key-token-address",
        );
        let original = reporter
            .check::<()>(Err(error.into()), Phase::Tls)
            .unwrap_err();
        assert_eq!(
            original.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let report = rx.await.unwrap().unwrap_err().to_string();
        assert_eq!(report, "phase=tls io_kind=Some(PermissionDenied)");
        assert!(!report.contains("private-path-key-token-address"));
    }

    #[tokio::test]
    async fn legacy_unit_ready_stays_closed_on_failure_and_opens_only_on_success() {
        let (tx, rx) = oneshot::channel();
        let mut reporter = Reporter::new(Some(Readiness::Unit(tx)));
        assert!(reporter
            .check::<()>(Err(anyhow::anyhow!("private error")), Phase::Endpoint)
            .is_err());
        assert!(rx.await.is_err());
        let (tx, rx) = oneshot::channel();
        Reporter::new(Some(Readiness::Unit(tx))).success();
        rx.await.unwrap();
        let (tx, rx) = oneshot::channel();
        Reporter::new(Some(Readiness::Report(tx))).success();
        assert!(rx.await.unwrap().is_ok());
    }
}
