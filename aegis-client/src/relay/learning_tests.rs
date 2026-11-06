use super::*;
use aegis_core::signals::FailSignal;
use std::time::Duration;

fn outcome(result: &anyhow::Result<()>, sent: u64, received: u64) -> RelayOutcome {
    RelayOutcome::from_attempt(
        TunnelTransportFamily::GrpcStream,
        result,
        sent,
        received,
        Duration::from_millis(20),
        Duration::from_secs(1),
    )
}

#[test]
fn relay_empty_success_is_typed_neutral_without_response() {
    let empty = outcome(&Ok(()), 0, 0);
    assert_eq!(
        empty.learning,
        RelayLearningDisposition::NoApplicationTraffic
    );
    assert!(empty.learning_signal().is_none());
    assert_eq!(empty.signal, FailSignal::Unknown);
    assert!(!empty.signal.is_success());
    assert_eq!(
        RelayTcpCompletion::from_result(&Ok(()), Some(&empty)).reason(),
        "no_response_observed"
    );
}

#[test]
fn relay_genuine_errors_remain_recordable() {
    for (kind, expected) in [
        (
            std::io::ErrorKind::ConnectionRefused,
            FailSignal::RemoteRefused,
        ),
        (
            std::io::ErrorKind::ConnectionReset,
            FailSignal::HandshakeMismatch,
        ),
        (std::io::ErrorKind::TimedOut, FailSignal::HandshakeMismatch),
        (std::io::ErrorKind::BrokenPipe, FailSignal::LocalIoError),
    ] {
        let result = Err(anyhow::Error::new(std::io::Error::from(kind)));
        let failed = outcome(&result, 0, 0);
        assert_eq!(failed.learning, RelayLearningDisposition::Recordable);
        assert_eq!(failed.learning_signal(), Some(&expected));
        assert_eq!(
            RelayTcpCompletion::from_result(&result, Some(&failed)),
            RelayTcpCompletion::Failed
        );
    }
    let l7 = outcome(
        &Err(anyhow::anyhow!("synthetic tunnel upgrade rejection")),
        0,
        0,
    );
    assert_eq!(l7.learning_signal(), Some(&FailSignal::HandshakeMismatch));
}

#[test]
fn relay_response_and_sent_request_stall_remain_recordable() {
    for sent in [0, 7] {
        let response = outcome(&Ok(()), sent, 9);
        assert_eq!(response.learning_signal(), Some(&FailSignal::Success));
        assert_eq!(
            RelayTcpCompletion::from_result(&Ok(()), Some(&response)),
            RelayTcpCompletion::ResponseObserved
        );
    }
    let stall = outcome(&Ok(()), 7, 0);
    assert_eq!(
        stall.learning_signal(),
        Some(&FailSignal::SessionFreeze {
            bytes_before_stall: 7
        })
    );
    assert_eq!(
        RelayTcpCompletion::from_result(&Ok(()), Some(&stall)).reason(),
        "no_response_observed"
    );
}

#[test]
fn relay_partial_send_error_remains_recordable() {
    let result = Err(anyhow::Error::new(std::io::Error::from(
        std::io::ErrorKind::ConnectionReset,
    )));
    let partial = outcome(&result, 3, 0);
    assert_eq!(partial.bytes_sent, 3);
    assert_eq!(
        partial.learning_signal(),
        Some(&FailSignal::HandshakeMismatch)
    );
    let response_then_reset = outcome(&result, 3, 9);
    assert_eq!(
        response_then_reset.learning_signal(),
        Some(&FailSignal::RemoteReset)
    );
    assert_eq!(response_then_reset.bytes_received_observed, 9);
}
