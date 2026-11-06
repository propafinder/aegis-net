//! Shared content-free error classification and explicit diagnostic chain helper.
#[derive(Debug)]
pub struct ProfileCommandFailure {
    pub kind: &'static str,
    pub message: String,
}

impl std::fmt::Display for ProfileCommandFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProfileCommandFailure {}
pub fn direct_io_error_kind_code(err: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;

    match err.kind() {
        ErrorKind::NotFound => "not_found",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "addr_in_use",
        ErrorKind::AddrNotAvailable => "addr_not_available",
        ErrorKind::NetworkUnreachable => "network_unreachable",
        ErrorKind::HostUnreachable => "host_unreachable",
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::AlreadyExists => "already_exists",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::NotADirectory => "not_a_directory",
        ErrorKind::IsADirectory => "is_a_directory",
        ErrorKind::DirectoryNotEmpty => "directory_not_empty",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::TimedOut => "timed_out",
        ErrorKind::WriteZero => "write_zero",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    }
}

pub fn io_error_kind_code(err: &std::io::Error) -> &'static str {
    let outer = direct_io_error_kind_code(err);
    if outer != "other" {
        return outer;
    }

    let mut source = err
        .get_ref()
        .map(|cause| cause as &(dyn std::error::Error + 'static));
    while let Some(cause) = source {
        if cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
        {
            return "timed_out";
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            let code = direct_io_error_kind_code(io);
            if code != "other" {
                return code;
            }
        }
        source = cause.source();
    }
    outer
}

pub fn anyhow_error_kind_code(err: &anyhow::Error) -> Option<&'static str> {
    let mut fallback = None;
    for cause in err.chain() {
        if let Some(profile) = cause.downcast_ref::<ProfileCommandFailure>() {
            return Some(profile.kind);
        }
        if cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
        {
            return Some("timed_out");
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            let code = io_error_kind_code(io);
            if code != "other" {
                return Some(code);
            }
            fallback = Some(code);
        }
        // io::Error::source can expose the wrapped error's source rather than
        // the wrapped error itself; inspect a generic IO payload explicitly.
        let quic = cause.downcast_ref::<quinn::ConnectionError>().or_else(|| {
            cause
                .downcast_ref::<std::io::Error>()?
                .get_ref()?
                .downcast_ref::<quinn::ConnectionError>()
        });
        if let Some(quic) = quic {
            match quic {
                quinn::ConnectionError::TimedOut => return Some("quic_timed_out"),
                quinn::ConnectionError::ConnectionClosed(close)
                    if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
                {
                    // A responding QUIC peer rejected this protocol opening.
                    // Keep it separate from TCP reachability/short-circuit kinds.
                    return Some("quic_connection_refused");
                }
                _ => {}
            }
        }
    }
    fallback
}

pub fn anyhow_error_chain_messages(err: &anyhow::Error) -> Vec<String> {
    err.chain().map(ToString::to_string).collect()
}
