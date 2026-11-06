//! Privacy-bounded operational logging for the relay runtime.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

/// Immutable logging policy copied into each server runtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationalLogPolicy {
    include_sensitive_context: bool,
}

impl OperationalLogPolicy {
    pub(crate) const fn new(include_sensitive_context: bool) -> Self {
        Self {
            include_sensitive_context,
        }
    }

    pub(crate) const fn includes_sensitive_context(self) -> bool {
        self.include_sensitive_context
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FailureStage {
    ConnectionAdmission,
    GrpcRequest,
    H2RequestTask,
    TcpSession,
    TlsHandshake,
    TcpSessionTask,
    QuicSession,
    QuicConnection,
    QuicIncoming,
    TargetPolicy,
    RateLimit,
}

impl FailureStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionAdmission => "connection_admission",
            Self::GrpcRequest => "grpc_request",
            Self::H2RequestTask => "h2_request_task",
            Self::TcpSession => "tcp_session",
            Self::TlsHandshake => "tls_handshake",
            Self::TcpSessionTask => "tcp_session_task",
            Self::QuicSession => "quic_session",
            Self::QuicConnection => "quic_connection",
            Self::QuicIncoming => "quic_incoming",
            Self::TargetPolicy => "target_policy",
            Self::RateLimit => "rate_limit",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FailureReason {
    Capacity,
    RequestFailed,
    TaskFailed,
    HandshakeFailed,
    ConnectionFailed,
    PolicyDenied,
    PartialDnsDenial,
    AuthFailureLimit,
}

impl FailureReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Capacity => "capacity",
            Self::RequestFailed => "request_failed",
            Self::TaskFailed => "task_failed",
            Self::HandshakeFailed => "handshake_failed",
            Self::ConnectionFailed => "connection_failed",
            Self::PolicyDenied => "policy_denied",
            Self::PartialDnsDenial => "partial_dns_denial",
            Self::AuthFailureLimit => "auth_failure_limit",
        }
    }
}

/// Emit a stable operational failure. The default path never formats the
/// supplied error or peer. `RUST_LOG` can select severity but cannot change
/// this policy branch.
pub(crate) fn warn_failure(
    policy: OperationalLogPolicy,
    stage: FailureStage,
    reason: FailureReason,
    peer: Option<SocketAddr>,
    error: &impl fmt::Display,
) {
    if policy.includes_sensitive_context() {
        if let Some(peer) = peer {
            tracing::warn!(
                event_code = "server_operation_failed",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                %peer,
                "server operation failed: {error:#}"
            );
        } else {
            tracing::warn!(
                event_code = "server_operation_failed",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                "server operation failed: {error:#}"
            );
        }
    } else {
        tracing::warn!(
            event_code = "server_operation_failed",
            failure_stage = stage.as_str(),
            reason_code = reason.as_str(),
            "server operation failed"
        );
    }
}

pub(crate) fn warn_counted(
    policy: OperationalLogPolicy,
    stage: FailureStage,
    reason: FailureReason,
    peer: Option<SocketAddr>,
    affected: usize,
    detail: &impl fmt::Display,
) {
    if policy.includes_sensitive_context() {
        if let Some(peer) = peer {
            tracing::warn!(
                event_code = "server_operation_counted",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                affected,
                %peer,
                "server operation counted: {detail}"
            );
        } else {
            tracing::warn!(
                event_code = "server_operation_counted",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                affected,
                "server operation counted: {detail}"
            );
        }
    } else {
        tracing::warn!(
            event_code = "server_operation_counted",
            failure_stage = stage.as_str(),
            reason_code = reason.as_str(),
            affected,
            "server operation counted"
        );
    }
}

pub(crate) fn error_failure(
    policy: OperationalLogPolicy,
    stage: FailureStage,
    reason: FailureReason,
    peer: Option<SocketAddr>,
    error: &impl fmt::Display,
) {
    if policy.includes_sensitive_context() {
        if let Some(peer) = peer {
            tracing::error!(
                event_code = "server_operation_failed",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                %peer,
                "server operation failed: {error:#}"
            );
        } else {
            tracing::error!(
                event_code = "server_operation_failed",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                "server operation failed: {error:#}"
            );
        }
    } else {
        tracing::error!(
            event_code = "server_operation_failed",
            failure_stage = stage.as_str(),
            reason_code = reason.as_str(),
            "server operation failed"
        );
    }
}

pub(crate) fn warn_optional_quic_unavailable(
    policy: OperationalLogPolicy,
    detail: &impl fmt::Display,
) {
    if policy.includes_sensitive_context() {
        tracing::warn!(
            event_code = "server_optional_quic_unavailable",
            "serving TCP only; optional QUIC did not bind: {detail:#}"
        );
    } else {
        tracing::warn!(
            event_code = "server_optional_quic_unavailable",
            "serving TCP only; optional QUIC did not bind"
        );
    }
}

pub(crate) fn warn_quic_shutdown_result(
    policy: OperationalLogPolicy,
    result: &Result<anyhow::Result<()>, tokio::task::JoinError>,
) {
    let error: &dyn fmt::Display = match result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => error,
        Err(error) => error,
    };
    warn_failure(
        policy,
        FailureStage::QuicSession,
        FailureReason::TaskFailed,
        None,
        &error,
    );
}

pub(crate) fn debug_failure(
    policy: OperationalLogPolicy,
    stage: FailureStage,
    reason: FailureReason,
    peer: Option<SocketAddr>,
    error: &impl fmt::Display,
) {
    if policy.includes_sensitive_context() {
        if let Some(peer) = peer {
            tracing::debug!(
                event_code = "server_operation_debug",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                %peer,
                "server operation debug: {error:#}"
            );
        } else {
            tracing::debug!(
                event_code = "server_operation_debug",
                failure_stage = stage.as_str(),
                reason_code = reason.as_str(),
                "server operation debug: {error:#}"
            );
        }
    } else {
        tracing::debug!(
            event_code = "server_operation_debug",
            failure_stage = stage.as_str(),
            reason_code = reason.as_str(),
            "server operation debug"
        );
    }
}

pub(crate) fn debug_peer_event(
    policy: OperationalLogPolicy,
    event_code: &'static str,
    peer: SocketAddr,
    message: &'static str,
) {
    if policy.includes_sensitive_context() {
        tracing::debug!(event_code, %peer, "{message}");
    } else {
        tracing::debug!(event_code, "{message}");
    }
}

pub(crate) fn debug_peer_identity_event(
    policy: OperationalLogPolicy,
    event_code: &'static str,
    peer: SocketAddr,
    identity: std::net::IpAddr,
    message: &'static str,
) {
    if policy.includes_sensitive_context() {
        tracing::debug!(event_code, %peer, %identity, "{message}");
    } else {
        tracing::debug!(event_code, "{message}");
    }
}

pub(crate) fn debug_bundle_rejected(
    policy: OperationalLogPolicy,
    event_code: &'static str,
    peer: SocketAddr,
    status: u16,
    reason_category: &'static str,
    error: &impl fmt::Display,
) {
    if policy.includes_sensitive_context() {
        tracing::debug!(
            event_code,
            %peer,
            status,
            reason_category,
            "bundle request rejected; serving decoy: {error:#}"
        );
    } else {
        tracing::debug!(
            event_code,
            status,
            reason_category,
            "bundle request rejected; serving decoy"
        );
    }
}

pub(crate) fn info_bundle_redeemed(
    policy: OperationalLogPolicy,
    peer: SocketAddr,
    bundle_path: &Path,
    bytes: usize,
) {
    if policy.includes_sensitive_context() {
        tracing::info!(event_code = "bundle_redeemed", %peer, bundle_path = %bundle_path.display(), bytes, "bundle token redeemed; serving tarball");
    } else {
        tracing::info!(
            event_code = "bundle_redeemed",
            bytes,
            "bundle token redeemed; serving tarball"
        );
    }
}

pub(crate) fn info_listener_bound(policy: OperationalLogPolicy, bound_address: SocketAddr) {
    if policy.includes_sensitive_context() {
        tracing::info!(event_code = "server_tcp_listener_bound", %bound_address, "server TCP listener bound");
    } else {
        tracing::info!(
            event_code = "server_tcp_listener_bound",
            "server TCP listener bound"
        );
    }
}

pub(crate) fn info_quic_listener_bound(policy: OperationalLogPolicy, listen_address: SocketAddr) {
    if policy.includes_sensitive_context() {
        tracing::info!(event_code = "server_quic_listener_bound", %listen_address, "server QUIC listener bound");
    } else {
        tracing::info!(
            event_code = "server_quic_listener_bound",
            "server QUIC listener bound"
        );
    }
}

pub(crate) fn info_bundle_enabled(
    policy: OperationalLogPolicy,
    token_store_path: &Path,
    path_prefix: &str,
    tokens: usize,
) {
    if policy.includes_sensitive_context() {
        tracing::info!(event_code = "bundle_endpoint_enabled", path = %token_store_path.display(), prefix = path_prefix, tokens, "bundle endpoint enabled");
    } else {
        tracing::info!(
            event_code = "bundle_endpoint_enabled",
            tokens,
            "bundle endpoint enabled"
        );
    }
}

pub(crate) fn warn_process_alias_failure(
    policy: OperationalLogPolicy,
    alias: &str,
    error: &(impl fmt::Display + ?Sized),
) {
    if policy.includes_sensitive_context() {
        tracing::warn!(
            event_code = "process_alias_failed",
            alias,
            "failed to apply process alias: {error:#}"
        );
    } else {
        tracing::warn!(
            event_code = "process_alias_failed",
            "failed to apply process alias"
        );
    }
}

pub(crate) fn warn_join_failure(
    policy: OperationalLogPolicy,
    event_code: &'static str,
    error: &tokio::task::JoinError,
    message: &'static str,
) {
    if policy.includes_sensitive_context() {
        tracing::warn!(event_code, "{message}: {error:#}");
    } else {
        tracing::warn!(event_code, "{message}");
    }
}
