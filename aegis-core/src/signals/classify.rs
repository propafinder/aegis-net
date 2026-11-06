//! Классификация результатов соединений.
//!
//! `FailSignal` — богатая модель сигналов вместо binary success/fail.
//! `classify_outcome` — определяет тип сигнала по характеристикам соединения.

use crate::probe::RstSource;
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;

/// Результат попытки соединения / стратегии.
///
/// Порядок вариантов: от лучшего к худшему.
/// Каждый вариант несёт достаточно контекста для Brain fitness scoring.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailSignal {
    // --- Успех ---
    /// Полный успех: данные переданы, latency в норме.
    Success,
    /// Успех, но с деградацией (высокая латентность или packet loss).
    SuccessDegraded,

    // --- Сервер (не DPI) ---
    /// Сервер отказал в подключении (ConnectionRefused). Не связано с DPI.
    RemoteRefused,
    /// RST от сервера с нормальным TTL. Вероятно сервер, не DPI.
    RemoteReset,

    // --- Сеть ---
    /// Таймаут без получения данных.
    Timeout,
    /// DNS не резолвится (NXDOMAIN / timeout). Возможно DNS poisoning.
    DnsFailure,

    // --- DPI / ТСПУ ---
    /// Нет ответа после SYN-ACK. Подозрение на DPI drop.
    DropSuspected,
    /// Throughput упал до 0 после передачи данных. DPI throttling.
    ThroughputCollapse,
    /// ТСПУ 2026: "заморозка" сессии при объёме >N байт.
    /// `bytes_before_stall` — сколько байт прошло до остановки.
    SessionFreeze { bytes_before_stall: usize },
    /// TLS handshake отклонён / не завершён. Возможно fingerprint mismatch.
    HandshakeMismatch,

    // --- Tunnel ---
    /// CDN / transport отклонил подключение.
    TransportRejected,
    /// Relay сервер отклонил auth.
    TunnelRejected,

    // --- Локальные ---
    /// Ошибка I/O на клиенте.
    LocalIoError,
    /// Заблокировано локальной политикой (config / rate limit).
    PolicyBlocked,

    // --- External calibration ---
    /// Подсказка от внешнего witness/adversarial/knowledge classifier.
    ExternalClassifierHint {
        source: String,
        score_milli: u16,
        confidence_milli: u16,
        hard_block: bool,
    },

    /// Не удалось классифицировать.
    Unknown,
}

impl FailSignal {
    /// Связана ли ошибка с DPI/ТСПУ (а не с сервером или сетью).
    pub fn is_dpi_related(&self) -> bool {
        matches!(
            self,
            FailSignal::DropSuspected
                | FailSignal::ThroughputCollapse
                | FailSignal::SessionFreeze { .. }
                | FailSignal::HandshakeMismatch
        ) || matches!(
            self,
            FailSignal::ExternalClassifierHint {
                hard_block: true,
                ..
            }
        )
    }

    /// Связана ли ошибка с сервером (не с DPI).
    pub fn is_server_related(&self) -> bool {
        matches!(self, FailSignal::RemoteRefused | FailSignal::RemoteReset)
    }

    /// Успех (полный или с деградацией).
    pub fn is_success(&self) -> bool {
        matches!(self, FailSignal::Success | FailSignal::SuccessDegraded)
    }
}

/// Контекст завершения попытки соединения для классификации.
pub struct OutcomeContext {
    /// Ошибка I/O, если была.
    pub io_error: Option<io::ErrorKind>,
    /// TTL из RST-пакета, если перехвачен (требует raw engine).
    pub rst_ttl: Option<u8>,
    /// Классификация источника RST из packet observer / TTL heuristics.
    pub rst_source: Option<RstSource>,
    /// Ожидаемый TTL от сервера (из предыдущих успешных соединений или traceroute).
    pub expected_ttl: Option<u8>,
    /// Сколько байт успели отправить.
    pub bytes_sent: usize,
    /// Сколько байт получили.
    pub bytes_received: usize,
    /// Был ли хотя бы TCP handshake response (`SYN-ACK`) подтверждён packet observer'ом.
    pub syn_ack_seen: bool,
    /// Видел ли packet observer уже первые inbound data bytes от удалённой стороны.
    pub first_data_seen: bool,
    /// Был ли target классифицирован как TLS path.
    pub is_tls: bool,
    /// Сколько длилась попытка.
    pub elapsed: Duration,
    /// Таймаут, заданный в конфиге.
    pub configured_timeout: Duration,
    /// Порог "заморозки" ТСПУ (из конфига, default 16384).
    pub freeze_threshold_bytes: usize,
    /// Порог деградации латентности (из конфига, default 5000ms).
    pub degraded_latency_ms: u64,
}

/// Классифицировать результат попытки.
///
/// Логика приоритетов (от специфичного к общему):
/// 1. DNS ошибки → DnsFailure
/// 2. ConnectionRefused → RemoteRefused
/// 3. RST от middlebox / с низким TTL → DPI (`DropSuspected` или `HandshakeMismatch`)
/// 4. RST с remote-like source / после server progress → RemoteReset
/// 5. Таймаут + bytes_sent > freeze_threshold → SessionFreeze
/// 6. TLS timeout после `SYN-ACK`, но без inbound data → HandshakeMismatch
/// 7. Timeout после inbound data / traffic progress → ThroughputCollapse
/// 8. Таймаут без progress → DropSuspected
/// 9. Успех + высокая латентность → SuccessDegraded
/// 10. Успех → Success
pub fn classify_outcome(success: bool, ctx: &OutcomeContext) -> FailSignal {
    // DNS
    if ctx.io_error == Some(io::ErrorKind::Other) && ctx.bytes_sent == 0 && ctx.bytes_received == 0
    {
        // Грубая эвристика: Other + 0 bytes часто = DNS failure.
        // Точная классификация требует отдельного DNS resolver с диагностикой.
        return FailSignal::DnsFailure;
    }

    // ConnectionRefused
    if ctx.io_error == Some(io::ErrorKind::ConnectionRefused) {
        return FailSignal::RemoteRefused;
    }

    // ConnectionReset — анализируем TTL
    if ctx.io_error == Some(io::ErrorKind::ConnectionReset) {
        if ctx.rst_source == Some(RstSource::Remote) {
            return FailSignal::RemoteReset;
        }
        if ctx.rst_source == Some(RstSource::Middlebox) {
            if ctx.is_tls && ctx.syn_ack_seen && !ctx.first_data_seen {
                return FailSignal::HandshakeMismatch;
            }
            return FailSignal::DropSuspected;
        }
        if let (Some(rst_ttl), Some(expected)) = (ctx.rst_ttl, ctx.expected_ttl) {
            if rst_ttl < expected.saturating_sub(10) {
                // RST с TTL значительно ниже ожидаемого → DPI injection
                if ctx.is_tls && ctx.syn_ack_seen && !ctx.first_data_seen {
                    return FailSignal::HandshakeMismatch;
                }
                return FailSignal::DropSuspected;
            }
        }
        if ctx.first_data_seen {
            return FailSignal::RemoteReset;
        }
        if ctx.is_tls && ctx.syn_ack_seen && !ctx.first_data_seen {
            return FailSignal::HandshakeMismatch;
        }
        return FailSignal::RemoteReset;
    }

    // Таймаут
    if ctx.io_error == Some(io::ErrorKind::TimedOut) || ctx.elapsed >= ctx.configured_timeout {
        if ctx.bytes_sent >= ctx.freeze_threshold_bytes {
            return FailSignal::SessionFreeze {
                bytes_before_stall: ctx.bytes_sent,
            };
        }
        // Stage-aware progress lets us distinguish "TCP path alive but TLS died"
        // from a deeper collapse after inbound application data started flowing.
        if ctx.is_tls && ctx.syn_ack_seen && !ctx.first_data_seen && ctx.bytes_received == 0 {
            return FailSignal::HandshakeMismatch;
        }
        if ctx.first_data_seen || ctx.bytes_sent > 0 || ctx.bytes_received > 0 {
            return FailSignal::ThroughputCollapse;
        }
        return FailSignal::DropSuspected;
    }

    // Прочие I/O ошибки
    if ctx.io_error.is_some() && !success {
        return FailSignal::LocalIoError;
    }

    // Успех
    if success {
        let latency_ms = ctx.elapsed.as_millis() as u64;
        if latency_ms > ctx.degraded_latency_ms {
            return FailSignal::SuccessDegraded;
        }
        return FailSignal::Success;
    }

    FailSignal::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_ctx() -> OutcomeContext {
        OutcomeContext {
            io_error: None,
            rst_ttl: None,
            rst_source: None,
            expected_ttl: None,
            bytes_sent: 0,
            bytes_received: 0,
            syn_ack_seen: false,
            first_data_seen: false,
            is_tls: false,
            elapsed: Duration::from_millis(100),
            configured_timeout: Duration::from_secs(8),
            freeze_threshold_bytes: 16384,
            degraded_latency_ms: 5000,
        }
    }

    #[test]
    fn classify_success() {
        let ctx = base_ctx();
        assert_eq!(classify_outcome(true, &ctx), FailSignal::Success);
    }

    #[test]
    fn classify_success_degraded() {
        let mut ctx = base_ctx();
        ctx.elapsed = Duration::from_millis(6000);
        assert_eq!(classify_outcome(true, &ctx), FailSignal::SuccessDegraded);
    }

    #[test]
    fn classify_connection_refused() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_outcome(false, &ctx), FailSignal::RemoteRefused);
    }

    #[test]
    fn classify_rst_normal_ttl() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::ConnectionReset);
        ctx.rst_source = Some(RstSource::Remote);
        ctx.rst_ttl = Some(58);
        ctx.expected_ttl = Some(64);
        assert_eq!(classify_outcome(false, &ctx), FailSignal::RemoteReset);
    }

    #[test]
    fn classify_rst_low_ttl_dpi() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::ConnectionReset);
        ctx.rst_source = Some(RstSource::Middlebox);
        ctx.rst_ttl = Some(5);
        ctx.expected_ttl = Some(64);
        assert_eq!(classify_outcome(false, &ctx), FailSignal::DropSuspected);
    }

    #[test]
    fn classify_rst_after_syn_ack_as_handshake_mismatch() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::ConnectionReset);
        ctx.rst_source = Some(RstSource::Middlebox);
        ctx.is_tls = true;
        ctx.syn_ack_seen = true;
        assert_eq!(classify_outcome(false, &ctx), FailSignal::HandshakeMismatch);
    }

    #[test]
    fn classify_rst_after_first_data_as_remote_reset_when_source_unknown() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::ConnectionReset);
        ctx.rst_ttl = Some(60);
        ctx.expected_ttl = Some(64);
        ctx.first_data_seen = true;
        assert_eq!(classify_outcome(false, &ctx), FailSignal::RemoteReset);
    }

    #[test]
    fn classify_timeout_no_data() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::TimedOut);
        assert_eq!(classify_outcome(false, &ctx), FailSignal::DropSuspected);
    }

    #[test]
    fn classify_tls_timeout_after_syn_ack_as_handshake_mismatch() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::TimedOut);
        ctx.is_tls = true;
        ctx.syn_ack_seen = true;
        assert_eq!(classify_outcome(false, &ctx), FailSignal::HandshakeMismatch);
    }

    #[test]
    fn classify_timeout_after_first_data_as_throughput_collapse() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::TimedOut);
        ctx.first_data_seen = true;
        assert_eq!(
            classify_outcome(false, &ctx),
            FailSignal::ThroughputCollapse
        );
    }

    #[test]
    fn classify_timeout_with_data_throughput_collapse() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::TimedOut);
        ctx.bytes_sent = 500;
        assert_eq!(
            classify_outcome(false, &ctx),
            FailSignal::ThroughputCollapse
        );
    }

    #[test]
    fn classify_session_freeze() {
        let mut ctx = base_ctx();
        ctx.io_error = Some(io::ErrorKind::TimedOut);
        ctx.bytes_sent = 20000; // > freeze_threshold (16384)
        assert_eq!(
            classify_outcome(false, &ctx),
            FailSignal::SessionFreeze {
                bytes_before_stall: 20000
            }
        );
    }

    #[test]
    fn fail_signal_is_dpi() {
        assert!(FailSignal::DropSuspected.is_dpi_related());
        assert!(FailSignal::ThroughputCollapse.is_dpi_related());
        assert!(FailSignal::SessionFreeze {
            bytes_before_stall: 0
        }
        .is_dpi_related());
        assert!(!FailSignal::RemoteRefused.is_dpi_related());
        assert!(!FailSignal::Success.is_dpi_related());
    }

    #[test]
    fn fail_signal_is_success() {
        assert!(FailSignal::Success.is_success());
        assert!(FailSignal::SuccessDegraded.is_success());
        assert!(!FailSignal::Timeout.is_success());
    }
}
