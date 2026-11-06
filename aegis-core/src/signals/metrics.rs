//! Модель наблюдаемых событий и runtime-метрики.

use super::classify::FailSignal;
use serde::{Deserialize, Serialize};

/// Наблюдаемое событие — результат одной попытки соединения / стратегии.
///
/// Записывается Brain после каждой попытки для обновления fitness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedEvent {
    /// Ключ контекста (строковый hash для сериализации).
    pub strategy_key: String,
    /// Режим: "direct" | "tunnel".
    pub mode: String,
    /// ID стратегии (если direct mode).
    pub strategy_id: Option<String>,
    /// ID транспорта (если tunnel mode).
    pub transport_id: Option<String>,
    /// Результат.
    pub signal: FailSignal,
    /// Латентность до первого ответа (мс).
    pub latency_ms: Option<u64>,
    /// Байт отправлено.
    pub bytes_sent: usize,
    /// Байт получено.
    pub bytes_received: usize,
    /// Длительность сессии (мс).
    pub session_duration_ms: Option<u64>,
    /// Timestamp (unix epoch seconds).
    pub timestamp: u64,
}

impl ObservedEvent {
    /// Создать событие успеха.
    pub fn success(
        strategy_key: String,
        mode: &str,
        strategy_id: Option<&str>,
        latency_ms: u64,
        bytes_sent: usize,
        bytes_received: usize,
    ) -> Self {
        Self {
            strategy_key,
            mode: mode.to_string(),
            strategy_id: strategy_id.map(String::from),
            transport_id: None,
            signal: FailSignal::Success,
            latency_ms: Some(latency_ms),
            bytes_sent,
            bytes_received,
            session_duration_ms: None,
            timestamp: now_epoch(),
        }
    }

    /// Создать событие провала.
    pub fn failure(
        strategy_key: String,
        mode: &str,
        strategy_id: Option<&str>,
        signal: FailSignal,
        bytes_sent: usize,
    ) -> Self {
        Self {
            strategy_key,
            mode: mode.to_string(),
            strategy_id: strategy_id.map(String::from),
            transport_id: None,
            signal,
            latency_ms: None,
            bytes_sent,
            bytes_received: 0,
            session_duration_ms: None,
            timestamp: now_epoch(),
        }
    }
}

/// Агрегированные runtime-метрики (для мониторинга, не для Brain).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeMetrics {
    pub active_sessions: u64,
    pub total_sessions: u64,
    pub successful_sessions: u64,
    pub degraded_sessions: u64,
    pub frozen_sessions: u64,
    pub timeout_sessions: u64,
    pub dpi_blocked_sessions: u64,
}

impl RuntimeMetrics {
    /// Обновить метрики на основе сигнала.
    pub fn record(&mut self, signal: &FailSignal) {
        self.total_sessions += 1;
        match signal {
            FailSignal::Success => self.successful_sessions += 1,
            FailSignal::SuccessDegraded => self.degraded_sessions += 1,
            FailSignal::SessionFreeze { .. } => self.frozen_sessions += 1,
            FailSignal::Timeout => self.timeout_sessions += 1,
            s if s.is_dpi_related() => self.dpi_blocked_sessions += 1,
            _ => {}
        }
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_event_success() {
        let ev = ObservedEvent::success("key".into(), "direct", Some("tcp_split"), 150, 1024, 4096);
        assert_eq!(ev.signal, FailSignal::Success);
        assert_eq!(ev.latency_ms, Some(150));
        assert_eq!(ev.bytes_sent, 1024);
    }

    #[test]
    fn observed_event_failure() {
        let ev = ObservedEvent::failure(
            "key".into(),
            "direct",
            Some("ttl_desync"),
            FailSignal::SessionFreeze {
                bytes_before_stall: 18000,
            },
            18000,
        );
        assert!(ev.signal.is_dpi_related());
        assert_eq!(ev.bytes_sent, 18000);
    }

    #[test]
    fn runtime_metrics_record() {
        let mut m = RuntimeMetrics::default();
        m.record(&FailSignal::Success);
        m.record(&FailSignal::SessionFreeze {
            bytes_before_stall: 15000,
        });
        m.record(&FailSignal::DropSuspected);
        assert_eq!(m.total_sessions, 3);
        assert_eq!(m.successful_sessions, 1);
        assert_eq!(m.frozen_sessions, 1);
        assert_eq!(m.dpi_blocked_sessions, 1);
    }
}
