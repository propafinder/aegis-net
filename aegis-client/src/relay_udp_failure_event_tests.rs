use super::*;
use crate::runtime_events::RuntimeEventCode;
use crate::tests::{ensure_runtime_jsonl_path, read_jsonl_records, RUNTIME_JSONL_LOCK};

#[tokio::test]
async fn udp_associate_child_failure_event_preserves_selected_family() {
    let _guard = RUNTIME_JSONL_LOCK.lock().await;
    let path = ensure_runtime_jsonl_path();
    let start = read_jsonl_records(path).len();
    let settings = RelaySettings::default();
    let profile = policy::build_session_profile(&settings, None);

    for (family, port) in [
        (TunnelTransportFamily::MasqueDerived, 41001),
        (TunnelTransportFamily::GrpcDatagram, 41002),
    ] {
        emit_udp_associate_target_failure(
            &settings,
            &profile,
            family,
            &crate::socks5::ConnectTarget {
                host: "127.0.0.1".into(),
                port,
            },
            &anyhow::anyhow!("synthetic child attempt failure"),
        );
    }

    let records = read_jsonl_records(path);
    let records: Vec<_> = records
        .iter()
        .skip(start)
        .filter(|record| {
            record["event_code"] == RuntimeEventCode::RelayTransportFailed.as_str()
                && matches!(record["fields"]["port"].as_u64(), Some(41001 | 41002))
        })
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["fields"]["transport"], "MasqueDerived");
    assert_eq!(
        records[0]["fields"]["planned_transports"],
        json!(["MasqueDerived"])
    );
    assert_eq!(records[1]["fields"]["transport"], "GrpcDatagram");
    assert_eq!(
        records[1]["fields"]["planned_transports"],
        json!(["GrpcDatagram"])
    );
    for record in records {
        assert_eq!(record["fields"]["attempt_index"], 1);
        assert_eq!(record["fields"]["attempts_total"], 1);
        assert_eq!(
            record["fields"]["relay_failure_scope"],
            "real_transport_outage"
        );
    }
}
