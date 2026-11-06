use crate::direct::add_runtime_baseline_mimicry_fields_compact;
use aegis_core::{TunnelTransportFamily, WireMimicryMode};
use serde_json::Value;
use std::net::SocketAddr;

use super::policy::{self, SurfaceBias};
use aegis_core::mimicry::StackProfileId;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RelayMimicryContext {
    pub target_addr: SocketAddr,
    pub stack_profile: Option<StackProfileId>,
    pub wire_mode: WireMimicryMode,
    /// Brain-derived bias for surface profile selection. `SurfaceBias`
    /// defaults to neutral, in which case the behavior matches pre-2.5
    /// deterministic mod-of-seed surface picking. A non-neutral bias is
    /// produced by `direct.rs` from the current session's `BrainAdvisory`
    /// and routes through `build_session_profile_with_brain_bias`.
    pub surface_bias: SurfaceBias,
}

pub(super) fn maybe_add_runtime_mimicry_fields(
    fields: &mut Value,
    mimicry_context: Option<RelayMimicryContext>,
) {
    let Some(context) = mimicry_context else {
        return;
    };
    add_runtime_baseline_mimicry_fields_compact(
        fields,
        context.stack_profile,
        context.wire_mode,
        context.target_addr,
    );
}

pub(super) fn maybe_add_relay_surface_fields(
    fields: &mut Value,
    profile: Option<&policy::RelaySessionProfile>,
) {
    let Some(profile) = profile else {
        return;
    };
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    map.insert(
        "relay_surface_profile_id".into(),
        Value::String(profile.profile_id.to_string()),
    );
    map.insert(
        "relay_surface_websocket_path".into(),
        Value::String(profile.websocket_path.clone()),
    );
    map.insert(
        "relay_surface_grpc_path".into(),
        Value::String(profile.grpc_path.clone()),
    );
    map.insert(
        "relay_surface_masque_path".into(),
        Value::String(profile.masque_path.clone()),
    );
    map.insert(
        "relay_surface_accept_language".into(),
        profile
            .accept_language_header
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_cache_control".into(),
        profile
            .cache_control_header
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_websocket_origin".into(),
        profile
            .websocket_origin_header
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_grpc_accept_encoding".into(),
        profile
            .grpc_accept_encoding_header
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_grpc_encoding".into(),
        profile
            .grpc_encoding_header
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_grpc_timeout".into(),
        profile
            .grpc_timeout_header
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_grpc_message_type".into(),
        profile
            .grpc_message_type_header
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_masque_alt_used".into(),
        profile
            .masque_alt_used_header
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_write_chunk_size".into(),
        Value::from(profile.write_chunk_size as u64),
    );
    map.insert(
        "relay_surface_inter_chunk_delay_ms".into(),
        Value::from(profile.inter_chunk_delay_ms),
    );
    // Emit the surface profile's distribution bounds alongside the sampled
    // scalars. This proves on the wire-event timeline that two sessions
    // landing on the same profile carried different sampled instances, and
    // that the per-chunk jitter window was non-zero where declared.
    let (chunk_min, chunk_max) = profile.surface_chunk_size_range;
    map.insert(
        "relay_surface_write_chunk_size_range_min".into(),
        Value::from(chunk_min as u64),
    );
    map.insert(
        "relay_surface_write_chunk_size_range_max".into(),
        Value::from(chunk_max as u64),
    );
    let (delay_min, delay_max) = profile.surface_delay_ms_range;
    map.insert(
        "relay_surface_inter_chunk_delay_ms_range_min".into(),
        Value::from(delay_min),
    );
    map.insert(
        "relay_surface_inter_chunk_delay_ms_range_max".into(),
        Value::from(delay_max),
    );
    map.insert(
        "relay_surface_inter_chunk_jitter_ms_window".into(),
        Value::from(profile.inter_chunk_jitter_ms_window),
    );
    // Phase 2.5: emitted so closed-loop adaptation is observable in
    // evidence — when a Brain-supplied SurfaceBias materially changes the
    // surface selection (i.e. the weighted picker landed on a different
    // family than the neutral mod-of-seed default would have), this flag
    // marks it on the relay_session_started event.
    map.insert(
        "relay_surface_bias_applied".into(),
        Value::from(profile.surface_bias_applied),
    );
    // Phase 5 Phase 2: padding-as-split policy. `padding_probability_milli`
    // is the per-write per-mille chance a chunk is split into two TLS
    // records; `padding_split_ratio_milli_range` bounds the ratio used.
    // Emitting both lets evidence captures show which sessions had
    // packet-size-widening enabled and at what intensity.
    map.insert(
        "relay_surface_padding_probability_milli".into(),
        Value::from(profile.padding_probability_milli),
    );
    let (pad_lo, pad_hi) = profile.padding_split_ratio_milli_range;
    map.insert(
        "relay_surface_padding_split_ratio_milli_range_min".into(),
        Value::from(pad_lo),
    );
    map.insert(
        "relay_surface_padding_split_ratio_milli_range_max".into(),
        Value::from(pad_hi),
    );
    map.insert(
        "relay_surface_tls_profile_target_class".into(),
        profile
            .tls_profile_target_class
            .as_ref()
            .map(|value| Value::String(value.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "relay_surface_tls_profile_target_alpn".into(),
        profile
            .tls_profile_target_class
            .as_deref()
            .map(tls_profile_target_alpn_value)
            .unwrap_or(Value::Null),
    );
}

pub(super) fn tls_profile_target_alpn_value(target_class: &str) -> Value {
    let profile = aegis_chrome_profile::chrome_stable();
    let values = match target_class {
        "legacy_tls" => profile.tls.alpn_http11.clone(),
        "https_ws" => profile.tls.alpn_h2_http11.clone(),
        "grpc_stream" => profile.tls.alpn_h2.clone(),
        // MASQUE offers the profile's QUIC ALPN. `masque` stays beside it
        // because the relay template advertises that extra protocol.
        "masque_derived" => {
            let mut values = profile.quic.alpn.clone();
            values.push("masque".to_string());
            values
        }
        _ => Vec::new(),
    };
    Value::Array(values.into_iter().map(Value::String).collect())
}

/// HTTP/2 client whose SETTINGS, order and connection window come from the
/// Chrome profile. The default h2 window is 65535, so the connection
/// WINDOW_UPDATE increment is `target - 65535`.
pub(super) fn chrome_h2_alpn() -> Vec<Vec<u8>> {
    let profile = aegis_chrome_profile::chrome_stable();
    profile.tls.wire(&profile.tls.alpn_h2)
}

pub(super) fn chrome_h2_http11_alpn() -> Vec<Vec<u8>> {
    let profile = aegis_chrome_profile::chrome_stable();
    profile.tls.wire(&profile.tls.alpn_h2_http11)
}

pub(super) fn chrome_like_h2_builder() -> h2::client::Builder {
    let http2 = &aegis_chrome_profile::chrome_stable().http2;
    let mut builder = h2::client::Builder::new();
    for setting in &http2.settings {
        match setting.id {
            1 => {
                builder.header_table_size(setting.value);
            }
            2 => {
                builder.enable_push(setting.value != 0);
            }
            3 => {
                builder.max_concurrent_streams(setting.value);
            }
            4 => {
                builder.initial_window_size(setting.value);
            }
            5 => {
                builder.max_frame_size(setting.value);
            }
            6 => {
                builder.max_header_list_size(setting.value);
            }
            other => panic!("chrome profile setting {other} has no client builder setter"),
        }
    }
    if http2.connection_window_increment > 0 {
        let target = 65_535u32
            .checked_add(http2.connection_window_increment)
            .expect("chrome connection window fits in u32");
        builder.initial_connection_window_size(target);
    }
    builder
}

/// ALPN offered by the explicit legacy framed-stream transport. Its encrypted
/// payload is AEGIS frames rather than HTTP; offering `http/1.1` does not prove
/// HTTP-like camouflage or browser equivalence.
pub(super) fn legacy_tls_wire_alpn(
    _profile: &policy::RelaySessionProfile,
) -> Option<&'static [u8]> {
    match aegis_chrome_profile::chrome_stable()
        .tls
        .alpn_http11
        .as_slice()
    {
        [protocol] if protocol == "http/1.1" => Some(b"http/1.1"),
        _ => None,
    }
}

/// Report the adapter's offered ALPN list, not an observed negotiated protocol.
pub(super) fn maybe_add_tls_wire_adapter_fields(
    fields: &mut Value,
    family: TunnelTransportFamily,
    profile: Option<&policy::RelaySessionProfile>,
) {
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    let chrome = aegis_chrome_profile::chrome_stable();
    let h2 = chrome.tls.alpn_h2.clone();
    let h2_http11 = chrome.tls.alpn_h2_http11.clone();
    let http11 = chrome.tls.alpn_http11.clone();
    let h3 = chrome.quic.alpn.clone();
    let (adapter, alpn): (&str, Vec<String>) = match family {
        TunnelTransportFamily::LegacyTls => {
            if profile.and_then(legacy_tls_wire_alpn).is_some() {
                ("legacy_tls_target_http11", http11)
            } else {
                ("legacy_tls_default", Vec::new())
            }
        }
        TunnelTransportFamily::HttpsWs => ("websocket_h2_extended_connect_offer", h2_http11),
        TunnelTransportFamily::GrpcStream => ("grpc_h2_fixed", h2.clone()),
        TunnelTransportFamily::GrpcDatagram => ("grpc_datagram_h2_fixed", h2),
        TunnelTransportFamily::MasqueDerived => ("masque_h3_fixed", h3),
    };
    map.insert(
        "relay_surface_tls_wire_adapter".into(),
        Value::String(adapter.to_string()),
    );
    map.insert(
        "relay_surface_tls_wire_alpn".into(),
        Value::Array(alpn.into_iter().map(Value::String).collect()),
    );
    map.insert(
        "relay_surface_tls_wire_alpn_semantics".into(),
        Value::String("offered".into()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_adapter_reports_offered_h2_and_http11() {
        let mut fields = serde_json::json!({});
        maybe_add_tls_wire_adapter_fields(&mut fields, TunnelTransportFamily::HttpsWs, None);

        assert_eq!(
            fields["relay_surface_tls_wire_adapter"],
            "websocket_h2_extended_connect_offer"
        );
        assert_eq!(
            fields["relay_surface_tls_wire_alpn"],
            serde_json::json!(["h2", "http/1.1"])
        );
        assert_eq!(fields["relay_surface_tls_wire_alpn_semantics"], "offered");
    }

    #[tokio::test]
    async fn h2_preface_matches_the_profile_fixture() {
        use tokio::io::AsyncReadExt;

        let expected = aegis_chrome_profile::chrome_stable().http2_preface();
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let drive = tokio::spawn(async move {
            let (send, mut connection) = chrome_like_h2_builder()
                .handshake::<_, bytes::Bytes>(client)
                .await
                .expect("h2 handshake");
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(300), &mut connection).await;
            drop(send);
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while got.len() < expected.len() && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(300), server.read(&mut buf))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        let _ = drive.await;
        assert!(
            got.starts_with(&expected),
            "HTTP/2 preface diverged from the profile: {:02x?}",
            got
        );
    }

    #[tokio::test]
    async fn h2_headers_priority_matches_the_profile() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let profile = aegis_chrome_profile::chrome_stable();
        let priority = profile
            .http2
            .headers_priority
            .clone()
            .expect("profile records HEADERS priority");
        let mut word = priority.dependency;
        if priority.exclusive {
            word |= 0x8000_0000;
        }
        let mut prefix = word.to_be_bytes().to_vec();
        prefix.push(priority.weight);

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let drive = tokio::spawn(async move {
            let (mut send, connection) = chrome_like_h2_builder()
                .handshake::<_, bytes::Bytes>(client)
                .await
                .expect("h2 handshake");
            let request = http::Request::builder()
                .method("GET")
                .uri("https://example.com/")
                .body(())
                .unwrap();
            let (_response, _stream) = send.send_request(request, true).expect("queue request");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), connection).await;
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        let preface = profile.http2_preface();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while got.len() < preface.len() && tokio::time::Instant::now() < deadline {
            let n =
                tokio::time::timeout(std::time::Duration::from_millis(300), server.read(&mut buf))
                    .await
                    .expect("preface read")
                    .expect("preface socket");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        server
            .write_all(&hex_settings_frame())
            .await
            .expect("server settings");
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(300), server.read(&mut buf))
                .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break,
            }
        }
        let _ = drive.await;
        let headers = frames_after_preface(&got[preface.len()..])
            .into_iter()
            .find(|frame| frame.0 == 1)
            .expect("HEADERS frame");
        assert_eq!(headers.1 & 0x20, 0x20, "PRIORITY flag");
        assert!(
            headers.2.starts_with(&prefix),
            "priority prefix {:02x?} != profile {:02x?}",
            &headers.2[..headers.2.len().min(5)],
            prefix
        );
    }

    fn hex_settings_frame() -> [u8; 9] {
        // Empty SETTINGS, the server connection preface.
        [0, 0, 0, 4, 0, 0, 0, 0, 0]
    }

    fn frames_after_preface(mut data: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
        let mut frames = Vec::new();
        while data.len() >= 9 {
            let length = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
            let kind = data[3];
            let flags = data[4];
            if data.len() < 9 + length {
                break;
            }
            frames.push((kind, flags, data[9..9 + length].to_vec()));
            data = &data[9 + length..];
        }
        frames
    }
}
