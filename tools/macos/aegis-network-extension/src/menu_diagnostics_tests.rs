use super::*;
use crate::host_lifecycle::ProfileLine;
use crate::menu_model::{derive, ExtensionState, FilterView, Observation, Probe};
use crate::provider_xpc::{CertStatusReport, StatusReport};

const NOW: u64 = 1_793_000_000;

#[test]
fn ipv4_addresses_keep_only_their_first_octet() {
    assert_eq!(mask("relay 192.168.1.107 up"), "relay 192.x.x.x up");
    assert_eq!(mask("relay=203.0.113.20:443"), "relay=203.x.x.x:443");
    assert_eq!(mask("dialed 10.0.0.1."), "dialed 10.x.x.x.");
    assert_eq!(mask("https://198.51.100.7/x"), "https://198.x.x.x/x");
    // Versions, dates and times are not addresses.
    assert_eq!(
        mask("app 0.1.0 (39) macOS 15.5.1"),
        "app 0.1.0 (39) macOS 15.5.1"
    );
    assert_eq!(
        mask("generated: 2026-11-02 12:03 UTC at 12:03:04Z"),
        "generated: 2026-11-02 12:03 UTC at 12:03:04Z"
    );
}

#[test]
fn ipv6_addresses_keep_only_their_first_group() {
    assert_eq!(mask("dns fd00:ae61::2"), "dns fd00:<masked>");
    assert_eq!(mask("relay [2001:db8::1]:443"), "relay [2001:<masked>]:443");
    assert_eq!(
        mask("peer 2001:0db8:0000:0000:0000:ff00:0042:8329."),
        "peer 2001:<masked>."
    );
    assert_eq!(mask("ten past: 10:10"), "ten past: 10:10");
}

#[test]
fn user_names_in_paths_are_masked() {
    assert_eq!(
        mask("/Users/developer/Downloads/enroll"),
        "/Users/<user>/Downloads/enroll"
    );
    assert_eq!(mask("dir=/Users/alice"), "dir=/Users/<user>");
    assert_eq!(mask("/Users/Shared/aegis"), "/Users/Shared/aegis");
    assert_eq!(
        mask("/private/var/folders/ab/cd12ef/T/AppTranslocation"),
        "/private/var/folders/<tmp>/T/AppTranslocation"
    );
}

#[test]
fn identifiers_digests_and_tokens_are_masked() {
    assert_eq!(
        mask("owner_generation=0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0 saved=true"),
        "owner_generation=<uuid 0F1E…> saved=true"
    );
    assert_eq!(
        mask(&format!("profile_sha256={}", "ab".repeat(32))),
        "profile_sha256=<hex 64>"
    );
    assert_eq!(
        mask("bearer dGhpcyBpcyBhIHNlY3JldCB0b2tlbjEyMw== end"),
        "bearer <redacted> end"
    );
    // Stable codes and words stay readable.
    for kept in [
        "identity_authorization_proof_rule_unexpected",
        "filter_result=ok exit_code=0 mode=guarding",
        "dev.aegis.macos.PacketTunnel TEAMID0000",
        "session_refusal=session_identity_expired",
        "key_material_removed=true",
    ] {
        assert_eq!(mask(kept), kept);
    }
}

#[test]
fn secret_keys_lose_their_values() {
    assert_eq!(mask("invitation=abc123"), "invitation=<redacted>");
    assert_eq!(
        mask("token=x password=y"),
        "token=<redacted> password=<redacted>"
    );
    assert_eq!(mask("armed_token=5"), "armed_token=<redacted>");
    assert_eq!(mask("device_key=zzz"), "device_key=<redacted>");
    assert_eq!(
        mask(r#"{"invitation": "s3cr3t", "state": "valid"}"#),
        r#"{"invitation": "<redacted>", "state": "valid"}"#
    );
    assert_eq!(mask(r#"{"token":"abc"}"#), r#"{"token":"<redacted>"}"#);
}

#[test]
fn pem_blocks_and_emails_are_removed() {
    let text = "before\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\nafter";
    assert_eq!(mask(text), "before\n<pem redacted>\nafter");
    assert_eq!(mask("-----BEGIN CERTIFICATE-----\nAAAA"), "<pem redacted>");
    assert_eq!(mask("mail friend@example.com now"), "mail <email> now");
}

#[test]
fn masking_is_idempotent() {
    let sample = "relay=203.0.113.20:443 dns fd00:ae61::2 /Users/developer/x \
owner_generation=0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0 token=abc \
digest=0123456789abcdef0123456789abcdef friend@example.com \
dGhpcyBpcyBhIHNlY3JldCB0b2tlbjEyMw== /var/folders/ab/cd/T";
    let once = mask(sample);
    assert_eq!(mask(&once), once);
    for leaked in [
        "203.0.113.20",
        "ae61",
        "developer",
        "4B5A",
        "abc",
        "0123456789abcdef",
        "friend@",
        "dGhp",
    ] {
        assert!(!once.contains(leaked), "{leaked} in {once}");
    }
}

#[test]
fn the_event_log_masks_bounds_and_folds_repeats() {
    let mut log = EventLog::new(3);
    log.push(NOW, "connect exit=0 relay=192.168.1.107");
    log.push(NOW + 1, "connect exit=0 relay=192.168.1.107");
    assert_eq!(
        log.entries(),
        vec!["07:33:20 connect exit=0 relay=192.x.x.x"]
    );
    for n in 0..5 {
        log.push(NOW + 10 + n, &format!("event {n}"));
    }
    let entries = log.entries();
    assert_eq!(entries.len(), 3);
    assert!(entries[2].ends_with("event 4"));
}

fn observation() -> Observation {
    Observation {
        refreshed: true,
        in_applications: true,
        app_build: Some("39".into()),
        extension: ExtensionState::Enabled {
            build: Some("39".into()),
        },
        profiles: Probe::Ok(vec![ProfileLine {
            index: 0,
            owner_generation: Some("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".into()),
            scutil_service_id: Some("11111111-2222-3333-4444-555555555555".into()),
            intent_valid: true,
            enabled: true,
            on_demand_enabled: false,
            native_vpn_status: 3,
        }]),
        provider: Probe::Ok(StatusReport {
            session_phase: "ready".into(),
            session_refusal: None,
        }),
        identity_present: Some(true),
        cert: Some(CertStatusReport {
            state: "valid".into(),
            not_before: Some(NOW - 86_400),
            not_after: Some(NOW + 2 * 86_400),
            renew_at: Some(NOW + 86_400),
            attempts: 0,
            last_attempt_at: None,
            next_attempt_at: None,
            last_failure: None,
            failing_since: None,
            check: None,
        }),
        filter: Probe::Ok(FilterView {
            outcome: "ok".into(),
            mode: Some("guarding".into()),
        }),
        status_since: Some((3, NOW - 60)),
        notice: Some("Connect failed near 192.168.1.107 for /Users/developer".into()),
        ..Observation::default()
    }
}

#[test]
fn the_report_names_states_and_codes_but_nothing_identifying() {
    let obs = observation();
    let view = derive(&obs, NOW);
    let events = vec!["12:00:00 connect exit=0 code=none".to_owned()];
    let text = report(&ReportInput {
        now: NOW,
        app_version: "0.1.0 (39)",
        macos_version: "15.5",
        observation: &obs,
        view: &view,
        events: &events,
    });
    for expected in [
        "state: Connected",
        "app: 0.1.0 (39)",
        "provider: session_phase=ready session_refusal=none",
        "certificate: state=valid",
        "leak guard: filter_result=ok mode=guarding",
        "native_vpn_status=3",
        "identity_present: true",
        "12:00:00 connect exit=0 code=none",
    ] {
        assert!(text.contains(expected), "{expected} missing in\n{text}");
    }
    for leaked in ["192.168.1.107", "developer", "0F1E2D3C", "11111111-2222"] {
        assert!(!text.contains(leaked), "{leaked} leaked in\n{text}");
    }
}
