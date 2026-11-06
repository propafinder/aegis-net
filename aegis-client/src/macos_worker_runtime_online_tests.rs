//! Local current-UID identity/authority/relay/PacketPort fixtures. No native
//! privilege drop, PF, utun, installation or target-network acceptance proof.
use super::*;
use crate::ingress::wide::ip_tunnel::PacketIo;
use crate::macos_tunnel::{worker_launch, worker_runtime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn spawn_parts(
    parts: worker_launch::RuntimeParts,
) -> tokio::task::JoinHandle<anyhow::Result<crate::ingress::wide::ip_tunnel::TunnelStats>> {
    tokio::spawn(async move {
        let result = worker_runtime::run_parts(parts).await;
        if let Err(error) = &result {
            eprintln!("owned current-UID runtime fixture result: {error:#}");
        }
        result
    })
}
fn runtime_file(f: &Fixture, settings: &aegis_core::Settings, renewal: &str) -> std::fs::File {
    let mut file = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut file, &serde_json::to_vec(&serde_json::json!({
        "version":1,"identity":f.identity,"online_bundle":f.bundle,"authority_server":f.config.listen,"renewal":renewal,"settings":settings,
        "run_seconds":30,"max_flows":8,"idle_seconds":10,"mtu":1280,"dns_upstream":"1.1.1.1:53"
    })).unwrap()).unwrap();
    file
}
async fn control_read(control: &mut tokio::net::UnixStream) -> serde_json::Value {
    let mut header = [0; 8];
    control.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[..4], b"AW\x02\x01");
    let n = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
    assert!(n <= 8192);
    let mut bytes = vec![0; n];
    control.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
async fn control_send(control: &mut tokio::net::UnixStream, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut header = [b'A', b'W', 2, 1, 0, 0, 0, 0];
    header[4..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    control.write_all(&header).await.unwrap();
    control.write_all(&bytes).await.unwrap();
}
async fn phase(control: &mut tokio::net::UnixStream) {
    let report = control_read(control).await;
    assert_eq!(report["state"], "IdentityPrepared");
    control_send(
        control,
        serde_json::json!({"challenge":report["challenge"]}),
    )
    .await;
    let report = control_read(control).await;
    assert_eq!(report["state"], "EngineConstructed");
}
async fn grant(control: &mut tokio::net::UnixStream, tag: &str) {
    grant_until(control, tag, Duration::from_secs(5)).await;
}
async fn grant_until(control: &mut tokio::net::UnixStream, tag: &str, duration: Duration) {
    let cutoff = worker_launch::monotonic_deadline(duration).unwrap();
    control_send(
        control,
        serde_json::json!({"challenge":tag,"deadline_ns":cutoff}),
    )
    .await;
    let report = control_read(control).await;
    assert_eq!(report["state"], "PolicyConfirmed");
    assert_eq!(report["challenge"], tag);
    assert!(report["remaining_ms"].as_u64().unwrap() <= 5000);
    let until = report["valid_until_ns"].as_u64().unwrap();
    assert!(worker_launch::monotonic_ns().unwrap() < until && until <= cutoff);
    assert_eq!(report["certificate_sha256"].as_str().unwrap().len(), 64);
}
fn udp4(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 28 + payload.len()];
    packet[0] = 0x45;
    let n = packet.len() as u16;
    packet[2..4].copy_from_slice(&n.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&aegis_core::tunnel_policy::CLIENT_V4.octets());
    packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
    packet[20..22].copy_from_slice(&35002u16.to_be_bytes());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    let mut sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16)
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_wide_worker_real_renewal_ack_refresh_udp_and_owned_eof() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let before = f.key();
    let authority = f.server().await;
    let relay = f.relay(&f.config.issuer.registry).await;
    let (parts, mut control, mut packets) = worker_launch::local_runtime_fixture(
        f.identity.clone(),
        runtime_file(&f, &settings, "automatic_renewal"),
    );
    let task = spawn_parts(parts);
    tokio::time::timeout(Duration::from_secs(10), phase(&mut control))
        .await
        .unwrap();
    assert_eq!(f.key(), before);
    assert!(
        !store::online_status(&f.identity, registry::unix_now().unwrap())
            .unwrap()
            .renewal_due
    );
    grant_until(&mut control, &"ab".repeat(16), Duration::from_secs(2)).await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 256];
        let (n, source) = target.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"actual packet engine");
        target.send_to(&bytes[..n], source).await.unwrap();
    });
    packets.send(&udp4(port, b"actual packet engine")).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(p) = packets.receive().unwrap() {
                break p;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(&response[28..], b"actual packet engine");
    echo.await.unwrap();
    grant(&mut control, &"cd".repeat(16)).await;
    control.shutdown().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(packets.receive().is_err());
    relay.stop().await;
    authority.stop().await;
}
#[tokio::test]
async fn full_wide_worker_renewal_disabled_refuses_before_request_or_network() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let (parts, mut control, _) = worker_launch::local_runtime_fixture(
        f.identity.clone(),
        runtime_file(&f, &settings, "existing_lease_only"),
    );
    assert!(worker_runtime::run_parts(parts).await.is_err());
    assert!(!f.identity.join("online-request.json").exists());
    let mut byte = [0];
    assert_eq!(control.read(&mut byte).await.unwrap(), 0);
}
#[tokio::test]
async fn worker_profile_downgrades_and_foreign_custody_fail_before_issuance() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let mut cases = Vec::new();
    let mut s = settings.clone();
    s.mode = aegis_core::Mode::Auto;
    cases.push(s);
    let mut s = settings.clone();
    s.relay.udp_transport_priority = None;
    cases.push(s);
    let mut s = settings.clone();
    s.relay.transport_priority = vec![aegis_core::TunnelTransportFamily::HttpsWs];
    cases.push(s);
    let mut s = settings.clone();
    s.relay.inner_tls = None;
    cases.push(s);
    let mut s = settings.clone();
    s.relay.transport_priority = vec![aegis_core::TunnelTransportFamily::MasqueDerived];
    cases.push(s);
    let mut s = settings.clone();
    s.ingress.allow_fallback = true;
    cases.push(s);
    for s in cases {
        let (parts, _, _) = worker_launch::local_runtime_fixture(
            f.identity.clone(),
            runtime_file(&f, &s, "automatic_renewal"),
        );
        assert!(worker_runtime::run_parts(parts).await.is_err());
    }
    let (parts, _, _) = worker_launch::local_runtime_fixture(
        f.identity.join("foreign"),
        runtime_file(&f, &settings, "automatic_renewal"),
    );
    assert!(worker_runtime::run_parts(parts).await.is_err());
    assert!(!f.identity.join("online-request.json").exists());
}
#[tokio::test]
async fn prepared_identity_stops_before_relay_ack_and_preserves_default_start_contract() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let authority = f.server().await;
    let prepared = crate::device_renewal::PreparedIdentity::prepare(&f.bundle, &settings, true)
        .await
        .unwrap();
    assert_eq!(prepared.fingerprint().len(), 64); // No relay listener exists yet.
    let relay = f.relay(&f.config.issuer.registry).await;
    let supervisor = prepared.confirm().await.unwrap();
    supervisor.confirm_before_ready().await.unwrap();
    drop(supervisor);
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_wide_worker_revoke_cannot_refresh_live_grant() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let authority = f.server().await;
    let relay = f.relay(&f.config.issuer.registry).await;
    let (parts, mut control, _packets) = worker_launch::local_runtime_fixture(
        f.identity.clone(),
        runtime_file(&f, &settings, "automatic_renewal"),
    );
    let task = spawn_parts(parts);
    tokio::time::timeout(Duration::from_secs(10), phase(&mut control))
        .await
        .unwrap();
    grant(&mut control, &"ab".repeat(16)).await;
    aegis_server::devices::revoke(&f.config.issuer.registry, "device-a").unwrap();
    let expected = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if crate::relay::policy_ack(&settings.relay, &expected)
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    control_send(
        &mut control,
        serde_json::json!({"challenge":"cd".repeat(16),"deadline_ns":worker_launch::monotonic_deadline(Duration::from_secs(5)).unwrap()}),
    )
    .await;
    assert!(tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    let mut byte = [0];
    assert_eq!(control.read(&mut byte).await.unwrap(), 0);
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_wide_worker_identity_change_and_replayed_challenge_stop_owned_engine() {
    for change_identity in [false, true] {
        let f = Fixture::new_with_policy(false, true).await;
        f.install_due_predecessor().await;
        let settings = f.settings();
        let authority = f.server().await;
        let relay = f.relay(&f.config.issuer.registry).await;
        let (parts, mut control, _packets) = worker_launch::local_runtime_fixture(
            f.identity.clone(),
            runtime_file(&f, &settings, "automatic_renewal"),
        );
        let task = spawn_parts(parts);
        tokio::time::timeout(Duration::from_secs(10), phase(&mut control))
            .await
            .unwrap();
        grant(&mut control, &"ab".repeat(16)).await;
        if change_identity {
            std::fs::rename(
                f.identity.join("device.pem"),
                f.identity.join("saved-device.pem"),
            )
            .unwrap();
        }
        control_send(&mut control,serde_json::json!({"challenge":if change_identity{"cd".repeat(16)}else{"ab".repeat(16)},"deadline_ns":worker_launch::monotonic_deadline(Duration::from_secs(5)).unwrap()})).await;
        assert!(tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        relay.stop().await;
        authority.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_wide_worker_parent_cannot_keep_capture_alive_without_refresh() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let authority = f.server().await;
    let relay = f.relay(&f.config.issuer.registry).await;
    let (parts, mut control, mut packets) = worker_launch::local_runtime_fixture(
        f.identity.clone(),
        runtime_file(&f, &settings, "automatic_renewal"),
    );
    let task = spawn_parts(parts);
    tokio::time::timeout(Duration::from_secs(10), phase(&mut control))
        .await
        .unwrap();
    grant(&mut control, &"ab".repeat(16)).await;
    let result = tokio::time::timeout(Duration::from_secs(7), task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert!(packets.receive().is_err());
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test]
async fn identity_prepared_is_not_ack_or_permission_and_parent_eof_ends_startup() {
    let f = Fixture::new_with_policy(false, true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let authority = f.server().await;
    let (parts, mut control, _) = worker_launch::local_runtime_fixture(
        f.identity.clone(),
        runtime_file(&f, &settings, "automatic_renewal"),
    );
    let task = spawn_parts(parts);
    let report = tokio::time::timeout(Duration::from_secs(10), control_read(&mut control))
        .await
        .unwrap();
    assert_eq!(report["state"], "IdentityPrepared");
    control.shutdown().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    authority.stop().await;
}
