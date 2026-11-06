//! Actual paired operator subprocesses, synthetic local identities only.
use aegis_core::secret_file;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    time::timeout,
};

fn write(path: &Path, bytes: &[u8]) {
    secret_file::write_private_new(path, bytes).unwrap();
}
fn identities(dir: &Path) -> (Value, Value) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = params.self_signed(&key).unwrap();
    write(&dir.join("ca.pem"), ca.pem().as_bytes());
    let mut fingerprints = vec![];
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let local = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&local, &ca, &key).unwrap();
        write(&dir.join(format!("{name}.pem")), cert.pem().as_bytes());
        write(
            &dir.join(format!("{name}.key")),
            local.serialize_pem().as_bytes(),
        );
        fingerprints.push(format!("{:x}", Sha256::digest(cert.der())));
    }
    (
        json!({"role":"client","settings":{"server_name":"inner.test","server_ca":"ca.pem","cert":"device.test.pem","key":"device.test.key"}}),
        json!({"role":"server","settings":{"cert":"inner.test.pem","key":"inner.test.key","client_ca":"ca.pem","allowed_client_sha256":[fingerprints[1]],"handshake_timeout_ms":1000,"idle_timeout_ms":2000}}),
    )
}
fn child(config: &Path, flag: &str, file: &Path) -> Command {
    let mut command = Command::new(
        std::env::var_os("AEGIS_TEST_RESEARCH_OPERATOR_EXECUTABLE")
            .or_else(|| {
                option_env!("CARGO_BIN_EXE_aegis-research-measure").map(std::ffi::OsString::from)
            })
            .expect("compiled restricted research source or explicit paired source required"),
    );
    command
        .arg("private-control")
        .arg("--config-json")
        .arg(config)
        .arg(flag)
        .arg(file)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
async fn paired(profile: Value, input: &[u8], mismatch: bool, dynamic_registry: bool) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (client, mut server) = identities(d);
    if dynamic_registry {
        use aegis_core::secure_channel::registry::{
            publish_snapshot, unix_now, DeviceRecord, DeviceRegistry,
        };
        let now = unix_now().unwrap();
        let mut registry = DeviceRegistry::new(now, 60).unwrap();
        registry.devices.push(DeviceRecord {
            device_id: "operator-test-device".into(),
            certificate_sha256: server["settings"]["allowed_client_sha256"][0]
                .as_str()
                .unwrap()
                .into(),
            not_after_unix_secs: now + 60,
            revoked: false,
        });
        publish_snapshot(&d.join("registry.json"), &registry).unwrap();
        server["settings"]["allowed_client_sha256"] = json!([]);
        server["settings"]["device_registry"] = json!("registry.json");
    }
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = reservation.local_addr().unwrap();
    drop(reservation);
    let mut server_profile = profile.clone();
    if mismatch {
        server_profile["capacity"] = json!(31);
    }
    let client_config = d.join("client.json");
    let server_config = d.join("server.json");
    let input_file = d.join("input");
    let output = d.join("decoded");
    write(&client_config,serde_json::to_vec(&json!({"endpoint":endpoint.to_string(),"deadline_ms":3000,"tls":client,"profile":profile})).unwrap().as_slice());
    write(&server_config,serde_json::to_vec(&json!({"endpoint":endpoint.to_string(),"deadline_ms":3000,"tls":server,"profile":server_profile})).unwrap().as_slice());
    write(&input_file, input);
    let mut receiver = child(&server_config, "--output-file", &output)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(receiver.stdout.take().unwrap());
    let mut ready = String::new();
    timeout(Duration::from_secs(4), stdout.read_line(&mut ready))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&ready).unwrap()["state"],
        "listening"
    );
    let sender = timeout(
        Duration::from_secs(4),
        child(&client_config, "--input-file", &input_file).output(),
    )
    .await
    .unwrap()
    .unwrap();
    let status = timeout(Duration::from_secs(4), receiver.wait())
        .await
        .unwrap()
        .unwrap();
    if mismatch {
        assert!(!sender.status.success());
        assert!(!status.success());
        assert!(!output.exists());
    } else {
        assert!(sender.status.success());
        assert!(status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&sender.stdout).unwrap()["peer_decoded"],
            true
        );
        let mut metadata = String::new();
        stdout
            .take(2048)
            .read_to_string(&mut metadata)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&metadata).unwrap()["decoded_file_written"],
            true
        );
        assert!(secret_file::read(&output, 16384).unwrap().as_slice() == input);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
fn cover() -> Value {
    json!({"mode":"cover","tokens":[[65],[66]],"weights":[1,1],"bits":1,"capacity":32,"io_timeout_ms":1000})
}
#[tokio::test]
async fn paired_processes_cover_decode_exclusive_private_file() {
    paired(cover(), b"synthetic control", false, false).await;
}
#[tokio::test]
async fn paired_processes_schedule_dummy_data_file_and_ack() {
    paired(json!({"mode":"binary_schedule","slots":3,"capacity":32,"cadence_ms":2,"io_timeout_ms":1000,"truthful":2,"flipped":1,"limit_numerator":"8","limit_denominator":"1"}),b"\x00\x03one\x00\x00\x00\x05three",false,false).await;
}
#[tokio::test]
async fn paired_processes_mismatch_produces_no_decoded_file() {
    paired(cover(), b"synthetic control", true, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn paired_processes_registry_backed_watcher_inside_runtime() {
    paired(cover(), b"synthetic dynamic control", false, true).await;
}
