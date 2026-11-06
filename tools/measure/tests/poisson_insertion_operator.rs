//! Actual paired operator subprocesses, synthetic local identities only.
use aegis_core::secret_file;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
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
fn child(config: &Path) -> Command {
    let mut c = Command::new(
        std::env::var_os("AEGIS_TEST_RESEARCH_OPERATOR_EXECUTABLE")
            .or_else(|| {
                option_env!("CARGO_BIN_EXE_aegis-research-measure").map(std::ffi::OsString::from)
            })
            .expect("compiled restricted research source or explicit paired source required"),
    );
    c.arg("poisson-insertion")
        .arg("--config-json")
        .arg(config)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}
async fn paired(mismatch: bool) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (client, server) = identities(d);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let profile = json!({"capacity":64,"horizon_ms":300,"insertion_rate_milli":100000,"overt_rate_milli":1000000,"max_records":128,"max_wire_bytes":10624,"io_timeout_ms":500,"max_lateness_ms":100});
    let mut other = profile.clone();
    if mismatch {
        other["horizon_ms"] = json!(301);
    }
    let cc = d.join("client.json");
    let sc = d.join("server.json");
    write(
        &cc,
        &serde_json::to_vec(
            &json!({"endpoint":addr.to_string(),"deadline_ms":3000,"tls":client,"profile":profile}),
        )
        .unwrap(),
    );
    write(
        &sc,
        &serde_json::to_vec(
            &json!({"endpoint":addr.to_string(),"deadline_ms":3000,"tls":server,"profile":other}),
        )
        .unwrap(),
    );
    let ai = d.join("application-input");
    let ci = d.join("control-input");
    let ao = d.join("application-output");
    let co = d.join("control-output");
    let original: Vec<u8> = (0..199).map(|x| x as u8).collect();
    write(&ai, &original);
    write(&ci, b"ONLY INSIDE ACTUAL INSERTIONS");
    let mut receiver = child(&sc)
        .arg("--application-output")
        .arg(&ao)
        .arg("--control-output")
        .arg(&co)
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
    let sent = timeout(
        Duration::from_secs(4),
        child(&cc)
            .arg("--application-input")
            .arg(&ai)
            .arg("--control-input")
            .arg(&ci)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let status = timeout(Duration::from_secs(4), receiver.wait())
        .await
        .unwrap()
        .unwrap();
    if mismatch {
        assert!(!sent.status.success());
        assert!(!status.success());
        assert!(!ao.exists());
        assert!(!co.exists());
    } else {
        assert!(
            sent.status.success(),
            "operator sender failed (content-free)"
        );
        assert!(status.success());
        let meta: Value = serde_json::from_slice(&sent.stdout).unwrap();
        assert_eq!(meta["peer_count_ack"], true);
        assert_eq!(meta["receipt"]["original_bytes"], 199);
        assert!(meta["receipt"]["inserted_records"].as_u64().unwrap() > 0);
        assert_eq!(meta["source_poisson_verified"], false);
        assert_eq!(secret_file::read(&ao, 4096).unwrap().as_slice(), original);
        assert_eq!(
            secret_file::read(&co, 4096).unwrap().as_slice(),
            b"ONLY INSIDE ACTUAL INSERTIONS"
        );
        assert!(!String::from_utf8_lossy(&sent.stdout).contains("ONLY INSIDE"));
    }
}
#[tokio::test]
async fn actual_paired_cli_owned_application_and_inserted_control_files() {
    paired(false).await;
}
#[tokio::test]
async fn actual_paired_cli_profile_mismatch_no_output() {
    paired(true).await;
}
