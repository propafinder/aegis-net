//! Shared catalog/configuration admission contract; no TLS/authentication/egress claim.

use aegis_core::{RelaySettings, Settings};
use aegis_server::config::{ServerConfig, TransportConfig};
use std::collections::BTreeSet;

fn paths(primary: &str, pool: &[String]) -> BTreeSet<String> {
    std::iter::once(primary.to_owned())
        .chain(pool.iter().cloned())
        .collect()
}

fn client_paths(client: &RelaySettings) -> [BTreeSet<String>; 3] {
    [
        paths(&client.websocket_path, &client.websocket_path_pool),
        paths(&client.grpc_path, &client.grpc_path_pool),
        paths(&client.masque_path, &client.masque_path_pool),
    ]
}

fn expected_paths() -> [BTreeSet<String>; 3] {
    [
        ["/socket", "/ws", "/realtime/connect", "/aegis/ws"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        [
            "/rpc.Tunnel/Open",
            "/cdn.tunnel.v1.Session/Open",
            "/grpc.gateway.v1.Proxy/Connect",
            "/aegis.tunnel.v1.TunnelService/Open",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        [
            "/.well-known/masque/udp",
            "/.well-known/masque/connect-udp",
            "/masque/v1/udp",
            "/relay/datagram",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    ]
}

fn refused(client: &RelaySettings, server: &TransportConfig) -> Vec<(usize, String)> {
    let families = client_paths(client);
    let masque: BTreeSet<_> = server.accepted_masque_paths().map(str::to_owned).collect();
    families
        .into_iter()
        .enumerate()
        .flat_map(|(family, paths)| {
            let masque = &masque;
            paths.into_iter().filter_map(move |path| {
                let accepted = match family {
                    0 => server.accepts_websocket_path(&path),
                    1 => server.accepts_grpc_path(&path),
                    2 => masque.contains(&path),
                    _ => unreachable!(),
                };
                (!accepted).then_some((family, path))
            })
        })
        .collect()
}

#[test]
fn shipped_server_example_accepts_every_default_client_catalog_path() {
    let defaults = RelaySettings::default();
    let client: Settings = toml::from_str(include_str!("../../config.example.toml"))
        .expect("actual shipped client example parses");
    let server: ServerConfig = toml::from_str(include_str!("../../aegis-server.toml.example"))
        .expect("actual shipped server example parses");
    assert_eq!(
        client_paths(&defaults),
        expected_paths(),
        "original three-family default catalog"
    );
    assert_eq!(
        client_paths(&client.relay),
        expected_paths(),
        "actual shipped client preserves catalog"
    );
    assert!(
        refused(&defaults, &TransportConfig::default()).is_empty(),
        "runtime server default accepts all twelve paths"
    );
    assert_eq!(
        server.transport.websocket_path, "/socket",
        "neutral server primary"
    );
    assert_eq!(
        server.transport.grpc_path, "/rpc.Tunnel/Open",
        "neutral server primary"
    );
    assert!(!server.transport.accepts_websocket_path("/unconfigured"));
    assert!(!server.transport.accepts_grpc_path("/unconfigured"));
    let missing = refused(&defaults, &server.transport);
    eprintln!("catalog_validity default_client=12 shipped_client=12 runtime_server=12 shipped_server_refused={}", missing.len());
    assert!(
        missing.is_empty(),
        "shipped server refuses default client catalog entries: {missing:?}"
    );
}

#[test]
fn explicit_server_mounts_preserve_exact_operator_acceptance() {
    let transport: TransportConfig = toml::from_str(
        r#"
websocket_path = "/operator/socket"
websocket_path_pool = []
grpc_path = "/operator.Service/Open"
grpc_path_pool = []
masque_path = "/operator/udp"
masque_path_pool = []
"#,
    )
    .expect("explicit paths parse");
    assert!(transport.accepts_websocket_path("/operator/socket"));
    assert!(transport.accepts_grpc_path("/operator.Service/Open"));
    assert_eq!(
        transport.accepted_masque_paths().collect::<Vec<_>>(),
        vec!["/operator/udp"]
    );
    assert_eq!(refused(&RelaySettings::default(), &transport).len(), 12);
    for unknown in [
        "/operator/socket/",
        "/operator/socket-extra",
        "/Operator/socket",
        "/operator.Service/Open",
        "/unconfigured",
    ] {
        assert!(!transport.accepts_websocket_path(unknown));
    }
    for unknown in [
        "/operator.Service/Open/",
        "/operator.Service/Open-extra",
        "/Operator.Service/Open",
        "/operator/socket",
        "/unconfigured",
    ] {
        assert!(!transport.accepts_grpc_path(unknown));
    }
}

// Actual shell producers require /bin/bash. All portable parser/admission
// assertions above remain enabled on every platform. Run this integration case
// under the parent-owned bounded process-group supervisor; it installs nothing.
#[cfg(unix)]
#[test]
fn actual_installer_and_renderer_preserve_all_three_path_families() {
    use std::{
        fs,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let dir = tempfile::tempdir().expect("owned temporary directory");
    let server_path = dir.path().join("server.toml");
    let installer = include_str!("../../install.sh");
    let start = installer
        .find("\nwrite_server_config() {\n")
        .expect("actual producer start");
    let end = installer[start..]
        .find("\ninstall_text_file() {\n")
        .expect("actual producer end")
        + start;
    let script_path = dir.path().join("actual-writer.sh");
    let script = format!("set -euo pipefail\numask 077\n{}\nwrite_server_config \"$1\" cert.pem key.pem \"$2\" 127.0.0.1:8443\n", &installer[start..end]);
    aegis_core::secret_file::write_private_new(&script_path, script.as_bytes())
        .expect("private actual writer");
    let token = "0123456789abcdef".repeat(4); // Synthetic accepted-format test input.
    let writer = Command::new("/bin/bash")
        .arg(&script_path)
        .arg(&server_path)
        .arg(&token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("actual writer executes");
    assert!(
        writer.success(),
        "actual writer must succeed before catalog assertion"
    );
    let server: ServerConfig =
        toml::from_str(&fs::read_to_string(&server_path).expect("actual generated server config"))
            .expect("actual generated server parses");
    assert_eq!(server.auth_token, token, "actual producer positive");
    assert!(refused(&RelaySettings::default(), &server.transport).is_empty());
    let ca = dir.path().join("ca.pem");
    aegis_core::secret_file::write_private_new(&ca, b"synthetic fixture CA\n")
        .expect("private temporary CA");
    let bundle = dir.path().join("bundle");
    let auth = dir.path().join("auth");
    aegis_core::secret_file::write_private_new(&auth, token.as_bytes())
        .expect("private synthetic token");
    let input = fs::File::open(&auth).expect("owned token stdin");
    let rendered = Command::new("/bin/bash")
        .arg(root.join("scripts/render-client-bundle.sh"))
        .arg(&bundle)
        .arg("192.0.2.9:443")
        .arg("fixture.example")
        .arg("--auth-token-stdin")
        .arg(&ca)
        .arg(env!("CARGO_BIN_EXE_aegis-server"))
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("actual complete renderer executes");
    assert!(
        rendered.success(),
        "actual verified Rust reader/renderer must succeed before catalog assertion"
    );
    for name in ["aegis-client.toml", "aegis-client-privileged-dns.toml"] {
        let client: Settings = toml::from_str(
            &fs::read_to_string(bundle.join(name)).expect("actual rendered profile"),
        )
        .expect("actual rendered profile parses");
        assert_eq!(client.relay.auth_token, token, "actual renderer positive");
        assert_eq!(client.relay.server, "192.0.2.9:443");
        // The actual renderer uses neutral primaries and retains the
        // compatibility catalog for an explicitly configured old relay.
        assert_eq!(client.relay.websocket_path, "/socket");
        assert_eq!(client.relay.grpc_path, "/rpc.Tunnel/Open");
        assert_eq!(client.relay.masque_path, "/.well-known/masque/udp");
        for (emitted, canonical) in client_paths(&client.relay)
            .into_iter()
            .zip(expected_paths())
        {
            assert!(!emitted.is_empty(), "actual rendered family is present");
            assert!(
                emitted.is_subset(&canonical),
                "actual renderer emits no unconfigured catalog mounts"
            );
        }
        assert!(
            refused(&client.relay, &server.transport).is_empty(),
            "actual installed pair supports each rendered path"
        );
    }
}
