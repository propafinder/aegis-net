//! Разбор примера конфига сервера.

use aegis_server::config::ServerConfig;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn parse_example_toml() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aegis-server.toml.example"
    ));
    let c: ServerConfig = toml::from_str(raw).expect("parse");
    assert_eq!(c.fallback, "close");
    assert_eq!(c.auth_token, "change-me");
    assert!(c.legacy_auth_tokens.is_empty());
    assert_eq!(c.transport.websocket_path, "/socket");
    assert_eq!(
        c.transport.websocket_path_pool,
        vec!["/ws", "/realtime/connect", "/aegis/ws"]
    );
    assert_eq!(c.transport.grpc_path, "/rpc.Tunnel/Open");
    assert_eq!(
        c.transport.grpc_path_pool,
        vec![
            "/cdn.tunnel.v1.Session/Open",
            "/grpc.gateway.v1.Proxy/Connect",
            "/aegis.tunnel.v1.TunnelService/Open"
        ]
    );
    assert_eq!(c.transport.masque_path, "/.well-known/masque/udp");
    assert_eq!(
        c.transport.masque_path_pool,
        vec![
            "/.well-known/masque/connect-udp",
            "/masque/v1/udp",
            "/relay/datagram",
        ]
    );
    assert_eq!(c.transport.quic_keep_alive_interval_ms, 10_000);
    assert_eq!(c.transport.quic_max_idle_timeout_ms, 120_000);
    assert!(c
        .transport
        .accepts_grpc_path("/aegis.tunnel.v1.TunnelService/Open"));
    assert!(c.transport.accepts_grpc_path("/rpc.Tunnel/Open"));
    assert!(c.transport.accepts_grpc_path("/cdn.tunnel.v1.Session/Open"));
    assert!(!c.transport.accepts_grpc_path("/grpc/exact-match-only"));
    let accepted_masque_paths: Vec<_> = c.transport.accepted_masque_paths().collect();
    assert_eq!(
        accepted_masque_paths,
        vec![
            "/.well-known/masque/udp",
            "/.well-known/masque/connect-udp",
            "/masque/v1/udp",
            "/relay/datagram",
        ]
    );
}

#[test]
fn load_resolves_relative_cert_and_key_against_config_directory() {
    let temp_root = unique_temp_dir("aegis-server-config-relative");
    fs::create_dir_all(temp_root.join("nested/certs")).expect("create temp config dir");
    let config_path = temp_root.join("nested/aegis-server.toml");
    fs::write(
        &config_path,
        r#"listen = "127.0.0.1:8443"
cert = "certs/server.pem"
key = "certs/server-key.pem"
auth_token = "5dbd91d03bfb3b29baec232c5fb24dbbebf20f7f11439c7118036a9bc1df2183"
"#,
    )
    .expect("write temp config");
    private_config(&config_path);
    let cfg = aegis_server::config::load(&config_path).expect("load config");
    assert_eq!(cfg.cert, temp_root.join("nested/certs/server.pem"));
    assert_eq!(cfg.key, temp_root.join("nested/certs/server-key.pem"));

    fs::remove_dir_all(&temp_root).expect("remove temp config dir");
}

#[test]
fn load_keeps_absolute_cert_and_key_paths_unchanged() {
    let temp_root = unique_temp_dir("aegis-server-config-absolute");
    fs::create_dir_all(&temp_root).expect("create temp root");
    let cert = temp_root.join("server.pem");
    let key = temp_root.join("server-key.pem");
    let config_path = temp_root.join("aegis-server.toml");
    fs::write(
        &config_path,
        format!(
            "listen = \"127.0.0.1:8443\"\ncert = \"{}\"\nkey = \"{}\"\nauth_token = \"5dbd91d03bfb3b29baec232c5fb24dbbebf20f7f11439c7118036a9bc1df2183\"\n",
            cert.display(),
            key.display()
        ),
    )
    .expect("write temp config");
    private_config(&config_path);
    let cfg = aegis_server::config::load(&config_path).expect("load config");
    assert_eq!(cfg.cert, cert);
    assert_eq!(cfg.key, key);

    fs::remove_dir_all(&temp_root).expect("remove temp root");
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn private_config(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}
