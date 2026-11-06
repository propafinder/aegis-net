use super::*;
use aegis_core::{
    tunnel_policy::WindowsTunnelSettings,
    windows_tunnel::{firewall, lifecycle, network},
};
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Args)]
pub(super) struct PrepareArgs {
    #[arg(long)]
    config: PathBuf,
    /// New private directory for the imported profile and credential copies.
    #[arg(long)]
    output: PathBuf,
    /// Resolve relay hostnames once before capture; TLS names remain unchanged.
    #[arg(long)]
    resolve_relay: bool,
    /// Explicit UDP preference, e.g. grpc_datagram. Requires matching relay support.
    #[arg(long, value_delimiter = ',')]
    udp_transport: Vec<String>,
}

fn pin_candidates(address: &str, resolve: bool) -> Result<Vec<String>, WinctlError> {
    if address.parse::<SocketAddr>().is_ok() {
        return Ok(vec![address.to_owned()]);
    }
    if !resolve {
        return Err(invalid("relay hostname requires --resolve-relay or a numeric dial address; keep its TLS server_name"));
    }
    let mut candidates: Vec<_> = address.to_socket_addrs()?.collect();
    candidates.sort_by_key(|a| (a.is_ipv6(), *a));
    candidates.dedup();
    if candidates.is_empty() || candidates.len() > 128 {
        return Err(invalid("relay DNS address count rejected"));
    }
    Ok(candidates.into_iter().map(|a| a.to_string()).collect())
}
fn pin(address: &mut String, resolve: bool) -> Result<(), WinctlError> {
    *address = pin_candidates(address, resolve)?.remove(0);
    Ok(())
}

pub(super) fn prepare(args: PrepareArgs) -> Result<Value, WinctlError> {
    validate_root(&args.output)?;
    if args.output.exists() {
        return Err(invalid("profile output already exists"));
    }
    let raw = aegis_core::secret_file::read_config(&args.config, 4 * 1024 * 1024)?;
    let mut cfg: Settings =
        toml::from_str(std::str::from_utf8(&raw).map_err(|_| invalid("config encoding"))?)
            .map_err(|_| invalid("config parse"))?;
    if !matches!(cfg.mode, Mode::Relay) {
        return Err(invalid("only relay profiles can be imported; direct/Geneva/hybrid intent requires a separate Windows policy"));
    }
    cfg.ingress.allow_fallback = false;
    cfg.ingress.primary = IngressPrimary::Socks5;
    cfg.windows_tunnel = Some(WindowsTunnelSettings {
        dns_upstream: cfg.ingress.wide.dns_relay_upstream,
        ..Default::default()
    });
    if !args.udp_transport.is_empty() {
        cfg.relay.udp_transport_priority = Some(
            serde_json::from_value(json!(args.udp_transport))
                .map_err(|_| invalid("invalid UDP transport family"))?,
        );
    }
    let seeds = if cfg.relay.endpoints.is_empty() {
        vec![aegis_core::RelayEndpointSettings {
            server: cfg.relay.server.clone(),
            server_name: cfg.relay.server_name.clone(),
            masque_server: cfg.relay.masque_server.clone(),
            masque_server_name: cfg.relay.masque_server_name.clone(),
        }]
    } else {
        cfg.relay.endpoints.clone()
    };
    if seeds.len() > 128 {
        return Err(invalid("relay endpoint count rejected"));
    }
    let mut expanded = Vec::new();
    for mut endpoint in seeds {
        let addresses = pin_candidates(&endpoint.server, args.resolve_relay)?;
        if let Some(server) = &mut endpoint.masque_server {
            pin(server, args.resolve_relay)?;
        }
        for address in addresses {
            let mut next = endpoint.clone();
            next.server = address;
            if !expanded.contains(&next) {
                expanded.push(next);
            }
            if expanded.len() > 128 {
                return Err(invalid("resolved relay endpoint count rejected"));
            }
        }
    }
    cfg.relay.server = expanded
        .first()
        .ok_or_else(|| invalid("relay endpoints missing"))?
        .server
        .clone();
    cfg.relay.endpoints = expanded;
    if let Some(server) = &mut cfg.relay.masque_server {
        pin(server, args.resolve_relay)?;
    }
    let base = args.config.parent().unwrap_or_else(|| Path::new("."));
    let (config, credentials) = render_settings(&mut cfg, base, &args.output)?;
    let pins = cfg
        .windows_tunnel
        .as_ref()
        .unwrap()
        .relay_pins(&cfg.relay)
        .map_err(|e| invalid(&e))?;
    // Every source and policy check precedes creation. Never print the TOML,
    // authentication token, identity or key in a diagnostic response.
    windows_file::create_private_directory(&args.output, false, false)?;
    windows_file::create_private_directory(&args.output.join("config"), false, false)?;
    for (name, bytes) in credentials {
        windows_file::write_private_new(&args.output.join("config").join(name), &bytes, false)?;
    }
    let path = args.output.join("config/aegis.toml");
    windows_file::write_private_new(&path, &config, false)?;
    Ok(
        json!({"ok":true,"config":path,"relay_pins":pins,"profile":"system-tunnel",
        "direct_fallback":false,"source_preserved":true,"requires_relay_udp_support":true}),
    )
}

fn managed(root: &Path) -> Result<Receipt, WinctlError> {
    let receipt = verify_installed(root)?;
    if !receipt.service {
        return Err(invalid("this installation has no managed service"));
    }
    service::require_binary_in(&receipt.service_name, &root.join("bin/aegis-client.exe"))?;
    Ok(receipt)
}

pub(super) fn connect(root: &Path) -> Result<Value, WinctlError> {
    let receipt = managed(root)?;
    render_config_online(
        &root.join("config/aegis.toml"),
        root,
        receipt.managed_online,
    )?;
    let result = if receipt.system_tunnel {
        service::auto_start_then_start(&receipt.service_name)?
    } else {
        service::run(ServiceCommand::Start(ServiceNameArg {
            service_name: receipt.service_name,
        }))?
    };
    Ok(json!({"ok":true,"root":root,"service":result["service"],"relay_health":"not_probed"}))
}

pub(super) fn disconnect(root: &Path) -> Result<Value, WinctlError> {
    let receipt = managed(root)?;
    if receipt.system_tunnel {
        service::disable_then_stop(&receipt.service_name)?;
    } else {
        service::run(ServiceCommand::Stop(ServiceNameArg {
            service_name: receipt.service_name,
        }))?;
    }
    let mut recovered = 0;
    if receipt.system_tunnel {
        let _exclusive = lifecycle::Exclusive::acquire()?;
        recovered =
            lifecycle::recover_routes(&lifecycle::journal_path(&root.join("config/aegis.toml")))?;
        firewall::disconnect_owned(&root.join("bin/aegis-client.exe"))?;
    }
    Ok(json!({"ok":true,"root":root,"disconnected":true,"recovered_routes":recovered}))
}

pub(super) fn doctor(root: &Path) -> Result<Value, WinctlError> {
    let receipt = verify_installed(root)?;
    let (config, _) = render_config_online(
        &root.join("config/aegis.toml"),
        root,
        receipt.managed_online,
    )?;
    let cfg: Settings =
        toml::from_str(std::str::from_utf8(&config).map_err(|_| invalid("config encoding"))?)
            .map_err(|_| invalid("config parse"))?;
    let owned = if receipt.service {
        service::require_binary_in(&receipt.service_name, &root.join("bin/aegis-client.exe"))?;
        service::query(&receipt.service_name)?
    } else {
        Value::Null
    };
    let tunnel = if let Some(policy) = cfg.windows_tunnel {
        let pins = policy.relay_pins(&cfg.relay).map_err(|e| invalid(&e))?;
        let adapter = network::adapter_luid(&policy.adapter_name);
        let adapter_lookup_error = adapter
            .as_ref()
            .err()
            .map(|error| json!({"os_code": error.raw_os_error(), "message": error.to_string()}));
        json!({"adapter_name":policy.adapter_name,"adapter_present":adapter.is_ok(),
            "adapter_lookup_error":adapter_lookup_error,
            "relay_pins":pins,"full_capture":policy.include_routes.is_empty(),
            "kill_switch_configured":policy.kill_switch,"system_dns_configured":policy.configure_dns,
            "persistent_filter_count":firewall::status()?,
            "protection":firewall::inspect(Some(&root.join("bin/aegis-client.exe")))?,
            "recovery_journal_present":lifecycle::journal_path(&root.join("config/aegis.toml")).try_exists()?})
    } else {
        Value::Null
    };
    Ok(
        json!({"ok":true,"root":root,"integrity":"verified","configuration":"valid",
        "administrator":super::super::is_elevated(),"service":owned,"tunnel":tunnel,
        "publisher_signature_verified":receipt.publisher_signature_verified,
        "relay_health":"not_probed","filter_presence_is_not_relay_health":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_linux_wide_with_separate_masque_ca_and_preserves_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("linux.toml");
        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Default::default()
        };
        cfg.ingress.primary = IngressPrimary::Wide;
        cfg.relay.server = "127.0.0.1:443".into();
        cfg.relay.server_name = "relay.test".into();
        cfg.relay.masque_server = Some("[::1]:8443".into());
        cfg.relay.masque_server_name = Some("quic.test".into());
        cfg.relay.ca_cert = Some("outer.pem".into());
        cfg.relay.masque_ca_cert = Some("quic.pem".into());
        std::fs::write(temp.path().join("outer.pem"), b"outer fixture").unwrap();
        std::fs::write(temp.path().join("quic.pem"), b"quic fixture").unwrap();
        let original = toml::to_string(&cfg).unwrap();
        windows_file::write_private_new(&source, original.as_bytes(), false).unwrap();
        let output = temp.path().join("windows");
        let result = prepare(PrepareArgs {
            config: source.clone(),
            output: output.clone(),
            resolve_relay: false,
            udp_transport: vec!["grpc_datagram".into()],
        })
        .unwrap();
        assert_eq!(result["ok"], true);
        assert!(!result.to_string().contains("auth_token"));
        let copied: Settings =
            toml::from_str(&std::fs::read_to_string(output.join("config/aegis.toml")).unwrap())
                .unwrap();
        assert_eq!(copied.relay.server_name, "relay.test");
        assert_eq!(
            copied.relay.masque_server_name.as_deref(),
            Some("quic.test")
        );
        assert_eq!(
            std::fs::read(copied.relay.masque_ca_cert.unwrap()).unwrap(),
            b"quic fixture"
        );
        assert_eq!(std::fs::read_to_string(source).unwrap(), original);
        assert!(!copied.ingress.allow_fallback);
        assert!(copied.windows_tunnel.unwrap().kill_switch);
    }
    #[test]
    fn hostname_never_resolves_without_explicit_import_option() {
        let mut address = "relay.example:443".to_owned();
        assert!(pin(&mut address, false).is_err());
        assert_eq!(address, "relay.example:443");
    }
}
