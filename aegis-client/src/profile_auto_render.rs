//! Private unapplied proposal: deterministic AUTO config rendering from captured bytes.
//! No file, resolver, process, credential-loader or publication IO occurs here.
use aegis_core::{Mode, Settings};
use rand::RngCore;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use toml_edit::{value, Array, DocumentMut, Item, Table};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SelectedMode {
    SocksOnly,
    WideRedirectSafe,
    FullWideTun,
}
pub(crate) enum InputKind {
    FreshBundle,
    ExistingUpgrade,
}
// This type must be constructed by the transaction from a captured resolver
// observation; arbitrary CLI arguments are not an authoritative observation.
pub(crate) struct RelayPin {
    pub original: String,
    pub selected: SocketAddrV4,
}
pub(crate) struct Options {
    pub mode: SelectedMode,
    pub input: InputKind,
    pub final_ca: PathBuf,
    pub final_state: PathBuf,
    pub logical_original_base: PathBuf,
    pub logical_final_base: PathBuf,
    pub fresh_local_token: Option<Zeroizing<String>>,
    pub masque_server: Option<String>,
    pub final_masque_ca: Option<PathBuf>,
    pub captured_bundle_ca: Option<PathBuf>,
    pub captured_masque_ca: Option<PathBuf>,
    pub captured_previous_state: Option<PathBuf>,
    pub relay_pin: Option<RelayPin>,
    // Capture separately supplies the expansion decision; never expand HOME here.
    pub state_path_needs_relocation: bool,
    pub wide_interface: Option<String>,
}
// No Debug/Serialize: config bytes and fingerprints must stay private.
pub(crate) struct Rendered {
    pub bytes: Zeroizing<String>,
    // This requests publication of a separately captured runtime state artifact,
    // not a fresh read or an implicit copy before the transaction's commit gate.
    pub previous_state_reference: Option<String>,
    pub logical_original_base: PathBuf,
    pub logical_final_base: PathBuf,
}
pub(crate) fn fresh_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(hex::encode(bytes.as_ref()))
}

fn table<'a>(doc: &'a mut DocumentMut, path: &[&str]) -> Result<&'a mut Table, &'static str> {
    let mut parent = doc.as_table_mut();
    for key in path {
        if !parent.contains_key(key) {
            parent.insert(key, Item::Table(Table::new()));
        }
        parent = parent
            .get_mut(key)
            .and_then(Item::as_table_mut)
            .ok_or("auto_render_table_invalid")?;
    }
    Ok(parent)
}
fn put(t: &mut Table, key: &str, mut item: Item) {
    // Preserve an existing value's comment/whitespace decoration.
    if let (Some(old), Some(new)) = (t.get(key).and_then(Item::as_value), item.as_value_mut()) {
        *new.decor_mut() = old.decor().clone();
    }
    t.insert(key, item);
}
fn path_string(p: &Path) -> Result<&str, &'static str> {
    if !p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("auto_render_final_path_invalid");
    }
    p.to_str().ok_or("auto_render_final_path_invalid")
}
fn plan(values: &[&str]) -> Item {
    let mut a = Array::new();
    for s in values {
        a.push(*s);
    }
    value(a)
}

fn scoped_redirect_listener(wide: &aegis_core::WideIngressSettings) -> Option<SocketAddrV4> {
    use aegis_core::WideRolloutProfile;
    if wide.rollout_profile != WideRolloutProfile::PreroutingScoped {
        return None;
    }
    let interface = wide.prerouting_interface.as_deref()?;
    if interface.is_empty()
        || interface.len() > 15
        || !interface.as_bytes()[0].is_ascii_alphanumeric()
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(&byte))
    {
        return None;
    }
    let SocketAddr::V4(listener) = wide.listen else {
        return None;
    };
    let address = listener.ip();
    if listener.port() != 15080
        || address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
    {
        return None;
    }
    Some(listener)
}

fn validate_selected_mode(settings: &Settings, mode: &SelectedMode) -> Result<(), &'static str> {
    use aegis_core::{
        IngressPrimary, WidePlatformBackend, WideRolloutProfile, WideUdpCaptureContract,
    };
    let wide = &settings.ingress.wide;
    match mode {
        SelectedMode::SocksOnly => {
            if settings.ingress.primary != IngressPrimary::Socks5 {
                return Err("auto_render_selected_socks_scope_mismatch");
            }
        }
        SelectedMode::WideRedirectSafe | SelectedMode::FullWideTun => {
            let full = matches!(mode, SelectedMode::FullWideTun);
            let listener_matches = if full {
                wide.listen.to_string() == "127.0.0.1:980"
            } else {
                match wide.rollout_profile {
                    WideRolloutProfile::OutputOnlySafe => {
                        wide.listen.to_string() == "127.0.0.1:15080"
                    }
                    WideRolloutProfile::PreroutingScoped => {
                        scoped_redirect_listener(wide).is_some()
                    }
                    WideRolloutProfile::TransparentPrivileged => false,
                }
            };
            if settings.ingress.primary != IngressPrimary::Wide
                || !wide.enabled
                || wide.platform_backend != WidePlatformBackend::LinuxRedirect
                || !listener_matches
                || wide.ipv6_tun_carried != full
                || wide.udp_capture_contract
                    != if full {
                        WideUdpCaptureContract::GenericCaptureUnstable
                    } else {
                        WideUdpCaptureContract::PreviewAllowlistOnly
                    }
            {
                return Err("auto_render_selected_wide_scope_mismatch");
            }
            if full
                && (!wide.capture_dns
                    || wide.dns_preview_listen.map(|x| x.to_string()).as_deref()
                        != Some("127.0.0.1:53"))
            {
                return Err("auto_render_selected_tun_dns_mismatch");
            }
        }
    }
    Ok(())
}

pub(crate) fn render(captured: &[u8], options: &Options) -> Result<Rendered, &'static str> {
    if captured.is_empty() || captured.len() > 4 * 1024 * 1024 {
        return Err("auto_render_input_bound");
    }
    let text = std::str::from_utf8(captured).map_err(|_| "auto_render_encoding_invalid")?;
    let mut doc = text
        .parse::<DocumentMut>()
        .map_err(|_| "auto_render_parse_invalid")?;
    // DocumentMut preserves unknown fields and comments; Settings is used only
    // for semantic validation, never as the source of reserialized output.
    let original: Settings = toml::from_str(text).map_err(|_| "auto_render_parse_invalid")?;
    if !matches!(original.mode, Mode::Relay)
        || (original.relay.inner_tls.is_none() && original.relay.auth_token.trim().is_empty())
    {
        return Err("auto_render_legacy_bundle_required");
    }
    crate::profile_auto::validate_auto_relay_auth(&original)
        .map_err(|_| "auto_render_relay_auth_invalid")?;
    if options.mode != SelectedMode::SocksOnly {
        crate::profile_auto::validate_auto_capture_tcp_carrier(&original)
            .map_err(|_| "auto_render_capture_tcp_carrier_unready")?;
    }
    let scoped_redirect_listen = if matches!(options.mode, SelectedMode::WideRedirectSafe)
        && original.ingress.wide.rollout_profile == aegis_core::WideRolloutProfile::PreroutingScoped
    {
        let explicit = doc
            .as_table()
            .get("ingress")
            .and_then(Item::as_table)
            .and_then(|ingress| ingress.get("wide"))
            .and_then(Item::as_table)
            .and_then(|wide| wide.get("listen"))
            .and_then(Item::as_str)
            .ok_or("auto_render_scoped_listen_explicit_required")?;
        let listener = scoped_redirect_listener(&original.ingress.wide)
            .ok_or("auto_render_scoped_listen_invalid")?;
        if explicit != listener.to_string()
            || options.wide_interface.as_deref()
                != original.ingress.wide.prerouting_interface.as_deref()
        {
            return Err("auto_render_scoped_binding_mismatch");
        }
        Some(listener.to_string())
    } else {
        None
    };
    let fresh = matches!(options.input, InputKind::FreshBundle);
    if fresh {
        let token = options
            .fresh_local_token
            .as_ref()
            .ok_or("auto_render_token_missing")?;
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("auto_render_token_invalid");
        }
        let socks = table(&mut doc, &["socks"])?;
        // Creating a partial [socks] table loses Settings' whole-table default.
        // Materialize the already parsed typed listener, preserving an explicit
        // operator listener and its decoration rather than inventing a new port.
        if !socks.contains_key("listen") {
            put(socks, "listen", value(original.socks.listen.to_string()));
        }
        put(socks, "auth_token", value(token.as_str()));
        put(table(&mut doc, &["ingress"])?, "primary", value("socks5"));
        if !doc.as_table().contains_key("local_stealth_profile") {
            put(
                doc.as_table_mut(),
                "local_stealth_profile",
                value("local_hardened"),
            );
        }
        let relay = table(&mut doc, &["relay"])?;
        if relay.get("ca_cert").and_then(Item::as_str) == Some("__CLIENT_CA_CERT_PATH__") {
            put(relay, "ca_cert", value(path_string(&options.final_ca)?));
        }
    } else if options.fresh_local_token.is_some() {
        return Err("auto_render_unexpected_token");
    }
    let direct = table(&mut doc, &["direct"])?;
    let previous_state_reference = direct
        .get("state_path")
        .and_then(Item::as_str)
        .map(str::to_owned);
    if previous_state_reference.is_none() || options.state_path_needs_relocation {
        put(
            direct,
            "state_path",
            value(path_string(&options.final_state)?),
        );
    }
    if !matches!(options.mode, SelectedMode::SocksOnly) {
        put(table(&mut doc, &["ingress"])?, "primary", value("wide"));
        let full = matches!(options.mode, SelectedMode::FullWideTun);
        let wide = table(&mut doc, &["ingress", "wide"])?;
        put(wide, "enabled", value(true));
        put(wide, "platform_backend", value("linux_redirect"));
        let listen = if full {
            "127.0.0.1:980"
        } else {
            scoped_redirect_listen
                .as_deref()
                .unwrap_or("127.0.0.1:15080")
        };
        put(wide, "listen", value(listen));
        put(wide, "ipv6_tun_carried", value(full));
        put(
            wide,
            "udp_capture_contract",
            value(if full {
                "generic_capture_unstable"
            } else {
                "preview_allowlist_only"
            }),
        );
        if full {
            put(wide, "capture_dns", value(true));
            put(wide, "dns_preview_listen", value("127.0.0.1:53"));
        }
        if !full {
            let wide = table(&mut doc, &["ingress", "wide"])?;
            put(wide, "dns_preview_listen", value("127.0.0.1:53"));
            put(wide, "dns_preview_fake_ip_pool", value("198.18.0.0/15"));
            put(wide, "dns_preview_fake_ip_ttl_secs", value(60));
        }
        let relay = table(&mut doc, &["relay"])?;
        let endpoint = relay
            .get("server")
            .and_then(Item::as_str)
            .ok_or("auto_render_relay_endpoint_missing")?
            .to_owned();
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or("auto_render_relay_endpoint_invalid")?;
        let port: u16 = port
            .parse()
            .map_err(|_| "auto_render_relay_endpoint_invalid")?;
        if let Some(pin) = &options.relay_pin {
            if pin.original != endpoint || pin.selected.port() != port {
                return Err("auto_render_pin_generation_mismatch");
            }
            put(relay, "server", value(pin.selected.to_string()));
        } else if host.parse::<Ipv4Addr>().is_err() {
            return Err("auto_render_resolver_observation_required");
        }
        if full {
            if let Some(server) = &options.masque_server {
                let (host, _) = server
                    .rsplit_once(':')
                    .ok_or("auto_render_masque_endpoint_invalid")?;
                put(relay, "masque_server", value(server.as_str()));
                put(
                    relay,
                    "masque_server_name",
                    value(host.trim_matches(['[', ']'])),
                );
            }
            if let Some(ca) = &options.final_masque_ca {
                put(relay, "masque_ca_cert", value(path_string(ca)?));
            }
            let masque = relay
                .get("masque_server")
                .and_then(Item::as_str)
                .is_some_and(|s| !s.is_empty());
            put(
                relay,
                "udp_transport_priority",
                if masque {
                    plan(&["masque_derived", "grpc_datagram"])
                } else {
                    plan(&["grpc_datagram"])
                },
            );
        } else {
            // Local Redirect carries non-A DNS through the relay datagram
            // channel too. A TCP-only input plan is not an executable UDP
            // plan; it otherwise produces immediate SERVFAIL for AAAA/UDP.
            // Capture stays DNS-only: arbitrary UDP remains guard-blocked.
            put(relay, "udp_transport_priority", plan(&["grpc_datagram"]));
        }
    }
    let rendered = Zeroizing::new(doc.to_string());
    let mut settings: Settings =
        toml::from_str(&rendered).map_err(|_| "auto_render_final_parse_invalid")?;
    settings
        .validate_privacy_plan()
        .map_err(|_| "auto_render_privacy_invalid")?;
    settings
        .socks
        .validate_tcp_policy()
        .map_err(|_| "auto_render_socks_policy_invalid")?;
    crate::profile_auto::validate_auto_relay_auth(&settings)
        .map_err(|_| "auto_render_relay_auth_invalid")?;
    if options.mode != SelectedMode::SocksOnly {
        crate::profile_auto::validate_auto_capture_tcp_carrier(&settings)
            .map_err(|_| "auto_render_capture_tcp_carrier_unready")?;
    }
    validate_selected_mode(&settings, &options.mode)?;
    settings.materialize_stealth_profiles();
    settings
        .validate_ech()
        .map_err(|_| "auto_render_ech_invalid")?;
    settings
        .validate_inner_tls()
        .map_err(|_| "auto_render_inner_policy_invalid")?;
    settings
        .validate_relay_outer_geneva()
        .map_err(|_| "auto_render_outer_geneva_invalid")?;
    settings
        .validate_hybrid_geneva()
        .map_err(|_| "auto_render_hybrid_invalid")?;
    // Runtime file-backed validators, compile-feature compatibility and selected
    // DNS-preview checks must run against separately captured references before
    // the transaction seals/publishes. This value is deliberately not a seal.
    Ok(Rendered {
        bytes: rendered,
        previous_state_reference: if options.state_path_needs_relocation {
            previous_state_reference
        } else {
            None
        },
        logical_original_base: options.logical_original_base.clone(),
        logical_final_base: options.logical_final_base.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device_fixture() -> String {
        "mode = 'relay'\n[relay]\nserver = '10.231.80.2:443'\nserver_name = 'relay.aegis.test'\nauth_token = ''\nca_cert = '/srv/bundle/ca.pem'\ntls_backend = 'rustls'\ntransport_priority = ['grpc_stream']\nudp_transport_priority = ['grpc_datagram']\n[relay.inner_tls]\nserver_name = 'origin.aegis.test'\nserver_ca = '/srv/bundle/inner-ca.pem'\ncert = '/srv/bundle/device.pem'\nkey = '/srv/bundle/device.key'\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '127.0.0.1:0'\n[direct]\npersist_state = false\n".into()
    }

    #[test]
    fn auto_device_auth_renders_and_rejects_legacy_or_mixed_carriers() {
        let opts = options(SelectedMode::SocksOnly, InputKind::ExistingUpgrade);
        let source = device_fixture();
        let rendered = render(source.as_bytes(), &opts).unwrap();
        let accepted: Settings = toml::from_str(&rendered.bytes).unwrap();
        assert!(accepted.relay.auth_token.is_empty());
        assert_eq!(
            accepted.relay.inner_tls.as_ref().unwrap().server_name,
            "origin.aegis.test"
        );
        assert!(crate::profile_auto::validate_auto_relay_auth(&accepted).is_ok());
        for (name, changed) in [
            ("mixed", source.replacen("auth_token = ''", "auth_token = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'", 1)),
            ("raw", source.replacen("transport_priority = ['grpc_stream']", "transport_priority = ['legacy_tls']", 1)),
            ("no_outer_ca", source.replacen("ca_cert = '/srv/bundle/ca.pem'\n", "", 1)),
        ] {
            let parsed: Settings = toml::from_str(&changed).unwrap();
            assert!(crate::profile_auto::validate_auto_relay_auth(&parsed).is_err(), "{name}");
            assert_eq!(render(changed.as_bytes(), &opts).err(),
                       Some("auto_render_relay_auth_invalid"), "{name}");
        }
        for token in ["", "synthetic-token"] {
            let legacy = source
                .replacen("auth_token = ''", &format!("auth_token = '{token}'"), 1)
                .replace("[relay.inner_tls]\nserver_name = 'origin.aegis.test'\nserver_ca = '/srv/bundle/inner-ca.pem'\ncert = '/srv/bundle/device.pem'\nkey = '/srv/bundle/device.key'\n", "");
            let parsed: Settings = toml::from_str(&legacy).unwrap();
            assert!(crate::profile_auto::validate_auto_relay_auth(&parsed).is_err());
            assert!(render(legacy.as_bytes(), &opts).is_err());
        }
    }
    fn fixture() -> String {
        format!("# preserved document comment\nmode = \"relay\"\nprocess_alias = 'untouched'\n[relay]\nserver = \"192.0.2.4:443\"\nserver_name = \"fixture.invalid\"\nauth_token = \"{}\"\nca_cert = \"__CLIENT_CA_CERT_PATH__\" # CA comment\ntransport_priority = ['grpc_stream']\n[direct]\nstate_path = \"/srv/custom-state.json\"\npersist_state = true # retained direct policy\n", "0123456789abcdef".repeat(4))
    }
    fn options(mode: SelectedMode, input: InputKind) -> Options {
        let fresh = matches!(input, InputKind::FreshBundle);
        Options {
            mode,
            input,
            final_ca: "/etc/aegis/client/ca.pem".into(),
            final_state: "/var/lib/aegis/state.json".into(),
            logical_original_base: "/srv/bundle".into(),
            logical_final_base: "/etc/aegis/client".into(),
            fresh_local_token: fresh.then(|| Zeroizing::new("b".repeat(64))),
            masque_server: None,
            final_masque_ca: None,
            captured_bundle_ca: Some("/srv/bundle/ca.pem".into()),
            captured_masque_ca: None,
            captured_previous_state: None,
            relay_pin: None,
            state_path_needs_relocation: false,
            wide_interface: None,
        }
    }
    #[test]
    fn wide_render_refuses_old_mixed_first_carrier_but_socks_remains_available() {
        let ready = fixture();
        let mixed = ready.replace(
            "transport_priority = ['grpc_stream']",
            "transport_priority = ['https_ws', 'grpc_stream', 'legacy_tls', 'masque_derived']",
        );
        for mode in [SelectedMode::WideRedirectSafe, SelectedMode::FullWideTun] {
            let options = options(mode, InputKind::ExistingUpgrade);
            assert_eq!(
                render(mixed.as_bytes(), &options).err(),
                Some("auto_render_capture_tcp_carrier_unready")
            );
        }
        assert!(render(
            mixed.as_bytes(),
            &options(SelectedMode::SocksOnly, InputKind::FreshBundle)
        )
        .is_ok());
        assert!(render(
            ready.as_bytes(),
            &options(SelectedMode::FullWideTun, InputKind::FreshBundle)
        )
        .is_ok());
    }
    #[test]
    fn fresh_socks_preserves_unknown_fields_comments_and_custom_state() {
        let out = render(
            fixture().as_bytes(),
            &options(SelectedMode::SocksOnly, InputKind::FreshBundle),
        )
        .unwrap();
        assert!(out.bytes.contains("# preserved document comment"));
        assert!(out.bytes.contains("process_alias = 'untouched'"));
        assert!(out
            .bytes
            .contains("persist_state = true # retained direct policy"));
        assert!(out.bytes.contains("# CA comment"));
        let value: toml::Value = toml::from_str(&out.bytes).unwrap();
        assert_eq!(
            value["relay"]["ca_cert"].as_str(),
            Some("/etc/aegis/client/ca.pem")
        );
        assert_eq!(
            value["direct"]["state_path"].as_str(),
            Some("/srv/custom-state.json")
        );
        assert_eq!(
            value["socks"]["auth_token"].as_str(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(value["ingress"]["primary"].as_str(), Some("socks5"));
        assert!(out.previous_state_reference.is_none());
    }
    #[test]
    fn fresh_missing_socks_materializes_the_parsed_whole_table_default() {
        let source = fixture();
        let original: Settings = toml::from_str(&source).unwrap();
        let out = render(
            source.as_bytes(),
            &options(SelectedMode::SocksOnly, InputKind::FreshBundle),
        )
        .unwrap();
        let parsed: Settings = toml::from_str(&out.bytes).unwrap();
        let value: toml::Value = toml::from_str(&out.bytes).unwrap();
        assert_eq!(parsed.socks.listen, original.socks.listen);
        assert_eq!(
            value["socks"]["listen"].as_str(),
            Some(original.socks.listen.to_string().as_str())
        );
        assert_eq!(
            parsed.socks.auth_token.as_deref(),
            Some("b".repeat(64).as_str())
        );
    }
    #[test]
    fn fresh_explicit_socks_listener_and_comment_are_preserved() {
        let source = fixture() + "[socks]\nlisten = '127.0.0.1:19080' # operator listener\n";
        let out = render(
            source.as_bytes(),
            &options(SelectedMode::SocksOnly, InputKind::FreshBundle),
        )
        .unwrap();
        let parsed: Settings = toml::from_str(&out.bytes).unwrap();
        assert_eq!(
            parsed.socks.listen,
            "127.0.0.1:19080".parse::<std::net::SocketAddr>().unwrap()
        );
        assert!(out.bytes.contains("# operator listener"));
        assert_eq!(
            parsed.socks.auth_token.as_deref(),
            Some("b".repeat(64).as_str())
        );
    }
    #[test]
    fn incomplete_existing_socks_table_keeps_the_mandatory_listener_guard() {
        let source = fixture() + "[socks]\nauth_token = 'existing-local-token'\n";
        assert_eq!(
            render(
                source.as_bytes(),
                &options(SelectedMode::SocksOnly, InputKind::FreshBundle),
            )
            .err(),
            Some("auto_render_parse_invalid")
        );
    }
    #[test]
    fn limited_upgrade_clears_carried_flags_without_rotating_token_or_relative_refs() {
        let source = fixture().replace("__CLIENT_CA_CERT_PATH__", "nested/ca.pem") + "[ingress.wide]\nipv6_tun_carried = true\nudp_capture_contract = 'generic_capture_unstable'\n[socks]\nlisten = '127.0.0.1:19080'\nauth_token = 'existing-local-token'\n";
        let out = render(
            source.as_bytes(),
            &options(SelectedMode::WideRedirectSafe, InputKind::ExistingUpgrade),
        )
        .unwrap();
        let value: toml::Value = toml::from_str(&out.bytes).unwrap();
        assert_eq!(value["relay"]["ca_cert"].as_str(), Some("nested/ca.pem"));
        assert_eq!(
            value["socks"]["auth_token"].as_str(),
            Some("existing-local-token")
        );
        assert_eq!(
            value["ingress"]["wide"]["listen"].as_str(),
            Some("127.0.0.1:15080")
        );
        assert_eq!(
            value["ingress"]["wide"]["ipv6_tun_carried"].as_bool(),
            Some(false)
        );
        assert_eq!(
            value["ingress"]["wide"]["udp_capture_contract"].as_str(),
            Some("preview_allowlist_only")
        );
        assert_eq!(out.logical_original_base, PathBuf::from("/srv/bundle"));
        assert_eq!(out.logical_final_base, PathBuf::from("/etc/aegis/client"));
    }
    #[test]
    fn scoped_redirect_preserves_only_explicit_source_bound_ipv4_listener() {
        let source = fixture()
            + "[ingress.wide]\nrollout_profile = 'prerouting_scoped'\nprerouting_interface = 'lan0'\nlisten = '10.231.81.1:15080'\n";
        let mut scoped = options(SelectedMode::WideRedirectSafe, InputKind::ExistingUpgrade);
        scoped.wide_interface = Some("lan0".into());
        let out = render(source.as_bytes(), &scoped).unwrap();
        let published: Settings = toml::from_str(&out.bytes).unwrap();
        assert_eq!(
            published.ingress.wide.listen.to_string(),
            "10.231.81.1:15080"
        );
        assert_eq!(
            published.ingress.wide.prerouting_interface.as_deref(),
            Some("lan0")
        );
        assert_eq!(
            render(
                source
                    .replace("listen = '10.231.81.1:15080'\n", "")
                    .as_bytes(),
                &scoped
            )
            .err(),
            Some("auto_render_scoped_listen_explicit_required")
        );
        for forbidden in [
            "0.0.0.0:15080",
            "127.0.0.1:15080",
            "224.0.0.1:15080",
            "255.255.255.255:15080",
            "10.231.81.1:15081",
            "[2001:db8::1]:15080",
        ] {
            assert_eq!(
                render(
                    source.replace("10.231.81.1:15080", forbidden).as_bytes(),
                    &scoped
                )
                .err(),
                Some("auto_render_scoped_listen_invalid")
            );
        }
        scoped.wide_interface = Some("other0".into());
        assert_eq!(
            render(source.as_bytes(), &scoped).err(),
            Some("auto_render_scoped_binding_mismatch")
        );
    }
    #[test]
    fn full_tun_has_reserved_ports_dns_and_independent_udp_plan() {
        let out = render(
            fixture().as_bytes(),
            &options(SelectedMode::FullWideTun, InputKind::FreshBundle),
        )
        .unwrap();
        let value: toml::Value = toml::from_str(&out.bytes).unwrap();
        assert_eq!(
            value["ingress"]["wide"]["listen"].as_str(),
            Some("127.0.0.1:980")
        );
        assert_eq!(
            value["ingress"]["wide"]["dns_preview_listen"].as_str(),
            Some("127.0.0.1:53")
        );
        assert_eq!(
            value["ingress"]["wide"]["capture_dns"].as_bool(),
            Some(true)
        );
        assert_eq!(
            value["relay"]["udp_transport_priority"].as_array().unwrap(),
            &vec![toml::Value::String("grpc_datagram".into())]
        );
        assert_eq!(
            value["relay"]["server_name"].as_str(),
            Some("fixture.invalid")
        );
    }
    #[test]
    fn redirect_tcp_only_bundle_still_has_executable_dns_datagram_plan() {
        let source = fixture();
        let before: Settings = toml::from_str(&source).unwrap();
        assert!(!crate::relay::runtime_udp_fallback_ready(&before.relay));
        let out = render(
            source.as_bytes(),
            &options(SelectedMode::WideRedirectSafe, InputKind::FreshBundle),
        )
        .unwrap();
        let after: Settings = toml::from_str(&out.bytes).unwrap();
        assert!(crate::relay::runtime_udp_fallback_ready(&after.relay));
        assert_eq!(after.relay.server, before.relay.server);
        assert_eq!(after.relay.server_name, before.relay.server_name);
        assert_eq!(
            after.ingress.wide.udp_capture_contract,
            aegis_core::WideUdpCaptureContract::PreviewAllowlistOnly
        );
        assert!(!after.ingress.wide.ipv6_tun_carried);
        assert_eq!(
            after.ingress.wide.dns_preview_listen,
            Some("127.0.0.1:53".parse().unwrap())
        );
    }
    #[test]
    fn resolver_observation_and_state_copy_request_bind_original_values() {
        let source = fixture().replace("192.0.2.4:443", "fixture.invalid:443");
        let mut o = options(SelectedMode::FullWideTun, InputKind::FreshBundle);
        assert!(render(source.as_bytes(), &o).is_err());
        o.relay_pin = Some(RelayPin {
            original: "other.invalid:443".into(),
            selected: "192.0.2.9:443".parse().unwrap(),
        });
        assert!(render(source.as_bytes(), &o).is_err());
        o.relay_pin.as_mut().unwrap().original = "fixture.invalid:443".into();
        o.state_path_needs_relocation = true;
        let out = render(source.as_bytes(), &o).unwrap();
        assert_eq!(
            out.previous_state_reference.as_deref(),
            Some("/srv/custom-state.json")
        );
        let value: toml::Value = toml::from_str(&out.bytes).unwrap();
        assert_eq!(value["relay"]["server"].as_str(), Some("192.0.2.9:443"));
        assert_eq!(
            value["relay"]["server_name"].as_str(),
            Some("fixture.invalid")
        );
        assert_eq!(
            value["direct"]["state_path"].as_str(),
            Some("/var/lib/aegis/state.json")
        );
    }
    #[test]
    fn invalid_text_and_token_refuse_without_echoing_config() {
        let mut o = options(SelectedMode::SocksOnly, InputKind::FreshBundle);
        assert_eq!(
            render(b"secret invalid = [", &o).err(),
            Some("auto_render_parse_invalid")
        );
        o.fresh_local_token = Some(Zeroizing::new("short-secret".into()));
        assert_eq!(
            render(fixture().as_bytes(), &o).err(),
            Some("auto_render_token_invalid")
        );
    }
}

// Construct references from independently admitted CapturedTree objects; not
// from JSON paths or original filesystem reads. This is an internal transaction
// contract, not a public credential-copy command.
pub(crate) struct CapturedReference<'a> {
    original_logical_path: &'a Path,
    final_logical_path: &'a Path,
    bytes: &'a [u8],
    private_admission: bool,
}
impl<'a> CapturedReference<'a> {
    pub(crate) fn public_certificate(
        original: &'a Path,
        final_path: &'a Path,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            original_logical_path: original,
            final_logical_path: final_path,
            bytes,
            private_admission: false,
        }
    }
    pub(crate) fn private_credential(
        final_path: &'a Path,
        capability: &'a crate::profile_auto_capture::PrivateReference<'a>,
    ) -> Self {
        Self {
            original_logical_path: capability.original_path(),
            final_logical_path: final_path,
            bytes: capability.bytes(),
            private_admission: true,
        }
    }
}
pub(crate) struct ReferenceSet<'a> {
    pub entries: &'a [CapturedReference<'a>],
}
impl<'a> ReferenceSet<'a> {
    fn require(&self, original: &Path, final_path: &Path) -> Result<&'a [u8], &'static str> {
        let mut matches = self
            .entries
            .iter()
            .filter(|r| r.original_logical_path == original && r.final_logical_path == final_path);
        let selected = matches.next().ok_or("auto_render_reference_not_captured")?;
        if matches.next().is_some() || selected.bytes.is_empty() {
            return Err("auto_render_reference_ambiguous");
        }
        Ok(selected.bytes)
    }
}
impl ReferenceSet<'_> {
    fn require_private(&self, original: &Path, final_path: &Path) -> Result<(), &'static str> {
        self.require(original, final_path)?;
        let entry = self
            .entries
            .iter()
            .find(|r| r.original_logical_path == original && r.final_logical_path == final_path)
            .ok_or("auto_render_reference_not_captured")?;
        if !entry.private_admission {
            return Err("auto_render_private_reference_not_admitted");
        }
        Ok(())
    }
}
// Every validation capability is mandatory. Implementations must parse the
// captured bytes, not reopen original logical paths. No implicit pass defaults.
pub(crate) trait CapturedValidators {
    fn validate_ca(&self, bytes: &[u8]) -> Result<(), &'static str>;
    fn validate_inner_identity(
        &self,
        settings: &Settings,
        references: &ReferenceSet<'_>,
    ) -> Result<(), &'static str>;
    fn validate_ech(
        &self,
        settings: &Settings,
        references: &ReferenceSet<'_>,
    ) -> Result<(), &'static str>;
    fn validate_bridge(
        &self,
        settings: &Settings,
        references: &ReferenceSet<'_>,
    ) -> Result<(), &'static str>;
    fn validate_feature_policy(&self, settings: &Settings) -> Result<(), &'static str>;
    fn validate_dns_policy(&self, settings: &Settings) -> Result<(), &'static str>;
}
fn joined(base: &Path, path: &Path) -> Result<PathBuf, &'static str> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                if !normalized.pop() || normalized.as_os_str().is_empty() {
                    return Err("auto_render_reference_escape");
                }
            }
            std::path::Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}
fn validate_references(
    original: &Settings,
    final_settings: &Settings,
    options: &Options,
    refs: &ReferenceSet<'_>,
    validators: &dyn CapturedValidators,
) -> Result<(), &'static str> {
    for (index, (before, after)) in [
        (&original.relay.ca_cert, &final_settings.relay.ca_cert),
        (
            &original.relay.masque_ca_cert,
            &final_settings.relay.masque_ca_cert,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(after) = after {
            let before = if index == 0
                && before
                    .as_ref()
                    .is_some_and(|p| p == Path::new("__CLIENT_CA_CERT_PATH__"))
            {
                options
                    .captured_bundle_ca
                    .as_ref()
                    .ok_or("auto_render_bundle_ca_not_captured")?
                    .clone()
            } else if index == 1 && options.final_masque_ca.is_some() {
                options
                    .captured_masque_ca
                    .as_ref()
                    .ok_or("auto_render_masque_ca_not_captured")?
                    .clone()
            } else {
                joined(
                    &options.logical_original_base,
                    before
                        .as_ref()
                        .ok_or("auto_render_ca_original_mapping_required")?,
                )?
            };
            let after = joined(&options.logical_final_base, after)?;
            validators.validate_ca(refs.require(&before, &after)?)?;
        }
    }
    // Identity/ECH/bridge strings are not renderer-owned transformations.
    // Require both their exact preserved spelling and their original->final
    // capture mapping before any byte parser can accept the final destination.
    let bind_preserved = |before: &Path, after: &Path| -> Result<(), &'static str> {
        if before != after {
            return Err("auto_render_reference_transform_unapproved");
        }
        refs.require(
            &joined(&options.logical_original_base, before)?,
            &joined(&options.logical_final_base, after)?,
        )?;
        Ok(())
    };
    match (&original.relay.inner_tls, &final_settings.relay.inner_tls) {
        (Some(before), Some(after)) => {
            if before.server_name != after.server_name {
                return Err("auto_render_identity_name_changed");
            }
            for (before, after) in [
                (&before.server_ca, &after.server_ca),
                (&before.cert, &after.cert),
                (&before.key, &after.key),
            ] {
                bind_preserved(before, after)?;
            }
            refs.require_private(
                &joined(&options.logical_original_base, &before.key)?,
                &joined(&options.logical_final_base, &after.key)?,
            )?;
        }
        (None, None) => {}
        _ => return Err("auto_render_identity_presence_changed"),
    }
    match (
        &original.relay.ech_config_list,
        &final_settings.relay.ech_config_list,
    ) {
        (Some(before), Some(after)) => bind_preserved(before, after)?,
        (None, None) => {}
        _ => return Err("auto_render_ech_presence_changed"),
    }
    if original.relay.ech_config_list_base64 != final_settings.relay.ech_config_list_base64 {
        return Err("auto_render_inline_ech_changed");
    }
    match (
        &original.relay.https_bridge,
        &final_settings.relay.https_bridge,
    ) {
        (Some(before), Some(after)) => {
            bind_preserved(&before.credential_file, &after.credential_file)?;
            refs.require_private(
                &joined(&options.logical_original_base, &before.credential_file)?,
                &joined(&options.logical_final_base, &after.credential_file)?,
            )?;
        }
        (None, None) => {}
        _ => return Err("auto_render_bridge_presence_changed"),
    }
    match (
        &original.relay.web_response,
        &final_settings.relay.web_response,
    ) {
        (Some(before), Some(after)) => {
            if before.authority != after.authority
                || before.descriptor_path != after.descriptor_path
                || before.allowed_ingress_ips != after.allowed_ingress_ips
            {
                return Err("auto_render_web_response_policy_changed");
            }
            bind_preserved(&before.credential_file, &after.credential_file)?;
            refs.require_private(
                &joined(&options.logical_original_base, &before.credential_file)?,
                &joined(&options.logical_final_base, &after.credential_file)?,
            )?;
        }
        (None, None) => {}
        _ => return Err("auto_render_web_response_presence_changed"),
    }
    // These explicit capabilities bind every credential-bearing runtime input
    // to admitted reference bytes. Current path-loading runtime APIs need an
    // actual byte-backed adapter implementation before this proposal is usable.
    validators.validate_inner_identity(final_settings, refs)?;
    validators.validate_ech(final_settings, refs)?;
    validators.validate_bridge(final_settings, refs)?;
    validators.validate_feature_policy(final_settings)?;
    validators.validate_dns_policy(final_settings)?;
    Ok(())
}
// Bind ordered relative leaf names and bytes privately; never expose digests in
// stdout, PR text, diagnostics or a serialized plan. Raw and final domains differ.
fn namespaced_generation(
    domain: &[u8],
    config: &[(&Path, &[u8])],
    binding: &[(PathBuf, Zeroizing<Vec<u8>>)],
    state: Option<&StagedLeaf>,
    context: Option<&RenderContext>,
) -> Result<PrivateGeneration, &'static str> {
    let mut owned = Vec::new();
    for (path, bytes) in config {
        owned.push((PathBuf::from("config").join(path), *bytes));
    }
    for (path, bytes) in binding {
        owned.push((PathBuf::from("references").join(path), bytes.as_slice()));
    }
    if let Some(state) = state {
        owned.push((
            PathBuf::from("state").join(&state.relative_leaf),
            state.bytes.as_slice(),
        ));
    }
    let context_bytes = context
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| "auto_render_context_invalid")?;
    if let Some(bytes) = context_bytes.as_ref() {
        owned.push((PathBuf::from("authority/render-context"), bytes.as_slice()));
    }
    let borrowed: Vec<_> = owned.iter().map(|(p, b)| (p.as_path(), *b)).collect();
    generation(domain, &borrowed)
}
struct PrivateGeneration([u8; 32]);
fn generation(domain: &[u8], leaves: &[(&Path, &[u8])]) -> Result<PrivateGeneration, &'static str> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(domain);
    let mut ordered = std::collections::BTreeMap::new();
    for (path, bytes) in leaves {
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("auto_render_generation_leaf_invalid");
        }
        if ordered.insert(*path, *bytes).is_some() {
            return Err("auto_render_generation_leaf_duplicate");
        }
    }
    for (path, bytes) in ordered {
        let name = path
            .to_str()
            .ok_or("auto_render_generation_leaf_invalid")?
            .as_bytes();
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    Ok(PrivateGeneration(digest.finalize().into()))
}
pub(crate) struct Supplementary<'a> {
    pub relative_leaf: &'a Path,
    pub captured: &'a [u8],
}
pub(crate) struct StateTransfer<'a> {
    pub original_logical_path: &'a Path,
    pub captured: &'a [u8],
    pub final_relative_leaf: &'a Path,
}
pub(crate) struct StagedLeaf {
    pub relative_leaf: PathBuf,
    pub bytes: Zeroizing<Vec<u8>>,
}
pub(crate) struct OwnedReference {
    pub original_logical_path: PathBuf,
    pub final_logical_path: PathBuf,
    pub bytes: Zeroizing<Vec<u8>>,
}
// Keep source/destination role mappings and contents in the private generation.
// Synthetic leaf names are generation inputs only, not automatic publication paths.
type PrivateBindingLeaves = Vec<(PathBuf, Zeroizing<Vec<u8>>)>;
fn reference_binding_leaves(
    references: &[OwnedReference],
    state: Option<(&Path, &[u8])>,
) -> Result<PrivateBindingLeaves, &'static str> {
    let mut entries: Vec<_> = references.iter().collect();
    entries.sort_by_key(|r| (&r.original_logical_path, &r.final_logical_path));
    let mut leaves = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, reference) in entries.into_iter().enumerate() {
        if !seen.insert((
            &reference.original_logical_path,
            &reference.final_logical_path,
        )) {
            return Err("auto_render_reference_duplicate");
        }
        let before = path_string(&reference.original_logical_path)?;
        let after = path_string(&reference.final_logical_path)?;
        let mut body = Zeroizing::new(Vec::new());
        for bytes in [
            before.as_bytes(),
            after.as_bytes(),
            reference.bytes.as_slice(),
        ] {
            body.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            body.extend_from_slice(bytes);
        }
        leaves.push((PathBuf::from(format!("_reference-bindings/{index}")), body));
    }
    if let Some((path, bytes)) = state {
        let mut body = Zeroizing::new(Vec::new());
        let path = path_string(path)?.as_bytes();
        body.extend_from_slice(&(path.len() as u64).to_be_bytes());
        body.extend_from_slice(path);
        body.extend_from_slice(bytes);
        leaves.push((PathBuf::from("_runtime-state-input"), body));
    }
    Ok(leaves)
}
pub(crate) struct PreparedRender {
    pub config: Rendered,
    pub supplementary: Vec<StagedLeaf>,
    pub state_transfer: Option<StagedLeaf>,
    pub references: Vec<OwnedReference>,
    pub context: RenderContext,
    config_leaf: PathBuf,
    binding_leaves: PrivateBindingLeaves,
    unchanged_config_leaves: Vec<StagedLeaf>,
    passthrough_bound: bool,
    raw_generation: PrivateGeneration,
    final_generation: PrivateGeneration,
}
impl PreparedRender {
    pub(crate) fn config_leaf(&self) -> &Path {
        &self.config_leaf
    }
    #[cfg(test)]
    pub(crate) fn revalidate_raw(
        &self,
        original_leaves: &[(&Path, &[u8])],
        reference_binding_leaves: &[(&Path, &[u8])],
    ) -> Result<(), &'static str> {
        let passthrough_names: std::collections::BTreeSet<_> = self
            .unchanged_config_leaves
            .iter()
            .map(|x| x.relative_leaf.as_path())
            .collect();
        let mut original = Vec::new();
        let mut passthrough = Vec::new();
        for (path, bytes) in original_leaves {
            if passthrough_names.contains(path) {
                passthrough.push((*path, *bytes));
            } else {
                original.push((*path, *bytes));
            }
        }
        if passthrough.len() != self.unchanged_config_leaves.len() {
            return Err("auto_render_raw_membership_changed");
        }
        let supplied: Vec<_> = reference_binding_leaves
            .iter()
            .map(|(p, b)| (p.to_path_buf(), Zeroizing::new(b.to_vec())))
            .collect();
        let base = namespaced_generation(
            b"aegis-auto-input-v1\0",
            &original,
            &supplied,
            None,
            Some(&self.context),
        )?;
        let actual = if self.passthrough_bound {
            use sha2::Digest;
            let mut digest = sha2::Sha256::new();
            digest.update(b"aegis-auto-input-passthrough-v1\0");
            digest.update(base.0);
            digest.update(generation(b"aegis-auto-passthrough-v1\0", &passthrough)?.0);
            PrivateGeneration(digest.finalize().into())
        } else {
            base
        };
        if actual.0 != self.raw_generation.0 {
            return Err("auto_render_raw_generation_changed");
        }
        Ok(())
    }
}
// Privileged DNS example is a distinct captured file: only its CA placeholder
// changes. Never rotate its local token or add main-profile defaults.
fn supplementary_dns(
    captured: &[u8],
    options: &Options,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if captured.is_empty() || captured.len() > 4 * 1024 * 1024 {
        return Err("auto_render_supplementary_bound");
    }
    let source = std::str::from_utf8(captured).map_err(|_| "auto_render_supplementary_encoding")?;
    let mut doc = source
        .parse::<DocumentMut>()
        .map_err(|_| "auto_render_supplementary_parse")?;
    let relay = table(&mut doc, &["relay"])?;
    if relay.get("ca_cert").and_then(Item::as_str) == Some("__CLIENT_CA_CERT_PATH__") {
        put(relay, "ca_cert", value(path_string(&options.final_ca)?));
    }
    Ok(Zeroizing::new(doc.to_string().into_bytes()))
}
// Complete prospective bytes here; commit publication remains a separate held-FD
// transaction and must revalidate original capture authority/generation.
pub(crate) fn prepare_render(
    config_leaf: &Path,
    captured: &[u8],
    supplementary: Option<Supplementary<'_>>,
    state: Option<StateTransfer<'_>>,
    options: &Options,
    refs: &ReferenceSet<'_>,
    validators: &dyn CapturedValidators,
) -> Result<PreparedRender, &'static str> {
    let config = render(captured, options)?;
    let original: Settings =
        toml::from_str(std::str::from_utf8(captured).map_err(|_| "auto_render_encoding_invalid")?)
            .map_err(|_| "auto_render_parse_invalid")?;
    let final_settings: Settings =
        toml::from_str(&config.bytes).map_err(|_| "auto_render_final_parse_invalid")?;
    validate_references(&original, &final_settings, options, refs, validators)?;
    let mut raw = vec![(config_leaf, captured)];
    let mut rendered_supplementary = Vec::new();
    if let Some(extra) = supplementary {
        if !matches!(options.input, InputKind::FreshBundle) {
            return Err("auto_render_unexpected_supplementary");
        }
        let bytes = supplementary_dns(extra.captured, options)?;
        let before: Settings = toml::from_str(
            std::str::from_utf8(extra.captured)
                .map_err(|_| "auto_render_supplementary_encoding")?,
        )
        .map_err(|_| "auto_render_supplementary_parse")?;
        let after: Settings = toml::from_str(
            std::str::from_utf8(&bytes).map_err(|_| "auto_render_supplementary_encoding")?,
        )
        .map_err(|_| "auto_render_supplementary_parse")?;
        validate_references(&before, &after, options, refs, validators)?;
        raw.push((extra.relative_leaf, extra.captured));
        rendered_supplementary.push(StagedLeaf {
            relative_leaf: extra.relative_leaf.to_path_buf(),
            bytes,
        });
    }
    let references: Vec<_> = refs
        .entries
        .iter()
        .map(|r| OwnedReference {
            original_logical_path: r.original_logical_path.to_path_buf(),
            final_logical_path: r.final_logical_path.to_path_buf(),
            bytes: Zeroizing::new(r.bytes.to_vec()),
        })
        .collect();
    let binding = reference_binding_leaves(
        &references,
        state
            .as_ref()
            .map(|s| (s.original_logical_path, s.captured)),
    )?;
    let state_transfer = if let Some(state) = state {
        // Copy custody is independent of configured-path relocation. Read the
        // explicit original spelling from the already captured document; the
        // rendered relocation receipt is absent for a preserved custom path.
        let original_document: toml::Value = toml::from_str(
            std::str::from_utf8(captured).map_err(|_| "auto_render_encoding_invalid")?,
        )
        .map_err(|_| "auto_render_parse_invalid")?;
        let previous = original_document
            .get("direct")
            .and_then(|direct| direct.get("state_path"))
            .and_then(toml::Value::as_str)
            .ok_or("auto_render_unexpected_state_transfer")?;
        let admitted = options
            .captured_previous_state
            .as_ref()
            .ok_or("auto_render_state_not_captured")?;
        if admitted != state.original_logical_path {
            return Err("auto_render_state_generation_mismatch");
        }
        // The explicit expansion was captured before planning; do not expand '~'
        // or inspect HOME during rendering. Non-home original spellings must
        // independently match the logical original base.
        if !previous.starts_with("~/")
            && joined(&options.logical_original_base, Path::new(previous))? != *admitted
        {
            return Err("auto_render_state_reference_mismatch");
        }
        if state.captured.len() > 16 * 1024 * 1024 {
            return Err("auto_render_state_bound");
        }
        // The publication coordinator handles state_dir in a separate admitted
        // administrator destination root; this relative leaf is not config-root.
        Some(StagedLeaf {
            relative_leaf: state.final_relative_leaf.to_path_buf(),
            bytes: Zeroizing::new(state.captured.to_vec()),
        })
    } else {
        None
    };
    let context = RenderContext::from_options(options, &final_settings)?;
    let raw_generation = namespaced_generation(
        b"aegis-auto-input-v1\0",
        &raw,
        &binding,
        None,
        Some(&context),
    )?;
    let mut final_leaves = vec![(config_leaf, config.bytes.as_bytes())];
    for extra in &rendered_supplementary {
        final_leaves.push((&extra.relative_leaf, &extra.bytes));
    }
    let final_generation = namespaced_generation(
        b"aegis-auto-final-v1\0",
        &final_leaves,
        &binding,
        state_transfer.as_ref(),
        Some(&context),
    )?;
    Ok(PreparedRender {
        config,
        supplementary: rendered_supplementary,
        state_transfer,
        references,
        context,
        config_leaf: config_leaf.to_path_buf(),
        binding_leaves: binding,
        unchanged_config_leaves: Vec::new(),
        passthrough_bound: false,
        raw_generation,
        final_generation,
    })
}

#[cfg(test)]
mod transaction_render_tests {
    use super::*;
    #[test]
    fn supplementary_ca_only_preserves_its_token_unknowns_and_comments() {
        let options = Options {
            mode: SelectedMode::SocksOnly,
            input: InputKind::FreshBundle,
            final_ca: "/etc/aegis/client/ca.pem".into(),
            final_state: "/var/lib/aegis/state.json".into(),
            logical_original_base: "/srv/bundle".into(),
            logical_final_base: "/etc/aegis/client".into(),
            fresh_local_token: Some(Zeroizing::new("b".repeat(64))),
            masque_server: None,
            final_masque_ca: None,
            captured_bundle_ca: Some("/srv/bundle/ca.pem".into()),
            captured_masque_ca: None,
            captured_previous_state: None,
            relay_pin: None,
            state_path_needs_relocation: false,
            wide_interface: None,
        };
        let source = b"# original example\n[relay]\nca_cert = '__CLIENT_CA_CERT_PATH__' # retained\n[socks]\nauth_token = 'do-not-rotate-example'\n[future]\nkey = 'unchanged'\n";
        let bytes = supplementary_dns(source, &options).unwrap();
        let output = std::str::from_utf8(&bytes).unwrap();
        assert!(output.contains("auth_token = 'do-not-rotate-example'"));
        assert!(output.contains("key = 'unchanged'"));
        assert!(output.contains("# original example"));
        assert!(output.contains("# retained"));
        let parsed: toml::Value = toml::from_str(output).unwrap();
        assert_eq!(
            parsed["relay"]["ca_cert"].as_str(),
            Some("/etc/aegis/client/ca.pem")
        );
        assert!(parsed.get("local_stealth_profile").is_none());
    }
    #[test]
    fn relative_and_parent_reference_bases_have_explicit_logical_mapping() {
        assert_eq!(
            joined(Path::new("/srv/bundle/nested"), Path::new("../ca.pem")).unwrap(),
            PathBuf::from("/srv/bundle/ca.pem")
        );
        let refs = [CapturedReference {
            original_logical_path: Path::new("/srv/bundle/ca.pem"),
            final_logical_path: Path::new("/etc/aegis/ca.pem"),
            bytes: b"captured synthetic CA",
            private_admission: false,
        }];
        let set = ReferenceSet { entries: &refs };
        assert_eq!(
            set.require(
                Path::new("/srv/bundle/ca.pem"),
                Path::new("/etc/aegis/ca.pem")
            )
            .unwrap(),
            b"captured synthetic CA"
        );
        assert!(set
            .require(
                Path::new("/srv/bundle/ca.pem"),
                Path::new("/tmp/stage/ca.pem")
            )
            .is_err());
    }
    #[test]
    fn raw_final_domains_and_reference_content_substitution_are_distinct() {
        let leaves = [(
            Path::new("aegis.toml"),
            b"synthetic configuration".as_slice(),
        )];
        let raw = generation(b"aegis-auto-input-v1\0", &leaves).unwrap();
        let final_generation = generation(b"aegis-auto-final-v1\0", &leaves).unwrap();
        assert_ne!(raw.0, final_generation.0);
        let changed = [(
            Path::new("aegis.toml"),
            b"substituted configuration".as_slice(),
        )];
        assert_ne!(
            raw.0,
            generation(b"aegis-auto-input-v1\0", &changed).unwrap().0
        );
        let references = [OwnedReference {
            original_logical_path: "/srv/bundle/ca.pem".into(),
            final_logical_path: "/etc/aegis/client/ca.pem".into(),
            bytes: Zeroizing::new(b"original synthetic CA".to_vec()),
        }];
        let a = reference_binding_leaves(&references, None).unwrap();
        let substituted = [OwnedReference {
            original_logical_path: "/srv/bundle/ca.pem".into(),
            final_logical_path: "/etc/aegis/client/ca.pem".into(),
            bytes: Zeroizing::new(b"substituted synthetic CA".to_vec()),
        }];
        let b = reference_binding_leaves(&substituted, None).unwrap();
        assert_ne!(a[0].1.as_slice(), b[0].1.as_slice());
    }
}

// Byte-backed validation using the same runtime parser/crypto primitives, without
// opening paths. ReferenceSet's admission/ownership remains the capture role.
pub(crate) struct RuntimeCapturedValidators {
    pub logical_final_base: PathBuf,
}
impl RuntimeCapturedValidators {
    fn bytes<'a>(&self, path: &Path, refs: &'a ReferenceSet<'a>) -> Result<&'a [u8], &'static str> {
        let target = joined(&self.logical_final_base, path)?;
        let mut entries = refs
            .entries
            .iter()
            .filter(|r| r.final_logical_path == target);
        let found = entries
            .next()
            .ok_or("auto_render_runtime_reference_missing")?;
        if entries.next().is_some() {
            return Err("auto_render_runtime_reference_duplicate");
        }
        Ok(found.bytes)
    }
    fn certs(
        bytes: &[u8],
    ) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, &'static str> {
        use rustls::pki_types::pem::PemObject;
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err("auto_render_certificate_bound");
        }
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "auto_render_certificate_invalid")?;
        if certs.is_empty() {
            return Err("auto_render_certificate_empty");
        }
        Ok(certs)
    }
    fn roots(bytes: &[u8]) -> Result<rustls::RootCertStore, &'static str> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in Self::certs(bytes)? {
            roots.add(cert).map_err(|_| "auto_render_ca_invalid")?;
        }
        Ok(roots)
    }
}
impl CapturedValidators for RuntimeCapturedValidators {
    fn validate_ca(&self, bytes: &[u8]) -> Result<(), &'static str> {
        Self::roots(bytes).map(|_| ())
    }
    fn validate_inner_identity(
        &self,
        settings: &Settings,
        refs: &ReferenceSet<'_>,
    ) -> Result<(), &'static str> {
        use rustls::pki_types::pem::PemObject;
        if let Some(inner) = &settings.relay.inner_tls {
            rustls::pki_types::ServerName::try_from(inner.server_name.clone())
                .map_err(|_| "auto_render_inner_name_invalid")?;
            let key_bytes = self.bytes(&inner.key, refs)?;
            if key_bytes.is_empty() || key_bytes.len() > 1024 * 1024 {
                return Err("auto_render_key_bound");
            }
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes)
                .map_err(|_| "auto_render_key_invalid")?;
            let mut provider = rustls::crypto::ring::default_provider();
            provider.cipher_suites = vec![
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
            let _ = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| "auto_render_inner_tls13_invalid")?
                .with_root_certificates(Self::roots(self.bytes(&inner.server_ca, refs)?)?)
                .with_client_auth_cert(Self::certs(self.bytes(&inner.cert, refs)?)?, key)
                .map_err(|_| "auto_render_inner_identity_invalid")?;
        }
        Ok(())
    }
    fn validate_ech(
        &self,
        settings: &Settings,
        refs: &ReferenceSet<'_>,
    ) -> Result<(), &'static str> {
        use base64::Engine;
        let bytes = if let Some(path) = &settings.relay.ech_config_list {
            Some(self.bytes(path, refs)?.to_vec())
        } else if let Some(encoded) = &settings.relay.ech_config_list_base64 {
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| "auto_render_ech_encoding_invalid")?,
            )
        } else {
            None
        };
        if let Some(bytes) = bytes {
            let bound = if settings.relay.ech_config_list.is_some() {
                65536
            } else {
                16384
            };
            if bytes.is_empty() || bytes.len() > bound {
                return Err("auto_render_ech_bound");
            }
            rustls::client::EchConfig::new(
                rustls::pki_types::EchConfigListBytes::from(bytes),
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(|_| "auto_render_ech_list_invalid")?;
        }
        Ok(())
    }
    fn validate_bridge(
        &self,
        settings: &Settings,
        refs: &ReferenceSet<'_>,
    ) -> Result<(), &'static str> {
        if let Some(bridge) = &settings.relay.https_bridge {
            let inner = settings
                .relay
                .inner_tls
                .as_ref()
                .ok_or("auto_render_bridge_identity_missing")?;
            let credential = joined(&self.logical_final_base, &bridge.credential_file)?;
            if credential == joined(&self.logical_final_base, &inner.key)?
                || credential == joined(&self.logical_final_base, &inner.cert)?
            {
                return Err("auto_render_bridge_credential_alias");
            }
            let raw = self.bytes(&bridge.credential_file, refs)?;
            let bytes = raw.strip_suffix(b"\n").unwrap_or(raw);
            if raw.len() > 65
                || bytes.len() != 64
                || bytes
                    .iter()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
                || bytes.iter().all(|b| *b == b'0')
            {
                return Err("auto_render_bridge_credential_invalid");
            }
        }
        if let Some(web) = &settings.relay.web_response {
            let inner = settings
                .relay
                .inner_tls
                .as_ref()
                .ok_or("auto_render_web_identity_missing")?;
            let credential = joined(&self.logical_final_base, &web.credential_file)?;
            if credential == joined(&self.logical_final_base, &inner.key)?
                || credential == joined(&self.logical_final_base, &inner.cert)?
            {
                return Err("auto_render_web_credential_alias");
            }
            let raw = self.bytes(&web.credential_file, refs)?;
            let bytes = raw.strip_suffix(b"\n").unwrap_or(raw);
            if raw.len() > 65
                || bytes.len() != 64
                || bytes
                    .iter()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
                || bytes.iter().all(|b| *b == b'0')
            {
                return Err("auto_render_web_credential_invalid");
            }
        }
        Ok(())
    }
    fn validate_feature_policy(&self, settings: &Settings) -> Result<(), &'static str> {
        if settings.windows_tunnel.is_some() {
            return Err("auto_render_platform_invalid");
        }
        crate::config::validate_hybrid_build_compatibility(settings)
            .map_err(|_| "auto_render_build_policy_invalid")
    }
    fn validate_dns_policy(&self, settings: &Settings) -> Result<(), &'static str> {
        #[cfg(target_os = "linux")]
        {
            crate::ingress::wide::dns_preview::validate_dns_preview_config(
                &settings.ingress.wide,
                &settings.relay,
            )
            .map_err(|_| "auto_render_dns_policy_invalid")
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = settings;
            Err("auto_render_linux_required")
        }
    }
}

#[cfg(test)]
mod captured_validator_tests {
    use super::*;
    #[test]
    fn captured_ca_and_ech_fail_on_invalid_owned_bytes_without_opening_paths() {
        let validator = RuntimeCapturedValidators {
            logical_final_base: "/etc/aegis/client".into(),
        };
        assert_eq!(
            validator.validate_ca(b"not a certificate"),
            Err("auto_render_certificate_empty")
        );
        let mut settings: Settings = toml::from_str("mode = 'relay'\n").unwrap();
        settings.relay.ech_config_list = Some("never-open-ech.bin".into());
        let entries = [CapturedReference {
            original_logical_path: Path::new("/srv/bundle/never-open-ech.bin"),
            final_logical_path: Path::new("/etc/aegis/client/never-open-ech.bin"),
            bytes: b"invalid captured ECH",
            private_admission: false,
        }];
        assert_eq!(
            validator.validate_ech(&settings, &ReferenceSet { entries: &entries }),
            Err("auto_render_ech_list_invalid")
        );
        assert_eq!(
            validator.validate_ech(&settings, &ReferenceSet { entries: &[] }),
            Err("auto_render_runtime_reference_missing")
        );
    }
    #[test]
    fn captured_runtime_reference_rejects_ambiguous_destination_aliases() {
        let validator = RuntimeCapturedValidators {
            logical_final_base: "/etc/aegis/client".into(),
        };
        let entries = [
            CapturedReference {
                original_logical_path: Path::new("/srv/one/ca.pem"),
                final_logical_path: Path::new("/etc/aegis/client/ca.pem"),
                bytes: b"one",
                private_admission: false,
            },
            CapturedReference {
                original_logical_path: Path::new("/srv/two/ca.pem"),
                final_logical_path: Path::new("/etc/aegis/client/ca.pem"),
                bytes: b"two",
                private_admission: false,
            },
        ];
        assert_eq!(
            validator.bytes(Path::new("ca.pem"), &ReferenceSet { entries: &entries }),
            Err("auto_render_runtime_reference_duplicate")
        );
    }
}

// Implement only with the transaction's held, role-validated descriptors. A JSON
// manifest, supplied hash or original source path is not a PublishedTree.
pub(crate) trait PublishedTree {
    fn config_leaf_names(&self) -> Result<std::collections::BTreeSet<PathBuf>, &'static str>;
    fn read_config_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str>;
    fn read_reference(&self, final_logical_path: &Path)
        -> Result<Zeroizing<Vec<u8>>, &'static str>;
    fn read_state_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str>;
}
impl PreparedRender {
    fn final_generation_from_owned(&self) -> Result<PrivateGeneration, &'static str> {
        if self.config.logical_original_base != self.context.logical_original_base
            || self.config.logical_final_base != self.context.logical_final_base
        {
            return Err("auto_render_logical_base_binding_changed");
        }
        self.final_generation_with_unchanged(&self.unchanged_config_leaves)
    }
    fn final_generation_with_unchanged(
        &self,
        unchanged: &[StagedLeaf],
    ) -> Result<PrivateGeneration, &'static str> {
        let mut leaves = vec![(self.config_leaf.as_path(), self.config.bytes.as_bytes())];
        for extra in self.supplementary.iter().chain(unchanged) {
            leaves.push((&extra.relative_leaf, &extra.bytes));
        }
        namespaced_generation(
            b"aegis-auto-final-v1\0",
            &leaves,
            &self.binding_leaves,
            self.state_transfer.as_ref(),
            Some(&self.context),
        )
    }
    // Call during PREPARE only, before plan seal. Preserve every admitted tree
    // leaf not transformed by render; never discover/copy source paths at commit.
    pub(crate) fn include_unchanged_captured_leaves(
        &mut self,
        leaves: Vec<StagedLeaf>,
    ) -> Result<(), &'static str> {
        let mut names: std::collections::BTreeSet<_> = self
            .supplementary
            .iter()
            .map(|x| x.relative_leaf.clone())
            .collect();
        names.insert(self.config_leaf.clone());
        if leaves.len() > 1024 {
            return Err("auto_render_unchanged_leaf_count");
        }
        let mut total = 0usize;
        for leaf in &leaves {
            if leaf.relative_leaf.is_absolute()
                || leaf
                    .relative_leaf
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return Err("auto_render_unchanged_leaf_invalid");
            }
            if leaf.bytes.len() > 16 * 1024 * 1024 {
                return Err("auto_render_unchanged_leaf_bound");
            }
            total = total
                .checked_add(leaf.bytes.len())
                .ok_or("auto_render_unchanged_tree_bound")?;
            if total > 64 * 1024 * 1024 {
                return Err("auto_render_unchanged_tree_bound");
            }
            if !names.insert(leaf.relative_leaf.clone()) {
                return Err("auto_render_duplicate_config_leaf");
            }
        }
        if self.passthrough_bound {
            return Err("auto_render_unchanged_leaves_already_bound");
        }
        // Keep original generation distinct; these captured passthrough bytes
        // are authoritative inputs and final outputs, not merely copied extras.
        let mut digest = sha2::Sha256::new();
        use sha2::Digest;
        digest.update(b"aegis-auto-input-passthrough-v1\0");
        digest.update(self.raw_generation.0);
        let borrowed: Vec<_> = leaves
            .iter()
            .map(|x| (x.relative_leaf.as_path(), x.bytes.as_slice()))
            .collect();
        digest.update(generation(b"aegis-auto-passthrough-v1\0", &borrowed)?.0);
        let raw_generation = PrivateGeneration(digest.finalize().into());
        let final_generation = self.final_generation_with_unchanged(&leaves)?;
        // No fallible operation follows: a refusal preserves every old field.
        self.raw_generation = raw_generation;
        self.final_generation = final_generation;
        self.unchanged_config_leaves = leaves;
        self.passthrough_bound = true;
        Ok(())
    }
    fn verify_other_published_bytes(
        &self,
        published: &dyn PublishedTree,
    ) -> Result<(), &'static str> {
        let mut expected_names: std::collections::BTreeSet<_> = self
            .supplementary
            .iter()
            .chain(&self.unchanged_config_leaves)
            .map(|x| x.relative_leaf.clone())
            .collect();
        expected_names.insert(self.config_leaf.clone());
        if published.config_leaf_names()? != expected_names {
            return Err("auto_render_published_membership_changed");
        }
        for leaf in self
            .supplementary
            .iter()
            .chain(&self.unchanged_config_leaves)
        {
            if published.read_config_leaf(&leaf.relative_leaf)?.as_slice() != leaf.bytes.as_slice()
            {
                return Err("auto_render_published_config_changed");
            }
        }
        for reference in &self.references {
            if published
                .read_reference(&reference.final_logical_path)?
                .as_slice()
                != reference.bytes.as_slice()
            {
                return Err("auto_render_published_reference_changed");
            }
        }
        if let Some(state) = &self.state_transfer {
            if published.read_state_leaf(&state.relative_leaf)?.as_slice() != state.bytes.as_slice()
            {
                return Err("auto_render_published_state_changed");
            }
        }
        Ok(())
    }
    pub(crate) fn verify_published_tree(
        &self,
        published: &dyn PublishedTree,
    ) -> Result<(), &'static str> {
        self.verify_other_published_bytes(published)?;
        if published.read_config_leaf(&self.config_leaf)?.as_slice() != self.config.bytes.as_bytes()
        {
            return Err("auto_render_published_main_changed");
        }
        if self.final_generation_from_owned()?.0 != self.final_generation.0 {
            return Err("auto_render_final_binding_changed");
        }
        Ok(())
    }
    // DNS wrapper may normalize formatting. Accept only identical complete TOML
    // semantics, including all unknown fields: the exact three projected DNS
    // values were already established in PREPARE. No arbitrary changed-key list.
    pub(crate) fn finalize_dns_projection(
        &mut self,
        published: &dyn PublishedTree,
    ) -> Result<(), &'static str> {
        if self.context.mode != SelectedMode::WideRedirectSafe {
            return Err("auto_render_dns_projection_wrong_mode");
        }
        self.finalize_installer_projection(published)
    }
    pub(crate) fn finalize_installer_projection(
        &mut self,
        published: &dyn PublishedTree,
    ) -> Result<(), &'static str> {
        let received = self.validate_installer_projection(published)?;
        let replacement = Zeroizing::new(
            String::from_utf8(received.to_vec())
                .map_err(|_| "auto_render_dns_projection_encoding")?,
        );
        let previous_bytes = std::mem::replace(&mut self.config.bytes, replacement);
        let previous_generation = self.final_generation.0;
        let validated = (|| {
            self.final_generation = self.final_generation_from_owned()?;
            self.verify_published_tree(published)
        })();
        if let Err(error) = validated {
            self.config.bytes = previous_bytes;
            self.final_generation = PrivateGeneration(previous_generation);
            return Err(error);
        }
        Ok(())
    }
    /// Admit the complete formatter output without changing the prepared
    /// recipe. The owner uses this before the first native capture recheck;
    /// final publication repeats the same checks against its held source.
    pub(crate) fn validate_installer_projection(
        &self,
        published: &dyn PublishedTree,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if self.context.mode == SelectedMode::SocksOnly {
            return Err("auto_render_installer_projection_wrong_mode");
        }
        self.verify_other_published_bytes(published)?;
        let received = published.read_config_leaf(&self.config_leaf)?;
        if received.is_empty() || received.len() > 4 * 1024 * 1024 {
            return Err("auto_render_dns_projection_bound");
        }
        let expected: toml::Value =
            toml::from_str(&self.config.bytes).map_err(|_| "auto_render_sealed_parse_invalid")?;
        let actual: toml::Value = toml::from_str(
            std::str::from_utf8(&received).map_err(|_| "auto_render_dns_projection_encoding")?,
        )
        .map_err(|_| "auto_render_dns_projection_parse")?;
        if actual != expected {
            return Err("auto_render_dns_projection_semantics_changed");
        }
        let wide = actual
            .get("ingress")
            .and_then(|x| x.get("wide"))
            .ok_or("auto_render_dns_projection_missing")?;
        if (self.context.mode == SelectedMode::FullWideTun
            && wide.get("capture_dns").and_then(toml::Value::as_bool) != Some(true))
            || wide.get("dns_preview_listen").and_then(toml::Value::as_str) != Some("127.0.0.1:53")
            || (self.context.mode == SelectedMode::WideRedirectSafe
                && (wide
                    .get("dns_preview_fake_ip_pool")
                    .and_then(toml::Value::as_str)
                    != Some("198.18.0.0/15")
                    || wide
                        .get("dns_preview_fake_ip_ttl_secs")
                        .and_then(toml::Value::as_integer)
                        != Some(60)))
        {
            return Err("auto_render_dns_projection_not_admitted");
        }
        Ok(received)
    }
}

#[cfg(test)]
mod published_tree_tests {
    use super::*;
    pub(super) struct Published {
        pub(super) files: std::collections::BTreeMap<PathBuf, Vec<u8>>,
    }
    impl PublishedTree for Published {
        fn config_leaf_names(&self) -> Result<std::collections::BTreeSet<PathBuf>, &'static str> {
            Ok(self.files.keys().cloned().collect())
        }
        fn read_config_leaf(&self, relative: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
            self.files
                .get(relative)
                .cloned()
                .map(Zeroizing::new)
                .ok_or("fixture_missing")
        }
        fn read_reference(&self, _: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
            Err("fixture_reference_unexpected")
        }
        fn read_state_leaf(&self, _: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
            Err("fixture_state_unexpected")
        }
    }
    pub(super) fn prepared() -> (PreparedRender, Published) {
        let text = "# original\n[ingress.wide]\ndns_preview_listen = '127.0.0.1:53'\ndns_preview_fake_ip_pool = '198.18.0.0/15'\ndns_preview_fake_ip_ttl_secs = 60\n[unmodeled]\nimportant = 'keep'\n";
        let leaves = [(Path::new("aegis.toml"), text.as_bytes())];
        let context = RenderContext {
            mode: SelectedMode::WideRedirectSafe,
            logical_original_base: "/srv/bundle".into(),
            logical_final_base: "/etc/aegis/client".into(),
            final_state: "/var/lib/aegis/state.json".into(),
            wide_interface: None,
        };
        let raw_generation =
            namespaced_generation(b"aegis-auto-input-v1\0", &leaves, &[], None, Some(&context))
                .unwrap();
        let final_generation =
            namespaced_generation(b"aegis-auto-final-v1\0", &leaves, &[], None, Some(&context))
                .unwrap();
        let prepared = PreparedRender {
            config: Rendered {
                bytes: Zeroizing::new(text.to_string()),
                previous_state_reference: None,
                logical_original_base: "/srv/bundle".into(),
                logical_final_base: "/etc/aegis/client".into(),
            },
            supplementary: Vec::new(),
            state_transfer: None,
            references: Vec::new(),
            context,
            config_leaf: "aegis.toml".into(),
            binding_leaves: Vec::new(),
            unchanged_config_leaves: Vec::new(),
            passthrough_bound: false,
            raw_generation,
            final_generation,
        };
        let published = Published {
            files: std::collections::BTreeMap::from([(
                PathBuf::from("aegis.toml"),
                text.as_bytes().to_vec(),
            )]),
        };
        (prepared, published)
    }
    #[test]
    fn dns_projection_allows_only_whole_document_semantic_equality() {
        let (mut prepared, mut published) = prepared();
        let before_raw = prepared.raw_generation.0;
        let before_final = prepared.final_generation.0;
        let text = String::from_utf8(published.files[Path::new("aegis.toml")].clone()).unwrap();
        published.files.insert(
            "aegis.toml".into(),
            text.replace("# original", "# normalized comment")
                .replace("'keep'", "\"keep\"")
                .into_bytes(),
        );
        prepared.finalize_dns_projection(&published).unwrap();
        assert_eq!(prepared.raw_generation.0, before_raw);
        assert_ne!(prepared.final_generation.0, before_final);
        prepared.verify_published_tree(&published).unwrap();
        let altered = String::from_utf8(published.files[Path::new("aegis.toml")].clone())
            .unwrap()
            .replace("\"keep\"", "\"removed unknown protection\"");
        published
            .files
            .insert("aegis.toml".into(), altered.into_bytes());
        assert_eq!(
            prepared.finalize_dns_projection(&published),
            Err("auto_render_dns_projection_semantics_changed")
        );
    }
    #[test]
    fn formatter_preflight_is_read_only_and_refuses_unknown_or_other_leaf_changes() {
        let (prepared, mut published) = prepared();
        let expected_bytes = prepared.config.bytes.clone();
        let expected_generation = prepared.final_generation.0;
        let text = String::from_utf8(published.files[Path::new("aegis.toml")].clone()).unwrap();
        published.files.insert(
            "aegis.toml".into(),
            text.replace("# original", "# normalized comment")
                .replace("'keep'", "\"keep\"")
                .into_bytes(),
        );
        let admitted = prepared.validate_installer_projection(&published).unwrap();
        assert_ne!(admitted.as_slice(), expected_bytes.as_bytes());
        assert_eq!(prepared.config.bytes.as_bytes(), expected_bytes.as_bytes());
        assert_eq!(prepared.final_generation.0, expected_generation);
        published.files.insert(
            "aegis.toml".into(),
            String::from_utf8(admitted.to_vec())
                .unwrap()
                .replace("\"keep\"", "\"changed unknown\"")
                .into_bytes(),
        );
        assert_eq!(
            prepared.validate_installer_projection(&published).err(),
            Some("auto_render_dns_projection_semantics_changed")
        );
        published
            .files
            .insert("aegis.toml".into(), admitted.to_vec());
        published
            .files
            .insert("unadmitted.toml".into(), b"extra".to_vec());
        assert_eq!(
            prepared.validate_installer_projection(&published).err(),
            Some("auto_render_published_membership_changed")
        );
        assert_eq!(prepared.config.bytes.as_bytes(), expected_bytes.as_bytes());
        assert_eq!(prepared.final_generation.0, expected_generation);
    }
    #[test]
    fn full_wide_formatter_projection_preserves_all_semantics() {
        let (mut prepared, mut published) = prepared();
        prepared.context.mode = SelectedMode::FullWideTun;
        prepared.config.bytes = Zeroizing::new(
            prepared
                .config
                .bytes
                .replace("[ingress.wide]", "[ingress.wide]\ncapture_dns = true"),
        );
        prepared.final_generation = prepared.final_generation_from_owned().unwrap();
        let expected = prepared.config.bytes.as_bytes().to_vec();
        published.files.insert(
            "aegis.toml".into(),
            prepared
                .config
                .bytes
                .replace("# original", "# wrapper formatting")
                .replace("'keep'", "\"keep\"")
                .into_bytes(),
        );
        prepared.validate_installer_projection(&published).unwrap();
        assert_eq!(prepared.config.bytes.as_bytes(), expected.as_slice());
        prepared.finalize_installer_projection(&published).unwrap();
        prepared.verify_published_tree(&published).unwrap();
        assert_ne!(prepared.config.bytes.as_bytes(), expected);
        let old_bytes = prepared.config.bytes.clone();
        let old_gen = prepared.final_generation.0;
        published.files.insert(
            "aegis.toml".into(),
            prepared
                .config
                .bytes
                .replace("\"keep\"", "\"changed unknown\"")
                .into_bytes(),
        );
        assert!(prepared.finalize_installer_projection(&published).is_err());
        assert_eq!(prepared.config.bytes.as_bytes(), old_bytes.as_bytes());
        assert_eq!(prepared.final_generation.0, old_gen);
    }
    #[test]
    fn formatter_projection_refuses_socks_and_dns_api_refuses_full_mode() {
        let (mut prepared, published) = prepared();
        prepared.context.mode = SelectedMode::SocksOnly;
        assert_eq!(
            prepared.finalize_installer_projection(&published),
            Err("auto_render_installer_projection_wrong_mode")
        );
        prepared.context.mode = SelectedMode::FullWideTun;
        assert_eq!(
            prepared.finalize_dns_projection(&published),
            Err("auto_render_dns_projection_wrong_mode")
        );
    }
    #[test]
    fn complete_published_membership_and_unchanged_bytes_are_required() {
        let (mut prepared, mut published) = prepared();
        prepared
            .include_unchanged_captured_leaves(vec![StagedLeaf {
                relative_leaf: "nested/ca.pem".into(),
                bytes: Zeroizing::new(b"captured synthetic reference".to_vec()),
            }])
            .unwrap();
        assert_eq!(
            prepared.verify_published_tree(&published),
            Err("auto_render_published_membership_changed")
        );
        published.files.insert(
            "nested/ca.pem".into(),
            b"captured synthetic reference".to_vec(),
        );
        prepared.verify_published_tree(&published).unwrap();
        published
            .files
            .insert("nested/ca.pem".into(), b"substitution".to_vec());
        assert_eq!(
            prepared.verify_published_tree(&published),
            Err("auto_render_published_config_changed")
        );
        assert!(prepared
            .include_unchanged_captured_leaves(Vec::new())
            .is_err());
    }
    #[test]
    fn unchanged_reserved_names_and_raw_generation_substitution_refuse() {
        let (mut prepared, published) = prepared();
        assert!(prepared
            .include_unchanged_captured_leaves(vec![StagedLeaf {
                relative_leaf: "../outside-state".into(),
                bytes: Zeroizing::new(Vec::new())
            }])
            .is_err());
        let original = published.files[Path::new("aegis.toml")].as_slice();
        prepared
            .include_unchanged_captured_leaves(vec![StagedLeaf {
                relative_leaf: "extra.toml".into(),
                bytes: Zeroizing::new(b"original-extra".to_vec()),
            }])
            .unwrap();
        prepared
            .revalidate_raw(
                &[
                    (Path::new("aegis.toml"), original),
                    (Path::new("extra.toml"), b"original-extra"),
                ],
                &[],
            )
            .unwrap();
        assert!(prepared
            .revalidate_raw(
                &[
                    (Path::new("aegis.toml"), original),
                    (Path::new("extra.toml"), b"substituted-extra")
                ],
                &[]
            )
            .is_err());
    }
}

#[cfg(test)]
mod reference_scope_regression_tests {
    use super::*;
    struct NoIoValidators;
    impl CapturedValidators for NoIoValidators {
        fn validate_ca(&self, _: &[u8]) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_inner_identity(
            &self,
            _: &Settings,
            _: &ReferenceSet<'_>,
        ) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_ech(&self, _: &Settings, _: &ReferenceSet<'_>) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_bridge(&self, _: &Settings, _: &ReferenceSet<'_>) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_feature_policy(&self, _: &Settings) -> Result<(), &'static str> {
            Ok(())
        }
        fn validate_dns_policy(&self, _: &Settings) -> Result<(), &'static str> {
            Ok(())
        }
    }
    fn options() -> Options {
        Options {
            mode: SelectedMode::SocksOnly,
            input: InputKind::ExistingUpgrade,
            final_ca: "/etc/aegis/client/ca.pem".into(),
            final_state: "/var/lib/aegis/state.json".into(),
            logical_original_base: "/srv/bundle".into(),
            logical_final_base: "/etc/aegis/client".into(),
            fresh_local_token: None,
            masque_server: None,
            final_masque_ca: None,
            captured_bundle_ca: None,
            captured_masque_ca: None,
            captured_previous_state: None,
            relay_pin: None,
            state_path_needs_relocation: false,
            wide_interface: None,
        }
    }
    #[test]
    fn original_ech_and_bridge_source_paths_cannot_be_swapped_behind_final_names() {
        let mut original: Settings = toml::from_str("mode = 'relay'\n").unwrap();
        original.relay.ech_config_list = Some("ech.bin".into());
        let final_settings = original.clone();
        let entries = [CapturedReference::public_certificate(
            Path::new("/other/ech.bin"),
            Path::new("/etc/aegis/client/ech.bin"),
            b"synthetic ECH bytes",
        )];
        assert_eq!(
            validate_references(
                &original,
                &final_settings,
                &options(),
                &ReferenceSet { entries: &entries },
                &NoIoValidators
            ),
            Err("auto_render_reference_not_captured")
        );
        original.relay.ech_config_list = None;
        original.relay.https_bridge = Some(aegis_core::https_bridge::ClientSettings {
            authority: "fixture.invalid".into(),
            path: "/fixture".into(),
            enrollment_path: "/fixture-enroll".into(),
            credential_file: "bridge.key".into(),
        });
        let final_settings = original.clone();
        let entries = [CapturedReference {
            original_logical_path: Path::new("/other/bridge.key"),
            final_logical_path: Path::new("/etc/aegis/client/bridge.key"),
            bytes: b"synthetic credential",
            private_admission: true,
        }];
        assert_eq!(
            validate_references(
                &original,
                &final_settings,
                &options(),
                &ReferenceSet { entries: &entries },
                &NoIoValidators
            ),
            Err("auto_render_reference_not_captured")
        );
    }
    #[test]
    fn inner_key_generic_admission_is_not_a_private_credential_capability() {
        let mut original: Settings = toml::from_str("mode = 'relay'\n").unwrap();
        original.relay.inner_tls = Some(aegis_core::secure_channel::ClientSettings {
            server_name: "fixture.invalid".into(),
            server_ca: "inner-ca.pem".into(),
            cert: "device.pem".into(),
            key: "device.key".into(),
        });
        let final_settings = original.clone();
        let entries = [
            CapturedReference::public_certificate(
                Path::new("/srv/bundle/inner-ca.pem"),
                Path::new("/etc/aegis/client/inner-ca.pem"),
                b"synthetic CA",
            ),
            CapturedReference::public_certificate(
                Path::new("/srv/bundle/device.pem"),
                Path::new("/etc/aegis/client/device.pem"),
                b"synthetic cert",
            ),
            CapturedReference::public_certificate(
                Path::new("/srv/bundle/device.key"),
                Path::new("/etc/aegis/client/device.key"),
                b"synthetic key",
            ),
        ];
        assert_eq!(
            validate_references(
                &original,
                &final_settings,
                &options(),
                &ReferenceSet { entries: &entries },
                &NoIoValidators
            ),
            Err("auto_render_private_reference_not_admitted")
        );
    }
    #[test]
    fn preserved_socks_mode_refuses_existing_wide_primary_without_rewriting_it() {
        let source = format!("mode = 'relay'\n[relay]\nserver = '192.0.2.4:443'\nserver_name = 'fixture.invalid'\nauth_token = '{}'\n[ingress]\nprimary = 'wide'\n", "0123456789abcdef".repeat(4));
        assert_eq!(
            render(source.as_bytes(), &options()).err(),
            Some("auto_render_selected_socks_scope_mismatch")
        );
        let valid = source.replace("primary = 'wide'", "primary = 'socks5'");
        assert!(render(valid.as_bytes(), &options()).is_ok());
        assert!(source.contains("primary = 'wide'"));
    }
}

#[cfg(test)]
mod tentative_generation_regression_tests {
    use super::*;
    #[test]
    fn refused_final_generation_keeps_every_prepared_field_unchanged() {
        let (mut prepared, _) = super::published_tree_tests::prepared();
        prepared.final_generation = prepared.final_generation_from_owned().unwrap();
        let raw_before = prepared.raw_generation.0;
        let final_before = prepared.final_generation.0;
        let body_before = prepared.config.bytes.as_bytes().to_vec();
        // Fault injection at a generation-binding boundary: malformed internal
        // binding must refuse without half-committing the candidate fields.
        prepared.binding_leaves.push((
            PathBuf::from("../malformed"),
            Zeroizing::new(b"invalid binding".to_vec()),
        ));
        let error = prepared.include_unchanged_captured_leaves(vec![StagedLeaf {
            relative_leaf: "state.json".into(),
            bytes: Zeroizing::new(b"separate config-side state".to_vec()),
        }]);
        assert!(error.is_err());
        assert_eq!(prepared.raw_generation.0, raw_before);
        assert_eq!(prepared.final_generation.0, final_before);
        assert_eq!(prepared.config.bytes.as_bytes(), body_before.as_slice());
        assert!(!prepared.passthrough_bound);
        assert!(prepared.unchanged_config_leaves.is_empty());
        prepared.binding_leaves.clear();
        prepared
            .include_unchanged_captured_leaves(vec![StagedLeaf {
                relative_leaf: "extra.toml".into(),
                bytes: Zeroizing::new(b"accepted config leaf".to_vec()),
            }])
            .unwrap();
        assert!(prepared.passthrough_bound);
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenderContext {
    pub mode: SelectedMode,
    pub logical_original_base: PathBuf,
    pub logical_final_base: PathBuf,
    // Actual rendered spelling: custom paths stay custom. This does not itself
    // authorize a state-root publication; StateTransfer owns that separate role.
    pub final_state: PathBuf,
    pub wide_interface: Option<String>,
}
impl RenderContext {
    fn from_options(options: &Options, settings: &Settings) -> Result<Self, &'static str> {
        let context = Self {
            mode: options.mode,
            logical_original_base: options.logical_original_base.clone(),
            logical_final_base: options.logical_final_base.clone(),
            final_state: settings.direct.state_path.clone(),
            wide_interface: options.wide_interface.clone(),
        };
        context.validate()?;
        Ok(context)
    }
    fn validate(&self) -> Result<(), &'static str> {
        path_string(&self.logical_original_base)?;
        path_string(&self.logical_final_base)?;
        if self.final_state.as_os_str().len() > 4096 || self.final_state.as_os_str().is_empty() {
            return Err("auto_render_context_state_invalid");
        }
        if self
            .wide_interface
            .as_ref()
            .is_some_and(|x| x.len() > 256 || x.contains(['\0', '\r', '\n']))
        {
            return Err("auto_render_context_interface_invalid");
        }
        Ok(())
    }
}
// Store implementation must hold administrator-owned, nofollow sealed-stage
// descriptors; it checks recipe hash + immutable accepted mode/root context.
// There is deliberately no restore(Vec<u8>) or public hash/JSON authority API.
pub(crate) trait SealedRenderAuthority {
    fn revalidate(&self) -> Result<(), &'static str>;
    fn read_recipe(&self) -> Result<Zeroizing<Vec<u8>>, &'static str>;
    fn accepted_context(&self) -> Result<RenderContext, &'static str>;
}
fn encode_blob(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn encoded_decoded_len(encoded: &str) -> Result<usize, &'static str> {
    let n = encoded.len();
    if n == 0 {
        return Ok(0);
    }
    if !n.is_multiple_of(4) {
        return Err("auto_render_recipe_blob_encoding_invalid");
    }
    let padding = if encoded.ends_with("==") {
        2
    } else if encoded.ends_with('=') {
        1
    } else {
        0
    };
    if encoded.as_bytes()[..n - padding]
        .iter()
        .any(|b| !b.is_ascii_alphanumeric() && *b != b'+' && *b != b'/')
    {
        return Err("auto_render_recipe_blob_encoding_invalid");
    }
    (n / 4)
        .checked_mul(3)
        .and_then(|x| x.checked_sub(padding))
        .ok_or("auto_render_recipe_blob_bound")
}
fn charge_decoded(total: &mut usize, length: usize, per_blob: usize) -> Result<(), &'static str> {
    if length > per_blob {
        return Err("auto_render_recipe_blob_bound");
    }
    let prospective = total
        .checked_add(length)
        .ok_or("auto_render_recipe_bound")?;
    if prospective > 64 * 1024 * 1024 {
        return Err("auto_render_recipe_bound");
    }
    *total = prospective;
    Ok(())
}
fn predecode_budget(recipe: &PrivateRecipe) -> Result<usize, &'static str> {
    let mut total = 0;
    charge_decoded(
        &mut total,
        encoded_decoded_len(&recipe.config)?,
        4 * 1024 * 1024,
    )?;
    for leaf in recipe
        .supplementary
        .iter()
        .chain(&recipe.unchanged)
        .chain(&recipe.bindings)
        .chain(recipe.state.iter())
    {
        charge_decoded(
            &mut total,
            encoded_decoded_len(&leaf.bytes)?,
            16 * 1024 * 1024,
        )?;
    }
    for reference in &recipe.references {
        charge_decoded(
            &mut total,
            encoded_decoded_len(&reference.bytes)?,
            16 * 1024 * 1024,
        )?;
    }
    Ok(total)
}
fn decode_blob(encoded: &str, bound: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    use base64::Engine;
    let expected = encoded_decoded_len(encoded)?;
    if expected > bound {
        return Err("auto_render_recipe_blob_bound");
    }
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "auto_render_recipe_blob_encoding_invalid")?,
    );
    if bytes.len() != expected {
        return Err("auto_render_recipe_blob_encoding_invalid");
    }
    let canonical =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()));
    if canonical.as_str() != encoded {
        return Err("auto_render_recipe_blob_noncanonical");
    }
    Ok(bytes)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeLeaf {
    path: PathBuf,
    bytes: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeReference {
    original: PathBuf,
    final_path: PathBuf,
    bytes: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRecipe {
    schema: u32,
    context: RenderContext,
    config_leaf: PathBuf,
    config: String,
    previous_state_reference: Option<String>,
    supplementary: Vec<RecipeLeaf>,
    unchanged: Vec<RecipeLeaf>,
    state: Option<RecipeLeaf>,
    references: Vec<RecipeReference>,
    bindings: Vec<RecipeLeaf>,
    passthrough_bound: bool,
    raw_generation: [u8; 32],
    final_generation: [u8; 32],
}
impl Drop for PrivateRecipe {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.config.zeroize();
        if let Some(path) = &mut self.previous_state_reference {
            path.zeroize();
        }
        for leaf in self
            .supplementary
            .iter_mut()
            .chain(&mut self.unchanged)
            .chain(&mut self.bindings)
        {
            leaf.bytes.zeroize();
        }
        if let Some(leaf) = &mut self.state {
            leaf.bytes.zeroize();
        }
        for reference in &mut self.references {
            reference.bytes.zeroize();
        }
    }
}
fn recipe_leaf(leaf: &StagedLeaf) -> RecipeLeaf {
    RecipeLeaf {
        path: leaf.relative_leaf.clone(),
        bytes: encode_blob(&leaf.bytes),
    }
}
fn restore_leaf(leaf: &RecipeLeaf) -> Result<StagedLeaf, &'static str> {
    if leaf.path.as_os_str().is_empty()
        || leaf.path.is_absolute()
        || leaf
            .path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err("auto_render_recipe_leaf_invalid");
    }
    Ok(StagedLeaf {
        relative_leaf: leaf.path.clone(),
        bytes: decode_blob(&leaf.bytes, 16 * 1024 * 1024)?,
    })
}
impl PreparedRender {
    pub(crate) fn export_private_recipe(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if self.final_generation_from_owned()?.0 != self.final_generation.0 {
            return Err("auto_render_recipe_seal_changed");
        }
        let recipe = PrivateRecipe {
            schema: 2,
            context: self.context.clone(),
            config_leaf: self.config_leaf.clone(),
            config: encode_blob(self.config.bytes.as_bytes()),
            previous_state_reference: self.config.previous_state_reference.clone(),
            supplementary: self.supplementary.iter().map(recipe_leaf).collect(),
            unchanged: self
                .unchanged_config_leaves
                .iter()
                .map(recipe_leaf)
                .collect(),
            state: self.state_transfer.as_ref().map(recipe_leaf),
            references: self
                .references
                .iter()
                .map(|x| RecipeReference {
                    original: x.original_logical_path.clone(),
                    final_path: x.final_logical_path.clone(),
                    bytes: encode_blob(&x.bytes),
                })
                .collect(),
            bindings: self
                .binding_leaves
                .iter()
                .map(|(p, b)| RecipeLeaf {
                    path: p.clone(),
                    bytes: encode_blob(b),
                })
                .collect(),
            passthrough_bound: self.passthrough_bound,
            raw_generation: self.raw_generation.0,
            final_generation: self.final_generation.0,
        };
        predecode_budget(&recipe)?;
        let bytes =
            serde_json::to_vec(&recipe).map_err(|_| "auto_render_recipe_encoding_invalid")?;
        // Canonical base64 bounds encoded overhead; independently admit the
        // decoded whole model before allocating any decoded payload.
        if bytes.len() > 96 * 1024 * 1024 {
            return Err("auto_render_recipe_bound");
        }
        Ok(Zeroizing::new(bytes))
    }
    pub(crate) fn restore_private_recipe(
        authority: &dyn SealedRenderAuthority,
    ) -> Result<Self, &'static str> {
        authority.revalidate()?;
        let accepted = authority.accepted_context()?;
        accepted.validate()?;
        let bytes = authority.read_recipe()?;
        if bytes.is_empty() || bytes.len() > 96 * 1024 * 1024 {
            return Err("auto_render_recipe_bound");
        }
        let recipe: PrivateRecipe =
            serde_json::from_slice(&bytes).map_err(|_| "auto_render_recipe_parse_invalid")?;
        if recipe.schema != 2
            || recipe.context != accepted
            || recipe.config.is_empty()
            || recipe.supplementary.len() > 32
            || recipe.unchanged.len() > 1024
            || recipe.references.len() > 1024
            || recipe.bindings.len() > 1025
        {
            return Err("auto_render_recipe_authority_mismatch");
        }
        // Every blob's exact decoded size and aggregate budget is checked
        // before the first decoder allocation, including refs and bindings.
        predecode_budget(&recipe)?;
        let config_decoded = decode_blob(&recipe.config, 4 * 1024 * 1024)?;
        let config_text = std::str::from_utf8(&config_decoded)
            .map_err(|_| "auto_render_recipe_config_encoding")?;
        let mut names = std::collections::BTreeSet::new();
        names.insert(recipe.config_leaf.clone());
        restore_leaf(&RecipeLeaf {
            path: recipe.config_leaf.clone(),
            bytes: String::new(),
        })?;
        let supplementary: Vec<_> = recipe
            .supplementary
            .iter()
            .map(restore_leaf)
            .collect::<Result<_, _>>()?;
        let unchanged: Vec<_> = recipe
            .unchanged
            .iter()
            .map(restore_leaf)
            .collect::<Result<_, _>>()?;
        let mut total = config_decoded.len();
        for leaf in supplementary.iter().chain(&unchanged) {
            if !names.insert(leaf.relative_leaf.clone()) {
                return Err("auto_render_recipe_duplicate_leaf");
            }
            total = total
                .checked_add(leaf.bytes.len())
                .ok_or("auto_render_recipe_bound")?;
        }
        let state = recipe.state.as_ref().map(restore_leaf).transpose()?;
        let mut references = Vec::new();
        let mut reference_names = std::collections::BTreeSet::new();
        for reference in &recipe.references {
            path_string(&reference.original)?;
            path_string(&reference.final_path)?;
            if !reference_names.insert((&reference.original, &reference.final_path)) {
                return Err("auto_render_recipe_reference_invalid");
            }
            let decoded = decode_blob(&reference.bytes, 16 * 1024 * 1024)?;
            total = total
                .checked_add(decoded.len())
                .ok_or("auto_render_recipe_bound")?;
            references.push(OwnedReference {
                original_logical_path: reference.original.clone(),
                final_logical_path: reference.final_path.clone(),
                bytes: decoded,
            });
        }
        let mut bindings = Vec::new();
        for binding in &recipe.bindings {
            let leaf = restore_leaf(binding)?;
            total = total
                .checked_add(leaf.bytes.len())
                .ok_or("auto_render_recipe_bound")?;
            bindings.push((leaf.relative_leaf, leaf.bytes));
        }
        if let Some(state) = &state {
            total = total
                .checked_add(state.bytes.len())
                .ok_or("auto_render_recipe_bound")?;
        }
        if total > 64 * 1024 * 1024 {
            return Err("auto_render_recipe_bound");
        }
        let restored = Self {
            config: Rendered {
                bytes: Zeroizing::new(config_text.to_owned()),
                previous_state_reference: recipe.previous_state_reference.clone(),
                logical_original_base: accepted.logical_original_base.clone(),
                logical_final_base: accepted.logical_final_base.clone(),
            },
            supplementary,
            state_transfer: state,
            references,
            context: accepted,
            config_leaf: recipe.config_leaf.clone(),
            binding_leaves: bindings,
            unchanged_config_leaves: unchanged,
            passthrough_bound: recipe.passthrough_bound,
            raw_generation: PrivateGeneration(recipe.raw_generation),
            final_generation: PrivateGeneration(recipe.final_generation),
        };
        if restored.final_generation_from_owned()?.0 != restored.final_generation.0 {
            return Err("auto_render_recipe_final_generation_mismatch");
        }
        authority.revalidate()?;
        // No second render, token generation, key parsing or original file read.
        Ok(restored)
    }
}

#[cfg(test)]
mod durable_recipe_regression_tests {
    use super::*;
    struct Stage {
        recipe: Zeroizing<Vec<u8>>,
        context: RenderContext,
        valid: bool,
    }
    impl SealedRenderAuthority for Stage {
        fn revalidate(&self) -> Result<(), &'static str> {
            if self.valid {
                Ok(())
            } else {
                Err("fixture_stage_changed")
            }
        }
        fn read_recipe(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
            Ok(Zeroizing::new(self.recipe.to_vec()))
        }
        fn accepted_context(&self) -> Result<RenderContext, &'static str> {
            Ok(self.context.clone())
        }
    }
    #[test]
    fn config_and_state_same_relative_leaf_are_separate_roles() {
        let (mut prepared, _) = super::published_tree_tests::prepared();
        prepared.state_transfer = Some(StagedLeaf {
            relative_leaf: "state.json".into(),
            bytes: Zeroizing::new(b"runtime-state-role".to_vec()),
        });
        prepared.final_generation = prepared.final_generation_from_owned().unwrap();
        prepared
            .include_unchanged_captured_leaves(vec![StagedLeaf {
                relative_leaf: "state.json".into(),
                bytes: Zeroizing::new(b"config-tree-role".to_vec()),
            }])
            .unwrap();
        assert_ne!(
            prepared.state_transfer.as_ref().unwrap().bytes.as_slice(),
            prepared.unchanged_config_leaves[0].bytes.as_slice()
        );
        let generation = prepared.final_generation.0;
        prepared.state_transfer.as_mut().unwrap().bytes[0] = b'X';
        assert_ne!(
            generation,
            prepared.final_generation_from_owned().unwrap().0
        );
    }
    #[test]
    fn protected_recipe_reentry_retains_owned_bytes_and_raw_generation() {
        let (mut prepared, published) = super::published_tree_tests::prepared();
        prepared.context.wide_interface = Some("fixture-uplink0".into());
        prepared.final_generation = prepared.final_generation_from_owned().unwrap();
        let stage = Stage {
            recipe: prepared.export_private_recipe().unwrap(),
            context: prepared.context.clone(),
            valid: true,
        };
        let restored = PreparedRender::restore_private_recipe(&stage).unwrap();
        assert_eq!(
            restored.config.bytes.as_bytes(),
            prepared.config.bytes.as_bytes()
        );
        assert_eq!(restored.raw_generation.0, prepared.raw_generation.0);
        assert_eq!(restored.final_generation.0, prepared.final_generation.0);
        assert_eq!(
            restored.context.wide_interface.as_deref(),
            Some("fixture-uplink0")
        );
        restored.verify_published_tree(&published).unwrap();
        // No original capture path, token factory or credential validator is
        // available through this authority: reentry uses only sealed stage bytes.
    }
    #[test]
    fn recipe_refuses_different_mode_root_context_or_changed_stage() {
        let (prepared, _) = super::published_tree_tests::prepared();
        let mut stage = Stage {
            recipe: prepared.export_private_recipe().unwrap(),
            context: prepared.context.clone(),
            valid: true,
        };
        stage.context.mode = SelectedMode::SocksOnly;
        assert_eq!(
            PreparedRender::restore_private_recipe(&stage).err(),
            Some("auto_render_recipe_authority_mismatch")
        );
        stage.context = prepared.context.clone();
        stage.context.logical_final_base = "/other/config-root".into();
        assert_eq!(
            PreparedRender::restore_private_recipe(&stage).err(),
            Some("auto_render_recipe_authority_mismatch")
        );
        stage.context = prepared.context.clone();
        stage.valid = false;
        assert_eq!(
            PreparedRender::restore_private_recipe(&stage).err(),
            Some("fixture_stage_changed")
        );
    }
    #[test]
    fn recipe_rejects_unsupported_fields_and_substituted_body_generation() {
        let (prepared, _) = super::published_tree_tests::prepared();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&prepared.export_private_recipe().unwrap()).unwrap();
        payload["unexpected_authority"] = serde_json::json!(true);
        let mut stage = Stage {
            recipe: Zeroizing::new(serde_json::to_vec(&payload).unwrap()),
            context: prepared.context.clone(),
            valid: true,
        };
        assert_eq!(
            PreparedRender::restore_private_recipe(&stage).err(),
            Some("auto_render_recipe_parse_invalid")
        );
        payload
            .as_object_mut()
            .unwrap()
            .remove("unexpected_authority");
        payload["config"] = serde_json::json!(encode_blob(b"substituted private body"));
        stage.recipe = Zeroizing::new(serde_json::to_vec(&payload).unwrap());
        assert_eq!(
            PreparedRender::restore_private_recipe(&stage).err(),
            Some("auto_render_recipe_final_generation_mismatch")
        );
    }
}

#[cfg(test)]
mod canonical_recipe_blob_regression_tests {
    use super::*;
    #[test]
    fn canonical_blobs_roundtrip_at_exact_limit_and_refuse_oversize() {
        let data = b"12345678";
        let encoded = encode_blob(data);
        assert_eq!(encoded_decoded_len(&encoded).unwrap(), 8);
        assert_eq!(decode_blob(&encoded, 8).unwrap().as_slice(), data);
        assert_eq!(
            decode_blob(&encode_blob(b"123456789"), 8).err(),
            Some("auto_render_recipe_blob_bound")
        );
        assert_eq!(decode_blob("", 0).unwrap().len(), 0);
    }
    #[test]
    fn malformed_padding_alphabet_and_noncanonical_trailing_bits_refuse() {
        for encoded in [
            "YQ", "YQ===", "YQ=A", "A===", "====", "YQ==\n", "Y Q=", "YR==",
        ] {
            assert!(
                decode_blob(encoded, 16).is_err(),
                "must refuse invalid canonical representation"
            );
        }
        assert_eq!(decode_blob("YQ==", 1).unwrap().as_slice(), b"a");
    }
    #[test]
    fn whole_decoded_model_exact_boundary_and_overflow_checked_before_decode() {
        let mut budget = 0;
        for _ in 0..4 {
            charge_decoded(&mut budget, 16 * 1024 * 1024, 16 * 1024 * 1024).unwrap();
        }
        assert_eq!(budget, 64 * 1024 * 1024);
        assert_eq!(
            charge_decoded(&mut budget, 1, 16 * 1024 * 1024),
            Err("auto_render_recipe_bound")
        );
        assert_eq!(budget, 64 * 1024 * 1024);
        let mut small = 0;
        assert_eq!(
            charge_decoded(&mut small, 16 * 1024 * 1024 + 1, 16 * 1024 * 1024),
            Err("auto_render_recipe_blob_bound")
        );
        assert_eq!(small, 0);
        let mut overflow = usize::MAX;
        assert_eq!(
            charge_decoded(&mut overflow, 1, 16),
            Err("auto_render_recipe_bound")
        );
        assert_eq!(overflow, usize::MAX);
    }
    #[test]
    fn preflight_checks_all_recipe_blobs_before_first_decoded_payload() {
        let (prepared, _) = super::published_tree_tests::prepared();
        let mut recipe: PrivateRecipe =
            serde_json::from_slice(&prepared.export_private_recipe().unwrap()).unwrap();
        assert!(predecode_budget(&recipe).is_ok());
        recipe.bindings.push(RecipeLeaf {
            path: "extra-private-binding".into(),
            bytes: "YQ=A".into(),
        });
        assert_eq!(
            predecode_budget(&recipe),
            Err("auto_render_recipe_blob_encoding_invalid")
        );
        recipe.bindings.pop();
        recipe.references.push(RecipeReference {
            original: "/source".into(),
            final_path: "/final".into(),
            bytes: "!!!!".into(),
        });
        assert_eq!(
            predecode_budget(&recipe),
            Err("auto_render_recipe_blob_encoding_invalid")
        );
    }
    #[test]
    fn envelope_uses_canonical_strings_not_json_integer_array_payloads() {
        let (prepared, _) = super::published_tree_tests::prepared();
        let exported = prepared.export_private_recipe().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(value["schema"], serde_json::json!(2));
        let encoded = value["config"].as_str().unwrap();
        assert_eq!(
            decode_blob(encoded, 4 * 1024 * 1024).unwrap().as_slice(),
            prepared.config.bytes.as_bytes()
        );
    }
}

#[cfg(test)]
mod logical_base_binding_tests {
    #[test]
    fn actual_private_recipe_refuses_changed_rendered_logical_bases() {
        let (mut prepared, _) = super::published_tree_tests::prepared();
        assert!(prepared.export_private_recipe().is_ok());
        prepared.config.logical_original_base = "/other-original".into();
        assert!(prepared.export_private_recipe().is_err());
        prepared.config.logical_original_base = prepared.context.logical_original_base.clone();
        prepared.config.logical_final_base = "/other-final".into();
        assert!(prepared.export_private_recipe().is_err());
    }
}
