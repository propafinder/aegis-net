use super::*;
use aegis_core::{tunnel_policy::WindowsTunnelSettings, TunnelTransportFamily};
use windows_sys::Win32::{Foundation::*, System::Threading::*};

#[test]
fn uninstall_waits_for_external_delete_lock() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("locked.exe");
    fs::write(&path, b"synthetic locked file").unwrap();
    let holder = fs::OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&path)
        .unwrap();
    assert_eq!(fs::remove_file(&path).unwrap_err().raw_os_error(), Some(32));
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        drop(holder);
    });
    let result = remove_verified_binary(&path, Instant::now() + Duration::from_secs(5));
    release.join().unwrap();
    result.unwrap();
    assert!(!path.exists());
}

// SEC_IMAGE reproduces the access-denied deletion caused by a mapped EXE.
// A readonly attribute is not sufficient: Rust's Windows removal can clear it.
struct MappedImage {
    _section: std::os::windows::io::OwnedHandle,
    view: usize,
}
impl Drop for MappedImage {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Memory::*;
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.view as *mut _,
            });
        }
    }
}
fn mapped_image(path: &Path) -> MappedImage {
    use std::os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    use windows_sys::Win32::{Storage::FileSystem::*, System::Memory::*};
    fs::copy(std::env::current_exe().unwrap(), path).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .unwrap();
    let section = unsafe {
        CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null(),
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            std::ptr::null(),
        )
    };
    assert!(!section.is_null(), "{}", std::io::Error::last_os_error());
    let section = unsafe { OwnedHandle::from_raw_handle(section) };
    let view = unsafe { MapViewOfFile(section.as_raw_handle(), FILE_MAP_READ, 0, 0, 0) };
    assert!(!view.Value.is_null(), "{}", std::io::Error::last_os_error());
    MappedImage {
        _section: section,
        view: view.Value as usize,
    }
}

#[test]
fn uninstall_waits_for_external_image_mapping_to_clear() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("mapped.exe");
    let image = mapped_image(&path);
    assert_eq!(fs::remove_file(&path).unwrap_err().raw_os_error(), Some(5));
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        drop(image);
    });
    let result = remove_verified_binary(&path, Instant::now() + Duration::from_secs(5));
    release.join().unwrap();
    result.unwrap();
    assert!(!path.exists());
}

#[test]
fn uninstall_timeout_retains_mapped_image() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("retained.exe");
    let image = mapped_image(&path);
    let original = fs::read(&path).unwrap();
    let readonly = fs::metadata(&path).unwrap().permissions().readonly();
    let error = remove_verified_binary(&path, Instant::now()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("file retained"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().readonly(),
        readonly
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    drop(image);
}

#[test]
#[ignore = "administrator, AEGIS_TEST_CLIENT/WINCTL/WINTUN_ROOT; isolated service and split routes with system DNS and kill switch disabled"]
fn full_package_service_crash_upgrade_and_rollback() {
    let result_path = std::env::var_os("AEGIS_LIFECYCLE_RESULT").map(PathBuf::from);
    if let Some(output) = &result_path {
        assert!(!output.exists(), "lifecycle result must be a new file");
    }
    let fixture = MachineFixture::new("service-lifecycle");
    let path = fixture.path().to_path_buf();
    let service_name = format!("AegisTunnelTest{}", std::process::id());
    assert_eq!(service::query(&service_name).unwrap()["exists"], false);
    struct Cleanup {
        name: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = service::run(ServiceCommand::Uninstall(ServiceNameArg {
                service_name: self.name.clone(),
            }));
        }
    }
    let _cleanup = Cleanup {
        name: service_name.clone(),
    };
    let kit = path.join("kit");
    let built = package::build_with_wintun(
        &PathBuf::from(std::env::var_os("AEGIS_TEST_CLIENT").unwrap()),
        &PathBuf::from(std::env::var_os("AEGIS_TEST_WINCTL").unwrap()),
        &kit,
        "1".repeat(40),
        Some(&PathBuf::from(
            std::env::var_os("AEGIS_TEST_WINTUN_ROOT").unwrap(),
        )),
    )
    .unwrap();
    let mut cfg = Settings {
        mode: Mode::Relay,
        windows_tunnel: Some(WindowsTunnelSettings {
            adapter_name: format!("AEGIS-Service-Test-{}", std::process::id()),
            include_routes: vec!["192.0.2.123/32".into(), "2001:db8::123/128".into()],
            configure_dns: false,
            kill_switch: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    cfg.ingress.allow_fallback = false;
    cfg.relay.server = "127.0.0.1:9".into();
    cfg.relay.server_name = "fixture.test".into();
    cfg.relay.auth_token = "0123456789abcdef".repeat(4);
    cfg.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    cfg.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
    let source = path.join("input.toml");
    InstallAccess::Machine
        .write_new(&source, toml::to_string(&cfg).unwrap().as_bytes())
        .unwrap();
    let v1 = path.join("v1");
    let pin = built["manifest_sha256"].as_str().unwrap().to_owned();
    install(InstallArgs {
        device_online_bundle: None,
        authenticode: Default::default(),
        package: kit.clone(),
        trust: package::trust::TrustArgs::pinned(pin.clone()),
        config: source,
        root: v1.clone(),
        service: true,
        start: true,
        service_name: service_name.clone(),
    })
    .unwrap();
    let first = service::query(&service_name).unwrap();
    assert_eq!(first["state"], "RUNNING");
    let tested_binaries = verify_installed(&v1).unwrap().binaries;
    let diagnostic = operator::doctor(&v1).unwrap();
    assert_eq!(diagnostic["integrity"], "verified");
    if diagnostic["tunnel"]["adapter_present"] != true {
        let failure = json!({
            "schema": "aegis_windows_native_lifecycle_v1",
            "status": "FAIL",
            "phase": "post_install_adapter_lookup",
            "binaries_sha256": tested_binaries,
            "diagnostic": diagnostic,
            "service_after_diagnostic": service::query(&service_name).ok(),
        });
        if let Some(output) = &result_path {
            fs::write(output, serde_json::to_vec_pretty(&failure).unwrap()).unwrap();
        }
        panic!("post-install adapter lookup failed: {failure}");
    }
    assert_eq!(diagnostic["relay_health"], "not_probed");
    assert_eq!(
        operator::doctor(&v1.canonicalize().unwrap()).unwrap()["integrity"],
        "verified"
    );
    let checkpoint = path.join("reboot-checkpoint");
    assert_eq!(
        reboot::prepare(&v1, &checkpoint).unwrap()["status"],
        "awaiting_manual_reboot"
    );
    assert!(reboot::verify(&v1, &checkpoint)
        .unwrap_err()
        .to_string()
        .contains("later Windows boot"));
    // Idempotent connect, explicit disconnect, then restart through the same
    // verified operator surface used by the shipped kit.
    assert_eq!(
        operator::connect(&v1).unwrap()["service"]["process_id"],
        first["process_id"]
    );
    let stopped_process = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE,
            0,
            first["process_id"].as_u64().unwrap() as u32,
        )
    };
    assert!(!stopped_process.is_null());
    assert_eq!(operator::disconnect(&v1).unwrap()["disconnected"], true);
    let exited = unsafe { WaitForSingleObject(stopped_process, 0) };
    unsafe { CloseHandle(stopped_process) };
    assert_eq!(
        exited, WAIT_OBJECT_0,
        "disconnect must wait for the service process, not only SCM STOPPED"
    );
    assert_eq!(service::query(&service_name).unwrap()["state"], "STOPPED");
    assert_eq!(
        operator::connect(&v1).unwrap()["service"]["state"],
        "RUNNING"
    );
    let first = service::query(&service_name).unwrap();
    let pid = first["process_id"].as_u64().unwrap() as u32;
    // Hold and validate a process handle before terminating this test service.
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    assert!(!handle.is_null());
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    assert_ne!(
        unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) },
        0
    );
    let executable = PathBuf::from(String::from_utf16_lossy(&buffer[..length as usize]));
    assert_eq!(
        executable.canonicalize().unwrap(),
        v1.join("bin/aegis-client.exe").canonicalize().unwrap()
    );
    assert_ne!(unsafe { TerminateProcess(handle, 77) }, 0);
    unsafe {
        CloseHandle(handle);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let current = service::query(&service_name).unwrap();
        if current["state"] == "RUNNING" && current["process_id"] != first["process_id"] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "SCM crash restart did not become ready: {current}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let recovered_pid = service::query(&service_name).unwrap()["process_id"].clone();
    let state = v1.join("state/retained.txt");
    // Change only a deliberately losing default route on another disposable
    // adapter. Verify the real physical route still wins before waiting for
    // the service to rebuild its own adapter without a process restart.
    {
        use aegis_core::windows_tunnel::{network, wintun::Wintun};
        let name = cfg.windows_tunnel.as_ref().unwrap().adapter_name.clone();
        // NET_LUID indices may be reused immediately after adapter removal;
        // the new Wintun device GUID is the stable generation identity.
        let identity = || {
            let luid = network::adapter_luid(&name).ok()?;
            let mut guid = windows_sys::core::GUID::from_u128(0);
            let luid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: luid };
            if unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid(
                    &luid, &mut guid,
                )
            } != 0
            {
                return None;
            }
            Some((guid.data1, guid.data2, guid.data3, guid.data4))
        };
        let original = identity().unwrap();
        let destination = "192.0.2.222".parse().unwrap();
        let physical = network::native_route(destination).unwrap();
        let driver = PathBuf::from(std::env::var_os("AEGIS_TEST_WINTUN_ROOT").unwrap())
            .join("bin/amd64/wintun.dll");
        let adapter = Wintun::open(
            &driver,
            &format!("AEGIS-Gateway-Test-{}", std::process::id()),
        )
        .unwrap();
        // This adapter only holds a route-table event. Do not configure the
        // service's fixed IP addresses on a second simultaneous adapter.
        let mut network = network::NetworkGuard::route_only(adapter.luid).unwrap();
        network
            .add(network::Route {
                luid: adapter.luid,
                index: network.index,
                prefix: aegis_core::tunnel_policy::Prefix::parse("0.0.0.0/0").unwrap(),
                next_hop: "0.0.0.0".parse().unwrap(),
                scope_id: 0,
                metric: 100000,
            })
            .unwrap();
        assert_eq!(
            network::native_route(destination).unwrap().luid,
            physical.luid,
            "test route must never replace real connectivity"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if identity().is_some_and(|guid| guid != original) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "gateway change did not rebuild the tunnel"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        network.cleanup().unwrap();
        drop(network);
        drop(adapter);
        assert_eq!(
            service::query(&service_name).unwrap()["process_id"],
            recovered_pid,
            "gateway recovery must not restart the process"
        );
    }
    windows_file::write_private_new(&state, b"retained learned state", true).unwrap();
    let v2 = path.join("v2");
    run(ClientArgs {
        command: ClientCommand::Upgrade {
            root: v1.clone(),
            package: kit,
            trust: package::trust::TrustArgs::pinned(pin),
            authenticode: Default::default(),
            new_root: v2.clone(),
        },
    })
    .unwrap();
    service::require_binary_in(&service_name, &v2.join("bin/aegis-client.exe")).unwrap();
    assert_eq!(service::query(&service_name).unwrap()["state"], "RUNNING");
    run(ClientArgs {
        command: ClientCommand::Rollback { root: v2.clone() },
    })
    .unwrap();
    service::require_binary_in(&service_name, &v1.join("bin/aegis-client.exe")).unwrap();
    assert_eq!(service::query(&service_name).unwrap()["state"], "RUNNING");
    assert_eq!(
        aegis_core::secret_file::read_config(&state, 1024)
            .unwrap()
            .as_slice(),
        b"retained learned state"
    );
    run(ClientArgs {
        command: ClientCommand::Uninstall { root: v1.clone() },
    })
    .unwrap();
    assert_eq!(service::query(&service_name).unwrap()["exists"], false);
    assert!(state.exists());
    assert!(v2.join("bin/wintun.dll").exists());
    assert!(!v1.join("bin/aegis-client.exe").exists());
    assert!(!v1.join("config/aegis.tunnel-state.json").exists());
    assert!(v1.join("config/aegis.toml").exists());
    assert!(aegis_core::windows_tunnel::network::adapter_luid(
        &cfg.windows_tunnel.as_ref().unwrap().adapter_name
    )
    .is_err());
    if let Some(output) = result_path {
        let result = json!({
            "schema": "aegis_windows_native_lifecycle_v1",
            "status": "PASS",
            "binaries_sha256": tested_binaries,
            "install": true,
            "connect_scm_ready": true,
            "disconnect_reconnect": true,
            "process_crash_scm_recovery": true,
            "route_change_recovery": true,
            "upgrade_and_rollback": true,
            "uninstall_service_binary_adapter_routes": true,
            "configuration_and_state_preserved": true,
            "scope": "isolated service and documentation-only split routes",
            "same_package_upgrade_transaction": true,
            "relay_payload_verified": false,
            "global_kill_switch_verified": false,
            "reboot_performed": false
        });
        windows_file::write_private_new(
            &output,
            &serde_json::to_vec_pretty(&result).unwrap(),
            false,
        )
        .unwrap();
    }
}

#[test]
fn managed_render_keeps_identity_outside_version_directories() {
    let fixture = MachineFixture::new("managed-render");
    let root = fixture.path().to_path_buf();
    let identity = root.as_path().join("identity");
    windows_file::create_machine_private_directory(&identity).unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["fixture.test".into()]).unwrap();
    let cert = certificate.cert.pem();
    let key = certificate.key_pair.serialize_pem();
    for (name, contents) in [
        ("device.pem", cert.as_bytes()),
        ("device.key", key.as_bytes()),
        ("ca.pem", cert.as_bytes()),
    ] {
        InstallAccess::Machine
            .write_new(&identity.join(name), contents)
            .unwrap();
    }
    let mut cfg = Settings {
        mode: Mode::Relay,
        windows_tunnel: Some(Default::default()),
        ..Default::default()
    };
    cfg.ingress.allow_fallback = false;
    cfg.relay.server = "192.0.2.10:443".into();
    cfg.relay.server_name = "fixture.test".into();
    cfg.relay.ca_cert = Some(identity.join("ca.pem"));
    cfg.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    cfg.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
    cfg.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
    cfg.relay.inner_tls = Some(aegis_core::secure_channel::ClientSettings {
        server_name: "fixture.test".into(),
        server_ca: identity.join("ca.pem"),
        cert: identity.join("device.pem"),
        key: identity.join("device.key"),
    });
    for version in ["first", "upgrade"] {
        let (rendered, copies) = render_settings_online(
            &mut cfg.clone(),
            root.as_path(),
            &root.as_path().join(version),
            true,
        )
        .unwrap();
        let parsed: Settings = toml::from_str(std::str::from_utf8(&rendered).unwrap()).unwrap();
        let inner = parsed.relay.inner_tls.unwrap();
        assert_eq!(inner.key, identity.join("device.key"));
        assert_eq!(inner.cert, identity.join("device.pem"));
        assert!(!copies.contains_key("device.pem"));
        assert!(!copies.contains_key("device-key.pem"));
    }
    assert!(render_settings_online(&mut cfg, root.as_path(), root.as_path(), true).is_err());
    assert_eq!(
        fs::read(identity.join("device.key")).unwrap(),
        key.as_bytes()
    );
}
