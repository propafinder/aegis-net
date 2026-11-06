//! Persistent, transactional WFP kill switch. Dropping a process handle never
//! opens the physical network: only an explicit disconnect removes protection.
use std::{
    ffi::c_void,
    io,
    net::{IpAddr, SocketAddr},
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr,
};
use windows_sys::{
    core::GUID,
    Win32::{Foundation::*, NetworkManagement::WindowsFilteringPlatform::*},
};

pub const PROVIDER: GUID = GUID::from_u128(0x7982f03b_10ba_4e75_a481_ae615c10a001);
pub const SUBLAYER: GUID = GUID::from_u128(0x7982f03b_10ba_4e75_a481_ae615c10a002);
fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    value.push(0);
    Ok(value)
}
struct Engine(HANDLE);
impl Engine {
    fn open() -> io::Result<Self> {
        let mut handle = ptr::null_mut();
        check(unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut handle) })?;
        Ok(Self(handle))
    }
    fn dynamic() -> io::Result<Self> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle = ptr::null_mut();
        check(unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), &session, &mut handle) })?;
        Ok(Self(handle))
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
struct Memory(*mut c_void);
impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0(&mut self.0);
        }
    }
}
struct AppId {
    blob: *mut FWP_BYTE_BLOB,
    _memory: Memory,
}
impl AppId {
    fn new(path: &Path) -> io::Result<Self> {
        let mut blob = ptr::null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(wide(path)?.as_ptr(), &mut blob) })?;
        Ok(Self {
            blob,
            _memory: Memory(blob.cast()),
        })
    }
}
struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}
impl<'a> Transaction<'a> {
    fn new(engine: &'a Engine) -> io::Result<Self> {
        check(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
        Ok(Self {
            engine,
            committed: false,
        })
    }
    fn commit(mut self) -> io::Result<()> {
        check(unsafe { FwpmTransactionCommit0(self.engine.0) })?;
        self.committed = true;
        Ok(())
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.0);
            }
        }
    }
}
fn condition(
    key: GUID,
    kind: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}
fn app_condition(app: &AppId) -> FWPM_FILTER_CONDITION0 {
    condition(
        FWPM_CONDITION_ALE_APP_ID,
        FWP_BYTE_BLOB_TYPE,
        FWP_CONDITION_VALUE0_0 { byteBlob: app.blob },
    )
}
fn u16_condition(key: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    condition(key, FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: value })
}
fn u8_condition(key: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
    condition(key, FWP_UINT8, FWP_CONDITION_VALUE0_0 { uint8: value })
}

fn enumerate(engine: &Engine, provider: GUID) -> io::Result<Vec<u64>> {
    let mut ids = vec![];
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    ] {
        ids.extend(enumerate_layer(engine, provider, layer)?);
    }
    Ok(ids)
}
fn enumerate_layer(engine: &Engine, provider: GUID, layer: GUID) -> io::Result<Vec<u64>> {
    let mut provider = provider;
    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &mut provider,
        layerKey: layer,
        enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
        actionMask: u32::MAX,
        flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
        ..Default::default()
    };
    let mut enumeration = ptr::null_mut();
    check(unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut enumeration) })?;
    let result = (|| {
        let mut ids = vec![];
        loop {
            let mut entries = ptr::null_mut();
            let mut count = 0;
            check(unsafe {
                FwpmFilterEnum0(engine.0, enumeration, 256, &mut entries, &mut count)
            })?;
            let _memory = Memory(entries.cast());
            for i in 0..count as usize {
                ids.push(unsafe { (**entries.add(i)).filterId });
            }
            if count == 0 {
                break;
            }
            if ids.len() > 4096 {
                return Err(io::Error::other("AEGIS firewall object count rejected"));
            }
        }
        Ok(ids)
    })();
    unsafe {
        FwpmFilterDestroyEnumHandle0(engine.0, enumeration);
    }
    result
}
fn remove_filters(engine: &Engine, provider: GUID) -> io::Result<()> {
    for id in enumerate(engine, provider)? {
        check(unsafe { FwpmFilterDeleteById0(engine.0, id) })?;
    }
    Ok(())
}

/// Holds the interface exception only while this tunnel instance is alive.
/// Closing the dynamic WFP session (including process death) removes the permit;
/// persistent block/relay/boot policy is intentionally unaffected.
#[must_use = "keep the permit alive until before the tunnel adapter is removed"]
pub struct TunnelPermit {
    _engine: Engine,
}
impl TunnelPermit {
    fn new(
        luid: u64,
        scope: Option<&Path>,
        mut provider: GUID,
        sublayer: GUID,
    ) -> io::Result<Self> {
        let engine = Engine::dynamic()?;
        let transaction = Transaction::new(&engine)?;
        let scope = scope.map(AppId::new).transpose()?;
        let mut name: Vec<u16> = "AEGIS live tunnel interface"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        for (layer, interface, inbound_reauthorization) in [
            (
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                false,
            ),
            (
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_CONDITION_IP_ARRIVAL_INTERFACE,
                true,
            ),
            (
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                false,
            ),
            (
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_CONDITION_IP_ARRIVAL_INTERFACE,
                true,
            ),
            (
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                false,
            ),
            (
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                false,
            ),
        ] {
            if luid == 0 {
                continue;
            }
            let mut luid = luid;
            let mut conditions = vec![condition(
                interface,
                FWP_UINT64,
                FWP_CONDITION_VALUE0_0 { uint64: &mut luid },
            )];
            if inbound_reauthorization {
                // ALE can reauthorize an outbound flow on an inbound packet.
                // Its next-hop interface is then FWP_EMPTY. Match the actual
                // arrival LUID, only for reauthorization; never permit an
                // empty interface or all previously authorized flows.
                let mut reauthorize = condition(
                    FWPM_CONDITION_FLAGS,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_REAUTHORIZE,
                    },
                );
                reauthorize.matchType = FWP_MATCH_FLAGS_ALL_SET;
                conditions.push(reauthorize);
            }
            if let Some(app) = &scope {
                conditions.push(app_condition(app));
            }
            let filter = FWPM_FILTER0 {
                filterKey: GUID::from_u128(rand::random()),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: ptr::null_mut(),
                },
                providerKey: &mut provider,
                layerKey: layer,
                subLayerKey: sublayer,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: 14 },
                },
                numFilterConditions: conditions.len() as u32,
                filterCondition: conditions.as_mut_ptr(),
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_PERMIT,
                    ..Default::default()
                },
                ..Default::default()
            };
            check(unsafe { FwpmFilterAdd0(engine.0, &filter, ptr::null_mut(), ptr::null_mut()) })?;
        }
        transaction.commit()?;
        Ok(Self { _engine: engine })
    }
}

/// `scope` is used only by isolated validation; product callers pass None for
/// machine-wide protection. Allows are limited to loopback, the tunnel, and
/// the exact relay executable's pinned control tuples.
pub fn install(
    luid: u64,
    executable: &Path,
    relays: &[SocketAddr],
    scope: Option<&Path>,
) -> io::Result<TunnelPermit> {
    install_with_identity(executable, relays, scope, PROVIDER, SUBLAYER)?;
    TunnelPermit::new(luid, scope, PROVIDER, SUBLAYER)
}
/// Arm persistent protection without permitting an adapter. Used before online
/// certificate recovery; only this executable's pinned control tuples can dial.
pub fn protect_control(executable: &Path, controls: &[SocketAddr]) -> io::Result<usize> {
    install_with_identity(executable, controls, None, PROVIDER, SUBLAYER)
}

fn install_with_identity(
    executable: &Path,
    relays: &[SocketAddr],
    scope: Option<&Path>,
    provider: GUID,
    sublayer: GUID,
) -> io::Result<usize> {
    if relays.is_empty() || relays.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kill switch requires bounded pinned relay endpoints",
        ));
    }
    let engine = Engine::open()?;
    let transaction = Transaction::new(&engine)?;
    let mut name: Vec<u16> = "AEGIS full tunnel protection"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut provider_key = provider;
    let display = FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    remove_filters(&engine, provider)?;
    let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &sublayer) };
    if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
        check(code)?;
    }
    let code = unsafe { FwpmProviderDeleteByKey0(engine.0, &provider) };
    if code != FWP_E_PROVIDER_NOT_FOUND as u32 {
        check(code)?;
    }
    let mut owner = executable
        .canonicalize()?
        .to_string_lossy()
        .to_lowercase()
        .into_bytes();
    let p = FWPM_PROVIDER0 {
        providerKey: provider,
        displayData: display,
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: FWP_BYTE_BLOB {
            size: owner.len() as u32,
            data: owner.as_mut_ptr(),
        },
        ..Default::default()
    };
    let code = unsafe { FwpmProviderAdd0(engine.0, &p, ptr::null_mut()) };
    if code != FWP_E_ALREADY_EXISTS as u32 {
        check(code)?;
    }
    let s = FWPM_SUBLAYER0 {
        subLayerKey: sublayer,
        displayData: display,
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        weight: 0xfff0,
        ..Default::default()
    };
    let code = unsafe { FwpmSubLayerAdd0(engine.0, &s, ptr::null_mut()) };
    if code != FWP_E_ALREADY_EXISTS as u32 {
        check(code)?;
    }
    remove_filters(&engine, provider)?;
    let app = AppId::new(executable)?;
    let scope = scope.map(AppId::new).transpose()?;
    let mut system = vec![0u16; 32768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            system.as_mut_ptr(),
            system.len() as u32,
        )
    } as usize;
    if length == 0 || length >= system.len() {
        return Err(io::Error::last_os_error());
    }
    let dhcp = AppId::new(
        &std::path::PathBuf::from(String::from_utf16_lossy(&system[..length])).join("svchost.exe"),
    )?;
    let mut count = 0;
    let mut add = |layer: GUID,
                   boot: bool,
                   permit: bool,
                   weight: u8,
                   mut conditions: Vec<FWPM_FILTER_CONDITION0>|
     -> io::Result<()> {
        if let Some(scope) = scope.as_ref().filter(|_| !boot) {
            if !conditions.iter().any(|c| {
                c.fieldKey.data1 == FWPM_CONDITION_ALE_APP_ID.data1
                    && c.fieldKey.data2 == FWPM_CONDITION_ALE_APP_ID.data2
                    && c.fieldKey.data3 == FWPM_CONDITION_ALE_APP_ID.data3
                    && c.fieldKey.data4 == FWPM_CONDITION_ALE_APP_ID.data4
            }) {
                conditions.push(app_condition(scope));
            }
        }
        let filter = FWPM_FILTER0 {
            filterKey: GUID::from_u128(rand::random()),
            displayData: display,
            flags: if boot {
                FWPM_FILTER_FLAG_BOOTTIME
            } else {
                FWPM_FILTER_FLAG_PERSISTENT
            },
            providerKey: &mut provider_key,
            layerKey: layer,
            subLayerKey: sublayer,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if permit {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                ..Default::default()
            },
            ..Default::default()
        };
        check(unsafe { FwpmFilterAdd0(engine.0, &filter, ptr::null_mut(), ptr::null_mut()) })?;
        count += 1;
        Ok(())
    };
    for (v6, layer, inbound) in [
        (false, FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
        (true, FWPM_LAYER_ALE_AUTH_CONNECT_V6, false),
        (false, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, true),
        (true, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true),
    ] {
        let mut loopback = condition(
            FWPM_CONDITION_FLAGS,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        );
        loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
        add(layer, false, true, 15, vec![loopback])?;
        for relay in relays
            .iter()
            .filter(|endpoint| !inbound && endpoint.is_ipv6() == v6)
        {
            if relay.port() == 0 || relay.ip().is_unspecified() || relay.ip().is_multicast() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut v6_bytes = FWP_BYTE_ARRAY16 {
                byteArray16: [0; 16],
            };
            let remote = match relay.ip() {
                IpAddr::V4(ip) => condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from(ip),
                    },
                ),
                IpAddr::V6(ip) => {
                    v6_bytes.byteArray16 = ip.octets();
                    condition(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        FWP_BYTE_ARRAY16_TYPE,
                        FWP_CONDITION_VALUE0_0 {
                            byteArray16: &mut v6_bytes,
                        },
                    )
                }
            };
            for protocol in [6, 17] {
                add(
                    layer,
                    false,
                    true,
                    13,
                    vec![
                        app_condition(&app),
                        remote,
                        u16_condition(FWPM_CONDITION_IP_REMOTE_PORT, relay.port()),
                        u8_condition(FWPM_CONDITION_IP_PROTOCOL, protocol),
                    ],
                )?;
            }
        }
        // Only the Windows service host may use the DHCP exception. An
        // ordinary app binding source port 68/546 must not gain direct egress.
        if scope.is_none() {
            add(
                layer,
                false,
                true,
                12,
                vec![
                    app_condition(&dhcp),
                    u8_condition(FWPM_CONDITION_IP_PROTOCOL, 17),
                    u16_condition(FWPM_CONDITION_IP_LOCAL_PORT, if v6 { 546 } else { 68 }),
                    u16_condition(FWPM_CONDITION_IP_REMOTE_PORT, if v6 { 547 } else { 67 }),
                ],
            )?;
        }
        if v6 {
            // Inbound DAD has an unspecified source. Multicast ff02::/16 is
            // an outbound destination, never an inbound remote peer address.
            let neighbors = if inbound {
                [(0xfe, 0x80, 10), (0, 0, 128)]
            } else {
                [(0xfe, 0x80, 10), (0xff, 0x02, 16)]
            };
            for (first, second, bits) in neighbors {
                let mut mask = FWP_V6_ADDR_AND_MASK {
                    addr: [0; 16],
                    prefixLength: bits,
                };
                mask.addr[0] = first;
                mask.addr[1] = second;
                add(
                    layer,
                    false,
                    true,
                    12,
                    vec![
                        u8_condition(FWPM_CONDITION_IP_PROTOCOL, 58),
                        condition(
                            FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            FWP_V6_ADDR_MASK,
                            FWP_CONDITION_VALUE0_0 {
                                v6AddrMask: &mut mask,
                            },
                        ),
                    ],
                )?;
            }
        }
        add(layer, false, false, 1, vec![])?;
    }
    // Boot filters cover the interval before BFE rehydrates persistent ALE
    // policy. Isolated tests narrow these otherwise inactive rules to TEST-NET.
    for (v6, layer) in [
        (false, FWPM_LAYER_OUTBOUND_IPPACKET_V4),
        (true, FWPM_LAYER_OUTBOUND_IPPACKET_V6),
    ] {
        let mut loopback = condition(
            FWPM_CONDITION_FLAGS,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        );
        loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
        add(layer, true, true, 15, vec![loopback])?;
        let mut restricted = vec![];
        let mut v6_bytes = FWP_BYTE_ARRAY16 {
            byteArray16: [0; 16],
        };
        if scope.is_some() {
            restricted.push(if v6 {
                v6_bytes.byteArray16 = "2001:db8::123"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets();
                condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_BYTE_ARRAY16_TYPE,
                    FWP_CONDITION_VALUE0_0 {
                        byteArray16: &mut v6_bytes,
                    },
                )
            } else {
                condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from(std::net::Ipv4Addr::new(192, 0, 2, 123)),
                    },
                )
            });
        }
        add(layer, true, false, 1, restricted)?;
    }
    transaction.commit()?;
    Ok(count)
}
pub fn status() -> io::Result<usize> {
    let status = inspect(None)?;
    Ok(status.persistent_filters + status.boot_filters)
}
#[derive(Default, serde::Serialize)]
pub struct ProtectionStatus {
    pub persistent_filters: usize,
    pub boot_filters: usize,
    pub persistent_blocks: usize,
    pub boot_blocks: usize,
    pub live_interface_permits: usize,
    pub disabled_filters: usize,
    pub owned_by_installation: bool,
}
/// Inventory is diagnostic evidence, not proof of packet delivery or leakage.
pub fn inspect(executable: Option<&Path>) -> io::Result<ProtectionStatus> {
    inspect_identity(PROVIDER, executable)
}
fn inspect_identity(provider: GUID, executable: Option<&Path>) -> io::Result<ProtectionStatus> {
    let engine = Engine::open()?;
    let mut result = ProtectionStatus::default();
    for id in enumerate(&engine, provider)? {
        let mut raw = ptr::null_mut();
        check(unsafe { FwpmFilterGetById0(engine.0, id, &mut raw) })?;
        let _memory = Memory(raw.cast());
        let filter = unsafe { &*raw };
        let persistent = filter.flags & FWPM_FILTER_FLAG_PERSISTENT != 0;
        let boot = filter.flags & FWPM_FILTER_FLAG_BOOTTIME != 0;
        let block = filter.action.r#type == FWP_ACTION_BLOCK;
        result.persistent_filters += usize::from(persistent);
        result.boot_filters += usize::from(boot);
        result.persistent_blocks += usize::from(persistent && block);
        result.boot_blocks += usize::from(boot && block);
        result.disabled_filters += usize::from(filter.flags & FWPM_FILTER_FLAG_DISABLED != 0);
        if !persistent && !boot && filter.action.r#type == FWP_ACTION_PERMIT {
            for index in 0..filter.numFilterConditions as usize {
                let condition = unsafe { &*filter.filterCondition.add(index) };
                let key = condition.fieldKey;
                if [
                    FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                    FWPM_CONDITION_IP_ARRIVAL_INTERFACE,
                ]
                .iter()
                .any(|expected| {
                    key.data1 == expected.data1
                        && key.data2 == expected.data2
                        && key.data3 == expected.data3
                        && key.data4 == expected.data4
                }) {
                    result.live_interface_permits += 1;
                }
            }
        }
    }
    if let Some(executable) = executable {
        result.owned_by_installation = owner_matches(&engine, provider, executable)?;
    }
    Ok(result)
}
/// Isolated native acceptance scope. Never touches product provider objects.
pub struct ScopedProtection {
    permit: Option<TunnelPermit>,
    provider: GUID,
    sublayer: GUID,
}
impl ScopedProtection {
    /// Test harness: force an ALE policy change without replacing a block or
    /// removing the original permits. The duplicate permits have identical
    /// scope and disappear with their temporary dynamic session.
    pub fn reauthorize(&self, luid: u64, executable: &Path) -> io::Result<()> {
        let _duplicate = TunnelPermit::new(luid, Some(executable), self.provider, self.sublayer)?;
        Ok(())
    }

    pub fn install(luid: u64, executable: &Path, relays: &[SocketAddr]) -> io::Result<Self> {
        let result = Self {
            permit: None,
            provider: GUID::from_u128(rand::random()),
            sublayer: GUID::from_u128(rand::random()),
        };
        install_with_identity(
            executable,
            relays,
            Some(executable),
            result.provider,
            result.sublayer,
        )?;
        let mut result = result;
        result.permit = Some(TunnelPermit::new(
            luid,
            Some(executable),
            result.provider,
            result.sublayer,
        )?);
        Ok(result)
    }
}
impl Drop for ScopedProtection {
    fn drop(&mut self) {
        drop(self.permit.take());
        let _ = disconnect_identity(self.provider, self.sublayer);
    }
}
pub fn disconnect() -> io::Result<()> {
    disconnect_identity(PROVIDER, SUBLAYER)
}
/// Uninstalling an old version must not remove the active version's policy.
pub fn disconnect_owned(executable: &Path) -> io::Result<bool> {
    let engine = Engine::open()?;
    if !owner_matches(&engine, PROVIDER, executable)? {
        return Ok(false);
    }
    disconnect()?;
    Ok(true)
}
fn owner_matches(engine: &Engine, identity: GUID, executable: &Path) -> io::Result<bool> {
    let mut provider = ptr::null_mut();
    let code = unsafe { FwpmProviderGetByKey0(engine.0, &identity, &mut provider) };
    if code == FWP_E_PROVIDER_NOT_FOUND as u32 {
        return Ok(false);
    }
    check(code)?;
    let _memory = Memory(provider.cast());
    let data = unsafe { (*provider).providerData };
    if data.size > 32768 || data.data.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let owner = unsafe { std::slice::from_raw_parts(data.data, data.size as usize) };
    Ok(owner
        == executable
            .canonicalize()?
            .to_string_lossy()
            .to_lowercase()
            .as_bytes())
}
fn disconnect_identity(provider: GUID, sublayer: GUID) -> io::Result<()> {
    let engine = Engine::open()?;
    let transaction = Transaction::new(&engine)?;
    remove_filters(&engine, provider)?;
    let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &sublayer) };
    if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
        check(code)?;
    }
    let code = unsafe { FwpmProviderDeleteByKey0(engine.0, &provider) };
    if code != FWP_E_PROVIDER_NOT_FOUND as u32 {
        check(code)?;
    }
    transaction.commit()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "administrator; terminates only its own helper process; separate WFP provider scoped to the test EXE"]
    fn process_death_removes_live_permit_but_not_persistent_block() {
        use std::{
            io::{BufRead, Write},
            os::windows::process::CommandExt,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let exe = std::env::current_exe().unwrap();
        if let Ok(provider) = std::env::var("AEGIS_DYNAMIC_CHILD_PROVIDER") {
            let sublayer = std::env::var("AEGIS_DYNAMIC_CHILD_SUBLAYER").unwrap();
            let luid = std::env::var("AEGIS_DYNAMIC_CHILD_LUID")
                .unwrap()
                .parse()
                .unwrap();
            let _permit = TunnelPermit::new(
                luid,
                Some(&exe),
                GUID::from_u128(provider.parse().unwrap()),
                GUID::from_u128(sublayer.parse().unwrap()),
            )
            .unwrap();
            println!("AEGIS_DYNAMIC_READY");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(60));
            panic!("parent did not terminate its helper");
        }
        let provider: u128 = rand::random();
        let sublayer: u128 = rand::random();
        let target = "192.0.2.123:9".parse::<SocketAddr>().unwrap();
        let route = super::super::network::native_route(target.ip()).unwrap();
        let cleanup = ScopedProtection {
            permit: None,
            provider: GUID::from_u128(provider),
            sublayer: GUID::from_u128(sublayer),
        };
        install_with_identity(
            &exe,
            &["127.0.0.1:9".parse().unwrap()],
            Some(&exe),
            cleanup.provider,
            cleanup.sublayer,
        )
        .unwrap();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(Command::new(&exe).args(["--exact", "windows_tunnel::firewall::tests::process_death_removes_live_permit_but_not_persistent_block", "--ignored", "--nocapture"])
            .env("AEGIS_DYNAMIC_CHILD_PROVIDER", provider.to_string()).env("AEGIS_DYNAMIC_CHILD_SUBLAYER", sublayer.to_string())
            .env("AEGIS_DYNAMIC_CHILD_LUID", route.luid.to_string()).creation_flags(0x08000000)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap());
        let output = child.0.stdout.take().unwrap();
        let (sender, ready) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(output)
                .lines()
                .map_while(Result::ok)
            {
                if line == "AEGIS_DYNAMIC_READY" {
                    let _ = sender.send(());
                    break;
                }
            }
        });
        let started = ready.recv_timeout(Duration::from_secs(15));
        if started.is_err() {
            drop(child);
            reader.join().unwrap();
            panic!("dynamic permit helper failed to start");
        }
        reader.join().unwrap();
        assert_eq!(
            inspect_identity(cleanup.provider, Some(&exe))
                .unwrap()
                .live_interface_permits,
            6
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = inspect_identity(cleanup.provider, Some(&exe)).unwrap();
            if state.live_interface_permits == 0 {
                assert_eq!(state.persistent_blocks, 4);
                assert_eq!(state.boot_blocks, 2);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "dynamic permit survived process death"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            std::net::TcpStream::connect_timeout(&target, Duration::from_secs(2))
                .unwrap_err()
                .raw_os_error(),
            Some(10013)
        );
    }

    #[test]
    #[ignore = "administrator; permits only this test executable on its physical interface and sends one TEST-NET UDP canary"]
    fn live_interface_permit_disappears_while_persistent_block_remains() {
        let exe = std::env::current_exe().unwrap();
        let target: SocketAddr = "192.0.2.123:9".parse().unwrap();
        let route = super::super::network::native_route(target.ip()).unwrap();
        let protection =
            ScopedProtection::install(route.luid, &exe, &["127.0.0.1:9".parse().unwrap()]).unwrap();
        let provider = protection.provider;
        let before = enumerate(&Engine::open().unwrap(), provider).unwrap().len();
        let status = inspect_identity(provider, Some(&exe)).unwrap();
        assert_eq!(status.live_interface_permits, 6);
        assert_eq!(status.persistent_blocks, 4);
        assert_eq!(status.boot_blocks, 2);
        assert_eq!(status.disabled_filters, 0);
        assert!(status.owned_by_installation);
        let send = || {
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.send_to(b"AEGIS-canary", target)
        };
        assert_eq!(send().unwrap(), 12);
        let mut protection = protection;
        drop(protection.permit.take());
        assert_eq!(
            enumerate(&Engine::open().unwrap(), provider).unwrap().len(),
            before - 6
        );
        assert_eq!(
            inspect_identity(provider, Some(&exe))
                .unwrap()
                .live_interface_permits,
            0
        );
        let blocked =
            || std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_secs(2));
        assert_eq!(blocked().unwrap_err().raw_os_error(), Some(10013));
        // A second close cannot remove the persistent block or another owner.
        drop(protection.permit.take());
        assert_eq!(blocked().unwrap_err().raw_os_error(), Some(10013));
        drop(protection);
        assert!(enumerate(&Engine::open().unwrap(), provider)
            .unwrap()
            .is_empty());
    }

    #[test]
    #[ignore = "requires administrator; blocks only this test executable, using separate test-only WFP identities"]
    fn persistent_scoped_block_survives_engine_close_and_cleans_up() {
        let provider = GUID::from_u128(rand::random());
        let sublayer = GUID::from_u128(rand::random());
        struct Cleanup(GUID, GUID);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = disconnect_identity(self.0, self.1);
            }
        }
        let _cleanup = Cleanup(provider, sublayer);
        let exe = std::env::current_exe().unwrap();
        let count = install_with_identity(
            &exe,
            &["127.0.0.1:9".parse().unwrap()],
            Some(&exe),
            provider,
            sublayer,
        )
        .unwrap();
        assert!(count >= 8);
        // Replacing live policy is atomic, and a rejected replacement must
        // leave the previous block rules in force.
        assert_eq!(
            install_with_identity(
                &exe,
                &["127.0.0.1:9".parse().unwrap()],
                Some(&exe),
                provider,
                sublayer
            )
            .unwrap(),
            count
        );
        assert!(install_with_identity(
            &exe,
            &["127.0.0.1:0".parse().unwrap()],
            Some(&exe),
            provider,
            sublayer
        )
        .is_err());
        assert_eq!(
            enumerate(&Engine::open().unwrap(), provider).unwrap().len(),
            count
        );
        let error = std::net::TcpStream::connect_timeout(
            &"192.0.2.123:443".parse().unwrap(),
            std::time::Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(10013),
            "WFP must refuse locally before any network attempt"
        );
        let loopback = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(std::net::TcpStream::connect(loopback.local_addr().unwrap()).is_ok());
        disconnect_identity(provider, sublayer).unwrap();
        disconnect_identity(provider, sublayer).unwrap();
        assert!(enumerate(&Engine::open().unwrap(), provider)
            .unwrap()
            .is_empty());
    }
}
