//! Experimental private proposal: separately admitted custody/runtime identities.
//! Wired only in this private v2 candidate. No daemon/routing/NSS calls.
//! Captured local group membership is narrowed before publication; actual
//! process admission separately checks the running supplementary group set.
use crate::profile_auto_capture::{CaptureLimits, CapturedTree, GenerationRecord, InputRole};
use crate::profile_auto_transaction::AutoMode;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Component,
};
use std::{io, path::Path};
const REFUSED: &str = "Administrative AUTO identity transition refused";
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, REFUSED)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ServiceUser {
    Root,
    Aegis,
    AegisSvc,
}
impl ServiceUser {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Aegis => "aegis",
            Self::AegisSvc => "aegis-svc",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimePolicy {
    Root,
    DedicatedNone,
    DedicatedBind,
}
/// Caller supplies only the already-admitted accepted render Settings and mode;
/// integration must bind that render generation to the protected Store first.
pub(crate) fn runtime_policy(
    mode: AutoMode,
    settings: &aegis_core::Settings,
) -> io::Result<RuntimePolicy> {
    match mode {
        AutoMode::FullWideTun => Ok(RuntimePolicy::Root),
        AutoMode::WideRedirectSafe => Ok(RuntimePolicy::DedicatedBind),
        AutoMode::SocksOnly => {
            // The AUTO caller must bind this policy to independently captured
            // and published credentials; the generic planner lacks that authority.
            if settings.relay.inner_tls.is_some() {
                if !matches!(settings.mode, aegis_core::Mode::Relay)
                    || settings.ingress.primary != aegis_core::IngressPrimary::Socks5
                    || crate::profile_auto::validate_auto_relay_auth(settings).is_err()
                {
                    return Err(invalid());
                }
                return Ok(if settings.socks.listen.port() < 1024 {
                    RuntimePolicy::DedicatedBind
                } else {
                    RuntimePolicy::DedicatedNone
                });
            }
            match crate::profile::service_capabilities(settings) {
                None => Ok(RuntimePolicy::Root),
                Some(c) if c.is_empty() => Ok(RuntimePolicy::DedicatedNone),
                Some(c) if c == ["CAP_NET_BIND_SERVICE"] => Ok(RuntimePolicy::DedicatedBind),
                _ => Err(invalid()),
            }
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    user: ServiceUser,
    uid: u32,
    gid: u32,
}
impl Identity {
    pub(crate) fn user(&self) -> ServiceUser {
        self.user
    }
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }
}
/// Sealed phase header stores BOTH roles; serialization alone is not authority.
/// Binding is created from held protected local account files, never UID flags.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeBinding {
    identity: Identity,
    policy: RuntimePolicy,
    passwd: GenerationRecord,
    #[serde(default)]
    passwd_sha256: Option<[u8; 32]>,
    group: GenerationRecord,
    #[serde(default)]
    group_sha256: Option<[u8; 32]>,
    #[serde(default)]
    nsswitch: Option<GenerationRecord>,
    #[serde(default)]
    nsswitch_sha256: Option<[u8; 32]>,
}
impl RuntimeBinding {
    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }
    pub(crate) fn policy(&self) -> RuntimePolicy {
        self.policy
    }
    pub(crate) fn revalidate_local_generation(&self) -> io::Result<()> {
        for (record, digest) in [
            (&self.passwd, self.passwd_sha256.as_ref()),
            (&self.group, self.group_sha256.as_ref()),
        ] {
            let digest = digest.ok_or_else(invalid)?;
            crate::profile_auto_capture::reopen_generation(record)?
                .revalidate_singleton_sha256(digest)?;
        }
        match (self.policy, &self.nsswitch, &self.nsswitch_sha256) {
            (RuntimePolicy::Root, None, None) => {}
            (
                RuntimePolicy::DedicatedNone | RuntimePolicy::DedicatedBind,
                Some(record),
                Some(digest),
            ) => {
                crate::profile_auto_capture::reopen_generation(record)?
                    .revalidate_singleton_sha256(digest)?;
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
/// Local files must resolve the dedicated account first. The stock systemd
/// fallback is admitted only with local account custody and actual process
/// identity checks; it never supplies an alternative UID, GID or group grant.
/// This captured generation is revalidated before publication and activation.
fn local_account_nss(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 1024 * 1024
        || !bytes.is_ascii()
        || bytes
            .iter()
            .any(|b| b.is_ascii_control() && !b"\t\r\n".contains(b))
    {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut passwd = false;
    let mut group = false;
    let mut initgroups = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Continuations can add a provider to the preceding database. Refuse
        // them even if a parser would otherwise see a harmless first line.
        if raw.as_bytes()[0].is_ascii_whitespace() || raw.ends_with('\\') {
            return Err(invalid());
        }
        let (database, providers) = line.split_once(':').ok_or_else(invalid)?;
        let seen = match database.trim() {
            "passwd" => &mut passwd,
            "group" => &mut group,
            "initgroups" => &mut initgroups,
            _ => continue,
        };
        if *seen || database != database.trim() {
            return Err(invalid());
        }
        *seen = true;
        let providers = if let Some((before, _)) = providers.split_once('#') {
            if !before.ends_with(char::is_whitespace) {
                return Err(invalid());
            }
            before
        } else {
            providers
        };
        let tokens: Vec<_> = providers.split_whitespace().collect();
        if tokens != ["files"] && tokens != ["files", "systemd"] {
            return Err(invalid());
        }
    }
    if !passwd || !group {
        return Err(invalid());
    }
    // glibc inherits group for initgroups when no explicit entry exists.
    Ok(())
}
fn tables(passwd: &Path, group: &Path) -> io::Result<(CapturedTree, CapturedTree)> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid());
    }
    let capture = |p: &Path| {
        CapturedTree::capture_file(
            p,
            p.parent().ok_or_else(invalid)?.into(),
            InputRole::AdministratorMetadata {
                administrator_uid: 0,
            },
            CaptureLimits {
                files: 1,
                file_bytes: 1024 * 1024,
                tree_bytes: 1024 * 1024,
                ..Default::default()
            },
        )
    };
    Ok((capture(passwd)?, capture(group)?))
}
fn row(user: ServiceUser, passwd: &[u8], group: &[u8], runtime: bool) -> io::Result<Identity> {
    let mut account = None;
    for line in std::str::from_utf8(passwd).map_err(|_| invalid())?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() != Some(&user.name()) {
            continue;
        }
        if fields.len() != 7 || account.is_some() {
            return Err(invalid());
        }
        let uid = fields[2].parse::<u32>().map_err(|_| invalid())?;
        let gid = fields[3].parse::<u32>().map_err(|_| invalid())?;
        if (user == ServiceUser::Root) != (uid == 0)
            || runtime
                && user != ServiceUser::Root
                && (!(1..1000).contains(&uid) || !(1..1000).contains(&gid))
        {
            return Err(invalid());
        }
        account = Some((uid, gid));
    }
    let (uid, gid) = account.ok_or_else(invalid)?;
    let mut named = None;
    for line in std::str::from_utf8(group).map_err(|_| invalid())?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if runtime
            && user != ServiceUser::Root
            && fields.len() == 4
            && fields[0] != user.name()
            && fields[2].parse::<u32>().map_err(|_| invalid())? == gid
        {
            return Err(invalid());
        }
        if runtime
            && user != ServiceUser::Root
            && fields.len() == 4
            && fields[3].split(',').any(|member| member == user.name())
            && fields[2].parse::<u32>().map_err(|_| invalid())? != gid
        {
            return Err(invalid());
        }
        if fields.first() != Some(&user.name()) {
            continue;
        }
        if fields.len() != 4 || named.is_some() {
            return Err(invalid());
        }
        let value = fields[2].parse::<u32>().map_err(|_| invalid())?;
        if value != gid {
            return Err(invalid());
        }
        if runtime
            && user != ServiceUser::Root
            && fields[3]
                .split(',')
                .any(|member| !member.is_empty() && member != user.name())
        {
            return Err(invalid());
        }
        named = Some(value);
    }
    if named != Some(gid) {
        return Err(invalid());
    }
    if runtime && user != ServiceUser::Root {
        for line in std::str::from_utf8(passwd).map_err(|_| invalid())?.lines() {
            let f: Vec<_> = line.split(':').collect();
            if f.len() == 7 && f[0] != user.name() {
                let other_uid = f[2].parse::<u32>().map_err(|_| invalid())?;
                if other_uid == uid || f[3].parse::<u32>().ok() == Some(gid) && other_uid != 0 {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(Identity { user, uid, gid })
}
/// For the current old service only; system UID narrowing applies to new runtime.
pub(crate) fn resolve_custody_identity(user: ServiceUser) -> io::Result<Identity> {
    let (p, g) = tables(Path::new("/etc/passwd"), Path::new("/etc/group"))?;
    let identity = row(
        user,
        p.bytes(Path::new("passwd"))?,
        g.bytes(Path::new("group"))?,
        false,
    )?;
    p.revalidate_original_generation()?;
    g.revalidate_original_generation()?;
    Ok(identity)
}
fn bind_tables(
    user: ServiceUser,
    policy: RuntimePolicy,
    passwd: &Path,
    group: &Path,
    nsswitch: &Path,
) -> io::Result<RuntimeBinding> {
    if (policy == RuntimePolicy::Root) != (user == ServiceUser::Root) {
        return Err(invalid());
    }
    let (p, g) = tables(passwd, group)?;
    let passwd_bytes = p.bytes(Path::new(passwd.file_name().ok_or_else(invalid)?))?;
    let group_bytes = g.bytes(Path::new(group.file_name().ok_or_else(invalid)?))?;
    let identity = row(user, passwd_bytes, group_bytes, true)?;
    use sha2::Digest;
    let passwd_sha256: [u8; 32] = sha2::Sha256::digest(passwd_bytes).into();
    let group_sha256: [u8; 32] = sha2::Sha256::digest(group_bytes).into();
    let nsswitch = if policy == RuntimePolicy::Root {
        None
    } else {
        let captured = CapturedTree::capture_file(
            nsswitch,
            nsswitch.parent().ok_or_else(invalid)?.into(),
            InputRole::AdministratorMetadata {
                administrator_uid: 0,
            },
            CaptureLimits {
                files: 1,
                file_bytes: 1024 * 1024,
                tree_bytes: 1024 * 1024,
                ..Default::default()
            },
        )?;
        let nss_bytes = captured.bytes(Path::new("nsswitch.conf"))?;
        local_account_nss(nss_bytes)?;
        let digest: [u8; 32] = sha2::Sha256::digest(nss_bytes).into();
        captured.revalidate_original_generation()?;
        Some((captured.export_private_generation()?, digest))
    };
    p.revalidate_original_generation()?;
    g.revalidate_original_generation()?;
    let (nsswitch, nsswitch_sha256) = match nsswitch {
        Some((record, digest)) => (Some(record), Some(digest)),
        None => (None, None),
    };
    Ok(RuntimeBinding {
        identity,
        policy,
        passwd: p.export_private_generation()?,
        passwd_sha256: Some(passwd_sha256),
        group: g.export_private_generation()?,
        group_sha256: Some(group_sha256),
        nsswitch,
        nsswitch_sha256,
    })
}
pub(crate) fn resolve_runtime_binding(
    user: ServiceUser,
    policy: RuntimePolicy,
) -> io::Result<RuntimeBinding> {
    bind_tables(
        user,
        policy,
        Path::new("/etc/passwd"),
        Path::new("/etc/group"),
        Path::new("/etc/nsswitch.conf"),
    )
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigLeafRole {
    ConfigOrPublicReference,
    PrivateRuntimeCredential,
    RetainedAdministratorPrivate,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attributes {
    uid: u32,
    gid: u32,
    mode: u32,
}
#[cfg(test)]
pub(crate) fn config_directory(binding: &RuntimeBinding) -> io::Result<Attributes> {
    binding.revalidate_local_generation()?;
    Ok(Attributes {
        uid: 0,
        gid: binding.identity.gid,
        mode: if binding.policy == RuntimePolicy::Root {
            0o700
        } else {
            0o750
        },
    })
}
#[cfg(test)]
pub(crate) fn config_leaf(
    binding: &RuntimeBinding,
    role: ConfigLeafRole,
) -> io::Result<Attributes> {
    binding.revalidate_local_generation()?;
    Ok(match role {
        ConfigLeafRole::ConfigOrPublicReference => Attributes {
            uid: 0,
            gid: binding.identity.gid,
            mode: if binding.policy == RuntimePolicy::Root {
                0o600
            } else {
                0o640
            },
        },
        ConfigLeafRole::PrivateRuntimeCredential => Attributes {
            uid: binding.identity.uid,
            gid: binding.identity.gid,
            mode: 0o600,
        },
        ConfigLeafRole::RetainedAdministratorPrivate => Attributes {
            uid: 0,
            gid: 0,
            mode: 0o600,
        },
    })
}
#[cfg(test)]
pub(crate) fn state_leaf(binding: &RuntimeBinding) -> io::Result<Attributes> {
    binding.revalidate_local_generation()?;
    Ok(Attributes {
        uid: binding.identity.uid,
        gid: binding.identity.gid,
        mode: 0o600,
    })
}
/// Concrete builder primitive for an UNPUBLISHED root-private held stage only.
/// Root Store must persist the full intent/policy before invoking this primitive.
/// It creates exactly one fresh O_EXCL leaf; existing inodes are never changed.
#[cfg(test)]
pub(crate) fn create_fresh_staged_leaf(
    parent: &File,
    name: &str,
    bytes: &[u8],
    attributes: Attributes,
) -> io::Result<File> {
    if unsafe { libc::geteuid() } != 0 || bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    let path = Path::new(name);
    if name.is_empty()
        || name.len() > 255
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(invalid());
    }
    let before = parent.metadata()?;
    if !before.is_dir() || before.uid() != 0 || before.mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let fresh = file.metadata()?;
    if !fresh.is_file() || fresh.nlink() != 1 || fresh.uid() != 0 || fresh.mode() & 0o777 != 0o600 {
        return Err(invalid());
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    if unsafe { libc::fchown(file.as_raw_fd(), attributes.uid, attributes.gid) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), attributes.mode) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let final_meta = file.metadata()?;
    let after = parent.metadata()?;
    if final_meta.dev() != fresh.dev()
        || final_meta.ino() != fresh.ino()
        || final_meta.nlink() != 1
        || final_meta.uid() != attributes.uid
        || final_meta.gid() != attributes.gid
        || final_meta.mode() & 0o777 != attributes.mode
        || final_meta.len() != bytes.len() as u64
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != 0
        || after.mode() & 0o777 != 0o700
    {
        return Err(invalid());
    }
    file.sync_all()?;
    parent.sync_all()?;
    Ok(file)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auto_socks_device_identity_needs_exclusive_valid_carrier() {
        let source = "mode = 'relay'\n[relay]\nserver = '10.231.80.2:443'\nserver_name = 'relay.aegis.test'\nauth_token = ''\nca_cert = '/srv/bundle/ca.pem'\ntls_backend = 'rustls'\ntransport_priority = ['grpc_stream']\nudp_transport_priority = ['grpc_datagram']\n[relay.inner_tls]\nserver_name = 'origin.aegis.test'\nserver_ca = '/srv/bundle/inner-ca.pem'\ncert = '/srv/bundle/device.pem'\nkey = '/srv/bundle/device.key'\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '127.0.0.1:1080'\n[direct]\npersist_state = false\n";
        let parsed = |text: &str| toml::from_str::<aegis_core::Settings>(text).unwrap();
        let valid = parsed(source);
        assert!(crate::profile::service_capabilities(&valid).is_none());
        assert!(matches!(
            runtime_policy(AutoMode::SocksOnly, &valid),
            Ok(RuntimePolicy::DedicatedNone)
        ));
        let privileged = parsed(&source.replace("127.0.0.1:1080", "127.0.0.1:443"));
        assert!(matches!(
            runtime_policy(AutoMode::SocksOnly, &privileged),
            Ok(RuntimePolicy::DedicatedBind)
        ));
        let port_zero = parsed(&source.replace("127.0.0.1:1080", "127.0.0.1:0"));
        assert!(matches!(
            runtime_policy(AutoMode::SocksOnly, &port_zero),
            Ok(RuntimePolicy::DedicatedBind)
        ));
        for changed in [
            source.replace(
                "auth_token = ''",
                "auth_token = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'",
            ),
            source.replace(
                "transport_priority = ['grpc_stream']",
                "transport_priority = ['legacy_tls']",
            ),
            source.replace("mode = 'relay'", "mode = 'direct'"),
            source.replace("primary = 'socks5'", "primary = 'wide'"),
        ] {
            assert!(runtime_policy(AutoMode::SocksOnly, &parsed(&changed)).is_err());
        }
        assert!(matches!(
            runtime_policy(AutoMode::FullWideTun, &valid),
            Ok(RuntimePolicy::Root)
        ));
        assert!(matches!(
            runtime_policy(AutoMode::WideRedirectSafe, &valid),
            Ok(RuntimePolicy::DedicatedBind)
        ));
        let legacy = source
            .replace("auth_token = ''", "auth_token = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'")
            .replace("[relay.inner_tls]\nserver_name = 'origin.aegis.test'\nserver_ca = '/srv/bundle/inner-ca.pem'\ncert = '/srv/bundle/device.pem'\nkey = '/srv/bundle/device.key'\n", "");
        assert!(matches!(
            runtime_policy(AutoMode::SocksOnly, &parsed(&legacy)),
            Ok(RuntimePolicy::DedicatedNone)
        ));
    }
    #[test]
    fn dedicated_nss_rejects_external_or_ambiguous_initgroups() {
        for good in [
            "passwd: files\ngroup: files\n",
            "passwd: files\ngroup: files\ninitgroups: files\n",
            "passwd: files systemd\ngroup: files systemd\n",
            "passwd: files systemd\ngroup: files\ninitgroups: files systemd\n",
            "passwd:\tfiles systemd # stock fallback\ngroup: files # local\n",
        ] {
            assert!(local_account_nss(good.as_bytes()).is_ok(), "{good}");
        }
        for bad in [
            "passwd: systemd files\ngroup: files\n",
            "passwd: files systemd systemd\ngroup: files\n",
            "passwd: files [SUCCESS=continue] systemd\ngroup: files\n",
            "passwd: files\ngroup: systemd\n",
            "passwd: files\ngroup: files sss\n",
            "passwd: files\ngroup: files#sss\n",
            "passwd: files systemd#comment\ngroup: files\n",
            "passwd: files systemd sss\ngroup: files\n",
            "passwd: files\npasswd : files systemd\ngroup: files\n",
            "passwd: files\ngroup: files\ninitgroups: ldap\n",
            "passwd: files\ngroup: files\ninitgroups: files [SUCCESS=return]\n",
            "passwd: files\ngroup: files\ninitgroups: files\ninitgroups: files\n",
            "passwd: files\ngroup: files\\\n ldap\n",
            "passwd: files\ngroup: files\n ldap\n",
            "passwd: files\ngroup: files\n# nonascii é\n",
            "passwd: files\ngroup: files\0\n",
            "passwd: files\ngroup: files\u{b}systemd\n",
            "passwd: files\n",
        ] {
            assert!(local_account_nss(bad.as_bytes()).is_err(), "{bad}");
        }
    }
    #[test]
    fn local_account_roles_and_named_group_are_not_arbitrary_uid_flags() {
        let passwd=b"root:x:0:0:root:/root:/bin/sh\naegis:x:1000:1000:old:/none:/bin/false\naegis-svc:x:997:997:new:/none:/bin/false\n";
        let groups = b"root:x:0:\naegis:x:1000:\naegis-svc:x:997:\n";
        assert_eq!(
            row(ServiceUser::Aegis, passwd, groups, false)
                .unwrap()
                .uid(),
            1000
        );
        assert!(row(ServiceUser::Aegis, passwd, groups, true).is_err());
        assert_eq!(
            row(ServiceUser::AegisSvc, passwd, groups, true)
                .unwrap()
                .uid(),
            997
        );
        assert!(row(ServiceUser::AegisSvc, passwd, b"aegis-svc:x:998:\n", true).is_err());
        assert!(row(
            ServiceUser::AegisSvc,
            passwd,
            b"aegis-svc:x:997:unrelated\n",
            true
        )
        .is_err());
        assert!(row(
            ServiceUser::AegisSvc,
            passwd,
            b"aegis-svc:x:997:\naegis-svc:x:997:\n",
            true
        )
        .is_err());
        for gid in [0, 1000, u32::MAX] {
            let passwd = format!(
                "root:x:0:0:root:/root:/bin/sh\naegis-svc:x:997:{gid}:new:/none:/bin/false\n"
            );
            let groups = format!("root:x:0:\naegis-svc:x:{gid}:\n");
            assert!(row(
                ServiceUser::AegisSvc,
                passwd.as_bytes(),
                groups.as_bytes(),
                true
            )
            .is_err());
            assert!(row(
                ServiceUser::AegisSvc,
                passwd.as_bytes(),
                groups.as_bytes(),
                false
            )
            .is_ok());
        }
    }
    #[test]
    fn dedicated_runtime_rejects_foreign_supplementary_groups() {
        let passwd = b"root:x:0:0:root:/root:/bin/sh\naegis-svc:x:997:997:new:/none:/bin/false\n";
        let base = "root:x:0:\naegis-svc:x:997:\n";
        assert!(row(ServiceUser::AegisSvc, passwd, base.as_bytes(), true).is_ok());
        for foreign in [
            "sudo:x:27:aegis-svc\n",
            "docker:x:998:other,aegis-svc\n",
            "root:x:0:aegis-svc\n",
        ] {
            let groups = format!("{base}{foreign}");
            assert!(row(ServiceUser::AegisSvc, passwd, groups.as_bytes(), true).is_err());
            // Historical custody preserves the selected old account; it never
            // grants the newly constrained dedicated runtime identity.
            assert!(row(ServiceUser::AegisSvc, passwd, groups.as_bytes(), false).is_ok());
        }
    }
    #[test]
    fn dedicated_runtime_rejects_local_uid_and_gid_aliases() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\naegis-svc:x:997:997:new:/none:/bin/false\n";
        let group = "root:x:0:\naegis-svc:x:997:\n";
        for alias in [
            "other:x:997:998:alias:/none:/bin/false\n",
            "other:x:998:997:shared group:/none:/bin/false\n",
        ] {
            let changed = format!("{passwd}{alias}");
            assert!(row(
                ServiceUser::AegisSvc,
                changed.as_bytes(),
                group.as_bytes(),
                true
            )
            .is_err());
            assert!(row(
                ServiceUser::AegisSvc,
                changed.as_bytes(),
                group.as_bytes(),
                false
            )
            .is_ok());
        }
        let changed = format!("{group}other:x:997:\n");
        assert!(row(
            ServiceUser::AegisSvc,
            passwd.as_bytes(),
            changed.as_bytes(),
            true
        )
        .is_err());
        assert!(row(
            ServiceUser::AegisSvc,
            passwd.as_bytes(),
            changed.as_bytes(),
            false
        )
        .is_ok());
    }
    #[test]
    fn actual_protected_account_generation_and_fresh_leaf_attributes_preserve_existing_inode() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::{fs, os::unix::fs::PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let passwd = d.path().join("passwd");
        let groups = d.path().join("group");
        let nsswitch = d.path().join("nsswitch.conf");
        fs::write(
            &passwd,
            b"root:x:0:0:r:/root:/bin/sh\naegis-svc:x:997:997:n:/none:/bin/false\n",
        )
        .unwrap();
        fs::write(&groups, b"root:x:0:\naegis-svc:x:997:\n").unwrap();
        fs::write(&nsswitch, b"passwd: files\ngroup: files\n").unwrap();
        for p in [&passwd, &groups, &nsswitch] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let binding = bind_tables(
            ServiceUser::AegisSvc,
            RuntimePolicy::DedicatedNone,
            &passwd,
            &groups,
            &nsswitch,
        )
        .unwrap();
        assert_eq!(binding.identity().uid(), 997);
        assert_eq!(binding.identity().gid(), 997);
        assert!(
            config_directory(&binding).unwrap()
                == Attributes {
                    uid: 0,
                    gid: 997,
                    mode: 0o750
                }
        );
        assert!(
            config_leaf(&binding, ConfigLeafRole::RetainedAdministratorPrivate).unwrap()
                == Attributes {
                    uid: 0,
                    gid: 0,
                    mode: 0o600
                }
        );
        let held = File::open(d.path()).unwrap();
        let public = create_fresh_staged_leaf(
            &held,
            "config.toml",
            b"synthetic settings",
            config_leaf(&binding, ConfigLeafRole::ConfigOrPublicReference).unwrap(),
        )
        .unwrap();
        let pm = public.metadata().unwrap();
        assert_eq!((pm.uid(), pm.gid(), pm.mode() & 0o777), (0, 997, 0o640));
        let secret = create_fresh_staged_leaf(
            &held,
            "identity.key",
            b"synthetic private fixture",
            config_leaf(&binding, ConfigLeafRole::PrivateRuntimeCredential).unwrap(),
        )
        .unwrap();
        let sm = secret.metadata().unwrap();
        assert_eq!((sm.uid(), sm.gid(), sm.mode() & 0o777), (997, 997, 0o600));
        let victim = d.path().join("existing");
        fs::write(&victim, b"retained unrelated").unwrap();
        let before = fs::metadata(&victim).unwrap();
        assert!(create_fresh_staged_leaf(
            &held,
            "existing",
            b"replacement",
            state_leaf(&binding).unwrap()
        )
        .is_err());
        let after = fs::metadata(&victim).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode()
            ),
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode()
            )
        );
        assert_eq!(fs::read(&victim).unwrap(), b"retained unrelated");
        fs::write(&groups, b"root:x:0:\naegis-svc:x:998:\n").unwrap();
        assert!(binding.revalidate_local_generation().is_err());
        assert!(config_leaf(&binding, ConfigLeafRole::PrivateRuntimeCredential).is_err());
        fs::write(&groups, b"root:x:0:\naegis-svc:x:997:\n").unwrap();
        fs::write(&nsswitch, b"passwd: files\ngroup: files sss\n").unwrap();
        assert!(binding.revalidate_local_generation().is_err());
    }

    #[test]
    fn sealed_account_content_rejects_same_length_rewrite_even_with_fresh_metadata_record() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::{fs, os::unix::fs::PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let passwd = d.path().join("passwd");
        let group = d.path().join("group");
        let nsswitch = d.path().join("nsswitch.conf");
        let original = [
            b"root:x:0:0:r:/root:/bin/sh\naegis-svc:x:997:997:n:/none:/bin/false\n".as_slice(),
            b"root:x:0:\naegis-svc:x:997:\n".as_slice(),
            b"passwd: files\ngroup: files\n".as_slice(),
        ];
        let changed = [
            b"root:x:0:0:r:/root:/bin/sh\naegis-svc:x:997:997:m:/none:/bin/false\n".as_slice(),
            b"root:x:0:\naegis-svc:x:998:\n".as_slice(),
            b"passwd: filex\ngroup: files\n".as_slice(),
        ];
        for (path, bytes) in [
            (&passwd, original[0]),
            (&group, original[1]),
            (&nsswitch, original[2]),
        ] {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        for (index, path) in [&passwd, &group, &nsswitch].into_iter().enumerate() {
            let mut binding = bind_tables(
                ServiceUser::AegisSvc,
                RuntimePolicy::DedicatedNone,
                &passwd,
                &group,
                &nsswitch,
            )
            .unwrap();
            let encoded = serde_json::to_value(&binding).unwrap();
            let mut legacy = encoded.clone();
            for key in ["passwd_sha256", "group_sha256", "nsswitch_sha256"] {
                legacy.as_object_mut().unwrap().remove(key);
            }
            // A pre-upgrade sealed Header can still decode this binding for
            // recovery inspection. No policy operation may use it as fresh.
            let legacy_binding: RuntimeBinding = serde_json::from_value(legacy).unwrap();
            assert_eq!(legacy_binding.identity().uid(), binding.identity().uid());
            assert_eq!(legacy_binding.identity().gid(), binding.identity().gid());
            assert!(legacy_binding.revalidate_local_generation().is_err());
            let mut missing = encoded.clone();
            missing.as_object_mut().unwrap().remove(match index {
                0 => "passwd_sha256",
                1 => "group_sha256",
                _ => "nsswitch_sha256",
            });
            // Old sealed headers remain decodable for read-only recovery, but
            // any policy use is refused until a new binding is captured.
            assert!(serde_json::from_value::<RuntimeBinding>(missing)
                .unwrap()
                .revalidate_local_generation()
                .is_err());
            assert_eq!(original[index].len(), changed[index].len());
            fs::write(path, changed[index]).unwrap();
            let fresh = CapturedTree::capture_file(
                path,
                path.parent().unwrap().into(),
                InputRole::AdministratorMetadata {
                    administrator_uid: 0,
                },
                CaptureLimits {
                    files: 1,
                    file_bytes: 1024 * 1024,
                    tree_bytes: 1024 * 1024,
                    ..Default::default()
                },
            )
            .unwrap()
            .export_private_generation()
            .unwrap();
            match index {
                0 => binding.passwd = fresh,
                1 => binding.group = fresh,
                _ => binding.nsswitch = Some(fresh),
            }
            // Metadata-only revalidation now accepts its fresh record. The
            // sealed original content digest must still reject the changed bytes.
            let fresh_record = match index {
                0 => &binding.passwd,
                1 => &binding.group,
                _ => binding.nsswitch.as_ref().unwrap(),
            };
            crate::profile_auto_capture::reopen_generation(fresh_record)
                .unwrap()
                .revalidate()
                .unwrap();
            assert!(binding.revalidate_local_generation().is_err());
            fs::write(path, original[index]).unwrap();
        }
    }
}
