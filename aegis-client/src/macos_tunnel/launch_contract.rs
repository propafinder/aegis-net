//! Read-only admission of a caller-supplied trusted account inventory and
//! minimum on-disk custody shape. This does not verify OS account provenance,
//! the public profile's contents, authenticated policy ACK or worker readiness.
//! There is deliberately no spawn/PF/capture-ready operation in this unit.
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

#[derive(Clone, Debug)]
pub(crate) struct AccountRecord {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub non_login: bool,
}
pub(crate) struct LaunchAdmission {
    uid: u32,
    gid: u32,
}
impl LaunchAdmission {
    pub fn from_inventory(records: &[AccountRecord], name: &str) -> io::Result<Self> {
        if records.is_empty()
            || records.len() > 4096
            || records.iter().any(|r| {
                r.name.is_empty()
                    || r.name.len() > 64
                    || !r
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            })
            || !name.starts_with("_aegis_")
            || name.len() <= 7
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(rejected());
        }
        let mut matches = records.iter().filter(|record| record.name == name);
        let record = matches.next().ok_or_else(rejected)?;
        if matches.next().is_some()
            || !record.non_login
            || [0, 65534, u32::MAX - 1, u32::MAX].contains(&record.uid)
            || [0, 65534, u32::MAX - 1, u32::MAX].contains(&record.gid)
            || records.iter().filter(|r| r.uid == record.uid).count() != 1
            || records.iter().filter(|r| r.gid == record.gid).count() != 1
        {
            return Err(rejected());
        }
        Ok(Self {
            uid: record.uid,
            gid: record.gid,
        })
    }
    pub fn ids(&self) -> (u32, u32) {
        (self.uid, self.gid)
    }
    /// Metadata only: never opens or exports private key/certificate contents.
    /// Actual worker must still use unchanged owner==euid identity readers.
    pub fn validate_custody(&self, identity: &Path, public_profile: &Path) -> io::Result<()> {
        clean_absolute(identity)?;
        clean_absolute(public_profile)?;
        if identity.starts_with(public_profile) || public_profile.starts_with(identity) {
            return Err(rejected());
        }
        for (path, private) in [
            (identity, true),
            (public_profile.parent().ok_or_else(rejected)?, false),
        ] {
            for ancestor in path.ancestors() {
                let metadata = fs::symlink_metadata(ancestor)?;
                if !metadata.is_dir()
                    || !trusted_ancestor(metadata.uid(), metadata.mode(), self.uid, private)
                {
                    return Err(rejected());
                }
            }
        }
        let directory = fs::symlink_metadata(identity)?;
        if directory.uid() != self.uid || directory.mode() & 0o077 != 0 {
            return Err(rejected());
        }
        for name in ["device.key", "device.pem", "identity.json"] {
            let metadata = fs::symlink_metadata(identity.join(name))?;
            validate_facts(FileFacts::from(&metadata), self.uid, true)?;
        }
        validate_facts(
            FileFacts::from(&fs::symlink_metadata(public_profile)?),
            0,
            false,
        )
    }
}
fn clean_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(rejected());
    }
    Ok(())
}
fn trusted_ancestor(uid: u32, mode: u32, worker: u32, private: bool) -> bool {
    // A root-owned public file inside a worker-writable directory can be
    // replaced by that worker. Public profile ancestry must remain root-owned.
    (uid == 0 || private && uid == worker) && mode & 0o022 == 0
}
struct FileFacts {
    regular: bool,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
}
impl From<&fs::Metadata> for FileFacts {
    fn from(m: &fs::Metadata) -> Self {
        Self {
            regular: m.is_file(),
            uid: m.uid(),
            mode: m.mode(),
            links: m.nlink(),
            bytes: m.len(),
        }
    }
}
fn validate_facts(f: FileFacts, uid: u32, private: bool) -> io::Result<()> {
    if !f.regular
        || f.uid != uid
        || f.links != 1
        || f.bytes == 0
        || f.bytes > 1024 * 1024
        || f.mode & if private { 0o077 } else { 0o022 } != 0
    {
        return Err(rejected());
    }
    Ok(())
}
fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "worker launch/custody admission rejected",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn account() -> AccountRecord {
        AccountRecord {
            name: "_aegis_network".into(),
            uid: 601,
            gid: 601,
            non_login: true,
        }
    }
    #[test]
    fn dedicated_inventory_contract_refuses_root_unknown_generic_login_and_shared_ids() {
        let good = account();
        assert_eq!(
            LaunchAdmission::from_inventory(std::slice::from_ref(&good), &good.name)
                .unwrap()
                .ids(),
            (601, 601)
        );
        assert!(LaunchAdmission::from_inventory(&[], &good.name).is_err());
        assert!(
            LaunchAdmission::from_inventory(std::slice::from_ref(&good), "_aegis_unknown").is_err()
        );
        for generic in [0, 65534, u32::MAX - 1, u32::MAX] {
            let mut a = account();
            a.uid = generic;
            assert!(LaunchAdmission::from_inventory(&[a], &good.name).is_err());
            let mut a = account();
            a.gid = generic;
            assert!(LaunchAdmission::from_inventory(&[a], &good.name).is_err());
        }
        let mut login = account();
        login.non_login = false;
        assert!(LaunchAdmission::from_inventory(&[login], &good.name).is_err());
        for same_uid in [true, false] {
            let mut other = account();
            other.name = "unrelated".into();
            if same_uid {
                other.gid = 602;
            } else {
                other.uid = 602;
            }
            assert!(LaunchAdmission::from_inventory(&[good.clone(), other], &good.name).is_err());
        }
        assert!(
            LaunchAdmission::from_inventory(&[good.clone(), good.clone()], &good.name).is_err()
        );
        assert!(LaunchAdmission::from_inventory(&vec![good.clone(); 4097], &good.name).is_err());
        assert!(LaunchAdmission::from_inventory(&[good], "nobody").is_err());
    }
    fn private() -> FileFacts {
        FileFacts {
            regular: true,
            uid: 601,
            mode: 0o600,
            links: 1,
            bytes: 64,
        }
    }
    #[test]
    fn custody_facts_require_exact_private_owner_permissions_regular_single_link_and_bounds() {
        assert!(validate_facts(private(), 601, true).is_ok());
        for mutation in 0..7 {
            let mut f = private();
            match mutation {
                0 => f.uid = 0,
                1 => f.mode = 0o640,
                2 => f.regular = false,
                3 => f.links = 2,
                4 => f.bytes = 1024 * 1024 + 1,
                5 => f.bytes = 0,
                _ => f.mode = 0o666,
            }
            assert!(validate_facts(f, 601, true).is_err());
        }
        let mut public = private();
        public.uid = 0;
        public.mode = 0o644;
        assert!(validate_facts(public, 0, false).is_ok());
        let mut writable = private();
        writable.uid = 0;
        writable.mode = 0o664;
        assert!(validate_facts(writable, 0, false).is_err());
    }
    #[test]
    fn public_profile_ancestry_cannot_be_replaced_by_the_worker_or_other_users() {
        assert!(trusted_ancestor(0, 0o755, 601, false));
        assert!(!trusted_ancestor(601, 0o700, 601, false));
        assert!(trusted_ancestor(601, 0o700, 601, true));
        assert!(!trusted_ancestor(602, 0o700, 601, true));
        assert!(!trusted_ancestor(0, 0o777, 601, false));
        assert!(!trusted_ancestor(0, 0o1777, 601, true));
    }
    #[test]
    fn actual_custody_paths_refuse_aliases_overlap_and_untrusted_ancestry_without_reading_keys() {
        let admission = LaunchAdmission::from_inventory(&[account()], "_aegis_network").unwrap();
        for path in ["relative", "/var/db/../tmp/identity"] {
            assert!(admission
                .validate_custody(Path::new(path), Path::new("/var/db/profile.toml"))
                .is_err());
        }
        assert!(admission
            .validate_custody(
                Path::new("/var/db/identity"),
                Path::new("/var/db/identity/profile.toml")
            )
            .is_err());
        let directory = tempfile::tempdir().unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(directory.path(), &alias).unwrap();
        assert!(admission
            .validate_custody(&alias, &directory.path().join("profile.toml"))
            .is_err());
    }
}
