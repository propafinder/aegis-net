//! Pure install payload planning; no filesystem, service, driver or native calls.
use std::collections::BTreeMap;

pub(crate) const PROJECT_LICENSE_NAMES: &[&str] = &["LICENSE-APACHE", "LICENSE-MIT", "NOTICE"];
const CLIENT_BINARIES: &[&str] = &["aegis-client.exe", "aegis-winctl.exe"];
const TUNNEL_BINARIES: &[&str] = &[
    "aegis-client.exe",
    "aegis-winctl.exe",
    "wintun.dll",
    "WINTUN-LICENSE.txt",
];

pub(crate) struct InstallPayloadPlan {
    pub(crate) binary_names: &'static [&'static str],
    pub(crate) license_names: &'static [&'static str],
}

pub(crate) fn plan<T>(
    system_tunnel: bool,
    project_licenses: bool,
    verified_files: &BTreeMap<String, T>,
) -> Result<InstallPayloadPlan, &'static str> {
    let binary_names = if system_tunnel {
        TUNNEL_BINARIES
    } else {
        CLIENT_BINARIES
    };
    if binary_names
        .iter()
        .any(|name| !verified_files.contains_key(*name))
    {
        return Err("installed binary payload is incomplete");
    }
    let count = PROJECT_LICENSE_NAMES
        .iter()
        .filter(|name| verified_files.contains_key(**name))
        .count();
    let license_names = match (project_licenses, count) {
        (false, 0) => &[][..],
        (true, 3) => PROJECT_LICENSE_NAMES,
        _ => return Err("installed project-license declaration and payload disagree"),
    };
    Ok(InstallPayloadPlan {
        binary_names,
        license_names,
    })
}

pub(crate) fn validate_license_receipt(
    files: &BTreeMap<String, String>,
) -> Result<(), &'static str> {
    if files.is_empty() {
        return Ok(());
    }
    if files.keys().map(String::as_str).collect::<Vec<_>>() != PROJECT_LICENSE_NAMES {
        return Err("installed project-license receipt leaf set rejected");
    }
    if files.values().any(|hash| {
        hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err("installed project-license receipt digest rejected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binaries() -> BTreeMap<String, ()> {
        TUNNEL_BINARIES
            .iter()
            .map(|name| (name.to_string(), ()))
            .collect()
    }
    #[test]
    fn legacy_and_licensed_plans_preserve_executable_members() {
        let mut files = binaries();
        for system_tunnel in [false, true] {
            let expected = if system_tunnel {
                TUNNEL_BINARIES
            } else {
                CLIENT_BINARIES
            };
            let legacy = plan(system_tunnel, false, &files).unwrap();
            assert_eq!(legacy.binary_names, expected);
            assert!(legacy.license_names.is_empty());
        }
        assert!(
            plan(false, true, &files).is_err(),
            "true flag requires all three licenses"
        );
        for name in PROJECT_LICENSE_NAMES {
            files.insert(name.to_string(), ());
        }
        assert!(
            plan(false, false, &files).is_err(),
            "legacy false flag refuses license extras"
        );
        for system_tunnel in [false, true] {
            let licensed = plan(system_tunnel, true, &files).unwrap();
            assert_eq!(
                licensed.binary_names,
                if system_tunnel {
                    TUNNEL_BINARIES
                } else {
                    CLIENT_BINARIES
                }
            );
            assert_eq!(licensed.license_names, PROJECT_LICENSE_NAMES);
            assert!(licensed
                .binary_names
                .iter()
                .all(|name| !PROJECT_LICENSE_NAMES.contains(name)));
        }
    }
    #[test]
    fn every_partial_license_set_and_missing_executable_refuses() {
        for mask in 1u8..7 {
            let mut files = binaries();
            for (index, name) in PROJECT_LICENSE_NAMES.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    files.insert(name.to_string(), ());
                }
            }
            assert!(plan(false, false, &files).is_err());
            assert!(plan(false, true, &files).is_err());
            assert!(plan(true, true, &files).is_err());
        }
        let mut files = binaries();
        files.remove("wintun.dll");
        assert!(plan(false, false, &files).is_ok());
        assert!(plan(true, false, &files).is_err());
    }
    #[test]
    fn license_receipt_refuses_partial_extra_traversal_and_bad_digests() {
        let complete: BTreeMap<_, _> = PROJECT_LICENSE_NAMES
            .iter()
            .map(|name| (name.to_string(), "a".repeat(64)))
            .collect();
        assert!(validate_license_receipt(&BTreeMap::new()).is_ok());
        assert!(validate_license_receipt(&complete).is_ok());
        for name in PROJECT_LICENSE_NAMES {
            let mut missing = complete.clone();
            missing.remove(*name);
            assert!(validate_license_receipt(&missing).is_err());
        }
        for name in ["extra.txt", "../NOTICE", "aegis-client.exe"] {
            let mut extra = complete.clone();
            extra.insert(name.into(), "a".repeat(64));
            assert!(validate_license_receipt(&extra).is_err());
        }
        for hash in [
            "A".repeat(64),
            "g".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            String::new(),
        ] {
            let mut bad = complete.clone();
            bad.insert("NOTICE".into(), hash);
            assert!(validate_license_receipt(&bad).is_err());
        }
    }
}
