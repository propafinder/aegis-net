//! Operator-only, read-only snapshot classification. Never proves revocation:
//! consumption and operator revocation share the same stored marker.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_STORE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_QUERIES: usize = 64;
const STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Keep digests private: this type intentionally implements neither Debug nor Serialize.
pub struct StatusQuery {
    pub opaque_id: String,
    pub digest: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    ActiveByStore,
    Expired,
    ConsumedOrRevoked,
    AbsentAtObservation,
    Unknown,
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub opaque_id: String,
    pub status: Status,
    pub observed_unix_secs: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    #[serde(deserialize_with = "unique_records")]
    tokens: BTreeMap<String, Record>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    bundle_path: String,
    issued_at: u64,
    expires_at: u64,
    #[serde(default)]
    consumed_at: Option<u64>,
    #[serde(default)]
    comment: Option<String>,
}
fn unique_records<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, Record>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, Record>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique token records")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut records = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, Record>()? {
                if records.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate record"));
                }
            }
            Ok(records)
        }
    }
    d.deserialize_map(Visitor)
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Invalid query batches return a constant error without echoing inputs.
/// Store, platform, clock or parsing failures return UNKNOWN for every query.
/// Caller must bind this snapshot to the actual deployed store independently.
pub fn observe(
    path: &Path,
    expected_owner: u32,
    queries: &[StatusQuery],
) -> Result<Vec<Observation>, &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap_or(0);
    observe_at(path, expected_owner, queries, now)
}
fn observe_at(
    path: &Path,
    owner: u32,
    queries: &[StatusQuery],
    now: u64,
) -> Result<Vec<Observation>, &'static str> {
    let mut ids = BTreeSet::new();
    if queries.is_empty()
        || queries.len() > MAX_QUERIES
        || queries.iter().any(|q| {
            q.opaque_id.is_empty()
                || q.opaque_id.len() > 32
                || !q
                    .opaque_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !digest_valid(&q.digest)
                || !ids.insert(&q.opaque_id)
        })
    {
        return Err("invalid status query batch");
    }
    let snapshot = (1_577_836_800..=4_102_444_800)
        .contains(&now)
        .then(|| read_snapshot(path, owner))
        .flatten();
    Ok(queries
        .iter()
        .map(|q| Observation {
            opaque_id: q.opaque_id.clone(),
            observed_unix_secs: now,
            status: match snapshot.as_ref() {
                None => Status::Unknown,
                Some(s) => match s.tokens.get(&q.digest) {
                    None => Status::AbsentAtObservation,
                    Some(r) if r.consumed_at.is_some() => Status::ConsumedOrRevoked,
                    Some(r) if r.expires_at <= now => Status::Expired,
                    Some(_) => Status::ActiveByStore,
                },
            },
        })
        .collect())
}
fn read_snapshot(path: &Path, owner: u32) -> Option<Snapshot> {
    // Use the same stable sidecar inode as issue/revoke/redeem. The reader
    // opens it without following symlinks and never creates or changes it.
    // A missing, untrusted or contended lock leaves status UNKNOWN.
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_file = open_private(Path::new(&lock_path), owner)?;
    let started = Instant::now();
    loop {
        match lock_file.try_lock_shared() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                let remaining = STORE_LOCK_TIMEOUT.checked_sub(started.elapsed())?;
                if remaining.is_zero() {
                    return None;
                }
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
            Err(std::fs::TryLockError::Error(_)) => return None,
        }
    }
    let file = open_private(path, owner)?;
    let mut bytes = Vec::new();
    file.take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return None;
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).ok()?;
    if snapshot.schema != crate::bundle_tokens::BUNDLE_TOKEN_STORE_SCHEMA
        || snapshot.tokens.iter().any(|(key, r)| {
            !digest_valid(key)
                || r.issued_at > r.expires_at
                || r.consumed_at.is_some_and(|t| t < r.issued_at)
                || r.bundle_path.is_empty()
                || r.comment.as_ref().is_some_and(|s| s.len() > 4096)
        })
    {
        return None;
    }
    Some(snapshot)
}
#[cfg(unix)]
fn open_private(path: &Path, owner: u32) -> Option<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    use std::path::Component;
    if !path.is_absolute() {
        return None;
    }
    let parts: Vec<_> = path.components().collect();
    if parts.len() < 2
        || parts
            .iter()
            .skip(1)
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return None;
    }
    let root = std::ffi::CString::new("/").ok()?;
    // Owned descriptors close on every error; openat binds each traversal to its parent inode.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut current = unsafe { std::fs::File::from_raw_fd(fd) };
    let euid = unsafe { libc::geteuid() };
    for (i, component) in parts.iter().enumerate().skip(1) {
        let parent = current.metadata().ok()?;
        if !parent.is_dir()
            || ![0, owner, euid].contains(&parent.uid())
            || parent.mode() & 0o022 != 0
        {
            return None;
        }
        let name = std::ffi::CString::new(component.as_os_str().as_bytes()).ok()?;
        let final_part = i + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if final_part { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return None;
        }
        current = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    let metadata = current.metadata().ok()?;
    (metadata.is_file()
        && metadata.uid() == owner
        && matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
        && metadata.len() <= MAX_STORE_BYTES
        && metadata.nlink() == 1)
        .then_some(current)
}
#[cfg(not(unix))]
fn open_private(_path: &Path, _owner: u32) -> Option<std::fs::File> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture(contents: &str) -> (tempfile::TempDir, std::path::PathBuf, u32) {
        // Cargo exposes module paths relative to the crate; an absolute #[path]
        // test harness exposes the same source with an absolute file!() value.
        // Both must place the fixture below the trusted workspace, not /tmp's
        // world-writable ancestor rejected by the read-only opener.
        let source = Path::new(file!());
        let workspace = if source.is_absolute() {
            source.parent().unwrap().parent().unwrap().parent().unwrap()
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
        };
        let dir = tempfile::tempdir_in(workspace).unwrap();
        let path = dir.path().join("store.json");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let lock_path = path.with_extension("json.lock");
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (dir, path, unsafe { libc::geteuid() })
    }
    fn query() -> Vec<StatusQuery> {
        vec![StatusQuery {
            opaque_id: "incident-1".into(),
            digest: "a".repeat(64),
        }]
    }
    fn store(expiry: u64, consumed: &str) -> String {
        format!(
            r#"{{"schema":"aegis_bundle_token_store_v1","tokens":{{"{}":{{"bundle_path":"/private/archive","issued_at":1600000000,"expires_at":{expiry},"consumed_at":{consumed}}}}}}}"#,
            "a".repeat(64)
        )
    }
    #[test]
    fn states_and_output_do_not_disclose_store_or_digest() {
        for (expiry, consumed, expected) in [
            (1900000000, "null", Status::ActiveByStore),
            (1700000000, "null", Status::Expired),
            (1700000000, "1650000000", Status::ConsumedOrRevoked),
        ] {
            let (_d, p, u) = fixture(&store(expiry, consumed));
            let results = observe_at(&p, u, &query(), 1800000000).unwrap();
            assert_eq!(results[0].status, expected);
            let text = serde_json::to_string(&results).unwrap();
            assert!(
                !text.contains(&"a".repeat(64))
                    && !text.contains("archive")
                    && !text.contains("store.json")
            );
        }
        let (_d, p, u) = fixture(r#"{"schema":"aegis_bundle_token_store_v1","tokens":{}}"#);
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::AbsentAtObservation
        );
    }
    #[test]
    fn unsafe_or_malformed_store_is_unknown_and_unchanged() {
        for text in [
            "broken".to_owned(),
            store(1500000000, "null"),
            store(1900000000, "1"),
            store(1900000000, "null").replace("_v1", "_v2"),
        ] {
            let (_d, p, u) = fixture(&text);
            assert_eq!(
                observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
                Status::Unknown
            );
            assert_eq!(std::fs::read_to_string(p).unwrap(), text);
        }
        let (_d, p, u) = fixture(&store(1900000000, "null"));
        assert_eq!(
            observe_at(&p, u.wrapping_add(1), &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        assert!(std::fs::metadata(p.with_extension("json.lock")).is_ok());
    }
    #[test]
    fn symlinks_hardlinks_size_and_bad_queries_fail_closed() {
        let (d, p, u) = fixture(&store(1900000000, "null"));
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&p, &alias).unwrap();
        assert_eq!(
            observe_at(&alias, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::remove_file(&alias).unwrap();
        std::fs::hard_link(&p, &alias).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::remove_file(&alias).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(MAX_STORE_BYTES + 1)
            .unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        let mut bad = query();
        bad[0].opaque_id = "a".repeat(64);
        assert!(observe_at(&p, u, &bad, 1800000000).is_err());
        assert_eq!(
            observe_at(&p, u, &query(), 0).unwrap()[0].status,
            Status::Unknown
        );
    }
    #[test]
    fn unsafe_parent_and_symlinked_parent_are_unknown() {
        let (d, p, u) = fixture(&store(1900000000, "null"));
        let alias = d.path().join("parent-alias");
        std::os::unix::fs::symlink(d.path(), &alias).unwrap();
        assert_eq!(
            observe_at(&alias.join("store.json"), u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            observe_at(&d.path().join("missing"), u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
    }
    #[test]
    fn unknown_fields_and_duplicate_queries_are_rejected() {
        let text = store(1900000000, "null").replacen(
            "\"issued_at\":",
            "\"unexpected\":1,\"issued_at\":",
            1,
        );
        let (_d, p, u) = fixture(&text);
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        let mut batch = query();
        batch.extend(query());
        assert!(observe_at(&p, u, &batch, 1800000000).is_err());
        let mut bad = query();
        bad[0].digest = "A".repeat(64);
        assert!(observe_at(&p, u, &bad, 1800000000).is_err());
        assert!(observe_at(&p, u, &[], 1800000000).is_err());
    }
    #[test]
    fn duplicate_record_is_unknown() {
        let text = store(1900000000, "null");
        let record = format!(
            r#""{}":{{"bundle_path":"/x","issued_at":1600000000,"expires_at":1900000000}}"#,
            "a".repeat(64)
        );
        let duplicate = text.replacen("\"tokens\":{", &format!("\"tokens\":{{{record},"), 1);
        let (_d, p, u) = fixture(&duplicate);
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
    }

    #[test]
    fn missing_or_busy_transaction_lock_is_unknown() {
        let (_d, p, u) = fixture(&store(1900000000, "null"));
        let lock_path = p.with_extension("json.lock");
        std::fs::remove_file(&lock_path).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        held.lock().unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        held.unlock().unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::ActiveByStore
        );
    }

    #[test]
    fn untrusted_transaction_lock_is_unknown() {
        let (d, p, u) = fixture(&store(1900000000, "null"));
        let lock_path = p.with_extension("json.lock");
        let alias = d.path().join("lock-alias");
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::write(&alias, b"").unwrap();
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&alias, &lock_path).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::hard_link(&alias, &lock_path).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            observe_at(&p, u, &query(), 1800000000).unwrap()[0].status,
            Status::Unknown
        );
    }
}
