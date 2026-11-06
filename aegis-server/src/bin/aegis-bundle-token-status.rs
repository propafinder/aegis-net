//! Opt-in operator snapshot tool. No network or token redemption.
use aegis_server::bundle_token_status::{observe, StatusQuery};
use serde::Deserialize;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
const MAX_INPUT: u64 = 16 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    queries: Vec<Query>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    opaque_id: String,
    digest: String,
}
fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<(PathBuf, u32), ()> {
    let mut args = args.into_iter();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--store")) {
        return Err(());
    }
    let path = PathBuf::from(args.next().ok_or(())?);
    if !path.is_absolute() || args.next().as_deref() != Some(std::ffi::OsStr::new("--owner")) {
        return Err(());
    }
    let raw = args.next().ok_or(())?;
    let owner = raw.to_str().ok_or(())?;
    if owner.is_empty() || !owner.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let owner = owner.parse::<u32>().map_err(|_| ())?;
    if args.next().is_some() {
        return Err(());
    }
    Ok((path, owner))
}
fn parse_input(mut input: impl Read) -> Result<Vec<StatusQuery>, ()> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(());
    }
    let batch: Batch = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if batch.queries.is_empty() || batch.queries.len() > 64 {
        return Err(());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    if batch.queries.iter().any(|q| {
        q.opaque_id.is_empty()
            || q.opaque_id.len() > 32
            || !q
                .opaque_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || q.digest.len() != 64
            || !q
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !ids.insert(&q.opaque_id)
            || !digests.insert(&q.digest)
    }) {
        return Err(());
    }
    Ok(batch
        .queries
        .into_iter()
        .map(|q| StatusQuery {
            opaque_id: q.opaque_id,
            digest: q.digest,
        })
        .collect())
}
#[cfg(unix)]
fn private_stdin() -> Result<std::fs::File, ()> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| ())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || !matches!(m.mode() & 0o7777, 0o400 | 0o600)
        || m.len() > MAX_INPUT
    {
        return Err(());
    }
    Ok(file)
}
#[cfg(not(unix))]
fn private_stdin() -> Result<std::fs::File, ()> {
    Err(())
}
fn run() -> Result<(), ()> {
    let (path, owner) = parse_args(std::env::args_os().skip(1))?;
    let queries = parse_input(private_stdin()?)?;
    let observations = observe(&path, owner, &queries).map_err(|_| ())?;
    let mut output = serde_json::to_vec(&observations).map_err(|_| ())?;
    output.push(b'\n');
    std::io::stdout().lock().write_all(&output).map_err(|_| ())
}
fn main() {
    if run().is_err() {
        let _ = std::io::stderr()
            .lock()
            .write_all(b"status query refused\n");
        std::process::exit(2);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> String {
        format!(
            r#"{{"queries":[{{"opaque_id":"case-1","digest":"{}"}}]}}"#,
            "a".repeat(64)
        )
    }
    #[test]
    fn valid_batch() {
        let q = parse_input(good().as_bytes()).unwrap();
        assert_eq!(q[0].opaque_id, "case-1");
    }
    #[test]
    fn bounds() {
        assert!(parse_input(vec![b' '; MAX_INPUT as usize + 1].as_slice()).is_err());
        assert!(parse_input(br#"{"queries":[]}"#.as_slice()).is_err());
    }
    #[test]
    fn unknown_and_duplicate_fields() {
        for s in [
            good().replace("\"queries\":", "\"extra\":1,\"queries\":"),
            good().replace("\"opaque_id\":", "\"opaque_id\":\"other\",\"opaque_id\":"),
            good() + "{}",
        ] {
            assert!(parse_input(s.as_bytes()).is_err());
        }
    }
    #[test]
    fn malformed_digest() {
        for s in [
            good().replace(&"a".repeat(64), &"A".repeat(64)),
            good().replace(&"a".repeat(64), "short"),
        ] {
            assert!(parse_input(s.as_bytes()).is_err());
        }
    }
    #[test]
    fn private_ids() {
        for id in ["../secret", "has space", "", "line\\nfeed"] {
            assert!(parse_input(good().replace("case-1", id).as_bytes()).is_err());
        }
    }
    #[test]
    fn duplicated_ids_or_digests() {
        let q = format!(
            r#"{{"queries":[{{"opaque_id":"one","digest":"{}"}},{{"opaque_id":"two","digest":"{}"}}]}}"#,
            "a".repeat(64),
            "a".repeat(64)
        );
        assert!(parse_input(q.as_bytes()).is_err());
        assert!(parse_input(
            q.replace("two", "one")
                .replace(&"a".repeat(64), &"b".repeat(64))
                .as_bytes()
        )
        .is_err());
    }
    #[test]
    fn argument_contract() {
        let args = [
            "--store",
            "/var/lib/aegis/bundle-tokens.json",
            "--owner",
            "0",
        ];
        assert!(parse_args(args.map(OsString::from)).is_ok());
        for a in [
            vec!["--store", "relative", "--owner", "0"],
            vec!["--store", "/path", "--owner", "-1"],
            vec!["--store", "/path", "--owner", "0", "extra"],
        ] {
            assert!(parse_args(a.into_iter().map(OsString::from)).is_err());
        }
    }
}
