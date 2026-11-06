use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

const DEFAULT_DENYLIST: &[&str] = &[
    "gfw",
    "ooni",
    "tspu",
    "china",
    "iran",
    "russia",
    "censor",
    "firewall",
    "roskomnadzor",
    "tehran",
    "beijing",
];

const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_FILES: usize = 10_000;

pub struct ReleaseOpsecInputs {
    pub inputs: Vec<PathBuf>,
    pub patterns: Vec<String>,
    pub include_nm: bool,
}

#[derive(Debug)]
struct Hit {
    path: String,
    source: &'static str,
    pattern: String,
}

pub fn release_opsec_gate(inputs: ReleaseOpsecInputs) -> Result<Value, Box<dyn std::error::Error>> {
    let files = expand_inputs(&inputs.inputs)?;
    let patterns = if inputs.patterns.is_empty() {
        DEFAULT_DENYLIST
            .iter()
            .map(|pattern| (*pattern).to_string())
            .collect()
    } else {
        inputs.patterns
    };
    if patterns.len() > 128
        || patterns
            .iter()
            .any(|p| p.is_empty() || !p.is_ascii() || p.len() > 1024)
    {
        return Err("opsec patterns must be nonempty bounded ASCII strings".into());
    }
    let mut hits = Vec::new();
    let mut budget = MAX_TOTAL_BYTES;
    for path in &files {
        hits.extend(scan_file(path, &patterns, &mut budget)?);
        if inputs.include_nm {
            hits.extend(scan_nm(path, &patterns));
        }
    }

    Ok(json!({
        "event": "release_opsec_gate",
        "schema_version": 1,
        "files_scanned": files.len(),
        "status": if hits.is_empty() { "PASS" } else { "FAIL" },
        "hits": hits.into_iter().map(|hit| {
            json!({
                "path": hit.path,
                "source": hit.source,
                "pattern": hit.pattern,
            })
        }).collect::<Vec<_>>(),
    }))
}

fn expand_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    let mut visited = 0;
    for input in inputs {
        if std::fs::symlink_metadata(input)?.file_type().is_symlink() {
            return Err("opsec input is a symbolic link".into());
        }
        if input.is_dir() {
            collect_files(input, &mut files, &mut visited, 0)?;
        } else if input.is_file() {
            files.push(input.clone());
        } else {
            return Err(format!("opsec input does not exist: {}", input.display()).into());
        }
    }
    files.sort();
    files.dedup();
    if files.is_empty() || files.len() > MAX_FILES {
        return Err("opsec input must contain a bounded nonempty file set".into());
    }
    Ok(files)
}

fn collect_files(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    visited: &mut usize,
    depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if depth > 64 {
        return Err("opsec directory nesting limit exceeded".into());
    }
    for entry in std::fs::read_dir(dir)? {
        *visited += 1;
        if *visited > MAX_FILES {
            return Err("opsec input contains too many entries".into());
        }
        let path = entry?.path();
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err("opsec input contains a symbolic link".into());
        }
        if path.is_dir() {
            collect_files(&path, files, visited, depth + 1)?;
        } else if path.is_file() {
            files.push(path);
            if files.len() > MAX_FILES {
                return Err("opsec input contains too many files".into());
            }
        } else {
            return Err("opsec input contains a nonregular entry".into());
        }
    }
    Ok(())
}

fn scan_reader(
    reader: impl Read,
    label: &str,
    source: &'static str,
    patterns: &[String],
    budget: &mut u64,
) -> Result<Vec<Hit>, Box<dyn std::error::Error>> {
    let needles: Vec<Vec<u8>> = patterns
        .iter()
        .map(|p| p.to_ascii_lowercase().into_bytes())
        .collect();
    let overlap = (needles.iter().map(Vec::len).max().unwrap_or(1) - 1).max(64);
    let mut seen = vec![false; needles.len()];
    let mut public_ipv4 = false;
    let mut reader = reader.take(MAX_FILE_BYTES + 1);
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut carry = Vec::new();
    loop {
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        count += size as u64;
        if count > MAX_FILE_BYTES || size as u64 > *budget {
            return Err("opsec scan byte budget exceeded".into());
        }
        *budget -= size as u64;
        carry.extend_from_slice(&buffer[..size]);
        carry.make_ascii_lowercase();
        for (found, needle) in seen.iter_mut().zip(&needles) {
            *found |= carry.windows(needle.len()).any(|window| window == needle);
        }
        public_ipv4 |= contains_public_ipv4(&carry);
        if carry.len() > overlap {
            carry.drain(..carry.len() - overlap);
        }
    }
    let mut hits: Vec<_> = patterns
        .iter()
        .zip(seen)
        .filter(|(_, found)| *found)
        .map(|(pattern, _)| Hit {
            path: label.to_owned(),
            source,
            pattern: pattern.clone(),
        })
        .collect();
    if public_ipv4 {
        // Neither the matched address nor a hash of it is emitted or embedded
        // in the scanner. Policy is deliberately broader than fleet inventory.
        hits.push(Hit {
            path: label.to_owned(),
            source,
            pattern: "unexpected_public_ipv4_literal".into(),
        });
    }
    Ok(hits)
}

fn contains_public_ipv4(bytes: &[u8]) -> bool {
    bytes
        .split(|b| !b.is_ascii_digit() && *b != b'.')
        .any(|token| {
            let Ok(text) = std::str::from_utf8(token) else {
                return false;
            };
            let Ok(ip) = text.parse::<std::net::Ipv4Addr>() else {
                return false;
            };
            let [a, b, _, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (18..=19).contains(&b)))
        })
}

fn scan_file(
    path: &Path,
    patterns: &[String],
    budget: &mut u64,
) -> Result<Vec<Hit>, Box<dyn std::error::Error>> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return Err("opsec input is not a bounded regular file".into());
    }
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0_u8; 4];
    let size = meta.len().min(4) as usize;
    file.read_exact(&mut magic[..size])?;
    file.seek(SeekFrom::Start(0))?;
    let label = path.display().to_string();
    if size >= 2 && magic[..2] == [0x1f, 0x8b] {
        // Inspect archive bytes without writing or executing an archive member.
        // The reader cap also bounds padding and metadata decompression.
        let decompression_limit = *budget + 1;
        let decoded = flate2::read::MultiGzDecoder::new(file).take(decompression_limit);
        let mut archive = tar::Archive::new(decoded);
        let mut hits = Vec::new();
        let mut count = 0;
        let mut regular_count = 0;
        let mut member_budget = *budget;
        let mut names = std::collections::HashSet::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            count += 1;
            if count > MAX_FILES {
                return Err("opsec archive contains too many entries".into());
            }
            let member = entry.path()?.into_owned();
            if !member
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
                || !names.insert(member.clone())
            {
                return Err("opsec archive path is unsafe or duplicated".into());
            }
            let kind = entry.header().entry_type();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() || entry.size() > MAX_FILE_BYTES {
                return Err("opsec archive member is not a bounded regular file".into());
            }
            regular_count += 1;
            let name = member.to_string_lossy();
            if name.ends_with(".gz")
                || name.ends_with(".zip")
                || name.ends_with(".xz")
                || name.ends_with(".tar")
            {
                return Err("nested opsec archives are unsupported".into());
            }
            let mut prefix = [0_u8; 4];
            let prefix_size = entry.size().min(4) as usize;
            entry.read_exact(&mut prefix[..prefix_size])?;
            if (prefix_size >= 2 && prefix[..2] == [0x1f, 0x8b])
                || (prefix_size == 4
                    && (prefix == [b'P', b'K', 3, 4] || prefix == [0xfd, b'7', b'z', b'X']))
            {
                return Err("nested opsec archives are unsupported".into());
            }
            let member_reader = std::io::Cursor::new(&prefix[..prefix_size]).chain(&mut entry);
            hits.extend(scan_reader(
                member_reader,
                &format!("{label}!{name}"),
                "archive_bytes",
                patterns,
                &mut member_budget,
            )?);
        }
        // Consume the remaining gzip trailer so malformed/truncated streams
        // cannot produce a clean result after an otherwise valid tar prefix.
        let mut decoded = archive.into_inner();
        let mut tail = [0_u8; 8192];
        loop {
            let size = decoded.read(&mut tail)?;
            if size == 0 {
                break;
            }
            if tail[..size].iter().any(|byte| *byte != 0) {
                return Err("opsec archive has uninspected trailing data".into());
            }
        }
        let decoded_bytes = decompression_limit - decoded.limit();
        if regular_count == 0 || decoded.limit() == 0 || decoded_bytes > *budget {
            return Err("opsec archive empty or decompression budget exceeded".into());
        }
        *budget -= decoded_bytes;
        Ok(hits)
    } else {
        if path
            .extension()
            .is_some_and(|e| matches!(e.to_str(), Some("gz" | "tgz" | "zip" | "xz")))
            || (size == 4 && magic == [b'P', b'K', 3, 4])
        {
            return Err("opsec unsupported or malformed archive".into());
        }
        scan_reader(file, &label, "bytes", patterns, budget)
    }
}

fn scan_nm(path: &Path, patterns: &[String]) -> Vec<Hit> {
    let Ok(output) = Command::new("nm").arg(path).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    patterns
        .iter()
        .filter(|pattern| text.contains(&pattern.to_lowercase()))
        .map(|pattern| Hit {
            path: path.display().to_string(),
            source: "nm",
            pattern: pattern.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{release_opsec_gate, ReleaseOpsecInputs};
    use std::io::Write;
    use std::path::Path;

    fn scan(path: &Path) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        release_opsec_gate(ReleaseOpsecInputs {
            inputs: vec![path.to_path_buf()],
            patterns: vec!["fixture-private-marker".into()],
            include_nm: false,
        })
    }

    fn archive(path: &Path, member: &str, body: &[u8]) {
        let gzip = flate2::write::GzEncoder::new(
            std::fs::File::create(path).unwrap(),
            flate2::Compression::default(),
        );
        let mut tar = tar::Builder::new(gzip);
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        // Raw fixture header also permits the traversal-negative case, which
        // the safe tar builder's path setter deliberately refuses to create.
        header.as_mut_bytes()[..member.len()].copy_from_slice(member.as_bytes());
        header.set_cksum();
        tar.append(&header, body).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn compressed_member_is_inspected_before_clean_admission() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.tar.gz");
        archive(&path, "bin/client", b"fixture-private-marker");
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw
            .windows(b"fixture-private-marker".len())
            .any(|w| w == b"fixture-private-marker"));
        let report = scan(&path).unwrap();
        assert_eq!(report["status"], "FAIL");
        assert_eq!(report["hits"][0]["source"], "archive_bytes");
    }

    #[test]
    fn clean_archive_and_test_net_literals_remain_eligible() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.tar.gz");
        archive(
            &path,
            "bin/client",
            b"ordinary 192.0.2.1 198.51.100.42 203.0.113.7",
        );
        assert_eq!(scan(&path).unwrap()["status"], "PASS");
    }

    #[test]
    fn unsafe_member_and_disguised_nested_archive_refuse_admission() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.tar.gz");
        archive(&path, "../outside", b"ordinary");
        assert!(scan(&path).is_err());
        let nested = temp.path().join("nested.gz");
        archive(&nested, "inside", b"fixture-private-marker");
        archive(&path, "disguised.bin", &std::fs::read(nested).unwrap());
        assert!(scan(&path).is_err());
    }

    #[test]
    fn malformed_archive_and_nonzero_tail_refuse_admission() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.tar.gz");
        std::fs::write(&path, b"not gzip").unwrap();
        assert!(scan(&path).is_err());
        archive(&path, "bin/client", b"ordinary");
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let mut trailing = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        trailing
            .write_all(b"uninspected additional payload")
            .unwrap();
        trailing.finish().unwrap();
        assert!(scan(&path).is_err());
    }

    #[test]
    fn empty_input_and_oversized_sparse_file_refuse_admission() {
        let temp = tempfile::tempdir().unwrap();
        assert!(scan(temp.path()).is_err());
        let path = temp.path().join("oversized.bin");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(512 * 1024 * 1024 + 1)
            .unwrap();
        assert!(scan(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_input_refuses_even_when_target_is_clean() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("clean.bin");
        std::fs::write(&target, b"ordinary").unwrap();
        let link = temp.path().join("linked");
        std::os::unix::fs::symlink(target, &link).unwrap();
        assert!(scan(&link).is_err());
    }

    #[test]
    fn public_literal_diagnostic_does_not_copy_the_address() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.bin");
        // An ordinary public resolver is synthetic policy input, not a fleet
        // indicator. Do not embed operator address inventories in this binary.
        let address = std::net::Ipv4Addr::new(1, 1, 1, 1).to_string();
        std::fs::write(&path, address.as_bytes()).unwrap();
        let report = scan(&path).unwrap();
        assert_eq!(report["status"], "FAIL");
        assert_eq!(
            report["hits"][0]["pattern"],
            "unexpected_public_ipv4_literal"
        );
        assert!(!report.to_string().contains(&address));
    }

    #[test]
    fn marker_split_at_read_boundary_is_still_detected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.bin");
        let mut bytes = vec![b'x'; 64 * 1024 - 10];
        bytes.extend_from_slice(b"fixture-private-marker");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(scan(&path).unwrap()["status"], "FAIL");
    }
}
