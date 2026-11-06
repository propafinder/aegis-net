//! Bounded-memory, closed worker stderr diagnostics used by Linux native QA.
use std::io::Read;

/// Continuous, bounded-memory drain. Only fixed tags and a digest enter QA logs.
pub(crate) struct WorkerStderrSummary {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) tags: Vec<&'static str>,
}
pub(crate) fn drain_worker_stderr(mut source: impl Read) -> std::io::Result<WorkerStderrSummary> {
    use sha2::{Digest, Sha256};
    const TAGS: [(&[u8], &str); 4] = [
        (b"foreign_policy_drift", "foreign_policy_drift"),
        (b"coordinator_disconnected", "coordinator_disconnected"),
        (b"phase_refused", "phase_refused"),
        (b"begin_capture", "begin_capture"),
    ];
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut seen = [false; TAGS.len()];
    let mut overlap = Vec::with_capacity(31);
    let mut block = [0u8; 8192];
    loop {
        let count = source.read(&mut block)?;
        if count == 0 {
            break;
        }
        bytes = bytes.saturating_add(count as u64);
        digest.update(&block[..count]);
        overlap.extend_from_slice(&block[..count]);
        for (index, (needle, _)) in TAGS.iter().enumerate() {
            if overlap
                .windows(needle.len())
                .any(|window| window == *needle)
            {
                seen[index] = true;
            }
        }
        let keep = overlap.len().min(31);
        let start = overlap.len() - keep;
        overlap.copy_within(start.., 0);
        overlap.truncate(keep);
    }
    Ok(WorkerStderrSummary {
        bytes,
        sha256: format!("{:x}", digest.finalize()),
        tags: TAGS
            .iter()
            .zip(seen)
            .filter_map(|((_, tag), hit)| hit.then_some(*tag))
            .collect(),
    })
}
#[test]
fn worker_stderr_over_pipe_capacity_keeps_closed_diagnostic() {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::{os::unix::net::UnixStream, sync::mpsc, time::Duration};
    let (mut writer, reader) = UnixStream::pair().unwrap();
    let drain = std::thread::spawn(move || drain_worker_stderr(reader).unwrap());
    let prefix = vec![b'x'; 192 * 1024];
    let tail = b"\nforeign_policy_drift\n";
    let (done, finished) = mpsc::channel();
    let write = std::thread::spawn(move || {
        writer.write_all(&prefix).unwrap();
        writer.write_all(tail).unwrap();
        drop(writer);
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(5))
        .expect("worker stderr pipe blocked");
    write.join().unwrap();
    let result = drain.join().unwrap();
    assert_eq!(result.bytes, (192 * 1024 + tail.len()) as u64);
    let mut expected = Sha256::new();
    expected.update(vec![b'x'; 192 * 1024]);
    expected.update(tail);
    assert_eq!(result.sha256, format!("{:x}", expected.finalize()));
    assert_eq!(result.tags, vec!["foreign_policy_drift"]);
}
