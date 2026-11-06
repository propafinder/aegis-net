//! Test-only aggregate diagnostics: no payload, peer, credential, or arbitrary error text.
#[cfg(windows)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Comparison {
    pub(super) equal: bool,
    requested_bytes: usize,
    received_bytes: usize,
    first_mismatch: Option<usize>,
}
impl Comparison {
    pub(super) fn new(request: &[u8], response: &[u8]) -> Self {
        Self {
            equal: request == response,
            requested_bytes: request.len(),
            received_bytes: response.len(),
            first_mismatch: request
                .iter()
                .zip(response)
                .position(|(a, b)| a != b)
                .or_else(|| {
                    (request.len() != response.len()).then_some(request.len().min(response.len()))
                }),
        }
    }
}

// Stage code: 0 not entered, 1 pending, 2 successful return, 3 error return.
// EOF flags only represent observed read(0); shutdown completion is not a wire FIN proof.
#[cfg(windows)]
#[derive(Default)]
pub(super) struct Stages {
    pub(super) echo_read: AtomicUsize,
    pub(super) echo_read_bytes: AtomicUsize,
    pub(super) echo_eof: AtomicUsize,
    pub(super) echo_reply_bytes: AtomicUsize,
    pub(super) echo_write: AtomicUsize,
    pub(super) echo_shutdown: AtomicUsize,
    pub(super) app_write: AtomicUsize,
    pub(super) app_shutdown: AtomicUsize,
    pub(super) app_read: AtomicUsize,
    pub(super) app_read_bytes: AtomicUsize,
    pub(super) app_eof: AtomicUsize,
}
#[cfg(windows)]
impl Stages {
    fn render(&self) -> String {
        format!("native TCP stages: echo_read={} echo_read_bytes={} echo_eof={} echo_reply_bytes={} echo_write={} echo_shutdown={} app_write={} app_shutdown={} app_read={} app_read_bytes={} app_eof={}",
            self.echo_read.load(Ordering::Relaxed), self.echo_read_bytes.load(Ordering::Relaxed),
            self.echo_eof.load(Ordering::Relaxed), self.echo_reply_bytes.load(Ordering::Relaxed),
            self.echo_write.load(Ordering::Relaxed), self.echo_shutdown.load(Ordering::Relaxed),
            self.app_write.load(Ordering::Relaxed), self.app_shutdown.load(Ordering::Relaxed),
            self.app_read.load(Ordering::Relaxed), self.app_read_bytes.load(Ordering::Relaxed),
            self.app_eof.load(Ordering::Relaxed))
    }
}
#[cfg(windows)]
pub(super) struct ReportOnDrop(pub(super) Arc<Stages>);
#[cfg(windows)]
impl Drop for ReportOnDrop {
    fn drop(&mut self) {
        eprintln!("{}", self.0.render());
    }
}

#[test]
fn byte_comparison_keeps_exact_equality_and_first_difference() {
    for (request, response, index) in [
        (&b""[..], &b""[..], None),
        (&b"abc"[..], &b"abc"[..], None),
        (&b"abc"[..], &b"ab"[..], Some(2)),
        (&b"ab"[..], &b"abc"[..], Some(2)),
        (&b"abc"[..], &b"xbc"[..], Some(0)),
        (&b"abc"[..], &b"axc"[..], Some(1)),
        (&b"abc"[..], &b"abx"[..], Some(2)),
    ] {
        let comparison = Comparison::new(request, response);
        assert_eq!(comparison.equal, request == response);
        assert_eq!(comparison.first_mismatch, index);
    }
}
#[test]
fn mismatch_diagnostic_is_bounded_and_does_not_dump_payload() {
    let request = vec![197; 2 * 1024 * 1024];
    let response = vec![197; 786432];
    let comparison = Comparison::new(&request, &response);
    assert!(!comparison.equal);
    assert_eq!(comparison.first_mismatch, Some(786432));
    let rendered = format!("{comparison:?}");
    assert!(rendered.len() < 256);
    assert!(!rendered.contains("[197"));
}
#[cfg(windows)]
#[test]
fn aggregate_stage_record_has_fixed_bound_even_for_maximum_counters() {
    let stages = Stages::default();
    for counter in [
        &stages.echo_read,
        &stages.echo_read_bytes,
        &stages.echo_eof,
        &stages.echo_reply_bytes,
        &stages.echo_write,
        &stages.echo_shutdown,
        &stages.app_write,
        &stages.app_shutdown,
        &stages.app_read,
        &stages.app_read_bytes,
        &stages.app_eof,
    ] {
        counter.store(usize::MAX, Ordering::Relaxed);
    }
    assert!(stages.render().len() < 1024);
}
