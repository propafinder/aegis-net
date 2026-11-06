use super::AwsLcTlsStream;
use std::cell::RefCell;
use std::ffi::{c_int, c_long, c_void, OsString};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, OnceLock};

type Events = Arc<Mutex<Vec<&'static str>>>;

struct Observation {
    events: Events,
    fail_before_io: bool,
}

thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

struct TraceScope(Events);

impl TraceScope {
    fn new(fail_before_io: bool) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        OBSERVATION.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Observation {
                events: events.clone(),
                fail_before_io,
            });
        });
        Self(events)
    }

    fn events(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

impl Drop for TraceScope {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| *slot.borrow_mut() = None);
    }
}

struct FreeWitness {
    events: Events,
    event: &'static str,
}

// AWS-LC invokes this when it actually destroys the observed object. This
// watches real SSL/SSL_CTX allocations; it does not replace allocators/frees.
unsafe extern "C" fn observe_free(
    _parent: *mut c_void,
    pointer: *mut c_void,
    _data: *mut aws_lc_sys::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: only attach_witness stores this uniquely owned box at our index;
    // AWS-LC calls the index's free callback exactly once on object destruction.
    let witness = unsafe { Box::from_raw(pointer.cast::<FreeWitness>()) };
    witness
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(witness.event);
}

fn attach_witness(
    allocated: &'static str,
    freed: &'static str,
    attach: impl FnOnce(*mut c_void) -> c_int,
) {
    let events = OBSERVATION.with(|slot| slot.borrow().as_ref().map(|state| state.events.clone()));
    let Some(events) = events else { return };
    let pointer = Box::into_raw(Box::new(FreeWitness {
        events: events.clone(),
        event: freed,
    }));
    if attach(pointer.cast()) != 1 {
        // SAFETY: a failed attach has not taken this pointer's ownership.
        unsafe { drop(Box::from_raw(pointer)) };
        panic!("could not attach actual AWS-LC destruction witness");
    }
    events.lock().unwrap().push(allocated);
}

pub(super) fn observe_context(ctx: NonNull<aws_lc_sys::SSL_CTX>) {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    let index = *INDEX.get_or_init(|| {
        // SAFETY: a dedicated index uses no new/dup hook or borrowed arg data.
        let index = unsafe {
            aws_lc_sys::SSL_CTX_get_ex_new_index(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                None,
                Some(observe_free),
            )
        };
        assert!(index >= 0);
        index
    });
    attach_witness("ctx_alloc", "ctx_free", |pointer| unsafe {
        aws_lc_sys::SSL_CTX_set_ex_data(ctx.as_ptr(), index, pointer)
    });
}

pub(super) fn observe_ssl(ssl: NonNull<aws_lc_sys::SSL>) {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    let index = *INDEX.get_or_init(|| {
        // SAFETY: a dedicated index uses no new/dup hook or borrowed arg data.
        let index = unsafe {
            aws_lc_sys::SSL_get_ex_new_index(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                None,
                Some(observe_free),
            )
        };
        assert!(index >= 0);
        index
    });
    attach_witness("ssl_alloc", "ssl_free", |pointer| unsafe {
        aws_lc_sys::SSL_set_ex_data(ssl.as_ptr(), index, pointer)
    });
}

pub(super) fn before_io_registration() -> anyhow::Result<()> {
    if OBSERVATION.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|state| state.fail_before_io)
    }) {
        anyhow::bail!("injected AWS-LC setup failure before AsyncFd registration");
    }
    Ok(())
}

fn unconnected_socket() -> std::net::TcpStream {
    // SAFETY: this creates one fresh owned socket descriptor. No bind, connect,
    // TLS handshake or network I/O occurs in these setup-only regressions.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "create unconnected setup fixture socket");
    // SAFETY: the new descriptor is valid and owned solely by this TcpStream.
    let tcp = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    tcp.set_nonblocking(true).unwrap();
    tcp
}

fn setup_error(ca: Option<&std::path::Path>, name: &str, alpn: &[Vec<u8>]) -> anyhow::Error {
    match AwsLcTlsStream::new(unconnected_socket(), ca, name, alpn, true, None) {
        Ok(_) => panic!("setup fault was unexpectedly accepted"),
        Err(error) => error,
    }
}

#[test]
fn actual_setup_frees_context_after_invalid_alpn() {
    let trace = TraceScope::new(false);
    let error = setup_error(None, "fixture.invalid", &[Vec::new()]);
    assert!(error.to_string().contains("ALPN protocol cannot be empty"));
    eprintln!(
        "actual AWS-LC invalid ALPN cleanup events: {:?}",
        trace.events()
    );
    assert_eq!(trace.events(), ["ctx_alloc", "ctx_free"]);
}

#[test]
fn actual_setup_frees_context_after_nul_ca_path() {
    let trace = TraceScope::new(false);
    let ca = PathBuf::from(OsString::from_vec(b"fixture\0ca".to_vec()));
    let error = setup_error(Some(&ca), "fixture.invalid", &[]);
    assert!(error.to_string().contains("path contains NUL"));
    assert_eq!(trace.events(), ["ctx_alloc", "ctx_free"]);
}

#[test]
fn actual_setup_frees_ssl_then_context_after_nul_verify_name() {
    let trace = TraceScope::new(false);
    let error = setup_error(None, "fixture\0invalid", &[]);
    assert!(error.to_string().contains("tls verify name contains NUL"));
    eprintln!(
        "actual AWS-LC NUL name cleanup events: {:?}",
        trace.events()
    );
    assert_eq!(
        trace.events(),
        ["ctx_alloc", "ssl_alloc", "ssl_free", "ctx_free"]
    );
}

#[test]
fn actual_setup_frees_both_on_injected_late_registration_failure() {
    let trace = TraceScope::new(true);
    let error = setup_error(None, "fixture.invalid", &[b"h2".to_vec()]);
    assert!(error.to_string().contains("injected AWS-LC setup failure"));
    assert_eq!(
        trace.events(),
        ["ctx_alloc", "ssl_alloc", "ssl_free", "ctx_free"]
    );
}

#[tokio::test]
async fn actual_setup_transfers_ownership_until_stream_drop() {
    let trace = TraceScope::new(false);
    let stream = AwsLcTlsStream::new(
        unconnected_socket(),
        None,
        "fixture.invalid",
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
        true,
        None,
    )
    .expect("successful setup without handshake or network I/O");
    assert_eq!(trace.events(), ["ctx_alloc", "ssl_alloc"]);
    drop(stream);
    assert_eq!(
        trace.events(),
        ["ctx_alloc", "ssl_alloc", "ssl_free", "ctx_free"]
    );
}
