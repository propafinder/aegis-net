// Test-only gate over canonical codec output. It never decodes or rewrites bytes.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

#[derive(Default)]
struct State {
    allowance: usize,
    consumed: usize,
    reader: Option<Waker>,
}

#[derive(Clone)]
pub struct Gate {
    state: Arc<Mutex<State>>,
    progress: Arc<tokio::sync::Notify>,
}

pub struct GatedWire {
    inner: DuplexStream,
    gate: Gate,
}

impl Gate {
    pub fn wrap(inner: DuplexStream) -> (GatedWire, Self) {
        let gate = Self {
            state: Arc::new(Mutex::new(State {
                allowance: 1,
                ..State::default()
            })),
            progress: Arc::new(tokio::sync::Notify::new()),
        };
        (
            GatedWire {
                inner,
                gate: gate.clone(),
            },
            gate,
        )
    }

    pub fn release(&self, count: usize) {
        let wake = {
            let mut state = self.state.lock().unwrap();
            state.allowance = state.allowance.saturating_add(count);
            state.reader.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    pub fn consumed(&self) -> usize {
        self.state.lock().unwrap().consumed
    }

    pub async fn wait_consumed(&self, count: usize) {
        loop {
            let notified = self.progress.notified();
            if self.consumed() >= count {
                return;
            }
            notified.await;
        }
    }
}

impl AsyncRead for GatedWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let gate = self.gate.clone();
        let mut state = gate.state.lock().unwrap();
        state.reader = Some(cx.waker().clone());
        let limit = state.allowance.min(buf.remaining());
        if limit == 0 {
            return Poll::Pending;
        }
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
        match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let count = limited.filled().len();
                buf.advance(count);
                state.allowance -= count;
                state.consumed += count;
                drop(state);
                if count > 0 {
                    gate.progress.notify_one();
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for GatedWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// The std wall-clock thread can abort the owned fixture even if Tokio time stops.
// Normal cleanup joins codec workers explicitly; panic/abort cleanup has only
// their existing Drop abort semantics and is not a descendant-join guarantee.
pub async fn wall_bounded(future: impl Future<Output = ()> + Send + 'static) {
    let fixture = tokio::spawn(future);
    let abort = fixture.abort_handle();
    let cancel = Arc::new((Mutex::new(false), Condvar::new()));
    let thread_cancel = cancel.clone();
    let wall = std::thread::spawn(move || {
        let (lock, wake) = &*thread_cancel;
        let cancelled = lock.lock().unwrap();
        let (cancelled, _) = wake
            .wait_timeout_while(cancelled, Duration::from_secs(20), |v| !*v)
            .unwrap();
        if !*cancelled {
            abort.abort();
        }
    });
    let result = fixture.await;
    *cancel.0.lock().unwrap() = true;
    cancel.1.notify_one();
    wall.join().unwrap();
    result.expect("owned fixture failed or exceeded real 20-second wall bound");
}
