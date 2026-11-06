//! Session-scoped Windows timer resolution for finite public-tick senders.
//! A failed request refuses before any input read or wire emission.

use std::io;

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period_ms: u32) -> u32;
    fn timeEndPeriod(period_ms: u32) -> u32;
}

pub(crate) struct WindowsTimerResolution;

impl WindowsTimerResolution {
    pub(crate) fn acquire() -> io::Result<Self> {
        // SAFETY: winmm retains no pointer; each successful request is paired
        // with exactly one timeEndPeriod in Drop, including early return.
        let result = unsafe { timeBeginPeriod(1) };
        if result != 0 {
            return Err(io::Error::other("Windows 1 ms timer request refused"));
        }
        Ok(Self)
    }
}

impl Drop for WindowsTimerResolution {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after a successful matching request.
        let result = unsafe { timeEndPeriod(1) };
        if result != 0 {
            tracing::error!(result, "Windows 1 ms timer release failed");
        }
    }
}
