//! Shared packet lease enforcement. This is not identity or OS admission:
//! callers must obtain the deadline through their authenticated session owner.
use crate::PacketIo;
use std::{
    io,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
pub struct CaptureLeaseDeadline(Arc<Mutex<Option<u64>>>);

impl CaptureLeaseDeadline {
    /// Replace the separately authenticated monotonic deadline. `None` closes
    /// ingress; this method does not establish permission to capture traffic.
    pub fn replace(&self, deadline: Option<u64>) -> io::Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| io::Error::other("worker gate poisoned"))? = deadline;
        Ok(())
    }

    /// Run one packet operation under the same lock used by revocation. The
    /// caller supplies the clock used to produce its authenticated deadline.
    /// Queue errors are returned by the operation inside the outer lease result.
    pub fn while_active<T>(
        &self,
        clock: impl FnOnce() -> io::Result<u64>,
        on_denied: impl FnOnce(),
        operation: impl FnOnce() -> T,
    ) -> io::Result<T> {
        let held = match self.0.lock() {
            Ok(held) => held,
            Err(_) => {
                on_denied();
                return Err(io::Error::other("worker gate poisoned"));
            }
        };
        let permission = match *held {
            None => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker capture lease missing",
            )),
            Some(until) => match clock() {
                Ok(now) if now < until => Ok(()),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "worker capture lease expired",
                )),
                Err(error) => Err(error),
            },
        };
        if let Err(error) = permission {
            on_denied();
            return Err(error);
        }
        Ok(operation())
    }
}

pub struct CaptureLeaseGate<P, C> {
    port: P,
    deadline: CaptureLeaseDeadline,
    clock: C,
}

impl<P, C: Fn() -> io::Result<u64>> CaptureLeaseGate<P, C> {
    pub fn new(port: P, deadline: CaptureLeaseDeadline, clock: C) -> Self {
        Self {
            port,
            deadline,
            clock,
        }
    }

    fn permitted(&self) -> io::Result<bool> {
        match *self
            .deadline
            .0
            .lock()
            .map_err(|_| io::Error::other("worker gate poisoned"))?
        {
            None => Ok(false),
            Some(until) if (self.clock)()? < until => Ok(true),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker capture lease expired",
            )),
        }
    }
}

impl<P: PacketIo, C: Fn() -> io::Result<u64>> PacketIo for CaptureLeaseGate<P, C> {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.permitted()? {
            return Ok(None);
        }
        self.port.receive()
    }

    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if !self.permitted()? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.port.send(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc;

    struct Port(Arc<AtomicUsize>);
    impl PacketIo for Port {
        fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Some(vec![1]))
        }
        fn send(&mut self, _: &[u8]) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn closed_expired_and_revoked_leases_never_touch_packet_port() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = AtomicU64::new(10);
        let deadline = CaptureLeaseDeadline::default();
        let mut gate = CaptureLeaseGate::new(Port(calls.clone()), deadline.clone(), || {
            Ok(now.load(Ordering::SeqCst))
        });
        assert_eq!(gate.receive().unwrap(), None);
        assert_eq!(
            gate.send(&[1]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        deadline.replace(Some(20)).unwrap();
        assert_eq!(gate.receive().unwrap(), Some(vec![1]));
        gate.send(&[1]).unwrap();
        now.store(20, Ordering::SeqCst);
        assert_eq!(
            gate.receive().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            gate.send(&[1]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        deadline.replace(None).unwrap();
        assert_eq!(gate.receive().unwrap(), None);
        assert_eq!(
            gate.send(&[1]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failed_clock_never_touches_packet_port() {
        let calls = Arc::new(AtomicUsize::new(0));
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let mut gate = CaptureLeaseGate::new(Port(calls.clone()), deadline, || {
            Err(io::Error::other("clock failed"))
        });
        assert!(gate.receive().is_err());
        assert!(gate.send(&[1]).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revocation_waits_for_one_in_flight_packet_operation() {
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let active = deadline.clone();
        let operation = std::thread::spawn(move || {
            active
                .while_active(
                    || Ok(10),
                    || panic!("active lease denied"),
                    || {
                        entered_tx.send(()).unwrap();
                        release_rx
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .unwrap();
                    },
                )
                .unwrap();
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let (revoked_tx, revoked_rx) = mpsc::channel();
        let revoker = std::thread::spawn(move || {
            deadline.replace(None).unwrap();
            revoked_tx.send(()).unwrap();
        });
        assert!(revoked_rx.try_recv().is_err());
        release_tx.send(()).unwrap();
        operation.join().unwrap();
        revoked_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        revoker.join().unwrap();
    }
}
