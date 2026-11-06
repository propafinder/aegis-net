//! Exclusive machine-wide tunnel ownership and durable crash cleanup intent.
use super::network::Route;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{Foundation::*, System::Threading::*};

pub struct Exclusive(HANDLE);
impl Exclusive {
    pub fn acquire() -> io::Result<Self> {
        let name: Vec<u16> = "Global\\AEGIS.FullTunnel.v1"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let result = Self(handle);
        let code = unsafe { WaitForSingleObject(result.0, 0) };
        if code != WAIT_OBJECT_0 && code != WAIT_ABANDONED {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an AEGIS tunnel or recovery is already active",
            ));
        }
        Ok(result)
    }
}
impl Drop for Exclusive {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: u32,
    /// Routes whose native creation returned success and whose ownership was
    /// then durably recorded. Recovery may remove only these routes.
    pub routes: Vec<Route>,
    /// The route being created. A crash between native creation and durable
    /// confirmation cannot prove ownership, so recovery must refuse if it
    /// exists rather than delete an indistinguishable foreign route.
    #[serde(default)]
    pub pending: Option<Route>,
    /// Deletion was durably announced but not durably completed. If this row
    /// still exists on restart, its ownership cannot be inferred.
    #[serde(default)]
    pub removing: Option<Route>,
}

fn invalid_journal() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Windows route journal")
}

fn ambiguous_route() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "pending Windows route ownership is ambiguous; manual recovery required",
    )
}

impl Journal {
    fn empty() -> Self {
        Self {
            schema: 2,
            routes: Vec::new(),
            pending: None,
            removing: None,
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != 2 || self.routes.len() > 260 {
            return Err(invalid_journal());
        }
        if self.pending.is_some() && self.removing.is_some() {
            return Err(invalid_journal());
        }
        for route in self
            .routes
            .iter()
            .chain(self.pending.iter())
            .chain(self.removing.iter())
        {
            let length = if route.prefix.address.is_ipv4() {
                32
            } else {
                128
            };
            if route.prefix.length > length || route.luid == 0 || route.metric != 0 {
                return Err(invalid_journal());
            }
        }
        Ok(())
    }

    fn begin(&mut self, route: Route) -> io::Result<()> {
        self.validate()?;
        if self.pending.is_some() || self.removing.is_some() || self.routes.len() >= 260 {
            return Err(invalid_journal());
        }
        self.pending = Some(route);
        self.validate()
    }

    fn commit(&mut self) -> io::Result<()> {
        self.validate()?;
        let route = self.pending.take().ok_or_else(invalid_journal)?;
        self.routes.push(route);
        self.validate()
    }

    fn begin_removal(&mut self) -> io::Result<Option<Route>> {
        self.validate()?;
        if self.pending.is_some() || self.removing.is_some() {
            return Err(invalid_journal());
        }
        let Some(route) = self.routes.pop() else {
            return Ok(None);
        };
        self.removing = Some(route.clone());
        self.validate()?;
        Ok(Some(route))
    }

    fn finish_removal(&mut self) -> io::Result<()> {
        self.validate()?;
        if self.removing.take().is_none() {
            return Err(invalid_journal());
        }
        self.validate()
    }
}

pub fn journal_path(config: &Path) -> PathBuf {
    config.with_extension("tunnel-state.json")
}

fn read(path: &Path) -> io::Result<Journal> {
    let bytes = crate::secret_file::read_config(path, 131072)?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    journal.validate()?;
    Ok(journal)
}

fn write(path: &Path, journal: &Journal, replace: bool) -> io::Result<()> {
    journal.validate()?;
    let bytes = serde_json::to_vec(journal).map_err(io::Error::other)?;
    if path
        .parent()
        .is_some_and(|parent| crate::windows_file::trusted_system_directory(parent).is_ok())
    {
        // Recovery may be run by an administrator, then read by SYSTEM. The
        // last writer's SID must not become the protected journal owner.
        crate::windows_file::atomic_write_machine_private(path, &bytes, replace)
    } else {
        crate::windows_file::atomic_write_private(path, &bytes, replace, false)
    }
}

/// Start an empty journal before any route creation. Caller holds Exclusive.
pub fn prepare(path: &Path) -> io::Result<()> {
    write(path, &Journal::empty(), false)
}

/// Persist an intent immediately before native route creation. The pending
/// route is deliberately excluded from automatic recovery if it exists.
pub fn begin_route(path: &Path, route: Route) -> io::Result<()> {
    let mut journal = read(path)?;
    journal.begin(route)?;
    write(path, &journal, true)
}

/// Call only after NetworkGuard::add returned success for this pending route.
pub fn commit_route(path: &Path) -> io::Result<()> {
    let mut journal = read(path)?;
    journal.commit()?;
    write(path, &journal, true)
}

/// The caller must hold Exclusive and have stopped the service first. Keep the
/// journal on any failed removal so a second recovery can finish the operation.
pub fn recover_routes(path: &Path) -> io::Result<usize> {
    let mut journal = match read(path) {
        Ok(journal) => journal,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    if let Some(pending) = journal.pending.as_ref() {
        if pending.exists()? {
            return Err(ambiguous_route());
        }
        journal.pending = None;
        write(path, &journal, true)?;
    }
    if let Some(removing) = journal.removing.as_ref() {
        if removing.exists()? {
            return Err(ambiguous_route());
        }
        journal.finish_removal()?;
        write(path, &journal, true)?;
    }
    let count = journal.routes.len();
    while let Some(route) = journal.begin_removal()? {
        write(path, &journal, true)?;
        route.remove()?;
        journal.finish_removal()?;
        write(path, &journal, true)?;
    }
    std::fs::remove_file(path)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_policy::Prefix;

    fn route() -> Route {
        Route {
            luid: 7,
            index: 7,
            prefix: Prefix::parse("192.0.2.7/32").unwrap(),
            next_hop: "192.0.2.1".parse().unwrap(),
            scope_id: 0,
            metric: 0,
        }
    }

    #[test]
    fn journal_records_only_confirmed_routes() {
        let mut journal = Journal::empty();
        journal.begin(route()).unwrap();
        assert!(journal.routes.is_empty());
        assert!(journal.pending.is_some());
        assert!(journal.begin(route()).is_err());
        journal.commit().unwrap();
        assert_eq!(journal.routes.len(), 1);
        assert!(journal.pending.is_none());
        assert!(journal.removing.is_none());
        assert!(journal.commit().is_err());
    }

    #[test]
    fn removal_transition_does_not_leave_a_route_committed() {
        let mut journal = Journal::empty();
        journal.begin(route()).unwrap();
        journal.commit().unwrap();
        let removing = journal.begin_removal().unwrap().unwrap();
        journal.validate().unwrap();
        assert!(journal.routes.is_empty());
        assert!(journal.removing.is_some());
        assert_eq!(removing.luid, 7);
        assert!(journal.begin(route()).is_err());
        journal.finish_removal().unwrap();
        assert!(journal.finish_removal().is_err());
        journal.validate().unwrap();
    }

    #[test]
    fn old_and_malformed_journals_refuse_automatic_recovery() {
        let mut journal = Journal::empty();
        journal.schema = 1;
        assert!(journal.validate().is_err());
        journal.schema = 2;
        journal.begin(route()).unwrap();
        journal.pending.as_mut().unwrap().luid = 0;
        assert!(journal.validate().is_err());
    }
}
