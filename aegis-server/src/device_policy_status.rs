//! Private local acknowledgement from the exact live authorization state.
#[cfg(unix)]
use aegis_core::secure_channel::registry::RuntimePolicyStatus;
use aegis_core::secure_channel::Server;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
pub(crate) const REQUEST: &[u8] = b"AEGIS-POLICY-STATUS 1\n";
#[cfg(unix)]
pub(crate) const RESPONSE_BYTES: u64 = 2048;
#[cfg(unix)]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub pid: u32,
    pub process_start_ticks: Option<u64>,
    pub version: String,
    pub build_git: String,
    pub build_target: String,
    pub cargo_lock_sha256: String,
}

impl ProcessIdentity {
    #[cfg(unix)]
    fn current() -> io::Result<Self> {
        Ok(Self {
            pid: std::process::id(),
            process_start_ticks: process_start_ticks(std::process::id())?,
            version: env!("CARGO_PKG_VERSION").into(),
            build_git: env!("AEGIS_BUILD_GIT_SHA").into(),
            build_target: env!("AEGIS_BUILD_TARGET").into(),
            cargo_lock_sha256: env!("AEGIS_CARGO_LOCK_SHA256").into(),
        })
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Response {
    Ready {
        policy: RuntimePolicyStatus,
        process: ProcessIdentity,
    },
    Unavailable,
}

fn unavailable() -> io::Error {
    io::Error::other("device_policy_status_unavailable")
}

#[cfg(target_os = "linux")]
pub(crate) fn process_start_ticks(pid: u32) -> io::Result<Option<u64>> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(format!("/proc/{pid}/stat"))?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(unavailable());
    }
    // comm can contain spaces and closing parentheses; subsequent stat fields
    // cannot. starttime is field 22, while the suffix starts at field 3.
    let value = text
        .rsplit_once(')')
        .ok_or_else(unavailable)?
        .1
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(unavailable)?
        .parse::<u64>()
        .map_err(|_| unavailable())?;
    if value == 0 {
        return Err(unavailable());
    }
    Ok(Some(value))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn process_start_ticks(_pid: u32) -> io::Result<Option<u64>> {
    Ok(None)
}

#[cfg(unix)]
pub(crate) fn private_socket_directory(
    path: &Path,
    service_uid: u32,
    service_gid: u32,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 100
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(unavailable());
    }
    let parent = path.parent().ok_or_else(unavailable)?;
    for (index, ancestor) in parent.ancestors().enumerate() {
        let m = std::fs::symlink_metadata(ancestor)?;
        let sticky_root = index > 0 && m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || (m.uid() != 0 && m.uid() != service_uid)
            || (m.mode() & 0o022 != 0 && !sticky_root)
            || (index == 0
                && (m.uid() != service_uid || m.gid() != service_gid || m.mode() & 0o777 != 0o750))
        {
            return Err(unavailable());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn private_socket(
    path: &Path,
    service_uid: u32,
    service_gid: u32,
) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    private_socket_directory(path, service_uid, service_gid)?;
    let m = std::fs::symlink_metadata(path)?;
    if !m.file_type().is_socket()
        || m.uid() != service_uid
        || m.gid() != service_gid
        || m.mode() & 0o777 != 0o660
        || m.nlink() != 1
    {
        return Err(unavailable());
    }
    Ok((m.dev(), m.ino()))
}

#[cfg(unix)]
struct OwnedSocket {
    path: PathBuf,
    identity: (u64, u64),
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl Drop for OwnedSocket {
    fn drop(&mut self) {
        // Never unlink a replacement, ordinary file or another listener. A
        // crash is recovered by the owned systemd RuntimeDirectory lifecycle.
        if private_socket(&self.path, self.uid, self.gid).ok() == Some(self.identity) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) struct StatusServer {
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
    #[cfg(unix)]
    _socket: Option<OwnedSocket>,
}

impl StatusServer {
    pub(crate) fn start(path: Option<&Path>, server: Option<&Server>) -> io::Result<Self> {
        let Some(path) = path else {
            return Ok(Self {
                task: None,
                #[cfg(unix)]
                _socket: None,
            });
        };
        Self::bind(path, server.ok_or_else(unavailable)?)
    }

    #[cfg(not(unix))]
    fn bind(_path: &Path, _server: &Server) -> io::Result<Self> {
        Err(unavailable())
    }

    #[cfg(unix)]
    fn bind(path: &Path, server: &Server) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        if !server.has_dynamic_registry() {
            return Err(unavailable());
        }
        // SAFETY: geteuid reads only the current process identity.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: getegid reads only the current process identity.
        let gid = unsafe { libc::getegid() };
        private_socket_directory(path, uid, gid)?;
        // No blanket unlink or connect-and-delete of an unknown stale socket.
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        let identity = private_socket(path, uid, gid)?;
        let socket = OwnedSocket {
            path: path.to_owned(),
            identity,
            uid,
            gid,
        };
        let server = server.clone();
        let process = ProcessIdentity::current()?;
        let socket_path = path.to_owned();
        let task = tokio::spawn(async move {
            let mut requests = tokio::task::JoinSet::new();
            let mut integrity = tokio::time::interval(Duration::from_secs(1));
            integrity.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = integrity.tick() => {
                        if private_socket(&socket_path, uid, gid)? != identity { return Err(unavailable()); }
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        if requests.len() >= 4 { continue; }
                        let server = server.clone();
                        let process = process.clone();
                        requests.spawn(async move {
                            let _ = tokio::time::timeout(REQUEST_TIMEOUT,
                                serve(stream, &server, process, uid)).await;
                        });
                    }
                    _ = requests.join_next(), if !requests.is_empty() => {}
                }
            }
        });
        Ok(Self {
            task: Some(task),
            _socket: Some(socket),
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.task.is_some()
    }

    pub(crate) async fn stopped(&mut self) -> io::Result<()> {
        match &mut self.task {
            Some(task) => task.await.map_err(|_| unavailable())?,
            None => std::future::pending().await,
        }
    }
}

impl Drop for StatusServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(unix)]
async fn serve(
    mut stream: tokio::net::UnixStream,
    server: &Server,
    process: ProcessIdentity,
    uid: u32,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let peer = stream.peer_cred()?;
    if peer.uid() != 0 && peer.uid() != uid {
        return Err(unavailable());
    }
    let mut request = Vec::new();
    (&mut stream)
        .take(REQUEST.len() as u64 + 1)
        .read_to_end(&mut request)
        .await?;
    if request != REQUEST {
        return Err(unavailable());
    }
    // The lock is released by registry_status before serializing or socket IO.
    let response = match server.registry_status() {
        Ok(policy) => Response::Ready { policy, process },
        Err(_) => Response::Unavailable,
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| unavailable())?;
    if bytes.len() as u64 > RESPONSE_BYTES {
        return Err(unavailable());
    }
    stream.write_all(&bytes).await?;
    stream.shutdown().await
}

#[cfg(all(unix, any(target_os = "linux", test)))]
pub(crate) async fn query(
    path: &Path,
    uid: u32,
    gid: u32,
    expected_pid: u32,
) -> io::Result<Response> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let inode = private_socket(path, uid, gid)?;
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        let peer = stream.peer_cred()?;
        if peer.uid() != uid
            || peer.gid() != gid
            || peer.pid().map(|v| v as u32) != Some(expected_pid)
            || private_socket(path, uid, gid)? != inode
        {
            return Err(unavailable());
        }
        stream.write_all(REQUEST).await?;
        stream.shutdown().await?;
        let mut bytes = Vec::new();
        stream
            .take(RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() as u64 > RESPONSE_BYTES {
            return Err(unavailable());
        }
        serde_json::from_slice(&bytes).map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())?
}

#[cfg(all(test, unix))]
#[path = "device_policy_status_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "device_policy_cross_uid_tests.rs"]
mod cross_uid_tests;
