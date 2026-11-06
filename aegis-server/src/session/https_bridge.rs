//! Public-site replies for exclusive HTTPS bridges. No filesystem serving,
//! redirects, forwarding, upgrades or legacy tunnel dispatch.
use aegis_core::https_bridge::{Gate, PublicResponse};
use bytes::Bytes;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADERS: usize = 8192;

#[derive(Clone, Default)]
pub struct Activity(std::sync::Arc<std::sync::Mutex<ActivityState>>);
#[derive(Default)]
struct ActivityState {
    active: usize,
    completed: Option<tokio::time::Instant>,
}
pub struct ActivityGuard(Activity);
impl Activity {
    /// Called only after successful device mTLS/registry or token authorization.
    pub fn authenticated(&self) -> ActivityGuard {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).active += 1;
        ActivityGuard(self.clone())
    }
    pub fn deadline_with_timeout(
        &self,
        initial: tokio::time::Instant,
        timeout: Duration,
    ) -> Option<tokio::time::Instant> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.active > 0 {
            None
        } else {
            Some(state.completed.map_or(initial, |at| at + timeout))
        }
    }
}
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let mut state = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        state.completed = Some(tokio::time::Instant::now());
    }
}

/// HTTP/1 is site-only: the authorized carrier uses HTTP/2. This intentionally
/// small parser accepts only an unambiguous origin-form HTTP/1.1 request with
/// one Host and no body or upgrade. All other complete requests get one 404.
fn public_request(bytes: &[u8]) -> Option<(&str, &str, &str)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix("\r\n\r\n")?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next()?.split(' ');
    let method = request.next()?;
    let path = request.next()?;
    if request.next()? != "HTTP/1.1"
        || request.next().is_some()
        || !matches!(method, "GET" | "HEAD")
        || !path.starts_with('/')
    {
        return None;
    }
    let mut host = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") && host.replace(value).is_some() {
            return None;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return None;
        }
    }
    Some((method, host?, path))
}

pub async fn serve_http1<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    gate: &Gate,
) -> anyhow::Result<()> {
    tokio::time::timeout(ADMISSION_TIMEOUT, async {
        let mut headers = Vec::with_capacity(1024);
        loop {
            if headers.windows(4).any(|w| w == b"\r\n\r\n") || headers.len() == MAX_HEADERS { break; }
            let mut chunk = [0; 512];
            let cap = chunk.len().min(MAX_HEADERS - headers.len());
            let count = stream.read(&mut chunk[..cap]).await?;
            if count == 0 { break; }
            headers.extend_from_slice(&chunk[..count]);
        }
        let reply = match public_request(&headers) {
            Some((method, authority, path)) => gate.public_response(method, Some(authority), Some(path)),
            None => gate.public_response("GET", None, None),
        };
        let reason = if reply.status == 200 { "OK" } else { "Not Found" };
        let header = format!("HTTP/1.1 {} {}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n", reply.status, reason, reply.body.len());
        stream.write_all(header.as_bytes()).await?;
        if !reply.head { stream.write_all(reply.body).await?; }
        stream.shutdown().await?;
        anyhow::Ok(())
    }).await.map_err(|_| anyhow::anyhow!("HTTPS site admission deadline exceeded"))?
}

pub async fn respond_h2(
    mut respond: h2::server::SendResponse<Bytes>,
    reply: PublicResponse<'_>,
) -> anyhow::Result<()> {
    let response = http::Response::builder()
        .status(reply.status)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", reply.body.len().to_string())
        .header("cache-control", "no-store")
        .body(())?;
    let mut stream = respond.send_response(response, reply.head)?;
    if !reply.head {
        tokio::time::timeout(ADMISSION_TIMEOUT, async {
            let mut remaining = Bytes::copy_from_slice(reply.body);
            while !remaining.is_empty() {
                stream.reserve_capacity(remaining.len());
                let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
                    .await
                    .ok_or_else(|| anyhow::anyhow!("HTTPS site stream closed"))??;
                if capacity == 0 {
                    continue;
                }
                let chunk = remaining.split_to(capacity.min(remaining.len()));
                stream.send_data(chunk, remaining.is_empty())?;
            }
            anyhow::Ok(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("HTTPS site write deadline exceeded"))??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn site_parser_rejects_conflicting_authority_body_and_upgrade() {
        assert_eq!(
            public_request(b"GET / HTTP/1.1\r\nHost: bridge.test\r\n\r\n"),
            Some(("GET", "bridge.test", "/"))
        );
        for request in [
            "GET / HTTP/1.1\r\nHost: bridge.test\r\nHost: other.test\r\n\r\n",
            "GET / HTTP/1.1\r\n Host: bridge.test\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: bridge.test\r\nUpgrade: websocket\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: bridge.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: bridge.test\r\nContent-Length: 1\r\n\r\nx",
            "POST /private/stream HTTP/1.1\r\nHost: bridge.test\r\n\r\n",
        ] {
            assert!(public_request(request.as_bytes()).is_none());
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn http1_site_and_all_private_or_legacy_paths_are_bounded_public_responses() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("bridge-key");
        std::fs::write(&key, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = std::sync::Arc::new(
            Gate::load(&aegis_core::https_bridge::ServerSettings {
                carrier: aegis_core::https_bridge::ClientSettings {
                    authority: "bridge.test".into(),
                    path: "/private/stream".into(),
                    enrollment_path: "/private/enroll".into(),
                    credential_file: key,
                },
                site_html: "<html>Public site</html>".into(),
            })
            .unwrap(),
        );
        for (method, path, authority, expected) in [
            ("GET", "/", "bridge.test", 200),
            ("HEAD", "/", "bridge.test", 200),
            ("GET", "/", "other.test", 404),
            ("GET", "/private/stream", "bridge.test", 404),
            ("GET", "/tunnel.v1.Channel/Connect", "bridge.test", 404),
            ("GET", "/bundle", "bridge.test", 404),
        ] {
            let (mut client, mut server) = tokio::io::duplex(8192);
            let gate = gate.clone();
            let task = tokio::spawn(async move {
                serve_http1(&mut server, &gate).await.unwrap();
            });
            client
                .write_all(
                    format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.unwrap();
            task.await.unwrap();
            assert!(reply.starts_with(&format!("HTTP/1.1 {expected} ")));
            let body = reply.split_once("\r\n\r\n").unwrap().1;
            assert_eq!(
                body,
                if method == "HEAD" {
                    ""
                } else if expected == 200 {
                    "<html>Public site</html>"
                } else {
                    "Not found\n"
                }
            );
        }
    }
}
