//! Shared active-probing decoy responses.
//!
//! Every unauthenticated / invalid / unknown / probe-like request that is
//! NOT a valid tunnel or a valid bundle redemption must look like an
//! ordinary stock HTTPS server, not like AEGIS. A central-DPID active
//! prober that connects to a suspected relay and pokes random paths,
//! `/bundle?token=bad`, or a bad WebSocket upgrade must not see any
//! AEGIS-, relay-, tunnel-, or token-specific string or status semantics.
//!
//! This module is the single source of those decoy responses so the HTTP/1.1
//! path (`session::write_http_decoy_response`), the bundle endpoint error
//! paths (h1 + h2), the gRPC/h2 unknown-path, the WebSocket wrong-path
//! rejection, and the QUIC/h3 endpoint (`session::quic`) — which sits directly
//! on the origin's UDP/443 because MASQUE is not Cloudflare-fronted — all emit
//! the *same* shape. Internal reasons are still logged; only the wire response
//! is generic.
//!
//! Scope note: this is "uniform decoy web behaviour", NOT browser-perfect
//! REALITY parity. It removes AEGIS-distinguishing wire tells; it does not
//! claim byte-for-byte parity with a specific origin web server.

use bytes::Bytes;
use http::Response;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Stock non-200 statuses a generic HTTPS server returns for unknown
/// paths. (status_code, reason).
const VARIANTS: [(u16, &str); 4] = [
    (404, "Not Found"),
    (403, "Forbidden"),
    (410, "Gone"),
    (301, "Moved Permanently"),
];

/// Real-world ORIGIN `Server` identities. Deliberately excludes "cloudflare":
/// behind a real CF edge the Server header is overwritten to "cloudflare" by
/// the edge anyway, and on the direct-origin path an origin that *claims* to be
/// Cloudflare is itself a tell. These are plausible self-hosted origins.
const SERVER_DECK: [&str; 5] = [
    "nginx/1.24.0",
    "nginx/1.26.1",
    "Apache/2.4.58 (Ubuntu)",
    "openresty/1.25.3.1",
    "Caddy",
];

/// A chosen decoy response.
pub(crate) struct Decoy {
    pub status: u16,
    pub reason: &'static str,
    pub server: &'static str,
}

/// The decoy identity for this relay process.
///
/// RED TEAM, 2026-08-10: seeding the deck from `peer.port()` made the same URL
/// on the same host answer with a different `Server` on every connection —
/// nginx/1.26.1, Apache/2.4.58, openresty/1.25.3.1, Caddy, in that order, with
/// the status flipping between 404 and 410. Measured against a live relay from
/// another fleet host.
///
/// No real origin does that. Probing any endpoint three times and comparing
/// the `Server` header was a zero-false-positive AEGIS detector costing three
/// requests — strictly worse than shipping no decoy at all, because a plain
/// static `nginx` is unremarkable and a rotating one is a signature.
///
/// The identity is now drawn once per process and reused. A relay is one
/// server and must answer as one server: same software, same status, over
/// HTTP/1.1 and HTTP/2 alike.
static PROCESS_DECOY_SEED: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

fn process_decoy_seed() -> u16 {
    *PROCESS_DECOY_SEED.get_or_init(|| {
        use std::hash::{Hash, Hasher};
        // Stable for the lifetime of the process, and different between
        // relays so the fleet is not one uniform fingerprint. Restarting a
        // relay may change it, which is indistinguishable from an operator
        // upgrading their web server.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::process::id().hash(&mut hasher);
        std::env::var("HOSTNAME")
            .unwrap_or_default()
            .hash(&mut hasher);
        (hasher.finish() % u16::MAX as u64) as u16
    })
}

/// Pick the decoy. The `seed` argument is accepted for call-site
/// compatibility and deliberately IGNORED: every response from this process
/// must present the same server identity. See [`process_decoy_seed`].
pub(crate) fn pick(seed: u16) -> Decoy {
    let _ = seed;
    let s = process_decoy_seed() as usize;
    let (status, reason) = VARIANTS[s % VARIANTS.len()];
    let server = SERVER_DECK[(s >> 4) % SERVER_DECK.len()];
    Decoy {
        status,
        reason,
        server,
    }
}

/// The authentic default error-page body the advertised `server` would return
/// for `status`/`reason`. A prober comparing the body against a real server's
/// default page sees a matching shape, not a too-short generic stub. Caddy and
/// other minimal servers return no body for errors.
pub(crate) fn error_body(server: &str, status: u16, reason: &str) -> String {
    if server.starts_with("nginx") || server.starts_with("openresty") {
        format!(
            "<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n\
             <center><h1>{status} {reason}</h1></center>\r\n<hr><center>{server}</center>\r\n\
             </body>\r\n</html>\r\n"
        )
    } else if server.starts_with("Apache") {
        format!(
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n\
             <title>{status} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n\
             <hr>\n<address>{server} Server at localhost Port 443</address>\n</body></html>\n"
        )
    } else {
        // Caddy / minimal servers: empty body for error statuses.
        String::new()
    }
}

/// Decoy parts for a reject context (HTTP/2 unknown path, WebSocket wrong-path
/// upgrade) where the response is built by a library that frames its own status
/// line/headers, so a 301+`Location` redirect is awkward. Collapses the 301
/// variant to a 404 so the body is a normal error page, and returns the body as
/// `None` for minimal servers that emit no error page. Draws from the SAME
/// seed-indexed deck as every other decoy path, so a prober poking several
/// endpoints on one connection (same `peer.port()` seed) sees ONE consistent
/// origin identity, not a different Server/body per endpoint.
/// Reason phrase to pair with a possibly-collapsed status.
pub(crate) fn reason_for(status: u16, original_reason: &'static str) -> &'static str {
    if status == 404 {
        "Not Found"
    } else {
        original_reason
    }
}

pub(crate) fn reject_parts(seed: u16) -> (u16, &'static str, Option<String>) {
    let d = pick(seed);
    let (status, reason) = if d.status == 301 {
        (404, "Not Found")
    } else {
        (d.status, d.reason)
    };
    let body = error_body(d.server, status, reason);
    let body = if body.is_empty() { None } else { Some(body) };
    (status, d.server, body)
}

/// The response a fronted origin gives to plain HTTP on the TLS port.
///
/// RED TEAM, 2026-08-11: probing 443 with a plain HTTP request returned a
/// 6-byte TLS `decode_error` alert, because rustls rejects the non-TLS bytes
/// before any AEGIS code runs. A Cloudflare-fronted origin — the thing this
/// relay is supposed to look like — detects plain HTTP on 443 and answers with
/// an HTTP 400 page instead. That difference was one of five probes that
/// distinguished the relay from a fronted control, scoring
/// active_probe_resistance at 0.375 against a 0.8 target
/// (`artifacts/live/2026-08-11/active-probe-resistance`).
///
/// The status is 400 rather than the deck's 404/410: those describe a missing
/// resource, and this is a malformed request. The server identity still comes
/// from the same per-process deck so the host answers as one server
/// everywhere.
/// RFC 7231 IMF-fixdate, as every real web server sends on every response.
///
/// RED TEAM, 2026-08-11: the decoy emitted no `Date` header at all. nginx,
/// Apache, Caddy and openresty all send one unconditionally — its absence is a
/// cheap, reliable tell present on every single response, and it survived four
/// rounds of decoy work because the comparisons kept looking at bodies.
pub(crate) fn http_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    // Civil-from-days (Howard Hinnant). Avoids pulling chrono in for one header.
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y0 + 1 } else { y0 };
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{wd}, {day:02} {mon} {year} {h:02}:{mi:02}:{s:02} GMT",
        wd = WD[days.rem_euclid(7) as usize],
        mon = MO[(month - 1) as usize],
        h = tod / 3600,
        mi = (tod % 3600) / 60,
        s = tod % 60
    )
}

/// Generic malformed-request response, distinct from the cleartext-on-TLS page.
pub(crate) fn malformed_http1_string() -> String {
    let d = pick(0);
    let reason = "Bad Request";
    let body = error_body(d.server, 400, reason);
    format!(
        "HTTP/1.1 400 {reason}\r\n\
         Server: {server}\r\n\
         Date: {date}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        server = d.server,
        date = http_date_now(),
        len = body.len(),
    )
}

/// Write the generic malformed-request response; callers retain their deadline.
pub(crate) async fn write_malformed_http1<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(malformed_http1_string().as_bytes()).await
}

pub(crate) fn plain_http_on_tls_port() -> String {
    let d = pick(0);
    let reason = "Bad Request";
    // nginx and openresty have a SPECIFIC page for this case, different from
    // their generic 400: the title carries the explanation and the body has an
    // extra centred line. A prober that knows nginx will compare against that
    // exact shape, so emitting the generic 400 body would still be a tell —
    // just a subtler one than the TLS alert.
    let body = if d.server.starts_with("nginx") || d.server.starts_with("openresty") {
        format!(
            "<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n\
             <body>\r\n<center><h1>400 Bad Request</h1></center>\r\n\
             <center>The plain HTTP request was sent to HTTPS port</center>\r\n\
             <hr><center>{server}</center>\r\n</body>\r\n</html>\r\n",
            server = d.server
        )
    } else {
        error_body(d.server, 400, reason)
    };
    format!(
        "HTTP/1.1 400 {reason}\r\n\
         Server: {server}\r\n\
         Date: {date}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        server = d.server,
        date = http_date_now(),
        len = body.len(),
    )
}

/// Render a full HTTP/1.1 decoy response. `head_only` (HEAD requests)
/// emits identical headers but no body.
pub(crate) fn http1_string(seed: u16, head_only: bool) -> String {
    let d = pick(seed);
    // Status and server come from the same place the HTTP/2 path uses.
    //
    // They used to diverge: reject_parts() collapsed the 301 variant to 404 so
    // a library-framed response could carry a normal error body, while this
    // function kept the 301 and sent a Location redirect. One host answering
    // 301 over HTTP/1.1 and 404 over HTTP/2 for the same path is the same
    // cross-protocol tell as answering with two different Server headers.
    let (status, server, body) = reject_parts(seed);
    let reason = super::decoy::reason_for(status, d.reason);
    let body = body.unwrap_or_default();
    let _ = server;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Server: {server}\r\n\
         Date: {date}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        status = status,
        reason = reason,
        server = d.server,
        date = http_date_now(),
        len = body.len(),
    );
    if head_only {
        head
    } else {
        format!("{head}{body}")
    }
}

/// Write an HTTP/1.1 decoy response to a stream.
pub(crate) async fn write_http1<S>(
    stream: &mut S,
    seed: u16,
    head_only: bool,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(http1_string(seed, head_only).as_bytes())
        .await
}

/// Build an HTTP/2 decoy `Response` head + body bytes. Caller sends the
/// response then a single DATA frame (for `head_only`, send end-of-stream
/// with the response and no body).
pub(crate) fn http2_response(seed: u16) -> (Response<()>, Bytes) {
    let (status, server, body) = reject_parts(seed);
    let resp = Response::builder()
        .status(status)
        .header("server", server)
        .header("content-type", "text/html")
        .body(())
        .expect("valid h2 decoy response");
    (resp, Bytes::from(body.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_aegis_tell(s: &str) -> bool {
        let l = s.to_lowercase();
        [
            "aegis",
            "relay",
            "tunnel",
            "token",
            "websocket path",
            "auth",
        ]
        .iter()
        .any(|t| l.contains(t))
    }

    // RED TEAM REGRESSION: the deck was seeded from peer.port(), so the same
    // URL answered as nginx, then Apache, then openresty, then Caddy across
    // four connections, with the status flipping 404/410. Probing an endpoint
    // three times and diffing the Server header identified an AEGIS relay with
    // no false positives.
    // A real nginx answers plain-HTTP-on-443 with a page whose title carries
    // the explanation, not with its generic 400. Emitting the generic body
    // would leave a subtler version of the same tell.
    // RED TEAM REGRESSION: the decoy sent no Date header. nginx, Apache, Caddy
    // and openresty all send one on every response, so its absence was a tell
    // on every single reply — and it survived four rounds of decoy work
    // because the comparisons kept looking at bodies.
    #[test]
    fn every_decoy_response_carries_a_date_header() {
        for response in [
            http1_string(0, false),
            http1_string(0, true),
            plain_http_on_tls_port(),
        ] {
            assert!(
                response.contains("\r\nDate: "),
                "a web server sends Date on every response; this one did not: {:?}",
                &response[..response.len().min(120)]
            );
        }
        let d = http_date_now();
        // IMF-fixdate: "Tue, 11 Aug 2026 03:34:13 GMT"
        assert!(d.ends_with(" GMT"), "not IMF-fixdate: {d}");
        assert_eq!(d.len(), 29, "IMF-fixdate is fixed width: {d}");
        assert_eq!(&d[3..5], ", ", "weekday must be followed by a comma: {d}");
    }

    #[test]
    fn plain_http_decoy_matches_the_advertised_server() {
        let response = plain_http_on_tls_port();
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        let server = pick(0).server;
        assert!(response.contains(&format!("Server: {server}")));
        if server.starts_with("nginx") || server.starts_with("openresty") {
            assert!(
                response.contains("The plain HTTP request was sent to HTTPS port"),
                "nginx has a specific page for this case and the decoy must use it"
            );
        }
        // Content-Length must describe the body actually sent.
        let (head, body) = response.split_once("\r\n\r\n").expect("headers end");
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .expect("content-length")
            .trim()
            .parse()
            .expect("numeric");
        assert_eq!(declared, body.len(), "Content-Length must match the body");
    }

    #[test]
    fn decoy_identity_is_stable_across_connections() {
        // Seeds stand in for different peer source ports.
        let first = pick(1024);
        for seed in [1025u16, 40000, 65535, 7, 31337] {
            let other = pick(seed);
            assert_eq!(
                first.server, other.server,
                "one relay must not answer as two different servers"
            );
            assert_eq!(
                first.status, other.status,
                "one relay must not flip its status per connection"
            );
        }
    }

    #[test]
    fn decoy_is_identical_over_http1_and_http2() {
        // A real origin runs one web server. Answering as Apache over h1 and
        // openresty over h2 — which is what the live relay did — is impossible
        // for a genuine host.
        let (h2_status, h2_server, _) = reject_parts(4242);
        let h1 = http1_string(9999, false);
        assert!(
            h1.contains(h2_server),
            "http1 decoy advertises a different server than http2: h1={h1:?} h2={h2_server}"
        );
        assert!(
            h1.contains(&h2_status.to_string()),
            "http1 decoy status differs from http2 ({h2_status})"
        );
    }

    #[test]
    fn http1_decoy_has_no_aegis_tells() {
        for seed in 0u16..64 {
            let r = http1_string(seed, false);
            assert!(r.starts_with("HTTP/1.1 "));
            assert!(r.contains("Server: "));
            assert!(!contains_aegis_tell(&r), "decoy leaked a tell: {r}");
        }
    }

    #[test]
    fn head_only_omits_body() {
        // pick a seed whose variant is not 301 AND whose server emits a
        // non-empty body (nginx/openresty/Apache — not Caddy) so a body exists.
        // pick() no longer varies with the seed — the identity is per
        // process — so there is nothing to search for. Skip when this
        // process's identity is a server that returns no error body (Caddy),
        // since then there is no body to omit.
        let seed = 0u16;
        let d = pick(seed);
        let (status, _, body) = reject_parts(seed);
        if body.is_none() {
            let _ = (d, status);
            return;
        }
        let full = http1_string(seed, false);
        let head = http1_string(seed, true);
        assert!(full.len() > head.len());
        assert!(head.ends_with("\r\n\r\n"));
        assert!(!head.contains("<html>"));
    }

    #[test]
    fn body_matches_advertised_server() {
        // For nginx/openresty and Apache, the error page must carry that exact
        // Server identity in its footer — a prober comparing the body to a real
        // default page must see a matching shape, not a generic stub.
        for seed in 0u16..64 {
            let d = pick(seed);
            if d.status == 301 {
                continue;
            }
            let body = error_body(d.server, d.status, d.reason);
            if d.server.starts_with("nginx") || d.server.starts_with("openresty") {
                assert!(body.contains(d.server), "nginx body must footer the server");
                assert!(body.contains("<center>"));
            } else if d.server.starts_with("Apache") {
                assert!(
                    body.contains(d.server),
                    "apache body must address the server"
                );
                assert!(body.contains("<address>"));
            } else {
                assert!(body.is_empty(), "minimal servers emit no error body");
            }
        }
    }

    #[test]
    fn http2_decoy_status_is_web_like_and_clean() {
        for seed in 0u16..64 {
            let (resp, body) = http2_response(seed);
            assert!(matches!(resp.status().as_u16(), 403 | 404 | 410));
            assert!(resp.headers().contains_key("server"));
            assert!(!contains_aegis_tell(std::str::from_utf8(&body).unwrap()));
        }
    }
}
