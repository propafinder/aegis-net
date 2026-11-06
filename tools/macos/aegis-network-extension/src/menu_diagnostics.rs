//! v39 (B-06 menu-bar app, source only): the masked "Copy Diagnostics"
//! report and the menu app's bounded event log.
//!
//! The report is built from allow-listed fields of the menu's observation
//! (codes, counts, states, times), never from a key, certificate, invitation,
//! bundle file, path or provider JSON. The whole text then passes `mask`
//! anyway, so a code or event line that ever carried one is still masked:
//! IP addresses keep only their first label, user names in paths, UUIDs,
//! long hex and base64-like runs, e-mail addresses, PEM blocks and the
//! values of secret-looking keys are replaced.

use crate::menu_model::{friendly_utc, MenuView, Observation, Probe};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Keys whose values are always replaced (`key=value` and `"key": "value"`).
const SECRET_KEYS: [&str; 10] = [
    "token",
    "secret",
    "password",
    "passwd",
    "invitation",
    "credential",
    "key",
    "private_key",
    "authorization",
    "cookie",
];

fn secret_key(name: &str) -> bool {
    let name = name.trim_matches('"').to_ascii_lowercase();
    SECRET_KEYS.contains(&name.as_str())
        || [
            "_token",
            "_secret",
            "_password",
            "_key",
            "_invitation",
            "_credential",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Mask everything in `text` that could identify a key, a token, an
/// invitation, a person or a full IP address. Idempotent.
pub fn mask(text: &str) -> String {
    let text = mask_pem(text);
    let mut out = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let line = mask_secret_values(line);
        let line = mask_json_secrets(&line);
        let line = mask_emails(&line);
        let line = mask_paths(&line);
        let line = mask_uuids(&line);
        let line = mask_ipv4(&line);
        let line = mask_ipv6(&line);
        let line = mask_hex(&line);
        let line = mask_base64(&line);
        out.push_str(&line);
    }
    out
}

fn mask_pem(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        // The block ends after the dashes that close its END line.
        let end = after.find("-----END").and_then(|end| {
            let tail = &after[end + 8..];
            tail.find("-----").map(|close| end + 8 + close + 5)
        });
        out.push_str("<pem redacted>");
        match end {
            Some(end) => rest = &after[end..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// `key=value` words whose key looks secret: the value is replaced.
fn mask_secret_values(line: &str) -> String {
    line.split(' ')
        .map(|word| match word.split_once('=') {
            Some((key, value)) if !value.is_empty() && secret_key(key) => {
                format!("{key}=<redacted>")
            }
            _ => word.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `"key": "value"` with a secret-looking key: the string is replaced.
fn mask_json_secrets(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    loop {
        // A quoted name followed by a colon and a quoted value.
        let Some(open) = rest.find('"') else {
            out.push_str(rest);
            return out;
        };
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('"') else {
            out.push_str(rest);
            return out;
        };
        let name = &after_open[..close];
        let tail = &after_open[close + 1..];
        let trimmed = tail.trim_start();
        let is_member = trimmed.starts_with(':');
        out.push_str(&rest[..open + 1 + close + 1]);
        if is_member && secret_key(name) {
            let value = trimmed[1..].trim_start();
            if let Some(value_body) = value.strip_prefix('"') {
                if let Some(value_end) = value_body.find('"') {
                    let skipped = tail.len() - value.len();
                    out.push_str(&tail[..skipped]);
                    out.push_str("\"<redacted>\"");
                    rest = &value_body[value_end + 1..];
                    continue;
                }
            }
        }
        rest = tail;
    }
}

/// Replace every maximal run of chars accepted by `accept` for which
/// `replace` returns a replacement.
fn map_runs(
    line: &str,
    accept: impl Fn(char) -> bool,
    replace: impl Fn(&str) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(line.len());
    let mut run_start: Option<usize> = None;
    let flush = |out: &mut String, run: &str| match replace(run) {
        Some(replacement) => out.push_str(&replacement),
        None => out.push_str(run),
    };
    for (index, ch) in line.char_indices() {
        if accept(ch) {
            run_start.get_or_insert(index);
        } else {
            if let Some(start) = run_start.take() {
                flush(&mut out, &line[start..index]);
            }
            out.push(ch);
        }
    }
    if let Some(start) = run_start {
        flush(&mut out, &line[start..]);
    }
    out
}

fn mask_emails(line: &str) -> String {
    map_runs(
        line,
        |c| c.is_ascii_alphanumeric() || "._%+-@".contains(c),
        |run| {
            let (local, domain) = run.split_once('@')?;
            (!local.is_empty() && domain.contains('.') && !domain.starts_with('.'))
                .then(|| "<email>".to_owned())
        },
    )
}

/// The user name after `/Users/` and the per-user part of
/// `/var/folders/` are replaced.
fn mask_paths(line: &str) -> String {
    let line = mask_path_segments(line, "/Users/", 1, "<user>");
    mask_path_segments(&line, "/var/folders/", 2, "<tmp>")
}

/// Replace the `count` path segments after each `marker` with `label`.
/// `/Users/Shared` names nobody and is kept.
fn mask_path_segments(line: &str, marker: &str, count: usize, label: &str) -> String {
    let stop = |c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'';
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(marker) {
        let (before, after) = rest.split_at(at + marker.len());
        out.push_str(before);
        if let Some(masked) = after.strip_prefix(label) {
            out.push_str(label);
            rest = masked;
            continue;
        }
        let mut end = 0;
        for segment in 0..count {
            end += after[end..].find(stop).unwrap_or(after.len() - end);
            if segment + 1 < count && after[end..].starts_with('/') {
                end += 1;
            } else {
                break;
            }
        }
        let taken = after[..end].trim_end_matches('/');
        if taken.is_empty() || taken == "Shared" {
            rest = after;
        } else {
            out.push_str(label);
            rest = &after[taken.len()..];
        }
    }
    out.push_str(rest);
    out
}

fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn mask_uuids(line: &str) -> String {
    map_runs(
        line,
        |c| c.is_ascii_hexdigit() || c == '-',
        |run| {
            let groups: Vec<&str> = run.split('-').collect();
            (groups.len() == 5
                && groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
                && groups.iter().all(|g| is_hex(g)))
            .then(|| format!("<uuid {}…>", &run[..4]))
        },
    )
}

fn mask_ipv4(line: &str) -> String {
    map_runs(
        line,
        |c| c.is_ascii_digit() || c == '.',
        |run| {
            // A dotted quad possibly followed by more dots (end of a
            // sentence): mask the quad, keep the rest.
            let quad_end = run
                .char_indices()
                .filter(|(_, c)| *c == '.')
                .nth(3)
                .map_or(run.len(), |(index, _)| index);
            let quad = &run[..quad_end];
            let address: Ipv4Addr = quad.parse().ok()?;
            let first = address.octets()[0];
            Some(format!("{first}.x.x.x{}", &run[quad_end..]))
        },
    )
}

fn mask_ipv6(line: &str) -> String {
    map_runs(
        line,
        |c| c.is_ascii_hexdigit() || c == ':' || c == '.' || c == '%',
        |run| {
            if run.matches(':').count() < 2 {
                return None;
            }
            // A sentence's closing dot is kept; a zone (`%en0`) is masked
            // with the address.
            let without_dots = run.trim_end_matches('.');
            let trailing = &run[without_dots.len()..];
            let bare = without_dots.split('%').next().unwrap_or(without_dots);
            let address: Ipv6Addr = bare.parse().ok()?;
            Some(format!("{:x}:<masked>{trailing}", address.segments()[0]))
        },
    )
}

fn mask_hex(line: &str) -> String {
    map_runs(
        line,
        |c| c.is_ascii_hexdigit(),
        |run| (run.len() >= 16).then(|| format!("<hex {}>", run.len())),
    )
}

/// Base64-like runs of 24 or more characters that mix upper case, lower
/// case and digits (keys, tokens, invitations); stable lowercase codes and
/// words never qualify.
fn mask_base64(line: &str) -> String {
    map_runs(
        line,
        |c| c.is_ascii_alphanumeric() || "+/=_-".contains(c),
        |run| {
            let core = run.trim_end_matches('=');
            let mixed = core.bytes().any(|b| b.is_ascii_uppercase())
                && core.bytes().any(|b| b.is_ascii_lowercase())
                && core.bytes().any(|b| b.is_ascii_digit());
            (core.len() >= 24 && mixed).then(|| "<redacted>".to_owned())
        },
    )
}

/// The menu app's recent actions and failures, masked when recorded.
#[derive(Clone, Debug)]
pub struct EventLog {
    entries: VecDeque<String>,
    cap: usize,
}

impl EventLog {
    pub fn new(cap: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(cap),
            cap: cap.max(1),
        }
    }

    /// Record `text` at `now`; a line equal to the previous one only counts.
    pub fn push(&mut self, now: u64, text: &str) {
        let masked = mask(text);
        let stamp = crate::provider_xpc::utc_text(now);
        let line = format!("{} {masked}", &stamp[11..19]);
        if let Some(last) = self.entries.back() {
            if last.get(9..) == line.get(9..) {
                return;
            }
        }
        if self.entries.len() == self.cap {
            self.entries.pop_front();
        }
        self.entries.push_back(line);
    }

    pub fn entries(&self) -> Vec<String> {
        self.entries.iter().cloned().collect()
    }
}

/// What the report needs besides the observation.
pub struct ReportInput<'a> {
    pub now: u64,
    /// `CFBundleShortVersionString (CFBundleVersion)`.
    pub app_version: &'a str,
    pub macos_version: &'a str,
    pub observation: &'a Observation,
    pub view: &'a MenuView,
    pub events: &'a [String],
}

fn probe_text<T>(probe: &Probe<T>, ok: impl Fn(&T) -> String) -> String {
    match probe {
        Probe::Unknown => "not asked".into(),
        Probe::Ok(value) => ok(value),
        Probe::Failed { exit, code } => format!(
            "failed exit={} code={}",
            exit.map_or_else(|| "none".to_owned(), |e| e.to_string()),
            code.as_deref().unwrap_or("none")
        ),
    }
}

fn opt_time(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), friendly_utc)
}

/// The masked report for "Copy Diagnostics".
pub fn report(input: &ReportInput) -> String {
    let obs = input.observation;
    let mut lines = vec![
        "AEGIS diagnostics (masked: no keys, tokens, invitations, user names or full IP addresses)"
            .to_owned(),
        format!("generated: {}", friendly_utc(input.now)),
        format!("app: {}", input.app_version),
        format!("runs from /Applications: {}", obs.in_applications),
        format!("macOS: {}", input.macos_version),
        format!("state: {}", input.view.title),
    ];
    lines.extend(input.view.details.iter().map(|d| format!("detail: {d}")));
    lines.push(format!("extension: {:?}", obs.extension));
    lines.push(format!("approval_requested: {}", obs.approval_requested));
    lines.push(format!(
        "profiles: {}",
        probe_text(&obs.profiles, |profiles| {
            let mut text = format!("{}", profiles.len());
            for p in profiles {
                text.push_str(&format!(
                    "; intent_valid={} enabled={} on_demand={} native_vpn_status={}",
                    p.intent_valid, p.enabled, p.on_demand_enabled, p.native_vpn_status
                ));
            }
            text
        })
    ));
    lines.push(format!(
        "provider: {}",
        probe_text(&obs.provider, |status| format!(
            "session_phase={} session_refusal={}",
            status.session_phase,
            status.session_refusal.as_deref().unwrap_or("none")
        ))
    ));
    lines.push(format!(
        "identity_present: {}",
        obs.identity_present
            .map_or_else(|| "unknown".to_owned(), |present| present.to_string())
    ));
    lines.push(match &obs.cert {
        Some(cert) => format!(
            "certificate: state={} not_before={} not_after={} renew_at={} attempts={} last_failure={} check={} next_attempt_at={}",
            cert.state,
            opt_time(cert.not_before),
            opt_time(cert.not_after),
            opt_time(cert.renew_at),
            cert.attempts,
            cert.last_failure.as_deref().unwrap_or("none"),
            cert.check.as_deref().unwrap_or("none"),
            opt_time(cert.next_attempt_at),
        ),
        None => "certificate: unknown".to_owned(),
    });
    lines.push(format!(
        "leak guard: {}",
        probe_text(&obs.filter, |filter| format!(
            "filter_result={} mode={}",
            filter.outcome,
            filter.mode.as_deref().unwrap_or("unknown")
        ))
    ));
    lines.push(format!(
        "activity: {}",
        obs.activity.map_or("none", |activity| activity.label())
    ));
    lines.push(format!(
        "status_since: {}",
        obs.status_since.map_or_else(
            || "none".to_owned(),
            |(status, since)| format!("{status} at {}", friendly_utc(since))
        )
    ));
    lines.push("recent events:".to_owned());
    if input.events.is_empty() {
        lines.push("  none".to_owned());
    }
    lines.extend(input.events.iter().map(|event| format!("  {event}")));
    mask(&lines.join("\n")) + "\n"
}

#[cfg(test)]
#[path = "menu_diagnostics_tests.rs"]
mod tests;
