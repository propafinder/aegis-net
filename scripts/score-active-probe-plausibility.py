#!/usr/bin/env python3
"""Score active-probe resistance by PLAUSIBILITY, not by byte-equality.

The previous scorer compared our response byte-for-byte against one control
server and called the difference a tell. That answers "are you the same server
as my control", which is the wrong question — it produced 0.375 against a CDN
edge, 0.750 against an nginx origin, and 0.500 after a decoy identity changed,
all without our resistance changing at all. Two different web servers is what
the internet looks like.

This scores each probe on properties a real origin has. A control corpus is
still used, but only to establish what "normal" looks like for a property, not
to demand equality with any one of them.

Usage:
    score-active-probe-plausibility.py <aegis.jsonl> <control.jsonl> [more-controls.jsonl ...]

Each JSONL row is one probe: {"probe", "response_b64", "elapsed_ms"}.
"""

import base64
import json
import statistics
import sys


def rows(path):
    out = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            out[row.get("probe", "?")] = row
    return out


def body(row):
    return base64.b64decode(row.get("response_b64") or "")


def parse_http(raw):
    """Split an HTTP response into (status_line, headers, body). None if not HTTP."""
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if value:
            headers[name.strip().lower()] = value.strip()
    return lines[0], headers, rest


def score_probe(name, raw, control_raws):
    """Return (score, [notes]). Absent probes and silent-by-design cases are skipped."""
    notes = []
    controls_silent = sum(1 for c in control_raws if not c)

    if not raw:
        # Silence is only fine if real servers are also silent for this probe.
        if controls_silent >= max(1, len(control_raws) // 2):
            return None, ["silent, and controls are silent too — not scored"]
        return 0.0, ["silent where real servers answer"]

    parsed = parse_http(raw)
    if parsed is None and raw.lstrip()[:1] == b"<":
        # Body without a status line. The 2026-08-11 corpus is like this: the
        # probe harness captured only what followed the headers, so Server,
        # Date and Content-Length cannot be checked at all. Score the one
        # property that survives and say the rest was not captured — silently
        # skipping would read as "nothing wrong here".
        body_text = raw.decode("latin1", "replace").lower()
        families = [f for f in ("nginx", "openresty", "apache", "caddy") if f in body_text]
        coherent = len(families) <= 1
        return (1.0 if coherent else 0.0), [
            "headers not captured by the probe harness — only body coherence scored",
            *([] if coherent else [f"FAIL body names several servers: {families}"]),
        ]
    if parsed is None:
        # A TLS alert is a legitimate answer only if controls also decline to
        # speak HTTP here.
        if controls_silent or not any(parse_http(c) for c in control_raws if c):
            return None, ["not HTTP, and no control answered HTTP either — not scored"]
        return 0.0, ["not an HTTP response where real servers send one"]

    status_line, headers, payload = parsed
    checks = []

    # 1. A plausible status line.
    parts = status_line.split(" ", 2)
    ok_status = len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit()
    checks.append(("status line well-formed", ok_status))

    # 2. The headers every real web server sends.
    checks.append(("Server present", "server" in headers))
    checks.append(("Date present", "date" in headers))

    # 3. Content-Length must describe the body actually sent.
    if "content-length" in headers:
        try:
            declared = int(headers["content-length"])
            checks.append(("Content-Length matches body", declared == len(payload)))
        except ValueError:
            checks.append(("Content-Length numeric", False))
    else:
        # Absent is only acceptable if controls omit it too.
        omitted = [c for c in control_raws if c and (p := parse_http(c)) and "content-length" not in p[1]]
        checks.append(("Content-Length present or omitted like controls", bool(omitted)))

    # 4. The body should look like the advertised server's error page, or be
    #    empty — both are real behaviours. What is not real is a body that
    #    names a different server than the header.
    server = headers.get("server", "")
    family = server.split("/")[0].lower()
    body_text = payload.decode("latin1", "replace").lower()
    other_families = {"nginx", "apache", "openresty", "caddy"} - {family}
    contradicts = any(other in body_text for other in other_families)
    checks.append(("body does not name a different server", not contradicts))

    for label, passed in checks:
        if not passed:
            notes.append(f"FAIL {label}")
    return sum(1 for _, passed in checks if passed) / len(checks), notes


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    aegis = rows(sys.argv[1])
    controls = [rows(p) for p in sys.argv[2:]]

    scored, skipped = [], []
    report = []
    for name, row in sorted(aegis.items()):
        control_raws = [c[name] and body(c[name]) for c in controls if name in c]
        score, notes = score_probe(name, body(row), control_raws)
        if score is None:
            skipped.append(name)
            report.append(f"  {name:<24} skipped — {notes[0]}")
            continue
        scored.append(score)
        detail = ("; ".join(notes)) if notes else "all checks pass"
        report.append(f"  {name:<24} {score:.2f}  {detail}")

    print("per-probe plausibility:")
    print("\n".join(report))

    overall = statistics.fmean(scored) if scored else 0.0
    print(f"\nscored {len(scored)} probes, skipped {len(skipped)}")
    print(f"active_probe_plausibility = {overall:.3f}  (target >=0.8)")
    print(
        "\nNOTE: acceptance is this score being STABLE across two different "
        "control origins, not the number from a single run. The old "
        "byte-equality metric moved 0.375 -> 0.750 -> 0.500 on control choice "
        "alone."
    )
    return 0 if overall >= 0.8 else 1


if __name__ == "__main__":
    sys.exit(main())
