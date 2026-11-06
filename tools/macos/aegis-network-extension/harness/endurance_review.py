#!/usr/bin/env python3
"""B-06 S24a: the summary rows of an ENDURANCE=1 window.

harness/endurance-load.sh runs this once after the last cycle, before the
disconnect, under the system python3 (3.9). It reads the window's
endurance.tsv (one row per planned cycle that ran or was missed), its
results.tsv so far (the status column from the `connected` row on), every
status sampled between cycles, and the provider log the cycles read. It
prints one `name<TAB>verdict<TAB>detail` line per summary row, in this
order: endurance_cycles, endurance_longest_gap,
endurance_connected_throughout, endurance_provider_stable,
endurance_rss_growth, endurance_rebuilds, endurance_renewal,
endurance_real_time. Details carry counts, cycle numbers, process ids and
stable tokens only, never an address. Exit 0 whenever it printed the rows,
2 for bad arguments.
"""
import argparse
import datetime
import sys

PROBES = ("whoami", "tcp_echo", "udp_echo", "dns_txt", "http")
# scutil prints Connecting while the provider reasserts (a session rebuild)
# and never Reasserting, which is taken the same way.
GOOD_STATUSES = ("Connected", "Connecting", "Reasserting")
# How far apart two passing cycles may start beyond two periods (one failing
# cycle between them) before the probes were blind too long.
PASS_GAP_SLACK_S = 5


def read_tsv(path):
    try:
        lines = open(path, errors="replace").read().splitlines()
    except OSError:
        return []
    if not lines:
        return []
    head = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        cells = line.split("\t")
        if len(cells) == len(head):
            rows.append(dict(zip(head, cells)))
    return rows


def utc(text):
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError):
        return None


def counts(items):
    seen = {}
    for item in items:
        seen[item] = seen.get(item, 0) + 1
    return ",".join("%s:%d" % (k, seen[k]) for k in sorted(seen)) or "none"


def number(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def provider_events(path):
    """(event, value) of every `aegis-ne <event> <value>` line, in order."""
    events = []
    try:
        lines = open(path, errors="replace").read().splitlines()
    except OSError:
        return events
    for line in lines:
        words = line.split()
        for i, word in enumerate(words[:-1]):
            if word == "aegis-ne":
                events.append((words[i + 1], words[i + 2] if i + 2 < len(words) else "-"))
                break
    return events


def cycles_row(rows, planned, stopped):
    passed = sum(1 for r in rows if r["verdict"] == "pass")
    failed = [r for r in rows if r["verdict"] == "fail"]
    missed = sum(1 for r in rows if r["verdict"] == "missed")
    not_run = max(0, planned - len(rows))
    ok = planned > 0 and passed * 100 >= 99 * planned
    failing = []
    for r in failed[:10]:
        failing.append("%s:%s" % (r["cycle"], "+".join(p for p in PROBES if r.get(p) != "pass") or "probes"))
    detail = "passed=%d/%d pct=%.2f%% failed=%d missed=%d not_run=%d threshold=99%%" % (
        passed, planned, (100.0 * passed / planned) if planned else 0.0, len(failed), missed, not_run)
    if stopped != "none":
        detail += " stopped=%s" % stopped
    if failing:
        detail += " failing=%s" % ",".join(failing)
    return "pass" if ok else "fail", detail


def gap_row(rows, planned, period, awake):
    # Every planned slot: a cycle that did not pass, was missed or never ran
    # fails; the longest run of failing slots in a row.
    by_cycle = {}
    for r in rows:
        try:
            by_cycle[int(r["cycle"])] = r["verdict"] == "pass"
        except ValueError:
            continue
    longest = run = 0
    at = None
    for k in range(planned):
        if by_cycle.get(k, False):
            run = 0
        else:
            run += 1
            if run > longest:
                longest, at = run, k - run + 1
    starts = [utc(r["start"]) for r in rows if r["verdict"] != "missed"]
    starts = [s for s in starts if s is not None]
    gap = max(((b - a).total_seconds() for a, b in zip(starts, starts[1:])), default=0.0)
    # The probes' blind span: the starts of two passing cycles in a row on
    # the schedule's clock (run_ms). A slot found missed only after a late
    # cycle could leave more than two periods between them with one failing
    # slot; past two periods and PASS_GAP_SLACK_S it fails too.
    passing = []
    for r in rows:
        ms = number(r.get("run_ms"))
        if r["verdict"] == "pass" and ms is not None:
            passing.append((ms / 1000.0, r["cycle"]))
    blind, after = 0.0, None
    for (a, ka), (b, _) in zip(passing, passing[1:]):
        if b - a > blind:
            blind, after = b - a, ka
    limit = 2 * period + PASS_GAP_SLACK_S
    detail = "longest_failing_run=%d cycles period_s=%d max_start_gap_s=%.1f max_pass_gap_s=%.1f pass_gap_limit_s=%d awake=%s" % (
        longest, period, gap, blind, limit, awake)
    if at is not None and longest > 1:
        detail += " from_cycle=%d" % at
    if blind > limit:
        detail += " pass_gap_after_cycle=%s" % after
    return ("pass" if planned > 0 and longest <= 1 and blind <= limit else "fail"), detail


def connected_row(rows, results, statuses_path, stopped):
    seen = []
    try:
        for line in open(statuses_path, errors="replace").read().splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                seen.append((parts[0], parts[1]))
    except OSError:
        pass
    for r in rows:
        if r["verdict"] != "missed":
            seen.append((r["cycle"], r["status_start"]))
            seen.append((r["cycle"], r["status_end"]))
    # The results rows' status column from the connected row on.
    try:
        on = False
        for line in open(results, errors="replace").read().splitlines():
            cells = line.split("\t")
            if len(cells) >= 4:
                on = on or cells[0] == "connected"
                if on:
                    seen.append(("row:" + cells[0], cells[3]))
    except OSError:
        pass
    bad = [(k, s) for k, s in seen if s not in GOOD_STATUSES]
    detail = "statuses=%s samples=%d" % (counts(s for _, s in seen), len(seen))
    if bad:
        detail += " first_bad=%s@%s" % (bad[0][1].replace(" ", "_"), bad[0][0])
    if stopped != "none":
        detail += " stopped=%s" % stopped
    return ("pass" if seen and not bad and stopped == "none" else "fail"), detail


def provider_row(rows, pid0):
    pids = [r["provider_pid"] for r in rows if r["verdict"] != "missed"]
    changes = sum(1 for p in pids if p != pid0)
    none = sum(1 for p in pids if p == "none")
    multi = sum(1 for p in pids if p.startswith("multi:"))
    others = sorted(set(p for p in pids if p != pid0 and p.isdigit()))
    ok = pid0.isdigit() and pids and changes == 0
    detail = "pid=%s readings=%d changes=%d none=%d multi=%d" % (pid0, len(pids), changes, none, multi)
    if others:
        detail += " other_pids=%s" % ",".join(others[:5])
    if not pid0.isdigit():
        detail += " first_reading=%s" % pid0
    return ("pass" if ok else "fail"), detail


def rss_row(rows, after_s, limit_kib, period):
    # The end is the last cycle that ran; the baseline the first that ran at
    # or after AFTER_S into the run and at least a period before the end
    # (else, a run too short to leave a period after AFTER_S, the first that
    # ran). Each needs its own reading of the same provider process, and a
    # baseline that is the end itself measures no growth.
    run = [r for r in rows if r["verdict"] != "missed"]
    if not run:
        return "fail", "no_rss_readings limit_kib=%d" % limit_kib
    end = run[-1]
    last = number(end["slot_s"]) or 0
    late = [r for r in run if after_s <= (number(r["slot_s"]) or 0) <= last - period]
    base = late[0] if late else run[0]
    if base is end:
        return "fail", "no_growth_window baseline_cycle=%s end_cycle=%s readings=1 limit_kib=%d" % (
            base["cycle"], end["cycle"], limit_kib)
    b, e = number(base["rss_kib"]), number(end["rss_kib"])
    if b is None or e is None:
        return "fail", "no_rss_reading baseline_cycle=%s baseline_kib=%s end_cycle=%s end_kib=%s limit_kib=%d" % (
            base["cycle"], base["rss_kib"], end["cycle"], end["rss_kib"], limit_kib)
    readings = [number(r["rss_kib"]) for r in run if number(r["rss_kib"]) is not None]
    cpu = [number(r["cpu_pct"]) for r in run if number(r["cpu_pct"]) is not None]
    growth = int(e - b)
    detail = "growth_kib=%d growth_mib=%.1f limit_kib=%d baseline_cycle=%s baseline_kib=%d end_cycle=%s end_kib=%d max_kib=%d cpu_max=%s" % (
        growth, growth / 1024.0, limit_kib, base["cycle"], int(b), end["cycle"], int(e), int(max(readings)),
        ("%.1f" % max(cpu)) if cpu else "none")
    if base["provider_pid"] != end["provider_pid"]:
        return "fail", detail + " reason=pid_changed"
    return ("pass" if growth <= limit_kib else "fail"), detail


def rebuilds_row(rows, log, recoverable, final):
    events = provider_events(log)
    lost = [v for e, v in events if e == "session_lost"]
    rebuilt = sum(1 for e, _ in events if e == "session_rebuilt")
    failed = [v for e, v in events if e == "session_failed"]
    outside = sorted(set(v for v in lost if v not in recoverable))
    pending = [r["cycle"] for r in rows if r["rebuild_pending"] == "1"]
    unknown = [r["cycle"] for r in rows if r["rebuild_pending"] == "unknown"]
    unread = sum(1 for r in rows if r["log_read"] == "failed")
    detail = "session_lost=%d causes=%s session_rebuilt=%d session_failed=%d rebuild_pending_cycles=%d unjudged=%d unread_logs=%d final=%s" % (
        len(lost), counts(lost), rebuilt, len(failed), len(pending), len(unknown), unread, final)
    reasons = []
    if not events:
        reasons.append("no_provider_log_lines")
    if outside:
        reasons.append("outside_recoverable=" + ",".join(outside[:5]))
    if failed:
        reasons.append("session_failed=" + counts(failed))
    if pending:
        reasons.append("not_rebuilt_before_cycle=" + ",".join(pending[:10]))
    if unknown:
        reasons.append("unjudged_cycle=" + ",".join(unknown[:10]))
    if final != "ok":
        reasons.append("final=" + final)
    if reasons:
        return "fail", detail + " reason=" + ";".join(reasons)
    return "info", detail


def renewal_row(rows, log):
    status = [r["renewal"] for r in rows if r["verdict"] != "missed"]
    states = [v[len("state:"):] for e, v in provider_events(log) if e == "identity_renewal" and v.startswith("state:")]
    phases = [r["phase"] for r in rows if r["verdict"] != "missed"]
    return "info", "status_lines=%s log_states=%s phases=%s" % (counts(status), counts(states), counts(phases))


def real_time_row(rows, duration, period, clock):
    # The cycles' real UTC span, from the first cycle's start to the last
    # one's, both cycles that ran: it must cover the run less one period (a
    # last slot missed). A schedule on the tests' clock or sleep passes
    # nothing: its slots are not real time.
    starts = [utc(r["start"]) for r in rows if r["verdict"] != "missed"]
    starts = [s for s in starts if s is not None]
    span = (starts[-1] - starts[0]).total_seconds() if starts else 0.0
    detail = "real_span_s=%.1f duration_s=%d need_s=%d clock=%s" % (span, duration, duration - period, clock)
    if clock != "default":
        return "unavailable", detail
    return ("pass" if starts and span >= duration - period else "fail"), detail


def main(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tsv", required=True)
    p.add_argument("--results", required=True)
    p.add_argument("--statuses", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--planned", type=int, required=True)
    p.add_argument("--period", type=int, required=True)
    p.add_argument("--pid0", required=True)
    p.add_argument("--final", required=True)
    p.add_argument("--stopped", default="none")
    p.add_argument("--awake", default="unknown")
    p.add_argument("--rss-after", type=int, default=600)
    p.add_argument("--rss-limit", type=int, default=65536)
    p.add_argument("--recoverable", required=True)
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--clock", default="override")
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return 2
    rows = read_tsv(a.tsv)
    recoverable = set(a.recoverable.split())
    out = [
        ("endurance_cycles",) + cycles_row(rows, a.planned, a.stopped),
        ("endurance_longest_gap",) + gap_row(rows, a.planned, a.period, a.awake),
        ("endurance_connected_throughout",) + connected_row(rows, a.results, a.statuses, a.stopped),
        ("endurance_provider_stable",) + provider_row(rows, a.pid0),
        ("endurance_rss_growth",) + rss_row(rows, a.rss_after, a.rss_limit, a.period),
        ("endurance_rebuilds",) + rebuilds_row(rows, a.log, recoverable, a.final),
        ("endurance_renewal",) + renewal_row(rows, a.log),
        ("endurance_real_time",) + real_time_row(rows, a.duration, a.period, a.clock),
    ]
    for name, verdict, detail in out:
        print("%s\t%s\t%s" % (name, verdict, detail.replace("\t", " ")[:400]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
