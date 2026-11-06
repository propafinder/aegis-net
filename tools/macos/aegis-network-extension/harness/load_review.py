#!/usr/bin/env python3
"""B-06 v34/v35 (S24b observability): the info rows of a LOAD=1 window.

harness/endurance-load.sh (el_after_window) runs this once after the
disconnect and the window's one provider-log read, under the system
python3 (3.9). No row it prints is ever pass or fail: each is `info`, or
`unavailable` with a reason, and the window refuses any other verdict from
it. It prints one `name<TAB>verdict<TAB>detail` line per row, in this
order:

- load_filter_series: the leak-guard filter's per-reason drop rates before
  and during the load, from the provider's 10 s `filter_counters` blocks
  (cumulative counters, while guarding), and the correlation of the drop
  rate with the allow_relay rate across the blocks' intervals.
- load_outbound_drops: the outbound drop ring's new records across the load
  (filter-status-load-before/after.txt), by interface, family, reason and
  TCP kind, the marked ones, the ring's overflow, and the per-class kind
  deltas.
- load_placement: the bulk flows (`flow_bulk`, flows over 1 MiB) that ended
  in the load: flows per pooled connection, overlapping bulk flows on one
  connection (the collision case), each flow's rate and the most credit the
  relay held on it (`win_kib`), and the load streams' own lines (v34
  review: the flows that moved at least one stream's cap, `per_stream=` of
  load_download).
- load_window: the adaptive stream window (`pool_window`) during the load.
- load_latency: the bursts and the timed TCP echo before the load against
  under it (results.tsv), the handshake percentiles (`pool_detail hs_ms`)
  and the per-connection RTT lines on the bulk flows' connections, with
  their sample count.
- load_queue (v35): per bulk connection during the load, its credit-loop
  delay `q_ms` p50/p90 (`pool_queue`), the credit its streams held
  (`held_kib` p50/p90), its largest extra, its credit against its own
  bandwidth-delay product p50/p90 ((min_ms + q_ms) / min_ms, min_ms from
  its `pool_rtt` lines), and the share of its samples with an extra while
  q_ms stood at 120 or more; then the load streams' `flow_queue` lines
  (the flows that moved at least one stream's cap): their zone bins,
  steps and resets.
- load_takes (v35): the `pool_take` sums over the load: new flows taken,
  those that went to a queued connection, their share, and the most
  connections queued at once among those taking streams.

With --endurance-log alone (an ENDURANCE=1 window, v34 review, critic B4) it
prints one row instead, endurance_window: the stream window's lines
(`pool_window`) across the whole run, from endurance-provider.log.

Every parser of a provider line is in the TELEMETRY block below. The v34
lines it assumes (the v34 spec; the NE source's names win if they differ,
and only this block then changes):

    pool_window grown:<n> max_kib:<k> budget_kib:<used>-<total> denied:<n>
        (`/` between used and total is read too; the stable log path
        carries no `/`)
    flow_bulk conn:<id> kib:<n> ms:<n> win_kib:<n>
        (one per flow over 1 MiB, at the flow's end; win_kib: the most
        credit the relay held on its stream, as its releases saw it)
    pool_rtt conn:<id> min_ms:<n> srtt_ms:<n> last_ms:<n>
        (per connection, at the pool_state cadence; conn_rtt is read too;
        last_ms: the latest round-trip sample since the line before, a
        carrier request to its 200 or a PONG, left out when none was taken)

v35's lines:

    pool_queue conn:<id> q_ms:<n|none> held_kib:<n> extra_kib:<n>
        (with each pool_rtt line: the connection's latest bulk
        measurement's credit-loop delay, its live streams' latest mean
        credit held and their extras, summed)
    flow_queue conn:<id> q_bins:<lo>-<mid>-<hi> grows:<n> resets:<a>-<b>
        (right after its flow's flow_bulk line: its measurements with q at
        most min(60 ms, RTT/3), between, and at least 120 ms; its growth
        steps; its returns to 128 KiB a kept step caused, and the others)
    pool_take n:<n> queued:<n> conns_queued:<k>-<m>
        (with pool_state while flows wait, at most once a second: the new
        flows taken since the line before, those on a queued connection,
        and the queued connections among the m taking streams)
    pool_policy mode:<adaptive|fixed>
        (once per flow pool; read by real-relay-window.sh's window_policy
        row, not here)

and the existing ones:

    filter_counters_state mode:<open|guarding> attached:<bool>
    filter_counters <reason>:<cumulative count> ... (four a line, non-zero)
    pool_detail oldest_ms:<n> sndq_kib:<n> hs_ms:<p50>-<p90>

Times are the compact log's local `YYYY-MM-DD HH:MM:SS.mmm`, compared with
the window's own local times (`date '+%Y-%m-%d %H:%M:%S'`). Details carry
counts, rates, connection ids and stable tokens, never an address. Exit 0
whenever it printed the rows, 2 for bad arguments.
"""
import argparse
import datetime
import json
import re
import statistics
import sys

ROWS = ("load_filter_series", "load_outbound_drops", "load_placement", "load_window", "load_latency",
        "load_queue", "load_takes")
ENDURANCE_ROW = "endurance_window"

# ------------------------------------------------------------- TELEMETRY
PROVIDER = " aegis-ne-provider["
LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s.*?\saegis-ne ([a-z][a-z0-9_]*)((?: [^ ]+)*)\s*$")
POOL_WINDOW = "pool_window"
FLOW_BULK = "flow_bulk"
RTT_EVENTS = ("pool_rtt", "conn_rtt")
POOL_DETAIL = "pool_detail"
POOL_QUEUE = "pool_queue"
FLOW_QUEUE = "flow_queue"
POOL_TAKE = "pool_take"
BINS = re.compile(r"^([0-9]+)-([0-9]+)-([0-9]+)$")
# v35's standing queue (stream_window.rs Q_SHRINK), in ms.
Q_SHRINK_MS = 120
COUNTERS = "filter_counters"
COUNTERS_STATE = "filter_counters_state"
PAIR = re.compile(r"^([0-9]+)[-/]([0-9]+)$")
# The stream window every stream starts with (flow_pool.rs STREAM_WINDOW).
INITIAL_WINDOW_KIB = 128
# A flow_bulk line is logged at its flow's end, which may follow the
# downloads' end by a little; a filter block at most one period after it
# still counts the load's tail.
BULK_TAIL_S = 30
BLOCK_TAIL_S = 10


def when(text):
    """A local time of the log or the window, or None."""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def read_lines(path):
    """The provider's own `aegis-ne` lines: (time, time text, event, fields)."""
    out = []
    try:
        text = open(path, errors="replace").read().splitlines()
    except (OSError, TypeError):
        return out
    for line in text:
        if PROVIDER not in line:
            continue
        m = LINE.match(line)
        if not m:
            continue
        t = when(m.group(1))
        if t is None:
            continue
        fields = {}
        for tok in m.group(3).split():
            k, sep, v = tok.partition(":")
            if sep:
                fields[k] = v
        out.append((t, m.group(1), m.group(2), fields))
    return out


def number(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------- helpers
def pct(values, p):
    """Nearest-rank percentile of a non-empty list."""
    v = sorted(values)
    k = max(1, int(-(-p * len(v) // 100)))
    return v[min(k, len(v)) - 1]


def fmt(x, digits=1):
    return "na" if x is None else ("%.*f" % (digits, x))


def pearson(xs, ys):
    if len(xs) < 3:
        return None
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sx = sum((x - mx) ** 2 for x in xs)
    sy = sum((y - my) ** 2 for y in ys)
    if sx <= 0 or sy <= 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy) ** 0.5


# ------------------------------------------------------------- rows
def filter_series(lines, window_from, load_from, load_to):
    # A block is one filter_counters_state line and the filter_counters
    # lines after it (the provider logs them together, four counters a line;
    # a zero counter is left out).
    blocks = []
    for t, _stamp, event, fields in lines:
        if event == COUNTERS_STATE:
            blocks.append({"t": t, "mode": fields.get("mode"), "c": {}})
        elif event == COUNTERS and blocks:
            for k, v in fields.items():
                n = number(v)
                if n is not None:
                    blocks[-1]["c"][k] = n
    guarded = sorted((b for b in blocks if b["mode"] == "guarding" and b["c"]), key=lambda b: b["t"])
    if len(guarded) < 2:
        return "unavailable", "no_filter_counters_blocks blocks=%d" % len(guarded)
    end = load_to + datetime.timedelta(seconds=BLOCK_TAIL_S)
    phases = {"before": [], "during": []}
    allints = []
    for a, b in zip(guarded, guarded[1:]):
        dt = (b["t"] - a["t"]).total_seconds()
        if dt <= 0 or a["t"] < window_from or b["t"] > end:
            continue
        keys = set(a["c"]) | set(b["c"])
        delta = {k: b["c"].get(k, 0) - a["c"].get(k, 0) for k in keys}
        if any(v < 0 for v in delta.values()):
            continue   # a counter went back: another provider process
        if b["t"] <= load_from:
            phase = "before"
        elif a["t"] >= load_from:
            phase = "during"
        else:
            phase = None   # straddles the load's start
        iv = (dt, delta)
        allints.append(iv)
        if phase:
            phases[phase].append(iv)
    if not allints:
        return "unavailable", "no_interval_in_window blocks=%d" % len(guarded)

    def rate(ivs, pred):
        s = sum(iv[0] for iv in ivs)
        if s <= 0:
            return None
        return sum(v for iv in ivs for k, v in iv[1].items() if pred(k)) / s

    reasons = sorted({k for iv in allints for k, v in iv[1].items() if v and k.startswith("drop_")})
    parts = ["intervals=%d/%d" % (len(phases["before"]), len(phases["during"])),
             "before_s=%s" % fmt(sum(iv[0] for iv in phases["before"])),
             "during_s=%s" % fmt(sum(iv[0] for iv in phases["during"]))]
    for name, pred in (("allow_relay", lambda k: k == "allow_relay"), ("drops", lambda k: k.startswith("drop_"))):
        parts.append("%s_per_s=%s->%s" % (name, fmt(rate(phases["before"], pred), 2), fmt(rate(phases["during"], pred), 2)))
    xs = [iv[1].get("allow_relay", 0) / iv[0] for iv in allints]
    ys = [sum(v for k, v in iv[1].items() if k.startswith("drop_")) / iv[0] for iv in allints]
    parts.append("corr_drops_vs_relay=%s" % fmt(pearson(xs, ys), 2))
    odd = sum(v for iv in phases["during"] for k, v in iv[1].items()
              if k in ("torn_snapshot", "drop_malformed", "drop_fragment"))
    parts.append("torn_malformed_fragment_during=%d" % odd)
    ranked = sorted(reasons, key=lambda k: -(rate(phases["during"], lambda x, k=k: x == k) or 0))
    for k in ranked[:8]:
        parts.append("%s=%s->%s" % (k, fmt(rate(phases["before"], lambda x, k=k: x == k), 2),
                                    fmt(rate(phases["during"], lambda x, k=k: x == k), 2)))
    return "info", " ".join(parts)


def read_report(path):
    try:
        text = open(path, errors="replace").read().splitlines()
    except (OSError, TypeError):
        return None
    for line in text:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("report"), dict) and r.get("verb", "filter-status") == "filter-status":
            return r["report"]
    return None


def outbound(report):
    obs = report.get("observability") if isinstance(report, dict) else None
    out = obs.get("outbound") if isinstance(obs, dict) else None
    return out if isinstance(out, dict) else None


def nested_delta(a, b):
    """`class:kind:+n` for each non-zero change of two {class: {kind: n}}."""
    parts = []
    if not isinstance(b, dict):
        return parts
    for cls in sorted(b):
        kb = b.get(cls) if isinstance(b.get(cls), dict) else {}
        ka = a.get(cls) if isinstance(a, dict) and isinstance(a.get(cls), dict) else {}
        for kind in sorted(kb):
            d = (number(kb.get(kind)) or 0) - (number(ka.get(kind)) or 0)
            if d:
                parts.append("%s:%s:%+d" % (cls, kind, d))
    return parts


def outbound_drops(before_path, after_path, slots):
    a, b = outbound(read_report(before_path)), outbound(read_report(after_path))
    if a is None or b is None:
        return "unavailable", "outbound_unexposed"
    ra, rb = a.get("ring"), b.get("ring")
    if not isinstance(ra, dict) or not isinstance(rb, dict) or number(ra.get("next")) is None \
            or number(rb.get("next")) is None:
        return "unavailable", "outbound_ring_unexposed"
    first, new = number(ra["next"]), number(rb["next"]) - number(ra["next"])
    records, marked, kinds = 0, 0, {}
    for e in rb.get("entries") or []:
        if not isinstance(e, dict) or (number(e.get("index")) is None) or number(e.get("index")) < first:
            continue
        records += 1
        marked += 1 if e.get("marked") is True else 0
        reason = str(e.get("reason", "?"))
        reason = reason[5:] if reason.startswith("drop_") else reason
        key = ":".join(re.sub(r"[^a-z0-9_]", "", str(e.get(k, "?")).lower()) or "?"
                       for k in ("iface", "family")) + ":" + reason + ":" + str(e.get("tcp", "none"))
        kinds[key] = kinds.get(key, 0) + 1
    rec = ",".join("%s:%d" % (k, kinds[k]) for k in sorted(kinds, key=lambda k: (-kinds[k], k))) or "none"
    parts = ["new=%d" % new, "recorded=%d" % records, "overflow=%d" % max(0, new - slots), "records=" + rec,
             "marked_records=%d" % marked,
             "kinds=" + (",".join(nested_delta(a.get("kinds"), b.get("kinds"))) or "none"),
             "marked=" + (",".join(nested_delta(a.get("marked"), b.get("marked"))) or "none")]
    return "info", " ".join(parts)


def bulk_flows(lines, load_from, load_to):
    end = load_to + datetime.timedelta(seconds=BULK_TAIL_S)
    flows = []
    for t, _stamp, event, fields in lines:
        if event != FLOW_BULK or t < load_from or t > end:
            continue
        kib, ms = number(fields.get("kib")), number(fields.get("ms"))
        conn = re.sub(r"[^a-z0-9_-]", "", fields.get("conn", "")) or "?"
        if kib is None or ms is None:
            continue
        flows.append({"conn": conn, "kib": kib, "ms": ms, "win": number(fields.get("win_kib")),
                      "end": t, "start": t - datetime.timedelta(milliseconds=ms)})
    return flows


def stream_cap(rows):
    """Each load stream's cap in bytes (load_download's per_stream=), or None."""
    m = re.search(r"(?:^| )per_stream=([0-9]+)(?: |$)", rows.get("load_download", ("", ""))[1])
    return int(m.group(1)) if m else None


def placement(flows, cap=None):
    if not flows:
        return "unavailable", "no_flow_bulk_lines"
    per = {}
    for f in flows:
        per.setdefault(f["conn"], []).append(f)
    pairs, most = 0, 0
    for fs in per.values():
        for i in range(len(fs)):
            for j in range(i + 1, len(fs)):
                if min(fs[i]["end"], fs[j]["end"]) > max(fs[i]["start"], fs[j]["start"]):
                    pairs += 1
        events = sorted([(f["start"], 1) for f in fs] + [(f["end"], -1) for f in fs], key=lambda e: (e[0], e[1]))
        live = 0
        for _t, d in events:
            live += d
            most = max(most, live)
    order = sorted(per, key=lambda c: (len(c), c))
    wins = [f["win"] for f in flows if f["win"] is not None]
    # The load streams' own lines: a flow that moved at least a stream's cap
    # (its stream's bytes include the inner TLS, so never fewer).
    if cap is None:
        own = "load_flows=unknown load_win_kib=unknown"
    else:
        mine = sorted((f for f in flows if f["kib"] * 1024 >= cap), key=lambda f: f["end"])
        own = "load_flows=%d load_win_kib=%s" % (
            len(mine), ",".join("none" if f["win"] is None else str(f["win"]) for f in mine) or "none")
    parts = ["bulk_flows=%d" % len(flows), "conns=%d" % len(per),
             "per_conn=" + ",".join("%s:%d" % (c, len(per[c])) for c in order),
             "max_concurrent_per_conn=%d" % most, "overlapping_pairs=%d" % pairs,
             "collision_case=%s" % ("exercised" if pairs else "not_exercised"),
             "win_kib_max=%s" % (max(wins) if wins else "none"), own,
             "flow_mbit_s=" + ",".join("%s:%.1f" % (f["conn"], f["kib"] * 8.192 / f["ms"] if f["ms"] > 0 else 0)
                                       for f in sorted(flows, key=lambda f: (len(f["conn"]), f["conn"], f["end"])))]
    return "info", " ".join(parts)


def window_record(fields):
    return {"grown": number(fields.get("grown")), "max": number(fields.get("max_kib")),
            "denied": number(fields.get("denied")), "budget": PAIR.match(fields.get("budget_kib", ""))}


def stream_window(lines, load_from, load_to):
    before, during = [], []
    end = load_to + datetime.timedelta(seconds=5)
    for t, _stamp, event, fields in lines:
        if event != POOL_WINDOW:
            continue
        rec = window_record(fields)
        if t < load_from:
            before.append(rec)
        elif t <= end:
            during.append(rec)
    if not during:
        return "unavailable", "no_pool_window_lines before=%d" % len(before)
    grown = [r["grown"] for r in during if r["grown"] is not None]
    mx = [r["max"] for r in during if r["max"] is not None]
    used = [(int(r["budget"].group(1)), int(r["budget"].group(2))) for r in during if r["budget"]]
    denied = [r["denied"] for r in during if r["denied"] is not None]
    d0 = next((r["denied"] for r in reversed(before) if r["denied"] is not None), None)
    top = max(mx) if mx else None
    parts = ["lines=%d" % len(during), "grown_max=%s" % (max(grown) if grown else "none"),
             "max_kib_max=%s" % (top if top is not None else "none"),
             "above_initial=%s" % ("none" if top is None else ("yes" if top > INITIAL_WINDOW_KIB else "no")),
             "budget_kib_max=%s" % ("%d/%d" % max(used) if used else "none"),
             "denied_last=%s" % (denied[-1] if denied else "none"),
             "denied_in_load=%s" % ((denied[-1] - (d0 or 0)) if denied else "none")]
    return "info", " ".join(parts)


def endurance_window(lines):
    """The stream window across an ENDURANCE=1 run: whether long-lived flows
    hold the budget (critic B4). Info only."""
    recs = [window_record(fields) for _t, _stamp, event, fields in lines if event == POOL_WINDOW]
    if not recs:
        return "unavailable", "no_pool_window_lines"
    grown = [r["grown"] for r in recs if r["grown"] is not None]
    mx = [r["max"] for r in recs if r["max"] is not None]
    used = [(int(r["budget"].group(1)), int(r["budget"].group(2))) for r in recs if r["budget"]]
    denied = [r["denied"] for r in recs if r["denied"] is not None]
    parts = ["lines=%d" % len(recs), "grown_max=%s" % (max(grown) if grown else "none"),
             "grown_last=%s" % (grown[-1] if grown else "none"),
             "max_kib_max=%s" % (max(mx) if mx else "none"),
             "budget_kib_max=%s" % ("%d/%d" % max(used) if used else "none"),
             "budget_kib_last=%s" % ("%d/%d" % used[-1] if used else "none"),
             "denied_last=%s" % (denied[-1] if denied else "none")]
    return "info", " ".join(parts)


def result_rows(path):
    rows = {}
    try:
        text = open(path, errors="replace").read().splitlines()
    except (OSError, TypeError):
        return rows
    for line in text:
        f = line.split("\t")
        if len(f) >= 3:
            rows[f[0]] = (f[1], f[2])
    return rows


def burst_s(rows, name):
    m = re.match(r"^[0-9]+/[0-9]+ ([0-9.]+)s$", rows.get(name, ("", ""))[1])
    return float(m.group(1)) if m else None


def echo_ms(rows, name):
    m = re.match(r"^[0-9]+/([0-9]+)/[a-z_]+$", rows.get(name, ("", ""))[1])
    return int(m.group(1)) if m else None


def latency(lines, rows, flows, window_from, load_from, load_to):
    parts = []
    for label, a, b, get in (("burst24_s", "flow_burst_24", "load_flow_burst_24", burst_s),
                             ("burst90_s", "flow_burst_90", "load_flow_burst_90", burst_s),
                             ("tcp_echo_ms", "tcp_echo_v4_warm", "load_tcp_echo_v4", echo_ms)):
        x, y = get(rows, a), get(rows, b)
        parts.append("%s=%s->%s" % (label, "na" if x is None else x, "na" if y is None else y))
    hs = {"before": [], "during": []}
    rtt = {"before": [], "during": []}
    for t, _stamp, event, fields in lines:
        if t < window_from or t > load_to:
            continue
        phase = "before" if t < load_from else "during"
        if event == POOL_DETAIL:
            m = PAIR.match(fields.get("hs_ms", ""))
            if m:
                hs[phase].append((int(m.group(1)), int(m.group(2))))
        elif event in RTT_EVENTS:
            rec = {k: number(fields.get(k)) for k in ("min_ms", "srtt_ms", "last_ms")}
            rec["conn"] = fields.get("conn", "?")
            rtt[phase].append(rec)
    for i, label in ((0, "hs_p50_ms_max"), (1, "hs_p90_ms_max")):
        x = max((h[i] for h in hs["before"]), default=None)
        y = max((h[i] for h in hs["during"]), default=None)
        parts.append("%s=%s->%s" % (label, "na" if x is None else x, "na" if y is None else y))
    bulk = {f["conn"] for f in flows}
    on = [r for r in rtt["during"] if not bulk or r["conn"] in bulk]
    if not rtt["during"]:
        parts.append("rtt=none")
    else:
        parts.append("rtt_lines=%d" % len(on))
        parts.append("rtt_conns=%s:%d" % ("bulk" if bulk else "all", len({r["conn"] for r in on})))
        for k in ("min_ms", "srtt_ms", "last_ms"):
            v = [r[k] for r in on if r[k] is not None]
            parts.append("%s_p50=%s %s_p90=%s" % (k, pct(v, 50) if v else "na", k, pct(v, 90) if v else "na"))
        # The latest sample less the least (v34 acceptance L4): a carrier's
        # 200 or a PONG queued behind the connection's data. rtt_samples
        # counts them; the acceptance judges L4 only from a declared count.
        q = [r["last_ms"] - r["min_ms"] for r in on if r["last_ms"] is not None and r["min_ms"] is not None]
        parts.append("rtt_samples=%d" % len(q))
        parts.append("rtt_queue_ms_p50=%s rtt_queue_ms_p90=%s" % (pct(q, 50) if q else "na", pct(q, 90) if q else "na"))
        pb = [r["last_ms"] for r in rtt["before"] if r["last_ms"] is not None]
        parts.append("last_ms_before_p50=%s" % (pct(pb, 50) if pb else "na"))
    if all(p.endswith("=na->na") for p in parts[:5]) and not rtt["during"]:
        return "unavailable", "no_latency_samples"
    return "info", " ".join(parts)


def queue_rows(lines, flows, load_from, load_to, cap=None):
    """v35: load_queue's detail from the pool_queue, pool_rtt and flow_queue
    lines of the load."""
    end = load_to + datetime.timedelta(seconds=BULK_TAIL_S)
    per, mins = {}, {}
    queues = []
    last_bulk = {}
    for t, _stamp, event, fields in lines:
        conn = re.sub(r"[^a-z0-9_-]", "", fields.get("conn", "")) or "?"
        if event in RTT_EVENTS and load_from <= t <= load_to:
            m = number(fields.get("min_ms"))
            if m:
                mins.setdefault(conn, []).append(m)
        elif event == POOL_QUEUE and load_from <= t <= load_to:
            per.setdefault(conn, []).append({"q": number(fields.get("q_ms")),
                                             "held": number(fields.get("held_kib")),
                                             "extra": number(fields.get("extra_kib"))})
        elif event == FLOW_BULK and load_from <= t <= end:
            last_bulk[conn] = number(fields.get("kib"))
        elif event == FLOW_QUEUE and load_from <= t <= end:
            m = BINS.match(fields.get("q_bins", ""))
            queues.append({"conn": conn, "kib": last_bulk.pop(conn, None),
                           "bins": tuple(int(x) for x in m.groups()) if m else None,
                           "grows": number(fields.get("grows")), "resets": fields.get("resets", "?")})
    bulk = {f["conn"] for f in flows}
    conns = sorted((c for c in per if not bulk or c in bulk), key=lambda c: (len(c), c))
    if not conns and not queues:
        return "unavailable", "no_pool_queue_lines"
    parts = ["conns=%d" % len(conns)]
    for c in conns:
        rs = per[c]
        q = [r["q"] for r in rs if r["q"] is not None]
        held = [r["held"] for r in rs if r["held"] is not None]
        extra = [r["extra"] for r in rs if r["extra"] is not None]
        low = min(mins.get(c, []), default=None)
        ratio = [(low + x) / low for x in q] if low else []
        standing = [r for r in rs if r["q"] is not None and r["extra"] is not None]
        sx = (100.0 * sum(1 for r in standing if r["extra"] > 0 and r["q"] >= Q_SHRINK_MS) / len(standing)
              if standing else None)
        parts.append("%s:q%s/%s:held%s/%s:x%s:bdp%s/%s:sx%s" % (
            c, pct(q, 50) if q else "na", pct(q, 90) if q else "na",
            pct(held, 50) if held else "na", pct(held, 90) if held else "na",
            max(extra) if extra else "na",
            fmt(pct(ratio, 50), 1) if ratio else "na", fmt(pct(ratio, 90), 1) if ratio else "na",
            fmt(sx, 0)))
    if cap is not None:
        mine = [f for f in queues if f["kib"] is not None and f["kib"] * 1024 >= cap]
    else:
        mine = queues
    parts.append("load_flows=" + (",".join(
        "%s:%s:g%s:r%s" % (f["conn"], "-".join(str(b) for b in f["bins"]) if f["bins"] else "na",
                           "na" if f["grows"] is None else f["grows"], re.sub(r"[^0-9-]", "", f["resets"]) or "na")
        for f in mine) or "none"))
    return "info", " ".join(parts)


def takes_rows(lines, load_from, load_to):
    """v35: load_takes's detail from the pool_take lines of the load."""
    recs = []
    for t, _stamp, event, fields in lines:
        if event != POOL_TAKE or not (load_from <= t <= load_to):
            continue
        n, queued = number(fields.get("n")), number(fields.get("queued"))
        m = PAIR.match(fields.get("conns_queued", ""))
        if n is None or queued is None:
            continue
        recs.append((n, queued, (int(m.group(1)), int(m.group(2))) if m else None))
    if not recs:
        return "unavailable", "no_pool_take_lines"
    n = sum(r[0] for r in recs)
    queued = sum(r[1] for r in recs)
    most = max((r[2] for r in recs if r[2] is not None), default=None)
    return "info", "lines=%d n=%d queued=%d share=%s conns_queued_max=%s" % (
        len(recs), n, queued, fmt(queued / n if n else None, 2), "%d-%d" % most if most else "na")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--endurance-log")
    ap.add_argument("--provider-log")
    ap.add_argument("--load-log")
    ap.add_argument("--window-from")
    ap.add_argument("--load-from")
    ap.add_argument("--load-to")
    ap.add_argument("--filter-before")
    ap.add_argument("--filter-after")
    ap.add_argument("--results")
    ap.add_argument("--ring-slots", type=int, default=64)
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2
    if args.endurance_log is not None:
        try:
            verdict, detail = endurance_window(read_lines(args.endurance_log))
        except Exception as error:   # an info row never fails the window
            verdict, detail = "unavailable", "review_error:%s" % type(error).__name__
        print("%s\t%s\t%s" % (ENDURANCE_ROW, verdict, detail.replace("\t", " ")[:600]))
        return 0
    load_args = (args.provider_log, args.load_log, args.window_from, args.load_from, args.load_to,
                 args.filter_before, args.filter_after, args.results)
    if any(a is None for a in load_args):
        print("load_review.py: the load rows need every --provider-log .. --results argument", file=sys.stderr)
        return 2
    window_from, load_from, load_to = when(args.window_from), when(args.load_from), when(args.load_to)
    if window_from is None or load_from is None or load_to is None:
        for name in ROWS:
            print("%s\tunavailable\tload_span_unreadable" % name)
        return 0
    lines = read_lines(args.provider_log)
    # The window's read may have been cut off at its bound; the load's own
    # read then still holds the lines of the load.
    if not any(load_from <= t <= load_to for t, _s, _e, _f in lines):
        lines = sorted(lines + read_lines(args.load_log), key=lambda x: x[0])
    rows = result_rows(args.results)
    flows = bulk_flows(lines, load_from, load_to)
    out = []
    for name, fn in (("load_filter_series", lambda: filter_series(lines, window_from, load_from, load_to)),
                     ("load_outbound_drops", lambda: outbound_drops(args.filter_before, args.filter_after,
                                                                    args.ring_slots)),
                     ("load_placement", lambda: placement(flows, stream_cap(rows))),
                     ("load_window", lambda: stream_window(lines, load_from, load_to)),
                     ("load_latency", lambda: latency(lines, rows, flows, window_from, load_from, load_to)),
                     ("load_queue", lambda: queue_rows(lines, flows, load_from, load_to, stream_cap(rows))),
                     ("load_takes", lambda: takes_rows(lines, load_from, load_to))):
        try:
            verdict, detail = fn()
        except Exception as error:   # an info row never stops the others
            verdict, detail = "unavailable", "review_error:%s" % type(error).__name__
        out.append("%s\t%s\t%s" % (name, verdict, detail.replace("\t", " ")[:600]))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
