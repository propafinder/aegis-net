#!/usr/bin/env python3
"""B-06 v35: the paired A/B of the v35 stream window against v33's fixed
window (docs/platforms/macos/v35-load-acceptance.md, the plan in
docs/platforms/macos/v35-ab-plan.json).

System python 3.9, stdlib only; the t quantiles are embedded. Three
subcommands:

- `check-plan --plan P`: the plan is exactly the declared one (shape, order
  and every number). Exit 0 when it is, 1 with one reason per line
  otherwise.
- `next --plan P --receipts DIR [--cert-status F] [--now ISO]`: the next
  declared step, as one line `next=<name> kind=<sentinel|window> arm=<c|t|
  none> env=<K=V,...>` (`reason=` says why when it is a re-run), or
  `refuse:<reason>`. The window wrapper takes every name from here. It
  refuses when `renew_at` (from F, the host's --cert-status output) is
  less than the plan's margin after now, or the state is not valid; when
  the series stopped (`refuse:series_stopped:<reason>:<window>`: a
  window_policy failure, a connected A/B window without the row or with
  another arm's mode, or a control-arm start refused or never connected);
  and once everything ran. The interim is taken once, on the first
  `interim_at` valid pairs: GAIN or REGRESSION there offers only the coda.
  A pair's second window is offered only while it can still start (after
  the plan's idle) within the plan's gap of the first; otherwise the
  attempt is invalid and the re-run comes next. After the coda, a declared
  W2 retry when window-v35-w2-r1 is invalid for a declared reason.
- `analyze --plan P --receipts DIR [--sentinels DIR]`: every declared
  window's numbers, each pair's validity, the statistics and the declared
  verdict, as one JSON object; its last line is `verdict=<V> n=<pairs in
  the deciding look> look=<interim|final|none>`.

A receipt is two directories in DIR: `<name>/` (the harness's OUT:
results.tsv, load-stream.<i>, provider.log) and `<name>.side/` (the
wrapper's: run.txt, and optionally relay-ss.txt and mac-sockq.txt). run.txt
holds whitespace-separated `key=value` tokens on any line; read here:
window, arm, env (comma-joined K=V), build, source, owner_head, start and
end (UTC ISO 8601), host_free (1 or 0), idle_s, renew_at (UTC ISO 8601),
and invalid (a declared reason, written only by the operator: an abort, a
host-free breach found afterwards). A sentinel's `<name>/summary.txt`
holds `single1 ... mbit=<x>` and `parallel_total ... mbit=<x>` lines. The
series ends when every declared pair is valid or missing, when the interim
stops it, or when the operator writes `DIR/series-end.txt` with
`reason=<deadline|host_not_free|operator_stop>`.

Per window: S = the sum over its streams of bytes_i / elapsed_i, where a
stream that delivered exactly the plan's stream_bytes within stream_bound_s
uses its own t1 - t0 and any other (short, failed, missing) counts bytes_i
/ stream_bound_s; A = the bytes of all streams over the makespan (from the
first t0 to the last complete stream's t1, or stream_bound_s when any
stream is incomplete); both at least the plan's floor_bytes_per_s (a
floored window is listed); the S24b verdict (the W2.1 rows pass and W2.2's
memory); the latency rows; window_policy. A pair is invalid only for the
plan's declared external or procedural reasons; anything after the connect
is an observation. Statistics, per look: d = ln(S_T / S_C) and ln(A_T /
A_C) per valid pair, their mean, SD and the t-based CI exp(mean +/- t x SD
/ sqrt(n)); the latency rows the same on ln(T / C); S24b by the exact
one-sided sign test on the discordant pairs (T failed, C passed against
the reverse). Exit 0 whenever it printed, 2 for bad arguments, 1 for a
plan that check-plan refuses.

v36 (docs/platforms/macos/v36-load-acceptance.md, plan v36-ab-r1 in
docs/platforms/macos/v36-ab-plan.json; v35-ab-r2 is unchanged). check-plan
accepts exactly one of the two declared plans. With v36-ab-r1: `next`
offers the declared renewal window (kind=renewal, no load) when the
identity is inside the renew margin and due, refuses at or after the
plan's deadline, gives each W2 gate window its arm, retries a W2 gate
window invalid for a declared reason once right after the prelude, and
stops at the interim only on REGRESSION. A window is also invalid
(`relay_condition`) unless run.txt's `relay_cond` (and `relay_cond_after`
when present) is exactly the plan's relay condition. `analyze` adds each
row's own verdict (`rows`), the W2 gate per arm (`w2_gate`) and the
default window policy (`default_policy`: adaptive only on GAIN or
NON_INFERIOR in every default row at the final look); its last line
carries `default=<adaptive|fixed>`.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
import re
import statistics
import sys

# Student's t, two-sided 95% (0.975) and 99% (0.995), df 1..30.
T975 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145,
        2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048,
        2.045, 2.042]
T995 = [63.657, 9.925, 5.841, 4.604, 4.032, 3.707, 3.499, 3.355, 3.250, 3.169, 3.106, 3.055, 3.012, 2.977,
        2.947, 2.921, 2.898, 2.878, 2.861, 2.845, 2.831, 2.819, 2.807, 2.797, 2.787, 2.779, 2.771, 2.763,
        2.756, 2.750]

DECLARED_ORDER = ["ct", "tc", "tc", "ct", "tc", "ct", "ct", "tc", "tc", "ct", "ct", "tc", "ct", "tc", "tc", "ct"]
# v36: 20 pairs in five blocks of four, each block balanced (B A A B A with
# A = ct tc tc ct and B = tc ct ct tc), so the W2 gate's t c t c runs on
# into t c of pair 01.
V36_ORDER = ["tc", "ct", "ct", "tc", "ct", "tc", "tc", "ct", "ct", "tc", "tc", "ct", "tc", "ct", "ct", "tc",
             "ct", "tc", "tc", "ct"]
LATENCY_ROWS = ("burst90_s", "tcp_echo_ms", "hs_p90_ms", "rtt_queue_p50_ms", "rtt_queue_p90_ms")
# v35 review: the whole plan as declared (every number pinned here too, so
# an edited plan file is refused rather than changing a verdict).
DECLARED_PLAN = {
    "plan": "v35-ab-r2",
    "acceptance": "docs/platforms/macos/v35-load-acceptance.md",
    "window_name": "window-v35-ab{pair:02d}-{arm}-r{attempt}",
    "arms": {"c": {"WINDOW_POLICY": "fixed", "expect": "fixed"}, "t": {"WINDOW_POLICY": "", "expect": "adaptive"}},
    "env": {"LOAD": "1"},
    "pairs": DECLARED_ORDER,
    "prelude": ["path-probe-v35-s1-r1", "window-v35-w2-r1", "window-v35-w1-r1"],
    "sentinel_after_pairs": {"4": "path-probe-v35-s2-r1", "8": "path-probe-v35-s3-r1", "12": "path-probe-v35-s4-r1"},
    "coda": ["path-probe-v35-s5-r1", "window-v35-w3-r1"],
    "w2_retry": ["path-probe-v35-w2r2-r1", "window-v35-w2-r2"],
    "w2_retry_reasons": ["host_free_breach", "harness_fault_before_connect", "identity_renewal", "operator_abort"],
    "invalid_reasons": ["host_free_breach", "idle_short", "harness_fault_before_connect", "pair_gap",
                        "identity_renewal", "renew_margin", "build_or_env_mismatch", "operator_abort"],
    "series_end_reasons": ["deadline", "host_not_free", "operator_stop"],
    "idle_before_s": 180,
    "pair_start_gap_max_s": 900,
    "pair_reruns_max": 2,
    "n_min": 8,
    "n_max": 16,
    "interim_at": 8,
    "final_n_min": 12,
    "alpha": {"interim": 0.01, "final": 0.05},
    "gain_lower": {"interim": 1.15, "final": 1.10},
    "noninferior_lower": 0.90,
    "aggregate_noninferior_lower": 0.90,
    "sign_min_fraction": 0.75,
    "latency_primary": "burst90_s",
    "latency_secondary": ["tcp_echo_ms", "hs_p90_ms", "rtt_queue_p50_ms", "rtt_queue_p90_ms"],
    "latency_margin": 1.25,
    "latency_missing_max": 2,
    "rtt_samples_min": 10,
    "s24b_block_p": 0.10,
    "floor_bytes_per_s": 1024,
    "stream_bytes": 52428800,
    "stream_bound_s": 180,
    "renew_margin_s": 2700,
}
V36_W2 = {"window-v36-w2t1-r1": "t", "window-v36-w2c1-r1": "c", "window-v36-w2t2-r1": "t", "window-v36-w2c2-r1": "c"}
# v36 (docs/platforms/macos/v36-load-acceptance.md): the same build 35 and
# the same paired protocol under the relay condition R1-R3, with the W2 gate
# on both arms and the default-policy rule. v35's numbers are kept; the
# additions are the keys after renew_margin_s.
DECLARED_V36 = {
    "plan": "v36-ab-r1",
    "acceptance": "docs/platforms/macos/v36-load-acceptance.md",
    "window_name": "window-v36-ab{pair:02d}-{arm}-r{attempt}",
    "arms": {"c": {"WINDOW_POLICY": "fixed", "expect": "fixed"}, "t": {"WINDOW_POLICY": "", "expect": "adaptive"}},
    "env": {"LOAD": "1"},
    "pairs": V36_ORDER,
    "prelude": ["path-probe-v36-s1-r1"] + list(V36_W2),
    "sentinel_after_pairs": {"5": "path-probe-v36-s2-r1", "10": "path-probe-v36-s3-r1", "15": "path-probe-v36-s4-r1"},
    "coda": ["path-probe-v36-s5-r1"],
    "w2_retry": {name: name[:-1] + "2" for name in V36_W2},
    "w2_retry_reasons": ["host_free_breach", "idle_short", "harness_fault_before_connect", "identity_renewal",
                         "renew_margin", "build_or_env_mismatch", "relay_condition", "operator_abort"],
    "invalid_reasons": ["host_free_breach", "idle_short", "harness_fault_before_connect", "pair_gap",
                        "identity_renewal", "renew_margin", "build_or_env_mismatch", "relay_condition",
                        "operator_abort"],
    "series_end_reasons": ["deadline", "host_not_free", "operator_stop"],
    "idle_before_s": 180,
    "pair_start_gap_max_s": 900,
    "pair_reruns_max": 2,
    "n_min": 8,
    "n_max": 20,
    "interim_at": 8,
    "final_n_min": 12,
    "alpha": {"interim": 0.01, "final": 0.05},
    "gain_lower": {"interim": 1.15, "final": 1.10},
    "noninferior_lower": 0.90,
    "aggregate_noninferior_lower": 0.90,
    "sign_min_fraction": 0.75,
    "latency_primary": "burst90_s",
    "latency_secondary": ["tcp_echo_ms", "hs_p90_ms", "rtt_queue_p50_ms", "rtt_queue_p90_ms"],
    "latency_margin": 1.25,
    "latency_missing_max": 2,
    "rtt_samples_min": 10,
    "s24b_block_p": 0.10,
    "floor_bytes_per_s": 1024,
    "stream_bytes": 52428800,
    "stream_bound_s": 180,
    "renew_margin_s": 2700,
    "prelude_arms": V36_W2,
    "w2_valid_min_per_arm": 2,
    "w2_bounds": {"burst24_s": 2.9, "burst90_s": 6.6, "hs_p50_ms": 770, "hs_p90_ms": 1150, "echo_ms_floor": 1100,
                  "echo_warm_factor": 1.3, "rtt_queue_p50_ms": 100, "rtt_queue_p90_ms": 250,
                  "rss_growth_kib": 11264},
    "interim_stops": ["REGRESSION"],
    "renewal_name": "window-v36-renew-r{attempt}",
    "renewal_attempts_max": 3,
    "renewal_due_skew_s": 60,
    "relay_condition": "cc:bbr,default_qdisc:fq,root_qdisc:fq,notsent_lowat:131072",
    "deadline_utc": "2026-10-29T01:10:00Z",
    "default_rows": ["throughput", "aggregate", "burst90_s", "tcp_echo_ms", "hs_p90_ms", "s24b", "w2"],
    "regression_only_rows": ["rtt_queue_p50_ms", "rtt_queue_p90_ms"],
}
DECLARED_PLANS = {DECLARED_PLAN["plan"]: DECLARED_PLAN, DECLARED_V36["plan"]: DECLARED_V36}
PLAN_KEYS = tuple(DECLARED_PLAN)
S24B_ROWS = ("load_download", "load_concurrent", "load_connected_throughout", "load_flow_burst_24",
             "load_flow_burst_90", "load_tcp_echo_v4", "load_udp_echo_v4", "disconnect_verified",
             "filter_armed_span")
RSS_LIMIT_KIB = 11264


def t_quantile(df, alpha):
    table = T995 if alpha <= 0.01 else T975
    return table[min(max(df, 1), len(table)) - 1]


def parse_utc(text):
    if not text:
        return None
    text = text.strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return datetime.datetime.strptime(text, fmt).astimezone(datetime.timezone.utc)
        except ValueError:
            continue
    return None


# ------------------------------------------------------------------ plan
def load_plan(path):
    with open(path) as f:
        return json.load(f)


def check_plan(plan):
    """The plan is exactly one declared plan (v35-ab-r2 or v36-ab-r1, chosen
    by its `plan` value; any other name is compared with v35's)."""
    declared = DECLARED_PLANS.get(plan.get("plan"), DECLARED_PLAN) if isinstance(plan, dict) else DECLARED_PLAN
    keys = tuple(declared)
    errors = []
    for key in keys:
        if key not in plan:
            errors.append("missing:%s" % key)
    if errors:
        return errors
    for key in sorted(set(plan) - set(keys)):
        errors.append("unknown:%s" % key)
    if plan["pairs"] != declared["pairs"]:
        errors.append("pairs_not_declared_order")
    if set(plan["arms"]) != {"c", "t"}:
        errors.append("arms_not_c_t")
    elif plan["arms"] != declared["arms"]:
        errors.append("arms_not_declared")
    for key in keys:
        if key not in ("pairs", "arms") and plan[key] != declared[key]:
            errors.append("value_not_declared:%s" % key)
    return errors


def binom_upper(b, m):
    """P(X >= b) for X ~ Binomial(m, 1/2): the exact one-sided sign test of
    b discordant pairs going one way out of m (1.0 when m is 0)."""
    if m <= 0:
        return 1.0
    return sum(math.comb(m, k) for k in range(b, m + 1)) / 2 ** m


def window_name(plan, pair, arm, attempt):
    return plan["window_name"].format(pair=pair, arm=arm, attempt=attempt)


# ------------------------------------------------------------- receipts
def slurp(path):
    with open(path, errors="replace") as f:
        return f.read()


def read_run(side):
    run = {}
    try:
        text = slurp(os.path.join(side, "run.txt"))
    except OSError:
        return None
    for tok in text.split():
        k, sep, v = tok.partition("=")
        if sep and k and k not in run:
            run[k] = v
        elif sep and k in ("end", "exit"):
            run[k] = v
    return run


def read_results(out):
    rows = {}
    try:
        text = slurp(os.path.join(out, "results.tsv")).splitlines()
    except OSError:
        return None
    for line in text:
        f = line.split("\t")
        if len(f) >= 3:
            rows[f[0]] = (f[1], f[2])
    return rows


def read_streams(out, count):
    streams = []
    for i in range(1, count + 1):
        rec = {"bytes": 0, "t0": None, "t1": None}
        try:
            text = slurp(os.path.join(out, "load-stream.%d" % i))
        except OSError:
            streams.append(rec)
            continue
        for tok in text.split():
            k, sep, v = tok.partition("=")
            if not sep:
                continue
            if k == "bytes" and v.isdigit():
                rec["bytes"] = int(v)
            elif k in ("t0", "t1"):
                try:
                    rec[k] = float(v)
                except ValueError:
                    pass
        streams.append(rec)
    return streams


def complete(s, stream_bytes, bound_s):
    el = (s["t1"] - s["t0"]) if s["t0"] is not None and s["t1"] is not None else None
    return s["bytes"] == stream_bytes and el is not None and 0 < el <= bound_s


def stream_rates(streams, stream_bytes, bound_s):
    rates = []
    for s in streams:
        if complete(s, stream_bytes, bound_s):
            rates.append(s["bytes"] / (s["t1"] - s["t0"]))
        else:
            rates.append(s["bytes"] / bound_s)
    return rates


def aggregate_rate(streams, stream_bytes, bound_s):
    """v35 review: every stream's bytes over the window's makespan: from the
    first t0 to the last complete stream's t1, or stream_bound_s once any
    stream is incomplete (short, failed, missing, past the bound). With
    every stream complete it is load_throughput's total_mbit_s."""
    total = sum(s["bytes"] for s in streams)
    starts = [s["t0"] for s in streams if s["t0"] is not None]
    if not streams or not starts or not all(complete(s, stream_bytes, bound_s) for s in streams):
        return total / bound_s
    span = max(s["t1"] for s in streams) - min(starts)
    return total / span if span > 0 else total / bound_s


def field(detail, name):
    m = re.search(r"(?:^| )%s=([^ ]+)" % re.escape(name), detail or "")
    return m.group(1) if m else None


def arrow_after(value):
    if value is None:
        return None
    after = value.split("->")[-1]
    try:
        return float(after)
    except ValueError:
        return None


def latency_values(rows, rtt_min):
    out = {}
    m = re.match(r"^[0-9]+/[0-9]+ ([0-9.]+)s$", rows.get("load_flow_burst_90", ("", ""))[1])
    out["burst90_s"] = float(m.group(1)) if m else None
    m = re.match(r"^[0-9]+/([0-9]+)/[a-z_]+$", rows.get("load_tcp_echo_v4", ("", ""))[1])
    out["tcp_echo_ms"] = float(m.group(1)) if m else None
    lat = rows.get("load_latency", ("", ""))[1]
    out["hs_p90_ms"] = arrow_after(field(lat, "hs_p90_ms_max"))
    samples = field(lat, "rtt_samples")
    enough = samples is not None and samples.isdigit() and int(samples) >= rtt_min
    for key, name in (("rtt_queue_p50_ms", "rtt_queue_ms_p50"), ("rtt_queue_p90_ms", "rtt_queue_ms_p90")):
        v = field(lat, name)
        out[key] = float(v) if enough and v not in (None, "na") else None
    return out


def bound_values(rows):
    """v36: the W2 latency-bound inputs of a window (L1 to L3 always, L4 with
    its sample count), from results.tsv; None where a row is missing."""
    def burst(name):
        m = re.match(r"^[0-9]+/[0-9]+ ([0-9.]+)s$", rows.get(name, ("", ""))[1])
        return float(m.group(1)) if m else None

    def echo(name):
        m = re.match(r"^[0-9]+/([0-9]+)/[a-z_]+$", rows.get(name, ("", ""))[1])
        return float(m.group(1)) if m else None
    lat = rows.get("load_latency", ("", ""))[1]
    samples = field(lat, "rtt_samples")
    return {"burst24_s": burst("load_flow_burst_24"), "burst90_s": burst("load_flow_burst_90"),
            "hs_p50_ms": arrow_after(field(lat, "hs_p50_ms_max")), "hs_p90_ms": arrow_after(field(lat, "hs_p90_ms_max")),
            "echo_ms": echo("load_tcp_echo_v4"), "echo_warm_ms": echo("tcp_echo_v4_warm"),
            "rtt_samples": int(samples) if samples and samples.isdigit() else 0,
            "rtt_queue_p50_ms": num(field(lat, "rtt_queue_ms_p50")),
            "rtt_queue_p90_ms": num(field(lat, "rtt_queue_ms_p90"))}


def w2_items(plan, rec, arm):
    """v36: the W2 items one window failed (an empty list: it passed): the
    S24b rows and memory (W2.1, W2.2), its arm's window_policy, and L1 to L4
    (L4 judged only with the plan's sample count; else unavailable, neither
    passed nor failed)."""
    b = plan["w2_bounds"]
    v = rec["bounds"]
    failed = list(rec["s24b_failed"])
    if rec["window_policy"] != "pass" or field(rec["window_policy_detail"], "expected") != plan["arms"][arm]["expect"]:
        failed.append("window_policy")
    for key, limit, item in (("burst24_s", b["burst24_s"], "L1_burst24"), ("burst90_s", b["burst90_s"], "L1_burst90"),
                             ("hs_p50_ms", b["hs_p50_ms"], "L2_hs_p50"), ("hs_p90_ms", b["hs_p90_ms"], "L2_hs_p90")):
        if v[key] is None or v[key] > limit:
            failed.append(item)
    warm = v["echo_warm_ms"]
    limit = max(b["echo_ms_floor"], b["echo_warm_factor"] * warm) if warm is not None else b["echo_ms_floor"]
    if v["echo_ms"] is None or v["echo_ms"] > limit:
        failed.append("L3_echo")
    if v["rtt_samples"] >= plan["rtt_samples_min"]:
        if v["rtt_queue_p50_ms"] is None or v["rtt_queue_p50_ms"] > b["rtt_queue_p50_ms"]:
            failed.append("L4_p50")
        if v["rtt_queue_p90_ms"] is None or v["rtt_queue_p90_ms"] > b["rtt_queue_p90_ms"]:
            failed.append("L4_p90")
    return failed


def s24b(rows, run):
    """The W2.1 rows and W2.2's memory, for an A/B window (window_policy is
    its validity, judged apart)."""
    if rows is None:
        return False, ["no_results"]
    missing = [r for r in S24B_ROWS if rows.get(r, ("", ""))[0] != "pass"]
    rss = rows.get("load_provider_rss", ("", ""))[1]
    growth = field(rss, "growth_kib")
    if growth is None or not growth.isdigit() or int(growth) > RSS_LIMIT_KIB:
        missing.append("load_provider_rss")
    pid, before = field(rss, "pid"), (run or {}).get("provider_pid_before")
    if pid and before and before.isdigit() and pid != before:
        missing.append("provider_process_changed")
    return not missing, missing


def provider_refused_policy(out):
    """Whether the provider refused the start for its window-policy option
    (`start_refused window_policy_refused`): the control arm's mechanism."""
    try:
        with open(os.path.join(out, "provider.log"), errors="replace") as f:
            return any("start_refused window_policy_refused" in line for line in f)
    except OSError:
        return False


def window_record(plan, receipts, name):
    out, side = os.path.join(receipts, name), os.path.join(receipts, name + ".side")
    run = read_run(side)
    if run is None:
        return None
    rows = read_results(out)
    pre = (rows or {}).get("load_preflight", ("", ""))[1]
    count = int(field(pre, "streams")) if field(pre, "streams") and field(pre, "streams").isdigit() else 4
    streams = read_streams(out, count)
    rates = stream_rates(streams, plan["stream_bytes"], plan["stream_bound_s"])
    floor = plan["floor_bytes_per_s"]
    S = sum(rates) if rates else 0.0
    A = aggregate_rate(streams, plan["stream_bytes"], plan["stream_bound_s"])
    ok, failed = s24b(rows, run)
    policy = (rows or {}).get("window_policy")
    thr = (rows or {}).get("load_throughput", ("", ""))[1]
    env = dict(kv.partition("=")[::2] for kv in run.get("env", "").split(",") if "=" in kv)
    connected = (rows or {}).get("connected")
    return {
        "name": name, "run": run, "complete": rows is not None,
        # The harness reached its connect (the row is written either way),
        # and the tunnel connected.
        "reached_connect": connected is not None, "tunnel_connected": connected is not None and connected[0] == "1",
        "start_refused_policy": provider_refused_policy(out),
        "start": parse_utc(run.get("start")), "env": env, "build": run.get("build"),
        "owner_head": run.get("owner_head"), "source": run.get("source"),
        "S": max(S, floor), "A": max(A, floor), "floored": S < floor or A < floor,
        "slowest": min(rates) if rates else 0.0,
        "total_mbit_s": num(field(thr, "total_mbit_s")),
        "s24b": ok, "s24b_failed": failed,
        "window_policy": policy[0] if policy else "missing",
        "window_policy_detail": policy[1] if policy else "",
        "above_initial": field((rows or {}).get("load_window", ("", ""))[1], "above_initial"),
        "latency": latency_values(rows or {}, plan["rtt_samples_min"]),
        "renewal_attempts": num(field((rows or {}).get("window_session_summary", ("", ""))[1], "renewal_attempts")),
        "renew_at": parse_utc(run.get("renew_at")),
        "bounds": bound_values(rows or {}),
        "relay_cond": run.get("relay_cond"), "relay_cond_after": run.get("relay_cond_after"),
        "side": side,
    }


def num(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def arm_env_ok(plan, rec, arm):
    want = plan["arms"][arm]["WINDOW_POLICY"]
    return rec["env"].get("WINDOW_POLICY", "") == want and all(
        rec["env"].get(k) == v for k, v in plan["env"].items())


def window_invalid(plan, rec, arm):
    """The declared external or procedural reasons one window is invalid, in
    the order found (v36: and the relay condition, when the plan declares
    one: the wrapper's read-only check before the window, and after it when
    it was read, must show exactly the declared value)."""
    reasons = []
    run = rec["run"]
    if run.get("invalid") in plan["invalid_reasons"]:
        reasons.append(run["invalid"])
    if run.get("host_free") != "1":
        reasons.append("host_free_breach")
    idle = run.get("idle_s")
    if idle is None or not idle.isdigit() or int(idle) < plan["idle_before_s"]:
        reasons.append("idle_short")
    if not rec["reached_connect"]:
        reasons.append("harness_fault_before_connect")
    if not arm_env_ok(plan, rec, arm):
        reasons.append("build_or_env_mismatch")
    if rec["renewal_attempts"]:
        reasons.append("identity_renewal")
    if rec["renew_at"] is None or rec["start"] is None or \
            (rec["renew_at"] - rec["start"]).total_seconds() < plan["renew_margin_s"]:
        reasons.append("renew_margin")
    want = plan.get("relay_condition")
    if want is not None and (rec["relay_cond"] != want
                             or rec["relay_cond_after"] not in (None, want)):
        reasons.append("relay_condition")
    return reasons


def invalid_reasons(plan, first, second, arms):
    """The declared external or procedural reasons this attempt is invalid
    (an empty list: valid)."""
    reasons = []
    for rec, arm in ((first, arms[0]), (second, arms[1])):
        reasons.extend(window_invalid(plan, rec, arm))
    if first["start"] is None or second["start"] is None or \
            (second["start"] - first["start"]).total_seconds() > plan["pair_start_gap_max_s"]:
        reasons.append("pair_gap")
    for key in ("build", "owner_head", "source"):
        if first[key] != second[key]:
            reasons.append("build_or_env_mismatch")
    strip = lambda env: {k: v for k, v in env.items() if k != "WINDOW_POLICY"}
    if strip(first["env"]) != strip(second["env"]):
        reasons.append("build_or_env_mismatch")
    if first["renew_at"] != second["renew_at"]:
        reasons.append("identity_renewal")
    seen, out = set(), []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


# ---------------------------------------------------------------- pairs
def pair_attempts(plan, receipts, k):
    """Every attempt of pair k (1-based) as dicts: attempt, windows {arm:
    record or None}, order, status (valid, invalid, incomplete), reasons."""
    order = plan["pairs"][k - 1]
    out = []
    for attempt in range(1, plan["pair_reruns_max"] + 2):
        recs = {arm: window_record(plan, receipts, window_name(plan, k, arm, attempt)) for arm in order}
        if recs[order[0]] is None and recs[order[1]] is None:
            break
        rec = {"attempt": attempt, "order": order, "windows": recs}
        if recs[order[0]] is None or recs[order[1]] is None:
            rec.update(status="incomplete", reasons=[])
        else:
            reasons = invalid_reasons(plan, recs[order[0]], recs[order[1]], order)
            rec.update(status="invalid" if reasons else "valid", reasons=reasons)
        out.append(rec)
    return out


def window_stop(plan, rec, arm):
    """Why this A/B window stops the series (its arm label or the control
    mechanism cannot be trusted), or None."""
    if rec is None or not rec["complete"]:
        return None
    if rec["start_refused_policy"]:
        return "control_start_refused"
    if not rec["reached_connect"]:
        return None
    if not rec["tunnel_connected"]:
        # A treatment window that never connected is an observation (an
        # S24b FAIL); a control window that never connected may be the
        # fixed-start option itself failing.
        return "control_not_connected" if arm == "c" else None
    if rec["window_policy"] == "missing":
        return "window_policy_missing"
    if rec["window_policy"] != "pass":
        return "window_policy_" + re.sub(r"[^a-z_]", "", rec["window_policy"])
    if field(rec["window_policy_detail"], "expected") != plan["arms"][arm]["expect"]:
        return "window_policy_arm_mismatch"
    return None


def stop_reason(plan, receipts):
    """The first A/B window, in declared order, that stops the series, as
    (window, reason), or None. v36: the W2 gate windows first, by the same
    rule (each has an arm)."""
    for name, arm in plan.get("prelude_arms", {}).items():
        for n, rec in w2_attempts(plan, receipts, name):
            why = window_stop(plan, rec, arm)
            if why:
                return n, why
    for k in range(1, len(plan["pairs"]) + 1):
        for att in pair_attempts(plan, receipts, k):
            for arm in att["order"]:
                why = window_stop(plan, att["windows"][arm], arm)
                if why:
                    return att["windows"][arm]["name"], why
    return None


def ci(values, alpha):
    n = len(values)
    if n < 2:
        return None
    mean = statistics.mean(values)
    sd = statistics.stdev(values)
    half = t_quantile(n - 1, alpha) * sd / math.sqrt(n)
    return {"n": n, "mean": mean, "sd": sd, "ratio": math.exp(mean), "lower": math.exp(mean - half),
            "upper": math.exp(mean + half)}


def decide(plan, valid, look):
    """One look's verdict over `valid` (pairs with "C" and "T" window
    records, in declared order) at the plan's alpha for `look`."""
    n = len(valid)
    alpha = plan["alpha"][look]
    d = [math.log(p["T"]["S"] / p["C"]["S"]) for p in valid]
    d_agg = [math.log(p["T"]["A"] / p["C"]["A"]) for p in valid]
    thr, agg = ci(d, alpha), ci(d_agg, alpha)
    signs = sum(1 for x in d if x > 0)
    sign_min = int(math.ceil(plan["sign_min_fraction"] * n))
    rows = {}
    for row in LATENCY_ROWS:
        # A queue of 0 ms counts 1 ms, so its ratio is defined.
        vals = [math.log(max(p["T"]["latency"][row], 1.0) / max(p["C"]["latency"][row], 1.0)) for p in valid
                if p["T"]["latency"][row] is not None and p["C"]["latency"][row] is not None]
        missing = n - len(vals)
        rec = {"missing": missing}
        if missing > plan["latency_missing_max"] or len(vals) < 2:
            rec["available"] = False
        else:
            rec.update(available=True, **ci(vals, alpha))
            rec["regression"] = rec["lower"] > 1.0 and rec["ratio"] > plan["latency_margin"]
            rec["noninferior"] = rec["upper"] <= plan["latency_margin"]
        rows[row] = rec
    # S24b: the exact one-sided sign test on the discordant pairs.
    t_only = sum(1 for p in valid if p["C"]["s24b"] and not p["T"]["s24b"])
    c_only = sum(1 for p in valid if p["T"]["s24b"] and not p["C"]["s24b"])
    p_t = binom_upper(t_only, t_only + c_only)
    s24b = {"fail": {"c": sum(1 for p in valid if not p["C"]["s24b"]), "t": sum(1 for p in valid if not p["T"]["s24b"])},
            "t_only": t_only, "c_only": c_only, "p_t_worse": p_t, "regression": p_t <= alpha,
            "blocks": p_t <= plan["s24b_block_p"], "p_c_worse": binom_upper(c_only, t_only + c_only)}
    out = {"n": n, "look": look, "alpha": alpha, "throughput": thr, "aggregate": agg, "signs": signs,
           "sign_min": sign_min, "latency": rows, "s24b": s24b, "s24b_fail": s24b["fail"], "d": d, "d_aggregate": d_agg,
           "pairs": [p["pair"] for p in valid]}
    primary = rows[plan["latency_primary"]]
    regression = (thr["upper"] < 1.0 or agg["upper"] < 1.0
                  or any(r.get("regression") for r in rows.values() if r["available"]) or s24b["regression"])
    latency_ok = primary["available"] and primary["noninferior"]
    others_ok = latency_ok and agg["lower"] >= plan["aggregate_noninferior_lower"] and not s24b["blocks"]
    if regression:
        verdict = "REGRESSION"
    elif thr["lower"] > plan["gain_lower"][look] and signs >= sign_min and others_ok:
        verdict = "GAIN"
    elif look == "final" and thr["lower"] >= plan["noninferior_lower"] and others_ok:
        verdict = "NON_INFERIOR"
    else:
        verdict = "CONTINUE" if look == "interim" else "NO_RESOLVABLE_DIFFERENCE"
    out["verdict"] = verdict
    out["rows"] = row_verdicts(plan, out)
    return out


def row_verdicts(plan, out):
    """v36: each A/B row's own verdict at this look (GAIN, NON_INFERIOR,
    REGRESSION, UNRESOLVED or UNAVAILABLE), REGRESSION first. Throughput:
    GAIN when its lower bound is above the look's gain bound with the sign
    condition, NON_INFERIOR at a lower bound of at least noninferior_lower,
    REGRESSION at an upper bound below 1. Aggregate the same without the
    sign condition. A latency row: REGRESSION when its lower bound is above 1
    and its ratio above the margin, GAIN at an upper bound below 1,
    NON_INFERIOR at an upper bound of at most the margin. S24b: REGRESSION
    at p(T worse) of at most the look's alpha, GAIN at p(C worse) of at
    most it, NON_INFERIOR at p(T worse) above s24b_block_p."""
    look, alpha = out["look"], out["alpha"]
    rows = {}
    for key, ci_, signs in (("throughput", out["throughput"], True), ("aggregate", out["aggregate"], False)):
        if ci_ is None:
            rows[key] = "UNAVAILABLE"
        elif ci_["upper"] < 1.0:
            rows[key] = "REGRESSION"
        elif ci_["lower"] > plan["gain_lower"][look] and (not signs or out["signs"] >= out["sign_min"]):
            rows[key] = "GAIN"
        elif ci_["lower"] >= (plan["noninferior_lower"] if signs else plan["aggregate_noninferior_lower"]):
            rows[key] = "NON_INFERIOR"
        else:
            rows[key] = "UNRESOLVED"
    for key, r in out["latency"].items():
        if not r["available"]:
            rows[key] = "UNAVAILABLE"
        elif r["regression"]:
            rows[key] = "REGRESSION"
        elif r["upper"] < 1.0:
            rows[key] = "GAIN"
        elif r["noninferior"]:
            rows[key] = "NON_INFERIOR"
        else:
            rows[key] = "UNRESOLVED"
    s = out["s24b"]
    rows["s24b"] = ("REGRESSION" if s["p_t_worse"] <= alpha else "GAIN" if s["p_c_worse"] <= alpha
                    else "NON_INFERIOR" if s["p_t_worse"] > plan["s24b_block_p"] else "UNRESOLVED")
    return rows


def series_verdict(plan, valid, ended=None):
    """The declared looks over the valid pairs in declared order: the
    interim exactly once, on the first `interim_at` (GAIN or REGRESSION
    there is the verdict and stops the series); the final once the series
    ended (`ended`: why) with at least `final_n_min` valid pairs, over all
    of them. Before the end no other look is taken; a series that ended
    with fewer than `final_n_min` keeps the interim's verdict (cut short),
    and one with fewer than `n_min` is NO_CLAIM."""
    n_valid = len(valid)
    if n_valid < plan["n_min"]:
        return {"n": n_valid, "n_valid": n_valid, "look": "none", "verdict": "NO_CLAIM", "series_end": ended}
    interim = decide(plan, valid[:plan["interim_at"]], "interim")
    # v36: the interim stops the series only on REGRESSION (interim_stops).
    if interim["verdict"] in plan.get("interim_stops", ("GAIN", "REGRESSION")):
        out = dict(interim, n_valid=n_valid, series_end="interim_stop")
        return out
    if ended and n_valid >= plan["final_n_min"]:
        final = decide(plan, valid, "final")
        return dict(final, n_valid=n_valid, series_end=ended,
                    interim={"verdict": interim["verdict"], "n": interim["n"], "throughput": interim["throughput"]})
    return dict(interim, n_valid=n_valid, series_end=ended, cut_short=bool(ended))


def series_end(plan, receipts, pairs):
    """Why the series ended (`complete`: every declared pair valid or
    missing; or the operator's declared reason), or None."""
    try:
        text = slurp(os.path.join(receipts, "series-end.txt"))
    except OSError:
        text = ""
    reason = field(" ".join(text.split()), "reason")
    if reason in plan["series_end_reasons"]:
        return reason
    if pairs and all(p["status"] in ("valid", "missing") for p in pairs):
        return "complete"
    return None


def sentinel(dir_, name):
    rec = {"name": name}
    try:
        text = slurp(os.path.join(dir_, name, "summary.txt")).splitlines()
    except OSError:
        rec["missing"] = True
        return rec
    for line in text:
        f = line.split()
        if f and f[0] in ("single1", "parallel_total"):
            rec[f[0]] = num(field(line, "mbit"))
    return rec


def mechanism(rec):
    """The optional socket samples of one window (never a validity input)."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import relay_ss_review as rs
    except ImportError:
        return {"unavailable": "no_relay_ss_review"}
    out = {}
    for key, fname, fn in (("relay", "relay-ss.txt", rs.relay_review), ("mac", "mac-sockq.txt", rs.mac_review)):
        try:
            lines = rs.read(os.path.join(rec["side"], fname))
        except rs.Unmasked:
            out[key] = {"unavailable": "unmasked"}
            continue
        if not lines:
            out[key] = {"unavailable": "missing"}
            continue
        r = fn(lines)
        socks = r["sockets"]
        if key == "relay":
            bulk = [s for s in socks if s.get("bulk")]
            out[key] = {"bulk": len(bulk),
                        "loss_events_per_segment": [s["loss_events_per_segment"] for s in bulk],
                        "notsent_p50": [s["notsent_p50"] for s in bulk],
                        "notsent_p90": [s["notsent_p90"] for s in bulk],
                        # v36: the congestion control of the bulk sockets
                        # (bbr under R2) and their retransmissions.
                        "cc": sorted({c for s in bulk for c in s.get("cc", [])}),
                        "retrans_total": [s.get("retrans_total") for s in bulk]}
        else:
            out[key] = {"recvq_p90": [s["recvq_p90"] for s in socks]}
    return out


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def pair_table(plan, receipts):
    """Every declared pair in order: its attempts, its status (valid,
    missing: invalid on every allowed attempt, pending) and, when valid, the
    chosen attempt's windows; and the valid pairs in declared order."""
    pairs, valid = [], []
    for k in range(1, len(plan["pairs"]) + 1):
        atts = pair_attempts(plan, receipts, k)
        chosen = next((a for a in atts if a["status"] == "valid"), None)
        pairs.append({"pair": k, "order": plan["pairs"][k - 1],
                      "attempts": [{"attempt": a["attempt"], "status": a["status"], "reasons": a["reasons"]}
                                   for a in atts],
                      "status": "valid" if chosen else ("missing" if len(atts) > plan["pair_reruns_max"]
                                                        and all(a["status"] == "invalid" for a in atts)
                                                        else "pending")})
        if chosen:
            valid.append({"pair": k, "C": chosen["windows"]["c"], "T": chosen["windows"]["t"]})
    return pairs, valid


def strata(valid):
    """Valid pairs grouped by the identity's renew_at (a renewal between
    pairs starts a new stratum): reported beside the pooled analysis."""
    groups = {}
    for p in valid:
        groups.setdefault(iso(p["C"]["renew_at"]), []).append(p)
    out = []
    for renew_at, ps in sorted(groups.items(), key=lambda kv: kv[0] or ""):
        d = [math.log(p["T"]["S"] / p["C"]["S"]) for p in ps]
        out.append({"renew_at": renew_at, "pairs": [p["pair"] for p in ps], "n": len(ps),
                    "throughput": ci(d, 0.05)})
    return out


def w2_attempts(plan, receipts, name):
    """v36: a W2 gate window's attempts (r1 and its declared retry) as
    (name, record) for those that ran."""
    names = [name] + ([plan["w2_retry"][name]] if name in plan["w2_retry"] else [])
    return [(n, rec) for n, rec in ((n, window_record(plan, receipts, n)) for n in names) if rec is not None]


def w2_gate(plan, receipts):
    """v36: the W2 S24b gate per arm. Each declared W2 window counts by its
    first valid attempt (r1, else its retry); a window invalid on every
    attempt does not count. An arm PASSes when it has at least
    w2_valid_min_per_arm valid windows and every one of them passed every W2
    item; it FAILs when any valid window failed one; otherwise it is
    INCOMPLETE."""
    arms = {"c": {"windows": []}, "t": {"windows": []}}
    for name, arm in plan["prelude_arms"].items():
        entry = {"window": name, "attempts": []}
        for n, rec in w2_attempts(plan, receipts, name):
            reasons = window_invalid(plan, rec, arm)
            att = {"name": n, "valid": not reasons, "invalid": reasons}
            if not reasons:
                att["failed"] = w2_items(plan, rec, arm)
                att["pass"] = not att["failed"]
                att.update(total_mbit_s=rec["total_mbit_s"], latency=rec["bounds"], mechanism=mechanism(rec))
            entry["attempts"].append(att)
        chosen = next((a for a in entry["attempts"] if a["valid"]), None)
        entry["counted"] = chosen["name"] if chosen else None
        entry["pass"] = chosen["pass"] if chosen else None
        arms[arm]["windows"].append(entry)
    for arm, rec in arms.items():
        counted = [w for w in rec["windows"] if w["counted"]]
        rec["valid"] = len(counted)
        rec["failed_windows"] = [w["counted"] for w in counted if not w["pass"]]
        if rec["failed_windows"]:
            rec["verdict"] = "FAIL"
        elif rec["valid"] >= plan["w2_valid_min_per_arm"]:
            rec["verdict"] = "PASS"
        else:
            rec["verdict"] = "INCOMPLETE"
    return arms


def default_policy(plan, result, gate):
    """v36: the default window policy. `adaptive` only when the series was
    not stopped, its deciding look is the final, every default row is GAIN
    or NON_INFERIOR and no regression-only row is a REGRESSION; otherwise
    `fixed`, with the reasons. The W2 row: NON_INFERIOR when T's gate PASSes
    or both arms FAIL, GAIN when T PASSes and C FAILs, REGRESSION when T
    FAILs and C PASSes, UNRESOLVED otherwise (an INCOMPLETE arm)."""
    t, c = gate["t"]["verdict"], gate["c"]["verdict"]
    w2 = ("GAIN" if t == "PASS" and c == "FAIL" else "NON_INFERIOR" if t == "PASS" or (t == "FAIL" and c == "FAIL")
          else "REGRESSION" if t == "FAIL" and c == "PASS" else "UNRESOLVED")
    rows = dict(result.get("rows") or {})
    rows["w2"] = w2
    why = []
    if result.get("verdict") == "STOPPED":
        why.append("series_stopped")
    if result.get("look") != "final":
        why.append("no_final_look:%s" % result.get("look", "none"))
    for row in plan["default_rows"]:
        if rows.get(row, "UNAVAILABLE") not in ("GAIN", "NON_INFERIOR"):
            why.append("%s:%s" % (row, rows.get(row, "UNAVAILABLE")))
    for row in plan["regression_only_rows"]:
        if rows.get(row) == "REGRESSION":
            why.append("%s:REGRESSION" % row)
    return {"default": "fixed" if why else "adaptive", "why": why, "rows": rows,
            "look": result.get("look", "none"), "n": result.get("n", 0)}


def analyze(plan, receipts, sentinels=None, plan_sha256=None):
    pairs, valid = pair_table(plan, receipts)
    for entry in pairs:
        p = next((v for v in valid if v["pair"] == entry["pair"]), None)
        if p is None:
            continue
        entry["windows"] = {arm: {
            "name": rec["name"], "S_mbit_s": rec["S"] * 8 / 1e6, "A_mbit_s": rec["A"] * 8 / 1e6,
            "floored": rec["floored"], "slowest_mbit_s": rec["slowest"] * 8 / 1e6,
            "total_mbit_s": rec["total_mbit_s"], "s24b": rec["s24b"], "s24b_failed": rec["s24b_failed"],
            "window_policy": rec["window_policy"], "above_initial": rec["above_initial"],
            "latency": rec["latency"], "build": rec["build"], "owner_head": rec["owner_head"],
            "start": iso(rec["start"]), "mechanism": mechanism(rec)} for arm, rec in (("c", p["C"]), ("t", p["T"]))}
    stop = stop_reason(plan, receipts)
    result = series_verdict(plan, valid, series_end(plan, receipts, pairs))
    if stop:
        result["verdict"] = "STOPPED"
        result["stopped_at"], result["stop_reason"] = stop
    t_windows = [p["T"] for p in valid]
    out = {"plan": plan["plan"], "plan_sha256": plan_sha256, "pairs": pairs, "result": result,
           "floored_windows": [rec["name"] for p in valid for rec in (p["C"], p["T"]) if rec["floored"]],
           # W1 item 2's fallback: above_initial=yes in at least half of the
           # valid T windows.
           "w1_growth_evidence": {"t_windows": len(t_windows),
                                  "above_initial_yes": sum(1 for r in t_windows if r["above_initial"] == "yes"),
                                  "half_or_more": bool(t_windows) and 2 * sum(
                                      1 for r in t_windows if r["above_initial"] == "yes") >= len(t_windows)},
           "strata": strata(valid)}
    if "prelude_arms" in plan:
        out["w2_gate"] = w2_gate(plan, receipts)
        out["default_policy"] = default_policy(plan, result, out["w2_gate"])
    if sentinels:
        names = [n for n in plan["prelude"] + list(plan["sentinel_after_pairs"].values()) + plan["coda"]
                 if n.startswith("path-probe-")]
        out["sentinels"] = [sentinel(sentinels, n) for n in names]
    return out


# ----------------------------------------------------------------- next
def cert_ok(path, now, margin):
    if path is None:
        return True, None
    try:
        text = slurp(path)
    except OSError:
        return False, "cert_status_unreadable"
    report = None
    for line in text.splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("report"), dict):
            report = r["report"]
    if report is None:
        return False, "cert_status_unreadable"
    if report.get("state") != "valid":
        return False, "cert_state"
    renew = report.get("renew_at")
    if not isinstance(renew, (int, float)) or renew - now.timestamp() < margin:
        return False, "renew_margin"
    return True, None


def ran(receipts, name):
    return read_run(os.path.join(receipts, name + ".side")) is not None


def line(name, kind, arm, plan, reason=None):
    env = dict(plan["env"])
    if arm in ("c", "t"):
        env["WINDOW_POLICY"] = plan["arms"][arm]["WINDOW_POLICY"]
    elif name.startswith("window-v35-w1"):
        env.update(LOAD_STREAMS="1", LOAD_BYTES="52428800")
    elif name.startswith("window-v35-w3"):
        env.update(LOAD_STREAMS="8", LOAD_BYTES="209715200")
    if kind in ("sentinel", "renewal"):
        env = {}
    text = "next=%s kind=%s arm=%s env=%s" % (name, kind, arm or "none",
                                              ",".join("%s=%s" % kv for kv in sorted(env.items())) or "none")
    return text + (" reason=%s" % reason if reason else "")


def cert_renew_at(path):
    """renew_at (Unix seconds) of the last report in a --cert-status file, or
    None."""
    try:
        text = slurp(path)
    except (OSError, TypeError):
        return None
    renew = None
    for row in text.splitlines():
        try:
            r = json.loads(row)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("report"), dict):
            v = r["report"].get("renew_at")
            renew = v if isinstance(v, (int, float)) else None
    return renew


def renewal_due_state(path):
    """v36 amendment (28 October 2026, before any v36 step): whether the last
    --cert-status report's state is one the declared renewal window answers.
    Once renew_at has passed the provider reports `due` (identity_renewal.rs
    `token`), or `failed:<class>` after a failed attempt, never `valid`, so
    cert_ok refuses `cert_state` there rather than `renew_margin`. Any other
    state (in_progress, pending, renewed_pending_ack, expired, parked, ...)
    is not a renewal step's to answer."""
    try:
        text = slurp(path)
    except (OSError, TypeError):
        return False
    state = None
    for row in text.splitlines():
        try:
            r = json.loads(row)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("report"), dict):
            state = r["report"].get("state")
    return isinstance(state, str) and (state == "due" or state.startswith("failed:"))


def renewal_step(plan, receipts, cert, now):
    """v36: with the identity inside the renew margin, the declared renewal
    window (a plain connect without load: the provider renews at Connect
    once renew_at plus its skew has passed) when it is due, else a wait
    (`refuse:renew_margin`); `refuse:renewal_failed` after the declared
    attempts."""
    renew = cert_renew_at(cert)
    if renew is None or now.timestamp() < renew + plan["renewal_due_skew_s"]:
        return "refuse:renew_margin"
    for attempt in range(1, plan["renewal_attempts_max"] + 1):
        name = plan["renewal_name"].format(attempt=attempt)
        if not ran(receipts, name):
            return line(name, "renewal", None, plan)
    return "refuse:renewal_failed"


def w2_retry_due(plan, receipts):
    """v36: the first W2 gate window, in declared order, whose r1 is invalid
    for a declared retry reason and whose retry has not run, as (retry name,
    arm, reasons), or None."""
    for name, arm in plan["prelude_arms"].items():
        retry = plan["w2_retry"].get(name)
        if retry is None or ran(receipts, retry):
            continue
        rec = window_record(plan, receipts, name)
        if rec is None:
            continue
        reasons = [r for r in window_invalid(plan, rec, arm) if r in plan["w2_retry_reasons"]]
        if reasons:
            return retry, arm, reasons
    return None


def next_step(plan, receipts, now, cert=None):
    ok, why = cert_ok(cert, now, plan["renew_margin_s"])
    stop = stop_reason(plan, receipts)
    if stop:
        return "refuse:series_stopped:%s:%s" % (stop[1], stop[0])
    # v36: no step starts at or after the declared deadline (the relay
    # window's end less the longest step).
    deadline = parse_utc(plan.get("deadline_utc"))
    if deadline is not None and now >= deadline:
        return "refuse:deadline"
    if not ok and "renewal_name" in plan and (
            why == "renew_margin" or (why == "cert_state" and renewal_due_state(cert))):
        return renewal_step(plan, receipts, cert, now)

    def offer(name, kind, arm=None, reason=None):
        return ("refuse:%s" % why) if not ok else line(name, kind, arm, plan, reason)

    arms_of = plan.get("prelude_arms", {})
    for name in plan["prelude"]:
        if not ran(receipts, name):
            return offer(name, "sentinel" if name.startswith("path-probe-") else "window", arms_of.get(name))
    # v36: a W2 gate window invalid for a declared reason is retried once,
    # right after the prelude.
    if isinstance(plan["w2_retry"], dict):
        due = w2_retry_due(plan, receipts)
        if due:
            return offer(due[0], "window", due[1], "w2_retry:" + "+".join(due[2]))
    pairs, valid = pair_table(plan, receipts)
    coda_only = series_end(plan, receipts, pairs) in plan["series_end_reasons"]
    valid_so_far, interim_done = 0, False
    for k in range(1, len(plan["pairs"]) + 1):
        if coda_only:
            break
        order = plan["pairs"][k - 1]
        atts = pair_attempts(plan, receipts, k)
        if any(a["status"] == "valid" for a in atts):
            valid_so_far += 1
        else:
            last = atts[-1] if atts else None
            if last is None:
                return offer(window_name(plan, k, order[0], 1), "window", order[0])
            if last["status"] == "incomplete":
                first = last["windows"][order[0]]
                # The second window can still start, after the plan's idle,
                # within the gap of the first one's start.
                if first is not None and first["start"] is not None and \
                        (now - first["start"]).total_seconds() + plan["idle_before_s"] \
                        <= plan["pair_start_gap_max_s"]:
                    return offer(window_name(plan, k, order[1], last["attempt"]), "window", order[1])
                status, reasons = "invalid", ["pair_gap"]
            else:
                status, reasons = last["status"], last["reasons"]
            if status == "invalid" and last["attempt"] <= plan["pair_reruns_max"]:
                return offer(window_name(plan, k, order[0], last["attempt"] + 1), "window", order[0],
                             "rerun:" + "+".join(reasons))
            # A pair invalid three times is missing: on to the next.
        sentinel_name = plan["sentinel_after_pairs"].get(str(k))
        if sentinel_name and not ran(receipts, sentinel_name):
            return offer(sentinel_name, "sentinel")
        # The interim, once, at the interim_at-th valid pair (on exactly
        # those pairs): GAIN or REGRESSION stops the series (only the coda
        # follows); anything else runs on to the end with no other look.
        if not interim_done and valid_so_far >= plan["interim_at"]:
            interim_done = True
            first = valid[:plan["interim_at"]]
            if decide(plan, first, "interim")["verdict"] in plan.get("interim_stops", ("GAIN", "REGRESSION")):
                coda_only = True
    for name in plan["coda"]:
        if not ran(receipts, name):
            return offer(name, "sentinel" if name.startswith("path-probe-") else "window")
    if isinstance(plan["w2_retry"], dict):
        return "refuse:series_complete"
    w2 = read_run(os.path.join(receipts, plan["prelude"][1] + ".side"))
    if w2 is not None and w2.get("invalid") in plan["w2_retry_reasons"]:
        for name in plan["w2_retry"]:
            if not ran(receipts, name):
                return offer(name, "sentinel" if name.startswith("path-probe-") else "window",
                             None, "w2_retry:" + w2["invalid"])
    return "refuse:series_complete"


def main(argv):
    ap = argparse.ArgumentParser(prog="ab_review.py")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check-plan")
    c.add_argument("--plan", required=True)
    n = sub.add_parser("next")
    n.add_argument("--plan", required=True)
    n.add_argument("--receipts", required=True)
    n.add_argument("--cert-status")
    n.add_argument("--now")
    a = sub.add_parser("analyze")
    a.add_argument("--plan", required=True)
    a.add_argument("--receipts", required=True)
    a.add_argument("--sentinels")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2
    if args.cmd is None:
        ap.print_usage(sys.stderr)
        return 2
    try:
        plan = load_plan(args.plan)
    except (OSError, ValueError) as error:
        print("ab_review.py: plan unreadable: %s" % type(error).__name__, file=sys.stderr)
        return 2
    errors = check_plan(plan)
    if args.cmd == "check-plan":
        print("\n".join(errors) if errors else "plan_ok %s" % plan["plan"])
        return 1 if errors else 0
    if errors:
        print("ab_review.py: plan refused: %s" % ",".join(errors), file=sys.stderr)
        return 1
    if args.cmd == "next":
        now = parse_utc(args.now) if args.now else datetime.datetime.now(datetime.timezone.utc)
        if now is None:
            return 2
        print(next_step(plan, args.receipts, now, args.cert_status))
        return 0
    with open(args.plan, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    out = analyze(plan, args.receipts, args.sentinels, sha)
    print(json.dumps(out, sort_keys=True, default=str))
    r = out["result"]
    tail = (" default=%s" % out["default_policy"]["default"]) if "default_policy" in out else ""
    print("verdict=%s n=%d look=%s%s" % (r["verdict"], r["n"], r.get("look", "none"), tail))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
