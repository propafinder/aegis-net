#!/usr/bin/env python3
"""B-06 v35: the operating characteristics of the declared A/B decision rule
(docs/platforms/macos/v35-load-acceptance.md, "Noise and power"), by
simulation through ab_review.py's own series_verdict(): the interim once on
the first 8 valid pairs, the final on all 16 at the series' end.

System python 3.9, stdlib only. `ab_oc.py [--trials N] [--seed S]` prints
one JSON object: per cell (a true per-stream rate ratio of T over C, an
extra per-window S24b failure probability, a noise model and a latency
model) the share of series ending in each verdict, the model's own paired
SD of d and of the aggregate's d, and its S24b failure rate per arm; and
the exact null false-positive rates of the S24b sign test.

The model (modelled, not measured; the acceptance labels it so): each
window's 4 streams run at mu x ratio x exp(e + w + c_i), with e shared by
the pair's two windows (the time of day), w the window's own path state
and c_i each connection's; a stream short of 50 MiB at 180 s is the S24b
download failure, and any window also fails S24b with the extra
probability. The latency rows are log-normal around the same median in
both arms (times `lat_ratio` in T), with the single-window log-SDs of
`LATENCY_SD`: burst90 and the TCP echo from the v33 4-stream receipts,
hs_p90 and the rtt_queue rows ASSUMED (no v33 receipt has them).
"""
import argparse
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ab_review  # noqa: E402

MB = 52428800
BOUND = 180.0
MU = 420000.0          # bytes/s per stream: v33's kernel4 3.6-4.1 and v34 W2's 1.8-6.9 Mbit/s
PAIR_SD = 0.30         # e: the time of day, shared by a pair's two windows
NOISE = {"moderate": (0.15, 0.40), "wide": (0.25, 0.60)}   # (w, c_i) log-SDs
# Single-window log-SDs: measured from the v33 4-stream receipts (burst90
# 0.20, TCP echo 0.16), and ASSUMED where no receipt has the row.
LATENCY_SD = {"burst90_s": 0.20, "tcp_echo_ms": 0.16, "hs_p90_ms": 0.12, "rtt_queue_p50_ms": 0.35,
              "rtt_queue_p90_ms": 0.35}
LATENCY_MEDIAN = {"burst90_s": 4.0, "tcp_echo_ms": 900.0, "hs_p90_ms": 800.0, "rtt_queue_p50_ms": 60.0,
                  "rtt_queue_p90_ms": 200.0}


def window(rnd, plan, ratio, e, noise, f_extra, lat_ratio, assumed_rows):
    w_sd, c_sd = NOISE[noise]
    w = rnd.gauss(0.0, w_sd)
    streams = []
    for _ in range(4):
        r = MU * ratio * math.exp(e + w + rnd.gauss(0.0, c_sd))
        if r * BOUND >= MB:
            streams.append({"bytes": MB, "t0": 0.0, "t1": MB / r})
        else:
            streams.append({"bytes": int(r * BOUND), "t0": 0.0, "t1": BOUND})
    rates = ab_review.stream_rates(streams, plan["stream_bytes"], plan["stream_bound_s"])
    floor = plan["floor_bytes_per_s"]
    download_ok = all(ab_review.complete(s, plan["stream_bytes"], plan["stream_bound_s"]) for s in streams)
    latency = {}
    for row, sd in LATENCY_SD.items():
        if row in ("hs_p90_ms", "rtt_queue_p50_ms", "rtt_queue_p90_ms") and not assumed_rows:
            latency[row] = None
        else:
            latency[row] = LATENCY_MEDIAN[row] * lat_ratio * math.exp(rnd.gauss(0.0, sd))
    return {"S": max(sum(rates), floor),
            "A": max(ab_review.aggregate_rate(streams, plan["stream_bytes"], plan["stream_bound_s"]), floor),
            "s24b": download_ok and rnd.random() >= f_extra, "latency": latency}


def cell(plan, rnd, trials, ratio, f_extra, noise, lat_ratio=1.0, assumed_rows=True):
    counts, d_s, d_a, fails = {}, [], [], {"c": 0, "t": 0}
    for _ in range(trials):
        valid = []
        for k in range(1, plan["n_max"] + 1):
            e = rnd.gauss(0.0, PAIR_SD)
            c = window(rnd, plan, 1.0, e, noise, f_extra, 1.0, assumed_rows)
            t = window(rnd, plan, ratio, e, noise, f_extra, lat_ratio, assumed_rows)
            valid.append({"pair": k, "C": c, "T": t})
            d_s.append(math.log(t["S"] / c["S"]))
            d_a.append(math.log(t["A"] / c["A"]))
            fails["c"] += not c["s24b"]
            fails["t"] += not t["s24b"]
        verdict = ab_review.series_verdict(plan, valid, "complete")["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
    windows = trials * plan["n_max"]
    sd = lambda xs: (sum((x - sum(xs) / len(xs)) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5
    return {"verdicts": {k: round(v / trials, 3) for k, v in sorted(counts.items())},
            "accepted": round((counts.get("GAIN", 0) + counts.get("NON_INFERIOR", 0)) / trials, 3),
            "paired_sd_d": round(sd(d_s), 3), "paired_sd_d_aggregate": round(sd(d_a), 3),
            "s24b_fail_rate": {"c": round(fails["c"] / windows, 3), "t": round(fails["t"] / windows, 3)}}


def s24b_null(plan, f, n, alpha):
    """Exact, under the null (each window fails S24b with probability f,
    independently, in both arms): the probability the sign test regresses
    (p <= alpha) and blocks (p <= s24b_block_p) over n pairs."""
    disc = f * (1 - f)          # each one-sided discordance
    conc = 1 - 2 * disc
    reg = block = 0.0
    for b in range(n + 1):
        for c in range(n - b + 1):
            prob = math.comb(n, b) * math.comb(n - b, c) * disc ** (b + c) * conc ** (n - b - c)
            p = ab_review.binom_upper(b, b + c)
            reg += prob if p <= alpha else 0.0
            block += prob if p <= plan["s24b_block_p"] else 0.0
    return {"regression": round(reg, 4), "blocks": round(block, 4)}


def main(argv):
    ap = argparse.ArgumentParser(prog="ab_oc.py")
    ap.add_argument("--trials", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=35)
    ap.add_argument("--plan", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                                                   "..", "docs", "platforms", "macos", "v35-ab-plan.json"))
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2
    plan = ab_review.load_plan(args.plan)
    if ab_review.check_plan(plan):
        print("ab_oc.py: plan refused", file=sys.stderr)
        return 1
    rnd = random.Random(args.seed)
    out = {"model": {"mu_bytes_per_s": MU, "pair_sd": PAIR_SD, "noise": NOISE, "latency_sd": LATENCY_SD,
                     "trials": args.trials, "seed": args.seed}, "cells": {}, "s24b_null_exact": {}}
    for noise in ("moderate", "wide"):
        for f_extra in (0.0, 0.3):
            for ratio in (0.85, 1.0, 1.13, 1.3):
                key = "noise=%s f_extra=%.1f ratio=%.2f" % (noise, f_extra, ratio)
                out["cells"][key] = cell(plan, rnd, args.trials, ratio, f_extra, noise)
            key = "noise=%s f_extra=%.1f ratio=1.00 assumed_rows=off" % (noise, f_extra)
            out["cells"][key] = cell(plan, rnd, args.trials, 1.0, f_extra, noise, assumed_rows=False)
            key = "noise=%s f_extra=%.1f ratio=1.13 lat_ratio=1.30" % (noise, f_extra)
            out["cells"][key] = cell(plan, rnd, args.trials, 1.13, f_extra, noise, lat_ratio=1.30)
    for f in (0.1, 0.2, 0.3, 0.5):
        out["s24b_null_exact"]["f=%.1f" % f] = {
            "interim_n8_alpha0.01": s24b_null(plan, f, plan["interim_at"], plan["alpha"]["interim"]),
            "final_n16_alpha0.05": s24b_null(plan, f, plan["n_max"], plan["alpha"]["final"])}
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
