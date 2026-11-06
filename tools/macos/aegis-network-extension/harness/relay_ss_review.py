#!/usr/bin/env python3
"""B-06 v35: the review of the masked socket samples beside an A/B window.

System python 3.9, stdlib only. Three subcommands, each printing one JSON
object on stdout:

- `relay FILE [--min-bytes N]`: the relay's samples (relay_ss_loop.sh run):
  per socket, keyed by its peer (the Mac side's) port, the series of cwnd,
  ssthresh, rtt, bytes_acked, segs_out, retrans, lost, notsent,
  delivery_rate and the busy/rwnd_limited/sndbuf_limited times; loss events
  (a cwnd cut of 20% or more between two samples); and for each socket that
  moved at least N bytes (default 1 MiB) during the samples: loss events per
  segment sent, notsent p50/p90, rtt p50/p90, and the rwnd_limited share of
  its busy time. v36: each socket's congestion control names (`cc`). A cwnd
  cut is a loss response under cubic; BBR does not cut its cwnd that way,
  so loss events are not comparable across the two (v36 acceptance).
- `mac FILE`: the Mac's samples (mac_sockq_loop.sh): per socket, keyed by
  its local port, Recv-Q and Send-Q p50/p90/max.
- `attribute --relay FILE --mac FILE [--provider-log FILE]`: the W2
  failure label of the v35 acceptance. The failing stream's connection is
  the relay socket that moved the fewest bytes among those that moved at
  least 1 MiB (one stream per connection in W2; a socket's port on the
  relay need not be the Mac's behind a NAT, so sockets are not matched
  across the two files). When that socket's notsent p50 is at least 64
  KiB the queue is in the relay's send buffer, which a larger client
  credit fills as surely as a lossy path does (v35 review): the label is
  `path_bound` only when the provider log shows the slowest bulk flow's
  connection (its `flow_bulk` line with the fewest KiB) never held extra
  credit (`extra_kib:0` on every `pool_queue` line of that connection),
  and `credit_or_path` otherwise, a missing log included. It is also
  `path_bound` when every Mac relay socket's Recv-Q p90 is under 16 KiB and
  that relay socket's rwnd_limited share is under 10% (nothing waits on
  the Mac and the Mac's window never held the relay: the relay's
  congestion window); else `unattributed`. A missing or empty sample file
  gives `unavailable`.

Every input must already be masked: a full IPv4 literal or an IPv6
literal (two colons between hex groups) anywhere in it exits 3 before
anything is printed (nothing unmasked is ever re-emitted).
Exit 0 on output, 2 for bad arguments.
"""
import argparse
import json
import re
import sys

FULL_IPV4 = re.compile(r"(?<![0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
# v35 review: an IPv6 literal (two colons between hex groups, as
# relay_ss_loop.sh mask refuses it); masked forms are [v6.x] and v6.x.
IPV6_LIKE = re.compile(r"[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}")
KV = re.compile(r"([a-z_]+):([^\s]+)")
CC_NAME = re.compile(r"(?:^|\s)(bbr2?|bbr3|cubic|reno|htcp|vegas|dctcp|westwood)(?=\s|$)")
CUT = 0.8          # a cwnd at most 80% of the sample before: a loss event
MIN_BYTES = 1048576
NOTSENT_QUEUE = 64 * 1024
RECVQ_IDLE = 16 * 1024
RWND_SHARE = 0.10


class Unmasked(Exception):
    pass


def read(path):
    try:
        text = open(path, errors="replace").read()
    except (OSError, TypeError):
        return None
    if FULL_IPV4.search(text) or IPV6_LIKE.search(text):
        raise Unmasked(path)
    return text.splitlines()


def read_fields(path):
    """The provider log's lines, unchecked: it carries timestamps (which the
    address check would refuse) and stable address-free lines, and only a
    connection ID and counts from its `flow_bulk` and `pool_queue` lines
    are ever printed."""
    try:
        return open(path, errors="replace").read().splitlines()
    except (OSError, TypeError):
        return None


def pct(values, p):
    v = sorted(values)
    if not v:
        return None
    k = max(1, -(-p * len(v) // 100))
    return v[min(k, len(v)) - 1]


def num(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def port_of(endpoint):
    m = re.search(r"[:.]([0-9]{1,5})$", endpoint)
    return m.group(1) if m else None


def parse_relay(lines):
    """[(t, {port: sample})]: each `T` block's sockets."""
    samples, cur, head = [], None, None
    for line in lines:
        if line.startswith("T "):
            t = num(line.split()[1]) if len(line.split()) > 1 else None
            cur = None if t is None else (t, {})
            if cur:
                samples.append(cur)
            head = None
            continue
        if cur is None:
            continue
        if line[:1] not in ("\t", " "):
            f = line.split()
            head = None
            if len(f) >= 4 and f[0].isdigit() and f[1].isdigit():
                head = {"recvq": int(f[0]), "sendq": int(f[1]), "port": port_of(f[3])}
            continue
        if head is None:
            continue
        s = dict(head)
        body = line.strip()
        for k, v in KV.findall(body):
            s[k] = v
        m = re.search(r"\brtt:([0-9.]+)/([0-9.]+)", body)
        if m:
            s["rtt_ms"] = float(m.group(1))
        m = re.search(r"\bdelivery_rate ([0-9]+)bps", body)
        if m:
            s["delivery_bps"] = int(m.group(1))
        for name in ("busy", "rwnd_limited", "sndbuf_limited"):
            m = re.search(r"\b%s:([0-9]+)ms" % name, body)
            if m:
                s[name + "_ms"] = int(m.group(1))
        m = re.search(r"\bretrans:([0-9]+)/([0-9]+)", body)
        if m:
            s["retrans_total"] = int(m.group(2))
        # v36: the socket's congestion control (ss prints its name as a bare
        # word; `bbr:(bw:...)` is BBR's own field and is not matched).
        m = CC_NAME.search(body)
        if m:
            s["cc"] = m.group(1)
        if head["port"]:
            cur[1][head["port"]] = s
        head = None
    return samples


def relay_review(lines, min_bytes=MIN_BYTES):
    samples = parse_relay(lines)
    series = {}
    for t, socks in samples:
        for port, s in socks.items():
            series.setdefault(port, []).append((t, s))
    out = {"samples": len(samples), "sockets": []}
    for port, ser in sorted(series.items(), key=lambda kv: kv[1][0][0]):
        def ints(key):
            return [int(num(s.get(key)) or 0) for _t, s in ser if num(s.get(key)) is not None]
        acked = ints("bytes_acked")
        moved = (max(acked) - min(acked)) if acked else 0
        cw = [(t, num(s.get("cwnd"))) for t, s in ser if num(s.get("cwnd")) is not None]
        events = sum(1 for (_a, x), (_b, y) in zip(cw, cw[1:]) if x and y is not None and y <= CUT * x)
        segs = ints("segs_out")
        sent = (max(segs) - min(segs)) if segs else 0
        notsent = ints("notsent")
        rtts = [s["rtt_ms"] for _t, s in ser if "rtt_ms" in s]
        busy = ints("busy_ms")
        rwnd = ints("rwnd_limited_ms")
        busy_d = (max(busy) - min(busy)) if busy else 0
        rwnd_d = (max(rwnd) - min(rwnd)) if rwnd else 0
        rec = {"port": port, "samples": len(ser), "bytes": moved,
               "cwnd_first": cw[0][1] if cw else None, "cwnd_last": cw[-1][1] if cw else None,
               "ssthresh_last": num(ser[-1][1].get("ssthresh")),
               "retrans_total": ser[-1][1].get("retrans_total"), "lost_last": num(ser[-1][1].get("lost")),
               "delivery_bps_p50": pct([s["delivery_bps"] for _t, s in ser if "delivery_bps" in s], 50),
               # v36: every congestion control seen on the socket (the relay
               # condition R2 shows bbr on every socket opened after it).
               "cc": sorted({s["cc"] for _t, s in ser if "cc" in s}),
               "loss_events": events}
        if moved >= min_bytes:
            rec.update({"bulk": True,
                        "loss_events_per_segment": (events / sent) if sent else None,
                        "notsent_p50": pct(notsent, 50) if notsent else 0,
                        "notsent_p90": pct(notsent, 90) if notsent else 0,
                        "rtt_ms_p50": pct(rtts, 50), "rtt_ms_p90": pct(rtts, 90),
                        "rwnd_limited_share": (rwnd_d / busy_d) if busy_d else None})
        else:
            rec["bulk"] = False
        out["sockets"].append(rec)
    return out


def mac_review(lines):
    per, n = {}, 0
    for line in lines:
        if line.startswith("T "):
            n += 1
            continue
        f = line.split()
        if len(f) >= 6 and f[0].startswith("tcp") and f[1].isdigit() and f[2].isdigit():
            port = port_of(f[3])
            if port:
                per.setdefault(port, []).append((int(f[1]), int(f[2])))
    socks = []
    for port, qs in sorted(per.items()):
        r = [q[0] for q in qs]
        s = [q[1] for q in qs]
        socks.append({"port": port, "samples": len(qs), "recvq_p50": pct(r, 50), "recvq_p90": pct(r, 90),
                      "recvq_max": max(r), "sendq_p50": pct(s, 50), "sendq_p90": pct(s, 90), "sendq_max": max(s)})
    return {"samples": n, "sockets": socks}


def slowest_flow_credit(provider_lines):
    """From the provider log: the connection of the bulk flow that moved the
    fewest KiB (`flow_bulk conn:<id> kib:<n>`), and the most extra credit
    any `pool_queue` line showed on it (None: no such flow or line)."""
    flows, extra = [], {}
    for line in provider_lines or []:
        f = line.split()
        for i, word in enumerate(f):
            if word in ("flow_bulk", "pool_queue"):
                kv = dict(w.split(":", 1) for w in f[i + 1:] if ":" in w)
                conn = kv.get("conn")
                if word == "flow_bulk" and conn and kv.get("kib", "").isdigit():
                    flows.append((int(kv["kib"]), conn))
                elif word == "pool_queue" and conn and kv.get("extra_kib", "").isdigit():
                    extra[conn] = max(extra.get(conn, 0), int(kv["extra_kib"]))
                break
    if not flows:
        return None, None
    conn = min(flows)[1]
    return conn, extra.get(conn)


def attribute(relay_lines, mac_lines, provider_lines=None):
    if not relay_lines or not mac_lines:
        return {"label": "unavailable", "reason": "missing_samples"}
    relay = relay_review(relay_lines)
    mac = mac_review(mac_lines)
    bulk = [s for s in relay["sockets"] if s.get("bulk")]
    if not bulk or not mac["sockets"]:
        return {"label": "unavailable", "reason": "no_bulk_relay_socket" if not bulk else "no_mac_relay_socket"}
    slowest = min(bulk, key=lambda s: s["bytes"])
    mac_quiet = all(s["recvq_p90"] < RECVQ_IDLE for s in mac["sockets"])
    rwnd = slowest.get("rwnd_limited_share")
    rec = {"slowest_port": slowest["port"], "slowest_bytes": slowest["bytes"],
           "notsent_p50": slowest["notsent_p50"], "mac_recvq_p90_max": max(s["recvq_p90"] for s in mac["sockets"]),
           "rwnd_limited_share": rwnd}
    conn, extra = slowest_flow_credit(provider_lines)
    rec.update(slowest_flow_conn=conn, slowest_flow_extra_kib_max=extra)
    if slowest["notsent_p50"] >= NOTSENT_QUEUE:
        # At v33's credit the client never offered more than its fixed
        # window: the queue is the path's. With extra credit it may be the
        # credit's.
        rec.update(label="path_bound" if extra == 0 else "credit_or_path", reason="relay_send_buffer")
    elif mac_quiet and rwnd is not None and rwnd < RWND_SHARE:
        rec.update(label="path_bound", reason="relay_congestion_window")
    else:
        rec.update(label="unattributed", reason="queue_not_located")
    return rec


def main(argv):
    ap = argparse.ArgumentParser(prog="relay_ss_review.py")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("relay")
    r.add_argument("file")
    r.add_argument("--min-bytes", type=int, default=MIN_BYTES)
    m = sub.add_parser("mac")
    m.add_argument("file")
    a = sub.add_parser("attribute")
    a.add_argument("--relay", required=True)
    a.add_argument("--mac", required=True)
    a.add_argument("--provider-log")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if args.cmd == "relay":
            lines = read(args.file)
            out = {"unavailable": "missing_file"} if lines is None else relay_review(lines, args.min_bytes)
        elif args.cmd == "mac":
            lines = read(args.file)
            out = {"unavailable": "missing_file"} if lines is None else mac_review(lines)
        elif args.cmd == "attribute":
            out = attribute(read(args.relay), read(args.mac), read_fields(args.provider_log))
        else:
            ap.print_usage(sys.stderr)
            return 2
    except Unmasked as error:
        print("relay_ss_review.py: an unmasked address literal in %s; nothing printed" % error, file=sys.stderr)
        return 3
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
