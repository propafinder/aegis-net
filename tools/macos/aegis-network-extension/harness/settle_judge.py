#!/usr/bin/env python3
"""B-06 v33: the judge of the IFSWITCH=1 settle gate (om_settle in
harness/owner-modes.sh). Runs under /usr/bin/python3 -I (3.9).

    settle_judge.py LOG ASK_MS ROUTE_MS QUIET_MS [NAME]

LOG is one `log show --style compact` read of the provider's `aegis-ne`
lines; ASK_MS is when the window asked for the owner's action, ROUTE_MS
when it saw the physical default route move (both epoch milliseconds, the
window's clock) and QUIET_MS the quiet period. Only lines of the
aegis-ne-provider process count: another process's `aegis-ne` lines (a
cargo test binary of this crate) never settle anything. The compact
timestamps are local time; they are read with time.mktime, which follows
the zone and daylight saving of this Mac.

Over the whole read a `session_lost` or `reasserting on` line makes a loss
pending and a `session_rebuilt` or `reasserting off` line clears it. From
ASK_MS on it counts `path_change`, `session_lost` (with its codes),
`session_rebuilt`, `session_rebuild_refused` and `session_failed`, and
(v33 review) with NAME, an interface name, `relay_interface_repinned
name:<NAME>`. The anchor is the latest of ROUTE_MS, the last path change
and the last rebuild (or `reasserting off`); `covered` is the newest
provider line. The switch has settled when no session failed, no loss is
pending, at least one path change was logged and the provider's log
reaches QUIET_MS past the anchor: log lines come in time order, so a line
stamped that late shows nothing in the quiet period was missed. A silent
provider or an empty read therefore never settles.

Prints one line of key=value pairs, times in seconds after ROUTE_MS
(`none` when there is no such line):

    settled=0|1 failed=none|<code> pending=0|1 path_change=N lost=N:<codes>
    rebuilt=N refused=N lines=N path_change_after=S rebuilt_after=S
    settled_after=S covered_after=S failed_after=S covered_ms=MS repinned=N

`settled_after` is when the gate settles (or would settle) if nothing
else happens. v33 review: `covered_ms` is `covered` itself (epoch
milliseconds, or `none`), where the gate's after-settle row starts
counting: every provider line the release was judged on is stamped at or
before it. `repinned` is 0 without NAME. Exit 0 whenever it printed that
line; for an unreadable LOG or bad arguments it prints `settled=0
error=<why>` and exits 2.
"""
import re
import sys
import time

PROVIDER = "aegis-ne-provider"
# date time type process[pid:tid] [subsystem] aegis-ne code [value ...]
LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d{3})\s+\S+\s+(\S+)\s+(?:\[[^\]]*\]\s+)?"
    r"aegis-ne\s+(\S+)(?:\s+(\S+))?")
CODE = re.compile(r"[^A-Za-z0-9_:.-]")
CODES_MAX = 120
NAME = re.compile(r"[A-Za-z0-9]{1,15}")


def stamp_ms(day_time, millis):
    return int(time.mktime(time.strptime(day_time, "%Y-%m-%d %H:%M:%S"))) * 1000 + int(millis)


def after(ms, route):
    return "none" if ms is None else "%.3f" % ((ms - route) / 1000.0)


def judge(lines, ask, route, quiet, name=None):
    pending = False
    failed = failed_ms = path_ms = rebuilt_ms = covered = None
    path_changes = lost = rebuilt = refused = provider_lines = repinned = 0
    codes = []
    for line in lines:
        m = LINE.match(line)
        if not m or not m.group(3).startswith(PROVIDER + "["):
            continue
        try:
            at = stamp_ms(m.group(1), m.group(2))
        except (ValueError, OverflowError):
            continue
        code, value = m.group(4), m.group(5) or "-"
        provider_lines += 1
        covered = at if covered is None else max(covered, at)
        if code == "session_lost" or (code == "reasserting" and value == "on"):
            pending = True
        elif code == "session_rebuilt" or (code == "reasserting" and value == "off"):
            pending = False
        if at < ask:
            continue
        if code == "path_change":
            path_changes += 1
            path_ms = at
        elif code == "session_lost":
            lost += 1
            value = CODE.sub("", value)[:40] or "-"
            if value not in codes:
                codes.append(value)
        elif code == "session_rebuilt" or (code == "reasserting" and value == "off"):
            if code == "session_rebuilt":
                rebuilt += 1
            rebuilt_ms = at if rebuilt_ms is None else max(rebuilt_ms, at)
        elif code == "session_rebuild_refused":
            refused += 1
        elif code == "session_failed" and failed is None:
            failed = CODE.sub("", value)[:40] or "-"
            failed_ms = at
        elif code == "relay_interface_repinned" and name is not None and value == "name:" + name:
            repinned += 1
    anchor = max(x for x in (route, path_ms, rebuilt_ms) if x is not None)
    settled = (failed is None and not pending and path_changes >= 1
               and covered is not None and covered >= anchor + quiet)
    return ("settled=%d failed=%s pending=%d path_change=%d lost=%d:%s rebuilt=%d refused=%d lines=%d "
            "path_change_after=%s rebuilt_after=%s settled_after=%s covered_after=%s failed_after=%s "
            "covered_ms=%s repinned=%d") % (
        int(settled), failed or "none", int(pending), path_changes, lost,
        (",".join(codes) or "none")[:CODES_MAX], rebuilt, refused, provider_lines,
        after(path_ms, route), after(rebuilt_ms, route), after(anchor + quiet, route),
        after(covered, route), after(failed_ms, route), "none" if covered is None else covered, repinned)


def main(argv):
    if len(argv) not in (5, 6):
        print("settled=0 error=usage")
        return 2
    try:
        ask, route, quiet = (int(x) for x in argv[2:5])
    except ValueError:
        print("settled=0 error=arguments")
        return 2
    name = argv[5] if len(argv) == 6 else None
    if ask <= 0 or route < ask or quiet <= 0 or (name is not None and not NAME.fullmatch(name)):
        print("settled=0 error=arguments")
        return 2
    try:
        with open(argv[1], errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        print("settled=0 error=unreadable")
        return 2
    print(judge(lines, ask, route, quiet, name))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
