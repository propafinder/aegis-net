# shellcheck shell=bash
# B-06 S20f: the owner-attended controls of harness/real-relay-window.sh,
# sourced by it after harness/owner-modes.sh (never run alone). Each is a
# separate window, never S20 evidence: every leak row of a control window
# (leak_*, no_v6_leak_physical, no_mac_sent_leak_physical,
# filter_armed_span) is written under the control's prefix
# (positive_control_ or negative_control_), and the window starts with an
# `evidence_scope` row saying so. Only one of POSITIVE_CONTROL=1,
# NEGATIVE_CONTROL=1, NETLOSS=1, SLEEP=1 and IFSWITCH=1 runs in a window;
# both controls need LEAK_CAPTURE=1 and the leak-guard filter configured,
# enabled and attached before the window (host --filter-status exit 0).
#
# S20g (v28), both controls: pre-existing sockets, the vector the filter
# exists for (kernel traffic of sockets connected before the tunnel:
# keepalives, retransmissions, data written later). Before the connect, for
# every captured interface with an IPv4 address and an on-link IPv4 default
# gateway, a helper (net_probe.py presock, one per interface) picks the
# first of PRESOCK_PORTS (80, 443, 53, 8080, in that order, never the relay
# port) that the gateway accepts and keeps PRESOCK_N (default 2, 1..4)
# connections to it bound with IP_BOUND_IF, with keepalives every
# PRESOCK_KEEPALIVE (idle/intvl/cnt, default 4/4/60) and (S20h) each bound
# to a TCP source port of the provider's marker range (PS_MARK_SPORT_FIRST,
# PS_MARK_SPORT_COUNT ports), so the filter counts their drops, kernel
# keepalives included, as marked (XNU keepalives carry the connection's
# ports, never the socket's TTL). Only the
# LAN gateway, never a third-party host or the relay. Its private state
# file presock-<if>.json (mode 0600, not for retained evidence) holds the
# chosen port and the local ports; rows and logs never name a port. It
# writes a few marked bytes on each socket and reads TCP_CONNECTION_INFO for
# up to PRESOCK_WAIT_S (default 5, 1..15); it closes them after the
# disconnect. Rows (under the control's prefix): presock_open_<if> (pass
# when every socket connected before the tunnel; unavailable when the
# gateway accepts none of the ports).
#
# S20h (v29), the positive control, after the standard checks while
# Connected and armed: a --filter-status right before the write, the
# write, and one more at least PS_KA_SPAN (2 * intvl + 2 s) after the first,
# so at least two keepalives per socket fall between them.
# presock_unacked_<if> (pass when every written socket's bytes stayed
# unacknowledged; fail when one was answered: acked, reset or data
# received; the armed filter also drops the gateway's answers inbound, so
# its pass says nothing about the outbound bytes). After the captures
# (leak_review.py presock-review): presock_keepalive_drops_<if> (pass when
# both reads guard under one arm, the provider is v29 with the helper's
# marker range and every socket inside it, at least two keepalives per
# socket were due between the reads
# from the capture's last receive before the arm, the marked bare-ACK drops
# of that interface's class grew by at least all of them, the outbound
# ring kept every record between the reads and its marked bare-ACK records
# on that interface fall on every due keepalive; marked data drops, when
# any, cover every data segment the sockets sent; unavailable when the
# keepalives were not counted, not attributed, or the reads are too close;
# fail only for reads not guarding, not under one arm or not parsed),
# presock_counted_<if> (info: data segments the sockets sent, those the
# filter counted, blocked_before_filter the rest, which never reached it:
# includeAllNetworks holds a pre-existing socket's own output before the
# filter, its kernel keepalives pass), presock_bpf_order_<if> (info:
# S20h review: post_filter when that interface's capture is complete, the
# armed span passed and the filter dropped more of the marker's segments of
# one kind on it between the reads than the capture holds frames from the
# marker's ports while armed (tap_evidence=post_filter: a tap before the
# filter records every dropped frame); unknown otherwise,
# capture_incomplete when the capture did not cover the armed span whole;
# never pre_filter) and positive_control_verdict
# (pc_verdict): fail when, on any
# interface, written bytes were answered, a fresh probe was answered
# (probe_failed fail) or a capture holds more of the helper's frames of a
# kind during the armed span than the filter counted marked drops of that
# kind (uncounted_frames), or (S20h review) holds any helper frame while
# armed although its tap is shown to come after the filter (frames_left:
# tap_evidence=post_filter on its complete capture, under a passing
# filter_armed_span); pass only when
# presock_open, presock_unacked and presock_keepalive_drops passed on the
# primary interface (PHYS), no frame of any helper is in any capture during
# the armed span, each counted, and (S20h review) every such capture is
# complete: alive at the disconnect, stopped by the window, no kernel drop,
# and a frame after the disarm (captures_incomplete otherwise); unavailable
# otherwise.
#
# S20h, the negative control: right after Connected (ctl_connected), never
# waiting for the arm or a --filter-status, each helper writes once:
# presock_acked_<if> (pass only when every written socket's bytes were
# acknowledged with the filter off; fail when a written socket's were not;
# unavailable when nothing was written, with not_written_causes when the
# gateway had reset or timed out the sockets). After the captures:
# presock_frames_<if> (info: its frames from the write to 1 s after the
# end of the wait; unknown nothing_written when nothing was written) and
# presock_wire_<if> (info: its frames over the Connected interval, its
# keepalives expected present with the filter off; S20h review:
# ack_only_marked, its bare ACKs carrying the provider's marker, the
# offline check of the marker). A window that never
# reaches Connected writes presock_unacked_<if> or presock_acked_<if>
# unavailable not_connected.
#
# S20g: the fresh bound probes of the positive control below cannot reach
# the filter when the system routes them into the tunnel (v27: every probe
# connected in 6-7 ms, no capture held a marked SYN, the filter counted
# none). When every probe of an interface connected, its probe_failed and
# filter_drop_delta rows wait for the captures and the provider log: with
# no marked SYN in any capture and at least PC_PROBES `engine_flow_open
# class:discard` lines (a v28 provider's engine answering port 9) timed
# within that interface's probes, they read info `tunnel_enforced`, as does
# bound_fresh_<if>; otherwise they keep their fail. bound_fresh_<if> (info)
# classifies every interface's probes: unanswered, answered, not_sent or
# tunnel_enforced.
#
# POSITIVE_CONTROL=1: while Connected and the filter armed, PC_PROBES
# (default 3, 1..10) marked TCP connects per captured interface that has an
# IPv4 address and an on-link IPv4 default gateway, bound to that interface
# (net_probe.py boundsyn: IP_BOUND_IF, source ports PC_SPORT_BASE + k), to
# that gateway's TCP port 9 (discard), each bounded by PC_TIMEOUT_S. Never
# a third-party host, never the relay address or the relay port. Rows per
# interface: probe_failed_<if> (pass only when every probe timed out; fail
# when one was answered, connected, refused or reset, since an answer needs
# the SYN out and the reply in through the filter; unavailable when none
# was answered but one never went out, such as eaddrinuse: it says
# nothing), filter_drop_delta_<if> (pass when, between a --filter-status
# right before and right after the probes, both read mode=guarding under
# the same arm, that interface's class out-drop counter grew by at least
# the probe count and the provider's drop ring holds at least that many
# new outbound IPv4 TCP SYN drops (drop_tcp_out) on that very interface;
# other drops of the class never count) and, after the captures stopped,
# bpf_order_<if> (info: pre_filter when the marked SYNs are in that
# interface's capture, post_filter when they are not; either only when
# both rows passed, so the filter counted the probes and none was
# answered; unknown otherwise).
#
# NEGATIVE_CONTROL=1: the same window with the filter disabled. Before any
# capture a detached filter rollback is armed (forked, adopted by launchd,
# its own session and group, ignoring INT/TERM/HUP/QUIT): it runs
# `host --enable-filter` and waits for `--filter-status` exit 0 as soon as
# the window is gone or its deadline passes, unless cancelled by its token,
# which it accepts only after reading exit 0 itself. Then
# `host --disable-filter` (the owner approves the administrator prompt;
# the window never answers it) and a --filter-status that must read exit
# 31 (disabled); otherwise the filter is restored and the window refuses
# before any capture or connect. After the disconnect, and again from the
# EXIT trap, `host --enable-filter` and --filter-status exit 0 within
# NC_ATTACH_WAIT_S of the enable's return. A filter not restored and
# verified attached fails the window (exit 1, "FAILED"), also on every
# refusal exit after the disable, and leaves the rollback armed.
# NC_MARKER, written before the rollback and removed only after a verified
# restore, outlives what a reboot, logout or power loss stops (the EXIT
# trap and the rollback are user processes): while it exists and the
# filter is not attached, every later window refuses before connecting.
#
# Uses from the window: OUT, PHYS, SID, LEAK_CAPTURE, NETLOSS, SLEEP,
# IFSWITCH, FILTER_RC, HOST_BIN, RELAY_IP, RELAY_PORT, ROLLBACK_S, PROBE_PY,
# HARNESS_DIR, LEAK_IFACES, CAP_ALIVE, CAP_STOPPED, XC_IFS, XC_ALIVE,
# XC_STOPPED, HOME, ARMED_AT, DISARMED_AT, SPAN_VERDICT, now, epoch,
# result, say, alive, drops_of; from netloss.sh: nl_int, nl_bounded; from
# owner-modes.sh: om_inet. Results and logs name interfaces, never an
# address or a port: gateways stay in memory and in argv, the helpers'
# ports in their private state files and in argv.
POSITIVE_CONTROL=${POSITIVE_CONTROL:-0}
NEGATIVE_CONTROL=${NEGATIVE_CONTROL:-0}
PC_PROBES=${PC_PROBES:-3}
PC_TIMEOUT_S=${PC_TIMEOUT_S:-2}
PC_SPORT_BASE=${PC_SPORT_BASE:-47100}
PC_PORT=9
NC_DISABLE_BOUND_S=${NC_DISABLE_BOUND_S:-180}
NC_ENABLE_BOUND_S=${NC_ENABLE_BOUND_S:-150}
NC_ATTACH_WAIT_S=${NC_ATTACH_WAIT_S:-30}
NC_PY=${NC_PY:-/usr/bin/python3}
NC_MARKER="$HOME/.aegis-local/negative-control-filter-disabled"
# S20g: the pre-existing sockets. The gateway ports are fixed here, never
# read from the environment; the relay port is never among those tried.
PRESOCK_N=${PRESOCK_N:-2}
PRESOCK_WAIT_S=${PRESOCK_WAIT_S:-5}
PRESOCK_LIMIT_S=${PRESOCK_LIMIT_S:-2}
PRESOCK_PORTS='80 443 53 8080'
# S20h: the helpers' keepalive (idle/intvl/cnt: idle and intvl 1..10 s, cnt
# 2..120) and the shortest time between the positive control's two reads
# around its write: two keepalive intervals and a second of tolerance on
# either side.
PRESOCK_KEEPALIVE=${PRESOCK_KEEPALIVE:-4/4/60}
PS_KA_SPAN=10
# S20h review: the provider's marker range of TCP source ports
# (leak_guard::MARK_SPORT_FIRST, MARK_SPORT_COUNT; net_probe.py binds the
# kept sockets there; a Rust test reads these two lines). The fresh probes'
# ports must stay out of it.
PS_MARK_SPORT_FIRST=47000
PS_MARK_SPORT_COUNT=32
CTL_MODE='' CTL_PREFIX='' CTL_REFUSAL='' CTL_SUMMARY='' CTL_EXTRA_S=0 CTL_FAILED=''
CTL_IFS=() CTL_GWS=() CTL_SKIPPED=''
PC_IFS=() PC_GWS=() PC_DELTA=() PC_PROBE=()
# S20g: per probed interface, the probes' times and scutil status, their
# output, the delta's detail, and whether every probe connected (pending).
# PC_PROBE is the probe_failed verdict: pass, unavailable or fail, and
# tunnel_enforced once pc_bpf_order has read a pending one so; S20h:
# not_run before pc_window probed (no Connected). v31 review: PC_FROM is the
# RESULT_FROM saved right before an interface's first --filter-status read:
# every per-interface row (probe_failed, filter_drop_delta, bound_fresh,
# bpf_order) reports those probes and reads and starts there (result_since).
PC_T0=() PC_T1=() PC_AT=() PC_OUT=() PC_DVAL=() PC_PENDING=() PC_FROM=()
# S20g: per presock interface: the helper's pid, and the open and unacked
# (positive) or acked (negative) verdicts. S20h: the keepalive verdict
# (positive), whether the write ran (1) and, positive, the helper's frames
# in that interface's capture during the armed span, `<frames> <data>
# <uncounted> <post_filter>` (S20h review: post_filter 1 when that complete
# capture under a passing armed span shows its tap after the filter), none
# (no socket to look for) or unknown (not counted), and PS_CAP whether that
# capture is complete (complete, or its reasons as `<if>:<reason>`).
PS_IFS=() PS_GWS=() PS_PIDS=() PS_OPEN=() PS_ANSWER=() PS_KA=() PS_RAN=() PS_FRAMES=() PS_CAP=()
NC_TOKEN='' NC_CANCEL='' NC_RB_LOG='' NC_RB_PID='' NC_DISABLED=0 NC_RESTORED=0

# S20f: a control window's leak rows under its prefix, never S20 rows.
# S20g: and its presock and bound_fresh rows.
ctl_row_name() {
    case "$CTL_PREFIX:$1" in
        :*) printf '%s' "$1" ;;
        *:leak_*|*:no_v6_leak_physical|*:no_mac_sent_leak_physical|*:filter_armed_span|*:presock_*|*:bound_fresh_*)
            printf '%s%s' "$CTL_PREFIX" "$1" ;;
        *) printf '%s' "$1" ;;
    esac
}

# Before the lock, the rollbacks, the captures or any connect: sets
# CTL_REFUSAL and returns 1 when the control cannot run here.
ctl_preflight() {
    local spec n n4 ps_extra
    if [ "$POSITIVE_CONTROL" = 1 ]; then CTL_MODE=POSITIVE_CONTROL=1 CTL_PREFIX=positive_control_
    else CTL_MODE=NEGATIVE_CONTROL=1 CTL_PREFIX=negative_control_
    fi
    if [ "$POSITIVE_CONTROL" = 1 ] && [ "$NEGATIVE_CONTROL" = 1 ]; then
        CTL_REFUSAL="not with NEGATIVE_CONTROL=1: one control per window"; return 1
    fi
    for spec in "NETLOSS $NETLOSS" "SLEEP $SLEEP" "IFSWITCH $IFSWITCH"; do
        # shellcheck disable=SC2086
        set -- $spec
        [ "$2" != 1 ] || { CTL_REFUSAL="not with $1=1: one owner-attended mode per window"; return 1; }
    done
    [ "$LEAK_CAPTURE" = 1 ] || { CTL_REFUSAL="needs LEAK_CAPTURE=1: a control without the captures shows nothing"; return 1; }
    [ "$FILTER_RC" = 0 ] \
        || { CTL_REFUSAL="needs the leak-guard filter configured, enabled and attached before the window (host --filter-status exit $FILTER_RC)"; return 1; }
    n=$(printf '%s\n' "$LEAK_IFACES_NOW" | grep -c .)
    [ "$n" -ge 1 ] || n=1
    for spec in "PRESOCK_N $PRESOCK_N 1 4" "PRESOCK_WAIT_S $PRESOCK_WAIT_S 1 15" "PRESOCK_LIMIT_S $PRESOCK_LIMIT_S 1 5"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { CTL_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    [ -x "$PROBE_PY" ] || { CTL_REFUSAL="no probe interpreter ($PROBE_PY missing)"; return 1; }
    # S20h: the helpers' keepalive, idle/intvl/cnt.
    spec=bad
    case "/$PRESOCK_KEEPALIVE/" in
        */0*|*//*|*[!0-9/]*) ;;
        /*/*/*/*/*) ;;
        /*/*/*/) spec=ok ;;
    esac
    # shellcheck disable=SC2046
    set -- $(printf '%s' "$PRESOCK_KEEPALIVE" | tr '/' ' ')
    if [ "$spec" != ok ] || [ "$#" != 3 ] || ! nl_int x "$1" 1 10 || ! nl_int x "$2" 1 10 || ! nl_int x "$3" 2 120; then
        CTL_REFUSAL="PRESOCK_KEEPALIVE=$PRESOCK_KEEPALIVE is not idle/intvl/cnt (idle and intvl 1..10 s, cnt 2..120)"; return 1
    fi
    PS_KA_SPAN=$((2 * $2 + 2))
    # S20g: per interface with an IPv4 address now, the helper's open (every
    # port and socket at its bound), the write's wait and two status reads;
    # S20h: and, positive, the time between the reads.
    n4=0
    for spec in $LEAK_IFACES_NOW; do [ "$(om_inet "$spec")" = 0 ] || n4=$((n4 + 1)); done
    [ "$n4" -ge 1 ] || n4=1
    ps_extra=$((n4 * ((4 + PRESOCK_N) * PRESOCK_LIMIT_S + PRESOCK_WAIT_S + 25)))
    [ "$POSITIVE_CONTROL" = 1 ] && ps_extra=$((ps_extra + n4 * PS_KA_SPAN))
    if [ "$POSITIVE_CONTROL" = 1 ]; then
        for spec in "PC_PROBES $PC_PROBES 1 10" "PC_TIMEOUT_S $PC_TIMEOUT_S 1 5" "PC_SPORT_BASE $PC_SPORT_BASE 1024 64000"; do
            # shellcheck disable=SC2086
            set -- $spec
            nl_int "$@" || { CTL_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
        done
        [ "$RELAY_PORT" != "$PC_PORT" ] || { CTL_REFUSAL="the relay port is $PC_PORT, the probes' port: never probe the relay port"; return 1; }
        # S20h review: the fresh probes' source ports never in the marker
        # range. Interface k of the probed ones (at most the n interfaces
        # now) uses PC_SPORT_BASE + k * PC_PROBES and the PC_PROBES - 1
        # ports after it (pc_window).
        if [ $((PC_SPORT_BASE + n * PC_PROBES)) -gt "$PS_MARK_SPORT_FIRST" ] \
                && [ "$PC_SPORT_BASE" -lt $((PS_MARK_SPORT_FIRST + PS_MARK_SPORT_COUNT)) ]; then
            CTL_REFUSAL="PC_SPORT_BASE=$PC_SPORT_BASE puts a probe's source port in the pre-existing sockets' marker range"; return 1
        fi
        # Two status reads (30 s bound each) and the probes, per interface.
        CTL_EXTRA_S=$((n * (PC_PROBES * PC_TIMEOUT_S + 20) + ps_extra))
        CTL_SUMMARY="probes=$PC_PROBES port=$PC_PORT timeout=${PC_TIMEOUT_S}s presock=$PRESOCK_N wait=${PRESOCK_WAIT_S}s"
    else
        for spec in "NC_DISABLE_BOUND_S $NC_DISABLE_BOUND_S 30 300" "NC_ENABLE_BOUND_S $NC_ENABLE_BOUND_S 30 300" \
            "NC_ATTACH_WAIT_S $NC_ATTACH_WAIT_S 5 120"; do
            # shellcheck disable=SC2086
            set -- $spec
            nl_int "$@" || { CTL_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
        done
        [ -x "$NC_PY" ] || { CTL_REFUSAL="no filter rollback can restore the leak guard ($NC_PY missing)"; return 1; }
        CTL_EXTRA_S=$ps_extra
        CTL_SUMMARY="disable_bound=${NC_DISABLE_BOUND_S}s enable_bound=${NC_ENABLE_BOUND_S}s attach_wait=${NC_ATTACH_WAIT_S}s presock=$PRESOCK_N wait=${PRESOCK_WAIT_S}s"
    fi
    return 0
}

# Every window, right after its first --filter-status (FILTER_RC): a
# NEGATIVE_CONTROL window that never restored its filter left NC_MARKER.
# Refuses (CTL_REFUSAL, return 1) while the filter is not attached; removes
# the marker once it is and the marker's window is gone.
ctl_marker_check() {
    local pid st
    [ -e "$NC_MARKER" ] || return 0
    if [ "$FILTER_RC" != 0 ]; then
        CTL_REFUSAL="an interrupted NEGATIVE_CONTROL window left the leak-guard filter disabled ($NC_MARKER: $(head -c 160 "$NC_MARKER" | tr -d '\n'); host --filter-status exit $FILTER_RC): run $HOST_BIN --enable-filter until --filter-status exits 0"
        return 1
    fi
    pid=$(sed -n 's/.* pid=\([0-9][0-9]*\) .*/\1/p' "$NC_MARKER" | head -1)
    st=''
    [ -n "$pid" ] && st=$(ps -p "$pid" -o stat= 2>/dev/null)
    if [ -n "$st" ] && [ "${st#Z}" = "$st" ]; then
        say "negative_control_marker: kept, its window (pid $pid) is still running"
        return 0
    fi
    rm -f "$NC_MARKER"
    say "negative_control_marker: removed, the leak-guard filter is attached again (--filter-status exit 0)"
}

# One --filter-status into $OUT/filter-status-<name>.txt; its exit code.
ctl_status() {
    nl_bounded 40 "$HOST_BIN" --filter-status >"$OUT/filter-status-$1.txt" 2>/dev/null
}

# ------------------------------------------------------------ negative control

# Arms the detached filter rollback; true once it is confirmed alive,
# adopted by launchd (ppid 1) and the leader of its own process group.
nc_arm() {
    local delay=$1 launcher info
    NC_TOKEN=$(uuidgen) NC_RB_LOG="$OUT/filter-rollback.log" NC_CANCEL="$OUT/filter-rollback.cancel" NC_RB_PID=''
    nohup "$NC_PY" -I - "$HOST_BIN" "$$" "$delay" "$NC_RB_LOG" "$NC_CANCEL" "$NC_TOKEN" "$NC_ENABLE_BOUND_S" \
        "$NC_ATTACH_WAIT_S" "$NC_MARKER" >/dev/null 2>&1 <<'PY' &
import os, signal, subprocess, sys, time
host, window, delay, logp, cancel, token, enable_bound, attach_wait, marker = sys.argv[1:10]
# The launcher only forks the rollback and exits: its child is adopted by
# launchd and is never a descendant of the window.
if os.fork() > 0:
    os._exit(0)
os.setsid()
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    signal.signal(s, signal.SIG_IGN)
log = open(logp, "a", buffering=1)
log.write(f"armed pid={os.getpid()} ppid={os.getppid()} delay={delay}\n")


def status():
    try:
        return subprocess.run([host, "--filter-status"], capture_output=True, timeout=40,
                              stdin=subprocess.DEVNULL).returncode
    except (OSError, subprocess.SubprocessError) as error:
        log.write(f"status_error {type(error).__name__}\n")
        return None


def window_alive():
    try:
        os.kill(int(window), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def clear_marker():
    # Only after a verified restore, and only this window's marker.
    try:
        if f" pid={window} " in " " + open(marker).read():
            os.unlink(marker)
            log.write("marker_removed\n")
    except OSError:
        pass


end = time.monotonic() + int(delay)
while time.monotonic() < end:
    try:
        if open(cancel).read().strip() == token:
            if status() == 0:
                clear_marker()
                log.write("rollback_cancelled restored_verified\n")
                sys.exit(0)
            log.write("cancel_refused filter_not_attached\n")
            break
    except OSError:
        pass
    if not window_alive():
        log.write("window_gone\n")
        break
    time.sleep(0.25)
log.write("rollback_fired\n")
for attempt in range(1, 4):
    try:
        rc = subprocess.run([host, "--enable-filter"], capture_output=True, timeout=int(enable_bound),
                            stdin=subprocess.DEVNULL).returncode
    except (OSError, subprocess.SubprocessError) as error:
        rc = type(error).__name__
    log.write(f"enable attempt={attempt} rc={rc}\n")
    deadline = time.monotonic() + int(attach_wait)
    while time.monotonic() < deadline:
        if status() == 0:
            clear_marker()
            log.write(f"restored attempt={attempt}\nrollback_done\n")
            sys.exit(0)
        time.sleep(1)
log.write("restore_failed\nrollback_done\n")
PY
    launcher=$!
    wait "$launcher"
    for _ in $(seq 1 40); do
        NC_RB_PID=$(sed -n 's/^armed pid=\([0-9][0-9]*\) .*/\1/p' "$NC_RB_LOG" 2>/dev/null | tail -1)
        [ -n "$NC_RB_PID" ] && break
        sleep 0.05
    done
    [ -n "$NC_RB_PID" ] && [ "$NC_RB_PID" != "$launcher" ] && alive "$NC_RB_PID" || return 1
    info=$(ps -p "$NC_RB_PID" -o ppid= -o pgid= 2>/dev/null | awk '{print $1, $2}')
    [ "$info" = "1 $NC_RB_PID" ]
}

# `host --enable-filter`, then --filter-status exit 0 within
# NC_ATTACH_WAIT_S of the enable's return (the enable may wait up to
# NC_ENABLE_BOUND_S for the owner), read at least once; only then are the
# marker removed and the rollback cancelled (it re-reads exit 0 itself
# before accepting). True when restored and verified attached.
nc_restore() {
    local quiet=${1:-} rc st=none t_start=$SECONDS t0
    nl_bounded "$NC_ENABLE_BOUND_S" "$HOST_BIN" --enable-filter >"$OUT/enable-filter.stdout" 2>"$OUT/enable-filter.stderr"
    rc=$?
    t0=$SECONDS
    while :; do
        ctl_status restored
        st=$?
        [ "$st" = 0 ] && break
        [ $((SECONDS - t0)) -lt "$NC_ATTACH_WAIT_S" ] || break
        sleep 1
    done
    if [ "$st" != 0 ]; then
        CTL_FAILED="the leak-guard filter is not restored (enable rc=$rc, --filter-status exit $st); the filter rollback (pid ${NC_RB_PID:-none}) retries when this window is gone"
        [ -n "$quiet" ] || result negative_control_filter_restored fail "enable_rc=$rc status_exit=$st waited=$((SECONDS - t_start))s rollback_pid=${NC_RB_PID:-none}"
        return 1
    fi
    NC_RESTORED=1 CTL_FAILED=''
    rm -f "$NC_MARKER"
    echo "$NC_TOKEN" > "$NC_CANCEL"
    [ -n "$quiet" ] || result negative_control_filter_restored pass "enable_rc=$rc status_exit=0 waited=$((SECONDS - t_start))s"
    for _ in $(seq 1 60); do
        grep -qE '^(rollback_cancelled|rollback_done)' "$NC_RB_LOG" 2>/dev/null && break
        sleep 0.25
    done
    [ -n "$quiet" ] || result negative_control_rollback_ended info "$(tail -1 "$NC_RB_LOG" 2>/dev/null)"
    return 0
}

# NEGATIVE_CONTROL=1, before any capture: the rollback, then the disable
# (the owner's administrator prompt) read back as disabled.
nc_disable() {
    local delay rc st
    delay=$((NC_DISABLE_BOUND_S + ROLLBACK_S + NC_ENABLE_BOUND_S + NC_ATTACH_WAIT_S + 120))
    # The marker outlives a reboot, a logout or a power loss, which stop
    # the EXIT trap and the rollback alike.
    if ! mkdir -p "${NC_MARKER%/*}" || ! printf 'start=%s pid=%s out=%s\n' "$(now)" "$$" "$OUT" > "$NC_MARKER"; then
        CTL_REFUSAL="the interrupted-control marker $NC_MARKER could not be written; the filter was not disabled"
        return 1
    fi
    if ! nc_arm "$delay"; then
        rm -f "$NC_MARKER"
        CTL_REFUSAL="the filter rollback was not confirmed (pid ${NC_RB_PID:-none}); the filter was not disabled"
        return 1
    fi
    result negative_control_rollback_armed pass "pid=$NC_RB_PID fires_after=${delay}s or_when_the_window_is_gone"
    printf '\a'
    say "OWNER ACTION: approve the administrator prompt that turns the AEGIS leak guard off for this negative control (within ${NC_DISABLE_BOUND_S}s); it is turned on again after the disconnect"
    NC_DISABLED=1
    nl_bounded "$NC_DISABLE_BOUND_S" "$HOST_BIN" --disable-filter >"$OUT/disable-filter.stdout" 2>"$OUT/disable-filter.stderr"
    rc=$?
    ctl_status disabled
    st=$?
    if [ "$rc" != 0 ] || [ "$st" != 31 ]; then
        result negative_control_filter_disabled fail "rc=$rc status_exit=$st $(grep '^filter_result=' "$OUT/disable-filter.stdout" | tail -n 1 | cut -c1-120)"
        nc_restore
        CTL_REFUSAL="the filter was not disabled (host exit $rc, --filter-status exit $st)"
        return 1
    fi
    result negative_control_filter_disabled pass "rc=0 status_exit=31"
    return 0
}

# ------------------------------------------------------------ positive control

# The on-link IPv4 default gateway of DEV, printed only when it is inside
# DEV's own IPv4 subnet, is neither DEV's address nor the relay, and the
# scoped default route names DEV. Memory and argv only, never recorded.
pc_gateway() {
    local dev=$1 gw
    gw=$(route -n get -ifscope "$dev" default 2>/dev/null | awk '/gateway:/{g=$2} /interface:/{i=$2} END{if (i!="") print g, i}')
    [ "${gw#* }" = "$dev" ] || return 1
    gw=${gw% *}
    ifconfig "$dev" 2>/dev/null | python3 -I -c '
import ipaddress, sys
gw, relay = sys.argv[1], sys.argv[2]
try:
    g = ipaddress.IPv4Address(gw)
except ValueError:
    sys.exit(1)
for line in sys.stdin:
    f = line.split()
    if len(f) >= 4 and f[0] == "inet" and f[2] == "netmask":
        try:
            a = ipaddress.IPv4Address(f[1])
            mask = int(f[3], 16) if f[3].startswith("0x") else int(ipaddress.IPv4Address(f[3]))
            net = ipaddress.IPv4Network((int(a) & mask, bin(mask).count("1")))
        except ValueError:
            continue
        if g in net and g != a and gw != relay and not g.is_multicast and g != net.broadcast_address:
            print(gw)
            sys.exit(0)
sys.exit(1)' "$gw" "$RELAY_IP"
}

# After the captures started: the captured interfaces with an IPv4 address
# and an on-link gateway (CTL_IFS, CTL_GWS) and the others (CTL_SKIPPED).
ctl_gateways() {
    local dev gw
    CTL_IFS=() CTL_GWS=() CTL_SKIPPED=''
    for dev in $LEAK_IFACES; do
        if [ "$(om_inet "$dev")" = 0 ]; then CTL_SKIPPED="${CTL_SKIPPED:+$CTL_SKIPPED,}$dev:no_ipv4"; continue; fi
        if ! gw=$(pc_gateway "$dev") || [ -z "$gw" ]; then CTL_SKIPPED="${CTL_SKIPPED:+$CTL_SKIPPED,}$dev:no_lan_gateway"; continue; fi
        CTL_IFS+=("$dev") CTL_GWS+=("$gw")
    done
}

# POSITIVE_CONTROL=1, after the captures started: the interfaces to probe
# (captured, an IPv4 address, an on-link gateway); refuses when none.
pc_prepare() {
    local i=0
    while [ "$i" -lt "${#CTL_IFS[@]}" ]; do
        # S20h: not_run until pc_window probes it (a window that never
        # reaches Connected never probes: never an answered probe).
        PC_IFS+=("${CTL_IFS[$i]}") PC_GWS+=("${CTL_GWS[$i]}") PC_DELTA+=(fail) PC_PROBE+=(not_run) PC_PENDING+=(0)
        i=$((i + 1))
    done
    result positive_control_ifaces info "probe=$(printf '%s' "${PC_IFS[*]:-none}" | tr ' ' ',') skipped=${CTL_SKIPPED:-none} probes=$PC_PROBES port=$PC_PORT"
    [ "${#PC_IFS[@]}" -ge 1 ] || { CTL_REFUSAL="no captured interface has an IPv4 address and an on-link default gateway to probe"; return 1; }
}

# The filter_drop_delta row of DEV from its --filter-status right before
# and right after the probes: `<pass|fail> <detail>`. Pass needs both
# readings guarding under the same arm (arm_seq and disarms unchanged), the
# out-drop counter of DEV's class grown by at least NEED, and at least NEED
# new ring records (index at or past the earlier reading's ring.next) of an
# outbound IPv4 TCP SYN dropped as drop_tcp_out on DEV itself: the class
# counter alone also counts every other drop on any interface of the class.
# Interface tokens and classes follow the provider's iface_code and
# drop_class. ring_lost counts new records no longer in the ring (more than
# 64 drops, or skipped and torn slots).
pc_drop_delta() { ctl_drop_delta syn "$1" "$2" "$3" "$PC_PROBES"; }

# S20g: ctl_drop_delta MODE BEFORE AFTER DEV NEED, MODE syn: pc_drop_delta's
# rule. S20h: the presock mode is gone; the pre-existing sockets are judged
# by leak_review.py presock-review (presock_keepalive_drops).
ctl_drop_delta() {
    python3 -I -c '
import json, re, sys
mode, before_path, after_path, dev, need = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
PREFIXES = ("en", "awdl", "llw", "bridge", "ap", "anpi", "utun", "ipsec", "lo", "gif", "stf", "pktap",
            "vmenet", "vmnet", "vnic")


def report(path):
    rep = None
    try:
        for line in open(path, errors="replace"):
            line = line.strip()
            if line.startswith("{"):
                v = json.loads(line)
                if isinstance(v, dict) and v.get("verb") == "filter-status":
                    rep = v.get("report")
    except (OSError, ValueError):
        return None
    return rep if isinstance(rep, dict) else None


def token(name):
    for prefix in PREFIXES:
        if name.startswith(prefix) and re.fullmatch(r"(0|[1-9][0-9]{0,3})", name[len(prefix):]):
            return name
    raw = name.encode()
    h = 0x811C9DC5
    for byte in raw[:32]:
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    h = ((h ^ min(len(raw), 255)) * 0x01000193) & 0xFFFFFFFF
    return "h:%08x" % max(h & 0x7FFFFFFF, 1)


def nat(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


tok = token(dev)


def klass(o):
    if tok == o.get("primary_iface"):
        return "primary"
    for c, pat in (("en_other", r"en(0|[1-9][0-9]{0,3})"), ("awdl_llw", r"(awdl|llw)(0|[1-9][0-9]{0,3})"),
                   ("bridge_ap_anpi", r"(bridge|ap|anpi)(0|[1-9][0-9]{0,3})")):
        if re.fullmatch(pat, dev):
            return c
    return "other"


def out_of(o, c):
    row = o["drops"].get(c)
    return row.get("out") if isinstance(row, dict) else None


b, a = report(before_path), report(after_path)
ob = b.get("observability") if b else None
oa = a.get("observability") if a else None
if not all(isinstance(o, dict) and isinstance(o.get("drops"), dict) for o in (ob, oa)):
    print("fail unavailable: no observability in --filter-status need=%d" % need); sys.exit()
c = klass(ob)
ob_out, oa_out = out_of(ob, c), out_of(oa, c)
if b.get("mode") != "guarding":
    print("fail mode=%s: the filter was not armed class=%s need=%d" % (b.get("mode", "?"), c, need)); sys.exit()
if klass(oa) != c or not nat(ob_out) or not nat(oa_out):
    print("fail unreadable class=%s out_before=%s out_after=%s need=%d" % (
        c, ob_out if nat(ob_out) else "?", oa_out if nat(oa_out) else "?", need)); sys.exit()
arms = [(o.get("arm_seq"), o.get("disarms")) for o in (ob, oa)]
if a.get("mode") != "guarding" or not all(nat(x) for arm in arms for x in arm) or arms[0] != arms[1]:
    print("fail rearmed: mode_after=%s arm_seq=%s->%s disarms=%s->%s: not one arm through the probes class=%s need=%d" % (
        a.get("mode", "?"), arms[0][0], arms[1][0], arms[0][1], arms[1][1], c, need)); sys.exit()
rb, ra = ob.get("ring"), oa.get("ring")
nb = rb.get("next") if isinstance(rb, dict) else None
na = ra.get("next") if isinstance(ra, dict) else None
entries = ra.get("entries") if isinstance(ra, dict) else None
if not nat(nb) or not nat(na) or na < nb or not isinstance(entries, list) \
        or not all(isinstance(e, dict) and nat(e.get("index")) for e in entries):
    print("fail unreadable ring class=%s out_before=%d out_after=%d need=%d" % (c, ob_out, oa_out, need)); sys.exit()
new = [e for e in entries if nb <= e["index"] < na]
delta = oa_out - ob_out
lost = (na - nb) - len(new)


def out_tcp(e, kind):
    return (e.get("iface") == tok and e.get("dir") == "out" and e.get("family") == "v4" and e.get("proto") == 6
            and e.get("tcp") == kind and e.get("reason") == "drop_tcp_out")


syn = sum(1 for e in new if out_tcp(e, "syn"))
print("%s class=%s out_before=%d out_after=%d delta=%d syn_drops=%d ring_lost=%d need=%d" % (
    "pass" if mode == "syn" and delta >= need and syn >= need else "fail", c, ob_out, oa_out, delta, syn, lost,
    need))' "$@" 2>/dev/null
}

# While Connected: the marked probes of every interface, between two
# --filter-status reads. S20g: an interface whose probes all connected
# keeps its probe_failed and filter_drop_delta rows for pc_bpf_order, which
# can tell an answer from the tunnel's own engine only after the captures
# and the provider log.
pc_window() {
    local i=0 dev gw base out rc v
    while [ "$i" -lt "${#PC_IFS[@]}" ]; do
        dev=${PC_IFS[$i]} gw=${PC_GWS[$i]} base=$((PC_SPORT_BASE + i * PC_PROBES))
        PC_FROM[$i]=$RESULT_FROM
        ctl_status "pc-$dev-before"
        PC_T0[$i]=$(epoch)
        out=$("$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" boundsyn "$dev" "$gw" "$PC_PORT" "$PC_PROBES" "$base" "$PC_TIMEOUT_S" 2>/dev/null)
        rc=$?
        PC_T1[$i]=$(epoch)
        PC_AT[$i]=$(scutil --nc status "$SID" | head -1)
        # 0: every probe timed out; 1: one was answered (the SYN out, the
        # answer in); 3: none answered, one never sent (says nothing).
        case "$rc" in
            0) PC_PROBE[$i]=pass ;;
            3) PC_PROBE[$i]=unavailable ;;
            *) PC_PROBE[$i]=fail ;;
        esac
        PC_OUT[$i]="${out:-no_output} rc=$rc port=$PC_PORT"
        PC_PENDING[$i]=0
        if [ "$rc" = 1 ]; then
            case "$out" in "probes=$PC_PROBES failed=0 kinds=connected:$PC_PROBES "*) PC_PENDING[$i]=1 ;; esac
        fi
        [ "${PC_PENDING[$i]}" = 1 ] || result_since "${PC_FROM[$i]:-$RESULT_FROM}" "probe_failed_$dev" "${PC_PROBE[$i]}" "${PC_OUT[$i]}"
        ctl_status "pc-$dev-after"
        v=$(pc_drop_delta "$OUT/filter-status-pc-$dev-before.txt" "$OUT/filter-status-pc-$dev-after.txt" "$dev")
        case "$v" in
            "pass "*) PC_DELTA[$i]=pass ;;
            "fail "*) ;;
            *) v="fail unreadable: --filter-status not parsed need=$PC_PROBES" ;;
        esac
        PC_DVAL[$i]=${v#* }
        # v31 review: its first read came before the probe_failed row.
        [ "${PC_PENDING[$i]}" = 1 ] || result_since "${PC_FROM[$i]:-$RESULT_FROM}" "filter_drop_delta_$dev" "${PC_DELTA[$i]}" "${PC_DVAL[$i]}"
        i=$((i + 1))
    done
}

# S20g: the provider's `engine_flow_open class:discard` lines (a v28
# engine answering a flow to port 9) with a wall time in [T0, T1]: their
# count, or none when the log holds no engine_flow_open line of any class
# (a provider before v28, or no log).
pc_engine_opens() {
    python3 -I -c '
import re, sys
t0, t1 = float(sys.argv[2]), float(sys.argv[3])
pat = re.compile(r"aegis-ne engine_flow_open class:([a-z_]+) n:[0-9]+ wall:([0-9]+(?:[.][0-9]+)?)(?:\s|$)")
seen = count = 0
try:
    lines = open(sys.argv[1], errors="replace").read().splitlines()
except OSError:
    lines = []
for line in lines:
    m = pat.search(line)
    if m:
        seen += 1
        count += m.group(1) == "discard" and t0 <= float(m.group(2)) <= t1
print(count if seen else "none")' "$OUT/provider.log" "$1" "$2" 2>/dev/null || echo none
}

# S20g: the marked SYNs of the probes from BASE to GW in every capture of
# the window, summed; unreadable when one capture cannot be read.
pc_syns_all() {
    local gw=$1 base=$2 f n total=0
    for f in "$OUT"/physical.pcap "$OUT"/physical-*.pcap; do
        [ -e "$f" ] || continue
        n=$(python3 -I "$HARNESS_DIR/leak_review.py" probe-syns --pcap "$f" --dst "$gw" --dport "$PC_PORT" \
            --sport-min "$base" --sport-max $((base + PC_PROBES - 1)) 2>/dev/null | sed -n 's/^probe_syns=\([0-9][0-9]*\) .*/\1/p')
        [ -n "$n" ] || { echo unreadable; return; }
        total=$((total + n))
    done
    echo "$total"
}

# After the captures stopped: whether each interface's capture holds the
# marked SYNs. Only when the filter counted the probes and none was
# answered: before the filter (pre_filter) when it does, after it
# (post_filter) when it does not. Otherwise unknown: a SYN the filter did
# not drop says nothing about where the tap sits. S20g: first the rows an
# interface whose probes all connected kept back (tunnel_enforced, or
# their fail as before), and every interface's bound_fresh_<if>.
pc_bpf_order() {
    local i=0 dev gw base file n opens all cls
    while [ "$i" -lt "${#PC_IFS[@]}" ]; do
        dev=${PC_IFS[$i]} gw=${PC_GWS[$i]} base=$((PC_SPORT_BASE + i * PC_PROBES))
        file=physical-$dev.pcap
        [ "$dev" = "$PHYS" ] && file=physical.pcap
        n=$(python3 -I "$HARNESS_DIR/leak_review.py" probe-syns --pcap "$OUT/$file" --dst "$gw" --dport "$PC_PORT" \
            --sport-min "$base" --sport-max $((base + PC_PROBES - 1)) 2>/dev/null | sed -n 's/^probe_syns=\([0-9][0-9]*\) .*/\1/p')
        opens=$(pc_engine_opens "${PC_T0[$i]:-0}" "${PC_T1[$i]:-0}")
        if [ "${PC_PROBE[$i]}" = not_run ]; then
            result "bound_fresh_$dev" info "not_run probe_failed=not_run: the window never probed (not Connected)"
            result "bpf_order_$dev" info "unknown not_run capture=$file"
            i=$((i + 1))
            continue
        fi
        if [ "${PC_PENDING[$i]:-0}" = 1 ]; then
            all=$(pc_syns_all "$gw" "$base")
            if [ "$all" = 0 ] && [ "$opens" != none ] && [ "$opens" -ge "$PC_PROBES" ]; then
                # The only way out of the probes' fail (pc_verdict).
                PC_PROBE[$i]=tunnel_enforced
                result_since "${PC_FROM[$i]:-$RESULT_FROM}" "probe_failed_$dev" info "tunnel_enforced ${PC_OUT[$i]} at=${PC_AT[$i]}"
                result_since "${PC_FROM[$i]:-$RESULT_FROM}" "filter_drop_delta_$dev" info "tunnel_enforced ${PC_DVAL[$i]}"
                result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bound_fresh_$dev" info "tunnel_enforced connected=$PC_PROBES engine_opens=$opens marked_syns_in_captures=0: the system routed sockets bound to $dev into the tunnel"
                result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bpf_order_$dev" info "unknown syns=${n:-unreadable} probes=$PC_PROBES capture=$file bound_fresh=tunnel_enforced: the probes never reached $dev"
                i=$((i + 1))
                continue
            fi
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "probe_failed_$dev" fail "${PC_OUT[$i]} at=${PC_AT[$i]}"
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "filter_drop_delta_$dev" "${PC_DELTA[$i]}" "${PC_DVAL[$i]}"
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bound_fresh_$dev" info "answered connected=$PC_PROBES engine_opens=$opens marked_syns_in_captures=$all"
        else
            case "${PC_PROBE[$i]}" in
                pass) cls=unanswered ;;
                unavailable) cls=not_sent ;;
                *) cls=answered ;;
            esac
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bound_fresh_$dev" info "$cls probe_failed=${PC_PROBE[$i]} engine_opens=$opens"
        fi
        if [ -z "$n" ]; then
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bpf_order_$dev" info "unknown capture_unreadable capture=$file"
        elif [ "${PC_DELTA[$i]}" != pass ]; then
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bpf_order_$dev" info "unknown syns=$n probes=$PC_PROBES capture=$file filter_drop_delta=fail: the filter did not count the probes"
        elif [ "${PC_PROBE[$i]}" != pass ]; then
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bpf_order_$dev" info "unknown syns=$n probes=$PC_PROBES capture=$file probe_failed=${PC_PROBE[$i]}: not every probe went unanswered"
        elif [ "$n" -gt 0 ]; then
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bpf_order_$dev" info "pre_filter syns=$n probes=$PC_PROBES capture=$file filter_drop_delta=pass"
        else
            result_since "${PC_FROM[$i]:-$RESULT_FROM}" "bpf_order_$dev" info "post_filter syns=0 probes=$PC_PROBES capture=$file filter_drop_delta=pass"
        fi
        i=$((i + 1))
    done
}

# ------------------------------------------------------- pre-existing sockets

# One line of a helper's state file (net_probe.py presock-read).
ps_read() { python3 -I "$HARNESS_DIR/net_probe.py" presock-read "$1" "$2" 2>/dev/null || echo none; }
ps_tok() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
# The gateway ports to try, in order, without the relay port.
ps_ports() {
    local p out=''
    for p in $PRESOCK_PORTS; do [ "$p" = "$RELAY_PORT" ] || out="${out:+$out,}$p"; done
    printf '%s' "$out"
}

# Before the lock, the rollback and the connect: one helper per interface
# of CTL_IFS, each waited for until its sockets are open (or it says the
# gateway accepts none of the ports, or fails), and presock_open_<if>.
ps_open() {
    local i=0 dev gw state pid v k bound lifetime ports
    ports=$(ps_ports)
    lifetime=$((ROLLBACK_S + 300))
    [ "$lifetime" -le 7200 ] || lifetime=7200
    bound=$((((4 + PRESOCK_N) * PRESOCK_LIMIT_S + 5) * 10))
    result presock_ifaces info "ifaces=$(printf '%s' "${CTL_IFS[*]:-none}" | tr ' ' ',') skipped=${CTL_SKIPPED:-none} n=$PRESOCK_N wait=${PRESOCK_WAIT_S}s"
    while [ "$i" -lt "${#CTL_IFS[@]}" ]; do
        dev=${CTL_IFS[$i]} gw=${CTL_GWS[$i]} state="$OUT/presock-$dev.json"
        "$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" presock "$dev" "$gw" "$ports" "$PRESOCK_N" "$state" \
            "$PRESOCK_LIMIT_S" "$PRESOCK_WAIT_S" "$lifetime" "$PRESOCK_KEEPALIVE" </dev/null >/dev/null \
            2>"$OUT/presock-$dev.stderr" &
        pid=$!
        PS_IFS+=("$dev") PS_GWS+=("$gw") PS_PIDS+=("$pid") PS_OPEN+=(fail) PS_ANSWER+=(unavailable) PS_KA+=(unavailable) \
            PS_RAN+=(0) PS_FRAMES+=(unknown) PS_CAP+=(unknown)
        v=none k=0
        while [ "$k" -lt "$bound" ]; do
            v=$(ps_read "$state" open)
            case "$v" in open\ *|unavailable\ *|failed\ *) break ;; esac
            alive "$pid" || { v=$(ps_read "$state" open); break; }
            sleep 0.1
            k=$((k + 1))
        done
        case "$v" in
            "open opened=$PRESOCK_N need=$PRESOCK_N "*) PS_OPEN[$i]=pass ;;
            unavailable\ *) PS_OPEN[$i]=unavailable ;;
            open\ *|failed\ *) ;;
            *) v="no_state helper_alive=$(alive "$pid" && echo 1 || echo 0) waited=$((k / 10))s" ;;
        esac
        result "presock_open_$dev" "${PS_OPEN[$i]}" "$v"
        i=$((i + 1))
    done
    return 0
}

# While Connected, each helper writes once. Positive (after the standard
# checks, the filter armed): between two --filter-status reads at least
# PS_KA_SPAN apart. S20h negative (right after Connected, ctl_connected):
# no read, nothing waits for the arm.
ps_write() {
    local i=0 dev state v k t_before written answered acked unacked wait_k
    wait_k=$(((PRESOCK_WAIT_S + 10) * 10))
    while [ "$i" -lt "${#PS_IFS[@]}" ]; do
        dev=${PS_IFS[$i]} state="$OUT/presock-$dev.json"
        PS_RAN[$i]=1
        if [ "$(ps_read "$state" phase)" != open ]; then
            if [ "$POSITIVE_CONTROL" = 1 ]; then
                result "presock_unacked_$dev" unavailable "not_open presock_open=${PS_OPEN[$i]}"
            else
                result "presock_acked_$dev" unavailable "not_open presock_open=${PS_OPEN[$i]}"
            fi
            i=$((i + 1))
            continue
        fi
        [ "$POSITIVE_CONTROL" = 1 ] && ctl_status "presock-$dev-before"
        t_before=$(epoch)
        printf 'write\n' > "$state.cmd.tmp" && mv -f "$state.cmd.tmp" "$state.cmd"
        k=0
        while [ "$k" -lt "$wait_k" ]; do
            [ "$(ps_read "$state" phase)" = written ] && break
            alive "${PS_PIDS[$i]}" || break
            sleep 0.1
            k=$((k + 1))
        done
        if [ "$POSITIVE_CONTROL" = 1 ]; then
            # S20h: at least two keepalives per socket between the reads.
            python3 -I -c 'import sys, time
time.sleep(max(0.0, min(float(sys.argv[2]), float(sys.argv[1]) + float(sys.argv[2]) - time.time())))' \
                "$t_before" "$PS_KA_SPAN" 2>/dev/null
            ctl_status "presock-$dev-after"
        fi
        v=$(ps_read "$state" write)
        written=$(ps_tok written "$v") answered=$(ps_tok answered "$v") acked=$(ps_tok acked "$v") unacked=$(ps_tok unacked "$v")
        if [ "$v" = none ] || [ -z "$written" ]; then
            v="no_write helper_alive=$(alive "${PS_PIDS[$i]}" && echo 1 || echo 0)"
            written=0 answered=0 acked=0 unacked=0
        fi
        if [ "$POSITIVE_CONTROL" = 1 ]; then
            # Any answer while armed fails; every written socket unacked passes.
            if [ "$answered" -gt 0 ]; then PS_ANSWER[$i]=fail
            elif [ "$written" -ge 1 ] && [ "$unacked" = "$written" ]; then PS_ANSWER[$i]=pass
            else PS_ANSWER[$i]=unavailable
            fi
            result "presock_unacked_$dev" "${PS_ANSWER[$i]}" "$v"
        else
            # S20h: a pass needs every written socket's bytes acknowledged.
            if [ "$written" -ge 1 ] && [ "$acked" = "$written" ]; then PS_ANSWER[$i]=pass
            elif [ "$written" -ge 1 ]; then PS_ANSWER[$i]=fail
            else PS_ANSWER[$i]=unavailable
            fi
            result "presock_acked_$dev" "${PS_ANSWER[$i]}" "$v"
        fi
        i=$((i + 1))
    done
}

# S20h: the rows of a helper whose write never ran (no Connected).
ps_not_connected() {
    local i=0 dev
    while [ "$i" -lt "${#PS_IFS[@]}" ]; do
        dev=${PS_IFS[$i]}
        if [ "${PS_RAN[$i]}" != 1 ]; then
            if [ "$POSITIVE_CONTROL" = 1 ]; then
                result "presock_unacked_$dev" unavailable "not_connected presock_open=${PS_OPEN[$i]}"
            else
                result "presock_acked_$dev" unavailable "not_connected presock_open=${PS_OPEN[$i]}"
            fi
        fi
        i=$((i + 1))
    done
}

# After the disconnect (and from the EXIT trap): every helper closes its
# sockets; one still running after 5 s is killed.
ps_close() {
    local quiet=${1:-} i=0 dev pid st detail=''
    while [ "$i" -lt "${#PS_IFS[@]}" ]; do
        dev=${PS_IFS[$i]} pid=${PS_PIDS[$i]}
        if [ -n "$pid" ]; then
            PS_PIDS[$i]=
            if alive "$pid"; then
                printf 'close\n' > "$OUT/presock-$dev.json.cmd.tmp" && mv -f "$OUT/presock-$dev.json.cmd.tmp" "$OUT/presock-$dev.json.cmd"
                for _ in $(seq 1 50); do alive "$pid" || break; sleep 0.1; done
                alive "$pid" && kill "$pid" 2>/dev/null
            fi
            st=$(ps_read "$OUT/presock-$dev.json" phase)
            detail="$detail $dev:$st"
        fi
        i=$((i + 1))
    done
    [ -n "$quiet" ] || [ -z "$detail" ] || result presock_closed info "${detail# }"
}

# S20h review: whether the capture of interface $1 covered the armed span
# whole, $2 its frames after the disarm (leak_review.py after_disarm):
# alive at the disconnect, stopped by the window, `0 packets dropped by
# kernel` in its tcpdump stderr, and at least one frame after DISARMED_AT.
# Prints complete, or every reason as `<if>:<reason>`, comma-separated.
ps_capture_state() {
    local dev=$1 after=$2 alive='' stopped='' err j=0 dr out=''
    if [ "$dev" = "$PHYS" ]; then
        alive=$CAP_ALIVE stopped=$CAP_STOPPED err="$OUT/tcpdump.stderr"
    else
        while [ "$j" -lt "${#XC_IFS[@]}" ]; do
            [ "${XC_IFS[$j]}" = "$dev" ] && alive=${XC_ALIVE[$j]} stopped=${XC_STOPPED[$j]}
            j=$((j + 1))
        done
        err="$OUT/tcpdump-$dev.stderr"
    fi
    if [ -z "$alive" ]; then printf '%s:no_capture' "$dev"; return 0; fi
    dr=$(drops_of "$err")
    [ "$alive" = 1 ] || out="$out,$dev:capture_alive=${alive:-0}"
    [ "$stopped" = 1 ] || out="$out,$dev:capture_stopped=${stopped:-0}"
    [ "$dr" = 0 ] || out="$out,$dev:kernel_drops=${dr:-unknown}"
    case "$after" in ''|*[!0-9]*|0) out="$out,$dev:after_disarm=${after:-unknown}" ;; esac
    printf '%s' "${out:-,complete}" | cut -c2-
}

# After the captures stopped. S20h positive: leak_review.py presock-review
# of each interface (the keepalive criterion, what the filter counted, and
# the helper's frames in that capture during the armed span, beyond the
# marked drops of their kind or not); then presock_bpf_order. Negative: its
# frames from the write to 1 s after the end of the wait (a capture's
# timestamps may trail the helper's clock reading), and over the Connected
# interval (presock_wire).
ps_captures() {
    local i=0 dev gw file set port lports args v times since until n d u a te p cap out ka counted frames written
    while [ "$i" -lt "${#PS_IFS[@]}" ]; do
        dev=${PS_IFS[$i]} gw=${PS_GWS[$i]}
        file=physical-$dev.pcap
        [ "$dev" = "$PHYS" ] && file=physical.pcap
        set=$(ps_read "$OUT/presock-$dev.json" ports)
        port=${set%% *} lports=${set#* }
        args=()
        if [ -n "$set" ] && [ "$lports" != "$set" ]; then
            args=(--pcap "$OUT/$file" --dst "$gw" --dport "$port")
            for v in $lports; do args+=(--sport "$v"); done
        fi
        if [ "$POSITIVE_CONTROL" = 1 ]; then
            PS_FRAMES[$i]=unknown PS_KA[$i]=unavailable
            if [ "${#args[@]}" = 0 ]; then
                PS_FRAMES[$i]=none
                result "presock_keepalive_drops_$dev" unavailable "no_sockets presock_open=${PS_OPEN[$i]}"
                result "presock_counted_$dev" info "unknown no_sockets"
                result "presock_bpf_order_$dev" info "unknown no_sockets capture=$file presock_open=${PS_OPEN[$i]}"
                i=$((i + 1))
                continue
            fi
            out=$(python3 -I "$HARNESS_DIR/leak_review.py" presock-review --pcap "$OUT/$file" --state "$OUT/presock-$dev.json" \
                --dst "$gw" --dev "$dev" --before "$OUT/filter-status-presock-$dev-before.txt" \
                --after "$OUT/filter-status-presock-$dev-after.txt" --span-before "$OUT/filter-status-before.txt" \
                --span-after "$OUT/filter-status-after.txt" ${ARMED_AT:+--armed-at "$ARMED_AT"} \
                ${DISARMED_AT:+--disarmed-at "$DISARMED_AT"} 2>/dev/null)
            ka=$(printf '%s\n' "$out" | sed -n 1p) counted=$(printf '%s\n' "$out" | sed -n 2p) frames=$(printf '%s\n' "$out" | sed -n 3p)
            if [ "${PS_RAN[$i]}" != 1 ] || [ "$(ps_read "$OUT/presock-$dev.json" times)" = none ]; then
                # No write, so no reads around it: nothing to count.
                ka="unavailable not_written presock_open=${PS_OPEN[$i]}" counted="unknown not_written"
            fi
            case "$ka" in
                "pass "*) PS_KA[$i]=pass ;;
                "fail "*) PS_KA[$i]=fail ;;
                "unavailable "*) PS_KA[$i]=unavailable ;;
                *) PS_KA[$i]=fail ka="fail unreadable: presock-review gave no verdict" ;;
            esac
            result "presock_keepalive_drops_$dev" "${PS_KA[$i]}" "${ka#* }"
            result "presock_counted_$dev" info "${counted:-unknown unreadable}"
            n='' d='' u='' a='' te=''
            case "$frames" in
                frames=[0-9]*)
                    v=${frames#frames=}
                    n=${v%% *} d=$(ps_tok data "$v") u=$(ps_tok uncounted "$v") a=$(ps_tok after_disarm "$v")
                    te=$(ps_tok tap_evidence "$v")
                    case "$n$d$u$a" in ''|*[!0-9]*) n='' ;; esac ;;
            esac
            if [ -z "$n" ] || [ -z "$d" ] || [ -z "$u" ] || [ -z "$a" ]; then
                result "presock_bpf_order_$dev" info "unknown ${frames#frames=unknown } capture=$file"
                i=$((i + 1))
                continue
            fi
            # S20h review: only a complete capture shows what left, and only
            # one under a passing armed span ties the filter's drops between
            # the reads to the frames counted in [arm, disarm].
            cap=$(ps_capture_state "$dev" "$a")
            PS_CAP[$i]=$cap
            p=0
            [ "$cap" = complete ] && [ "$te" = post_filter ] && [ "${SPAN_VERDICT:-}" = pass ] && p=1
            PS_FRAMES[$i]="$n $d $u $p"
            # The helper's frames in the capture while armed are frames the
            # filter dropped after a tap before it, or frames that left:
            # never read as pre_filter. S20h review: they left when the
            # filter dropped more of the marker's segments of one kind on
            # that interface between the reads than its complete capture
            # holds (a tap before the filter records every dropped frame).
            if [ "$cap" != complete ]; then
                result "presock_bpf_order_$dev" info "unknown frames=$v capture=$file capture_incomplete=$cap: the capture did not cover the armed span whole"
            elif [ "$p" = 1 ] && [ "$n" -gt 0 ]; then
                result "presock_bpf_order_$dev" info "post_filter frames=$v capture=$file presock_keepalive_drops=${PS_KA[$i]} span=armed: the filter dropped more of the marker's segments on this interface than its capture holds, so its tap comes after the filter and the helper's frames in it while armed left the Mac"
            elif [ "$p" = 1 ]; then
                result "presock_bpf_order_$dev" info "post_filter frames=$v capture=$file presock_keepalive_drops=${PS_KA[$i]} span=armed"
            elif [ "${PS_KA[$i]}" != pass ]; then
                result "presock_bpf_order_$dev" info "unknown frames=$v capture=$file presock_keepalive_drops=${PS_KA[$i]}: the filter's count of the helper's keepalives did not pass"
            elif [ "$n" -gt 0 ]; then
                result "presock_bpf_order_$dev" info "unknown frames=$v capture=$file presock_keepalive_drops=pass span=armed: the helper's frames are in the capture while armed; they may be frames the filter dropped after the tap or frames that left"
            else
                result "presock_bpf_order_$dev" info "unknown frames=$v capture=$file presock_keepalive_drops=pass filter_armed_span=${SPAN_VERDICT:-unknown}: no tap evidence under one arm through the window"
            fi
        else
            times=$(ps_read "$OUT/presock-$dev.json" times)
            written=$(ps_tok written "$(ps_read "$OUT/presock-$dev.json" write)")
            if [ "${#args[@]}" = 0 ] || [ "$times" = none ]; then
                result "presock_frames_$dev" info "unknown no_write capture=$file"
            elif [ "${written:-0}" = 0 ]; then
                result "presock_frames_$dev" info "unknown nothing_written capture=$file presock_acked=${PS_ANSWER[$i]}"
            else
                since=${times%% *} until=${times#* }
                v=$(python3 -I "$HARNESS_DIR/leak_review.py" presock-frames "${args[@]}" --since "$since" \
                    --until "$(python3 -I -c 'import sys; print("%.6f" % (float(sys.argv[1]) + 1))' "$until")" 2>/dev/null)
                case "$v" in
                    presock_frames=[0-9]*) result "presock_frames_$dev" info "frames=${v#presock_frames=} capture=$file span=write+1s presock_acked=${PS_ANSWER[$i]}" ;;
                    *) result "presock_frames_$dev" info "unknown capture_unreadable capture=$file" ;;
                esac
            fi
            # S20h: the helper's frames on the wire while Connected, its
            # keepalives among them: expected present with the filter off.
            if [ "${#args[@]}" = 0 ]; then
                result "presock_wire_$dev" info "unknown no_sockets capture=$file"
            elif [ -z "$CONNECTED_AT" ] || [ -z "$DISCONNECT_AT" ]; then
                result "presock_wire_$dev" info "unknown not_connected capture=$file"
            else
                v=$(python3 -I "$HARNESS_DIR/leak_review.py" presock-frames "${args[@]}" --since "$CONNECTED_AT" \
                    --until "$DISCONNECT_AT" 2>/dev/null)
                case "$v" in
                    presock_frames=[0-9]*) result "presock_wire_$dev" info "frames=${v#presock_frames=} capture=$file span=connected: the helper's frames with the filter off, its keepalives expected among them, ack_only_marked those carrying the provider's marker" ;;
                    *) result "presock_wire_$dev" info "unknown capture_unreadable capture=$file" ;;
                esac
            fi
        fi
        i=$((i + 1))
    done
}

# The positive control's verdict. While armed the filter also drops the
# gateway's answers inbound, so presock_unacked passing says nothing about
# the outbound bytes; the capture does. Fail, on any interface, when
# written bytes were answered (presock_unacked fail), when a fresh probe
# was answered (probe_failed fail: not pass, unavailable or
# tunnel_enforced), or when a capture holds more of the helper's frames of
# a kind during the armed span than the filter counted marked drops of that
# kind (uncounted: they left), or (S20h review) any helper frame while
# armed in a complete capture whose tap is shown to come after the filter
# (frames_left: the filter dropped more of the marker's segments of one
# kind on that interface between the reads than the capture holds).
# Pass only with presock_open, presock_unacked and presock_keepalive_drops
# passed on the primary interface and no frame of any helper in any capture
# during the armed span, every helper's capture counted and complete (S20h
# review: alive at the disconnect, stopped, no kernel drop, a frame after
# the disarm; a lost frame could be a transmission that left): a counted
# frame in a capture may be one the filter dropped after the tap or one
# that left, and only the tap evidence settles which. Unavailable
# otherwise.
pc_verdict() {
    local i=0 k=-1 answered='' fresh='' uncounted='' left='' seen='' unchecked='' checked='' incomplete='' fails='' why='' dev
    while [ "$i" -lt "${#PC_IFS[@]}" ]; do
        [ "${PC_PROBE[$i]}" = fail ] && fresh="${fresh:+$fresh,}${PC_IFS[$i]}"
        i=$((i + 1))
    done
    i=0
    while [ "$i" -lt "${#PS_IFS[@]}" ]; do
        dev=${PS_IFS[$i]}
        [ "${PS_ANSWER[$i]}" = fail ] && answered="${answered:+$answered,}$dev"
        case "${PS_FRAMES[$i]:-unknown}" in
            none) ;;
            [0-9]*\ [0-9]*\ [0-9]*\ [01])
                checked="${checked:+$checked,}$dev"
                # shellcheck disable=SC2086
                set -- ${PS_FRAMES[$i]}
                if [ "$3" -gt 0 ]; then uncounted="${uncounted:+$uncounted,}$dev"
                elif [ "$1" -gt 0 ] && [ "$4" = 1 ]; then left="${left:+$left,}$dev"
                elif [ "$1" -gt 0 ]; then seen="${seen:+$seen,}$dev"
                fi
                [ "${PS_CAP[$i]}" = complete ] || incomplete="${incomplete:+$incomplete,}${PS_CAP[$i]}" ;;
            *) unchecked="${unchecked:+$unchecked,}$dev" ;;
        esac
        [ "$dev" = "$PHYS" ] && k=$i
        i=$((i + 1))
    done
    if [ -n "$answered" ]; then
        fails="answered_while_armed=$answered" why="written bytes of a pre-existing socket were answered while the filter was armed"
    fi
    if [ -n "$fresh" ]; then
        fails="${fails:+$fails }fresh_probe_answered=$fresh"
        why="${why:+$why; }a fresh probe bound to that interface was answered while the filter was armed (probe_failed fail)"
    fi
    if [ -n "$uncounted" ]; then
        fails="${fails:+$fails }uncounted_frames=$uncounted"
        why="${why:+$why; }that interface's capture holds more of the helper's frames while armed than the filter counted marked drops of their kind: they left the Mac"
    fi
    if [ -n "$left" ]; then
        fails="${fails:+$fails }frames_left=$left"
        why="${why:+$why; }that interface's complete capture holds the helper's frames while armed but fewer of the marker's frames than the filter dropped on it, so its tap comes after the filter: they left the Mac"
    fi
    if [ -n "$fails" ]; then
        result positive_control_verdict fail "$fails primary=$PHYS: $why"
    elif [ "$k" -lt 0 ]; then
        result positive_control_verdict unavailable "primary=$PHYS not_probed presock_ifaces=$(printf '%s' "${PS_IFS[*]:-none}" | tr ' ' ',')"
    elif [ "${PS_OPEN[$k]}" = pass ] && [ "${PS_ANSWER[$k]}" = pass ] && [ "${PS_KA[$k]}" = pass ] \
            && [ -z "$seen" ] && [ -z "$unchecked" ] && [ -z "$incomplete" ] && [ "${PS_FRAMES[$k]% *}" = "0 0 0" ]; then
        result positive_control_verdict pass "primary=$PHYS presock_open=pass presock_unacked=pass presock_keepalive_drops=pass frames_while_armed=0 frames_checked=$checked captures=complete"
    else
        why=''
        [ -z "$seen" ] || why=": the helper's frames are in a capture while armed; they may be frames the filter dropped after the tap or frames that left the Mac"
        [ -z "$incomplete" ] || why="${why:-:}${why:+;} a capture that lost frames or did not run through the armed span cannot show that nothing left"
        result positive_control_verdict unavailable "primary=$PHYS presock_open=${PS_OPEN[$k]} presock_unacked=${PS_ANSWER[$k]} presock_keepalive_drops=${PS_KA[$k]} frames_seen=${seen:-none} frames_unchecked=${unchecked:-none}${incomplete:+ captures_incomplete=$incomplete}$why"
    fi
}

# ------------------------------------------------------------ window hooks

# The first rows of a control window.
ctl_scope() {
    [ -n "$CTL_PREFIX" ] || return 0
    if [ "$POSITIVE_CONTROL" = 1 ]; then
        result evidence_scope info "positive_control: owner-attended control with marked probes; its rows are never S20 evidence"
    else
        result evidence_scope info "negative_control: the leak-guard filter is disabled for this window; its rows are never S20 evidence"
    fi
}
ctl_before_capture() {
    ctl_scope
    [ "$NEGATIVE_CONTROL" = 1 ] || return 0
    nc_disable
}
# S20g: the gateways, the positive control's probe interfaces, and the
# pre-existing sockets of both controls, before the lock and the connect.
ctl_after_captures() {
    [ -n "$CTL_PREFIX" ] || return 0
    ctl_gateways
    if [ "$POSITIVE_CONTROL" = 1 ]; then pc_prepare || return 1; fi
    ps_open
}
# S20h: right after Connected, the negative control's write; nothing waits
# for the arm or reads --filter-status.
ctl_connected() {
    [ -n "$CTL_PREFIX" ] || return 0
    [ "$NEGATIVE_CONTROL" = 1 ] && ps_write
    return 0
}
ctl_window() {
    [ -n "$CTL_PREFIX" ] || return 0
    if [ "$POSITIVE_CONTROL" = 1 ]; then
        ps_write
        pc_window
    fi
    return 0
}
ctl_after_disconnect() {
    [ -n "$CTL_PREFIX" ] && ps_close
    [ "$NEGATIVE_CONTROL" = 1 ] && [ "$NC_DISABLED" = 1 ] && [ "$NC_RESTORED" = 0 ] && nc_restore
    return 0
}
ctl_after_reviews() {
    [ -n "$CTL_PREFIX" ] || return 0
    [ "$POSITIVE_CONTROL" = 1 ] && pc_bpf_order
    ps_not_connected
    ps_captures
    [ "$POSITIVE_CONTROL" = 1 ] && pc_verdict
    return 0
}
# The EXIT trap's part: the helpers' sockets are closed; a disabled filter
# not yet restored is restored. One still not restored fails whatever exit
# led here (a refusal's exit 3 too): exit 1 with FAILED.
ctl_on_exit() {
    ps_close quiet
    if [ "$NEGATIVE_CONTROL" = 1 ] && [ "$NC_DISABLED" = 1 ] && [ "$NC_RESTORED" = 0 ]; then
        if ! nc_restore quiet; then
            say "FAILED: negative control: $CTL_FAILED"
            exit 1
        fi
    fi
    return 0
}
# A control that left the filter unrestored never reports success.
ctl_final() {
    [ -n "$CTL_FAILED" ] || return 0
    say "FAILED: negative control: $CTL_FAILED"
    exit 1
}
