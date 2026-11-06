# shellcheck shell=bash
# B-06 S24: the ENDURANCE=1 and LOAD=1 modes of harness/real-relay-window.sh,
# sourced by it after harness/controls.sh (never run alone). Both run
# without sudo, with the window's connect, detached rollback, timing-self
# lock (held for the whole window), timing-peer refusal and verified
# disconnect unchanged, and neither runs with another mode: ENDURANCE=1
# refuses beside LOAD=1, LEAK_CAPTURE=1, NETLOSS=1, SLEEP=1, IFSWITCH=1 and
# either control; LOAD=1 refuses beside ENDURANCE=1, NETLOSS=1, SLEEP=1,
# IFSWITCH=1 and either control, and may run with LEAK_CAPTURE=1. Every
# refusal comes before the lock, the rollback, any capture or any connect.
#
# ENDURANCE=1 (S24a): after the baseline rows, one cycle every
# ENDURANCE_PERIOD_S (default 60, 15..600) until ENDURANCE_S (default 7200,
# 600..86400) has passed, the last one at ENDURANCE_S. A cycle reads the
# provider log since the last read (bounded), then runs its probes, the
# host's --status and the provider's ps sample at once, each bounded:
# egress whoami (the relay), a timed TCP echo, a UDP echo, a TXT query
# through the relay and HTTP by name. Between cycles the tunnel status is
# polled; a status other than Connected or, while the provider reasserts,
# Connecting (what scutil prints for a reassert; Reasserting is taken the
# same way) ends the cycles (the probes would no longer go through a
# tunnel). A slot that no cycle could start within its period (the Mac
# asleep, a stalled window, also while it waited for that slot) is a
# missed cycle. One row per cycle goes to endurance.tsv; the summary rows
# go to results.tsv (harness/endurance_review.py). The Mac is kept awake by
# `caffeinate -i -w <window pid>` (a power assertion of the window's life,
# not a setting).
#
# LOAD=1 (S24b): after the baseline rows, LOAD_STREAMS (default 4, 1..8)
# concurrent downloads of LOAD_URL through the tunnel (curl to a byte cap,
# LOAD_BYTES / LOAD_STREAMS each, LOAD_BYTES default 209715200, 1 MiB..1
# GiB in total, each bounded by LOAD_BOUND_S, default 180, 10..900); while
# they run the window repeats its two flow bursts (the same thresholds), a
# timed TCP echo and a UDP echo, and reads the leak-guard filter's counters
# before and after. v34: the default LOAD_URL is the immutable kernel
# tarball on cdn.kernel.org (EL_LOAD_URL_DEFAULT, 140064536 bytes); the
# speed-test host (speed.cloudflare.com, which refused one of v33's four
# identical requests) runs only as an explicit LOAD_URL. A declared size
# (the default's, a LOAD_URL's bytes=, or LOAD_URL_BYTES for a given URL)
# below each stream's cap is refused (no stream could reach its cap). Each
# stream keeps its response's status line and a few headers
# (load-target.<i>.head) and, for a status other than 2xx, the first 64
# printable bytes of the body (load-target.<i>.body), all masked; the gate
# is unchanged. After the disconnect, LOAD=1 adds info rows read from the
# provider log, the filter reads and the rows (harness/load_review.py), and
# ENDURANCE=1 one, endurance_window (the stream window's budget over the
# run). A window stopped mid-load removes the unmasked captures on its EXIT
# path (el_on_exit).
#
# Uses from the window: OUT, SID, HOST_BIN, HANDOFF, RELAY_IP, ECHO_TCP,
# ECHO_UDP, WHOAMI, PROBE_PY, HARNESS_DIR, LEAK_CAPTURE, NETLOSS, SLEEP,
# IFSWITCH, POSITIVE_CONTROL, NEGATIVE_CONTROL, ROLLBACK_S, ROLLBACK_S_GIVEN,
# PROVIDER_LOG_BOUND_S, RESULT_FROM, FILTER_RC, FILTER_LINE, START_LOCAL,
# result, result_since, tcp_probe, burst, filter_status, alive, say, utc_ms,
# mask_addrs, egress_is_relay; from netloss.sh: nl_int, nl_bounded, LOG_BIN.
# Rows, endurance.tsv and the logs never name an address.
ENDURANCE=${ENDURANCE:-0}
ENDURANCE_S=${ENDURANCE_S:-7200}
ENDURANCE_PERIOD_S=${ENDURANCE_PERIOD_S:-60}
LOAD=${LOAD:-0}
# Empty: EL_LOAD_URL_DEFAULT, set by el_load_preflight. v34: an immutable
# file on a CDN (Fastly: HTTP/2 200, no redirect, no Content-Encoding), its
# size pinned; each stream's cap must not exceed it. LOAD_URL_BYTES: the
# size a given LOAD_URL serves, when its URL names none (optional).
LOAD_URL=${LOAD_URL:-}
LOAD_URL_BYTES=${LOAD_URL_BYTES:-}
EL_LOAD_URL_DEFAULT='https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz'
EL_LOAD_URL_DEFAULT_BYTES=140064536
LOAD_STREAMS=${LOAD_STREAMS:-4}
LOAD_BYTES=${LOAD_BYTES:-209715200}
LOAD_BOUND_S=${LOAD_BOUND_S:-180}
# The provider process (pgrep -x) and the session_lost codes its rebuild
# table documents as recoverable (session_rebuild.rs REFUSALS, Recoverable;
# a test compares the two lists).
EL_PROVIDER_EXE=aegis-ne-provider
EL_RECOVERABLE='capture_lease_expired session_ack_refused session_ack_too_short session_lease_refused
session_connect_failed carrier_unavailable session_clock_failed relay_interface_unresolved relay_path_changed
store_revalidation_failed session_packet_config_refused session_services_refused session_packet_terminal
session_monitor_ended session_monitor_failed session_engine_spawn_failed session_engine_failed
session_engine_timeout session_engine_not_ready session_runtime_failed session_spawn_failed
session_worker_refused session_ended session_rebuild_timeout session_rebuild_spawn_failed
session_identity_not_current session_identity_expired identity_renewal_due identity_renewal_pending
identity_renewal_busy identity_renewal_stopped packet_path_not_ready packet_io_failed native_packet_malformed'
# The provider-log reads keep the provider's own lines: this crate's cargo
# tests log the same `aegis-ne` lines from their own process.
EL_LOG_PREDICATE="process == \"$EL_PROVIDER_EXE\" AND eventMessage BEGINSWITH \"aegis-ne\""
# One cycle's bounds (el_cycle_bounds): the provider-log read (EL_LOG_S, a
# quarter of the period, 3..30 s, but never so long that the probes lose
# their full bounds), once more after a 1 s settle when a loss looks
# pending, then every probe, the host's --status and the ps sample at once
# (EL_GROUP_S, the longest of them), and 3 s for the processes and the
# row. At full length the probes have the baseline rows' own bounds (the
# TCP echo EL_PROBE_MAX_S, as PROBE_LIMIT_S's default, whoami 5 s, HTTP
# 8 s, the TXT query and the UDP echo 3 s), --status 4 s and pgrep and ps
# 5 s each; a period too short for that cuts them to what it leaves (4 s,
# pgrep and ps 2 s each, at 15 s). The bound stays below the period (14 s
# at 15 s, 44 s at 60 s).
EL_PROBE_MAX_S=10 EL_POLL_S=5 EL_LOG_S=0 EL_GROUP_S=0 EL_CYCLE_BOUND_S=0
EL_TCP_S=0 EL_WHOAMI_S=0 EL_HTTP_S=0 EL_DNS_S=0 EL_UDP_S=0 EL_STATUS_S=0 EL_PS_S=0
# The data volume's floor (31 GiB), and with LOAD=1 LEAK_CAPTURE=1 the
# captures' margin beyond LOAD_BYTES (the window's other traffic, every
# interface's capture).
EL_FLOOR_KIB=$((31 * 1024 * 1024))
EL_PCAP_MARGIN_BYTES=$((1024 * 1024 * 1024))
# The window's default rollback (ROLLBACK_S), which a mode's extra adds to.
EL_BASE_ROLLBACK_S=180
# The provider's drop ring (leak_guard::RING_SLOTS; a test compares them).
EL_RING_SLOTS=64
EL_RSS_LIMIT_KIB=65536 EL_RSS_AFTER_S=600
# The clock (integer milliseconds) and the sleep of the cycle schedule, and
# the awake assertion: EL_CLOCK, EL_SLEEP and EL_CAFFEINATE exist for the
# tests (endurance_preflight names an overridden clock or sleep, and with
# either endurance_real_time passes nothing).
EL_CLOCK=${EL_CLOCK:-}
EL_SLEEP=${EL_SLEEP:-sleep}
EL_CAFFEINATE=${EL_CAFFEINATE:-/usr/bin/caffeinate}
EL_MODE='' EL_PREFIX='' EL_REFUSAL='' EL_EXTRA_S=0 EL_SUMMARY='' EL_LOCK_NOTE='' EL_WINDOW_BOUND_S=0
EL_PREFLIGHT_FROM='' EL_PREFLIGHT_INFO='' EL_T0_S=0 EL_PLANNED=0
# ENDURANCE=1 while it runs: the log's read state (from when, whether a loss
# is waiting for its rebuild, whether a read failed since the last good one),
# the stop reason and the awake assertion.
EL_LOG_FROM_S=0 EL_PENDING=0 EL_LOG_GAP=0 EL_STOPPED='' EL_CAFF_PID='' EL_FROM=''
EL_LAST_STATUS='' EL_READ='' EL_PID0=''
# LOAD=1: the streams' subshells and the running streams at each check's end;
# v34: whether the load ran, and its span in the provider log's local time.
EL_LOAD_PIDS=() EL_LOAD_MARKS='' EL_LOAD_RAN=0 EL_LOAD_FROM_LOCAL='' EL_LOAD_TO_LOCAL=''
# v34: the info rows harness/load_review.py writes after the disconnect
# (v35: load_queue and load_takes too).
EL_LOAD_REVIEW_ROWS='load_filter_series load_outbound_drops load_placement load_window load_latency load_queue load_takes'

el_now_ms() {
    if [ -n "$EL_CLOCK" ]; then "$EL_CLOCK"
    else /usr/bin/perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'
    fi
}
el_sleep_ms() { "$EL_SLEEP" "$(printf '%d.%03d' $(($1 / 1000)) $(($1 % 1000)))"; }
el_epoch() { /usr/bin/perl -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
el_utc() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
el_free_kib() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 {print $4}'; }
el_status() { scutil --nc status "$SID" | head -1; }
# scutil prints Connecting while the provider reasserts (a session rebuild);
# it never prints Reasserting, which is taken the same way.
el_status_ok() { [ "$1" = Connected ] || [ "$1" = Connecting ] || [ "$1" = Reasserting ]; }
el_codex_lock() { [ -e "$FOREIGN_TIMING_LOCK" ] && echo 1 || echo 0; }
# The provider's own lines of a log show read on stdin (log show adds a
# header and a summary; other processes log `aegis-ne` lines too).
el_provider_lines() { grep -F " $EL_PROVIDER_EXE[" | grep -vE 'Timestamp|secinitd' | grep -F 'aegis-ne'; }
el_cycle_bounds() {
    local avail b
    EL_LOG_S=$(($1 / 4))
    [ "$EL_LOG_S" -le $((($1 - EL_PROBE_MAX_S - 5) / 2)) ] || EL_LOG_S=$((($1 - EL_PROBE_MAX_S - 5) / 2))
    [ "$EL_LOG_S" -ge 3 ] || EL_LOG_S=3
    [ "$EL_LOG_S" -le 30 ] || EL_LOG_S=30
    # What the period leaves the group: less both reads, the settle, 3 s for
    # the processes and the row, and 1 s to stay below the period.
    avail=$(($1 - 2 * EL_LOG_S - 1 - 3 - 1))
    EL_TCP_S=$((avail < EL_PROBE_MAX_S ? avail : EL_PROBE_MAX_S)) EL_WHOAMI_S=$((avail < 5 ? avail : 5))
    EL_HTTP_S=$((avail < 8 ? avail : 8)) EL_DNS_S=$((avail < 3 ? avail : 3)) EL_UDP_S=$((avail < 3 ? avail : 3))
    EL_STATUS_S=$((avail < 4 ? avail : 4)) EL_PS_S=$((avail / 2 < 5 ? avail / 2 : 5))
    # The ps sample is pgrep, then ps: twice its bound.
    EL_GROUP_S=0
    for b in "$EL_TCP_S" "$EL_WHOAMI_S" "$EL_HTTP_S" "$EL_DNS_S" "$EL_UDP_S" "$EL_STATUS_S" $((2 * EL_PS_S)); do
        [ "$b" -le "$EL_GROUP_S" ] || EL_GROUP_S=$b
    done
    EL_CYCLE_BOUND_S=$((2 * EL_LOG_S + 1 + EL_GROUP_S + 3))
}

# The device certificate's not_after and state from the host's
# --cert-status (stdout JSON; unprivileged, no provider tree). Prints
# `<not_after> <state>`, or nothing.
el_cert_not_after() {
    nl_bounded 15 "$HOST_BIN" --cert-status 2>"$OUT/endurance-cert-status.err" | python3 -I -c 'import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if isinstance(r, dict) and r.get("verb") == "cert-status" and isinstance(r.get("report"), dict):
        v, s = r["report"].get("not_after"), r["report"].get("state")
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            print(v, s if isinstance(s, str) and s.replace(":", "").replace("_", "").isalnum() else "unknown")
        break' 2>/dev/null
}
# The handoff's expires_utc as Unix seconds; only that field is read.
el_relay_expires() {
    python3 -I -c 'import datetime, json, sys
try:
    v = json.load(open(sys.argv[1])).get("expires_utc")
    t = datetime.datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
except (OSError, ValueError, AttributeError, TypeError):
    sys.exit(1)
if t.tzinfo is None:
    sys.exit(1)
print(int(t.timestamp()))' "$HANDOFF" 2>/dev/null
}

# Before the lock, the rollback, any capture or any connect: sets EL_MODE,
# EL_EXTRA_S and the preflight row, or EL_REFUSAL and returns 1.
el_preflight() {
    local spec others
    EL_PREFLIGHT_FROM=$RESULT_FROM
    EL_T0_S=$(date +%s)
    if [ "$ENDURANCE" = 1 ]; then
        EL_MODE=ENDURANCE=1 EL_PREFIX=endurance_
        others="LOAD LEAK_CAPTURE NETLOSS SLEEP IFSWITCH POSITIVE_CONTROL NEGATIVE_CONTROL"
    else
        EL_MODE=LOAD=1 EL_PREFIX=load_
        others="NETLOSS SLEEP IFSWITCH POSITIVE_CONTROL NEGATIVE_CONTROL"
    fi
    for spec in $others; do
        [ "${!spec:-0}" != 1 ] && continue
        if [ "$spec" = LEAK_CAPTURE ]; then
            EL_REFUSAL="not with LEAK_CAPTURE=1: one disruption or capture per window, and hours of capture would threaten the disk floor"
        else
            EL_REFUSAL="not with $spec=1: one disruption, capture or load per window"
        fi
        return 1
    done
    if [ "$ENDURANCE" = 1 ]; then el_endurance_preflight || return 1
    else el_load_preflight || return 1
    fi
    # A given ROLLBACK_S is kept, but never one that would stop the tunnel
    # before the mode is done.
    if [ -n "$ROLLBACK_S_GIVEN" ]; then
        case "$ROLLBACK_S" in
            ''|*[!0-9]*) EL_REFUSAL="ROLLBACK_S=$ROLLBACK_S is not a number of seconds"; return 1 ;;
        esac
        if [ "$ROLLBACK_S" -lt $((EL_BASE_ROLLBACK_S + EL_EXTRA_S)) ]; then
            EL_REFUSAL="ROLLBACK_S=$ROLLBACK_S is shorter than this window needs ($((EL_BASE_ROLLBACK_S + EL_EXTRA_S)) s): the rollback would stop the tunnel mid-run"
            return 1
        fi
    fi
    return 0
}

el_endurance_preflight() {
    local spec free na state ex end
    for spec in "ENDURANCE_S $ENDURANCE_S 600 86400" "ENDURANCE_PERIOD_S $ENDURANCE_PERIOD_S 15 600"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { EL_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    # Decimal from here on, whatever leading zeros were given.
    ENDURANCE_S=$((10#$ENDURANCE_S)) ENDURANCE_PERIOD_S=$((10#$ENDURANCE_PERIOD_S))
    el_cycle_bounds "$ENDURANCE_PERIOD_S"
    [ "$EL_CYCLE_BOUND_S" -lt "$ENDURANCE_PERIOD_S" ] \
        || { EL_REFUSAL="a cycle's bound (${EL_CYCLE_BOUND_S}s) is not below ENDURANCE_PERIOD_S=$ENDURANCE_PERIOD_S"; return 1; }
    free=$(el_free_kib "$OUT")
    case "$free" in ''|*[!0-9]*) EL_REFUSAL="free space of the volume holding OUT is unreadable (df)"; return 1 ;; esac
    [ "$free" -ge "$EL_FLOOR_KIB" ] \
        || { EL_REFUSAL="$((free / 1048576)) GiB free on the volume holding OUT, below the 31 GiB floor"; return 1; }
    [ -x "$EL_CAFFEINATE" ] || { EL_REFUSAL="no $EL_CAFFEINATE to keep the Mac awake through the run"; return 1; }
    end=$((EL_T0_S + ENDURANCE_S))
    # shellcheck disable=SC2046
    set -- $(el_cert_not_after)
    na=${1:-} state=${2:-}
    if [ -z "$na" ]; then
        EL_REFUSAL="the device certificate's not_after is unreadable (host --cert-status: $(head -n 1 "$OUT/endurance-cert-status.err" 2>/dev/null | tr -cd 'A-Za-z0-9_:. -' | cut -c1-80)); a provider that has not run a session since it started answers no_epoch: run one ordinary window first"
        return 1
    fi
    if [ "$na" -lt $((end + 1800)) ]; then
        EL_REFUSAL="the device certificate expires at $(el_utc "$na") (not_after, state $state), before the run's end + 30 min ($(el_utc $((end + 1800)))): a session past its due point defers renewal until reconnect"
        return 1
    fi
    ex=$(el_relay_expires)
    [ -n "$ex" ] || { EL_REFUSAL="the relay handoff's expires_utc is absent or unreadable"; return 1; }
    if [ "$ex" -lt $((end + 900)) ]; then
        EL_REFUSAL="the relay handoff expires at $(el_utc "$ex") (expires_utc), before the run's end + 15 min ($(el_utc $((end + 900))))"
        return 1
    fi
    EL_PLANNED=$(( (ENDURANCE_S + ENDURANCE_PERIOD_S - 1) / ENDURANCE_PERIOD_S + 1 ))
    # The cycles (the last one may start up to a period late), the last
    # one's bound, a final log read (and its settle and re-read), with a
    # loss still pending the same again after the wait until the next slot,
    # and a margin; the window's one provider-log read after the disconnect
    # covers hours.
    EL_EXTRA_S=$((ENDURANCE_S + ENDURANCE_PERIOD_S + EL_CYCLE_BOUND_S + 2 * (2 * EL_LOG_S + 1) + 120))
    PROVIDER_LOG_BOUND_S=$((60 + ENDURANCE_S / 30))
    EL_SUMMARY="duration_s=$ENDURANCE_S period_s=$ENDURANCE_PERIOD_S cycles=$EL_PLANNED cycle_bound_s=$EL_CYCLE_BOUND_S log_bound_s=$EL_LOG_S probe_bound_s=$EL_TCP_S"
    EL_PREFLIGHT_INFO="$EL_SUMMARY not_after_margin_s=$((na - end)) cert_state=$state relay_expires_margin_s=$((ex - end)) free_gib=$((free / 1048576)) clock=$([ -n "$EL_CLOCK" ] && echo override || echo default) sleep=$([ "$EL_SLEEP" = sleep ] && echo default || echo override)"
}

el_load_preflight() {
    local spec free need host cap url=given n given=''
    for spec in "LOAD_STREAMS $LOAD_STREAMS 1 8" "LOAD_BYTES $LOAD_BYTES 1048576 1073741824" "LOAD_BOUND_S $LOAD_BOUND_S 10 900"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { EL_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    LOAD_STREAMS=$((10#$LOAD_STREAMS)) LOAD_BYTES=$((10#$LOAD_BYTES)) LOAD_BOUND_S=$((10#$LOAD_BOUND_S))
    cap=$((LOAD_BYTES / LOAD_STREAMS))
    # v34: LOAD_URL_BYTES declares the size a given LOAD_URL serves.
    if [ -n "$LOAD_URL_BYTES" ]; then
        [ -n "$LOAD_URL" ] \
            || { EL_REFUSAL="LOAD_URL_BYTES declares the size of a given LOAD_URL; the default LOAD_URL's is pinned ($EL_LOAD_URL_DEFAULT_BYTES bytes)"; return 1; }
        nl_int LOAD_URL_BYTES "$LOAD_URL_BYTES" 1 1099511627776 \
            || { EL_REFUSAL="LOAD_URL_BYTES=$LOAD_URL_BYTES is outside 1..1099511627776"; return 1; }
        given=$((10#$LOAD_URL_BYTES))
    fi
    [ -n "$LOAD_URL" ] || { LOAD_URL=$EL_LOAD_URL_DEFAULT url=default; }
    printf '%s' "$LOAD_URL" | grep -qE '^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/?=&%+-]*)?$' \
        || { EL_REFUSAL="LOAD_URL is not a plain http(s) URL"; return 1; }
    # The size the URL names (bytes=N, as the speed-test host's does); the
    # default's is pinned.
    n=$(printf '%s' "$LOAD_URL" | sed -n 's/^[^?]*?\(.*&\)\{0,1\}bytes=\([0-9][0-9]*\)\(&.*\)\{0,1\}$/\2/p')
    case "$n" in
        '') n=undeclared ;;
        ????????????????*) n=large ;;
        *) n=$((10#$n)) ;;
    esac
    [ "$url" = default ] && n=$EL_LOAD_URL_DEFAULT_BYTES
    # The load is meant to run with the filter on: armed while Connected.
    [ "$FILTER_RC" = 0 ] \
        || { EL_REFUSAL="needs the leak-guard filter configured, enabled and attached (host --filter-status exit $FILTER_RC)"; return 1; }
    host=${LOAD_URL#*://} host=${host%%[:/]*}
    case "$host" in *[!0-9.]*) ;; *) host=address ;; esac
    free=$(el_free_kib "$OUT")
    case "$free" in ''|*[!0-9]*) EL_REFUSAL="free space of the volume holding OUT is unreadable (df)"; return 1 ;; esac
    # With LEAK_CAPTURE=1 the captures may hold up to LOAD_BYTES and a margin.
    need=0
    [ "$LEAK_CAPTURE" = 1 ] && need=$(( (LOAD_BYTES + EL_PCAP_MARGIN_BYTES) / 1024 ))
    if [ $((free - need)) -lt "$EL_FLOOR_KIB" ]; then
        EL_REFUSAL="$((free / 1048576)) GiB free on the volume holding OUT$([ "$need" = 0 ] || echo " less the captures' expected $((need / 1048576)) GiB") leaves less than the 31 GiB floor"
        return 1
    fi
    # A URL with a declared size must serve at least each stream's cap, which
    # no stream could reach otherwise: load_download needs exactly the cap
    # from every stream. v34: the default's pinned size, a URL's bytes= and
    # LOAD_URL_BYTES are each checked.
    case "$n" in
        undeclared|large) ;;
        *) if [ "$n" -lt "$cap" ] && [ "$url" = default ]; then
               EL_REFUSAL="each stream's cap of $cap (LOAD_BYTES / LOAD_STREAMS) is more than the default LOAD_URL serves ($EL_LOAD_URL_DEFAULT_BYTES bytes): lower LOAD_BYTES or raise LOAD_STREAMS, or give a LOAD_URL that serves the cap"
               return 1
           elif [ "$n" -lt "$cap" ]; then
               EL_REFUSAL="LOAD_URL serves bytes=$n per request, fewer than each stream's cap of $cap (LOAD_BYTES / LOAD_STREAMS): raise its bytes= or lower LOAD_BYTES"
               return 1
           fi ;;
    esac
    if [ -n "$given" ] && [ "$given" -lt "$cap" ]; then
        EL_REFUSAL="LOAD_URL serves LOAD_URL_BYTES=$given bytes, fewer than each stream's cap of $cap (LOAD_BYTES / LOAD_STREAMS): lower LOAD_BYTES or give a LOAD_URL that serves the cap"
        return 1
    fi
    # The smallest declared size is the one shown.
    if [ -n "$given" ]; then
        case "$n" in
            undeclared|large) n=$given ;;
            *) [ "$given" -ge "$n" ] || n=$given ;;
        esac
    fi
    # The downloads at their bound (the checks run inside them), two filter
    # reads, the provider log and a margin.
    EL_EXTRA_S=$((LOAD_BOUND_S + 120))
    EL_SUMMARY="streams=$LOAD_STREAMS bytes=$LOAD_BYTES per_stream=$cap bound_s=$LOAD_BOUND_S url_host=$host url=$url url_bytes=$n"
    EL_PREFLIGHT_INFO="$EL_SUMMARY capture=$LEAK_CAPTURE free_gib=$((free / 1048576))"
}

# After the rollback grew: the whole window's bound and the lock's note.
el_bounds() {
    EL_WINDOW_BOUND_S=$((ROLLBACK_S + PROVIDER_LOG_BOUND_S + 120))
    EL_LOCK_NOTE=" mode=${EL_MODE%%=*} ends_by=$(el_utc $(($(date +%s) + EL_WINDOW_BOUND_S)))"
}

# The preflight's reads, before the connect (result_since: they came before
# any row).
el_preflight_row() {
    [ -n "$EL_MODE" ] || return 0
    result_since "$EL_PREFLIGHT_FROM" "${EL_PREFIX}preflight" info "$EL_PREFLIGHT_INFO"
}

el_window() {
    if [ "$ENDURANCE" = 1 ]; then el_endurance_window
    elif [ "$LOAD" = 1 ]; then el_load_window
    fi
    return 0
}

# A mode whose window never reached Connected passes nothing.
el_not_connected() {
    local name
    if [ "$ENDURANCE" = 1 ]; then
        for name in cycles longest_gap connected_throughout provider_stable rss_growth rebuilds renewal real_time; do
            result "endurance_$name" unavailable "not_connected"
        done
    elif [ "$LOAD" = 1 ]; then
        for name in download throughput concurrent connected_throughout filter_counters provider_rss; do
            result "load_$name" unavailable "not_connected"
        done
    fi
    return 0
}

# --------------------------------------------------------------- ENDURANCE

# One provider sample: `<pid> <rss_kib> <cpu>`, or none/multi:<n>; pgrep
# and ps within EL_PS_S each.
el_provider_sample() {
    local p n
    p=$(nl_bounded "$EL_PS_S" pgrep -x "$EL_PROVIDER_EXE" 2>/dev/null)
    n=$(printf '%s' "$p" | grep -c .)
    if [ "$n" = 1 ]; then
        # shellcheck disable=SC2046
        set -- $(nl_bounded "$EL_PS_S" ps -o rss= -o %cpu= -p "$p" 2>/dev/null)
        echo "$p ${1:-none} ${2:-none}"
    elif [ "$n" = 0 ]; then
        echo "none none none"
    else
        echo "multi:$n none none"
    fi
}

# One status sample, kept for endurance_connected_throughout. False (and
# EL_STOPPED set) once the status is neither Connected nor Reasserting.
el_sample_status() {
    EL_LAST_STATUS=$(el_status)
    printf '%s %s\n' "$1" "${EL_LAST_STATUS:-none}" >> "$OUT/endurance-statuses.txt"
    el_status_ok "$EL_LAST_STATUS" && return 0
    EL_STOPPED="${EL_LAST_STATUS:-none}@cycle=$1"
    return 1
}

# Waits until the clock reaches $1 (ms), polling the status every
# EL_POLL_S; false once a sample stops the cycles.
el_wait_until() {
    local now left
    while :; do
        now=$(el_now_ms)
        left=$(($1 - now))
        [ "$left" -gt 0 ] || return 0
        [ "$left" -le $((EL_POLL_S * 1000)) ] || left=$((EL_POLL_S * 1000))
        el_sleep_ms "$left"
        el_sample_status "$2" || return 1
    done
}

# The provider log since the last good read (with a 10 s overlap; lines
# already kept are dropped), appended to endurance-provider.log and to this
# judgement's endurance-log.cycle. False when the read failed (EL_LOG_GAP).
el_log_fetch() {
    local now from tmp="$OUT/endurance-log.read" rc
    now=$(date +%s)
    from=$(date -r "$EL_LOG_FROM_S" '+%Y-%m-%d %H:%M:%S')
    nl_bounded "$EL_LOG_S" "$LOG_BIN" show --start "$from" --style compact --predicate "$EL_LOG_PREDICATE" \
        > "$tmp" 2>/dev/null
    rc=$?
    if [ "$rc" != 0 ]; then
        EL_LOG_GAP=1
        rm -f "$tmp"
        return 1
    fi
    # Only the provider's own lines.
    el_provider_lines < "$tmp" > "$tmp.lines"
    awk 'FILENAME == ARGV[1] {seen[$0] = 1; next} !($0 in seen) {seen[$0] = 1; print}' \
        "$OUT/endurance-provider.log" "$tmp.lines" > "$tmp.fresh"
    cat "$tmp.fresh" >> "$OUT/endurance-provider.log"
    cat "$tmp.fresh" >> "$OUT/endurance-log.cycle"
    rm -f "$tmp" "$tmp.lines" "$tmp.fresh"
    EL_LOG_FROM_S=$((now - 10))
    return 0
}
# The codes of endurance-log.cycle, in log order from EL_PENDING: `<lost>
# <causes> <rebuilt> <failed> <states> <pending>`; a loss stays pending
# until a session_rebuilt follows it.
el_log_count() {
    awk -v p="$EL_PENDING" '{for (i = 1; i < NF; i++) if ($i == "aegis-ne") {
            e = $(i + 1); v = (i + 2 <= NF) ? $(i + 2) : "-"
            if (e == "session_lost") { lost++; p = 1; if (!(v in c)) k[++n] = v; c[v]++ }
            else if (e == "session_rebuilt") { rebuilt++; p = 0 }
            else if (e == "session_failed") failed++
            else if (e == "identity_renewal" && v ~ /^state:/) { s = substr(v, 7); if (!(s in t)) q[++m] = s; t[s]++ }
            break
        } }
        END {
            for (a = 1; a <= n; a++) cs = cs (cs == "" ? "" : ",") k[a] ":" c[k[a]]
            for (a = 1; a <= m; a++) ss = ss (ss == "" ? "" : ",") q[a] ":" t[q[a]]
            printf "%d %s %d %d %s %d", lost, (cs == "" ? "none" : cs), rebuilt, failed, (ss == "" ? "none" : ss), p
        }' "$OUT/endurance-log.cycle"
}
# The log right before a cycle's probes (or the planned disconnect). Sets
# EL_READ: `<ok|failed> <lost> <causes> <rebuilt> <failed> <states>
# <pending> <judge>`. judge: 1 for a loss not rebuilt before now, unknown
# for a loss among new lines after a failed read (it may have come before
# an unread cycle's probes), - for a failed read, else 0. A rebuild logged
# right before the read may not be visible yet: a loss that looks pending
# is read once more after a 1 s settle. Then EL_PENDING and EL_LOG_GAP move on.
el_log_judge() {
    local ok=ok judge
    : > "$OUT/endurance-log.cycle"
    el_log_fetch || ok=failed
    # shellcheck disable=SC2046
    set -- $(el_log_count)
    if [ "$ok" = ok ] && [ "$6" = 1 ]; then
        sleep 1
        el_log_fetch
        # shellcheck disable=SC2046
        set -- $(el_log_count)
    fi
    if [ "$ok" != ok ]; then judge=-
    elif [ "$6" = 1 ]; then judge=1
    elif [ "$EL_LOG_GAP" = 1 ] && [ "$1" != 0 ]; then judge=unknown
    else judge=0
    fi
    [ "$ok" = ok ] && EL_LOG_GAP=0 EL_PENDING=$6
    EL_READ="$ok $* $judge"
    rm -f "$OUT/endurance-log.cycle"
}

# One cycle: the log read, then every probe, --status and ps at once, each
# within its el_cycle_bounds bound. Appends its endurance.tsv row (run_ms:
# its start on the schedule's clock, $3); false when a status stops the
# cycles.
el_cycle() {
    local k=$1 slot=$2 d="$OUT/endurance-cycle" start end st0 st1 pids=() v w t x h judge phase ren rc probes
    local ok lost causes rebuilt failed states run_ms=$3
    printf 'cycle=%s of=%s\n' "$k" "$EL_PLANNED" > "$OUT/endurance.progress"
    start=$(utc_ms)
    el_sample_status "$k" || return 1
    st0=$EL_LAST_STATUS
    # The probes start right after this read.
    el_log_judge
    # shellcheck disable=SC2086
    set -- $EL_READ
    ok=$1 lost=$2 causes=$3 rebuilt=$4 failed=$5 states=$6 judge=$8
    rm -f "$d".*
    # v34: the relay's address as a whole literal of the body, as the
    # window's whoami rows judge it (egress_is_relay: brackets ignored).
    ( w=$(curl -s -m "$EL_WHOAMI_S" "$WHOAMI" 2>/dev/null | head -c 80)
      egress_is_relay "$w" && echo pass || echo fail ) > "$d.whoami" 2>/dev/null &
    pids+=($!)
    ( t=$("$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" tcp hc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping "$EL_TCP_S" 2>/dev/null)
      rc=$?
      echo "$([ "$rc" = 0 ] && echo pass || echo fail) ${t:-no_output}" ) > "$d.tcp" 2>/dev/null &
    pids+=($!)
    ( u=$(printf pong | nc -u -w "$EL_UDP_S" "${ECHO_UDP%:*}" "${ECHO_UDP#*:}" 2>/dev/null | head -c 20)
      [ "$u" = pong ] && echo pass || echo fail ) > "$d.udp" 2>/dev/null &
    pids+=($!)
    ( x=$(dig +short +time="$EL_DNS_S" +tries=1 @198.19.255.2 example.com TXT 2>&1 | head -1)
      [ -n "$x" ] && ! printf '%s' "$x" | grep -q '^;;' && echo pass || echo fail ) > "$d.dns" 2>/dev/null &
    pids+=($!)
    ( h=$(curl -s -m "$EL_HTTP_S" -o /dev/null -w '%{http_code}' http://example.com/ 2>/dev/null)
      echo "$([ "$h" = 200 ] && echo pass || echo fail) ${h:-none}" ) > "$d.http" 2>/dev/null &
    pids+=($!)
    ( nl_bounded "$EL_STATUS_S" "$HOST_BIN" --status > "$d.status.out" 2> "$d.status.err"
      echo $? > "$d.status.rc" ) &
    pids+=($!)
    el_provider_sample > "$d.ps" 2>/dev/null &
    pids+=($!)
    wait "${pids[@]}"
    el_sample_status "$k"
    rc=$?
    st1=$EL_LAST_STATUS
    # Each probe's verdict (pass, else fail), and the cycle's: every probe.
    v=pass probes=''
    for w in whoami tcp udp dns http; do
        x=$(cut -d' ' -f1 "$d.$w" 2>/dev/null)
        [ "$x" = pass ] || { x=fail v=fail; }
        probes="$probes"$'\t'"$x"
    done
    t=$(cut -d' ' -f2 "$d.tcp" 2>/dev/null) h=$(cut -d' ' -f2 "$d.http" 2>/dev/null)
    phase=$(sed -n 's/.*"session_phase":"\([A-Za-z_:-]*\)".*/\1/p' "$d.status.out" 2>/dev/null | head -1)
    [ -n "$phase" ] || phase="unreadable:rc=$(cat "$d.status.rc" 2>/dev/null || echo none)"
    ren=$(awk '/^renewal / { if ($2 == "failing") { c = $3; gsub(/[()]/, "", c); print "failing:" c } else print $2; exit }' \
        "$d.status.err" 2>/dev/null | tr -cd 'A-Za-z0-9_:-')
    # shellcheck disable=SC2046
    set -- $(cat "$d.ps" 2>/dev/null)
    end=$(utc_ms)
    printf '%s\t%s\t%s\t%s\t%s%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$k" "$((slot / 1000))" "$start" "$end" "$v" "$probes" \
        "tcp=${t:-none} http=${h:-none}" "$st0" "${st1:-none}" "$phase" "${ren:-none}" "${1:-none}" "${2:-none}" "${3:-none}" \
        "$ok" "$lost" "$causes" "$rebuilt" "$failed" "$states" "$judge" "$(el_codex_lock)" "$run_ms" >> "$OUT/endurance.tsv"
    rm -f "$d".*
    say "endurance: cycle $k/$((EL_PLANNED - 1)) $v status=$st0/${st1:-none}"
    return "$rc"
}

# A slot no cycle could start within its period (the Mac asleep, a
# stalled window): a missed cycle, which fails like a failing one. run_ms
# is when it was found missed ($3).
el_missed() {
    printf '%s\t%s\t%s\t%s\tmissed\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t%s\t%s\n' \
        "$1" "$(($2 / 1000))" "$(utc_ms)" "$(utc_ms)" "$(el_codex_lock)" "$3" >> "$OUT/endurance.tsv"
    say "endurance: cycle $1/$((EL_PLANNED - 1)) missed"
}

el_endurance_window() {
    local k=0 t0 now slot period_ms=$((ENDURANCE_PERIOD_S * 1000)) end_ms=$((ENDURANCE_S * 1000)) final awake=no
    local name verdict detail seen=' ' clock=default
    # The tests' clock or sleep: endurance_real_time then passes nothing.
    { [ -n "$EL_CLOCK" ] || [ "$EL_SLEEP" != sleep ]; } && clock=override
    EL_FROM=$RESULT_FROM
    : > "$OUT/endurance-provider.log"
    : > "$OUT/endurance-statuses.txt"
    printf 'cycle\tslot_s\tstart\tend\tverdict\twhoami\ttcp_echo\tudp_echo\tdns_txt\thttp\tprobe_detail\tstatus_start\tstatus_end\tphase\trenewal\tprovider_pid\trss_kib\tcpu_pct\tlog_read\tsession_lost\tlost_causes\tsession_rebuilt\tsession_failed\trenewal_states\trebuild_pending\tcodex_lock\trun_ms\n' \
        > "$OUT/endurance.tsv"
    "$EL_CAFFEINATE" -i -w "$$" >/dev/null 2>&1 &
    EL_CAFF_PID=$!
    EL_LOG_FROM_S=$(date +%s)
    # shellcheck disable=SC2046
    set -- $(el_provider_sample)
    EL_PID0=${1:-none}
    t0=$(el_now_ms)
    alive "$EL_CAFF_PID" && awake=yes
    say "endurance: $EL_PLANNED cycles every ${ENDURANCE_PERIOD_S}s for ${ENDURANCE_S}s provider_pid=$EL_PID0 awake=$awake"
    while [ "$k" -lt "$EL_PLANNED" ]; do
        slot=$((k * period_ms))
        [ "$slot" -le "$end_ms" ] || slot=$end_ms
        now=$(el_now_ms)
        if [ $((now - t0)) -ge $((slot + period_ms)) ]; then
            el_missed "$k" "$slot" $((now - t0))
            k=$((k + 1))
            continue
        fi
        # After the wait the clock is read again: a sleep or a stall during
        # it may have taken this slot's whole period too.
        if [ $((now - t0)) -lt "$slot" ]; then
            el_wait_until $((t0 + slot)) "$k" || break
            continue
        fi
        el_cycle "$k" "$slot" $((now - t0)) || break
        k=$((k + 1))
    done
    # The planned disconnect: one more status sample and a final read. A
    # loss after the last cycle's probes gets what a loss in any other cycle
    # gets: it must have rebuilt by the time the next slot's probes would
    # run, so one still pending is read again at that slot.
    printf 'cycle=%s of=%s\n' "$EL_PLANNED" "$EL_PLANNED" > "$OUT/endurance.progress"
    [ -n "$EL_STOPPED" ] || el_sample_status final
    el_log_judge
    # shellcheck disable=SC2086
    set -- $EL_READ
    if [ "$8" = 1 ] && [ -z "$EL_STOPPED" ]; then
        el_wait_until $((t0 + end_ms + period_ms)) final
        el_log_judge
        # shellcheck disable=SC2086
        set -- $EL_READ
    fi
    case "$8" in
        -) final=failed ;;
        1) final=pending ;;
        unknown) final=unknown ;;
        *) final=ok ;;
    esac
    kill "$EL_CAFF_PID" 2>/dev/null
    rm -f "$OUT/endurance.progress"
    while IFS=$'\t' read -r name verdict detail; do
        case "$name" in endurance_*) ;; *) continue ;; esac
        result_since "$EL_FROM" "$name" "$verdict" "$detail"
        seen="$seen$name "
    done < <(python3 -I "$HARNESS_DIR/endurance_review.py" --tsv "$OUT/endurance.tsv" --results "$OUT/results.tsv" \
        --statuses "$OUT/endurance-statuses.txt" --log "$OUT/endurance-provider.log" --planned "$EL_PLANNED" \
        --period "$ENDURANCE_PERIOD_S" --pid0 "$EL_PID0" --final "$final" --stopped "${EL_STOPPED:-none}" \
        --awake "$awake" --rss-after "$EL_RSS_AFTER_S" --rss-limit "$EL_RSS_LIMIT_KIB" --recoverable "$EL_RECOVERABLE" \
        --duration "$ENDURANCE_S" --clock "$clock" 2>/dev/null)
    # A review that wrote no row for a criterion passes nothing.
    for name in cycles longest_gap connected_throughout provider_stable rss_growth rebuilds renewal real_time; do
        case "$seen" in *" endurance_$name "*) ;; *) result_since "$EL_FROM" "endurance_$name" fail "review_unreadable" ;; esac
    done
}

# -------------------------------------------------------------------- LOAD

# One download stream (a background subshell): LOAD_URL through the tunnel
# to a cap of $2 bytes, bounded by LOAD_BOUND_S; its load-stream.<i>.
# v34: curl -D keeps the response's headers (load-target.<i>.raw) and the
# counter (as wc -c before it, after the same head -c) keeps the body's
# first 256 bytes (load-target.<i>.first); el_load_target turns them into
# the masked load-target.<i>.head and .body and adds status= (the status
# line's code, or none) to load-stream.<i>. What is counted and judged is
# unchanged.
el_load_stream() {
    local f="$OUT/load-stream.$1" g="$OUT/load-target.$1" t0 t1 rc http st
    t0=$(el_epoch)
    curl -sS -m "$LOAD_BOUND_S" -D "$g.raw" -o - -w '%{stderr}http=%{http_code}\n' "$LOAD_URL" 2>"$f.err" \
        | head -c "$2" | el_load_count "$g.first" > "$f.count"
    rc=${PIPESTATUS[0]}
    t1=$(el_epoch)
    http=$(sed -n 's/^http=\([0-9][0-9]*\)$/\1/p' "$f.err" 2>/dev/null | tail -1)
    st=$(el_load_target "$1")
    printf 'bytes=%s rc=%s t0=%s t1=%s http=%s status=%s\n' "$(tr -cd '0-9' < "$f.count")" "$rc" "$t0" "$t1" "${http:-none}" \
        "${st:-none}" > "$f.tmp"
    mv -f "$f.tmp" "$f"
    rm -f "$f.err" "$f.count" "$g.raw" "$g.first"
}
# Counts the bytes on stdin (wc -c's number) and keeps the first 256 of them
# in $1.
el_load_count() {
    /usr/bin/perl -e 'my ($keep) = @ARGV; my ($n, $first) = (0, "");
        while (my $r = sysread(STDIN, my $buf, 65536)) {
            $first .= substr($buf, 0, 256 - length($first)) if length($first) < 256;
            $n += $r;
        }
        if (open(my $f, ">", $keep)) { print $f $first; close $f }
        print "$n\n";' "$1"
}
# The status line's code of stream $1's response (its last one: without -L
# there is only one), or none. Writes load-target.<i>.head: that status
# line and a few of its headers, printable ASCII, masked. For a code other
# than 2xx it also writes load-target.<i>.body, the body's first 64
# printable bytes (masked first, then cut; a cut-off literal at the end of
# the 256 bytes kept is dropped before), and says it in window.log. The
# verdict never reads either file.
el_load_target() {
    local g="$OUT/load-target.$1" code text
    [ -s "$g.raw" ] || { echo none; return 0; }
    code=$(tr -d '\r' < "$g.raw" | awk '/^HTTP\/[0-9.]+ [0-9][0-9][0-9]( |$)/ {c = $2} END {print (c == "" ? "none" : c)}')
    text=$(tr -d '\r' < "$g.raw" | awk '
        /^HTTP\// {n = 0; out = $0; next}
        {k = tolower($0); sub(/:.*/, "", k)}
        k ~ /^(content-type|content-length|content-encoding|server|location|retry-after|x-cache|cf-ray|cf-mitigated|via)$/ && n < 10 {out = out "\n" $0; n++}
        END {print out}' | LC_ALL=C tr -cd '\n -~' | cut -c1-200)
    mask_addrs "$text" > "$g.head"
    echo >> "$g.head"
    case "$code" in
        2[0-9][0-9]) ;;
        *) text=$(LC_ALL=C tr -cd ' -~' < "$g.first" 2>/dev/null)
           [ "$(wc -c < "$g.first" 2>/dev/null | tr -cd '0-9')" = 256 ] && text=$(printf '%s' "$text" | sed 's/[0-9A-Fa-f.:]*$//')
           text=$(mask_addrs "$text" | head -c 64)
           # stdout is the caller's capture; the window's log is on stderr too.
           if [ -n "$text" ]; then
               printf '%s\n' "$text" > "$g.body"
               say "load: stream $1 status $code: $text" >&2
           else
               say "load: stream $1 status $code, no body" >&2
           fi ;;
    esac
    echo "$code"
}
# v34 review: on the window's EXIT path (every EXIT trap in
# real-relay-window.sh, after om_on_exit_first): a stream still running (a
# window stopped mid-load: Ctrl-C, SIGTERM, an error) is stopped, then the
# unmasked captures (load-target.<i>.raw, the target's headers, and .first,
# the body's first 256 bytes, which a CDN's error page can fill with the
# egress address) and the stream's own temporaries (load-stream.<i>.err,
# curl's stderr, .count and .tmp) are removed, so none stays in OUT. Only
# this window's own stream subshells are signalled (their parent is this
# shell), and it waits at most 2 s for their pipelines to end first.
el_on_exit() {
    local p n=0 left
    for p in ${EL_LOAD_PIDS[@]+"${EL_LOAD_PIDS[@]}"}; do
        [ "$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')" = "$$" ] || continue
        pkill -P "$p" 2>/dev/null
        kill "$p" 2>/dev/null
    done
    while [ "$n" -lt 20 ]; do
        left=0
        for p in ${EL_LOAD_PIDS[@]+"${EL_LOAD_PIDS[@]}"}; do
            if alive "$p" || pgrep -P "$p" >/dev/null 2>&1; then left=1; fi
        done
        [ "$left" = 1 ] || break
        sleep 0.1
        n=$((n + 1))
    done
    [ -z "${OUT:-}" ] || rm -f "$OUT"/load-target.*.raw "$OUT"/load-target.*.first "$OUT"/load-stream.*.err \
        "$OUT"/load-stream.*.count "$OUT"/load-stream.*.tmp 2>/dev/null
    return 0
}
el_load_running() {
    local p n=0
    for p in "${EL_LOAD_PIDS[@]}"; do alive "$p" && n=$((n + 1)); done
    echo "$n"
}
# The streams still running when a check ended, and the status then; v34:
# and a provider sample for load_provider_rss.
el_load_mark() {
    EL_LOAD_MARKS="$EL_LOAD_MARKS $1=$(el_load_running)"
    el_status >> "$OUT/load-statuses.txt"
    el_load_rss "$1"
}
# v34: one provider sample (`<label> <pid> <rss_kib> <cpu>`, pgrep and ps
# within EL_PS_S each) to load-provider-rss.txt. Info only.
el_load_rss() {
    printf '%s %s\n' "$1" "$(el_provider_sample)" >> "$OUT/load-provider-rss.txt"
}
# v34: the provider's RSS across the load, from load-provider-rss.txt: the
# sample before the downloads, the largest one after it, their difference
# and whether one process was sampled throughout. Info: the acceptance
# reads it against the stream-window budget (v34-load-acceptance.md).
el_load_rss_row() {
    local d
    d=$(awk 'NR == 1 {p0 = $2; r0 = $3}
        {n++; if ($2 != p0) moved = 1; if (NR > 1 && $3 ~ /^[0-9]+$/ && ($3 + 0 > max + 0 || max == "")) max = $3}
        END {
            if (n == 0 || r0 !~ /^[0-9]+$/) { printf "unavailable\tno_sample"; exit }
            if (max == "") max = r0
            printf "info\tpid=%s rss_kib_before=%d rss_kib_max=%d growth_kib=%d samples=%d", (moved ? "changed" : p0), r0, max, max - r0, n
        }' "$OUT/load-provider-rss.txt" 2>/dev/null)
    result_since "$1" load_provider_rss "$(printf '%s' "${d:-unavailable}" | cut -f1)" "$(printf '%s' "$d" | cut -f2)"
}

el_load_window() {
    local i cap from_local deadline p u f0_rc f0_line f1_rc f1_line saved_rc=$FILTER_RC saved_line=$FILTER_LINE d log_rc
    local load_from=$RESULT_FROM
    cap=$((LOAD_BYTES / LOAD_STREAMS))
    from_local=$(date '+%Y-%m-%d %H:%M:%S')
    # v34: the load's span in the provider log's local time (load_review.py).
    EL_LOAD_FROM_LOCAL=$from_local EL_LOAD_RAN=1
    : > "$OUT/load-statuses.txt"
    : > "$OUT/load-provider-rss.txt"
    EL_PS_S=5
    filter_status load-before
    f0_rc=$FILTER_RC f0_line=$FILTER_LINE
    rm -f "$OUT"/load-stream.* "$OUT"/load-target.*
    EL_LOAD_PIDS=() EL_LOAD_MARKS=''
    el_load_rss before
    say "load: $LOAD_STREAMS streams of $cap bytes, bound ${LOAD_BOUND_S}s"
    for i in $(seq 1 "$LOAD_STREAMS"); do
        el_load_stream "$i" "$cap" &
        EL_LOAD_PIDS+=($!)
    done
    sleep 1   # the streams ramp up
    burst 24 22 load_
    el_load_mark burst24
    burst 90 88 load_
    el_load_mark burst90
    tcp_probe load_tcp_echo_v4 hc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping
    el_load_mark tcp
    u=$(printf pong | nc -u -w 3 "${ECHO_UDP%:*}" "${ECHO_UDP#*:}" 2>&1 | head -c 20)
    result load_udp_echo_v4 "$([ "$u" = pong ] && echo pass || echo fail)" "$u"
    el_load_mark udp
    # Every stream ends by its own bound; one still running then is stopped.
    deadline=$((SECONDS + LOAD_BOUND_S + 5))
    while [ "$(el_load_running)" != 0 ] && [ "$SECONDS" -lt "$deadline" ]; do
        el_status >> "$OUT/load-statuses.txt"
        sleep 0.5
    done
    for p in "${EL_LOAD_PIDS[@]}"; do
        alive "$p" || continue
        pkill -P "$p" 2>/dev/null
        kill "$p" 2>/dev/null
    done
    EL_LOAD_TO_LOCAL=$(date '+%Y-%m-%d %H:%M:%S')
    el_load_rss after
    # A stopped stream leaves its unmasked header and body capture.
    rm -f "$OUT"/load-target.*.raw "$OUT"/load-target.*.first
    filter_status load-after
    f1_rc=$FILTER_RC f1_line=$FILTER_LINE
    FILTER_RC=$saved_rc FILTER_LINE=$saved_line
    sleep 1
    # The provider's own lines of the load; a read cut off at its bound
    # (rc 142) may lack the latest of them, so its rc goes to the judgement.
    nl_bounded 30 "$LOG_BIN" show --start "$from_local" --style compact --predicate "$EL_LOG_PREDICATE" \
        > "$OUT/load-provider.read" 2>/dev/null
    log_rc=$?
    el_provider_lines < "$OUT/load-provider.read" > "$OUT/load-provider.log"
    rm -f "$OUT/load-provider.read"
    # Each stream's bytes against its cap within the bound; the throughput.
    # v34: exactly load-stream.1 .. load-stream.<LOAD_STREAMS>, one record
    # each, read afresh (a stopped stream's leftovers never stand in for its
    # record, which is then missing and fails), and target_status, the
    # streams whose response's status line was not 2xx (none: no status
    # line, so no answer from the target at all).
    d=$(for i in $(seq 1 "$LOAD_STREAMS"); do
            if [ -s "$OUT/load-stream.$i" ]; then printf 'stream=%s %s\n' "$i" "$(head -n 1 "$OUT/load-stream.$i")"
            else printf 'stream=%s rc=missing\n' "$i"
            fi
        done | awk -v cap="$cap" -v bound="$LOAD_BOUND_S" -v n="$LOAD_STREAMS" '
        { split("", f)
          for (i = 1; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
          got++; b = f["bytes"] + 0; total += b
          if (f["rc"] == "missing") {
            bad = bad (bad == "" ? "" : ",") f["stream"] ":missing"
            http = http (http == "" ? "" : ",") "none"; ts = ts (ts == "" ? "" : ",") f["stream"] ":none"
            rate = rate (rate == "" ? "" : ",") "0.0"
            next
          }
          e = f["t1"] - f["t0"]
          if (lo == "" || f["t0"] < lo) lo = f["t0"]; if (hi == "" || f["t1"] > hi) hi = f["t1"]
          if (b == cap && e <= bound) ok++; else bad = bad (bad == "" ? "" : ",") f["stream"] ":" b "/" sprintf("%.1fs", e) ":rc=" f["rc"]
          if (e > emax) emax = e
          http = http (http == "" ? "" : ",") f["http"]
          if (f["status"] !~ /^2[0-9][0-9]$/) ts = ts (ts == "" ? "" : ",") f["stream"] ":" (f["status"] == "" ? "none" : f["status"])
          rate = rate (rate == "" ? "" : ",") sprintf("%.1f", (e > 0 ? b * 8 / e / 1e6 : 0)) }
        END {
          span = (hi != "" ? hi - lo : 0)
          printf "%s\t%s\t%s", ((ok == n && got == n) ? "pass" : "fail"),
            sprintf("ok=%d/%d bytes=%d/%d per_stream=%d elapsed_max=%.1fs bound=%ds http=%s target_status=%s%s", ok, n, total, cap * n, cap, emax, bound, (http == "" ? "none" : http), (ts == "" ? "2xx" : ts), (bad == "" ? "" : " short=" bad)),
            sprintf("total_mbit_s=%.1f per_stream_mbit_s=%s bytes=%d span_s=%.1f", (span > 0 ? total * 8 / span / 1e6 : 0), (rate == "" ? "none" : rate), total, span)
        }')
    result_since "$load_from" load_download "$(printf '%s' "$d" | cut -f1)" "$(printf '%s' "$d" | cut -f2)"
    result_since "$load_from" load_throughput info "$(printf '%s' "$d" | cut -f3)"
    # The checks ran under load only if a stream was still running at the
    # end of each.
    p=pass
    for i in $EL_LOAD_MARKS; do [ "${i#*=}" != 0 ] || p=fail; done
    result_since "$load_from" load_concurrent "$p" "running_at_end:${EL_LOAD_MARKS} streams=$LOAD_STREAMS"
    el_load_connected "$load_from" "$log_rc"
    el_load_counters "$load_from" "$f0_rc" "$f0_line" "$f1_rc" "$f1_line"
    el_load_rss_row "$load_from"
}

# No session_lost in the provider log of the load, and Connected at every
# sample. A loss or another status fails it whatever the read; without a
# whole read of the load's log (cut off at its bound, $2 the rc) or without
# any provider line nothing is shown either way.
el_load_connected() {
    local from=$1 rc=$2 d st
    st=$(sort "$OUT/load-statuses.txt" | uniq -c | awk '{s = s (s == "" ? "" : ",") $2 ":" $1} END {print (s == "" ? "none" : s)}')
    d=$(awk '{for (i = 1; i < NF; i++) if ($i == "aegis-ne") { if ($(i + 1) == "session_lost") { n++; v = (i + 2 <= NF) ? $(i + 2) : "-"; c = c (c == "" ? "" : ",") v }; break } }
        END {printf "%d %s", n, (c == "" ? "none" : c)}' "$OUT/load-provider.log")
    # shellcheck disable=SC2086
    set -- $d
    if [ "$1" != 0 ] || [ ! -s "$OUT/load-statuses.txt" ] || grep -qv '^Connected$' "$OUT/load-statuses.txt"; then
        result_since "$from" load_connected_throughout fail "session_lost=$1 causes=$2 statuses=$st"
    elif [ "$rc" != 0 ]; then
        result_since "$from" load_connected_throughout unavailable "provider_log_read=failed:rc=$rc statuses=$st"
    elif [ ! -s "$OUT/load-provider.log" ]; then
        result_since "$from" load_connected_throughout unavailable "no provider log lines statuses=$st"
    else
        result_since "$from" load_connected_throughout pass "session_lost=0 statuses=$st"
    fi
}

# The filter's counters across the load: allowed and dropped (the sums on
# the filter_result line), its mode, and the drop rings' records (a ring
# keeps EL_RING_SLOTS; more new records than that overflowed it).
el_load_counters() {
    local from=$1 d
    if [ "$2" != 0 ] || [ "$4" != 0 ]; then
        result_since "$from" load_filter_counters unavailable "exit=$2/$4"
        return 0
    fi
    d=$(python3 -I -c 'import json, re, sys
def read(path):
    line, report = "", None
    try:
        text = open(path, errors="replace").read().splitlines()
    except OSError:
        text = []
    for t in text:
        if t.startswith("filter_result="):
            line = t
        else:
            try:
                r = json.loads(t)
            except ValueError:
                continue
            if isinstance(r, dict) and r.get("verb") == "filter-status" and isinstance(r.get("report"), dict):
                report = r["report"]
    num = lambda k: int(re.search(r"(?:^| )%s=([0-9]+)(?: |$)" % k, line).group(1)) if re.search(r"(?:^| )%s=[0-9]+(?: |$)" % k, line) else None
    mode = re.search(r"(?:^| )mode=([a-z]+)", line)
    obs = report.get("observability") if isinstance(report, dict) else None
    ring = obs.get("ring") if isinstance(obs, dict) else None
    out = obs.get("outbound") if isinstance(obs, dict) else None
    oring = out.get("ring") if isinstance(out, dict) else None
    get = lambda d, k: d.get(k) if isinstance(d, dict) and isinstance(d.get(k), int) else None
    return {"allowed": num("allowed"), "dropped": num("dropped"), "mode": mode.group(1) if mode else "unknown",
            "next": get(ring, "next"), "skipped": get(ring, "skipped"), "onext": get(oring, "next")}
a, b, slots = read(sys.argv[1]), read(sys.argv[2]), int(sys.argv[3])
delta = lambda k: "?" if a[k] is None or b[k] is None else b[k] - a[k]
parts = ["allowed_delta=%s" % delta("allowed"), "dropped_delta=%s" % delta("dropped"), "mode=%s/%s" % (a["mode"], b["mode"])]
if a["next"] is None or b["next"] is None:
    parts.append("ring=unexposed")
else:
    n = b["next"] - a["next"]
    parts += ["ring_next_delta=%d" % n, "ring_overflow=%d" % max(0, n - slots), "ring_skipped_delta=%s" % delta("skipped")]
    if a["onext"] is not None and b["onext"] is not None:
        o = b["onext"] - a["onext"]
        parts += ["out_ring_next_delta=%d" % o, "out_ring_overflow=%d" % max(0, o - slots)]
print(" ".join(parts))' "$OUT/filter-status-load-before.txt" "$OUT/filter-status-load-after.txt" "$EL_RING_SLOTS" 2>/dev/null)
    result_since "$from" load_filter_counters info "exit=0/0 ${d:-unreadable}"
}

# v34 (S24b observability): after the disconnect and the window's one
# provider-log read (provider.log, from before the connect), LOAD=1's info
# rows from harness/load_review.py: the filter's drop rates before and
# during the load, the outbound drops, the bulk flows' placement, the
# adaptive stream window and the latency under load, and (v35) the
# connections' credit-loop delay and the new flows' placement
# (EL_LOAD_REVIEW_ROWS).
# None is ever pass or fail: any other verdict is written unavailable, and
# a load that never ran writes them unavailable too. The review runs within
# 60 s. v34 review (critic B4): ENDURANCE=1 adds one info row the same way,
# endurance_window, the stream window's budget across the whole run from
# endurance-provider.log (load_review.py --endurance-log): whether
# long-lived flows hold the budget.
el_after_window() {
    local name verdict detail seen=' ' d
    if [ "$ENDURANCE" = 1 ]; then
        if [ -z "$EL_FROM" ]; then
            result endurance_window unavailable "not_connected"
            return 0
        fi
        d=$(nl_bounded 60 python3 -I "$HARNESS_DIR/load_review.py" --endurance-log "$OUT/endurance-provider.log" \
            2>/dev/null | awk -F'\t' '$1 == "endurance_window" {print; exit}')
        verdict=$(printf '%s' "$d" | cut -f2) detail=$(printf '%s' "$d" | cut -f3)
        case "$verdict" in
            info|unavailable) ;;
            '') verdict=unavailable detail="review_unreadable" ;;
            *) verdict=unavailable detail="review_verdict_refused" ;;
        esac
        result endurance_window "$verdict" "$detail"
        return 0
    fi
    [ "$LOAD" = 1 ] || return 0
    if [ "$EL_LOAD_RAN" != 1 ]; then
        for name in $EL_LOAD_REVIEW_ROWS; do result "$name" unavailable "not_connected"; done
        return 0
    fi
    while IFS=$'\t' read -r name verdict detail; do
        case " $EL_LOAD_REVIEW_ROWS " in *" $name "*) ;; *) continue ;; esac
        case " $seen " in *" $name "*) continue ;; esac
        case "$verdict" in info|unavailable) ;; *) verdict=unavailable detail="review_verdict_refused" ;; esac
        result "$name" "$verdict" "$detail"
        seen="$seen$name "
    done < <(nl_bounded 60 python3 -I "$HARNESS_DIR/load_review.py" --provider-log "$OUT/provider.log" \
        --load-log "$OUT/load-provider.log" --window-from "$START_LOCAL" --load-from "$EL_LOAD_FROM_LOCAL" \
        --load-to "$EL_LOAD_TO_LOCAL" --filter-before "$OUT/filter-status-load-before.txt" \
        --filter-after "$OUT/filter-status-load-after.txt" --results "$OUT/results.tsv" \
        --ring-slots "$EL_RING_SLOTS" 2>/dev/null)
    for name in $EL_LOAD_REVIEW_ROWS; do
        case "$seen" in *" $name "*) ;; *) result "$name" unavailable "review_unreadable" ;; esac
    done
}
