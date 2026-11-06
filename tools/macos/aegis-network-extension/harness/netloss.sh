# shellcheck shell=bash
# B-06 S21i: the NETLOSS=1 mode of harness/real-relay-window.sh, sourced by
# it (never run alone). While Connected it turns the physical Wi-Fi off for
# NETLOSS_OFF_S seconds with `networksetup -setairportpower <device> off` and
# back on, then checks that the tunnel recovers to Connected within
# NETLOSS_RECOVER_S and that traffic works again. NETLOSS_ADDR=1 adds an
# interface address change: `networksetup -setv6off <service>` and back to
# -setv6automatic, only for an IPv6 relay (the provider watches only the
# relay's address family, so an IPv6 change says nothing about an IPv4
# relay) and only when the one enabled service of the Wi-Fi device has
# IPv6 Automatic beforehand.
#
# Every off is preceded by a detached rollback that turns the interface back
# on when it fires, whatever happened to this shell, and retries until it
# reads the restored state back. Its launcher forks it and exits, so before
# anything is turned off it is confirmed adopted by launchd (ppid 1), the
# leader of its own session and group, and ignoring INT, TERM, HUP and QUIT:
# no kill of this shell's process tree or group reaches it. It is cancelled only by its token, written only
# after this shell has read the restored state back, and the rollback itself
# re-reads that state before it accepts the cancel.
#
# Uses from the window: OUT, PHYS, LEAK_CAPTURE, ECHO_TCP, ECHO_UDP, WHOAMI,
# RELAY_IP, result, tcp_probe, alive, say, egress_is_relay, egress_detail.
# Results never name an address: IPv6 addresses on the physical interface
# are only counted, and (v34) the whoami detail is masked.
NETLOSS=${NETLOSS:-0}
NETLOSS_OFF_S=${NETLOSS_OFF_S:-10}
NETLOSS_GRACE_S=${NETLOSS_GRACE_S:-15}
NETLOSS_RECOVER_S=${NETLOSS_RECOVER_S:-60}
NETLOSS_ADDR=${NETLOSS_ADDR:-0}
NETLOSS_ADDR_OFF_S=${NETLOSS_ADDR_OFF_S:-10}
# Each of the three restore attempts waits this long to read On back.
NETLOSS_RESTORE_WAIT_S=${NETLOSS_RESTORE_WAIT_S:-10}
NETWORKSETUP=${NETWORKSETUP:-networksetup}
LOG_BIN=${LOG_BIN:-/usr/bin/log}
NL_PY=${NL_PY:-/usr/bin/python3}
NL_PORT='' NL_SERVICE='' NL_ONLY_ROUTE='' NL_ADDR_SKIP='' NL_REFUSAL='' NL_EXTRA_S=0
NL_TOKEN='' NL_CANCEL='' NL_RB_LOG='' NL_RB_PID='' NL_RESTORE_FAILED=0 NL_LOG_COUNTS=''

nl_bounded() { local secs=$1; shift; perl -e 'alarm shift; exec { $ARGV[0] } @ARGV; exit 127' "$secs" "$@"; }
nl_int() { case "$2" in ''|*[!0-9]*) return 1 ;; esac; [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; }

# The state of one switch as On, Off or the raw value: Wi-Fi power of PHYS,
# or IPv6 of the service (Automatic counts as On).
nl_state() {
    if [ "$1" = wifi ]; then
        nl_bounded 20 "$NETWORKSETUP" -getairportpower "$PHYS" 2>/dev/null | awk -F': ' 'NF>1{v=$NF} END{print v}'
    else
        nl_bounded 20 "$NETWORKSETUP" -getinfo "$NL_SERVICE" 2>/dev/null \
            | awk -F': ' '$1=="IPv6"{v=$2} END{if (v=="Automatic") print "On"; else print v}'
    fi
}
nl_set() {
    case "$1 $2" in
        "wifi on") nl_bounded 20 "$NETWORKSETUP" -setairportpower "$PHYS" on ;;
        "wifi off") nl_bounded 20 "$NETWORKSETUP" -setairportpower "$PHYS" off ;;
        "v6 on") nl_bounded 20 "$NETWORKSETUP" -setv6automatic "$NL_SERVICE" ;;
        "v6 off") nl_bounded 20 "$NETWORKSETUP" -setv6off "$NL_SERVICE" ;;
    esac
}
nl_v6_count() { ifconfig "$PHYS" 2>/dev/null | awk '$1=="inet6" && $2!~/^fe80/ {n++} END{print n+0}'; }
nl_phys_inet() { ifconfig "$PHYS" 2>/dev/null | awk '$1=="inet" {n++} END{print n+0}'; }

# Before the lock, the rollback or any connect: sets NL_REFUSAL and returns 1
# when NETLOSS=1 cannot run safely here.
netloss_preflight() {
    local spec ports dev other=0 order
    for spec in "NETLOSS_OFF_S $NETLOSS_OFF_S 1 60" "NETLOSS_GRACE_S $NETLOSS_GRACE_S 1 60" \
        "NETLOSS_RECOVER_S $NETLOSS_RECOVER_S 5 180" "NETLOSS_ADDR_OFF_S $NETLOSS_ADDR_OFF_S 1 60" \
        "NETLOSS_RESTORE_WAIT_S $NETLOSS_RESTORE_WAIT_S 1 30"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { NL_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    [ "$LEAK_CAPTURE" != 1 ] || { NL_REFUSAL="not with LEAK_CAPTURE=1: the captured interface goes down"; return 1; }
    [ -n "${PHYS:-}" ] || { NL_REFUSAL="no physical default interface"; return 1; }
    dev=$(command -v "$NETWORKSETUP") || { NL_REFUSAL="networksetup not found"; return 1; }
    NETWORKSETUP=$dev
    ports=$(nl_bounded 20 "$NETWORKSETUP" -listallhardwareports 2>/dev/null) \
        || { NL_REFUSAL="networksetup -listallhardwareports failed"; return 1; }
    NL_PORT=$(printf '%s\n' "$ports" | awk -v d="$PHYS" '
        /^Hardware Port: /{p=substr($0, 16)} /^Device: /{if ($2==d) {print p; exit}}')
    [ "$NL_PORT" = Wi-Fi ] || { NL_REFUSAL="physical interface $PHYS is ${NL_PORT:-no hardware port}, not Wi-Fi"; return 1; }
    for dev in $(printf '%s\n' "$ports" | awk '/^Device: /{print $2}'); do
        [ "$dev" = "$PHYS" ] && continue
        ifconfig "$dev" 2>/dev/null | grep -q 'status: active' \
            && [ "$(ifconfig "$dev" 2>/dev/null | awk '$1=="inet" {n++} END{print n+0}')" != 0 ] && other=$((other + 1))
    done
    NL_ONLY_ROUTE=$([ "$other" = 0 ] && echo true || echo false)
    # The rollback needs its interpreter and a readable On to verify against;
    # with Wi-Fi the only route nothing else could bring this Mac back.
    [ -x "$NL_PY" ] || { NL_REFUSAL="no rollback can restore $PHYS ($NL_PY missing, only_route=$NL_ONLY_ROUTE)"; return 1; }
    dev=$(nl_state wifi)
    [ "$dev" = On ] || { NL_REFUSAL="Wi-Fi power of $PHYS reads '${dev:-nothing}', not On: no rollback could verify its restoration (only_route=$NL_ONLY_ROUTE)"; return 1; }
    if [ "$NETLOSS_ADDR" = 1 ]; then
        nl_addr_service
    fi
    # Each cycle at its bounds: arm 2, off check 5, off, restore 3 attempts,
    # rollback end 10, recovery, traffic 20, provider log 31.
    NL_EXTRA_S=$((NETLOSS_OFF_S + NETLOSS_RECOVER_S + 3 * NETLOSS_RESTORE_WAIT_S + 70))
    [ "$NETLOSS_ADDR" = 1 ] && NL_EXTRA_S=$((NL_EXTRA_S + NETLOSS_ADDR_OFF_S + NETLOSS_RECOVER_S + 3 * NETLOSS_RESTORE_WAIT_S + 70))
    return 0
}

# NETLOSS_ADDR=1: sets NL_SERVICE, or NL_ADDR_SKIP with the reason the
# address phase cannot exercise anything here.
nl_addr_service() {
    local order services n port rip=${RELAY_IP#\[}
    rip=${rip%\]}
    # The provider's path watch keeps only relay-family addresses
    # (path_watch::observe): with an IPv4 relay an IPv6 change re-pins and
    # rebuilds nothing, so its rows would pass without testing anything.
    case "$rip" in
        *:*) ;;
        *) NL_ADDR_SKIP="the relay is not IPv6: an IPv6-only change leaves the relay family's egress addresses unchanged"; return 0 ;;
    esac
    order=$(nl_bounded 20 "$NETWORKSETUP" -listnetworkserviceorder 2>/dev/null)
    # Every enabled service of PHYS as <name><TAB><hardware port>; a
    # disabled `(*) name` entry is never one, whatever its device.
    services=$(printf '%s\n' "$order" | awk -v suf=", Device: $PHYS)" '
        /^\([0-9]+\) / {n = $0; sub(/^\([0-9]+\) /, "", n); en = 1; next}
        /^\(\*\) / {n = $0; sub(/^\(\*\) /, "", n); en = 0; next}
        /^\(Hardware Port: / {
            if (en && length($0) > length(suf) && substr($0, length($0) - length(suf) + 1) == suf) {
                p = $0; sub(/^\(Hardware Port: /, "", p); sub(/, Device: .*$/, "", p); print n "\t" p
            }
            en = 0
        }')
    n=$(printf '%s' "$services" | grep -c .)
    if [ "$n" != 1 ]; then
        NL_ADDR_SKIP="$n enabled network services on $PHYS, not exactly one"
        return 0
    fi
    NL_SERVICE=${services%%$'\t'*} port=${services#*$'\t'}
    if [ "$port" != "$NL_PORT" ]; then
        NL_ADDR_SKIP="service '$NL_SERVICE' is on hardware port '$port', not $NL_PORT"
    elif [ "$(nl_state v6)" != On ]; then
        NL_ADDR_SKIP="IPv6 of '$NL_SERVICE' is not Automatic"
    fi
}

# Arms the detached rollback of one switch; true once it is confirmed alive,
# adopted by launchd (ppid 1) and the leader of its own process group.
nl_arm() {
    local kind=$1 delay=$2 target=$PHYS info='' launcher
    [ "$kind" = v6 ] && target=$NL_SERVICE
    NL_TOKEN=$(uuidgen) NL_RB_LOG="$OUT/netloss-$kind-rollback.log" NL_CANCEL="$OUT/netloss-$kind-rollback.cancel" NL_RB_PID=''
    nohup "$NL_PY" -I - "$kind" "$NETWORKSETUP" "$target" "$delay" "$NL_RB_LOG" "$NL_CANCEL" "$NL_TOKEN" >/dev/null 2>&1 <<'PY' &
import os, signal, subprocess, sys, time
kind, ns, target, delay, logp, cancel, token = sys.argv[1:8]
# The launcher only forks the rollback and exits: its child is adopted by
# launchd and is never a descendant of the window.
if os.fork() > 0:
    os._exit(0)
os.setsid()
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    signal.signal(s, signal.SIG_IGN)
log = open(logp, "a", buffering=1)
log.write(f"armed pid={os.getpid()} ppid={os.getppid()} kind={kind} delay={delay}\n")


def run(args):
    try:
        return subprocess.run([ns] + args, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as error:
        log.write(f"command_error {args[0]} {type(error).__name__}\n")
        return None


def state():
    if kind == "wifi":
        r = run(["-getairportpower", target])
        out = r.stdout.strip().splitlines()[-1] if r and r.stdout.strip() else ""
        return out.rsplit(": ", 1)[-1] if ": " in out else ""
    r = run(["-getinfo", target])
    for line in (r.stdout.splitlines() if r else []):
        if line.startswith("IPv6: "):
            value = line[6:].strip()
            return "On" if value == "Automatic" else value
    return ""


end = time.monotonic() + int(delay)
while time.monotonic() < end:
    try:
        if open(cancel).read().strip() == token:
            if state() == "On":
                log.write("rollback_cancelled restored_verified\n")
                sys.exit(0)
            log.write("cancel_refused state_not_restored\n")
            break
    except OSError:
        pass
    time.sleep(0.25)
log.write("rollback_fired\n")
for attempt in range(1, 31):
    run(["-setairportpower", target, "on"] if kind == "wifi" else ["-setv6automatic", target])
    for _ in range(10):
        if state() == "On":
            log.write(f"restored attempt={attempt}\nrollback_done\n")
            sys.exit(0)
        time.sleep(0.5)
log.write("restore_failed\nrollback_done\n")
PY
    launcher=$!
    wait "$launcher"
    for _ in $(seq 1 40); do
        NL_RB_PID=$(sed -n 's/^armed pid=\([0-9][0-9]*\) .*/\1/p' "$NL_RB_LOG" 2>/dev/null | tail -1)
        [ -n "$NL_RB_PID" ] && break
        sleep 0.05
    done
    [ -n "$NL_RB_PID" ] && [ "$NL_RB_PID" != "$launcher" ] && alive "$NL_RB_PID" || return 1
    info=$(ps -p "$NL_RB_PID" -o ppid= -o pgid= 2>/dev/null | awk '{print $1, $2}')
    [ "$info" = "1 $NL_RB_PID" ]
}

# Turns the switch back on and reads On back; only then is the rollback
# cancelled. Otherwise the rollback stays armed and fires by itself.
nl_restore() {
    local kind=$1 p=$2 st='' i
    for i in 1 2 3; do
        nl_set "$kind" on >/dev/null 2>&1
        for _ in $(seq 1 $((2 * NETLOSS_RESTORE_WAIT_S))); do
            st=$(nl_state "$kind")
            [ "$st" = On ] && break 2
            sleep 0.5
        done
    done
    if [ "$st" != On ]; then
        NL_RESTORE_FAILED=1
        result "${p}restored" fail "state=${st:-unreadable}; rollback stays armed (pid=$NL_RB_PID)"
        return 1
    fi
    echo "$NL_TOKEN" > "$NL_CANCEL"
    result "${p}restored" pass "attempts=$i state=On"
    for _ in $(seq 1 40); do
        grep -qE '^(rollback_cancelled|rollback_done)' "$NL_RB_LOG" 2>/dev/null && break
        sleep 0.25
    done
    result "${p}rollback_ended" info "$(tail -1 "$NL_RB_LOG" 2>/dev/null)"
    return 0
}

# Every distinct tunnel status and default route interface while off.
nl_observe() {
    local end=$((SECONDS + $1)) st seen='' def defs=''
    while [ "$SECONDS" -lt "$end" ]; do
        st=$(scutil --nc status "$SID" | head -1)
        case ",$seen," in *",$st,"*) ;; *) seen=${seen:+$seen,}$st ;; esac
        def=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
        def=${def:-none}
        case ",$defs," in *",$def,"*) ;; *) defs=${defs:+$defs,}$def ;; esac
        sleep 0.5
    done
    echo "statuses=${seen:-none} default=${defs:-none}"
}

# Connected on two polls in a row with the physical IPv4 address back and
# the default route on the tunnel's utun, within NETLOSS_RECOVER_S.
nl_recover() {
    local p=$1 t0=$SECONDS ok=0 st inet def utun
    while [ $((SECONDS - t0)) -le "$NETLOSS_RECOVER_S" ]; do
        st=$(scutil --nc status "$SID" | head -1)
        inet=$(nl_phys_inet)
        utun=$(ifconfig | awk '/^utun[0-9]+:/{i=$1} /inet 198\.19\.255\.1 /{sub(":","",i); print i}' | head -1)
        def=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
        if [ "$st" = Connected ] && [ "$inet" != 0 ] && [ -n "$utun" ] && [ "$def" = "$utun" ]; then
            ok=$((ok + 1))
            [ "$ok" -ge 2 ] && break
        else
            ok=0
        fi
        sleep 0.5
    done
    if [ "$ok" -ge 2 ]; then
        result "${p}recovered" pass "$((SECONDS - t0))s bound=${NETLOSS_RECOVER_S}s"
    else
        result "${p}recovered" fail "not within ${NETLOSS_RECOVER_S}s status=${st:-none} phys_inet=$inet default=${def:-none} utun=${utun:-none}"
    fi
}

# The provider's own record of the cycle: counts and values of its codes.
nl_provider_log() {
    local p=$1 start=$2 file="$OUT/${1}provider.log" ev d
    sleep 1
    nl_bounded 30 "$LOG_BIN" show --start "$start" --style compact --predicate 'eventMessage BEGINSWITH "aegis-ne"' \
        2>/dev/null | grep -vE 'Timestamp|secinitd' > "$file"
    NL_LOG_COUNTS=''
    for ev in path_change relay_interface_repinned session_lost session_rebuilt reasserting; do
        d=$(awk -v e="$ev" '{for (i = 1; i < NF; i++) if ($i == "aegis-ne" && $(i + 1) == e) {
                n++; v = (i + 2 <= NF) ? $(i + 2) : "-"; s = s (s == "" ? "" : ",") v } }
            END { printf "count=%d seq=%s", n, (s == "" ? "none" : s) }' "$file" | cut -c1-240)
        result "${p}log_$ev" info "$d"
        d=${d#count=}
        NL_LOG_COUNTS="$NL_LOG_COUNTS $ev=${d%% *}"
    done
    # A reassertion that began must have ended: the last reasserting code is off.
    d=$(awk '{for (i = 1; i < NF; i++) if ($i == "aegis-ne" && $(i + 1) == "reasserting") v = $(i + 2)} END {print v}' "$file")
    if [ ! -s "$file" ]; then result "${p}rebuild_settled" unavailable "no provider log lines"
    elif [ -z "$d" ]; then result "${p}rebuild_settled" pass "no_reassert"
    elif [ "$d" = off ]; then result "${p}rebuild_settled" pass "reasserting_off"
    else result "${p}rebuild_settled" fail "last_reasserting=$d"
    fi
}

nl_traffic() {
    local p=$1 w u
    # v34 (S24 review F): the verdict from the raw body's first 80 bytes
    # (the window's egress_is_relay), the detail masked (egress_detail).
    w=$(curl -s -m 5 "$WHOAMI" 2>&1 | head -c 4096)
    result "${p}whoami_egress" "$(egress_is_relay "$(printf '%s' "$w" | head -c 80)" && echo pass || echo fail)" "$(egress_detail "$w")"
    u=$(printf pong | nc -u -w 3 "${ECHO_UDP%:*}" "${ECHO_UDP#*:}" 2>&1 | head -c 20)
    result "${p}udp_echo_v4" "$([ "$u" = pong ] && echo pass || echo fail)" "$u"
    tcp_probe "${p}tcp_echo_v4" hc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping
}

# One off/on cycle of a switch (wifi or v6), from its rollback to its rows.
nl_cycle() {
    local kind=$1 p=netloss_ off_s=$NETLOSS_OFF_S start rc st before='' during='' from=''
    if [ "$kind" = v6 ]; then p=netloss_addr_ off_s=$NETLOSS_ADDR_OFF_S; fi
    start=$(date '+%Y-%m-%d %H:%M:%S')
    if ! nl_arm "$kind" $((off_s + NETLOSS_GRACE_S)); then
        result "${p}rollback_armed" fail "pid=${NL_RB_PID:-none}; nothing was turned off"
        return 1
    fi
    result "${p}rollback_armed" pass "pid=$NL_RB_PID fires_after=$((off_s + NETLOSS_GRACE_S))s"
    # v31 review: ${p}v6_count reports this count, taken before the off row.
    [ "$kind" = v6 ] && { from=$RESULT_FROM; before=$(nl_v6_count); }
    say "netloss: $kind off for ${off_s}s"
    nl_set "$kind" off >/dev/null 2>&1
    rc=$?
    st=''
    for _ in $(seq 1 10); do
        st=$(nl_state "$kind")
        [ "$st" = Off ] && break
        # A refused request that left the switch on is not waited for.
        [ "$rc" != 0 ] && [ "$st" = On ] && break
        sleep 0.5
    done
    if [ "$st" != Off ]; then
        # Nothing went off as asked: restore anyway, then record why.
        result "${p}off" "$([ "$kind" = v6 ] && [ "$rc" != 0 ] && echo unavailable || echo fail)" "rc=$rc state=${st:-unreadable}"
        nl_restore "$kind" "$p"
        return 1
    fi
    result "${p}off" pass "rc=$rc state=Off"
    result "${p}status_during_off" info "$(nl_observe "$off_s")"
    [ "$kind" = v6 ] && during=$(nl_v6_count)
    say "netloss: $kind on"
    nl_restore "$kind" "$p" || return 1
    nl_recover "$p"
    [ "$kind" = v6 ] && result_since "$from" "${p}v6_count" info "before=$before during=$during after=$(nl_v6_count)"
    nl_traffic "$p"
    nl_provider_log "$p" "$start"
    [ "$kind" = v6 ] && nl_addr_exercised "$p"
    return 0
}

# The address change reached the provider: it saw the relay-family path
# change and re-pinned or rebuilt the session, not only survived it.
nl_addr_exercised() {
    local p=$1 c pc=0 rp=0 rb=0
    for c in $NL_LOG_COUNTS; do
        case "$c" in
            path_change=*) pc=${c#*=} ;;
            relay_interface_repinned=*) rp=${c#*=} ;;
            session_rebuilt=*) rb=${c#*=} ;;
        esac
    done
    if [ "$pc" -ge 1 ] && { [ "$rp" -ge 1 ] || [ "$rb" -ge 1 ]; }; then
        result "${p}relay_path_exercised" pass "path_change=$pc repinned=$rp rebuilt=$rb"
    else
        result "${p}relay_path_exercised" fail "path_change=$pc repinned=$rp rebuilt=$rb: the provider recorded no relay-family re-pin or rebuild"
    fi
}

netloss_window() {
    result netloss_preflight info "port=$NL_PORT device=$PHYS only_route=$NL_ONLY_ROUTE off=${NETLOSS_OFF_S}s recover_bound=${NETLOSS_RECOVER_S}s"
    nl_cycle wifi
    [ "$NETLOSS_ADDR" = 1 ] || return 0
    if [ "$NL_RESTORE_FAILED" = 1 ]; then
        result netloss_addr_change skip "Wi-Fi not restored"
    elif [ -n "$NL_ADDR_SKIP" ]; then
        result netloss_addr_change skip "$NL_ADDR_SKIP"
    else
        nl_cycle v6
    fi
}
