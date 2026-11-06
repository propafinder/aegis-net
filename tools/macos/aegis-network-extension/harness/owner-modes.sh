# shellcheck shell=bash
# B-06 owner-attended modes of harness/real-relay-window.sh, sourced by it
# after harness/netloss.sh (never run alone). Each runs once while
# Connected, after the IPv6 rows, and never together with another
# disruption (NETLOSS=1, SLEEP=1 or IFSWITCH=1) in the same window.
#
# SLEEP=1: needs `sudo -n` for /usr/bin/pmset (the owner ran `sudo -v` in
# this terminal; never a prompt) and (v30) SleepDisabled 0 in the
# unprivileged `pmset -g` (`pmset disablesleep 1` makes the kernel refuse
# every demand sleep, kPMUserDisabledAllSleep: pmset sleepnow exits 71, as
# in window-v29-sleep-r3; only the owner changes it). It first arms a
# detached guard (harness/sleep_guard.py), which must report that it can use
# the sudo credential itself and that sleep is not disabled, and that waits
# for a go, then schedules a dated wake
# with `sudo -n /usr/bin/pmset schedule wake <date> aegis-b06` (only with
# SLEEP_WAKE_KIND=relative a `pmset relative wake SLEEP_WAKE_S`, which can
# never be cancelled), reads it back from `pmset -g sched` and gives the go;
# the guard reads it (and SleepDisabled) back again right before
# `sudo -n /usr/bin/pmset sleepnow` and refuses without it. The guard records
# that request's exit code, its cause and its bounded stdout and stderr
# (pmset writes its errors to stdout); the window records the schedule and
# cancel calls' output the same way. A dated wake
# that is still ahead is cancelled on every refusal and at exit. After the wake
# (kern.waketime advances) it records the provider's sleep, wake, reack and
# rebuild codes, the recovery to Connected within SLEEP_RECOVER_S and the
# traffic rows again. With LEAK_CAPTURE=1 the capture's bound covers the
# sleep, so the one capture spans it.
#
# IFSWITCH=1: the owner moves the physical default route between two
# hardware ports (Wi-Fi -> Ethernet by plugging the cable in, Ethernet ->
# Wi-Fi by unplugging it). v30: in the plug direction with an explicit
# IFSWITCH_TO that is not attached yet (an adapter plugged in seconds
# before), the preflight waits up to IFSWITCH_ATTACH_WAIT_S for it to show
# as a hardware port and an interface for IFSWITCH_ATTACH_SETTLE_S in a
# row, then reads the ports, the primary and the timing-peer lock again;
# every other check is unchanged, and a target with a link already (cable
# in) is refused. The window prints the action, waits up to
# IFSWITCH_BOUND_S for the IPv4 primary of `scutil --nwi` to move, then
# records the provider's path codes, the recovery and the traffic rows. With
# LEAK_CAPTURE=1 both interfaces are captured (two tcpdump processes) and
# both reviewed (S20d: any other interface the Mac could send on gets its
# own capture from the window, never a second one of the target; S20e: the
# window starts those under the same alarm with or without IFSWITCH=1). One
# of them sits on an interface without a link, where
# tcpdump's packet-driven -G bound never fires, so both start under a root
# alarm (`sudo -n /usr/bin/perl -e 'alarm shift; exec @ARGV'`, which the
# exec keeps) that ends them at the latest OM_CAPTURE_ALARM_S after their
# start. The window stops both; the detached rollback's `sudo -n /bin/kill`
# is best effort only (its new session has no cached sudo credential), the
# alarm is what guarantees they end. In the plug direction the target's
# network service must rank above the current one.
#
# v33: between ifswitch_recovered and the probes a settle gate (om_settle)
# reads the provider's own log until the switch has settled
# (harness/settle_judge.py): ifswitch_recovered reads only the system's
# state, and in window-v32-ifswitch-r3 the provider lost its session 1.4 s
# after that passed, so the whoami probe ran inside the rebuild. The gate
# shares IFSWITCH_RECOVER_S with the recovery, counted from the route
# change: the rollback and capture bounds are unchanged.
#
# Uses from the window: OUT, PHYS, SID, LEAK_CAPTURE, NETLOSS, CAP_PID,
# CAPTURE_BOUND_S, RELAY_IP, RELAY_PORT, HARNESS_DIR, MS_ARGS, ARMED_ARGS, result, alive,
# say, is_capture, capture_leaf, capture_running, strict_line; from netloss.sh:
# nl_int, nl_bounded, nl_traffic, NETWORKSETUP, LOG_BIN. Results and logs name
# interfaces, never an address.
SLEEP=${SLEEP:-0}
SLEEP_WAKE_S=${SLEEP_WAKE_S:-40}
SLEEP_WAKE_KIND=${SLEEP_WAKE_KIND:-absolute}
SLEEP_WAKE_SLACK_S=${SLEEP_WAKE_SLACK_S:-60}
SLEEP_RECOVER_S=${SLEEP_RECOVER_S:-60}
SLEEP_GUARD_SETTLE_S=${SLEEP_GUARD_SETTLE_S:-2}
# v30: the guard's bound for its one sudo -n pmset sleepnow.
SLEEP_GUARD_CALL_S=${SLEEP_GUARD_CALL_S:-20}
IFSWITCH=${IFSWITCH:-0}
IFSWITCH_TO=${IFSWITCH_TO:-}
IFSWITCH_BOTH_ACTIVE=${IFSWITCH_BOTH_ACTIVE:-0}
IFSWITCH_BOUND_S=${IFSWITCH_BOUND_S:-120}
IFSWITCH_RECOVER_S=${IFSWITCH_RECOVER_S:-60}
# v33: the settle gate's quiet period: how much provider log after the last
# path change, rebuild or route change (with no loss pending) releases the
# probes. 5 s is above the longest capture lease of the v32 windows
# (3660 ms), the latest a silently broken path surfaces as
# capture_lease_expired.
IFSWITCH_SETTLE_QUIET_S=${IFSWITCH_SETTLE_QUIET_S:-5}
# v33 review: what IFSWITCH_RECOVER_S must leave beyond the quiet period.
# The gate starts no read in the bound's last second and reads about once a
# second, and the quiet period counts from the last rebuild, which came
# 3.79 s after the route change in window-v32-ifswitch-r3: 1 + 1 + 4 s.
OM_SETTLE_SLACK_S=6
# v30: how long the plug direction waits for a just-attached IFSWITCH_TO
# (0 refuses at once, as before), and how long it must stay attached.
IFSWITCH_ATTACH_WAIT_S=${IFSWITCH_ATTACH_WAIT_S:-30}
IFSWITCH_ATTACH_SETTLE_S=${IFSWITCH_ATTACH_SETTLE_S:-6}
# Unprivileged reads only (`-g sched`); every change goes through
# `sudo -n /usr/bin/pmset`. PMSET and SYSCTL exist for the tests.
PMSET=${PMSET:-/usr/bin/pmset}
SYSCTL=${SYSCTL:-sysctl}
OM_PY=${OM_PY:-/usr/bin/python3}
OM_MODE='' OM_REFUSAL='' OM_EXTRA_S=0 OM_CAPTURE_EXTRA_S=0 OM_SUMMARY='' OM_EXIT=3
OM_SLEEP_DISABLED='' OM_GUARD_CREDENTIAL='' OM_ATTACH_NOTE='' OM_ATTACH_INFO=''
OM_PORTS='' OM_DEVICES='' OM_PORT='' OM_TO_PORT='' OM_DIR=''
OM_EXPECT_PHYS='' OM_PHYS0='' OM_DEF6_ALT='' OM_BASE_ADDRS='' OM_BASE_ADDRS2=''
OM_WAKE_DATE='' OM_WAKE_AT='' OM_GUARD_LOG='' OM_GUARD_PID='' OM_LOG_COUNTS='' OM_DEF6_NONE_OK=0
OM_WIFI_ARMED=0
# v30 review: who holds sleep-guard.log.claim ('' not yet asked, window or
# guard), a dated wake kept because a request may still sleep the Mac, and
# whether the window saw the wake after the guard's request.
OM_GUARD_CLAIM='' OM_GUARD_CLAIM_LINE='' OM_WAKE_KEEP=0 OM_SLEEP_WOKE=0
# v30 review: the guard's longest path from the go to its verdict besides
# the settle and its request (SLEEP_GUARD_CALL_S): one bounded ps while it
# waits for the go, then ps, pmset -g, pmset -g sched and the ps after its
# claim, 10 s each in sleep_guard.py. The window waits that long and a
# margin before it reads "no verdict" (OM_VERDICT_WAIT_S).
OM_GUARD_READS_S=50 OM_GUARD_MARGIN_S=10 OM_VERDICT_WAIT_S=0
# The root alarm of the IFSWITCH=1 captures (perl keeps it across its exec
# of tcpdump, which sets none of its own without -v): the hard end of a
# capture on an interface that never sees a packet.
OM_PERL=/usr/bin/perl
OM_ALARM_PL='alarm shift; exec @ARGV; exit 127'
OM_CAPTURE_ALARM_S=0 CAPTURE_WRAP=() CAPTURE_END_NOTE=''
CAP2_PID='' TCPDUMP2_PID='' CAP2_FILE='' CAP2_ALIVE=0 CAP2_STOPPED=0
# v33: the settle gate. The owner's prompt and the route change (epoch ms,
# om_ms), whether ifswitch_recovered passed, when the gate released the
# probes, om_up's last reads, and the provider-only predicate the gate
# reads with (S24's EL_LOG_PREDICATE, kept equal by a test). v33 review:
# the newest provider line the releasing read held (its judge's covered_ms).
OM_ASK_MS='' OM_ROUTE_MS='' OM_RECOVERED=0 OM_SETTLED_MS='' OM_ST='' OM_INET=0 OM_DEF='' OM_UTUN=''
OM_SETTLE_COVERED_MS=''
OM_SETTLE_PREDICATE='process == "aegis-ne-provider" AND eventMessage BEGINSWITH "aegis-ne"'

om_active() {
    ifconfig "$1" 2>/dev/null | grep -q 'status: active' \
        && [ "$(ifconfig "$1" 2>/dev/null | awk '$1=="inet" {n++} END{print n+0}')" != 0 ]
}
om_inet() { ifconfig "$1" 2>/dev/null | awk '$1=="inet" {n++} END{print n+0}'; }
# v30: a link (cable in), with or without an address yet.
om_link() { ifconfig "$1" 2>/dev/null | grep -q 'status: active'; }
# v30: one bounded, printable line of FILE (addresses masked), or nothing.
om_text() { [ -s "$1" ] && "$OM_PY" -I "$HARNESS_DIR/sleep_guard.py" text < "$1" 2>/dev/null; }
# Every address of one interface, for leak_review only (never recorded).
om_addrs() { ifconfig "$1" 2>/dev/null | awk '$1=="inet"||$1=="inet6"{sub(/%.*/,"",$2); print $2}'; }
om_port_of() {
    printf '%s\n' "$OM_PORTS" | awk -v d="$1" '/^Hardware Port: /{p=substr($0, 16)} /^Device: /{if ($2==d) {print p; exit}}'
}
# The physical IPv4 primary: the first hardware-port interface in the IPv4
# list of `scutil --nwi`, which keeps the physical one after the utun.
om_primary() {
    scutil --nwi 2>/dev/null | awk -v devs=" $OM_DEVICES " '
        /^IPv4 network interface information/ {f=1; next}
        /^IPv6 network interface information/ {f=0}
        f && $2==":" && $3=="flags" && index(devs, " " $1 " ") {print $1; exit}'
}
# v33: wall time in epoch milliseconds; one key's value of a key=value line.
om_ms() { "$OM_PERL" -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }
om_kv() { printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1; }
# v33: a judge's seconds with their unit; `none` (or nothing) as it is.
om_s() { case "$1" in ''|none) echo "${1:-none}" ;; *) echo "${1}s" ;; esac; }
# Seconds of kern.waketime or kern.sleeptime ({ sec = N, usec = M } ...).
om_kern_time() {
    "$SYSCTL" -n "kern.$1" 2>/dev/null \
        | awk '{for (i = 1; i < NF - 1; i++) if ($i == "sec" && $(i + 1) == "=") {v = $(i + 2); sub(/,$/, "", v); print v; exit}}'
}

# Before the lock, the rollback, the captures or any connect: sets
# OM_REFUSAL and returns 1 when the mode cannot run safely here.
om_preflight() {
    if [ "$SLEEP" = 1 ]; then OM_MODE=SLEEP=1; else OM_MODE=IFSWITCH=1; fi
    if [ "$SLEEP" = 1 ] && [ "$IFSWITCH" = 1 ]; then
        OM_REFUSAL="not with IFSWITCH=1: one owner-attended disruption per window"; return 1
    fi
    [ "$NETLOSS" != 1 ] || { OM_REFUSAL="not with NETLOSS=1: one owner-attended disruption per window"; return 1; }
    [ -n "${PHYS:-}" ] || { OM_REFUSAL="no physical default interface"; return 1; }
    if [ "$SLEEP" = 1 ]; then om_sleep_preflight; else om_ifswitch_preflight; fi
}

om_sleep_preflight() {
    local spec
    for spec in "SLEEP_WAKE_S $SLEEP_WAKE_S 20 600" "SLEEP_WAKE_SLACK_S $SLEEP_WAKE_SLACK_S 10 300" \
        "SLEEP_RECOVER_S $SLEEP_RECOVER_S 5 300" "SLEEP_GUARD_SETTLE_S $SLEEP_GUARD_SETTLE_S 0 30" \
        "SLEEP_GUARD_CALL_S $SLEEP_GUARD_CALL_S 1 60"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { OM_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    case "$SLEEP_WAKE_KIND" in
        relative|absolute) ;;
        *) OM_REFUSAL="SLEEP_WAKE_KIND=$SLEEP_WAKE_KIND is not relative or absolute"; return 1 ;;
    esac
    # A dated wake runs from its scheduling: after the guard's settle it must
    # still be far enough ahead for the system to be asleep before it.
    if [ "$SLEEP_WAKE_KIND" = absolute ] && [ "$SLEEP_WAKE_S" -lt $((SLEEP_GUARD_SETTLE_S + 20)) ]; then
        OM_REFUSAL="SLEEP_WAKE_S=$SLEEP_WAKE_S leaves under 20s between the guard's settle (${SLEEP_GUARD_SETTLE_S}s) and the dated wake: use at least $((SLEEP_GUARD_SETTLE_S + 20))"
        return 1
    fi
    sudo -n -l /usr/bin/pmset >/dev/null 2>&1 \
        || { OM_REFUSAL="needs sudo -n for /usr/bin/pmset (run sudo -v in this terminal first)"; return 1; }
    [ -n "$(om_kern_time waketime)" ] || { OM_REFUSAL="kern.waketime is unreadable: no wake could be observed"; return 1; }
    [ -x "$OM_PY" ] || { OM_REFUSAL="no sleep guard interpreter ($OM_PY missing)"; return 1; }
    # v30: a disabled sleep refuses every demand sleep; only the owner
    # changes it (sudo pmset disablesleep 0), never the window.
    OM_SLEEP_DISABLED=$("$OM_PY" -I "$HARNESS_DIR/sleep_guard.py" disabled "$PMSET" 2>/dev/null)
    case "$OM_SLEEP_DISABLED" in
        0) ;;
        1) OM_REFUSAL="SleepDisabled=1 (pmset disablesleep) refuses every pmset sleepnow (kPMUserDisabledAllSleep): the owner clears it before the window (sudo pmset disablesleep 0) and decides whether to set it again afterwards"
           return 1 ;;
        *) OM_REFUSAL="pmset -g is unreadable: SleepDisabled unknown, so no sleep could be relied on"; return 1 ;;
    esac
    OM_VERDICT_WAIT_S=$((SLEEP_GUARD_SETTLE_S + OM_GUARD_READS_S + SLEEP_GUARD_CALL_S + OM_GUARD_MARGIN_S))
    # The tunnel rollback counts awake time and tcpdump's -G bound wall time:
    # both grow by the whole cycle, the sleep and (v30 review) the whole
    # verdict wait included.
    OM_EXTRA_S=$((SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S + SLEEP_RECOVER_S + OM_VERDICT_WAIT_S + 60))
    OM_CAPTURE_EXTRA_S=$((SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S))
    OM_SUMMARY="wake=$SLEEP_WAKE_KIND:${SLEEP_WAKE_S}s"
}

om_ifswitch_preflight() {
    local spec dev cands p n explicit
    for spec in "IFSWITCH_BOUND_S $IFSWITCH_BOUND_S 5 600" "IFSWITCH_RECOVER_S $IFSWITCH_RECOVER_S 5 300" \
        "IFSWITCH_SETTLE_QUIET_S $IFSWITCH_SETTLE_QUIET_S 2 30"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { OM_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    # v33: the settle gate shares IFSWITCH_RECOVER_S. v33 review: a quiet
    # period closer to it than OM_SETTLE_SLACK_S could never settle after a
    # rebuild (no read in the last second, about one a second, the quiet
    # period from the rebuild on), so the gate would fail every switch.
    [ $((IFSWITCH_RECOVER_S - IFSWITCH_SETTLE_QUIET_S)) -ge "$OM_SETTLE_SLACK_S" ] \
        || { OM_REFUSAL="IFSWITCH_SETTLE_QUIET_S=$IFSWITCH_SETTLE_QUIET_S leaves under ${OM_SETTLE_SLACK_S}s of IFSWITCH_RECOVER_S=$IFSWITCH_RECOVER_S, which the settle gate shares (no read in its last second, about one a second, a rebuild up to 4s after the route change): use IFSWITCH_RECOVER_S of at least $((IFSWITCH_SETTLE_QUIET_S + OM_SETTLE_SLACK_S))"; return 1; }
    [ -x "$OM_PY" ] && [ -f "$HARNESS_DIR/settle_judge.py" ] \
        || { OM_REFUSAL="no settle judge ($OM_PY or harness/settle_judge.py missing)"; return 1; }
    dev=$(command -v "$NETWORKSETUP") || { OM_REFUSAL="networksetup not found"; return 1; }
    NETWORKSETUP=$dev
    OM_PORTS=$(nl_bounded 20 "$NETWORKSETUP" -listallhardwareports 2>/dev/null) \
        || { OM_REFUSAL="networksetup -listallhardwareports failed"; return 1; }
    OM_DEVICES=$(printf '%s\n' "$OM_PORTS" | awk '/^Device: /{printf "%s ", $2}')
    OM_PORT=$(om_port_of "$PHYS")
    [ -n "$OM_PORT" ] || { OM_REFUSAL="physical interface $PHYS is no hardware port"; return 1; }
    for spec in "IFSWITCH_ATTACH_WAIT_S $IFSWITCH_ATTACH_WAIT_S 0 180" "IFSWITCH_ATTACH_SETTLE_S $IFSWITCH_ATTACH_SETTLE_S 2 30"; do
        # shellcheck disable=SC2086
        set -- $spec
        nl_int "$@" || { OM_REFUSAL="$1=$2 is outside $3..$4"; return 1; }
    done
    p=$(om_primary)
    [ "$p" = "$PHYS" ] || { OM_REFUSAL="scutil --nwi names ${p:-no hardware port} as the IPv4 primary, not $PHYS"; return 1; }
    # Wi-Fi -> Ethernet by plugging the cable in; Ethernet -> Wi-Fi by unplugging it.
    if [ "$OM_PORT" = Wi-Fi ]; then
        OM_DIR=plug
        cands=$(printf '%s\n' "$OM_PORTS" | awk -v d="$PHYS" '/^Hardware Port: /{p=substr($0, 16)}
            /^Device: /{if ($2!=d && $2~/^en[0-9]+$/ && p~/Ethernet|LAN/) print $2}')
    else
        OM_DIR=unplug
        cands=$(printf '%s\n' "$OM_PORTS" | awk -v d="$PHYS" '/^Hardware Port: /{p=substr($0, 16)}
            /^Device: /{if ($2!=d && p=="Wi-Fi") print $2}')
    fi
    explicit=0
    [ -z "$IFSWITCH_TO" ] || { cands=$IFSWITCH_TO; explicit=1; }
    n=$(printf '%s' "$cands" | grep -c .)
    [ "$n" = 1 ] || { OM_REFUSAL="$n interfaces to switch to from $PHYS ($OM_PORT), not one: set IFSWITCH_TO"; return 1; }
    IFSWITCH_TO=$cands
    [ "$IFSWITCH_TO" != "$PHYS" ] || { OM_REFUSAL="IFSWITCH_TO=$IFSWITCH_TO is the physical default interface"; return 1; }
    if [ "$OM_DIR" = plug ] && [ "$explicit" = 1 ] && [ "$IFSWITCH_ATTACH_WAIT_S" -gt 0 ] && ! om_attached "$IFSWITCH_TO"; then
        om_wait_attach || return 1
    fi
    OM_TO_PORT=$(om_port_of "$IFSWITCH_TO")
    [ -n "$OM_TO_PORT" ] || { OM_REFUSAL="IFSWITCH_TO=$IFSWITCH_TO is no hardware port$OM_ATTACH_NOTE"; return 1; }
    ifconfig "$IFSWITCH_TO" >/dev/null 2>&1 || { OM_REFUSAL="$IFSWITCH_TO is not present (attach the adapter first)$OM_ATTACH_NOTE"; return 1; }
    if [ "$IFSWITCH_BOTH_ACTIVE" = 1 ]; then
        [ "$PHYS" = en0 ] && [ "$IFSWITCH_TO" = en10 ] && [ "$OM_PORT" = Wi-Fi ] \
            && om_active en0 && om_active en10 && [ -n "${AEGIS_CAPTURE_SOCKET:-}" ] \
            && [ "$LEAK_CAPTURE" = 1 ] \
            || { OM_REFUSAL="both-active requires captured en0 Wi-Fi and active en10 IPv4 under the reviewed root bridge"; return 1; }
        OM_DIR=both_active
        [ "$(nl_state wifi)" = On ] \
            || { OM_REFUSAL="both-active Wi-Fi power is not On"; return 1; }
    elif [ "$OM_DIR" = plug ]; then
        ! om_active "$IFSWITCH_TO" \
            || { OM_REFUSAL="$IFSWITCH_TO ($OM_TO_PORT) is already active but not the primary: unplug its cable before the window"; return 1; }
        # v30: a link without an address yet gets one within seconds and
        # could move the primary before the owner's action.
        ! om_link "$IFSWITCH_TO" \
            || { OM_REFUSAL="$IFSWITCH_TO ($OM_TO_PORT) has a link already (status: active): take the cable out of the adapter before the window"; return 1; }
        om_service_order || return 1
    else
        om_active "$IFSWITCH_TO" \
            || { OM_REFUSAL="$IFSWITCH_TO ($OM_TO_PORT) has no active IPv4 address: unplugging $PHYS would leave no route"; return 1; }
    fi
    if [ "$LEAK_CAPTURE" = 1 ]; then
        [ -x "$OM_PERL" ] || { OM_REFUSAL="LEAK_CAPTURE=1 needs $OM_PERL for the captures' wall-clock bound"; return 1; }
        sudo -n -l "$OM_PERL" >/dev/null 2>&1 \
            || { OM_REFUSAL="LEAK_CAPTURE=1 needs sudo -n for $OM_PERL (the captures' wall-clock bound; run sudo -v first)"; return 1; }
    fi
    OM_BASE_ADDRS=$(om_addrs "$PHYS")
    OM_BASE_ADDRS2=$(om_addrs "$IFSWITCH_TO")
    # Primary check, prompt, the owner's bound, recovery, traffic 20, provider log 31.
    OM_EXTRA_S=$((IFSWITCH_BOUND_S + IFSWITCH_RECOVER_S + 100))
    OM_SUMMARY="from=$PHYS to=$IFSWITCH_TO direction=$OM_DIR"
}

# v30: DEV is listed as a hardware port in OM_PORTS and present as an
# interface.
om_attached() {
    printf '%s\n' "$OM_PORTS" | awk -v d="$1" '/^Device: /{if ($2==d) f=1} END{exit !f}' \
        && ifconfig "$1" >/dev/null 2>&1
}

# v30: the plug direction's wait for a just-attached IFSWITCH_TO, before the
# lock, the rollback, the captures and any connect. Polls once a second;
# proceeds once the target has been a hardware port and an interface for
# IFSWITCH_ATTACH_SETTLE_S in a row (a disappearance restarts the settle),
# then reads OM_PORTS and OM_DEVICES again and repeats the primary and the
# timing-peer checks. When nothing attaches in time it returns 0 with
# OM_ATTACH_NOTE set, so the usual checks refuse with their own texts; new
# hardware-port names seen meanwhile are named (names only).
om_wait_attach() {
    local dev=$IFSWITCH_TO t0=$SECONDS since='' ports='' before=" $OM_DEVICES " new d p
    say "ifswitch: waiting up to ${IFSWITCH_ATTACH_WAIT_S}s for $dev to attach (adapter in, cable out)"
    while :; do
        ports=$(nl_bounded 10 "$NETWORKSETUP" -listallhardwareports 2>/dev/null) || ports=''
        if printf '%s\n' "$ports" | awk -v d="$dev" '/^Device: /{if ($2==d) f=1} END{exit !f}' \
            && ifconfig "$dev" >/dev/null 2>&1; then
            [ -n "$since" ] || since=$SECONDS
            [ $((SECONDS - since)) -lt "$IFSWITCH_ATTACH_SETTLE_S" ] || break
        else
            since=''
            if [ $((SECONDS - t0)) -ge "$IFSWITCH_ATTACH_WAIT_S" ]; then
                new=''
                for d in $(printf '%s\n' "$ports" | awk '/^Device: /{print $2}'); do
                    case "$before" in *" $d "*) ;; *) new="${new:+$new,}$d" ;; esac
                done
                OM_ATTACH_NOTE=" (not attached within ${IFSWITCH_ATTACH_WAIT_S}s${new:+; new hardware ports: $new})"
                return 0
            fi
        fi
        sleep 1
    done
    OM_ATTACH_INFO="attach_after=$((since - t0))s settle=${IFSWITCH_ATTACH_SETTLE_S}s"
    say "ifswitch: $dev attached after $((since - t0))s and stayed for ${IFSWITCH_ATTACH_SETTLE_S}s"
    OM_PORTS=$ports
    OM_DEVICES=$(printf '%s\n' "$OM_PORTS" | awk '/^Device: /{printf "%s ", $2}')
    p=$(om_primary)
    [ "$p" = "$PHYS" ] || { OM_REFUSAL="scutil --nwi names ${p:-no hardware port} as the IPv4 primary after $dev attached, not $PHYS"; return 1; }
    if [ -e "$FOREIGN_TIMING_LOCK" ]; then
        OM_REFUSAL="foreign timing lock taken while waiting for $dev" OM_EXIT=4
        return 1
    fi
}

# The plug direction moves the IPv4 primary only when the target's network
# service ranks above the current one in the service order: the lowest
# enabled rank of each device in `networksetup -listnetworkserviceorder`
# (a disabled `(*)` entry never counts).
om_service_rank() {
    printf '%s\n' "$1" | awk -v suf=", Device: $2)" '
        /^\([0-9]+\) / {r = $0; sub(/^\(/, "", r); sub(/\).*$/, "", r); en = 1; next}
        /^\(\*\) / {en = 0; next}
        /^\(Hardware Port: / {
            if (en && length($0) > length(suf) && substr($0, length($0) - length(suf) + 1) == suf && (best == "" || r + 0 < best + 0)) best = r
            en = 0
        }
        END {print best}'
}
om_service_order() {
    local order from to
    order=$(nl_bounded 20 "$NETWORKSETUP" -listnetworkserviceorder 2>/dev/null) \
        || { OM_REFUSAL="networksetup -listnetworkserviceorder failed"; return 1; }
    to=$(om_service_rank "$order" "$IFSWITCH_TO") from=$(om_service_rank "$order" "$PHYS")
    [ -n "$to" ] || { OM_REFUSAL="$IFSWITCH_TO ($OM_TO_PORT) has no enabled network service in networksetup -listnetworkserviceorder"; return 1; }
    [ -z "$from" ] || [ "$to" -lt "$from" ] \
        || { OM_REFUSAL="the $IFSWITCH_TO service (order $to) ranks below the $PHYS service (order $from) in networksetup -listnetworkserviceorder: plugging in would not move the primary; move it above first"; return 1; }
}

# IFSWITCH=1 with LEAK_CAPTURE=1: every capture under the root alarm, set
# once the capture bound is known (both captures share it).
om_capture_wrap() {
    if [ "$IFSWITCH" = 1 ] && [ "$LEAK_CAPTURE" = 1 ]; then
        OM_CAPTURE_ALARM_S=$((CAPTURE_BOUND_S + 30))
        CAPTURE_WRAP=("$OM_PERL" -e "$OM_ALARM_PL" "$OM_CAPTURE_ALARM_S")
        CAPTURE_END_NOTE="its root alarm ends it at the latest ${OM_CAPTURE_ALARM_S}s after its start"
    fi
}

# LEAK_CAPTURE=1 with IFSWITCH=1: the second physical interface, the same
# way as the first. An interface without a link writes no packet, so the
# start is read from tcpdump's own `listening on` line, not the file size.
om_start_capture2() {
    local dev=$IFSWITCH_TO err
    CAP2_FILE="physical-$dev.pcap" err="$OUT/tcpdump-$dev.stderr"
    sudo -n "${CAPTURE_WRAP[@]}" /usr/sbin/tcpdump -i "$dev" -p -s 160 -B 4096 -G "$CAPTURE_BOUND_S" -W 1 -U \
        -w "$OUT/$CAP2_FILE" >/dev/null 2>"$err" &
    CAP2_PID=$!
    for _ in $(seq 1 12); do grep -q "listening on $dev" "$err" 2>/dev/null && break; alive "$CAP2_PID" || break; sleep 0.25; done
    TCPDUMP2_PID=$(capture_leaf "$CAP2_PID" "$OUT/$CAP2_FILE")
    if ! alive "$CAP2_PID" || ! grep -q "listening on $dev" "$err" 2>/dev/null || [ -z "$TCPDUMP2_PID" ]; then
        say "refused: tcpdump on $dev did not start: $(head -c 200 "$err")"
        return 1
    fi
    result ifswitch_capture_started pass "pid=$CAP2_PID tcpdump=$TCPDUMP2_PID if=$dev file=$CAP2_FILE bound=${CAPTURE_BOUND_S}s alarm=${OM_CAPTURE_ALARM_S}s"
}

# Stops the second capture once, like stop_capture stops the first.
om_stop_capture2() {
    [ -n "$CAP2_PID" ] || return 0
    local pid=$CAP2_PID tpid=$TCPDUMP2_PID
    CAP2_PID=
    [ -n "$tpid" ] && is_capture "$tpid" "$OUT/$CAP2_FILE" || tpid=
    if [ -n "$tpid" ]; then
        sudo -n /bin/kill -INT "$tpid" 2>/dev/null || kill -INT "$pid" 2>/dev/null
    else
        kill -INT "$pid" 2>/dev/null
    fi
    for _ in $(seq 1 20); do capture_running "$pid" "$tpid" || break; sleep 0.25; done
    capture_running "$pid" "$tpid" && [ -n "$tpid" ] && sudo -n /bin/kill -TERM "$tpid" 2>/dev/null
    for _ in $(seq 1 8); do capture_running "$pid" "$tpid" || break; sleep 0.25; done
    if capture_running "$pid" "$tpid" || ! capture_sealed "$OUT/$CAP2_FILE"; then
        say "capture of $IFSWITCH_TO still running: $CAPTURE_END_NOTE; stop it now with: sudo kill -INT ${tpid:-$pid}"
        result ifswitch_capture_stopped fail "pid=$pid tcpdump=${tpid:-?} still running"
        CAP2_STOPPED=0
    else
        result ifswitch_capture_stopped pass "pid=$pid tcpdump=${tpid:-?}"
        CAP2_STOPPED=1
    fi
}

# v33: the state om_recover waits for, read once: Connected, an IPv4
# address on DEV and the default route on the tunnel's utun. The reads stay
# in OM_ST, OM_INET, OM_DEF and OM_UTUN for the rows.
om_up() {
    OM_ST=$(scutil --nc status "$SID" | head -1)
    OM_INET=$(om_inet "$1")
    OM_UTUN=$(ifconfig | awk '/^utun[0-9]+:/{i=$1} /inet 198\.19\.255\.1 /{sub(":","",i); print i}' | head -1)
    OM_DEF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    [ "$OM_ST" = Connected ] && [ "$OM_INET" != 0 ] && [ -n "$OM_UTUN" ] && [ "$OM_DEF" = "$OM_UTUN" ]
}
# Connected on two polls in a row, the default route on the tunnel's utun
# and an IPv4 address on DEV, within BOUND seconds.
om_recover() {
    local p=$1 bound=$2 dev=$3 t0=$SECONDS ok=0
    OM_RECOVERED=0 OM_ST='' OM_INET=0 OM_DEF='' OM_UTUN=''
    while [ $((SECONDS - t0)) -le "$bound" ]; do
        if om_up "$dev"; then
            ok=$((ok + 1))
            [ "$ok" -ge 2 ] && break
        else
            ok=0
        fi
        sleep 0.5
    done
    if [ "$ok" -ge 2 ]; then
        OM_RECOVERED=1
        result "${p}recovered" pass "$((SECONDS - t0))s bound=${bound}s if=$dev"
    else
        result "${p}recovered" fail "not within ${bound}s status=${OM_ST:-none} ${dev}_inet=$OM_INET default=${OM_DEF:-none} utun=${OM_UTUN:-none}"
    fi
}

# v33: the settle gate between ifswitch_recovered and the post-switch
# probes. om_recover reads only the system's state, and the provider can
# lose its session after that passed: in window-v32-ifswitch-r3 it passed
# 0.56 s after the route change, the provider lost the session by lease
# expiry at +1.97 s and rebuilt it at +3.79 s, so the whoami probe ran
# inside the rebuild. Once a second the gate reads the provider's own log
# (OM_SETTLE_PREDICATE: that process only, from the window's START) into
# OUT/<P>settle.log and asks harness/settle_judge.py whether the switch
# settled: no session_failed, no loss pending, a path_change since the
# owner's prompt, and IFSWITCH_SETTLE_QUIET_S of provider log after the
# last path change, rebuild or route change; om_up must hold then too, and
# a failed read never settles. It shares IFSWITCH_RECOVER_S with om_recover,
# counted from the route change (OM_ROUTE_MS), so the rollback and capture
# bounds are unchanged: no read starts with under 1 s left, and each is
# bounded by what is left, at most 10 s. Every read is traced in
# OUT/<P>settle.trace. <P>settled_before_probes passes with the settle
# times; it fails at once on a session_failed and at the bound otherwise (a
# rebuild that never settles, a loss pending, flapping rebuilds, a silent
# provider, failed reads, no path change). The probes always run afterwards
# and are judged as before. v33 review: on a release OM_SETTLE_COVERED_MS
# keeps the newest provider line that read held (the judge's covered_ms, or
# the read's start if it printed none): a line stamped later was not judged
# by the release, whatever the judge and om_up took before OM_SETTLED_MS.
om_settle() {
    local p=$1 start=$2 dev=$3
    local row="${p}settled_before_probes" file="$OUT/${p}settle.log" trace="$OUT/${p}settle.trace"
    local deadline now left b rc judge='' reads=0 bad=0 t0 up=0 failed rb
    OM_SETTLED_MS='' OM_SETTLE_COVERED_MS=''
    if [ "$OM_RECOVERED" != 1 ] || [ -z "$OM_ASK_MS" ] || [ -z "$OM_ROUTE_MS" ]; then
        result "$row" skip "not recovered"
        return 0
    fi
    deadline=$((OM_ROUTE_MS + 1000 * IFSWITCH_RECOVER_S))
    t0=$(om_ms)
    : > "$trace"
    while :; do
        now=$(om_ms)
        left=$((deadline - now))
        [ "$left" -ge 1000 ] || break
        b=$((left / 1000))
        [ "$b" -le 10 ] || b=10
        nl_bounded "$b" "$LOG_BIN" show --start "$start" --style compact --predicate "$OM_SETTLE_PREDICATE" \
            > "$file" 2>/dev/null
        rc=$?
        reads=$((reads + 1))
        [ "$rc" = 0 ] || bad=$((bad + 1))
        judge=$("$OM_PY" -I "$HARNESS_DIR/settle_judge.py" "$file" "$OM_ASK_MS" "$OM_ROUTE_MS" \
            "$((1000 * IFSWITCH_SETTLE_QUIET_S))" 2>/dev/null | head -n 1 | cut -c1-400)
        printf 'at_ms=%s rc=%s read_ms=%s %s\n' "$now" "$rc" "$(($(om_ms) - now))" "${judge:-judge=none}" >> "$trace"
        failed=$(om_kv "$judge" failed)
        if [ -n "$failed" ] && [ "$failed" != none ]; then
            result "$row" fail "session_failed:$failed after $(om_s "$(om_kv "$judge" failed_after)") reads=$reads"
            return 0
        fi
        if [ "$rc" = 0 ] && [ "$(om_kv "$judge" settled)" = 1 ] && om_up "$dev"; then
            OM_SETTLED_MS=$(om_ms)
            OM_SETTLE_COVERED_MS=$(om_kv "$judge" covered_ms)
            case "$OM_SETTLE_COVERED_MS" in ''|*[!0-9]*) OM_SETTLE_COVERED_MS=$now ;; esac
            rb="rebuilt_after=$(om_kv "$judge" rebuilt_after)s"
            [ "$(om_kv "$judge" rebuilt_after)" != none ] || rb=no_loss
            result "$row" pass "settled_after=$(om_kv "$judge" settled_after)s $rb path_change_after=$(om_kv "$judge" path_change_after)s quiet=${IFSWITCH_SETTLE_QUIET_S}s lost=$(om_kv "$judge" lost) rebuilt=$(om_kv "$judge" rebuilt) reads=$reads probes_after=$(awk -v a="$OM_SETTLED_MS" -v r="$OM_ROUTE_MS" 'BEGIN {printf "%.1f", (a - r) / 1000}')s bound=${IFSWITCH_RECOVER_S}s"
            return 0
        fi
        sleep 1
    done
    om_up "$dev" && up=1
    result "$row" fail "not settled within ${IFSWITCH_RECOVER_S}s of the route change: pending=$(om_kv "$judge" pending) lost=$(om_kv "$judge" lost) rebuilt=$(om_kv "$judge" rebuilt) path_change=$(om_kv "$judge" path_change) settled_after=$(om_s "$(om_kv "$judge" settled_after)") covered_after=$(om_s "$(om_kv "$judge" covered_after)") reads=$reads failed_reads=$bad up=$up status=${OM_ST:-none} waited=$((($(om_ms) - t0) / 1000))s"
}

# The provider's codes since START: one info row per event (count and
# values), the counts in OM_LOG_COUNTS, and whether a reassertion settled.
om_provider_log() {
    local p=$1 start=$2 file="$OUT/${1}provider.log" ev d n
    shift 2
    sleep 1
    nl_bounded 30 "$LOG_BIN" show --start "$start" --style compact --predicate 'eventMessage BEGINSWITH "aegis-ne"' \
        2>/dev/null | grep -vE 'Timestamp|secinitd' > "$file"
    OM_LOG_COUNTS=''
    for ev in "$@"; do
        d=$(awk -v e="$ev" '{for (i = 1; i < NF; i++) if ($i == "aegis-ne" && $(i + 1) == e) {
                n++; v = (i + 2 <= NF) ? $(i + 2) : "-"; s = s (s == "" ? "" : ",") v } }
            END { printf "count=%d seq=%s", n, (s == "" ? "none" : s) }' "$file" | cut -c1-240)
        result "${p}log_$ev" info "$d"
        n=${d#count=}
        OM_LOG_COUNTS="$OM_LOG_COUNTS $ev=${n%% *}"
    done
    d=$(om_last "$file" reasserting)
    if [ ! -s "$file" ]; then result "${p}rebuild_settled" unavailable "no provider log lines"
    elif [ -z "$d" ]; then result "${p}rebuild_settled" pass "no_reassert"
    elif [ "$d" = off ]; then result "${p}rebuild_settled" pass "reasserting_off"
    else result "${p}rebuild_settled" fail "last_reasserting=$d"
    fi
}
om_count() {
    local c
    for c in $OM_LOG_COUNTS; do case "$c" in "$1="*) echo "${c#*=}"; return ;; esac; done
    echo 0
}
om_last() { awk -v e="$2" '{for (i = 1; i < NF; i++) if ($i == "aegis-ne" && $(i + 1) == e) v = (i + 2 <= NF) ? $(i + 2) : "-"} END {print v}' "$1"; }
om_count_value() { awk -v e="$2" -v w="$3" '{for (i = 1; i + 2 <= NF; i++) if ($i == "aegis-ne" && $(i + 1) == e && $(i + 2) == w) n++} END {print n+0}' "$1"; }

# Best effort, after a refusal and at exit: a dated wake that is still
# ahead is cancelled by its date and owner, once; a relative one cannot be
# (it applies to the next sleep), which the window said before scheduling it.
# v30 review: never once it is kept (om_keep_wake).
om_cancel_wake() {
    local why=${1:-} rc out
    [ "$OM_WAKE_KEEP" = 0 ] || return 0
    if [ "$SLEEP_WAKE_KIND" = absolute ] && [ -n "$OM_WAKE_DATE" ]; then
        if [ "$(date +%s)" -lt "$OM_WAKE_AT" ]; then
            sudo -n /usr/bin/pmset schedule cancel wake "$OM_WAKE_DATE" aegis-b06 >"$OUT/sleep-cancel.out" 2>&1
            rc=$?
            out=$(om_text "$OUT/sleep-cancel.out")
            result sleep_wake_cancelled info "rc=$rc${why:+ $why}${out:+ out=[$out]}"
        fi
        OM_WAKE_DATE=''
    elif [ "$SLEEP_WAKE_KIND" = relative ] && [ -n "$OM_WAKE_AT" ] && [ -z "$why" ]; then
        result sleep_wake_cancelled info "relative wake cannot be cancelled: it applies to the next sleep"
    fi
}

# v30 review: a sleep request that may still bring the Mac to sleep keeps
# the dated wake, its only way back: the row says so and how to remove the
# wake later. A wake already past needs no row.
om_keep_wake() {
    OM_WAKE_KEEP=1
    if [ "$SLEEP_WAKE_KIND" = absolute ] && [ -n "$OM_WAKE_DATE" ] && [ "$(date +%s)" -lt "$OM_WAKE_AT" ]; then
        result sleep_wake_kept info "$1: the dated wake $OM_WAKE_DATE is kept so the Mac wakes by itself; remove it once awake with: sudo pmset schedule cancel wake '$OM_WAKE_DATE' aegis-b06"
    fi
}
# True while the guard holds the claim and its log does not show that its
# request is over: no verdict yet, a request bounded by a timeout (only
# sudo was killed) or by a signal, or an accepted one whose wake the window
# has not seen. A refusal, a request that sudo or pmset refused, or a
# sudo that could not start ends it.
om_request_pending() {
    local line
    [ "$OM_GUARD_CLAIM" = guard ] || return 1
    line=$(grep -E '^sleep_(requested|refused) ' "$OM_GUARD_LOG" 2>/dev/null | tail -1)
    case "$line" in
        'sleep_refused '*|'sleep_requested rc=error '*) return 1 ;;
        'sleep_requested rc=0 '*) [ "$OM_SLEEP_WOKE" = 0 ] ;;
        'sleep_requested rc='[1-9]*) return 1 ;;
        *) return 0 ;;
    esac
}
# The EXIT trap's first step, before any capture is stopped (v30 review): an
# armed guard is told to stand down at once, so an aborted window does not
# sleep the Mac while its trap is still running.
om_on_exit_first() {
    [ -z "$OM_GUARD_LOG" ] || om_guard_cancel || true
}
# The EXIT trap's part of the modes: the second capture and a dated wake
# that is still ahead, unless a request may still sleep the Mac.
om_on_exit() {
    if [ "$OM_WIFI_ARMED" = 1 ]; then
        if sudo --wifi on >/dev/null 2>&1; then
            result ifswitch_wifi_restored pass "en0 Wi-Fi On; detached restore actor ended"
            OM_WIFI_ARMED=0
        else
            result ifswitch_wifi_restored fail "root bridge refused; independent 180s restore remains armed"
        fi
    fi
    om_stop_capture2
    [ "$OM_WAKE_KEEP" = 0 ] || return 0
    if [ -n "$OM_GUARD_LOG" ] && ! om_guard_cancel && om_request_pending; then
        om_keep_wake "at_exit: the guard's sleep request may still run (${OM_GUARD_CLAIM_LINE:-claim held by the guard})"
    else
        om_cancel_wake at_exit
    fi
}

# The detached guard, armed before any wake is scheduled; true once it is
# confirmed alive, adopted by launchd (ppid 1) and the leader of its own
# process group. It waits for $OM_GUARD_LOG.go.
om_arm_guard() {
    local launcher info
    OM_GUARD_LOG="$OUT/sleep-guard.log" OM_GUARD_PID='' OM_GUARD_CREDENTIAL=''
    nohup "$OM_PY" -I "$HARNESS_DIR/sleep_guard.py" guard "$PMSET" "$OM_GUARD_LOG" "$$" "$SLEEP_GUARD_SETTLE_S" \
        "$SLEEP_GUARD_CALL_S" </dev/null >/dev/null 2>&1 &
    launcher=$!
    wait "$launcher"
    for _ in $(seq 1 40); do
        OM_GUARD_PID=$(sed -n 's/^armed pid=\([0-9][0-9]*\) .*/\1/p' "$OM_GUARD_LOG" 2>/dev/null | tail -1)
        [ -n "$OM_GUARD_PID" ] && break
        sleep 0.05
    done
    [ -n "$OM_GUARD_PID" ] && [ "$OM_GUARD_PID" != "$launcher" ] && alive "$OM_GUARD_PID" || return 1
    info=$(ps -p "$OM_GUARD_PID" -o ppid= -o pgid= 2>/dev/null | awk '{print $1, $2}')
    [ "$info" = "1 $OM_GUARD_PID" ] || return 1
    # v30: the guard itself, detached as it is when it asks for the sleep,
    # must be able to use the sudo credential, and sleep must be enabled.
    for _ in $(seq 1 60); do
        OM_GUARD_CREDENTIAL=$(grep '^credential ' "$OM_GUARD_LOG" 2>/dev/null | head -n 1 | cut -c1-300)
        [ -n "$OM_GUARD_CREDENTIAL" ] && break
        sleep 0.25
    done
    [ "${OM_GUARD_CREDENTIAL%% rc=*}" = "credential sudo=ok sleep_disabled=0" ]
}
# The guard stands down: LOG.cancel for its earlier checks, then (v30
# review) the claim, which it creates right before its request. True when
# the window holds the claim, so the guard can never ask for the sleep any
# more; false when the guard holds it, so its request may have run. The
# answer, once known, never changes.
om_guard_cancel() {
    : > "$OM_GUARD_LOG.cancel"
    if [ -z "$OM_GUARD_CLAIM" ]; then
        if (set -C; printf 'window pid=%s at=%s\n' "$$" "$(date +%s)" > "$OM_GUARD_LOG.claim") 2>/dev/null; then
            OM_GUARD_CLAIM=window
        else
            OM_GUARD_CLAIM=guard
            OM_GUARD_CLAIM_LINE=$(head -n 1 "$OM_GUARD_LOG.claim" 2>/dev/null | cut -c1-80)
        fi
    fi
    [ "$OM_GUARD_CLAIM" = window ]
}

om_sleep_window() {
    local start t0 rc hi listed line req_at wake0 wake1 sleep1 deadline st a s w rk rb ok out
    start=$(date '+%Y-%m-%d %H:%M:%S')
    result sleep_preflight info "kind=$SLEEP_WAKE_KIND wake_s=$SLEEP_WAKE_S slack_s=$SLEEP_WAKE_SLACK_S recover_bound=${SLEEP_RECOVER_S}s sleep_disabled=$OM_SLEEP_DISABLED"
    wake0=$(om_kern_time waketime)
    # The guard first: a guard that cannot be confirmed leaves no wake behind.
    if ! om_arm_guard; then
        om_guard_cancel
        result sleep_guard_armed fail "pid=${OM_GUARD_PID:-none} ${OM_GUARD_CREDENTIAL:-credential=none}; cancelled, no wake scheduled, nothing slept"
        return 1
    fi
    result sleep_guard_armed pass "pid=$OM_GUARD_PID settle=${SLEEP_GUARD_SETTLE_S}s"
    t0=$(date +%s)
    if [ "$SLEEP_WAKE_KIND" = absolute ]; then
        OM_WAKE_AT=$((t0 + SLEEP_WAKE_S))
        OM_WAKE_DATE=$(date -r "$OM_WAKE_AT" '+%m/%d/%y %H:%M:%S')
        sudo -n /usr/bin/pmset schedule wake "$OM_WAKE_DATE" aegis-b06 >"$OUT/sleep-pmset.out" 2>&1
    else
        say "sleep: SLEEP_WAKE_KIND=relative: this wake cannot be cancelled or undone; if the window refuses after it, the Mac wakes about ${SLEEP_WAKE_S}s into its next sleep"
        OM_WAKE_AT=$t0
        sudo -n /usr/bin/pmset relative wake "$SLEEP_WAKE_S" >"$OUT/sleep-pmset.out" 2>&1
    fi
    rc=$?
    out=$(om_text "$OUT/sleep-pmset.out")
    hi=$((t0 + SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S))
    listed=$("$OM_PY" -I "$HARNESS_DIR/sleep_guard.py" check "$PMSET" "$hi" 2>/dev/null)
    if [ "$rc" != 0 ] || [ -z "$listed" ]; then
        om_guard_cancel
        result sleep_wake_scheduled fail "kind=$SLEEP_WAKE_KIND rc=$rc listed=${listed:-none}${out:+ out=[$out]}; nothing slept"
        om_cancel_wake
        return 1
    fi
    result sleep_wake_scheduled pass "kind=$SLEEP_WAKE_KIND rc=0 listed=$listed${out:+ out=[$out]}"
    printf 'hi=%s\n' "$hi" > "$OM_GUARD_LOG.go.tmp" && mv -f "$OM_GUARD_LOG.go.tmp" "$OM_GUARD_LOG.go"
    a=$SLEEP_WAKE_S
    [ "$SLEEP_WAKE_KIND" = absolute ] && a=$((SLEEP_WAKE_S - SLEEP_GUARD_SETTLE_S))
    say "sleep: this Mac sleeps in ${SLEEP_GUARD_SETTLE_S}s and wakes by itself about ${a}s later; leave it alone"
    line=''
    # v30 review: as long as the guard's own bounds allow (half-second
    # polls of awake time).
    for _ in $(seq 1 $((2 * OM_VERDICT_WAIT_S))); do
        line=$(grep -E '^sleep_(requested|refused) ' "$OM_GUARD_LOG" 2>/dev/null | tail -1)
        [ -n "$line" ] && break
        sleep 0.5
    done
    case "$line" in
        "sleep_requested rc=0 "*) ;;
        "")
            # The guard may still sleep later: it is told not to, and the
            # wake goes only when it can no longer ask (the claim).
            if om_guard_cancel; then
                result sleep_guard fail "no verdict from the guard pid=$OM_GUARD_PID within ${OM_VERDICT_WAIT_S}s; cancelled before its request, nothing slept"
                om_cancel_wake
            else
                result sleep_guard fail "no verdict from the guard pid=$OM_GUARD_PID within ${OM_VERDICT_WAIT_S}s; its request had started (${OM_GUARD_CLAIM_LINE:-claim held by the guard})"
                om_keep_wake "no verdict"
            fi
            return 1 ;;
        "sleep_requested rc=timeout "*|"sleep_requested rc=-"*)
            # The bound or a signal stopped only the user's sudo; the root
            # pmset it started may still ask for the sleep.
            req_at=$(printf '%s\n' "$line" | sed -n 's/.* at=\([0-9][0-9]*\).*/\1/p')
            sleep1=$(om_kern_time sleeptime)
            st=no
            [ -z "$sleep1" ] && st=unknown
            [ -n "$sleep1" ] && [ -n "$req_at" ] && [ "$sleep1" -ge $((req_at - 2)) ] && st=yes
            result sleep_guard fail "$line; outcome unknown (only sudo was stopped, the root pmset may still ask for the sleep): slept_since_request=$st"
            om_keep_wake "request outcome unknown"
            return 1 ;;
        *)
            result sleep_guard fail "$line; nothing slept"
            om_cancel_wake
            return 1 ;;
    esac
    result sleep_guard pass "$line"
    req_at=$(printf '%s\n' "$line" | sed -n 's/.* at=\([0-9][0-9]*\).*/\1/p')
    deadline=$((req_at + SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S))
    wake1=$wake0
    while [ "$(date +%s)" -le "$deadline" ]; do
        wake1=$(om_kern_time waketime)
        [ -n "$wake1" ] && [ "$wake1" -gt "$wake0" ] && { OM_SLEEP_WOKE=1; break; }
        sleep 0.5
    done
    sleep1=$(om_kern_time sleeptime)
    if [ -z "$wake1" ] || [ "$wake1" -le "$wake0" ]; then
        result sleep_woke fail "no wake within $((SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S))s of the request"
    elif [ -z "$sleep1" ] || [ "$sleep1" -lt $((req_at - 2)) ] || [ "$sleep1" -gt "$wake1" ]; then
        result sleep_woke fail "a wake without a sleep after the request: sleep_after=$(( ${sleep1:-0} - req_at ))s"
    elif [ "$wake1" -gt "$deadline" ]; then
        result sleep_woke fail "woke $((wake1 - req_at))s after the request, bound $((SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S))s"
    else
        result sleep_woke pass "slept=$((wake1 - sleep1))s woke_after=$((wake1 - req_at))s bound=$((SLEEP_WAKE_S + SLEEP_WAKE_SLACK_S))s"
    fi
    if [ "$LEAK_CAPTURE" = 1 ]; then
        st=fail
        [ -n "$CAP_PID" ] && alive "$CAP_PID" && st=pass
        result sleep_capture_alive_after_wake "$st" "pid=${CAP_PID:-none}"
    fi
    om_recover sleep_ "$SLEEP_RECOVER_S" "$PHYS"
    nl_traffic sleep_
    om_provider_log sleep_ "$start" sleep wake reack session_lost session_rebuild session_rebuilt reasserting path_change
    # The provider saw the sleep and the wake and did what its wake code says:
    # a forced re-ACK of a live lease, or a rebuild of a lapsed one.
    s=$(om_count sleep) w=$(om_count wake) rk=$(om_count reack) rb=$(om_count session_rebuilt)
    a=$(om_last "$OUT/sleep_provider.log" wake)
    ok=0
    case "$a" in
        reack) [ "$(om_count_value "$OUT/sleep_provider.log" reack forced)" -ge 1 ] && ok=1 ;;
        rebuild|reasserting) [ "$rb" -ge 1 ] && ok=1 ;;
    esac
    { [ "$s" -ge 1 ] && [ "$w" -ge 1 ]; } || ok=0
    if [ ! -s "$OUT/sleep_provider.log" ]; then
        result sleep_provider_cycle unavailable "no provider log lines"
    else
        result sleep_provider_cycle "$([ "$ok" = 1 ] && echo pass || echo fail)" "sleep=$s wake=$w last_wake=${a:-none} reack=$rk rebuilt=$rb"
    fi
}

om_ifswitch_window() {
    local start p t0 st seen='' prim prims='' new='' from
    local first_ask='' first_route='' first_settled='' first_covered=''
    start=$(date '+%Y-%m-%d %H:%M:%S')
    result ifswitch_preflight info "from=$PHYS($OM_PORT) to=$IFSWITCH_TO($OM_TO_PORT) direction=$OM_DIR bound=${IFSWITCH_BOUND_S}s recover_bound=${IFSWITCH_RECOVER_S}s${OM_ATTACH_INFO:+ $OM_ATTACH_INFO}"
    p=$(om_primary)
    if [ "$p" != "$PHYS" ]; then
        result ifswitch_primary_before fail "${p:-none}: scutil --nwi does not name $PHYS while Connected; no owner action asked"
        return 1
    fi
    result ifswitch_primary_before pass "$PHYS"
    # v33: the settle gate counts the provider's codes from the prompt on.
    OM_ASK_MS=$(om_ms)
    if [ "$OM_DIR" = both_active ]; then
        if ! sudo --wifi arm >/dev/null 2>&1; then
            result ifswitch_wifi_restore_armed fail "independent root 180s restore not armed"
            return 1
        fi
        OM_WIFI_ARMED=1
        result ifswitch_wifi_restore_armed pass "independent root 180s restore armed before off"
        if ! sudo --wifi off >/dev/null 2>&1; then
            result ifswitch_wifi_off fail "root bridge refused; restore remains armed"
            return 1
        fi
        result ifswitch_wifi_off pass "en0 power Off while en10 remains active"
    else
        printf '\a'
    fi
    if [ "$OM_DIR" = plug ]; then
        say "OWNER ACTION: plug the Ethernet cable into $IFSWITCH_TO ($OM_TO_PORT) now"
    elif [ "$OM_DIR" = unplug ]; then
        say "OWNER ACTION: unplug the Ethernet cable from $PHYS ($OM_PORT) now (the cable, not the adapter)"
    fi
    say "ifswitch: waiting up to ${IFSWITCH_BOUND_S}s for the physical default route to move from $PHYS to $IFSWITCH_TO; then leave the cable as it is until 'done'"
    # v31 review: ifswitch_route_changed reports this loop's change, written
    # after ifswitch_status_during_switch: it starts where that row does.
    from=$RESULT_FROM
    t0=$SECONDS
    while [ $((SECONDS - t0)) -lt "$IFSWITCH_BOUND_S" ]; do
        st=$(scutil --nc status "$SID" | head -1)
        case ",$seen," in *",$st,"*) ;; *) seen=${seen:+$seen,}$st ;; esac
        prim=$(om_primary)
        prim=${prim:-none}
        case ",$prims," in *",$prim,"*) ;; *) prims=${prims:+$prims,}$prim ;; esac
        if [ "$prim" != none ] && [ "$prim" != "$PHYS" ]; then new=$prim; OM_ROUTE_MS=$(om_ms); break; fi
        sleep 0.5
    done
    result ifswitch_status_during_switch info "statuses=${seen:-none} primary=${prims:-none}"
    if [ -z "$new" ]; then
        result_since "$from" ifswitch_route_changed fail "no change from $PHYS within ${IFSWITCH_BOUND_S}s"
        result ifswitch_recovered skip "no route change"
        say "ifswitch: no route change seen"
        return 1
    fi
    # The disconnect gate then waits for the default route on the new interface.
    OM_EXPECT_PHYS=$new
    result_since "$from" ifswitch_route_changed "$([ "$new" = "$IFSWITCH_TO" ] && echo pass || echo fail)" \
        "$PHYS->$new after $((SECONDS - t0))s expected=$IFSWITCH_TO"
    om_recover ifswitch_ "$IFSWITCH_RECOVER_S" "$new"
    om_settle ifswitch_ "$start" "$new"
    nl_traffic ifswitch_
    om_provider_log ifswitch_ "$start" path_change relay_interface_repinned relay_interface_repin_refused session_lost \
        session_rebuilt reasserting
    if [ "$OM_DIR" = both_active ]; then
        first_ask=$OM_ASK_MS first_route=$OM_ROUTE_MS
        first_settled=$OM_SETTLED_MS first_covered=$OM_SETTLE_COVERED_MS
        OM_ASK_MS=$(om_ms)
        if sudo --wifi on >/dev/null 2>&1; then
            OM_WIFI_ARMED=0
            result ifswitch_wifi_restored pass "en0 Wi-Fi On; detached restore actor ended"
            for _ in $(seq 1 20); do
                [ "$(om_primary)" = en0 ] && break
                sleep 0.5
            done
            if [ "$(om_primary)" = en0 ]; then
                OM_EXPECT_PHYS=en0
                OM_ROUTE_MS=$(om_ms)
                result ifswitch_primary_restored pass "en0 primary after en10 switch"
                om_recover ifswitch_return_ "$IFSWITCH_RECOVER_S" en0
                om_settle ifswitch_return_ "$start" en0
                nl_traffic ifswitch_return_
                om_provider_log ifswitch_return_ "$start" path_change relay_interface_repinned \
                    relay_interface_repin_refused session_lost session_rebuilt reasserting
                local returned pc2 rp2 rb2
                returned=$("$OM_PY" -I "$HARNESS_DIR/settle_judge.py" \
                    "$OUT/ifswitch_return_provider.log" "$OM_ASK_MS" "$OM_ROUTE_MS" 1 en0 \
                    2>/dev/null | head -n 1)
                pc2=$(om_kv "$returned" path_change) rp2=$(om_kv "$returned" repinned) \
                    rb2=$(om_kv "$returned" rebuilt)
                pc2=${pc2:-0} rp2=${rp2:-0} rb2=${rb2:-0}
                if [ "$pc2" -ge 1 ] && [ "$rp2" -ge 1 ]; then
                    result ifswitch_return_relay_path_exercised pass \
                        "path_change=$pc2 repinned_to_en0=$rp2 rebuilt=$rb2"
                else
                    result ifswitch_return_relay_path_exercised fail \
                        "no en0 return re-pin path_change=$pc2 repinned=$rp2 rebuilt=$rb2"
                fi
            else
                result ifswitch_primary_restored fail "en0 did not regain primary after restore"
            fi
        else
            result ifswitch_wifi_restored fail "root bridge refused; independent restore remains armed"
        fi
        OM_ASK_MS=$first_ask OM_ROUTE_MS=$first_route
        OM_SETTLED_MS=$first_settled OM_SETTLE_COVERED_MS=$first_covered
    fi
    # The provider followed the switch. v33 review: from its own lines since
    # the owner's prompt (the read above, that process only), a path change
    # and a re-pin to the new interface; a rebuild alone no longer passes
    # (window-v32-ifswitch-r3 passed on one rebuilt on the stale en0 pin).
    local d pc rp rb lost n codes detail
    d=$("$OM_PY" -I "$HARNESS_DIR/settle_judge.py" "$OUT/ifswitch_provider.log" "$OM_ASK_MS" "$OM_ROUTE_MS" 1 "$new" \
        2>/dev/null | head -n 1)
    pc=$(om_kv "$d" path_change) rp=$(om_kv "$d" repinned) rb=$(om_kv "$d" rebuilt) lost=$(om_kv "$d" lost)
    pc=${pc:-0} rp=${rp:-0} rb=${rb:-0}
    if [ "$pc" -ge 1 ] && [ "$rp" -ge 1 ]; then
        result ifswitch_relay_path_exercised pass "path_change=$pc repinned_to_$new=$rp rebuilt=$rb"
    else
        result ifswitch_relay_path_exercised fail "path_change=$pc repinned_to_$new=$rp rebuilt=$rb: the provider recorded no path change or no re-pin to $new"
    fi
    # v33 review: every session the provider lost since the prompt was
    # sealed by such a re-pin (relay_path_changed), and one was. Any other
    # loss (r3's capture_lease_expired) is an outage the gate would wait out
    # before the probes, so it fails here, whenever it came.
    if [ -z "$lost" ] || [ "$(om_kv "$d" lines)" = 0 ]; then
        result ifswitch_session_lost_by_repin unavailable "no provider log lines"
    else
        n=${lost%%:*} codes=${lost#*:}
        detail="count=$n codes=$codes rebuilt_after=$(om_s "$(om_kv "$d" rebuilt_after)")"
        if [ "$codes" = relay_path_changed ]; then
            result ifswitch_session_lost_by_repin pass "$detail"
        elif [ "$n" = 0 ]; then
            result ifswitch_session_lost_by_repin fail "$detail: no session_lost relay_path_changed, so no session was sealed by a re-pin"
        else
            result ifswitch_session_lost_by_repin fail "$detail: a session_lost other than the re-pin's relay_path_changed"
        fi
    fi
    # v33: a loss the provider logged after the gate released the probes
    # (from the read above, that process only), shown next to them. v33
    # review: counted from the newest line the releasing read held, so a
    # loss logged while the judge and om_up ran is not missed.
    if [ -n "$OM_SETTLED_MS" ]; then
        d=$("$OM_PY" -I "$HARNESS_DIR/settle_judge.py" "$OUT/ifswitch_provider.log" "$OM_SETTLE_COVERED_MS" \
            "$OM_SETTLE_COVERED_MS" 1 2>/dev/null | head -n 1)
        lost=$(om_kv "$d" lost)
        if [ -n "$lost" ] && [ "$(om_kv "$d" lines)" != 0 ]; then
            result ifswitch_session_lost_after_settle info "count=${lost%%:*} codes=${lost#*:}"
        else
            result ifswitch_session_lost_after_settle unavailable "no provider log lines"
        fi
    fi
}

om_window() {
    if [ "$SLEEP" = 1 ]; then om_sleep_window
    elif [ "$IFSWITCH" = 1 ]; then om_ifswitch_window
    fi
    return 0
}

om_global_v6() { ifconfig "$1" 2>/dev/null | awk '$1=="inet6" && $2!~/^fe80/ {n++} END{print n+0}'; }

# Right before the disconnect: whether the second capture is still alive,
# and, after a switch, the interface the default route must come back on.
# When neither the baseline IPv6 interface nor the new one holds a global
# IPv6 address now (an unplug onto a Wi-Fi without IPv6), no IPv6 default
# is the expected state after the disconnect.
om_before_disconnect() {
    [ -n "$CAP2_PID" ] && alive "$CAP2_PID" && CAP2_ALIVE=1
    # v31 review: DISCONNECT_AT was taken before leak_window_disconnect_at.
    [ -n "$CAP2_FILE" ] && result_since "${DISCONNECT_FROM:-$RESULT_FROM}" ifswitch_leak_window_disconnect_at "${DISCONNECT_AT:-none}" "capture_alive=$CAP2_ALIVE"
    OM_PHYS0=$PHYS
    if [ -n "$OM_EXPECT_PHYS" ]; then
        PHYS=$OM_EXPECT_PHYS OM_DEF6_ALT=$OM_EXPECT_PHYS
        if [ -n "$PHYS_DEF6" ] && [ "$(om_global_v6 "$PHYS_DEF6")" = 0 ] && [ "$(om_global_v6 "$OM_EXPECT_PHYS")" = 0 ]; then
            OM_DEF6_NONE_OK=1
        fi
    fi
    return 0
}
om_after_gate() { PHYS=$OM_PHYS0; }
# The IPv6 default after the disconnect: the baseline or, after a switch,
# the new interface, or none when neither has a global IPv6 address.
om_v6_back() {
    [ "$1" = "$PHYS_DEF6" ] || { [ -n "$OM_DEF6_ALT" ] && [ "$1" = "$OM_DEF6_ALT" ]; } \
        || { [ "$OM_DEF6_NONE_OK" = 1 ] && [ -z "$1" ]; }
}

# The second capture's review, as the first: leak_review pass, alive at the
# disconnect, stopped afterwards and no kernel drop.
om_leak_review2() {
    [ -n "$CAP2_FILE" ] || return 0
    local dev=$IFSWITCH_TO lr drops lp mac a b args
    om_stop_capture2
    # S20e: MS_ARGS, the window's Mac-sent identities, as for every review.
    # S20f: ARMED_ARGS, the window's armed span, as for every review.
    args=(--pcap "$OUT/$CAP2_FILE" --relay-ip "$RELAY_IP" --relay-port "$RELAY_PORT" --relay-proto "$PIN_RELAY_PROTOS"
          --out "$OUT/leak-review-$dev.json" ${MS_ARGS[@]+"${MS_ARGS[@]}"} ${ARMED_ARGS[@]+"${ARMED_ARGS[@]}"}
          ${PIN_REVIEW_ARGS[@]+"${PIN_REVIEW_ARGS[@]}"})
    mac=$(ifconfig "$dev" 2>/dev/null | awk '$1=="ether"{print $2; exit}')
    [ -n "$mac" ] && args+=(--local-mac "$mac")
    [ -n "$CONNECTED_AT" ] && args+=(--connected-at "$CONNECTED_AT" --disconnect-at "$DISCONNECT_AT")
    for a in $OM_BASE_ADDRS2 $(om_addrs "$dev"); do args+=(--local-addr "$a"); done
    for b in $(ifconfig "$dev" 2>/dev/null | awk '$1=="inet"{for(i=1;i<NF;i++) if($i=="broadcast") print $(i+1)}'); do args+=(--broadcast "$b"); done
    # S20d: without the summary's mac_sent_* suffix, as before it existed.
    lr=$(strict_line "$(python3 -I "$HARNESS_DIR/leak_review.py" "${args[@]}" 2>&1 | tail -1)")
    drops=$(sed -n 's/^\([0-9][0-9]*\) packets\{0,1\} dropped by kernel$/\1/p' "$OUT/tcpdump-$dev.stderr" | tail -1)
    lp=fail
    echo "$lr" | grep -q '^leak_review pass=true ' && [ "$CAP2_ALIVE" = 1 ] && [ "$CAP2_STOPPED" = 1 ] && [ "$drops" = 0 ] && lp=pass
    result ifswitch_leak_proof "$lp" "if=$dev $lr capture_alive=$CAP2_ALIVE capture_stopped=$CAP2_STOPPED kernel_drops=${drops:-unknown}"
    result ifswitch_leak_capture_sha256 "$(shasum -a 256 "$OUT/$CAP2_FILE" 2>/dev/null | awk '{print $1}')" "$CAP2_FILE not for retained evidence"
}
