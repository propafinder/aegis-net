#!/bin/bash
# B-06 S16c: one self-contained, bounded installed window for the activated
# PacketTunnel provider (S16, reusable for S17-S20). Owner-attended only: it
# connects the one saved AEGIS profile, runs bounded probes through the
# tunnel against the fixture relay, disconnects and verifies the physical
# default route is back. It never saves or removes a profile, never imports
# an identity and never elevates privileges.
#
# Safety order: refuse unless every precondition holds; take the timing lock;
# arm a rollback outside the harness process tree (reparented to launchd, own
# session, ignores INT/TERM/HUP/QUIT; scutil --nc stop, then --emergency-stop,
# at min(arm + N s, start + hard timeout)) and confirm it before --connect.
# The EXIT/INT/TERM/HUP trap stops the tunnel; a disconnect counts as verified
# only when scutil reports Disconnected on two polls in a row with the default
# route physical and no tunnel address. Only then is the rollback cancelled
# (through a token file, never a signal) and the timing lock released;
# otherwise both stay and the rollback releases the lock after it observes
# Disconnected. A watchdog sends TERM so a short stop sequence and the receipt
# still fit inside the hard timeout, then KILL at the hard timeout itself.
# Every run, refused or failed included, keeps a uniquely named directory with
# its receipt (a provisional one is written before --connect).
set -uo pipefail
umask 077
export LC_ALL=C

PROVIDER_ID=dev.aegis.macos.PacketTunnel
PROVIDER_EXE=aegis-ne-provider
TEAM=TEAMID0000
APP=/Applications/AEGIS.app
RELAY=192.168.1.107:443
ROLLBACK_SECS=90
HARD_SECS=120
# The watchdog's TERM leaves this much of the hard timeout for cleanup.
RESERVE=15
# Commands never run into the last FLOOR seconds: they are kept for the
# rollback cancel, the lock and the receipt.
FLOOR=4
CONNECT_WAIT=20
DISCONNECT_WAIT=5
MODE=window
DRY_RUN=0
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
SELF="$HERE/$(basename -- "$0")"
ARTIFACTS="$HERE/artifacts"
COORD="$HOME/.aegis-local/locks"
CODEX_LOCK="$COORD/timing-peer"
OWN_LOCK="$COORD/timing-self"
PURPOSE='B-06 S16 installed NetworkExtension window (harness/installed-run.sh)'
TUN_V4=198.19.255.1
DNS_V4=198.19.255.2
DNS_V6=fd00:ae61::2
ECHO_V4=192.0.2.10
ECHO_V6=2001:db8::10
ECHO_PORT=7
PROBE=probe.test
PROBE_TXT='"aegis-b06-probe"'
PAYLOAD=ping
DIG_OPTS=(+short +time=2 +tries=1)

usage() {
    cat >&2 <<'EOF'
usage: installed-run.sh [--relay IPV4:PORT] [--rollback-seconds N]
                        [--hard-timeout N] [--app ABS_APP] [--artifacts-dir ABS]
                        [--checks-only] [--dry-run]
  --relay IPV4:PORT        fixture relay bind address (default 192.168.1.107:443)
  --rollback-seconds N     detached rollback delay, 1..90 (default 90); it
                           never fires later than the hard timeout
  --hard-timeout N         whole-run bound, 20..120 (default 120)
  --app ABS_APP            installed app (default /Applications/AEGIS.app)
  --artifacts-dir ABS      receipts and logs (default harness/artifacts)
  --checks-only            only the in-tunnel checks while already connected:
                           no connect, disconnect or rollback
  --dry-run                print every command and run nothing
Exit: 0 pass, 1 check/connect failure, 2 usage, 3 precondition refused,
4 timing-peer lock present, 5 hard timeout, 6 disconnect not verified
(rollback and timing-self lock left in place), 129/130/143 interrupted.
EOF
    exit 2
}
die_usage() { echo "installed-run: $*" >&2; usage; }
quote() { local out='' arg; for arg in "$@"; do out="$out $(printf '%q' "$arg")"; done; printf '%s\n' "${out# }"; }
utc() { date -u +%Y%m%dT%H%M%SZ; }
# Whole decimal in [lo, hi], no sign or leading zero; never more digits than
# hi, so test(1) never sees an overflowing number.
in_range() {
    case "$1" in ''|0*|*[!0-9]*) return 1 ;; esac
    [ "${#1}" -le "${#3}" ] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}
octet() { case "$1" in 0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) return 0 ;; esac; return 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --relay) [ "$#" -ge 2 ] || die_usage '--relay needs a value'; RELAY=$2; shift 2 ;;
        --rollback-seconds) [ "$#" -ge 2 ] || die_usage '--rollback-seconds needs a value'; ROLLBACK_SECS=$2; shift 2 ;;
        --hard-timeout) [ "$#" -ge 2 ] || die_usage '--hard-timeout needs a value'; HARD_SECS=$2; shift 2 ;;
        --app) [ "$#" -ge 2 ] || die_usage '--app needs a value'; APP=$2; shift 2 ;;
        --artifacts-dir) [ "$#" -ge 2 ] || die_usage '--artifacts-dir needs a value'; ARTIFACTS=$2; shift 2 ;;
        --checks-only) MODE=checks-only; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) die_usage "unknown argument: $1" ;;
    esac
done
in_range "$ROLLBACK_SECS" 1 90 || die_usage '--rollback-seconds must be 1..90'
in_range "$HARD_SECS" 20 120 || die_usage '--hard-timeout must be 20..120'
case "$APP" in /*.app) ;; *) die_usage '--app must be an absolute .app path' ;; esac
case "$ARTIFACTS" in /*) ;; *) die_usage '--artifacts-dir must be absolute' ;; esac
RELAY_IP=${RELAY%:*}
RELAY_PORT=${RELAY##*:}
IFS=. read -r o1 o2 o3 o4 extra <<<"$RELAY_IP"
{ [ "$RELAY" = "$RELAY_IP:$RELAY_PORT" ] && [ -z "${extra:-}" ] && octet "${o1:-}" && octet "${o2:-}" \
    && octet "${o3:-}" && octet "${o4:-}" && [ "$RELAY_IP" = "$o1.$o2.$o3.$o4" ] \
    && in_range "$RELAY_PORT" 1 65535; } || die_usage '--relay must be IPV4:PORT'
# Never a tunnel-reserved, loopback, unspecified or multicast/reserved relay.
if [ "$o1" = 0 ] || [ "$o1" = 127 ] || [ "$o1" -ge 224 ] \
    || { [ "$o1" = 198 ] && { [ "$o2" = 18 ] || [ "$o2" = 19 ]; }; }; then
    die_usage '--relay must be a usable unicast address outside the tunnel ranges'
fi
HOST="$APP/Contents/MacOS/aegis-ne-host"

if [ "$DRY_RUN" = 1 ]; then
    p() { printf '+ %s\n' "$(quote "$@")"; }
    echo "# dry run ($MODE): nothing below is executed; <SID>/<GEN> come from --list, <UTUN> from ifconfig"
    echo "# preconditions (refuse on any failure; each command bounded)"
    p test ! -e "$CODEX_LOCK"
    echo "#   no live rollback from an earlier run (rollback.log under $ARTIFACTS)"
    p test -d "$APP" -a -x "$HOST"
    p systemextensionsctl list; echo "#   need one '$TEAM ... $PROVIDER_ID (...) ... [activated enabled]' line"
    p "$HOST" --ping; echo '#   need report.identity_present=true and report.container_open.admitted=true'
    p "$HOST" --list; echo '#   need exactly one profile: UUID service id and owner generation, intent_valid=true, on_demand_enabled=false'
    p scutil --nc list; echo '#   must list <SID>'
    p nc -z -w2 "$RELAY_IP" "$RELAY_PORT"
    if [ "$MODE" = window ]; then
        p scutil --nc status '<SID>'; echo '#   need Disconnected'
        p route -n get default; echo '#   physical interface, not utun'
        p ifconfig; echo "#   no interface holds $TUN_V4"
    else
        p scutil --nc status '<SID>'; echo '#   need Connected'
    fi
    echo "# lock: create $OWN_LOCK exclusively (start time, purpose, run token); re-check $CODEX_LOCK"
    if [ "$MODE" = window ]; then
        echo "# provisional receipt (outcome in_progress), then the rollback: it forks, the launcher exits and the"
        echo "#   rollback calls setsid, so it is reparented to launchd and is outside the harness process tree;"
        echo "#   it ignores INT/TERM/HUP/QUIT and must be confirmed alive with ppid 1 and its own pgid before connect"
        p nohup perl -e '<rollback>' "$ROLLBACK_SECS" '<START+HARD>' '<SID>' "$HOST" '<RUN>/rollback.cancel' \
            "$OWN_LOCK" '<TOKEN>' "$TUN_V4" '<HARNESS_PID>'
        echo "#   fires at min(arm + ${ROLLBACK_SECS}s, start + ${HARD_SECS}s): scutil --nc stop <SID>; $HOST --emergency-stop;"
        echo "#   after it observes Disconnected twice with no $TUN_V4 address and the harness has exited,"
        echo "#   it removes $OWN_LOCK if the lock still holds this run's token"
        echo "#   cancelled only by writing the run token to <RUN>/rollback.cancel after a verified disconnect"
        echo "# watchdog: TERM at $((HARD_SECS - RESERVE))s (short stop sequence), KILL at ${HARD_SECS}s;"
        echo "#   after KILL it removes $OWN_LOCK only when no rollback was armed"
        p "$HOST" --connect "$PROVIDER_ID" '<GEN>' "$RELAY_IP"
        p scutil --nc status '<SID>'; echo "#   poll until Connected, at most ${CONNECT_WAIT}s"
    fi
    echo '# checks (each bounded at 5 s)'
    p ifconfig; echo "#   exactly one utun holds $TUN_V4"
    p route -n get default; echo '#   interface is <UTUN>'
    p nc -w2 "$ECHO_V4" "$ECHO_PORT"; echo "#   stdin '$PAYLOAD' (no newline), must echo exactly it"
    p nc -6 -w2 "$ECHO_V6" "$ECHO_PORT"; echo "#   stdin '$PAYLOAD'"
    p nc -u -w2 "$ECHO_V4" "$ECHO_PORT"; echo "#   stdin '$PAYLOAD'"
    p dig "${DIG_OPTS[@]}" "@$DNS_V4" "$PROBE" A; echo '#   one address in 198.18.0.0/15 (not a tunnel anchor)'
    p nc -w2 '<FAKE_IP>' "$ECHO_PORT"; echo "#   stdin '$PAYLOAD'"
    p dig "${DIG_OPTS[@]}" "@$DNS_V4" "$PROBE" TXT
    p dig -6 "${DIG_OPTS[@]}" "@$DNS_V6" "$PROBE" AAAA; echo "#   $ECHO_V6"
    p dig +tcp "${DIG_OPTS[@]}" "@$DNS_V4" "$PROBE" TXT
    p scutil --dns; echo "#   a nameserver is $DNS_V4"
    p pgrep -x "$PROVIDER_EXE"
    p lsof -nP -a -p '<PROVIDER_PID>' -i; echo "#   ->$RELAY (ESTABLISHED); a failed lsof is recorded as unavailable"
    if [ "$MODE" = window ]; then
        echo '# disconnect, then verify within 5 s: scutil --nc status Disconnected on two polls in a row,'
        echo '#   default route on the physical interface, no interface with the tunnel address'
        p "$HOST" --disconnect "$PROVIDER_ID" '<GEN>' "$RELAY_IP"
        p scutil --nc status '<SID>'
        p route -n get default
        p ifconfig
        echo '#   a failed --disconnect or an unverified state escalates: scutil --nc stop <SID>, verify,'
        echo '#   then --emergency-stop, verify (shorter bounds after the watchdog TERM)'
        p scutil --nc stop '<SID>'
        p "$HOST" --emergency-stop
        echo '#   unverified: the rollback stays armed and the lock stays, annotated, for the rollback to release'
    fi
    echo "# cancel the rollback, release the lock, write the receipt under $ARTIFACTS"
    exit 0
fi

SECONDS=0
START_EPOCH=$(date +%s)
STARTED=$(utc)
mkdir -p "$ARTIFACTS" || { echo "installed-run: cannot create $ARTIFACTS" >&2; exit 3; }
RUN="$ARTIFACTS/s16-window-$STARTED-$MODE"
n=1
until mkdir "$RUN" 2>/dev/null; do
    RUN="$ARTIFACTS/s16-window-$STARTED-$MODE.$n"; n=$((n + 1))
    [ "$n" -lt 100 ] || { echo 'installed-run: no fresh run directory' >&2; exit 3; }
done
mkdir "$RUN/steps"
EVENTS="$RUN/events.tsv" FIELDS="$RUN/fields.tsv" ROLLBACK_LOG="$RUN/rollback.log"
PAYLOAD_FILE="$RUN/payload"
printf '%s' "$PAYLOAD" >"$PAYLOAD_FILE"
: >"$EVENTS"; : >"$FIELDS"; : >"$RUN/commands.log"
TOKEN="owner=claude pid=$$ run=$(basename -- "$RUN")"
OUTCOME=error EXIT_CODE=1 CHILD='' STEPN=0 EVSEQ=0 RC=0 OUT='' ERR=''
CONNECT_ATTEMPTED=0 DISCONNECT_DONE=0 DISCONNECT_VERIFIED=0 LOCK_CREATED=0
ROLLBACK_LAUNCHED=0 ROLLBACK_PID='' FIRE_AT='' WATCHDOG_PID='' SID='' GEN='' PHYS_IFACE=''
UTUN='' FAKE_IP='' BUDGET=0 TUNS='' IFACE=''
PASSED=0 FAILED=0 UNAVAILABLE=0

clean() { local s=${1//$'\t'/ }; s=${s//$'\n'/ }; s=${s//$'\r'/ }; CLEAN=${s:0:400}; }
event() {
    EVSEQ=$((EVSEQ + 1)); clean "${4:-}"
    printf '%d\t%s\t%s\t%s\t%s\t%s\n' "$EVSEQ" "$(utc)" "$1" "$2" "$3" "$CLEAN" >>"$EVENTS"
}
field() { clean "$2"; printf '%s\t%s\n' "$1" "$CLEAN" >>"$FIELDS"; }
first_line() { head -n 1 "$1" 2>/dev/null | tr -d '\r'; }

# Whole seconds still usable for commands: the hard timeout minus the FLOOR
# kept for the rollback cancel, the lock and the receipt.
budget_left() { BUDGET=$((HARD_SECS - SECONDS - FLOOR)); [ "$BUDGET" -ge 1 ]; }

# step SECS NAME CMD...: one bounded command in the background, so a signal
# interrupts the wait at once. stdout/stderr go to $OUT/$ERR; RC is the exit
# (142 = alarm, 124 = no budget left). The bound never runs into the FLOOR.
step() {
    local secs=$1 name=$2
    shift 2
    budget_left
    [ "$secs" -le "$BUDGET" ] || secs=$BUDGET
    STEPN=$((STEPN + 1))
    printf -v OUT '%s/steps/%02d-%s.out' "$RUN" "$STEPN" "$name"
    ERR=${OUT%.out}.err
    if [ "$secs" -lt 1 ]; then
        RC=124; : >"$OUT"; echo budget_exhausted >"$ERR"; return 0
    fi
    printf '%s %ss %s\n' "$(utc)" "$secs" "$(quote "$@")" >>"$RUN/commands.log"
    perl -e 'alarm shift; exec { $ARGV[0] } @ARGV; print STDERR "exec: $!\n"; exit 127' \
        "$secs" "$@" <"${STDIN_FILE:-/dev/null}" >"$OUT" 2>"$ERR" &
    CHILD=$!
    wait "$CHILD"
    RC=$?
    CHILD=''
}

refuse() {
    event precondition "$1" fail "$2"
    echo "installed-run: refused: $1: $2" >&2
    OUTCOME=${3:-refused} EXIT_CODE=${4:-3}
    exit "$EXIT_CODE"
}
admit() { event precondition "$1" pass "${2:-}"; }
codex_lock_present() { [ -e "$CODEX_LOCK" ] || [ -L "$CODEX_LOCK" ]; }
# Rollbacks of earlier runs that are still alive and neither cancelled nor
# done: a new window must not start while one may still stop the service.
pending_rollbacks() {
    local log pid
    PENDING=''
    for log in "$ARTIFACTS"/s16-window-*/rollback.log; do
        [ -f "$log" ] && [ "$log" != "$ROLLBACK_LOG" ] || continue
        grep -qE '^rollback_(cancelled|done)$' "$log" && continue
        pid=$(sed -n 's/^rollback_armed pid=\([0-9][0-9]*\) .*/\1/p' "$log" | head -n 1)
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || continue
        case "$(ps -o comm= -p "$pid" 2>/dev/null)" in
            *perl*) PENDING="$PENDING $pid:$(basename -- "$(dirname -- "$log")")" ;;
        esac
    done
    PENDING=${PENDING# }
}

default_iface() {
    step 5 route-default route -n get default
    IFACE=$(awk '$1 == "interface:" { print $2; exit }' "$OUT")
}
# Every interface that holds the tunnel IPv4 address.
tunnel_ifaces() {
    step 5 ifconfig ifconfig
    TUNS=$(awk -v ip="$TUN_V4" '/^[^ \t]/ { name = $1; sub(/:$/, "", name) } $1 == "inet" && $2 == ip { print name }' "$OUT" | tr '\n' ' ')
    TUNS=${TUNS% }
}
nc_state() {
    step 5 nc-status scutil --nc status "$SID"
    NC_STATE=$(first_line "$OUT")
    [ "$RC" = 0 ] || NC_STATE="error_rc_$RC"
}

preconditions() {
    codex_lock_present && refuse timing_codex_lock_absent "$CODEX_LOCK exists" refused_timing_codex 4
    admit timing_codex_lock_absent
    pending_rollbacks
    [ -z "$PENDING" ] || refuse no_pending_rollback "live rollback from an earlier run: $PENDING"
    admit no_pending_rollback
    [ -d "$APP" ] && [ ! -L "$APP" ] && [ -f "$HOST" ] && [ -x "$HOST" ] || refuse app_installed "$HOST missing"
    admit app_installed "$APP"
    field host_sha256 "$(shasum -a 256 "$HOST" 2>/dev/null | awk '{print $1}')"
    field app_bundle_version "$(plutil -extract CFBundleVersion raw -o - "$APP/Contents/Info.plist" 2>/dev/null || echo unavailable)"

    step 10 sysext systemextensionsctl list
    local active
    active=$(grep -F "$TEAM" "$OUT" | grep -F "$PROVIDER_ID (" | grep -cF '[activated enabled]')
    [ "$RC" = 0 ] && [ "$active" = 1 ] || refuse system_extension_activated "rc=$RC activated_enabled_lines=$active"
    admit system_extension_activated "$(grep -F "$PROVIDER_ID (" "$OUT" | grep -F '[activated enabled]')"

    step 15 ping "$HOST" --ping
    [ "$RC" = 0 ] || refuse provider_ping "rc=$RC $(first_line "$ERR")"
    local ping
    ping=$(python3 -I -B -c '
import json, sys
lines = [line for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
try:
    value = json.loads(lines[0]) if len(lines) == 1 else None
except ValueError:
    value = None
report = value.get("report") if isinstance(value, dict) and value.get("verb") == "ping" else None
if not isinstance(report, dict):
    print("malformed")
    raise SystemExit
opened = report.get("container_open")
admitted = isinstance(opened, dict) and opened.get("admitted") is True
print("identity_present=%s container_admitted=%s session_phase=%s" % (
    "true" if report.get("identity_present") is True else "false",
    "true" if admitted else "false", str(report.get("session_phase"))[:32]))
' "$OUT" 2>/dev/null)
    case "$ping" in
        "identity_present=true container_admitted=true "*) admit provider_ping "$ping" ;;
        *) refuse provider_ping "${ping:-unparsed}" ;;
    esac

    step 35 list "$HOST" --list
    [ "$RC" = 0 ] || refuse single_profile "rc=$RC $(first_line "$ERR")"
    local count line re
    count=$(grep -c '^profile ' "$OUT")
    grep -qx 'profiles=1 native_acceptance=false' "$OUT" && [ "$count" = 1 ] \
        || refuse single_profile "profile_lines=$count"
    line=$(grep '^profile ' "$OUT")
    re='^profile index=0 owner_generation=([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}) scutil_service_id=([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}) intent_valid=(true|false) enabled=(true|false) on_demand_enabled=(true|false) native_vpn_status=([0-9]{1,3})$'
    [[ "$line" =~ $re ]] || refuse single_profile "profile line has no owner generation and service id"
    GEN=${BASH_REMATCH[1]} SID=${BASH_REMATCH[2]}
    [ "${BASH_REMATCH[3]}" = true ] || refuse single_profile 'intent_valid=false'
    # On-demand could restart the tunnel after every stop.
    [ "${BASH_REMATCH[5]}" = false ] || refuse single_profile 'on_demand_enabled=true'
    field service_id "$SID"; field owner_generation "$GEN"
    admit single_profile "service_id=$SID enabled=${BASH_REMATCH[4]} native_vpn_status=${BASH_REMATCH[6]}"

    step 10 nc-list scutil --nc list
    [ "$RC" = 0 ] && grep -qF "$SID" "$OUT" || refuse scutil_service_listed "rc=$RC"
    admit scutil_service_listed

    step 5 relay-probe nc -z -w2 "$RELAY_IP" "$RELAY_PORT"
    [ "$RC" = 0 ] || refuse relay_listening "rc=$RC $RELAY"
    admit relay_listening "$RELAY"

    nc_state
    if [ "$MODE" = window ]; then
        [ "$NC_STATE" = Disconnected ] || refuse tunnel_disconnected "status=$NC_STATE"
        admit tunnel_disconnected
        default_iface
        [ "$RC" = 0 ] && [ -n "$IFACE" ] || refuse physical_default_route "rc=$RC no default interface"
        case "$IFACE" in utun*|ipsec*|ppp*) refuse physical_default_route "default interface $IFACE" ;; esac
        tunnel_ifaces
        [ "$RC" = 0 ] && [ -z "$TUNS" ] || refuse physical_default_route "rc=$RC tunnel address on ${TUNS:-unknown}"
        PHYS_IFACE=$IFACE
        field physical_interface "$PHYS_IFACE"
        admit physical_default_route "interface=$PHYS_IFACE"
    else
        [ "$NC_STATE" = Connected ] || refuse tunnel_connected "status=$NC_STATE"
        admit tunnel_connected
    fi

    mkdir -p "$COORD" || refuse timing_lock_created "cannot create $COORD"
    if (set -o noclobber; printf 'started=%s\npurpose=%s\n%s\n' "$(utc)" "$PURPOSE" "$TOKEN" >"$OWN_LOCK") 2>/dev/null; then
        LOCK_CREATED=1
    else
        refuse timing_lock_created "$OWN_LOCK already exists"
    fi
    field lock_path "$OWN_LOCK"
    admit timing_lock_created "$OWN_LOCK"
    # Both agents may take their locks at once; the later one must yield.
    codex_lock_present && refuse timing_codex_lock_absent_after_lock "$CODEX_LOCK appeared" refused_timing_codex 4
    admit timing_codex_lock_absent_after_lock
}

# The rollback. The launcher forks and exits at once, and the child calls
# setsid, so the rollback is reparented to launchd: no process-group signal
# and no walk over the harness's descendants reaches it. It ignores INT, TERM,
# HUP and QUIT; it is cancelled only by the run token in its cancel file. It
# fires at min(arm + N s, start + hard timeout), runs scutil --nc stop and
# --emergency-stop (35 s each), then releases the timing lock only after it
# observes Disconnected on two polls in a row with no tunnel address and the
# harness has exited. Its commands get default signal dispositions back.
ROLLBACK_PERL='
use strict; use warnings; use POSIX (); use Time::HiRes ();
my ($secs, $deadline, $sid, $host, $cancel, $lock, $token, $tun, $harness) = @ARGV;
my @held = qw(INT TERM HUP QUIT PIPE);
$SIG{$_} = "IGNORE" for @held;
defined(my $child = fork) or die "rollback fork: $!\n";
POSIX::_exit(0) if $child;
my $session = POSIX::setsid();
die "rollback setsid: $!\n" unless defined $session && $session > 0;
$| = 1;
my $fire = time + $secs;
$fire = $deadline if $deadline < $fire;
sub run {
    my ($limit, @cmd) = @_;
    my $pid = open(my $fh, "-|");
    return (-1, "") unless defined $pid;
    if (!$pid) {
        $SIG{$_} = "DEFAULT" for @held;
        open STDIN, "<", "/dev/null"; open STDERR, ">", "/dev/null";
        alarm $limit;
        exec { $cmd[0] } @cmd or POSIX::_exit(127);
    }
    local $/; my $out = <$fh>; close $fh;
    return ($?, defined $out ? $out : "");
}
sub cancelled {
    open(my $fh, "<", $cancel) or return 0;
    local $/; my $text = <$fh>; close $fh;
    return defined $text && $text eq "$token\n";
}
sub harness_gone {
    return 1 unless kill 0, $harness;
    my (undef, $stat) = run(2, "ps", "-o", "stat=", "-p", $harness);
    return $stat =~ /^\s*Z/ ? 1 : 0;
}
sub release_lock {
    my $until = $deadline + 10;
    Time::HiRes::sleep(0.3) until harness_gone() || time > $until;
    if (!harness_gone()) { print "rollback_lock_kept reason=harness_running\n"; return }
    if (-l $lock) { print "rollback_lock_kept reason=symlink\n"; return }
    if (!-e $lock) { print "rollback_lock_absent\n"; return }
    open(my $fh, "<", $lock) or do { print "rollback_lock_kept reason=unreadable\n"; return };
    local $/; my $text = <$fh>; close $fh;
    if (defined $text && $text =~ /^\Q$token\E$/m && unlink $lock) { print "rollback_lock_released\n" }
    else { print "rollback_lock_kept reason=not_ours\n" }
}
print "rollback_armed pid=$$ seconds=$secs fires_at_epoch=$fire\n";
while (1) {
    if (cancelled()) { print "rollback_cancelled\n"; release_lock(); exit 0 }
    last if time >= $fire;
    Time::HiRes::sleep(0.1);
}
print "rollback_fired\n";
for my $cmd (["scutil", "--nc", "stop", $sid], [$host, "--emergency-stop"]) {
    my ($status) = run(35, @$cmd);
    print "rollback_ran ", join(" ", @$cmd), " status=$status\n";
}
my ($streak, $ok, $until) = (0, 0, time + 10);
while (1) {
    my ($status, $out) = run(5, "scutil", "--nc", "status", $sid);
    my ($ifrc, $ifconfig) = run(5, "ifconfig");
    my ($first) = split /\n/, $out, 2;
    if ($status == 0 && defined $first && $first eq "Disconnected" && $ifrc == 0
        && $ifconfig !~ /^\s*inet \Q$tun\E\s/m) {
        if (++$streak >= 2) { $ok = 1; last }
    } else {
        $streak = 0;
    }
    last if $streak == 0 && time >= $until;
    Time::HiRes::sleep(0.5);
}
if ($ok) { print "rollback_observed status=Disconnected tunnel_address=absent\n"; release_lock() }
else { print "rollback_unverified\nrollback_lock_kept reason=unverified\n" }
print "rollback_done\n";
'
rollback_log_has() { grep -qE "$1" "$ROLLBACK_LOG" 2>/dev/null; }
# Alive and still able to act: neither cancelled nor done.
rollback_alive() {
    [ -n "$ROLLBACK_PID" ] && kill -0 "$ROLLBACK_PID" 2>/dev/null \
        && ! rollback_log_has '^rollback_(cancelled|done)$'
}
start_rollback() {
    local launcher i pid='' info=''
    ROLLBACK_LAUNCHED=1
    nohup perl -e "$ROLLBACK_PERL" "$ROLLBACK_SECS" "$((START_EPOCH + HARD_SECS))" "$SID" "$HOST" \
        "$RUN/rollback.cancel" "$OWN_LOCK" "$TOKEN" "$TUN_V4" "$$" </dev/null >>"$ROLLBACK_LOG" 2>&1 &
    launcher=$!
    # The launcher only forks the rollback and exits.
    wait "$launcher"
    for i in 1 2 3 4 5 6 7 8 9 10; do
        pid=$(sed -n 's/^rollback_armed pid=\([0-9][0-9]*\) .*/\1/p' "$ROLLBACK_LOG" | head -n 1)
        if [ -n "$pid" ] && [ "$pid" != "$launcher" ] && kill -0 "$pid" 2>/dev/null; then
            # Detached means reparented to launchd and leading its own group.
            info=$(ps -o ppid= -o pgid= -p "$pid" 2>/dev/null | awk '{ print $1, $2 }')
            if [ "$info" = "1 $pid" ]; then
                ROLLBACK_PID=$pid
                FIRE_AT=$(sed -n 's/^rollback_armed .* fires_at_epoch=\([0-9][0-9]*\)$/\1/p' "$ROLLBACK_LOG" | head -n 1)
                field rollback_pid "$ROLLBACK_PID"
                field rollback_fires_at_epoch "$FIRE_AT"
                event rollback armed pass "pid=$pid ppid=1 pgid=$pid seconds=$ROLLBACK_SECS fires_at_epoch=$FIRE_AT"
                return 0
            fi
        fi
        sleep 0.3
    done
    ROLLBACK_PID=$pid
    event rollback armed fail "pid=${pid:-none} ppid_pgid=${info:-none}: not confirmed detached"
    OUTCOME=rollback_not_armed EXIT_CODE=1
    exit 1
}
# Only after a verified disconnect (or before any connect): the run token in
# the cancel file stops a rollback that has not fired yet.
cancel_rollback() {
    [ "$ROLLBACK_LAUNCHED" = 1 ] || return 0
    printf '%s\n' "$TOKEN" >"$RUN/rollback.cancel"
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        rollback_alive || break
        sleep 0.1
    done
    if rollback_log_has '^rollback_fired$'; then
        event rollback fired info "the rollback ran its stop commands"
    fi
    if rollback_log_has '^rollback_cancelled$'; then
        event rollback cancelled pass "pid=$ROLLBACK_PID"
        field rollback_cancelled true
    elif rollback_alive; then
        # A fired rollback finishes its stops; only one that has not fired
        # and ignores its token is a failure.
        event rollback cancelled "$(rollback_log_has '^rollback_fired$' && echo info || echo fail)" \
            "pid=$ROLLBACK_PID still running; it keeps the lock until it observes Disconnected"
        field rollback_cancelled false
    else
        event rollback cancelled info "pid=${ROLLBACK_PID:-none} not running"
        field rollback_cancelled false
    fi
}

# The watchdog, a child of the harness, signals only while its parent is still
# the harness, so a dead harness (and a reused pid) is never signalled. After
# its KILL it removes the timing lock only when no rollback was ever armed and
# the lock still holds this run's token; an armed rollback owns the lock then.
WATCHDOG_PERL='
use strict; use warnings; use Time::HiRes ();
my ($soft, $reserve, $pid, $marker, $lock, $token, $rollback_log) = @ARGV;
$SIG{INT} = $SIG{HUP} = "IGNORE";
sub hold {
    my $until = Time::HiRes::time() + shift;
    while (Time::HiRes::time() < $until) { exit 0 if getppid() != $pid; Time::HiRes::sleep(0.2) }
}
sub note { if (open my $fh, ">>", $marker) { print $fh "@_\n"; close $fh } }
hold($soft);
exit 0 if getppid() != $pid;
note("hard_timeout term");
kill "TERM", $pid;
hold($reserve);
exit 0 if getppid() != $pid;
kill "KILL", $pid;
note("hard_timeout kill");
my $armed = 0;
if (open my $fh, "<", $rollback_log) {
    local $/; my $text = <$fh>; close $fh;
    $armed = defined $text && $text =~ /^rollback_armed /m;
}
if ($armed) {
    note("lock_left_to_rollback");
} elsif (!-l $lock && open my $fh, "<", $lock) {
    local $/; my $text = <$fh>; close $fh;
    unlink $lock if defined $text && $text =~ /^\Q$token\E$/m;
}
'

wait_connected() {
    local start=$SECONDS
    while :; do
        nc_state
        if [ "$NC_STATE" = Connected ]; then
            event connect connected pass "elapsed_s=$((SECONDS - start))"
            return 0
        fi
        [ $((SECONDS - start)) -lt "$CONNECT_WAIT" ] && budget_left || break
        sleep 0.5
    done
    event connect connected fail "status=$NC_STATE after ${CONNECT_WAIT}s"
    return 1
}

check() {
    event check "$1" "$2" "${3:-}"
    case "$2" in pass) PASSED=$((PASSED + 1)) ;; fail) FAILED=$((FAILED + 1)) ;; *) UNAVAILABLE=$((UNAVAILABLE + 1)) ;; esac
}
echo_check() {
    local name=$1 flag=$2 target=$3 args=(nc)
    [ -z "$flag" ] || args+=("$flag")
    args+=(-w2 "$target" "$ECHO_PORT")
    STDIN_FILE=$PAYLOAD_FILE step 5 "$name" "${args[@]}"
    if [ "$(cat "$OUT")" = "$PAYLOAD" ]; then
        check "$name" pass "target=$target rc=$RC"
    else
        check "$name" fail "target=$target rc=$RC bytes=$(wc -c <"$OUT" | tr -d ' ')"
    fi
}
# dig answers, without comments or blank lines.
dig_answers() {
    step 5 "$1" dig "${@:2}"
    ANSWERS=$(grep -v '^;' "$OUT" | sed '/^[[:space:]]*$/d')
    ANSWER_COUNT=$(printf '%s' "$ANSWERS" | grep -c '')
}
# A fake IPv4 from 198.18.0.0/15, never a tunnel interface or DNS anchor.
fake_v4() {
    local a b c d x
    IFS=. read -r a b c d x <<<"$1"
    [ -z "$x" ] && octet "${a:-}" && octet "${b:-}" && octet "${c:-}" && octet "${d:-}" \
        && [ "$1" = "$a.$b.$c.$d" ] && [ "$a" = 198 ] && { [ "$b" = 18 ] || [ "$b" = 19 ]; } \
        && [ "$1" != "$TUN_V4" ] && [ "$1" != "$DNS_V4" ]
}
one_answer() { # NAME EXPECTED
    if [ "$RC" = 0 ] && [ "$ANSWER_COUNT" = 1 ] && [ "$ANSWERS" = "$2" ]; then
        check "$1" pass "answer=$ANSWERS"
    else
        check "$1" fail "rc=$RC answers=$ANSWER_COUNT first=$(printf '%s' "$ANSWERS" | head -n 1)"
    fi
}

run_checks() {
    tunnel_ifaces
    UTUN=''
    if [ "$RC" = 0 ] && [[ "$TUNS" =~ ^utun[0-9]+$ ]]; then
        UTUN=$TUNS
        check utun_interface pass "interface=$UTUN address=$TUN_V4"
    else
        check utun_interface fail "rc=$RC interfaces=${TUNS:-none}"
    fi
    field tunnel_interface "${UTUN:-none}"
    default_iface
    if [ "$RC" = 0 ] && [ -n "$UTUN" ] && [ "$IFACE" = "$UTUN" ]; then
        check default_route_tunnel pass "interface=$IFACE"
    else
        check default_route_tunnel fail "rc=$RC interface=${IFACE:-none}"
    fi
    echo_check tcp4_echo '' "$ECHO_V4"
    echo_check tcp6_echo -6 "$ECHO_V6"
    echo_check udp4_echo -u "$ECHO_V4"

    dig_answers dns_a "${DIG_OPTS[@]}" "@$DNS_V4" "$PROBE" A
    FAKE_IP=''
    if [ "$RC" = 0 ] && [ "$ANSWER_COUNT" = 1 ] && fake_v4 "$ANSWERS"; then
        FAKE_IP=$ANSWERS
        check dns_a_fake_ip pass "answer=$FAKE_IP"
    else
        check dns_a_fake_ip fail "rc=$RC answers=$ANSWER_COUNT first=$(printf '%s' "$ANSWERS" | head -n 1)"
    fi
    if [ -n "$FAKE_IP" ]; then
        echo_check fake_ip_tcp_echo '' "$FAKE_IP"
    else
        check fake_ip_tcp_echo fail 'no fake IP answer'
    fi
    dig_answers dns_txt "${DIG_OPTS[@]}" "@$DNS_V4" "$PROBE" TXT
    one_answer dns_txt "$PROBE_TXT"
    dig_answers dns_aaaa_v6 -6 "${DIG_OPTS[@]}" "@$DNS_V6" "$PROBE" AAAA
    one_answer dns_aaaa_v6 "$ECHO_V6"
    dig_answers dns_tcp +tcp "${DIG_OPTS[@]}" "@$DNS_V4" "$PROBE" TXT
    one_answer dns_tcp "$PROBE_TXT"

    step 5 scutil-dns scutil --dns
    if [ "$RC" = 0 ] && grep -Eq "^[[:space:]]*nameserver\[[0-9]+\][[:space:]]*:[[:space:]]*${DNS_V4//./\\.}[[:space:]]*$" "$OUT"; then
        check dns_resolver pass "nameserver=$DNS_V4"
    else
        check dns_resolver fail "rc=$RC no nameserver $DNS_V4"
    fi

    # The provider runs as root, so lsof without privileges may see nothing:
    # that is recorded as unavailable, never retried with elevation.
    step 5 pgrep-provider pgrep -x "$PROVIDER_EXE"
    local pids pid_count
    pids=$(grep -E '^[0-9]+$' "$OUT")
    pid_count=$(printf '%s' "$pids" | grep -c '')
    if [ "$RC" = 0 ] && [ "$pid_count" = 1 ]; then
        step 5 lsof-provider lsof -nP -a -p "$pids" -i
        if [ "$RC" = 0 ] && grep -qF -- "->$RELAY (ESTABLISHED)" "$OUT"; then
            check relay_socket pass "provider_pid=$pids ->$RELAY"
        elif [ "$RC" = 0 ] && [ -s "$OUT" ]; then
            check relay_socket fail "provider_pid=$pids no established socket to $RELAY"
        else
            check relay_socket unavailable "lsof rc=$RC provider_pid=$pids"
        fi
    else
        check relay_socket unavailable "provider pids=$pid_count rc=$RC"
    fi
    field checks_passed "$PASSED"; field checks_failed "$FAILED"; field checks_unavailable "$UNAVAILABLE"
}

# verify_down LABEL WAIT: verified only when scutil reports Disconnected on two
# polls in a row and, on both, the default route is on the physical interface
# and no interface holds the tunnel address. A tunnel still Connecting has no
# routes yet, so the routes alone never count. A first clean poll always gets
# its confirming poll; polling stops when the budget is gone.
verify_down() {
    local start=$SECONDS streak=0 state=none iface=none route_rc=0 why=''
    TUNS=unknown
    while :; do
        if ! budget_left; then why=' budget_exhausted'; break; fi
        nc_state; state=$NC_STATE
        default_iface; iface=${IFACE:-none} route_rc=$RC
        tunnel_ifaces
        if [ "$state" = Disconnected ] && [ "$route_rc" = 0 ] && [ "$RC" = 0 ] && [ -n "$PHYS_IFACE" ] \
            && [ "$iface" = "$PHYS_IFACE" ] && [ -z "$TUNS" ]; then
            streak=$((streak + 1))
            if [ "$streak" -ge 2 ]; then
                DISCONNECT_VERIFIED=1
                event disconnect "verified_after_$1" pass \
                    "status=Disconnected polls=2 default_interface=$iface elapsed_s=$((SECONDS - start))"
                return 0
            fi
        else
            streak=0
        fi
        [ "$streak" = 1 ] || [ $((SECONDS - start)) -lt "$2" ] || break
        sleep 0.5
    done
    event disconnect "verified_after_$1" fail \
        "status=$state default_interface=$iface tunnel_interfaces=${TUNS:-none}$why"
    return 1
}
# The whole stop sequence; DISCONNECT_DONE only once it has run to the end,
# so a signal in the middle of it makes the trap run it again.
disconnect_and_verify() {
    stop_sequence
    DISCONNECT_DONE=1
    [ "$DISCONNECT_VERIFIED" = 1 ]
}
# Full bounds while the budget allows them; after the watchdog TERM, or when
# less is left, short bounds so all three stops are still attempted and the
# receipt is still written before the KILL.
stop_bounds() {
    if [ -e "$RUN/hard-timeout" ] || ! budget_left || [ "$BUDGET" -lt 50 ]; then
        STOP_MODE=short B_DISC=3 B_STOP=2 B_EMERG=2 B_VERIFY=1
    else
        STOP_MODE=full B_DISC=15 B_STOP=5 B_EMERG=15 B_VERIFY=$DISCONNECT_WAIT
    fi
}
# A failed stop command may never have reached the provider, so its rc alone
# escalates; after the last one only the observed state decides.
stop_sequence() {
    stop_bounds
    event disconnect stop_sequence info "bounds=$STOP_MODE budget_s=$BUDGET"
    step "$B_DISC" disconnect "$HOST" --disconnect "$PROVIDER_ID" "$GEN" "$RELAY_IP"
    if [ "$RC" = 0 ]; then
        event disconnect host_disconnect pass "rc=0 $(first_line "$OUT")"
        verify_down host_disconnect "$B_VERIFY" && return 0
    else
        event disconnect host_disconnect fail "rc=$RC $(first_line "$ERR")"
    fi
    step "$B_STOP" nc-stop scutil --nc stop "$SID"
    if [ "$RC" = 0 ]; then
        event disconnect scutil_stop pass "rc=0"
        verify_down scutil_stop "$B_VERIFY" && return 0
    else
        event disconnect scutil_stop fail "rc=$RC"
    fi
    step "$B_EMERG" emergency-stop "$HOST" --emergency-stop
    event disconnect emergency_stop "$([ "$RC" = 0 ] && echo pass || echo fail)" "rc=$RC"
    verify_down emergency_stop "$B_VERIFY"
}

RECEIPT_PY='
import json, os, sys
run = sys.argv[1]
ints = {"exit_code", "rollback_seconds", "hard_timeout_seconds", "rollback_pid",
        "rollback_fires_at_epoch",
        "elapsed_seconds", "checks_passed", "checks_failed", "checks_unavailable", "steps"}
fields = {}
with open(os.path.join(run, "fields.tsv"), encoding="utf-8", errors="replace") as handle:
    for line in handle:
        key, _, value = line.rstrip("\n").partition("\t")
        if key in ints and value.isdigit():
            value = int(value)
        elif value in ("true", "false"):
            value = value == "true"
        fields[key] = value
events = []
with open(os.path.join(run, "events.tsv"), encoding="utf-8", errors="replace") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t", 5)
        if len(parts) == 6:
            seq, at, kind, name, status, detail = parts
            events.append({"seq": int(seq), "utc": at, "kind": kind, "name": name,
                           "status": status, "detail": detail})
def of(kind):
    return [{k: e[k] for k in ("seq", "name", "status", "detail")} for e in events if e["kind"] == kind]
receipt = {"schema": "aegis-b06-installed-window-receipt-v1", "work_item": "S16c-window-harness"}
receipt.update(fields)
receipt.update({"preconditions": of("precondition"), "checks": of("check"),
                "connect": of("connect"), "disconnect": of("disconnect"),
                "rollback": of("rollback"), "events": events, "run_dir": run})
path = os.path.join(run, "receipt.json")
temp = path + ".tmp"
try:
    os.unlink(temp)
except FileNotFoundError:
    pass
with open(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(temp, path)
'

remove_lock() {
    if [ ! -L "$OWN_LOCK" ] && grep -qxF "$TOKEN" "$OWN_LOCK" 2>/dev/null && rm -f "$OWN_LOCK"; then
        field lock_removed true
        field lock_released_by harness
    elif [ ! -e "$OWN_LOCK" ] && [ ! -L "$OWN_LOCK" ] && rollback_log_has '^rollback_lock_released$'; then
        field lock_removed true
        field lock_released_by rollback
    else
        field lock_removed false
        event lock removed fail "$OWN_LOCK not ours or not removable"
    fi
}
# keep_lock REASON RELEASE: the lock stays, annotated, while the tunnel state
# is unverified or a rollback may still act.
keep_lock() {
    field lock_removed false
    field lock_kept_reason "$1"
    if [ ! -L "$OWN_LOCK" ] && grep -qxF "$TOKEN" "$OWN_LOCK" 2>/dev/null; then
        printf 'kept=%s rollback_pid=%s rollback_fires_at_epoch=%s release=%s\n' \
            "$1" "${ROLLBACK_PID:-none}" "${FIRE_AT:-none}" "$2" >>"$OWN_LOCK"
        event lock kept info "$1: $2"
        echo "installed-run: $OWN_LOCK kept ($1): $2" >&2
    elif rollback_log_has '^rollback_lock_released$'; then
        event lock kept info "$1: already released by the rollback"
    else
        event lock kept fail "$1: $OWN_LOCK not ours"
    fi
}
finish_lock() {
    [ "$LOCK_CREATED" = 1 ] || return 0
    if [ "$CONNECT_ATTEMPTED" = 1 ] && [ "$DISCONNECT_VERIFIED" != 1 ]; then
        if rollback_alive; then
            keep_lock rollback_pending 'the rollback removes it after it observes Disconnected'
        else
            keep_lock disconnect_unverified 'remove it by hand only after scutil --nc status shows Disconnected'
        fi
    elif rollback_alive; then
        keep_lock rollback_running 'the rollback removes it after it observes Disconnected'
    else
        remove_lock
    fi
}
write_receipt() { python3 -I -B -c "$RECEIPT_PY" "$RUN"; }

cleanup() {
    trap '' INT TERM HUP
    if [ -n "$CHILD" ]; then
        kill -TERM "$CHILD" 2>/dev/null
        wait "$CHILD" 2>/dev/null
        CHILD=''
    fi
    if [ "$CONNECT_ATTEMPTED" = 1 ] && [ "$DISCONNECT_DONE" = 0 ] && [ "$DISCONNECT_VERIFIED" = 0 ]; then
        event cleanup stop_tunnel info "outcome=$OUTCOME"
        disconnect_and_verify
    fi
    if [ "$CONNECT_ATTEMPTED" = 0 ] || [ "$DISCONNECT_VERIFIED" = 1 ]; then
        cancel_rollback
    else
        if rollback_alive; then
            event rollback kept pass "pid=$ROLLBACK_PID stays armed (fires_at_epoch=$FIRE_AT): disconnect not verified"
        else
            event rollback kept fail "pid=${ROLLBACK_PID:-none} is not running: disconnect not verified and no rollback pending"
        fi
        field rollback_cancelled false
        [ "$OUTCOME" = disconnect_unverified ] || field outcome_before_disconnect "$OUTCOME"
        OUTCOME=disconnect_unverified EXIT_CODE=6
    fi
    [ "$CONNECT_ATTEMPTED" = 0 ] || field disconnect_verified "$([ "$DISCONNECT_VERIFIED" = 1 ] && echo true || echo false)"
    finish_lock
    if [ -n "$WATCHDOG_PID" ]; then
        kill -TERM "$WATCHDOG_PID" 2>/dev/null
        wait "$WATCHDOG_PID" 2>/dev/null
    fi
    field outcome "$OUTCOME"
    field exit_code "$EXIT_CODE"
    field elapsed_seconds "$SECONDS"
    field steps "$STEPN"
    field finished_utc "$(utc)"
    if write_receipt; then
        echo "receipt=$RUN/receipt.json"
    else
        echo "installed-run: receipt not written; raw records in $RUN" >&2
    fi
    echo "outcome=$OUTCOME exit=$EXIT_CODE"
    exit "$EXIT_CODE"
}
on_signal() {
    if [ -e "$RUN/hard-timeout" ]; then
        OUTCOME=hard_timeout EXIT_CODE=5
    else
        OUTCOME=interrupted EXIT_CODE=$2
    fi
    event signal "$1" fail "$OUTCOME"
    exit "$EXIT_CODE"
}

field mode "$MODE"
field started_utc "$STARTED"
field harness_sha256 "$(shasum -a 256 "$SELF" | awk '{print $1}')"
field app "$APP"
field provider_id "$PROVIDER_ID"
field relay "$RELAY"
field rollback_seconds "$ROLLBACK_SECS"
field hard_timeout_seconds "$HARD_SECS"
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM
trap 'on_signal HUP 129' HUP
trap cleanup EXIT
perl -e "$WATCHDOG_PERL" "$((HARD_SECS - RESERVE))" "$RESERVE" "$$" "$RUN/hard-timeout" "$OWN_LOCK" "$TOKEN" \
    "$ROLLBACK_LOG" </dev/null >/dev/null 2>&1 &
WATCHDOG_PID=$!
printf '%s\n' "$WATCHDOG_PID" >"$RUN/watchdog.pid"

preconditions
if [ "$MODE" = window ]; then
    # A KILL from now on still leaves a parseable receipt.
    field outcome in_progress
    write_receipt || event receipt provisional fail "not written"
    start_rollback
    CONNECT_ATTEMPTED=1
    step 35 connect "$HOST" --connect "$PROVIDER_ID" "$GEN" "$RELAY_IP"
    if [ "$RC" != 0 ]; then
        event connect host_connect fail "rc=$RC $(first_line "$ERR")"
        OUTCOME=connect_failed EXIT_CODE=1
        exit 1
    fi
    event connect host_connect pass "$(first_line "$OUT")"
    if ! wait_connected; then
        OUTCOME=connect_failed EXIT_CODE=1
        exit 1
    fi
fi
run_checks
if [ "$MODE" = window ]; then
    disconnect_and_verify
fi
if [ "$FAILED" != 0 ]; then
    OUTCOME=checks_failed EXIT_CODE=1
elif [ "$MODE" = window ] && [ "$DISCONNECT_VERIFIED" != 1 ]; then
    OUTCOME=disconnect_unverified EXIT_CODE=6
else
    OUTCOME=pass EXIT_CODE=0
fi
exit "$EXIT_CODE"
