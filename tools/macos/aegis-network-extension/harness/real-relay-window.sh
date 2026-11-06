#!/bin/bash
# B-06 S25-lite: one bounded owner-attended window against a real aegis-server
# relay. Targets come from the non-secret handoff file written by the relay
# owner; nothing here dials third-party services. A detached rollback outside
# this process tree stops the tunnel even if this script dies.
set -u
HANDOFF=${HANDOFF:-$HOME/.aegis-local/handoff/macos-relay.json}
APP=${APP:-/Applications/AEGIS.app}
HOST_BIN="$APP/Contents/MacOS/aegis-ne-host"
# S16i-3: worst case with every check at its bound is about 165 s (connect 20,
# cold TCP probes 10+10+3, UDP 3, whoami 5, bursts 10+10, re-ACK 4, warm
# probes 10+10, IPv4 DNS/HTTP 14, IPv6 block about 45, disconnect 10).
# S21i: NETLOSS=1 lengthens only this default, never a ROLLBACK_S given.
ROLLBACK_S_GIVEN=${ROLLBACK_S:-}
ROLLBACK_S=${ROLLBACK_S:-180}
OUT=${OUT:?set OUT to a new private directory}
AEGIS_QA_AGENT=${AEGIS_QA_AGENT:-self}
case "$AEGIS_QA_AGENT" in
    self) FOREIGN_TIMING_LOCK="$HOME/.aegis-local/locks/timing-peer" ;;
    peer) FOREIGN_TIMING_LOCK="$HOME/.aegis-local/locks/timing-self" ;;
    *) echo "refused: AEGIS_QA_AGENT must be self or peer" >&2; exit 3 ;;
esac
LOCK="$HOME/.aegis-local/locks/timing-$AEGIS_QA_AGENT"
# S20: LEAK_CAPTURE=1 records the physical interface for the whole window
# with tcpdump through `sudo -n` (never a prompt) and reviews it afterwards.
# Headers only (-s 160), no promiscuous mode (-p), and self-bounded: with
# -G/-W 1 tcpdump exits by itself at the first packet after CAPTURE_BOUND_S.
# PHYS carries the default route, so that packet comes within seconds and
# no signal is needed if this shell is killed or sudo refuses a kill.
# S20d: it also records every other interface the Mac could send on the
# same way (physical-<if>.pcap), so no_mac_sent_leak_physical sees whatever
# the Mac sends on any of them, not only on the default route.
# S20e: those can stay quiet for hours (awdl0, llw0, a port without a link),
# and the packet-driven -G bound never fires there; the detached rollback's
# `sudo -n /bin/kill` is best effort only (no cached sudo credential in its
# new session). So each of them also runs under owner-modes.sh's root alarm
# (perl's alarm, kept across its exec of tcpdump), CAPTURE_BOUND_S + 30 s,
# and LEAK_CAPTURE=1 refuses without `sudo -n` for /usr/bin/perl.
LEAK_CAPTURE=${LEAK_CAPTURE:-0}
CAPTURE_BOUND_S=$((ROLLBACK_S + 60))
# S24: the bound of the one provider-log read after the disconnect
# (collect_provider_log); ENDURANCE=1 raises it for its hours of log.
PROVIDER_LOG_BOUND_S=60
# S20b: the leak-guard packet filter (aegis-ne-host --filter-status) is read
# before anything connects and again after the disconnect. With
# FILTER_REQUIRED=1 (the default when LEAK_CAPTURE=1) a filter that is not
# configured, enabled and attached refuses the window before connecting.
FILTER_REQUIRED=${FILTER_REQUIRED:-$LEAK_CAPTURE}
SIGNED_BUNDLE_DIR=${SIGNED_BUNDLE_DIR:-}
PIN_REVIEW_ARGS=()
PIN_RELAY_PROTOS=tcp,udp
FILTER_RC= FILTER_LINE=
HARNESS_DIR=$(cd "$(dirname "$0")" && pwd)
CAP_PID= TCPDUMP_PID=
# S20d: the other interfaces' captures, by index: name, sudo pid, tcpdump
# leaf pid, addresses before connect (memory only), alive at the disconnect,
# stopped afterwards. LEAK_IFACES_START/END: leak_ifaces names before
# connect and right before the disconnect.
XC_IFS=() XC_PIDS=() XC_TPIDS=() XC_ADDRS=() XC_ALIVE=() XC_STOPPED=()
LEAK_IFACES_START='' LEAK_IFACES_END='' LEAK_IFACES=''
# S20e: the other captures' root alarm (XC_WRAP, XC_ALARM_S), and the Mac's
# MACs and addresses on every leak_ifaces interface before connect and
# right before the disconnect (memory and argv only, never recorded), which
# become MS_ARGS: the Mac-sent criterion's identities for every review.
XC_WRAP=() XC_ALARM_S=0 XC_END_NOTE=''
LEAK_ID_START='' LEAK_ID_END='' MS_ARGS=()
# S20f: the provider's armed span of this window (leak_guard_span lines),
# memory and argv only, given to every review as ARMED_ARGS.
ARMED_AT='' DISARMED_AT='' ARMED_ARGS=() LEAK_IFACES_NOW=''
# S20h review: filter_armed_span's verdict, for the positive control's tap
# evidence (controls.sh), which needs one arm through the window.
SPAN_VERDICT=''
# S21i: NETLOSS=1 (harness/netloss.sh) turns the physical Wi-Fi off and on
# while Connected, under its own detached rollback.
. "$HARNESS_DIR/netloss.sh"
# Owner-attended SLEEP=1 and IFSWITCH=1 (harness/owner-modes.sh): a sleep and
# timed wake, or a switch between two physical interfaces, while Connected.
. "$HARNESS_DIR/owner-modes.sh"
# S20f: the owner-attended POSITIVE_CONTROL=1 and NEGATIVE_CONTROL=1
# windows (harness/controls.sh), never S20 evidence.
. "$HARNESS_DIR/controls.sh"
# S24: the unattended ENDURANCE=1 and LOAD=1 windows, without sudo
# (harness/endurance-load.sh).
. "$HARNESS_DIR/endurance-load.sh"

# v35: WINDOW_POLICY=fixed connects this one tunnel start with v33's fixed
# stream window (aegis-ne-host --connect ... --window-policy fixed). v36
# (outcome fixed): WINDOW_POLICY=adaptive connects it with the v35 window
# (--window-policy adaptive, a QA arm); empty (the default) connects the
# product default, which build 36 makes v33's fixed window. Any other value
# is refused here, before the lock, the rollback or any connect. The
# window_policy row then checks the provider's pool_policy lines against it
# (window_policy_row).
WINDOW_POLICY=${WINDOW_POLICY:-}
if [ -n "${AEGIS_CAPTURE_SOCKET:-}" ]; then
    # The source-bound operator creates this output directory before it asks
    # macOS for the one narrow root bridge; no other pre-existing OUT is used.
    [ -d "$OUT" ] && [ ! -L "$OUT" ] && [ "$(stat -f '%u:%Lp' "$OUT" 2>/dev/null)" = "$EUID:700" ] || exit 2
else
    mkdir -m 700 "$OUT" || exit 2
fi
exec > >(tee "$OUT/window.log") 2>&1
now() { date -u +%Y%m%dT%H%M%SZ; }
# v34 (S24 review F): no relay, egress or Mac address reaches results.tsv
# or window.log. Every check computes its verdict from the raw value
# first; then each row's detail (result) and each log line (say) passes
# through harness/addr_mask.py, which writes the relay's address as
# relay_addr and any other address as its class (ip4_global, ip6_ula, ...),
# and keeps only the tunnel's own fixed addresses (198.18.0.0/15,
# fd00:ae61::/32). Text with nothing address-like is written as it is,
# without python; a masker that fails masks every candidate (fail closed).
MASK_RE4='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
MASK_RE6='[0-9A-Fa-f]*:[0-9A-Fa-f]*:'
mask_addrs() {
    local t=$1 m
    if ! [[ $t =~ $MASK_RE4 ]] && ! [[ $t =~ $MASK_RE6 ]]; then
        printf '%s' "$t"
        return 0
    fi
    if m=$(printf '%s' "$t" | python3 -I "$HARNESS_DIR/addr_mask.py" --relay "${RELAY_IP:-}" --relay "${RELAY_V6:-}" 2>/dev/null); then
        printf '%s' "$m"
    else
        printf '%s' "$t" | sed -E 's/[0-9]+(\.[0-9]+){3}/ip4_masked/g; s/[0-9A-Fa-f]*(:[0-9A-Fa-f]*){2,}/ip6_masked/g'
    fi
}
# v34 (S24 review F): whether a whoami body (raw) names the relay's address
# as a whole literal, not inside a longer one (an IPv4-mapped form counts);
# brackets and case are ignored. The whoami rows' verdict.
egress_is_relay() {
    local x=${RELAY_IP:-}
    x=${x#\[} x=${x%\]}
    [ -n "$x" ] || return 1
    printf '%s\n' "$1" | awk -v a="$x" '{
        s = tolower($0); a = tolower(a); n = length(a); o = 0
        while ((i = index(substr(s, o + 1), a)) > 0) {
            p = o + i
            b = (p > 1) ? substr(s, p - 1, 1) : ""; e = substr(s, p + n, 1)
            if (b == ":" && p > 7 && substr(s, p - 7, 7) == "::ffff:") b = ""
            if (b !~ /[0-9a-f:.]/ && e !~ /[0-9a-f:.]/) { found = 1; exit }
            o = p
        }
    } END { exit !found }'
}
# A whoami body's detail: masked first, then cut to 80 bytes on one line.
egress_detail() { mask_addrs "$1" | tr '\t\n' '  ' | head -c 80; }
say() { echo "$(now) $(mask_addrs "$*")"; }
case "$WINDOW_POLICY" in
    ''|fixed|adaptive) ;;
    *) say "refused: WINDOW_POLICY must be empty, fixed or adaptive; nothing connected"; exit 2 ;;
esac
# v31: UTC wall time to the millisecond (YYYY-MM-DDTHH:MM:SS.mmmZ).
utc_ms() { /usr/bin/perl -MTime::HiRes=time -MPOSIX=strftime -e '$t = time; printf "%s.%03dZ\n", strftime("%Y-%m-%dT%H:%M:%S", gmtime($t)), ($t - int($t)) * 1000'; }
# v31 review: the window's start, taken before its first baseline read: the
# first row starts here, and so does every row whose check came before any
# row was written (result_since).
WINDOW_FROM=$(utc_ms)
RESULT_FROM=$WINDOW_FROM
field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$HANDOFF" "$1"; }
# S16i-3: optional handoff fields read as empty when absent or null.
ofield() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$HANDOFF" "$1"; }
hostpart() { local h=${1%]:*}; echo "${h#\[}"; }  # [2001:db8::7]:7 -> 2001:db8::7
portpart() { echo "${1##*:}"; }
# The probes run under the system python3 (3.9), never a newer one on PATH.
PROBE_PY=${PROBE_PY:-/usr/bin/python3}
PROBE_LIMIT_S=${PROBE_LIMIT_S:-10}

[ -e "$FOREIGN_TIMING_LOCK" ] && { say "refused: foreign timing lock"; exit 4; }
# S24 review: the detached tunnel rollbacks of earlier windows (and of any
# other run of this LOCK) that are still armed, as pids. One fires on
# whatever tunnel is up then: a window that died, its lock removed by hand,
# keeps its rollback armed for up to its rollback_s (hours with
# ENDURANCE=1). ps lists before awk runs, so awk's own arguments are never
# matched.
armed_rollbacks() {
    local t
    t=$(ps -axww -o pid=,args= 2>/dev/null)
    printf '%s\n' "$t" | awk -v c="/rollback.cancel " -v l=" $LOCK " 'index($0, c) && index($0 " ", l) {print $1}'
}
RB_ARMED=$(armed_rollbacks | tr '\n' ' ')
[ -z "$RB_ARMED" ] || { say "refused: a detached tunnel rollback of an earlier window is still armed (pid ${RB_ARMED% }): it would stop this window's tunnel; disarm it first (harness/README.md, a window that dies)"; exit 3; }
RELAY=$(field relay); ECHO_TCP=$(field echo_tcp); ECHO_UDP=$(field echo_udp); WHOAMI=$(field whoami)
RELAY_IP=${RELAY%:*}
RELAY_PORT=${RELAY##*:}
if [ "$LEAK_CAPTURE" = 1 ] && [ -n "$SIGNED_BUNDLE_DIR" ]; then
    # The source of extra physical allowances is the exact public four-file
    # bundle the installed provider reports, never an operator pin list.
    # The reviewer recomputes that digest and derives every numeric pin.
    terms=$("$HOST_BIN" --profile-terms 2>/dev/null) || { say "refused: installed profile terms unavailable"; exit 3; }
    profile_sha=$(printf '%s' "$terms" | python3 -I -c 'import json,sys
r=json.load(sys.stdin).get("report",{}); d=r.get("profile_sha256","")
assert isinstance(d,str) and len(d)==64 and all(c in "0123456789abcdef" for c in d)
print(d)' 2>/dev/null) || { say "refused: installed profile digest invalid"; exit 3; }
    pin_count=$(python3 -I "$HARNESS_DIR/leak_review.py" profile-pins \
        --bundle-dir "$SIGNED_BUNDLE_DIR" --profile-sha256 "$profile_sha" \
        --relay-ip "$RELAY_IP" --relay-port "$RELAY_PORT") \
        || { say "refused: signed pool differs from installed profile; nothing connected"; exit 3; }
    PIN_REVIEW_ARGS=(--bundle-dir "$SIGNED_BUNDLE_DIR" --profile-sha256 "$profile_sha")
    PIN_RELAY_PROTOS=tcp
    say "signed_pool_review profile_sha256=$profile_sha $pin_count transport=signed-route-map cli_gate=tcp"
fi
ECHO_TCP6=$(ofield echo_tcp6); ECHO_UDP6=$(ofield echo_udp6); WHOAMI6=$(ofield whoami6); RELAY_V6=$(ofield relay_ipv6)
SID=$("$HOST_BIN" --list 2>/dev/null | sed -n 's/^profile index=0 .*scutil_service_id=\([0-9A-F-]*\) intent_valid=true .*/\1/p')
[ -n "$SID" ] || { say "refused: no single valid profile"; exit 3; }
[ "$(scutil --nc status "$SID" | head -1)" = "Disconnected" ] || { say "refused: service not Disconnected"; exit 3; }
PHYS=$(route -n get default | awk '/interface:/{print $2}')
say "relay=$RELAY sid=$SID physical=$PHYS"
# S16i-3: the physical IPv6 baseline. Only the count of addresses is ever
# logged, never an address; HOST_V6 stays in memory for whoami6 and source6.
# macOS picks the IPv4 and IPv6 primary interfaces separately, so HOST_V6 is
# every non-link-local IPv6 address on any interface (the tunnel is down
# here), not only those on PHYS.
PHYS_DEF6=$(route -n get -inet6 default 2>/dev/null | awk '/interface:/{print $2}')
HOST_V6=$(ifconfig 2>/dev/null | awk '$1=="inet6" && $2!~/^fe80/ {sub(/%.*/,"",$2); if ($2!="::1" && $2!="fd00:ae61::1") print $2}')
HOST_V6_N=$(printf '%s' "$HOST_V6" | grep -c .)
say "physical_v6_default=${PHYS_DEF6:-none} host_global_v6=$HOST_V6_N"
# The S20 capture watches PHYS only: with the IPv6 default elsewhere, an IPv6
# leak would leave unseen, so no_v6_leak_physical cannot pass.
V6_IF_DIFFERS=0
[ -n "$PHYS_DEF6" ] && [ "$PHYS_DEF6" != "$PHYS" ] && { V6_IF_DIFFERS=1; say "ipv6 default $PHYS_DEF6 is not the captured $PHYS: no_v6_leak_physical will be unavailable"; }
# The host's one filter_result= line (stable tokens and counter sums, no
# address); the whole output, the provider's JSON counters included, is kept.
filter_status() {
    local out
    out=$("$HOST_BIN" --filter-status 2>/dev/null)
    FILTER_RC=$?
    printf '%s\n' "$out" > "$OUT/filter-status-$1.txt"
    FILTER_LINE=$(printf '%s\n' "$out" | grep '^filter_result=' | tail -n 1)
    FILTER_LINE=${FILTER_LINE:-none}
}
# v31 review: filter_preflight reports this read, made before any row.
PREFLIGHT_FROM=$RESULT_FROM
filter_status before
say "filter_status exit=$FILTER_RC $FILTER_LINE"
# S20f: a NEGATIVE_CONTROL window cut off by a reboot, a logout or a power
# loss (which stop its EXIT trap and its rollback) left its marker; while
# the filter is not attached every window refuses, FILTER_REQUIRED=0 too.
ctl_marker_check || { say "refused: $CTL_REFUSAL; nothing connected"; exit 3; }
if [ "$FILTER_REQUIRED" = 1 ] && [ "$FILTER_RC" != 0 ]; then
    say "refused: FILTER_REQUIRED=1 needs the leak-guard filter configured, enabled and attached (host --filter-status exit $FILTER_RC; enable it with $HOST_BIN --enable-filter); nothing connected"
    exit 3
fi
# S24: refused beside any other mode before that mode's own preflight runs;
# the rollback, and with LOAD=1 LEAK_CAPTURE=1 the capture bound, grow by
# the mode's worst case.
if [ "$ENDURANCE" = 1 ] || [ "$LOAD" = 1 ]; then
    el_preflight || { say "refused: $EL_MODE: $EL_REFUSAL; nothing connected"; exit 3; }
    [ -n "$ROLLBACK_S_GIVEN" ] || ROLLBACK_S=$((ROLLBACK_S + EL_EXTRA_S))
    CAPTURE_BOUND_S=$((ROLLBACK_S + 60))
    el_bounds
    say "$EL_MODE: $EL_SUMMARY rollback_s=$ROLLBACK_S capture_bound_s=$CAPTURE_BOUND_S window_bound_s=$EL_WINDOW_BOUND_S"
fi
if [ "$NETLOSS" = 1 ]; then
    netloss_preflight || { say "refused: NETLOSS=1: $NL_REFUSAL; nothing connected"; exit 3; }
    [ -n "$ROLLBACK_S_GIVEN" ] || ROLLBACK_S=$((ROLLBACK_S + NL_EXTRA_S))
    say "netloss: device=$PHYS port=$NL_PORT only_route=$NL_ONLY_ROUTE rollback_s=$ROLLBACK_S"
fi
if [ "$SLEEP" = 1 ] || [ "$IFSWITCH" = 1 ]; then
    om_preflight || { say "refused: $OM_MODE: $OM_REFUSAL; nothing connected"; exit "$OM_EXIT"; }
    [ -n "$ROLLBACK_S_GIVEN" ] || ROLLBACK_S=$((ROLLBACK_S + OM_EXTRA_S))
    # tcpdump's -G bound is wall time: with SLEEP=1 it also covers the sleep.
    CAPTURE_BOUND_S=$((ROLLBACK_S + 60 + OM_CAPTURE_EXTRA_S))
    # IFSWITCH=1 with LEAK_CAPTURE=1: both captures under a root alarm.
    om_capture_wrap
    say "$OM_MODE: $OM_SUMMARY rollback_s=$ROLLBACK_S capture_bound_s=$CAPTURE_BOUND_S"
fi
# The modes' exit work (a second capture, a dated wake still ahead). v30
# review: every EXIT trap below first tells an armed sleep guard to stand
# down (om_on_exit_first), before anything slow such as a capture stop. v34
# review: then a load cut off mid-run leaves no unmasked capture
# (el_on_exit).
trap 'om_on_exit_first; el_on_exit; om_on_exit' EXIT

epoch() { python3 -I -c 'import time; print(f"{time.time():.6f}")'; }
alive() { local s; s=$(ps -p "$1" -o stat= 2>/dev/null); [ -n "$s" ] && [ "${s#Z}" = "$s" ]; }
# S16i-3: a timed TCP echo through harness/net_probe.py. Field 3 is
# <bytes>/<ms>/<outcome>; pass needs exactly the payload back (hc: then EOF).
tcp_probe() {
    local name=$1 mode=$2 host=$3 port=$4 payload=$5 d rc
    d=$("$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" tcp "$mode" "$host" "$port" "$payload" "$PROBE_LIMIT_S")
    rc=$?
    result "$name" "$([ "$rc" = 0 ] && echo pass || echo fail)" "${d:-no_output}"
}
# The kernel's IPv6 source for a tunnel-routed destination, as a class unless
# it is the tunnel address: a physical address is never recorded.
v6_source_class() {
    local a
    case "$1" in
        fd00:ae61::1) echo "$1" ;;
        error:*) echo "${1%%[!A-Za-z:]*}" ;;
        "") echo none ;;
        [Ff][Ee]8*) echo link_local ;;
        *) for a in $HOST_V6; do [ "$a" = "$1" ] && { echo physical_address; return; }; done; echo other_address ;;
    esac
}
# AAAA for example.com: at least one 2000::/3 answer and no other IPv6 answer
# (fd00:, fe80:, ::ffff: and the like).
aaaa_row() {
    local name=$1 q good bad global='^[23][0-9a-f]{3}:[0-9a-f:]+$'
    shift
    q=$(dig "$@" +short +time=3 +tries=1 example.com AAAA 2>&1)
    good=$(echo "$q" | grep -iE "$global")
    bad=$(echo "$q" | grep ':' | grep -v '^;;' | grep -viE "$global")
    result "$name" "$([ -n "$good" ] && [ -z "$bad" ] && echo pass || echo fail)" \
        "$(if [ -n "$bad" ]; then echo "$bad" | head -1; elif [ -n "$good" ]; then echo "$good" | head -1; else echo "${q:-empty}" | head -1; fi)"
}
# S16i-3 IPv6 checks, run once while Connected. Rows that need relay IPv6 are
# info or skip until the handoff publishes relay_ipv6, echo_*6 and whoami6.
# No line of this body is a bare closing brace (the tests extract it).
# S16j-2: the utun prefix is /120 (a /128 got no IPv6 route in v21); the
# anchor must route through the utun; the physical interface's scoped IPv6
# default and the utun's IPv6 routes are info. Only utun routes are read, and
# a destination outside the tunnel's own, link-local and multicast prefixes is
# only counted, so no physical or remote address is recorded.
v6_checks() {
    local a6= d6 n6 p6 t6 s6 r6 q y h6 st u6 w6 sc sd
    [ -n "$UTUN" ] && a6=$(ifconfig "$UTUN" 2>/dev/null | awk '$1=="inet6" && $2=="fd00:ae61::1" {for(i=3;i<NF;i++) if($i=="prefixlen") print $2"/"$(i+1)}' | head -1)
    result utun_addr_v6 "$([ "$a6" = fd00:ae61::1/120 ] && echo pass || echo fail)" "${a6:-none}"
    d6=$(route -n get -inet6 default 2>/dev/null | awk '/interface:/{print $2}')
    result default_route_v6 "$([ -n "$UTUN" ] && [ "$d6" = "$UTUN" ] && echo pass || echo fail)" "${d6:-none}"
    n6=$(route -n get -inet6 fd00:ae61::2 2>/dev/null | awk '/interface:/{print $2}')
    result route_v6_anchor "$([ -n "$UTUN" ] && [ "$n6" = "$UTUN" ] && echo pass || echo fail)" "${n6:-none}"
    if [ -n "${PHYS:-}" ]; then
        p6=$(route -n get -inet6 -ifscope "$PHYS" default 2>/dev/null | awk '/interface:/{print $2}')
        result scoped_phys_v6_default info "$PHYS:$([ -n "$p6" ] && echo present || echo absent)"
    else
        result scoped_phys_v6_default info "no_physical"
    fi
    [ -n "$UTUN" ] && t6=$(netstat -rn -f inet6 2>/dev/null | awk -v u="$UTUN" '$4==u {
        k=$1; sub("%"u, "", k)
        if (k=="default" || k~/^fd00:ae61:[0-9a-f:]*(\/[0-9]+)?$/ || k~/^fe80::\/64$/ || k~/^ff[0-9a-f][0-9a-f]::\/[0-9]+$/) { s=s (s==""?"":",") k ":" $3 } else o++ }
        END { printf "%s other=%d", (s==""?"none":s), o }')
    result utun_routes_v6 info "${t6:-none other=0}"
    s6=$("$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" source6 2001:db8::1 2>/dev/null | tail -1)
    result source_v6_tunnel "$([ "$s6" = fd00:ae61::1 ] && echo pass || echo fail)" "$(v6_source_class "$s6")"
    r6=$(scutil --dns | awk '/resolver #1/{f=1} f&&/nameserver\[1\]/{print $3; exit}')
    result system_resolver_v6 "$([ "$r6" = fd00:ae61::2 ] && echo pass || echo fail)" "${r6:-none}"
    q=$(dig -6 +short +time=3 +tries=1 @fd00:ae61::2 example.com A 2>&1 | head -1)
    result dns_udp6_anchor "$(echo "$q" | grep -qE '^198\.1[89]\.' && echo pass || echo fail)" "$q"
    q=$(dig -6 +tcp +short +time=3 +tries=1 @fd00:ae61::2 example.com A 2>&1 | head -1)
    result dns_tcp6_anchor "$(echo "$q" | grep -qE '^198\.1[89]\.' && echo pass || echo fail)" "$q"
    aaaa_row dns_aaaa_via_relay @198.19.255.2
    aaaa_row dns_aaaa_v6_anchor -6 @fd00:ae61::2
    y=$("$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" aaaa example.com 5 2>/dev/null | tail -1)
    result system_aaaa_observed info "${y:-none}"
    h6=$(curl -6 -s -m 8 -o /dev/null -w '%{http_code} %{remote_ip}' http://example.com/ 2>&1)
    case "$h6" in "200 "[23][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]:*) st=pass ;; *) st=fail ;; esac
    [ -n "$RELAY_V6" ] || st=info_$st
    result http6_by_name "$st" "$h6"
    if [ -n "$ECHO_UDP6" ]; then
        u6=$(printf pong6 | nc -6 -u -w 3 "$(hostpart "$ECHO_UDP6")" "$(portpart "$ECHO_UDP6")" 2>&1 | head -c 20)
        result udp_echo_v6 "$([ "$u6" = pong6 ] && echo pass || echo fail)" "$u6"
    else
        result udp_echo_v6 skip "no echo_udp6"
    fi
    if [ -n "$ECHO_TCP6" ]; then
        tcp_probe tcp_echo_v6 hc "$(hostpart "$ECHO_TCP6")" "$(portpart "$ECHO_TCP6")" ping6
    else
        result tcp_echo_v6 skip "no echo_tcp6"
    fi
    if [ -n "$WHOAMI6" ]; then
        w6=$(curl -6 -s -m 5 "$WHOAMI6" 2>&1 | head -c 4096)
        # The whole body is scanned before any of it is recorded.
        printf '%s' "$w6" | "$PROBE_PY" -I "$HARNESS_DIR/net_probe.py" scan64 $HOST_V6 >/dev/null 2>&1
        sc=$?
        # Body text only on a pass: a failing body may be the Mac's own address
        # from a prefix scan64 never saw (NAT66, renumbering), so only a class.
        if [ "$sc" = 1 ]; then st=fail sd=physical_prefix_seen
        elif [ "$sc" != 0 ]; then st=fail sd=scan_error
        # v34 review: the relay's whole address, as the IPv4 rows judge it
        # (egress_is_relay on the first 80 bytes, brackets and case
        # ignored), no longer any text that merely contains it.
        elif [ -n "$RELAY_V6" ] && RELAY_IP=$RELAY_V6 egress_is_relay "$(printf '%s' "$w6" | head -c 80)"; then
            st=pass sd=$(egress_detail "$w6")
        elif [ -z "$w6" ]; then st=fail sd=empty
        elif [ -z "$RELAY_V6" ]; then st=fail sd=no_relay_ipv6
        else st=fail sd=not_relay_address
        fi
        result whoami6_egress "$st" "$sd"
    else
        result whoami6_egress skip "no whoami6"
    fi
}
# The tcpdump itself is the leaf under sudo (sudo -> sudo monitor -> tcpdump
# with use_pty), named by its own -w file so a reused pid is never signalled.
# An optional second argument names another capture file (IFSWITCH=1).
is_capture() {
    if [ -n "${AEGIS_CAPTURE_SOCKET:-}" ]; then
        [ "$(/usr/bin/python3 -I "$AEGIS_CAPTURE_BRIDGE" client --leaf "${2:-$OUT/physical.pcap}" 2>/dev/null)" = "$1" ]
    else
        ps -p "$1" -o args= 2>/dev/null | grep -qF -- "-w ${2:-$OUT/physical.pcap}"
    fi
}
capture_leaf() {
    local p=$1 c
    if [ -n "${AEGIS_CAPTURE_SOCKET:-}" ]; then
        /usr/bin/python3 -I "$AEGIS_CAPTURE_BRIDGE" client --leaf "${2:-$OUT/physical.pcap}"
        return
    fi
    while c=$(pgrep -P "$p" 2>/dev/null | head -1) && [ -n "$c" ]; do p=$c; done
    is_capture "$p" "${2:-}" && echo "$p"
}
capture_running() { alive "$1" || { [ -n "$2" ] && alive "$2"; }; }
capture_sealed() {
    [ -n "${AEGIS_CAPTURE_SOCKET:-}" ] || return 0
    local expected actual
    expected=$(/usr/bin/python3 -I "$AEGIS_CAPTURE_BRIDGE" client --seal "$1" 2>/dev/null) || return 1
    actual=$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}')
    [ -n "$expected" ] && [ "$expected" = "$actual" ]
}
# Stops the capture once; the EXIT trap calls it again harmlessly. sudo
# drops or refuses an unprivileged signal, so the root tcpdump is signalled
# with `sudo -n /bin/kill`; the user's signal to sudo is only a fallback.
stop_capture() {
    [ -n "$CAP_PID" ] || return 0
    local pid=$CAP_PID tpid=$TCPDUMP_PID
    CAP_PID=
    [ -n "$tpid" ] && is_capture "$tpid" || tpid=
    if [ -n "$tpid" ]; then
        sudo -n /bin/kill -INT "$tpid" 2>/dev/null || kill -INT "$pid" 2>/dev/null
    else
        kill -INT "$pid" 2>/dev/null
    fi
    for _ in $(seq 1 20); do capture_running "$pid" "$tpid" || break; sleep 0.25; done
    capture_running "$pid" "$tpid" && [ -n "$tpid" ] && sudo -n /bin/kill -TERM "$tpid" 2>/dev/null
    for _ in $(seq 1 8); do capture_running "$pid" "$tpid" || break; sleep 0.25; done
    if capture_running "$pid" "$tpid" || ! capture_sealed "$OUT/physical.pcap"; then
        say "capture still running: ${CAPTURE_END_NOTE:-it exits by itself at the first packet after ${CAPTURE_BOUND_S}s}; stop it now with: sudo kill -INT ${tpid:-$pid}"
        result capture_stopped fail "pid=$pid tcpdump=${tpid:-?} still running"
        CAP_STOPPED=0
    else
        result capture_stopped pass "pid=$pid tcpdump=${tpid:-?}"
        CAP_STOPPED=1
    fi
}
# S20f: a control window's leak rows carry the control's prefix (ctl_row_name).
# v31: every row also carries its UTC start and end (columns 5 and 6). A
# row's start is the end of the row before it (the window's start for the
# first) and its end is when it is written, so a check made since the row
# before ran inside [start, end] and its overlap with the provider's
# rebuilds is computed, not inferred from the status column.
# v34 (S24 review F): the detail is written masked (mask_addrs); the
# verdict ($2) was computed from the raw value by the caller.
result() {
    local end
    end=$(utc_ms)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(ctl_row_name "$1")" "$2" "$(mask_addrs "$3")" "$(scutil --nc status "$SID" | head -1)" \
        "$RESULT_FROM" "$end" | tee -a "$OUT/results.tsv"
    RESULT_FROM=$end
}
# v31 review: `result_since FROM name verdict detail` for a row that reports
# a check made before an earlier row was written: it starts at FROM, the
# RESULT_FROM saved right before that check (the end of the row before it,
# or WINDOW_FROM), so its [start, end] still contains the check. It overlaps
# the rows between; the rows after it chain from its end as usual.
result_since() {
    RESULT_FROM=$1
    shift
    result "$@"
}
# S20d: the summary line without its mac_sent_* suffix, so the rows that
# embed it (leak_proof, ifswitch_leak_proof) read exactly as before.
strict_line() { printf '%s\n' "$1" | sed -E 's/ mac_sent_leaks=[0-9]+ mac_sent_pass=(true|false)$//'; }
drops_of() { sed -n 's/^\([0-9][0-9]*\) packets\{0,1\} dropped by kernel$/\1/p' "$1" 2>/dev/null | tail -1; }
# S20e: every interface the Mac could put a frame on during the window,
# whatever its addresses: up, and `status: active`, or an Ethernet port
# (`ether`) whose link may come up while Connected, or a radio (awdl, llw)
# that turns itself on. So a link-local-only port, a bridge member without
# an address of its own, a Thunderbolt Bridge, Internet Sharing's ap and
# the USB-C anpi ports count, active or not. Never loopback, a tunnel (utun,
# gif, stf, ipsec), a VM's host-side port (vmenet, vmnet, vnic) or a bridge
# whose members are all VM ports (its frames never leave the Mac).
# mode=names prints names; mode=identity prints `mac <ether>` and
# `addr <address>` lines of the same interfaces (memory and argv only).
LEAK_IFACES_AWK='
    function keep(i,   k, j, m, vm) {
        if (!up_[i] || nm[i] ~ /^(lo|utun|gif|stf|ipsec|vmenet|vmnet|vnic)[0-9]+$/) return 0
        if (!(act[i] || eth[i] != "" || nm[i] ~ /^(awdl|llw)[0-9]+$/)) return 0
        if (nm[i] ~ /^bridge[0-9]+$/ && mem[i] != "") {
            k = split(mem[i], m, " "); vm = 1
            for (j = 1; j <= k; j++) if (m[j] !~ /^(vmenet|vmnet|vnic)[0-9]+$/) vm = 0
            if (vm) return 0
        }
        return 1
    }
    function flush() { if (name != "") { n++; nm[n] = name; up_[n] = up; act[n] = active; eth[n] = ether; ad[n] = addrs; mem[n] = members } }
    /^[A-Za-z][A-Za-z0-9]*: flags=/ { flush(); name = $1; sub(/:$/, "", name); up = ($2 ~ /<UP[,>]/); active = 0; ether = ""; addrs = ""; members = ""; next }
    $1 == "status:" { active = ($2 == "active") }
    $1 == "ether" { ether = tolower($2) }
    $1 == "inet" || $1 == "inet6" { a = $2; sub(/%.*/, "", a); addrs = addrs " " a }
    $1 == "member:" { members = members " " $2 }
    END {
        flush()
        for (i = 1; i <= n; i++) {
            if (!keep(i)) continue
            if (mode == "names") { print nm[i]; continue }
            if (eth[i] != "") print "mac " eth[i]
            k = split(ad[i], w, " ")
            for (j = 1; j <= k; j++) print "addr " w[j]
        }
    }'
leak_ifaces() { ifconfig 2>/dev/null | awk -v mode=names "$LEAK_IFACES_AWK"; }
leak_identity() { ifconfig 2>/dev/null | awk -v mode=identity "$LEAK_IFACES_AWK"; }
if [ "${AEGIS_CAPTURE_ROSTER_ONLY:-0}" = 1 ]; then
    # This is the exact source predicate used by the later all-interface
    # review. It exits before sudo, capture, timing lock and connect. A new
    # interface after this snapshot cannot be captured by the root bridge;
    # the existing all_ifaces_rows then refuses its uncaptured name.
    [ "$LEAK_CAPTURE" = 1 ] && [ "$FILTER_REQUIRED" = 1 ] &&
        [ "$SLEEP" = 0 ] && [ "$IFSWITCH" = 0 ] && [ "$NETLOSS" = 0 ] &&
        [ "$ENDURANCE" = 0 ] && [ "$LOAD" = 0 ] &&
        [ "$POSITIVE_CONTROL" = 0 ] && [ "$NEGATIVE_CONTROL" = 0 ] || exit 3
    roster=$(printf '%s\n%s\n' "$PHYS" "$(leak_ifaces)" | sed '/^$/d' | sort -u | tr '\n' ',')
    [ -n "$PHYS" ] && [ -n "$roster" ] || exit 3
    printf 'aegis_capture_roster_v1 primary=%s ifaces=%s\n' "$PHYS" "${roster%,}"
    exit 0
fi
# The review arguments of those identities: before connect, right before the
# disconnect and now, each once.
mac_sent_id_args() {
    local kind v
    MS_ARGS=()
    while read -r kind v; do
        case "$kind" in
            mac) MS_ARGS+=(--mac-sent-mac "$v") ;;
            addr) MS_ARGS+=(--mac-sent-addr "$v") ;;
        esac
    done < <(printf '%s\n%s\n%s\n' "$LEAK_ID_START" "$LEAK_ID_END" "$(leak_identity)" | sort -u)
}
# S20d: one more interface, with the same tcpdump argv as PHYS's capture.
# S20e: always under the root alarm (XC_WRAP), with or without IFSWITCH=1.
# A quiet interface may write no packet, so the start is read from
# tcpdump's own `listening on` line.
start_extra_capture() {
    local dev=$1 file="physical-$1.pcap" err="$OUT/tcpdump-$1.stderr" pid tpid n
    sudo -n "${XC_WRAP[@]}" /usr/sbin/tcpdump -i "$dev" -p -s 160 -B 4096 -G "$CAPTURE_BOUND_S" \
        -W 1 -U -w "$OUT/$file" >/dev/null 2>"$err" &
    pid=$!
    n=${#XC_IFS[@]}
    XC_IFS+=("$dev") XC_PIDS+=("$pid") XC_TPIDS+=("") XC_ADDRS+=("$(om_addrs "$dev" | tr '\n' ' ')") XC_ALIVE+=(0) XC_STOPPED+=(0)
    for _ in $(seq 1 12); do grep -q "listening on $dev" "$err" 2>/dev/null && break; alive "$pid" || break; sleep 0.25; done
    tpid=$(capture_leaf "$pid" "$OUT/$file")
    XC_TPIDS[$n]=$tpid
    if ! alive "$pid" || ! grep -q "listening on $dev" "$err" 2>/dev/null || [ -z "$tpid" ]; then
        say "refused: tcpdump on $dev did not start: $(head -c 200 "$err")"
        return 1
    fi
    result "capture_started_$dev" pass "pid=$pid tcpdump=$tpid if=$dev file=$file bound=${CAPTURE_BOUND_S}s alarm=${XC_ALARM_S}s"
}
# Stops every other capture once, the way stop_capture stops PHYS's.
stop_extra_captures() {
    local i=0 dev pid tpid
    while [ "$i" -lt "${#XC_IFS[@]}" ]; do
        dev=${XC_IFS[$i]} pid=${XC_PIDS[$i]} tpid=${XC_TPIDS[$i]}
        if [ -n "$pid" ]; then
            XC_PIDS[$i]=
            [ -n "$tpid" ] && is_capture "$tpid" "$OUT/physical-$dev.pcap" || tpid=
            if [ -n "$tpid" ]; then
                sudo -n /bin/kill -INT "$tpid" 2>/dev/null || kill -INT "$pid" 2>/dev/null
            else
                kill -INT "$pid" 2>/dev/null
            fi
            for _ in $(seq 1 20); do capture_running "$pid" "$tpid" || break; sleep 0.25; done
            capture_running "$pid" "$tpid" && [ -n "$tpid" ] && sudo -n /bin/kill -TERM "$tpid" 2>/dev/null
            for _ in $(seq 1 8); do capture_running "$pid" "$tpid" || break; sleep 0.25; done
            if capture_running "$pid" "$tpid" || ! capture_sealed "$OUT/physical-$dev.pcap"; then
                say "capture of $dev still running: $XC_END_NOTE; stop it now with: sudo kill -INT ${tpid:-$pid}"
                result "capture_stopped_$dev" fail "pid=$pid tcpdump=${tpid:-?} still running"
                XC_STOPPED[$i]=0
            else
                result "capture_stopped_$dev" pass "pid=$pid tcpdump=${tpid:-?}"
                XC_STOPPED[$i]=1
            fi
        fi
        i=$((i + 1))
    done
}
# S20d: each other capture's review. These interfaces carry no relay
# traffic, so --relay-optional: only mac_sent_pass drops the relay term.
# S20e: MS_ARGS, the Mac-sent criterion's identities, as for every review.
review_extra_captures() {
    local i=0 dev mac a b lr dr args
    while [ "$i" -lt "${#XC_IFS[@]}" ]; do
        dev=${XC_IFS[$i]}
        args=(--pcap "$OUT/physical-$dev.pcap" --relay-ip "$RELAY_IP" --relay-port "$RELAY_PORT" --relay-proto "$PIN_RELAY_PROTOS"
              --relay-optional --out "$OUT/leak-review-$dev.json" ${MS_ARGS[@]+"${MS_ARGS[@]}"}
              ${ARMED_ARGS[@]+"${ARMED_ARGS[@]}"} ${PIN_REVIEW_ARGS[@]+"${PIN_REVIEW_ARGS[@]}"})
        mac=$(ifconfig "$dev" 2>/dev/null | awk '$1=="ether"{print $2; exit}')
        [ -n "$mac" ] && args+=(--local-mac "$mac")
        [ -n "$CONNECTED_AT" ] && args+=(--connected-at "$CONNECTED_AT" --disconnect-at "$DISCONNECT_AT")
        for a in ${XC_ADDRS[$i]} $(om_addrs "$dev"); do args+=(--local-addr "$a"); done
        for b in $(ifconfig "$dev" 2>/dev/null | awk '$1=="inet"{for(i=1;i<NF;i++) if($i=="broadcast") print $(i+1)}'); do args+=(--broadcast "$b"); done
        lr=$(python3 -I "$HARNESS_DIR/leak_review.py" "${args[@]}" 2>&1 | tail -1)
        dr=$(drops_of "$OUT/tcpdump-$dev.stderr")
        result "leak_review_$dev" info "if=$dev $lr capture_alive=${XC_ALIVE[$i]} capture_stopped=${XC_STOPPED[$i]} kernel_drops=${dr:-unknown}"
        result "leak_capture_sha256_$dev" "$(shasum -a 256 "$OUT/physical-$dev.pcap" 2>/dev/null | awk '{print $1}')" "physical-$dev.pcap not for retained evidence"
        i=$((i + 1))
    done
}
# The tokens the S20d rows read from one leak-review JSON (counts only).
review_tokens() {
    python3 -I -c 'import json, sys
try:
    r = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    r = None
if not isinstance(r, dict):
    print("pass=unreadable relay=? mac_sent_leaks=? mac_sent_pass=unreadable mac_sent_error=unreadable mac_sent_armed=?"); sys.exit()
e = r.get("mac_sent_error") or ""
code = "none" if "mac_sent_error" not in r else next(
    (c for p, c in (("no --local-mac", "no_local_mac"), ("no relay packet", "no_relay"),
                    ("no Connected interval", "no_interval"), ("unreadable --mac-sent-addr", "bad_identity"))
     if e.startswith(p)), "review_error")
n = r.get("mac_sent_leaks")
# S20f: the Mac-sent count of the armed span, none without a span.
na = r.get("mac_sent_armed_leaks")
armed = "?" if "mac_sent_armed_error" in r else ("none" if r.get("mac_sent_armed_span") is None
                                                 else (na if isinstance(na, int) else "?"))
print("pass=%s relay=%s mac_sent_leaks=%s mac_sent_pass=%s mac_sent_error=%s mac_sent_armed=%s" % (
    "true" if r.get("pass") is True else "false", r.get("relay_packets", "?"),
    n if isinstance(n, int) else "?", "true" if r.get("mac_sent_pass") is True else "false", code, armed))' "$1" 2>/dev/null \
        || echo "pass=unreadable relay=? mac_sent_leaks=? mac_sent_pass=unreadable mac_sent_error=unreadable mac_sent_armed=?"
}
tok() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }
# S20d: leak_proof_all_ifaces (pass's rule, as leak_proof, on every capture)
# and no_mac_sent_leak_physical (the Mac-sent criterion on every capture):
# each needs every leak_ifaces interface before connect or right before the
# disconnect (S20e: active or not, so one that appeared during the window
# too) to have been captured, alive at the disconnect, stopped and without a
# kernel drop; any other is named in uncaptured=. PHYS (and IFSWITCH=1's
# target) must also carry relay packets; the other interfaces never do
# (their reviews use --relay-optional).
all_ifaces_rows() {
    local ad=("$PHYS") aj=("$OUT/leak-review.json") aa=("$CAP_ALIVE") as=("$CAP_STOPPED") ae=("$OUT/tcpdump.stderr")
    local i=0 k=0 d t sp rl ml mp me ma dr ok sv=pass mv=pass sdet='' mdet='' reason='' unc=''
    if [ -n "$CAP2_FILE" ]; then
        ad+=("$IFSWITCH_TO") aj+=("$OUT/leak-review-$IFSWITCH_TO.json") aa+=("$CAP2_ALIVE") as+=("$CAP2_STOPPED")
        ae+=("$OUT/tcpdump-$IFSWITCH_TO.stderr")
    fi
    while [ "$i" -lt "${#XC_IFS[@]}" ]; do
        ad+=("${XC_IFS[$i]}") aj+=("$OUT/leak-review-${XC_IFS[$i]}.json") aa+=("${XC_ALIVE[$i]}") as+=("${XC_STOPPED[$i]}")
        ae+=("$OUT/tcpdump-${XC_IFS[$i]}.stderr")
        i=$((i + 1))
    done
    for d in $LEAK_IFACES_START $LEAK_IFACES_END; do
        case " ${ad[*]} " in *" $d "*) continue ;; esac
        case " $unc " in *" $d "*) continue ;; esac
        unc="${unc:+$unc }$d"
    done
    if [ -n "$unc" ]; then
        sv=fail mv=fail reason="uncaptured=$(printf '%s' "$unc" | tr ' ' ',')"
    fi
    while [ "$k" -lt "${#ad[@]}" ]; do
        d=${ad[$k]}
        t=$(review_tokens "${aj[$k]}")
        sp=$(tok pass "$t") rl=$(tok relay "$t") ml=$(tok mac_sent_leaks "$t") mp=$(tok mac_sent_pass "$t") me=$(tok mac_sent_error "$t")
        ma=$(tok mac_sent_armed "$t")
        dr=$(drops_of "${ae[$k]}")
        ok=1
        { [ "${aa[$k]}" = 1 ] && [ "${as[$k]}" = 1 ] && [ "$dr" = 0 ]; } || ok=0
        # PHYS keeps leak_proof's own verdict, word for word.
        if [ "$k" = 0 ]; then [ "$lp" = pass ] || sv=fail
        elif [ "$sp" != true ] || [ "$ok" != 1 ]; then sv=fail
        fi
        if [ "$mp" != true ] || [ "$ml" != 0 ] || [ "$ok" != 1 ]; then
            mv=fail
            [ "$ml" = 0 ] || reason="${reason:+$reason,}$d:mac_sent_leaks=$ml"
            [ "$me" = none ] || reason="${reason:+$reason,}$d:$me"
            [ "${aa[$k]}" = 1 ] || reason="${reason:+$reason,}$d:capture_alive=${aa[$k]:-0}"
            [ "${as[$k]}" = 1 ] || reason="${reason:+$reason,}$d:capture_stopped=${as[$k]:-0}"
            [ "$dr" = 0 ] || reason="${reason:+$reason,}$d:kernel_drops=${dr:-unknown}"
        fi
        # S20f: with the provider's armed span, a Mac-sent frame anywhere in
        # [arm, disarm] fails the row too.
        if [ -n "$ARMED_AT" ] && [ "$ma" != 0 ]; then
            mv=fail
            reason="${reason:+$reason,}$d:mac_sent_armed_leaks=$ma"
        fi
        sdet="$sdet $d:pass=$sp,relay=$rl,alive=${aa[$k]:-0},stopped=${as[$k]:-0},drops=${dr:-unknown}"
        mdet="$mdet $d:mac_sent_leaks=$ml,mac_sent_pass=$mp,alive=${aa[$k]:-0},stopped=${as[$k]:-0},drops=${dr:-unknown}${ARMED_AT:+,armed_leaks=$ma}"
        k=$((k + 1))
    done
    unc=$(printf '%s' "${unc:-none}" | tr ' ' ',')
    result leak_proof_all_ifaces "$sv" "ifaces=$(printf '%s' "${ad[*]}" | tr ' ' ',')$sdet uncaptured=$unc"
    result no_mac_sent_leak_physical "$mv" "ifaces=$(printf '%s' "${ad[*]}" | tr ' ' ',')$mdet${ARMED_AT:+ armed_span=reviewed} uncaptured=$unc${reason:+ reason=$reason}"
}
# S20f: the provider's log of the window, read once after the disconnect
# (bounded), before the reviews that need its armed span.
collect_provider_log() {
    sleep 1
    nl_bounded "$PROVIDER_LOG_BOUND_S" "$LOG_BIN" show --start "$START_LOCAL" --style compact --predicate 'eventMessage BEGINSWITH "aegis-ne"' 2>/dev/null \
        | grep -vE 'Timestamp|secinitd' > "$OUT/provider.log"
}
# v31: the whole window's session losses (by cause) and rebuilds, and its
# renewal attempts, deferrals and holds, from provider.log (from the
# connect to after the disconnect). The ifswitch_ and sleep_ log rows count
# only from their owner action on. Info only: no criterion reads it.
# v35: whether this window ran in the stream-window mode it asked for. For
# every LOAD=1 window and whenever WINDOW_POLICY is set: pass only when the
# provider logged at least one pool_policy line (one per flow pool, so one
# per session, a rebuild included) and every one names the expected mode
# (v36: adaptive with WINDOW_POLICY=adaptive, else fixed, the product
# default). A window that never connected logged none: unavailable, not a
# failure.
window_policy_row() {
    local expect=fixed seen n verdict
    [ "$LOAD" = 1 ] || [ -n "$WINDOW_POLICY" ] || return 0
    [ "$WINDOW_POLICY" = adaptive ] && expect=adaptive
    seen=$(awk '{for (i = 1; i < NF; i++) if ($i == "aegis-ne" && $(i + 1) == "pool_policy") {
            v = (i + 2 <= NF) ? $(i + 2) : "-"; print v; break } }' "$OUT/provider.log" 2>/dev/null)
    n=$(printf '%s' "$seen" | grep -c .)
    if [ "$n" = 0 ] && [ "$connected" != 1 ]; then
        result window_policy unavailable "expected=$expect seen=none lines=0 not_connected"
        return 0
    fi
    verdict=fail
    [ "$n" -ge 1 ] && ! printf '%s\n' "$seen" | grep -qvx "mode:$expect" && verdict=pass
    seen=$(printf '%s\n' "$seen" | sed 's/^mode://' | tr -cd 'a-z0-9_:\n-' | sort -u | grep . | paste -sd, -)
    result window_policy "$verdict" "expected=$expect seen=${seen:-none} lines=$n"
}
window_sessions() {
    local d
    if [ ! -s "$OUT/provider.log" ]; then
        result window_session_summary unavailable "no provider log lines"
        return 0
    fi
    d=$(awk '{for (i = 1; i < NF; i++) if ($i == "aegis-ne") {
            e = $(i + 1); v = (i + 2 <= NF) ? $(i + 2) : "-"
            if (e == "session_lost") { lost++; if (!(v in c)) k[++n] = v; c[v]++ }
            else if (e == "session_rebuilt") rebuilt++
            else if (e == "reasserting" && v == "on") on++
            else if (e == "identity_renewal" && v == "state:start") renew++
            else if (e == "identity_renewal" && v ~ /^state:deferred:/) deferred++
            else if (e == "identity_renewal" && v ~ /^state:held:/) held++
            break
        } }
        END {
            for (a = 1; a <= n; a++) for (b = a + 1; b <= n; b++) if (k[b] < k[a]) { t = k[a]; k[a] = k[b]; k[b] = t }
            for (a = 1; a <= n; a++) s = s (s == "" ? "" : ",") k[a] ":" c[k[a]]
            printf "session_lost=%d causes=%s session_rebuilt=%d reasserting_on=%d renewal_attempts=%d renewal_deferred=%d renewal_held=%d",
                lost, (s == "" ? "none" : s), rebuilt, on, renew, deferred, held
        }' "$OUT/provider.log" | cut -c1-400)
    result window_session_summary info "$d"
}
# S20f: the armed span of this window from the provider's address-free
# `leak_guard_span armed|disarmed seq:N wall:T` lines: the last arm at or
# before the connect and that arm's disarm. filter_armed_span passes when
# that arm came before the connect, its disarm after the disconnect, and no
# other arm came between; with both times every review also gets
# --armed-at/--disarmed-at (ARMED_ARGS), and no_mac_sent_leak_physical then
# fails on a Mac-sent frame anywhere in [arm, disarm]. seq restarts at 1 in
# every provider process, so an arm is the seq and the [pid:tid] of its
# compact log line (when the line has one), its disarm is the first one of
# that seq and pid at or after it, and any other arm line in between is a
# re-arm, whatever its seq (a restarted provider's arm repeats seq:1).
armed_span() {
    local v
    ARMED_AT='' DISARMED_AT='' ARMED_ARGS=() SPAN_VERDICT=unavailable
    if [ -z "$CONNECTED_AT" ]; then result filter_armed_span unavailable "not_connected"; return 0; fi
    v=$(python3 -I -c 'import re, sys
connected, disconnect = float(sys.argv[2]), float(sys.argv[3])
pat = re.compile(r"aegis-ne leak_guard_span (armed|disarmed) seq:([0-9]+) wall:([0-9]+(?:[.][0-9]+)?)(?:\s|$)")
proc = re.compile(r"\[([0-9]+):[0-9]+\]")
arms, disarms = [], []
try:
    lines = open(sys.argv[1], errors="replace").read().splitlines()
except OSError:
    lines = []
for line in lines:
    m = pat.search(line)
    if m:
        p = proc.findall(line[:m.start()])
        # -1: no [pid:tid] in the line, which then pairs by seq alone.
        span = (float(m.group(3)), int(m.group(2)), int(p[-1]) if p else -1)
        (arms if m.group(1) == "armed" else disarms).append(span)
if not arms and not disarms:
    print("unavailable - - no_span_lines"); sys.exit()
before = [a for a in arms if a[0] <= connected]
if not before:
    print("fail - - no_arm_before_connect arms=%d" % len(arms)); sys.exit()
armed, seq, pid = max(before)
disarmed = next((w for w, s, q in disarms
                 if s == seq and w >= armed and (pid < 0 or q < 0 or q == pid)), None)
end = disarmed if disarmed is not None else float("inf")
rearms = sum(1 for w, s, q in arms if armed < w <= end)
reasons = []
if disarmed is None:
    reasons.append("no_disarm")
elif disarmed < disconnect:
    reasons.append("disarmed_before_disconnect")
if rearms:
    reasons.append("rearms")
detail = "seq=%d armed_before_connect=%.3fs" % (seq, connected - armed)
detail += (" disarmed_after_disconnect=%.3fs" % (disarmed - disconnect)) if disarmed is not None else " disarmed=none"
detail += " rearms=%d" % rearms + ((" reason=" + ",".join(reasons)) if reasons else "")
print("%s %.6f %s %s" % ("fail" if reasons else "pass", armed, "-" if disarmed is None else "%.6f" % disarmed, detail))' \
        "$OUT/provider.log" "$CONNECTED_AT" "$DISCONNECT_AT" 2>/dev/null)
    # shellcheck disable=SC2086
    set -- ${v:-unavailable - - span_unreadable}
    if [ "$2" != - ] && [ "$3" != - ]; then
        ARMED_AT=$2 DISARMED_AT=$3
        ARMED_ARGS=(--armed-at "$ARMED_AT" --disarmed-at "$DISARMED_AT")
    fi
    local verdict=$1
    SPAN_VERDICT=$verdict
    shift 3
    result filter_armed_span "$verdict" "$*"
}
# S20f: a control's preflight, before the lock, any capture or connect.
if [ "$POSITIVE_CONTROL" = 1 ] || [ "$NEGATIVE_CONTROL" = 1 ]; then
    LEAK_IFACES_NOW=$(leak_ifaces)
    ctl_preflight || { say "refused: $CTL_MODE: $CTL_REFUSAL; nothing connected"; exit 3; }
    [ -n "$ROLLBACK_S_GIVEN" ] || ROLLBACK_S=$((ROLLBACK_S + CTL_EXTRA_S))
    CAPTURE_BOUND_S=$((ROLLBACK_S + 60))
    say "$CTL_MODE: $CTL_SUMMARY rollback_s=$ROLLBACK_S capture_bound_s=$CAPTURE_BOUND_S"
    trap 'om_on_exit_first; el_on_exit; om_on_exit; ctl_on_exit' EXIT
fi
if [ "$LEAK_CAPTURE" = 1 ]; then
    for cmd in /usr/sbin/tcpdump /bin/kill; do
        sudo -n -l "$cmd" >/dev/null 2>&1 \
            || { say "refused: LEAK_CAPTURE=1 needs sudo -n for $cmd (run sudo -v first); nothing connected"; exit 3; }
    done
    # S20e: the other interfaces' captures always run under the root alarm.
    [ -x "$OM_PERL" ] \
        || { say "refused: LEAK_CAPTURE=1 needs $OM_PERL for the other captures' wall-clock bound; nothing connected"; exit 3; }
    sudo -n -l "$OM_PERL" >/dev/null 2>&1 \
        || { say "refused: LEAK_CAPTURE=1 needs sudo -n for $OM_PERL (the other captures' wall-clock bound; run sudo -v first); nothing connected"; exit 3; }
    XC_ALARM_S=$((CAPTURE_BOUND_S + 30))
    XC_WRAP=("$OM_PERL" -e "$OM_ALARM_PL" "$XC_ALARM_S")
    XC_END_NOTE="its root alarm ends it at the latest ${XC_ALARM_S}s after its start"
    # S20f: NEGATIVE_CONTROL=1 disables the filter here, under its own
    # detached rollback, before any capture or connect.
    ctl_before_capture || { say "refused: $CTL_MODE: $CTL_REFUSAL; nothing connected"; exit 3; }
    trap 'om_on_exit_first; el_on_exit; stop_capture; stop_extra_captures; om_on_exit; ctl_on_exit' EXIT
    # v31 review: leak_capture_ifaces reports this listing, made before the
    # capture_started rows.
    CAPS_FROM=$RESULT_FROM
    LEAK_IFACES_START=$(leak_ifaces | tr '\n' ' ')
    LEAK_ID_START=$(leak_identity)
    # CAPTURE_WRAP is empty except with IFSWITCH=1 (owner-modes.sh).
    sudo -n ${CAPTURE_WRAP[@]+"${CAPTURE_WRAP[@]}"} /usr/sbin/tcpdump -i "$PHYS" -p -s 160 -B 4096 -G "$CAPTURE_BOUND_S" \
        -W 1 -U -w "$OUT/physical.pcap" >/dev/null 2>"$OUT/tcpdump.stderr" &
    CAP_PID=$!
    for _ in $(seq 1 12); do [ -s "$OUT/physical.pcap" ] && break; alive "$CAP_PID" || break; sleep 0.25; done
    TCPDUMP_PID=$(capture_leaf "$CAP_PID")
    if ! alive "$CAP_PID" || [ ! -s "$OUT/physical.pcap" ] || [ -z "$TCPDUMP_PID" ]; then
        say "refused: tcpdump on $PHYS did not start: $(head -c 200 "$OUT/tcpdump.stderr")"
        stop_capture; exit 3
    fi
    result capture_started pass "pid=$CAP_PID tcpdump=$TCPDUMP_PID if=$PHYS file=physical.pcap bound=${CAPTURE_BOUND_S}s"
    if [ "$IFSWITCH" = 1 ]; then
        om_start_capture2 || { stop_capture; om_stop_capture2; exit 3; }
    fi
    # S20d: every other leak_ifaces interface; IFSWITCH=1's target has its own.
    LEAK_IFACES=$PHYS
    [ -n "$CAP2_FILE" ] && LEAK_IFACES="$LEAK_IFACES $IFSWITCH_TO"
    for dev in $LEAK_IFACES_START; do
        case " $LEAK_IFACES " in *" $dev "*) continue ;; esac
        LEAK_IFACES="$LEAK_IFACES $dev"
        start_extra_capture "$dev" || { stop_capture; om_stop_capture2; stop_extra_captures; exit 3; }
    done
    result_since "$CAPS_FROM" leak_capture_ifaces info "$(printf '%s' "$LEAK_IFACES" | tr ' ' ',')"
    # S20f: POSITIVE_CONTROL=1 picks the interfaces it probes. S20g: both
    # controls open their pre-existing sockets here, before the connect.
    ctl_after_captures || { say "refused: $CTL_MODE: $CTL_REFUSAL; nothing connected"; stop_capture; om_stop_capture2; stop_extra_captures; exit 3; }
fi

# S24 review: the rollback gets this line, and releases the lock only while
# it still holds it (a lock taken since, by hand or by another run, stays).
LOCK_LINE="start=$(now) purpose=b06-real-relay-window$EL_LOCK_NOTE"
( set -o noclobber; printf '%s\n' "$LOCK_LINE" > "$LOCK" ) || { say "refused: lock busy"; exit 3; }
TOKEN=$(uuidgen)
# Detached rollback: new session, ignores signals. It stays a child of this
# shell until the shell exits (launchd adopts it then), so a bare `wait` here
# would also wait for its whole timer: wait only for named PIDs.
# With LEAK_CAPTURE=1 it also asks sudo -n to stop the tcpdump when it fires
# (best effort: its new session has no cached sudo credential, so the kill
# may be refused, rc in rollback.log; PHYS's own -G bound, and with
# IFSWITCH=1 its root alarm, is what guarantees it ends), and with
# IFSWITCH=1 the second interface's tcpdump as well, and (S20d) every
# other interface's tcpdump, which (S20e) its root alarm ends in any case.
RB_CAPS=() i=0
while [ "$i" -lt "${#XC_IFS[@]}" ]; do RB_CAPS+=("${XC_TPIDS[$i]}" "-w $OUT/physical-${XC_IFS[$i]}.pcap"); i=$((i + 1)); done
nohup /usr/bin/python3 -I - "$SID" "$HOST_BIN" "$ROLLBACK_S" "$OUT/rollback.log" "$OUT/rollback.cancel" "$TOKEN" "$LOCK" \
    "$LOCK_LINE" "$TCPDUMP_PID" "-w $OUT/physical.pcap" "$TCPDUMP2_PID" "-w $OUT/${CAP2_FILE:-none}" ${RB_CAPS[@]+"${RB_CAPS[@]}"} \
    >/dev/null 2>&1 <<'PY' &
import os, signal, subprocess, sys, time
sid, host, delay, logp, cancel, token, lock, lock_line = sys.argv[1:9]
caps = list(zip(sys.argv[9::2], sys.argv[10::2]))
os.setsid()
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    signal.signal(s, signal.SIG_IGN)
log = open(logp, "a", buffering=1)
log.write(f"armed pid={os.getpid()} ppid={os.getppid()}\n")
end = time.monotonic() + int(delay)
while time.monotonic() < end:
    try:
        if open(cancel).read().strip() == token:
            log.write("rollback_cancelled\n"); sys.exit(0)
    except OSError:
        pass
    time.sleep(0.5)
log.write("rollback_fired\n")
subprocess.run(["scutil", "--nc", "stop", sid], timeout=10)
subprocess.run([host, "--emergency-stop"], timeout=20)
for _ in range(40):
    if subprocess.run(["scutil", "--nc", "status", sid], capture_output=True, text=True).stdout.startswith("Disconnected"):
        break
    time.sleep(0.5)
for cap_pid, cap_mark in caps:
    if not cap_pid:
        continue
    try:
        args = subprocess.run(["ps", "-p", cap_pid, "-o", "args="], capture_output=True, text=True, timeout=10).stdout
        if cap_mark in args or (os.environ.get("AEGIS_CAPTURE_SOCKET") and cap_pid.isdecimal()):
            rc = subprocess.run(["sudo", "-n", "/bin/kill", "-INT", cap_pid], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10).returncode
            log.write(f"capture_stop_requested pid={cap_pid} rc={rc}\n")
        else:
            log.write(f"capture_already_stopped pid={cap_pid}\n")
    except (OSError, subprocess.SubprocessError) as error:
        log.write(f"capture_stop_error pid={cap_pid} {type(error).__name__}\n")
try:
    with open(lock) as f:
        ours = f.read() == lock_line + "\n"
    if ours:
        os.unlink(lock)
    log.write("lock_released\n" if ours else "lock_kept not_ours\n")
except OSError:
    pass
log.write("rollback_done\n")
PY
sleep 1
grep -q armed "$OUT/rollback.log" || { say "refused: rollback not armed"; rm -f "$LOCK"; exit 3; }

# Every check records the tunnel status at that moment, so a check that
# passes after the tunnel dropped is never mistaken for a tunnel pass.
START_LOCAL=$(date '+%Y-%m-%d %H:%M:%S')
# v31 review: both report reads made before any row (the baseline, then the
# filter's preflight read), so they start at the window's start.
result_since "$WINDOW_FROM" physical_v6_baseline info "default=${PHYS_DEF6:-none} global=$HOST_V6_N"
result_since "$PREFLIGHT_FROM" filter_preflight "$([ "$FILTER_RC" = 0 ] && echo pass || echo fail)" "exit=$FILTER_RC required=$FILTER_REQUIRED $FILTER_LINE"
# S24: endurance_preflight or load_preflight, the mode's reads before connect.
el_preflight_row
# v31 review: leak_window_connected_at reports the time the loop below saw
# Connected, before the connected row.
CONNECT_FROM=$RESULT_FROM
say "connect${WINDOW_POLICY:+ window_policy=$WINDOW_POLICY}"
# v35: the connect's argv as an array; a set WINDOW_POLICY (v36: fixed or
# adaptive) adds the flag with its value.
CONNECT_ARGS=(--connect dev.aegis.macos.PacketTunnel "$("$HOST_BIN" --list 2>/dev/null | sed -n 's/^profile index=0 owner_generation=\([0-9A-F-]*\) .*/\1/p')" "$RELAY_IP")
[ -n "$WINDOW_POLICY" ] && CONNECT_ARGS+=(--window-policy "$WINDOW_POLICY")
"$HOST_BIN" "${CONNECT_ARGS[@]}"
connected=0 CONNECTED_AT= DISCONNECT_AT=
for _ in $(seq 1 40); do
    [ "$(scutil --nc status "$SID" | head -1)" = "Connected" ] && { connected=1; CONNECTED_AT=$(epoch); break; }
    sleep 0.5
done
result connected "$connected" "$(scutil --nc status "$SID" | head -1)"
[ "$LEAK_CAPTURE" = 1 ] && result_since "$CONNECT_FROM" leak_window_connected_at "${CONNECTED_AT:-none}" ""
# S20h: the negative control's pre-existing sockets write right away, before
# a gateway that resets idle connections (about 15 s on the v28 LAN) can.
[ "$connected" = 1 ] && ctl_connected
if [ "$connected" = 1 ]; then
    UTUN=$(ifconfig | awk '/^utun[0-9]+:/{i=$1} /inet 198\.19\.255\.1 /{sub(":","",i); print i}')
    result utun_addr "$([ -n "$UTUN" ] && echo pass || echo fail)" "$UTUN"
    DEF=$(route -n get default | awk '/interface:/{print $2}')
    result default_route "$([ "$DEF" = "$UTUN" ] && echo pass || echo fail)" "$DEF"
    # S16i-3: the timed half-close probe stays the first user flow (cold
    # pool), then the no-half-close control and the old nc line for the series.
    tcp_probe tcp_echo_v4 hc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping
    tcp_probe tcp_echo_v4_nohc nohc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping
    t=$(printf ping | nc -w 3 "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" 2>&1 | head -c 20)
    result tcp_echo_v4_nc "$([ "$t" = ping ] && echo pass || echo fail)" "$t"
    u=$(printf pong | nc -u -w 3 "${ECHO_UDP%:*}" "${ECHO_UDP#*:}" 2>&1 | head -c 20)
    result udp_echo_v4 "$([ "$u" = pong ] && echo pass || echo fail)" "$u"
    # v34 (S24 review F): the verdict reads the raw body's first 80 bytes,
    # as before, for the relay's address as a whole literal; the detail is
    # the masked body (egress_detail).
    w=$(curl -s -m 5 "$WHOAMI" 2>&1 | head -c 4096)
    result whoami_egress "$(egress_is_relay "$(printf '%s' "$w" | head -c 80)" && echo pass || echo fail)" "$(egress_detail "$w")"
    # S16g: a burst of simultaneous flows must queue under the establishment
    # cap without costing the session its lease.
    # S16h: the same at 90 flows. Each burst records its wall time; only the
    # named curl PIDs are awaited (the rollback is a child of this shell too).
    # Wall clock, not monotonic: the system python3 3.9 counts monotonic per process.
    # S24: an optional third argument prefixes the row (LOAD=1's load_).
    burst() {
        local n=$1 need=$2 p=${3:-} t0 t1 ok pids=()
        t0=$(python3 -I -c 'import time; print(time.time())')
        for i in $(seq 1 "$n"); do curl -s -m 10 -o /dev/null -w '%{http_code}\n' "$WHOAMI" > "$OUT/burst.$i" 2>&1 & pids+=($!); done
        wait "${pids[@]}"
        t1=$(python3 -I -c 'import time; print(time.time())')
        ok=$(cat "$OUT"/burst.* | grep -c '^200$'); rm -f "$OUT"/burst.*
        result "${p}flow_burst_$n" "$([ "$ok" -ge "$need" ] && echo pass || echo fail)" "$ok/$n $(python3 -I -c "print(f'{$t1-$t0:.2f}s')")"
    }
    burst 24 22
    burst 90 88
    sleep 4  # cross at least two re-ACK periods before the traffic checks
    result still_connected_after_reack "$([ "$(scutil --nc status "$SID" | head -1)" = Connected ] && echo pass || echo fail)" ""
    tcp_probe tcp_echo_v4_warm hc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping
    tcp_probe tcp_echo_v4_warm_nohc nohc "${ECHO_TCP%:*}" "${ECHO_TCP#*:}" ping
    a=$(dig +short +time=3 +tries=1 @198.19.255.2 example.com A 2>&1 | head -1)
    result dns_a_fakeip "$(echo "$a" | grep -qE '^198\.1[89]\.' && echo pass || echo fail)" "$a"
    h=$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://example.com/ 2>&1)
    result http_by_name "$([ "$h" = 200 ] && echo pass || echo fail)" "$h"
    x=$(dig +short +time=3 +tries=1 @198.19.255.2 example.com TXT 2>&1 | head -1)
    result dns_txt_via_relay "$([ -n "$x" ] && ! echo "$x" | grep -q '^;;' && echo pass || echo fail)" "$x"
    r=$(scutil --dns | awk '/resolver #1/{f=1} f&&/nameserver\[0\]/{print $3; exit}')
    result system_resolver "$([ "$r" = 198.19.255.2 ] && echo pass || echo fail)" "$r"
    v6_checks
    [ "$NETLOSS" = 1 ] && netloss_window
    om_window
    ctl_window
    el_window
fi
[ "$connected" = 1 ] || el_not_connected
say "disconnect"
# v31 review: owner-modes.sh's ifswitch_leak_window_disconnect_at reports
# DISCONNECT_AT after other rows.
DISCONNECT_FROM=$RESULT_FROM
[ -n "$CONNECTED_AT" ] && DISCONNECT_AT=$(epoch)
CAP_ALIVE=0
[ -n "$CAP_PID" ] && alive "$CAP_PID" && CAP_ALIVE=1
[ "$LEAK_CAPTURE" = 1 ] && result leak_window_disconnect_at "${DISCONNECT_AT:-none}" "capture_alive=$CAP_ALIVE"
if [ "$LEAK_CAPTURE" = 1 ]; then
    # S20d: the other captures at the same moment, and the leak_ifaces
    # interfaces now, while Connected (one that appeared during the window
    # included), with (S20e) their MACs and addresses.
    i=0
    while [ "$i" -lt "${#XC_IFS[@]}" ]; do
        XC_ALIVE[$i]=0
        [ -n "${XC_PIDS[$i]}" ] && alive "${XC_PIDS[$i]}" && XC_ALIVE[$i]=1
        i=$((i + 1))
    done
    LEAK_IFACES_END=$(leak_ifaces | tr '\n' ' ')
    LEAK_ID_END=$(leak_identity)
fi
om_before_disconnect
scutil --nc stop "$SID"
down=0
for _ in $(seq 1 20); do
    if [ "$(scutil --nc status "$SID" | head -1)" = "Disconnected" ] && [ "$(route -n get default | awk '/interface:/{print $2}')" = "$PHYS" ]; then
        down=$((down+1)); [ "$down" -ge 2 ] && break
    else
        down=0
    fi
    sleep 0.5
done
if [ "$down" -ge 2 ]; then
    echo "$TOKEN" > "$OUT/rollback.cancel"
    rm -f "$LOCK"
    result disconnect_verified pass "$PHYS"
else
    "$HOST_BIN" --emergency-stop
    result disconnect_verified fail "rollback stays armed"
fi
om_after_gate
# S16i-3: the IPv6 route and address must go too. Separate rows, after the
# rollback-cancel gate above, which they never change. v31 review: both are
# checked in this loop, and disconnect_v6_addr is written after the reviews
# below, so it starts where disconnect_v6_route does (V6_FROM).
V6_FROM=$RESULT_FROM
for _ in $(seq 1 10); do
    d6=$(route -n get -inet6 default 2>/dev/null | awk '/interface:/{print $2}')
    l6=$(ifconfig | grep -c 'inet6 fd00:ae61::1 ')
    om_v6_back "$d6" && [ "$l6" = 0 ] && break
    sleep 0.5
done
result disconnect_v6_route "$(om_v6_back "$d6" && echo pass || echo fail)" "${d6:-none} baseline=${PHYS_DEF6:-none}${OM_DEF6_ALT:+ or_switched=$OM_DEF6_ALT}$([ "$OM_DEF6_NONE_OK" = 1 ] && echo ' or_none')"
# S20b: the gate is Open again after the disconnect; the counters show what
# the filter dropped and allowed during the window.
filter_status after
result filter_counters_after info "exit=$FILTER_RC $FILTER_LINE"
# S20f: NEGATIVE_CONTROL=1 restores the filter first; then the provider's
# log and the window's armed span, which the reviews below need.
ctl_after_disconnect
collect_provider_log
window_policy_row
armed_span
window_sessions
# v34: LOAD=1's info rows from the window's provider log (endurance-load.sh).
el_after_window
result_since "$V6_FROM" disconnect_v6_addr "$([ "$l6" = 0 ] && echo pass || echo fail)" "count=$l6"
if [ "$LEAK_CAPTURE" = 1 ]; then
    CAP_STOPPED=0
    stop_capture
    stop_extra_captures
    # S20e: the Mac-sent identities of every review (PHYS's strict
    # --local-mac and --local-addr below are unchanged).
    mac_sent_id_args
    lr_args=(--pcap "$OUT/physical.pcap" --relay-ip "$RELAY_IP" --relay-port "$RELAY_PORT" --relay-proto "$PIN_RELAY_PROTOS"
             --out "$OUT/leak-review.json" ${MS_ARGS[@]+"${MS_ARGS[@]}"} ${ARMED_ARGS[@]+"${ARMED_ARGS[@]}"}
             ${PIN_REVIEW_ARGS[@]+"${PIN_REVIEW_ARGS[@]}"})
    mac=$(ifconfig "$PHYS" 2>/dev/null | awk '$1=="ether"{print $2; exit}')
    [ -n "$mac" ] && lr_args+=(--local-mac "$mac")
    [ -n "$CONNECTED_AT" ] && lr_args+=(--connected-at "$CONNECTED_AT" --disconnect-at "$DISCONNECT_AT")
    for a in $(ifconfig "$PHYS" 2>/dev/null | awk '$1=="inet"||$1=="inet6"{sub(/%.*/,"",$2); print $2}') $OM_BASE_ADDRS; do lr_args+=(--local-addr "$a"); done
    for b in $(ifconfig "$PHYS" 2>/dev/null | awk '$1=="inet"{for(i=1;i<NF;i++) if($i=="broadcast") print $(i+1)}'); do lr_args+=(--broadcast "$b"); done
    lr=$(strict_line "$(python3 -I "$HARNESS_DIR/leak_review.py" "${lr_args[@]}" 2>&1 | tail -1)")
    # The capture must have run through the whole interval and lost nothing.
    drops=$(sed -n 's/^\([0-9][0-9]*\) packets\{0,1\} dropped by kernel$/\1/p' "$OUT/tcpdump.stderr" | tail -1)
    lp=fail
    echo "$lr" | grep -q '^leak_review pass=true ' && [ "$CAP_ALIVE" = 1 ] && [ "$CAP_STOPPED" = 1 ] && [ "$drops" = 0 ] && lp=pass
    result leak_proof "$lp" "$lr capture_alive=$CAP_ALIVE capture_stopped=$CAP_STOPPED kernel_drops=${drops:-unknown}"
    # physical.pcap is headers only and stays in OUT: retained evidence is
    # leak-review.json, results.tsv and this digest, never the capture itself.
    result leak_capture_sha256 "$(shasum -a 256 "$OUT/physical.pcap" 2>/dev/null | awk '{print $1}')" "physical.pcap not for retained evidence"
    # S16i-3: IPv6 on the physical interface from the same capture, no second
    # tcpdump: the review's IPv6 leaks (ND, MLD, DHCPv6, mDNS are control).
    v6l=$(python3 -I -c 'import json,sys
r = json.load(open(sys.argv[1]))
f = r.get("leak_families")
print(f.get("ipv6", "") if isinstance(f, dict) and r.get("connected_interval") and r.get("relay_packets") else "unreviewed")' \
        "$OUT/leak-review.json" 2>/dev/null)
    if [ "$V6_IF_DIFFERS" = 1 ]; then
        result no_v6_leak_physical unavailable "v6_default_interface_differs capture=$PHYS v6_default=$PHYS_DEF6"
    else
        vp=fail
        [ "$v6l" = 0 ] && [ "$CAP_ALIVE" = 1 ] && [ "$CAP_STOPPED" = 1 ] && [ "$drops" = 0 ] && vp=pass
        result no_v6_leak_physical "$vp" "ipv6_leaks=${v6l:-unreadable} capture_alive=$CAP_ALIVE capture_stopped=$CAP_STOPPED kernel_drops=${drops:-unknown}"
    fi
    om_leak_review2
    review_extra_captures
    all_ifaces_rows
    ctl_after_reviews
else
    result no_v6_leak_physical unavailable "LEAK_CAPTURE=0: no physical capture"
fi
# The provider's log was read once after the disconnect (collect_provider_log).
ctl_final
say "done"
