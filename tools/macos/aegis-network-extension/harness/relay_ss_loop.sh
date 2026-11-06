#!/bin/bash
# B-06 v35: the read-only relay socket sampler of the A/B windows
# (docs/platforms/macos/v35-load-acceptance.md, run rules).
#
# During a tunnel window the leak guard lets the Mac reach the relay only on
# the relay's own :443 tuple, so SSH to the relay is dropped and a streaming
# sampler cannot run. This sampler is therefore started over one SSH command
# while the tunnel is Disconnected, runs detached on the relay for a bounded
# time, and is fetched and removed after the disconnect. It only reads
# socket state: no sysctl, qdisc, congestion-control, unit, config or binary
# change, and no script file is copied to the relay. Its one relay-side
# write is the masked sample file, for the window's life.
#
# Modes (each prints to stdout; the window wrapper passes the printed remote
# commands to ssh):
#
#   run N                  the loop itself: N samples, once a second, each a
#                          `T <epoch>` line, then `ss -tinH state established
#                          "( sport = :443 )"`; every IPv4 literal masked to
#                          a.b.x.x, every bracketed IPv6 literal to [v6.x] and
#                          every unbracketed one (`ip tcp_metrics show` prints
#                          them bare) to v6.x inside the pipeline, before
#                          anything is written.
#                          It runs ss, date, sleep and sed, nothing else.
#   remote-start NAME N BOUND [DIR]
#                          the one remote command line that runs the loop
#                          inline (bash -c, no file copied): umask 077; refuse
#                          (exit 4, nothing started) when a DIR/aegis-ss-*
#                          file or an aegis-ss process is left over; else
#                          `setsid nohup timeout BOUND bash -c <loop>` writing
#                          DIR/aegis-ss-NAME.txt (DIR defaults to /tmp).
#   remote-fetch NAME [DIR]
#                          the remote command that prints that file.
#   remote-clean NAME [DIR]
#                          the remote command that removes it, stops a loop
#                          still running, and fails (exit 4) unless neither
#                          the file nor an aegis-ss process remains.
#   remote-metrics         the remote command that prints, read only and
#                          masked, `ip tcp_metrics show` and
#                          net.ipv4.tcp_no_metrics_save (relay-snap's v35
#                          additions); nothing is flushed.
#   mask                   the local second pass over a fetched file (stdin
#                          to stdout); exit 3, printing nothing, when a full
#                          IPv4 literal or an IPv6 literal (two colons or
#                          more between hex groups) is still there
#                          afterwards.
#
# NAME is a window or sentinel name ([a-z0-9-], at most 64); N and BOUND are
# whole seconds (1..7200, BOUND at least N).
set -u

# The masks: bracketed IPv6 first (an IPv4-mapped literal inside brackets is
# IPv6), then an unbracketed IPv6 literal (v35 review: `ip tcp_metrics show`
# prints the peer and its own `source` bare): a token that starts after a
# character that is not a letter, digit, `_`, `:` or `.` and has two colons
# or more between hex groups of at most four (`::1`, `2001:db8::5`,
# `::ffff:192.0.2.1` whole), so ss's `rtt:180.5/2`, `wscale:7,7` and
# `bbr:(bw:...)` fields stay; then every dotted quad. The same text for the
# relay (GNU sed) and the local pass (BSD sed); both are POSIX EREs.
MASK_SED='s/\[[0-9a-fA-F:.]+\]/[v6.x]/g; s/(^|[^0-9A-Za-z_:.])([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F.]*/\1v6.x/g; s/([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.\2.x.x/g'
# What the local pass refuses to keep: a full dotted quad, or two colons
# between hex groups anywhere (stricter than the IPv6 mask: no boundary).
LEFT_IPV4='([0-9]{1,3}\.){3}[0-9]{1,3}'
LEFT_IPV6='[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}'
# The loop: it runs as `bash -c "$LOOP" aegis-ss-NAME N` on the relay and
# through eval here (run mode), so both are the same code.
LOOP="i=0; while [ \"\$i\" -lt \"\$1\" ]; do i=\$((i + 1)); echo \"T \$(date +%s.%N)\"; ss -tinH state established \"( sport = :443 )\" 2>/dev/null; [ \"\$i\" -lt \"\$1\" ] && sleep 1; done | sed -u -E \"$MASK_SED\""

usage() {
    echo "usage: relay_ss_loop.sh run N | remote-start NAME N BOUND [DIR] | remote-fetch NAME [DIR] | remote-clean NAME [DIR] | remote-metrics | mask" >&2
    exit 2
}
name_ok() { [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; }
seconds_ok() { [[ $1 =~ ^[0-9]{1,4}$ ]] && [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 7200 ]; }
dir_ok() { [[ $1 =~ ^/[A-Za-z0-9_./-]*$ ]] && [[ $1 != *..* ]]; }

mode=${1:-}
case "$mode" in
    run)
        [ $# -eq 2 ] && seconds_ok "$2" || usage
        set -- "$((10#$2))"
        eval "$LOOP"
        ;;
    remote-start)
        [ $# -eq 4 ] || [ $# -eq 5 ] || usage
        name_ok "$2" && seconds_ok "$3" && seconds_ok "$4" || usage
        n=$((10#$3)) bound=$((10#$4)) dir=${5:-/tmp}
        dir_ok "$dir" || usage
        [ "$bound" -ge "$n" ] || usage
        # One line for ssh. The loop is quoted with printf %q, so the remote
        # shell sees it as one argument whatever it holds. The marker
        # aegis-ss- is assembled at run time (m), so it never appears in the
        # remote shell's own command line, and pgrep finds only a loop.
        printf 'umask 077; m=aegis-s; m=${m}s-; for f in %q/${m}*.txt; do [ -e "$f" ] && { echo aegis_ss_leftover; exit 4; }; done; pgrep -f "$m" >/dev/null && { echo aegis_ss_running; exit 4; }; setsid nohup timeout %d bash -c %q "${m}%s" %d > %q/"${m}%s.txt" 2>/dev/null < /dev/null & echo aegis_ss_started\n' \
            "$dir" "$bound" "$LOOP" "$2" "$n" "$dir" "$2"
        ;;
    remote-fetch)
        [ $# -eq 2 ] || [ $# -eq 3 ] || usage
        name_ok "$2" || usage
        dir=${3:-/tmp}
        dir_ok "$dir" || usage
        printf 'm=aegis-s; m=${m}s-; cat %q/"${m}%s.txt"\n' "$dir" "$2"
        ;;
    remote-clean)
        [ $# -eq 2 ] || [ $# -eq 3 ] || usage
        name_ok "$2" || usage
        dir=${3:-/tmp}
        dir_ok "$dir" || usage
        printf 'm=aegis-s; m=${m}s-; pkill -f "${m}%s" 2>/dev/null; rm -f %q/"${m}%s.txt"; sleep 1; if [ -e %q/"${m}%s.txt" ] || pgrep -f "$m" >/dev/null; then echo aegis_ss_left; exit 4; fi; echo aegis_ss_clean\n' \
            "$2" "$dir" "$2" "$dir" "$2"
        ;;
    remote-metrics)
        [ $# -eq 1 ] || usage
        printf 'echo "tcp_no_metrics_save=$(sysctl -n net.ipv4.tcp_no_metrics_save 2>/dev/null)"; ip tcp_metrics show 2>/dev/null | sed -E %q\n' "$MASK_SED"
        ;;
    mask)
        [ $# -eq 1 ] || usage
        masked=$(sed -E "$MASK_SED")
        if printf '%s\n' "$masked" | grep -Eq "$LEFT_IPV4"; then
            echo "relay_ss_loop.sh: a full IPv4 literal remains; nothing kept" >&2
            exit 3
        fi
        if printf '%s\n' "$masked" | grep -Eq "$LEFT_IPV6"; then
            echo "relay_ss_loop.sh: an IPv6 literal remains; nothing kept" >&2
            exit 3
        fi
        [ -z "$masked" ] || printf '%s\n' "$masked"
        ;;
    *)
        usage
        ;;
esac
