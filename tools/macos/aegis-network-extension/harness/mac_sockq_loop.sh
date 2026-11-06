#!/bin/bash
# B-06 v35: the Mac's socket-queue sampler beside an A/B window (critic
# REQUIRED 11): whether data waits unread in the provider's own relay
# sockets (Recv-Q) rather than at the relay. Passive and without sudo: N
# samples, once a second, each a `T <epoch>` line and then the `netstat -an
# -p tcp` lines of the ESTABLISHED TCP sockets whose foreign end is the
# relay's :443 (RELAY, compared before anything is written). Every address
# is masked (IPv4 to a.b.x.x, IPv6 to v6.x) before a line reaches stdout;
# the ports and the Recv-Q and Send-Q columns are kept.
#
# Usage: mac_sockq_loop.sh N RELAY_IPV4   (N whole seconds, 1..7200)
# It runs netstat, date, sleep, awk and sed, nothing else.
set -u
[ $# -eq 2 ] || { echo "usage: mac_sockq_loop.sh N RELAY_IPV4" >&2; exit 2; }
[[ $1 =~ ^[0-9]{1,4}$ ]] && [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 7200 ] \
    || { echo "mac_sockq_loop.sh: N must be 1..7200" >&2; exit 2; }
[[ $2 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "mac_sockq_loop.sh: RELAY must be an IPv4 literal" >&2; exit 2; }
n=$((10#$1)) relay=$2
i=0
while [ "$i" -lt "$n" ]; do
    i=$((i + 1))
    echo "T $(date +%s)"
    netstat -an -p tcp 2>/dev/null | awk -v r="$relay.443" '$1 ~ /^tcp/ && $5 == r && $6 == "ESTABLISHED"'
    [ "$i" -lt "$n" ] && sleep 1
done | sed -u -E 's/[0-9a-fA-F]*:[0-9a-fA-F:]*[0-9a-fA-F]/v6.x/g; s/([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.\2.x.x/g'
