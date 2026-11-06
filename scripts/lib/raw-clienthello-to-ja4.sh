#!/usr/bin/env bash
# Canonical JA4 for a raw TLS ClientHello record, via text2pcap + tshark.
# Usage: raw-clienthello-to-ja4.sh <clienthello.raw> [tshark_bin]
set -euo pipefail
RAW="$1"
TSHARK="${2:-tshark}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
# text2pcap wants an offset+hex dump; -T fakes a TCP stream so tshark sees TLS.
od -Ax -tx1 -v "${RAW}" > "${WORK}/hex.txt"
text2pcap -q -T 44444,443 "${WORK}/hex.txt" "${WORK}/ch.pcap" 2>/dev/null
"${TSHARK}" -q -r "${WORK}/ch.pcap" -Y tls.handshake.type==1 \
  -T fields -e tls.handshake.ja4 -e tls.handshake.ja3 2>/dev/null | head -1
