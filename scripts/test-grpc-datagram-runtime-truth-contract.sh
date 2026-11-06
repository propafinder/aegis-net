#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY="${ROOT}/aegis-client/src/relay.rs"
UDP_PROXY="${ROOT}/aegis-client/src/ingress/wide/udp_redirect_proxy.rs"
TUN="${ROOT}/aegis-client/src/ingress/wide/tun_smoltcp_engine.rs"

require() {
  grep -Fq -- "$1" "$2" || {
    echo "grpc datagram runtime truth contract: missing '$1' in $2" >&2
    exit 1
  }
}

reject() {
  if grep -Fq -- "$1" "$2"; then
    echo "grpc datagram runtime truth contract: stale claim '$1' in $2" >&2
    exit 1
  fi
}

# Persistent full-wide flows must use the same explicit relay event surface as
# one-shot UDP. This is the authoritative transport evidence consumed by RT
# audits; capture backends must not guess which policy attempt succeeded.
require 'session_kind: "udp_flow"' "${RELAY}"
require 'emit_relay_transport_selected(' "${RELAY}"
require 'emit_relay_transport_failed(' "${RELAY}"
require 'emit_relay_session_succeeded(' "${RELAY}"

require '"carry": "policy_ordered_persistent_datagram"' "${UDP_PROXY}"
require '"transport_evidence": "relay_transport_selected"' "${UDP_PROXY}"
reject '"carry": "masque_direct_persistent_flow"' "${UDP_PROXY}"
reject '"carry": "masque_direct_bidirectional"' "${UDP_PROXY}"
reject '"through_cloudflare": false' "${UDP_PROXY}"
reject 'persistent masque per-flow' "${TUN}"

echo "grpc datagram runtime truth contract: PASS"
