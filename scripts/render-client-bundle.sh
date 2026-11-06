#!/usr/bin/env bash
set -euo pipefail

# The rendered TOML files embed the relay auth token.  Make creation safe even
# when the caller has the common 0022 umask, and also repair permissions when a
# previously world-readable bundle directory is re-rendered in place.
umask 077

usage() {
  cat <<'EOF'
Usage:
  scripts/render-client-bundle.sh <bundle-dir> <relay-server> <server-name> --auth-token-stdin <ca-cert-source> <verified-secret-reader> [relay-endpoints] [relay-transport-priority] [masque-ca-source]

Creates a client bundle directory with:
  aegis-client.toml
  ca.pem
  README.txt

The generated config contains a placeholder CA path that `install.sh client`
replaces with the final local path during installation.

Optional `relay-endpoints` format:
  server,server_name[,masque_server][;server,server_name[,masque_server]...]

Optional `relay-transport-priority` format:
  https_ws,grpc_stream[,legacy_tls][,masque_derived]

Optional `masque-ca-source` is copied separately and referenced only by the
direct MASQUE leg; it does not replace the primary TLS CA.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 6 || $# -gt 9 || "${4:-}" != --auth-token-stdin ]]; then
  echo "Inline relay credentials are refused; pipe into --auth-token-stdin with the verified Rust reader." >&2
  usage >&2
  exit 1
fi

BUNDLE_DIR="$1"
RELAY_SERVER="$2"
SERVER_NAME="$3"
CA_CERT_SOURCE="$5"
SECRET_READER="$6"
RELAY_ENDPOINTS="${7:-}"
RELAY_TRANSPORT_PRIORITY="${8:-grpc_stream,https_ws,legacy_tls,masque_derived}"
MASQUE_CA_SOURCE="${9:-}"
MASQUE_CA_TOML=""
[[ "$SECRET_READER" == /* && -x "$SECRET_READER" ]] || { echo "Verified Rust secret reader required." >&2; exit 2; }
[[ "$("$SECRET_READER" installer-secret version)" == installer-secret-v1 ]] || { echo "Private installer input protocol required." >&2; exit 2; }
export -n AUTH_TOKEN
AUTH_TOKEN="$("$SECRET_READER" installer-secret token-stdin)" || exit $?
# All controls were rejected by Rust. Preserve the exact token value when
# embedding ordinary quoted/backslash values into TOML string syntax.
AUTH_TOKEN="${AUTH_TOKEN//\\/\\\\}"
AUTH_TOKEN="${AUTH_TOKEN//\"/\\\"}"

if [[ ! -f "${CA_CERT_SOURCE}" ]]; then
  echo "CA certificate not found: ${CA_CERT_SOURCE}" >&2
  exit 1
fi

mkdir -p "${BUNDLE_DIR}"
chmod 0700 "${BUNDLE_DIR}"
install -m 0600 "${CA_CERT_SOURCE}" "${BUNDLE_DIR}/ca.pem"
if [[ -n "${MASQUE_CA_SOURCE}" ]]; then
  [[ -f "${MASQUE_CA_SOURCE}" ]] || { echo "Direct MASQUE CA file required." >&2; exit 1; }
  install -m 0600 "${MASQUE_CA_SOURCE}" "${BUNDLE_DIR}/masque-ca.pem"
  MASQUE_CA_TOML='masque_ca_cert = "masque-ca.pem"'
fi

render_relay_endpoints_toml() {
  local endpoints="$1"
  local entry=""
  local server=""
  local server_name=""
  local masque_server=""
  local first=1
  if [[ -z "${endpoints}" ]]; then
    return 0
  fi
  printf 'endpoints = [\n'
  IFS=';' read -r -a endpoint_entries <<< "${endpoints}"
  for entry in "${endpoint_entries[@]}"; do
    [[ -z "${entry}" ]] && continue
    IFS=',' read -r server server_name masque_server <<< "${entry}"
    if [[ -z "${server:-}" || -z "${server_name:-}" ]]; then
      echo "invalid relay endpoint entry: ${entry}" >&2
      return 1
    fi
    if [[ "${first}" -eq 0 ]]; then
      printf ',\n'
    fi
    first=0
    if [[ -n "${masque_server:-}" ]]; then
      printf '  { server = "%s", server_name = "%s", masque_server = "%s" }' \
        "${server}" "${server_name}" "${masque_server}"
    else
      printf '  { server = "%s", server_name = "%s" }' "${server}" "${server_name}"
    fi
  done
  printf '\n]\n'
}

render_transport_priority_toml() {
  local priority="$1"
  local item=""
  local first=1
  local rendered=""
  if [[ -z "${priority}" ]]; then
    echo "relay transport priority must not be empty" >&2
    return 1
  fi
  IFS=',' read -r -a priority_items <<< "${priority}"
  for item in "${priority_items[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -z "${item}" ]] && continue
    case "${item}" in
      https_ws|grpc_stream|legacy_tls|masque_derived)
        ;;
      *)
        echo "invalid relay transport priority entry: ${item}" >&2
        return 1
        ;;
    esac
    if [[ "${first}" -eq 0 ]]; then
      rendered+=", "
    fi
    first=0
    rendered+="\"${item}\""
  done
  if [[ -z "${rendered}" ]]; then
    echo "relay transport priority must contain at least one transport" >&2
    return 1
  fi
  printf '[%s]\n' "${rendered}"
}

RELAY_ENDPOINTS_TOML="$(render_relay_endpoints_toml "${RELAY_ENDPOINTS}")"
RELAY_TRANSPORT_PRIORITY_TOML="$(render_transport_priority_toml "${RELAY_TRANSPORT_PRIORITY}")"

cat > "${BUNDLE_DIR}/aegis-client.toml" <<EOF
# Generated server-side bundle for a remote Linux client.
# The client installer rewrites ca_cert to the final local path.

mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "auto"
rollout_profile = "output_only_safe"
listen = "0.0.0.0:15080"
# Safe installed baseline: keep DNS off here and reserve real DNS interception
# for the explicit privileged linux_tproxy profile shipped alongside this file.
capture_dns = false
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
udp_preview_ports = []
default_mark = 0

[socks]
listen = "127.0.0.1:1080"

[direct]
state_path = "~/.cache/aegis/state.json"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "${RELAY_SERVER}"
# TLS and HTTP authorities follow relay.server_name, while relay.server remains
# the dial target so IP fallback can stay routable without forcing IP-in-SNI.
server_name = "${SERVER_NAME}"
auth_token = "${AUTH_TOKEN}"
transport_priority = ${RELAY_TRANSPORT_PRIORITY_TOML}
${RELAY_ENDPOINTS_TOML}
websocket_path = "/socket"
grpc_path = "/rpc.Tunnel/Open"
masque_path = "/.well-known/masque/udp"
ca_cert = "__CLIENT_CA_CERT_PATH__"
${MASQUE_CA_TOML}
connect_timeout_ms = 5000

[relay.policy]
rotate_transports_per_session = true
max_transport_attempts = 4
write_chunk_size = 16384
inter_chunk_delay_ms = 0
EOF

cat > "${BUNDLE_DIR}/aegis-client-privileged-dns.toml" <<EOF
# Generated privileged DNS profile for a remote Linux client.
# This profile is intentionally not installed as the default because it expects
# a privileged linux_tproxy rollout and host-specific interface selection.
# The client installer rewrites ca_cert to the final local path.

mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
# Set prerouting_interface to the client host ingress interface before use.
# prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
udp_preview_ports = []
default_mark = 1

[socks]
listen = "127.0.0.1:1080"

[direct]
state_path = "~/.cache/aegis/state.json"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "${RELAY_SERVER}"
# TLS and HTTP authorities follow relay.server_name, while relay.server remains
# the dial target so IP fallback can stay routable without forcing IP-in-SNI.
server_name = "${SERVER_NAME}"
auth_token = "${AUTH_TOKEN}"
transport_priority = ${RELAY_TRANSPORT_PRIORITY_TOML}
${RELAY_ENDPOINTS_TOML}
websocket_path = "/socket"
grpc_path = "/rpc.Tunnel/Open"
masque_path = "/.well-known/masque/udp"
ca_cert = "__CLIENT_CA_CERT_PATH__"
${MASQUE_CA_TOML}
connect_timeout_ms = 5000

[relay.policy]
rotate_transports_per_session = true
max_transport_attempts = 4
write_chunk_size = 16384
inter_chunk_delay_ms = 0
EOF

cat > "${BUNDLE_DIR}/README.txt" <<EOF
AEGIS client bundle
===================

This bundle is generated by the server setup and is meant to be transferred to a
remote Linux client host.

Contents:
- aegis-client.toml                : safe installed baseline for relay/TCP runtime
- aegis-client-privileged-dns.toml : privileged linux_tproxy profile for real DNS
- ca.pem                           : relay CA certificate used to verify the server

Important:
- this bundle contains the shared relay auth token;
- transfer it only over a trusted channel;
- do not leave it world-readable on shared machines.
- aegis-client.toml is the default installed baseline and does not enable DNS
  interception by default.
- relay.server is the dial target, while relay.server_name is the TLS/HTTP
  authority and may intentionally differ during IP fallback.
- relay.endpoints, when present, is the Phase C endpoint pool tried before
  terminal relay failure. Leave it absent for the backward-compatible single
  relay path.
- aegis-client-privileged-dns.toml is an opt-in profile for privileged
  linux_tproxy; set prerouting_interface before using it.

Recommended client-side install:
  ./install.sh client --bundle ${BUNDLE_DIR}
EOF

# `>` preserves the mode of an existing file.  Enforce the secret-bearing
# contract after every render as well as through the restrictive umask used for
# new files.
chmod 0600 \
  "${BUNDLE_DIR}/aegis-client.toml" \
  "${BUNDLE_DIR}/aegis-client-privileged-dns.toml" \
  "${BUNDLE_DIR}/README.txt" \
  "${BUNDLE_DIR}/ca.pem"

echo "Generated client bundle in ${BUNDLE_DIR}"
