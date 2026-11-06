#!/usr/bin/env bash
set -euo pipefail

# Generate a Cloudflare-fronted client bundle from an already-installed
# relay and (optionally) mint a one-time download token for it.
#
# Unlike the default bundle produced at server-install time — whose
# `relay.server` is the relay's own (direct origin) address — a fronted
# bundle dials a Cloudflare-fronted authority pool. No direct origin IP
# appears as the primary endpoint, no manual TOML editing is required,
# and no Cloudflare Origin CA pin is used (the client validates the
# Cloudflare public edge certificate against system roots).
#
# This is the hostile-network / RKN delivery path. It pairs with the
# server-side fix that serves `GET /bundle` over HTTP/2 (so the token URL
# can point at the Cloudflare authority and download THROUGH Cloudflare),
# but it also works for out-of-band bundle-file delivery.
#
# It reuses scripts/render-client-bundle.sh (the official renderer) — it
# never hand-edits a generated TOML.

usage() {
  cat <<'EOF'
Usage:
  scripts/issue-fronted-bundle.sh \
    --config <aegis-server.toml> \
    --primary <fronted-authority[:port]> \
    [--failover <fronted-authority[:port]>]... \
    [--out <bundle.tar.gz>] \
    [--ca <ca-bundle-path>] \
    [--masque-ca <direct-origin-ca-path>] \
    [--masque-server <literal-ip:port>] \
    [--transport-priority grpc_stream] \
    [--issue-token] [--ttl-secs N] [--server-bin <path>]

Required:
  --config       Path to the relay's aegis-server.toml (auth_token is read from it).
  --primary      Primary Cloudflare-fronted authority, e.g. relay.example.invalid or relay.example.invalid:443.

Optional:
  --failover     Additional fronted authority for the failover pool (repeatable),
                 e.g. relay-b.example.com relay-c.example.com. A censor must block
                 ALL of them through Cloudflare at once to kill the tunnel.
  --out          Output tarball path (default: <config-dir>/client-bundle-fronted.tar.gz).
  --ca           CA file shipped in the bundle. Default: the system CA bundle, because
                 the Cloudflare public edge certificate validates against system roots.
                 Do NOT pass a Cloudflare Origin CA here for the fronted edge path.
  --masque-ca    Optional additional CA shipped as masque-ca.pem for a full-wide
                 client's direct MASQUE/UDP leg. This is commonly the Cloudflare
                 Origin Root. It is separate from --ca and never replaces edge trust.
  --masque-server  Optional direct UDP socket address for the primary relay,
                 e.g. 203.0.113.9:8443 or [2001:db8::9]:8443. The TLS authority
                 remains --primary. Include masque_derived in --transport-priority
                 when enabling this direct UDP leg.
  --transport-priority  Default: grpc_stream. The current https_ws client uses
                 RFC 8441 extended CONNECT, which the verified Cloudflare edge
                 contour refuses; do not re-enable it without a forced live proof.
  --issue-token  Also mint a one-time bundle token for the generated tarball and
                 write the Cloudflare-fronted access URL to a private file beside --out.
  --ttl-secs     Token TTL when --issue-token is set (default: 3600).
  --server-bin   Path to aegis-server (default: looked up on PATH, then
                 /usr/local/bin/aegis-server).

The bundle's auth_token is a shared secret. The script never prints it.
EOF
}

CONFIG=""
PRIMARY=""
FAILOVERS=()
OUT=""
CA=""
MASQUE_CA=""
MASQUE_SERVER=""
TRANSPORT_PRIORITY="grpc_stream"
ISSUE_TOKEN=0
TTL_SECS=3600
SERVER_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --primary) PRIMARY="$2"; shift 2 ;;
    --failover) FAILOVERS+=("$2"); shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --ca) CA="$2"; shift 2 ;;
    --masque-ca) MASQUE_CA="$2"; shift 2 ;;
    --masque-server) MASQUE_SERVER="$2"; shift 2 ;;
    --transport-priority) TRANSPORT_PRIORITY="$2"; shift 2 ;;
    --issue-token) ISSUE_TOKEN=1; shift ;;
    --ttl-secs) TTL_SECS="$2"; shift 2 ;;
    --server-bin) SERVER_BIN="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "${CONFIG}" || -z "${PRIMARY}" ]]; then
  echo "ERROR: --config and --primary are required" >&2
  usage >&2
  exit 1
fi
if [[ ! -f "${CONFIG}" ]]; then
  echo "ERROR: server config not found: ${CONFIG}" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RENDER="${SCRIPT_DIR}/render-client-bundle.sh"
PACKAGE="${SCRIPT_DIR}/package-client-bundle.sh"
if [[ ! -x "${RENDER}" && ! -f "${RENDER}" ]]; then
  echo "ERROR: renderer not found: ${RENDER}" >&2
  exit 1
fi
if [[ ! -x "${PACKAGE}" && ! -f "${PACKAGE}" ]]; then
  echo "ERROR: bundle packager not found: ${PACKAGE}" >&2
  exit 1
fi

CONFIG_DIR="$(cd "$(dirname "${CONFIG}")" && pwd)"

# Read the shared auth token from the server config without echoing it.
export -n AUTH_TOKEN
AUTH_TOKEN="$(sed -n 's/^auth_token *= *"\(.*\)"/\1/p' "${CONFIG}" | head -n1)"
if [[ -z "${AUTH_TOKEN}" ]]; then
  echo "ERROR: could not read auth_token from ${CONFIG}" >&2
  exit 1
fi

# Default CA = system trust bundle (Cloudflare edge cert is publicly trusted).
if [[ -z "${CA}" ]]; then
  for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [[ -f "${candidate}" ]]; then CA="${candidate}"; break; fi
  done
fi
if [[ -z "${CA}" || ! -f "${CA}" ]]; then
  echo "ERROR: no CA bundle found; pass --ca <path> (system CA bundle, NOT the origin CA)" >&2
  exit 1
fi
if [[ -n "${MASQUE_CA}" && ! -f "${MASQUE_CA}" ]]; then
  echo "ERROR: direct MASQUE CA not found: ${MASQUE_CA}" >&2
  exit 1
fi
if [[ -n "${MASQUE_SERVER}" ]]; then
  python3 -I -B - "${MASQUE_SERVER}" <<'PY'
import ipaddress, sys
value = sys.argv[1]
try:
    if value.startswith('['):
        host, port = value[1:].split(']:')
        assert isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    else:
        host, port = value.split(':')
        assert isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    assert '%' not in host and port.isascii() and port.isdecimal()
    assert str(int(port)) == port and 1 <= int(port) <= 65535
except (ValueError, AssertionError):
    sys.exit('ERROR: --masque-server requires a literal IP and port 1..65535')
PY
fi

add_default_port() { case "$1" in *:*) echo "$1" ;; *) echo "$1:443" ;; esac; }

PRIMARY_HOSTPORT="$(add_default_port "${PRIMARY}")"
PRIMARY_HOST="${PRIMARY%%:*}"

# Build the endpoint pool. Relay endpoint-pool semantics replace the top-level
# single endpoint when the list is present, so the primary MUST be the first
# list member whenever failovers are requested. Previously this helper emitted
# only the failovers, silently removing --primary from runtime selection.
ENDPOINTS=""
if ((${#FAILOVERS[@]})) || [[ -n "${MASQUE_SERVER}" ]]; then
  ENDPOINTS="${PRIMARY_HOSTPORT},${PRIMARY_HOST}"
  [[ -z "${MASQUE_SERVER}" ]] || ENDPOINTS+=",${MASQUE_SERVER}"
fi
for f in "${FAILOVERS[@]:-}"; do
  [[ -z "${f}" ]] && continue
  fhp="$(add_default_port "${f}")"
  fhost="${f%%:*}"
  if [[ -n "${ENDPOINTS}" ]]; then ENDPOINTS+=";"; fi
  ENDPOINTS+="${fhp},${fhost}"
done

if [[ -z "$SERVER_BIN" ]]; then
  SERVER_BIN="$(command -v aegis-server || true)"
  [[ -n "$SERVER_BIN" || ! -x /usr/local/bin/aegis-server ]] || SERVER_BIN=/usr/local/bin/aegis-server
fi
[[ "$SERVER_BIN" == /* && -x "$SERVER_BIN" ]] || { echo "Verified Rust private input reader required." >&2; exit 2; }
[[ "$("$SERVER_BIN" installer-secret version)" == installer-secret-v1 ]] || { echo "Private installer input protocol required." >&2; exit 2; }
OUT="${OUT:-${CONFIG_DIR}/client-bundle-fronted.tar.gz}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
BUNDLE_DIR="${WORK}/client-bundle"

# Render via the official renderer (no hand-editing of the TOML).
printf '%s' "$AUTH_TOKEN" | bash "${RENDER}" \
  "${BUNDLE_DIR}" \
  "${PRIMARY_HOSTPORT}" \
  "${PRIMARY_HOST}" \
  --auth-token-stdin \
  "${CA}" \
  "$SERVER_BIN" \
  "${ENDPOINTS}" \
  "${TRANSPORT_PRIORITY}" \
  "${MASQUE_CA}" >/dev/null

# The renderer binds the optional masque-ca.pem to relay.masque_ca_cert in
# both configurations, including fresh V2 SOCKS. Edge ca.pem remains separate.

# Sanity: the primary must be a fronted hostname, never a bare IP.
if [[ "${PRIMARY_HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: --primary must be a Cloudflare-fronted hostname, not a direct origin IP" >&2
  exit 1
fi

bash "${PACKAGE}" "${BUNDLE_DIR}" "${OUT}" >/dev/null
echo "Fronted client bundle written: ${OUT}"
echo "  primary  : ${PRIMARY_HOSTPORT} (server_name ${PRIMARY_HOST})"
if [[ -n "${ENDPOINTS}" ]]; then
  echo "  failovers: ${#FAILOVERS[@]} (primary retained first)"
fi
if [[ -n "${MASQUE_SERVER}" ]]; then
  echo "  direct UDP: explicitly configured"
fi
echo "  transports: ${TRANSPORT_PRIORITY}"
echo "  ca       : ${CA} (system trust for the Cloudflare public edge cert)"
if [[ -n "${MASQUE_CA}" ]]; then
  echo "  masque ca: bundled separately for the direct UDP leg"
fi

if [[ "${ISSUE_TOKEN}" -eq 1 ]]; then
  if [[ -z "${SERVER_BIN}" ]]; then
    SERVER_BIN="$(command -v aegis-server || true)"
    [[ -z "${SERVER_BIN}" && -x /usr/local/bin/aegis-server ]] && SERVER_BIN=/usr/local/bin/aegis-server
  fi
  if [[ -z "${SERVER_BIN}" ]]; then
    echo "WARN: aegis-server not found; skipping token issue. Re-run with --server-bin <path>." >&2
    exit 0
  fi
  echo
  echo "Minting one-time access into a private file (ttl ${TTL_SECS}s)."
  # No --public-cacert-pin: the fronted download validates the Cloudflare
  # public edge certificate against system roots (origin CA pin would be wrong
  # for the edge path). Requires the HTTP/2 /bundle fix to be deployed so the
  # download traverses Cloudflare (which negotiates h2 to origin).
  "${SERVER_BIN}" --config "${CONFIG}" bundle-token issue \
    --bundle-path "${OUT}" \
    --url-output "${OUT}.access-url.txt" \
    --ttl-secs "${TTL_SECS}" \
    --public-host "${PRIMARY_HOST}" \
    --public-port "${PRIMARY_HOSTPORT##*:}" \
    --comment "cloudflare-fronted bundle"
fi
