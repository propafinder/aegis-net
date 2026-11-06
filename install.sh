#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Separate opt-in Linux backend; no implicit full-wide/direct profile change.
if [[ "${1:-}" == geneva-bridge ]]; then
  shift
  exec bash "${ROOT}/tools/geneva/install-bridge.sh" "$@"
fi
if [[ "${1:-}" == relay-geneva-profile ]]; then
  shift
  exec bash "${ROOT}/tools/geneva/install-relay-profile.sh" "$@"
fi

if [[ "${1:-}" == relay-geneva-profile-remove ]]; then
  shift
  exec /bin/bash "${ROOT}/tools/geneva/uninstall-relay-profile.sh" "$@"
fi

# Explicit boot-policy administration. The opt-in is a separate operation so
# an install can never silently modify the image used by the next boot.
if [[ "${1:-}" == initrd-policy ]]; then
  shift
  exec /usr/bin/python3 -I -B "${ROOT}/scripts/lib/aegis_initrd_policy.py" "$@"
fi

SOURCE_LAYOUT=0
TARGET_DIR=""

if [[ -f "${ROOT}/Cargo.toml" && -d "${ROOT}/aegis-client" && -d "${ROOT}/aegis-server" ]]; then
  SOURCE_LAYOUT=1
fi
# Prebuilt root/service installations need neither a login HOME nor Rust tools.
if [[ "${SOURCE_LAYOUT}" -eq 1 && -n "${HOME:-}" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

usage() {
  cat <<'EOF'
AEGIS installer
===============

This installer works in two modes:
  1. From a git checkout / repo root (builds with cargo)
  2. From a release bundle (installs prebuilt binaries)

Usage:
  ./install.sh server [options]
  ./install.sh client [options]
  ./install.sh initrd-policy detect
  ./install.sh initrd-policy prepare-cloud --opt-in  # reviewed marker boot, before AUTO install
  ./install.sh initrd-policy restore-cloud --opt-in  # after complete AUTO removal
  ./install.sh initrd-policy prepare-classic --opt-in  # disable qualified external overlay config
  ./install.sh initrd-policy restore-classic --opt-in  # after verified ordinary-image restoration
  ./install.sh initrd-policy apply --opt-in  # local root only; reboot required
  ./install.sh initrd-policy uninstall

Server options:
  --prefix <path>          Install binaries into <path>/bin
  --config-dir <path>      Store server config/certs under this directory
  --state-dir <path>       Working directory for the server service/runtime
  --systemd-dir <path>     Install rendered systemd units into this directory
  --env-dir <path>         Install service env files into this directory
  --listen <addr:port>     Relay listen address (default: 0.0.0.0:8443)
  --relay-address <addr>   Dial target clients should use (default: verified DNS or IP fallback)
  --server-name <name>     TLS/HTTP authority for clients; may differ from --relay-address
  --relay-endpoint <server,server_name[,masque_server]>
                           Add a Phase C client endpoint-pool entry; may repeat
  --relay-transport-priority <comma-list>
                           Client relay transport priority (default: grpc_stream,https_ws,legacy_tls,masque_derived)
  --auth-token-file <path> Use an existing private relay credential instead of generating one
  --bundle-out <path>      Where to write the generated client bundle
  --bundle-archive-out <path>
                           Where to write the generated client bundle tar.gz
  --force                  Overwrite generated config/certs/bundle/service files
                           only after saving the current config diff

Client options:
  --abort-fresh-passive    Cancel a never-active first AUTO preparation after verified rollback
                           or guard was armed; preserve its protected recovery archive
  --profile <auto|name>    Automatic host adaptation by default; named profiles
                           retain advanced manual control
  --prefix <path>          Install binaries into <path>/bin
  --config-dir <path>      Store client config under this directory
  --state-dir <path>       Working directory for the client service/runtime
  --log-dir <path>         Directory for client runtime-events JSONL
  --systemd-dir <path>     Install rendered systemd units into this directory
  --env-dir <path>         Install service env files into this directory
  --bundle <path>          Install from a server-generated client bundle directory
  --bundle-url-file <path> Download using an existing private access URL record
  --device-id <id>         Prepare/resume device enrollment from a trusted public bundle
  --device-certificate <path>
                           Complete enrollment with the operator-issued public certificate
  --stage-auto-device-guard
                           Arm the assessed v2 device guard for an existing stopped AUTO owner
  --stage-auto-owner-receipt <path>
                           Protected source/provision receipt for that stopped owner
  --device-invitation-file <path>
                           Redeem a protected v3 invitation; omit to resume a saved request
  --relay-geneva-request <path>
  --relay-geneva-request-sha256 <digest>
  --relay-geneva-profile-manifest <path>
  --relay-geneva-profile-sha256 <digest>
                           Explicit host-bound relay Geneva for a first full-wide
                           device install; all four options are required together
  --identity-dir <path>    Protected device identity directory (default: /var/lib/aegis-identity/client)
                           Online v3 identities must remain under /var/lib outside installer state
  --masque-server <ip:port>  Preferred direct MASQUE/QUIC origin for the UDP leg; gRPC/H2 is fallback.
                           Cloudflare does not proxy MASQUE; this optional direct
                           attempt exposes its origin IP before the fronted fallback.
  --masque-ca <path>       CA bundle validating the direct MASQUE origin (e.g. the
                           CloudFlare Origin Root); scoped to the MASQUE leg only
  --geneva-strategy-file <path>
                           Geneva DSL program for full-wide-hybrid-geneva. Read
                           from a file to avoid shell-quoting damage; not a secret.
  --udp-carry              Carry generic v4 UDP (incl QUIC/443) over MASQUE via the
                           conntrack redirect proxy instead of fail-closing it.
                           Opt-in; UNSTABLE path; linux_redirect backend only.
  --force                  Overwrite generated config and copied CA cert
                           only after saving the current config diff

Examples:
  ./install.sh server --relay-address relay.example.org:8443 --server-name relay.example.org
  ./install.sh client --bundle /tmp/client-bundle
  ./install.sh client --profile full-wide-tun --masque-server 203.0.113.7:443 --masque-ca cf-origin-root.pem
  ./install.sh client --profile full-wide-tun --udp-carry --masque-server 203.0.113.7:443 --masque-ca cf-origin-root.pem
  ./install.sh client --profile full-wide-hybrid-geneva --geneva-strategy-file geneva.dsl --masque-server 203.0.113.7:443 --masque-ca cf-origin-root.pem
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

ROLE="$1"
shift
AEGIS_ROLE_ARGUMENT_COUNT=$#

PREFIX=""
CONFIG_DIR=""
STATE_DIR=""
LOG_DIR=""
SYSTEMD_DIR=""
ENV_DIR=""
LISTEN_ADDR="0.0.0.0:8443"
LISTEN_ADDR_EXPLICIT=0
RELAY_ADDRESS=""
SERVER_NAME=""
RELAY_ENDPOINTS=""
RELAY_TRANSPORT_PRIORITY="grpc_stream,https_ws,legacy_tls,masque_derived"
AUTH_TOKEN=""
export -n AUTH_TOKEN
AUTH_TOKEN_FILE=""
BUNDLE_OUT=""
BUNDLE_ARCHIVE_OUT=""
BUNDLE_PATH=""
BUNDLE_URL_FILE=""
BUNDLE_LOCAL_ONLY=0
DEVICE_ID=""
DEVICE_CERTIFICATE=""
DEVICE_INVITATION_FILE=""
DEVICE_BUNDLE_SCHEMA=""
DEVICE_INSTALL_READY=0
DEVICE_ONLINE=0
DEVICE_ONLINE_BUNDLE=""
DEVICE_IDENTITY_DIR=""
DEVICE_BUNDLE=0
DEVICE_PUBLIC_BUNDLE=""
DEVICE_PRODUCT_MODE=""
DEVICE_GUARD_ASSESSMENT=""
STAGE_AUTO_DEVICE_GUARD=0
STAGE_AUTO_OWNER_RECEIPT=""
DEVICE_RELAY_GENEVA_REQUEST=""
DEVICE_RELAY_GENEVA_REQUEST_SHA256=""
DEVICE_RELAY_GENEVA_MANIFEST=""
DEVICE_RELAY_GENEVA_MANIFEST_SHA256=""
RELAY_TRANSPORT_PRIORITY_EXPLICIT=0
FORCE=0
AUTO_ISSUE_TOKEN=1
BUNDLE_CACERT_PIN=""
BUNDLE_INSECURE=0
REINSTALL_MODE=""  # "" → prompt if TTY else upgrade; "upgrade" / "reinstall" → forced
OPERATOR_MODE=""        # optional internal operator mode selector (validated below)
OPERATOR_TRANSPORT=""   # optional relay transport preference
FRONTED_AUTHORITY=""    # optional Cloudflare-fronted authority (host)
MASQUE_SERVER=""        # optional direct MASQUE/QUIC origin (ip:port) for the UDP leg
MASQUE_CA=""            # optional CA bundle validating the direct MASQUE origin
GENEVA_STRATEGY_FILE="" # Geneva DSL file required by full-wide-hybrid-geneva
UDP_CARRY=0             # when 1 (--udp-carry), carry generic v4 UDP (incl QUIC/443)
                        # over the UDP relay plan via the conntrack proxy instead of
                        # fail-closing it. Opt-in; rides the generic_capture_unstable
                        # path. Only meaningful with a linux_redirect wide backend.
# User-facing wide PRODUCT mode (socks-only|wide-redirect-safe|wide-udp-direct|
# gateway-tproxy|full-wide-nfqueue|full-wide-tun|full-wide-hybrid-geneva|
# wide-compat). Maps to an internal OPERATOR_MODE
# + explicit per-class policy via the Rust-owned `aegis-client profile` model.
PRODUCT_MODE="${AEGIS_INSTALL_PROFILE:-${AEGIS_INSTALL_MODE:-}}"
AUTO_PROFILE=0
AUTO_V2_REQUESTED_MODE=""
AUTO_V2_RESUME_UPGRADE=0
AUTO_V2_ABORT_FRESH_PASSIVE=0
AUTO_V2_VERIFY_BOOT=0
AUTO_V2_BOOT_INSTALL_FD="" AUTO_V2_BOOT_GUARD_FD="" AUTO_V2_BOOT_MODE=""
AUTO_FRESH_PACKAGE=0 AUTO_FRESH_PACKAGE_ROOT=""
AUTO_V2_PASSIVE_PHASE="" AUTO_V2_PASSIVE_BUNDLE=""
AUTO_V2_PASSIVE_ORIGIN=""
AUTO_V2_PASSIVE_STATUS="" AUTO_V2_LOCATED_STATUS="" AUTO_V2_LOCATED_ROOT=""
AUTO_V2_LOCATED_ORIGINAL="" AUTO_V2_LOCATED_SNAPSHOT="" AUTO_V2_LOCATED_ORIGIN=""
CLIENT_PACKAGE=""
AUTO_PLAN_PATH=""
PREFLIGHT_CLIENT_BINARY=""
WIDE_INTERFACE="${AEGIS_WIDE_INTERFACE:-}"           # informational egress iface
WIDE_UDP_POLICY="${AEGIS_WIDE_UDP_POLICY:-}"         # override: native|block|masque_direct|preview_allowlist
WIDE_DNS_POLICY="${AEGIS_WIDE_DNS_POLICY:-}"         # override: native|preview|block
WIDE_IPV6_POLICY="${AEGIS_WIDE_IPV6_POLICY:-}"       # override: native|block|capture
# Resolved policy strings (filled by resolve_wide_policies from the Rust model).
RES_UDP_POLICY="" RES_DNS_POLICY="" RES_IPV6_POLICY="" RES_LEAK_RISK=""
NO_RUNTIME_EVENTS=0     # when 1, the client writes no on-disk runtime events
TEMP_PATHS=()
INSTALL_SOURCE_MANIFEST_URL="${AEGIS_INSTALL_SOURCE_MANIFEST_URL:-}"
INSTALL_SOURCE_RELEASE_CHANNEL="${AEGIS_INSTALL_SOURCE_RELEASE_CHANNEL:-}"

cleanup_temp_paths() {
  local path=""
  for path in "${TEMP_PATHS[@]:-}"; do
    if [[ -e "${path}" ]]; then
      rm -rf "${path}"
    fi
  done
}

trap cleanup_temp_paths EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --abort-fresh-passive)
      [[ "$ROLE" == client && "$AEGIS_ROLE_ARGUMENT_COUNT" == 1 &&
         "$SOURCE_LAYOUT" == 0 && "$EUID" == 0 && "$(uname -s)" == Linux ]] || {
        echo '--abort-fresh-passive requires Linux root and an administrative release bundle; use it alone.' >&2
        exit 2
      }
      AUTO_V2_ABORT_FRESH_PASSIVE=1
      shift
      ;;
    --verify-v2-boot-host)
      [[ $# -ge 4 && "$AUTO_V2_VERIFY_BOOT" == 0 && "$2" =~ ^[1-9][0-9]{0,9}$ && "$3" =~ ^[1-9][0-9]{0,9}$ && "$2" != "$3" && ( "$4" == full-wide-tun || "$4" == wide-redirect-safe ) ]] || exit 2
      AUTO_V2_VERIFY_BOOT=1;AUTO_V2_BOOT_INSTALL_FD="$2";AUTO_V2_BOOT_GUARD_FD="$3";AUTO_V2_BOOT_MODE="$4"
      shift 4
      ;;
    --client-package)
      [[ $# -ge 2 && -z "$CLIENT_PACKAGE" ]] || exit 2
      CLIENT_PACKAGE="$2"
      shift 2
      ;;
    --resume-v2-upgrade)
      [[ "$AUTO_V2_RESUME_UPGRADE" == 0 ]] || exit 2
      AUTO_V2_RESUME_UPGRADE=1
      shift
      ;;
    --mode|--operator-mode)
      OPERATOR_MODE="$2"
      shift 2
      ;;
    --profile)
      PRODUCT_MODE="$2"
      shift 2
      ;;
    --wide-interface)
      WIDE_INTERFACE="$2"
      shift 2
      ;;
    --udp-policy)
      WIDE_UDP_POLICY="$2"
      shift 2
      ;;
    --dns-policy)
      WIDE_DNS_POLICY="$2"
      shift 2
      ;;
    --ipv6-policy)
      WIDE_IPV6_POLICY="$2"
      shift 2
      ;;
    --transport)
      OPERATOR_TRANSPORT="$2"
      shift 2
      ;;
    --fronted-authority)
      FRONTED_AUTHORITY="$2"
      shift 2
      ;;
    --masque-server)
      # Direct MASQUE/QUIC origin (ip:port) for the UDP leg. Cloudflare 405s
      # MASQUE. This origin is preferred for UDP; gRPC/H2 remains the fallback.
      MASQUE_SERVER="$2"
      shift 2
      ;;
    --masque-ca)
      # CA bundle that validates the direct MASQUE origin's cert (e.g. the
      # CloudFlare Origin Root when the origin is behind CF). Scoped to the
      # MASQUE leg only; the fronted TCP path keeps its own trust.
      MASQUE_CA="$2"
      shift 2
      ;;
    --geneva-strategy-file)
      GENEVA_STRATEGY_FILE="$2"
      shift 2
      ;;
    --udp-carry)
      # Opt-in generic v4 UDP carry (incl QUIC/443) over the relay plan via conntrack
      # redirect proxy. Sets udp_capture_contract=generic_capture_unstable and, at
      # apply time, redirects v4 UDP to the proxy instead of fail-closing it.
      UDP_CARRY=1
      shift
      ;;
    --no-runtime-events)
      NO_RUNTIME_EVENTS=1
      shift
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="$2"
      shift 2
      ;;
    --systemd-dir)
      SYSTEMD_DIR="$2"
      shift 2
      ;;
    --env-dir)
      ENV_DIR="$2"
      shift 2
      ;;
    --listen)
      LISTEN_ADDR="$2"
      LISTEN_ADDR_EXPLICIT=1
      shift 2
      ;;
    --relay-address)
      RELAY_ADDRESS="$2"
      shift 2
      ;;
    --server-name)
      SERVER_NAME="$2"
      shift 2
      ;;
    --relay-endpoint)
      if [[ -n "${RELAY_ENDPOINTS}" ]]; then
        RELAY_ENDPOINTS+=";"
      fi
      RELAY_ENDPOINTS+="$2"
      shift 2
      ;;
    --relay-transport-priority)
      RELAY_TRANSPORT_PRIORITY="$2"
      RELAY_TRANSPORT_PRIORITY_EXPLICIT=1
      shift 2
      ;;
    --auth-token|--auth-token=*|--bundle-url|--bundle-url=*)
      echo "Inline installer secrets are refused; use --auth-token-file or --bundle-url-file." >&2
      exit 2
      ;;
    --auth-token-file)
      [[ $# -ge 2 && -z "$AUTH_TOKEN_FILE" ]] || exit 2
      AUTH_TOKEN_FILE="$2"
      shift 2
      ;;
    --bundle-out)
      BUNDLE_OUT="$2"
      shift 2
      ;;
    --bundle-archive-out)
      BUNDLE_ARCHIVE_OUT="$2"
      shift 2
      ;;
    --bundle)
      BUNDLE_PATH="$2"
      shift 2
      ;;
    --device-id)
      DEVICE_ID="$2"
      shift 2
      ;;
    --device-invitation-file)
      DEVICE_INVITATION_FILE="$2"
      shift 2
      ;;
    --relay-geneva-request)
      [[ -z "$DEVICE_RELAY_GENEVA_REQUEST" && $# -ge 2 ]] || exit 2
      DEVICE_RELAY_GENEVA_REQUEST="$2"
      shift 2
      ;;
    --relay-geneva-request-sha256)
      [[ -z "$DEVICE_RELAY_GENEVA_REQUEST_SHA256" && $# -ge 2 ]] || exit 2
      DEVICE_RELAY_GENEVA_REQUEST_SHA256="$2"
      shift 2
      ;;
    --relay-geneva-profile-manifest)
      [[ -z "$DEVICE_RELAY_GENEVA_MANIFEST" && $# -ge 2 ]] || exit 2
      DEVICE_RELAY_GENEVA_MANIFEST="$2"
      shift 2
      ;;
    --relay-geneva-profile-sha256)
      [[ -z "$DEVICE_RELAY_GENEVA_MANIFEST_SHA256" && $# -ge 2 ]] || exit 2
      DEVICE_RELAY_GENEVA_MANIFEST_SHA256="$2"
      shift 2
      ;;
    --device-certificate)
      DEVICE_CERTIFICATE="$2"
      shift 2
      ;;
    --stage-auto-device-guard)
      STAGE_AUTO_DEVICE_GUARD=1
      shift
      ;;
    --stage-auto-owner-receipt)
      [[ $# -ge 2 && -z "$STAGE_AUTO_OWNER_RECEIPT" ]] || exit 2
      STAGE_AUTO_OWNER_RECEIPT="$2"
      shift 2
      ;;
    --identity-dir)
      DEVICE_IDENTITY_DIR="$2"
      shift 2
      ;;
    --bundle-url-file)
      [[ $# -ge 2 && -z "$BUNDLE_URL_FILE" ]] || exit 2
      BUNDLE_URL_FILE="$2"
      shift 2
      ;;
    --bundle-local-only)
      BUNDLE_LOCAL_ONLY=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --no-auto-token)
      # Server role: skip the auto-issued first /bundle token after install.
      # Operator will run `aegis-server bundle-token issue` manually.
      AUTO_ISSUE_TOKEN=0
      shift
      ;;
    --no-auto-start)
      # Server role: skip systemctl enable --now after writing units.
      AEGIS_INSTALL_FORCE_SYSTEMD_ACTIVATE=0
      export AEGIS_INSTALL_FORCE_SYSTEMD_ACTIVATE
      shift
      ;;
    --bundle-cacert-pin)
      # v0.3.1: SPKI pin for bundle download TLS validation. Format
      # accepts "sha256//<base64>" or just "<base64>" (canonicalised
      # to "sha256//<base64>" before passing to curl --pinnedpubkey).
      BUNDLE_CACERT_PIN="$2"
      shift 2
      ;;
    --insecure)
      # v0.3.1: skip TLS validation for bundle download (TOFU mode).
      # Use only over an out-of-band trusted channel for the URL.
      # Stronger alternative: --bundle-cacert-pin from operator.
      BUNDLE_INSECURE=1
      shift
      ;;
    --reinstall)
      # Detect existing install and run scripts/purge-installed-aegis.sh
      # before installing fresh. DESTROYS old auth_token, state.json, and
      # all systemd unit + config residue under /etc/aegis + /var/lib/aegis.
      REINSTALL_MODE=reinstall
      shift
      ;;
    --upgrade)
      # Reapply binary + render config in place; reuse existing auth_token
      # and state.json. This is also the default for non-interactive runs.
      REINSTALL_MODE=upgrade
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$STAGE_AUTO_DEVICE_GUARD" == 1 ]]; then
  [[ "$ROLE" == client && -n "$STAGE_AUTO_OWNER_RECEIPT" && "$REINSTALL_MODE" != reinstall &&
     -n "$BUNDLE_PATH" && -z "$BUNDLE_URL_FILE" && -n "$DEVICE_ID" && -n "$DEVICE_CERTIFICATE" &&
     "$PRODUCT_MODE" == full-wide-tun ]] || {
    echo 'Staged AUTO guard requires client, full-wide-tun, a ready v2 device bundle and a protected owner receipt.' >&2
    exit 2
  }
elif [[ -n "$STAGE_AUTO_OWNER_RECEIPT" ]]; then
  echo '--stage-auto-owner-receipt requires --stage-auto-device-guard.' >&2
  exit 2
fi

if [[ "${ROLE}" != client && -n "${DEVICE_ID}${DEVICE_CERTIFICATE}${DEVICE_IDENTITY_DIR}${DEVICE_INVITATION_FILE:-}" ]]; then
  echo "Device enrollment options apply only to the client role." >&2
  exit 2
fi

if [[ -n "${DEVICE_RELAY_GENEVA_REQUEST}${DEVICE_RELAY_GENEVA_REQUEST_SHA256}${DEVICE_RELAY_GENEVA_MANIFEST}${DEVICE_RELAY_GENEVA_MANIFEST_SHA256}" ]]; then
  [[ "$ROLE" == client && "$(uname -s)" == Linux && "$EUID" == 0 && -n "$DEVICE_ID" &&
     "$DEVICE_RELAY_GENEVA_REQUEST" == /* && "$DEVICE_RELAY_GENEVA_MANIFEST" == /* &&
     "$DEVICE_RELAY_GENEVA_REQUEST_SHA256" =~ ^[a-f0-9]{64}$ &&
     "$DEVICE_RELAY_GENEVA_MANIFEST_SHA256" =~ ^[a-f0-9]{64}$ ]] || {
    echo 'Relay Geneva requires all four pinned local options and a Linux root device installation.' >&2
    exit 2
  }
fi

# Operator mode selector: validate + normalize aliases to the canonical slug used
# by `aegis-client operator`. Empty = unchanged default behavior. Invalid = fail.
normalize_operator_mode() {
  case "$1" in
    server) echo "server" ;;
    socks|client-socks) echo "client-socks" ;;
    wide-redirect|client-wide-redirect) echo "client-wide-redirect" ;;
    wide-tproxy|client-wide-tproxy) echo "client-wide-tproxy" ;;
    nfqueue-observer|client-wide-nfqueue-observer) echo "client-wide-nfqueue-observer" ;;
    ipv6-tun-lab|client-ipv6-tun-lab) echo "client-ipv6-tun-lab" ;;
    ipv6-tun-smoltcp|client-ipv6-tun-smoltcp) echo "client-ipv6-tun-smoltcp" ;;
    cloudflare-fronted) echo "cloudflare-fronted" ;;
    masque-direct) echo "masque-direct" ;;
    *) return 1 ;;
  esac
}
# Map a user-facing PRODUCT mode to the internal operator mode it activates. The
# per-class POLICY (udp/dns/ipv6/leak-risk) is owned by the Rust model
# (`aegis-client profile`), NOT re-encoded here — this only picks the backend.
product_mode_to_operator() {
  case "$1" in
    socks-only)         echo "client-socks" ;;
    wide-redirect-safe) echo "client-wide-redirect" ;;
    wide-udp-direct)    echo "client-wide-redirect" ;;
    gateway-tproxy)     echo "client-wide-tproxy" ;;
    full-wide-nfqueue)  echo "client-wide-nfqueue-observer" ;;
    full-wide-tun)      echo "client-ipv6-tun-smoltcp" ;;
    full-wide-hybrid-geneva) echo "client-ipv6-tun-smoltcp" ;;
    wide-compat)        echo "client-wide-redirect" ;;
    *) return 1 ;;
  esac
}
is_product_mode() { product_mode_to_operator "$1" >/dev/null 2>&1; }
PRODUCT_MODE_LIST="socks-only, wide-redirect-safe, wide-udp-direct, gateway-tproxy, full-wide-nfqueue, full-wide-tun, full-wide-hybrid-geneva, wide-compat"

# Back-compat: if --mode was actually given a PRODUCT mode string, treat it as
# --profile so users can use either flag interchangeably.
if [[ -n "${OPERATOR_MODE}" ]] && { is_product_mode "${OPERATOR_MODE}" || [[ "${OPERATOR_MODE}" == "auto" ]]; }; then
  PRODUCT_MODE="${OPERATOR_MODE}"
  OPERATOR_MODE=""
fi
# Resolve a chosen product mode to its internal operator mode.
if [[ "${ROLE}" == "client" && -z "${PRODUCT_MODE}" && -z "${OPERATOR_MODE}" ]]; then
  PRODUCT_MODE="auto"
fi
if [[ "${PRODUCT_MODE}" == "auto" ]]; then
  if [[ "${ROLE}" != "client" || -n "${OPERATOR_MODE}${WIDE_UDP_POLICY}${WIDE_DNS_POLICY}${WIDE_IPV6_POLICY}${OPERATOR_TRANSPORT}${FRONTED_AUTHORITY}${GENEVA_STRATEGY_FILE}" || "${UDP_CARRY}" == "1" ]]; then
    echo "Automatic client installation cannot be combined with manual mode/policy overrides; choose an explicit --profile." >&2
    exit 2
  fi
  AUTO_PROFILE=1
elif [[ -n "${PRODUCT_MODE}" ]]; then
  if ! OPERATOR_MODE="$(product_mode_to_operator "${PRODUCT_MODE}")"; then
    echo "Invalid --profile/--mode product mode '${PRODUCT_MODE}'. Valid: ${PRODUCT_MODE_LIST}" >&2
    exit 2
  fi
fi

# These product profiles promise carried UDP. Make that promise real by
# activating the generic capture path automatically; a user must not need to
# discover an extra --udp-carry flag after selecting full-wide.
if [[ "${PRODUCT_MODE}" == "full-wide-tun" || "${PRODUCT_MODE}" == "full-wide-hybrid-geneva" ]]; then
  UDP_CARRY=1
fi
# Normalize an explicit internal operator mode (also covers the slug emitted above).
if [[ -n "${OPERATOR_MODE}" ]]; then
  if ! OPERATOR_MODE="$(normalize_operator_mode "${OPERATOR_MODE}")"; then
    echo "Invalid --mode (known products: ${PRODUCT_MODE_LIST}; or internal: server, socks, wide-redirect, wide-tproxy, nfqueue-observer, ipv6-tun-lab, ipv6-tun-smoltcp, cloudflare-fronted, masque-direct)" >&2
    exit 2
  fi
fi

# The Geneva hybrid profile is deliberately impossible to select without its
# complete direct + relay inputs. Accept bundle-carried files as defaults for an
# on-disk bundle; bundle URLs must provide the files explicitly because they have
# not been downloaded at this early fail-fast validation boundary.
if [[ "${PRODUCT_MODE}" == "full-wide-hybrid-geneva" ]]; then
  if [[ -z "${GENEVA_STRATEGY_FILE}" && -n "${BUNDLE_PATH}" && -f "${BUNDLE_PATH}/geneva.strategy" ]]; then
    GENEVA_STRATEGY_FILE="${BUNDLE_PATH}/geneva.strategy"
  fi
  if [[ -z "${MASQUE_CA}" && -n "${BUNDLE_PATH}" && -f "${BUNDLE_PATH}/masque-ca.pem" ]]; then
    MASQUE_CA="${BUNDLE_PATH}/masque-ca.pem"
  fi
  if [[ -z "${GENEVA_STRATEGY_FILE}" || ! -s "${GENEVA_STRATEGY_FILE}" ]]; then
    echo "full-wide-hybrid-geneva requires a non-empty --geneva-strategy-file (or bundle/geneva.strategy)." >&2
    exit 2
  fi
  if [[ -z "${MASQUE_SERVER}" ]]; then
    echo "full-wide-hybrid-geneva requires --masque-server for the direct UDP leg." >&2
    exit 2
  fi
  if [[ -z "${MASQUE_CA}" || ! -s "${MASQUE_CA}" ]]; then
    echo "full-wide-hybrid-geneva requires a readable --masque-ca (or bundle/masque-ca.pem)." >&2
    exit 2
  fi
  if [[ -n "${WIDE_UDP_POLICY}" && "${WIDE_UDP_POLICY}" != "masque_direct" ]]; then
    echo "full-wide-hybrid-geneva has fixed udp_policy=masque_direct; override rejected." >&2
    exit 2
  fi
  if [[ -n "${WIDE_DNS_POLICY}" && "${WIDE_DNS_POLICY}" != "preview" ]]; then
    echo "full-wide-hybrid-geneva has fixed dns_policy=preview; override rejected." >&2
    exit 2
  fi
  if [[ -n "${WIDE_IPV6_POLICY}" && "${WIDE_IPV6_POLICY}" != "tun_carried" ]]; then
    echo "full-wide-hybrid-geneva has fixed ipv6_policy=tun_carried; override rejected." >&2
    exit 2
  fi
  # Unlike full-wide-tun's historical optional flag, the hybrid route matrix
  # promises UDP carry and therefore enables its redirect leg unconditionally.
  UDP_CARRY=1
fi
# Record the selected operator mode into the config (a comment marker — never
# mutates parsed fields or secrets) and a status-metadata JSON. Safe no-op when no
# mode was selected, preserving the historical default install behavior.
record_operator_mode() {
  local cfg="$1" state_dir="$2"
  state_dir="$(dirname "$(install_manifest_path_for_role client "${state_dir}")")"
  [[ -z "${OPERATOR_MODE}" ]] && return 0
  if [[ -f "${cfg}" ]] && ! grep -q "aegis-operator-mode:" "${cfg}" 2>/dev/null; then
    {
      printf '# aegis-operator-mode: %s\n' "${OPERATOR_MODE}"
      [[ -n "${OPERATOR_TRANSPORT}" ]] && printf '# aegis-operator-transport: %s\n' "${OPERATOR_TRANSPORT}"
      [[ -n "${FRONTED_AUTHORITY}" ]] && printf '# aegis-fronted-authority: %s\n' "${FRONTED_AUTHORITY}"
    } >> "${cfg}"
  fi
  if [[ -n "${state_dir}" ]]; then
    printf '{"operator_mode":"%s","transport":"%s","fronted_authority":"%s"}\n' \
      "${OPERATOR_MODE}" "${OPERATOR_TRANSPORT}" "${FRONTED_AUTHORITY}" \
      | install_atomic_write "${state_dir}/operator-mode.json" 0644 strict
  fi
  if [[ "${AUTO_PROFILE}" != "1" && ( "${OPERATOR_MODE}" == "client-wide-nfqueue-observer" || "${OPERATOR_MODE}" == "client-ipv6-tun-lab" || "${OPERATOR_MODE}" == "client-ipv6-tun-smoltcp" ) ]]; then
    echo "Note: '${OPERATOR_MODE}' is a privileged advanced mode. After install, run:" >&2
    echo "      sudo aegis-client operator apply --mode ${OPERATOR_MODE} --apply-confirm" >&2
  fi
}

# Resolve the per-class policy (udp/dns/ipv6/leak-risk) for the selected product
# mode by asking the Rust-owned model — the single source of truth. Also enforces
# the safety gate: a safe mode given a native override makes the binary exit
# nonzero, which we propagate. Fills RES_* globals. No-op without a product mode.
resolve_wide_policies() {
  local bin="$1" json
  [[ -z "${PRODUCT_MODE}" ]] && return 0
  [[ "${PRODUCT_MODE}" == "socks-only" ]] && return 0
  [[ -x "${bin}" ]] || return 0
  local extra=()
  [[ -n "${WIDE_UDP_POLICY}" ]] && extra+=(--udp "${WIDE_UDP_POLICY}")
  [[ -n "${WIDE_DNS_POLICY}" ]] && extra+=(--dns "${WIDE_DNS_POLICY}")
  [[ -n "${WIDE_IPV6_POLICY}" ]] && extra+=(--ipv6 "${WIDE_IPV6_POLICY}")
  if ((${#extra[@]})); then
    json="$("${bin}" profile resolve --mode "${PRODUCT_MODE}" "${extra[@]}" --json 2>/dev/null)" || {
      echo "ERROR: policy resolution rejected for product mode '${PRODUCT_MODE}':" >&2
      "${bin}" profile resolve --mode "${PRODUCT_MODE}" "${extra[@]}" --json >&2 || true
      return 1
    }
  else
    json="$("${bin}" profile resolve --mode "${PRODUCT_MODE}" --json 2>/dev/null)" || {
      echo "ERROR: policy resolution rejected for product mode '${PRODUCT_MODE}':" >&2
      "${bin}" profile resolve --mode "${PRODUCT_MODE}" --json >&2 || true
      return 1
    }
  fi
  RES_UDP_POLICY="$(printf '%s' "${json}" | python3 -I -c 'import sys,json;print(json.load(sys.stdin).get("udp_policy",""))' 2>/dev/null)"
  RES_DNS_POLICY="$(printf '%s' "${json}" | python3 -I -c 'import sys,json;print(json.load(sys.stdin).get("dns_policy",""))' 2>/dev/null)"
  RES_IPV6_POLICY="$(printf '%s' "${json}" | python3 -I -c 'import sys,json;print(json.load(sys.stdin).get("ipv6_policy",""))' 2>/dev/null)"
  RES_LEAK_RISK="$(printf '%s' "${json}" | python3 -I -c 'import sys,json;print(json.load(sys.stdin).get("leak_risk",""))' 2>/dev/null)"
}

# Ask the candidate Rust binary to plan before the transaction's mutation
# boundary. A missing/old planner, malformed output or blocked host stops here.
resolve_auto_profile() {
  local candidate="$1" cfg="$2" state_dir="$3" selected="" parser=""
  state_dir="$(dirname "$(install_manifest_path_for_role client "${state_dir}")")"
  [[ "${AUTO_PROFILE}" == "1" ]] || return 0
  if [[ "${SYSTEMD_DIR}" != "/etc/systemd/system" ]]; then
    echo "Automatic activation requires the system service directory; use an explicit --profile for staged installations." >&2
    return 1
  fi
  AUTO_PLAN_PATH="$(mktemp "${TMPDIR:-/tmp}/aegis-auto-plan.XXXXXX")"
  TEMP_PATHS+=("${AUTO_PLAN_PATH}")
  if ! "${candidate}" profile auto --config "${cfg}" --state-dir "${state_dir}" --json > "${AUTO_PLAN_PATH}"; then
    python3 -I - "${AUTO_PLAN_PATH}" <<'PY' >&2 || true
import json, sys
try:
    p = json.load(open(sys.argv[1]))
    print(p.get('message', 'Automatic installation preflight failed.'))
    for reason in p.get('reasons', []):
        print('  ' + reason)
except (ValueError, OSError):
    pass
PY
    return 1
  fi
  IFS= read -r -d '' parser <<'PY' || true
import json, sys
p = json.load(open(sys.argv[1]))
if p.get('schema') != 'aegis_auto_install_plan_v1' or p.get('status') != 'planned' or p.get('connectivity_verified') is not False:
    raise SystemExit('Invalid automatic installation plan')
print(p['product_mode'])
print(p['message'], file=sys.stderr)
for reason in p.get('reasons', []):
    print('  ' + reason, file=sys.stderr)
PY
  selected="$(printf '%s' "${parser}" | python3 -I - "${AUTO_PLAN_PATH}")" || return 1
  OPERATOR_MODE="$(product_mode_to_operator "${selected}")" || return 1
  PRODUCT_MODE="${selected}"
  [[ "${PRODUCT_MODE}" != "full-wide-tun" ]] || UDP_CARRY=1
  resolve_wide_policies "${candidate}"
}

# An automatic in-place upgrade without a new access bundle keeps the config
# that was validated during preflight. Never replace its relay credentials and
# endpoint policy with the example after stopping the old service.
install_client_config_without_bundle() {
  local cfg="$1"
  if [[ "${AUTO_PROFILE:-0}" == "1" && -f "${cfg}" ]]; then
    echo "Keeping existing client configuration."
    return 0
  fi
  install_copy_file "${ROOT}/config.example.toml" "${cfg}" 0600
}

# Record the selected product mode + resolved policies so `aegis-client profile
# show` / `wide status` work post-install without root.
record_product_mode() {
  local state_dir="$1"
  state_dir="$(dirname "$(install_manifest_path_for_role client "${state_dir}")")"
  [[ -z "${PRODUCT_MODE}" || -z "${state_dir}" ]] && return 0
  printf '{"product_mode":"%s","udp_policy":"%s","dns_policy":"%s","ipv6_policy":"%s","leak_risk":"%s","interface":"%s"}\n' \
    "${PRODUCT_MODE}" "${RES_UDP_POLICY}" "${RES_DNS_POLICY}" "${RES_IPV6_POLICY}" "${RES_LEAK_RISK}" "${WIDE_INTERFACE}" \
    | install_atomic_write "${state_dir}/wide-profile.json" 0644 strict
}

# Persistent path for the wide setup helpers so teardown works long after the
# temporary install payload is gone.
AEGIS_WIDE_LIB_DIR="/usr/local/lib/aegis"
AEGIS_HYBRID_DIRECT_SOCKET_MARK=44641

# Turn the rendered client config into a wide-ingress config (primary=wide +
# backend + a loopback listener matching the redirect port). Idempotent.
set_client_config_wide() {
  local cfg="$1" backend="$2" port="$3"
  python3 -I - "$cfg" "$backend" "$port" "${WIDE_INTERFACE:-}" <<'PY'
import re, sys
p, backend, port = sys.argv[1], sys.argv[2], sys.argv[3]
iface = sys.argv[4] if len(sys.argv) > 4 else ""
t = open(p).read()
# TPROXY (gateway-tproxy / linux_tproxy) preserves the original destination and
# the mangle rule redirects with `--on-ip 0.0.0.0`, so the transparent listener
# MUST bind 0.0.0.0 or the kernel socket lookup never matches and downstream
# (routed) traffic is silently NOT captured. REDIRECT rewrites the dst to the
# loopback listener, so 127.0.0.1 stays correct there. Proven in the arm64
# gateway drill: 127.0.0.1 => zero capture; 0.0.0.0 => device egress flips to
# the relay.
listen_host = "0.0.0.0" if backend == "linux_tproxy" else "127.0.0.1"
# ingress.primary = "wide"
if re.search(r'(?m)^\s*\[ingress\]\s*$', t):
    if re.search(r'(?ms)^\[ingress\]\s*$.*?^\s*primary\s*=', t):
        t = re.sub(r'(?ms)(^\[ingress\]\s*$.*?^\s*primary\s*=\s*")[^"]*(")', r'\g<1>wide\g<2>', t, count=1)
    else:
        t = re.sub(r'(?m)^(\[ingress\]\s*)$', r'\1\nprimary = "wide"', t, count=1)
else:
    t = '[ingress]\nprimary = "wide"\n' + t
# ingress.wide section: enabled + platform_backend + listen
if re.search(r'(?m)^\s*\[ingress\.wide\]\s*$', t):
    block = re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)', t).group(0)
    nb = block
    def setkv(b, key, val):
        if re.search(r'(?m)^\s*%s\s*=' % key, b):
            return re.sub(r'(?m)^(\s*%s\s*=\s*).*$' % key, r'\g<1>%s' % val, b, count=1)
        return b.rstrip()+'\n'+key+' = '+val+'\n'
    nb = setkv(nb, 'enabled', 'true')
    nb = setkv(nb, 'platform_backend', '"%s"' % backend)
    nb = setkv(nb, 'listen', '"%s:%s"' % (listen_host, port))
    # P0: linux_tproxy REQUIRES the transparent_privileged rollout + a non-zero
    # fwmark. The pre-built bundle ships rollout_profile="output_only_safe" +
    # default_mark=0, which the client rejects as incompatible with an explicit
    # linux_tproxy backend (readiness=ConfigError → the client never binds the
    # transparent listener → gateway capture silently dead, downstream traffic
    # falls through to NAT). Setting them here is what makes gateway-tproxy start.
    # capture_dns is turned off: on a routed gateway the downstream device's DNS
    # is served/forwarded separately, not captured by the box's own client.
    if backend == "linux_tproxy":
        nb = setkv(nb, 'rollout_profile', '"transparent_privileged"')
        nb = setkv(nb, 'default_mark', '1')
        nb = setkv(nb, 'capture_dns', 'false')
        if iface:
            nb = setkv(nb, 'prerouting_interface', '"%s"' % iface)
    t = t.replace(block, nb)
else:
    extra = ""
    if backend == "linux_tproxy":
        extra += 'rollout_profile = "transparent_privileged"\ndefault_mark = 1\ncapture_dns = false\n'
        if iface:
            extra += 'prerouting_interface = "%s"\n' % iface
    t += '\n[ingress.wide]\nenabled = true\nplatform_backend = "%s"\nlisten = "%s:%s"\n%s' % (backend, listen_host, port, extra)
open(p, "w").write(t)
PY
}

# Set [ingress.wide] ipv6_tun_carried (full-wide-tun gate). Idempotent. When true,
# the client launches the production IPv6 TUN+smoltcp engine alongside the v4 leg.
set_client_config_ipv6_tun() {
  local cfg="$1" val="$2"
  python3 -I - "$cfg" "$val" <<'PY'
import re, sys
p, val = sys.argv[1], sys.argv[2]
t = open(p).read()
if re.search(r'(?m)^\s*\[ingress\.wide\]\s*$', t):
    block = re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)', t).group(0)
    if re.search(r'(?m)^\s*ipv6_tun_carried\s*=', block):
        nb = re.sub(r'(?m)^(\s*ipv6_tun_carried\s*=\s*).*$', r'\g<1>%s' % val, block, count=1)
    else:
        nb = block.rstrip() + '\nipv6_tun_carried = %s\n' % val
    t = t.replace(block, nb)
else:
    t += '\n[ingress.wide]\nipv6_tun_carried = %s\n' % val
open(p, "w").write(t)
PY
}

# Set [ingress.wide] udp_capture_contract. For --udp-carry we set
# "generic_capture_unstable" so the client daemon spawns the conntrack UDP redirect
# proxy (wide listen port + 1) that carries generic v4 UDP -- incl QUIC/443 -- over
# MASQUE. Idempotent; never touches secrets.
set_client_config_udp_contract() {
  local cfg="$1" val="$2"
  python3 -I - "$cfg" "$val" <<'PY'
import re, sys
p, val = sys.argv[1], sys.argv[2]
t = open(p).read()
if re.search(r'(?m)^\s*\[ingress\.wide\]\s*$', t):
    block = re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)', t).group(0)
    if re.search(r'(?m)^\s*udp_capture_contract\s*=', block):
        nb = re.sub(r'(?m)^(\s*udp_capture_contract\s*=\s*).*$', r'\g<1>"%s"' % val, block, count=1)
    else:
        nb = block.rstrip() + '\nudp_capture_contract = "%s"\n' % val
    t = t.replace(block, nb)
else:
    t += '\n[ingress.wide]\nudp_capture_contract = "%s"\n' % val
open(p, "w").write(t)
PY
}

# A reused full-wide bundle can retain carry flags even when host planning
# selects the limited profile. Clear those requests before the first service
# start so the runtime does not launch engines excluded by the selected policy.
normalize_auto_limited_config() {
  local cfg="$1"
  [[ "${AUTO_PROFILE:-0}" == "1" && "${PRODUCT_MODE:-}" == "wide-redirect-safe" ]] || return 0
  set_client_config_ipv6_tun "$cfg" false
  set_client_config_udp_contract "$cfg" "preview_allowlist_only"
}

# Arm the legacy TUN privacy policy before restarting the wide client. The
# capture unit below remains disposable; only explicit operator disconnect may
# release this independent deny table. Device enrollment owns its own guard.
install_legacy_tun_guard_unit() {
  local setup="$1" port="$2" udp_port="$3"
  local state=/var/lib/aegis-install/client/legacy-tun-guard.conf candidate manager
  [[ "$SYSTEMD_DIR" == /etc/systemd/system &&
     "$setup" == /usr/local/lib/aegis/helpers/setup-wide-linux-redirect.sh &&
     "$port" == 980 && "$udp_port" == 981 ]] || {
    echo 'ERROR: legacy TUN guard requires standard system paths and reserved privileged capture ports.' >&2; return 1;
  }
  [[ ! -e /var/lib/aegis-install/client/device-guard.conf && ! -L /var/lib/aegis-install/client/device-guard.conf &&
     ! -e "${SYSTEMD_DIR}/aegis-device-egress-guard.service" ]] || {
    echo 'ERROR: device guard ownership requires its explicit device recovery before legacy installation.' >&2; return 1;
  }
  [[ "$(bash "$setup" guard-version)" == aegis_legacy_tun_guard_v1 ]] || {
    echo 'ERROR: upgrade the signed redirect helper before arming legacy full-wide TUN.' >&2; return 1;
  }
  ensure_dir "$(dirname "$state")"
  candidate="$(mktemp "${state}.candidate.XXXXXXXX")" || return 1
  install_atomic_write "$candidate" 0600 strict <<EOF || return 1
schema=aegis_legacy_tun_guard_v1
armed=1
service=aegis-client.service
tun=aegis-tun0
tcp_port=${port}
udp_port=${udp_port}
management_ports=${AEGIS_WIDE_SSH_SAFE_PORTS:-22}
EOF
  # Preflight checks the actual nft cgroup matcher without changing any rules.
  # Retain candidate receipts on failure for recovery/review; never enable a
  # unit whose generated policy failed validation.
  AEGIS_LEGACY_TUN_GUARD_STATE="$candidate" bash "$setup" guard-preflight || return 1
  install_atomic_write "$state" 0600 strict < "$candidate" || return 1
  ensure_dir "${SYSTEMD_DIR}/aegis-client.service.d"
  install_atomic_write "${SYSTEMD_DIR}/aegis-legacy-tun-guard.service" 0644 strict <<EOF || return 1
[Unit]
Description=AEGIS legacy TUN persistent egress block
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AEGIS_LEGACY_TUN_GUARD_STATE=${state}
ExecStart=/bin/bash ${setup} guard-block
# No ExecStop: client stop, restart and failure never release the deny policy.
TimeoutStartSec=60
[Install]
WantedBy=multi-user.target
EOF
  install_atomic_write "${SYSTEMD_DIR}/aegis-client.service.d/29-legacy-tun-guard.conf" 0644 strict <<EOF || return 1
[Unit]
Requires=aegis-legacy-tun-guard.service
After=aegis-legacy-tun-guard.service
[Service]
Environment=AEGIS_LEGACY_TUN_GUARD_STATE=${state}
ExecStartPre=/bin/bash ${setup} guard-bind
ExecStopPost=/bin/bash ${setup} guard-block
EOF
  # Require the early guard even if its nft transaction fails. Before= alone
  # only orders work; it would allow a failed block to boot native networking.
  for manager in NetworkManager systemd-networkd networking; do
    ensure_dir "${SYSTEMD_DIR}/${manager}.service.d"
    install_atomic_write "${SYSTEMD_DIR}/${manager}.service.d/29-aegis-legacy-tun-guard.conf" 0644 strict <<EOF || return 1
[Unit]
Requires=aegis-legacy-tun-guard.service
After=aegis-legacy-tun-guard.service
EOF
  done
  systemctl daemon-reload || return 1
  systemctl enable --now aegis-legacy-tun-guard.service || return 1
  systemctl is-active --quiet aegis-legacy-tun-guard.service || return 1
  # The existing client did not run the new pre-hook. Bind its current cgroup
  # now; the immediately following restart re-blocks and binds the new object.
  AEGIS_LEGACY_TUN_GUARD_STATE="$state" bash "$setup" guard-refresh || return 1
}

# Install a boot unit that re-applies the full-wide-tun capture after reboot.
# The client itself restores the TUN + UDP proxy from its on-disk config
# (ipv6_tun_carried / udp_capture_contract / masque_server), but the firewall
# (REDIRECT + fail-closed backstop + resolv.conf repoint + relay exemptions) is
# not persistent — without this, a reboot leaves full-wide-tun half-up. Runs the
# same setup helper + env as the install-time apply, ordered After=aegis-client.
install_wide_tun_boot_unit() {
  local setup="$1" port="$2" cuid="$3" b_udp="$4" b_tcpdns="$5" b_ipv6="$6" dns_prev="$7" tun_dev="$8" udp_redir="$9" relay_ips="${10}" cap_root="${11}" direct_mark="${12:-}"
  local require_cgroup="${13:-0}" exempt_service="${14:-}" exempt_cgroup="${15:-}"
  local unit="/etc/systemd/system/aegis-wide-tun-firewall.service"
  cat > "${unit}" <<UNIT
[Unit]
Description=AEGIS full-wide-tun firewall reapply on boot
After=network-online.target aegis-client.service systemd-resolved.service
Wants=network-online.target
Requires=aegis-client.service
PartOf=aegis-client.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AEGIS_WIDE_PORT=${port}
Environment=AEGIS_EXEMPT_UID=${cuid}
Environment=AEGIS_WIDE_BLOCK_LEAKS=1
Environment=AEGIS_WIDE_BLOCK_UDP=${b_udp}
Environment=AEGIS_WIDE_BLOCK_TCP_DNS=${b_tcpdns}
Environment=AEGIS_WIDE_BLOCK_IPV6=${b_ipv6}
Environment=AEGIS_ENABLE_DNS_PREVIEW=${dns_prev}
Environment=AEGIS_WIDE_MANAGE_RESOLV=${dns_prev}
Environment=AEGIS_WIDE_IPV6_TUN_DEV=${tun_dev}
Environment=AEGIS_WIDE_UDP_REDIRECT_PORT=${udp_redir}
Environment="AEGIS_WIDE_RELAY_EXCLUDE_IPS=${relay_ips}"
Environment=AEGIS_WIDE_CAPTURE_ROOT=${cap_root}
Environment=AEGIS_DIRECT_SOCKET_MARK=${direct_mark}
Environment=AEGIS_WIDE_REQUIRE_CGROUP=${require_cgroup}
Environment=AEGIS_WIDE_EXEMPT_SERVICE=${exempt_service}
Environment=AEGIS_WIDE_EXEMPT_CGROUP=${exempt_cgroup}
ExecStart=/bin/bash ${setup} apply
ExecStop=/bin/bash ${setup} teardown
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
# PartOf propagates stop/restart from the client, but it deliberately does not
# propagate a later plain start.  Pull the firewall back in whenever an
# operator performs a plain client stop followed by a plain client start;
# otherwise teardown restores the native resolver and the new
# client process comes up behind the independent TUN guard without capture.
WantedBy=multi-user.target aegis-client.service
UNIT
  if ! systemctl daemon-reload 2>/dev/null; then
    echo "ERROR: failed to reload systemd for aegis-wide-tun-firewall.service" >&2
    return 1
  fi
  # A previous unit teardown may have timed out on an older release. Rewriting
  # and enabling the unit does not clear that sticky failed state, which makes
  # a successful repair look broken and obscures the next boot result.
  systemctl reset-failed aegis-wide-tun-firewall.service 2>/dev/null || true
  # The live firewall was applied by the installer before this unit existed.
  # Merely enabling the oneshot leaves it inactive until the next reboot, so
  # stopping aegis-client in the current boot never executes ExecStop and can
  # strand capture rules + the AEGIS resolver. Start it now so systemd owns the
  # already-live state. PartOf above also propagates an operator restart back
  # through ExecStop/ExecStart in the correct reverse/forward ordering.
  if ! systemctl enable --now aegis-wide-tun-firewall.service 2>/dev/null || \
     ! systemctl is-active --quiet aegis-wide-tun-firewall.service 2>/dev/null; then
    echo "ERROR: aegis-wide-tun-firewall.service did not become active" >&2
    systemctl disable --now aegis-wide-tun-firewall.service >/dev/null 2>&1 || true
    return 1
  fi
  echo "reboot-persistence: capture unit active; the independent TUN guard retains privacy across stop/restart/failure" >&2
}


# Device-only persistent privacy block. This is deliberately separate from
# legacy capture persistence: stopping/restarting capture never restores native
# egress. The full-wide device dispatcher requires actual host/boot assessment.
device_guard_assessment_lock_ensure() {
  # The foreign-policy monitor reserves this exact inode on its first poll.
  # Both the AUTO first arm and the staged device upgrade must publish it
  # before either path can start the guard/monitor units.
  /usr/bin/python3 -I -B - <<'PY_AUTO_ASSESSMENT_LOCK'
import os,pathlib,stat
path=pathlib.Path('/var/lib/aegis-install/client/device-guard.conf.assessment.lock')
parent=path.parent.stat(follow_symlinks=False)
assert stat.S_ISDIR(parent.st_mode) and parent.st_uid==parent.st_gid==0 and not parent.st_mode&0o022
created=False
try:
 fd=os.open(path,os.O_RDONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 created=True
except FileExistsError:
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
try:
 item=os.fstat(fd);named=path.stat(follow_symlinks=False)
 assert stat.S_ISREG(item.st_mode) and item.st_uid==item.st_gid==0 and item.st_nlink==1
 assert stat.S_IMODE(item.st_mode)==0o600 and item.st_size==0
 assert (item.st_dev,item.st_ino)==(named.st_dev,named.st_ino)
 if created:os.fsync(fd)
finally:os.close(fd)
if created:
 directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(directory)
 finally:os.close(directory)
PY_AUTO_ASSESSMENT_LOCK
}

install_device_egress_guard_units() {
  local state="$1" manager="$2" bundle="${3:-}" helper="${AEGIS_WIDE_LIB_DIR}/aegis-device-egress-guard.sh"
  local candidate="${4:-$state}" phase="${5:-activate}"
  [[ "$phase" == stage || "$phase" == activate || "$phase" == v2-stage ]] || return 1
  local client="${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}"
  # Recovery and early boot use these supported administrator-owned locations;
  # do not arm a custom-prefix installation that cannot be recovered correctly.
  [[ "$state" == /var/lib/aegis-install/client/device-guard.conf &&
     "$SYSTEMD_DIR" == /etc/systemd/system &&
     "$AEGIS_WIDE_LIB_DIR" == /usr/local/lib/aegis/helpers ]] || {
    echo 'ERROR: device guard requires the standard system installation paths.' >&2; return 1;
  }
  [[ -n "$bundle" ]] || { echo 'ERROR: device guard requires a validated v2 full-wide public profile.' >&2; return 1; }
  # The Rust inspector authenticates/validates the public bundle and fixed v2
  # policy, including numeric IPv4 relay pinning, before any network mutation.
  if [[ "$phase" == v2-stage ]]; then
    # The ordinary AUTO bundle has a separate captured Settings authority. It
    # is not represented as a signed device profile. This branch is reachable
    # only after that input and the original installer flock were admitted.
    [[ "${AUTO_V2_FIRST_ARM_ADMITTED:-0}" == 1 && "$AUTO_PROFILE" == 1 ]] || return 1
  else
    "$client" device bundle-inspect --bundle-dir "$bundle" --json | python3 -I -c '
import json,sys
p=json.load(sys.stdin);r=p["resolved"]
assert p["schema"] in ("aegis_device_bundle_v2","aegis_device_bundle_v3","aegis_device_bundle_v4") and p["product_mode"]=="full-wide-tun" and p["udp"] is True
assert r["capture_scope"]=="local_host" and r["tcp_transport"]=="grpc_stream" and r["udp_transport"]=="grpc_datagram"
assert r["inner_tls"] is True and r["native_fallback"] is False and r["requires_privileged_capture"] is True
assert r["dns_policy"]=="preview" and r["ipv6_policy"]=="tun_carried"
' || return 1
  fi
  [[ "$state" =~ ^/[A-Za-z0-9_./-]+$ && "/$state/" != */../* && "$manager" =~ ^(NetworkManager|systemd-networkd|networking)\.service$ ]] || return 1
  [[ "$helper" =~ ^/[A-Za-z0-9_./-]+$ ]] || return 1
  mkdir -p "${AEGIS_WIDE_LIB_DIR}/lib" || return 1
  install_copy_file "${ROOT}/scripts/lib/root-state.sh" "${AEGIS_WIDE_LIB_DIR}/lib/root-state.sh" 0755 || return 1
  install_copy_file "${ROOT}/scripts/aegis-device-egress-guard.sh" "$helper" 0755 || return 1
  # Includes actual kernel cgroup matcher and unsupported host/manager checks;
  # nothing is enabled before this read-only nft check succeeds.
  if [[ "$phase" == v2-stage ]]; then
    AEGIS_DEVICE_GUARD_STATE="$candidate" /usr/bin/timeout --signal=TERM --kill-after=3s 40s bash "$helper" preflight || return 1
  else
    AEGIS_DEVICE_GUARD_STATE="$candidate" bash "$helper" preflight || return 1
  fi
  /usr/bin/python3 -I -B "${AEGIS_WIDE_LIB_DIR}/lib/aegis_auto_foreign_policy.py" \
    --snapshot /var/lib/aegis-install/client/ufw-before-guard.json || return 1
  local recorded_manager recorded_schema manager_hook='' dhcp_timer_want='' startup_timeout=60
  [[ "${DEVICE_ONLINE:-0}" != 1 ]] || startup_timeout=180
  recorded_manager="$("${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}" profile metadata read --path "$candidate" | sed -n 's/^manager=//p')" || return 1
  [[ "$recorded_manager" == "$manager" ]] || return 1
  recorded_schema="$("${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}" profile metadata read --path "$candidate" | sed -n 's/^schema=//p')" || return 1
  if [[ "$recorded_schema" == aegis_device_guard_v2 ]]; then
    dhcp_timer_want=' aegis-device-dhcp-refresh.timer'
    [[ "$manager" == systemd-networkd.service || "$manager" == NetworkManager.service ]] || return 1
    if [[ "$manager" == NetworkManager.service ]]; then
      # This precedes owned boot-unit publication. A crash here leaves an
      # identifiable orphan policy recoverable without a final guard record.
      AEGIS_DEVICE_GUARD_STATE="$candidate" bash "$helper" prepare-nm-policy || return 1
    fi
    # A privileged control command retains the manager's mount namespace on
    # systemd 255 even though it has full capabilities. Enter PID1's mount/root
    # before running the *same* ControlPID helper, so the installed guardian's
    # host anchor and policy seal execute against the real host. This exact
    # nsenter form preserves PID, cgroup and inherited guard FD9.
    manager_hook="[Service]
Environment=AEGIS_DEVICE_GUARD_STATE=${state}
ExecStartPre=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash ${helper} bind-manager"
    if [[ "$manager" == NetworkManager.service || "$manager" == systemd-networkd.service ]]; then
      manager_hook+="
ExecStartPost=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash ${helper} manager-ready
TimeoutStartSec=90"
    fi
  elif [[ "$recorded_schema" != aegis_device_guard_v1 ]]; then
    return 1
  fi
  mkdir -p "${SYSTEMD_DIR}/${manager}.d" || return 1
  if [[ "$phase" != v2-stage ]]; then
    mkdir -p "${SYSTEMD_DIR}/aegis-client.service.d" || return 1
  fi
  install_atomic_write "${SYSTEMD_DIR}/aegis-device-egress-guard.service" 0644 strict <<EOF || return 1
[Unit]
Description=AEGIS device persistent egress block
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service ufw.service
Before=network-pre.target
Wants=network-pre.target aegis-foreign-policy-monitor.service${dhcp_timer_want}
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AEGIS_DEVICE_GUARD_STATE=${state}
ExecStart=/bin/bash ${helper} block
# No ExecStop: failure/stop/restart must never release the independent guard.
[Install]
WantedBy=multi-user.target
EOF
  install_atomic_write "${SYSTEMD_DIR}/${manager}.d/30-aegis-device-guard.conf" 0644 strict <<EOF || return 1
[Unit]
Requires=aegis-device-egress-guard.service
After=aegis-device-egress-guard.service
${manager_hook}
EOF
  if [[ "$phase" != v2-stage ]]; then
    install_atomic_write "${SYSTEMD_DIR}/aegis-client.service.d/30-device-egress-guard.conf" 0644 strict <<EOF || return 1
[Unit]
Requires=aegis-device-egress-guard.service
After=aegis-device-egress-guard.service ufw.service
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=${startup_timeout}
Environment=AEGIS_DEVICE_GUARD_STATE=${state}
ExecStartPre=/bin/bash ${helper} bind
ExecStartPost=/bin/bash ${helper} capture-bind-legacy
ExecStopPost=/bin/bash ${helper} block
EOF
  fi
  systemctl daemon-reload || return 1
  if [[ "$phase" == v2-stage ]]; then
    systemctl enable aegis-device-egress-guard.service aegis-foreign-policy-monitor.service aegis-auto-clean-shutdown.service aegis-device-dhcp-refresh.timer || return 1
  else
    if [[ "$recorded_schema" == aegis_device_guard_v2 ]]; then
      systemctl enable aegis-device-egress-guard.service aegis-foreign-policy-monitor.service aegis-device-dhcp-refresh.timer || return 1
    else
      systemctl enable aegis-device-egress-guard.service aegis-foreign-policy-monitor.service || return 1
    fi
  fi
  # Staging dependencies before armed-state commit makes an interrupted boot
  # fail closed on missing state instead of booting an unguarded network.
  [[ "$phase" != stage && "$phase" != v2-stage ]] || return 0
  # First arm is one nft inet transaction; failure does not tear down an armed
  # table. Client restart/readiness/capture activation are a later transaction.
  systemctl start aegis-device-egress-guard.service || return 1
  systemctl is-active --quiet aegis-device-egress-guard.service || return 1
  if [[ "$recorded_schema" == aegis_device_guard_v2 ]]; then
    systemctl start aegis-device-dhcp-refresh.timer || return 1
    systemctl is-active --quiet aegis-device-dhcp-refresh.timer || return 1
  fi
}

# The device dispatcher reaches this transaction only after actual host, boot
# and configuration checks. It never calls legacy config mutators or a native
# fallback rollback; isolated contracts exercise the same failure boundaries.
device_full_wide_probes() {
  curl --noproxy '*' -4 --fail --silent --show-error --max-time 20 https://1.1.1.1/ >/dev/null || return 1
  curl --noproxy '*' -6 --fail --silent --show-error --max-time 20 'https://[2606:4700:4700::1111]/' >/dev/null || return 1
  # Real UDP to external recursive resolvers exercises both generic redirect
  # and IPv6 TUN carry. The local fake-IP resolver cannot satisfy these probes.
  python3 -I - <<'PY' || return 1
import secrets,socket,struct
for family,address in [(socket.AF_INET,'1.1.1.1'),(socket.AF_INET6,'2606:4700:4700::1111')]:
    ident=secrets.token_bytes(2)
    request=ident+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07example\x03com\x00\x00\x01\x00\x01'
    with socket.socket(family,socket.SOCK_DGRAM) as sock:
        sock.settimeout(8);sock.connect((address,53));sock.send(request);reply=sock.recv(4096)
    assert len(reply)>=12 and reply[:2]==ident
    flags,questions,answers=struct.unpack('!HHH',reply[2:8])
    assert flags&0x8000 and not flags&0x020f and questions==1 and answers>0
PY
  getent ahostsv4 example.com >/dev/null || return 1
}

device_full_wide_arm_failure() {
  local guard="$1" state="$2"
  # The persistent guard is independent of capture/TUN teardown. Never restore
  # native routing or rewrite to SOCKS automatically after the armed commit.
  AEGIS_DEVICE_GUARD_STATE="$state" bash "$guard" block >&2 || \
    echo 'ERROR: guard refresh failed; existing atomic guard was not removed.' >&2
  systemctl stop aegis-client.service >/dev/null 2>&1 || true
  echo 'ERROR: device full-wide activation failed; persistent block and recovery state were retained.' >&2
  return 1
}

device_bundle_render() {
  local client="$1"
  shift
  if [[ -n "${DEVICE_RELAY_GENEVA_REQUEST:-}" ]]; then
    "$client" device bundle-render "$@" \
      --relay-geneva-request "$DEVICE_RELAY_GENEVA_REQUEST" \
      --relay-geneva-request-sha256 "$DEVICE_RELAY_GENEVA_REQUEST_SHA256" \
      --relay-geneva-profile-manifest "$DEVICE_RELAY_GENEVA_MANIFEST" \
      --relay-geneva-profile-sha256 "$DEVICE_RELAY_GENEVA_MANIFEST_SHA256"
  else
    "$client" device bundle-render "$@"
  fi
}

device_relay_geneva_absent() {
  local path
  # This handoff is a first selection, never adoption/reinstall of an existing
  # selected role. Refuse before replacing any of its pinned ordinary assets.
  for path in /var/lib/aegis-install/client/relay-geneva-profile.json \
    /var/lib/aegis-install/client/relay-geneva-guard-state.json \
    /var/lib/aegis-install/client/relay-geneva-guard-intent.json \
    /var/lib/aegis-install/client/relay-geneva-install-intent.json \
    /var/lib/aegis-install/client/relay-geneva-teardown.json \
    /usr/local/lib/aegis/aegis-relay-geneva-profile.sh \
    /etc/systemd/system/aegis-client.service.d/25-relay-geneva-profile.conf \
    /run/aegis-relay-geneva; do
    [[ ! -e "$path" && ! -L "$path" ]] || {
      echo 'Existing relay Geneva ownership requires explicit stopped recovery or teardown before installation.' >&2
      return 1
    }
  done
}

device_relay_geneva_verify_snapshot() {
  local client="$1" path="$2" expected="$3"
  "$client" profile metadata read --path "$path" | python3 -I -c '
import hashlib,re,sys
raw=sys.stdin.buffer.read(65537)
assert len(raw)<=65536 and re.fullmatch("[a-f0-9]{64}",sys.argv[1])
assert hashlib.sha256(raw).hexdigest()==sys.argv[1],"Pinned relay Geneva input changed"
' "$expected"
}

device_relay_geneva_existing_installation_eligible() {
  local client="$1" state=/var/lib/aegis-install/client/device-guard.conf old_state
  if [[ -e "$state" || -L "$state" ]]; then
    old_state="$("$client" profile metadata read --path "$state")" || return 1
    [[ "$old_state" == *$'\narmed=1\n'* || "$old_state" == *$'\narmed=1' ]] || {
      [[ ! -e /etc/systemd/system/aegis-device-egress-guard.service && ! -L /etc/systemd/system/aegis-device-egress-guard.service ]] || {
        echo 'Interrupted explicit device recovery must finish before selected installation.' >&2
        return 1
      }
    }
  elif [[ -e /etc/aegis/client/aegis.toml || -L /etc/aegis/client/aegis.toml ||
          -e /etc/systemd/system/aegis-client.service || -L /etc/systemd/system/aegis-client.service ]]; then
    echo 'An existing installation without a device guard requires explicit migration before enrollment.' >&2
    return 1
  fi
}

device_relay_geneva_preflight() {
  [[ -n "${DEVICE_RELAY_GENEVA_REQUEST:-}" ]] || return 0
  local bundle="$1" identity="$2" config="$3" state="$4"
  local client="$PREFLIGHT_CLIENT_BINARY" assessment stage
  [[ "$(detect_os_kind)" == linux && "$EUID" == 0 && "$DEVICE_PRODUCT_MODE" == full-wide-tun &&
     "$config" == /etc/aegis/client && "$state" == /var/lib/aegis-client &&
     "${PREFIX:-/usr/local}" == /usr/local && "$SYSTEMD_DIR" == /etc/systemd/system &&
     "$ENV_DIR" == /etc/default ]] && systemd_activation_requested || {
    echo 'Relay Geneva requires a standard full-wide Linux systemd device installation.' >&2
    return 1
  }
  device_relay_geneva_absent || return 1
  device_relay_geneva_existing_installation_eligible "$client" || return 1
  assessment="$(device_assess_full_wide_host "$bundle" "$client")" || return 1
  grep -Fxq 'schema=aegis_device_guard_v2' <<<"$assessment" || {
    echo 'Relay Geneva requires a supported v2 device guard manager.' >&2
    return 1
  }
  # Read-only Rust validation checks the original private request and exact
  # public profile before creating a key or redeeming an enrollment invitation.
  device_bundle_render "$client" --bundle-dir "$bundle" --identity-dir "$identity" \
    --config-dir "$config" --output "$config/aegis.toml" --validate-only || return 1
  # Freeze both supplied inputs as bounded administrator-owned records. Hash
  # the exact preserved bytes; no command substitution strips JSON newlines.
  ensure_dir /var/lib/aegis-install/client || return 1
  stage="$(mktemp -d /var/lib/aegis-install/client/.relay-geneva-handoff.XXXXXXXX)" || return 1
  "$client" profile metadata read --path "$DEVICE_RELAY_GENEVA_REQUEST" | \
    "$client" profile metadata write --path "$stage/request.json" --mode 0600 --exclusive || return 1
  device_relay_geneva_verify_snapshot "$client" "$stage/request.json" "$DEVICE_RELAY_GENEVA_REQUEST_SHA256" || return 1
  "$client" profile metadata read --path "$DEVICE_RELAY_GENEVA_MANIFEST" | \
    "$client" profile metadata write --path "$stage/profile.json" --mode 0600 --exclusive || return 1
  device_relay_geneva_verify_snapshot "$client" "$stage/profile.json" "$DEVICE_RELAY_GENEVA_MANIFEST_SHA256" || return 1
  # Keep failed handoff snapshots for explicit recovery; do not add them to the
  # generic temporary-file cleanup list or silently retry a partial selection.
  DEVICE_RELAY_GENEVA_REQUEST="$stage/request.json"
  DEVICE_RELAY_GENEVA_MANIFEST="$stage/profile.json"
}

device_relay_geneva_install_selected() {
  [[ -n "${DEVICE_RELAY_GENEVA_REQUEST:-}" ]] || return 0
  local client="${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}" lib=/usr/local/lib/aegis
  device_relay_geneva_verify_snapshot "$client" "$DEVICE_RELAY_GENEVA_REQUEST" "$DEVICE_RELAY_GENEVA_REQUEST_SHA256" || return 1
  device_relay_geneva_verify_snapshot "$client" "$DEVICE_RELAY_GENEVA_MANIFEST" "$DEVICE_RELAY_GENEVA_MANIFEST_SHA256" || return 1
  device_relay_geneva_absent || return 1
  # The selected hook has its own fixed parent-root paths. Supply those exact
  # ordinary prerequisites, while leaving selected helper/drop-in absent for
  # the Rust prepare-install intent and stopped-role verification.
  ensure_dir "$lib/lib" || return 1
  install_copy_file "$ROOT/scripts/lib/root-state.sh" "$lib/lib/root-state.sh" 0755 || return 1
  install_copy_file "$ROOT/scripts/aegis-device-egress-guard.sh" "$lib/aegis-device-egress-guard.sh" 0755 || return 1
  /bin/bash "$ROOT/tools/geneva/install-relay-profile.sh" --manifest "$DEVICE_RELAY_GENEVA_MANIFEST"
}

activate_device_full_wide_capture() {
  local public_bundle="$1" identity="$2" config="$3" assessment="$4" stage_auto="${5:-0}"
  local client="${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}"
  local state=/var/lib/aegis-install/client/device-guard.conf
  local guard="${AEGIS_WIDE_LIB_DIR}/aegis-device-egress-guard.sh"
  local capture="${AEGIS_WIDE_LIB_DIR}/setup-wide-linux-redirect.sh"
  local config_dir stage manager cgroup guard_schema
  [[ "$config" == /etc/aegis/client/aegis.toml ]] || return 1
  config_dir="$(dirname "$config")"
  # Validate final local identity and trust pin before creating even a staging
  # config. Renderer validates the complete fixed v2 Settings before writing.
  "$client" device bundle-inspect --bundle-dir "$public_bundle" --identity-dir "$identity" --json >/dev/null || return 1
  if [[ "${DEVICE_ONLINE:-0}" == 1 ]]; then
    local identity_phase
    identity_phase="$(device_recover_online_local "$identity" "$public_bundle" "$client")" || return 1
    [[ "$identity_phase" == ready || "$identity_phase" == runtime_recovery_required ]] || return 1
  else
    "$client" device status --identity-dir "$identity" --json | python3 -I -c 'import json,sys; assert json.load(sys.stdin)["phase"]=="ready"' || return 1
  fi
  "$client" profile metadata validate --path "$state" || return 1
  "$client" profile metadata validate --path "$config" || return 1
  "$client" profile metadata validate --path "$assessment" || return 1
  stage="$(mktemp -d /var/lib/aegis-install/client/.device-arm.XXXXXXXX)" || return 1
  # Failed arm attempts retain this root-private assessment/config for recovery.
  install_copy_file "$public_bundle/outer-ca.pem" "$stage/ca.pem" 0600 || return 1
  install_copy_file "$public_bundle/inner-ca.pem" "$stage/inner-ca.pem" 0600 || return 1
  device_bundle_render "$client" --bundle-dir "$public_bundle" --identity-dir "$identity" --config-dir "$stage" --output "$stage/check.toml" || return 1
  inject_client_service_state_path "$stage/check.toml" /var/lib/aegis-client || return 1
  device_validate_config "$client" "$stage/check.toml" >/dev/null || return 1
  device_bundle_render "$client" --bundle-dir "$public_bundle" --identity-dir "$identity" --config-dir "$config_dir" --output "$stage/final.toml" || return 1
  inject_client_service_state_path "$stage/final.toml" /var/lib/aegis-client || return 1
  # Freeze the assessed policy as administrator-owned data before preflight.
  "$client" profile metadata read --path "$assessment" | install_atomic_write "$stage/guard.conf" 0600 strict || return 1
  manager="$("$client" profile metadata read --path "$stage/guard.conf" | sed -n 's/^manager=//p')" || return 1
  guard_schema="$("$client" profile metadata read --path "$stage/guard.conf" | sed -n 's/^schema=//p')" || return 1
  # Staging installs dependency gates before the armed record. This calls actual
  # host, kernel, manager and initramfs checks using the private candidate state.
  install_device_egress_guard_units "$state" "$manager" "$public_bundle" "$stage/guard.conf" stage || return 1
  if [[ "$guard_schema" == aegis_device_guard_v2 ]]; then
    device_guard_assessment_lock_ensure || return 1
  fi
  for helper_name in setup-wide-linux-redirect.sh aegis-wide-disable.sh aegis-wide-persist-install.sh aegis-wide-enable.sh janitor-wide-linux-tproxy.sh; do
    install_copy_file "$ROOT/scripts/$helper_name" "$AEGIS_WIDE_LIB_DIR/$helper_name" 0755 || return 1
  done
  if [[ "$stage_auto" == 1 ]]; then
    # The candidate block admits the installed v2 guard generation only after
    # its kernel deny readback. The passive guardian holds the singleton used
    # by that admission, so stop it first while the original InstallLock still
    # excludes any new AUTO owner. A live private unit must never be stopped
    # merely to make the upgrade lock available.
    stage_auto_device_owner_admit >/dev/null || return 1
    if ! python3 -I - <<'PY_AUTO_GUARDIAN_STOP'
import os
import pathlib
import select
import subprocess

def show(unit):
    result = subprocess.run(
        ('systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'SubState',
         '-p', 'MainPID', '-p', 'ControlPID', '-p', 'ControlGroup',
         '-p', 'NFileDescriptorStore'),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=8, check=True, text=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines())

guardian = show('aegis-auto-guardian.service')
watchdog = show('aegis-auto-guardian-watchdog.service')
assert guardian.get('ActiveState') == 'active'
assert guardian.get('SubState') == 'running'
pid = int(guardian.get('MainPID', '0'))
assert pid > 1 and guardian.get('ControlPID') == '0'
assert watchdog.get('ActiveState') == 'active'
assert int(watchdog.get('MainPID', '0')) > 1
assert watchdog.get('ControlPID') == '0'
assert watchdog.get('NFileDescriptorStore') == '0'
assert not os.path.lexists('/var/lib/aegis-install/client/auto-watchdog-pending.json')
assert not os.path.lexists('/var/lib/aegis-install/client/auto-stop-intent.json')
group = guardian.get('ControlGroup', '')
assert group == '/system.slice/aegis-auto-guardian.service'
group_path = pathlib.Path('/sys/fs/cgroup' + group)
pidfd = os.pidfd_open(pid, 0)
try:
    stopped = subprocess.run(
        ('systemctl', 'stop', 'aegis-auto-guardian.service'),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=15, check=False)
    assert stopped.returncode == 0
    poll = select.poll()
    poll.register(pidfd, select.POLLIN)
    assert poll.poll(1000)
finally:
    os.close(pidfd)
guardian = show('aegis-auto-guardian.service')
watchdog = show('aegis-auto-guardian-watchdog.service')
assert guardian.get('ActiveState') == 'inactive'
assert guardian.get('SubState') == 'dead'
assert guardian.get('MainPID') == guardian.get('ControlPID') == '0'
assert guardian.get('ControlGroup') in ('', None)
if group_path.exists():
    assert 'populated 0' in group_path.joinpath('cgroup.events').read_text().splitlines()
assert watchdog.get('ActiveState') == 'active'
assert int(watchdog.get('MainPID', '0')) > 1
assert watchdog.get('ControlPID') == '0'
assert watchdog.get('NFileDescriptorStore') == '0'
assert not os.path.lexists('/var/lib/aegis-install/client/auto-watchdog-pending.json')
assert not os.path.lexists('/var/lib/aegis-install/client/auto-stop-intent.json')
PY_AUTO_GUARDIAN_STOP
    then
      echo 'ERROR: passive AUTO guardian stop/readback refused before first device block.' >&2
      return 1
    fi
  fi
  # The candidate is already durable and boot dependencies already exist.
  # Establish the first atomic block before publishing the final armed record:
  # failure before this point is an incomplete first arm, never an armed claim.
  if ! AEGIS_DEVICE_GUARD_STATE="$stage/guard.conf" bash "$guard" block; then
    echo "ERROR: first device guard activation failed; installation is not armed. Staged recovery assessment: $stage/guard.conf" >&2
    return 1
  fi
  if ! cat "$stage/guard.conf" | install_atomic_write "$state" 0600 strict; then
    echo "ERROR: armed state commit failed; blocking candidate retained at $stage/guard.conf" >&2
    device_full_wide_arm_failure "$guard" "$stage/guard.conf"; return 1
  fi
  # From this commit onward all failure paths retain a device block. Never call
  # the legacy activate_wide_capture function, which can rewrite policy/rollback.
  if ! systemctl start aegis-device-egress-guard.service; then
    device_full_wide_arm_failure "$guard" "$state"; return 1
  fi
  if [[ "$guard_schema" == aegis_device_guard_v2 ]]; then
    # A first install cannot enroll an existing manager cgroup from an unrelated
    # installer process. Restart only after durable guard arm, so the reviewed
    # ExecStartPre binds that new manager incarnation before its DHCP traffic.
    if [[ "$manager" != systemd-networkd.service && "$manager" != NetworkManager.service ]] ||
       ! systemctl restart "$manager" || ! systemctl is-active --quiet "$manager" ||
       ! AEGIS_DEVICE_GUARD_STATE="$state" bash "$guard" manager-status ||
       ! systemctl start aegis-device-dhcp-refresh.timer ||
       ! systemctl is-active --quiet aegis-device-dhcp-refresh.timer; then
      device_full_wide_arm_failure "$guard" "$state"; return 1
    fi
  fi
  if ! install_copy_file "$stage/ca.pem" "$config_dir/ca.pem" 0600 ||
     ! install_copy_file "$stage/inner-ca.pem" "$config_dir/inner-ca.pem" 0600 ||
     ! install_copy_file "$stage/final.toml" "$config" 0600 ||
     ! device_validate_config "$client" "$config" >/dev/null; then
    device_full_wide_arm_failure "$guard" "$state"; return 1
  fi
  if [[ "$stage_auto" == 1 ]]; then
    # This barrier is before every client start, capture apply, external probe,
    # boot capture unit and full-install success record. Re-observe the stopped
    # owner and the live manager after the first durable guard commit.
    # The first block and the restarted manager's ExecStartPre already sealed
    # the deny policy. A second installer-owned block would take the guard
    # flock after the independent monitor starts; only its authenticated PID1
    # actors may own that flock while it assesses the live policy.
    if ! stage_auto_device_owner_admit >/dev/null ||
       ! AEGIS_DEVICE_GUARD_STATE="$state" bash "$guard" manager-status ||
       ! systemctl is-active --quiet aegis-device-egress-guard.service ||
       ! systemctl is-active --quiet "$manager" ||
       ! systemctl stop aegis-auto-guardian.service ||
       systemctl is-active --quiet aegis-auto-guardian.service ||
       ! /usr/bin/python3 -I -B "$AEGIS_WIDE_LIB_DIR/lib/aegis_auto_guardian.py" upgrade-guard ||
       ! systemctl start aegis-auto-guardian.service ||
       ! systemctl is-active --quiet aegis-auto-guardian.service ||
       ! write_stage_auto_device_guard_receipt "$public_bundle" "$identity" "$assessment" "$state" "$manager"; then
      device_full_wide_arm_failure "$guard" "$state"; return 1
    fi
    TEMP_PATHS+=("$stage")
    return 0
  fi
  # Exact privileged TUN policy plus Type=notify ensure restart waits for all
  # required workers and the primary backend, not merely an allocated MainPID.
  if ! ( PRODUCT_MODE=full-wide-tun; install_client_ipv6_tun_dropin ) ||
     ! systemctl daemon-reload; then
    device_full_wide_arm_failure "$guard" "$state"; return 1
  fi
  # Final config, ordinary drop-ins and the armed v2 block are already durable.
  # The explicit selected installer must complete while the service is stopped
  # before the first start; any partial selection retains its refusing gate.
  if ! device_relay_geneva_install_selected || ! restart_systemd_unit_checked aegis-client.service; then
    device_full_wide_arm_failure "$guard" "$state"; return 1
  fi
  cgroup="$(AEGIS_WIDE_REQUIRE_CGROUP=1 AEGIS_WIDE_EXEMPT_SERVICE=aegis-client.service AEGIS_WIDE_EXEMPT_CGROUP='' bash "$capture" cgroup-path)" || {
    device_full_wide_arm_failure "$guard" "$state"; return 1;
  }
  if ! AEGIS_WIDE_PORT=15080 AEGIS_WIDE_REQUIRE_CGROUP=1 AEGIS_WIDE_EXEMPT_SERVICE=aegis-client.service AEGIS_WIDE_EXEMPT_CGROUP="$cgroup" \
       AEGIS_WIDE_BLOCK_LEAKS=1 AEGIS_WIDE_BLOCK_UDP=0 AEGIS_WIDE_BLOCK_TCP_DNS=0 AEGIS_WIDE_BLOCK_IPV6=1 \
       AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_WIDE_MANAGE_RESOLV=1 AEGIS_WIDE_IPV6_TUN_DEV=aegis-tun0 AEGIS_WIDE_UDP_REDIRECT_PORT=15081 \
       AEGIS_WIDE_RELAY_EXCLUDE_IPS='' AEGIS_EXEMPT_UID='' AEGIS_DIRECT_SOCKET_MARK='' bash "$capture" apply >&2 ||
     ! device_full_wide_probes; then
    device_full_wide_arm_failure "$guard" "$state"; return 1
  fi
  if ! install_wide_tun_boot_unit "$capture" 15080 0 0 0 1 1 aegis-tun0 15081 '' 1 '' 1 aegis-client.service "$cgroup"; then
    device_full_wide_arm_failure "$guard" "$state"; return 1
  fi
  TEMP_PATHS+=("$stage")
  echo 'Device full-wide capture ready; inner TLS TCP/UDP and persistent guard are active.' >&2
}

write_stage_auto_device_guard_receipt() {
  local bundle="$1" identity="$2" assessment="$3" state="$4" manager="$5"
  local receipt=/var/lib/aegis-install/client/auto-device-guard-stage.json
  local payload stage_receipt_program
  IFS= read -r -d '' stage_receipt_program <<'PY_STAGE_RECEIPT' || true
import hashlib,json,os,pathlib,stat,subprocess,sys
bundle,identity,assessment,state,manager,owner=map(pathlib.Path,sys.argv[1:])
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def check(ok):
    if not ok: raise SystemExit('staged AUTO guard readback refused')
def run(*args):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,check=False)
    check(result.returncode==0 and len(result.stdout)<1048576); return result.stdout
def unit(name):
    data=run('systemctl','show',name,'-p','ActiveState','-p','SubState','-p','MainPID','-p','ControlPID','-p','FragmentPath','-p','InvocationID','-p','ControlGroup')
    return dict(line.split('=',1) for line in data.decode().splitlines())
owner_record=json.loads(owner.read_bytes()); client=pathlib.Path(owner_record['installed_binary'])
check(owner_record.get('schema')=='aegis_auto_stage_owner_v1' and sha(client)==owner_record['installed_binary_sha256'])
guard=unit('aegis-device-egress-guard.service'); network=unit(str(manager)); base=unit('aegis-client.service'); guardian=unit('aegis-auto-guardian.service')
check(guard.get('ActiveState')=='active' and guard.get('ControlPID')=='0' and guard.get('FragmentPath')=='/etc/systemd/system/aegis-device-egress-guard.service')
check(network.get('ActiveState')=='active' and int(network.get('MainPID','0'))>1 and network.get('ControlPID')=='0')
check(base.get('ActiveState')=='inactive' and base.get('MainPID')=='0' and base.get('ControlPID')=='0')
check(guardian.get('ActiveState')=='active' and int(guardian.get('MainPID','0'))>1 and guardian.get('ControlPID')=='0')
guardian_receipt=pathlib.Path('/var/lib/aegis-install/client/auto-guardian-install.json')
guardian_install=json.loads(guardian_receipt.read_bytes())
check(guardian_install.get('guard_unit_sha256')==sha(pathlib.Path('/etc/systemd/system/aegis-device-egress-guard.service')))
check(not pathlib.Path(str(state)+'.client-binding').exists())
policy=run('nft','--json','--handle','list','table','inet','aegis_device_guard'); document=json.loads(policy)
items=document.get('nftables',[])
check(any(x.get('table',{}).get('name')=='aegis_device_guard' for x in items))
handles=sorted({x['rule']['handle'] for x in items if isinstance(x.get('rule'),dict) and isinstance(x['rule'].get('handle'),int)})
check(bool(handles))
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
netns=os.stat('/proc/self/ns/net').st_ino
check(len(boot)==36 and netns>0)
record={'schema':'aegis_auto_device_guard_stage_v1','boot_id':boot,'netns_inode':netns,
        'bundle_path':str(bundle),'bundle_sha256':sha(bundle/'bundle.json'),
        'ready_identity_certificate_sha256':sha(identity/'device.pem'),
        'installed_client_path':str(client),'installed_client_sha256':sha(client),
        'owner_receipt_path':str(owner),'owner_receipt_sha256':sha(owner),
        'assessment_path':str(assessment),'assessment_sha256':sha(assessment),
        'armed_state_path':str(state),'armed_state_sha256':sha(state),
        'nft_policy_sha256':hashlib.sha256(policy).hexdigest(),'nft_rule_handles':handles,
        'guard_unit':guard,'manager_unit':network,'client_unit':base,'guardian_unit':guardian,
        'guardian_install_sha256':sha(guardian_receipt),
        'runtime_activated':False,'capture_applied':False,'internet_probes_passed':False,
        'release_acceptance':False}
print(json.dumps(record,sort_keys=True,separators=(',',':')))
PY_STAGE_RECEIPT
  payload="$(printf '%s' "$stage_receipt_program" | python3 -I - "$bundle" "$identity" "$assessment" "$state" "$manager" "$STAGE_AUTO_OWNER_RECEIPT")" || return 1
  printf '%s\n' "$payload" | install_atomic_write "$receipt" 0600 strict || return 1
}

# A product-profile install is expected to survive a reboot.  The firewall
# helpers deliberately use runtime-only rules, so safe redirect/TPROXY profiles
# need the generic boot unit just as full-wide-tun needs its specialised unit.
# Install it only after the live egress/DNS probes pass; a broken candidate must
# never become sticky across reboot.
install_wide_profile_boot_unit() {
  local enable_wrapper="$1" persist_installer="$2" backend="$3" dns_preview="$4"
  local block_ipv6="$5" udp_redirect_port="$6" interface="$7"
  local mode="redirect" dns="off" ipv6="out_of_scope" udp="block"
  local -a args=()

  [[ "${backend}" == "linux_tproxy" ]] && mode="tproxy"
  [[ "${dns_preview}" == "1" ]] && dns="preview"
  [[ "${block_ipv6}" == "1" ]] && ipv6="block"
  [[ -n "${udp_redirect_port}" ]] && udp="carry"

  args=(install "--mode=${mode}" "--dns=${dns}" "--ipv6=${ipv6}" "--udp=${udp}" \
    "--ssh-safe-ports=${AEGIS_WIDE_SSH_SAFE_PORTS:-22}")
  [[ -n "${interface}" ]] && args+=("--interface=${interface}")

  if [[ ! -x "${persist_installer}" || ! -x "${enable_wrapper}" ]]; then
    echo "ERROR: reboot persistence helper missing; refusing a non-persistent safe wide install." >&2
    return 1
  fi
  AEGIS_WIDE_PERSIST_SCRIPT_PATH="${enable_wrapper}" \
    bash "${persist_installer}" "${args[@]}" >&2
  echo "reboot-persistence: installed + enabled aegis-wide.service (re-applies ${mode} fail-closed firewall after boot)" >&2
}

# Remove active/stale boot units before a client reinstall rewrites config.  A
# unit's ExecStop performs the symmetric firewall/resolver teardown; doing this
# before config replacement avoids restoring an old wide backup over the new
# client config during wide -> socks or wide -> wide transitions.
deactivate_existing_wide_boot_units() {
  [[ ${EUID} -eq 0 ]] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0

  systemctl disable --now aegis-wide.service >/dev/null 2>&1 || true
  systemctl disable --now aegis-wide-tun-firewall.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/aegis-wide.service \
    /etc/systemd/system/aegis-wide-tun-firewall.service 2>/dev/null || true
  systemctl daemon-reload >/dev/null 2>&1 || true

  local disable="/usr/local/lib/aegis/helpers/aegis-wide-disable.sh"
  if [[ -x "${disable}" ]]; then
    AEGIS_WIDE_DISABLE_KEEP_LEGACY_GUARD=1 bash "${disable}" >/dev/null 2>&1 || true
  fi
}

# Set [relay] masque_server (+ optional masque_ca_cert) so the MASQUE/UDP leg dials
# a DIRECT origin instead of the Cloudflare-fronted edge (CF 405s MASQUE). Required
# for full-wide-tun IPv6/IPv4 UDP. Idempotent; never touches secrets.
set_client_config_masque() {
  local cfg="$1" masque_server="$2" masque_ca="$3"
  python3 -I - "$cfg" "$masque_server" "$masque_ca" <<'PY'
import re, sys
p, ms, ca = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(p).read()
def setk(block, key, val):
    if re.search(r'(?m)^\s*%s\s*=' % key, block):
        return re.sub(r'(?m)^(\s*%s\s*=\s*).*$' % key, r'\g<1>"%s"' % val, block, count=1)
    return block.rstrip() + '\n%s = "%s"\n' % (key, val)
def setraw(block, key, val):
    if re.search(r'(?m)^\s*%s\s*=' % key, block):
        return re.sub(r'(?m)^(\s*%s\s*=\s*).*$' % key, r'\g<1>%s' % val, block, count=1)
    return block.rstrip() + '\n%s = %s\n' % (key, val)
m = re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)', t)
if m:
    b = m.group(0); nb = b
    if ms:
        nb = setk(nb, 'masque_server', ms)
        # The direct QUIC origin has an independent validation authority from
        # the Cloudflare TCP hostname. Default it to the actual direct host/IP;
        # otherwise QUIC dials the right IP but verifies relay.server_name and
        # fails before CONNECT-UDP (TLS alert 42).
        host = ms.rsplit(':', 1)[0].strip('[]')
        nb = setk(nb, 'masque_server_name', host)
        # Keep the ordinary TCP plan (for example Cloudflare grpc_stream)
        # independent from the direct UDP leg. Without this explicit UDP-only
        # plan a grpc-only fronted bundle rejects all UDP, while appending
        # masque_derived to transport_priority also makes the origin-exposing
        # direct transport eligible for TCP sessions.
        nb = setraw(nb, 'udp_transport_priority', '["masque_derived", "grpc_datagram"]')
    if ca:
        nb = setk(nb, 'masque_ca_cert', ca)
    t = t.replace(b, nb)
    open(p, 'w').write(t)
    print('masque_server=%s masque_server_name=%s masque_ca_cert=%s' % (ms or '<unchanged>', (ms.rsplit(':', 1)[0].strip('[]') if ms else '<unchanged>'), ca or '<unchanged>'))
else:
    print('WARN: no [relay] section; masque_server not set', file=sys.stderr)
PY
}

# Render the independent UDP plan even when no direct MASQUE endpoint was
# supplied. A configured MASQUE origin stays primary; fronted gRPC/H2 over
# TCP/443 is the censorship-resistant fallback (or the sole UDP carrier).
set_client_config_udp_relay_plan() {
  local cfg="$1"
  python3 -I - "$cfg" <<'PY'
import re, sys
p = sys.argv[1]
t = open(p).read()
m = re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)', t)
if not m:
    raise SystemExit("missing [relay] section in client config")
b = m.group(0)
has_masque = bool(re.search(r'(?m)^\s*masque_server\s*=\s*"[^\"]+"', b))
plan = '["masque_derived", "grpc_datagram"]' if has_masque else '["grpc_datagram"]'
if re.search(r'(?m)^\s*udp_transport_priority\s*=', b):
    nb = re.sub(
        r'(?m)^(\s*udp_transport_priority\s*=\s*).*$',
        lambda found: found.group(1) + plan,
        b,
        count=1,
    )
else:
    nb = b.rstrip() + '\nudp_transport_priority = ' + plan + '\n'
t = t.replace(b, nb, 1)
open(p, 'w').write(t)
print('udp_transport_priority=%s' % plan)
PY
}

# Render the explicit Geneva hybrid runtime contract. The Rust loader validates
# the same invariants again at every startup, so an operator edit cannot silently
# reintroduce passthrough or a non-fronted TCP transport after installation.
set_client_config_hybrid_geneva() {
  local cfg="$1" strategy_file="$2"
  python3 -I - "$cfg" "$strategy_file" <<'PY'
import json
import re
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
strategy_path = Path(sys.argv[2])
strategy = strategy_path.read_text(encoding="utf-8").strip()
if not strategy:
    raise SystemExit("Geneva strategy file is empty")

text = config_path.read_text(encoding="utf-8")

def set_top_level_mode(value):
    global text
    if re.search(r'(?m)^\s*mode\s*=', text):
        text = re.sub(r'(?m)^(\s*mode\s*=\s*).+$', r'\g<1>"%s"' % value, text, count=1)
    else:
        text = 'mode = "%s"\n' % value + text

def set_section_value(section, key, value):
    global text
    match = re.search(r'(?ms)^\[%s\]\s*$.*?(?=^\[|\Z)' % re.escape(section), text)
    if not match:
        raise SystemExit("missing [%s] section in client config" % section)
    block = match.group(0)
    if re.search(r'(?m)^\s*%s\s*=' % re.escape(key), block):
        updated = re.sub(
            r'(?m)^(\s*%s\s*=\s*).*$' % re.escape(key),
            lambda found: found.group(1) + value,
            block,
            count=1,
        )
    else:
        updated = block.rstrip() + '\n%s = %s\n' % (key, value)
    text = text.replace(block, updated, 1)

set_top_level_mode("auto")
set_section_value("direct", "strategies", '["geneva"]')
set_section_value("direct", "geneva_strategy", json.dumps(strategy))
set_section_value("direct", "hybrid_geneva", "true")
set_section_value("relay", "transport_priority", '["grpc_stream"]')
set_section_value("relay", "udp_transport_priority", '["masque_derived", "grpc_datagram"]')
config_path.write_text(text, encoding="utf-8")
PY
}

# Enable the client's fake-IP DNS preview server in [ingress.wide]: capture_dns +
# dns_preview_listen. Idempotent. Used when the resolved DNS policy is "preview"
# so the firewall's UDP/53 redirect has a responder.
set_client_dns_preview() {
  local cfg="$1" listen="$2"
  python3 -I - "$cfg" "$listen" <<'PY'
import re, sys
p, listen = sys.argv[1], sys.argv[2]
t = open(p).read()
def setkv_in_wide(text, key, val):
    if re.search(r'(?m)^\s*\[ingress\.wide\]\s*$', text):
        block = re.search(r'(?ms)^\[ingress\.wide\]\s*$.*?(?=^\[|\Z)', text).group(0)
        if re.search(r'(?m)^\s*%s\s*=' % key, block):
            nb = re.sub(r'(?m)^(\s*%s\s*=\s*).*$' % key, r'\g<1>%s' % val, block, count=1)
        else:
            nb = block.rstrip() + '\n' + key + ' = ' + val + '\n'
        return text.replace(block, nb)
    return text + '\n[ingress.wide]\n%s = %s\n' % (key, val)
t = setkv_in_wide(t, 'capture_dns', 'true')
t = setkv_in_wide(t, 'dns_preview_listen', '"%s"' % listen)
open(p, "w").write(t)
PY
}

pin_relay_server_to_resolved_ipv4() {
  local cfg="$1"
  python3 -I - "$cfg" <<'PY'
import ipaddress
import re
import socket
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
match = re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)', text)
if not match:
    sys.exit(0)
block = match.group(0)
server_pattern = re.compile(r'(\bserver\s*=\s*")([^"]+)(")')
if not server_pattern.search(block):
    sys.exit(0)
failures = []
pinned = []

def pin_server(server_match):
    server = server_match.group(2)
    if server.startswith("[") or ":" not in server:
        failures.append(f"unsupported relay endpoint {server!r}; full-wide requires an IPv4 relay egress")
        return server_match.group(0)
    host, port = server.rsplit(":", 1)
    try:
        ipaddress.ip_address(host)
        return server_match.group(0)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM)
    except Exception as exc:
        failures.append(f"could not resolve relay endpoint {host}:{port}: {exc}")
        return server_match.group(0)
    if not infos:
        failures.append(f"relay endpoint {host}:{port} resolved to no IPv4 address")
        return server_match.group(0)
    new_server = f"{infos[0][4][0]}:{port}"
    pinned.append((server, new_server))
    return f'{server_match.group(1)}{new_server}{server_match.group(3)}'

new_block = server_pattern.sub(pin_server, block)
if failures:
    for failure in failures:
        print(f"ERROR: relay loop-avoidance: {failure}", file=sys.stderr)
    print("ERROR: refusing full-wide activation with an unpinned relay endpoint; its control connection would be captured recursively", file=sys.stderr)
    sys.exit(1)
if new_block != block:
    path.write_text(text[:match.start()] + new_block + text[match.end():], encoding="utf-8")
for old, new in pinned:
    print(f"relay loop-avoidance: pinned endpoint {old} -> {new}; server_name remains the TLS/HTTP authority", file=sys.stderr)
PY
}

# Apply the NFQUEUE ENFORCE policy layer for full-wide-nfqueue on top of the
# REDIRECT TCP relay: install + apply fail-closed divert rules (generic UDP +
# IPv6, no --queue-bypass) and start the consumer that emits the per-packet
# verdict per the resolved product policy. NFQUEUE is the policy/verdict layer,
# never the TCP relay. Best-effort: returns nonzero if the helper/binary is
# unavailable so the caller can warn (REDIRECT + firewall fail-closed remain).
apply_nfqueue_policy_layer() {
  local cfg="$1" cuid="$2"
  local nscript="setup-wide-linux-nfqueue.sh" queue="${AEGIS_NFQ_QUEUE:-100}"
  if [[ -f "${ROOT}/scripts/${nscript}" ]]; then
    install -m 0755 "${ROOT}/scripts/${nscript}" "${AEGIS_WIDE_LIB_DIR}/${nscript}" 2>/dev/null || \
      cp "${ROOT}/scripts/${nscript}" "${AEGIS_WIDE_LIB_DIR}/${nscript}" 2>/dev/null || true
  fi
  local np="${AEGIS_WIDE_LIB_DIR}/${nscript}"
  [[ -x "$np" ]] || return 1

  # Loop-avoidance excludes: every resolved relay/CF endpoint IP (so the
  # client's relay leg is never queued). Space-separated for the helper.
  local excludes; excludes="$(relay_excludes_from_config "$cfg" | tr '\n' ' ')"

  # Derive the consumer's per-class block flags from the resolved policy. For
  # full-wide-nfqueue: udp=block, dns=preview (NOT dropped — REDIRECT preview
  # handles it), ipv6=capture (observe + fail-closed DROP).
  local block_args=()
  [[ "${RES_UDP_POLICY}" != "native" ]] && block_args+=(--nfqueue-udp-block)
  [[ "${RES_DNS_POLICY}" == "block" ]] && block_args+=(--nfqueue-dns-block)
  [[ "${RES_IPV6_POLICY}" == "block" || "${RES_IPV6_POLICY}" == "capture" ]] && block_args+=(--nfqueue-ipv6-block)

  echo "Applying NFQUEUE enforce policy layer (queue ${queue}, exempt uid ${cuid})..." >&2
  if ! AEGIS_NFQ_MODE=enforce AEGIS_EXEMPT_UID="${cuid}" AEGIS_RELAY_EXCLUDES="${excludes}" \
        bash "$np" apply --queue-num="${queue}" >&2; then
    echo "WARN: NFQUEUE enforce rules failed to apply." >&2
    return 1
  fi

  # Start the enforce consumer. Without it, the no-bypass rules fail CLOSED
  # (kernel DROPs) — safe — but starting it lets DNS be ACCEPTed (preview) while
  # generic UDP/IPv6 are DROPped per policy + witnessed.
  local bin; bin="$(command -v aegis-client 2>/dev/null || echo /usr/local/bin/aegis-client)"
  if [[ -x "${bin}" ]]; then
    if command -v systemd-run >/dev/null 2>&1; then
      systemd-run --unit=aegis-nfqueue --collect --setenv=AEGIS_NO_BANNER=1 \
        "${bin}" --nfqueue-observe "${queue}" --nfqueue-enforce "${block_args[@]}" \
        >/dev/null 2>&1 \
        && echo "NFQUEUE enforce consumer started (systemd unit aegis-nfqueue)." >&2 \
        || echo "WARN: could not start aegis-nfqueue consumer; rules remain fail-closed." >&2
    else
      echo "Note: start the NFQUEUE enforce consumer with:" >&2
      echo "  ${bin} --nfqueue-observe ${queue} --nfqueue-enforce ${block_args[*]}" >&2
    fi
  fi
  return 0
}

# Post-install product summary, rendered by the Rust model (single source of
# truth) so the printed scope can never drift from the enforced policy.
print_product_summary() {
  local bin="$1" cfg="$2"
  [[ -z "${PRODUCT_MODE}" ]] && return 0
  [[ -x "${bin}" ]] || return 0
  local extra=()
  [[ -n "${WIDE_UDP_POLICY}" ]] && extra+=(--udp "${WIDE_UDP_POLICY}")
  [[ -n "${WIDE_DNS_POLICY}" ]] && extra+=(--dns "${WIDE_DNS_POLICY}")
  [[ -n "${WIDE_IPV6_POLICY}" ]] && extra+=(--ipv6 "${WIDE_IPV6_POLICY}")
  [[ -n "${WIDE_INTERFACE}" ]] && extra+=(--interface "${WIDE_INTERFACE}")
  echo ""
  echo "════════════════════════════════════════════════════════════════════════"
  echo "AEGIS WIDE PRODUCT PROFILE"
  echo "════════════════════════════════════════════════════════════════════════"
  if ((${#extra[@]})); then
    "${bin}" profile resolve --mode "${PRODUCT_MODE}" "${extra[@]}" 2>/dev/null || true
  else
    "${bin}" profile resolve --mode "${PRODUCT_MODE}" 2>/dev/null || true
  fi
  echo "Config path:   ${cfg}"
  echo "Service:       aegis-client.service"
  echo "════════════════════════════════════════════════════════════════════════"
}

# Activate transparent wide capture for a wide mode. Fail-safe: if connectivity
# through the tunnel does not come up, the rules are torn down so the host is
# never left blackholed (important for a remote test host in a blocked region).
# Generic, infra-agnostic loop avoidance: read EVERY configured relay endpoint
# host from the operator's client config ([relay].server + every
# [[relay.endpoints]].server) and resolve each to its IPv4 address(es). Nothing
# here is AEGIS-specific — the relay set comes entirely from the bundle/config, so
# the project stays portable for any operator's own relays/domain.
relay_hosts_from_config() {
  python3 -I - "$1" <<'PY' 2>/dev/null || true
import re, sys
t = open(sys.argv[1]).read()
hosts = []
relay = re.search(r'(?ms)^\[relay\]\s*$.*?(?=^\[|\Z)', t)
if relay:
    # Match both the top-level `server` and inline `endpoints = [
    # { server = ... }]`. `\bserver` deliberately does not match
    # `masque_server` or `server_name`.
    hosts.extend(em.group(1) for em in re.finditer(r'\bserver\s*=\s*"([^"]+)"', relay.group(0)))
for endpoint_table in re.finditer(r'(?ms)^\[\[relay\.endpoints\]\]\s*$.*?(?=^\[|\Z)', t):
    em = re.search(r'(?m)^\s*server\s*=\s*"([^"]+)"', endpoint_table.group(0))
    if em:
        hosts.append(em.group(1))
seen = set()
for hp in hosts:
    h = hp.rsplit(":", 1)[0].strip("[]")
    if h and h not in seen:
        seen.add(h); print(h)
PY
}

# Resolve all configured relay hosts to a de-duplicated set of IPv4 addresses.
relay_excludes_from_config() {
  local cfg="$1" host
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s\n' "$host"
    else
      getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}'
    fi
  done < <(relay_hosts_from_config "$cfg") | sort -u
}

# The uid the aegis-client service runs as (systemd User=, default root/0). Wide
# loop-avoidance exempts this uid so the client's own relay leg is never
# redirected — robust for ANY relay (direct, Cloudflare-fronted, pool) without a
# hardcoded edge-IP list.
client_service_uid() {
  local u
  u="$(systemctl show aegis-client.service -p User --value 2>/dev/null)"
  if [[ -n "$u" ]]; then id -u "$u" 2>/dev/null || echo 0; else echo 0; fi
}

# Run the client under the DEDICATED `aegis` system uid via an additive systemd
# drop-in (never edits the base unit). This is what makes DNS capture/recovery
# privacy-safe WITHOUT breaking the relay leg: the wide DNS/redirect rules capture
# ordinary-user app DNS but EXEMPT the aegis service uid, so the client can still
# resolve the (Cloudflare-fronted) relay hostname for its control plane. Only used
# for redirect-family wide modes (the REDIRECT client needs no root); TPROXY-family
# keeps the default privileged unit. CAP_NET_BIND_SERVICE lets the fake-IP DNS
# server bind :53; NoNewPrivileges is relaxed only so the ambient cap applies.
# Resolve the dedicated SYSTEM account the redirect-family wide client runs as.
# CRITICAL: wide loop-avoidance EXEMPTS this uid from capture, so it must NEVER be
# the operator's login account — otherwise every app they run (browser, etc.)
# bypasses the tunnel (native IP; foreign sites blocked by the local censor) and a
# broken activation can knock the box off the network entirely. The convention is
# 'aegis'; but if 'aegis' already exists as a LOGIN account (uid >= 1000, e.g. the
# machine's human user is literally named aegis) we must NOT hijack it — fall back
# to a dedicated 'aegis-svc' system account, created on demand. Echoes the chosen
# name so the caller (client_service_uid → AEGIS_EXEMPT_UID) picks up the real uid.
resolve_wide_client_service_user() {
  local state_dir="$1" svc=aegis uid
  if uid="$(id -u aegis 2>/dev/null)"; then
    if [[ "${uid}" =~ ^[1-9][0-9]{3,}$ ]]; then
      svc=aegis-svc
      echo "note: 'aegis' is a login account (uid ${uid}); wide client will run as dedicated system user '${svc}' so capture does not exempt your login." >&2
    elif [[ ! "${uid}" =~ ^[1-9][0-9]{0,2}$ ]]; then
      echo "ERROR: 'aegis' must be a non-root system account or a login account with a separate system service user." >&2
      return 1
    fi
  fi
  if ! uid="$(id -u "${svc}" 2>/dev/null)"; then
    useradd --system --no-create-home --home-dir "${state_dir}" --shell /usr/sbin/nologin "${svc}" >&2 2>/dev/null || return 1
    uid="$(id -u "${svc}" 2>/dev/null)" || {
      echo "ERROR: dedicated system user '${svc}' is unavailable after creation." >&2
      return 1
    }
  fi
  if [[ ! "${uid}" =~ ^[1-9][0-9]{0,2}$ ]]; then
    echo "ERROR: dedicated system user '${svc}' must have a non-root system uid below 1000." >&2
    return 1
  fi
  printf '%s' "${svc}"
}

install_client_dedicated_uid_dropin() {
  local config_path="$1" ca_path="$2" state_dir="$3" events_path="$4"
  local capabilities="${5-CAP_NET_BIND_SERVICE}"
  local events_dir=''
  if [[ -n "${events_path}" && "${events_path}" != /dev/null ]]; then
    events_dir="${events_path%/*}"
  fi
  [[ ${EUID} -eq 0 ]] || return 0
  local svc
  svc="$(resolve_wide_client_service_user "${state_dir}")" || {
    echo "ERROR: could not resolve/create a dedicated system user; client activation was not attempted." >&2
    return 1
  }
  local config_root
  config_root="$(dirname "${config_path}")"
  local dropin_dir="${SYSTEMD_DIR}/aegis-client.service.d"
  # NOTE: the heredoc is read into a variable rather than passed as
  # "$(cat <<EOF ... EOF)". bash 3.2 (still /bin/bash on macOS) mis-parses a
  # heredoc nested inside command substitution: it loses track of quoting from
  # that point on and silently swallows the next function definitions instead
  # of erroring. That is how remove_client_dedicated_uid_dropin below vanished
  # and the client install died with "command not found" at line 3063.
  local dropin_content=''
  IFS= read -r -d '' dropin_content <<EOF || true
# Added by install.sh for redirect-family wide modes: run the client as a
# dedicated unprivileged SYSTEM uid so wide DNS/redirect rules can exempt ONLY
# this uid (relay control-plane DNS) while capturing ordinary user app DNS.
# The service user is resolved to never be the operator's login account
# (resolve_wide_client_service_user in install.sh; falls back to 'aegis-svc').
[Service]
User=${svc}
Group=${svc}
NoNewPrivileges=true
AmbientCapabilities=
AmbientCapabilities=${capabilities}
CapabilityBoundingSet=
CapabilityBoundingSet=${capabilities}
ReadWritePaths=${state_dir}${events_dir:+ ${events_dir}}
EOF
  # The runtime may read configuration but must never replace a directory
  # entry that the privileged installer later writes. Runtime state remains
  # separately writable. Private TLS key files retain owner-only access.
  chown "root:${svc}" "${config_root}" "${config_path}" || return 1
  chmod 0750 "${config_root}" || return 1
  chmod 0640 "${config_path}" || return 1
  if [[ -f "${ca_path}" ]]; then
    chown "root:${svc}" "${ca_path}" || return 1
    chmod 0640 "${ca_path}" || return 1
  fi
  # full-wide-tun also ships a masque-ca.pem; the ${svc} service uid opens it for
  # the direct-MASQUE leg, so make it readable too (same rationale as ca.pem above).
  if [[ -f "${config_root}/masque-ca.pem" ]]; then
    chown "root:${svc}" "${config_root}/masque-ca.pem" || return 1
    chmod 0640 "${config_root}/masque-ca.pem" || return 1
  fi
  chown -h -R -P "${svc}:${svc}" "${state_dir}" || return 1
  if [[ -n "${events_dir}" ]]; then
    mkdir -p "${events_dir}" || return 1
    chown -h -R -P "${svc}:${svc}" "${events_dir}" || return 1
  fi
  # Keep the previous service profile until its required filesystem access is
  # prepared. A later write/unlink failure still stops activation; these two
  # profile files and earlier installer work are not a transaction.
  ensure_dir "${dropin_dir}" || return 1
  install_text_file "${dropin_dir}/10-dedicated-uid.conf" 0644 "${dropin_content%$'\n'}" || return 1
  rm -f "${dropin_dir}/20-ipv6-tun.conf" 2>/dev/null || return 1
  echo "dedicated uid: aegis-client will run as '${svc}' with the selected capability policy." >&2
}

# Profiles requiring privileged engines cannot inherit a dedicated-UID
# drop-in from a previous SOCKS or redirect install. full-wide-tun installs
# its own explicit capability policy through install_client_ipv6_tun_dropin.
remove_client_dedicated_uid_dropin() {
  local dropin_dir="${SYSTEMD_DIR}/aegis-client.service.d"
  if [[ -f "${dropin_dir}/10-dedicated-uid.conf" ]]; then
    rm -f "${dropin_dir}/10-dedicated-uid.conf"
    # Drop the now-empty drop-in dir so `systemctl cat` stays clean.
    rmdir "${dropin_dir}" 2>/dev/null || true
    echo "removed stale 10-dedicated-uid.conf (root-runtime profile reads its root-owned config directly)." >&2
  fi
  if [[ -f "${dropin_dir}/20-ipv6-tun.conf" ]]; then
    rm -f "${dropin_dir}/20-ipv6-tun.conf"
    rmdir "${dropin_dir}" 2>/dev/null || true
    echo "removed stale 20-ipv6-tun.conf (non-TUN profile must not retain capture capabilities or socket marks)." >&2
  fi
}

# full-wide-tun: belt-and-suspenders teardown. The aegis-tun0 device is
# non-persistent, so a clean process exit already drops its ::/1 + 8000::/1
# capture routes (real ::/0 restored). This ExecStopPost guarantees removal even
# on SIGKILL where the in-process RAII guard never runs. CAP_NET_ADMIN is implicit
# (this mode runs the client as root for /dev/net/tun + route changes).
install_client_ipv6_tun_dropin() {
  local dropin_dir="${SYSTEMD_DIR}/aegis-client.service.d"
  ensure_dir "${dropin_dir}"
  # full-wide-tun runs the client as root with CAP_NET_ADMIN. A prior
  # redirect-family install may have left a 10-dedicated-uid.conf that pins
  # User=aegis + CapabilityBoundingSet=CAP_NET_BIND_SERVICE — which would cap out
  # CAP_NET_ADMIN and stop the TUN engine. Remove it so a mode-switch works (a
  # fresh full-wide-tun install never has it).
  if [[ -f "${dropin_dir}/10-dedicated-uid.conf" ]]; then
    rm -f "${dropin_dir}/10-dedicated-uid.conf"
    echo "full-wide-tun: removed stale 10-dedicated-uid.conf before applying the TUN capability policy." >&2
  fi
  # NOTE: the heredoc is read into a variable rather than passed as
  # "$(cat <<EOF ... EOF)". bash 3.2 (still /bin/bash on macOS) mis-parses a
  # heredoc nested inside command substitution: it loses track of quoting from
  # that point on and silently swallows the next function definitions instead
  # of erroring. That is how remove_client_dedicated_uid_dropin below vanished
  # and the client install died with "command not found" at line 3063.
  local direct_mark_line=''
  local capabilities='CAP_NET_ADMIN CAP_NET_BIND_SERVICE'
  if [[ "${PRODUCT_MODE:-}" == "full-wide-hybrid-geneva" ]]; then
    direct_mark_line="Environment=AEGIS_DIRECT_SOCKET_MARK=${AEGIS_HYBRID_DIRECT_SOCKET_MARK}"
    capabilities="${capabilities} CAP_NET_RAW"
  fi
  local tun_dropin_content=''
  IFS= read -r -d '' tun_dropin_content <<EOF || true
# Added by install.sh for full-wide-tun: guarantee IPv6 capture teardown even on
# SIGKILL (the non-persistent tun + in-process RAII cover clean exits).
[Service]
NoNewPrivileges=true
AmbientCapabilities=
AmbientCapabilities=${capabilities}
CapabilityBoundingSet=
CapabilityBoundingSet=${capabilities}
${direct_mark_line}
ExecStopPost=/bin/sh -c 'ip -6 route del ::/1 dev aegis-tun0 2>/dev/null; ip -6 route del 8000::/1 dev aegis-tun0 2>/dev/null; ip link del aegis-tun0 2>/dev/null; true'
EOF
  install_text_file "${dropin_dir}/20-ipv6-tun.conf" 0644 "${tun_dropin_content%$'\n'}"
  echo "full-wide-tun: installed ExecStopPost IPv6 capture-teardown drop-in (SIGKILL-safe)." >&2
}

preflight_wide_capture() {
  local mode="$1" script
  case "$mode" in
    client-wide-redirect|client-wide-nfqueue-observer|client-ipv6-tun-smoltcp)
      script="setup-wide-linux-redirect.sh" ;;
    client-wide-tproxy) script="setup-wide-linux-tproxy.sh" ;;
    *) return 0 ;;
  esac
  [[ "$(id -u)" == "0" ]] || {
    echo 'ERROR: requested wide activation requires root; installation was not activated.' >&2
    return 1
  }
  [[ -f "${ROOT}/scripts/${script}" && -r "${ROOT}/scripts/${script}" &&
     -x "${ROOT}/scripts/${script}" ]] || {
    echo 'ERROR: requested wide setup helper is unavailable; activation refused.' >&2
    return 1
  }
  [[ -f "${ROOT}/scripts/lib/root-state.sh" && -r "${ROOT}/scripts/lib/root-state.sh" ]] || {
    echo 'ERROR: requested wide root-state helper is unavailable; activation refused.' >&2
    return 1
  }
}

activate_wide_capture() {
  local cfg="$1" mode="$2"
  preflight_wide_capture "$mode" || return $?
  local backend script port=15080
  case "$mode" in
    client-wide-redirect) backend="linux_redirect"; script="setup-wide-linux-redirect.sh" ;;
    client-wide-tproxy)   backend="linux_tproxy";   script="setup-wide-linux-tproxy.sh" ;;
    # full-wide-nfqueue carries TCP via the REDIRECT relay path; the NFQUEUE
    # observe/policy layer (UDP/IPv6 fail-closed + witness) is applied on top by
    # apply_nfqueue_policy_layer below. NFQUEUE is NOT the TCP relay (it cannot
    # terminate connections) — it is the policy/verdict layer.
    client-wide-nfqueue-observer) backend="linux_redirect"; script="setup-wide-linux-redirect.sh" ;;
    # full-wide-tun: v4 TCP via the REDIRECT relay path; the IPv6 TUN+smoltcp
    # engine is launched in-process by the client (ipv6_tun_carried below) and
    # IPv6 is routed INTO the tun rather than fail-closed-blocked.
    client-ipv6-tun-smoltcp) backend="linux_redirect"; script="setup-wide-linux-redirect.sh" ;;
    *) return 0 ;;
  esac
  # Both local interception sockets must require CAP_NET_BIND_SERVICE; a local
  # unprivileged process must not impersonate capture during client restart.
  [[ "${PRODUCT_MODE:-}" != full-wide-tun ]] || port=980
  mkdir -p "${AEGIS_WIDE_LIB_DIR}/lib" || return 1
  install_copy_file "${ROOT}/scripts/lib/root-state.sh" "${AEGIS_WIDE_LIB_DIR}/lib/root-state.sh" 0755 || return 1
  if [[ -f "${ROOT}/scripts/${script}" ]]; then
    install -m 0755 "${ROOT}/scripts/${script}" "${AEGIS_WIDE_LIB_DIR}/${script}" 2>/dev/null || \
      cp "${ROOT}/scripts/${script}" "${AEGIS_WIDE_LIB_DIR}/${script}" || {
        echo 'ERROR: wide setup helper could not be installed; activation refused.' >&2
        return 1
      }
  fi
  for wrapper_script in aegis-wide-enable.sh aegis-wide-disable.sh aegis-wide-persist-install.sh janitor-wide-linux-tproxy.sh; do
    if [[ -f "${ROOT}/scripts/${wrapper_script}" ]]; then
      install -m 0755 "${ROOT}/scripts/${wrapper_script}" "${AEGIS_WIDE_LIB_DIR}/${wrapper_script}" 2>/dev/null || \
        cp "${ROOT}/scripts/${wrapper_script}" "${AEGIS_WIDE_LIB_DIR}/${wrapper_script}" 2>/dev/null || true
    fi
  done
  local persisted="${AEGIS_WIDE_LIB_DIR}/${script}"
  local enable_wrapper="${AEGIS_WIDE_LIB_DIR}/aegis-wide-enable.sh"
  local disable_wrapper="${AEGIS_WIDE_LIB_DIR}/aegis-wide-disable.sh"
  local persist_installer="${AEGIS_WIDE_LIB_DIR}/aegis-wide-persist-install.sh"
  local used_wrapper=0
  local teardown_cmd="bash ${persisted} teardown"
  [[ -x "$persisted" ]] || { echo "ERROR: installed wide setup helper missing; activation refused." >&2; return 1; }
  if [[ "${PRODUCT_MODE:-}" == full-wide-tun &&
        "$(bash "$persisted" guard-version)" != aegis_legacy_tun_guard_v1 ]]; then
    echo 'ERROR: signed helper lacks the independent TUN guard; wide config/start was not changed.' >&2
    return 1
  fi

  # TUN needs a root service. Its OUTPUT exemption must identify only that
  # service, including when relay endpoints move or share CDN IPs with users.
  # Probe support before changing config or restarting the running client.
  local require_cgroup=0 exempt_service="" exempt_cgroup=""
  if [[ "${mode}" == "client-ipv6-tun-smoltcp" ]]; then
    require_cgroup=1
    exempt_service="aegis-client.service"
    if ! AEGIS_WIDE_REQUIRE_CGROUP=1 AEGIS_WIDE_EXEMPT_SERVICE="$exempt_service" \
         AEGIS_WIDE_EXEMPT_CGROUP="" bash "$persisted" preflight; then
      echo "ERROR: strict service cgroup capture is unavailable; wide config was not changed." >&2
      return 1
    fi
  fi
  local cuid; cuid="$(client_service_uid)"
  set_client_config_wide "$cfg" "$backend" "$port"
  # --udp-carry: opt into generic v4 UDP carry (incl QUIC/443) over the relay plan. Only the
  # linux_redirect backend runs the conntrack redirect proxy; on any other backend
  # the flag is a no-op (warn) rather than a silent false promise.
  local udp_redirect_port=""
  if [[ "${UDP_CARRY}" == "1" ]]; then
    if [[ "${backend}" == "linux_redirect" ]]; then
      set_client_config_udp_contract "$cfg" "generic_capture_unstable"
      udp_redirect_port="$((port + 1))"
      echo "--udp-carry: generic v4 UDP carry ENABLED (contract=generic_capture_unstable, proxy 127.0.0.1:${udp_redirect_port}); MASQUE preferred, gRPC/H2 fallback. UNSTABLE path." >&2
    else
      echo "--udp-carry: ignored — backend '${backend}' has no generic UDP redirect proxy (linux_redirect only)." >&2
    fi
  fi
  # full-wide-tun: enable the in-process IPv6 TUN+smoltcp engine (the only mode
  # that carries IPv6 rather than fail-closed-blocking it).
  if [[ "${mode}" == "client-ipv6-tun-smoltcp" ]]; then
    set_client_config_ipv6_tun "$cfg" true
    # Direct-MASQUE UDP leg (optional): point the preferred QUIC carry at a
    # direct origin + its CA. Without these, the UDP plan uses fronted
    # grpc_datagram over H2/TCP instead of failing or leaking natively.
    if [[ -n "${MASQUE_SERVER}" || -n "${MASQUE_CA}" ]]; then
      local masque_ca_dst=""
      if [[ -n "${MASQUE_CA}" && -f "${MASQUE_CA}" ]]; then
        masque_ca_dst="$(dirname "$cfg")/masque-ca.pem"
        if [[ "${MASQUE_CA}" != "${masque_ca_dst}" ]]; then
          install -m 0644 "${MASQUE_CA}" "${masque_ca_dst}" 2>/dev/null || cp "${MASQUE_CA}" "${masque_ca_dst}"
        fi
        chown aegis:aegis "${masque_ca_dst}" 2>/dev/null || true
      fi
      set_client_config_masque "$cfg" "${MASQUE_SERVER}" "${masque_ca_dst}"
      echo "full-wide-tun: MASQUE UDP leg -> direct origin ${MASQUE_SERVER:-<unchanged>} (UDP egress is NOT CF-fronted; origin IP is exposed for the UDP leg)." >&2
    fi
    set_client_config_udp_relay_plan "$cfg"
  fi
  # For TPROXY, the helper can deliver UDP/53 with original-destination
  # preservation to the wide listener. For REDIRECT, UDP NAT rewrites the
  # destination to the local listener and loses the useful original DNS target;
  # the correct product path is the wrapper's resolver-based fake-IP DNS
  # listener on 127.0.0.1:53.
  if [[ "${backend}" == "linux_redirect" && "${RES_DNS_POLICY:-}" == "preview" ]]; then
    if ! pin_relay_server_to_resolved_ipv4 "$cfg"; then
      echo "ERROR: relay endpoint pinning failed; refusing capture activation." >&2
      return 1
    fi
  fi
  # main routes non-redirect preview here; full-wide-tun (redirect + tun) uses the
  # standard apply path below (not the dns wrapper), so it also needs the listener.
  if [[ "${RES_DNS_POLICY}" == "preview" && ( "${backend}" != "linux_redirect" || "${mode}" == "client-ipv6-tun-smoltcp" ) ]]; then
    # Bind the fake-IP listener on :53 (NOT the wide TCP port): the resolver must
    # reach it as an ordinary nameserver once resolv.conf is repointed below.
    set_client_dns_preview "$cfg" "127.0.0.1:53"
  fi
  if [[ "${PRODUCT_MODE:-}" == full-wide-tun ]]; then
    [[ "$udp_redirect_port" == 981 ]] || { echo 'ERROR: full-wide TUN requires its UDP carry listener.' >&2; return 1; }
    if ! install_legacy_tun_guard_unit "$persisted" "$port" "$udp_redirect_port"; then
      echo 'ERROR: independent legacy TUN guard was not armed; capture activation refused.' >&2
      return 1
    fi
    teardown_cmd="bash ${disable_wrapper}"
  fi
  if ! restart_systemd_unit_checked aegis-client.service; then
    echo "ERROR: aegis-client.service did not restart with the rendered wide config; refusing capture activation." >&2
    return 1
  fi
  sleep 3
  if [[ "$require_cgroup" == 1 ]]; then
    exempt_cgroup="$(AEGIS_WIDE_REQUIRE_CGROUP=1 AEGIS_WIDE_EXEMPT_SERVICE="$exempt_service" \
      AEGIS_WIDE_EXEMPT_CGROUP="" bash "$persisted" cgroup-path)" || {
      echo "ERROR: restarted client has no verified service cgroup; refusing capture activation." >&2
      return 1
    }
  fi

  echo "Activating transparent wide capture (${mode}, port ${port}, client uid ${cuid})..." >&2
  # Loop avoidance is PRIMARILY by exempting the client service's own uid: its
  # relay leg (to a direct IP, a Cloudflare-fronted edge, or any pooled endpoint)
  # is never redirected, with no hardcoded edge-IP list — robust for any relay
  # topology. We ALSO RETURN the resolved IPs of every configured relay endpoint
  # (a best-effort snapshot) so non-client traffic to a direct relay isn't looped.
  #
  # Firewall knobs. When a product profile resolved explicit policies, derive the
  # fail-closed knobs from them (the Rust model is the source of truth). Otherwise
  # keep the legacy turnkey defaults (IPv4 DNS/UDP NATIVE so a remote host can
  # never be DNS-blackholed, IPv6 BLOCKED) for a bare internal `--mode
  # wide-redirect` with no product profile — back-compat, no behavior change.
  local k_block_udp=0 k_block_tcp_dns=0 k_block_ipv6=1 k_dns_preview=0 k_ipv6_tun_dev="" direct_socket_mark=""
  if [[ -n "${RES_UDP_POLICY}" ]]; then
    [[ "${RES_UDP_POLICY}" != "native" ]] && k_block_udp=1
    [[ "${RES_DNS_POLICY}" == "block" ]] && k_block_tcp_dns=1
    [[ "${RES_DNS_POLICY}" == "preview" ]] && k_dns_preview=1
    if [[ "${RES_IPV6_POLICY}" == "native" ]]; then k_block_ipv6=0; else k_block_ipv6=1; fi
    # full-wide-tun: IPv6 is captured by the TUN (routed into aegis-tun0), so the
    # fail-closed IPv6 backstop must EXEMPT the tun device (reject only IPv6 that
    # escapes to the real WAN). Keep block_ipv6=1 (the backstop) + name the tun.
    if [[ "${RES_IPV6_POLICY}" == "tun_carried" ]]; then k_block_ipv6=1; k_ipv6_tun_dev="aegis-tun0"; fi
    echo "wide policy (${PRODUCT_MODE:-internal}): udp=${RES_UDP_POLICY} dns=${RES_DNS_POLICY} ipv6=${RES_IPV6_POLICY} leak=${RES_LEAK_RISK} -> block_udp=${k_block_udp} dns_preview=${k_dns_preview} block_tcp_dns=${k_block_tcp_dns} block_ipv6=${k_block_ipv6} ipv6_tun_dev=${k_ipv6_tun_dev:-<none>}" >&2
  fi
  # --udp-carry override: instead of fail-closing v4 UDP, REDIRECT it to the
  # conntrack proxy (setup-wide-linux-redirect.sh reads AEGIS_WIDE_UDP_REDIRECT_PORT
  # and stops REJECT-ing UDP). Applied after the policy-derived knobs so it wins.
  if [[ -n "${udp_redirect_port}" ]]; then k_block_udp=0; fi
  # The strict TUN path deliberately has no destination-IP, UID, or socket-mark
  # exemptions. Only sockets created within the verified service cgroup escape.
  # Compatibility profiles still use their existing non-root loop avoidance.
  local relay_exclude_ips="" capture_root=0
  [[ "$require_cgroup" == 1 ]] && capture_root=1
  # full-wide-tun needs the IPv6 backstop to exempt the tun (AEGIS_WIDE_IPV6_TUN_DEV),
  # which the dns-preview wrapper does not pass — so when a tun device is named, use
  # the direct apply path. Non-tun redirect+preview keeps main's wrapper path verbatim.
  if [[ "${backend}" == "linux_redirect" && "${k_dns_preview}" == "1" && -z "${k_ipv6_tun_dev}" && -x "${enable_wrapper}" && -x "${disable_wrapper}" ]]; then
    used_wrapper=1
    teardown_cmd="bash ${disable_wrapper}"
    if ! AEGIS_CONFIG_FILE="$cfg" AEGIS_WIDE_PORT="$port" AEGIS_WIDE_ROLLBACK_SECS="${AEGIS_WIDE_ROLLBACK_SECS:-180}" \
          bash "$enable_wrapper" --yes --mode=redirect --ssh-safe-ports="${AEGIS_WIDE_SSH_SAFE_PORTS:-22}" --dns=preview --udp="$([[ -n "${udp_redirect_port}" ]] && echo carry || echo block)" --ipv6="$([[ "$k_block_ipv6" == "1" ]] && echo block || echo out_of_scope)" >&2; then
      echo "ERROR: wide wrapper apply failed; tearing down." >&2
      AEGIS_CONFIG_FILE="$cfg" AEGIS_WIDE_PORT="$port" bash "$disable_wrapper" >/dev/null 2>&1 || true
      return 1
    fi
  else
    # P1: propagate the operator-supplied downstream interface (--wide-interface)
    # to the helper. Without AEGIS_WIDE_INTERFACE the TPROXY helper has no
    # PREROUTING scope: it either refuses (fail-safe) or, on an all-interface
    # lab run, would capture the host's OWN uplink. Empty when --wide-interface
    # was not given → unchanged default (host-local) behaviour. Gateway-tproxy
    # (routed downstream) REQUIRES this to be its LAN interface.
    if ! AEGIS_WIDE_PORT="$port" AEGIS_EXEMPT_UID="$cuid" AEGIS_WIDE_INTERFACE="${WIDE_INTERFACE}" \
          AEGIS_DIRECT_SOCKET_MARK="${direct_socket_mark}" \
          AEGIS_WIDE_REQUIRE_CGROUP="$require_cgroup" AEGIS_WIDE_EXEMPT_SERVICE="$exempt_service" AEGIS_WIDE_EXEMPT_CGROUP="$exempt_cgroup" \
          AEGIS_WIDE_BLOCK_LEAKS=1 AEGIS_WIDE_BLOCK_UDP="${k_block_udp}" AEGIS_WIDE_BLOCK_TCP_DNS="${k_block_tcp_dns}" AEGIS_WIDE_BLOCK_IPV6="${k_block_ipv6}" AEGIS_ENABLE_DNS_PREVIEW="${k_dns_preview}" AEGIS_WIDE_MANAGE_RESOLV="${k_dns_preview}" AEGIS_WIDE_IPV6_TUN_DEV="${k_ipv6_tun_dev}" AEGIS_WIDE_UDP_REDIRECT_PORT="${udp_redirect_port}" AEGIS_WIDE_RELAY_EXCLUDE_IPS="${relay_exclude_ips}" AEGIS_WIDE_CAPTURE_ROOT="${capture_root}" \
          bash "$persisted" apply >&2; then
      echo "ERROR: wide apply failed; tearing down." >&2
      AEGIS_WIDE_PORT="$port" AEGIS_WIDE_BLOCK_LEAKS=1 AEGIS_WIDE_BLOCK_IPV6="${k_block_ipv6}" bash "$persisted" teardown >/dev/null 2>&1 || true
      return 1
    fi
  fi
  if [[ "$require_cgroup" == 1 ]]; then
    echo "loop-avoidance: verified service cgroup ${exempt_cgroup}; other traffic to relay IPs remains captured" >&2
  else
    # Compatibility profiles retain their existing relay exclusions.
    local _rip _added=0
    while IFS= read -r _rip; do
      [[ -z "$_rip" ]] && continue
      iptables -t nat -C AEGIS_WIDE_OUTPUT -d "$_rip" -p tcp -j RETURN 2>/dev/null || \
        iptables -t nat -I AEGIS_WIDE_OUTPUT 1 -d "$_rip" -p tcp -j RETURN 2>/dev/null || true
      _added=$((_added+1))
    done < <(relay_excludes_from_config "$cfg")
    echo "loop-avoidance: client uid ${cuid} exempt + ${_added} relay endpoint IP(s) excluded" >&2
  fi

  # Fail-safe connectivity probe THROUGH the tunnel (root traffic is captured now).
  # The first relay session is "cold" and high-latency / censored networks (e.g.
  # from a blocked region to the relay) can take far longer than a single short
  # timeout, so retry several times over a generous window before deciding the
  # tunnel is dead. Tunable via AEGIS_WIDE_PROBE_ATTEMPTS / AEGIS_WIDE_PROBE_TIMEOUT.
  local attempts="${AEGIS_WIDE_PROBE_ATTEMPTS:-5}"
  local per_timeout="${AEGIS_WIDE_PROBE_TIMEOUT:-20}"
  local code="000" i
  for ((i = 1; i <= attempts; i++)); do
    code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time "$per_timeout" https://1.1.1.1/ 2>/dev/null || echo 000)"
    if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
      break
    fi
    echo "wide egress probe ${i}/${attempts} not ready (HTTP ${code}); retrying..." >&2
    sleep 2
  done
  if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
    # DNS fail-safe: when the policy CAPTURES DNS (preview), a host that can reach
    # IPs but can no longer resolve names is broken. Verify name resolution still
    # works; if not, roll back so the host is never left unable to resolve. (For
    # dns=block this failure is intentional, so it is skipped; for dns=native DNS
    # is unchanged.)
    if [[ "${RES_DNS_POLICY}" == "preview" ]]; then
      local dns_ok=0 dn
      local dns_probe=(getent)
      if [[ "${AUTO_PROFILE:-0}" == "1" ]]; then
        dns_probe=(timeout 10 getent)
      fi
      for dn in 1 2 3; do
        if "${dns_probe[@]}" hosts example.com >/dev/null 2>&1 || "${dns_probe[@]}" hosts cloudflare.com >/dev/null 2>&1; then
          dns_ok=1; break
        fi
        sleep 2
      done
      if [[ "${dns_ok}" != "1" ]]; then
        echo "ERROR: DNS resolution did not work under captured-DNS policy; tearing down to keep the host resolvable." >&2
        if [[ "${used_wrapper}" == "1" ]]; then
          AEGIS_CONFIG_FILE="$cfg" AEGIS_WIDE_PORT="$port" bash "$disable_wrapper" >/dev/null 2>&1 || true
        else
          AEGIS_WIDE_PORT="$port" bash "$persisted" teardown >/dev/null 2>&1 || true
        fi
        echo "Wide capture rolled back (DNS preview not resolving). An armed TUN guard remains until explicit disconnect." >&2
        echo "Retry with --dns-policy block (intentional no-DNS) or --profile wide-compat (native DNS)." >&2
        return 1
      fi
      echo "DNS resolution verified under captured-DNS (preview) policy." >&2
    fi
    # full-wide-nfqueue: apply the NFQUEUE observe/policy layer on top of the
    # REDIRECT TCP relay (UDP/IPv6 fail-closed + per-packet witness).
    if [[ "${mode}" == "client-wide-nfqueue-observer" ]]; then
      apply_nfqueue_policy_layer "$cfg" "$cuid" || \
        echo "WARN: NFQUEUE policy layer not applied; TCP relay + firewall fail-closed still active." >&2
    fi
    # wide-udp-direct: health-check the MASQUE direct CONNECT-UDP path against a
    # controlled echo target if the operator provided one. Generic UDP stays
    # blocked at the firewall regardless — this only reports whether MASQUE
    # direct can additionally carry it (no native fallback on failure).
    if [[ "${RES_UDP_POLICY}" == "masque_direct" && -n "${AEGIS_MASQUE_UDP_HEALTH_TARGET:-}" ]]; then
      local mbin; mbin="$(command -v aegis-client 2>/dev/null || echo /usr/local/bin/aegis-client)"
      if [[ -x "${mbin}" ]]; then
        echo "Health-checking MASQUE direct UDP via ${AEGIS_MASQUE_UDP_HEALTH_TARGET}..." >&2
        if "${mbin}" --config "$cfg" --masque-udp-health "${AEGIS_MASQUE_UDP_HEALTH_TARGET}" >&2; then
          echo "MASQUE direct UDP healthy — generic UDP may be carried via MASQUE." >&2
        else
          echo "MASQUE direct UDP health FAILED — generic UDP stays blocked (no native fallback)." >&2
        fi
      fi
    fi
    if [[ "${used_wrapper}" == "1" ]]; then
      touch /run/aegis-wide-confirmed 2>/dev/null || true
    fi
    # Persist only a profile that has passed the live tunnel and DNS probes.
    # Safe non-TUN profiles use the generic wrapper-backed boot unit; the TUN
    # profile needs its exact low-level environment and specialised unit.
    if [[ -n "${k_ipv6_tun_dev}" ]]; then
      if ! install_wide_tun_boot_unit "$persisted" "$port" "$cuid" "$k_block_udp" "$k_block_tcp_dns" \
          "$k_block_ipv6" "$k_dns_preview" "$k_ipv6_tun_dev" "$udp_redirect_port" "$relay_exclude_ips" "$capture_root" "$direct_socket_mark" "$require_cgroup" "$exempt_service" "$exempt_cgroup"; then
        echo "ERROR: full-wide-tun capture persistence failed; capture is removed and the independent guard is retained." >&2
        AEGIS_WIDE_PORT="$port" bash "$persisted" teardown >/dev/null 2>&1 || true
        inject_client_default_primary_socks5 "$cfg" || true
        restart_systemd_unit_checked aegis-client.service 2>/dev/null || true
        return 1
      fi
    elif [[ "${RES_LEAK_RISK:-high}" != "high" ]]; then
      if ! install_wide_profile_boot_unit "$enable_wrapper" "$persist_installer" "$backend" \
          "$k_dns_preview" "$k_block_ipv6" "$udp_redirect_port" "$WIDE_INTERFACE"; then
        echo "ERROR: wide reboot persistence failed; tearing down rather than leaving a reboot-fail-open install." >&2
        if [[ "${used_wrapper}" == "1" ]]; then
          AEGIS_CONFIG_FILE="$cfg" AEGIS_WIDE_PORT="$port" bash "$disable_wrapper" >/dev/null 2>&1 || true
        else
          AEGIS_WIDE_PORT="$port" bash "$persisted" teardown >/dev/null 2>&1 || true
        fi
        inject_client_default_primary_socks5 "$cfg" || true
        restart_systemd_unit_checked aegis-client.service 2>/dev/null || true
        return 1
      fi
    fi
    echo "Wide capture ACTIVE — transparent egress verified (HTTP ${code}). No SOCKS config needed." >&2
    echo "Teardown later with: sudo ${teardown_cmd}" >&2
    printf '{"operator_mode":"%s","product_mode":"%s","wide_active":true,"backend":"%s","udp_policy":"%s","dns_policy":"%s","ipv6_policy":"%s","teardown":"%s"}\n' \
      "$mode" "${PRODUCT_MODE}" "$backend" "${RES_UDP_POLICY}" "${RES_DNS_POLICY}" "${RES_IPV6_POLICY}" "${teardown_cmd}" | install_atomic_write "${AEGIS_WIDE_LIB_DIR}/wide-state.json" 0644 strict || return 1
  else
    echo "ERROR: egress through wide capture did not verify after ${attempts} attempts (HTTP ${code}); tearing down to keep the host online." >&2
    if [[ "${used_wrapper}" == "1" ]]; then
      AEGIS_CONFIG_FILE="$cfg" AEGIS_WIDE_PORT="$port" bash "$disable_wrapper" >/dev/null 2>&1 || true
    else
      AEGIS_WIDE_PORT="$port" bash "$persisted" teardown >/dev/null 2>&1 || true
    fi
    echo "Wide capture rolled back. Host networking restored. Check relay reachability, then retry." >&2
    inject_client_default_primary_socks5 "$cfg" || true
    if ! restart_systemd_unit_checked aegis-client.service; then
      echo "ERROR: fallback SOCKS config was restored but aegis-client.service did not restart." >&2
    fi
    echo "Fallback SOCKS mode restored in client config." >&2
    return 1
  fi
}
# Validate-only fast path for packaging contracts (no install side effects).
if [[ "${AEGIS_INSTALL_VALIDATE_MODE_ONLY:-0}" == "1" ]]; then
  echo "product_mode=${PRODUCT_MODE:-<none>}"
  echo "operator_mode=${OPERATOR_MODE:-<none>}"
  echo "operator_transport=${OPERATOR_TRANSPORT:-<none>}"
  echo "fronted_authority=${FRONTED_AUTHORITY:-<none>}"
  echo "wide_interface=${WIDE_INTERFACE:-<none>}"
  echo "udp_policy_override=${WIDE_UDP_POLICY:-<none>}"
  echo "dns_policy_override=${WIDE_DNS_POLICY:-<none>}"
  echo "ipv6_policy_override=${WIDE_IPV6_POLICY:-<none>}"
  echo "geneva_strategy_file=${GENEVA_STRATEGY_FILE:-<none>}"
  echo "udp_carry=${UDP_CARRY}"
  exit 0
fi

# Branded install banner (flair). Suppressed in CI/validate paths via AEGIS_NO_BANNER.
aegis_banner() {
  [[ "${AEGIS_NO_BANNER:-0}" == "1" ]] && return 0
  local ver="dev"
  [[ -f "${ROOT}/release.manifest.json" ]] && ver="$(grep -oE '"version"[^,]*' "${ROOT}/release.manifest.json" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  local C='' B='' DIM='' R=''
  if [[ -t 2 ]]; then C=$'\033[38;5;45m'; B=$'\033[1;38;5;51m'; DIM=$'\033[2m'; R=$'\033[0m'; fi
  {
    printf '%s\n' ""
    printf '%s █████╗ ███████╗ ██████╗ ██╗███████╗%s\n' "$C" "$R"
    printf '%s██╔══██╗██╔════╝██╔════╝ ██║██╔════╝%s\n' "$C" "$R"
    printf '%s███████║█████╗  ██║  ███╗██║███████╗%s\n' "$C" "$R"
    printf '%s██╔══██║██╔══╝  ██║   ██║██║╚════██║%s\n' "$C" "$R"
    printf '%s██║  ██║███████╗╚██████╔╝██║███████║%s\n' "$C" "$R"
    printf '%s╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝%s\n' "$C" "$R"
    printf '          %sAEGIS%s  ·  %sby AEGIS contributors%s\n' "$B" "$R" "$B" "$R"
    printf '   %sadaptive censorship-resilient transport%s%s\n' "$DIM" "${ver:+ · v$ver}" "$R"
    printf '%s\n' ""
  } >&2
}
aegis_banner

# The normal client path uses the Rust automatic planner after bundle/binary
# acquisition. Advanced profiles remain available through --profile / --mode.

# Interactive server setup — only with a real terminal and when identity flags
# were not supplied. Piped curl|bash has no TTY and keeps the flag-driven path.
if [[ "${ROLE}" == "server" && -z "${AEGIS_INSTALL_NONINTERACTIVE:-}" && -z "${RELAY_ADDRESS}" && -e /dev/tty ]] && { [[ -t 0 ]] || [[ -t 2 ]]; }; then
  printf 'AEGIS relay setup:\n' >&2
  printf '  Public host/IP clients will reach (FQDN or IP): ' >&2
  read -r _aegis_host </dev/tty 2>/dev/null || _aegis_host=""
  if [[ -n "${_aegis_host}" ]]; then
    printf '  Listen/public port [443]: ' >&2
    read -r _aegis_port </dev/tty 2>/dev/null || _aegis_port=""
    _aegis_port="${_aegis_port:-443}"
    printf '  Profile:  1) Standard relay   2) Cloudflare-fronted (grpc_stream)  [1]: ' >&2
    read -r _aegis_prof </dev/tty 2>/dev/null || _aegis_prof=""
    LISTEN_ADDR="0.0.0.0:${_aegis_port}"
    RELAY_ADDRESS="${_aegis_host}:${_aegis_port}"
    SERVER_NAME="${_aegis_host}"
    if [[ "${_aegis_prof}" == "2" ]]; then
      RELAY_TRANSPORT_PRIORITY="grpc_stream"
      echo "→ Cloudflare-fronted profile: after install, point a proxied DNS record at this host (Full strict + a Cloudflare Origin CA cert on the origin). See docs/cloudflare-fronted-operator-guide.md" >&2
    fi
    echo "→ relay ${RELAY_ADDRESS} (server_name ${SERVER_NAME}), listen ${LISTEN_ADDR}" >&2
  fi
fi

if [[ ! -f "${ROOT}/config.example.toml" ]]; then
  echo "Install root is missing client config template" >&2
  exit 1
fi
if [[ "${ROLE}" == "server" ]]; then
  for asset in aegis-server.toml.example scripts/generate-relay-materials.sh \
    scripts/render-client-bundle.sh scripts/package-client-bundle.sh; do
    if [[ ! -f "${ROOT}/${asset}" ]]; then
      echo "Server installation requires the private operator distribution" >&2
      exit 1
    fi
  done
fi

if [[ ! -f "${ROOT}/scripts/setup-wide-linux-redirect.sh" || ! -f "${ROOT}/scripts/setup-wide-linux-tproxy.sh" ]]; then
  echo "Install root is missing Linux wide helper scripts" >&2
  exit 1
fi

if [[ "${SOURCE_LAYOUT}" -eq 0 && ! -f "${ROOT}/bundle.manifest.json" ]]; then
  echo "Packaged install root is missing bundle.manifest.json" >&2
  exit 1
fi

if [[ "${SOURCE_LAYOUT}" -eq 0 ]]; then
  if [[ ! -f "${ROOT}/SHA256SUMS" ]]; then
    echo "Packaged install root is missing SHA256SUMS" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${ROOT}" && sha256sum -c SHA256SUMS >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "${ROOT}" && shasum -a 256 -c SHA256SUMS >/dev/null)
  else
    echo "sha256sum or shasum is required to verify packaged install payload" >&2
    exit 1
  fi
  python3 -I - "${ROOT}/bundle.manifest.json" "${ROOT}" "${ROLE}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
root = Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
schema = manifest.get("schema")
client_only = schema in ("aegis_client_release_bundle_manifest_v1", "aegis_client_release_bundle_manifest_v2", "aegis_client_release_bundle_manifest_v3")
if schema == "aegis_client_release_bundle_manifest_v3":
    def unique_v3(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("public v3 duplicate provenance field")
            value[key] = item
        return value
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=unique_v3)

if client_only and sys.argv[3] != "client":
    raise SystemExit("this release supports only the client role")
if not client_only and manifest.get("schema") != "aegis_release_bundle_manifest_v2":
    raise SystemExit("unsupported or missing release bundle provenance schema")

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

lock_hash = manifest.get("cargo_lock_sha256")
if client_only:
    import re
    if not isinstance(lock_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", lock_hash):
        raise SystemExit("missing build dependency provenance digest")
    expected_files = manifest.get("files")
    if not isinstance(expected_files, list) or not all(isinstance(name, str) for name in expected_files) or len(set(expected_files)) != len(expected_files):
        raise SystemExit("invalid client release inventory")
    # Immutable public delivery policy; a manifest cannot authorize arbitrary
    # operator executables, source, credentials or an expanded helper set.
    allowed_files = {
        "bin/aegis-client", "install.sh", "config.example.toml",
        "scripts/setup-wide-linux-redirect.sh", "scripts/setup-wide-linux-tproxy.sh",
        "scripts/aegis-wide-enable.sh", "scripts/aegis-wide-disable.sh",
        "scripts/aegis-wide-persist-install.sh", "scripts/purge-installed-aegis.sh",
        "scripts/aegis-ubuntu-uninstall.sh", "scripts/janitor-wide-linux-tproxy.sh",
        "scripts/aegis-rpi-gateway.sh", "scripts/lib/root-state.sh",
        "packaging/systemd/aegis-client.service", "packaging/env/aegis-client.env.example",
        "README.txt", "THIRD-PARTY-NOTICES.txt", "SHA256SUMS",
    }
    if schema in ("aegis_client_release_bundle_manifest_v2", "aegis_client_release_bundle_manifest_v3"):
        allowed_files.add("scripts/aegis-device-egress-guard.sh")
    if schema == "aegis_client_release_bundle_manifest_v3":
        allowed_files.add("client-cargo-inventory.json")
    if set(expected_files) != allowed_files:
        raise SystemExit("client release inventory differs from its versioned policy")
    actual_files = set()
    for item in root.rglob("*"):
        if item.is_symlink():
            raise SystemExit("client release must not contain links")
        if item.is_file():
            if item.stat().st_nlink != 1:
                raise SystemExit("client release must not contain hard links")
            actual_files.add(item.relative_to(root).as_posix())
        elif not item.is_dir():
            raise SystemExit("client release must contain only regular files and directories")
    if actual_files != set(expected_files) | {"bundle.manifest.json"}:
        raise SystemExit("client release inventory mismatch")
else:
    if not isinstance(lock_hash, str) or sha256(root / "Cargo.lock") != lock_hash:
        raise SystemExit("Cargo.lock provenance hash mismatch")

binaries = manifest.get("binaries")
if not isinstance(binaries, dict):
    raise SystemExit("release bundle manifest is missing binary provenance")
expected_binaries = ("aegis-client",) if client_only else ("aegis-server", "aegis-client")
if client_only and set(binaries) != set(expected_binaries):
    raise SystemExit("unexpected executable in client release")
for name in expected_binaries:
    entry = binaries.get(name)
    if not isinstance(entry, dict):
        raise SystemExit(f"release bundle manifest is missing {name} provenance")
    if entry.get("path") != "bin/" + name:
        raise SystemExit("unexpected binary provenance path")
    path = root / entry["path"]
    if not path.is_file() or sha256(path) != entry.get("sha256"):
        raise SystemExit(f"{name} provenance hash mismatch")
    features = entry.get("features")
    if not isinstance(features, list):
        raise SystemExit(f"{name} provenance features are missing")
def validate_shipping_client_inventory(raw, provenance, actual_binary_sha256):
    """Require the Rust producer's closed graph and exact artifact bindings.

    A valid signed record is producer-observed evidence, never independent
    compiler linkage, native dependency completeness or legal acceptance.
    """
    import json
    import re

    def need(condition):
        if not condition:
            raise ValueError("shipping Cargo inventory rejected")

    def unique(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value

    def hex_value(value, length=64):
        return isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None

    def token(value):
        return isinstance(value, str) and 0 < len(value) <= 256 and re.fullmatch(r"[A-Za-z0-9._+\-]+", value) is not None

    def ordered_strings(values, safe=False):
        return isinstance(values, list) and all(isinstance(v, str) and (not safe or token(v)) for v in values) and all(a < b for a, b in zip(values, values[1:]))

    need(isinstance(raw, bytes) and 0 < len(raw) <= 4 * 1024 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: need(False))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise ValueError("shipping Cargo inventory rejected") from None
    fields = {"schema", "scope", "native_payload_complete", "compiler_linkage_proven",
              "source_revision", "target_triple", "default_features", "requested_features",
              "cargo_lock_sha256", "client_binary_sha256", "cargo_metadata_sha256",
              "producer", "root_component", "components"}
    need(isinstance(value, dict) and set(value) == fields)
    need(value["schema"] == "aegis_shipping_client_cargo_inventory_v1" and
         value["scope"] == "selected_target_filtered_cargo_graph_not_compiler_linkage" and
         value["native_payload_complete"] is False and value["compiler_linkage_proven"] is False and
         value["default_features"] is True and hex_value(value["cargo_metadata_sha256"]))
    features = ["chrome-like-quic", "chrome-like-tls", "raw-socket"]
    need(isinstance(provenance, dict) and hex_value(provenance.get("git_sha"), 40) and
         hex_value(provenance.get("cargo_lock_sha256")) and hex_value(actual_binary_sha256) and
         provenance.get("target_triple") in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"))
    need(provenance.get("schema") == "aegis_client_release_bundle_manifest_v3" and set(provenance) == {
        "schema", "distribution", "bundle_name", "version", "arch", "platform", "target_triple",
        "git_sha", "build_timestamp", "cargo_lock_sha256", "runtime_abi", "binaries", "files", "install_entrypoints"})
    need(provenance["distribution"] == "public_client" and provenance["platform"] == "linux" and
         provenance["arch"] in ("x86_64", "aarch64") and provenance["target_triple"] == provenance["arch"] + "-unknown-linux-gnu")
    binaries = provenance.get("binaries")
    need(isinstance(binaries, dict) and set(binaries) == {"aegis-client"})
    binary = binaries["aegis-client"]
    need(isinstance(binary, dict) and set(binary) == {"features", "path", "sha256"} and binary.get("path") == "bin/aegis-client" and
         binary.get("sha256") == actual_binary_sha256 and isinstance(binary.get("features"), list) and
         len(binary["features"]) == 3 and all(isinstance(f, str) for f in binary["features"]) and
         set(binary["features"]) == set(features))
    need(value["source_revision"] == provenance["git_sha"] and
         value["target_triple"] == provenance["target_triple"] and
         value["cargo_lock_sha256"] == provenance["cargo_lock_sha256"] and
         value["client_binary_sha256"] == actual_binary_sha256 and
         value["requested_features"] == features)
    record = value["producer"]
    record_fields = {"schema", "source_revision", "target_triple", "cargo_lock_sha256",
                     "binary_sha256", "default_features", "requested_features", "resolved_root_features",
                     "compiler_artifact_message_sha256", "build_message_stream_sha256", "target_evidence"}
    need(isinstance(record, dict) and set(record) == record_fields)
    need(record["schema"] == "aegis_linux_client_build_record_v1" and
         record["source_revision"] == provenance["git_sha"] and record["target_triple"] == provenance["target_triple"] and
         record["cargo_lock_sha256"] == provenance["cargo_lock_sha256"] and
         record["binary_sha256"] == actual_binary_sha256 and record["default_features"] is True and
         record["requested_features"] == features and
         record["target_evidence"] == "explicit_cargo_target_and_fixed_producer_invocation" and
         hex_value(record["compiler_artifact_message_sha256"]) and hex_value(record["build_message_stream_sha256"]) and
         ordered_strings(record["resolved_root_features"], safe=True) and
         set(features).issubset(record["resolved_root_features"]))
    components = value["components"]
    need(isinstance(components, list) and 0 < len(components) <= 4096 and isinstance(value["root_component"], str))
    by_key, order, edges = {}, [], 0
    component_fields = {"key", "name", "version", "source_kind", "source_identity_sha256", "features", "dependencies"}
    for item in components:
        need(isinstance(item, dict) and set(item) == component_fields and token(item["name"]) and token(item["version"]) and
             hex_value(item["source_identity_sha256"]) and item["source_kind"] in ("reviewed_local_manifest", "crates_io_registry"))
        key = item["name"] + "@" + item["version"] + "#" + item["source_identity_sha256"]
        need(item["key"] == key and key not in by_key and ordered_strings(item["features"], safe=True) and
             ordered_strings(item["dependencies"]))
        by_key[key] = item
        order.append(key)
        edges += len(item["dependencies"])
    need(edges <= 16384 and all(a < b for a, b in zip(order, order[1:])) and value["root_component"] in by_key)
    root = by_key[value["root_component"]]
    need(root["name"] == "aegis-client" and root["source_kind"] == "reviewed_local_manifest" and
         root["features"] == record["resolved_root_features"] and set(features).issubset(root["features"]))
    visited, pending = set(), [value["root_component"]]
    while pending:
        key = pending.pop()
        need(key in by_key)
        if key in visited:
            continue
        visited.add(key)
        pending.extend(by_key[key]["dependencies"])
    need(len(visited) == len(by_key))
    return {"schema": value["schema"], "source_revision": value["source_revision"],
            "target_triple": value["target_triple"], "client_binary_sha256": actual_binary_sha256,
            "components": len(components), "native_payload_complete": False, "compiler_linkage_proven": False}

required_client_features = {"raw-socket", "chrome-like-tls", "chrome-like-quic"}
if not required_client_features.issubset(set(binaries["aegis-client"]["features"])):
    raise SystemExit("aegis-client release is missing required feature provenance")
if schema == "aegis_client_release_bundle_manifest_v3":
    inventory_path = root / "client-cargo-inventory.json"
    if not 0 < inventory_path.stat().st_size <= 4 * 1024 * 1024:
        raise SystemExit("shipping Cargo inventory exceeds bound")
    raw_inventory = inventory_path.read_bytes()
    validate_shipping_client_inventory(raw_inventory, manifest, sha256(root / "bin/aegis-client"))
PY
fi

# Staged AUTO first-arm consumes the already installed binary admitted from
# the protected owner receipt. It never builds a candidate from this checkout.
# Ordinary source installs still require Cargo and resolve their target dir.
if [[ "${SOURCE_LAYOUT}" -eq 1 && "${STAGE_AUTO_DEVICE_GUARD}" != 1 ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required; install Rust via rustup first" >&2
    exit 1
  fi

  TARGET_DIR="$(
    python3 -I - "${ROOT}/Cargo.toml" <<'PY'
import json
import subprocess
import sys

meta = subprocess.check_output(
    [
        "cargo", "metadata", "--no-deps", "--format-version", "1",
        "--manifest-path", sys.argv[1],
    ],
    text=True,
)
print(json.loads(meta)["target_directory"])
PY
  )"
fi

default_prefix() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/usr/local\n'
  else
    printf '%s/.local\n' "${HOME}"
  fi
}

default_server_config_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/etc/aegis/server\n'
  else
    printf '%s/.config/aegis/server\n' "${HOME}"
  fi
}

default_client_config_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/etc/aegis/client\n'
  else
    printf '%s/.config/aegis/client\n' "${HOME}"
  fi
}

default_server_state_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/var/lib/aegis-server\n'
  else
    printf '%s/.local/state/aegis/server\n' "${HOME}"
  fi
}

default_client_state_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/var/lib/aegis-client\n'
  else
    printf '%s/.local/state/aegis/client\n' "${HOME}"
  fi
}

default_client_log_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/var/log/aegis-client\n'
  else
    printf '%s/.local/state/aegis/client/log\n' "${HOME}"
  fi
}

default_client_helper_dir() {
  local prefix="${1}"
  printf '%s/lib/aegis/helpers\n' "${prefix}"
}

default_systemd_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/etc/systemd/system\n'
  fi
}

# AEGIS install.sh auto-detects host OS kind so a single entry point can
# render systemd units on Linux and launchd plists on macOS. The override
# is only used by contract tests that must pin a specific OS shape.
detect_os_kind() {
  local override="${AEGIS_INSTALL_TEST_OS_KIND:-}"
  if [[ -n "${override}" ]]; then
    printf '%s\n' "${override}"
    return 0
  fi
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux) printf 'linux\n' ;;
    Darwin) printf 'darwin\n' ;;
    *) printf 'other\n' ;;
  esac
}

default_launchd_agent_dir() {
  # macOS LaunchAgents under the installing user's home. Headless dedicated
  # users need the packaged macOS installer with explicit LaunchDaemon mode;
  # repo install.sh only materializes the interactive-user LaunchAgent asset.
  printf '%s/Library/LaunchAgents\n' "${HOME}"
}

launchd_target_uid() {
  id -u 2>/dev/null
}

launchd_gui_domain_exists() {
  local uid
  uid="$(launchd_target_uid)" || return 1
  launchctl print "gui/${uid}" >/dev/null 2>&1
}

default_env_dir() {
  if [[ ${EUID} -eq 0 ]]; then
    printf '/etc/default\n'
  fi
}

detected_host() {
  if [[ -n "${AEGIS_INSTALL_TEST_DETECTED_HOST:-}" ]]; then
    printf '%s\n' "${AEGIS_INSTALL_TEST_DETECTED_HOST}"
    return 0
  fi
  hostname -f 2>/dev/null || hostname 2>/dev/null || printf 'localhost\n'
}

host_from_address() {
  local value="$1"
  if [[ "${value}" == \[*\]:* ]]; then
    printf '%s\n' "${value#\[}" | sed 's/\]:.*$//'
    return 0
  fi
  if [[ "${value}" == *:* ]]; then
    printf '%s\n' "${value%%:*}"
    return 0
  fi
  printf '%s\n' "${value}"
}

port_from_address() {
  local value="$1"
  local fallback="${2:-8443}"
  if [[ "${value}" == \[*\]:* ]]; then
    printf '%s\n' "${value##*:}"
    return 0
  fi
  if [[ "${value}" == *:* ]]; then
    printf '%s\n' "${value##*:}"
    return 0
  fi
  printf '%s\n' "${fallback}"
}

is_ip_literal() {
  local value="$1"
  if [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0
  fi
  if [[ "${value}" == *:* ]]; then
    return 0
  fi
  return 1
}

host_is_local_only() {
  local value="$1"
  python3 -I - <<'PY' "${value}"
import ipaddress
import sys

value = sys.argv[1].strip()
if not value:
    raise SystemExit(0)

lowered = value.lower()
if lowered in {"localhost", "localhost.localdomain"}:
    raise SystemExit(0)
if lowered.endswith(".localdomain") or lowered.endswith(".local"):
    raise SystemExit(0)

try:
    ip = ipaddress.ip_address(value)
except ValueError:
    # Treat unqualified hostnames as local-only defaults for the generated
    # remote-client bundle. Separate-host product flow should use a real FQDN
    # or an explicit reachable IP instead.
    if "." not in value:
        raise SystemExit(0)
    raise SystemExit(1)

if ip.is_loopback or ip.is_unspecified:
    raise SystemExit(0)

raise SystemExit(1)
PY
}

resolve_host_addrs() {
  local host="$1"
  python3 -I - <<'PY' "${host}"
import os
import socket
import sys

host = sys.argv[1]
mapping = os.environ.get("AEGIS_INSTALL_TEST_RESOLUTION_MAP", "").strip()
if mapping:
    records = {}
    for entry in mapping.split(";"):
        if not entry:
            continue
        name, sep, values = entry.partition("=")
        if not sep:
            continue
        records[name] = [value for value in values.split(",") if value]
    for value in records.get(host, []):
        print(value)
    raise SystemExit(0 if host in records else 1)

try:
    infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
except socket.gaierror:
    raise SystemExit(1)

seen = []
for info in infos:
    addr = info[4][0]
    if addr not in seen:
        seen.append(addr)

if not seen:
    raise SystemExit(1)

for addr in seen:
    print(addr)
PY
}

host_has_nonlocal_resolution() {
  local host="$1"
  local addr=""

  if host_is_local_only "${host}"; then
    return 1
  fi

  while IFS= read -r addr; do
    if [[ -n "${addr}" ]] && ! host_is_local_only "${addr}"; then
      return 0
    fi
  done < <(resolve_host_addrs "${host}" 2>/dev/null || true)

  return 1
}

detected_relay_ip_fallback() {
  local candidate=""

  if [[ "${AEGIS_INSTALL_TEST_DISABLE_AUTO_IP_FALLBACK:-0}" == "1" ]]; then
    return 1
  fi

  if [[ -n "${AEGIS_INSTALL_TEST_FALLBACK_IP:-}" ]]; then
    printf '%s\n' "${AEGIS_INSTALL_TEST_FALLBACK_IP}"
    return 0
  fi

  if has_command hostname; then
    for candidate in $(hostname -I 2>/dev/null || true); do
      if [[ -n "${candidate}" ]] && ! host_is_local_only "${candidate}"; then
        printf '%s\n' "${candidate}"
        return 0
      fi
    done
  fi

  if has_command ip; then
    candidate="$(
      ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | sed -n '1p'
    )"
    if [[ -n "${candidate}" ]] && ! host_is_local_only "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  fi

  return 1
}

choose_bundle_relay_endpoint() {
  local dns_candidate="$1"
  local explicit_server_name="$2"
  # Phase 5.0.A fix: the port published in the bundle must match the
  # port the server is actually listening on. Callers pass the
  # install-time `--listen` port here (defaulting to 8443 for callers
  # that still don't know it). Previously this function hardcoded
  # `:8443` and silently drifted from explicit `--listen :443`
  # configurations, producing a bundle that pointed clients at a port
  # nothing was bound to.
  local default_relay_port="${3:-8443}"
  local fallback_ip=""

  if host_has_nonlocal_resolution "${dns_candidate}"; then
    printf '%s\n%s\n' "${dns_candidate}:${default_relay_port}" "${explicit_server_name:-${dns_candidate}}"
    return 0
  fi

  fallback_ip="$(detected_relay_ip_fallback || true)"
  if [[ -n "${fallback_ip}" ]]; then
    if [[ -n "${explicit_server_name}" ]]; then
      printf '%s\n%s\n' "${fallback_ip}:${default_relay_port}" "${explicit_server_name}"
      return 0
    fi
    if [[ -n "${dns_candidate}" ]] && ! host_is_local_only "${dns_candidate}"; then
      printf '%s\n%s\n' "${fallback_ip}:${default_relay_port}" "${dns_candidate}"
      return 0
    fi
    printf '%s\n%s\n' "${fallback_ip}:${default_relay_port}" "${fallback_ip}"
    return 0
  fi

  cat >&2 <<EOF
Unable to choose a relay address for the generated client bundle.
Detected host: ${dns_candidate}
Reason: detected hostname is not usable for a remote client bundle and no
non-loopback IP fallback was found.

Provide an explicit external address:
  ./install.sh server --relay-address relay.example.org:8443 --server-name relay.example.org
EOF
  return 1
}

ensure_dir() {
  mkdir -p "$1"
}

# The runtime UID may replace entries in its state directory. Never open a
# destination there for writing as root: write a new inode through a pinned
# directory fd, set permissions on that fd, and atomically replace the entry.
# Strict metadata additionally requires every directory to be installer-owned.
install_atomic_write() {
  local destination="$1" mode="$2" policy="${3:-runtime}" operation="${4:-write}"
  python3 -I -c '
import os, secrets, stat, sys
path, mode, policy, operation = sys.argv[1], int(sys.argv[2], 8), sys.argv[3], sys.argv[4]
# macOS exposes these OS-owned aliases. Normalize only the fixed platform
# prefixes; arbitrary directory and destination symlinks are still rejected.
if sys.platform == "darwin":
    for prefix in ("/var/", "/tmp/", "/etc/"):
        if path.startswith(prefix):
            path = "/private" + path
            break
if not os.path.isabs(path) or ".." in path.split("/"):
    raise SystemExit("Install metadata requires an absolute path without parent traversal")
parts = [part for part in path.split("/") if part]
if len(parts) < 2 or policy not in ("runtime", "strict") or operation not in ("write", "validate"):
    raise SystemExit("Invalid install metadata destination")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
directory = os.open("/", flags)
temporary = None
try:
    for index, part in enumerate(parts[:-1]):
        try:
            child = os.open(part, flags, dir_fd=directory)
        except FileNotFoundError:
            os.mkdir(part, 0o755, dir_fd=directory)
            child = os.open(part, flags, dir_fd=directory)
        metadata = os.fstat(child)
        runtime_leaf = policy == "runtime" and index == len(parts) - 2
        sticky_ancestor = index < len(parts) - 2 and metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        if not runtime_leaf and (metadata.st_uid not in (0, os.geteuid()) or (metadata.st_mode & 0o022 and not sticky_ancestor)):
            os.close(child)
            raise SystemExit("Untrusted install metadata directory; previous record preserved")
        os.close(directory)
        directory = child
    try:
        current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or (policy == "strict" and (current.st_uid not in (0, os.geteuid()) or current.st_mode & 0o022)):
            raise SystemExit("Install metadata must be a regular, unlinked file; previous entry preserved")
    except FileNotFoundError:
        pass
    if operation == "validate":
        sys.exit(0)
    temporary = ".aegis-install-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as output:
        data = sys.stdin.buffer.read(1048577)
        if len(data) > 1048576:
            raise SystemExit("Install metadata exceeds one MiB; previous record preserved")
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())
    os.replace(temporary, parts[-1], src_dir_fd=directory, dst_dir_fd=directory)
    temporary = None
    os.fsync(directory)
finally:
    if temporary is not None:
        os.unlink(temporary, dir_fd=directory)
    os.close(directory)
' "${destination}" "${mode}" "${policy}" "${operation}"
}

# Validate and migrate old service-owned configuration through directory fds.
# Recovery is a separate root-private snapshot: neither the retired runtime
# inode tree nor an old open file descriptor can change the published files.
client_config_boundary_tree() {
  python3 -I - "$1" "$2" "${3:-root}" <<'PY'
import os, pwd, secrets, stat, sys
path, operation, service = sys.argv[1:]
admin = os.geteuid()
admin_gid = os.getegid()
if sys.platform == "darwin":
    for prefix in ("/var/", "/tmp/", "/etc/"):
        if path.startswith(prefix):
            path = "/private" + path
            break
if not os.path.isabs(path) or ".." in path.split("/") or operation not in ("check", "apply"):
    raise SystemExit("Invalid configuration boundary path or operation")
allowed = {0, admin}
for name in ("aegis", "aegis-svc"):
    try:
        account = pwd.getpwnam(name)
        if account.pw_uid < 1000:
            allowed.add(account.pw_uid)
    except KeyError:
        pass
access_uid, access_gid = admin, admin_gid
if service != "root":
    account = pwd.getpwnam(service)
    if service not in ("aegis", "aegis-svc") or account.pw_uid not in allowed:
        raise SystemExit("Unexpected client service identity; configuration unchanged")
    access_uid, access_gid = account.pw_uid, account.pw_gid
parts = [part for part in path.split("/") if part]
if not parts:
    raise SystemExit("The filesystem root cannot be a client configuration directory")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
parent = os.open("/", flags)
opened = []
stages = []
retired = None
def discard_stage(directory, name):
    fd = os.open(name, flags, dir_fd=directory)
    try:
        for leaf in os.listdir(fd):
            metadata = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                discard_stage(fd, leaf)
            else:
                os.unlink(leaf, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=directory)
try:
    for index, part in enumerate(parts[:-1]):
        try:
            child = os.open(part, flags, dir_fd=parent)
        except FileNotFoundError:
            if operation == "check":
                print("absent")
                sys.exit(0)
            os.mkdir(part, 0o700, dir_fd=parent)
            child = os.open(part, flags, dir_fd=parent)
        metadata = os.fstat(child)
        sticky = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX and index < len(parts) - 2
        if metadata.st_uid not in (0, admin) or (metadata.st_mode & 0o022 and not sticky):
            os.close(child)
            raise SystemExit("Untrusted configuration parent; configuration unchanged")
        os.close(parent)
        parent = child
    name = parts[-1]
    try:
        source = os.open(name, flags, dir_fd=parent)
        opened.append(source)
    except FileNotFoundError:
        if operation == "apply":
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        print("absent")
        sys.exit(0)
    original = os.fstat(source)
    needs_migration = original.st_uid != admin
    budget = {"files": 0, "bytes": 0}
    def clone(src, dst=None, depth=0, runtime_access=False):
        global needs_migration
        directory = os.fstat(src)
        if depth > 8 or directory.st_uid not in allowed or directory.st_mode & 0o022:
            raise ValueError("Untrusted configuration directory")
        needs_migration = needs_migration or directory.st_uid != admin
        for leaf in sorted(os.listdir(src)):
            metadata = os.stat(leaf, dir_fd=src, follow_symlinks=False)
            if metadata.st_uid not in allowed or metadata.st_mode & 0o022:
                raise ValueError("Unexpected configuration owner or writable permissions")
            needs_migration = needs_migration or metadata.st_uid != admin
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(leaf, flags, dir_fd=src)
                target = None
                try:
                    if dst is not None:
                        os.mkdir(leaf, 0o700, dir_fd=dst)
                        target = os.open(leaf, flags, dir_fd=dst)
                    clone(child, target, depth + 1, runtime_access)
                finally:
                    os.close(child)
                    if target is not None:
                        os.close(target)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("Configuration links and special files are not accepted")
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src)
            with os.fdopen(fd, "rb") as incoming:
                before = os.fstat(incoming.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid not in allowed or before.st_mode & 0o022:
                    raise ValueError("Configuration changed during validation")
                data = incoming.read(16777217)
                after = os.fstat(incoming.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("Configuration changed during snapshot")
            budget["files"] += 1
            budget["bytes"] += len(data)
            if len(data) > 16777216 or budget["files"] > 1024 or budget["bytes"] > 67108864:
                raise ValueError("Configuration snapshot exceeds its bounded size")
            if dst is not None:
                fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst)
                with os.fdopen(fd, "wb") as outgoing:
                    outgoing.write(data)
                    outgoing.flush()
                    private_key = b"PRIVATE KEY-----" in data or leaf.endswith((".key", ".seed"))
                    shared = runtime_access and access_uid != admin
                    os.fchown(outgoing.fileno(), access_uid if shared and private_key else admin, access_gid if shared else admin_gid)
                    os.fchmod(outgoing.fileno(), 0o640 if shared and not private_key else 0o600)
                    os.fsync(outgoing.fileno())
        if dst is not None:
            shared = runtime_access and access_uid != admin
            os.fchown(dst, admin, access_gid if shared else admin_gid)
            os.fchmod(dst, 0o750 if shared else 0o700)
            os.fsync(dst)
    if operation == "check":
        clone(source)
        print("migrate" if needs_migration else "trusted")
        sys.exit(0)
    nonce = secrets.token_hex(16)
    snapshot_name = "." + name + ".root-recovery-" + nonce
    fresh_name = "." + name + ".root-new-" + nonce
    retired_name = "." + name + ".runtime-retired-" + nonce
    for leaf in (snapshot_name, fresh_name):
        os.mkdir(leaf, 0o700, dir_fd=parent)
        stages.append(leaf)
    snapshot = os.open(snapshot_name, flags, dir_fd=parent)
    fresh = os.open(fresh_name, flags, dir_fd=parent)
    opened.extend((snapshot, fresh))
    clone(source, snapshot)
    budget = {"files": 0, "bytes": 0}
    clone(snapshot, fresh, runtime_access=True)
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
        raise ValueError("Configuration directory changed during migration")
    os.rename(name, retired_name, src_dir_fd=parent, dst_dir_fd=parent)
    retired = retired_name
    try:
        os.rename(fresh_name, name, src_dir_fd=parent, dst_dir_fd=parent)
    except BaseException:
        os.rename(retired_name, name, src_dir_fd=parent, dst_dir_fd=parent)
        retired = None
        raise
    stages.remove(fresh_name)
    stages.remove(snapshot_name)
    os.fchown(source, admin, admin_gid)
    os.fchmod(source, 0o700)
    os.fsync(parent)
    print(os.path.join(os.path.dirname(path), snapshot_name))
except (OSError, ValueError) as error:
    raise SystemExit("Configuration boundary validation/migration failed: " + str(error))
finally:
    for fd in reversed(opened):
        os.close(fd)
    for leaf in stages:
        discard_stage(parent, leaf)
    os.close(parent)
PY
}

prepare_client_config_boundary() {
  [[ ${EUID} -eq 0 ]] || return 0
  local config_root="$1" state service=root was_active=0 snapshot
  state="$(client_config_boundary_tree "${config_root}" check)" || return 1
  [[ "${state}" != trusted ]] || return 0
  if [[ "${SYSTEMD_DIR}" == /etc/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    service="$(systemctl show aegis-client.service -p User --value 2>/dev/null || true)"
    service="${service:-root}"
    if systemctl is-active --quiet aegis-client.service; then
      was_active=1
      systemctl stop aegis-client.service || return 1
      if systemctl is-active --quiet aegis-client.service; then
        echo "Client service did not stop; configuration unchanged." >&2
        return 1
      fi
    fi
  fi
  if ! snapshot="$(client_config_boundary_tree "${config_root}" apply "${service}")"; then
    if [[ "${was_active}" == 1 ]]; then
      systemctl start aegis-client.service || echo "Previous client service could not be restarted." >&2
    fi
    return 1
  fi
  if [[ "${snapshot}" != absent ]]; then
    printf 'Configuration migrated; root-private recovery snapshot: %s\n' "${snapshot}"
  fi
  # Resume the previously active service with the copied configuration before
  # the normal upgrade starts. Old runtime fds address only retired inodes.
  if [[ "${was_active}" == 1 ]]; then
    systemctl start aegis-client.service || return 1
    systemctl is-active --quiet aegis-client.service || return 1
  fi
}

random_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return 0
  fi
  python3 -I - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

inject_client_socks_auth_token() {
  # v0.3.0: insert/replace `auth_token = "..."` inside the [socks]
  # section of an aegis-client.toml. Idempotent: re-running on a config
  # that already has auth_token replaces it with a fresh random value.
  local config_path="$1"
  if [[ ! -f "${config_path}" ]]; then
    return 0
  fi
  # Generate the credential in the writer process so it never enters argv.
  python3 -I - "${config_path}" <<'PY'
import re
import secrets
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.chmod(0o600)
token = secrets.token_hex(32)
text = path.read_text(encoding="utf-8")

lines = text.splitlines()
out = []
in_socks = False
injected = False
i = 0
while i < len(lines):
    line = lines[i]
    if line.strip().startswith("[") and line.strip().endswith("]"):
        if in_socks and not injected:
            # closing previous [socks] section without finding auth_token
            out.append(f'auth_token = "{token}"')
            injected = True
        in_socks = (line.strip() == "[socks]")
    if in_socks and re.match(r'^\s*auth_token\s*=', line):
        out.append(f'auth_token = "{token}"')
        injected = True
        i += 1
        continue
    out.append(line)
    i += 1

if in_socks and not injected:
    out.append(f'auth_token = "{token}"')
    injected = True

# If the config doesn't have a [socks] block at all, append one.
if not injected:
    out.append("")
    out.append("[socks]")
    out.append('# v0.3.0 auto-generated SOCKS5 RFC 1929 password (per-install).')
    out.append(f'auth_token = "{token}"')

path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
  chmod 0600 "${config_path}"
}

inject_client_default_primary_socks5() {
  # v0.3.5: ensure [ingress] primary = "socks5" в default client config
  # so service starts with bind-only-loopback SOCKS5 listener (works
  # everywhere — macOS, fresh Linux, anywhere без TPROXY/PF helpers).
  # Operator can switch к "wide" manually после running setup-wide-*.sh.
  local config_path="$1"
  if [[ ! -f "${config_path}" ]]; then
    return 0
  fi
  python3 -I - "${config_path}" <<'PY'
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
lines = text.splitlines()
out = []
in_ingress_section = False
replaced_primary = False
for line in lines:
    s = line.strip()
    if s.startswith("[") and s.endswith("]"):
        in_ingress_section = (s == "[ingress]")
    if in_ingress_section and re.match(r'^\s*primary\s*=', line):
        out.append('primary = "socks5"')
        replaced_primary = True
        continue
    out.append(line)
if not replaced_primary:
    # No [ingress] block в template — add minimal one before [direct].
    new_out = []
    inserted = False
    for line in out:
        if not inserted and line.strip().startswith("[direct]"):
            new_out.append("[ingress]")
            new_out.append('primary = "socks5"')
            new_out.append("allow_fallback = true")
            new_out.append("")
            inserted = True
        new_out.append(line)
    out = new_out
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
  chmod 0600 "${config_path}"
}

inject_client_local_hardened_default() {
  # v0.3.0: ensure top-level `local_stealth_profile = "local_hardened"`
  # is present in the config. If the rendered template already has any
  # local_stealth_profile assignment, leave it alone (operator might
  # have customized). If absent, insert the line at the top of the
  # file (above any [section]).
  local config_path="$1"
  if [[ ! -f "${config_path}" ]]; then
    return 0
  fi
  python3 -I - "${config_path}" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if re.search(r'^\s*local_stealth_profile\s*=', text, re.MULTILINE):
    sys.exit(0)

lines = text.splitlines()
out = []
inserted = False
for line in lines:
    s = line.strip()
    if not inserted and s.startswith("[") and s.endswith("]"):
        out.append('# v0.3.0 default: hide aegis-client process name in `ps`')
        out.append('local_stealth_profile = "local_hardened"')
        out.append("")
        inserted = True
    out.append(line)
if not inserted:
    out.insert(0, '# v0.3.0 default: hide aegis-client process name in `ps`')
    out.insert(1, 'local_stealth_profile = "local_hardened"')
    out.insert(2, "")

path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
  chmod 0600 "${config_path}"
}

inject_client_service_state_path() {
  # The systemd service uses ProtectHome=true and can write only its state
  # directory. Rewrite shipped/home-cache defaults while preserving an
  # explicit operator-managed path. Copy an existing default state once during
  # upgrade so learned state is not discarded.
  local config_path="$1"
  local state_dir="$2"
  local service_state_path="${state_dir%/}/state.json"
  if [[ ! -f "${config_path}" ]]; then
    return 0
  fi
  python3 -I - "${config_path}" "${service_state_path}" <<'PY'
import os
import re
import shutil
import sys
from pathlib import Path

path = Path(sys.argv[1])
new_path = Path(sys.argv[2])
lines = path.read_text(encoding="utf-8").splitlines()
out = []
in_direct = False
found = False
old_value = None
default_literals = {
    "~/.cache/aegis/state.json",
    "~/.cache/.aegis/state.json",
}

for line in lines:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        if in_direct and not found:
            out.append(f'state_path = "{new_path}"')
            found = True
        in_direct = stripped == "[direct]"
    match = re.match(r'^\s*state_path\s*=\s*"([^"]+)"\s*$', line) if in_direct else None
    if match:
        old_value = match.group(1)
        expanded = Path(os.path.expanduser(old_value))
        if old_value in default_literals or str(expanded).startswith(("/root/", "/home/")):
            out.append(f'state_path = "{new_path}"')
        else:
            out.append(line)
        found = True
        continue
    out.append(line)

if in_direct and not found:
    out.append(f'state_path = "{new_path}"')
    found = True
if not found:
    out.extend(["", "[direct]", f'state_path = "{new_path}"'])

if old_value:
    old_path = Path(os.path.expanduser(old_value))
    if old_path != new_path and old_path.is_file() and not new_path.exists():
        new_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(old_path, new_path)
        os.chmod(new_path, 0o600)

path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
  chmod 0600 "${config_path}"
}

extract_toml_string() {
  local file_path="$1"
  local key_name="$2"
  sed -n "s/^${key_name} = \"\\(.*\\)\"/\\1/p" "${file_path}" | sed -n '1p'
}

require_asset() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Required install asset is missing: ${path}" >&2
    exit 1
  fi
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

cleanup_stale_client_redirect_helper() {
  local helper_script="${ROOT}/scripts/setup-wide-linux-redirect.sh"
  local nat_output_rules=""

  if [[ ${EUID} -ne 0 ]]; then
    return 0
  fi
  if [[ ! -x "${helper_script}" ]] || ! has_command iptables; then
    return 0
  fi

  nat_output_rules="$(iptables -t nat -S OUTPUT 2>/dev/null || true)"
  if [[ "${nat_output_rules}" != *"AEGIS_WIDE_OUTPUT"* ]]; then
    return 0
  fi

  # A previous client role can leave OUTPUT redirect rules behind. On a server
  # host those rules shadow outbound target connects for non-root users like the
  # packaged `aegis` service account, so clear the default helper residue first.
  if bash "${helper_script}" teardown >/dev/null 2>&1; then
    cat <<'EOF'
Detected stale Linux wide redirect helper state from a previous client role.
Removed default AEGIS_WIDE nat redirect residue before installing server role.
EOF
  fi
}

require_runtime_dependency() {
  local command_name="$1"
  local reason="$2"

  if has_command "${command_name}"; then
    return 0
  fi

  cat >&2 <<EOF
Missing runtime dependency: ${command_name}
Reason: ${reason}

Ubuntu product path:
  rerun via ./bootstrap-install.sh so the Ubuntu/debian-apt bootstrap layer can
  auto-install minimal host prerequisites before entering install.sh.
EOF
  exit 1
}

require_role_dependencies() {
  case "${ROLE}" in
    client)
      if [[ -n "${BUNDLE_URL_FILE}" ]]; then
        require_runtime_dependency "tar" "client --bundle-url-file extracts a packaged client bundle archive"
        require_runtime_dependency "python3" "client bundle archive validation uses the existing validator"

      fi
      ;;
  esac
}

download_url() {
  local input="$1" destination="$2"
  local -a args=(profile installer-secret fetch --input "$input" --output "$destination"
    --connect-seconds "${AEGIS_DOWNLOAD_CONNECT_TIMEOUT_SECONDS:-10}"
    --total-seconds "${AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS:-120}")
  [[ -z "${BUNDLE_CACERT_PIN:-}" ]] || args+=(--pin "$BUNDLE_CACERT_PIN")
  [[ "${BUNDLE_INSECURE:-0}" != 1 ]] || args+=(--insecure)
  [[ "${BUNDLE_LOCAL_ONLY:-0}" != 1 ]] || args+=(--local-only)
  [[ -n "${PREFLIGHT_CLIENT_BINARY:-}" ]] || { echo "Verified private-transfer client required." >&2; return 2; }
  "$PREFLIGHT_CLIENT_BINARY" "${args[@]}"
}

resolve_downloaded_bundle() {
  local source="$1"
  local output_var="$2"
  local temp_root=""
  local archive_path=""
  local extracted_root=""
  local nested_dir=""

  # Keep installer-owned input out of the runtime/purge helper namespace. The
  # purge helper removes aegis-client-* as stale runtime residue; sharing that
  # prefix let a reinstall delete its downloaded bundle after preflight.
  temp_root="$(mktemp -d "${TMPDIR:-/tmp}/aegis-installer-bundle.XXXXXX")" || return 1
  TEMP_PATHS+=("${temp_root}")
  archive_path="${temp_root}/bundle.tar.gz"
  extracted_root="${temp_root}/extracted"
  ensure_dir "${extracted_root}" || return 1

  local acquisition_status=0
  download_url "${source}" "${archive_path}" || acquisition_status=$?
  if [[ "${acquisition_status}" -ne 0 ]]; then
    echo "[install] stage=bundle_acquisition reason=transfer_failed exit_code=${acquisition_status}; no retry attempted; one-time access may be consumed, request a fresh bundle from the operator" >&2
    return "${acquisition_status}"
  fi
  # Validate the complete compressed stream before extracting: an HTTP EOF
  # without Content-Length can otherwise look successful after partial bytes.
  # In particular, some tar readers accept missing gzip trailers after all
  # visible members, which is not a completed one-time transfer.
  if ! python3 -I - "${archive_path}" <<'PY'
import gzip
import sys
import zlib

try:
    with gzip.open(sys.argv[1], "rb") as archive:
        while archive.read(65536):
            pass
except (OSError, EOFError, zlib.error):
    raise SystemExit(65)
PY
  then
    echo "[install] stage=bundle_acquisition reason=incomplete_or_invalid_archive; no retry attempted; request a fresh bundle from the operator" >&2
    return 65
  fi
  if ! tar --no-same-owner -xzf "${archive_path}" -C "${extracted_root}" 2>/dev/null; then
    echo "[install] stage=bundle_acquisition reason=archive_extraction_failed; no retry attempted" >&2
    return 65
  fi

  if [[ -f "${extracted_root}/aegis-client.toml" && -r "${extracted_root}/aegis-client.toml" && -s "${extracted_root}/aegis-client.toml" &&
    -f "${extracted_root}/ca.pem" && -r "${extracted_root}/ca.pem" && -s "${extracted_root}/ca.pem" ]]; then
    printf -v "${output_var}" '%s' "${extracted_root}"
    return 0
  fi

  # Heredoc into a variable, then pipe. A heredoc written directly inside
  # "$( ... )" is parsed for quotes by bash 3.2, so an odd apostrophe count in
  # the body silently swallows the rest of the file.
  local py_find_bundle=''
  IFS= read -r -d '' py_find_bundle <<'PY' || true
import sys
from pathlib import Path

root = Path(sys.argv[1])
for candidate in sorted(root.iterdir()):
    if candidate.is_dir() and (candidate / "aegis-client.toml").is_file() and (candidate / "ca.pem").is_file():
        print(candidate)
        sys.exit(0)
sys.exit(1)
PY
  nested_dir="$(printf '%s' "${py_find_bundle}" | python3 -I - "${extracted_root}")" || {
    echo "[install] stage=bundle_acquisition reason=bundle_files_missing; no retry attempted" >&2
    return 65
  }

  if [[ ! -f "${nested_dir}/aegis-client.toml" || ! -r "${nested_dir}/aegis-client.toml" || ! -s "${nested_dir}/aegis-client.toml" ||
    ! -f "${nested_dir}/ca.pem" || ! -r "${nested_dir}/ca.pem" || ! -s "${nested_dir}/ca.pem" ]]; then
    echo "[install] stage=bundle_acquisition reason=bundle_files_unreadable_or_empty; no retry attempted" >&2
    return 65
  fi
  printf -v "${output_var}" '%s' "${nested_dir}"
}

install_binary() {
  local package_name="$1"
  local binary_name="$2"
  local bin_dir="$3"
  local operation="${4:-install}"
  local -a cargo_args=()
  local candidate=""
  local compatibility_error=""

  if [[ "${SOURCE_LAYOUT}" -eq 1 ]]; then
    cargo_args=(build --release --manifest-path "${ROOT}/Cargo.toml" -p "${package_name}")
    if [[ "${package_name}" == "aegis-client" ]]; then
      cargo_args+=(--features raw-socket,chrome-like-tls,chrome-like-quic)
    fi
    cargo "${cargo_args[@]}"
    candidate="${TARGET_DIR}/release/${binary_name}"
  else
    candidate="${ROOT}/bin/${binary_name}"
    require_asset "${candidate}"
  fi

  # Execute the exact candidate before creating/replacing anything under the
  # install prefix. Architecture, loader, shared-library and glibc symbol
  # mismatches otherwise surface only after the old working binary has already
  # been overwritten (for example an Ubuntu 26 client requiring GLIBC_2.39 on
  # AlmaLinux 9 / glibc 2.34).
  if ! compatibility_error="$("${candidate}" --version 2>&1 >/dev/null)"; then
    echo "Prebuilt ${binary_name} is not executable on this host; refusing to mutate the install prefix." >&2
    echo "This bundle has an architecture/ABI/runtime mismatch. Use an artifact built for this host baseline." >&2
    if [[ -n "${compatibility_error}" ]]; then
      printf '%s\n' "${compatibility_error}" >&2
    fi
    return 1
  fi

  # Reinstall preflight calls this exact resolver/ABI check before any existing
  # client state, units, firewall rules, or binaries are changed. The ordinary
  # install call below repeats the cheap check at the mutation boundary and
  # then copies the already verified candidate.
  if [[ "${operation}" == "preflight" ]]; then
    if [[ "${binary_name}" == "aegis-client" ]]; then
      PREFLIGHT_CLIENT_BINARY="${candidate}"
    fi
    return 0
  fi
  if [[ "${operation}" != "install" ]]; then
    echo "Unknown install_binary operation: ${operation}" >&2
    return 1
  fi

  ensure_dir "${bin_dir}"
  install -m 0755 "${candidate}" "${bin_dir}/${binary_name}"
}

install_manifest_path_for_role() {
  local role="$1"
  local state_dir="$2"
  # Root installs normally keep the server manifest at the canonical product
  # path.  Isolated installer contracts use a temporary state directory and
  # must never overwrite a live host's manifest while exercising that path.
  if [[ "${AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST:-0}" == "1" ]]; then
    printf '%s/install-manifest.json\n' "${state_dir}"
    return 0
  fi
  if [[ ${EUID} -eq 0 ]]; then
    # Installation receipts belong to the administrator, separately from the
    # runtime UID and its ReadWritePaths. Do not migrate by following an old
    # runtime-owned receipt; create a fresh record from the verified bundle.
    local default_state
    default_state="$(default_${role}_state_dir)"
    if [[ "${state_dir}" == "${default_state}" ]]; then
      printf '/var/lib/aegis-install/%s/install-manifest.json\n' "${role}"
    else
      # Staged/custom roots must not mutate the real host metadata. Keep the
      # record beside (never inside) the separately service-owned runtime tree.
      printf '%s.install-metadata/install-manifest.json\n' "${state_dir%/}"
    fi
    return 0
  fi
  printf '%s/install-manifest.json\n' "${state_dir}"
}

write_install_manifest() {
  local role="$1"
  local manifest_path="$2"
  local binary_path="$3"

  local payload program
  # Bash 3.2 mis-parses heredocs nested inside command substitution. Keep the
  # literal program outside it; read returns nonzero at the expected EOF.
  IFS= read -r -d '' program <<'PY' || true
import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path

bundle_manifest_path = Path(sys.argv[1])
install_manifest_path = Path(sys.argv[2])
role = sys.argv[3]
binary_path = Path(sys.argv[4])
source_manifest_url = sys.argv[5] or None
source_release_channel = sys.argv[6] or None

bundle_manifest = {}
if bundle_manifest_path.is_file():
    bundle_manifest = json.loads(bundle_manifest_path.read_text(encoding="utf-8"))

def binary_version():
    try:
        return subprocess.check_output(
            [str(binary_path), "--version"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=5,
        ).strip()
    except Exception:
        return None

payload = {
    "schema": "aegis_install_manifest_v1",
    "role": role,
    "version": bundle_manifest.get("version"),
    "git_sha": bundle_manifest.get("git_sha", "unknown"),
    "build_timestamp": bundle_manifest.get("build_timestamp"),
    "installed_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source_manifest_url": source_manifest_url,
    "source_release_channel": source_release_channel,
    "binary_path": str(binary_path),
    "binary_sha256": hashlib.sha256(binary_path.read_bytes()).hexdigest(),
    "binary_version": binary_version(),
    "platform": bundle_manifest.get("platform"),
    "arch": bundle_manifest.get("arch"),
    "target_triple": bundle_manifest.get("target_triple"),
    "bundle_manifest_path": str(bundle_manifest_path) if bundle_manifest_path.is_file() else None,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY
  payload="$(python3 -I -c "${program}" "${ROOT}/bundle.manifest.json" "${manifest_path}" "${role}" "${binary_path}" "${INSTALL_SOURCE_MANIFEST_URL}" "${INSTALL_SOURCE_RELEASE_CHANNEL}")" || return 1
  printf '%s\n' "${payload}" | install_atomic_write "${manifest_path}" 0644 strict
}

write_server_config() {
  local config_path="$1"
  local cert_path="$2"
  local key_path="$3"
  local auth_token="$4"
  local listen_addr="$5"

  cat > "${config_path}" <<EOF
listen = "${listen_addr}"
cert = "${cert_path}"
key = "${key_path}"
auth_token = "${auth_token}"
fallback = "close"

[transport]
# Neutral primaries shared with the client renderer; legacy mounts remain
# explicit compatibility entries for previously issued profiles.
websocket_path = "/socket"
grpc_path = "/rpc.Tunnel/Open"
masque_path = "/.well-known/masque/udp"
# quic_listen = "0.0.0.0:8443"

# v0.3.7: explicit path pools (was relying on serde defaults which could
# drift between aegis-core and aegis-server deserialisers). Server now
# accepts client TLS rotations across these alternates without per-target
# fingerprint locking. Match aegis-core::config_types::default_*_path_pool().
websocket_path_pool = ["/ws", "/realtime/connect", "/aegis/ws"]
grpc_path_pool = ["/cdn.tunnel.v1.Session/Open", "/grpc.gateway.v1.Proxy/Connect", "/aegis.tunnel.v1.TunnelService/Open"]
masque_path_pool = ["/.well-known/masque/connect-udp", "/masque/v1/udp", "/relay/datagram"]

# v0.2.0+: serve client bundles via HTTPS /bundle?token=... on the same
# 8443 listener. install.sh auto-issues the first token after activation;
# operator can rotate via 'aegis-server bundle-token issue|list|prune'.
[bundle_endpoint]
enabled = true
EOF
}

install_text_file() {
  local destination="$1"
  local mode="$2"
  local content="$3"

  install_atomic_write "${destination}" "${mode}" strict validate </dev/null || return 1
  if [[ "${FORCE}" -eq 0 && -e "${destination}" ]]; then
    echo "Refusing to overwrite existing file without --force: ${destination}" >&2
    exit 1
  fi
  if [[ "${FORCE}" -eq 1 && -e "${destination}" ]]; then
    # Preserve the previous file so a reapply keeps an audit trail instead of
    # silently replacing the operator-managed state.
    local backup_path="${destination}.bak.$(date +%Y%m%d%H%M%S)"
    install_atomic_write "${backup_path}" "${mode}" strict validate </dev/null || return 1
    cp -a "${destination}" "${backup_path}" || return 1
    echo "Backed up existing file to ${backup_path}"
  fi
  printf '%s\n' "${content}" | install_atomic_write "${destination}" "${mode}" strict
}

install_copy_file() {
  local source="$1"
  local destination="$2"
  local mode="$3"

  require_asset "${source}"
  install_atomic_write "${destination}" "${mode}" strict validate </dev/null || return 1
  if [[ "${FORCE}" -eq 0 && -e "${destination}" ]]; then
    echo "Refusing to overwrite existing file without --force: ${destination}" >&2
    exit 1
  fi
  if [[ "${FORCE}" -eq 1 && -e "${destination}" ]]; then
    # Keep the previous rendered asset for diff/reapply review on Ubuntu hosts.
    local backup_path="${destination}.bak.$(date +%Y%m%d%H%M%S)"
    install_atomic_write "${backup_path}" "${mode}" strict validate </dev/null || return 1
    cp -a "${destination}" "${backup_path}"
    echo "Backed up existing file to ${backup_path}"
  fi
  install -m "${mode}" "${source}" "${destination}"
}

render_template() {
  local template_path="$1"
  shift
  local rendered
  rendered="$(<"${template_path}")"
  while [[ $# -gt 1 ]]; do
    local needle="$1"
    local value="$2"
    shift 2
    rendered="${rendered//${needle}/${value}}"
  done

require_role_dependencies
  printf '%s\n' "${rendered}"
}

current_user_name() {
  id -un
}

current_group_name() {
  id -gn
}

ensure_server_service_account() {
  local state_dir="$1"

  if [[ ${EUID} -ne 0 ]]; then
    return 0
  fi

  if ! id -u aegis >/dev/null 2>&1; then
    # When state_dir already exists from a prior install, useradd would
    # emit "warning: the home directory ... already exists" — silence
    # that by skipping --create-home; ensure_dir + chown below cover it.
    if [[ -d "${state_dir}" ]]; then
      useradd --system --no-create-home --home-dir "${state_dir}" --shell /usr/sbin/nologin aegis
    else
      useradd --system --create-home --home-dir "${state_dir}" --shell /usr/sbin/nologin aegis
    fi
  fi
  ensure_dir "${state_dir}"
  chown aegis:aegis "${state_dir}"

  # v0.3.5: bundle token store dir defaults to /var/lib/aegis/ and is
  # created by `BundleTokenStore::load()` with mode 0o700 на first
  # invocation. Without explicit ownership setup, it ends up
  # 0o700 root:root because the FIRST writer is `aegis-server
  # bundle-token issue` invoked by install.sh as root. Then service
  # (running as aegis user) cannot enter the dir → load returns
  # empty store → every /bundle redeem → 403.
  # Fix: pre-create the bundle-token-store directory с aegis:aegis
  # ownership и 0o700 so both root-as-CLI и aegis-as-service can
  # write/read by file ACL alone.
  local bundle_store_dir="/var/lib/aegis"
  ensure_dir "${bundle_store_dir}"
  chown aegis:aegis "${bundle_store_dir}"
  chmod 0700 "${bundle_store_dir}"
}

secure_server_materials() {
  local config_root="$1"
  local cert_dir="$2"
  local config_path="$3"
  local service_group="$4"

  if [[ ${EUID} -ne 0 ]]; then
    chmod 700 "${config_root}" "${cert_dir}"
    chmod 600 "${config_path}" "${cert_dir}/server.pem" "${cert_dir}/server-key.pem" "${cert_dir}/ca.pem"
    return 0
  fi

  chown root:"${service_group}" "${config_root}" "${cert_dir}"
  chown root:"${service_group}" "${config_path}" "${cert_dir}/server.pem" "${cert_dir}/server-key.pem" "${cert_dir}/ca.pem"
  chmod 750 "${config_root}" "${cert_dir}"
  chmod 640 "${config_path}" "${cert_dir}/server.pem" "${cert_dir}/server-key.pem" "${cert_dir}/ca.pem"
}

secure_server_bundle_archive() {
  local archive_path="$1"
  local service_user="$2"
  local service_group="$3"

  if [[ ! -f "${archive_path}" ]]; then
    echo "Generated client bundle archive is missing: ${archive_path}" >&2
    return 1
  fi

  # The archive contains the relay credential, so it remains private. A
  # root-owned 0600 file lets a one-time token validate and become consumed,
  # then fails the actual download with a misleading 404 because aegis-server
  # cannot read the file. Root installs grant the service group read-only
  # access; the daemon never needs permission to mutate the archive.
  if [[ ${EUID} -eq 0 ]]; then
    chown root:"${service_group}" "${archive_path}"
    chmod 0640 "${archive_path}"
    if command -v runuser >/dev/null 2>&1 && \
       ! runuser -u "${service_user}" -g "${service_group}" -- test -r "${archive_path}"; then
      echo "Generated client bundle archive is not readable by ${service_user}" >&2
      return 1
    fi
    return 0
  fi

  # A non-root install cannot hand ownership to another account and does not
  # need to: package-client-bundle.sh created the archive as the current
  # service owner. Keep this path usable on minimal user-mode hosts where
  # chown is intentionally absent from PATH.
  chmod 0600 "${archive_path}"
}

install_server_service_assets() {
  local bin_path="$1"
  local config_path="$2"
  local state_dir="$3"
  local service_user="$4"
  local service_group="$5"

  if [[ -z "${SYSTEMD_DIR}" || -z "${ENV_DIR}" ]]; then
    return 0
  fi

  local unit_template="${ROOT}/packaging/systemd/aegis-server.service"
  local env_template="${ROOT}/packaging/env/aegis-server.env.example"
  local env_file="${ENV_DIR}/aegis-server"
  local unit_file="${SYSTEMD_DIR}/aegis-server.service"

  require_asset "${unit_template}"
  require_asset "${env_template}"

  install_copy_file "${env_template}" "${env_file}" 0644 || return 1
  install_text_file "${unit_file}" 0644 "$(
    render_template "${unit_template}" \
      "__AEGIS_SERVER_ENV_FILE__" "${env_file}" \
      "__AEGIS_SERVER_STATE_DIR__" "${state_dir}" \
      "__AEGIS_SERVER_BIN__" "${bin_path}" \
      "__AEGIS_SERVER_CONFIG__" "${config_path}" \
      "__AEGIS_SERVER_USER__" "${service_user}" \
      "__AEGIS_SERVER_GROUP__" "${service_group}"
  )"
}

device_online_identity_path() {
  [[ "$1" == /var/lib/* ]] || {
    echo 'Online device identity must use a persistent directory under /var/lib so the protected service can renew it.' >&2; return 1;
  }
  case "$1" in
    /var/lib/aegis-install|/var/lib/aegis-install/*|/var/lib/aegis|/var/lib/aegis/*|/var/lib/aegis-server|/var/lib/aegis-server/*)
      echo 'Online device identity must not overlap installer metadata or recovery state.' >&2; return 1 ;;
  esac
}

device_preflight_online_public_bundle() {
  [[ "${DEVICE_ONLINE:-0}" == 1 ]] || return 0
  local source="$1" destination=/etc/aegis/client/device-bundle
  # This check precedes identity preparation, profile pinning and enrollment.
  # An identical interrupted public copy can resume; every conflicting member
  # or unknown entry requires an explicit profile migration instead.
  python3 -I - "$source" "$destination" <<'PY_PUBLIC_PREFLIGHT'
import os,pathlib,stat,sys
source,destination=sys.argv[1:]
anchor='/'
allowed={'bundle.json','outer-ca.pem','inner-ca.pem','device-ca.pem'}
def need(ok,message):
    if not ok: raise SystemExit('Online public profile preflight: '+message)
def directory(path,missing=False,public_source=False):
    parts=pathlib.PurePath(path).parts[1:]
    fd=os.open(anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for index,part in enumerate(parts):
            try: child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:
                if missing: return None
                raise
            os.close(fd);fd=child
            value=os.fstat(fd)
            sticky_ancestor=public_source and index+1<len(parts) and bool(value.st_mode&0o1000)
            need(value.st_uid==0 and (not value.st_mode&0o022 or sticky_ancestor),'untrusted directory')
        result=fd;fd=None;return result
    finally:
        if fd is not None: os.close(fd)
def read(fd,name):
    leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    try:
        value=os.fstat(leaf)
        need(stat.S_ISREG(value.st_mode) and value.st_uid==0 and not value.st_mode&0o022 and value.st_nlink==1 and value.st_size<=65536,'untrusted public member')
        with os.fdopen(leaf,'rb',closefd=False) as stream: data=stream.read(65537)
        need(len(data)<=65536,'public member exceeds bound')
        return data
    finally: os.close(leaf)
existing=directory(destination,missing=True)
if existing is None: sys.exit(0)
expected=None
try:
    # Public sources may live below a root-owned sticky temporary ancestor,
    # matching the Rust trust policy; their final directory remains protected.
    # Destination ancestry never permits writable/sticky directories.
    # There can only be four entries. Bound enumeration before reading content.
    names=[]
    with os.scandir(existing) as entries:
        for entry in entries:
            need(len(names)<4 and entry.name in allowed,'unknown or excess existing public member')
            names.append(entry.name)
    expected=directory(source,public_source=True)
    for name in names:
        need(read(existing,name)==read(expected,name),'existing public profile differs; explicit migration required')
finally:
    if expected is not None: os.close(expected)
    os.close(existing)
PY_PUBLIC_PREFLIGHT
}

device_install_online_public_bundle() {
  local source="$DEVICE_PUBLIC_BUNDLE" destination=/etc/aegis/client/device-bundle file
  local client="${AEGIS_ROOT_STATE_CLIENT:-/usr/local/bin/aegis-client}"
  [[ "${DEVICE_ONLINE:-0}" == 1 ]] || return 0
  "$client" device bundle-inspect --bundle-dir "$source" --identity-dir "$DEVICE_IDENTITY_DIR" --json >/dev/null || return 1
  device_preflight_online_public_bundle "$source" || return 1
  "$client" profile metadata validate --path "$destination/bundle.json" || return 1
  if [[ "$source" != "$destination" ]]; then
    ensure_dir "$destination" || return 1
    chmod 0700 "$destination" || return 1
    for file in bundle.json outer-ca.pem inner-ca.pem device-ca.pem; do
      install_atomic_write "$destination/$file" 0600 strict validate </dev/null || return 1
      if [[ -e "$destination/$file" ]] && ! cmp -s "$source/$file" "$destination/$file"; then
        echo 'Existing public online profile differs; use the explicit profile migration workflow before replacing it.' >&2; return 1
      fi
      # Generic install_copy_file creates adjacent .bak files. Exact public
      # bundles must retain only four members, including interrupted retries.
      cat "$source/$file" | install_atomic_write "$destination/$file" 0600 strict || return 1
    done
  fi
  # Unknown files, a changed profile or any inconsistent partial copy refuse
  # activation. A device key/invitation is never a member of this directory.
  "$client" device bundle-inspect --bundle-dir "$destination" --identity-dir "$DEVICE_IDENTITY_DIR" --json >/dev/null || return 1
  DEVICE_ONLINE_BUNDLE="$destination"
  DEVICE_PUBLIC_BUNDLE="$destination"
}

device_recover_online_local() {
  local client="${3:-${PREFLIGHT_CLIENT_BINARY}}"
  "$client" device recover-local --device-id "$DEVICE_ID" --identity-dir "$1" --bundle-dir "$2" --json | python3 -I -c '
import json,sys
r=json.load(sys.stdin)
assert r["schema"]=="aegis_device_local_recovery_v1"
assert r["phase"] in ("prepared","ready","runtime_recovery_required")
assert type(r["repaired"]) is bool and type(r["pending_request"]) is bool
print(r["phase"])
'
}

device_validate_config() {
  local client="$1" config="$2"
  local -a args=(--config "$config" --validate-config --json)
  [[ "${DEVICE_ONLINE:-0}" != 1 ]] || args+=(--device-online-bundle "$DEVICE_PUBLIC_BUNDLE")
  "$client" "${args[@]}"
}

install_client_systemd_asset() {
  local bin_path="$1"
  local config_path="$2"
  local state_dir="$3"
  local runtime_events_path="$4"

  if [[ -z "${SYSTEMD_DIR}" || -z "${ENV_DIR}" ]]; then
    return 0
  fi

  local service_command="$bin_path" notify_settings=''
  if [[ "${DEVICE_ONLINE:-0}" == 1 ]]; then
    [[ "$bin_path" == /usr/local/bin/aegis-client && "$config_path" == /etc/aegis/client/aegis.toml &&
       "$SYSTEMD_DIR" == /etc/systemd/system && "$state_dir" == /var/lib/aegis-client ]] || return 1
    device_install_online_public_bundle || return 1
    service_command="$bin_path --device-online-bundle $DEVICE_ONLINE_BUNDLE"
    notify_settings='
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=180
Restart=on-failure
RestartSec=30'
  fi
  local unit_template="${ROOT}/packaging/systemd/aegis-client.service"
  local env_template="${ROOT}/packaging/env/aegis-client.env.example"
  local env_file="${ENV_DIR}/aegis-client"
  local unit_file="${SYSTEMD_DIR}/aegis-client.service"

  require_asset "${unit_template}"
  require_asset "${env_template}"

  local rendered_unit
  rendered_unit="$(
    render_template "${unit_template}" \
      "__AEGIS_CLIENT_ENV_FILE__" "${env_file}" \
      "__AEGIS_CLIENT_STATE_DIR__" "${state_dir}" \
      "__AEGIS_CLIENT_BIN__" "${service_command}" \
      "__AEGIS_CLIENT_CONFIG__" "${config_path}" \
      "__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__" "${runtime_events_path}"
  )" || return 1
  install_copy_file "${env_template}" "${env_file}" 0644 || return 1
  install_text_file "${unit_file}" 0644 "${rendered_unit}${notify_settings}"
}

install_client_launchd_asset() {
  local bin_path="$1"
  local config_path="$2"
  local state_dir="$3"
  local runtime_events_path="$4"
  local log_dir="$5"

  local plist_template="${ROOT}/packaging/launchd/dev.aegis.client.plist"
  if [[ ! -f "${plist_template}" ]]; then
    # Template missing in older release bundles — skip quietly.
    return 0
  fi
  local target_dir="${LAUNCHD_DIR:-$(default_launchd_agent_dir)}"
  ensure_dir "${target_dir}"
  ensure_dir "${log_dir}"
  local plist_path="${target_dir}/dev.aegis.client.plist"

  install_text_file "${plist_path}" 0644 "$(
    render_template "${plist_template}" \
      "__AEGIS_CLIENT_BIN__" "${bin_path}" \
      "__AEGIS_CLIENT_CONFIG__" "${config_path}" \
      "__AEGIS_CLIENT_STATE_DIR__" "${state_dir}" \
      "__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__" "${runtime_events_path}" \
      "__AEGIS_CLIENT_LOG_DIR__" "${log_dir}"
  )"

  local uid
  uid="$(launchd_target_uid 2>/dev/null || printf '?')"
  local launchagent_status="BLOCKED"
  local launchagent_reason="No gui/${uid} launchd domain is visible for this shell; do not claim LaunchAgent service readiness from this install."
  if launchd_gui_domain_exists; then
    launchagent_status="READY_TO_BOOTSTRAP"
    launchagent_reason="gui/${uid} launchd domain exists; bootstrap can be attempted from this interactive desktop session."
  fi

  cat <<EOF
macOS LaunchAgent asset installed:
  ${plist_path}

LaunchAgent status: ${launchagent_status}
Reason: ${launchagent_reason}

To start the LaunchAgent from an interactive desktop session:
  launchctl bootout "gui/${uid}" "${plist_path}" 2>/dev/null || true
  launchctl bootstrap "gui/${uid}" "${plist_path}"

To check status:
  launchctl print "gui/${uid}/dev.aegis.client"

Headless/dedicated-user options:
  - Use the packaged macOS installer with --service-mode launchdaemon --service-user <user>.
  - Or run foreground/operator mode:
      "${bin_path}" --config "${config_path}" --runtime-events-jsonl "${runtime_events_path}"

EOF
}

# Dispatcher: picks systemd or launchd based on OS. Kept under the
# original name so existing call-sites keep working — contract tests
# pin the systemd path, which still runs on detected linux hosts.
install_client_service_assets() {
  local bin_path="$1"
  local config_path="$2"
  local state_dir="$3"
  local runtime_events_path="$4"
  local log_dir="${5:-${LOG_DIR:-$(default_client_log_dir)}}"

  local kind
  kind="$(detect_os_kind)"
  case "${kind}" in
    darwin)
      install_client_launchd_asset "${bin_path}" "${config_path}" "${state_dir}" "${runtime_events_path}" "${log_dir}"
      ;;
    *)
      install_client_systemd_asset "${bin_path}" "${config_path}" "${state_dir}" "${runtime_events_path}"
      ;;
  esac
}

install_root_auto_native_role() {
  if [[ "${SOURCE_LAYOUT}" -eq 1 ]]; then
    AUTO_NATIVE_ROLE=admin
    return 0
  fi
  # The packaged manifest has already passed the release inventory and
  # SHA256SUMS gate above. Read its exact role again here so public client-only
  # bundles keep their closed, unprivileged helper set.
  local role_program
  IFS= read -r -d '' role_program <<'PY_AUTO_ROLE' || true
import json
import sys
from pathlib import Path
schema = json.loads(Path(sys.argv[1]).read_bytes()).get("schema")
if schema == "aegis_release_bundle_manifest_v2":
    print("admin")
elif schema in ("aegis_client_release_bundle_manifest_v1",
                "aegis_client_release_bundle_manifest_v2",
                "aegis_client_release_bundle_manifest_v3"):
    print("public")
else:
    raise SystemExit("unknown install payload role")
PY_AUTO_ROLE
  AUTO_NATIVE_ROLE="$(printf '%s' "$role_program" | python3 -I - "${ROOT}/bundle.manifest.json")" || return 1
  [[ "${AUTO_NATIVE_ROLE}" == admin || "${AUTO_NATIVE_ROLE}" == public ]] || return 1
}

install_client_auto_native_assets() {
  local helper_dir="$1"
  local module unit
  # These are passive, source-owned leaves. A valid v2 device assessment
  # installs the guard unit separately; copying these leaves does not start,
  # enable, or grant any AUTO service.
  install_copy_file "${ROOT}/scripts/aegis-device-egress-guard.sh" \
    "${helper_dir}/aegis-device-egress-guard.sh" 0755 || return 1
  for module in \
    aegis_installer_auto_v2.py \
    aegis_auto_capture.py \
    aegis_auto_capture_topology.py \
    aegis_auto_endpoint.py \
    aegis_auto_guard_policy.py \
    aegis_auto_foreign_policy.py \
    aegis_auto_foreign_monitor.py \
    aegis_auto_ufw_pins.json \
    aegis_initrd_policy.py \
    aegis_initrd_classic.py \
    aegis_auto_guardian.py \
    aegis_auto_guardian_watchdog.py \
    aegis_auto_terminal_witness.py \
    aegis_auto_terminal_boot_store.py \
    aegis_auto_terminal_register.py \
    aegis_auto_boot_transition.py \
    aegis_auto_launch.py \
    aegis_auto_native_witness.py \
    aegis_auto_sink.py \
    aegis_auto_trace_rollback.py \
    aegis_auto_witness_topology.py; do
    install_copy_file "${ROOT}/scripts/lib/${module}" \
      "${helper_dir}/lib/${module}" 0500 || return 1
  done
  ensure_dir "${SYSTEMD_DIR}" || return 1
  install_copy_file "${ROOT}/packaging/systemd/system-shutdown/aegis-auto-terminal-hook" \
    "${helper_dir}/lib/aegis-auto-terminal-hook" 0500 || return 1
  for unit in \
    aegis-auto-config.service \
    aegis-auto-capture-topology.service \
    aegis-auto-guardian-watchdog.service \
    aegis-auto-guardian.service \
    aegis-auto-terminal-a@.service \
    aegis-auto-terminal-b@.service \
    aegis-auto-terminal-observer.service \
    aegis-auto-terminal-transition.service \
    aegis-auto-trace-rollback-actor.service \
    aegis-auto-trace-rollback.service \
    aegis-auto-trace-rollback.timer \
    aegis-auto-witness-topology.service \
    aegis-foreign-policy-monitor.service \
    aegis-device-dhcp-refresh.service \
    aegis-device-dhcp-refresh.timer \
    aegis-auto-clean-shutdown.service; do
    install_copy_file "${ROOT}/packaging/systemd/${unit}" \
      "${SYSTEMD_DIR}/${unit}" 0644 || return 1
  done
}

install_client_wide_helpers() {
  local helper_dir="$1"

  ensure_dir "${helper_dir}" || return 1
  ensure_dir "${helper_dir}/lib" || return 1
  install_copy_file "${ROOT}/scripts/lib/root-state.sh" "${helper_dir}/lib/root-state.sh" 0755 || return 1
  # Keep operator-facing wide rollout helpers on-host so release installs no
  # longer depend on repo-side scp from the source checkout.
  install_copy_file "${ROOT}/scripts/setup-wide-linux-redirect.sh" \
    "${helper_dir}/setup-wide-linux-redirect.sh" 0755 || return 1
  install_copy_file "${ROOT}/scripts/setup-wide-linux-tproxy.sh" \
    "${helper_dir}/setup-wide-linux-tproxy.sh" 0755 || return 1
  if [[ -f "${ROOT}/scripts/setup-wide-linux-nfqueue.sh" ]]; then
    install_copy_file "${ROOT}/scripts/setup-wide-linux-nfqueue.sh" \
      "${helper_dir}/setup-wide-linux-nfqueue.sh" 0755 || return 1
  fi
  install_copy_file "${ROOT}/scripts/aegis-wide-enable.sh" \
    "${helper_dir}/aegis-wide-enable.sh" 0755 || return 1
  install_copy_file "${ROOT}/scripts/aegis-wide-disable.sh" \
    "${helper_dir}/aegis-wide-disable.sh" 0755 || return 1
  install_copy_file "${ROOT}/scripts/aegis-wide-persist-install.sh" \
    "${helper_dir}/aegis-wide-persist-install.sh" 0755 || return 1
  # Keep the role-aware purge helper on-host. The standalone Ubuntu client
  # uninstaller delegates to this exact helper so it can remove env files,
  # service drop-ins and networking state without falling back to a weaker
  # manual sweep.
  install_copy_file "${ROOT}/scripts/purge-installed-aegis.sh" \
    "${helper_dir}/purge-installed-aegis.sh" 0755 || return 1
  install_copy_file "${ROOT}/scripts/aegis-ubuntu-uninstall.sh" \
    "${helper_dir}/aegis-ubuntu-uninstall.sh" 0755 || return 1
  if [[ -f "${ROOT}/scripts/janitor-wide-linux-tproxy.sh" ]]; then
    install_copy_file "${ROOT}/scripts/janitor-wide-linux-tproxy.sh" \
      "${helper_dir}/janitor-wide-linux-tproxy.sh" 0755 || return 1
  fi
  # Turnkey gateway wrapper (RPi/router): ip_forward + NAT + tproxy capture on a
  # downstream interface in one command, on top of the linux_tproxy client.
  if [[ -f "${ROOT}/scripts/aegis-rpi-gateway.sh" ]]; then
    install_copy_file "${ROOT}/scripts/aegis-rpi-gateway.sh" \
      "${helper_dir}/aegis-rpi-gateway.sh" 0755 || return 1
  fi
  if [[ "$(detect_os_kind)" == linux ]]; then
    install_root_auto_native_role || return 1
    if [[ "${AUTO_NATIVE_ROLE}" == admin ]]; then
      install_client_auto_native_assets "${helper_dir}" || return 1
    fi
  fi
}

print_systemd_followup() {
  local unit_name="$1"
  if [[ -n "${SYSTEMD_DIR}" ]]; then
    cat <<EOF
Systemd unit:
  ${SYSTEMD_DIR}/${unit_name}
EOF
  fi
}

systemd_activation_requested() {
  local override="${AEGIS_INSTALL_FORCE_SYSTEMD_ACTIVATE:-}"
  case "${override}" in
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn])
      return 0
      ;;
    0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Oo][Ff][Ff])
      return 1
      ;;
  esac

  [[ ${EUID} -eq 0 ]] || return 1
  [[ "${SYSTEMD_DIR}" == "/etc/systemd/system" ]] || return 1
  command -v systemctl >/dev/null 2>&1
}

restart_systemd_unit_checked() {
  local unit_name="$1"
  # Repeated install/repair performs a bounded sequence of intentional restarts
  # (new binary, then rewritten wide config, and possibly fail-safe rollback).
  # systemd counts those like crashes and may reject the next start with
  # start-limit-hit. Reset only this unit's failed/rate-limit state immediately
  # before our requested restart, then require the new process to be active.
  systemctl reset-failed "${unit_name}" >/dev/null 2>&1 || true
  systemctl restart "${unit_name}" || return 1
  systemctl is-active --quiet "${unit_name}"
}

activate_systemd_unit() {
  local unit_name="$1"
  local was_active=0
  if ! systemd_activation_requested; then
    # Print actionable hint when activation is gated (non-root, custom
    # systemd-dir, no systemctl) so operators don't think the installer
    # silently succeeded but did nothing.
    if [[ -n "${SYSTEMD_DIR}" ]]; then
      cat <<EOF

Systemd activation skipped (run installer as root with default
--systemd-dir=/etc/systemd/system to enable auto-start). Manual:
  sudo systemctl daemon-reload
  sudo systemctl enable --now ${unit_name}
EOF
    fi
    return 0
  fi

  printf '\n[install] activating %s...\n' "${unit_name}"
  # `enable --now` is intentionally idempotent and does not restart an already
  # active service. During upgrade or a wide -> socks mode switch that leaves
  # the old process running the previous binary/config (and, for TUN, its old
  # capture routes) while the installer reports success. Remember the state
  # before activation and explicitly restart only an existing instance; a
  # fresh install still starts exactly once through `enable --now`.
  if systemctl is-active --quiet "${unit_name}"; then
    was_active=1
  fi
  systemctl daemon-reload
  systemctl reset-failed "${unit_name}" >/dev/null 2>&1 || true
  # Preserve the packaged preset policy when available, but do not fail the
  # install if the host lacks preset metadata for this unit yet.
  systemctl preset "${unit_name}" >/dev/null 2>&1 || true
  systemctl enable --now "${unit_name}"
  if [[ "${was_active}" == "1" ]]; then
    restart_systemd_unit_checked "${unit_name}"
  fi

  if systemctl is-active --quiet "${unit_name}"; then
    printf '[install] \xe2\x9c\x85 %s is active\n' "${unit_name}"
  else
    printf '[install] \xe2\x9d\x8c %s failed to start. Last 20 journalctl lines:\n' "${unit_name}"
    journalctl -u "${unit_name}" -n 20 --no-pager 2>/dev/null || true
    printf '[install] aborting: a requested system service is not active.\n' >&2
    return 1
  fi
}

print_client_bootstrap_command() {
  local bundle_url_file="$1" server_binary="$2"
  [[ -n "${AEGIS_CLIENT_LAUNCHER_PINS:-}" ]] || return 1
  # The installed Rust renderer is shared with bundle-token issue. A mirror's
  # bootstrap or checksum is never used to establish its own trust.
  "${server_binary}" install-launcher --pins "${AEGIS_CLIENT_LAUNCHER_PINS}" --bundle-url-file "${bundle_url_file}"
}

auto_issue_first_bundle_token() {
  # Run `aegis-server bundle-token issue` once during server install so
  # operators get a private access record without editing TOML by hand.
  # Requires the binary to be present and the token-store path writable
  # (we run as root so default /var/lib/aegis/bundle-tokens.json is fine).
  #
  # The binary derives the printed URL from --public-host / --public-port
  # (passed by install.sh from RELAY_ADDRESS, which choose_bundle_relay_endpoint
  # already resolves to a routable FQDN or public IP). Without these flags
  # the binary would fall back to `cfg.listen` (often 0.0.0.0:8443) and
  # produce a non-routable URL.
  #
  # v0.3.1: also reads `${cert_dir}/server.spki.b64` (written by
  # generate-relay-materials.sh after cert gen) and passes it as
  # --public-cacert-pin so the printed bundle URL contains
  # &pin=sha256//<base64>. Client-side curl uses --pinnedpubkey to
  # validate the relay public key WITHOUT needing the CA, breaking
  # the chicken-and-egg of CA delivery.
  local bin_path="$1"
  local config_path="$2"
  local bundle_archive_out="$3"
  local relay_address="$4"  # "host:port" or "host" (FQDN/IP)
  local cert_dir="$5"       # absolute path to the cert directory

  if [[ "${AUTO_ISSUE_TOKEN}" -ne 1 ]]; then
    return 0
  fi
  if [[ ! -x "${bin_path}" ]]; then
    return 0
  fi
  if [[ ! -f "${bundle_archive_out}" ]]; then
    return 0
  fi

  local public_host="${relay_address%:*}"
  local public_port="${relay_address##*:}"
  if [[ "${public_host}" == "${public_port}" ]] || [[ -z "${public_port}" ]]; then
    # No port suffix → default to 8443 (matches install.sh LISTEN_ADDR default).
    public_port="8443"
  fi
  if [[ -z "${public_host}" ]]; then
    printf '\n[install] auto-issue skipped: no resolvable public host for bundle URL.\n' >&2
    return 0
  fi

  local spki_pin=""
  if [[ -n "${cert_dir}" && -f "${cert_dir}/server.spki.b64" ]]; then
    spki_pin="$(tr -d '\n\r ' < "${cert_dir}/server.spki.b64")"
  fi

  local issue_args=(
    --bundle-path "${bundle_archive_out}"
    --comment "auto-issued by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    --public-host "${public_host}"
    --public-port "${public_port}"
  )
  if [[ -n "${spki_pin}" ]]; then
    issue_args+=(--public-cacert-pin "${spki_pin}")
  fi

  # v0.3.5: when EUID=0 и aegis user exists, drop privs to aegis для
  # CLI invocation. Это критично потому что service runs as aegis;
  # token-store JSON file должен принадлежать aegis (не root) чтобы
  # service мог прочитать perms-restricted файл (0600 owner-only).
  # Без этого root пишет 0600 root:root → service aegis получает
  # NotFound → 403 на каждом redeem.
  local issue_runner=()
  local service_user="$(current_user_name)" service_group="$(current_group_name)"
  if [[ ${EUID} -eq 0 ]] && id -u aegis >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then
    issue_runner=(runuser -u aegis -g aegis --)
    service_user=aegis; service_group=aegis
  fi
  [[ "$("$bin_path" installer-secret version)" == installer-secret-v1 ]] || {
    echo "[install] private URL issuer unavailable; no token was requested." >&2; return 0;
  }
  local issue_dir output_dir issued_url private_url
  issue_dir="$(mktemp -d "${config_path%/*}/client-access-transfer.XXXXXXXX")" || return 1
  chmod 0700 "$issue_dir" || return 1
  [[ ${EUID} -ne 0 ]] || chown "$service_user:$service_group" "$issue_dir" || return 1
  output_dir="$(mktemp -d "${config_path%/*}/client-access.XXXXXXXX")" || return 1
  chmod 0700 "$output_dir" || return 1
  issued_url="$issue_dir/access-url.txt"; private_url="$output_dir/access-url.txt"
  issue_args+=(--url-output "$issued_url")
  if ! "${issue_runner[@]+"${issue_runner[@]}"}" "$bin_path" --config "$config_path" bundle-token issue "${issue_args[@]}" >/dev/null 2>&1; then
    echo "[install] access issuance failed; no retry attempted, store may have committed." >&2
    echo "[install] retained private issuance directory: $issue_dir" >&2
    echo "[install] retained destination directory (record not verified): $output_dir" >&2
    return 0
  fi
  # The already established service owner emits its own private record into
  # the root/current-euid Rust writer. No SUDO_UID/path trust promotion occurs.
  if ! "${issue_runner[@]+"${issue_runner[@]}"}" "$bin_path" installer-secret read-url --path "$issued_url" \
      | "$bin_path" installer-secret write-url-stdin --output "$private_url" >/dev/null 2>&1; then
    echo "[install] private access transfer failed; issuance may have committed; no retry attempted." >&2
    echo "[install] retained private issuance directory: $issue_dir" >&2
    echo "[install] retained destination directory (record not verified): $output_dir" >&2
    return 0
  fi
  # The original source is disposable only after the complete Rust writer
  # reports success; an uncertain publication retains both private directories.
  TEMP_PATHS+=("$issue_dir")
  echo "Client access record saved privately: $private_url"
  echo "Transfer this record privately to a client-owned absolute path before installing."
  print_client_bootstrap_command "$private_url" "$bin_path" || echo "Verified client launcher is not configured."

}

detect_existing_install() {
  # Returns 0 if any AEGIS install residue is detected for the given role.
  # Looks at well-known config paths + the installer's own --config-dir.
  local role="$1"
  local current_config_dir="$2"
  case "${role}" in
    server)
      [[ -f /etc/aegis/server/aegis-server.toml ]] && return 0
      [[ -f "${current_config_dir}/aegis-server.toml" ]] && return 0
      [[ -f /usr/local/bin/aegis-server ]] && return 0
      ;;
    client)
      [[ -f /etc/aegis/aegis.toml ]] && return 0
      [[ -f "${current_config_dir}/aegis.toml" ]] && return 0
      [[ -f /usr/local/bin/aegis-client ]] && return 0
      ;;
  esac
  return 1
}

prompt_reinstall_choice() {
  # Returns the selected mode via stdout: "upgrade" | "reinstall" | "cancel".
  # Reads from /dev/tty (so it works under `curl | bash` where stdin is
  # the install.sh source). Falls back to "upgrade" silently when no TTY.
  local role="$1"
  if [[ -n "${REINSTALL_MODE}" ]]; then
    printf '%s\n' "${REINSTALL_MODE}"
    return 0
  fi
  if [[ -n "${AEGIS_INSTALL_NONINTERACTIVE:-}" ]]; then
    printf 'upgrade\n'
    return 0
  fi
  if [[ ! -r /dev/tty ]] || [[ ! -w /dev/tty ]]; then
    printf 'upgrade\n'
    return 0
  fi
  local choice=""
  {
    printf '\n'
    printf 'Detected an existing AEGIS %s install on this host.\n' "${role}"
    printf '\n'
    printf '  [U] Upgrade in place  (keep auth_token + state, reapply binary + config)\n'
    printf '  [R] Reinstall fresh   (purge + install \xe2\x80\x94 DESTROYS state.json + auth_token)\n'
    printf '  [C] Cancel\n'
    printf '\n'
  } >/dev/tty
  while true; do
    printf 'Choice [U/R/C]: ' >/dev/tty
    if ! read -r choice </dev/tty; then
      printf 'upgrade\n'
      return 0
    fi
    case "${choice}" in
      [Uu]|[Uu][Pp]*) printf 'upgrade\n'; return 0 ;;
      [Rr]|[Rr][Ee]*) printf 'reinstall\n'; return 0 ;;
      [Cc]|[Cc][Aa]*) printf 'cancel\n'; return 0 ;;
      *) printf 'Please answer U, R, or C.\n' >/dev/tty ;;
    esac
  done
}

resolve_existing_install_choice() {
  # Resolve the operator's choice without mutating the existing install. Client
  # reinstall uses this split phase to let cancel win before consuming a
  # one-time bundle URL, while still delaying purge until all preflight checks
  # have passed.
  local role="$1"
  local current_config_dir="$2"

  if ! detect_existing_install "${role}" "${current_config_dir}"; then
    printf 'none\n'
    return 0
  fi

  prompt_reinstall_choice "${role}"
}

apply_existing_install_choice() {
  local role="$1"
  local choice="$2"
  local preserve_path="${3:-}"
  local purge_status=0

  case "${choice}" in
    none)
      ;;
    upgrade)
      printf '\n[install] upgrading existing AEGIS %s install in place.\n' "${role}"
      ;;
    reinstall)
      printf '\n[install] reinstalling fresh \xe2\x80\x94 purging existing AEGIS %s residue first.\n' "${role}"
      if [[ -x "${ROOT}/scripts/purge-installed-aegis.sh" ]]; then
        # The validated client bundle is installer input, not installed
        # residue. Protect it across destructive cleanup and align purge's
        # temporary root with the mktemp root used by this installer.
        if AEGIS_PURGE_PRESERVE_PATH="${preserve_path}" \
          AEGIS_PURGE_TMPDIR="${TMPDIR:-/tmp}" \
          bash "${ROOT}/scripts/purge-installed-aegis.sh" "${role}" --force; then
          :
        else
          purge_status=$?
          # A failed purge may already have changed installed state. Stopping
          # prevents further overwrite; it is not rollback of partial cleanup.
          printf '[install] error: purge failed (exit=%s); reinstall stopped before further overwrite. Partial purge changes are not rolled back.\n' \
            "${purge_status}" >&2
          return "${purge_status}"
        fi
      else
        printf '[install] error: purge helper missing or not executable at %s; reinstall stopped before overwrite.\n' \
          "${ROOT}/scripts/purge-installed-aegis.sh" >&2
        return 1
      fi
      # Successful reinstall purge implies --force semantics: the operator asked for
      # a clean state, so install steps must be allowed to overwrite any
      # files purge missed (env files, leftover certs, stale unit files).
      # Without this, install_text_file refuses on /etc/default/aegis-server
      # when the env file persisted from a prior install.
      FORCE=1
      ;;
    cancel)
      printf '\n[install] cancelled by operator. No changes made.\n'
      exit 0
      ;;
    *)
      echo "Unknown existing-install choice: ${choice}" >&2
      return 1
      ;;
  esac
}

handle_existing_install() {
  # Server installs keep the single-call behavior. Client installs use the
  # split resolve/apply functions around their remote-input preflight.
  local role="$1"
  local current_config_dir="$2"
  local choice=""

  choice="$(resolve_existing_install_choice "${role}" "${current_config_dir}")" || return $?
  apply_existing_install_choice "${role}" "${choice}" || return $?
}

install_server_role() {
  local prefix="${PREFIX:-$(default_prefix)}"
  local config_root="${CONFIG_DIR:-$(default_server_config_dir)}"
  local state_dir="${STATE_DIR:-$(default_server_state_dir)}"
  local bin_dir="${prefix}/bin"
  local bin_path="${bin_dir}/aegis-server"
  local cert_dir="${config_root}/certs"
  local config_path="${config_root}/aegis-server.toml"
  local relay_host
  local ca_cert_path
  local service_user
  local service_group
  local detected_bundle_host
  local chosen_bundle_endpoint
  local chosen_bundle_server_name
  local install_manifest_path

  SYSTEMD_DIR="${SYSTEMD_DIR:-$(default_systemd_dir)}"
  ENV_DIR="${ENV_DIR:-$(default_env_dir)}"

  # Resolve cancellation before any source build/private read. Every admitted
  # server install needs the renderer's protocol, including generated/reused
  # credentials; refuse old releases before destructive existing-install apply.
  local existing_choice reader
  existing_choice="$(resolve_existing_install_choice "server" "${config_root}")" || return $?
  if [[ "$existing_choice" == cancel ]]; then
    apply_existing_install_choice "server" "$existing_choice" || return $?
    return 0
  fi
  # Refuse a known service-asset conflict before source build/private input
  # or installed binary/manifest writes. Explicit reinstall retains its
  # existing purge-before-FORCE path. The late writer checks remain defensive.
  if [[ "${FORCE}" -eq 0 && "$existing_choice" != reinstall &&
        -n "${SYSTEMD_DIR}" && -n "${ENV_DIR}" ]]; then
    local service_asset
    for service_asset in "${ENV_DIR}/aegis-server" "${SYSTEMD_DIR}/aegis-server.service"; do
      if [[ -e "$service_asset" || -L "$service_asset" ]]; then
        echo "Refusing to overwrite existing file without --force: ${service_asset}" >&2
        return 1
      fi
    done
  fi
  install_binary "aegis-server" "aegis-server" "$bin_dir" preflight || return $?
  reader="$ROOT/bin/aegis-server"
  [[ "$SOURCE_LAYOUT" != 1 ]] || reader="$TARGET_DIR/release/aegis-server"
  [[ "$("$reader" installer-secret version)" == installer-secret-v1 ]] || {
    echo "Selected release lacks the private installer input protocol." >&2; return 2;
  }
  if [[ -n "$AUTH_TOKEN_FILE" ]]; then
    AUTH_TOKEN="$("$reader" installer-secret read-token --path "$AUTH_TOKEN_FILE")" || return $?
  fi
  apply_existing_install_choice "server" "$existing_choice" || return $?

  if [[ -f "${config_path}" && -z "${AUTH_TOKEN}" && "${FORCE}" -eq 0 ]]; then
    AUTH_TOKEN="$(extract_toml_string "${config_path}" "auth_token")"
  fi
  if [[ -z "${RELAY_ADDRESS}" ]]; then
    detected_bundle_host="${SERVER_NAME:-$(detected_host)}"
    # Phase 5.0.A fix: pass the install-time --listen port into endpoint
    # selection so the bundle's advertised relay address agrees with what
    # the server actually binds. If --listen was not explicit, this still
    # resolves to the canonical 8443 default; if --listen was explicit
    # (e.g. :443) the bundle will publish that port instead.
    local listen_port_for_bundle
    listen_port_for_bundle="$(port_from_address "${LISTEN_ADDR}" "8443")"
    local endpoint_output
    endpoint_output="$(choose_bundle_relay_endpoint "${detected_bundle_host}" "${SERVER_NAME}" "${listen_port_for_bundle}")"
    chosen_bundle_endpoint=()
    while IFS= read -r endpoint_line; do
      chosen_bundle_endpoint+=("${endpoint_line}")
    done <<EOF
${endpoint_output}
EOF
    RELAY_ADDRESS="${chosen_bundle_endpoint[0]}"
    chosen_bundle_server_name="${chosen_bundle_endpoint[1]}"
    if [[ -z "${SERVER_NAME}" ]]; then
      SERVER_NAME="${chosen_bundle_server_name}"
    fi
  fi
  if [[ -z "${SERVER_NAME}" ]]; then
    SERVER_NAME="$(host_from_address "${RELAY_ADDRESS}")"
  fi
  if [[ "${LISTEN_ADDR_EXPLICIT}" -eq 0 ]]; then
    LISTEN_ADDR="0.0.0.0:$(port_from_address "${RELAY_ADDRESS}" "8443")"
  fi
  if [[ -z "${AUTH_TOKEN}" ]]; then
    AUTH_TOKEN="$(random_token)"
  fi
  if [[ -z "${BUNDLE_OUT}" ]]; then
    BUNDLE_OUT="${config_root}/client-bundle"
  fi
  if [[ -z "${BUNDLE_ARCHIVE_OUT}" ]]; then
    BUNDLE_ARCHIVE_OUT="${BUNDLE_OUT}.tar.gz"
  fi

  relay_host="$(host_from_address "${RELAY_ADDRESS}")"
  if [[ ${EUID} -eq 0 ]]; then
    service_user="aegis"
    service_group="aegis"
  else
    service_user="$(current_user_name)"
    service_group="$(current_group_name)"
  fi

  install_manifest_path="$(install_manifest_path_for_role server "${state_dir}")"
  install_atomic_write "${install_manifest_path}" 0644 strict validate </dev/null
  install_binary "aegis-server" "aegis-server" "${bin_dir}"
  ensure_dir "${config_root}"
  ensure_dir "${cert_dir}"
  ensure_dir "${state_dir}"
  ensure_server_service_account "${state_dir}"
  write_install_manifest server "${install_manifest_path}" "${bin_path}"
  cleanup_stale_client_redirect_helper

  if [[ "${FORCE}" -eq 1 || ! -f "${cert_dir}/server.pem" || ! -f "${cert_dir}/server-key.pem" || ! -f "${cert_dir}/ca.pem" ]]; then
    require_runtime_dependency "openssl" "server role generates relay certificates and auth materials"
    "${ROOT}/scripts/generate-relay-materials.sh" "${cert_dir}" "${SERVER_NAME}" "${relay_host}"
  fi

  if [[ "${FORCE}" -eq 1 || ! -f "${config_path}" ]]; then
    write_server_config \
      "${config_path}" \
      "${cert_dir}/server.pem" \
      "${cert_dir}/server-key.pem" \
      "${AUTH_TOKEN}" \
      "${LISTEN_ADDR}"
  fi

  secure_server_materials "${config_root}" "${cert_dir}" "${config_path}" "${service_group}"

  ca_cert_path="${cert_dir}/ca.pem"
  if [[ "${FORCE}" -eq 1 && -e "${BUNDLE_OUT}" ]]; then
    rm -rf "${BUNDLE_OUT}"
  fi
  printf '%s' "$AUTH_TOKEN" | "${ROOT}/scripts/render-client-bundle.sh" \
    "${BUNDLE_OUT}" \
    "${RELAY_ADDRESS}" \
    "${SERVER_NAME}" \
    --auth-token-stdin \
    "${ca_cert_path}" \
    "$bin_path" \
    "${RELAY_ENDPOINTS}" \
    "${RELAY_TRANSPORT_PRIORITY}"
  "${ROOT}/scripts/package-client-bundle.sh" "${BUNDLE_OUT}" "${BUNDLE_ARCHIVE_OUT}"
  secure_server_bundle_archive "${BUNDLE_ARCHIVE_OUT}" "${service_user}" "${service_group}"

  chmod 600 "${BUNDLE_OUT}/aegis-client.toml" "${BUNDLE_OUT}/aegis-client-privileged-dns.toml" "${BUNDLE_OUT}/README.txt"
  install_server_service_assets "${bin_path}" "${config_path}" "${state_dir}" "${service_user}" "${service_group}"
  activate_systemd_unit "aegis-server.service"

  # Give the just-activated server a moment to bind 8443 before issuing
  # the first /bundle token (the issue subcommand only writes to the
  # token store, but the operator-facing curl one-liner is only useful
  # once the listener is up).
  if [[ "${AUTO_ISSUE_TOKEN}" -eq 1 ]] && systemctl is-active --quiet aegis-server.service 2>/dev/null; then
    sleep 2
  fi
  auto_issue_first_bundle_token "${bin_path}" "${config_path}" "${BUNDLE_ARCHIVE_OUT}" "${RELAY_ADDRESS}" "${cert_dir}"

  cat <<EOF

AEGIS server installed
----------------------
Binary:
  ${bin_path}

Server config:
  ${config_path}

Server state dir:
  ${state_dir}

Install manifest:
  ${install_manifest_path}

Generated relay materials:
  ${cert_dir}/server.pem
  ${cert_dir}/server-key.pem
  ${cert_dir}/ca.pem

Generated client bundle:
  ${BUNDLE_OUT}

Generated client bundle archive:
  ${BUNDLE_ARCHIVE_OUT}

Server status:
  sudo systemctl status --no-pager aegis-server.service
  sudo journalctl -u aegis-server.service -n 50 --no-pager

Manual handoff (legacy path, see "CLIENT ONBOARDING" below for one-liner):
  Transfer ${BUNDLE_ARCHIVE_OUT} to the client host over a trusted channel:
    ./install.sh client --bundle /path/to/client-bundle
    ./install.sh client --bundle-url-file /absolute/owner-private/client-access-url.txt

HTTPS /bundle endpoint:
  Auto-enabled in this server config (${config_path}, [bundle_endpoint] enabled = true).
  install.sh issued the first one-time token above (look for the
  CLIENT ONBOARDING block). Rotate / audit any time:
    sudo -u aegis ${bin_path} --config ${config_path} bundle-token issue --bundle-path ${BUNDLE_ARCHIVE_OUT} --url-output ${state_dir}/client-access-url-NEW.txt
    sudo -u aegis ${bin_path} --config ${config_path} bundle-token list
    sudo -u aegis ${bin_path} --config ${config_path} bundle-token prune
  Disable auto-issue at install time with --no-auto-token; disable
  service auto-start with --no-auto-start.

Short operator checks:
  sudo journalctl -u aegis-server.service -n 20 --no-pager
  ${bin_path} --config ${config_path}

Upgrade/reapply discipline:
  - do not treat a repeated installer run as release validation
  - before --force, save the current server config diff and generated materials metadata
  - after reapply on Ubuntu, rerun:
      ./scripts/validate-debian-package-host.sh --run
EOF
  print_systemd_followup "aegis-server.service"
}

# Prepare a device identity before any install/config/service mutation. Only
# public data enters the render staging tree; the private key stays in its final
# separate directory through completion, retries and ordinary configuration backup.
device_absolute_path() {
  local path="$1" suffix="" leaf
  [[ "${path}" == /* && "${path}/" != *'/../'* && "${path}/" != *'/./'* ]] || return 1
  path="${path%/}"
  [[ -n "${path}" ]] || path=/
  while [[ ! -d "${path}" ]]; do
    leaf="$(basename "${path}")"
    suffix="/${leaf}${suffix}"
    path="$(dirname "${path}")"
  done
  path="$(cd "${path}" && pwd -P)" || return 1
  printf '%s%s' "${path%/}" "${suffix}"
}

device_service_identity_path() {
  case "$1" in
    /root|/root/*|/home|/home/*|/run|/run/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/private/tmp|/private/tmp/*|/private/var/tmp|/private/var/tmp/*|/dev|/dev/*|/proc|/proc/*|/sys|/sys/*)
      echo "Device identity/config directory is hidden from the protected service or is not persistent; use the default managed paths." >&2
      return 1 ;;
  esac
}

resolve_device_bundle_policy() {
  local public_bundle="$1" policy expected_operator
  policy="$("${PREFLIGHT_CLIENT_BINARY}" device bundle-inspect --bundle-dir "$public_bundle" --json)" || return 1
  DEVICE_PRODUCT_MODE="$(printf '%s' "$policy" | python3 -I -c '
import json,sys
p=json.load(sys.stdin);r=p["resolved"];mode=p["product_mode"]
assert mode in ("socks-only","full-wide-tun") and r["product_mode"]==mode
assert r["inner_tls"] is True and r["native_fallback"] is False
assert r["tcp_transport"]=="grpc_stream"
if mode=="full-wide-tun":
    assert p["schema"] in ("aegis_device_bundle_v2","aegis_device_bundle_v3","aegis_device_bundle_v4") and p["udp"] is True
    assert r["udp_transport"]=="grpc_datagram" and r["capture_scope"]=="local_host"
    assert r["dns_policy"]=="preview" and r["ipv6_policy"]=="tun_carried"
print(mode)
')" || return 1
  DEVICE_BUNDLE_SCHEMA="$(printf '%s' "$policy" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["schema"])')" || return 1
  DEVICE_ONLINE=0
  if [[ "$DEVICE_BUNDLE_SCHEMA" == aegis_device_bundle_v3 || "$DEVICE_BUNDLE_SCHEMA" == aegis_device_bundle_v4 ]]; then
    [[ -z "${DEVICE_CERTIFICATE:-}" ]] || { echo 'Online enrollment uses its authenticated protocol; --device-certificate conflicts.' >&2; return 1; }
    DEVICE_ONLINE=1
  else
    [[ -z "${DEVICE_INVITATION_FILE:-}" ]] || { echo 'An online invitation requires a v3/v4 device profile.' >&2; return 1; }
  fi
  expected_operator=client-socks
  [[ "$DEVICE_PRODUCT_MODE" != full-wide-tun ]] || expected_operator=client-ipv6-tun-smoltcp
  if [[ -n "${PRODUCT_MODE}" && "${PRODUCT_MODE}" != auto && "${PRODUCT_MODE}" != "$DEVICE_PRODUCT_MODE" ]] ||
     [[ -n "${OPERATOR_MODE}" && "${OPERATOR_MODE}" != "$expected_operator" ]] ||
     [[ -n "${MASQUE_SERVER}${MASQUE_CA}${GENEVA_STRATEGY_FILE}${OPERATOR_TRANSPORT}${FRONTED_AUTHORITY}${AUTH_TOKEN:-}${RELAY_ADDRESS:-}${SERVER_NAME:-}${RELAY_ENDPOINTS:-}" || "${RELAY_TRANSPORT_PRIORITY_EXPLICIT:-0}" == 1 ]]; then
    echo 'Device public profile conflicts with explicit mode or transport options; nothing was installed.' >&2
    return 1
  fi
  if [[ "$DEVICE_PRODUCT_MODE" == socks-only ]]; then
    [[ -z "${WIDE_UDP_POLICY}${WIDE_DNS_POLICY}${WIDE_IPV6_POLICY}" && "${UDP_CARRY}" == 0 ]] || {
      echo 'SOCKS device profile does not accept wide policy overrides.' >&2; return 1;
    }
  else
    [[ -z "${WIDE_UDP_POLICY}" || "${WIDE_UDP_POLICY}" == masque_direct ]] &&
    [[ -z "${WIDE_DNS_POLICY}" || "${WIDE_DNS_POLICY}" == preview ]] &&
    [[ -z "${WIDE_IPV6_POLICY}" || "${WIDE_IPV6_POLICY}" == tun_carried ]] || {
      echo 'Full-wide device policy is fixed by its public profile; conflicting overrides were refused.' >&2; return 1;
    }
    UDP_CARRY=1
  fi
  DEVICE_PUBLIC_BUNDLE="$public_bundle"
  PRODUCT_MODE="$DEVICE_PRODUCT_MODE"
  OPERATOR_MODE="$expected_operator"
  # The legacy auto planner requires shared-token profiles. A device profile
  # instead uses its authenticated public mode and the dedicated host assessor.
  AUTO_PROFILE=0
}

prepare_device_bundle() {
  local config_root="$1" state_dir="$2" public_bundle="${BUNDLE_PATH}"
  local stage="" identity="${DEVICE_IDENTITY_DIR:-/var/lib/aegis-identity/client}" existing_choice="${3:-}"
  DEVICE_INSTALL_READY=0
  [[ ${EUID} -eq 0 ]] || { echo "Device service installation requires root." >&2; return 1; }
  [[ -n "${DEVICE_ID}" ]] || { echo "A public device bundle requires --device-id." >&2; return 1; }
  identity="$(device_absolute_path "${identity}")" || return 1
  if [[ "${AUTO_DEVICE_V2_REQUESTED:-0}" == 1 &&
        "$identity" != /var/lib/aegis-identity/client ]]; then
    echo 'Automatic device V2 requires the separate managed identity directory.' >&2
    return 1
  fi
  device_service_identity_path "${identity}" || return 1
  config_root="$(device_absolute_path "${config_root}")" || return 1
  device_service_identity_path "${config_root}" || return 1
  state_dir="$(device_absolute_path "${state_dir}")" || return 1
  if [[ "${identity}" != /* || "${identity}" == / || "${identity}/" == *'/../'* || "${identity}/" == *'/./'* ]]; then
    echo "Device identity requires a clean absolute directory." >&2
    return 1
  fi
  local excluded
  for excluded in "${config_root}" "${state_dir}" "${public_bundle}"; do
    if [[ "${identity}" == "${excluded}" || "${identity}" == "${excluded}/"* || "${excluded}" == "${identity}/"* ]]; then
      echo "Device identity must be separate from config, runtime state and bundle directories." >&2
      return 1
    fi
  done
  if [[ "${BUNDLE_INSECURE}" == 1 ]]; then
    echo "Public enrollment trust cannot be acquired using --insecure." >&2
    return 1
  fi
  resolve_device_bundle_policy "$public_bundle" || return 1
  if [[ "${AUTO_DEVICE_V2_REQUESTED:-0}" == 1 &&
        ( "$DEVICE_PRODUCT_MODE" != full-wide-tun || "$DEVICE_BUNDLE_SCHEMA" != aegis_device_bundle_v2 || "$DEVICE_ONLINE" != 0 ) ]]; then
    echo 'Automatic device installation requires an offline v2 full-wide profile; other device modes use an explicit profile.' >&2
    return 1
  fi
  if [[ "${AUTO_DEVICE_V2_REQUESTED:-0}" == 1 &&
        -n "${DEVICE_RELAY_GENEVA_REQUEST:-}${DEVICE_RELAY_GENEVA_MANIFEST:-}" ]]; then
    echo 'Automatic device V2 does not admit the separate relay Geneva selection.' >&2
    return 1
  fi
  [[ "$DEVICE_PRODUCT_MODE" != full-wide-tun ]] || device_relay_geneva_absent || return 1
  device_relay_geneva_preflight "$public_bundle" "$identity" "$config_root" "$state_dir" || return 1
  if [[ "${DEVICE_ONLINE:-0}" == 1 ]]; then
    [[ "$(detect_os_kind)" == linux && "$config_root" == /etc/aegis/client && "$state_dir" == /var/lib/aegis-client &&
       "${PREFIX:-/usr/local}" == /usr/local && "$SYSTEMD_DIR" == /etc/systemd/system && "$ENV_DIR" == /etc/default ]] || {
      echo 'Installed online renewal requires the standard Linux systemd paths.' >&2; return 1;
    }
    [[ "$existing_choice" == reinstall || "${FORCE:-0}" == 1 || ( ! -e "$config_root/aegis.toml" && ! -e "$config_root/ca.pem" ) ]] || {
      echo 'Existing online device configuration requires --force or --reinstall before any enrollment request.' >&2; return 1;
    }
    device_online_identity_path "$identity" || return 1
    device_preflight_online_public_bundle "$public_bundle" || return 1
    if [[ "$DEVICE_PRODUCT_MODE" == full-wide-tun ]]; then
      # Refuse unsupported boot/manager/ownership before creating a device key
      # or redeeming a one-use invitation. The arm path reassesses again.
      device_assess_full_wide_host "$public_bundle" "$PREFLIGHT_CLIENT_BINARY" >/dev/null || return 1
    fi
  fi
  local identity_phase='' guard_record
  if [[ "${DEVICE_ONLINE:-0}" == 1 && ( -e "$identity/bundle-profile.sha256" || -L "$identity/bundle-profile.sha256" ) ]]; then
    # A saved, verified online response may need local repair before legacy
    # ready validation. This bound API creates no key, pin, request or network.
    identity_phase="$(device_recover_online_local "$identity" "$public_bundle")" || return 1
  else
    "${PREFLIGHT_CLIENT_BINARY}" device prepare --device-id "${DEVICE_ID}" --identity-dir "${identity}" --device-ca "${public_bundle}/device-ca.pem" >/dev/null || return 1
    "${PREFLIGHT_CLIENT_BINARY}" device bundle-inspect --bundle-dir "${public_bundle}" --identity-dir "${identity}" || return 1
    if [[ "${DEVICE_ONLINE:-0}" == 1 ]]; then
      identity_phase="$(device_recover_online_local "$identity" "$public_bundle")" || return 1
    fi
  fi
  DEVICE_IDENTITY_DIR="${identity}"
  if [[ "${DEVICE_ONLINE:-0}" == 1 ]]; then
    if [[ "$identity_phase" == prepared ]]; then
      # An armed installation never performs enrollment from the unbound shell.
      # Runtime recovery of an already enrolled identity belongs to the client.
      if [[ -e /var/lib/aegis-install/client/device-guard.conf ]]; then
        guard_record="$("${PREFLIGHT_CLIENT_BINARY}" profile metadata read --path /var/lib/aegis-install/client/device-guard.conf)" || return 1
        if [[ "$guard_record" == *$'\narmed=1\n'* || "$guard_record" == *$'\narmed=1' ]]; then
          echo 'Prepared enrollment cannot run from an installer while the prior device guard is armed. Resume the existing enrolled client, or explicitly recover that installation before enrolling a new identity.' >&2; return 1
        fi
      fi
      local -a redeem_args=(device redeem --identity-dir "$identity" --bundle-dir "$public_bundle")
      [[ -z "${DEVICE_INVITATION_FILE:-}" ]] || redeem_args+=(--invitation-file "$DEVICE_INVITATION_FILE")
      "${PREFLIGHT_CLIENT_BINARY}" "${redeem_args[@]}" || return 1
      identity_phase="$(device_recover_online_local "$identity" "$public_bundle")" || return 1
      [[ "$identity_phase" == ready ]] || { echo 'Initial enrollment did not complete local identity preparation.' >&2; return 1; }
    fi
    # A validated expired predecessor with its saved Renew request is allowed
    # only through managed runtime receipt recovery, never shell enrollment.
    # Neither local phase is a live fleet-policy ACK or a readiness assertion.
    [[ "$identity_phase" == ready || "$identity_phase" == runtime_recovery_required ]] || return 1
  else
  if [[ -z "${DEVICE_CERTIFICATE}" ]]; then
    "${PREFLIGHT_CLIENT_BINARY}" device status --identity-dir "${identity}" --json || return 1
    printf 'Device prepared. Send only the CSR at %s/device.csr to your operator.\n' "${identity}"
    printf 'After receiving the public certificate, rerun these installation options with --device-certificate <path>.\n'
    printf 'Installation is pending; this run has not changed the installed service or networking.\n'
    return 0
  fi
  "${PREFLIGHT_CLIENT_BINARY}" device complete --identity-dir "${identity}" --certificate "${DEVICE_CERTIFICATE}" --device-ca "${public_bundle}/device-ca.pem" || return 1
  fi
  DEVICE_INSTALL_READY=1
  # Full-wide retains the real public bundle and enters its own transaction.
  # Never disguise it as a legacy access bundle or force its ingress to SOCKS.
  [[ "$DEVICE_PRODUCT_MODE" != full-wide-tun ]] || return 0
  stage="$(mktemp -d "${identity}/.install-render.XXXXXXXX")" || return 1
  TEMP_PATHS+=("${stage}")
  device_bundle_render "${PREFLIGHT_CLIENT_BINARY}" --bundle-dir "${public_bundle}" --identity-dir "${identity}" --config-dir "${config_root}" --output "${stage}/aegis-client.toml" || return 1
  install -m 0600 "${public_bundle}/outer-ca.pem" "${stage}/ca.pem" || return 1
  install -m 0600 "${public_bundle}/inner-ca.pem" "${stage}/inner-ca.pem" || return 1
  if [[ "${DEVICE_ONLINE:-0}" == 1 ]]; then
    # The SOCKS reinstall path may remove the old /etc public bundle. Preserve
    # only its four public members beside the already retained render, outside
    # config/runtime purge roots and without copying the identity private key.
    local file
    for file in bundle.json outer-ca.pem inner-ca.pem device-ca.pem; do
      cat "$public_bundle/$file" | install_atomic_write "$stage/public-profile/$file" 0600 strict || return 1
    done
    "${PREFLIGHT_CLIENT_BINARY}" device bundle-inspect --bundle-dir "$stage/public-profile" --identity-dir "$identity" --json >/dev/null || return 1
    DEVICE_PUBLIC_BUNDLE="$stage/public-profile"
  fi
  BUNDLE_PATH="${stage}"
}

# Read the actual boot archive without extracting files (in particular, never
# duplicate embedded recovery keys). Unknown boot/config scripts are refused.
device_verify_initramfs_image() {
  device_verify_initramfs "$@"
}
device_verify_initramfs() {
  python3 -I - "${1:-}" "${2:-}" "${ROOT}/scripts/lib" <<'PY'
import hashlib,io,json,os,pathlib,posixpath,re,shlex,signal,stat,struct,subprocess,sys,time

def need(ok, message):
    if not ok: raise SystemExit('Device boot assessment: '+message)
def expired(*_): raise TimeoutError('Device boot assessment exceeded 45 seconds')
signal.signal(signal.SIGALRM,expired);signal.alarm(45)
assessment_start=time.monotonic()
def trusted(path):
    path=pathlib.Path(path).resolve(strict=True)
    for item in (path,*path.parents):
        s=item.stat();need(s.st_uid==0 and not s.st_mode&0o022,'untrusted boot input '+str(item))
    return path
CLOUD_INDICATORS = (
    '/usr/bin/cloud-init', '/bin/cloud-init', '/usr/local/bin/cloud-init',
    '/usr/lib/systemd/system/cloud-init-main.service',
    '/usr/lib/systemd/system/cloud-init-local.service',
    '/usr/lib/systemd/system/cloud-init-network.service',
    '/usr/lib/systemd/system/cloud-init.service',
    '/usr/lib/systemd/system/cloud-config.service',
    '/usr/lib/systemd/system/cloud-final.service',
    '/usr/lib/systemd/system/cloud-init-hotplugd.service',
    '/usr/lib/systemd/system/cloud-init-hotplugd.socket',
    '/usr/lib/systemd/system/cloud-init.target',
    '/usr/lib/systemd/system/cloud-config.target',
    '/lib/systemd/system/cloud-init-local.service',
    '/lib/systemd/system/cloud-init-network.service',
    '/etc/systemd/system/cloud-init-local.service',
    '/etc/systemd/system/cloud-init-network.service',
    '/usr/lib/systemd/system-generators/cloud-init-generator',
    '/lib/systemd/system-generators/cloud-init-generator',
)
CLOUD_UNIT_DIRS = (
    '/etc/systemd/system.control', '/run/systemd/system.control',
    '/run/systemd/transient', '/run/systemd/generator.early', '/etc/systemd/system',
    '/run/systemd/system', '/run/systemd/generator', '/usr/local/lib/systemd/system',
    '/usr/lib/systemd/system', '/lib/systemd/system', '/run/systemd/generator.late',
)
CLOUD_GENERATOR_DIRS = (
    '/run/systemd/system-generators', '/etc/systemd/system-generators',
    '/usr/local/lib/systemd/system-generators', '/usr/lib/systemd/system-generators',
    '/lib/systemd/system-generators',
)
CLOUD_UNIT_PREFIXES = ('cloud-init', 'cloud-config', 'cloud-final')
CLOUD_UNIT_PATTERNS = ('cloud-init*', 'cloud-config*', 'cloud-final*')
def cloud_refusal(error):
    print(json.dumps({
        'schema':'aegis_install_refusal_v1',
        'code':'cloud_init_early_network_unverified',
        'action':'use_reviewed_local_boot_image',
        'message':'Trusted cloud-init inspector unavailable. Use a verified full installer bundle or a reviewed local-root image without cloud-init.',
    },sort_keys=True,separators=(',',':')),file=sys.stderr)
    raise SystemExit(78)
cloud_state='absent'
try:
    module_root=trusted(sys.argv[3])
    trusted(module_root/'aegis_initrd_policy.py')
    trusted(module_root/'aegis_auto_foreign_policy.py')
except (OSError,RuntimeError,SystemExit):
    # Public v3/non-AUTO layouts may omit AUTO inspectors on a no-cloud host.
    # Their absence cannot prove or admit the disabled-marker cloud profile.
    for indicator in CLOUD_INDICATORS:
        try: os.lstat(indicator)
        except FileNotFoundError: continue
        except OSError: cloud_refusal('cloud-init indicator cannot be read')
        cloud_refusal('trusted cloud-init inspector unavailable')
    # A missing binary alone is not absence: units/generators can live in any
    # systemd search path or remain loaded in PID1 after a fragment is removed.
    try:
        for directory in CLOUD_UNIT_DIRS + CLOUD_GENERATOR_DIRS:
            try: entries=os.listdir(directory)
            except FileNotFoundError: continue
            if len(entries)>65536: cloud_refusal('cloud-init search path bound')
            if any(entry.startswith(CLOUD_UNIT_PREFIXES) and not entry.endswith(
                    ('.wants','.requires','.upholds')) for entry in entries):
                cloud_refusal('cloud-init unit or generator present')
        result=subprocess.run(['systemctl','list-units','--all','--no-legend',
            '--no-pager','--plain',*CLOUD_UNIT_PATTERNS],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        if result.returncode or len(result.stdout)>1<<20 or len(result.stderr)>4096:
            cloud_refusal('cloud-init PID1 absence unavailable')
        rows=result.stdout.decode('utf-8','strict').splitlines()
        if len(rows)>4096: cloud_refusal('cloud-init PID1 unit bound')
        for row in rows:
            tokens=row.split()
            if tokens and tokens[0] in ('\u25cf','*'): tokens=tokens[1:]
            if not tokens or len(tokens)>1 and tokens[1]=='not-found': continue
            cloud_refusal('cloud-init PID1 unit present')
    except (OSError,ValueError,subprocess.SubprocessError):
        cloud_refusal('cloud-init absence cannot be inspected')
else:
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(module_root))
    try:
        from aegis_initrd_policy import verify_cloud_init_boot,CloudInitRefusal,cloud_init_refusal_json,journal_cloud_init_refusal
    except ImportError:
        cloud_refusal('trusted cloud-init inspector unavailable')
    try:
        cloud_state=verify_cloud_init_boot({})
    except CloudInitRefusal as error:
        journal_cloud_init_refusal(error)
        print(cloud_init_refusal_json(error),file=sys.stderr)
        raise SystemExit(78)
need(not pathlib.Path('/sys/firmware/ibft').exists(),'firmware iSCSI boot table requires separate review')
kernel=sys.argv[1] if len(sys.argv)>1 and sys.argv[1] else os.uname().release
need(re.fullmatch(r'[A-Za-z0-9_.+-]+',kernel),'unsupported kernel name')
debian_image=pathlib.Path('/boot/initrd.img-'+kernel)
rpm_image=pathlib.Path('/boot/initramfs-'+kernel+'.img')
need(not (debian_image.exists() and rpm_image.exists()),'ambiguous initramfs family')
is_dracut=not debian_image.exists()
image=trusted(sys.argv[2] if len(sys.argv)>2 and sys.argv[2] else rpm_image if is_dracut else debian_image)
need(image.stat().st_size<=256*1024*1024,'boot archive exceeds assessment bound')
cmdline=pathlib.Path('/proc/cmdline').read_text().split()
for token in cmdline:
    key,_,value=token.partition('=')
    need(key not in ('ip','ip6','nfsroot','BOOTIF','BOOTIF_DEFAULT','vlan','rd.neednet','rd.iscsi.initiator','ISCSI_AUTO','ISCSI_INITIATOR','iscsi','fetch','url','overlayroot') and not key.startswith(('rd.net.','rd.iscsi.','iscsi_')),'network/custom early boot option')
    if key=='boot': need(value=='local','non-local boot')
    if key=='rootfstype': need(value in ('ext2','ext3','ext4','xfs','btrfs','f2fs'),'non-local root filesystem')
    if key=='init': need(value in ('/sbin/init','/lib/systemd/systemd','/usr/lib/systemd/systemd'),'custom init')
    if key=='root': need(value.startswith(('UUID=','LABEL=','PARTUUID=','/dev/')) and value!='/dev/nfs','non-local root')
need(any(x.startswith('root=') for x in cmdline),'root device is not explicit')
for alias in (() if is_dracut or len(sys.argv)>2 and sys.argv[2] else ('/initrd.img','/boot/initrd.img')):
    if pathlib.Path(alias).exists():
        selected=pathlib.Path(alias).resolve(strict=True)
        if selected!=image:
            # A package-selected initrd for a different installed kernel is a
            # temporary, typed refusal. Do not assess it as the running boot.
            next_kernel=re.fullmatch(r'initrd\.img-([A-Za-z0-9_.+-]+)',selected.name)
            if selected.parent==image.parent and next_kernel and next_kernel.group(1)!=kernel and selected.is_file():
                trusted(alias)
                print(json.dumps({'schema':'aegis_install_refusal_v1',
                    'code':'reboot_required_kernel_changed','action':'reboot_computer',
                    'message':'A newer kernel is selected for the next boot. Reboot the computer, then retry installation.'},
                    sort_keys=True,separators=(',',':')),file=sys.stderr)
                raise SystemExit(75)
            need(False,'default initrd differs from running kernel')
# An owned Debian profile has its own complete streamed archive/provenance
# verifier. Enter it before the legacy format-discovery reader allocates bodies
# or spends a second decompression pass. The owner file only selects a verifier;
# the nonce, changed boot, source, module and activation checks still authorize.
if not is_dracut and pathlib.Path('/var/lib/aegis-install/boot-backup/manifest.json').exists():
    need(len(sys.argv)>3,'strict Debian dracut verifier unavailable')
    module_root=trusted(sys.argv[3]);sys.path.insert(0,str(module_root))
    from aegis_initrd_policy import verify_profile, assessment_seconds, MANIFEST, trusted_read, decode, owner_profile
    owner=decode(trusted_read(MANIFEST))
    if owner.get('phase') not in ('removed','rolled_back'):
        seconds=assessment_seconds(image)
        signal.setitimer(signal.ITIMER_REAL,max(0.000001,seconds-(time.monotonic()-assessment_start)))
        result=verify_profile(kernel,image,boot=not (len(sys.argv)>2 and sys.argv[2]),profile=owner_profile(owner))
        print(json.dumps({k:result[k] for k in ('initramfs_network','initrd_sha256','kernel','checked_policy_files','boot_profile','network_manager')}))
        sys.exit(0)
if cloud_state=='disabled_proved':
    # Only the complete owned-image branch above can prove a recurring
    # switch-root barrier. Inactive/removed or absent owners cannot borrow the
    # legacy stock-image classifier's install-time-only cloud proof.
    from aegis_initrd_policy import CLOUD_INIT_SWITCH_ROOT
    error=CloudInitRefusal(CLOUD_INIT_SWITCH_ROOT,'disabled_profile_requires_owned_networkless_normal_boot')
    journal_cloud_init_refusal(error)
    print(cloud_init_refusal_json(error),file=sys.stderr)
    raise SystemExit(78)
# Package metadata is an integrity baseline from the root administrator, not a
# remote signature assertion. Only the known local-boot hook families qualify.
if not is_dracut:
    allowed_packages={'initramfs-tools-core','udev','kmod','busybox-initramfs','klibc-utils','cloud-initramfs-dyn-netconf','cloud-initramfs-copymods','cloud-initramfs-growroot','overlayroot','lvm2','dmsetup','sg3-utils-udev','kpartx','multipath-tools','bcache-tools','e2fsprogs','xfsprogs','mdadm','cryptsetup-initramfs','cryptsetup','console-setup-linux','console-setup','keyboard-configuration','plymouth','btrfs-progs','ntfs-3g','open-iscsi','systemd','finalrd'}
    packaged={}
    for name in allowed_packages:
        matches=list(pathlib.Path('/var/lib/dpkg/info').glob(name+'.md5sums'))+list(pathlib.Path('/var/lib/dpkg/info').glob(name+':*.md5sums'))
        for metadata in matches:
            for line in trusted(metadata).read_text().splitlines():
                digest,sep,path=line.partition('  ')
                if sep and re.fullmatch('[0-9a-f]{32}',digest): packaged['/'+path]=digest
    # dpkg keeps administrator configuration baselines separately from md5sums.
    # Read that metadata as data; never execute an embedded module action to test it.
    status=pathlib.Path('/var/lib/dpkg/status')
    if status.exists():
        for paragraph in trusted(status).read_text().split('\n\n'):
            package=re.search(r'(?m)^Package: (.+)$',paragraph)
            if not package or package[1] not in allowed_packages: continue
            conffiles=re.search(r'(?m)^Conffiles:\n((?: .*(?:\n|$))*)',paragraph)
            if conffiles:
                for line in conffiles[1].splitlines():
                    fields=line.split()
                    if len(fields)>=2 and fields[0].startswith('/') and re.fullmatch('[0-9a-f]{32}',fields[1]): packaged[fields[0]]=fields[1]
selected={};total=0;dracut_entries={};debian_dracut={};linked_policy=[]

def elf_identity(data):
    if data[:6]!=b'\x7fELF\x02\x01': return None
    need(len(data)>=64,'truncated ELF header')
    fields=struct.unpack_from('<HHIQQQIHHHHHH',data,16)
    typ,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,_,_,_=fields
    if typ!=3: return None
    need(version==1 and ehsize==64 and phsize==56 and 0<phnum<=128 and phoff+phsize*phnum<=len(data),'unsupported ELF program headers')
    loads=[];dynamic=None;os_abi=None
    for i in range(phnum):
        kind,_,off,addr,_,size,_,alignment=struct.unpack_from('<IIQQQQQQ',data,phoff+i*phsize)
        need(off+size<=len(data),'ELF segment outside file')
        if kind==1: loads.append((addr,off,size))
        if kind==4:
            need(size<=65536 and alignment in (4,8),'ELF note segment bound or alignment');pos=off
            while pos<off+size:
                need(pos+12<=off+size,'truncated ELF note header')
                note_start=pos;namesz,descsz,note_type=struct.unpack_from('<III',data,pos);pos+=12
                name_end=pos+namesz;descriptor=note_start+((12+namesz+alignment-1)&~(alignment-1));end=descriptor+descsz;next_note=note_start+((end-note_start+alignment-1)&~(alignment-1))
                need(name_end<=off+size and next_note<=off+size,'truncated ELF note body')
                if data[pos:name_end]==b'GNU\0' and note_type==1:
                    need(namesz==4 and descsz==16 and os_abi is None,'duplicate or invalid ELF GNU ABI tag')
                    system,major,minor,patch=struct.unpack_from('<IIII',data,descriptor)
                    need(system==0 and max(major,minor,patch)<=255,'unreviewed ELF OS ABI requirement')
                    os_abi=(major<<16)|(minor<<8)|patch
                pos=next_note
        if kind==2:
            need(dynamic is None and size<=65536 and size%16==0,'ambiguous ELF dynamic segment');dynamic=(off,size)
    if dynamic is None: return None
    values={};terminated=False
    for pos in range(dynamic[0],sum(dynamic),16):
        tag,value=struct.unpack_from('<qQ',data,pos)
        if tag==0: terminated=True;break
        if tag in (5,10,14): need(tag not in values,'duplicate ELF dynamic identity');values[tag]=value
    need(terminated,'unterminated ELF dynamic segment')
    if 14 not in values: return None
    need(5 in values and 10 in values and 0<values[10]<=2*1024*1024 and values[14]<values[10],'invalid ELF SONAME table')
    offsets=[off+values[5]-addr for addr,off,size in loads if addr<=values[5] and values[5]+values[10]<=addr+size]
    need(len(offsets)==1,'ambiguous ELF string table mapping')
    begin=offsets[0]+values[14];end=data.find(b'\0',begin,offsets[0]+values[10])
    need(begin<=end<=begin+255,'unterminated ELF SONAME')
    soname=data[begin:end].decode('ascii');need(re.fullmatch(r'[A-Za-z0-9_.+\-]+',soname),'invalid ELF SONAME')
    return (soname,machine,typ,os_abi or 0)

def exact(stream,n):
    global total
    need(0<=n<=256*1024*1024,'invalid boot archive entry bound')
    chunks=[];left=n
    while left:
        data=stream.read(min(left,1024*1024));need(data,'truncated boot archive');chunks.append(data);left-=len(data)
    total+=n;need(total<=768*1024*1024,'expanded boot archive exceeds assessment bound')
    return b''.join(chunks)
def archive(stream):
    while True:
        h=exact(stream,110);need(h[:6] in (b'070701',b'070702'),'unsupported cpio format')
        try: fields=[int(h[i:i+8],16) for i in range(6,110,8)]
        except ValueError: raise SystemExit('Device boot assessment: malformed cpio header')
        mode,size,namesize=fields[1],fields[6],fields[11]
        need(0<namesize<=4096,'invalid boot archive name')
        raw=exact(stream,namesize);need(raw.endswith(b'\0'),'unterminated boot path')
        name=raw[:-1].decode('utf8');name=name.removeprefix('./')
        need(not name.startswith('/') and '..' not in name.split('/'),'unsafe boot archive path')
        exact(stream,(-110-namesize)%4)
        data=exact(stream,size);exact(stream,(-size)%4)
        if name=='TRAILER!!!': break
        if is_dracut:
            need(name==posixpath.normpath(name),'noncanonical dracut entry '+name)
            need(name not in dracut_entries or stat.S_ISDIR(mode) and stat.S_ISDIR(dracut_entries[name]['mode']),'duplicate dracut entry '+name)
            need(fields[2]==0 and fields[3]==0,'non-root dracut archive entry '+name)
            need(not mode&0o022 or stat.S_ISLNK(mode) or stat.S_ISDIR(mode) and name in ('tmp','var/tmp') and mode&stat.S_ISVTX,'writable dracut entry '+name)
            policy=name in ('usr/lib/initrd-release','usr/lib/tmpfiles.d/cryptsetup.conf') or name.startswith(('etc/','usr/lib/modules/','usr/lib/dracut/','usr/lib/systemd/system/','usr/lib/NetworkManager/','run/','tmp/')) or stat.S_ISLNK(mode)
            need(not policy or size<=2*1024*1024,'dracut policy entry exceeds bound')
            dracut_entries[name]={'mode':mode,'digest':hashlib.sha256(data).hexdigest(),'data':data if policy else None,'hardlink':(fields[7],fields[8],fields[0]) if fields[4]>1 and stat.S_ISREG(mode) else None,'size':size,'rdev':(fields[9],fields[10]),'elf':elf_identity(data) if data[:4]==b'\x7fELF' else None}
        else:
            # Debian also names dracut images initrd.img-*. The filename is
            # only a discovery convention, never proof of the boot policy.
            # Retain only public format/activation markers; do not extract
            # the archive or inspect embedded credentials for this diagnosis.
            if name in ('init','usr/lib/dracut/modules.txt','etc/aegis-initrd-id') or name in ('etc/systemd/system/multi-user.target.wants/systemd-networkd.service','etc/systemd/system/sysinit.target.wants/systemd-network-generator.service'):
                need(name not in debian_dracut,'duplicate boot format marker '+name)
                need(size<=65536,'boot format marker exceeds bound')
                debian_dracut[name]=(mode,data)
        if not is_dracut and (name=='init' or name.startswith(('scripts/','conf/','etc/iscsi','etc/crypttab','etc/overlayroot','cryptroot/','etc/udev/rules.d/','usr/lib/udev/rules.d/','lib/udev/rules.d/','etc/modprobe.d/','etc/ld.so.preload'))):
            if stat.S_ISREG(mode):
                need(name not in selected,'duplicate boot policy entry '+name)
                need(size<=2*1024*1024,'boot policy entry exceeds bound');selected[name]=data
            elif stat.S_ISLNK(mode): linked_policy.append(name)
with image.open('rb',buffering=0) as raw:
    while True:
        marker=raw.read(6)
        if not marker: break
        if marker[0]==0:
            raw.seek(-5,1);continue
        raw.seek(-len(marker),1)
        if marker in (b'070701',b'070702'):
            archive(raw);continue
        decoder=None
        if marker.startswith(b'\x28\xb5\x2f\xfd'): decoder=['zstd','-q','-d','-c']
        elif marker.startswith(b'\x1f\x8b'): decoder=['gzip','-d','-c']
        elif marker.startswith(b'\xfd7zXZ\x00'): decoder=['xz','-d','-c']
        elif marker.startswith(b'\x04\x22\x4d\x18'): decoder=['lz4','-d','-c']
        need(decoder is not None,'unsupported initrd compression')
        # The input file descriptor begins at the exact compressed archive;
        # no temporary uncompressed/archive file is created.
        process=subprocess.Popen(decoder,stdin=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            archive(process.stdout)
            while True:
                tail=process.stdout.read(1024*1024)
                if not tail: break
                total+=len(tail);need(total<=768*1024*1024,'expanded boot archive exceeds assessment bound')
                need(not tail.strip(b'\0'),'unexpected data after main archive')
            need(process.wait(timeout=20)==0,'boot decompression failed')
        finally:
            if process.poll() is None: process.kill();process.wait()
        break
if is_dracut:
    # The RPM database is the local administrator's integrity baseline. It is
    # queried as data with plugins disabled; initrd code is never executed.
    db=next((p for p in ('/usr/lib/sysimage/rpm','/var/lib/rpm') if pathlib.Path(p).is_dir()),None)
    need(db is not None,'RPM boot integrity database missing')
    trusted(db);rpm=str(trusted('/usr/bin/rpm'))
    fmt='PACKAGE\t%{NAME}\t%{VERSION}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES}\t%{FILELINKTOS}\n]'
    proc=subprocess.Popen([rpm,'--noplugins','--dbpath',db,'-qa','--qf',fmt],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        metadata=proc.stdout.read(32*1024*1024+1)
        need(len(metadata)<=32*1024*1024,'RPM metadata exceeds assessment bound')
        need(proc.wait(timeout=15)==0,'RPM boot metadata query failed')
    finally:
        if proc.poll() is None: proc.kill();proc.wait()
    rpm_files={};package=version=algorithm=None;dracut_version=None;package_versions={}
    for line in metadata.decode().splitlines():
        fields=line.split('\t')
        if fields[0]=='PACKAGE':
            need(len(fields)==4,'invalid RPM package metadata')
            _,package,version,algorithm=fields
            package_versions.setdefault(package,set()).add(version)
            if package=='dracut': dracut_version=version
        elif len(fields)==4 and fields[0].startswith('/'):
            path,digest,mode,link=fields
            need(package and algorithm=='8','RPM boot baseline requires SHA256')
            need(not digest or re.fullmatch('[0-9a-f]{64}',digest),'invalid RPM file digest')
            # Multiple kernel packages share directories; regular file baseline
            # ambiguity must not silently select an arbitrary version.
            entry=(digest,int(mode),link,package)
            if path in rpm_files and stat.S_ISREG(int(mode)):
                need(rpm_files[path][:3]==entry[:3],'ambiguous RPM file baseline '+path)
            rpm_files[path]=entry
    need(dracut_version=='057','unsupported dracut policy version (expected reviewed 057)')
    need(not pathlib.Path('/sys/firmware/acpi/tables/NBFT').exists(),'firmware NVMe network boot requires separate review')
    entries=dracut_entries
    def payload(name):
        e=entries.get(name)
        need(e and stat.S_ISREG(e['mode']) and e['data'] is not None,'missing dracut policy '+name)
        return e['data']
    def local_cmdline(tokens):
        allowed={'BOOT_IMAGE','root','ro','rw','resume','resume_offset','rootfstype','rootflags','console','quiet','rhgb','loglevel','crashkernel','biosdevname','net.ifnames','rd.lvm.lv','rd.md.uuid','rd.driver.blacklist','modprobe.blacklist','audit','audit_backlog_limit','selinux','enforcing','LANG','vconsole.keymap','vconsole.font','fsck.mode','fsck.repair','rd.auto','rd.hostonly','rd.retry','rd.timeout'}
        for token in tokens:
            key,_,value=token.partition('=')
            if key=='BOOT_IMAGE':
                need(re.fullmatch(r'[A-Za-z0-9_./(),+\-]+',value),'nonliteral GRUB image metadata');continue
            if key=='no_timer_check':
                # Stock Alma cloud images disable the APIC timer IRQ test.
                # This bare kernel flag does not activate initrd networking.
                need(token=='no_timer_check','unexpected timer flag value');continue
            need(re.fullmatch(r'[A-Za-z0-9_./:=,+@%\-]+',token),'nonliteral dracut command line')
            need(key in allowed,'unsupported or network dracut command-line key '+key)
            if key in ('root','resume'): need(value.startswith(('UUID=','LABEL=','PARTUUID=','/dev/')) and not value.startswith(('/dev/nfs','/dev/iscsi')),'non-local dracut device')
            if key=='rootfstype': need(value in ('ext2','ext3','ext4','xfs','btrfs','f2fs'),'non-local dracut root filesystem')
            if key=='rootflags': need(all(re.fullmatch(r'(?:defaults|ro|rw|noatime|relatime|discard|subvol=[A-Za-z0-9_/@.\-]+|subvolid=[0-9]+)',v) for v in value.split(',')),'unsupported root mount options')
    local_cmdline(cmdline)
    modules=payload('usr/lib/dracut/modules.txt').decode().split()
    known={'bash','systemd','systemd-initrd','systemd-sysusers','dbus-broker','dbus','i18n','network-manager','network','ifcfg','drm','prefixdevname','kernel-modules','kernel-modules-extra','kernel-network-modules','qemu','qemu-net','resume','rootfs-block','terminfo','udev-rules','virtiofs','dracut-systemd','usrmount','base','fs-lib','microcode_ctl-fw_dir_override','openssl','shutdown','fips','modsign','crypt','dm','nvdimm','lunmask','virtfs'}
    need(len(modules)==len(set(modules)) and set(modules)<=known and {'systemd','dracut-systemd','base','rootfs-block'}<=set(modules),'unsupported dracut module set')
    if any(name in entries for name in ('usr/lib/systemd/system-generators/systemd-cryptsetup-generator','usr/lib/systemd/systemd-cryptsetup','usr/lib/tmpfiles.d/cryptsetup.conf')):
        need('crypt' in modules,'cryptsetup payload without reviewed crypt module')
    # modules.txt is generated data, not authority to skip semantic checks.
    # Infer the provider from the actual archive too, including disabled units.
    nm_footprint=any(name.startswith(('usr/lib/NetworkManager/','usr/lib64/NetworkManager/','etc/NetworkManager/')) or name in {'usr/lib/nm-lib.sh','usr/lib/net-lib.sh','usr/libexec/nm-initrd-generator','usr/lib/nm-initrd-generator','usr/sbin/NetworkManager','usr/sbin/netroot','usr/bin/nmcli','usr/bin/nm-online','usr/sbin/dhclient','usr/lib/systemd/system/nm-initrd.service','usr/lib/systemd/system/nm-wait-online-initrd.service','usr/lib/dracut/hooks/cmdline/99-nm-config.sh','usr/lib/dracut/hooks/initqueue/settled/99-nm-run.sh','usr/lib/dracut/hooks/cmdline/91-dhcp-root.sh'} for name in entries)
    network=nm_footprint or bool(set(modules)&{'network-manager','network','ifcfg','qemu-net'})
    need(not network or nm_footprint and {'network-manager','network','ifcfg'}<=set(modules),'incoherent or unsupported initrd network provider')
    # Exact source-to-initrd relocation rules; a matching digest at an arbitrary
    # hook name is not sufficient authorization to execute it during boot.
    relocate={
      'shutdown':'99shutdown/shutdown.sh',
      'usr/lib/dracut-lib.sh':'99base/dracut-lib.sh','usr/lib/dracut-dev-lib.sh':'99base/dracut-dev-lib.sh','usr/lib/fs-lib.sh':'99fs-lib/fs-lib.sh','usr/lib/net-lib.sh':'40network/net-lib.sh','usr/lib/nm-lib.sh':'35network-manager/nm-lib.sh',
      'usr/sbin/initqueue':'99base/initqueue.sh','usr/sbin/loginit':'99base/loginit.sh','usr/sbin/rdsosreport':'99base/rdsosreport.sh','usr/sbin/netroot':'40network/netroot.sh','usr/sbin/insmodpost.sh':'90kernel-modules/insmodpost.sh','usr/sbin/fips.sh':'01fips/fips.sh',
      'usr/lib/dracut/hooks/cmdline/91-dhcp-root.sh':'40network/dhcp-root.sh','usr/lib/dracut/hooks/cmdline/95-parse-virtiofs.sh':'95virtiofs/parse-virtiofs.sh','usr/lib/dracut/hooks/cmdline/99-nm-config.sh':'35network-manager/nm-config.sh','usr/lib/dracut/hooks/initqueue/settled/99-nm-run.sh':'35network-manager/nm-run.sh','usr/lib/dracut/hooks/initqueue/timeout/99-rootfallback.sh':'95rootfs-block/rootfallback.sh','usr/lib/dracut/hooks/pre-mount/99-mount-virtiofs.sh':'95virtiofs/mount-virtiofs.sh','usr/lib/dracut/hooks/pre-pivot/00-fips-boot.sh':'01fips/fips-boot.sh','usr/lib/dracut/hooks/pre-pivot/01-fips-noboot.sh':'01fips/fips-noboot.sh','usr/lib/dracut/hooks/pre-pivot/85-write-ifcfg.sh':'45ifcfg/write-ifcfg.sh','usr/lib/dracut/hooks/pre-udev/01-fips-load-crypto.sh':'01fips/fips-load-crypto.sh','usr/lib/dracut/hooks/pre-udev/50-ifname-genrules.sh':'40network/ifname-genrules.sh',
      'usr/lib/NetworkManager/conf.d/initrd-no-auto-default.conf':'35network-manager/initrd-no-auto-default.conf',
      'usr/lib/systemd/system/nm-initrd.service':'35network-manager/nm-initrd.service','usr/lib/systemd/system/nm-wait-online-initrd.service':'35network-manager/nm-wait-online-initrd.service','usr/lib/systemd/system-generators/dracut-rootfs-generator':'98dracut-systemd/rootfs-generator.sh',
      'usr/lib/systemd/system/emergency.service':'98dracut-systemd/emergency.service','usr/lib/systemd/system/rescue.service':'98dracut-systemd/emergency.service','usr/lib/systemd/system/systemd-sysusers.service.d/sysusers-dracut.conf':'01systemd-sysusers/sysusers-dracut.conf',
    }
    for stage in ('cmdline','cmdline-ask','emergency','initqueue','mount','pre-mount','pre-pivot','pre-trigger','pre-udev'):
        relocate['usr/bin/dracut-'+stage]='98dracut-systemd/dracut-'+stage+'.sh'
        relocate['usr/lib/systemd/system/dracut-'+stage+'.service']='98dracut-systemd/dracut-'+stage+'.service'
    # Stock generic-cloud local-root closure. Module names are not authority:
    # require the reviewed hook bytes, exact RPM origin, and inert activation
    # inputs. Encrypted-root/custom-key profiles require separate acceptance.
    cloud_hooks={
      'usr/lib/udev/sas_transport_scan_lun.sh':('lunmask','95lunmask/sas_transport_scan_lun.sh','7a2badcc7055584b0903a77d617455485c5036bac4f567067c21b5c9cf78b81c'),
      'usr/lib/udev/fc_transport_scan_lun.sh':('lunmask','95lunmask/fc_transport_scan_lun.sh','f7303614110682ac6f80d1ff977d4045b38efd24c3373794408353be7e7b0e07'),
      'usr/sbin/crypt-run-generator':('crypt','90crypt/crypt-run-generator.sh','75de2b4a9a8f697a1af742a986ccc6c98a8841db14591cf50bba4e8c070cb572'),
      'usr/lib/dracut/hooks/pre-trigger/01-load-modsign-keys.sh':('modsign','03modsign/load-modsign-keys.sh','c62efa82b52c7e984bb4833e894c0b07354aaf9c54e0c9a46100c10730430bc4'),
      'usr/lib/dracut-crypt-lib.sh':('crypt','90crypt/crypt-lib.sh','3b3ff8e5fcad61f7198be3d305a65c2d562e50055daca255cbd0aa89ee363544'),
      'usr/lib/dracut/hooks/cmdline/30-parse-crypt.sh':('crypt','90crypt/parse-crypt.sh','20f5eb0d4d6bf612f92a3ee3ef3b915d15b573c7e53e9cc7c1294f7c17c4cefe'),
      'usr/lib/dracut/hooks/pre-udev/30-dm-pre-udev.sh':('dm','90dm/dm-pre-udev.sh','27bc52b37061c640ebbf587955d6d07ed60c5403faad5fe58981369d8b9de7c9'),
      'usr/lib/dracut/hooks/shutdown/25-dm-shutdown.sh':('dm','90dm/dm-shutdown.sh','3db7a687ea929401b3b5bd7c394b50c7de9ef9e6ee04de4c58e7d570e18b10f7'),
      'usr/lib/dracut/hooks/cmdline/30-parse-lunmask.sh':('lunmask','95lunmask/parse-lunmask.sh','3c587b9c559efedd02601c322a5173570727f490f3736b0bb76039a3c570ddeb'),
      'usr/lib/dracut/hooks/cmdline/95-parse-virtfs.sh':('virtfs','95virtfs/parse-virtfs.sh','c01ab51a10ca5b8c22310c452dcacfc697762826688065b24ae13127974c3834'),
      'usr/lib/dracut/hooks/mount/99-mount-virtfs.sh':('virtfs','95virtfs/mount-virtfs.sh','bfb4c6db1037d8dc9917789dd08197b6501783b5fc7704234c45aa2fad7edae9'),
    }
    for name,(module,source,digest) in cloud_hooks.items():
        if module in modules or name in entries:
            need(module in modules and name in entries and entries[name]['digest']==digest,'unreviewed generic-cloud boot hook '+name)
            relocate[name]=source
    relocate['etc/udev/rules.d/11-dm.rules']='90dm/11-dm.rules'
    source_map={name:'/usr/lib/dracut/modules.d/'+value for name,value in relocate.items()}
    source_map['usr/bin/dracut-util']='/usr/lib/dracut/dracut-util'
    source_map['usr/lib/tmpfiles.d/dracut-tmpfiles.conf']='/usr/lib/dracut/modules.d/98dracut-systemd/dracut-tmpfiles.conf'
    def public_source(path):
        source=path
        if source not in rpm_files and source.startswith(('/usr/lib/modules/','/usr/lib64/')): source=source[4:]
        r=rpm_files.get(source)
        need(r and stat.S_ISREG(r[1]) and r[0],'missing public RPM source '+path)
        p=trusted(path);need(p.is_file() and p.stat().st_size<=64*1024*1024,'public source bound '+path)
        data=p.read_bytes();need(hashlib.sha256(data).hexdigest()==r[0],'changed public RPM source '+path)
        return data
    def openssl_activation(main,backend_data):
        sections={'default':{}};section='default';includes=[]
        for line in main.decode().splitlines():
            line=line.split('#',1)[0].strip()
            if not line: continue
            if line.startswith('.include'):
                includes.append(line);continue
            if line.startswith('['):
                need(line.endswith(']'),'malformed public OpenSSL section');section=line[1:-1].strip()
                need(section not in sections,'duplicate public OpenSSL section');sections[section]={};continue
            key,sep,value=line.partition('=')
            need(sep and key.strip() not in sections[section],'malformed public OpenSSL assignment');sections[section][key.strip()]=value.strip()
        need(includes==['.include /etc/pki/tls/openssl.d','.include = /etc/crypto-policies/back-ends/opensslcnf.config'],'unknown OpenSSL include closure')
        need(sections['default'].get('openssl_conf')=='openssl_init','unknown OpenSSL initialization section')
        expected={'openssl_init':{'providers':'provider_sect','ssl_conf':'ssl_module','alg_section':'evp_properties'},'provider_sect':{'default':'default_sect'},'default_sect':{'activate':'1'},'evp_properties':{},'ssl_module':{'system_default':'crypto_policy'},'crypto_policy':{}}
        need(all(sections.get(key)==value for key,value in expected.items()),'custom OpenSSL initialization modules/provider')
        # The only included active section supplies SSL policy values, never
        # engines, provider DSOs, key paths, or another configuration include.
        backend=backend_data.decode();keys=set()
        for line in backend.splitlines():
            key,sep,value=line.partition('=');key=key.strip()
            need(sep and key not in keys and not any(c in value for c in '$\\\n\r'),'nonliteral crypto policy include');keys.add(key)
        need(keys=={'CipherString','Ciphersuites','TLS.MinProtocol','TLS.MaxProtocol','DTLS.MinProtocol','DTLS.MaxProtocol','SignatureAlgorithms','Groups'},'unknown crypto policy include fields')
    def openssl_public_inputs():
        need(package_versions.get('openssl-libs')=={'3.5.5'},'unreviewed OpenSSL serializer ABI')
        pins={'/usr/lib/dracut/ossl-config':'8df8ec5c104ce1bd2fceedd867aaab1753bd57691081072a6b57b59b2bc6f7cf','/etc/pki/tls/openssl.cnf':'34108f65c3c759083f6b2d8ff8c509e3504aa78e5180b197827d90827ddc663f','/usr/share/crypto-policies/DEFAULT/opensslcnf.txt':'5db272604fd06ed01b7bf95427e133ca891aacc5eb8158ebe5437c7ffe63db73'}
        values={path:public_source(path) for path in pins}
        # Alma dracut057-110 and057-117 carry the identical ossl-config.c
        # patch; both packaged x86_64 binaries were RPM-verified. Configuration
        # hashes, provider/include closure and pre/post checks stay identical.
        serializer_hashes={pins['/usr/lib/dracut/ossl-config'],'e941642a709db983ff44f00b2a8278b88ab91bbbe86b99dcbaaf12cda4bc5a7c'}
        need(all(hashlib.sha256(values[path]).hexdigest() in (serializer_hashes if path=='/usr/lib/dracut/ossl-config' else {digest}) for path,digest in pins.items()),'unreviewed public OpenSSL configuration/tool revision')
        directory=trusted('/etc/pki/tls/openssl.d')
        need(directory.is_dir() and not any(directory.iterdir()),'nonempty OpenSSL include directory')
        need(trusted('/etc/crypto-policies/back-ends/opensslcnf.config')==trusted('/usr/share/crypto-policies/DEFAULT/opensslcnf.txt'),'custom crypto policy include')
        openssl_activation(values['/etc/pki/tls/openssl.cnf'],values['/usr/share/crypto-policies/DEFAULT/opensslcnf.txt'])
        return values
    def openssl_generated(data):
        before=openssl_public_inputs()
        # NCONF is a parser/serializer. Even if OpenSSL implicitly initializes,
        # the reviewed closure activates only its built-in default provider.
        # The archived input is never executed or passed to the installed tool.
        child=subprocess.Popen(['/usr/lib/dracut/ossl-config'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','OPENSSL_CONF':'/etc/pki/tls/openssl.cnf'})
        try:
            output=child.stdout.read(1024*1024+1)
            need(len(output)<=1024*1024,'OpenSSL serialization output bound')
            need(child.wait(timeout=15)==0,'verified OpenSSL serialization failed')
        finally:
            if child.poll() is None: child.kill();child.wait()
        need(openssl_public_inputs()==before,'OpenSSL public inputs changed during assessment')
        need(output==data,'modified generated OpenSSL configuration')
    def generated_recipe(name,data):
        if name=='etc/pki/tls/openssl.cnf': openssl_generated(data);return True
        if name=='etc/nsswitch.conf':
            expected={'passwd':['sss','files','systemd'],'shadow':['files'],'group':['sss','files','systemd'],'hosts':['files','dns','myhostname'],'services':['files','sss'],'netgroup':['sss'],'automount':['files','sss'],'aliases':['files'],'ethers':['files'],'gshadow':['files'],'networks':['files','dns'],'protocols':['files'],'publickey':['files'],'rpc':['files']}
            fields={}
            for line in data.decode().splitlines():
                line=line.split('#',1)[0].strip()
                if not line: continue
                key,sep,value=line.partition(':')
                need(sep and key in expected and key not in fields and re.fullmatch(r'[a-z \t]+',value),'unreviewed generated NSS policy')
                fields[key]=value.split()
            need(fields==expected,'unreviewed generated NSS provider mapping')
            need(not any(x.startswith(('etc/sssd/','usr/sbin/sssd','usr/libexec/sssd/','var/lib/sss/','run/sss/','var/run/sss/')) for x in entries),'SSSD activation data in early boot')
            return True
        if name=='etc/conf.d/systemd.conf':
            expected=b'systemdutildir="/usr/lib/systemd"\nsystemdsystemunitdir="/usr/lib/systemd/system"\nsystemdsystemconfdir="/etc/systemd/system"\n'
            need(data==expected,'modified generated systemd paths');return True
        if name=='usr/lib/initrd-release':
            original=public_source('/usr/lib/os-release').decode()
            release_script=public_source('/usr/lib/dracut/dracut-version.sh').decode().strip()
            match=re.fullmatch(r'''DRACUT_VERSION=(?:([A-Za-z0-9_.+\-]+)|"([A-Za-z0-9_.+\-]+)"|'([A-Za-z0-9_.+\-]+)')''',release_script)
            need(match,'unreviewed dracut release declaration');release=next(x for x in match.groups() if x is not None)
            output=[];values={}
            for line in original.splitlines():
                if line.startswith(('VERSION=','PRETTY_NAME=')):
                    key,value=line.split('=',1);tokens=shlex.split(value)
                    need(len(tokens)==1 and not any(c in tokens[0] for c in '\\"$`'),'nonliteral public OS release value');values[key]=tokens[0]
                else: output.append(line)
            for key,suffix in (('VERSION','dracut-'+release),('PRETTY_NAME','dracut-'+release+' (Initramfs)')):
                output.append(key+'="'+(values[key]+' ' if values.get(key) else '')+suffix+'"')
            output.append('DRACUT_VERSION="'+release+'"')
            need(data==('\n'.join(output)+'\n').encode(),'modified generated initrd release metadata');return True
        if name in ('etc/fipsmodules','etc/modprobe.d/fips.conf'):
            allowed=set('sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 crc32c crct10dif ghash cipher_null des3_ede aes cfb dh ecdh ecb cbc ctr xts gcm ccm authenc hmac cmac ofb cts deflate lzo zlib ansi_cprng aead cryptomgr tcrypt crypto_user'.split())
            listed=payload('etc/fipsmodules').decode().splitlines()
            need(listed and len(listed)==len(set(listed)) and set(listed)<=allowed,'unreviewed FIPS module policy')
            expected=(''.join('blacklist '+x+'\n' for x in listed)).encode()
            need(payload('etc/modprobe.d/fips.conf')==expected,'modified FIPS blacklist recipe');return True
        source=None;expected=None
        if name=='etc/systemd/journald.conf':
            source='/etc/systemd/journald.conf'
            generated=b'[Journal]\nStorage=volatile\nRateLimitInterval=0\nRateLimitBurst=0\n'
            # Generic images need not copy the host configuration first.
            # Admit only the complete literal stock recipe or the RPM source
            # plus that recipe; additional/drop-in policy remains forbidden.
            expected=generated if data==generated else public_source(source)+generated
        elif name=='usr/lib/systemd/system/dbus.socket':
            source='/'+name;expected=public_source(source).replace(b'[Unit]\n',b'[Unit]\nDefaultDependencies=no\n        Conflicts=shutdown.target\n        Before=shutdown.target\n').replace(b'[Socket]\n',b'[Socket]\nRemoveOnStop=yes\n')
        elif name=='usr/lib/systemd/system/systemd-tmpfiles-setup.service':
            source='/'+name;expected=re.sub(rb'(?m)^(After\s*=.*)local-fs.target\s*(.*)$',rb'\1-.mount \2',public_source(source))
        elif name in ('etc/udev/rules.d/59-persistent-storage.rules','etc/udev/rules.d/61-persistent-storage.rules','etc/udev/rules.d/59-persistent-storage-dm.rules'):
            module='90dm' if name.endswith('/59-persistent-storage-dm.rules') else '95udev-rules'
            source='/usr/lib/dracut/modules.d/'+module+'/'+posixpath.basename(name)
            lines=[]
            for line in public_source(source).decode().splitlines():
                line=line.strip(' \t')
                for token,replacement in (('IMPORT PATH_ID','IMPORT{builtin}="path_id"'),('IMPORT BLKID','IMPORT{builtin}="blkid"')):
                    if line.endswith(token): line=line[:-len(token)]+replacement;break
                lines.append(line)
            expected=('\n'.join(lines)+'\n').encode()
        if expected is None: return False
        need(data==expected,'modified generated boot recipe '+name);return True

    def kbd_source(path):
        seen=set();packages=set()
        for _ in range(16):
            need(path.startswith('/usr/lib/kbd/') and path not in seen,'escaping or cyclic packaged keyboard alias');seen.add(path)
            parts=path.strip('/').split('/');found=False
            for i in range(1,len(parts)+1):
                prefix='/'+ '/'.join(parts[:i]);entry=rpm_files.get(prefix)
                if entry and stat.S_ISLNK(entry[1]):
                    packages.add(entry[3]);target=entry[2]
                    need(target and '\x00' not in target and '\n' not in target,'invalid packaged keyboard alias')
                    path=posixpath.normpath(posixpath.join(target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix),target),*parts[i:]))
                    found=True;break
            if found: continue
            entry=rpm_files.get(path)
            need(entry and stat.S_ISREG(entry[1]) and not entry[1]&0o111,'unknown packaged keyboard data')
            packages.add(entry[3]);need(len(packages)==1 and packages<={'kbd','kbd-misc','kbd-legacy'},'keyboard alias changes package authority')
            return path
        need(False,'packaged keyboard alias depth exceeded')
    def baseline(name,e):
        source=source_map.get(name,'/'+name)
        if name.startswith('usr/lib/kbd/'):
            need(not e['mode']&0o111,'executable keyboard data');source=kbd_source(source)
        if source not in rpm_files and source.startswith(('/usr/lib/modules/','/usr/lib64/')): source=source[4:]
        r=rpm_files.get(source)
        need(r and stat.S_ISREG(r[1]) and r[0]==e['digest'],'unrecognized or modified RPM boot file '+name)
        expected_mode=r[1]|0o100 if name in source_map and '/dracut/hooks/' in name else r[1]
        need(expected_mode&0o111==e['mode']&0o111,'unrecognized RPM boot file executable mode '+name)
        if source.startswith('/usr/lib/dracut/'):
            need(r[3] in ('dracut','dracut-network'),'untrusted dracut source package '+name)
        if name.startswith(('etc/','usr/lib/udev/','usr/lib/systemd/','usr/lib/tmpfiles.d/','usr/lib/sysusers.d/','usr/lib/NetworkManager/','usr/share/dbus-1/')):
            allowed={'dracut','dracut-network','systemd','systemd-udev','systemd-libs','dbus','dbus-common','dbus-broker','NetworkManager','NetworkManager-libnm','setup','glibc','glibc-common','crypto-policies','openssl','openssl-libs','firewalld','firewalld-filesystem','sg3_utils','device-mapper','device-mapper-libs','kmod','kbd','kbd-misc','almalinux-release','redhat-release'}
            need(r[3] in allowed or (r[3],name) in {('teamd','etc/dbus-1/system.d/teamd.conf'),('vim-minimal','etc/virc'),('cryptsetup-libs','usr/lib/tmpfiles.d/cryptsetup.conf')},'unreviewed RPM boot policy package '+name)
        return source
    # These reviewed guards are an additional semantic baseline, not a fetched
    # hash asserted as trust. Package upgrades with changed guards need review.
    nm_pins={'nm-config.sh':'363c67def0fbaf188d3a398b3aa9be60a272f861f3d2fb7325d82d9dfd07f59a','nm-run.sh':'617e8acb55b0475485d5c3de54edea32aafa26e23871b137fcfa9afcf8860f47','nm-lib.sh':'8afd9183fa68ba2ae435986d6edf72033be819a06bb95b93575722bc9259aafb','nm-initrd.service':'d3d7ec5afec46ef94dce6b49470dfa7c2c0f5693c9e701050fcf42e956ec2052','nm-wait-online-initrd.service':'73d5f5b17b9a6a2f4bd8b1033e5e8bd62ddf36f812683d0550b7ee8ef695c7cb','initrd-no-auto-default.conf':'39015224a61189108dfb796b49adcc8b6271a07eb7215a3d6ab35a023c28ea50'}
    if network:
        for leaf,digest in nm_pins.items():
            source='/usr/lib/dracut/modules.d/35network-manager/'+leaf
            target=next(name for name,path in source_map.items() if path==source)
            need(target in entries and entries[target]['digest']==digest,'unreviewed NetworkManager initrd activation guard '+leaf)
    # Collapse cpio hardlinks in memory. No archive member is extracted, and
    # two disagreeing payloads for one inode cannot choose the last one.
    links={}
    for e in entries.values():
        if e['hardlink'] and e['size']:
            prior=links.get(e['hardlink']);need(not prior or prior['digest']==e['digest'] and prior['mode']==e['mode'],'conflicting initrd hardlink contents')
            links[e['hardlink']]=e
    for e in entries.values():
        if e['hardlink'] and not e['size']:
            prior=links.get(e['hardlink']);need(prior is not None and prior['mode']==e['mode'],'unresolved or inconsistent initrd hardlink')
            e.update(digest=prior['digest'],data=prior['data'],size=prior['size'],elf=prior['elf'])
    unit_names={'basic.target','cryptsetup-pre.target','cryptsetup.target','dbus-broker.service','dbus.service','dbus.socket','debug-shell.service','emergency.service','emergency.target','final.target','halt.target','initrd-cleanup.service','initrd-fs.target','initrd-parse-etc.service','initrd-root-device.target','initrd-root-fs.target','initrd-switch-root.service','initrd-switch-root.target','initrd-udevadm-cleanup-db.service','initrd-usr-fs.target','initrd.target','kexec.target','kmod-static-nodes.service','local-fs-pre.target','local-fs.target','modprobe@.service','multi-user.target','network-online.target','network-pre.target','network.target','nm-initrd.service','nm-wait-online-initrd.service','nss-lookup.target','nss-user-lookup.target','paths.target','poweroff.target','reboot.target','remote-cryptsetup.target','remote-fs-pre.target','remote-fs.target','rescue.service','rescue.target','rpcbind.target','shutdown.target','sigpwr.target','slices.target','sockets.target','swap.target','sys-kernel-config.mount','sysinit.target','syslog.socket','timers.target','umount.target'}
    systemd_units={'ask-password-console.path','ask-password-console.service','fsck@.service','halt.service','hibernate-resume@.service','journald-audit.socket','journald-dev-log.socket','journald.service','journald.socket','kexec.service','modules-load.service','poweroff.service','random-seed.service','reboot.service','sysctl.service','sysusers.service','tmpfiles-setup-dev.service','tmpfiles-setup.service','udev-settle.service','udev-trigger.service','udevd-control.socket','udevd-kernel.socket','udevd.service','vconsole-setup.service','volatile-root.service'}
    unit_names|={'systemd-'+name for name in systemd_units}|{'dracut-'+x+'.service' for x in ('cmdline','cmdline-ask','emergency','initqueue','mount','pre-mount','pre-pivot','pre-trigger','pre-udev')}
    def resolved_link(name,target):
        need(target and '\x00' not in target and '\n' not in target,'invalid initrd symlink')
        return posixpath.normpath(target.lstrip('/') if target.startswith('/') else posixpath.join(posixpath.dirname(name),target))
    def canonical(name):
        for old,new in (('lib/','usr/lib/'),('lib64/','usr/lib64/'),('bin/','usr/bin/'),('sbin/','usr/sbin/')):
            if name.startswith(old): return new+name[len(old):]
        return name
    def resolve_archive(path):
        path=canonical(path.lstrip('/'));seen=set()
        for _ in range(16):
            need(path not in seen,'cyclic archive library alias');seen.add(path)
            e=entries.get(path);need(e is not None,'missing archive library alias')
            if stat.S_ISREG(e['mode']): return path,e
            need(stat.S_ISLNK(e['mode']),'non-file archive library alias')
            path=canonical(resolved_link(path,e['data'].decode()))
        need(False,'archive library alias depth exceeded')
    need(entries.get('init',{}).get('data')==b'usr/lib/systemd/systemd' and stat.S_ISLNK(entries['init']['mode']),'unsupported dracut init entry')
    binary_metadata_names={'etc/ld.so.cache'}|{'usr/lib/modules/'+kernel+'/'+x for x in ('modules.dep','modules.dep.bin','modules.alias','modules.alias.bin','modules.softdep','modules.symbols','modules.symbols.bin','modules.builtin.bin','modules.builtin.alias.bin','modules.devname')}
    checked=0
    for name,e in entries.items():
        if name in binary_metadata_names: need(stat.S_ISREG(e['mode']) and not e['mode']&0o111,'nonregular or executable generated index '+name)
        # Existence-based systemd/shell activation checks also match directories.
        # Reject generated runtime state and connection entries before skipping
        # structural directory records; an empty directory is not inert here.
        need(not name.startswith(('run/','var/run/','tmp/','var/tmp/','etc/NetworkManager/','etc/sysconfig/network','usr/lib/NetworkManager/system-connections/','etc/systemd/network/','etc/connman/','etc/wicked/','etc/dropbear/','etc/ssh/','etc/iscsi/','etc/crypttab','etc/cryptroot','etc/ld.so.preload','etc/fstab')) or name=='etc/fstab.empty' and stat.S_ISREG(e['mode']) and not e['size'],'early-network or unsupported initrd activation input '+name)
        # Generic-cloud may include an empty signing-key directory. A key,
        # TPM blob or cryptsetup credential is not covered by local-root proof.
        need(not name.startswith(('etc/ndctl/','etc/cryptsetup-keys.d/','usr/lib/cryptsetup-keys.d/','usr/lib/modules/keys/','lib/modules/keys/')),'unreviewed early key or TPM payload '+name)
        if name in ('usr/lib/modules/keys','lib/modules/keys'):
            need(stat.S_ISDIR(e['mode']),'linked early module key directory')
        if stat.S_ISDIR(e['mode']): continue
        if stat.S_ISCHR(e['mode']):
            devices={'dev/console':(5,1),'dev/kmsg':(1,11),'dev/null':(1,3),'dev/random':(1,8),'dev/urandom':(1,9)}
            need(name in devices and e['rdev']==devices[name] and not e['size'],'unsupported early device node '+name)
            checked+=1;continue
        need(stat.S_ISREG(e['mode']) or stat.S_ISLNK(e['mode']),'unsupported dracut special entry '+name)
        if name.startswith('usr/lib/systemd/system/'):
            relative=name[len('usr/lib/systemd/system/'):];leaf=posixpath.basename(name)
            special=name=='usr/lib/systemd/system/systemd-sysusers.service.d/sysusers-dracut.conf'
            need(special or leaf in unit_names|{'default.target','ctrl-alt-del.target'} and ('/' not in relative or '.wants/' in relative or '.requires/' in relative),'unknown initrd unit or drop-in '+name)
        if '/systemd/system-generators/' in name:
            need(posixpath.basename(name) in {'dracut-rootfs-generator','systemd-fstab-generator','systemd-gpt-auto-generator','systemd-hibernate-resume-generator','systemd-debug-generator','systemd-cryptsetup-generator'},'unsupported initrd generator '+name)
            if posixpath.basename(name) in ('systemd-debug-generator','systemd-cryptsetup-generator'):
                need(package_versions.get('systemd')=={'252'},'unreviewed systemd generator version')
        if name.startswith('usr/lib/systemd/network/'):
            need(name=='usr/lib/systemd/network/99-default.link','networkd activation policy in initrd')
        if name.startswith(('etc/tmpfiles.d/','usr/lib/tmpfiles.d/')):
            need(name in ('usr/lib/tmpfiles.d/systemd.conf','usr/lib/tmpfiles.d/dracut-tmpfiles.conf','usr/lib/tmpfiles.d/cryptsetup.conf'),'unreviewed initrd tmpfiles policy')
            if name=='usr/lib/tmpfiles.d/cryptsetup.conf':
                need(payload(name)==b'd /run/cryptsetup 0700 root root -\n','modified cryptsetup tmpfiles policy')
        if name.startswith(('etc/sysusers.d/','usr/lib/sysusers.d/')):
            need(name in ('usr/lib/sysusers.d/basic.conf','usr/lib/sysusers.d/dbus.conf'),'unreviewed initrd sysusers policy')
        if name=='etc/cmdline' or name.startswith('etc/cmdline.d/'):
            need(stat.S_ISREG(e['mode']),'linked embedded boot command line')
        if stat.S_ISLNK(e['mode']):
            target=e['data'].decode();resolved=resolved_link(name,target)
            need(not resolved.startswith('../'),'escaping initrd symlink '+name)
            fixed={'init':'usr/lib/systemd/systemd','bin':'usr/bin','sbin':'usr/sbin','lib':'usr/lib','lib64':'usr/lib64','var/run':'run','var/lock':'run/lock','usr/share/consolefonts':'usr/lib/kbd/consolefonts','usr/share/consoletrans':'usr/lib/kbd/consoletrans','usr/share/keymaps':'usr/lib/kbd/keymaps','usr/share/unimaps':'usr/lib/kbd/unimaps','etc/mtab':'proc/self/mounts','etc/os-release':'etc/initrd-release','etc/initrd-release':'usr/lib/initrd-release','usr/lib/os-release':'usr/lib/initrd-release','usr/bin/dracut-getarg':'usr/bin/dracut-util','usr/bin/dracut-getargs':'usr/bin/dracut-util','usr/bin/loginctl':'usr/bin/true','usr/sbin/init':'usr/lib/systemd/systemd','etc/crypto-policies/back-ends/opensslcnf.config':'usr/share/crypto-policies/DEFAULT/opensslcnf.txt','etc/systemd/system/default.target':'usr/lib/systemd/system/initrd.target','usr/lib/systemd/system/default.target':'usr/lib/systemd/system/initrd.target','usr/lib/systemd/system/ctrl-alt-del.target':'usr/lib/systemd/system/reboot.target','etc/systemd/system/dbus.service':'usr/lib/systemd/system/dbus-broker.service'}
            if name in fixed: need(resolved==fixed[name],'modified initrd alias '+name)
            elif '/systemd/system/' in name and ('.wants/' in name or '.requires/' in name):
                leaf=posixpath.basename(name)
                need(leaf in unit_names and leaf not in ('debug-shell.service','multi-user.target') and resolved=='usr/lib/systemd/system/'+leaf and resolved in entries,'unknown enabled initrd unit '+name)
            else:
                r=rpm_files.get('/'+name)
                if r is None and name.startswith('usr/lib64/'): r=rpm_files.get('/'+name[4:])
                need(r and stat.S_ISLNK(r[1]) and canonical(resolved)==canonical(resolved_link(name,r[2])),'unrecognized initrd symlink '+name)
                need(canonical(resolved) in entries,'missing initrd symlink target '+name)
                if name.startswith('usr/lib64/'):
                    library,record=resolve_archive(name);baseline(library,record)
            checked+=1;continue
        if name=='etc/cmdline' or name.startswith('etc/cmdline.d/'):
            local_cmdline(payload(name).decode().split());checked+=1;continue
        if name in ('usr/lib/dracut/modules.txt','usr/lib/dracut/need-initqueue','early_cpio') or name.startswith(('usr/lib/dracut/dracut-','usr/lib/dracut/build-parameter','usr/lib/dracut/hostonly-files','kernel/x86/microcode/')):
            continue
        if '/dracut/hooks/' in name: need(name in source_map,'unknown dracut hook '+name)
        if name.startswith('etc/systemd/system/'):
            need(False,'custom initrd systemd policy '+name)
        # Generated host identities carry no executable policy; contents are
        # neither persisted nor hashed in the public receipt. No shell source
        # or dynamic loader policy is exempted here.
        if name in ('etc/locale.conf','etc/vconsole.conf'):
            keys={'LANG','LC_ADDRESS','LC_COLLATE','LC_CTYPE','LC_IDENTIFICATION','LC_MEASUREMENT','LC_MESSAGES','LC_MONETARY','LC_NAME','LC_NUMERIC','LC_PAPER','LC_TELEPHONE','LC_TIME'} if name=='etc/locale.conf' else {'KEYMAP','KEYMAP_TOGGLE','FONT','FONT_MAP','FONT_UNIMAP'}
            seen=set()
            for line in payload(name).decode().splitlines():
                line=line.strip()
                if not line or line.startswith('#'): continue
                match=re.fullmatch(r'''([A-Z_]+)=(?:([A-Za-z0-9_.@+/-]*)|"([A-Za-z0-9_.@+/-]*)"|'([A-Za-z0-9_.@+/-]*)')''',line)
                need(match and match[1] in keys and match[1] not in seen,'unsupported generated locale/console policy '+name)
                seen.add(match[1])
            need(not e['mode']&0o111,'executable generated locale/console policy '+name);checked+=1;continue
        if name in ('etc/hostname','etc/machine-id','etc/passwd','etc/group','etc/fstab.empty'):
            need(not e['mode']&0o111,'executable generated identity config '+name);continue
        if name=='usr/lib/modules/'+kernel+'/modules.builtin.alias.bin':
            need(package_versions.get('kmod')=={'28'} and not e['size'] and not e['mode']&0o111,'unreviewed built-in module alias index');checked+=1;continue
        if name=='etc/ld.so.cache': continue
        if name.startswith('usr/lib/modules/'+kernel+'/') and posixpath.basename(name) in {'modules.dep','modules.dep.bin','modules.alias','modules.alias.bin','modules.softdep','modules.symbols','modules.symbols.bin','modules.builtin.bin','modules.devname'}: continue
        if generated_recipe(name,e['data']): need(not e['mode']&0o111,'executable generated configuration '+name);checked+=1;continue
        baseline(name,e);checked+=1
    if 'etc/ld.so.cache' in entries:
        cache=payload('etc/ld.so.cache')
        need(package_versions.get('glibc')=={'2.34'} and os.uname().machine=='x86_64','unreviewed glibc cache ABI')
        need(len(cache)>=48 and cache[:20]==b'glibc-ld.so.cache1.1','unreviewed loader cache format')
        count,size=struct.unpack_from('<II',cache,20);extension=struct.unpack_from('<I',cache,32)[0]
        strings=48+24*count;strings_end=strings+size
        need(count<=4096 and strings_end<=len(cache) and cache[28]==2 and not any(cache[29:32]+cache[36:48]),'invalid loader cache header')
        def cache_string(offset):
            need(strings<=offset<strings_end,'loader cache string offset outside table')
            end=cache.find(b'\0',offset,strings_end);need(offset<=end<=offset+4096,'unterminated loader cache string')
            return cache[offset:end].decode('ascii')
        cached={}
        for i in range(count):
            flags,key,value,osversion,hwcap=struct.unpack_from('<iIIIQ',cache,48+i*24)
            need(flags==0x303 and hwcap==0,'unreviewed loader cache architecture or hardware override')
            soname=cache_string(key);path=cache_string(value)
            need(re.fullmatch(r'[A-Za-z0-9_.+\-]+',soname) and re.fullmatch(r'/(?:usr/)?lib64/[A-Za-z0-9_.+\-]+',path),'noncanonical loader cache name')
            actual,e=resolve_archive(path);expected,_=resolve_archive('usr/lib64/'+soname)
            need(actual==expected and e.get('elf')==(soname,62,3,osversion),'loader cache SONAME/code mapping mismatch')
            baseline(actual,e)
            need(soname not in cached,'competing loader cache SONAME mapping');cached[soname]=actual
        if extension:
            need(extension%4==0 and strings_end<=extension<=strings_end+3 and not any(cache[strings_end:extension]) and extension+24<=len(cache),'invalid loader cache extension offset')
            magic,nsections=struct.unpack_from('<II',cache,extension)
            tag,flags,offset,size=struct.unpack_from('<IIII',cache,extension+8)
            need(magic==0xeaa42174 and nsections==1 and tag==0 and flags==0 and offset==extension+24 and 0<size<=256 and offset+size==len(cache),'unreviewed loader cache extension')
            need(all(32<=c<127 for c in cache[offset:]),'invalid loader generator metadata')
        else: need(strings_end==len(cache),'unexpected loader cache suffix')
        checked+=1

    def module_name(path):
        leaf=posixpath.basename(path)
        need(re.fullmatch(r'[A-Za-z0-9_\-]+\.ko(?:\.(?:xz|gz|zst))?',leaf),'noncanonical kernel module filename')
        return leaf.split('.')[0].replace('-','_')
    def alias_key(value):
        out=[];bracket=False
        for c in value:
            if c=='[': need(not bracket,'nested kernel alias range');bracket=True
            elif c==']': need(bracket,'unmatched kernel alias range');bracket=False
            out.append('_' if c=='-' and not bracket else c)
        need(not bracket,'unterminated kernel alias range');return ''.join(out)
    def decode_index(data):
        need(12<=len(data)<=8*1024*1024,'kernel index size bound')
        magic,version,root=struct.unpack_from('>III',data)
        need(magic==0xb007f457 and version==0x20001,'unsupported kernel index format')
        nodes=set();spans=[(0,12)];result={};stack=[(root,'',0)];nvalues=0
        while stack:
            offset,key,depth=stack.pop()
            if offset==0: continue
            base=offset&0xfffffff
            need(not offset&0x10000000 and 12<=base<len(data) and base not in nodes and depth<=256,'kernel index offset cycle or depth')
            nodes.add(base);need(len(nodes)<=100000,'kernel index node bound');pos=base
            def number():
                nonlocal pos
                need(pos+4<=len(data),'truncated kernel index number')
                value=struct.unpack_from('>I',data,pos)[0];pos+=4;return value
            def string():
                nonlocal pos
                end=data.find(b'\0',pos,min(len(data),pos+4097))
                need(end>=pos and all(32<=c<127 for c in data[pos:end]),'invalid kernel index string')
                value=data[pos:end].decode('ascii');pos=end+1;return value
            if offset&0x80000000: key+=string()
            need(len(key)<=4096,'kernel index key bound')
            children=[]
            if offset&0x20000000:
                need(pos+2<=len(data),'truncated kernel index children')
                first,last=data[pos:pos+2];pos+=2
                need(0<=first<=last<128,'invalid kernel index child range')
                children=[(number(),key+chr(c),depth+1) for c in range(first,last+1)]
            if offset&0x40000000:
                count=number();nvalues+=count
                need(0<count<=10000 and nvalues<=100000 and key not in result,'kernel index value bound or duplicate key')
                values=[(number(),string()) for _ in range(count)]
                need(values==sorted(values,key=lambda v:v[0]),'kernel index priority order')
                result[key]=values
            spans.append((base,pos));stack.extend(children)
        cursor=0
        for begin,end in sorted(spans):
            need(begin==cursor and end>begin,'overlapping or unaccounted kernel index bytes');cursor=end
        need(cursor==len(data),'kernel index suffix');return result
    module_prefix='usr/lib/modules/'+kernel+'/'
    index_names={'modules.dep','modules.dep.bin','modules.alias','modules.alias.bin','modules.softdep','modules.symbols','modules.symbols.bin','modules.builtin.bin','modules.devname'}
    present_indexes={name[len(module_prefix):] for name in entries if name.startswith(module_prefix) and name[len(module_prefix):] in index_names}
    if present_indexes:
        need(present_indexes==index_names and package_versions.get('kmod')=={'28'},'unsupported or incomplete kernel index family')
        modules_in_image=[name for name,e in entries.items() if name.startswith(module_prefix) and re.search(r'\.ko(?:\.(?:xz|gz|zst))?$',name) and stat.S_ISREG(e['mode'])]
        need(0<len(modules_in_image)<=2048,'kernel module oracle input bound')
        args=[];names=set()
        for name in sorted(modules_in_image):
            relative=name[len(module_prefix):];mod=module_name(relative)
            need(mod not in names,'competing packaged kernel module names');names.add(mod)
            path='/lib/modules/'+kernel+'/'+relative
            data=public_source(path)
            need(hashlib.sha256(data).hexdigest()==entries[name]['digest'],'host module differs from assessed archive')
            args.append(path)
        for leaf in ('modules.order','modules.builtin','modules.builtin.modinfo'):
            data=public_source('/lib/modules/'+kernel+'/'+leaf)
            need(module_prefix+leaf in entries and entries[module_prefix+leaf]['digest']==hashlib.sha256(data).hexdigest(),'host kernel metadata differs from archive')
        tool='/usr/sbin/depmod';backing=str(trusted(tool))
        need(backing==str(trusted('/usr/bin/kmod')),'unexpected depmod executable binding')
        public_source('/usr/bin/kmod')
        need(sum(len(x)+1 for x in args)<=192*1024,'kernel oracle argument bound')
        # kmod28 explicit-file mode skips cfg_load/discovery. -n sets stdout;
        # output callbacks do not open or create any destination file in it.
        child=subprocess.Popen([tool,'-n','-C','/dev/null',kernel,*args],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
        try:
            output=child.stdout.read(16*1024*1024+1)
            need(len(output)<=16*1024*1024,'kernel oracle output bound')
            need(child.wait(timeout=15)==0,'verified depmod dry-run failed')
        finally:
            if child.poll() is None: child.kill();child.wait()
        groups={'modules.dep':[],'modules.alias':[],'modules.softdep':[],'modules.symbols':[],'modules.devname':[]}
        for line in output.decode('ascii').splitlines():
            if not line or line.startswith('#'): continue
            if line.startswith('alias '): group='modules.symbols' if line.startswith('alias symbol:') else 'modules.alias'
            elif line.startswith('softdep '): group='modules.softdep'
            elif re.fullmatch(r'[A-Za-z0-9_]+ [A-Za-z0-9_/.-]+ [bc][0-9]+:[0-9]+',line): group='modules.devname'
            else: group='modules.dep'
            groups[group].append(line)
        ranks={};expected={name:{} for name in ('modules.dep.bin','modules.alias.bin','modules.symbols.bin','modules.builtin.bin')}
        for rank,line in enumerate(groups['modules.dep']):
            path,sep,dependencies=line.partition(':')
            need(sep and module_prefix+path in modules_in_image and all(module_prefix+x in modules_in_image for x in dependencies.split()),'noncanonical module dependency oracle')
            mod=module_name(path);need(mod not in ranks,'duplicate module dependency oracle');ranks[mod]=rank
            expected['modules.dep.bin'][mod]=[(rank,line)]
        need(set(ranks)==names,'incomplete kernel dependency oracle')
        for group in ('modules.alias','modules.symbols'):
            for line in groups[group]:
                fields=line.split();need(len(fields)==3 and fields[0]=='alias' and fields[2] in ranks,'invalid alias oracle')
                key=alias_key(fields[1])
                expected[group+'.bin'].setdefault(key,[]).append((ranks[fields[2]],fields[2]))
            for values in expected[group+'.bin'].values(): values.sort(key=lambda v:v[0])
        for line in public_source('/lib/modules/'+kernel+'/modules.builtin').decode('ascii').splitlines():
            if line: expected['modules.builtin.bin'][module_name(line)]=[(0,'')]
        for name,lines in groups.items():
            actual=[line for line in payload(module_prefix+name).decode('ascii').splitlines() if line and not line.startswith('#')]
            # Symbol hash-table iteration order has no lookup semantics;
            # aliases/dependencies retain exact canonical ordering below.
            need((sorted(actual)==sorted(lines) if name=='modules.symbols' else actual==lines),'kernel text index differs from canonical oracle '+name)
        for name,mapping in expected.items():
            need(decode_index(payload(module_prefix+name))==mapping,'kernel binary index differs from canonical oracle '+name)
        checked+=len(index_names)

    print(json.dumps({'initramfs_network':'absent_verified','initrd_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'kernel':kernel,'checked_policy_files':checked,'boot_profile':'dracut-057-rpm-local-v1','network_manager':'packaged_dormant' if network else 'absent'}))
    sys.exit(0)

if 'usr/lib/dracut/modules.txt' in debian_dracut:
    init_mode,init_data=debian_dracut.get('init',(0,b''))
    need(stat.S_ISLNK(init_mode) and init_data==b'usr/lib/systemd/systemd','unsupported Debian dracut init entry')
    mode,modules=debian_dracut['usr/lib/dracut/modules.txt']
    need(stat.S_ISREG(mode),'nonregular Debian dracut module list')
    if 'etc/aegis-initrd-id' in debian_dracut:
        need(len(sys.argv)>3,'strict Debian dracut verifier unavailable')
        module_root=trusted(sys.argv[3])
        sys.path.insert(0,str(module_root))
        from aegis_initrd_policy import verify_profile
        result=verify_profile(kernel,image,boot=not (len(sys.argv)>2 and sys.argv[2]))
        print(json.dumps({k:result[k] for k in ('initramfs_network','initrd_sha256','kernel','checked_policy_files','boot_profile','network_manager')}))
        sys.exit(0)
    networkd=bool({'systemd-networkd','systemd-network-management'}&set(modules.decode().split())) or any('/systemd/system/' in name for name in debian_dracut)
    print(json.dumps({
        'schema':'aegis_install_refusal_v1',
        'code':'debian_dracut_boot_profile_unreviewed',
        'action':'use_reviewed_local_boot_image',
        'message':('This Debian dracut boot profile has not been proved networkless; '
                   'early network services may run before Aegis guards traffic. '
                   'Use a reviewed local-root image with a verified networkless '
                   'initrd, then retry.'),
        'early_network_services_present':networkd,
    },sort_keys=True,separators=(',',':')),file=sys.stderr)
    raise SystemExit(78)
need(not linked_policy,'symlinked boot policy entry '+(linked_policy[0] if linked_policy else ''))
need('/usr/share/initramfs-tools/init' in packaged,'initramfs-tools package baseline missing')
need('init' in selected and 'conf/initramfs.conf' in selected,'missing boot policy')
for name,data in selected.items():
    if name=='init' or name.startswith('scripts/') and not name.endswith('/ORDER'):
        source='/usr/share/initramfs-tools/'+name
        need(source in packaged,'unrecognized boot hook '+name)
        current=trusted(source).read_bytes()
        need(hashlib.md5(current).hexdigest()==packaged[source] and current==data,'modified boot hook '+name)
    elif '/udev/rules.d/' in name:
        source='/'+name
        if source not in packaged and source.startswith('/lib/'): source='/usr'+source
        elif source not in packaged and source.startswith('/usr/lib/'): source=source[4:]
        need(source in packaged,'unrecognized initrd udev rule '+name)
        current=trusted(source).read_bytes()
        need(hashlib.md5(current).hexdigest()==packaged[source] and current==data,'modified initrd udev rule '+name)
    elif name.startswith('etc/modprobe.d/'):
        source='/'+name
        if source in packaged:
            current=trusted(source).read_bytes()
            if current==data and hashlib.md5(current).hexdigest()==packaged[source]: continue
        for line in data.decode().replace('\\\n','').splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            tokens=shlex.split(line,comments=True)
            literal_noop=(len(tokens)==3 and tokens[0] in ('install','remove') and re.fullmatch(r'[A-Za-z0-9_-]+',tokens[1]) and tokens[2] in ('/bin/true','/bin/false','/usr/bin/true','/usr/bin/false'))
            need(tokens and (tokens[0] in ('options','blacklist','alias','softdep','weakdep') or literal_noop),'custom executable modprobe action')
    elif name.endswith('/ORDER'):
        # Generated ORDER files are executable shell too. Admit only literal
        # calls to individually checked scripts and their stock error guard.
        text=data.decode()
        for line in text.splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            need(re.fullmatch(r'/scripts/[A-Za-z0-9_./-]+ "\$@"',line) or line in ('[ -e /conf/param.conf ] && . /conf/param.conf','true'),'custom boot script order')
            if line.startswith('/scripts/'):
                target=line.split(' ',1)[0][1:]
                need('..' not in target.split('/') and target in selected and not target.endswith('/ORDER'),'unchecked boot order target')
    elif name.startswith('conf/'):
        if name=='conf/modules': continue
        for line in data.decode().splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:+,=%\-]*',line) or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=[\'\"][A-Za-z0-9_./:+,=% \-]*[\'\"]',line),'nonliteral early boot config')
            key,value=line.split('=',1);value=value.strip('\'"')
            need(key in {'MODULES','BUSYBOX','COMPRESS','COMPRESSLEVEL','DEVICE','NFSROOT','RUNSIZE','FSTYPE','BOOT','DPKG_ARCH','ROOT','UMASK','KEYMAP','RESUME'},'unsupported early boot variable '+key)
            if key=='RESUME': need(value=='none' or re.fullmatch(r'UUID=[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',value),'unsupported early resume device')
            if key=='KEYMAP': need(value in ('y','n'),'unsupported early keyboard policy')
            if key=='NFSROOT': need(value in ('','auto'),'configured early NFS root')
            if key in ('IP','IP6','BOOTIF','DEVICE','VLAN','overlayroot') or key.startswith('ISCSI_'): need(not value,'early networking is configured')
            if key=='BOOT': need(value in ('','local'),'non-local initramfs boot')
            if key=='MODULES': need(value!='netboot','netboot initramfs')
    else:
        need(not data.strip(),'optional network/unlock boot policy requires separate review')
print(json.dumps({'initramfs_network':'absent_verified','initrd_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'kernel':kernel,'checked_policy_files':len(selected)}))
PY
}

device_assess_full_wide_host() {
  local bundle="$1" client="$2" boot_proof
  boot_proof="$(device_verify_initramfs)" || return $?
  "$client" device bundle-inspect --bundle-dir "$bundle" --json | device_assess_guard_host "$boot_proof"
}

# The shared host assessor consumes only admitted relay route facts. Device
# callers authenticate their public profile above; AUTO uses captured Settings
# below. Its boot, manager, socket, forwarding and kernel checks are identical.
device_assess_guard_host() {
  local boot_proof="$1" assessment_mode="${2:-device-full-wide-tun}"
  [[ "$assessment_mode" == device-full-wide-tun || "$assessment_mode" == full-wide-tun || "$assessment_mode" == wide-redirect-safe ]] || return 1
  python3 -I -c '
import ipaddress,json,os,pathlib,re,shutil,signal,stat,subprocess,sys
p=json.load(sys.stdin)
def need(ok,message):
    if not ok: raise SystemExit("Device host assessment: "+message)
def run(*args):
    # The NM helper has a 5s ownership lock plus a 30s plan budget. Give that
    # complete operation room to finish and reap its entire process group on
    # failure; killing just the shell would leave its read-only probes running.
    timeout=40 if len(args)==4 and args[0]=="bash" and args[2]=="assess-networkmanager" else 15
    child=subprocess.Popen(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        output,_=child.communicate(timeout=timeout)
        if child.returncode: raise subprocess.CalledProcessError(child.returncode,args)
        return output.strip()
    except BaseException:
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        child.communicate()
        raise
def active(unit): return subprocess.run(["systemctl","is-active","--quiet",unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
def enabled(unit): return subprocess.run(["systemctl","is-enabled","--quiet",unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
need(os.geteuid()==0 and sys.platform.startswith("linux"),"Linux root required")
for command in ("nft","ip","iptables","ip6tables","systemctl","ss","flock","curl","getent"):
    need(shutil.which(command),command+" is required; install it before arming")
need(pathlib.Path("/run/systemd/system").is_dir(),"systemd is not running")
need(run("stat","-f","-c","%T","/sys/fs/cgroup")=="cgroup2fs","cgroup v2 required")
def capture_prerequisites(mode):
    need(mode in ("device-full-wide-tun","full-wide-tun","wide-redirect-safe"),"invalid assessment mode")
    if mode!="wide-redirect-safe":
        need(pathlib.Path("/dev/net/tun").is_char_device(),"TUN device is unavailable")
        need(pathlib.Path("/proc/net/if_inet6").exists(),"IPv6 kernel support required")
    need(pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()=="0","forwarding host is unsupported")
    ipv6_forwarding=pathlib.Path("/proc/sys/net/ipv6/conf/all/forwarding")
    if ipv6_forwarding.exists():
        need(ipv6_forwarding.read_text().strip()=="0","forwarding host is unsupported")
    else:
        need(mode=="wide-redirect-safe" and not pathlib.Path("/proc/net/if_inet6").exists(),
             "IPv6 kernel policy is unavailable")
mode=sys.argv[4]
capture_prerequisites(mode)
for path in pathlib.Path("/sys/class/net").iterdir():
    need(not re.match(r"(?:docker|br-|cni|veth|virbr|flannel|kube)",path.name),"forwarding/container interfaces are unsupported")
for unit in ("docker.service","containerd.service","libvirtd.service","kubelet.service","firewalld.service","nftables.service"):
    need(not active(unit) and not enabled(unit),"active/enabled "+unit+" is unsupported")
managers=[u for u in ("NetworkManager.service","systemd-networkd.service","networking.service") if active(u) or enabled(u)]
need(len(managers)==1 and active(managers[0]),"exactly one active network manager required")
manager=managers[0]
# Readback of the real interface owning the pinned relay route; no DNS lookup.
host,port=p["relay_server"].rsplit(":",1);need(ipaddress.ip_address(host).version==4,"numeric IPv4 relay required")
routes=json.loads(run("ip","-j","route","get",host));need(len(routes)==1,"ambiguous relay route")
route=routes[0];uplink=route.get("dev","")
need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}",uplink) and uplink not in ("lo","aegis-tun0"),"unsupported uplink")
need(not sys.argv[1] or sys.argv[1]==uplink,"requested interface conflicts with actual relay route")
foreign=json.loads(run("bash",sys.argv[3],"assess-foreign-policy",uplink))
need(foreign.get("schema")=="aegis_foreign_policy_v1" and foreign.get("class")=="filter_only" and foreign.get("backend")=="nf_tables","foreign filtering policy refused")
for endpoint in p.get("relay_endpoints",[]):
    peer,peer_port=endpoint["server"].rsplit(":",1)
    need(ipaddress.ip_address(peer).version==4,"numeric IPv4 pool endpoint required")
    peer_routes=json.loads(run("ip","-j","route","get",peer))
    need(len(peer_routes)==1 and peer_routes[0].get("dev")==uplink,"relay pool spans unsupported uplinks")
addresses=json.loads(run("ip","-j","address","show","dev",uplink))[0]["addr_info"]
v4=[a for a in addresses if a["family"]=="inet" and a["scope"]=="global"]
need(len(v4)==1 and route.get("prefsrc",route.get("src"))==v4[0]["local"],"uplink needs one unambiguous IPv4 source")
v6=[a for a in addresses if a["family"]=="inet6" and a["scope"]=="global"]
need(len(v6)<=1,"multiple global IPv6 management addresses require explicit support")
dhcp4=bool(v4[0].get("dynamic",False));dhcp6=any(a.get("dynamic",False) for a in v6)
nm_policy=None
# Versioned manager binding supports networkd unicast renewal and address
# changes. Other dynamic manager layouts remain explicit unsupported cases.
if manager=="systemd-networkd.service":
    text=run("networkctl","status",uplink,"--no-pager")
    match=re.search(r"Network File:\s+(/[^\n]+)",text);need(match,"networkd effective file missing")
    roots=tuple(pathlib.Path(x) for x in ("/etc/systemd/network","/run/systemd/network","/usr/local/lib/systemd/network","/usr/lib/systemd/network","/lib/systemd/network"))
    config=pathlib.Path(match[1]);need(config.parent in roots and config.name.endswith(".network"),"unsupported effective networkd path")
    need(not re.search(r"(?m)^\s*Drop-In:",text),"networkd drop-in policy requires explicit support")
    # Fail before arm for unmerged drop-ins, including vendor/runtime overrides.
    # Do not infer DHCP=no from a base file whose effective policy is unknown.
    for directory in roots:
        if not directory.exists(): continue
        with os.scandir(directory) as entries:
            for index,entry in enumerate(entries):
                need(index<512,"networkd policy directory exceeds assessment bound")
                need(not entry.name.endswith(".network.d"),"networkd drop-in policy requires explicit support")
    for item in (config,*config.parents):
        st=item.lstat();need(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,"untrusted networkd file ancestry")
    fd=os.open(config,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as stream:
        metadata=os.fstat(stream.fileno());need(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1 and metadata.st_uid==0 and not metadata.st_mode&0o022 and metadata.st_size<=65536,"untrusted or oversized networkd file")
        data=stream.read(65537);need(len(data)<=65536,"networkd file changed beyond assessment bound")
    section=None;values=[]
    for raw in data.decode().splitlines():
        line=raw.strip()
        if not line or line.startswith(("#",";")): continue
        need(not line.endswith(chr(92)),"networkd continuation requires explicit support")
        if line.startswith("["):
            need(re.fullmatch(r"\[[A-Za-z0-9]+\]",line),"invalid networkd section")
            section=line[1:-1];continue
        key,separator,value=line.partition("=")
        need(section is not None and separator and re.fullmatch(r"[A-Za-z0-9]+",key.strip()),"invalid networkd assignment")
        if section=="Network" and key.strip()=="DHCP": values.append(value.strip().lower())
    need(len(values)<=1,"ambiguous DHCP policy")
    dhcp=values[0] if values else "no"
    need(dhcp in ("no","false","0","yes","true","1","ipv4","ipv6"),"unknown DHCP policy")
    effective4=dhcp in ("yes","true","1","ipv4");effective6=dhcp in ("yes","true","1","ipv6")
    need(not dhcp4 or effective4,"dynamic IPv4 address contradicts effective DHCP policy")
    dhcp4=effective4;dhcp6=effective6
elif manager=="NetworkManager.service":
    nm_policy=json.loads(run("bash",sys.argv[3],"assess-networkmanager",uplink))
    need(nm_policy.get("schema")=="aegis_networkmanager_assessment_v1","missing NetworkManager assessment")
    need(type(nm_policy.get("dhcp4")) is bool and type(nm_policy.get("dhcp6")) is bool,"invalid NetworkManager DHCP assessment")
    need(not dhcp4 or nm_policy["dhcp4"],"dynamic IPv4 contradicts assessed NetworkManager connection")
    dhcp4=nm_policy["dhcp4"];dhcp6=nm_policy["dhcp6"]
else:
    need(not dhcp4 and not dhcp6,"dynamic addressing on this manager needs a supported lease integration")
# Reassessing an already armed installation may observe its required UDP
# wildcard listener. Admit only sockets owned by the current exact service
# process; names such as "aegis-client" are not an authentication mechanism.
managed=None
state_path=pathlib.Path("/var/lib/aegis-install/client/device-guard.conf")
def root_file(path):
    path=pathlib.Path(path)
    for item in (path,*path.parents):
        st=item.lstat();need(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,"untrusted managed service input")
    return path
if state_path.exists() and active("aegis-client.service"):
    state_text=root_file(state_path).read_text()
    fields={}
    for line in state_text.splitlines():
        key,sep,value=line.partition("=");need(sep and key not in fields,"invalid managed guard state");fields[key]=value
    need(fields.get("schema") in ("aegis_device_guard_v1","aegis_device_guard_v2") and fields.get("armed")=="1" and fields.get("service")=="aegis-client.service","active client is not an armed device service")
    pid=run("systemctl","show","aegis-client.service","-p","MainPID","--value")
    cgroup=run("systemctl","show","aegis-client.service","-p","ControlGroup","--value")
    need(pid.isascii() and pid.isdecimal() and int(pid)>1 and cgroup.startswith("/") and cgroup!="/","invalid current service process")
    proc=pathlib.Path("/proc")/pid
    def process_identity():
        start=(proc/"stat").read_text().rsplit(")",1)[1].split()[19]
        actual=(proc/"cgroup").read_text().strip()
        executable=proc/"exe";installed=root_file("/usr/local/bin/aegis-client")
        need(executable.resolve()==installed and executable.stat().st_ino==installed.stat().st_ino and executable.stat().st_dev==installed.stat().st_dev,"service is not running the installed client")
        need(actual=="0::"+cgroup,"service cgroup mismatch")
        return start,actual,installed.stat().st_ino
    identity=process_identity();sockets={}
    for fd in (proc/"fd").iterdir():
        try: link=os.readlink(fd)
        except FileNotFoundError: continue
        match=re.fullmatch(r"socket:\[(\d+)\]",link)
        if match:sockets[int(fd.name)]=match[1]
    managed=(pid,identity,sockets)
def managed_listener(line,port,transport):
    if managed is None or (transport,port) not in (("tcp","15080"),("udp","15081")): return False
    pid,identity,sockets=managed
    inode=re.search(r"(?:^|\s)ino:(\d+)(?:\s|$)",line)
    owners=re.findall(r"pid=(\d+),fd=(\d+)",line)
    if not inode or not owners or any(owner!=pid or sockets.get(int(fd))!=inode[1] for owner,fd in owners): return False
    return process_identity()==identity
# The local resolver may listen for LLMNR on stock client images. Recognize
# its exact service-owned socket, but grant it no management port or outbound
# exemption: full-wide protection deliberately blocks local name discovery.
resolver_seen=None
def local_resolver_listener(line,port):
    global resolver_seen
    if port!="5355" or not active("systemd-resolved.service"): return False
    pid=run("systemctl","show","systemd-resolved.service","-p","MainPID","--value")
    if not pid.isascii() or not pid.isdecimal() or int(pid)<=1: return False
    proc=pathlib.Path("/proc")/pid
    installed=root_file(pathlib.Path("/usr/lib/systemd/systemd-resolved").resolve(strict=True))
    executable=proc/"exe"
    if executable.resolve()!=installed or executable.stat().st_ino!=installed.stat().st_ino or executable.stat().st_dev!=installed.stat().st_dev: return False
    if (proc/"cgroup").read_text().strip()!="0::/system.slice/systemd-resolved.service": return False
    start=(proc/"stat").read_text().rsplit(")",1)[1].split()[19]
    inode=re.search(r"(?:^|\s)ino:(\d+)(?:\s|$)",line)
    owners=re.findall(r"pid=(\d+),fd=(\d+)",line)
    if not inode or not owners: return False
    for owner,fd in owners:
        if owner!=pid or os.readlink(proc/"fd"/fd)!="socket:["+inode[1]+"]": return False
    current=(pid,start,installed.stat().st_ino)
    need(resolver_seen is None or resolver_seen==current,"resolver changed during assessment; retry")
    resolver_seen=current
    return True
# timesyncd uses an unconnected ephemeral UDP client socket, which ss -l
# also reports. Attest its owner instead of treating it as a public server.
# This only permits host assessment: it adds no native egress exemption.
timesync_seen=None
def timesync_listener(line,port):
    global timesync_seen
    if not port.isascii() or not port.isdecimal() or int(port)<=1023 or not active("systemd-timesyncd.service"): return False
    bounds=pathlib.Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
    if len(bounds)!=2 or not all(x.isascii() and x.isdecimal() for x in bounds): return False
    low,high=map(int,bounds)
    if not 1024<=low<=int(port)<=high<=65535: return False
    pid=run("systemctl","show","systemd-timesyncd.service","-p","MainPID","--value")
    if not pid.isascii() or not pid.isdecimal() or int(pid)<=1: return False
    proc=pathlib.Path("/proc")/pid
    installed=root_file(pathlib.Path("/usr/lib/systemd/systemd-timesyncd").resolve(strict=True))
    executable=proc/"exe"
    identity=(installed.stat().st_dev,installed.stat().st_ino)
    if executable.resolve()!=installed or (executable.stat().st_dev,executable.stat().st_ino)!=identity: return False
    if (proc/"cgroup").read_text().strip()!="0::/system.slice/systemd-timesyncd.service": return False
    start=(proc/"stat").read_text().rsplit(")",1)[1].split()[19]
    inode=re.search(r"(?:^|\s)ino:(\d+)(?:\s|$)",line)
    owners=re.findall(r"pid=(\d+),fd=(\d+)",line)
    if not inode or not owners: return False
    for owner,fd in owners:
        if owner!=pid or os.readlink(proc/"fd"/fd)!="socket:["+inode[1]+"]": return False
    current=(pid,start,identity)
    need(timesync_seen is None or timesync_seen==current,"timesyncd changed during assessment; retry")
    timesync_seen=current
    return True
def listener_address(local):
    address, separator, port = local.rpartition(":")
    need(separator == ":" and port.isascii() and port.isdecimal() and
         1 <= int(port) <= 65535, "unrecognized listener address")
    # ss prints scoped IPv6 as [fe80::... ]%interface:port. Strip the
    # interface before the display brackets; the address remains validated.
    address = address.split("%", 1)[0]
    if address.startswith("["):
        need(address.endswith("]"), "unrecognized listener address")
        address = address[1:-1]
    need(address == "*" or ipaddress.ip_address(address),
         "unrecognized listener address")
    return address, port
ports=set()
for line in run("ss","-H","-ltnpe").splitlines():
    fields=line.split();need(len(fields)>=5,"unrecognized TCP listener record")
    address,port=listener_address(fields[3])
    if address not in ("*","0.0.0.0","::") and ipaddress.ip_address(address).is_loopback: continue
    if managed_listener(line,port,"tcp") or local_resolver_listener(line,port): continue
    need("\"sshd\"" in line or ("\"systemd\"" in line and active("ssh.socket")),"non-SSH public listener is unsupported")
    ports.add(int(port))
need(len(ports)<=8,"too many management ports")
# Existing unrelated UDP services must not be silently disconnected. Only
# attested local clients and DHCP bootstrap sockets fit this local-host mode.
for line in run("ss","-H","-lunpe").splitlines():
    fields=line.split();need(len(fields)>=5,"unrecognized UDP listener record")
    address,port=listener_address(fields[3])
    if address not in ("*","0.0.0.0","::") and ipaddress.ip_address(address).is_loopback: continue
    if managed_listener(line,port,"udp") or local_resolver_listener(line,port) or timesync_listener(line,port): continue
    need((port=="68" and dhcp4 or port=="546" and dhcp6) and ((manager=="systemd-networkd.service" and "systemd-network" in line) or (manager=="NetworkManager.service" and "NetworkManager" in line)),"non-bootstrap public UDP listener is unsupported")
if timesync_seen is not None:
    pid,start,identity=timesync_seen
    proc=pathlib.Path("/proc")/pid
    executable=proc/"exe"
    need(executable.resolve()==pathlib.Path("/usr/lib/systemd/systemd-timesyncd").resolve(strict=True) and (executable.stat().st_dev,executable.stat().st_ino)==identity,"timesyncd executable changed during assessment; retry")
    need(run("systemctl","show","systemd-timesyncd.service","-p","MainPID","--value")==pid and (proc/"stat").read_text().rsplit(")",1)[1].split()[19]==start and (proc/"cgroup").read_text().strip()=="0::/system.slice/systemd-timesyncd.service","timesyncd changed during assessment; retry")
    print("Device host assessment: timesyncd receives no native egress exemption",file=sys.stderr)
if resolver_seen is not None:
    pid,start,inode=resolver_seen
    executable=pathlib.Path("/proc")/pid/"exe"
    need(executable.resolve()==pathlib.Path("/usr/lib/systemd/systemd-resolved").resolve(strict=True) and executable.stat().st_ino==inode,"resolver executable changed during assessment; retry")
    need(run("systemctl","show","systemd-resolved.service","-p","MainPID","--value")==pid and (pathlib.Path("/proc")/pid/"stat").read_text().rsplit(")",1)[1].split()[19]==start,"resolver changed during assessment; retry")
    print("Device host assessment: local LLMNR discovery will be blocked while protection is armed",file=sys.stderr)
if managed is not None:
    need(run("systemctl","show","aegis-client.service","-p","MainPID","--value")==managed[0] and process_identity()==managed[1],"client changed during host assessment; retry")
boot=json.loads(sys.argv[2]);need(boot["initramfs_network"]=="absent_verified","boot assessment missing")
schema="aegis_device_guard_v2" if manager in ("systemd-networkd.service","NetworkManager.service") else "aegis_device_guard_v1"
address_policy="management_address_policy=current_local" if schema=="aegis_device_guard_v2" else "management_ipv4="+v4[0]["local"]+"\nmanagement_ipv6="+(v6[0]["local"] if v6 else "")
if nm_policy is not None:
    for name in ("manager_connection_uuid","manager_ipv4_method","manager_ipv6_method"):
        value=nm_policy.get(name)
        pattern=r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}" if name.endswith("uuid") else r"auto|manual" if name=="manager_ipv4_method" else r"auto|dhcp|manual|disabled|ignore|link-local"
        need(type(value) is str and re.fullmatch(pattern,value),"invalid NetworkManager policy field")
        print(name+"="+value)
profile="" if mode=="device-full-wide-tun" else "\ncapture_profile="+mode
print("schema="+schema+"\narmed=1\nservice=aegis-client.service\nuplink="+uplink+"\nmanager="+manager+"\ncapture_interface=aegis-tun0\n"+address_policy+"\nmanagement_ports="+",".join(str(x) for x in sorted(ports))+"\ndhcp4="+str(int(dhcp4))+"\ndhcp6="+str(int(dhcp6))+"\ninitramfs_network=absent_verified\nforeign_policy="+foreign["class"]+"\nufw_integrity_sha256="+foreign["ufw_integrity_sha256"]+profile)
print("Device host assessment: "+manager+" / "+uplink+" / initrd "+boot["initrd_sha256"],file=sys.stderr)
' "$WIDE_INTERFACE" "$boot_proof" "$ROOT/scripts/aegis-device-egress-guard.sh" "$assessment_mode"
}

stage_auto_device_owner_admit() {
  # The receipt identifies a production source-rendered owner generation. All
  # files, their ancestry and PID1 are checked again while InstallLock is held.
  python3 -I - "$STAGE_AUTO_OWNER_RECEIPT" "$ROOT" "$PREFLIGHT_CLIENT_BINARY" <<'PY_STAGE_OWNER'
import hashlib,json,os,pathlib,re,select,stat,subprocess,sys,time
receipt_path=pathlib.Path(sys.argv[1]); source=pathlib.Path(sys.argv[2]); candidate=pathlib.Path(sys.argv[3])
def need(ok):
    if not ok: raise SystemExit('staged AUTO owner/source/PID1 admission refused')
def read(path,limit,mode):
    need(path.is_absolute() and '..' not in path.parts)
    parent=path.parent
    while parent!=pathlib.Path('/'):
        metadata=parent.lstat()
        need(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==0 and not metadata.st_mode & 0o022)
        parent=parent.parent
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==mode)
    data=path.read_bytes(); need(len(data)<=limit); return data
def sha(data): return hashlib.sha256(data).hexdigest()
def call(*argv):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,check=False,text=True)
    need(result.returncode==0 and len(result.stdout)<65536); return result.stdout
need(os.geteuid()==0 and receipt_path==pathlib.Path('/var/lib/aegis-install/client/auto-stage-owner.json'))
receipt=json.loads(read(receipt_path,65536,0o600))
need(receipt.get('schema')=='aegis_auto_stage_owner_v1')
installed=pathlib.Path(receipt['installed_binary']); config=pathlib.Path(receipt['config_path'])
need(installed.name=='aegis-client')
need(receipt.get('state_dir')=='/var/lib/aegis-client' and receipt.get('runtime_events_path')=='/var/lib/aegis-client/runtime-events.jsonl')
client_sha=receipt.get('installed_binary_sha256')
need(isinstance(client_sha,str) and re.fullmatch('[a-f0-9]{64}',client_sha) is not None)
need(sha(read(installed,512*1024*1024,0o555))==client_sha and sha(candidate.read_bytes())==client_sha)
need(sha(read(config,1<<20,0o600))==receipt.get('config_sha256'))
template_name='packaging/systemd/aegis-client.service'; env_name='packaging/env/aegis-client.env.example'
template=(source/template_name).read_bytes(); env=(source/env_name).read_bytes()
need(sha(template)==receipt.get('source_template_sha256') and sha(env)==receipt.get('source_env_sha256'))
need(not any(x in str(config)+str(installed) for x in ('\n','\r','\x00',' ')))
render=template.decode()
for marker,value,count in (
    ('__AEGIS_CLIENT_ENV_FILE__','/etc/default/aegis-client',1),
    ('__AEGIS_CLIENT_STATE_DIR__','/var/lib/aegis-client',2),
    ('__AEGIS_CLIENT_BIN__',str(installed),1),
    ('__AEGIS_CLIENT_CONFIG__',str(config),1),
    ('__AEGIS_CLIENT_RUNTIME_EVENTS_JSONL__','/var/lib/aegis-client/runtime-events.jsonl',1)):
    need(render.count(marker)==count); render=render.replace(marker,value)
need('__AEGIS_' not in render)
unit=pathlib.Path('/etc/systemd/system/aegis-client.service'); env_path=pathlib.Path('/etc/default/aegis-client')
need(sha(read(unit,1<<20,0o644))==sha(render.encode())==receipt.get('base_unit_sha256'))
need(sha(read(env_path,1<<20,0o644))==sha(env)==receipt.get('environment_sha256'))
need(receipt.get('user')=='aegis-svc' and type(receipt.get('uid')) is int and type(receipt.get('gid')) is int)
nss={}
raw=read(pathlib.Path('/etc/nsswitch.conf'),1<<20,0o644)
need(all(value in (9,10,13) or 32<=value<=126 for value in raw))
for row in raw.decode('ascii').splitlines():
    line=row.strip()
    if not line or line.startswith('#'): continue
    need(not row[:1].isspace() and not row.endswith('\\'))
    key,sep,value=line.partition(':'); need(sep)
    if key.strip() in ('passwd','group','initgroups'):
        need(key==key.strip())
        tokens=value.split()
        tokens=tokens[:next((i for i,token in enumerate(tokens) if token.startswith('#')),len(tokens))]
        need(key not in nss and tokens in (['files'],['files','systemd'])); nss[key]=True
need(nss.get('passwd') and nss.get('group'))
nss_query='''import json,os,pwd,grp
u=pwd.getpwnam("aegis-svc"); g=grp.getgrnam("aegis-svc")
print(json.dumps({"name":u.pw_name,"uid":u.pw_uid,"gid":u.pw_gid,"home":u.pw_dir,
"shell":u.pw_shell,"group":g.gr_name,"group_gid":g.gr_gid,"members":g.gr_mem,
"reverse_user":pwd.getpwuid(u.pw_uid).pw_name,
"reverse_group":grp.getgrgid(g.gr_gid).gr_name,
"groups":os.getgrouplist("aegis-svc",u.pw_gid)},separators=(",",":")))'''
lookup=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',nss_query],stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
try:
    output=bytearray(); deadline=time.monotonic()+3
    while True:
        remaining=deadline-time.monotonic(); need(remaining>0)
        ready,_,_=select.select([lookup.stdout.fileno()],[],[],remaining); need(ready)
        chunk=os.read(lookup.stdout.fileno(),min(2049-len(output),4096))
        if not chunk: break
        output.extend(chunk); need(len(output)<=2048)
    need(lookup.wait(timeout=1)==0)
finally:
    if lookup.poll() is None:
        lookup.kill(); lookup.wait(timeout=1)
    lookup.stdout.close()
user=json.loads(output)
need(type(user) is dict and set(user)=={'name','uid','gid','home','shell','group',
     'group_gid','members','reverse_user','reverse_group','groups'})
need(user['name']==user['group']==user['reverse_user']==user['reverse_group']=='aegis-svc' and
     type(user['uid']) is int and type(user['gid']) is int and
     0<user['uid']<1000 and 0<user['gid']<1000 and
     (user['uid'],user['gid'],user['group_gid'])==(receipt['uid'],receipt['gid'],receipt['gid']) and
     user['home']=='/var/lib/aegis-client' and user['shell']=='/usr/sbin/nologin' and
     user['members']==[] and user['groups']==[user['gid']])
passwd_rows=[line.split(':') for line in read(pathlib.Path('/etc/passwd'),1<<20,0o644).decode('utf-8').splitlines()
             if line and not line.startswith('#')]
group_rows=[line.split(':') for line in read(pathlib.Path('/etc/group'),1<<20,0o644).decode('utf-8').splitlines()
            if line and not line.startswith('#')]
def decimal(value):
    need(re.fullmatch(r'[0-9]+',value) is not None)
    number=int(value); need(number<=0xffffffff); return number
need(sum(row[0]=='aegis-svc' for row in passwd_rows)==1 and
     sum(row[0]=='aegis-svc' for row in group_rows)==1 and
     all(len(row)==7 for row in passwd_rows) and all(len(row)==4 for row in group_rows))
accounts=[(row,decimal(row[2]),decimal(row[3])) for row in passwd_rows]
groups=[(row,decimal(row[2])) for row in group_rows]
own=next(entry for entry in accounts if entry[0][0]=='aegis-svc')
own_group=next(entry for entry in groups if entry[0][0]=='aegis-svc')
need(own[1:]==(user['uid'],user['gid']) and
     own[0][5:]==['/var/lib/aegis-client','/usr/sbin/nologin'] and
     own_group[1]==user['gid'] and own_group[0][3]=='' and
     all(row[0]=='aegis-svc' or uid!=user['uid'] for row,uid,_gid in accounts) and
     all(row[0]=='aegis-svc' or gid!=user['gid'] or row[0]=='root' and uid==0
         for row,uid,gid in accounts) and
     all(row[0]=='aegis-svc' or gid!=user['gid'] for row,gid in groups) and
     all(row[0]=='aegis-svc' or 'aegis-svc' not in row[3].split(',') for row,gid in groups))
need(raw==read(pathlib.Path('/etc/nsswitch.conf'),1<<20,0o644))
state=pathlib.Path('/var/lib/aegis-client').lstat()
need(stat.S_ISDIR(state.st_mode) and state.st_uid==0 and state.st_gid==user['gid'] and stat.S_IMODE(state.st_mode)==0o750)
properties=dict(line.split('=',1) for line in call('systemctl','show','aegis-client.service','-p','ActiveState','-p','SubState','-p','MainPID','-p','ControlPID','-p','ControlGroup','-p','NeedDaemonReload','-p','FragmentPath','-p','DropInPaths').splitlines())
need(properties.get('ActiveState')=='inactive' and properties.get('SubState')=='dead' and properties.get('MainPID')=='0' and properties.get('ControlPID')=='0')
need(properties.get('ControlGroup') in ('',None) and properties.get('NeedDaemonReload')=='no' and properties.get('FragmentPath')==str(unit))
dropins=properties.get('DropInPaths','').split()
need(dropins in ([],['/etc/systemd/system/aegis-client.service.d/30-device-egress-guard.conf']))
if dropins: read(pathlib.Path(dropins[0]),1<<20,0o644)
need(not call('systemctl','list-units','--all','--plain','--no-legend','--no-pager','aegis-auto@*.service').strip())
jobs=call('systemctl','list-jobs','--plain','--no-legend','--no-pager')
need('aegis-client.service' not in jobs and re.search(r'aegis-auto@[0-9a-f]{64}\.service',jobs) is None)
print(str(installed))
PY_STAGE_OWNER
}

stage_auto_device_owner_binary() {
  python3 -I - "$STAGE_AUTO_OWNER_RECEIPT" <<'PY_STAGE_BINARY'
import json,pathlib,stat,sys
path=pathlib.Path(sys.argv[1])
assert path==pathlib.Path('/var/lib/aegis-install/client/auto-stage-owner.json')
info=path.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
receipt=json.loads(path.read_bytes())
assert receipt.get('schema')=='aegis_auto_stage_owner_v1'
binary=receipt.get('installed_binary')
assert isinstance(binary,str) and binary.startswith('/') and '\n' not in binary and '\x00' not in binary
print(binary)
PY_STAGE_BINARY
}

stage_auto_install_lock_acquire() {
  local lock=/run/aegis-auto-install.lock
  umask 077
  python3 -I - "$lock" <<'PY_STAGE_LOCK' || return 1
import pathlib,stat,sys
path=pathlib.Path(sys.argv[1]); parent=path.parent.lstat()
assert stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode & 0o022
if path.exists() or path.is_symlink():
    info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
PY_STAGE_LOCK
  exec {STAGE_AUTO_INSTALL_LOCK_FD}<>"$lock" || return 1
  flock -x -w 5 "$STAGE_AUTO_INSTALL_LOCK_FD" || {
    printf '%s\n' 'AUTO_V2_INSTALL_REFUSED phase=install_lock_timeout' >&2
    return 1
  }
  python3 -I - "$lock" "$STAGE_AUTO_INSTALL_LOCK_FD" <<'PY_STAGE_LOCK_HELD' || return 1
import fcntl,os,pathlib,stat,sys
path=pathlib.Path(sys.argv[1]); fd=int(sys.argv[2]); a=os.fstat(fd); b=path.lstat()
assert stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600
assert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
PY_STAGE_LOCK_HELD
}

install_device_full_wide_role() {
  local prefix="$1" config_root="$2" state_dir="$3" log_dir="$4" runtime_events_path="$5" existing_choice="$6" stage_auto="${7:-0}"
  local metadata=/var/lib/aegis-install/client state=/var/lib/aegis-install/client/device-guard.conf
  local bin_path=/usr/local/bin/aegis-client helper_dir=/usr/local/lib/aegis/helpers
  local assessment stage old_state='' candidate="$PREFLIGHT_CLIENT_BINARY"
  [[ "$(detect_os_kind)" == linux && ${EUID} -eq 0 && "$prefix" == /usr/local &&
     "$config_root" == /etc/aegis/client && "$state_dir" == /var/lib/aegis-client &&
     "$log_dir" == /var/log/aegis-client && "$SYSTEMD_DIR" == /etc/systemd/system &&
     "$ENV_DIR" == /etc/default ]] || {
    echo 'Device full-wide requires Linux root and the standard system installation paths.' >&2; return 1;
  }
  systemd_activation_requested || {
    echo 'Device enrollment is ready, but full-wide installation requires systemd activation; nothing was armed.' >&2; return 1;
  }
  device_relay_geneva_absent || return 1
  if [[ "$stage_auto" == 1 ]]; then
    [[ "$DEVICE_BUNDLE_SCHEMA" == aegis_device_bundle_v2 && "$DEVICE_ONLINE" == 0 && "$existing_choice" != reinstall ]] || return 1
    stage_auto_device_owner_admit >/dev/null || return 1
  fi
  # Observe before replacing any installed binary, config, unit or working
  # service. No shared-token auto planner or legacy cleanup runs in this branch.
  assessment="$(device_assess_full_wide_host "$DEVICE_PUBLIC_BUNDLE" "$candidate")" || return 1
  install_atomic_write "$metadata/device-assessment.conf" 0600 strict validate </dev/null || return 1
  stage="$(mktemp -d "$metadata/.device-preflight.XXXXXXXX")" || return 1
  TEMP_PATHS+=("$stage")
  printf '%s\n' "$assessment" | install_atomic_write "$stage/assessment.conf" 0600 strict || return 1
  # Freeze the executable for actual root-state validation; an in-tree build
  # can be user-owned and must not become the administrator-state authority.
  install -m 0755 "$candidate" "$stage/aegis-client" || return 1
  export AEGIS_ROOT_STATE_CLIENT="$stage/aegis-client"
  install_copy_file "$DEVICE_PUBLIC_BUNDLE/outer-ca.pem" "$stage/ca.pem" 0600 || return 1
  install_copy_file "$DEVICE_PUBLIC_BUNDLE/inner-ca.pem" "$stage/inner-ca.pem" 0600 || return 1
  device_bundle_render "$AEGIS_ROOT_STATE_CLIENT" --bundle-dir "$DEVICE_PUBLIC_BUNDLE" --identity-dir "$DEVICE_IDENTITY_DIR" \
    --config-dir "$stage" --output "$stage/check.toml" || return 1
  inject_client_service_state_path "$stage/check.toml" "$state_dir" || return 1
  device_validate_config "$AEGIS_ROOT_STATE_CLIENT" "$stage/check.toml" >/dev/null || return 1
  AEGIS_DEVICE_GUARD_STATE="$stage/assessment.conf" bash "$ROOT/scripts/aegis-device-egress-guard.sh" preflight || return 1
  # Existing protected installations stay blocked throughout replacement. A
  # generic reinstall/purge would release native egress and is never called.
  "$AEGIS_ROOT_STATE_CLIENT" profile metadata validate --path "$state" || return 1
  if [[ -e "$state" ]]; then
    old_state="$("$AEGIS_ROOT_STATE_CLIENT" profile metadata read --path "$state")" || return 1
    if [[ "$old_state" == *$'\narmed=1\n'* || "$old_state" == *$'\narmed=1' ]]; then
      AEGIS_DEVICE_GUARD_STATE="$state" bash "$helper_dir/aegis-device-egress-guard.sh" block || return 1
      systemctl stop aegis-client.service || return 1
      ! systemctl is-active --quiet aegis-client.service || return 1
    elif [[ -e "$SYSTEMD_DIR/aegis-device-egress-guard.service" ]]; then
      echo 'Interrupted explicit recovery must finish before a new device installation.' >&2; return 1
    fi
  elif [[ "$stage_auto" != 1 && ( -e "$config_root/aegis.toml" || -e "$SYSTEMD_DIR/aegis-client.service" ) ]]; then
    echo 'An existing installation without a device guard requires explicit migration/recovery before full-wide enrollment.' >&2; return 1
  fi
  # Assessment and candidate config are valid. Preserve the existing device key
  # even for --reinstall; only managed executable/config/unit assets are replaced.
  [[ "$existing_choice" != reinstall ]] || echo 'Device reinstall retains the enrolled identity and persistent guard.' >&2
  FORCE=1
  AEGIS_WIDE_LIB_DIR="$helper_dir"
  prepare_client_config_boundary "$config_root" || return 1
  ensure_dir "$prefix/bin" || return 1
  ensure_dir "$state_dir" || return 1
  ensure_dir "$log_dir" || return 1
  install_copy_file "$stage/aegis-client" "$bin_path" 0755 || return 1
  export AEGIS_ROOT_STATE_CLIENT="$bin_path"
  install_client_wide_helpers "$helper_dir" || return 1
  if [[ "$stage_auto" != 1 ]]; then
    install_client_service_assets "$bin_path" "$config_root/aegis.toml" "$state_dir" "$runtime_events_path" "$log_dir" || return 1
  fi
  # Enable without starting: the guard transaction supplies the first start,
  # Type=notify readiness and strict service-cgroup capture binding.
  if [[ "$stage_auto" != 1 ]]; then
    systemctl enable aegis-client.service || return 1
  fi
  printf '%s\n' "$assessment" | install_atomic_write "$metadata/device-assessment.conf" 0600 strict || return 1
  DEVICE_GUARD_ASSESSMENT="$metadata/device-assessment.conf"
  if ! activate_device_full_wide_capture "$DEVICE_PUBLIC_BUNDLE" "$DEVICE_IDENTITY_DIR" "$config_root/aegis.toml" "$DEVICE_GUARD_ASSESSMENT" "$stage_auto"; then
    echo 'Device installation did not complete; enrolled identity and any armed block were retained.' >&2; return 1
  fi
  if [[ "$stage_auto" == 1 ]]; then
    echo 'Device guard staged and armed for AUTO; runtime has not been activated.'
    return 0
  fi
  RES_UDP_POLICY=masque_direct RES_DNS_POLICY=preview RES_IPV6_POLICY=tun_carried RES_LEAK_RISK=low
  WIDE_INTERFACE="$(printf '%s\n' "$assessment" | sed -n 's/^uplink=//p')"
  record_product_mode "$state_dir" || return 1
  write_install_manifest client "$metadata/install-manifest.json" "$bin_path" || return 1
  echo 'Device full-wide installation completed with inner TLS, verified readiness and persistent capture.'
}

# The public device bundle has no client TOML. AUTO V2 accepts a captured
# configuration bundle, so render the already enrolled device with the product
# CLI and adapt only its two CA references to V2's source-to-final mapping.
# The device certificate and key keep their original protected identity paths.
auto_v2_device_input() {
  local client="$1" public_bundle="$2" identity="$3" config_root="$4" stage="" snapshot=""
  [[ "$AUTO_PROFILE" == 1 && "$DEVICE_PRODUCT_MODE" == full-wide-tun &&
     "$DEVICE_BUNDLE_SCHEMA" == aegis_device_bundle_v2 && "$DEVICE_ONLINE" == 0 &&
     "$config_root" == /etc/aegis/client ]] || return 1
  "$client" device bundle-ready --bundle-dir "$public_bundle" \
    --identity-dir "$identity" --device-id "$DEVICE_ID" >/dev/null || return 1
  # Keep the disposable rendering outside guardian metadata. Fresh passive
  # admission requires that metadata namespace to be empty before its intent.
  [[ -n "${STAGE_AUTO_INSTALL_LOCK_FD:-}" ]] || return 1
  python3 -I - <<'PY_AUTO_DEVICE_INPUT_DIR' || return 1
import os, pathlib, stat
base = pathlib.Path('/var/lib/aegis-auto')
info = base.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
assert stat.S_IMODE(info.st_mode) == 0o700
fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    child = 'device-inputs'
    try:
        os.mkdir(child, 0o700, dir_fd=fd)
        os.fsync(fd)
    except FileExistsError:
        pass
    child_fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        info = os.fstat(child_fd)
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
        assert stat.S_IMODE(info.st_mode) == 0o700
        assert not os.listdir(child_fd)
    finally:
        os.close(child_fd)
finally:
    os.close(fd)
PY_AUTO_DEVICE_INPUT_DIR
  stage="$(umask 077; mktemp -d /var/lib/aegis-auto/device-inputs/.auto-device-input.XXXXXXXX)" || return 1
  TEMP_PATHS+=("$stage")
  snapshot="$stage/public"
  mkdir -m 0700 "$snapshot" || return 1
  local member=""
  for member in bundle.json outer-ca.pem inner-ca.pem device-ca.pem; do
    install_copy_file "$public_bundle/$member" "$snapshot/$member" 0600 || return 1
  done
  # The enrolled identity pins the four-member public profile. Render only
  # from this root-owned snapshot so later changes to the operator path cannot
  # mix CA bytes with a different profile between the two consumers.
  "$client" device bundle-ready --bundle-dir "$snapshot" \
    --identity-dir "$identity" --device-id "$DEVICE_ID" >/dev/null || return 1
  install_copy_file "$snapshot/outer-ca.pem" "$stage/ca.pem" 0600 || return 1
  install_copy_file "$snapshot/inner-ca.pem" "$stage/inner-ca.pem" 0600 || return 1
  device_bundle_render "$client" --bundle-dir "$snapshot" --identity-dir "$identity" \
    --config-dir "$config_root" --output "$stage/rendered.toml" >/dev/null || return 1
  python3 -I -B - "$stage/rendered.toml" "$stage/aegis-client.toml" \
    "$config_root" "$identity" <<'PY_AUTO_DEVICE_INPUT' || return 1
import copy, os, pathlib, re, stat, sys, tomllib
source, target, config, identity = map(pathlib.Path, sys.argv[1:])
def need(value):
    if not value:
        raise SystemExit('AUTO device configuration admission refused')
need(config == pathlib.Path('/etc/aegis/client') and identity.is_absolute())
info = source.lstat()
need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
     info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
     0 < info.st_size <= 4 * 1024 * 1024)
raw = source.read_bytes()
need(len(raw) == info.st_size and b'\r' not in raw)
text = raw.decode('utf-8')
before = tomllib.loads(text)
relay = before['relay']; inner = relay['inner_tls']
need(before['mode'] == 'relay' and relay['auth_token'] == '' and
     relay['ca_cert'] == str(config / 'ca.pem') and
     inner['server_ca'] == str(config / 'inner-ca.pem') and
     inner['cert'] == str(identity / 'device.pem') and
     inner['key'] == str(identity / 'device.key') and
     relay['transport_priority'] == ['grpc_stream'] and
     relay['udp_transport_priority'] == ['grpc_datagram'])
after = copy.deepcopy(before)
after['relay']['ca_cert'] = 'ca.pem'
after['relay']['inner_tls']['server_ca'] = 'inner-ca.pem'
section = None
seen = set()
lines = []
for line in text.splitlines(keepends=True):
    stripped = line.strip()
    if stripped.startswith('['):
        need(bool(re.fullmatch(r'\[[A-Za-z0-9_.-]+\]', stripped)))
        section = stripped[1:-1]
    key, separator, value = line.partition('=')
    field = (section, key.strip())
    if separator and field in {('relay', 'ca_cert'), ('relay.inner_tls', 'server_ca')}:
        need(field not in seen and tomllib.loads('v=' + value)['v'] ==
             str(config / ('ca.pem' if field[1] == 'ca_cert' else 'inner-ca.pem')))
        seen.add(field)
        line = key + '= "' + ('ca.pem' if field[1] == 'ca_cert' else 'inner-ca.pem') + '"\n'
    lines.append(line)
need(seen == {('relay', 'ca_cert'), ('relay.inner_tls', 'server_ca')})
adapted = ''.join(lines)
need(tomllib.loads(adapted) == after)
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(adapted.encode('utf-8'))
    output.flush()
    os.fsync(output.fileno())
PY_AUTO_DEVICE_INPUT
  device_validate_config "$client" "$stage/aegis-client.toml" >/dev/null || return 1
  AUTO_V2_DEVICE_INPUT_PATH="$stage"
}

# AUTO V2 owns config/state/unit publication and activation. This dispatcher
# must be entered before any legacy custody, purge, manifest or service write.
auto_v2_retain_public_payload() {
  python3 -I - "$ROOT" "$SOURCE_LAYOUT" "$PREFLIGHT_CLIENT_BINARY" <<'PY_AUTO_RETAIN_PAYLOAD'
import hashlib,json,os,pathlib,re,secrets,stat,sys
source=pathlib.Path(sys.argv[1])
source_layout=sys.argv[2]=='1'
source_uid=source.stat().st_uid if source_layout else 0
source_candidate=pathlib.Path(sys.argv[3])
def need(ok):
    if not ok: raise SystemExit('AUTO retained administrative payload refused')
def unique(pairs):
    result={}
    for key,value in pairs:
        need(key not in result);result[key]=value
    return result
def open_directory(parent,name,source_input=False):
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    info=os.fstat(fd)
    need(info.st_uid in ({0,source_uid} if source_input else {0}) and not info.st_mode&0o022 and (source_input or info.st_gid==0))
    return fd
def ancestry(path,create=False,source_input=False):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            need(part not in ('','..','.'))
            if create:
                try: os.mkdir(part,0o700,dir_fd=fd);os.fsync(fd)
                except FileExistsError: pass
            child=open_directory(fd,part,source_input);os.close(fd);fd=child
        return fd
    except BaseException: os.close(fd);raise
source_fd=ancestry(source,source_input=source_layout)
try:
    try: manifest_fd=os.open('bundle.manifest.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=source_fd)
    except FileNotFoundError: manifest_fd=None
    expected_source=None
    if manifest_fd is not None:
        try:
            info=os.fstat(manifest_fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022 and 0<info.st_size<=4<<20)
            manifest=os.read(manifest_fd,(4<<20)+1)
            need(len(manifest)==info.st_size)
        finally: os.close(manifest_fd)
        document=json.loads(manifest,object_pairs_hook=unique)
        need(document.get('schema')=='aegis_release_bundle_manifest_v2')
        files=document.get('files')
        need(type(files) is list and 1<=len(files)<=4096 and all(type(item) is str for item in files) and len(files)==len(set(files)))
        files=set(files)|{'bundle.manifest.json','SHA256SUMS'}
        generation=hashlib.sha256(manifest).hexdigest()
    else:
        # Retain only public installer source assets, never the checkout's
        # credentials, artifacts, Git database or build/cache directories.
        # Provenance remains absent-manifest source layout, not a new release.
        need(source_layout)
        files={'install.sh','bin/aegis-client'}
        for name in ('setup-wide-linux-redirect.sh','setup-wide-linux-tproxy.sh','setup-wide-linux-nfqueue.sh',
                     'aegis-wide-enable.sh','aegis-wide-disable.sh','aegis-wide-persist-install.sh',
                     'purge-installed-aegis.sh','aegis-ubuntu-uninstall.sh','janitor-wide-linux-tproxy.sh',
                     'aegis-rpi-gateway.sh','aegis-device-egress-guard.sh','lib/root-state.sh'):
            if (source/'scripts'/name).exists(): files.add('scripts/'+name)
        for name in ('aegis_installer_auto_v2','aegis_auto_capture','aegis_auto_capture_topology',
                     'aegis_auto_endpoint','aegis_auto_guard_policy','aegis_auto_guardian',
                     'aegis_auto_guardian_watchdog','aegis_auto_terminal_witness',
                     'aegis_auto_terminal_boot_store','aegis_auto_terminal_register',
                     'aegis_auto_boot_transition','aegis_auto_launch','aegis_auto_native_witness',
                     'aegis_auto_sink','aegis_auto_trace_rollback','aegis_auto_witness_topology'):
            files.add('scripts/lib/'+name+'.py')
        files.add('packaging/systemd/system-shutdown/aegis-auto-terminal-hook')
        files.add('packaging/env/aegis-client.env.example')
        for name in ('aegis-client.service','aegis-auto-config.service','aegis-auto-capture-topology.service',
                     'aegis-auto-guardian-watchdog.service','aegis-auto-guardian.service',
                     'aegis-auto-terminal-a@.service','aegis-auto-terminal-b@.service',
                     'aegis-auto-terminal-observer.service',
                     'aegis-auto-terminal-transition.service',
                     'aegis-auto-trace-rollback-actor.service','aegis-auto-trace-rollback.service',
                     'aegis-auto-trace-rollback.timer','aegis-auto-witness-topology.service',
                     'aegis-auto-clean-shutdown.service',
                     'aegis-device-dhcp-refresh.service',
                     'aegis-device-dhcp-refresh.timer'):
            files.add('packaging/systemd/'+name)
        need(len(files)<=4096)
        expected_source={}
        for name in sorted(files):
            path=source_candidate if name=='bin/aegis-client' else source/name
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid in (0,source_uid) and not info.st_mode&0o022 and info.st_size<=512<<20)
                digest=hashlib.sha256();count=0
                while True:
                    block=os.read(fd,65536)
                    if not block: break
                    count+=len(block);need(count<=info.st_size);digest.update(block)
                need(count==info.st_size);expected_source[name]=digest.hexdigest()
            finally: os.close(fd)
        generation='source-'+hashlib.sha256(json.dumps(expected_source,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        document=None
    need({'bin/aegis-client','install.sh','packaging/systemd/aegis-client.service','packaging/env/aegis-client.env.example'}<=files)
    destination=pathlib.Path('/var/lib/aegis-auto/releases')/generation
    target_fd=ancestry(destination,create=True)
    total=0;digests={}
    try:
        # The manifest is published last. A partial copy cannot be mistaken
        # for a complete release; conflicting retained bytes always refuse.
        ordered=sorted(files-{'bundle.manifest.json'})+(['bundle.manifest.json'] if document is not None else [])
        for name in ordered:
            parts=name.split('/')
            need(all(part not in ('','..','.') and not any(ord(c)<32 for c in part) for part in parts) and not name.startswith('/'))
            original=os.dup(source_fd);parent=os.dup(target_fd)
            try:
                for part in parts[:-1]:
                    if not (source_layout and name=='bin/aegis-client'):
                        child=open_directory(original,part,source_layout);os.close(original);original=child
                    try: os.mkdir(part,0o700,dir_fd=parent);os.fsync(parent)
                    except FileExistsError: pass
                    child=open_directory(parent,part);os.close(parent);parent=child
                fd=(os.open(source_candidate,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK) if source_layout and name=='bin/aegis-client' else
                    os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=original))
                try:
                    before=os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and before.st_uid in ({0,source_uid} if source_layout else {0}) and (source_layout or before.st_gid==0) and before.st_nlink==1 and not before.st_mode&0o022 and 0<=before.st_size<=512<<20)
                    total+=before.st_size;need(total<=1<<30)
                    # Git/release archives may mark Python policy modules as
                    # executable. Rotation admission requires these retained
                    # sources to be read-only data, independent of that bit.
                    policy_data=name.startswith('scripts/lib/') and name.endswith(('.py','.json'))
                    mode=0o444 if policy_data else (0o555 if before.st_mode&0o111 else 0o444)
                    temporary='.retain-'+secrets.token_hex(12)
                    out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                    digest=hashlib.sha256();count=0
                    try:
                        while True:
                            block=os.read(fd,65536)
                            if not block: break
                            count+=len(block);need(count<=before.st_size);digest.update(block)
                            view=memoryview(block)
                            while view:
                                written=os.write(out,view);need(written>0);view=view[written:]
                        os.fchmod(out,mode);os.fsync(out)
                    finally: os.close(out)
                    after=os.fstat(fd)
                    need(count==before.st_size and all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')))
                    digests[name]=digest.hexdigest()
                    try: existing=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                    except FileNotFoundError:
                        os.rename(temporary,parts[-1],src_dir_fd=parent,dst_dir_fd=parent)
                    else:
                        try:
                            retained=os.fstat(existing);actual=hashlib.sha256();size=0
                            need(stat.S_ISREG(retained.st_mode) and retained.st_uid==retained.st_gid==0 and retained.st_nlink==1 and stat.S_IMODE(retained.st_mode)==mode and retained.st_size==count)
                            while True:
                                block=os.read(existing,65536)
                                if not block: break
                                size+=len(block);need(size<=count);actual.update(block)
                            need(size==count and actual.hexdigest()==digests[name])
                        finally: os.close(existing)
                        os.unlink(temporary,dir_fd=parent)
                    os.fsync(parent)
                finally: os.close(fd)
            finally: os.close(original);os.close(parent)
        if document is not None:
            need(digests['bundle.manifest.json']==hashlib.sha256(manifest).hexdigest() and document['binaries']['aegis-client']['path']=='bin/aegis-client' and digests['bin/aegis-client']==document['binaries']['aegis-client']['sha256'])
            checks=(destination/'SHA256SUMS').read_text().splitlines();seen=set()
            for line in checks:
                match=re.fullmatch(r'([0-9a-f]{64})  (.+)',line);need(match is not None)
                value,name=match.groups();need(name in digests and name not in seen and digests[name]==value);seen.add(name)
            need(seen==files-{'SHA256SUMS','bundle.manifest.json'})
        else: need(digests==expected_source)
        actual={str(path.relative_to(destination)) for path in destination.rglob('*') if path.is_file() or path.is_symlink()}
        need(actual==files)
        os.fsync(target_fd)
    finally: os.close(target_fd)
    print(destination)
finally: os.close(source_fd)
PY_AUTO_RETAIN_PAYLOAD
}

auto_v2_prepare_boot_gate() {
  python3 -I -B - "$STAGE_AUTO_INSTALL_LOCK_FD" "$ROOT" <<'PY_AUTO_BOOT_GATE'
import importlib.util,os,pathlib,re,stat,subprocess,sys
def need(ok):
    if not ok: raise SystemExit('AUTO fixed-service boot interlock refused')
lock_fd=int(sys.argv[1]);held_lock=os.fstat(lock_fd)
named_lock=os.stat('/run/aegis-auto-install.lock',follow_symlinks=False)
need(stat.S_ISREG(held_lock.st_mode) and held_lock.st_uid==held_lock.st_gid==0 and
     held_lock.st_nlink==1 and stat.S_IMODE(held_lock.st_mode)==0o600 and
     (held_lock.st_dev,held_lock.st_ino)==(named_lock.st_dev,named_lock.st_ino))
locks=[line.split() for line in pathlib.Path(f'/proc/self/fdinfo/{lock_fd}').read_text().splitlines() if line.startswith('lock:')]
need(len(locks)==1 and len(locks[0])==9 and locks[0][2:5]==['FLOCK','ADVISORY','WRITE'] and locks[0][7:]==['0','EOF'])
device=re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)',locks[0][6])
need(device and (int(device[1],16),int(device[2],16),int(device[3]))==(os.major(held_lock.st_dev),os.minor(held_lock.st_dev),held_lock.st_ino))
def call(*args):
    result=subprocess.run(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,
                          capture_output=True,timeout=10,check=False)
    need(result.returncode==0 and len(result.stdout)<=16384 and len(result.stderr)<=4096)
    return result.stdout.decode('ascii')
def stopped():
    raw=call('show','aegis-client.service','-p','Id','-p','LoadState','-p','ActiveState',
             '-p','SubState','-p','MainPID','-p','ControlPID','-p','ControlGroup',
             '-p','NFileDescriptorStore','-p','NeedDaemonReload','-p','DropInPaths')
    values={}
    for line in raw.splitlines():
        key,separator,value=line.partition('=');need(separator and key not in values);values[key]=value
    need(values.get('Id')=='aegis-client.service' and values.get('LoadState') in ('loaded','not-found') and
         values.get('ActiveState')=='inactive' and values.get('SubState')=='dead' and
         values.get('MainPID')==values.get('ControlPID')=='0' and values.get('ControlGroup')=='' and
         values.get('NFileDescriptorStore')=='0')
    need(not any('aegis-client.service' in line for line in call('list-jobs','--plain','--no-legend','--no-pager').splitlines()))
    return values
stopped()
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
try:
    for component in ('etc','systemd','system','aegis-client.service.d'):
        if component=='aegis-client.service.d':
            try: os.mkdir(component,0o755,dir_fd=parent);os.fsync(parent)
            except FileExistsError: pass
        child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        item=os.fstat(child)
        need(stat.S_ISDIR(item.st_mode) and item.st_uid==item.st_gid==0 and not item.st_mode&0o022)
        os.close(parent);parent=child
    leaf='00-v2-boot-gate.conf'
    # The filesystem root exists independently of marker publication. The
    # fixed AUTO service must never bypass the private V2 activation owner.
    payload=b'[Unit]\nConditionPathExists=!/\n'
    coordinator=pathlib.Path(sys.argv[2])/'scripts/lib/aegis_installer_auto_v2.py'
    spec=importlib.util.spec_from_file_location('aegis_boot_gate_atomic',coordinator)
    need(spec is not None and spec.loader is not None)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    try: os.stat(leaf,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:
        try: module.atomic_exclusive_bytes(parent,leaf,payload,0o644)
        except FileExistsError: pass
    def verify():
        target=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(target)
            need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and
                 stat.S_IMODE(before.st_mode)==0o644 and before.st_size==len(payload) and os.read(target,len(payload)+1)==payload)
            after=os.fstat(target);named=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            need(all(getattr(before,k)==getattr(observed,k) for observed in (after,named) for k in fields))
        finally: os.close(target)
    verify();call('daemon-reload');current=stopped();verify()
    need(current.get('NeedDaemonReload')=='no')
    if current['LoadState']=='loaded':
        need('/etc/systemd/system/aegis-client.service.d/'+leaf in current.get('DropInPaths','').split())
finally: os.close(parent)
PY_AUTO_BOOT_GATE
}

auto_v2_relay_facts() {
  python3 -I - "$1" "$2" "$3" <<'PY_AUTO_GUARD_INPUT'
import hashlib,ipaddress,json,os,pathlib,re,signal,socket,stat,sys,tomllib
source=pathlib.Path(sys.argv[1]);lock=int(sys.argv[2]);target=pathlib.Path(sys.argv[3])
def need(ok):
    if not ok: raise SystemExit('AUTO first-arm source or lock admission refused')
held=os.fstat(lock);named=os.stat('/run/aegis-auto-install.lock',follow_symlinks=False)
need(stat.S_ISREG(held.st_mode) and held.st_uid==held.st_gid==0 and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o600 and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino))
locks=[line.split() for line in pathlib.Path(f'/proc/self/fdinfo/{lock}').read_text().splitlines() if line.startswith('lock:')]
need(len(locks)==1 and len(locks[0])==9 and locks[0][2:5]==['FLOCK','ADVISORY','WRITE'] and locks[0][7:]==['0','EOF'])
device=re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)',locks[0][6])
need(device and (int(device[1],16),int(device[2],16),int(device[3]))==(os.major(held.st_dev),os.minor(held.st_dev),held.st_ino))
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
try:
    info=os.fstat(fd)
    allowed={0}
    if os.environ.get('SUDO_UID','').isdecimal(): allowed.add(int(os.environ['SUDO_UID']))
    need(stat.S_ISREG(info.st_mode) and info.st_uid in allowed and info.st_nlink==1 and not info.st_mode&0o022 and 0<info.st_size<=4<<20)
    raw=os.read(fd,(4<<20)+1);after=os.fstat(fd)
    need(len(raw)==info.st_size and all(getattr(info,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')))
finally: os.close(fd)
settings=tomllib.loads(raw.decode());relay=settings.get('relay')
need(settings.get('mode')=='relay' and type(relay) is dict)
endpoints=[relay]+relay.get('endpoints',[])
need(1<=len(endpoints)<=17)
def expired(*_): raise TimeoutError('AUTO relay route resolution deadline')
signal.signal(signal.SIGALRM,expired);signal.alarm(15)
servers=[]
seen_inputs=set()
for index,endpoint in enumerate(endpoints):
    need(type(endpoint) is dict and type(endpoint.get('server')) is str)
    # An ordinary bundle repeats its primary in relay.endpoints. Keep the
    # primary's one sealed resolver observation; an identical input grants no
    # additional endpoint and must not trigger a second DNS observation.
    if endpoint['server'] in seen_inputs: continue
    seen_inputs.add(endpoint['server'])
    host,separator,port=endpoint['server'].rpartition(':')
    need(separator==':' and port.isdecimal() and 0<int(port)<65536)
    try: address=ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        # Prepare currently seals one resolver observation for the primary.
        # Additional endpoints must already carry explicit numeric pins.
        need(index==0)
        addresses=sorted({row[4][0] for row in socket.getaddrinfo(host,int(port),socket.AF_INET,socket.SOCK_STREAM)})
        need(len(addresses)==1);address=ipaddress.IPv4Address(addresses[0])
    need(not (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local))
    server=str(address)+':'+str(int(port))
    if server not in servers: servers.append(server)
signal.alarm(0)
value={'relay_server':servers[0],'relay_endpoints':[{'server':server} for server in servers[1:]],'source_config_sha256':hashlib.sha256(raw).hexdigest(),'relay_servers':servers}
payload=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    need(os.write(out,payload)==len(payload));os.fsync(out)
finally: os.close(out)
PY_AUTO_GUARD_INPUT
}

auto_v2_verify_boot_host() (
  set -euo pipefail
  [[ "$EUID" == 0 && "$(detect_os_kind)" == linux && "$ROLE" == client &&
     "$AUTO_PROFILE" == 1 && "$AUTO_V2_RESUME_UPGRADE" == 0 &&
     -z "$CLIENT_PACKAGE$BUNDLE_PATH$BUNDLE_URL_FILE" ]] || return 1
  local helper=/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py
  /usr/bin/python3 -I -B "$helper" boot-denied-readback "$AUTO_V2_BOOT_INSTALL_FD" "$AUTO_V2_BOOT_GUARD_FD" >/dev/null || return 1
  local stage facts assessment boot_proof
  stage="$(mktemp -d /var/lib/aegis-auto/control/boot-assessment.XXXXXXXX)" || return 1
  facts="$stage/relay-facts.json";assessment="$stage/guard.conf"
  auto_v2_relay_facts /etc/aegis/client/aegis.toml "$AUTO_V2_BOOT_INSTALL_FD" "$facts" || return 1
  boot_proof="$(device_verify_initramfs)" || return $?
  WIDE_INTERFACE="$("$ROOT/bin/aegis-client" profile metadata read --path /var/lib/aegis-install/client/device-guard.conf | sed -n 's/^uplink=//p')" || return 1
  [[ -n "$WIDE_INTERFACE" ]] || return 1
  device_assess_guard_host "$boot_proof" "$AUTO_V2_BOOT_MODE" <"$facts" | install_atomic_write "$assessment" 0600 strict || return 1
  # Reboot does not grant a policy migration. Changed host policy refuses
  # safely and retains its assessment for explicit administrative recovery.
  cmp -s "$assessment" /var/lib/aegis-install/client/device-guard.conf || return 1
  /usr/bin/python3 -I -B "$helper" boot-denied-readback "$AUTO_V2_BOOT_INSTALL_FD" "$AUTO_V2_BOOT_GUARD_FD" >/dev/null || return 1
  /usr/bin/python3 -I -B - "$ROOT" "$facts" "$assessment" "$boot_proof" "$AUTO_V2_BOOT_MODE" <<'PY_AUTO_BOOT_HOST_RESULT'
import hashlib,json,pathlib,sys
root,facts,assessment=map(pathlib.Path,sys.argv[1:4]);boot=json.loads(sys.argv[4]);relay=json.loads(facts.read_bytes())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert boot['initramfs_network']=='absent_verified'
assert sys.argv[5] in ('full-wide-tun','wide-redirect-safe')
assert ('capture_profile='+sys.argv[5]).encode() in assessment.read_bytes().splitlines()
print(json.dumps({'schema':'aegis_auto_v2_boot_host_assessment_v1','boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'public_payload_root':str(root),'installer_sha256':sha(root/'install.sh'),'source_config_sha256':relay['source_config_sha256'],'assessment_sha256':sha(assessment),'initrd_sha256':boot['initrd_sha256'],'kernel':boot['kernel'],'capture_profile':sys.argv[5],'current_policy_unchanged':True},sort_keys=True,separators=(',',':')))
PY_AUTO_BOOT_HOST_RESULT
)

auto_v2_first_arm_proof() {
  # Every retry uses the original assessment and input generation. This proof
  # is written before Stop; it is never inferred from a late guard marker.
  /usr/bin/python3 -I -B - "$@" <<'PY_AUTO_FIRST_ARM_INTENT'
import hashlib,json,os,pathlib,re,stat,sys,time,types
action,candidate,config,mode,helpers,installer,lock,*rest=sys.argv[1:]
candidate,config,helpers,installer=map(pathlib.Path,(candidate,config,helpers,installer))
def load(name):
    path=helpers/'lib'/(name+'.py')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o500 and 0<info.st_size<=1<<20
        raw=os.read(fd,(1<<20)+1);assert len(raw)==info.st_size
    finally: os.close(fd)
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__);return module
c=load('aegis_installer_auto_v2');g=c.installed_guardian()
c.fresh_package_lock(int(lock));parent=c.control_directory()
def raw(path,maximum=65536,modes=(0o600,)):
    return c.bounded_root_bytes(path,maximum,modes)
def digest(data): return hashlib.sha256(data).hexdigest()
def exists(path): return os.path.lexists(path)
def exact(path,data,permissions):
    assert raw(path,len(data)+1,(permissions,))==data
def exclusive(name,data):
    try: existing=c.control_leaf(parent,name,65536)[0]
    except FileNotFoundError: c._passive_write(parent,name,c.strict_json(data))
    else: assert existing==data
def encode(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def show(unit):
    names=('Id','LoadState','ActiveState','SubState','MainPID','ControlPID','ControlGroup','InvocationID','NFileDescriptorStore')
    argv=['/usr/bin/systemctl','show',unit,'--no-pager']
    for name in names: argv.extend(('-p',name))
    lines=c.call_output(argv,maximum=4096,timeout=5).decode('ascii').splitlines()
    facts=dict(line.split('=',1) for line in lines)
    assert len(lines)==len(facts) and set(facts)==set(names) and facts['Id']==unit and facts['LoadState']=='loaded' and facts['ControlPID']=='0' and facts['NFileDescriptorStore']=='0'
    return facts
def stopped(facts):
    return facts['ActiveState']=='inactive' and facts['SubState']=='dead' and facts['MainPID']=='0' and facts['ControlGroup']==''
def birth(pid):
    try: text=pathlib.Path('/proc/'+str(pid)+'/stat').read_text()
    except FileNotFoundError: return None
    tail=text.rsplit(')',1)[1].split();assert len(tail)>=20
    return int(tail[19])
def no_client():
    c.no_private_jobs_or_units()
    assert stopped(show('aegis-client.service'))
    for path in ('current.json','prepare-current.json','prepare-completed.json','prepare-stage-created.json','generation-active-current.json','generation-stopped-current.json','generation-successor-current.json'):
        assert not exists(c.CONTROL/path)
    for name in ('auto-stage-owner.json','auto-watchdog-pending.json','auto-stop-intent.json','auto-guard-rotation-intent.json','device-guard.conf.client-binding','device-guard.conf.capture-binding','device-guard.conf.main-binding'):
        assert not exists(g.INSTALL.parent/name)
    for path in ('/etc/aegis/client/aegis.toml','/etc/aegis/client/ca.pem'):
        assert not exists(path)
    snapshots=pathlib.Path('/run/aegis-installer-config-snapshots')
    if exists(snapshots):
        fd=c.directory(snapshots)
        try: assert not os.listdir(fd)
        finally: os.close(fd)
    jobs=c.call_output(['/usr/bin/systemctl','list-jobs','--no-legend','--plain'],maximum=65536,timeout=5)
    assert not any(b'aegis-' in line for line in jobs.splitlines())
try:
    no_client()
    passive=raw(c.CONTROL/'fresh-passive-intent.json')
    boot=c.current_boot();netns=os.stat('/proc/self/ns/net').st_ino
    pins={'passive_intent_sha256':digest(passive),'boot_id':boot,'netns_ino':netns,'candidate_binary':str(candidate),'candidate_sha256':digest(raw(candidate,512<<20,(0o555,))),'installer_sha256':digest(raw(installer,4<<20,(0o555,))),'source_config':str(config),'source_config_sha256':digest(raw(config,4<<20,(0o400,0o444,0o600))),'mode':mode}
    name='fresh-first-arm-intent.json';path=c.CONTROL/name
    if action=='begin':
        assert len(rest)==1 and not exists(path)
        c.guardian_ready(candidate,'passive')
        stage=c.absolute(rest[0]);assert stage.parent==c.CONTROL and re.fullmatch(r'first-arm\.[A-Za-z0-9]{8}',stage.name)
        fd=c.directory(stage,0o700);os.close(fd)
        facts_raw=raw(stage/'relay-facts.json');assessment=raw(stage/'guard.conf')
        facts=c.strict_json(facts_raw)
        assert facts['source_config_sha256']==pins['source_config_sha256']
        fields=dict(line.split('=',1) for line in assessment.decode('ascii').splitlines())
        manager=fields['manager'];assert manager in ('systemd-networkd.service','NetworkManager.service') and fields['capture_profile']==mode
        install_raw=raw(g.INSTALL);installation=c.strict_json(install_raw);assert installation['guard_unit_sha256'] is None
        guardian=show('aegis-auto-guardian.service');start=birth(guardian['MainPID']);assert type(start) is int and start>0
        value=dict(pins,schema='aegis_auto_v2_first_arm_intent_v1',stage=str(stage),facts_sha256=digest(facts_raw),assessment_sha256=digest(assessment),manager=manager,passive_install=installation,passive_install_raw=install_raw.decode('ascii'),passive_install_sha256=digest(install_raw),guardian=guardian,guardian_start_ticks=start)
        exclusive(name,encode(value))
    else:
        assert action in ('resume','stopped') and not rest
        value=c.strict_json(raw(path));assert type(value) is dict and set(value)==set(pins)|{'schema','stage','facts_sha256','assessment_sha256','manager','passive_install','passive_install_raw','passive_install_sha256','guardian','guardian_start_ticks'} and value['schema']=='aegis_auto_v2_first_arm_intent_v1'
        assert all(value[key]==item for key,item in pins.items())
        stage=c.absolute(value['stage']);assert stage.parent==c.CONTROL and re.fullmatch(r'first-arm\.[A-Za-z0-9]{8}',stage.name)
        fd=c.directory(stage,0o700);os.close(fd)
        facts_raw=raw(stage/'relay-facts.json');assessment=raw(stage/'guard.conf')
        assert digest(facts_raw)==value['facts_sha256'] and digest(assessment)==value['assessment_sha256']
    manager=value['manager'];assert manager in ('systemd-networkd.service','NetworkManager.service')
    original=value['passive_install'];install_raw=raw(g.INSTALL);current=c.strict_json(install_raw)
    upgraded=dict(original,guard_unit_sha256=digest(g.EXPECTED_GUARD_UNIT))
    assert current in (original,upgraded) and original['guard_unit_sha256'] is None and original['worker_sha256']==pins['candidate_sha256']
    original_raw=value['passive_install_raw'].encode('ascii')
    assert digest(original_raw)==value['passive_install_sha256'] and c.strict_json(original_raw)==original
    assert install_raw==(original_raw if current==original else encode(upgraded))
    before=value['guardian'];assert type(before) is dict and before['ActiveState']=='active' and before['SubState']=='running' and int(before['MainPID'])>1 and before['ControlGroup']=='/system.slice/aegis-auto-guardian.service' and re.fullmatch(r'[a-f0-9]{32}',before['InvocationID'])
    assert type(value['guardian_start_ticks']) is int and value['guardian_start_ticks']>0
    stop_path=c.CONTROL/'fresh-first-arm-stopped.json'
    expected_stop={'schema':'aegis_auto_v2_first_arm_stopped_v1','intent_sha256':digest(raw(path)),'guardian':before,'guardian_start_ticks':value['guardian_start_ticks']}
    if current==upgraded:
        assert c.strict_json(raw(stop_path))==expected_stop and birth(before['MainPID'])!=value['guardian_start_ticks']
    unit=g.GUARD_UNIT_FILE
    if exists(unit): exact(unit,g.EXPECTED_GUARD_UNIT,0o644)
    g.own_source(pending_guard_unit=(current==original and exists(unit)))
    helper='/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh';state=pathlib.Path('/var/lib/aegis-install/client/device-guard.conf')
    hook='[Service]\nEnvironment=AEGIS_DEVICE_GUARD_STATE='+str(state)+'\nExecStartPre=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash '+helper+' bind-manager'
    if manager in ('NetworkManager.service','systemd-networkd.service'): hook+='\nExecStartPost=+/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root -- /bin/bash '+helper+' manager-ready\nTimeoutStartSec=90'
    dropin=pathlib.Path('/etc/systemd/system')/(manager+'.d')/'30-aegis-device-guard.conf'
    expected=('[Unit]\nRequires=aegis-device-egress-guard.service\nAfter=aegis-device-egress-guard.service\n'+hook+'\n').encode()
    if exists(dropin):
        assert exists(unit);exact(dropin,expected,0o644)
    if exists(state):
        assert exists(dropin) and current==upgraded;exact(state,assessment,0o600)
    if exists(g.POLICY):
        observed,projection=g._semantic_policy_readback(deadline=time.monotonic()+5)
        policy=g.record(g.POLICY)
        assert observed==assessment and g._no_client_grant(projection) and policy['boot_id']==boot and policy['state_sha256']==digest(observed) and policy['policy_sha256']==digest(projection)
    receipt=g.INSTALL.parent/'auto-guard-first-arm.json'
    if exists(receipt):
        assert current==upgraded
        c.guardian_ready(candidate,'guarded')
        observed,projection=g._semantic_policy_readback(deadline=time.monotonic()+5)
        facts=c.strict_json(facts_raw)
        expected_receipt={'schema':'aegis_auto_guard_first_arm_v1','boot_id':boot,'candidate_sha256':pins['candidate_sha256'],'source_config_sha256':pins['source_config_sha256'],'relay_servers':facts['relay_servers'],'assessment_sha256':digest(assessment),'guard_unit_sha256':digest(g.EXPECTED_GUARD_UNIT),'manager':manager,'manager_dropin_sha256':digest(expected),'guardian_install_sha256':digest(raw(g.INSTALL)),'policy_sha256':digest(projection),'installer_source_sha256':pins['installer_sha256']}
        assert c.strict_json(raw(receipt))==expected_receipt and observed==assessment and g._no_client_grant(projection)
        guard=show('aegis-device-egress-guard.service')
        assert guard['ActiveState']=='active' and guard['SubState']=='exited' and guard['MainPID']=='0'
        manager_state=show(manager)
        assert manager_state['ActiveState']=='active' and manager_state['SubState']=='running' and int(manager_state['MainPID'])>1
        c.call_output(['/bin/bash',helper,'manager-status'],maximum=8192,timeout=c.PHASE_TIMEOUT,
                      env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','AEGIS_DEVICE_GUARD_STATE':str(state)})
        print(str(stage)+' ready')
    else:
        live=show('aegis-auto-guardian.service')
        if action=='stopped': assert stopped(live)
        if stopped(live):
            # The immutable pre-Stop identity is the write-ahead authority. An
            # inactive PID1, dead original process and empty original cgroup
            # close a Stop even if the caller died before its completion write.
            assert birth(before['MainPID'])!=value['guardian_start_ticks']
            group=pathlib.Path('/sys/fs/cgroup'+before['ControlGroup'])
            if group.exists():
                assert 'populated 0' in (group/'cgroup.events').read_text().splitlines() and not (group/'cgroup.procs').read_text().strip()
            _actors,missing=c.passive_actor_status(
                deadline=time.monotonic()+c.PHASE_TIMEOUT,
                retired_guardian_invocation=before['InvocationID'])
            assert missing==['aegis-auto-guardian.service'] and len(_actors)==3
            exclusive(stop_path.name,encode(expected_stop))
            phase='stopped'
        elif current==upgraded:
            assert exists(stop_path)
            assert c.strict_json(raw(stop_path))==expected_stop
            c.guardian_ready(candidate,'guarded');phase='guarded'
        else:
            assert current==original and not exists(unit) and live==before and birth(before['MainPID'])==value['guardian_start_ticks']
            c.guardian_ready(candidate,'passive');phase='live'
        print(str(stage)+' '+phase)
    c.fresh_package_lock(int(lock));no_client()
finally: os.close(parent)
PY_AUTO_FIRST_ARM_INTENT
}

auto_v2_first_arm_exact_write() {
  /usr/bin/python3 -I -B -c '
import os,pathlib,stat,sys,types
path=pathlib.Path(sys.argv[1]);mode=int(sys.argv[2],8);raw=sys.stdin.buffer.read((1<<20)+1)
assert 0<len(raw)<=1<<20 and path.is_absolute() and mode in (0o600,0o644)
parent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
try:
 for part in path.parts[1:-1]:
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);item=os.fstat(child)
  assert item.st_uid==item.st_gid==0 and not stat.S_IMODE(item.st_mode)&0o022
  os.close(parent);parent=child
 def check():
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  try:
   before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==mode and before.st_size==len(raw) and os.read(fd,len(raw)+1)==raw
   after=os.fstat(fd);named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
   assert all(getattr(before,k)==getattr(observed,k) for observed in (after,named) for k in fields)
  finally: os.close(fd)
 try: check()
 except FileNotFoundError:
  source=pathlib.Path("/usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py")
  held=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  try:
   for part in source.parts[1:-1]:
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=held);item=os.fstat(child)
    assert item.st_uid==item.st_gid==0 and not stat.S_IMODE(item.st_mode)&0o022
    os.close(held);held=child
   fd=os.open(source.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=held)
   try:
    item=os.fstat(fd);assert stat.S_ISREG(item.st_mode) and item.st_uid==item.st_gid==0 and item.st_nlink==1 and stat.S_IMODE(item.st_mode)==0o500 and 0<item.st_size<=1<<20
    code=os.read(fd,(1<<20)+1);assert len(code)==item.st_size
   finally: os.close(fd)
  finally: os.close(held)
  module=types.ModuleType("aegis_first_arm_atomic");module.__file__=str(source)
  exec(compile(code,str(source),"exec",dont_inherit=True),module.__dict__)
  try: module.atomic_exclusive_bytes(parent,path.name,raw,mode)
  except FileExistsError: check()
finally: os.close(parent)
' "$1" "$2"
}

auto_v2_first_arm() (
  local candidate="$1" source_config="$2" mode="$3" helper_dir="$4"
  local transition="${5:-fresh}"
  local control=/var/lib/aegis-auto/control state=/var/lib/aegis-install/client/device-guard.conf
  local stage facts assessment manager boot_proof first_arm_phase=live first_arm_proof
  # Manager start may consume its existing 90-second source policy budget.
  # Bound the caller without changing that policy or the V2 worker deadlines.
  systemctl() { /usr/bin/timeout --signal=TERM --kill-after=3s 95s /usr/bin/systemctl "$@"; }
  auto_guard() { /usr/bin/timeout --signal=TERM --kill-after=3s 40s /bin/bash "$helper_dir/aegis-device-egress-guard.sh" "$@"; }
  [[ "$mode" == full-wide-tun || "$mode" == wide-redirect-safe ]] || return 1
  [[ "$transition" == fresh || "$transition" == stopped-successor ]] || return 1
  if [[ "$transition" == stopped-successor ]]; then
    # This is a typed phase proof over both original OFDs. The private flag
    # alone authorizes neither reassessment nor replacement of guard state.
    /usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" rotation-admitted-readback 9 10 >/dev/null || return 1
    export AEGIS_AUTO_HELD_GUARD_FD=10
  fi
  # This is the persistent deny transaction, before V2 captures metadata. Its
  # private assessment remains available on every failure. It never publishes
  # a client config, client unit or client drop-in.
  if [[ "$transition" == fresh && ( -e "$control/fresh-first-arm-intent.json" || -L "$control/fresh-first-arm-intent.json" ) ]]; then
    first_arm_proof="$(auto_v2_first_arm_proof resume "$candidate" "$source_config" "$mode" "$helper_dir" "$ROOT/install.sh" "$STAGE_AUTO_INSTALL_LOCK_FD")" || return 1
    read -r stage first_arm_phase <<<"$first_arm_proof"
    [[ "$first_arm_phase" != ready ]] || return 0
    facts="$stage/relay-facts.json";assessment="$stage/guard.conf"
  else
    stage="$(mktemp -d "$control/first-arm.XXXXXXXX")" || return 1
    facts="$stage/relay-facts.json"
    auto_v2_relay_facts "$source_config" "$STAGE_AUTO_INSTALL_LOCK_FD" "$facts" || return 1
    boot_proof="$(device_verify_initramfs)" || return $?
    assessment="$stage/guard.conf"
    device_assess_guard_host "$boot_proof" "$mode" <"$facts" | install_atomic_write "$assessment" 0600 strict || return 1
    if [[ "$transition" == fresh ]]; then
      first_arm_proof="$(auto_v2_first_arm_proof begin "$candidate" "$source_config" "$mode" "$helper_dir" "$ROOT/install.sh" "$STAGE_AUTO_INSTALL_LOCK_FD" "$stage")" || return 1
      read -r stage first_arm_phase <<<"$first_arm_proof"
    fi
  fi
  manager="$("$candidate" profile metadata read --path "$assessment" | sed -n 's/^manager=//p')" || return 1
  [[ "$manager" == systemd-networkd.service || "$manager" == NetworkManager.service ]] || {
    echo 'AUTO requires the reviewed v2 network-manager guard binding.' >&2; return 1;
  }
  # Recheck the complete passive generation before stopping it. Only its exact
  # PID may be retired, with no private owner, stored FD or pending Stop.
  if [[ "$transition" == fresh && "$first_arm_phase" == live ]]; then
    /usr/bin/python3 -I -B "$helper_dir/lib/aegis_installer_auto_v2.py" preflight-passive --candidate-binary "$candidate" >/dev/null || return 1
    python3 -I - "$control/fresh-first-arm-intent.json" <<'PY_AUTO_FIRST_ARM_STOP'
import json,os,pathlib,select,stat,subprocess,sys
def show(unit):
    result=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','MainPID','-p','ControlPID','-p','ControlGroup','-p','InvocationID','-p','NFileDescriptorStore'],capture_output=True,timeout=5,check=True,text=True)
    return dict(line.split('=',1) for line in result.stdout.splitlines())
def start(pid):
    return int(pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])
path=pathlib.Path(sys.argv[1]);parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    item=os.fstat(parent);assert item.st_uid==item.st_gid==0 and stat.S_IMODE(item.st_mode)==0o700
    intent_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    try:
        item=os.fstat(intent_fd);assert stat.S_ISREG(item.st_mode) and item.st_uid==item.st_gid==0 and item.st_nlink==1 and stat.S_IMODE(item.st_mode)==0o600 and 0<item.st_size<=65536
        raw=os.read(intent_fd,65537);assert len(raw)==item.st_size
        intent=json.loads(raw)
    finally: os.close(intent_fd)
finally: os.close(parent)
before=show('aegis-auto-guardian.service');pid=int(before['MainPID'])
assert before['ActiveState']=='active' and before['SubState']=='running' and pid>1 and before['ControlPID']=='0' and before['ControlGroup']=='/system.slice/aegis-auto-guardian.service'
fd=os.pidfd_open(pid)
try:
    expected=intent['guardian']
    assert all(before[key]==expected[key] for key in before) and start(pid)==intent['guardian_start_ticks']
    poll=select.poll();poll.register(fd,select.POLLIN);assert not poll.poll(0)
    assert show('aegis-auto-guardian.service')==before and start(pid)==intent['guardian_start_ticks']
    subprocess.run(['/usr/bin/systemctl','stop','aegis-auto-guardian.service'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=True)
    assert poll.poll(1000)
finally: os.close(fd)
after=show('aegis-auto-guardian.service');watch=show('aegis-auto-guardian-watchdog.service')
assert after['ActiveState']=='inactive' and after['SubState']=='dead' and after['MainPID']==after['ControlPID']=='0' and after['ControlGroup']==''
assert watch['ActiveState']=='active' and watch['ControlPID']=='0' and watch['NFileDescriptorStore']=='0'
assert not any(os.path.lexists('/var/lib/aegis-install/client/'+name) for name in ('auto-watchdog-pending.json','auto-stop-intent.json'))
PY_AUTO_FIRST_ARM_STOP
    auto_v2_first_arm_proof stopped "$candidate" "$source_config" "$mode" "$helper_dir" "$ROOT/install.sh" "$STAGE_AUTO_INSTALL_LOCK_FD" >/dev/null || return 1
  elif [[ "$transition" == stopped-successor ]]; then
    /usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" rotation-admitted-readback 9 10 >/dev/null || return 1
  fi
  if [[ "$transition" == fresh ]]; then
    # Passive preparation already installed these exact helpers. Never replace
    # executing source during a retry. New guard/state leaves are exclusive or
    # byte-identical, so a foreign or incomplete leaf cannot be overwritten.
    install_copy_file() {
      /usr/bin/python3 -I -B -c '
import os,pathlib,stat,sys
source,target=map(pathlib.Path,sys.argv[1:3]);mode=int(sys.argv[3],8)
def read(path,expected=None):
 parent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);item=os.fstat(child)
   assert item.st_uid==item.st_gid==0 and not stat.S_IMODE(item.st_mode)&0o022
   os.close(parent);parent=child
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  try:
   before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and not stat.S_IMODE(before.st_mode)&0o022 and 0<before.st_size<=1<<20
   assert expected is None or stat.S_IMODE(before.st_mode)==expected
   data=os.read(fd,(1<<20)+1);after=os.fstat(fd);named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
   fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
   assert len(data)==before.st_size and all(getattr(before,k)==getattr(observed,k) for observed in (after,named) for k in fields)
   return data
  finally: os.close(fd)
 finally: os.close(parent)
assert read(source)==read(target,mode)
' "$1" "$2" "$3"
    }
    install_atomic_write() { auto_v2_first_arm_exact_write "$1" "$2"; }
  fi
  local AUTO_V2_FIRST_ARM_ADMITTED=1
  install_device_egress_guard_units "$state" "$manager" "$facts" "$assessment" v2-stage || return 1
  device_guard_assessment_lock_ensure || return 1
  AEGIS_DEVICE_GUARD_STATE="$assessment" auto_guard block || return 1
  if [[ "$transition" == stopped-successor ]]; then
    python3 -I - "$assessment" <<'PY_AUTO_ROTATION_ASSESSMENT'
import os,pathlib,stat,sys
source=pathlib.Path(sys.argv[1]);target=pathlib.Path('/var/lib/aegis-install/client/auto-guard-rotation-assessment.conf')
raw=source.read_bytes()
assert 0<len(raw)<=65536
try: fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
except FileExistsError:
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        item=os.fstat(fd)
        assert stat.S_ISREG(item.st_mode) and item.st_uid==item.st_gid==0 and item.st_nlink==1 and stat.S_IMODE(item.st_mode)==0o600
        assert os.read(fd,65537)==raw
    finally: os.close(fd)
else:
    try:
        assert os.write(fd,raw)==len(raw);os.fsync(fd)
    finally: os.close(fd)
    parent=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)
PY_AUTO_ROTATION_ASSESSMENT
  fi
  "$candidate" profile metadata read --path "$assessment" | install_atomic_write "$state" 0600 strict || return 1
  if [[ "$transition" == stopped-successor ]]; then
    AEGIS_DEVICE_GUARD_STATE="$state" auto_guard block || return 1
    /usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" rotation-state-handoff 9 10 >/dev/null || return 1
    # PID1's guard/manager hooks take their own guard flock. The protected
    # handoff above authorizes this release; the installer OFD stays held.
    flock -u 10 || return 1
    unset AEGIS_AUTO_HELD_GUARD_FD
  fi
  systemctl start aegis-device-egress-guard.service || return 1
  systemctl is-active --quiet aegis-device-egress-guard.service || return 1
  # Rotation retires the old monitor under a typed deny and a PID1 resume
  systemctl start aegis-device-dhcp-refresh.timer || return 1
  systemctl is-active --quiet aegis-device-dhcp-refresh.timer || return 1
  # timer. FD10 has now been released; start the successor before readiness.
  systemctl start aegis-foreign-policy-monitor.service || return 1
  systemctl start aegis-auto-clean-shutdown.service || return 1
  systemctl restart "$manager" || return 1
  systemctl is-active --quiet "$manager" || return 1
  AEGIS_DEVICE_GUARD_STATE="$state" auto_guard manager-status || return 1
  # ExecStartPre bind-manager has already applied and sealed the deny policy
  # with this manager's DHCP binding. There is no client grant: fresh starts
  # from passive, and stopped-successor committed its typed deny beforehand.
  # A second anonymous installer block would take the guard OFD while the
  # independent monitor is live. That OFD belongs to none of its authenticated
  # PID1 actors, so the monitor must revoke. Keep the manager's sealed policy;
  # the strict receipt below still proves the complete no-client projection.
  /usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" upgrade-guard >/dev/null || return 1
  if [[ "$transition" == stopped-successor ]]; then
    systemctl start aegis-auto-guardian-watchdog.service || return 1
  fi
  systemctl start aegis-auto-guardian.service || return 1
  local receipt=/var/lib/aegis-install/client/auto-guard-first-arm.json
  python3 -I -B - "$helper_dir" "$candidate" "$facts" "$assessment" "$ROOT/install.sh" "$manager" <<'PY_AUTO_FIRST_ARM_RECEIPT' | install_atomic_write "$receipt" 0600 strict
import hashlib,importlib.util,json,pathlib,sys
root,candidate,facts,assessment,installer,manager=map(pathlib.Path,sys.argv[1:])
def load(name):
    spec=importlib.util.spec_from_file_location(name,root/'lib'/f'{name}.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
coordinator=load('aegis_installer_auto_v2');coordinator.wait_guardian_ready(candidate,'guarded')
guardian=coordinator.installed_guardian();guardian.own_source()
state,projection=guardian._semantic_policy_readback()
assert guardian._no_client_grant(projection)
policy=guardian.record(guardian.POLICY)
assert policy['state_sha256']==hashlib.sha256(state).hexdigest() and policy['policy_sha256']==hashlib.sha256(projection).hexdigest()
source=json.loads(facts.read_bytes())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
assert assessment.read_bytes()==state
value={'schema':'aegis_auto_guard_first_arm_v1','boot_id':coordinator.current_boot(),'candidate_sha256':sha(candidate),'source_config_sha256':source['source_config_sha256'],'relay_servers':source['relay_servers'],'assessment_sha256':hashlib.sha256(state).hexdigest(),'guard_unit_sha256':sha(guardian.GUARD_UNIT_FILE),'manager':str(manager),'manager_dropin_sha256':sha(pathlib.Path('/etc/systemd/system')/(str(manager)+'.d')/'30-aegis-device-guard.conf'),'guardian_install_sha256':sha(guardian.INSTALL),'policy_sha256':hashlib.sha256(projection).hexdigest(),'installer_source_sha256':sha(installer)}
print(json.dumps(value,sort_keys=True,separators=(',',':')))
PY_AUTO_FIRST_ARM_RECEIPT
)

auto_v2_resume_upgrade() (
  set -euo pipefail
  [[ "$EUID" == 0 && "$(detect_os_kind)" == linux && "$ROLE" == client &&
     "$AUTO_PROFILE" == 1 && -z "$CLIENT_PACKAGE$BUNDLE_PATH$BUNDLE_URL_FILE" ]] || return 1
  local helper_dir=/usr/local/lib/aegis/helpers candidate="$ROOT/bin/aegis-client"
  local metadata=/var/lib/aegis-install/auto-client guardian_metadata=/var/lib/aegis-install/client
  if [[ -e /var/lib/aegis-auto/control/passive-package-preinst.json ||
        -L /var/lib/aegis-auto/control/passive-package-preinst.json ]]; then
    local passive_missing passive_unit passive_resume_program
    IFS= read -r -d '' passive_resume_program <<'PY_AUTO_PASSIVE_RESUME' || true
import hashlib,importlib.util,pathlib,sys
root=pathlib.Path(sys.argv[1]);source=pathlib.Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
spec=importlib.util.spec_from_file_location('aegis_passive_resume',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
proof=m.passive_successor_progress_readback(9)
successor=m.record(m.SUCCESSOR);stopped=m.record(m.PASSIVE_OLD_STOPPED,128<<10)
fixed={'aegis-auto-witness-topology.service','aegis-auto-trace-rollback-actor.service',
       'aegis-auto-guardian-watchdog.service','aegis-auto-guardian.service'}
assert set(proof)=={'schema','boot_id','preinst_sha256','new_install_sha256',
                   'candidate_sha256','active','missing'}
assert proof['schema']=='aegis_auto_guard_passive_successor_progress_v1'
assert type(proof['active']) is list and type(proof['missing']) is list
assert len(proof['active'])+len(proof['missing'])==4
assert len(set(proof['active']+proof['missing']))==4
assert set(proof['active']+proof['missing'])==fixed
assert stopped['stage']['mode']=='socks-only'
assert successor['next_public_payload_root']==str(root)
assert successor['next_candidate_binary']==str(root/'bin/aegis-client')
assert proof['candidate_sha256']==successor['next_candidate_sha256']
assert hashlib.sha256((root/'install.sh').read_bytes()).hexdigest()==successor['next_installer_sha256']
for unit in ('aegis-auto-witness-topology.service',
             'aegis-auto-trace-rollback-actor.service',
             'aegis-auto-guardian-watchdog.service',
             'aegis-auto-guardian.service'):
    if unit in proof['missing']: print(unit)
PY_AUTO_PASSIVE_RESUME
    passive_missing="$(printf '%s' "$passive_resume_program" | /usr/bin/python3 -I -B - "$ROOT")" || return 1
    /usr/bin/systemctl daemon-reload || return 1
    /usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" \
      passive-successor-progress-readback 9 | /usr/bin/python3 -I -c '
import json,sys
value=json.load(sys.stdin)
expected=set(sys.argv[1].splitlines())
assert value.get("schema")=="aegis_auto_guard_passive_successor_progress_v1"
assert type(value.get("missing")) is list and set(value["missing"])==expected
' "$passive_missing" || return 1
    if [[ -n "$passive_missing" ]]; then
      while IFS= read -r passive_unit; do
        [[ -n "$passive_unit" ]] || return 1
        /usr/bin/systemctl start "$passive_unit" || return 1
      done <<< "$passive_missing"
    fi
    /usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" \
      passive-successor-progress-wait 9 | /usr/bin/python3 -I -c '
import json,sys
value=json.load(sys.stdin)
assert value.get("schema")=="aegis_auto_guard_passive_successor_progress_v1"
assert value.get("missing")==[]
' || return 1
    return 0
  fi
  # Admit the exact retained installer and both original OFDs, rather than
  # treating this hidden dispatch or a caller-supplied path as authority.
  /usr/bin/python3 -I -B - "$ROOT" <<'PY_AUTO_ROTATION_RESUME'
import hashlib,importlib.util,pathlib,sys
root=pathlib.Path(sys.argv[1]);source=pathlib.Path('/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py')
spec=importlib.util.spec_from_file_location('aegis_rotation_resume',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
proof=m.rotation_admitted_readback(9,10);intent=m.record(m.ROTATION_INTENT)
assert proof['no_live_actors'] is True and intent['successor']['next_public_payload_root']==str(root)
assert intent['successor']['next_candidate_binary']==str(root/'bin/aegis-client')
assert hashlib.sha256((root/'install.sh').read_bytes()).hexdigest()==intent['successor']['next_installer_sha256']
PY_AUTO_ROTATION_RESUME
  local STAGE_AUTO_INSTALL_LOCK_FD=9 AEGIS_WIDE_LIB_DIR="$helper_dir" selected_mode
  PREFLIGHT_CLIENT_BINARY="$candidate";export AEGIS_ROOT_STATE_CLIENT="$candidate"
  SYSTEMD_DIR=/etc/systemd/system;ENV_DIR=/etc/default;FORCE=1
  selected_mode="$("$candidate" profile auto --config /etc/aegis/client/aegis.toml --state-dir "$metadata" --json | python3 -I -c '
import json,sys
p=json.load(sys.stdin);assert p.get("schema")=="aegis_auto_install_plan_v1" and p.get("status")=="planned"
assert p.get("product_mode") in ("wide-redirect-safe","full-wide-tun")
print(p["product_mode"])
')" || return 1
  auto_v2_first_arm "$candidate" /etc/aegis/client/aegis.toml "$selected_mode" "$helper_dir" stopped-successor || return $?
  "$candidate" profile metadata read --path "$guardian_metadata/auto-guard-first-arm.json" |
    install_atomic_write "$metadata/auto-guard-first-arm.json" 0600 strict || return 1
)

auto_v2_passive_receipt() {
  # The Python coordinator owns the protected input snapshot and its phase
  # admission. Keep the original InstallLock held across this exchange.
  local operation="$1" retained="$2" original_bundle="$3" reply parsed line passive_reply_program
  local -a args=("$operation" --install-fd "$STAGE_AUTO_INSTALL_LOCK_FD"
    --fresh-origin "$AUTO_V2_PASSIVE_ORIGIN"
    --public-payload-root "$retained" --bundle-dir "$original_bundle")
  [[ -z "${AUTO_V2_REQUESTED_MODE:-}" ]] || args+=(--requested-mode "$AUTO_V2_REQUESTED_MODE")
  [[ -z "$MASQUE_SERVER" ]] || args+=(--masque-server "$MASQUE_SERVER")
  [[ -z "$MASQUE_CA" ]] || args+=(--masque-ca "$MASQUE_CA")
  [[ -z "$WIDE_INTERFACE" ]] || args+=(--wide-interface "$WIDE_INTERFACE")
  [[ -z "$INSTALL_SOURCE_MANIFEST_URL" ]] || args+=(--source-manifest-url "$INSTALL_SOURCE_MANIFEST_URL")
  [[ -z "$INSTALL_SOURCE_RELEASE_CHANNEL" ]] || args+=(--source-release-channel "$INSTALL_SOURCE_RELEASE_CHANNEL")
  reply="$(/usr/bin/python3 -I -B "$retained/scripts/lib/aegis_installer_auto_v2.py" "${args[@]}")" || { printf '%s\n' 'AUTO_V2_INSTALL_REFUSED phase=passive_receipt' >&2; return 1; }
  IFS= read -r -d '' passive_reply_program <<'PY_AUTO_PASSIVE_REPLY' || true
import json,pathlib,sys
raw=sys.argv[1]
if len(raw)>8192: raise SystemExit('AUTO passive receipt is oversized')
value=json.loads(raw)
if (type(value) is not dict or set(value)!={'status','phase','bundle_dir'} or
    value['status'] not in ('fresh','resume') or
    value['phase'] not in ('prefix','actors-starting','passive-ready','first-arm') or
    type(value['bundle_dir']) is not str or
    value['bundle_dir']!='/var/lib/aegis-auto/control/fresh-passive-input'):
    raise SystemExit('AUTO passive receipt refused')
print(value['status']);print(value['phase']);print(value['bundle_dir'])
PY_AUTO_PASSIVE_REPLY
  parsed="$(printf '%s' "$passive_reply_program" | python3 -I - "$reply")" || return 1
  local -a fields
  fields=()
  while IFS= read -r line; do fields+=("$line"); done <<< "$parsed"
  [[ "${#fields[@]}" == 3 ]] || return 1
  AUTO_V2_PASSIVE_PHASE="${fields[1]}"
  AUTO_V2_PASSIVE_STATUS="${fields[0]}"
  AUTO_V2_PASSIVE_BUNDLE="${fields[2]}"
  if [[ "$operation" == passive-ready ]]; then
    [[ "$AUTO_V2_PASSIVE_PHASE" == passive-ready ]] || return 1
  fi
}

auto_v2_start_missing_passive_actors() {
  local retained="$1" original_bundle="$2" reply parsed unit missing missing_actors_program
  local -a args=(passive-actors --install-fd "$STAGE_AUTO_INSTALL_LOCK_FD"
    --fresh-origin "$AUTO_V2_PASSIVE_ORIGIN"
    --public-payload-root "$retained" --bundle-dir "$original_bundle")
  [[ -z "${AUTO_V2_REQUESTED_MODE:-}" ]] || args+=(--requested-mode "$AUTO_V2_REQUESTED_MODE")
  [[ -z "$MASQUE_SERVER" ]] || args+=(--masque-server "$MASQUE_SERVER")
  [[ -z "$MASQUE_CA" ]] || args+=(--masque-ca "$MASQUE_CA")
  [[ -z "$WIDE_INTERFACE" ]] || args+=(--wide-interface "$WIDE_INTERFACE")
  [[ -z "$INSTALL_SOURCE_MANIFEST_URL" ]] || args+=(--source-manifest-url "$INSTALL_SOURCE_MANIFEST_URL")
  [[ -z "$INSTALL_SOURCE_RELEASE_CHANNEL" ]] || args+=(--source-release-channel "$INSTALL_SOURCE_RELEASE_CHANNEL")
  reply="$(/usr/bin/python3 -I -B "$retained/scripts/lib/aegis_installer_auto_v2.py" "${args[@]}")" || { printf '%s\n' 'AUTO_V2_INSTALL_REFUSED phase=passive_actors' >&2; return 1; }
  IFS= read -r -d '' missing_actors_program <<'PY_AUTO_MISSING_ACTORS' || true
import json,sys
raw=sys.argv[1]
if len(raw)>2048: raise SystemExit('AUTO actor receipt is oversized')
value=json.loads(raw)
fixed={'aegis-auto-guardian.service','aegis-auto-guardian-watchdog.service',
       'aegis-auto-witness-topology.service','aegis-auto-trace-rollback-actor.service'}
if (type(value) is not dict or set(value)!={'status','missing'} or
    value['status']!='actors-starting' or type(value['missing']) is not list or
    len(value['missing'])!=len(set(value['missing'])) or
    not all(type(name) is str and name in fixed for name in value['missing'])):
    raise SystemExit('AUTO actor receipt refused')
for name in value['missing']: print(name)
PY_AUTO_MISSING_ACTORS
  parsed="$(printf '%s' "$missing_actors_program" | python3 -I - "$reply")" || return 1
  local -a missing_units
  missing_units=()
  if [[ -n "$parsed" ]]; then
    while IFS= read -r missing; do missing_units+=("$missing"); done <<< "$parsed"
  fi
  # Fixed dependency order; the coordinator's list is a read-only locator.
  for unit in aegis-auto-witness-topology.service \
              aegis-auto-trace-rollback-actor.service \
              aegis-auto-guardian-watchdog.service \
              aegis-auto-guardian.service; do
    for missing in "${missing_units[@]}"; do
      if [[ "$missing" == "$unit" ]]; then
        /usr/bin/systemctl start "$unit" || return 1
      fi
    done
  done
}

auto_v2_passive_locate() {
  local retained="$1" reply parsed line passive_locate_program
  reply="$(/usr/bin/python3 -I -B "$retained/scripts/lib/aegis_installer_auto_v2.py" \
    passive-locate --install-fd "$STAGE_AUTO_INSTALL_LOCK_FD")" || { printf '%s\n' 'AUTO_V2_INSTALL_REFUSED phase=passive_locate' >&2; return 1; }
  IFS= read -r -d '' passive_locate_program <<'PY_AUTO_PASSIVE_LOCATE' || true
import json,pathlib,sys
raw=sys.argv[1]
if len(raw)>8192: raise SystemExit('AUTO passive locator is oversized')
value=json.loads(raw)
if value=={'status':'absent'}:
    print('absent');print('-');print('-');print('-');print('-')
elif (type(value) is dict and set(value)=={'status','public_payload_root','bundle_dir','snapshot_dir','fresh_origin'} and
      value['status']=='intent' and
      value['fresh_origin'] in ('packaged','source-layout') and
      all(type(value[key]) is str and value[key].startswith('/') and
          '\n' not in value[key] and '\r' not in value[key]
          for key in ('public_payload_root','bundle_dir','snapshot_dir')) and
      value['snapshot_dir']=='/var/lib/aegis-auto/control/fresh-passive-input' and
      pathlib.Path(value['public_payload_root']).parent==pathlib.Path('/var/lib/aegis-auto/releases')):
    print('intent');print(value['public_payload_root']);print(value['bundle_dir']);print(value['snapshot_dir']);print(value['fresh_origin'])
else:
    raise SystemExit('AUTO passive locator refused')
PY_AUTO_PASSIVE_LOCATE
  parsed="$(printf '%s' "$passive_locate_program" | python3 -I - "$reply")" || return 1
  local -a fields
  fields=()
  while IFS= read -r line; do fields+=("$line"); done <<< "$parsed"
  [[ "${#fields[@]}" == 5 ]] || return 1
  AUTO_V2_LOCATED_STATUS="${fields[0]}"
  if [[ "$AUTO_V2_LOCATED_STATUS" == absent ]]; then
    AUTO_V2_LOCATED_ROOT="" AUTO_V2_LOCATED_ORIGINAL="" AUTO_V2_LOCATED_SNAPSHOT="" AUTO_V2_LOCATED_ORIGIN=""
  else
    AUTO_V2_LOCATED_ROOT="${fields[1]}"
    AUTO_V2_LOCATED_ORIGINAL="${fields[2]}"
    AUTO_V2_LOCATED_SNAPSHOT="${fields[3]}"
    AUTO_V2_LOCATED_ORIGIN="${fields[4]}"
  fi
}

auto_v2_admit_pristine_package() {
  # A freshly installed client DEB leaves only its package-owned binary as an
  # existing-install signal. Keep the original InstallLock through enrollment
  # and the later passive phase; a stale or different package remains upgrade.
  [[ "$EUID" == 0 && "$(detect_os_kind)" == linux && "$AUTO_PROFILE" == 1 ]] || return 1
  install_root_auto_native_role || return 1
  [[ "$AUTO_NATIVE_ROLE" == admin ]] || return 1
  install_binary "aegis-client" "aegis-client" /usr/local/bin preflight || return 1
  stage_auto_install_lock_acquire || return 1
  local retained reply
  retained="$(auto_v2_retain_public_payload)" || return 1
  auto_v2_passive_locate "$retained" || return 1
  if [[ "$AUTO_V2_LOCATED_STATUS" == intent ]]; then
    [[ "$AUTO_V2_LOCATED_ROOT" == "$retained" && "${DEVICE_BUNDLE:-0}" != 1 ]] || {
      echo 'Existing automatic device preparation requires its dedicated recovery path.' >&2
      return 1
    }
    if [[ -z "$BUNDLE_PATH" ]]; then
      BUNDLE_PATH="$AUTO_V2_LOCATED_SNAPSHOT"
    fi
    AUTO_V2_PASSIVE_ORIGIN="$AUTO_V2_LOCATED_ORIGIN"
  else
    [[ -n "$BUNDLE_PATH" ]] || return 1
    if [[ "${SOURCE_LAYOUT:-0}" == 1 ]]; then
      AUTO_V2_PASSIVE_ORIGIN=source-layout
    else
      AUTO_V2_PASSIVE_ORIGIN=packaged
      reply="$(/usr/bin/python3 -I -B "$retained/scripts/lib/aegis_installer_auto_v2.py" \
        admit-fresh-package --public-payload-root "$retained" \
        --install-fd "$STAGE_AUTO_INSTALL_LOCK_FD")" || {
        printf '%s\n' 'AUTO_V2_INSTALL_REFUSED phase=admit_fresh_package' >&2
        return 1
      }
      [[ "$reply" == '{"status":"fresh"}' ]] || return 1
    fi
  fi
  AUTO_FRESH_PACKAGE_ROOT="$retained"
  AUTO_FRESH_PACKAGE=1
}

auto_v2_install_and_release_package_lock() {
  local status=0
  install_client_auto_v2 "$@" || status=$?
  if [[ "${AUTO_FRESH_PACKAGE:-0}" == 1 ]]; then
    exec {STAGE_AUTO_INSTALL_LOCK_FD}>&-
  fi
  return "$status"
}

auto_v2_selected_plan() {
  local candidate="$1" planning_config="$2" metadata="$3"
  local -a planner_args=(profile auto --config "$planning_config" --state-dir "$metadata" --json)
  [[ -z "${AUTO_V2_REQUESTED_MODE:-}" ]] || planner_args+=(--requested-mode "$AUTO_V2_REQUESTED_MODE")
  "$candidate" "${planner_args[@]}" | python3 -I -c '
import json,sys
p=json.load(sys.stdin)
assert p.get("schema")=="aegis_auto_install_plan_v1" and p.get("status")=="planned"
assert p.get("product_mode") in ("socks-only","wide-redirect-safe","full-wide-tun")
assert p.get("connectivity_verified") is False
print(p["product_mode"])
'
}

install_client_auto_v2() (
  set -euo pipefail
  local prefix="$1" config_root="$2" state_dir="$3" log_dir="$4" events="$5" choice="$6"
  local helper_dir=/usr/local/lib/aegis/helpers metadata=/var/lib/aegis-install/auto-client
  local guardian_metadata=/var/lib/aegis-install/client
  local AEGIS_WIDE_LIB_DIR="$helper_dir"
  local candidate="$PREFLIGHT_CLIENT_BINARY" installed=/usr/local/bin/aegis-client
  [[ "$(detect_os_kind)" == linux && "$EUID" == 0 && "$prefix" == /usr/local &&
     "$config_root" == /etc/aegis/client && "$state_dir" == /var/lib/aegis-client &&
     "$log_dir" == /var/log/aegis-client && "$SYSTEMD_DIR" == /etc/systemd/system &&
     "$ENV_DIR" == /etc/default ]] || {
    echo 'Automatic V2 installation requires Linux root and the standard system paths.' >&2; return 1;
  }
  systemd_activation_requested || {
    echo 'Automatic V2 installation requires systemd activation.' >&2; return 1;
  }
  [[ ( -z "$choice" || "$choice" == none ) && -n "$BUNDLE_PATH" ||
     "$choice" == upgrade && -z "$BUNDLE_PATH" ]] || {
    echo 'Automatic V2 currently accepts a fresh access bundle or an upgrade preserving existing credentials. Credential replacement requires recovery first; existing installation has not been changed.' >&2; return 1;
  }
  [[ "$("$candidate" profile auto-config protocol)" == auto-config-snapshot-v2 ]] || {
    echo 'Selected client does not support the required AUTO V2 transaction.' >&2; return 1;
  }
  install_root_auto_native_role || return 1
  [[ "$AUTO_NATIVE_ROLE" == admin ]] || {
    echo 'Automatic V2 requires an authenticated administrative payload with protected helpers and units.' >&2; return 1;
  }
  require_asset "$ROOT/scripts/lib/aegis_installer_auto_v2.py"
  if [[ -n "$CLIENT_PACKAGE" || "$choice" == upgrade && -e /var/lib/aegis-auto/control/v2-enabled ]]; then
    [[ "$choice" == upgrade && -z "$BUNDLE_PATH" && ( -z "$CLIENT_PACKAGE" || "$CLIENT_PACKAGE" == /* ) ]] || return 1
    if [[ "$AUTO_V2_REQUESTED_MODE" == socks-only &&
          ! -e /var/lib/aegis-auto/control/passive-package-preinst.json &&
          ! -L /var/lib/aegis-auto/control/passive-package-preinst.json &&
          ! -e /var/lib/aegis-auto/control/passive-successor-retirement-intent.json &&
          ! -L /var/lib/aegis-auto/control/passive-successor-retirement-intent.json ]]; then
      /usr/local/bin/aegis-client auto-verify-current-socks >/dev/null || return 1
    fi
    stage_auto_install_lock_acquire || return 1
    ROOT="$(auto_v2_retain_public_payload)" || return 1
    flock -u "$STAGE_AUTO_INSTALL_LOCK_FD" || return 1
    exec {STAGE_AUTO_INSTALL_LOCK_FD}>&-
    local -a upgrade_args=(upgrade-package --public-payload-root "$ROOT")
    [[ -z "$CLIENT_PACKAGE" ]] || upgrade_args+=(--incoming-deb "$CLIENT_PACKAGE")
    [[ -z "$AUTO_V2_REQUESTED_MODE" ]] || upgrade_args+=(--requested-mode "$AUTO_V2_REQUESTED_MODE")
    # The incoming retained release owns the retry coordinator. The installed
    # predecessor remains the authority for its Stop and retirement proofs.
    /usr/bin/python3 -I -B "$ROOT/scripts/lib/aegis_installer_auto_v2.py" "${upgrade_args[@]}"
    return $?
  fi
  # The shell owns only passive asset preparation. Close this exact descriptor
  # before the single Rust worker acquires its own original InstallLock.
  if [[ "${AUTO_FRESH_PACKAGE:-0}" == 1 ]]; then
    [[ -n "${STAGE_AUTO_INSTALL_LOCK_FD:-}" && -n "${AUTO_FRESH_PACKAGE_ROOT:-}" ]] || return 1
    ROOT="$AUTO_FRESH_PACKAGE_ROOT"
  else
    stage_auto_install_lock_acquire || return 1
    ROOT="$(auto_v2_retain_public_payload)" || return 1
  fi
  if [[ -z "$AUTO_V2_PASSIVE_ORIGIN" ]]; then
    if [[ "${SOURCE_LAYOUT:-0}" == 1 ]]; then
      AUTO_V2_PASSIVE_ORIGIN=source-layout
    else
      AUTO_V2_PASSIVE_ORIGIN=packaged
    fi
  fi
  local original_bundle="$BUNDLE_PATH"
  auto_v2_passive_receipt passive-intent "$ROOT" "$original_bundle" || return 1
  BUNDLE_PATH="$AUTO_V2_PASSIVE_BUNDLE"
  if [[ "$AUTO_V2_PASSIVE_STATUS" == fresh ]]; then
  # The passive receipt holds the exact config. Refuse a blocked planner or
  # selected capture helper before starting any passive actor. Repeat the
  # plan below against current host and metadata state before installation.
  local early_planning_config="$BUNDLE_PATH/aegis-client.toml" early_selected
  early_selected="$(auto_v2_selected_plan "$candidate" "$early_planning_config" "$metadata")" || return 1
  if [[ "${AUTO_DEVICE_V2_REQUIRED:-0}" == 1 && "$early_selected" != full-wide-tun ]]; then
    echo 'Enrolled full-wide device profile cannot be downgraded by host planning.' >&2
    return 1
  fi
  case "$early_selected" in
    full-wide-tun) preflight_wide_capture client-ipv6-tun-smoltcp || return $? ;;
    wide-redirect-safe) preflight_wide_capture client-wide-redirect || return $? ;;
  esac
  python3 -I -B - <<'PY_AUTO_PASSIVE' || return 1
import os, pathlib, stat, subprocess

# The preceding typed passive admission authenticates static package units by
# exact source bytes/modes. Their mere presence is not an active generation.
# Existing installation generations require their explicit owned upgrade.
# Refuse before replacing even one authenticated helper or passive unit.
for raw in ('/etc/systemd/system/aegis-device-egress-guard.service',
            '/var/lib/aegis-install/client/device-guard.conf',
            '/var/lib/aegis-install/client/auto-guardian-install.json',
            '/var/lib/aegis-install/client/auto-stage-owner.json',
            '/var/lib/aegis-install/client/auto-watchdog-pending.json',
            '/var/lib/aegis-install/client/auto-stop-intent.json',
            '/var/lib/aegis-auto/control/current.json'):
    path = pathlib.Path(raw)
    if path.exists() or path.is_symlink():
        raise SystemExit('Existing AUTO generation requires authenticated recovery before asset replacement')
stages = pathlib.Path('/run/aegis-installer-config-snapshots')
if stages.exists() or stages.is_symlink():
    info = stages.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or
        next(stages.iterdir(), None) is not None):
        raise SystemExit('Retained AUTO stages require recovery before asset replacement')

def call(*argv):
    result = subprocess.run(['/usr/bin/systemctl', *argv], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=5, check=False)
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 4096:
        raise SystemExit('AUTO passive asset preflight refused')
    return result.stdout.decode('utf-8', 'strict')

def inactive(unit):
    properties = ['Id', 'LoadState', 'ActiveState', 'SubState', 'FragmentPath',
                  'DropInPaths', 'Triggers', 'NeedDaemonReload', 'UnitFileState']
    if unit.endswith('.service'):
        properties += ['MainPID', 'ControlPID', 'ControlGroup', 'NFileDescriptorStore']
    args = [part for name in properties for part in ('-p', name)]
    values = dict(line.split('=', 1) for line in call('show', unit, '--no-pager',
                                                    *args).splitlines())
    if (values.get('Id') != unit or values.get('LoadState') not in ('loaded', 'not-found') or
        values.get('ActiveState') != 'inactive' or values.get('SubState') != 'dead'):
        raise SystemExit('AUTO asset replacement requires authenticated stopped services')
    if unit.endswith('.service') and (
        values.get('MainPID') != '0' or values.get('ControlPID') != '0' or
        values.get('ControlGroup') not in ('', None) or
        values.get('NFileDescriptorStore') != '0'):
        raise SystemExit('AUTO asset replacement requires authenticated stopped services')
    if unit in ('aegis-device-dhcp-refresh.service', 'aegis-device-dhcp-refresh.timer'):
        if values.get('DropInPaths') != '' or values.get('NeedDaemonReload') != 'no':
            raise SystemExit('AUTO DHCP passive unit configuration is not exact')
        if values.get('LoadState') == 'loaded' and (
            values.get('FragmentPath') != '/etc/systemd/system/' + unit or
            values.get('UnitFileState') != ('disabled' if unit.endswith('.timer') else 'static') or
            values.get('Triggers') != ('aegis-device-dhcp-refresh.service'
                                       if unit.endswith('.timer') else '')):
            raise SystemExit('AUTO DHCP passive unit configuration is not exact')

for unit in ('aegis-client.service', 'aegis-device-egress-guard.service',
             'aegis-device-dhcp-refresh.service',
             'aegis-device-dhcp-refresh.timer',
             'aegis-auto-guardian.service',
             'aegis-auto-guardian-watchdog.service'):
    inactive(unit)
if call('list-units', '--all', '--plain', '--no-legend', '--no-pager',
        'aegis-auto@*.service').strip():
    raise SystemExit('AUTO private owner must finish its authenticated stop before replacement')
if any('aegis-' in line for line in call('list-jobs', '--plain', '--no-legend',
                                       '--no-pager').splitlines()):
    raise SystemExit('AUTO pending service job prevents asset replacement')
PY_AUTO_PASSIVE
  fi
  candidate="$ROOT/bin/aegis-client"
  if [[ "$AUTO_V2_PASSIVE_PHASE" == prefix ]]; then
  # Gate the existing fixed unit and reload PID1 before persisting v2-enabled;
  # the later V2 publication also carries the source-owned condition.
  auto_v2_prepare_boot_gate || return 1
  # Freeze the already authenticated candidate without rebuilding it. The
  # content-addressed root-owned copy survives shell temp cleanup and is never
  # overwritten while a retained stage may refer to its generation.
  local candidate_program
  IFS= read -r -d '' candidate_program <<'PY_AUTO_CANDIDATE' || true
import hashlib, importlib.util, os, pathlib, re, stat, subprocess, sys
lock_fd = int(sys.argv[3])
lock = os.fstat(lock_fd)
named_lock = os.stat('/run/aegis-auto-install.lock', follow_symlinks=False)
if (not stat.S_ISREG(lock.st_mode) or lock.st_uid != lock.st_gid or lock.st_uid != 0 or
    lock.st_nlink != 1 or stat.S_IMODE(lock.st_mode) != 0o600 or
    (lock.st_dev, lock.st_ino) != (named_lock.st_dev, named_lock.st_ino)):
    raise SystemExit('AUTO boot interlock requires the original install lock')
locks = [line.split() for line in pathlib.Path(f'/proc/self/fdinfo/{lock_fd}').read_text().splitlines()
         if line.startswith('lock:')]
if (len(locks) != 1 or len(locks[0]) != 9 or
    locks[0][2:5] != ['FLOCK', 'ADVISORY', 'WRITE'] or locks[0][7:] != ['0', 'EOF']):
    raise SystemExit('AUTO boot interlock requires the original install lock')
device = re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)', locks[0][6])
if (device is None or (int(device[1], 16), int(device[2], 16), int(device[3])) !=
    (os.major(lock.st_dev), os.minor(lock.st_dev), lock.st_ino)):
    raise SystemExit('AUTO boot interlock requires the original install lock')
source = pathlib.Path(sys.argv[1])
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
        info.st_nlink != 1 or info.st_mode & 0o022 or not info.st_mode & 0o111 or
        not 0 < info.st_size <= 512 << 20):
        raise SystemExit('AUTO candidate is not a protected executable')
    with os.fdopen(os.dup(fd), 'rb') as stream:
        raw = stream.read((512 << 20) + 1)
    after = os.fstat(fd)
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) != info.st_size or not raw.startswith(b'\x7fELF') or
        any(getattr(info, key) != getattr(after, key) for key in fields)):
        raise SystemExit('AUTO candidate generation changed')
finally:
    os.close(fd)
payload = pathlib.Path(sys.argv[2])
retained_release = payload.parent == pathlib.Path('/var/lib/aegis-auto/releases')
parent = (payload / 'bin' if retained_release else
          pathlib.Path('/var/lib/aegis-auto/candidates') / hashlib.sha256(raw).hexdigest())
current = pathlib.Path('/')
for part in parent.parts[1:]:
    current /= part
    try:
        current.mkdir(mode=0o700)
    except FileExistsError:
        pass
    item = current.lstat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
        raise SystemExit('AUTO candidate parent is untrusted')
target = parent / 'aegis-client'
try:
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o555)
except FileExistsError:
    item = target.lstat()
    if (not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_gid != 0 or
        item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o555 or target.read_bytes() != raw):
        raise SystemExit('AUTO retained candidate generation is not exact')
else:
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o555)
        os.fsync(stream.fileno())
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
# Prepare the separate recovery namespace without following any component.
# It is deliberately outside all three trees captured by V2 Prepare.
held = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    for component in ('var', 'lib', 'aegis-auto', 'control'):
        try:
            os.mkdir(component, 0o700, dir_fd=held)
            os.fsync(held)
        except FileExistsError:
            pass
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
        item = os.fstat(child)
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_gid != 0 or
            item.st_mode & 0o022 or
            (component == 'control' and stat.S_IMODE(item.st_mode) != 0o700)):
            os.close(child)
            raise SystemExit('AUTO recovery namespace is untrusted')
        os.close(held)
        held = child
    # Persist the boot interlock before any client unit can be published. A
    # crash before Finalize must not make the fixed service eligible to bypass
    # the fresh-boot V2 coordinator. Generation seals are separate evidence.
    gate = b'{"schema":"aegis_installer_auto_v2_enabled_v1"}\n'
    coordinator = payload / 'scripts/lib/aegis_installer_auto_v2.py'
    spec = importlib.util.spec_from_file_location('aegis_marker_atomic', coordinator)
    if spec is None or spec.loader is None:
        raise SystemExit('AUTO boot interlock source unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        os.stat('v2-enabled', dir_fd=held, follow_symlinks=False)
    except FileNotFoundError:
        try:
            module.atomic_exclusive_bytes(held, 'v2-enabled', gate, 0o600)
        except FileExistsError:
            pass
    gate_fd = os.open('v2-enabled', os.O_RDONLY | os.O_NOFOLLOW |
                      os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=held)
    try:
        item = os.fstat(gate_fd)
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != item.st_gid or item.st_uid != 0 or
            item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600 or item.st_size != len(gate) or
            os.read(gate_fd, len(gate) + 1) != gate):
            raise SystemExit('AUTO boot interlock is foreign or incomplete')
        after = os.fstat(gate_fd)
        named = os.stat('v2-enabled', dir_fd=held, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(item, field) != getattr(observed, field)
               for observed in (after, named) for field in fields):
            raise SystemExit('AUTO boot interlock changed during readback')
    finally:
        os.close(gate_fd)
finally:
    os.close(held)
# Execute the exact retained bytes, not the earlier mutable pathname.
for argv, expected in (([str(target), '--version'], None),
                       ([str(target), 'profile', 'auto-config', 'protocol'],
                        b'auto-config-snapshot-v2\n')):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=10, check=False)
    if (result.returncode or len(result.stdout) > 8192 or len(result.stderr) > 8192 or
        (expected is not None and result.stdout != expected)):
        raise SystemExit('Retained AUTO executable preflight refused')
print(target)
PY_AUTO_CANDIDATE
  candidate="$(printf '%s' "$candidate_program" | python3 -I -B - "$candidate" "$ROOT" "$STAGE_AUTO_INSTALL_LOCK_FD")" || return 1
  PREFLIGHT_CLIENT_BINARY="$candidate"
  export AEGIS_ROOT_STATE_CLIENT="$candidate"
  FORCE=1
  # This override lives only in the fresh passive subshell. The original
  # InstallLock and prefix proof established that no AUTO actor can execute
  # these files; publish each complete byte stream through the atomic writer
  # without the generic install helper's truncating copy or backup sidecar.
  install_copy_file() {
    local source="$1" destination="$2" mode="$3"
    require_asset "$source" || return 1
    install_atomic_write "$destination" "$mode" strict < "$source"
  }
  install_client_wide_helpers "$helper_dir" || return 1
  # Provision describes exact installed bytes and the machine/root anchor. It
  # does not grant native egress or substitute a guard assessment.
  ensure_dir "$guardian_metadata" || return 1
  local provision
  provision="$(/usr/bin/python3 -I -B "$helper_dir/lib/aegis_auto_guardian.py" provision "$candidate")" || return 1
  python3 -I - "$provision" <<'PY_AUTO_PASSIVE_RECEIPT' || return 1
import json, sys
receipt = json.loads(sys.argv[1])
assert receipt.get('schema') == 'aegis_auto_guardian_install_v1'
assert receipt.get('guard_unit_sha256') is None
PY_AUTO_PASSIVE_RECEIPT
  if [[ -e "$guardian_metadata/auto-guardian-install.json" || -L "$guardian_metadata/auto-guardian-install.json" ]]; then
    python3 -I - "$guardian_metadata/auto-guardian-install.json" "$provision" <<'PY_AUTO_PROVISION' || return 1
import json, pathlib, stat, sys
path = pathlib.Path(sys.argv[1]); info = path.lstat()
if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096 or
    json.loads(path.read_bytes()) != json.loads(sys.argv[2])):
    raise SystemExit('Existing AUTO provisioning requires its authenticated upgrade transition')
PY_AUTO_PROVISION
  else
    printf '%s\n' "$provision" | install_atomic_write "$guardian_metadata/auto-guardian-install.json" 0600 strict || return 1
  fi
  /usr/bin/systemctl daemon-reload || return 1
  /usr/bin/systemctl start aegis-auto-guardian-watchdog.service || return 1
  /usr/bin/systemctl start aegis-auto-guardian.service || return 1
  auto_v2_passive_receipt passive-ready "$ROOT" "$original_bundle" || return 1
  else
    [[ "$AUTO_V2_PASSIVE_PHASE" == actors-starting ||
       "$AUTO_V2_PASSIVE_PHASE" == passive-ready ||
       "$AUTO_V2_PASSIVE_PHASE" == first-arm ]] || return 1
    PREFLIGHT_CLIENT_BINARY="$candidate"
    export AEGIS_ROOT_STATE_CLIENT="$candidate"
    FORCE=1
    if [[ "$AUTO_V2_PASSIVE_PHASE" == actors-starting ]]; then
      # The coordinator has authenticated complete passive source and every
      # already live actor. Start only its named missing units. No helper,
      # unit, provision receipt or guard state is recopied in this branch.
      auto_v2_start_missing_passive_actors "$ROOT" "$original_bundle" || return 1
      auto_v2_passive_receipt passive-ready "$ROOT" "$original_bundle" || return 1
    elif [[ "$AUTO_V2_PASSIVE_PHASE" == passive-ready ]]; then
      auto_v2_passive_receipt passive-ready "$ROOT" "$original_bundle" || return 1
    fi
  fi
  # Mutable guardian policy and owner journals must remain outside the tree
  # V2 publishes atomically. Native binding legitimately changes those files.
  ensure_dir "$metadata" || return 1
  if [[ "$choice" == upgrade && ! -e "$metadata/wide-profile.json" ]]; then
    "$candidate" profile metadata read --path "$guardian_metadata/wide-profile.json" |
      install_atomic_write "$metadata/wide-profile.json" 0600 strict || return 1
  fi
  local planning_config="${BUNDLE_PATH:+$BUNDLE_PATH/aegis-client.toml}" selected_mode
  [[ -n "$planning_config" ]] || planning_config="$config_root/aegis.toml"
  selected_mode="$(auto_v2_selected_plan "$candidate" "$planning_config" "$metadata")" || return 1
  if [[ "${AUTO_DEVICE_V2_REQUIRED:-0}" == 1 && "$selected_mode" != full-wide-tun ]]; then
    echo 'Enrolled full-wide device profile cannot be downgraded by host planning.' >&2
    return 1
  fi
  if [[ "$AUTO_V2_PASSIVE_PHASE" == first-arm && "$selected_mode" == socks-only ]]; then
    echo 'A protected first-arm transition cannot be resumed as SOCKS.' >&2
    return 1
  fi
  if [[ "$selected_mode" != socks-only ]]; then
    auto_v2_first_arm "$candidate" "$planning_config" "$selected_mode" "$helper_dir" || return $?
    "$candidate" profile metadata read --path "$guardian_metadata/auto-guard-first-arm.json" |
      auto_v2_first_arm_exact_write "$metadata/auto-guard-first-arm.json" 0600 || return 1
  fi
  flock -u "$STAGE_AUTO_INSTALL_LOCK_FD" || return 1
  exec {STAGE_AUTO_INSTALL_LOCK_FD}>&-
  local -a args=(install --candidate-binary "$candidate" --installed-binary "$installed"
    --public-payload-root "$ROOT" --config-root "$config_root" --state-dir "$state_dir"
    --metadata-dir "$metadata" --staging-parent /run/aegis-installer-config-snapshots
    --runtime-events "$events" --existing-choice "${choice:-none}")
  [[ -z "${AUTO_V2_REQUESTED_MODE:-}" ]] || args+=(--requested-mode "$AUTO_V2_REQUESTED_MODE")
  [[ -z "$BUNDLE_PATH" ]] || args+=(--bundle-dir "$BUNDLE_PATH")
  [[ -z "$MASQUE_SERVER" ]] || args+=(--masque-server "$MASQUE_SERVER")
  [[ -z "$MASQUE_CA" ]] || args+=(--masque-ca "$MASQUE_CA")
  [[ -z "$WIDE_INTERFACE" ]] || args+=(--wide-interface "$WIDE_INTERFACE")
  [[ -z "$INSTALL_SOURCE_MANIFEST_URL" ]] || args+=(--source-manifest-url "$INSTALL_SOURCE_MANIFEST_URL")
  [[ -z "$INSTALL_SOURCE_RELEASE_CHANNEL" ]] || args+=(--source-release-channel "$INSTALL_SOURCE_RELEASE_CHANNEL")
  /usr/bin/python3 -I -B "$helper_dir/lib/aegis_installer_auto_v2.py" "${args[@]}" || return 1
  # An incomplete installation stays fenced on reboot. Enable the source-owned
  # boot controller only after the active generation was actually sealed.
  if [[ "$choice" != upgrade ]]; then
    /usr/bin/systemctl enable aegis-auto-config.service || return 1
  fi
)

install_client_role() {
  local prefix="${PREFIX:-$(default_prefix)}"
  local config_root="${CONFIG_DIR:-$(default_client_config_dir)}"
  local state_dir="${STATE_DIR:-$(default_client_state_dir)}"
  local log_dir="${LOG_DIR:-$(default_client_log_dir)}"
  local helper_dir="${prefix}/lib/aegis/helpers"
  local bin_dir="${prefix}/bin"
  local bin_path="${bin_dir}/aegis-client"
  local config_path="${config_root}/aegis.toml"
  local ca_path="${config_root}/ca.pem"
  local privileged_dns_example_path="${config_root}/aegis-privileged-dns.toml.example"
  local privileged_dns_profile_installed=0
  # Admit a fresh explicit SOCKS selection to current V2 on standard Linux
  # system paths. Existing V2 generations retain their sealed prior mode;
  # legacy installations continue through their explicit legacy path.
  if [[ "$PRODUCT_MODE" == socks-only && "$EUID" == 0 &&
        "$(detect_os_kind)" == linux && "$prefix" == /usr/local &&
        "$config_root" == /etc/aegis/client && "$state_dir" == /var/lib/aegis-client &&
        ( -e /var/lib/aegis-auto/control/v2-enabled ||
          ( ! -e "$config_path" && -n "$BUNDLE_PATH$BUNDLE_URL_FILE" ) ) &&
        -z "${DEVICE_ID}${DEVICE_CERTIFICATE}${DEVICE_IDENTITY_DIR}${DEVICE_INVITATION_FILE:-}" ]]; then
    [[ -z "${WIDE_UDP_POLICY}${WIDE_DNS_POLICY}${WIDE_IPV6_POLICY}${OPERATOR_TRANSPORT}${FRONTED_AUTHORITY}${GENEVA_STRATEGY_FILE}" && "$UDP_CARRY" != 1 ]] || {
      echo 'Current V2 SOCKS refuses manual capture or transport policy overrides.' >&2
      return 1
    }
    AUTO_PROFILE=1
    AUTO_V2_REQUESTED_MODE=socks-only
  fi
  local runtime_events_path="${log_dir}/runtime-events.jsonl"
  # --no-runtime-events: route the client's event stream to /dev/null so nothing
  # is persisted on disk (forensic trail / hostile-host hardening).
  if [[ "${NO_RUNTIME_EVENTS:-0}" == "1" ]]; then
    runtime_events_path="/dev/null"
  elif [[ "${AUTO_PROFILE:-0}" == 1 ]]; then
    # Stock /var/log can be group-writable. V2 keeps its strict ancestry
    # policy and selects a protected sibling outside sealed client state.
    [[ "$log_dir" == /var/log/aegis-client ]] || {
      echo 'Automatic V2 uses its fixed protected runtime log directory; a custom log directory requires an explicit manual profile.' >&2
      return 1
    }
    runtime_events_path="/var/lib/aegis-client-logs/runtime/runtime-events.jsonl"
  fi
  local install_manifest_path
  local existing_install_choice=""

  SYSTEMD_DIR="${SYSTEMD_DIR:-$(default_systemd_dir)}"
  ENV_DIR="${ENV_DIR:-$(default_env_dir)}"
  helper_dir="$(default_client_helper_dir "${prefix}")"

  if [[ -n "${BUNDLE_PATH}" && -n "${BUNDLE_URL_FILE}" ]]; then
    echo "Use either --bundle or --bundle-url-file, not both" >&2
    exit 1
  fi
  if [[ -n "${BUNDLE_URL_FILE}" && -n "${DEVICE_ID}${DEVICE_CERTIFICATE}${DEVICE_IDENTITY_DIR}${DEVICE_INVITATION_FILE:-}" ]]; then
    echo "Device enrollment requires a trusted local public --bundle directory; archive enrollment is not supported by this path." >&2
    return 1
  fi

  # Ask first: cancellation must neither mutate local state nor consume a
  # one-time bundle URL. Applying upgrade/reinstall is deliberately delayed
  # until all remote and binary preflight checks have passed.
  existing_install_choice="$(resolve_existing_install_choice "client" "${config_root}")" || return $?
  if [[ "${existing_install_choice}" == "cancel" ]]; then
    apply_existing_install_choice "client" "${existing_install_choice}" || return $?
  fi

  # Explicit legacy capture selection must be admitted before replacing or
  # stopping an existing installation. Public device bundles retain their
  # separate typed role and activation transaction below.
  case "${OPERATOR_MODE:-}" in
    client-wide-redirect|client-wide-tproxy|client-wide-nfqueue-observer|client-ipv6-tun-smoltcp)
      if [[ -z "${BUNDLE_PATH}" || ! -f "${BUNDLE_PATH}/bundle.json" ]]; then
        preflight_wide_capture "${OPERATOR_MODE}" || return $?
      fi
      ;;
  esac

  # Transaction boundary: acquire and validate every remote client-bundle
  # input, and prove that the release binary executes on this host, BEFORE
  # touching an existing service, firewall, config, state, or binary. The old
  # ordering purged the working client first and only then fetched --bundle-url;
  # a timeout/403 therefore left a restricted-network user with an incomplete
  # installation even though later network rollback restored native routing.
  if [[ -n "${BUNDLE_URL_FILE}" ]]; then
    install_binary "aegis-client" "aegis-client" "$bin_dir" preflight || return $?
    [[ "$("$PREFLIGHT_CLIENT_BINARY" profile installer-secret version)" == installer-secret-v1 ]] || {
      echo "Selected release lacks the private installer input protocol." >&2; return 2;
    }
    # Call in the current shell so resolve_downloaded_bundle's TEMP_PATHS
    # registration survives until the EXIT cleanup trap. Command substitution
    # would run the resolver in a subshell and leak its temporary directory.
    resolve_downloaded_bundle "${BUNDLE_URL_FILE}" BUNDLE_PATH || return $?
  fi
  if [[ -n "${BUNDLE_PATH}" ]]; then
    if [[ ! -d "${BUNDLE_PATH}" ]]; then
      echo "Expected --bundle to point to a bundle directory" >&2
      exit 1
    fi
    # A relative --bundle may itself live below an affected temporary family.
    # Canonicalise it before crossing the purge boundary.
    BUNDLE_PATH="$(cd "${BUNDLE_PATH}" && pwd -P)"
    if [[ -f "${BUNDLE_PATH}/bundle.json" ]]; then
      DEVICE_BUNDLE=1
    elif [[ -n "${DEVICE_ID}${DEVICE_CERTIFICATE}${DEVICE_IDENTITY_DIR}${DEVICE_INVITATION_FILE:-}" ]]; then
      echo "Device enrollment requires a public aegis_device_bundle_v1, v2 or v3 profile." >&2
      return 1
    elif [[ ! -f "${BUNDLE_PATH}/aegis-client.toml" || ! -r "${BUNDLE_PATH}/aegis-client.toml" || ! -s "${BUNDLE_PATH}/aegis-client.toml" ||
      ! -f "${BUNDLE_PATH}/ca.pem" || ! -r "${BUNDLE_PATH}/ca.pem" || ! -s "${BUNDLE_PATH}/ca.pem" ]]; then
      echo "Bundle directory must contain readable nonempty aegis-client.toml and ca.pem" >&2
      exit 1
    fi
    # An in-place upgrade without --force cannot overwrite bundle-provided
    # config/CA. Reject it before replacing the binary or helpers.
    if [[ !( "${DEVICE_BUNDLE}" == 1 && -z "${DEVICE_CERTIFICATE}" ) && "${existing_install_choice}" != "reinstall" && "${FORCE}" -eq 0 && ( -f "${config_path}" || -f "${ca_path}" ) ]]; then
      echo "Client config already exists; rerun with --force to overwrite" >&2
      exit 1
    fi
  fi
  if [[ -z "${BUNDLE_PATH}" && -n "${DEVICE_ID}${DEVICE_CERTIFICATE}${DEVICE_IDENTITY_DIR}${DEVICE_INVITATION_FILE:-}" ]]; then
    echo "Device enrollment requires a trusted public --bundle directory." >&2
    return 1
  fi
  if [[ "${AUTO_PROFILE:-0}" == 1 && "$existing_install_choice" == upgrade &&
        -z "$CLIENT_PACKAGE" &&
        ( -n "$BUNDLE_PATH" ||
          ( -e /var/lib/aegis-auto/control/v2-enabled &&
            ! -e /var/lib/aegis-auto/control/current.json ) ) ]]; then
    auto_v2_admit_pristine_package || return 1
    existing_install_choice=none
  fi
  if [[ "$STAGE_AUTO_DEVICE_GUARD" == 1 ]]; then
    stage_auto_install_lock_acquire || return 1
    PREFLIGHT_CLIENT_BINARY="$(stage_auto_device_owner_binary)" || return 1
    stage_auto_device_owner_admit >/dev/null || return 1
    "$PREFLIGHT_CLIENT_BINARY" --version >/dev/null || return 1
  else
    install_binary "aegis-client" "aegis-client" "${bin_dir}" preflight
  fi
  if [[ "${DEVICE_BUNDLE}" == 1 && "${AUTO_PROFILE:-0}" == 1 &&
        "${SOURCE_LAYOUT:-0}" == 1 && "${AUTO_FRESH_PACKAGE:-0}" != 1 ]]; then
    # The source-layout device adapter may prepare identity before it renders
    # the four V2 input leaves. Locate any prior passive attempt first. A
    # bound device retry needs its own identity handoff and cannot be inferred
    # from the newly supplied public bundle.
    [[ -n "${STAGE_AUTO_INSTALL_LOCK_FD:-}" ]] || stage_auto_install_lock_acquire || return 1
    local retained_device_root
    retained_device_root="$(auto_v2_retain_public_payload)" || return 1
    auto_v2_passive_locate "$retained_device_root" || return 1
    if [[ "$AUTO_V2_LOCATED_STATUS" != absent ]]; then
      echo 'Existing automatic device preparation requires its dedicated recovery path.' >&2
      return 1
    fi
    ROOT="$retained_device_root"
    AUTO_FRESH_PACKAGE_ROOT="$retained_device_root"
    AUTO_FRESH_PACKAGE=1
    AUTO_V2_PASSIVE_ORIGIN=source-layout
  fi
  if [[ "${DEVICE_BUNDLE}" == 1 ]]; then
    local auto_device_v2_requested="${AUTO_PROFILE:-0}"
    AUTO_DEVICE_V2_REQUESTED="$auto_device_v2_requested"
    prepare_device_bundle "${config_root}" "${state_dir}" "$existing_install_choice" || return 1
    [[ "${DEVICE_INSTALL_READY:-0}" == 1 ]] || return 0
    if [[ "$DEVICE_PRODUCT_MODE" == full-wide-tun ]]; then
      if [[ "$auto_device_v2_requested" == 1 ]]; then
        [[ "$DEVICE_BUNDLE_SCHEMA" == aegis_device_bundle_v2 && "$DEVICE_ONLINE" == 0 ]] || {
          echo 'Automatic device V2 requires an offline v2 profile; online renewal remains on its dedicated device path.' >&2
          return 1
        }
        [[ -z "$existing_install_choice" || "$existing_install_choice" == none ]] || {
          echo 'An enrolled AUTO device generation requires the authenticated package upgrade or recovery path.' >&2
          return 1
        }
        AUTO_PROFILE=1
        AUTO_DEVICE_V2_REQUIRED=1
        auto_v2_device_input "$PREFLIGHT_CLIENT_BINARY" "$DEVICE_PUBLIC_BUNDLE" \
          "$DEVICE_IDENTITY_DIR" "$config_root" || return 1
        BUNDLE_PATH="$AUTO_V2_DEVICE_INPUT_PATH"
        auto_v2_install_and_release_package_lock "$prefix" "$config_root" "$state_dir" "$log_dir" \
          "$runtime_events_path" "$existing_install_choice"
        return $?
      fi
      install_device_full_wide_role "$prefix" "$config_root" "$state_dir" "$log_dir" "$runtime_events_path" "$existing_install_choice" "$STAGE_AUTO_DEVICE_GUARD"
      return $?
    fi
  fi
  if [[ "${AUTO_PROFILE:-0}" == 1 ]]; then
    # Preserve deterministic refusals before passive provisioning as well as
    # before the V2 worker. Existing credential generations are never replaced
    # by the legacy reinstall/purge implementation.
    if [[ -z "${BUNDLE_PATH}" && "${existing_install_choice}" == reinstall ]]; then
      echo "A fresh automatic reinstall requires --bundle or --bundle-url-file; use --upgrade to keep the existing configuration. Existing installation has not been changed." >&2
      return 1
    fi
    if [[ "${SYSTEMD_DIR}" != /etc/systemd/system ]]; then
      echo "Automatic activation requires the system service directory; use an explicit --profile for staged installations. Existing installation has not been changed." >&2
      return 1
    fi
    local auto_metadata
    auto_metadata=/var/lib/aegis-install/auto-client
    [[ -f "$auto_metadata/wide-profile.json" ]] || auto_metadata="$(dirname "$(install_manifest_path_for_role client "${state_dir}")")"
    if [[ -f "${config_path}" && ! -f "$auto_metadata/wide-profile.json" ]]; then
      echo "Existing client has no administrator-owned product profile; choose --profile explicitly once before automatic updates. Runtime-owned legacy planning data is not trusted." >&2
      return 1
    fi
    auto_v2_install_and_release_package_lock "$prefix" "$config_root" "$state_dir" "$log_dir" "$runtime_events_path" "$existing_install_choice"
    return $?
  fi
  install_manifest_path="$(install_manifest_path_for_role client "${state_dir}")"
  install_atomic_write "${install_manifest_path}" 0644 strict validate </dev/null
  # The candidate was authenticated and ABI-checked before this point. Legacy
  # purge/rollback can use its safe metadata CLI before the installed binary is
  # replaced; boot helpers later resolve the administrator-owned installed path.
  export AEGIS_ROOT_STATE_CLIENT="${PREFLIGHT_CLIENT_BINARY}"
  # These deterministic AUTO refusals inspect only existing path state. Admit
  # them before configuration custody can migrate/restart the old service.
  # The planner still reads only after the validated custody boundary below.
  if [[ "${AUTO_PROFILE:-0}" == "1" ]]; then
    if [[ -z "${BUNDLE_PATH}" && "${existing_install_choice}" == "reinstall" ]]; then
      echo "A fresh automatic reinstall requires --bundle or --bundle-url-file; use --upgrade to keep the existing configuration. Existing installation has not been changed." >&2
      return 1
    fi
    if [[ "${SYSTEMD_DIR}" != "/etc/systemd/system" ]]; then
      echo "Automatic activation requires the system service directory; use an explicit --profile for staged installations. Existing installation has not been changed." >&2
      return 1
    fi
    if [[ -f "${config_path}" && ! -f "$(dirname "${install_manifest_path}")/wide-profile.json" ]]; then
      echo "Existing client has no administrator-owned product profile; choose --profile explicitly once before automatic updates. Runtime-owned legacy planning data is not trusted." >&2
      return 1
    fi
  fi
  prepare_client_config_boundary "${config_root}" || return $?

  if [[ "${AUTO_PROFILE:-0}" == "1" ]]; then
    local auto_config="${config_path}"
    [[ -z "${BUNDLE_PATH}" ]] || auto_config="${BUNDLE_PATH}/aegis-client.toml"
    for auto_helper in aegis-wide-enable.sh aegis-wide-disable.sh aegis-wide-persist-install.sh janitor-wide-linux-tproxy.sh; do
      require_asset "${ROOT}/scripts/${auto_helper}"
    done
    resolve_auto_profile "${PREFLIGHT_CLIENT_BINARY}" "${auto_config}" "${state_dir}" || return $?
    # Config custody above may already migrate/restart the old configuration;
    # retain that ordering until the planner has a checked read contract. This
    # selected-mode check still precedes purge and installed asset replacement.
    preflight_wide_capture "${OPERATOR_MODE}" || return $?
    if [[ "${existing_install_choice}" == "upgrade" && -z "${BUNDLE_PATH}" ]]; then
      # Refresh managed binary/helper/service assets, with their existing
      # backup mechanism. The validated config is preserved by the helper.
      FORCE=1
    fi
  fi

  # Capture reinstall/mode switching is not an implicit privacy disconnect.
  # In-place full-wide upgrades keep the table while capture is replaced; a
  # destructive reinstall or limited-mode switch needs explicit recovery first.
  local legacy_guard_state=/var/lib/aegis-install/client/legacy-tun-guard.conf legacy_guard_policy=''
  if [[ -e "$legacy_guard_state" || -L "$legacy_guard_state" ]]; then
    legacy_guard_policy="$("${AEGIS_ROOT_STATE_CLIENT}" profile metadata read --path "$legacy_guard_state")" || return 1
    if [[ "$legacy_guard_policy" == *$'\narmed=1\n'* &&
          ( "${existing_install_choice}" == reinstall || "${PRODUCT_MODE:-}" != full-wide-tun ) ]]; then
      echo 'ERROR: explicitly disconnect the legacy TUN guard with aegis-wide-disable.sh before reinstalling or switching profiles.' >&2
      return 1
    fi
  fi
  apply_existing_install_choice "client" "${existing_install_choice}" "${BUNDLE_PATH:-}" || return $?
  # Reinstall purge already removes these units; the call remains idempotent
  # for both reinstall and in-place upgrade paths.
  deactivate_existing_wide_boot_units

  install_binary "aegis-client" "aegis-client" "${bin_dir}"
  ensure_dir "${config_root}"
  ensure_dir "${state_dir}"
  ensure_dir "${log_dir}"
  write_install_manifest client "${install_manifest_path}" "${bin_path}"
  install_client_wide_helpers "${helper_dir}" || return 1

  if [[ -n "${BUNDLE_PATH}" ]]; then
    if [[ "${FORCE}" -eq 0 && ( -f "${config_path}" || -f "${ca_path}" ) ]]; then
      echo "Client config already exists; rerun with --force to overwrite" >&2
      exit 1
    fi
    install_copy_file "${BUNDLE_PATH}/ca.pem" "${ca_path}" 0600
    if [[ "${DEVICE_BUNDLE}" == 1 ]]; then
      install_copy_file "${BUNDLE_PATH}/inner-ca.pem" "${config_root}/inner-ca.pem" 0600
    fi
    # A fronted full-wide bundle may carry a second, explicitly scoped trust
    # anchor for its direct MASQUE/UDP origin. Keep it separate from ca.pem:
    # the latter validates the public Cloudflare edge, while this file is used
    # only by relay.masque_ca_cert. An explicit --masque-ca still wins.
    if [[ -z "${MASQUE_CA}" && -f "${BUNDLE_PATH}/masque-ca.pem" ]]; then
      MASQUE_CA="${BUNDLE_PATH}/masque-ca.pem"
      echo "full-wide-tun: using bundled masque-ca.pem for the direct UDP leg." >&2
    fi
    install_text_file "${config_path}" 0600 "$(
      sed "s|__CLIENT_CA_CERT_PATH__|${ca_path}|g" "${BUNDLE_PATH}/aegis-client.toml"
    )"
    # v0.3.0: inject a per-install random SOCKS5 RFC 1929 auth_token so
    # rogue local processes (same UID, different application) cannot
    # piggyback on the tunnel by speaking SOCKS5 without credentials.
    # Done in-place after install_text_file because the rendered
    # template's [socks] block doesn't carry an auth_token field.
    inject_client_socks_auth_token "${config_path}"
    # v0.3.5: default ingress.primary = "socks5" since wide ingress
    # requires post-install root setup (TPROXY/PF rules). Forcing
    # primary=wide + local_stealth_profile=local_hardened (which
    # implies allow_fallback=false) caused service-restart loop on
    # macOS (wide unsupported) and on fresh Linux clients without
    # the wide helpers run. Operator can switch к wide manually
    # after running setup-wide-linux-redirect.sh / -tproxy.sh.
    inject_client_default_primary_socks5 "${config_path}"
    # v0.3.0 slice 6: enable local_hardened stealth profile by default
    # in fresh client installs. This auto-selects a process_alias from
    # the catalog (netd-helper / sysupdaterd / cacheagentd) so `ps aux`
    # doesn't show literal "aegis-client". Operator can opt out by
    # editing the config to local_stealth_profile = "disabled".
    inject_client_local_hardened_default "${config_path}"
    if [[ -f "${BUNDLE_PATH}/aegis-client-privileged-dns.toml" ]]; then
      install_text_file "${privileged_dns_example_path}" 0600 "$(
        sed "s|__CLIENT_CA_CERT_PATH__|${ca_path}|g" "${BUNDLE_PATH}/aegis-client-privileged-dns.toml"
      )"
      privileged_dns_profile_installed=1
    fi
  else
    install_client_config_without_bundle "${config_path}"
  fi

  inject_client_service_state_path "${config_path}" "${state_dir}"

  if [[ "${PRODUCT_MODE}" == "full-wide-hybrid-geneva" ]]; then
    local hybrid_masque_ca_path="${config_root}/masque-ca.pem"
    if [[ "${MASQUE_CA}" != "${hybrid_masque_ca_path}" ]]; then
      install_copy_file "${MASQUE_CA}" "${hybrid_masque_ca_path}" 0600
    else
      chmod 0600 "${hybrid_masque_ca_path}" 2>/dev/null || true
    fi
    set_client_config_masque "${config_path}" "${MASQUE_SERVER}" "${hybrid_masque_ca_path}"
    set_client_config_hybrid_geneva "${config_path}" "${GENEVA_STRATEGY_FILE}"
    echo "full-wide-hybrid-geneva: EXPERIMENTAL direct IPv4 Geneva enabled." >&2
    echo "PRIVACY DISCLOSURE: the access network sees each direct IPv4 destination IP." >&2
    echo "Replay-safe TCP terminals use grpc_stream fallback; ambiguous post-send failures block; UDP uses direct MASQUE; no native passthrough." >&2
  fi

  record_operator_mode "${config_path}" "${state_dir}"
  # Resolve per-class policy from the Rust model (single source of truth) and
  # record the product profile so `aegis-client profile show` / `wide status`
  # work post-install. A safe mode given a native override fails here.
  if ! resolve_wide_policies "${bin_path}"; then
    echo "ERROR: invalid wide policy override for product mode '${PRODUCT_MODE}'." >&2
    exit 2
  fi
  record_product_mode "${state_dir}"
  if [[ "${AUTO_PROFILE}" == "1" ]]; then
    # Derived planning metadata is refreshed on each run, like wide-profile.json.
    install_atomic_write "$(dirname "${install_manifest_path}")/auto-install-plan.json" 0600 strict < "${AUTO_PLAN_PATH}"
  fi

  normalize_auto_limited_config "${config_path}"
  # Redirect-family wide modes run the client under the dedicated 'aegis' uid (via
  # an additive drop-in) so wide DNS/redirect rules exempt only that uid for relay
  # control-plane DNS while capturing ordinary user app DNS. TPROXY keeps root.
  case "${OPERATOR_MODE}" in
    client-socks)
      if [[ ${EUID} -eq 0 ]]; then
        local service_policy service_caps
        service_policy="$("${bin_path}" profile service-policy --config "${config_path}" --json)" || return 1
        service_caps="$(printf '%s' "${service_policy}" | python3 -I -c '
import json, sys
p = json.load(sys.stdin)
if p.get("schema") != "aegis_client_service_policy_v1":
    raise SystemExit("Invalid client service privilege policy")
if not p.get("dedicated_uid"):
    print("root")
elif p.get("capabilities") == []:
    print("none")
elif p.get("capabilities") == ["CAP_NET_BIND_SERVICE"]:
    print("CAP_NET_BIND_SERVICE")
else:
    raise SystemExit("Unsupported client service capability request")
')" || return 1
        case "${service_caps}" in
          none) install_client_dedicated_uid_dropin "${config_path}" "${ca_path}" "${state_dir}" "${runtime_events_path}" "" || return 1 ;;
          CAP_NET_BIND_SERVICE) install_client_dedicated_uid_dropin "${config_path}" "${ca_path}" "${state_dir}" "${runtime_events_path}" "CAP_NET_BIND_SERVICE" || return 1 ;;
          root) remove_client_dedicated_uid_dropin ;;
        esac
      fi
      ;;
    client-wide-redirect|client-wide-nfqueue-observer)
      install_client_dedicated_uid_dropin "${config_path}" "${ca_path}" "${state_dir}" "${runtime_events_path}" || return 1
      ;;
    # full-wide-tun keeps the client as root (the TUN engine needs CAP_NET_ADMIN
    # for /dev/net/tun + route changes); add the SIGKILL-safe teardown drop-in.
    client-ipv6-tun-smoltcp)
      install_client_ipv6_tun_dropin
      ;;
    # Other privileged modes retain their constrained root service profile.
    # Purge any stale dedicated-uid drop-in left by a prior redirect-family
    # install so a wide->socks downgrade doesn't crash-loop on a uid mismatch.
    *)
      remove_client_dedicated_uid_dropin
      ;;
  esac
  # Do not publish the base unit or reach activation after a required UID policy fails.
  install_client_service_assets "${bin_path}" "${config_path}" "${state_dir}" "${runtime_events_path}"
  activate_systemd_unit "aegis-client.service"

  # Turnkey wide capture: if a wide mode was selected, activate transparent
  # capture now (fail-safe: rolls back if egress through the tunnel doesn't work).
  # The redirect family covers wide-redirect-safe / wide-udp-direct / wide-compat
  # and (TCP leg + NFQUEUE policy layer) full-wide-nfqueue; tproxy covers the
  # gateway product mode.
  case "${OPERATOR_MODE}" in
    client-wide-redirect|client-wide-tproxy|client-wide-nfqueue-observer|client-ipv6-tun-smoltcp)
      if ! activate_wide_capture "${config_path}" "${OPERATOR_MODE}"; then
        echo "ERROR: requested full/wide capture did not activate; the install is incomplete. Check the rollback messages and host networking before retrying." >&2
        return 1
      fi
      # Wide activation replaces the config inode. Restore group read access
      # while retaining administrative ownership of the file and its directory.
      if [[ ${EUID} -eq 0 ]]; then
        local _wsvc; _wsvc="$(systemctl show aegis-client.service -p User --value 2>/dev/null)"
        if [[ -n "${_wsvc}" && "${_wsvc}" != "root" ]]; then
          chown "root:${_wsvc}" "${config_path}"
          chmod 0640 "${config_path}"
          if ! restart_systemd_unit_checked aegis-client.service; then
            echo "ERROR: client did not restart after config ownership repair; installation is incomplete." >&2
            return 1
          fi
        fi
      fi
      ;;
  esac

  if [[ "${AUTO_PROFILE}" == "1" ]]; then
    if [[ "${PRODUCT_MODE}" == "socks-only" ]]; then
      echo "AEGIS installed. Your existing per-application proxy selection was preserved; host-wide connectivity is not enabled."
    else
      echo "AEGIS installed. TCP and DNS checks passed."
      if [[ "${PRODUCT_MODE}" == "full-wide-tun" ]]; then
        echo "UDP and IPv6 relay paths are configured; their connectivity still requires live validation."
      else
        echo "Limited connection: generic UDP and IPv6 are blocked in this profile."
      fi
    fi
    echo "Installation plan: $(dirname "${install_manifest_path}")/auto-install-plan.json"
    echo "Connection status: ${bin_path} wide status"
    echo "Diagnostics: ${bin_path} doctor"
    return 0
  fi

  cat <<EOF

AEGIS client installed
----------------------
Binary:
  ${bin_path}

Client config:
  ${config_path}

Client state dir:
  ${state_dir}

Install manifest:
  ${install_manifest_path}

Runtime events path:
  ${runtime_events_path}

Installed wide helpers:
  ${helper_dir}/setup-wide-linux-redirect.sh
  ${helper_dir}/setup-wide-linux-tproxy.sh

Ubuntu client happy-path:
  ${bin_path} --config ${config_path} --ingress-preflight
  ${bin_path} --config ${config_path} --ingress-startup-probe --json
  sudo systemctl daemon-reload
  sudo systemctl enable --now aegis-client.service
  sudo systemctl status --no-pager aegis-client.service

Short operator checks:
  sudo journalctl -u aegis-client.service -n 20 --no-pager
  tail -n 20 ${runtime_events_path}
  sudo ${helper_dir}/setup-wide-linux-redirect.sh doctor --config ${config_path}

Upgrade/reapply discipline:
  - before --force, save the current client config diff
  - after reapply on Ubuntu, rerun:
      ./scripts/validate-debian-package-host.sh --run
EOF
  if [[ "${privileged_dns_profile_installed}" -eq 1 ]]; then
    cat <<EOF

Privileged DNS profile example:
  ${privileged_dns_example_path}

Privileged DNS opt-in:
  - edit ${privileged_dns_example_path} and set prerouting_interface for the client host
  - switch the active config only when you are ready to run linux_tproxy with root/CAP_NET_ADMIN
  - use ${helper_dir}/setup-wide-linux-tproxy.sh for doctor/probe/events on that profile
EOF
  fi
  echo "Local proxy credentials remain in the private client configuration."
  print_product_summary "${bin_path}" "${config_path}"
  print_systemd_followup "aegis-client.service"
}

auto_v2_abort_fresh_passive() (
  set -euo pipefail
  install_root_auto_native_role || return 1
  [[ "$AUTO_NATIVE_ROLE" == admin ]] || {
    echo 'Fresh AUTO recovery requires the administrative release bundle.' >&2
    return 1
  }
  # Retain the authenticated incoming recovery implementation without replacing
  # any installed helper. Its coordinator authenticates the old passive source.
  stage_auto_install_lock_acquire || return 1
  ROOT="$(auto_v2_retain_public_payload)" || return 1
  # The Rust recovery actor owns the original lock itself. Reacquire only
  # after it has finished, for the independent terminal abort proof.
  flock -u "$STAGE_AUTO_INSTALL_LOCK_FD" || return 1
  exec {STAGE_AUTO_INSTALL_LOCK_FD}>&-
  local recovered
  recovered="$(/usr/bin/python3 -I -B "$ROOT/scripts/lib/aegis_installer_auto_v2.py" \
    recover-fresh-prepared --public-payload-root "$ROOT")" || return 1
  [[ "$recovered" == '{"status":"recovered"}' ||
     "$recovered" == '{"status":"abort-readback-required"}' ]] || return 1
  stage_auto_install_lock_acquire || return 1
  /usr/bin/python3 -I -B "$ROOT/scripts/lib/aegis_installer_auto_v2.py" \
    abort-fresh-passive --install-fd "$STAGE_AUTO_INSTALL_LOCK_FD"
)

if [[ "$AUTO_V2_ABORT_FRESH_PASSIVE" == 1 ]]; then
  auto_v2_abort_fresh_passive
  exit $?
fi
if [[ "$AUTO_V2_VERIFY_BOOT" == 1 ]]; then
  auto_v2_verify_boot_host
  exit $?
fi
if [[ "$AUTO_V2_RESUME_UPGRADE" == 1 ]]; then
  auto_v2_resume_upgrade
  exit $?
fi
if [[ -n "$CLIENT_PACKAGE" && ( "$ROLE" != client || "$AUTO_PROFILE" != 1 ) ]]; then
  echo '--client-package requires an automatic client upgrade.' >&2
  exit 2
fi
case "${ROLE}" in
  server)
    install_server_role
    ;;
  client)
    install_client_role
    ;;
  *)
    echo "Role must be either 'server' or 'client'" >&2
    usage >&2
    exit 1
    ;;
esac
