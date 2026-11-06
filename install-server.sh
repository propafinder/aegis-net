#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
AEGIS server installer
======================

Usage:
  ./install-server.sh --release-base <exact-release-url> \
    --bootstrap-sha256 <independently-trusted-sha256> [server install options]

Options:
  --release-base <url>    Base release asset URL containing release.manifest.json
                          and bootstrap-install.sh
  --manifest-url <url>    Explicit release manifest URL
  --bootstrap-url <url>   Explicit bootstrap installer URL
  --bootstrap-sha256 <sha256>  Required bootstrap pin from a trusted channel
  --keep-downloads        Keep temporary downloads

All remaining options are forwarded to the server installer, for example:
  --relay-address relay.example.org:8443 --server-name relay.example.org

This facade is server-only and installs from published release assets. It does
not build from source on the target host.
EOF
}

DEFAULT_RELEASE_BASE="${AEGIS_INSTALL_RELEASE_BASE:-}"
RELEASE_BASE="${DEFAULT_RELEASE_BASE}"
MANIFEST_URL="${AEGIS_INSTALL_MANIFEST_URL:-}"
BOOTSTRAP_URL="${AEGIS_INSTALL_BOOTSTRAP_URL:-}"
BOOTSTRAP_SHA256="${AEGIS_INSTALL_BOOTSTRAP_SHA256:-}"
DOWNLOAD_DIR=""
KEEP_DOWNLOADS=0
AUTO_DOWNLOAD_DIR=0
FORWARDED_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-base)
      RELEASE_BASE="${2%/}"
      shift 2
      ;;
    --manifest-url)
      MANIFEST_URL="$2"
      shift 2
      ;;
    --bootstrap-url)
      BOOTSTRAP_URL="$2"
      shift 2
      ;;
    --bootstrap-sha256)
      BOOTSTRAP_SHA256="$2"
      shift 2
      ;;
    --download-dir)
      echo "Server bootstrap execution uses a private temporary directory; use --keep-downloads to retain it." >&2
      exit 2
      ;;
    --keep-downloads)
      KEEP_DOWNLOADS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    client)
      echo "install-server.sh is server-only; use bootstrap-install.sh client for client installs." >&2
      exit 1
      ;;
    server)
      shift
      ;;
    *)
      FORWARDED_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ! "${BOOTSTRAP_SHA256}" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "A trusted --bootstrap-sha256 is required before any installer is downloaded or executed." >&2
  exit 2
fi
BOOTSTRAP_SHA256="$(printf '%s' "${BOOTSTRAP_SHA256}" | tr 'A-F' 'a-f')"
if [[ -n "${RELEASE_BASE}" ]]; then
  case "${RELEASE_BASE}" in
    https://*/v[0-9]*|file://*) ;;
    *) echo "--release-base must select an exact versioned HTTPS release or a local file source." >&2; exit 2 ;;
  esac
fi
if [[ -z "${RELEASE_BASE}" && ( -z "${MANIFEST_URL}" || -z "${BOOTSTRAP_URL}" ) ]]; then
  echo "Select an exact release with --release-base, or provide both explicit asset URLs." >&2
  exit 2
fi
if [[ -z "${MANIFEST_URL}" ]]; then
  MANIFEST_URL="${RELEASE_BASE}/release.manifest.json"
fi
if [[ -z "${BOOTSTRAP_URL}" ]]; then
  BOOTSTRAP_URL="${RELEASE_BASE}/bootstrap-install.sh"
fi

cleanup() {
  if [[ "${AUTO_DOWNLOAD_DIR}" -eq 1 && "${KEEP_DOWNLOADS}" -eq 0 && -n "${DOWNLOAD_DIR}" && -d "${DOWNLOAD_DIR}" ]]; then
    rm -rf "${DOWNLOAD_DIR}"
  fi
}
trap cleanup EXIT

has_command() {
  command -v "$1" >/dev/null 2>&1
}

download_url() {
  local url="$1"
  local destination="$2"

  if [[ "${url}" == file://* ]]; then
    cp -- "${url#file://}" "${destination}"
    return 0
  fi
  [[ "${url}" == https://* ]] || { echo "Bootstrap downloads require HTTPS." >&2; return 1; }
  if has_command curl; then
    curl -fsSL --http1.1 --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 120 "${url}" -o "${destination}"
    return 0
  fi
  if has_command wget; then
    wget --https-only --timeout=30 --tries=1 -qO "${destination}" "${url}"
    return 0
  fi
  echo "Need curl or wget to download the selected bootstrap." >&2
  exit 1
}

umask 077
DOWNLOAD_DIR="$(mktemp -d /tmp/aegis-install-server.XXXXXX)"
AUTO_DOWNLOAD_DIR=1

BOOTSTRAP_PATH="${DOWNLOAD_DIR}/bootstrap-install.sh"
download_url "${BOOTSTRAP_URL}" "${BOOTSTRAP_PATH}"
if has_command sha256sum; then
  ACTUAL_SHA256="$(sha256sum "${BOOTSTRAP_PATH}" | awk '{print $1}')"
elif has_command shasum; then
  ACTUAL_SHA256="$(shasum -a 256 "${BOOTSTRAP_PATH}" | awk '{print $1}')"
elif has_command openssl; then
  ACTUAL_SHA256="$(openssl dgst -sha256 "${BOOTSTRAP_PATH}" | awk '{print $NF}')"
else
  echo "A SHA-256 utility is required to authenticate the bootstrap." >&2
  exit 1
fi
[[ "${ACTUAL_SHA256}" == "${BOOTSTRAP_SHA256}" ]] || { echo "Bootstrap SHA-256 verification failed; installer not executed." >&2; exit 1; }

AEGIS_INSTALL_ALLOW_UNSIGNED=0 bash "${BOOTSTRAP_PATH}" server \
  --manifest-url "${MANIFEST_URL}" \
  ${FORWARDED_ARGS[@]+"${FORWARDED_ARGS[@]}"}
if [[ "${KEEP_DOWNLOADS}" -eq 1 ]]; then
  printf 'Verified bootstrap retained in %s\n' "${DOWNLOAD_DIR}"
fi
