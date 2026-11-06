#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required; install Rust via rustup first" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-relay-source-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# This contract tests relay-address rendering, not the portable-release ABI.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "relay-source contract"
"${ROOT}/scripts/build-release-bundle.sh" "${TMP_DIR}" >/dev/null

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
VERSION="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/aegis-server/Cargo.toml" | head -n 1
)"
BUNDLE_DIR="${TMP_DIR}/aegis-${VERSION}-linux-${ARCH}"

run_server_install() {
  local case_dir="$1"
  shift
  mkdir -p "${case_dir}/home"
  HOME="${case_dir}/home" PATH="/usr/bin:/bin" AEGIS_INSTALL_NONINTERACTIVE=1 \
    AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST=1 "$@" \
    "${BUNDLE_DIR}/install.sh" server \
    --prefix "${case_dir}/prefix" \
    --config-dir "${case_dir}/server-config" \
    --state-dir "${case_dir}/server-state" \
    --systemd-dir "${case_dir}/systemd" \
    --env-dir "${case_dir}/env" \
    --force >/dev/null
}

DNS_CASE="${TMP_DIR}/dns-case"
run_server_install "${DNS_CASE}" \
  env \
  AEGIS_INSTALL_TEST_DETECTED_HOST="relay.example.org" \
  AEGIS_INSTALL_TEST_RESOLUTION_MAP="relay.example.org=203.0.113.10"

FALLBACK_CASE="${TMP_DIR}/fallback-case"
run_server_install "${FALLBACK_CASE}" \
  env \
  AEGIS_INSTALL_TEST_DETECTED_HOST="vps3357217.trouble-free.net" \
  AEGIS_INSTALL_TEST_FALLBACK_IP="198.51.100.22"

PORT_CASE="${TMP_DIR}/port-case"
mkdir -p "${PORT_CASE}/home"
HOME="${PORT_CASE}/home" PATH="/usr/bin:/bin" \
  env \
  AEGIS_INSTALL_NONINTERACTIVE="1" \
  AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST="1" \
  AEGIS_INSTALL_TEST_DETECTED_HOST="relay.example.org" \
  AEGIS_INSTALL_TEST_RESOLUTION_MAP="relay.example.org=203.0.113.10" \
  "${BUNDLE_DIR}/install.sh" server \
  --prefix "${PORT_CASE}/prefix" \
  --config-dir "${PORT_CASE}/server-config" \
  --state-dir "${PORT_CASE}/server-state" \
  --systemd-dir "${PORT_CASE}/systemd" \
  --env-dir "${PORT_CASE}/env" \
  --relay-address "198.51.100.22:443" \
  --server-name "aegis-relay.example.com" \
  --force >/dev/null

FAIL_CASE="${TMP_DIR}/fail-case"
mkdir -p "${FAIL_CASE}/home"
set +e
HOME="${FAIL_CASE}/home" PATH="/usr/bin:/bin" \
  env \
  AEGIS_INSTALL_NONINTERACTIVE="1" \
  AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST="1" \
  AEGIS_INSTALL_TEST_DETECTED_HOST="localhost" \
  AEGIS_INSTALL_TEST_RESOLUTION_MAP="" \
  AEGIS_INSTALL_TEST_FALLBACK_IP="" \
  AEGIS_INSTALL_TEST_DISABLE_AUTO_IP_FALLBACK="1" \
  "${BUNDLE_DIR}/install.sh" server \
  --prefix "${FAIL_CASE}/prefix" \
  --config-dir "${FAIL_CASE}/server-config" \
  --state-dir "${FAIL_CASE}/server-state" \
  --systemd-dir "${FAIL_CASE}/systemd" \
  --env-dir "${FAIL_CASE}/env" \
  --force >"${FAIL_CASE}/stdout.log" 2>"${FAIL_CASE}/stderr.log"
FAIL_STATUS=$?
set -e

require_file_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "${needle}" "${file}"; then
    echo "missing expected content in ${file}: ${needle}" >&2
    exit 1
  fi
}

DNS_CFG="${DNS_CASE}/server-config/client-bundle/aegis-client.toml"
FALLBACK_CFG="${FALLBACK_CASE}/server-config/client-bundle/aegis-client.toml"
PORT_SERVER_CFG="${PORT_CASE}/server-config/aegis-server.toml"
PORT_CLIENT_CFG="${PORT_CASE}/server-config/client-bundle/aegis-client.toml"
FALLBACK_CERT_TEXT="${TMP_DIR}/fallback-cert.txt"

require_file_contains "${DNS_CFG}" 'server = "relay.example.org:8443"'
require_file_contains "${DNS_CFG}" 'server_name = "relay.example.org"'
require_file_contains "${DNS_CFG}" "relay.server remains"

require_file_contains "${FALLBACK_CFG}" 'server = "198.51.100.22:8443"'
require_file_contains "${FALLBACK_CFG}" 'server_name = "vps3357217.trouble-free.net"'
require_file_contains "${FALLBACK_CFG}" "IP fallback can stay routable without forcing IP-in-SNI"

require_file_contains "${PORT_SERVER_CFG}" 'listen = "0.0.0.0:443"'
require_file_contains "${PORT_CLIENT_CFG}" 'server = "198.51.100.22:443"'
require_file_contains "${PORT_CLIENT_CFG}" 'server_name = "aegis-relay.example.com"'

openssl x509 \
  -in "${FALLBACK_CASE}/server-config/certs/server.pem" \
  -noout \
  -text >"${FALLBACK_CERT_TEXT}"
require_file_contains "${FALLBACK_CERT_TEXT}" "DNS:vps3357217.trouble-free.net"
require_file_contains "${FALLBACK_CERT_TEXT}" "IP Address:198.51.100.22"

if [[ "${FAIL_STATUS}" -eq 0 ]]; then
  echo "expected relay source failure case to fail" >&2
  exit 1
fi
require_file_contains "${FAIL_CASE}/stderr.log" "Unable to choose a relay address for the generated client bundle."
require_file_contains "${FAIL_CASE}/stderr.log" "--relay-address relay.example.org:8443"

echo "PASS: install server relay source contract"
