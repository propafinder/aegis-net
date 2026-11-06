#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST=1
export PATH="${HOME}/.cargo/bin:${PATH}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-bootstrap-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# This temporary bundle validates bootstrap/install behavior on the current
# host. The portable bundle keeps the GLIBC_2.34 AlmaLinux release gate.
# shellcheck source=scripts/lib/test-host-release-abi.sh
. "${ROOT}/scripts/lib/test-host-release-abi.sh"
aegis_test_use_host_release_abi "bootstrap-install contract"
"${ROOT}/scripts/build-release-bundle.sh" "${TMP_DIR}/release" >/dev/null

require_file_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    echo "expected ${file} to contain: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

require_regular_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "expected file to exist: ${path}" >&2
    exit 1
  fi
}

require_directory() {
  local path="$1"
  if [[ ! -d "${path}" ]]; then
    echo "expected directory to exist: ${path}" >&2
    exit 1
  fi
}

reject_file_content() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq -- "${unexpected}" "${file}"; then
    echo "expected ${file} not to contain: ${unexpected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

reject_nonempty_file() {
  local path="$1"
  if [[ -s "${path}" ]]; then
    echo "expected file to be empty or absent: ${path}" >&2
    echo "--- ${path} ---" >&2
    cat "${path}" >&2
    exit 1
  fi
}

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
ARCH="$(host_arch)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/aegis-server/Cargo.toml" | head -n 1)"
BUNDLE_NAME="aegis-${VERSION}-linux-${ARCH}"

# The archive digest must live INSIDE the manifest, because that is what the
# ed25519 signature covers. bootstrap-install.sh refuses a manifest without it
# rather than falling back to the sibling .sha256 file, which a hostile mirror
# could regenerate to match a tampered archive.
BUNDLE_SHA256="$(openssl dgst -sha256 "${TMP_DIR}/release/${BUNDLE_NAME}.tar.gz" | awk '{print $NF}')"

cat > "${TMP_DIR}/release/release.manifest.json" <<EOF
{
  "artifacts": {
    "bundle": {
      "archive": {
        "path": "${BUNDLE_NAME}.tar.gz",
        "sha256": "${BUNDLE_SHA256}",
        "sha256_path": "${BUNDLE_NAME}.tar.gz.sha256"
      },
      "directory": "${BUNDLE_NAME}",
      "status": "ready"
    }
  },
  "arch": "${ARCH}",
  "channel": "test",
  "platform": "linux",
  "schema": "aegis_linux_release_manifest_v1",
  "version": "${VERSION}"
}
EOF

# Fresh signed policy and private floor state are part of the bootstrap
# contract. Only the fixture bootstrap copy redirects the root state path.
mkdir -p "${TMP_DIR}/fixture-home"
export HOME="${TMP_DIR}/fixture-home"
FIXTURE_BOOTSTRAP="${TMP_DIR}/bootstrap-install.sh"
cp "${ROOT}/bootstrap-install.sh" "${FIXTURE_BOOTSTRAP}"
python3 - "${TMP_DIR}/release/release.manifest.json" "${FIXTURE_BOOTSTRAP}" "${TMP_DIR}/root-release-floor" <<'PY_POLICY_FIXTURE'
import json, sys, time
from pathlib import Path
manifest_path, bootstrap_path, floor = map(Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())
manifest["channel"] = "stable"
manifest["prerelease"] = False
now = int(time.time())
manifest["release_policy"] = {"schema":"aegis_release_policy_v1",
    "authority":"github:fixture/aegis:.github/workflows/release.yml",
    "sequence":1, "tag":"v" + manifest["version"],
    "issued_at_unix":now - 10, "expires_at_unix":now + 3600}
manifest_path.write_text(json.dumps(manifest))
bootstrap_path.write_text(bootstrap_path.read_text().replace('/var/lib/aegis-install/releases', str(floor)))
PY_POLICY_FIXTURE

# The bootstrap signature anchor requires a detached ed25519 signature over
# the manifest, verified before any field is trusted. Sign the contract
# manifest with an ephemeral key and pin that key via
# AEGIS_INSTALL_MANIFEST_PUBKEY so the full install flow exercises the real
# signed path. (Reject paths are proven by
# scripts/test-manifest-signature-anchor-contract.sh.) openssl here is the
# real builder binary; the SIMULATE_MISSING list only affects bootstrap's
# apt prerequisite detection, not actual openssl invocation.
EPHEMERAL_SIGN_KEY="${TMP_DIR}/ephemeral-sign-key.pem"
EPHEMERAL_SIGN_PUB="${TMP_DIR}/ephemeral-sign-pub.pem"
openssl genpkey -algorithm ed25519 -out "${EPHEMERAL_SIGN_KEY}" 2>/dev/null
openssl pkey -in "${EPHEMERAL_SIGN_KEY}" -pubout -out "${EPHEMERAL_SIGN_PUB}" 2>/dev/null
AEGIS_MANIFEST_SIGNING_KEY="${EPHEMERAL_SIGN_KEY}" \
  bash "${ROOT}/scripts/sign-release-manifest.sh" "${TMP_DIR}/release/release.manifest.json" >/dev/null
export AEGIS_INSTALL_MANIFEST_PUBKEY="${EPHEMERAL_SIGN_PUB}"

MANIFEST_URL="file://${TMP_DIR}/release/release.manifest.json"
FAKE_BIN_DIR="${TMP_DIR}/fake-bin"
PYTHON_PACKAGE=py"thon3"
APT_LOG="${TMP_DIR}/apt.log"
SUDO_LOG="${TMP_DIR}/sudo.log"
CURL_LOG="${TMP_DIR}/curl.log"
WGET_LOG="${TMP_DIR}/wget.log"
SYSTEMCTL_LOG="${TMP_DIR}/systemctl.log"
mkdir -p "${FAKE_BIN_DIR}"

cat > "${FAKE_BIN_DIR}/apt-get" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${AEGIS_TEST_APT_LOG:?}"
EOF
chmod +x "${FAKE_BIN_DIR}/apt-get"

cat > "${FAKE_BIN_DIR}/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${AEGIS_TEST_SUDO_LOG:?}"
"$@"
EOF
chmod +x "${FAKE_BIN_DIR}/sudo"

cat > "${FAKE_BIN_DIR}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${AEGIS_TEST_CURL_LOG:?}"
echo "curl should not be used for file:// contract downloads" >&2
exit 97
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

cat > "${FAKE_BIN_DIR}/wget" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${AEGIS_TEST_WGET_LOG:?}"
echo "wget should not be used for file:// contract downloads" >&2
exit 98
EOF
chmod +x "${FAKE_BIN_DIR}/wget"

cat > "${FAKE_BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${AEGIS_TEST_SYSTEMCTL_LOG:?}"
exit 0
EOF
chmod +x "${FAKE_BIN_DIR}/systemctl"

PATH="${FAKE_BIN_DIR}:${PATH}" \
AEGIS_BOOTSTRAP_SIMULATE_MISSING_COMMANDS="${PYTHON_PACKAGE},tar,curl,wget,openssl" \
AEGIS_BOOTSTRAP_APT_GET_BIN="${FAKE_BIN_DIR}/apt-get" \
AEGIS_BOOTSTRAP_SUDO_BIN="${FAKE_BIN_DIR}/sudo" \
AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE="debian_like" \
AEGIS_INSTALL_FORCE_SYSTEMD_ACTIVATE=1 \
AEGIS_INSTALL_TEST_OS_KIND=linux \
AEGIS_INSTALL_NONINTERACTIVE=1 \
AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST=1 \
AEGIS_TEST_APT_LOG="${APT_LOG}" \
AEGIS_TEST_SUDO_LOG="${SUDO_LOG}" \
AEGIS_TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" \
bash "${FIXTURE_BOOTSTRAP}" server \
  --manifest-url "${MANIFEST_URL}" \
  --download-dir "${TMP_DIR}/bootstrap-server" \
  --prefix "${TMP_DIR}/prefix" \
  --config-dir "${TMP_DIR}/server-config" \
  --state-dir "${TMP_DIR}/server-state" \
  --systemd-dir "${TMP_DIR}/systemd" \
  --env-dir "${TMP_DIR}/env" \
  --relay-address "relay.example.org:8443" \
  --server-name "relay.example.org" \
  --no-auto-token \
  --force >/dev/null

# Fresh owner-private access record; bootstrap forwards only its pathname.
ACCESS_URL_FILE="${TMP_DIR}/client-access-url.txt"
( umask 0077; printf '%s' "file://${TMP_DIR}/server-config/client-bundle.tar.gz" > "$ACCESS_URL_FILE" )

PATH="${FAKE_BIN_DIR}:${PATH}" \
AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE="debian_like" \
AEGIS_INSTALL_FORCE_SYSTEMD_ACTIVATE=1 \
AEGIS_INSTALL_TEST_OS_KIND=linux \
AEGIS_INSTALL_NONINTERACTIVE=1 \
AEGIS_TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}" \
bash "${FIXTURE_BOOTSTRAP}" client \
  --manifest-url "${MANIFEST_URL}" \
  --download-dir "${TMP_DIR}/bootstrap-client" \
  --prefix "${TMP_DIR}/prefix" \
  --config-dir "${TMP_DIR}/client-config" \
  --state-dir "${TMP_DIR}/client-state" \
  --log-dir "${TMP_DIR}/client-log" \
  --systemd-dir "${TMP_DIR}/systemd" \
  --env-dir "${TMP_DIR}/env" \
  --bundle-url-file "$ACCESS_URL_FILE" \
  --profile socks-only \
  --force >/dev/null

require_file_contains "${TMP_DIR}/server-config/aegis-server.toml" 'listen = "0.0.0.0:8443"'
reject_file_content "${TMP_DIR}/client-config/aegis.toml" "__CLIENT_CA_CERT_PATH__"
require_directory "${TMP_DIR}/server-config/client-bundle"
require_regular_file "${TMP_DIR}/server-config/client-bundle.tar.gz"
require_file_contains "${TMP_DIR}/systemd/aegis-server.service" "ExecStart="
require_file_contains "${TMP_DIR}/systemd/aegis-client.service" "ExecStart="
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/aegis-wide-enable.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/aegis-wide-disable.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/aegis-wide-persist-install.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/janitor-wide-linux-tproxy.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/setup-wide-linux-redirect.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/lib/root-state.sh"
require_regular_file "${TMP_DIR}/prefix/lib/aegis/helpers/setup-wide-linux-tproxy.sh"

if [[ ! -s "${APT_LOG}" ]]; then
  echo "expected apt-get calls" >&2
  exit 1
fi
if [[ "$(head -n 1 "${APT_LOG}")" != "update" ]]; then
  echo "expected first apt-get call to be update" >&2
  cat "${APT_LOG}" >&2
  exit 1
fi
require_file_contains "${APT_LOG}" "install -y "
require_file_contains "${APT_LOG}" "${PYTHON_PACKAGE}"
require_file_contains "${APT_LOG}" "tar"
require_file_contains "${APT_LOG}" "curl"
require_file_contains "${APT_LOG}" "openssl"
require_file_contains "${SYSTEMCTL_LOG}" "daemon-reload"
require_file_contains "${SYSTEMCTL_LOG}" "enable --now aegis-server.service"
require_file_contains "${SYSTEMCTL_LOG}" "enable --now aegis-client.service"
require_file_contains "${SYSTEMCTL_LOG}" "restart aegis-server.service"
require_file_contains "${SYSTEMCTL_LOG}" "restart aegis-client.service"

PATH="${FAKE_BIN_DIR}:${PATH}" \
AEGIS_INSTALL_TEST_OS_KIND=linux \
AEGIS_INSTALL_NONINTERACTIVE=1 \
AEGIS_BOOTSTRAP_OS_KIND_OVERRIDE=linux \
AEGIS_TEST_CURL_LOG="${CURL_LOG}" \
AEGIS_TEST_WGET_LOG="${WGET_LOG}" \
bash "${FIXTURE_BOOTSTRAP}" client \
  --manifest-url "${MANIFEST_URL}" \
  --download-dir "${TMP_DIR}/bootstrap-client-file-url" \
  --prefix "${TMP_DIR}/prefix-file-url" \
  --config-dir "${TMP_DIR}/client-config-file-url" \
  --state-dir "${TMP_DIR}/client-state-file-url" \
  --log-dir "${TMP_DIR}/client-log-file-url" \
  --systemd-dir "${TMP_DIR}/systemd-file-url" \
  --env-dir "${TMP_DIR}/env-file-url" \
  --bundle-url-file "$ACCESS_URL_FILE" \
  --profile socks-only \
  --force >/dev/null

reject_file_content "${TMP_DIR}/client-config-file-url/aegis.toml" "__CLIENT_CA_CERT_PATH__"
require_file_contains "${TMP_DIR}/systemd-file-url/aegis-client.service" "ExecStart="
reject_nonempty_file "${CURL_LOG}"
reject_nonempty_file "${WGET_LOG}"

echo "PASS: bootstrap installer contract"
