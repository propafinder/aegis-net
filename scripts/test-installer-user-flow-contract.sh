#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# These are Linux packaged-installer fixtures even on a macOS development host.
export AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE=generic_linux
# Keep root CI executions inside the fixture state tree as well.
export AEGIS_INSTALL_TEST_FORCE_STATE_MANIFEST=1

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-installer-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Preserve existing outer binary/service mocks, but private inputs must run
# the actual compiled Rust owner, never a mock parser.
export AEGIS_TEST_SECRET_CLIENT="${AEGIS_TEST_SECRET_CLIENT:-${ROOT}/target/debug/aegis-client}"
export AEGIS_TEST_SECRET_READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$AEGIS_TEST_SECRET_CLIENT" == /* && -x "$AEGIS_TEST_SECRET_CLIENT" && "$AEGIS_TEST_SECRET_READER" == /* && -x "$AEGIS_TEST_SECRET_READER" ]] || exit 2

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

assert_no_target_build_words() {
  local path="$1"
  if grep -Eq '\b(cargo|rustup)\b' "${path}"; then
    echo "production installer must not mention cargo/rustup: ${path}" >&2
    exit 1
  fi
}

make_fake_build_tool() {
  local dir="$1"
  local name="$2"
  cat > "${dir}/${name}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$0 $*" >> "${AEGIS_FAKE_BUILD_TOOL_LOG:?}"
exit 99
EOF
  chmod +x "${dir}/${name}"
}

assert_no_target_build_words "${ROOT}/install-server.sh"

PACKAGE_ROOT="${TMP_DIR}/package-root"
FAKE_BIN="${TMP_DIR}/fake-bin"
FAKE_HOME="${TMP_DIR}/home"
BUILD_TOOL_LOG="${TMP_DIR}/build-tools.log"
mkdir -p \
  "${PACKAGE_ROOT}/bin" \
  "${PACKAGE_ROOT}/scripts" \
  "${FAKE_BIN}" \
  "${FAKE_HOME}/.cargo/bin"

export HOME="${FAKE_HOME}"

cp "${ROOT}/install.sh" "${PACKAGE_ROOT}/install.sh"
# Both entry points must remain usable in a service environment without HOME.
env -u HOME bash "${ROOT}/install.sh" client --help > "${TMP_DIR}/source-no-home.log"
env -u HOME bash "${PACKAGE_ROOT}/install.sh" client --help > "${TMP_DIR}/package-no-home.log"
require_file_contains "${TMP_DIR}/source-no-home.log" "AEGIS installer"
require_file_contains "${TMP_DIR}/package-no-home.log" "AEGIS installer"
cp "${ROOT}/config.example.toml" "${PACKAGE_ROOT}/config.example.toml"
cp "${ROOT}/aegis-server.toml.example" "${PACKAGE_ROOT}/aegis-server.toml.example"
cp -R "${ROOT}/packaging" "${PACKAGE_ROOT}/packaging"
for helper in \
  generate-relay-materials.sh \
  render-client-bundle.sh \
  package-client-bundle.sh \
  issue-fronted-bundle.sh \
  aegis-device-egress-guard.sh \
  aegis-wide-enable.sh \
  aegis-wide-disable.sh \
  aegis-ubuntu-uninstall.sh \
  aegis-wide-persist-install.sh \
  janitor-wide-linux-tproxy.sh \
  setup-wide-linux-redirect.sh \
  setup-wide-linux-tproxy.sh \
  purge-installed-aegis.sh; do
  cp "${ROOT}/scripts/${helper}" "${PACKAGE_ROOT}/scripts/${helper}"
done
mkdir -p "${PACKAGE_ROOT}/scripts/lib"
cp "${ROOT}/scripts/lib/root-state.sh" "${PACKAGE_ROOT}/scripts/lib/root-state.sh"
# This fixture is a complete administrative release payload, including the
# passive AUTO assets copied by the actual packaged installer.
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
  cp "${ROOT}/scripts/lib/${module}" "${PACKAGE_ROOT}/scripts/lib/${module}"
done
chmod +x "${PACKAGE_ROOT}/install.sh" "${PACKAGE_ROOT}/scripts/"*.sh

cat > "${PACKAGE_ROOT}/bin/aegis-client" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == profile && "${2:-}" == installer-secret ]]; then
  exec "${AEGIS_TEST_SECRET_CLIENT:?}" "$@"
fi
if [[ "${1:-}" == "--version" ]]; then
  echo "aegis-client 9.9.9 (git contractsha, built 2026-04-29T00:00:00Z)"
  exit 0
fi
if [[ "${1:-}" == profile && "${2:-}" == service-policy ]]; then
  echo '{"schema":"aegis_client_service_policy_v1","dedicated_uid":false,"capabilities":[]}'
fi
exit 0
EOF
cat > "${PACKAGE_ROOT}/bin/aegis-server" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == installer-secret ]]; then
  exec "${AEGIS_TEST_SECRET_READER:?}" "$@"
fi
if [[ "${1:-}" == "--version" ]]; then
  echo "aegis-server 9.9.9 (git contractsha, built 2026-04-29T00:00:00Z)"
  exit 0
fi
exit 0
EOF
chmod +x "${PACKAGE_ROOT}/bin/aegis-client" "${PACKAGE_ROOT}/bin/aegis-server"
printf '%s\n' 'contract-lock' > "${PACKAGE_ROOT}/Cargo.lock"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
CLIENT_SHA256="$(hash_file "${PACKAGE_ROOT}/bin/aegis-client")"
SERVER_SHA256="$(hash_file "${PACKAGE_ROOT}/bin/aegis-server")"
LOCK_SHA256="$(hash_file "${PACKAGE_ROOT}/Cargo.lock")"

cat > "${PACKAGE_ROOT}/bundle.manifest.json" <<EOF
{
  "schema": "aegis_release_bundle_manifest_v2",
  "arch": "x86_64",
  "build_timestamp": "2026-04-29T00:00:00Z",
  "bundle_name": "aegis-contract",
  "git_sha": "contractsha",
  "platform": "linux",
  "target_triple": "x86_64-unknown-linux-gnu",
  "cargo_lock_sha256": "${LOCK_SHA256}",
  "binaries": {
    "aegis-client": {
      "path": "bin/aegis-client",
      "sha256": "${CLIENT_SHA256}",
      "features": ["raw-socket", "chrome-like-tls", "chrome-like-quic"]
    },
    "aegis-server": {
      "path": "bin/aegis-server",
      "sha256": "${SERVER_SHA256}",
      "features": []
    }
  },
  "version": "9.9.9"
}
EOF
cat > "${PACKAGE_ROOT}/SHA256SUMS" <<EOF
${CLIENT_SHA256}  bin/aegis-client
${SERVER_SHA256}  bin/aegis-server
${LOCK_SHA256}  Cargo.lock
EOF

CLIENT_BUNDLE="${TMP_DIR}/client-bundle"
mkdir -p "${CLIENT_BUNDLE}"
cat > "${CLIENT_BUNDLE}/aegis-client.toml" <<'EOF'
mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = true

[socks]
listen = "127.0.0.1:1080"

[relay]
server = "127.0.0.1:8443"
server_name = "127.0.0.1"
auth_token = "contract"
ca_cert = "__CLIENT_CA_CERT_PATH__"
EOF
printf '%s\n' 'contract-ca' > "${CLIENT_BUNDLE}/ca.pem"

make_fake_build_tool "${FAKE_BIN}" cargo
make_fake_build_tool "${FAKE_BIN}" rustup
make_fake_build_tool "${FAKE_HOME}/.cargo/bin" cargo
make_fake_build_tool "${FAKE_HOME}/.cargo/bin" rustup

HOME="${FAKE_HOME}" \
PATH="${FAKE_BIN}:${PATH}" \
AEGIS_FAKE_BUILD_TOOL_LOG="${BUILD_TOOL_LOG}" \
AEGIS_INSTALL_SOURCE_MANIFEST_URL="file://${TMP_DIR}/release/release.manifest.json" \
AEGIS_INSTALL_SOURCE_RELEASE_CHANNEL="contract" \
AEGIS_INSTALL_TEST_OS_KIND=linux \
AEGIS_INSTALL_NONINTERACTIVE=1 \
bash "${PACKAGE_ROOT}/install.sh" client --profile socks-only \
  --prefix "${TMP_DIR}/prefix" \
  --config-dir "${TMP_DIR}/client-config" \
  --state-dir "${TMP_DIR}/client-state" \
  --log-dir "${TMP_DIR}/client-log" \
  --systemd-dir "${TMP_DIR}/systemd" \
  --env-dir "${TMP_DIR}/env" \
  --bundle "${CLIENT_BUNDLE}" \
  --force >/dev/null

if [[ -s "${BUILD_TOOL_LOG}" ]]; then
  echo "production client install unexpectedly invoked build tooling" >&2
  cat "${BUILD_TOOL_LOG}" >&2
  exit 1
fi

CLIENT_INSTALL_MANIFEST="${TMP_DIR}/client-state/install-manifest.json"
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"schema": "aegis_install_manifest_v1"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"role": "client"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"version": "9.9.9"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"git_sha": "contractsha"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"source_manifest_url": "file://'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '/release.manifest.json"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '/aegis-client"'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" '"binary_sha256": "'
require_file_contains "${CLIENT_INSTALL_MANIFEST}" 'aegis-client 9.9.9 (git contractsha'
NORMALIZED_CLIENT_STATE_DIR="$(cd "${TMP_DIR}/client-state" && pwd)"
require_file_contains "${TMP_DIR}/client-config/aegis.toml" \
  "state_path = \"${NORMALIZED_CLIENT_STATE_DIR}/state.json\""

RELEASE_DIR="${TMP_DIR}/release"
mkdir -p "${RELEASE_DIR}/payload"
cp "${ROOT}/bootstrap-install.sh" "${RELEASE_DIR}/bootstrap-install.sh"
# Root CI must never create a production release floor. Rewrite only the
# fixture copy's absolute state location; its checks still run unchanged.
python3 - "${RELEASE_DIR}/bootstrap-install.sh" "${TMP_DIR}/root-release-floor" <<'PY_FLOOR_FIXTURE'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace('/var/lib/aegis-install/releases', sys.argv[2]))
PY_FLOOR_FIXTURE

tar -czf "${RELEASE_DIR}/aegis-contract.tar.gz" -C "${RELEASE_DIR}" payload
printf '%s  aegis-contract.tar.gz\n' '0000000000000000000000000000000000000000000000000000000000000000' > "${RELEASE_DIR}/aegis-contract.tar.gz.sha256"

# bootstrap-install.sh requires a signed manifest before trusting any field
# (incl. arch/checksum). Sign the negative-test manifests with an ephemeral
# key + pin it so each case reaches its intended arch/checksum failure rather
# than failing at the signature gate. (Reject paths for the gate itself are
# covered by scripts/test-manifest-signature-anchor-contract.sh.)
EPHEMERAL_SIGN_KEY="${TMP_DIR}/ephemeral-sign-key.pem"
EPHEMERAL_SIGN_PUB="${TMP_DIR}/ephemeral-sign-pub.pem"
openssl genpkey -algorithm ed25519 -out "${EPHEMERAL_SIGN_KEY}" 2>/dev/null
openssl pkey -in "${EPHEMERAL_SIGN_KEY}" -pubout -out "${EPHEMERAL_SIGN_PUB}" 2>/dev/null
export AEGIS_INSTALL_MANIFEST_PUBKEY="${EPHEMERAL_SIGN_PUB}"
FIXTURE_RELEASE_SEQUENCE=0
sign_test_manifest() {
  FIXTURE_RELEASE_SEQUENCE=$((FIXTURE_RELEASE_SEQUENCE + 1))
  python3 - "$1" "${FIXTURE_RELEASE_SEQUENCE}" <<'PY_POLICY_FIXTURE'
import json, sys, time
from pathlib import Path
path = Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["channel"] = "stable"
manifest["prerelease"] = False
now = int(time.time())
manifest["release_policy"] = {
    "schema": "aegis_release_policy_v1",
    "authority": "github:fixture/aegis:.github/workflows/release.yml",
    "sequence": int(sys.argv[2]), "tag": "v" + manifest["version"],
    "issued_at_unix": now - 10, "expires_at_unix": now + 3600,
}
path.write_text(json.dumps(manifest))
PY_POLICY_FIXTURE
  AEGIS_MANIFEST_SIGNING_KEY="${EPHEMERAL_SIGN_KEY}" \
    bash "${ROOT}/scripts/sign-release-manifest.sh" "$1" >/dev/null
}

# NOTE: every fixture below carries artifacts.bundle.archive.sha256, because the
# bootstrap now takes the expected digest from the signed manifest and refuses a
# manifest without one. Without it these negative tests would trip that refusal
# first and never exercise the behaviour they are actually asserting.
cat > "${RELEASE_DIR}/release.unsupported-arch.json" <<'EOF'
{
  "arch": "definitely-not-this-host",
  "artifacts": {
    "bundle": {
      "archive": {
        "path": "aegis-contract.tar.gz",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "sha256_path": "aegis-contract.tar.gz.sha256"
      },
      "status": "ready"
    }
  },
  "build_timestamp": "2026-04-29T00:00:00Z",
  "channel": "contract",
  "git_sha": "contractsha",
  "platform": "linux",
  "prerelease": false,
  "schema": "aegis_linux_release_manifest_v1",
  "target_triple": "definitely-not-this-host",
  "version": "9.9.9"
}
EOF
sign_test_manifest "${RELEASE_DIR}/release.unsupported-arch.json"

if bash "${ROOT}/install-server.sh" \
  --manifest-url "file://${RELEASE_DIR}/release.unsupported-arch.json" \
  --bootstrap-url "file://${RELEASE_DIR}/bootstrap-install.sh" \
  --bootstrap-sha256 "$(hash_file "${RELEASE_DIR}/bootstrap-install.sh")" \
  --force >"${TMP_DIR}/unsupported.out" 2>"${TMP_DIR}/unsupported.err"; then
  echo "unsupported arch unexpectedly succeeded" >&2
  exit 1
fi
grep -q "Unsupported architecture" "${TMP_DIR}/unsupported.err"

# shellcheck source=scripts/lib/host-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/host-arch.sh"
# host_arch() normalises arm64 -> aarch64 so this matches the manifest/artifact
# naming. (The line below previously read `HOST_# shellcheck source=...`, a botched
# edit that left HOST_ARCH unset while the case below still branched on it.)
ARCH="$(host_arch)"
HOST_ARCH="${ARCH}"
case "${HOST_ARCH}" in
  x86_64) HOST_TRIPLE="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) HOST_TRIPLE="aarch64-unknown-linux-gnu" ;;
  *) HOST_TRIPLE="${HOST_ARCH}-unknown-linux-gnu" ;;
esac

cat > "${RELEASE_DIR}/release.bad-checksum.json" <<EOF
{
  "arch": "${HOST_ARCH}",
  "artifacts": {
    "bundle": {
      "archive": {
        "path": "aegis-contract.tar.gz",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "sha256_path": "aegis-contract.tar.gz.sha256"
      },
      "status": "ready"
    }
  },
  "build_timestamp": "2026-04-29T00:00:00Z",
  "channel": "contract",
  "git_sha": "contractsha",
  "platform": "linux",
  "prerelease": false,
  "schema": "aegis_linux_release_manifest_v1",
  "target_triple": "${HOST_TRIPLE}",
  "version": "9.9.9"
}
EOF
sign_test_manifest "${RELEASE_DIR}/release.bad-checksum.json"

if bash "${ROOT}/install-server.sh" \
  --manifest-url "file://${RELEASE_DIR}/release.bad-checksum.json" \
  --bootstrap-url "file://${RELEASE_DIR}/bootstrap-install.sh" \
  --bootstrap-sha256 "$(hash_file "${RELEASE_DIR}/bootstrap-install.sh")" \
  --force >"${TMP_DIR}/checksum.out" 2>"${TMP_DIR}/checksum.err"; then
  echo "checksum mismatch unexpectedly succeeded" >&2
  exit 1
fi
grep -q "bundle checksum mismatch" "${TMP_DIR}/checksum.err"

# A destructive client reinstall must stage its one-time bundle before touching
# the existing install. This is the exact restricted-network failure shape:
# bundle delivery times out after the release archive itself was downloaded.
# The old ordering called systemctl/purge before curl; the contract makes every
# such mutation observable and requires none of them to occur.
PREFLIGHT_BIN="${TMP_DIR}/preflight-bin"
PREFLIGHT_LOG="${TMP_DIR}/preflight.log"
MUTATION_LOG="${TMP_DIR}/mutation.log"
PREFLIGHT_CONFIG="${TMP_DIR}/preflight-config"
PREFLIGHT_PREFIX="${TMP_DIR}/preflight-prefix"
PREFLIGHT_TMP="${TMP_DIR}/preflight-tmp"
mkdir -p "${PREFLIGHT_BIN}" "${PREFLIGHT_CONFIG}" "${PREFLIGHT_PREFIX}/bin"
mkdir -p "${PREFLIGHT_TMP}"
printf '%s\n' 'existing-config-must-survive' >"${PREFLIGHT_CONFIG}/aegis.toml"
printf '%s\n' 'existing-binary-must-survive' >"${PREFLIGHT_PREFIX}/bin/aegis-client"

cat >"${PREFLIGHT_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
printf 'bundle_fetch_attempted\n' >>"${AEGIS_PREFLIGHT_FETCH_LOG:?}"
exit 28
EOF
cat >"${PREFLIGHT_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl_mutation %s\n' "$*" >>"${AEGIS_PREFLIGHT_MUTATION_LOG:?}"
exit 0
EOF
cat >"${PACKAGE_ROOT}/scripts/purge-installed-aegis.sh" <<'EOF'
#!/usr/bin/env bash
preserve_path="${AEGIS_PURGE_PRESERVE_PATH:-}"
if [[ -z "${preserve_path}" || ! -f "${preserve_path}/ca.pem" || ! -f "${preserve_path}/aegis-client.toml" ]]; then
  printf 'purge lost validated bundle input before mutation\n' >&2
  exit 90
fi
printf 'purge_mutation %s\n' "$*" >>"${AEGIS_PREFLIGHT_MUTATION_LOG:?}"
exit 0
EOF
chmod +x \
  "${PREFLIGHT_BIN}/curl" \
  "${PREFLIGHT_BIN}/systemctl" \
  "${PACKAGE_ROOT}/scripts/purge-installed-aegis.sh"

FAILED_ACCESS_URL_FILE="${TMP_DIR}/failed_access_url_file.txt"
( umask 0077; printf '%s' "https://unreachable.invalid/one-time-client-bundle.tar.gz" > "$FAILED_ACCESS_URL_FILE" )

# Separate delegated offline admission control: actual Rust + actual installer
# reject the HTTP private record before purge, binary/config overwrite or service
# callbacks. The original failed-fetch case below remains unchanged.
if HOME="${FAKE_HOME}" \
  TMPDIR="${PREFLIGHT_TMP}" \
  PATH="${PREFLIGHT_BIN}:${FAKE_BIN}:${PATH}" \
  AEGIS_FAKE_BUILD_TOOL_LOG="${BUILD_TOOL_LOG}" \
  AEGIS_PREFLIGHT_FETCH_LOG="${PREFLIGHT_LOG}" \
  AEGIS_PREFLIGHT_MUTATION_LOG="${MUTATION_LOG}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux \
  AEGIS_INSTALL_NONINTERACTIVE=1 \
  bash "${PACKAGE_ROOT}/install.sh" client --profile socks-only \
    --prefix "${PREFLIGHT_PREFIX}" \
    --config-dir "${PREFLIGHT_CONFIG}" \
    --state-dir "${TMP_DIR}/offline-state" \
    --log-dir "${TMP_DIR}/offline-client-log" \
    --systemd-dir "${TMP_DIR}/offline-systemd" \
    --env-dir "${TMP_DIR}/offline-env" \
    --bundle-url-file "$FAILED_ACCESS_URL_FILE" --bundle-local-only \
    --reinstall >"${TMP_DIR}/offline.out" 2>"${TMP_DIR}/offline.err"; then
  echo "offline HTTP private input unexpectedly passed actual installer admission" >&2
  exit 1
fi
[[ ! -s "${MUTATION_LOG}" ]] || exit 1
grep -Fxq 'existing-config-must-survive' "${PREFLIGHT_CONFIG}/aegis.toml"
grep -Fxq 'existing-binary-must-survive' "${PREFLIGHT_PREFIX}/bin/aegis-client"
grep -Fq 'offline_requires_local_bundle' "${TMP_DIR}/offline.err"
[[ ! -s "${PREFLIGHT_LOG}" ]] || exit 1

if HOME="${FAKE_HOME}" \
  TMPDIR="${PREFLIGHT_TMP}" \
  PATH="${PREFLIGHT_BIN}:${FAKE_BIN}:${PATH}" \
  AEGIS_FAKE_BUILD_TOOL_LOG="${BUILD_TOOL_LOG}" \
  AEGIS_PREFLIGHT_FETCH_LOG="${PREFLIGHT_LOG}" \
  AEGIS_PREFLIGHT_MUTATION_LOG="${MUTATION_LOG}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux \
  AEGIS_INSTALL_NONINTERACTIVE=1 \
  bash "${PACKAGE_ROOT}/install.sh" client --profile socks-only \
    --prefix "${PREFLIGHT_PREFIX}" \
    --config-dir "${PREFLIGHT_CONFIG}" \
    --state-dir "${TMP_DIR}/preflight-state" \
    --log-dir "${TMP_DIR}/preflight-client-log" \
    --systemd-dir "${TMP_DIR}/preflight-systemd" \
    --env-dir "${TMP_DIR}/preflight-env" \
    --bundle-url-file "$FAILED_ACCESS_URL_FILE" \
    --reinstall >"${TMP_DIR}/preflight.out" 2>"${TMP_DIR}/preflight.err"; then
  echo "client reinstall unexpectedly succeeded after bundle fetch failure" >&2
  exit 1
fi

grep -Fq 'bundle_fetch_attempted' "${PREFLIGHT_LOG}"
if find "${PREFLIGHT_TMP}" -mindepth 1 -print -quit | grep -q .; then
  echo "failed bundle preflight leaked an installer temporary directory" >&2
  find "${PREFLIGHT_TMP}" -mindepth 1 -maxdepth 2 -print >&2
  exit 1
fi
if [[ -s "${MUTATION_LOG}" ]]; then
  echo "client reinstall mutated the old install before bundle preflight completed" >&2
  cat "${MUTATION_LOG}" >&2
  exit 1
fi
grep -Fxq 'existing-config-must-survive' "${PREFLIGHT_CONFIG}/aegis.toml"
grep -Fxq 'existing-binary-must-survive' "${PREFLIGHT_PREFIX}/bin/aegis-client"

# A bundle-backed in-place upgrade without --force is known to be unable to
# overwrite the existing config. It must reject that conflict before copying
# the candidate binary or deactivating any units.
: >"${MUTATION_LOG}"
if HOME="${FAKE_HOME}" \
  PATH="${PREFLIGHT_BIN}:${FAKE_BIN}:${PATH}" \
  AEGIS_FAKE_BUILD_TOOL_LOG="${BUILD_TOOL_LOG}" \
  AEGIS_PREFLIGHT_FETCH_LOG="${PREFLIGHT_LOG}" \
  AEGIS_PREFLIGHT_MUTATION_LOG="${MUTATION_LOG}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux \
  AEGIS_INSTALL_NONINTERACTIVE=1 \
  bash "${PACKAGE_ROOT}/install.sh" client --profile socks-only \
    --prefix "${PREFLIGHT_PREFIX}" \
    --config-dir "${PREFLIGHT_CONFIG}" \
    --state-dir "${TMP_DIR}/preflight-state" \
    --log-dir "${TMP_DIR}/preflight-client-log" \
    --systemd-dir "${TMP_DIR}/preflight-systemd" \
    --env-dir "${TMP_DIR}/preflight-env" \
    --bundle "${CLIENT_BUNDLE}" \
    --upgrade >"${TMP_DIR}/preflight-upgrade.out" 2>"${TMP_DIR}/preflight-upgrade.err"; then
  echo "client upgrade unexpectedly overwrote bundle config without --force" >&2
  exit 1
fi
grep -Fq 'Client config already exists' "${TMP_DIR}/preflight-upgrade.err"
if [[ -s "${MUTATION_LOG}" ]]; then
  echo "client upgrade mutated the old install before rejecting a config conflict" >&2
  cat "${MUTATION_LOG}" >&2
  exit 1
fi
grep -Fxq 'existing-config-must-survive' "${PREFLIGHT_CONFIG}/aegis.toml"
grep -Fxq 'existing-binary-must-survive' "${PREFLIGHT_PREFIX}/bin/aegis-client"

# A successful destructive reinstall must keep the downloaded, validated
# one-time bundle alive across purge and remove its installer temp root only at
# process exit. The purge shim fails if either required file vanished before it
# was invoked, reproducing the live RC8 failure boundary exactly.
: >"${MUTATION_LOG}"
PREFLIGHT_BUNDLE_ARCHIVE="${TMP_DIR}/preflight-client-bundle.tar.gz"
tar -czf "${PREFLIGHT_BUNDLE_ARCHIVE}" -C "${TMP_DIR}" "$(basename "${CLIENT_BUNDLE}")"
cat >"${PREFLIGHT_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
destination=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) destination="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "${destination}" ]]
cp "${AEGIS_PREFLIGHT_BUNDLE_ARCHIVE:?}" "${destination}"
EOF
chmod +x "${PREFLIGHT_BIN}/curl"

SUCCESS_ACCESS_URL_FILE="${TMP_DIR}/success_access_url_file.txt"
( umask 0077; printf '%s' "https://relay.invalid/one-time-client-bundle.tar.gz" > "$SUCCESS_ACCESS_URL_FILE" )

HOME="${FAKE_HOME}" \
  TMPDIR="${PREFLIGHT_TMP}" \
  PATH="${PREFLIGHT_BIN}:${FAKE_BIN}:${PATH}" \
  AEGIS_FAKE_BUILD_TOOL_LOG="${BUILD_TOOL_LOG}" \
  AEGIS_PREFLIGHT_BUNDLE_ARCHIVE="${PREFLIGHT_BUNDLE_ARCHIVE}" \
  AEGIS_PREFLIGHT_FETCH_LOG="${PREFLIGHT_LOG}" \
  AEGIS_PREFLIGHT_MUTATION_LOG="${MUTATION_LOG}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux \
  AEGIS_INSTALL_NONINTERACTIVE=1 \
  bash "${PACKAGE_ROOT}/install.sh" client --profile socks-only \
    --prefix "${PREFLIGHT_PREFIX}" \
    --config-dir "${PREFLIGHT_CONFIG}" \
    --state-dir "${TMP_DIR}/preflight-state" \
    --log-dir "${TMP_DIR}/preflight-client-log" \
    --systemd-dir "${TMP_DIR}/preflight-systemd" \
    --env-dir "${TMP_DIR}/preflight-env" \
    --bundle-url-file "$SUCCESS_ACCESS_URL_FILE" \
    --reinstall >"${TMP_DIR}/preflight-success.out" 2>"${TMP_DIR}/preflight-success.err"

grep -Fq 'purge_mutation client --force' "${MUTATION_LOG}"
grep -Fxq 'contract-ca' "${PREFLIGHT_CONFIG}/ca.pem"
if find "${PREFLIGHT_TMP}" -mindepth 1 -print -quit | grep -q .; then
  echo "successful bundle reinstall leaked an installer temporary directory" >&2
  find "${PREFLIGHT_TMP}" -mindepth 1 -maxdepth 2 -print >&2
  exit 1
fi

# Restore the old-install sentinels for the incompatible-binary rejection below.
printf '%s\n' 'existing-config-must-survive' >"${PREFLIGHT_CONFIG}/aegis.toml"
printf '%s\n' 'existing-binary-must-survive' >"${PREFLIGHT_PREFIX}/bin/aegis-client"

# A downloaded release with the wrong ABI/loader must fail at the same
# pre-mutation boundary. The client bundle is valid here, so this case reaches
# the exact candidate --version compatibility gate.
: >"${MUTATION_LOG}"
cat >"${PACKAGE_ROOT}/bin/aegis-client" <<'EOF'
#!/usr/bin/env bash
echo 'contract incompatible candidate' >&2
exit 126
EOF
chmod +x "${PACKAGE_ROOT}/bin/aegis-client"
INCOMPAT_CLIENT_SHA256="$(hash_file "${PACKAGE_ROOT}/bin/aegis-client")"
python3 - "${PACKAGE_ROOT}/bundle.manifest.json" "${INCOMPAT_CLIENT_SHA256}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text())
payload["binaries"]["aegis-client"]["sha256"] = sys.argv[2]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
cat >"${PACKAGE_ROOT}/SHA256SUMS" <<EOF
${INCOMPAT_CLIENT_SHA256}  bin/aegis-client
${SERVER_SHA256}  bin/aegis-server
${LOCK_SHA256}  Cargo.lock
EOF

if HOME="${FAKE_HOME}" \
  PATH="${PREFLIGHT_BIN}:${FAKE_BIN}:${PATH}" \
  AEGIS_FAKE_BUILD_TOOL_LOG="${BUILD_TOOL_LOG}" \
  AEGIS_PREFLIGHT_FETCH_LOG="${PREFLIGHT_LOG}" \
  AEGIS_PREFLIGHT_MUTATION_LOG="${MUTATION_LOG}" \
  AEGIS_INSTALL_TEST_OS_KIND=linux \
  AEGIS_INSTALL_NONINTERACTIVE=1 \
  bash "${PACKAGE_ROOT}/install.sh" client --profile socks-only \
    --prefix "${PREFLIGHT_PREFIX}" \
    --config-dir "${PREFLIGHT_CONFIG}" \
    --state-dir "${TMP_DIR}/preflight-state" \
    --log-dir "${TMP_DIR}/preflight-client-log" \
    --systemd-dir "${TMP_DIR}/preflight-systemd" \
    --env-dir "${TMP_DIR}/preflight-env" \
    --bundle "${CLIENT_BUNDLE}" \
    --reinstall >"${TMP_DIR}/preflight-abi.out" 2>"${TMP_DIR}/preflight-abi.err"; then
  echo "client reinstall unexpectedly accepted an incompatible release binary" >&2
  exit 1
fi

grep -Fq 'Prebuilt aegis-client is not executable on this host' "${TMP_DIR}/preflight-abi.err"
if [[ -s "${MUTATION_LOG}" ]]; then
  echo "client reinstall mutated the old install before binary preflight completed" >&2
  cat "${MUTATION_LOG}" >&2
  exit 1
fi
grep -Fxq 'existing-config-must-survive' "${PREFLIGHT_CONFIG}/aegis.toml"
grep -Fxq 'existing-binary-must-survive' "${PREFLIGHT_PREFIX}/bin/aegis-client"

echo "PASS: installer user flow contract"
