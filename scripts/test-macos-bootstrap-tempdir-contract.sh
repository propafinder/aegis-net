#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-tempdir-contract.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

FAKE_BUNDLE_DIR="${TMP_DIR}/fake-macos-bundle"
INSTALLER="${FAKE_BUNDLE_DIR}/install-macos-client.sh"
HOME_DIR="${TMP_DIR}/home"
UNWRITABLE_TMP="${TMP_DIR}/unwritable-tmp"
FALLBACK_TMP="${HOME_DIR}/.cache/aegis/tmp"
BUNDLE_SRC="${TMP_DIR}/bundle-src/client-bundle"
BUNDLE_TGZ="${TMP_DIR}/client-bundle.tar.gz"
STDOUT_LOG="${TMP_DIR}/stdout.log"
STDERR_LOG="${TMP_DIR}/stderr.log"

mkdir -p "${FAKE_BUNDLE_DIR}/bin" "${HOME_DIR}" "${UNWRITABLE_TMP}" "${BUNDLE_SRC}" "$FALLBACK_TMP"
chmod 0500 "${UNWRITABLE_TMP}"

awk '
  $0 == "cat > \"${BUNDLE_DIR}/install-macos-client.sh\" <<'\''EOF'\''" {
    in_installer = 1
    next
  }
  in_installer && $0 == "EOF" {
    in_installer = 0
    found = 1
    next
  }
  in_installer {
    print
  }
  END {
    if (!found) {
      exit 1
    }
  }
' "${ROOT}/scripts/build-macos-client-tarball.sh" > "${INSTALLER}"
chmod +x "${INSTALLER}"

# The private-input fixture must exercise the actual Rust reader/transfer.
CLIENT="${AEGIS_TEST_SECRET_CLIENT:-${ROOT}/target/debug/aegis-client}"
[[ "$CLIENT" == /* && -x "$CLIENT" ]] || { echo "Actual compiled client required." >&2; exit 2; }
cp "$CLIENT" "${FAKE_BUNDLE_DIR}/bin/aegis-client"
chmod 0755 "${FAKE_BUNDLE_DIR}/bin/aegis-client"

cat > "${FAKE_BUNDLE_DIR}/macos-client-bundle.manifest.json" <<'EOF'
{
  "arch": "aarch64",
  "build_timestamp": "2026-04-30T00:00:00Z",
  "git_sha": "contract-git-sha",
  "platform": "macos",
  "target_triple": "aarch64-apple-darwin",
  "version": "0.3.7"
}
EOF

cat > "${BUNDLE_SRC}/aegis-client.toml" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[socks]
listen = "127.0.0.1:1080"

[relay]
server = "198.51.100.22:8443"
server_name = "198.51.100.22"
auth_token = "REDACTED"
ca_cert = "__CLIENT_CA_CERT_PATH__"
EOF

cat > "${BUNDLE_SRC}/ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
contract-ca
-----END CERTIFICATE-----
EOF

tar -czf "${BUNDLE_TGZ}" -C "${TMP_DIR}/bundle-src" client-bundle
ACCESS_URL_FILE="${TMP_DIR}/client-access-url.txt"
( umask 0077; printf '%s' "file://${BUNDLE_TGZ}" > "$ACCESS_URL_FILE" )

if ! (
  cd "${FAKE_BUNDLE_DIR}"
  HOME="${HOME_DIR}" \
  TMPDIR="${UNWRITABLE_TMP}" \
  AEGIS_INSTALL_TMPDIR_CANDIDATES="${UNWRITABLE_TMP}:${FALLBACK_TMP}" \
  AEGIS_INSTALL_SOURCE_MANIFEST_URL="file://${TMP_DIR}/release.manifest.json" \
  bash "${INSTALLER}" \
    --bundle-url-file "$ACCESS_URL_FILE" \
    --service-mode foreground \
    --no-browser-proxy \
    --reinstall \
    >"${STDOUT_LOG}" 2>"${STDERR_LOG}"
); then
  cat "${STDOUT_LOG}" >&2 || true
  cat "${STDERR_LOG}" >&2 || true
  exit 1
fi

GENERATED_SOURCE="${ROOT}/scripts/build-macos-client-tarball.sh"
BOOTSTRAP_SOURCE="${ROOT}/bootstrap-install.sh"
CONFIG="${HOME_DIR}/.config/aegis/aegis.toml"
CA="${HOME_DIR}/.config/aegis/ca.pem"
MANIFEST="${HOME_DIR}/.local/state/aegis/install-manifest.json"
BINARY="${HOME_DIR}/.local/bin/aegis-client"

if grep -Fq -- 'mktemp -d "/tmp/aegis-bundle.XXXXXX"' "${GENERATED_SOURCE}"; then
  echo "generated macOS installer still uses hard-coded /tmp bundle tempdir" >&2
  exit 1
fi
grep -Fq -- "make_macos_temp_dir" "${GENERATED_SOURCE}"
grep -Fq -- "AEGIS_INSTALL_TMPDIR_CANDIDATES" "${GENERATED_SOURCE}"
if grep -Fq -- 'mktemp -d "/tmp/aegis-bootstrap-mac.XXXXXX"' "${BOOTSTRAP_SOURCE}"; then
  echo "bootstrap still uses hard-coded /tmp macOS tempdir" >&2
  exit 1
fi
grep -Fq -- "make_bootstrap_temp_dir" "${BOOTSTRAP_SOURCE}"

for path in "${CONFIG}" "${CA}" "${MANIFEST}" "${BINARY}"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing installed macOS artifact: ${path}" >&2
    exit 1
  fi
done

if grep -Fq -- "__CLIENT_CA_CERT_PATH__" "${CONFIG}"; then
  echo "client config still has CA placeholder" >&2
  exit 1
fi
CA_CONFIG_PATH="$(sed -n 's/^ca_cert = "\(.*\)"$/\1/p' "${CONFIG}" | head -n 1)"
if [[ "$(cd "$(dirname "${CA_CONFIG_PATH}")" && pwd)/$(basename "${CA_CONFIG_PATH}")" != "$(cd "$(dirname "${CA}")" && pwd)/$(basename "${CA}")" ]]; then
  echo "client config CA path does not point to installed ca.pem" >&2
  exit 1
fi
grep -Fq -- 'primary = "socks5"' "${CONFIG}"
grep -Fq -- 'auth_token = "' "${CONFIG}"

BINARY_CANONICAL="$(cd "$(dirname "${BINARY}")" && pwd)/$(basename "${BINARY}")"

jq -e --arg binary "${BINARY_CANONICAL}" '
  .schema == "aegis_install_manifest_v1"
  and .role == "client"
  and .git_sha == "contract-git-sha"
  and .binary_path == $binary
' "${MANIFEST}" >/dev/null

if [[ ! -d "${FALLBACK_TMP}" ]]; then
  echo "fallback temp base was not created" >&2
  exit 1
fi
if find "${FALLBACK_TMP}" -name 'aegis-bundle.*' -print -quit | grep -q .; then
  echo "temporary bundle dir was not cleaned up" >&2
  exit 1
fi
if find "${UNWRITABLE_TMP}" -name 'aegis-bundle.*' -print -quit | grep -q .; then
  echo "installer wrote into unwritable temp candidate" >&2
  exit 1
fi
grep -Fq -- "AEGIS macOS client installed" "${STDOUT_LOG}"
if grep -Fq -- "mktemp" "${STDERR_LOG}"; then
  echo "unexpected mktemp stderr" >&2
  exit 1
fi

echo "PASS: macOS bootstrap tempdir contract"
