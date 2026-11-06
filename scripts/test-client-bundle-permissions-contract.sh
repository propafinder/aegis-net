#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-bundle-permissions.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

SECRET_READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$SECRET_READER" == /* && -x "$SECRET_READER" ]] || { echo "Actual compiled Rust secret reader required." >&2; exit 2; }
[[ "$("$SECRET_READER" installer-secret version)" == installer-secret-v1 ]] || exit 2

mode_of() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

assert_mode() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(mode_of "${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "expected mode ${expected} for ${path}, got ${actual}" >&2
    exit 1
  fi
}

CA_CERT="${TMP_DIR}/source-ca.pem"
BUNDLE_DIR="${TMP_DIR}/client-bundle"
ARCHIVE="${TMP_DIR}/client-bundle.tar.gz"
printf '%s\n' 'contract-ca' > "${CA_CERT}"

# Prove a rerender repairs old insecure modes instead of relying only on umask.
mkdir -p "${BUNDLE_DIR}"
chmod 0755 "${BUNDLE_DIR}"
for path in aegis-client.toml aegis-client-privileged-dns.toml README.txt ca.pem; do
  printf '%s\n' stale > "${BUNDLE_DIR}/${path}"
  chmod 0644 "${BUNDLE_DIR}/${path}"
done

(
  umask 0022
  printf '%s' 'contract-secret-token' | bash "${ROOT}/scripts/render-client-bundle.sh" \
    "${BUNDLE_DIR}" \
    "relay.example.org:443" \
    "relay.example.org" \
    --auth-token-stdin \
    "${CA_CERT}" \
    "$SECRET_READER" \
    "" \
    "grpc_stream"
)

assert_mode 700 "${BUNDLE_DIR}"
for path in aegis-client.toml aegis-client-privileged-dns.toml README.txt ca.pem; do
  assert_mode 600 "${BUNDLE_DIR}/${path}"
done
grep -Fq 'auth_token = "contract-secret-token"' "${BUNDLE_DIR}/aegis-client.toml"

(
  umask 0022
  bash "${ROOT}/scripts/package-client-bundle.sh" "${BUNDLE_DIR}" "${ARCHIVE}"
)
assert_mode 600 "${ARCHIVE}"

# The server serves this private archive as its dedicated service account.
# Exercise the exact installer helper in the non-root install model and prove
# it remains owner-only and readable.
helper_file="${TMP_DIR}/secure-server-bundle-archive.sh"
awk '
  /^secure_server_bundle_archive\(\) \{/ { in_fn = 1; depth = 0 }
  in_fn {
    print
    depth += gsub(/\{/, "{")
    depth -= gsub(/\}/, "}")
    if (depth == 0 && /^}/) in_fn = 0
  }
' "${ROOT}/install.sh" > "${helper_file}"
# shellcheck disable=SC1090
. "${helper_file}"
secure_server_bundle_archive "${ARCHIVE}" "$(id -un)" "$(id -gn)"
assert_mode 600 "${ARCHIVE}"
[[ -r "${ARCHIVE}" ]] || {
  echo "server bundle archive is not readable by its service owner" >&2
  exit 1
}

# Wiring matters: ownership must be repaired after the atomic package writer
# replaces the archive and before the service/token endpoint is activated.
package_line="$(grep -nF '"${ROOT}/scripts/package-client-bundle.sh" "${BUNDLE_OUT}" "${BUNDLE_ARCHIVE_OUT}"' "${ROOT}/install.sh" | cut -d: -f1)"
ownership_line="$(grep -nF 'secure_server_bundle_archive "${BUNDLE_ARCHIVE_OUT}" "${service_user}" "${service_group}"' "${ROOT}/install.sh" | cut -d: -f1)"
activate_line="$(grep -nF 'activate_systemd_unit "aegis-server.service"' "${ROOT}/install.sh" | cut -d: -f1)"
[[ -n "${package_line}" && -n "${ownership_line}" && -n "${activate_line}" ]] || {
  echo "server bundle ownership wiring is incomplete" >&2
  exit 1
}
(( package_line < ownership_line && ownership_line < activate_line )) || {
  echo "server bundle ownership must run after packaging and before activation" >&2
  exit 1
}

if find "${TMP_DIR}" -maxdepth 1 -name '.client-bundle.tar.gz.tmp.*' -print -quit | grep -q .; then
  echo "temporary archive survived successful packaging" >&2
  exit 1
fi

echo "PASS: client bundle directory/archive stay private and the server archive is service-readable"
