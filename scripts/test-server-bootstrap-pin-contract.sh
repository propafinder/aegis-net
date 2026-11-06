#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "${FIXTURE}"' EXIT
cat > "${FIXTURE}/bootstrap-install.sh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$0" "$@" "${AEGIS_INSTALL_ALLOW_UNSIGNED}" > "${AEGIS_FACADE_TEST_MARKER}"
SH
export AEGIS_FACADE_TEST_MARKER="${FIXTURE}/marker"
export AEGIS_INSTALL_BOOTSTRAP_SHA256=""
export AEGIS_INSTALL_RELEASE_BASE=""
sha="$(shasum -a 256 "${FIXTURE}/bootstrap-install.sh" | awk '{print $1}')"
invoke() {
  bash "${ROOT}/install-server.sh" \
    --manifest-url "file://${FIXTURE}/release.manifest.json" \
    --bootstrap-url "file://${FIXTURE}/bootstrap-install.sh" "$@"
}
if invoke --force >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo 'FAIL: missing independent pin accepted' >&2; exit 1
fi
[[ ! -e "${AEGIS_FACADE_TEST_MARKER}" ]]
invoke --bootstrap-sha256 "${sha}" --force
[[ -s "${AEGIS_FACADE_TEST_MARKER}" ]]
execution_path="$(head -1 "${AEGIS_FACADE_TEST_MARKER}")"
[[ "${execution_path}" == /tmp/aegis-install-server.*/bootstrap-install.sh ]]
[[ ! -d "${execution_path%/*}" ]]
[[ "$(tail -1 "${AEGIS_FACADE_TEST_MARKER}")" == 0 ]]
rm "${AEGIS_FACADE_TEST_MARKER}"
printf '\nchanged bytes\n' >> "${FIXTURE}/bootstrap-install.sh"
if invoke --bootstrap-sha256 "${sha}" --force >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo 'FAIL: changed bootstrap bytes accepted' >&2; exit 1
fi
[[ ! -e "${AEGIS_FACADE_TEST_MARKER}" ]]
grep -Fq 'Bootstrap SHA-256 verification failed' "${FIXTURE}/stderr"
printf '%s\n' 'PASS: server facade requires independent pin, verifies bytes before execution, uses private scratch, cleans up and forwards arguments'
