#!/usr/bin/env bash
# Contract: one architecture-neutral bootstrap command must fetch the signed
# ARM manifest on an ARM host, including explicit --manifest-url and mirror
# URLs. The test executes the bootstrap through manifest selection and uses a
# failing local curl shim, so it cannot contact the network or install files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP="${ROOT}/bootstrap-install.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/bin" "${WORK}/downloads"

cat > "${WORK}/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  case "${argument}" in
    http://*|https://*) printf '%s\n' "${argument}" >> "${AEGIS_TEST_URL_LOG}" ;;
  esac
done
exit 22
SH
chmod +x "${WORK}/bin/curl"

run_to_manifest_failure() {
  local arch="$1"
  local log="$2"
  shift 2
  : > "${log}"
  if env \
    PATH="${WORK}/bin:${PATH}" \
    AEGIS_BOOTSTRAP_ARCH_OVERRIDE="${arch}" \
    AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE=generic_linux \
    AEGIS_INSTALL_PROFILE=socks-only \
    AEGIS_TEST_URL_LOG="${log}" \
    "$@"; then
    fail "bootstrap unexpectedly succeeded with the deliberately failing downloader"
  fi
}

# Environment-provided primary and every configured mirror are both rewritten.
arm_env_log="${WORK}/arm-env.log"
run_to_manifest_failure aarch64 "${arm_env_log}" \
  AEGIS_INSTALL_MANIFEST_URL=https://primary.invalid/release.manifest.json \
  AEGIS_INSTALL_MIRRORS='https://mirror-a.invalid/release.manifest.json, https://mirror-b.invalid/release.manifest.json' \
  bash "${BOOTSTRAP}" client --download-dir "${WORK}/downloads/arm-env"

[[ "$(wc -l < "${arm_env_log}" | tr -d ' ')" == 3 ]] \
  || fail "ARM environment/mirror case did not attempt exactly three sources"
if grep -q '/release\.manifest\.json$' "${arm_env_log}"; then
  fail "ARM environment/mirror case attempted the x86 manifest"
fi
[[ "$(grep -c '/release\.manifest-aarch64\.json$' "${arm_env_log}")" == 3 ]] \
  || fail "ARM environment/mirror sources did not all select the ARM manifest"

# An explicit CLI URL must receive the same architecture selection.
arm_cli_log="${WORK}/arm-cli.log"
run_to_manifest_failure arm64 "${arm_cli_log}" \
  bash "${BOOTSTRAP}" client \
    --download-dir "${WORK}/downloads/arm-cli" \
    --manifest-url https://explicit.invalid/release.manifest.json
grep -qx 'https://explicit.invalid/release.manifest-aarch64.json' "${arm_cli_log}" \
  || fail "explicit ARM --manifest-url did not select the ARM sibling"

# x86_64 keeps the canonical manifest unchanged.
x86_log="${WORK}/x86.log"
run_to_manifest_failure x86_64 "${x86_log}" \
  bash "${BOOTSTRAP}" client \
    --download-dir "${WORK}/downloads/x86" \
    --manifest-url https://explicit.invalid/release.manifest.json
grep -qx 'https://explicit.invalid/release.manifest.json' "${x86_log}" \
  || fail "x86_64 canonical manifest URL changed unexpectedly"

# Custom names and local fixtures are operator-defined and must remain intact.
helper_file="${WORK}/manifest-url-helper.sh"
awk '
  /^manifest_url_for_host_arch\(\) \{/ { in_fn = 1; depth = 0 }
  in_fn {
    print
    depth += gsub(/\{/, "{")
    depth -= gsub(/\}/, "}")
    if (depth == 0 && /^}/) in_fn = 0
  }
' "${BOOTSTRAP}" > "${helper_file}"
# shellcheck disable=SC1090
. "${helper_file}"
AEGIS_MANIFEST_NAME=release.manifest-aarch64.json
[[ "$(manifest_url_for_host_arch 'https://custom.invalid/operator-arm.json')" == \
   'https://custom.invalid/operator-arm.json' ]] \
  || fail "custom manifest filename changed unexpectedly"
[[ "$(manifest_url_for_host_arch 'file:///tmp/release.manifest.json')" == \
   'file:///tmp/release.manifest.json' ]] \
  || fail "file:// manifest fixture changed unexpectedly"

echo "ok: bootstrap host-arch manifest URL selection (env, mirrors, CLI, x86, custom fixtures)"
