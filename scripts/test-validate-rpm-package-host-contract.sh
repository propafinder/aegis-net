#!/usr/bin/env bash
# Contract self-test for RPM package host validation helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_TEST_SECRET_READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$AEGIS_TEST_SECRET_READER" == /* && -x "$AEGIS_TEST_SECRET_READER" ]] || exit 2
SCRIPT="${ROOT}/scripts/validate-rpm-package-host.sh"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-rpm-host-contract.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

cargo build -q -p aegis-measure
export AEGIS_MEASURE_BIN="${ROOT}/target/debug/aegis-measure"

make_common_bin() {
  local bindir="$1"
  mkdir -p "${bindir}"
  ln -sf /bin/bash "${bindir}/bash"
  ln -sf /usr/bin/dirname "${bindir}/dirname"
  ln -sf /bin/mkdir "${bindir}/mkdir"
  ln -sf /usr/bin/touch "${bindir}/touch"
  ln -sf /usr/bin/mktemp "${bindir}/mktemp"
  ln -sf /bin/rm "${bindir}/rm"
  ln -sf /bin/cat "${bindir}/cat"
  ln -sf /usr/bin/awk "${bindir}/awk"
  ln -sf /usr/bin/python3 "${bindir}/python3"
  ln -sf /usr/bin/env "${bindir}/env"

  for tool in systemctl systemd-tmpfiles systemd-sysusers sudo rpmbuild rpm dnf; do
    cat > "${bindir}/${tool}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${bindir}/${tool}"
  done
}

make_fake_build_script() {
  local path="$1"
  cat > "${path}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out="$1"
mkdir -p "${out}"
touch "${out}/aegis-server-0.0.1-1.x86_64.rpm"
touch "${out}/aegis-client-0.0.1-1.x86_64.rpm"
/usr/bin/python3 - "${out}" <<'PYINNER'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
packages = {}
for role in ('server', 'client'):
    name = f'aegis-{role}-0.0.1-1.x86_64.rpm'
    digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
    (out / f'{name}.sha256').write_text(f'{digest}  {name}\n')
    packages[f'aegis-{role}'] = {'rpm_file': name, 'sha256_file': f'{name}.sha256'}
(out / 'rpm-packages.manifest.json').write_text(json.dumps({'version': '0.0.1', 'arch': 'x86_64', 'packages': packages}))
PYINNER
EOF
  chmod +x "${path}"
}

run_json_case_capture_status() {
  local output_path="$1"
  shift

  local status=0
  set +e
  "$@" > "${output_path}"
  status=$?
  set -e
  printf '%s\n' "${status}"
}

run_happy_json_case() {
  local case_dir="${tmpdir}/happy"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --check --json)"

  "${AEGIS_MEASURE_BIN}" check-rpm-package-host-contract-json-case \
    --scenario happy-check \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_missing_cargo_json_case() {
  local case_dir="${tmpdir}/missing-cargo"
  local status=0
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --check --json)"

  "${AEGIS_MEASURE_BIN}" check-rpm-package-host-contract-json-case \
    --scenario missing-cargo \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_unknown_argument_json_case() {
  local case_dir="${tmpdir}/unknown-arg"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin" /bin/bash "${SCRIPT}" --bogus --json)"

  "${AEGIS_MEASURE_BIN}" check-rpm-package-host-contract-json-case \
    --scenario unknown-argument \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_fake_root_run_mode_case() {
  [[ "${EUID}" -ne 0 ]] || { echo 'RPM receipt fixture requires an unprivileged runner.' >&2; exit 2; }
  local case_name="${1:-run-mode}"
  local skip_client_receipt="${2:-0}"
  local case_dir="${tmpdir}/${case_name}"
  local status=0
  mkdir -p "${case_dir}/bin" "${case_dir}/root" "${case_dir}/artifacts" "${case_dir}/receipts"
  make_common_bin "${case_dir}/bin"
  make_fake_build_script "${case_dir}/build-split-rpms.sh"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
receipt_root="${AEGIS_TEST_RPM_RECEIPT_ROOT:?}"
map_receipt() {
  [[ "$1" =~ ^/run/aegis-rpm-postinstall\.([a-zA-Z0-9]+)(/aegis-(server|client)\.ok)?$ ]] || exit 64
  printf '%s/aegis-rpm-postinstall.%s%s\n' "${receipt_root}" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}
case "${1:-}" in
  stat)
    [[ $# -eq 5 && "$2" == -Lc && "$4" == -- ]] || exit 64
    if [[ "$5" == /run ]]; then
      /usr/bin/stat -Lc "$3" -- /run
    else
      [[ "$3" == %u:%a ]] || exit 64
      mapped="$(map_receipt "$5")"
      [[ -d "$mapped" && ! -L "$mapped" && "$(/usr/bin/stat -Lc %a -- "$mapped")" == 700 ]] || exit 1
      printf '0:700\n'
    fi
    ;;
  mktemp)
    [[ $# -eq 3 && "$2" == -d && "$3" == '/run/aegis-rpm-postinstall.XXXXXX' ]] || exit 64
    actual="$(/usr/bin/mktemp -d "${receipt_root}/aegis-rpm-postinstall.XXXXXX")"
    printf '/run/%s\n' "${actual##*/}"
    ;;
  cat)
    [[ $# -eq 3 && "$2" == -- ]] || exit 64
    exec /bin/cat -- "$(map_receipt "$3")"
    ;;
  rm)
    [[ $# -eq 5 && "$2" == -f && "$3" == -- ]] || exit 64
    exec /bin/rm -f -- "$(map_receipt "$4")" "$(map_receipt "$5")"
    ;;
  rmdir)
    [[ $# -eq 3 && "$2" == -- ]] || exit 64
    exec /bin/rmdir -- "$(map_receipt "$3")"
    ;;
  env)
    exec "$@"
    ;;
  "${AEGIS_RPM_HOST_VALIDATION_RPM_BIN:?}")
    exec "$@"
    ;;
  *) exit 64 ;;
esac
EOF
  chmod +x "${case_dir}/bin/sudo"

  cat > "${case_dir}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "is-enabled" ]]; then
  printf 'disabled\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${case_dir}/bin/systemctl"

  cat > "${case_dir}/bin/rpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${AEGIS_RPM_HOST_VALIDATION_ROOT}"
state="${AEGIS_TEST_RPM_STATE_FILE}"
log="${AEGIS_TEST_RPM_LOG}"
mkdir -p "$(dirname "${state}")" "$(dirname "${log}")"
printf '%s\n' "$*" >> "${log}"

write_state() {
  cat > "${state}" <<'STATE'
aegis-server
aegis-client
STATE
}

clear_state() {
  : > "${state}"
}

install_files() {
  mkdir -p \
    "${root}/usr/local/bin" \
    "${root}/usr/lib/systemd/system-preset" \
    "${root}/usr/share/doc/aegis" \
    "${root}/etc/default"
  cat > "${root}/usr/local/bin/aegis-server" <<'RUST_READER_DELEGATE'
#!/bin/bash
if [[ "${1:-}" == installer-secret ]]; then exec "${AEGIS_TEST_SECRET_READER:?}" "$@"; fi
exit 0
RUST_READER_DELEGATE
  : > "${root}/usr/local/bin/aegis-client"
  : > "${root}/usr/lib/systemd/system-preset/90-aegis-server.preset"
  : > "${root}/usr/lib/systemd/system-preset/90-aegis-client.preset"
  : > "${root}/usr/share/doc/aegis/README.server.Debian"
  : > "${root}/usr/share/doc/aegis/README.client.Debian"
  : > "${root}/etc/default/aegis-server"
  : > "${root}/etc/default/aegis-client"
}

write_postinstall_receipts() {
  local nonce="${AEGIS_RPM_POSTINSTALL_NONCE:-}"
  [[ "${nonce}" =~ ^[a-zA-Z0-9]+$ ]] || exit 1
  local receipt="${AEGIS_TEST_RPM_RECEIPT_ROOT:?}/aegis-rpm-postinstall.${nonce}"
  [[ -d "${receipt}" && ! -L "${receipt}" ]] || exit 1
  [[ "$(/usr/bin/stat -Lc %a -- "${receipt}")" == 700 ]] || exit 1
  printf '%s\n' "${nonce}" > "${receipt}/aegis-server.ok"
  if [[ "${AEGIS_TEST_SKIP_CLIENT_RECEIPT:-0}" != 1 ]]; then
    printf '%s\n' "${nonce}" > "${receipt}/aegis-client.ok"
  fi
}

remove_files() {
  rm -f \
    "${root}/usr/local/bin/aegis-server" \
    "${root}/usr/local/bin/aegis-client" \
    "${root}/usr/lib/systemd/system-preset/90-aegis-server.preset" \
    "${root}/usr/lib/systemd/system-preset/90-aegis-client.preset" \
    "${root}/usr/share/doc/aegis/README.server.Debian" \
    "${root}/usr/share/doc/aegis/README.client.Debian" \
    "${root}/etc/default/aegis-server" \
    "${root}/etc/default/aegis-client"
}

case "${1:-}" in
  -q)
    if [[ ! -f "${state}" ]]; then
      exit 1
    fi
    pkg="${2:-}"
    if awk -v pkg="${pkg}" '$1 == pkg { found = 1 } END { exit(found ? 0 : 1) }' "${state}"; then
      printf '%s\n' "${pkg}"
      exit 0
    fi
    exit 1
    ;;
  -Uvh)
    install_files
    write_postinstall_receipts
    write_state
    ;;
  -e)
    remove_files
    clear_state
    ;;
  *)
    echo "unexpected rpm args: $*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "${case_dir}/bin/rpm"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env \
    PATH="${case_dir}/bin" \
    AEGIS_RPM_HOST_VALIDATION_ROOT="${case_dir}/root" \
    AEGIS_RPM_HOST_VALIDATION_ARTIFACT_DIR="${case_dir}/artifacts" \
    AEGIS_RPM_HOST_VALIDATION_BUILD_SPLIT_RPMS_SCRIPT="${case_dir}/build-split-rpms.sh" \
    AEGIS_RPM_HOST_VALIDATION_RPM_BIN="${case_dir}/bin/rpm" \
    AEGIS_RPM_HOST_VALIDATION_RPM_QUERY_BIN="${case_dir}/bin/rpm" \
    AEGIS_RPM_HOST_VALIDATION_SYSTEMCTL_BIN="${case_dir}/bin/systemctl" \
    AEGIS_RPM_HOST_VALIDATION_SYSTEMD_TMPFILES_BIN="${case_dir}/bin/systemd-tmpfiles" \
    AEGIS_RPM_HOST_VALIDATION_SYSTEMD_SYSUSERS_BIN="${case_dir}/bin/systemd-sysusers" \
    AEGIS_RPM_HOST_VALIDATION_SUDO_BIN="${case_dir}/bin/sudo" \
    AEGIS_TEST_RPM_RECEIPT_ROOT="${case_dir}/receipts" \
    AEGIS_TEST_SKIP_CLIENT_RECEIPT="${skip_client_receipt}" \
    AEGIS_TEST_RPM_STATE_FILE="${case_dir}/rpm-state.txt" \
    AEGIS_TEST_RPM_LOG="${case_dir}/rpm.log" \
    /bin/bash "${SCRIPT}" --run --json)"

  python3 - "${case_dir}/output.json" <<'PY'
import json, sys
json.load(open(sys.argv[1]))
PY

  if [[ "${skip_client_receipt}" == 0 ]]; then
    "${AEGIS_MEASURE_BIN}" check-rpm-package-host-contract-run-mode \
      --output "${case_dir}/output.json" \
      --validation-summary "${case_dir}/artifacts/validation-summary.json" \
      --rpm-log "${case_dir}/rpm.log" \
      --exit-status "${status}" \
      --validation-root "${case_dir}/root"
    for stage in first reinstall reapply; do
      grep -l '^server_postinstall=confirmed$' "${case_dir}/artifacts/postinstall-${stage}."* >/dev/null
      grep -l '^client_postinstall=confirmed$' "${case_dir}/artifacts/postinstall-${stage}."* >/dev/null
    done
  else
    python3 - "${case_dir}/output.json" "${status}" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
assert int(sys.argv[2]) == 3
assert payload["error_code"] == "rpm_postinstall_unconfirmed"
assert payload["ready"] is False
PY
    grep -l '^client_postinstall=missing$' "${case_dir}/artifacts/postinstall-first."* >/dev/null
  fi
  [[ -z "$(ls -A "${case_dir}/receipts")" ]]
}

run_script_contract_drift_check() {
  "${AEGIS_MEASURE_BIN}" check-rpm-package-host-contract-script \
    --script "${SCRIPT}"
}

run_happy_json_case
run_missing_cargo_json_case
run_unknown_argument_json_case
run_fake_root_run_mode_case
run_fake_root_run_mode_case missing-receipt 1
run_script_contract_drift_check

echo "RPM package host validation contract ok"
