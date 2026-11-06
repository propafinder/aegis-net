#!/usr/bin/env bash
# Contract self-test for Debian package host validation helper.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_TEST_SECRET_READER="${AEGIS_TEST_SECRET_READER:-${ROOT}/target/debug/aegis-server}"
[[ "$AEGIS_TEST_SECRET_READER" == /* && -x "$AEGIS_TEST_SECRET_READER" ]] || exit 2
SCRIPT="${ROOT}/scripts/validate-debian-package-host.sh"
AEGIS_MEASURE_BIN="${AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN:-${ROOT}/target/debug/aegis-measure}"
if [[ ! -x "${AEGIS_MEASURE_BIN}" ]]; then
  cargo build -q -p aegis-measure
fi
export AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN="${AEGIS_MEASURE_BIN}"
TEST_PYTHON_BIN="$(command -v python3)"
TEST_TIMEOUT_BIN="$(command -v timeout)"
TEST_OPENSSL_BIN="$(command -v openssl)"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-debian-host-contract.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

make_common_bin() {
  local bindir="$1"
  local tool
  mkdir -p "${bindir}"
  ln -sf /bin/bash "${bindir}/bash"
  ln -sf "${TEST_PYTHON_BIN}" "${bindir}/python3"
  ln -sf "${TEST_TIMEOUT_BIN}" "${bindir}/timeout"
  ln -sf "${TEST_OPENSSL_BIN}" "${bindir}/openssl"

  for tool in dpkg dpkg-deb dpkg-query systemctl journalctl systemd-tmpfiles systemd-sysusers sudo ip iptables ip6tables nft; do
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
python3 - "${out}" <<'PY'
import hashlib, io, json, lzma, pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
def archive():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        for name, is_dir in (('./', True), ('./control', False)):
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.mode = 0o755 if is_dir else 0o644
            info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
            if is_dir: tar.addfile(info)
            else:
                payload = b'fixture\n'
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    return lzma.compress(stream.getvalue())
def ar_member(name, payload):
    header = (f'{name}/'.ljust(16) + '0'.ljust(12) + '0'.ljust(6)
              + '0'.ljust(6) + '100644'.ljust(8)
              + str(len(payload)).ljust(10) + '`\n').encode('ascii')
    return header + payload + (b'\n' if len(payload) % 2 else b'')
packages = {}
for role in ('server', 'client'):
    package = f'aegis-{role}'
    name = f'{package}_0.0.1_amd64.deb'
    payload = (b'!<arch>\n' + ar_member('debian-binary', b'2.0\n')
               + ar_member('control.tar.xz', archive()) + ar_member('data.tar.xz', archive()))
    (root / name).write_bytes(payload)
    (root / (name + '.sha256')).write_text(hashlib.sha256(payload).hexdigest() + '  ' + name + '\n')
    packages[package] = {'deb_file': name}
(root / 'split-deb-packages.manifest.json').write_text(json.dumps({
    'version': '0.0.1', 'deb_arch': 'amd64', 'packages': packages}))
PY
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

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --check --json)"

  "${AEGIS_MEASURE_BIN}" check-debian-package-host-contract-json-case \
    --scenario happy-check \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_missing_cargo_json_case() {
  local case_dir="${tmpdir}/missing-cargo"
  local status=0
  mkdir -p "${case_dir}/home"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env HOME="${case_dir}/home" PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --check --json)"

  "${AEGIS_MEASURE_BIN}" check-debian-package-host-contract-json-case \
    --scenario missing-cargo \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_prebuilt_release_check_case() {
  local case_dir="${tmpdir}/prebuilt-check"
  local status=0
  mkdir -p "${case_dir}/bin" "${case_dir}/artifacts"
  make_common_bin "${case_dir}/bin"
  touch "${case_dir}/artifacts/aegis-server_0.0.1_amd64.deb"
  touch "${case_dir}/artifacts/aegis-client_0.0.1_amd64.deb"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    /bin/bash "${SCRIPT}" \
      --check \
      --json \
      --server-deb "${case_dir}/artifacts/aegis-server_0.0.1_amd64.deb" \
      --client-deb "${case_dir}/artifacts/aegis-client_0.0.1_amd64.deb")"

  "${AEGIS_MEASURE_BIN}" check-debian-package-host-contract-json-case \
    --scenario prebuilt-check \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_unknown_argument_json_case() {
  local case_dir="${tmpdir}/unknown-arg"
  local status=0
  mkdir -p "${case_dir}"
  make_common_bin "${case_dir}/bin"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env PATH="${case_dir}/bin:/usr/bin:/bin" /bin/bash "${SCRIPT}" --bogus --json)"

  "${AEGIS_MEASURE_BIN}" check-debian-package-host-contract-json-case \
    --scenario unknown-argument \
    --output "${case_dir}/output.json" \
    --exit-status "${status}"
}

run_fake_root_run_mode_case() {
  local case_dir="${tmpdir}/run-mode"
  local status=0
  mkdir -p "${case_dir}/bin" "${case_dir}/root" "${case_dir}/artifacts"
  make_common_bin "${case_dir}/bin"
  make_fake_build_script "${case_dir}/build-split-debs.sh"

  cat > "${case_dir}/setup-wide-linux-redirect.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'redirect:%s\n' "${1:-}" >> "${AEGIS_TEST_HELPER_LOG:?}"
exit 0
EOF
  chmod +x "${case_dir}/setup-wide-linux-redirect.sh"

  cat > "${case_dir}/setup-wide-linux-tproxy.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'tproxy:%s\n' "${1:-}" >> "${AEGIS_TEST_HELPER_LOG:?}"
exit 0
EOF
  chmod +x "${case_dir}/setup-wide-linux-tproxy.sh"

  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"

  cat > "${case_dir}/bin/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF
  chmod +x "${case_dir}/bin/sudo"

  cat > "${case_dir}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state_dir="${AEGIS_TEST_SYSTEMCTL_STATE_DIR}"
root="${AEGIS_DEB_HOST_VALIDATION_ROOT}"
mkdir -p "${state_dir}" "${root}/var/log/aegis-client"
if [[ "${1:-}" == "is-enabled" ]]; then
  printf 'disabled\n'
  exit 0
fi
if [[ "${1:-}" == "is-active" ]]; then
  unit="${2:-}"
  if [[ -f "${state_dir}/${unit}.active" ]]; then
    printf 'active\n'
    exit 0
  fi
  printf 'inactive\n'
  exit 3
fi
if [[ "${1:-}" == "status" ]]; then
  unit="${2:-}"
  if [[ -f "${state_dir}/${unit}.active" ]]; then
    printf '%s active (running)\n' "${unit}"
    exit 0
  fi
  printf '%s inactive\n' "${unit}"
  exit 3
fi
case "${1:-}" in
  daemon-reload)
    exit 0
    ;;
  start|restart)
    unit="${2:-}"
    : > "${state_dir}/${unit}.active"
    if [[ "${unit}" == "aegis-client.service" ]]; then
      cat > "${root}/var/log/aegis-client/runtime-events.jsonl" <<'JSON'
{"level":"info","event_code":"ingress_backend_started","message":"stub backend started","fields":{"backend":"linux_tproxy","backend_runtime_id":"stub-runtime"}}
JSON
    fi
    exit 0
    ;;
esac
exit 0
EOF
  chmod +x "${case_dir}/bin/systemctl"

  cat > "${case_dir}/bin/journalctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
unit=""
while [[ $# -gt 0 ]]; do
  case "${1}" in
    -u)
      unit="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf 'stub journal for %s\n' "${unit:-unknown}"
EOF
  chmod +x "${case_dir}/bin/journalctl"

  cat > "${case_dir}/bin/dpkg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${AEGIS_DEB_HOST_VALIDATION_ROOT}"
state="${AEGIS_TEST_DPKG_STATE_FILE}"
log="${AEGIS_TEST_DPKG_LOG}"
mkdir -p "$(dirname "${state}")" "$(dirname "${log}")"
printf '%s\n' "$*" >> "${log}"

write_state() {
  cat > "${state}" <<'STATE'
aegis-server|install ok installed
aegis-client|install ok installed
STATE
}

write_removed_state() {
  cat > "${state}" <<'STATE'
aegis-server|deinstall ok config-files
aegis-client|deinstall ok config-files
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
  cat > "${root}/usr/local/bin/aegis-server" <<'BIN'
#!/usr/bin/env bash
if [[ "${1:-}" == installer-secret ]]; then exec "${AEGIS_TEST_SECRET_READER:?}" "$@"; fi
exit 0
BIN
  cat > "${root}/usr/local/bin/aegis-client" <<'BIN'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == profile && "${2:-}" == tproxy-diagnostics && "${3:-}" == runtime-events-summary ]]; then
  printf 'EVENTS_TOTAL\t1\nEVENTS_LATEST_CODE\tingress_backend_started\nEVENTS_LATEST_LEVEL\tinfo\nEVENTS_BACKEND\tlinux_tproxy\nEVENTS_BACKEND_RUNTIME_ID\tstub-runtime\nEVENTS_STARTUP_HEALTH\thealthy\nEVENTS_RUNTIME_STATUS\thealthy\nEVENTS_PRODUCT_VERDICT\tgreen\n'
  exit 0
fi
if [[ "${1:-}" == profile && "${2:-}" == tproxy-diagnostics && "${3:-}" == write-operator-evidence ]]; then
  shift 3
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == --output ]]; then
      printf '{"backend":"linux_tproxy","startup_health":"healthy","runtime_status":"healthy","product_verdict":"green","runtime_degradation_count":0,"failover_count":0,"terminal_failure_count":0}\n' > "$2"
      exit 0
    fi
    shift
  done
  exit 2
fi
if [[ " $* " == *" --ingress-preflight "* ]]; then
  cat <<'JSON'
{"status":"ok","selection":{"selected_backend":"wide_primary","wide_runtime_readiness":"ready"}}
JSON
  exit 0
fi
if [[ " $* " == *" --ingress-startup-probe "* ]]; then
  cat <<'JSON'
{"status":"ok","startup":{"code":"bind_ok","started_backend":"linux_tproxy","message":"stub startup ok"}}
JSON
  exit 0
fi
exit 0
BIN
  chmod +x "${root}/usr/local/bin/aegis-server" "${root}/usr/local/bin/aegis-client"
  : > "${root}/usr/lib/systemd/system-preset/90-aegis-server.preset"
  : > "${root}/usr/lib/systemd/system-preset/90-aegis-client.preset"
  : > "${root}/usr/share/doc/aegis/README.server.Debian"
  : > "${root}/usr/share/doc/aegis/README.client.Debian"
  : > "${root}/etc/default/aegis-server"
  : > "${root}/etc/default/aegis-client"
}

remove_payload_keep_config() {
  rm -f \
    "${root}/usr/local/bin/aegis-server" \
    "${root}/usr/local/bin/aegis-client" \
    "${root}/usr/lib/systemd/system-preset/90-aegis-server.preset" \
    "${root}/usr/lib/systemd/system-preset/90-aegis-client.preset" \
    "${root}/usr/share/doc/aegis/README.server.Debian" \
    "${root}/usr/share/doc/aegis/README.client.Debian"
}

purge_config() {
  rm -f "${root}/etc/default/aegis-server" "${root}/etc/default/aegis-client"
}

case "${1:-}" in
  --install)
    install_files
    write_state
    ;;
  --remove)
    remove_payload_keep_config
    write_removed_state
    ;;
  --purge)
    purge_config
    clear_state
    ;;
  *)
    echo "unexpected dpkg args: $*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "${case_dir}/bin/dpkg"

  cat > "${case_dir}/bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${AEGIS_TEST_DPKG_STATE_FILE}"
pkg="${@: -1}"
if [[ ! -f "${state}" ]]; then
  exit 1
fi
line="$(awk -F'|' -v pkg="${pkg}" '$1 == pkg { print $2 }' "${state}")"
if [[ -z "${line}" ]]; then
  exit 1
fi
printf '%s' "${line}"
EOF
  chmod +x "${case_dir}/bin/dpkg-query"

  status="$(run_json_case_capture_status "${case_dir}/output.json" env \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    AEGIS_DEB_HOST_VALIDATION_ROOT="${case_dir}/root" \
    AEGIS_CLIENT_BIN="${case_dir}/root/usr/local/bin/aegis-client" \
    AEGIS_DEB_HOST_VALIDATION_ARTIFACT_DIR="${case_dir}/artifacts" \
    AEGIS_DEB_HOST_VALIDATION_BUILD_SPLIT_DEBS_SCRIPT="${case_dir}/build-split-debs.sh" \
    AEGIS_DEB_HOST_VALIDATION_DPKG_BIN="${case_dir}/bin/dpkg" \
    AEGIS_DEB_HOST_VALIDATION_DPKG_DEB_BIN="${case_dir}/bin/dpkg-deb" \
    AEGIS_DEB_HOST_VALIDATION_DPKG_QUERY_BIN="${case_dir}/bin/dpkg-query" \
    AEGIS_DEB_HOST_VALIDATION_SYSTEMCTL_BIN="${case_dir}/bin/systemctl" \
    AEGIS_DEB_HOST_VALIDATION_JOURNALCTL_BIN="${case_dir}/bin/journalctl" \
    AEGIS_DEB_HOST_VALIDATION_SYSTEMD_TMPFILES_BIN="${case_dir}/bin/systemd-tmpfiles" \
    AEGIS_DEB_HOST_VALIDATION_SYSTEMD_SYSUSERS_BIN="${case_dir}/bin/systemd-sysusers" \
    AEGIS_DEB_HOST_VALIDATION_SUDO_BIN="${case_dir}/bin/sudo" \
    AEGIS_DEB_HOST_VALIDATION_SETUP_WIDE_REDIRECT_SCRIPT="${case_dir}/setup-wide-linux-redirect.sh" \
    AEGIS_DEB_HOST_VALIDATION_SETUP_WIDE_TPROXY_SCRIPT="${case_dir}/setup-wide-linux-tproxy.sh" \
    AEGIS_TEST_DPKG_STATE_FILE="${case_dir}/dpkg-state.txt" \
    AEGIS_TEST_DPKG_LOG="${case_dir}/dpkg.log" \
    AEGIS_TEST_SYSTEMCTL_STATE_DIR="${case_dir}/systemctl-state" \
    AEGIS_TEST_HELPER_LOG="${case_dir}/helper.log" \
    /bin/bash "${SCRIPT}" --run --json)"

  python3 - "${case_dir}/output.json" <<'PY'
import json, sys
json.load(open(sys.argv[1]))
PY

  if [[ "${EUID}" -ne 0 ]]; then
    python3 - "${case_dir}/output.json" "${status}" "${case_dir}/dpkg.log" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert int(sys.argv[2]) == 1, sys.argv[2]
assert payload["error_code"] == "root_required", payload
assert not pathlib.Path(sys.argv[3]).exists(), "nonroot reached dpkg"
PY
    return 0
  fi

  if [[ "${status}" -ne 0 ]]; then
    cat "${case_dir}/output.json" >&2
    return 1
  fi

  "${AEGIS_MEASURE_BIN}" check-debian-package-host-contract-run-mode \
    --output "${case_dir}/output.json" \
    --validation-summary "${case_dir}/artifacts/validation-summary.json" \
    --release-handoff "${case_dir}/artifacts/ubuntu-release-gate-handoff.json" \
    --release-summary "${case_dir}/artifacts/ubuntu-product-release-summary.json" \
    --pilot-inputs "${case_dir}/artifacts/ubuntu-controlled-pilot-inputs.json" \
    --operator-loop "${case_dir}/artifacts/runtime/client-operator-loop-summary.json" \
    --dpkg-log "${case_dir}/dpkg.log" \
    --helper-log "${case_dir}/helper.log" \
    --exit-status "${status}" \
    --validation-root "${case_dir}/root"
}

run_script_contract_drift_check() {
  "${AEGIS_MEASURE_BIN}" check-debian-package-host-contract-script \
    --script "${SCRIPT}"
}

run_fifo_source_refusal_case() {
  [[ "${EUID}" -eq 0 ]] || return 0
  local case_dir="${tmpdir}/fifo-source"
  local status=0
  mkdir -p "${case_dir}/bin" "${case_dir}/root" "${case_dir}/artifacts"
  make_common_bin "${case_dir}/bin"
  make_fake_build_script "${case_dir}/generate.sh"
  cat > "${case_dir}/build.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
bash "${case_dir}/generate.sh" "\$1"
rm -f "\$1/aegis-server_0.0.1_amd64.deb"
mkfifo "\$1/aegis-server_0.0.1_amd64.deb"
EOF
  chmod +x "${case_dir}/build.sh"
  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${case_dir}/bin/cargo"
  status="$(run_json_case_capture_status "${case_dir}/output.json" timeout 15s env \
    PATH="${case_dir}/bin:/usr/bin:/bin" \
    AEGIS_DEB_HOST_VALIDATION_ROOT="${case_dir}/root" \
    AEGIS_DEB_HOST_VALIDATION_ARTIFACT_DIR="${case_dir}/artifacts" \
    AEGIS_DEB_HOST_VALIDATION_BUILD_SPLIT_DEBS_SCRIPT="${case_dir}/build.sh" \
    /bin/bash "${SCRIPT}" --run --json)"
  python3 - "${case_dir}/output.json" "${status}" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert int(sys.argv[2]) == 1, sys.argv[2]
assert payload['error_code'] == 'split_deb_stage_failed', payload
PY
}

run_missing_runtime_prerequisite_cases() {
  local tool case_dir status
  for tool in python3 timeout openssl python3-without-tomllib; do
    case_dir="${tmpdir}/missing-runtime-${tool}"
    mkdir -p "${case_dir}/artifacts"
    make_common_bin "${case_dir}/bin"
    touch "${case_dir}/artifacts/aegis-server_0.0.1_amd64.deb" \
      "${case_dir}/artifacts/aegis-client_0.0.1_amd64.deb"
    cat > "${case_dir}/hide-command.sh" <<'EOF'
command() {
  if [[ "${1:-}" == -v && "${2:-}" == "${AEGIS_TEST_HIDDEN_COMMAND:?}" ]]; then
    return 1
  fi
  builtin command "$@"
}
python3() {
  if [[ "${AEGIS_TEST_HIDDEN_COMMAND:?}" == python3-without-tomllib && "${*}" == '-I -B -c import tomllib' ]]; then
    return 1
  fi
  builtin command python3 "$@"
}
EOF
    status="$(run_json_case_capture_status "${case_dir}/output.json" env \
      PATH="${case_dir}/bin:/usr/bin:/bin" BASH_ENV="${case_dir}/hide-command.sh" \
      AEGIS_TEST_HIDDEN_COMMAND="${tool}" \
      /bin/bash "${SCRIPT}" --check --json \
      --server-deb "${case_dir}/artifacts/aegis-server_0.0.1_amd64.deb" \
      --client-deb "${case_dir}/artifacts/aegis-client_0.0.1_amd64.deb")"
    "${TEST_PYTHON_BIN}" - "${case_dir}/output.json" "${status}" "${tool%%-without-*}" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert int(sys.argv[2]) == 1, (sys.argv[3], sys.argv[2], payload)
assert payload['ready'] is False, payload
assert sys.argv[3] in payload['missing_commands'], payload
PY
  done
}

run_prebuilt_missing_reporter_case() {
  local case_dir="${tmpdir}/prebuilt-missing-reporter" status mode
  mkdir -p "${case_dir}/artifacts"
  make_common_bin "${case_dir}/bin"
  touch "${case_dir}/artifacts/aegis-server_0.0.1_amd64.deb" \
    "${case_dir}/artifacts/aegis-client_0.0.1_amd64.deb"
  cat > "${case_dir}/bin/cargo" <<'EOF'
#!/bin/bash
touch "${AEGIS_TEST_CARGO_MARKER:?}"
exit 99
EOF
  chmod +x "${case_dir}/bin/cargo"
  for mode in text json; do
    local args=(--check)
    [[ "${mode}" != json ]] || args+=(--json)
    status="$(run_json_case_capture_status "${case_dir}/${mode}.out" env \
      PATH="${case_dir}/bin:/usr/bin:/bin" \
      AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN= \
      AEGIS_TEST_CARGO_MARKER="${case_dir}/cargo-called" \
      /bin/bash "${SCRIPT}" "${args[@]}" \
      --server-deb "${case_dir}/artifacts/aegis-server_0.0.1_amd64.deb" \
      --client-deb "${case_dir}/artifacts/aegis-client_0.0.1_amd64.deb")"
    [[ "${status}" -eq 1 ]]
    [[ ! -e "${case_dir}/cargo-called" ]]
  done
}

run_happy_json_case
run_missing_cargo_json_case
run_prebuilt_release_check_case
run_unknown_argument_json_case
run_missing_runtime_prerequisite_cases
run_prebuilt_missing_reporter_case
run_fake_root_run_mode_case
run_fifo_source_refusal_case
run_script_contract_drift_check

echo "Debian package host validation contract ok"
