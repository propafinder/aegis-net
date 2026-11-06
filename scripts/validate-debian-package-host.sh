#!/usr/bin/env bash
# Best-effort Debian host validation for the AEGIS split .deb lifecycle.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="check"
JSON_OUTPUT=0
READY=0
PACKAGE_MANAGER=""
OS_PRETTY_NAME="unknown-linux"
OS_ID="unknown"
OS_VERSION_ID=""
HOST_FAMILY_ID="unknown-linux"
HOST_FAMILY_VALIDATION_TIER="manual_only"
ERROR_CODE=""
HELPER_EXIT_CODE=""
MISSING_COMMANDS=()
COMMAND_STATUS_ARGS=()
COMMAND_STATUS_TEXT=()
ARTIFACT_DIR="${AEGIS_DEB_HOST_VALIDATION_ARTIFACT_DIR:-}"
STAGED_DEB_DIR=""
VALIDATION_ROOT="${AEGIS_DEB_HOST_VALIDATION_ROOT:-/}"
VALIDATION_ROOT="$(printf '%s\n' "${VALIDATION_ROOT}" | sed 's#//*#/#g')"
export AEGIS_DEB_HOST_VALIDATION_ROOT="${VALIDATION_ROOT}"
PREBUILT_SERVER_DEB="${AEGIS_DEB_HOST_VALIDATION_SERVER_DEB:-}"
PREBUILT_CLIENT_DEB="${AEGIS_DEB_HOST_VALIDATION_CLIENT_DEB:-}"
AEGIS_MEASURE_BIN="${AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN:-}"

BUILD_SPLIT_DEBS_SCRIPT="${AEGIS_DEB_HOST_VALIDATION_BUILD_SPLIT_DEBS_SCRIPT:-${ROOT}/scripts/build-split-deb-packages.sh}"
DPKG_BIN="${AEGIS_DEB_HOST_VALIDATION_DPKG_BIN:-dpkg}"
DPKG_DEB_BIN="${AEGIS_DEB_HOST_VALIDATION_DPKG_DEB_BIN:-dpkg-deb}"
DPKG_QUERY_BIN="${AEGIS_DEB_HOST_VALIDATION_DPKG_QUERY_BIN:-dpkg-query}"
SYSTEMCTL_BIN="${AEGIS_DEB_HOST_VALIDATION_SYSTEMCTL_BIN:-systemctl}"
JOURNALCTL_BIN="${AEGIS_DEB_HOST_VALIDATION_JOURNALCTL_BIN:-journalctl}"
SYSTEMD_TMPFILES_BIN="${AEGIS_DEB_HOST_VALIDATION_SYSTEMD_TMPFILES_BIN:-systemd-tmpfiles}"
SYSTEMD_SYSUSERS_BIN="${AEGIS_DEB_HOST_VALIDATION_SYSTEMD_SYSUSERS_BIN:-systemd-sysusers}"
SUDO_BIN="${AEGIS_DEB_HOST_VALIDATION_SUDO_BIN:-sudo}"
SERVER_BIN_OVERRIDE="${AEGIS_DEB_HOST_VALIDATION_SERVER_BIN:-}"
CLIENT_BIN_OVERRIDE="${AEGIS_DEB_HOST_VALIDATION_CLIENT_BIN:-}"
GENERATE_RELAY_SCRIPT_OVERRIDE="${AEGIS_DEB_HOST_VALIDATION_GENERATE_RELAY_SCRIPT:-}"
RENDER_CLIENT_BUNDLE_SCRIPT_OVERRIDE="${AEGIS_DEB_HOST_VALIDATION_RENDER_CLIENT_BUNDLE_SCRIPT:-}"
SETUP_WIDE_REDIRECT_SCRIPT_OVERRIDE="${AEGIS_DEB_HOST_VALIDATION_SETUP_WIDE_REDIRECT_SCRIPT:-}"
SETUP_WIDE_TPROXY_SCRIPT_OVERRIDE="${AEGIS_DEB_HOST_VALIDATION_SETUP_WIDE_TPROXY_SCRIPT:-}"

REMEDIATION_COMMAND='bash scripts/validate-debian-package-host.sh --check'
RUN_COMMAND='sudo env HOME="$HOME" PATH="$HOME/.cargo/bin:$PATH" bash scripts/validate-debian-package-host.sh --run'
SUPPORTED_PRODUCT_CONTOUR='linux_first_split_deb_package_validation'
SUPPORTED_OPERATOR_SCOPE='debian_host_package_lifecycle_validation'
SERVER_CONFIG_DIR='/etc/aegis/server'
CLIENT_CONFIG_DIR='/etc/aegis/client'
SERVER_STATE_DIR='/var/lib/aegis-server'
CLIENT_STATE_DIR='/var/lib/aegis-client'
CLIENT_LOG_DIR='/var/log/aegis-client'
SERVER_UNIT='aegis-server.service'
CLIENT_UNIT='aegis-client.service'
PHASE_RESULTS=()
UPGRADE_REAPPLY_MODE='same_version_reapply'
RELEASE_GATE_NAME='ubuntu_first_product_release_gate'
RELEASE_GATE_SCOPE='ubuntu_first_product_candidate'
RELEASE_GATE_REQUIRED_PHASES=(
  install
  preset_policy
  service_start
  service_restart
  reboot_contract
  remove
  reinstall
  upgrade_reapply
  purge
)
RELEASE_HANDOFF_ARTIFACT=""
RELEASE_SUMMARY_ARTIFACT=""
OPERATOR_LOOP_SUMMARY_ARTIFACT=""
PILOT_INPUTS_ARTIFACT=""

path_in_root() {
  local rel="$1"
  printf '%s/%s' "${VALIDATION_ROOT%/}" "${rel#/}"
}

resolve_existing_path() {
  local candidate=""
  for candidate in "$@"; do
    if [[ -n "${candidate}" && -e "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

resolve_server_bin() {
  resolve_existing_path "${SERVER_BIN_OVERRIDE}" "$(path_in_root "/usr/local/bin/aegis-server")"
}

resolve_client_bin() {
  resolve_existing_path "${CLIENT_BIN_OVERRIDE}" "$(path_in_root "/usr/local/bin/aegis-client")"
}

resolve_generate_relay_script() {
  resolve_existing_path \
    "${GENERATE_RELAY_SCRIPT_OVERRIDE}" \
    "$(path_in_root "/usr/share/aegis/scripts/generate-relay-materials.sh")" \
    "${ROOT}/scripts/generate-relay-materials.sh"
}

resolve_render_client_bundle_script() {
  resolve_existing_path \
    "${RENDER_CLIENT_BUNDLE_SCRIPT_OVERRIDE}" \
    "$(path_in_root "/usr/share/aegis/scripts/render-client-bundle.sh")" \
    "${ROOT}/scripts/render-client-bundle.sh"
}

resolve_setup_wide_redirect_script() {
  resolve_existing_path \
    "${SETUP_WIDE_REDIRECT_SCRIPT_OVERRIDE}" \
    "$(path_in_root "/usr/share/aegis/scripts/setup-wide-linux-redirect.sh")" \
    "${ROOT}/scripts/setup-wide-linux-redirect.sh"
}

resolve_setup_wide_tproxy_script() {
  resolve_existing_path \
    "${SETUP_WIDE_TPROXY_SCRIPT_OVERRIDE}" \
    "$(path_in_root "/usr/share/aegis/scripts/setup-wide-linux-tproxy.sh")" \
    "${ROOT}/scripts/setup-wide-linux-tproxy.sh"
}

record_phase_result() {
  local phase="$1"
  local status="$2"
  local detail="$3"
  PHASE_RESULTS+=("${phase}|${status}|${detail}")
}

restore_artifact_ownership() {
  local owner=""
  local group=""
  if [[ -n "${STAGED_DEB_DIR}" && -d "${STAGED_DEB_DIR}" && ! -L "${STAGED_DEB_DIR}" ]]; then
    rm -rf -- "${STAGED_DEB_DIR}"
  fi
  if [[ -z "${ARTIFACT_DIR}" || ! -e "${ARTIFACT_DIR}" ]]; then
    return 0
  fi
  if [[ "${EUID}" -ne 0 || -z "${SUDO_USER:-}" ]]; then
    return 0
  fi
  owner="${SUDO_USER}"
  group="$(id -gn "${owner}" 2>/dev/null || true)"
  if [[ -n "${group}" ]]; then
    chown -R "${owner}:${group}" "${ARTIFACT_DIR}" 2>/dev/null || true
  else
    chown -R "${owner}" "${ARTIFACT_DIR}" 2>/dev/null || true
  fi
}

ensure_user_cargo_path() {
  if [[ -d "${HOME}/.cargo/bin" ]]; then
    case ":${PATH}:" in
      *":${HOME}/.cargo/bin:"*) ;;
      *) export PATH="${HOME}/.cargo/bin:${PATH}" ;;
    esac
  fi
}

usage() {
  cat <<'EOF'
Usage:
  scripts/validate-debian-package-host.sh [--check|--run] [--json] [--artifact-dir <dir>]
    [--server-deb <path>] [--client-deb <path>]

Modes:
  --check             Validate Debian-host prerequisites for split package lifecycle proof.
  --run               Build split .deb packages, then run Ubuntu acceptance:
                      install -> service start/restart/status/logs/events ->
                      remove -> reinstall -> same-version reapply -> purge.
                      A release candidate is not ship-ready without a green --run.
  --json              Emit machine-readable JSON instead of text.
  --artifact-dir DIR  Directory for built packages and validation summary.
  --server-deb PATH   Use a prebuilt aegis-server .deb instead of building locally.
  --client-deb PATH   Use a prebuilt aegis-client .deb instead of building locally.

This helper targets real Debian-family host validation for:
  scripts/build-split-deb-packages.sh

When both prebuilt package paths are provided, the helper switches to
release-artifact mode and skips the local cargo-backed package build. Supply
the exact matching reporting ELF through
AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN; this mode never builds a reporter.
EOF
}

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_PRETTY_NAME="${PRETTY_NAME:-${NAME:-unknown-linux}}"
  OS_ID="${ID:-unknown}"
  OS_VERSION_ID="${VERSION_ID:-}"
fi

detect_package_manager() {
  local candidate=""
  for candidate in apt-get apt; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      PACKAGE_MANAGER="${candidate}"
      return 0
    fi
  done
  if command -v "${DPKG_BIN}" >/dev/null 2>&1 && command -v "${DPKG_DEB_BIN}" >/dev/null 2>&1; then
    PACKAGE_MANAGER="dpkg"
    return 0
  fi
  return 1
}

classify_host_family() {
  case "${OS_ID}" in
    debian|ubuntu|linuxmint|pop|neon|elementary)
      HOST_FAMILY_ID="debian-apt"
      HOST_FAMILY_VALIDATION_TIER="packaging_validation_target"
      ;;
    *)
      case "${PACKAGE_MANAGER}" in
        apt|apt-get|dpkg)
          HOST_FAMILY_ID="debian-apt"
          HOST_FAMILY_VALIDATION_TIER="packaging_validation_target"
          ;;
        *)
          HOST_FAMILY_ID="unknown-linux"
          HOST_FAMILY_VALIDATION_TIER="manual_only"
          ;;
      esac
      ;;
  esac
}

print_json_report() {
  local ready_value="false"
  local missing=""
  local phase=""
  local args=()

  if [[ "${READY}" -eq 1 ]]; then
    ready_value="true"
  fi

  args+=(
    build-debian-package-host-validation-report
    --mode "${MODE}"
    --os-pretty-name "${OS_PRETTY_NAME}"
    --os-id "${OS_ID}"
    --supported-product-contour "${SUPPORTED_PRODUCT_CONTOUR}"
    --supported-operator-scope "${SUPPORTED_OPERATOR_SCOPE}"
    --release-gate-name "${RELEASE_GATE_NAME}"
    --release-gate-scope "${RELEASE_GATE_SCOPE}"
    --host-family-id "${HOST_FAMILY_ID}"
    --host-family-validation-tier "${HOST_FAMILY_VALIDATION_TIER}"
    --ready "${ready_value}"
    --remediation-command "${REMEDIATION_COMMAND}"
    --run-command "${RUN_COMMAND}"
    --validation-root "${VALIDATION_ROOT}"
  )
  if [[ -n "${OS_VERSION_ID}" ]]; then
    args+=(--os-version-id "${OS_VERSION_ID}")
  fi
  if [[ -n "${PACKAGE_MANAGER}" ]]; then
    args+=(--package-manager "${PACKAGE_MANAGER}")
  fi
  for phase in "${RELEASE_GATE_REQUIRED_PHASES[@]}"; do
    args+=(--release-gate-required-phase "${phase}")
  done
  if (( ${#COMMAND_STATUS_ARGS[@]} != 0 )); then
    args+=("${COMMAND_STATUS_ARGS[@]}")
  fi
  if (( ${#MISSING_COMMANDS[@]} != 0 )); then
    for missing in "${MISSING_COMMANDS[@]}"; do
      args+=(--missing-command "${missing}")
    done
  fi
  if [[ -n "${ARTIFACT_DIR}" ]]; then
    args+=(--artifact-dir "${ARTIFACT_DIR}")
  fi
  if [[ -n "${RELEASE_HANDOFF_ARTIFACT}" ]]; then
    args+=(--release-handoff-artifact "${RELEASE_HANDOFF_ARTIFACT}")
  fi
  if [[ -n "${RELEASE_SUMMARY_ARTIFACT}" ]]; then
    args+=(--release-summary-artifact "${RELEASE_SUMMARY_ARTIFACT}")
  fi
  if [[ -n "${OPERATOR_LOOP_SUMMARY_ARTIFACT}" ]]; then
    args+=(--operator-loop-summary-artifact "${OPERATOR_LOOP_SUMMARY_ARTIFACT}")
  fi
  if [[ -n "${PILOT_INPUTS_ARTIFACT}" ]]; then
    args+=(--pilot-inputs-artifact "${PILOT_INPUTS_ARTIFACT}")
  fi
  if [[ -n "${HELPER_EXIT_CODE}" ]]; then
    args+=(--helper-exit-code "${HELPER_EXIT_CODE}")
  fi
  if [[ -n "${ERROR_CODE}" ]]; then
    args+=(--error-code "${ERROR_CODE}")
  fi

  run_aegis_measure "${args[@]}"
}

fail_helper() {
  local error_code="$1"
  local detail="$2"
  local exit_code="${3:-1}"

  READY=0
  ERROR_CODE="${error_code}"
  HELPER_EXIT_CODE="${exit_code}"
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    print_json_report
  else
    echo "${detail}" >&2
  fi
  exit "${exit_code}"
}

record_command_status() {
  local name="$1"
  local status="$2"
  local detail="$3"
  COMMAND_STATUS_ARGS+=(--command "${name}"$'\t'"${status}"$'\t'"${detail}")
  COMMAND_STATUS_TEXT+=("- ${name}: ${status} (${detail})")
}

command_basename() {
  local command_path="$1"
  printf '%s' "${command_path##*/}"
}

check_command() {
  local logical_name="$1"
  local command_path="$2"
  local detail="$3"

  if command -v "${command_path}" >/dev/null 2>&1; then
    record_command_status "${logical_name}" "ok" "${detail}"
  else
    MISSING_COMMANDS+=("${logical_name}")
    record_command_status "${logical_name}" "missing" "${detail}"
  fi
}

need_sudo() {
  [[ "${EUID}" -ne 0 ]]
}

run_as_root() {
  if need_sudo; then
    "${SUDO_BIN}" "$@"
  else
    "$@"
  fi
}

run_dpkg_mutation() {
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    # dpkg progress belongs in operator diagnostics, not in the promised JSON
    # document on stdout.
    run_as_root "${DPKG_BIN}" "$@" >&2
  else
    run_as_root "${DPKG_BIN}" "$@"
  fi
}

verify_staged_debs() {
  python3 -I -B "${ROOT}/scripts/verify-split-deb-package-set.py" \
    "${STAGED_DEB_DIR}" --arch "${deb_arch}" \
    --server-deb "${server_deb}" --client-deb "${client_deb}" >/dev/null ||
    fail_helper "split_deb_set_refused" "Private staged DEB pair changed before dpkg" 1
}

stage_regular_source() {
  local source="$1"
  local destination="$2"
  local max_bytes="$3"
  # The caller may replace the published path with a FIFO or symlink while
  # staging. Bind a nonblocking, no-follow regular-file descriptor, then copy
  # only a bounded number of bytes into the root-owned private directory.
  timeout --signal=TERM --kill-after=5s 75s python3 -I -B - \
    "${source}" "${destination}" "${max_bytes}" <<'PY'
import os, stat, sys, time

source, destination, cap_text = sys.argv[1:]
cap = int(cap_text)
read_fd = write_fd = None
try:
    read_fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    before = os.fstat(read_fd)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
        raise ValueError('source is not a bounded regular file')
    write_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    remaining = before.st_size
    deadline = time.monotonic() + 60
    while remaining:
        if time.monotonic() > deadline:
            raise TimeoutError('source copy exceeded 60 seconds')
        chunk = os.read(read_fd, min(1024 * 1024, remaining))
        if not chunk:
            raise ValueError('source changed or ended during copy')
        view = memoryview(chunk)
        while view:
            view = view[os.write(write_fd, view):]
        remaining -= len(chunk)
    after = os.fstat(read_fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('source changed during copy')
    os.fsync(write_fd)
except (OSError, ValueError, TimeoutError) as error:
    print(f'bounded stage REFUSED: {error}', file=sys.stderr)
    if write_fd is not None:
        os.close(write_fd)
        write_fd = None
        os.unlink(destination)
    sys.exit(1)
finally:
    if read_fd is not None:
        os.close(read_fd)
    if write_fd is not None:
        os.close(write_fd)
PY
}

run_aegis_measure() {
  if [[ -n "${AEGIS_MEASURE_BIN:-}" ]]; then
    [[ -x "${AEGIS_MEASURE_BIN}" ]] || {
      echo 'The explicitly supplied aegis-measure reporter is not executable.' >&2
      return 1
    }
    "${AEGIS_MEASURE_BIN}" "$@"
  elif using_prebuilt_split_debs; then
    echo 'Prebuilt validation requires the exact AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN executable; Cargo fallback is disabled.' >&2
    return 1
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-debian-package-host-validation-report --help >/dev/null 2>&1
  then
    "${ROOT}/target/debug/aegis-measure" "$@"
  else
    cargo run --locked -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
  fi
}

gather_prerequisites() {
  detect_package_manager || true
  classify_host_family

  if [[ -n "${PREBUILT_SERVER_DEB}" && -n "${PREBUILT_CLIENT_DEB}" ]]; then
    record_command_status "cargo" "not_required" "prebuilt split packages supplied explicitly"
    check_command "aegis-measure" "${AEGIS_MEASURE_BIN:-}" \
      "exact reporting ELF required through AEGIS_DEB_HOST_VALIDATION_AEGIS_MEASURE_BIN"
  else
    check_command "cargo" "cargo" "required to build split Debian packages"
  fi
  check_command "dpkg" "${DPKG_BIN}" "required for install/remove/purge lifecycle"
  check_command "dpkg-deb" "${DPKG_DEB_BIN}" "required to build and inspect .deb artifacts"
  check_command "dpkg-query" "${DPKG_QUERY_BIN}" "required to verify package states on host"
  check_command "systemctl" "${SYSTEMCTL_BIN}" "required for service-policy validation"
  check_command "journalctl" "${JOURNALCTL_BIN}" "required for service log validation"
  check_command "systemd-tmpfiles" "${SYSTEMD_TMPFILES_BIN}" "required for tmpfiles lifecycle validation"
  check_command "systemd-sysusers" "${SYSTEMD_SYSUSERS_BIN}" "required for sysusers lifecycle validation"
  if command -v python3 >/dev/null 2>&1 && python3 -I -B -c 'import tomllib' >/dev/null 2>&1; then
    record_command_status "python3" "ok" "Python >=3.11 with tomllib required by the packaged AUTO actors"
  else
    MISSING_COMMANDS+=("python3")
    record_command_status "python3" "missing" "Python >=3.11 with tomllib required by the packaged AUTO actors"
  fi
  check_command "timeout" "timeout" "required for bounded split package staging"
  check_command "openssl" "openssl" "required by packaged relay-material generation"

  if need_sudo; then
    check_command "sudo" "${SUDO_BIN}" "required unless validation runs as root"
  fi
}

using_prebuilt_split_debs() {
  [[ -n "${PREBUILT_SERVER_DEB}" && -n "${PREBUILT_CLIENT_DEB}" ]]
}

validate_prebuilt_split_debs() {
  if [[ -n "${PREBUILT_SERVER_DEB}" && -z "${PREBUILT_CLIENT_DEB}" ]]; then
    fail_helper "missing_client_deb" "--client-deb is required when --server-deb is provided" 1
  fi
  if [[ -n "${PREBUILT_CLIENT_DEB}" && -z "${PREBUILT_SERVER_DEB}" ]]; then
    fail_helper "missing_server_deb" "--server-deb is required when --client-deb is provided" 1
  fi
  if [[ -n "${PREBUILT_SERVER_DEB}" && ! -f "${PREBUILT_SERVER_DEB}" ]]; then
    fail_helper "missing_server_deb" "Missing prebuilt server package: ${PREBUILT_SERVER_DEB}" 1
  fi
  if [[ -n "${PREBUILT_CLIENT_DEB}" && ! -f "${PREBUILT_CLIENT_DEB}" ]]; then
    fail_helper "missing_client_deb" "Missing prebuilt client package: ${PREBUILT_CLIENT_DEB}" 1
  fi
}

print_text_report() {
  local item=""
  echo "Debian package host validation prerequisites"
  echo "------------------------------------------"
  echo "Host: ${OS_PRETTY_NAME}"
  echo "Family: ${HOST_FAMILY_ID} (${HOST_FAMILY_VALIDATION_TIER})"
  if [[ -n "${PACKAGE_MANAGER}" ]]; then
    echo "Package manager: ${PACKAGE_MANAGER}"
  else
    echo "Package manager: unavailable"
  fi
  echo
  for item in "${COMMAND_STATUS_TEXT[@]}"; do
    printf '%s\n' "${item}"
  done
  echo
  if [[ "${READY}" -eq 1 ]]; then
    echo "Host prerequisites look ready for Debian package lifecycle validation."
    echo "Run: ${RUN_COMMAND}"
  else
    echo "Host prerequisites are incomplete."
    echo "Remediation: ${REMEDIATION_COMMAND}"
  fi
}

write_summary_json() {
  local output_path="$1"
  local operator_loop_summary_path=""
  local args=()
  if [[ $# -ge 2 ]]; then
    operator_loop_summary_path="$2"
    shift 2
  else
    shift 1
  fi
  args=(build-debian-package-host-run-summary
    --output "${output_path}"
    --validation-root "${VALIDATION_ROOT}"
    --upgrade-reapply-mode "${UPGRADE_REAPPLY_MODE}")
  if [[ -n "${operator_loop_summary_path}" ]]; then
    args+=(--operator-loop-summary "${operator_loop_summary_path}")
  fi
  local phase_entry=""
  for phase_entry in "$@"; do
    args+=(--phase "${phase_entry}")
  done
  run_aegis_measure "${args[@]}"
}

write_release_gate_handoff_json() {
  local output_path="$1"
  local host_summary_path="$2"
  run_aegis_measure build-debian-package-host-release-gate-handoff \
    --output "${output_path}" \
    --host-summary "${host_summary_path}"
}

write_operator_loop_summary_json() {
  local output_path="$1"
  local client_config="$2"
  local runtime_events="$3"
  local preflight_json="$4"
  local startup_probe_json="$5"
  local events_summary_json="$6"
  local operator_evidence_json="$7"
  local operator_evidence_txt="$8"
  run_aegis_measure build-debian-package-host-operator-loop-summary \
    --output "${output_path}" \
    --client-config "${client_config}" \
    --runtime-events "${runtime_events}" \
    --preflight-json "${preflight_json}" \
    --startup-probe-json "${startup_probe_json}" \
    --events-summary-json "${events_summary_json}" \
    --operator-evidence-json "${operator_evidence_json}" \
    --operator-evidence-txt "${operator_evidence_txt}"
}

write_release_summary_json() {
  local output_path="$1"
  local host_summary_path="$2"
  local release_handoff_path="$3"
  local operator_loop_summary_path="$4"
  run_aegis_measure build-debian-package-host-release-summary \
    --output "${output_path}" \
    --host-summary "${host_summary_path}" \
    --release-handoff "${release_handoff_path}" \
    --operator-loop-summary "${operator_loop_summary_path}"
}

write_pilot_inputs_json() {
  local output_path="$1"
  local summary_json="$2"
  local runtime_artifacts_dir="$3"
  local release_handoff_path="$4"
  local release_summary_path="$5"
  local operator_loop_summary_path="$6"
  run_aegis_measure build-debian-package-host-pilot-inputs \
    --output "${output_path}" \
    --validation-summary "${summary_json}" \
    --runtime-artifacts-dir "${runtime_artifacts_dir}" \
    --release-handoff "${release_handoff_path}" \
    --release-summary "${release_summary_path}" \
    --operator-loop-summary "${operator_loop_summary_path}"
}

service_ctl() {
  run_as_root "${SYSTEMCTL_BIN}" "$@"
}

journal_read() {
  run_as_root "${JOURNALCTL_BIN}" "$@"
}

run_client_cli() {
  local client_bin=""
  client_bin="$(resolve_client_bin)" || fail_helper "client_binary_missing" "Unable to locate aegis-client for Ubuntu acceptance gate." 4
  "${client_bin}" "$@"
}

write_server_config() {
  local config_path="$1"
  local cert_path="$2"
  local key_path="$3"
  local auth_token="$4"
  local listen_addr="$5"

  cat > "${config_path}" <<EOF
listen = "${listen_addr}"
cert = "${cert_path}"
key = "${key_path}"
auth_token = "${auth_token}"
fallback = "close"

[transport]
websocket_path = "/aegis/ws"
grpc_path = "/aegis.tunnel.v1.TunnelService/Open"
masque_path = "/.well-known/masque/udp"
EOF
}

prepare_runtime_materials() {
  local artifact_dir="$1"
  local server_root=""
  local client_root=""
  local cert_root=""
  local bundle_root=""
  local server_config=""
  local client_config=""
  local client_ca=""
  local auth_token="a5a1cdad68ab5561b973a58933b7d731725e06b2adc2c1cfd1249be0242b74d5"
  local relay_host="127.0.0.1"
  local relay_addr="${relay_host}:8443"
  local generate_script=""
  local render_script=""
  local secret_reader=""
  local service_group="root"

  server_root="$(path_in_root "${SERVER_CONFIG_DIR}")"
  client_root="$(path_in_root "${CLIENT_CONFIG_DIR}")"
  cert_root="${server_root}/certs"
  bundle_root="${artifact_dir}/client-bundle"
  server_config="${server_root}/aegis-server.toml"
  client_config="${client_root}/aegis.toml"
  client_ca="${client_root}/ca.pem"
  generate_script="$(resolve_generate_relay_script)" || fail_helper "generate_relay_script_missing" "Unable to locate generate-relay-materials.sh." 4
  render_script="$(resolve_render_client_bundle_script)" || fail_helper "render_client_bundle_script_missing" "Unable to locate render-client-bundle.sh." 4
  secret_reader="$(resolve_server_bin)" || fail_helper "private_secret_reader_missing" "Installed Rust secret reader unavailable." 4
  [[ "$secret_reader" == /* && -x "$secret_reader" && "$("$secret_reader" installer-secret version)" == installer-secret-v1 ]] ||
    fail_helper "private_secret_reader_missing" "Installed private input protocol unavailable." 4
  export -n auth_token

  mkdir -p \
    "${server_root}" \
    "${client_root}" \
    "${cert_root}" \
    "$(path_in_root "${SERVER_STATE_DIR}")" \
    "$(path_in_root "${CLIENT_STATE_DIR}")" \
    "$(path_in_root "${CLIENT_LOG_DIR}")" \
    "${bundle_root}"

  "${generate_script}" "${cert_root}" "localhost" "${relay_host}" >/dev/null
  write_server_config \
    "${server_config}" \
    "${cert_root}/server.pem" \
    "${cert_root}/server-key.pem" \
    "${auth_token}" \
    "${relay_addr}"

  printf '%s' "$auth_token" | "${render_script}" \
    "${bundle_root}" \
    "${relay_addr}" \
    "localhost" \
    --auth-token-stdin \
    "${cert_root}/ca.pem" \
    "$secret_reader" >/dev/null

  cp "${bundle_root}/ca.pem" "${client_ca}"
  sed "s|__CLIENT_CA_CERT_PATH__|${client_ca}|g" "${bundle_root}/aegis-client.toml" > "${client_config}"
  chmod 0600 "${server_config}" "${cert_root}/server.pem" "${cert_root}/server-key.pem" "${cert_root}/ca.pem" "${client_config}" "${client_ca}"

  if [[ "${VALIDATION_ROOT}" == "/" && "${EUID}" -eq 0 && "$(id -u aegis >/dev/null 2>&1; echo $?)" -eq 0 ]]; then
    service_group="aegis"
    chown root:"${service_group}" "${server_root}" "${cert_root}"
    chown root:"${service_group}" "${server_config}" "${cert_root}/server.pem" "${cert_root}/server-key.pem" "${cert_root}/ca.pem"
    chmod 0750 "${server_root}" "${cert_root}"
    chmod 0640 "${server_config}" "${cert_root}/server.pem" "${cert_root}/server-key.pem" "${cert_root}/ca.pem"
  fi
}

validate_host_family() {
  if [[ "${HOST_FAMILY_ID}" != "debian-apt" ]]; then
    fail_helper "unsupported_host_family" "This helper currently targets Debian-family hosts with apt-based userspace." 2
  fi
}

run_check_mode() {
  validate_prebuilt_split_debs
  gather_prerequisites
  validate_host_family

  if (( ${#MISSING_COMMANDS[@]} == 0 )); then
    READY=1
    HELPER_EXIT_CODE=0
  else
    READY=0
    HELPER_EXIT_CODE=1
  fi

  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    print_json_report
  else
    print_text_report
  fi

  exit "${HELPER_EXIT_CODE}"
}

verify_install_state() {
  local summary_json="$1"
  run_aegis_measure verify-debian-package-host-install-state \
    --dpkg-query "${DPKG_QUERY_BIN}" \
    --validation-root "${VALIDATION_ROOT}"

  write_summary_json "${summary_json}"
}

verify_disabled_units() {
  local unit=""
  local state=""
  for unit in aegis-server.service aegis-client.service; do
    state="$("${SYSTEMCTL_BIN}" is-enabled "${unit}" 2>/dev/null || true)"
    case "${state}" in
      enabled|enabled-runtime|linked|linked-runtime|alias)
        fail_helper "unexpected_enabled_unit" "Expected ${unit} to remain disabled after preset policy, got '${state}'." 3
        ;;
    esac
  done
}

verify_remove_state() {
  run_aegis_measure verify-debian-package-host-remove-state \
    --dpkg-query "${DPKG_QUERY_BIN}" \
    --validation-root "${VALIDATION_ROOT}"
}

verify_purge_state() {
  run_aegis_measure verify-debian-package-host-purge-state \
    --dpkg-query "${DPKG_QUERY_BIN}" \
    --validation-root "${VALIDATION_ROOT}"
}

verify_service_active() {
  local unit="$1"
  local artifact_path="$2"
  local state=""

  state="$(service_ctl is-active "${unit}" 2>/dev/null || true)"
  printf '%s\n' "${state}" > "${artifact_path}"
  case "${state}" in
    active) ;;
    *)
      fail_helper "service_not_active" "Expected ${unit} to be active, got '${state}'." 5
      ;;
  esac
}

capture_service_status() {
  local unit="$1"
  local artifact_path="$2"
  service_ctl status "${unit}" > "${artifact_path}" 2>&1 || fail_helper "service_status_failed" "Failed to collect systemctl status for ${unit}." 5
}

capture_service_journal() {
  local unit="$1"
  local artifact_path="$2"
  journal_read -u "${unit}" --no-pager -n 20 > "${artifact_path}" 2>&1 || fail_helper "journal_read_failed" "Failed to collect journal for ${unit}." 5
}

run_client_preflight() {
  local client_config="$1"
  local artifact_path="$2"
  local status=0

  set +e
  run_client_cli --config "${client_config}" --ingress-preflight --json > "${artifact_path}" 2>&1
  status=$?
  set -e
  run_aegis_measure verify-debian-package-host-client-json-artifact \
    --artifact "${artifact_path}" \
    --exit-status "${status}"
}

run_client_startup_probe() {
  local client_config="$1"
  local artifact_path="$2"
  local status=0

  set +e
  run_client_cli --config "${client_config}" --ingress-startup-probe --json > "${artifact_path}" 2>&1
  status=$?
  set -e
  run_aegis_measure verify-debian-package-host-client-json-artifact \
    --artifact "${artifact_path}" \
    --exit-status "${status}"
}

verify_runtime_events() {
  local events_path="$1"
  local artifact_path="$2"
  run_aegis_measure build-debian-package-host-runtime-events-summary \
    --runtime-events "${events_path}" \
    --output "${artifact_path}"
}

cleanup_client_network_helper_residue() {
  local redirect_script=""
  local tproxy_script=""

  redirect_script="$(resolve_setup_wide_redirect_script || true)"
  if [[ -n "${redirect_script}" && -x "${redirect_script}" ]]; then
    run_as_root bash "${redirect_script}" teardown >/dev/null 2>&1 || true
  fi

  tproxy_script="$(resolve_setup_wide_tproxy_script || true)"
  if [[ -n "${tproxy_script}" && -x "${tproxy_script}" ]]; then
    run_as_root bash "${tproxy_script}" teardown >/dev/null 2>&1 || true
  fi
}

run_service_acceptance_checks() {
  local summary_json="$1"
  local artifact_dir="$2"
  local client_config=""
  local runtime_events=""
  local server_status_file="${artifact_dir}/server-systemctl-status.log"
  local client_status_file="${artifact_dir}/client-systemctl-status.log"
  local server_active_file="${artifact_dir}/server-is-active.txt"
  local client_active_file="${artifact_dir}/client-is-active.txt"
  local server_journal_file="${artifact_dir}/server-journal.log"
  local client_journal_file="${artifact_dir}/client-journal.log"
  local preflight_json="${artifact_dir}/client-preflight.json"
  local startup_probe_json="${artifact_dir}/client-startup-probe.json"
  local events_summary_json="${artifact_dir}/client-runtime-events-summary.json"
  local operator_loop_summary_json="${artifact_dir}/client-operator-loop-summary.json"
  local operator_evidence_json="${artifact_dir}/client-operator-evidence.json"
  local operator_evidence_txt="${artifact_dir}/client-operator-evidence.txt"

  client_config="$(path_in_root "${CLIENT_CONFIG_DIR}/aegis.toml")"
  runtime_events="$(path_in_root "${CLIENT_LOG_DIR}/runtime-events.jsonl")"

  prepare_runtime_materials "${artifact_dir}"
  # A previous live session can leave one of the packaged units active on the
  # host, which would make the preflight/startup bind probes report
  # `listener_busy` before this validation window even starts. Stop both units
  # best-effort so the acceptance run always measures a fresh service contour.
  service_ctl stop "${CLIENT_UNIT}" >/dev/null 2>&1 || true
  service_ctl stop "${SERVER_UNIT}" >/dev/null 2>&1 || true
  service_ctl daemon-reload >/dev/null 2>&1 || true
  service_ctl start "${SERVER_UNIT}"
  run_client_preflight "${client_config}" "${preflight_json}"
  run_client_startup_probe "${client_config}" "${startup_probe_json}"
  service_ctl start "${CLIENT_UNIT}"
  verify_service_active "${SERVER_UNIT}" "${server_active_file}"
  verify_service_active "${CLIENT_UNIT}" "${client_active_file}"
  capture_service_status "${SERVER_UNIT}" "${server_status_file}"
  capture_service_status "${CLIENT_UNIT}" "${client_status_file}"
  capture_service_journal "${SERVER_UNIT}" "${server_journal_file}"
  capture_service_journal "${CLIENT_UNIT}" "${client_journal_file}"
  verify_runtime_events "${runtime_events}" "${events_summary_json}"
  AEGIS_CLIENT_CONFIG="${client_config}" \
    AEGIS_RUNTIME_EVENTS_JSONL="${runtime_events}" \
    AEGIS_OPERATOR_EVIDENCE_JSON="${operator_evidence_json}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" events >"${operator_evidence_txt}"
  write_operator_loop_summary_json \
    "${operator_loop_summary_json}" \
    "${client_config}" \
    "${runtime_events}" \
    "${preflight_json}" \
    "${startup_probe_json}" \
    "${events_summary_json}" \
    "${operator_evidence_json}" \
    "${operator_evidence_txt}"
  OPERATOR_LOOP_SUMMARY_ARTIFACT="${operator_loop_summary_json}"
  record_phase_result "service_start" "passed" "server service, green client preflight/startup probe and active client runtime all succeeded"

  service_ctl restart "${SERVER_UNIT}"
  service_ctl restart "${CLIENT_UNIT}"
  verify_service_active "${SERVER_UNIT}" "${server_active_file}"
  verify_service_active "${CLIENT_UNIT}" "${client_active_file}"
  record_phase_result "service_restart" "passed" "server/client services survived explicit restart"

  service_ctl daemon-reload >/dev/null 2>&1 || true
  service_ctl restart "${SERVER_UNIT}"
  service_ctl restart "${CLIENT_UNIT}"
  verify_service_active "${SERVER_UNIT}" "${server_active_file}"
  verify_service_active "${CLIENT_UNIT}" "${client_active_file}"
  record_phase_result "reboot_contract" "passed" "daemon-reload plus restart kept both services healthy (reboot-proximate contract)"

  write_summary_json "${summary_json}" "${OPERATOR_LOOP_SUMMARY_ARTIFACT:-}" "${PHASE_RESULTS[@]}"
}

run_lifecycle_validation() {
  local output_dir=""
  local server_deb=""
  local client_deb=""
  local summary_json=""
  local runtime_artifacts_dir=""
  local release_handoff_json=""
  local release_summary_json=""
  local pilot_inputs_json=""

  # dpkg is privileged; a nonroot caller cannot hold an immutable staged
  # package directory against another process with the same UID.
  [[ "${EUID}" -eq 0 ]] ||
    fail_helper "root_required" "Run package lifecycle validation as root" 1

  validate_prebuilt_split_debs
  gather_prerequisites
  validate_host_family
  if (( ${#MISSING_COMMANDS[@]} != 0 )); then
    fail_helper "missing_prerequisites" "Host prerequisites are incomplete; run --check first." 1
  fi

  if [[ -z "${ARTIFACT_DIR}" ]]; then
    ARTIFACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-debian-host-validation.XXXXXX")"
  fi
  mkdir -p "${ARTIFACT_DIR}"

  output_dir="${ARTIFACT_DIR}/packages"
  summary_json="${ARTIFACT_DIR}/validation-summary.json"
  runtime_artifacts_dir="${ARTIFACT_DIR}/runtime"
  release_handoff_json="${ARTIFACT_DIR}/ubuntu-release-gate-handoff.json"
  release_summary_json="${ARTIFACT_DIR}/ubuntu-product-release-summary.json"
  pilot_inputs_json="${ARTIFACT_DIR}/ubuntu-controlled-pilot-inputs.json"
  mkdir -p "${output_dir}"
  mkdir -p "${runtime_artifacts_dir}"

  if using_prebuilt_split_debs; then
    # Release-bound evidence must be able to validate the published .deb assets
    # directly, without reconstructing packages from a local source checkout.
    server_deb="${PREBUILT_SERVER_DEB}"
    client_deb="${PREBUILT_CLIENT_DEB}"
  else
    # Keep the source-checkout entrypoint simple when release assets are not
    # supplied: build the split packages locally, then validate their lifecycle.
    "${BUILD_SPLIT_DEBS_SCRIPT}" "${output_dir}" >/dev/null
    server_deb="$(printf '%s\n' "${output_dir}"/aegis-server_*.deb)"
    client_deb="$(printf '%s\n' "${output_dir}"/aegis-client_*.deb)"
  fi

  # The split marker is the publication boundary. Select names, then take a
  # private snapshot before verification so dpkg reads the very bytes checked.
  [[ "$(dirname "${server_deb}")" == "$(dirname "${client_deb}")" ]] ||
    fail_helper "split_deb_set_refused" "Server/client DEBs must share a package directory" 1
  [[ "${server_deb##*/}" =~ ^aegis-server_[^/]+_(amd64|arm64|armhf)\.deb$ ]] ||
    fail_helper "split_deb_set_refused" "Invalid server DEB filename" 1
  deb_arch="${BASH_REMATCH[1]}"
  command -v python3 >/dev/null 2>&1 ||
    fail_helper "split_deb_set_refused" "python3 is required to verify split DEBs" 1
  command -v timeout >/dev/null 2>&1 ||
    fail_helper "split_deb_stage_failed" "timeout is required for bounded DEB staging" 1
  # Do not let dpkg reopen user-writable prebuilt paths after staging.
  # The private 0700 directory remains owned by this process for the complete
  # install/remove/reapply lifecycle; every install verifies its staged bytes.
  [[ -O /tmp && -k /tmp ]] ||
    fail_helper "split_deb_stage_failed" "Private DEB staging parent is not trusted" 1
  STAGED_DEB_DIR="$(mktemp -d /tmp/aegis-verified-debs.XXXXXX)" ||
    fail_helper "split_deb_stage_failed" "Could not create private DEB staging directory" 1
  chmod 0700 "${STAGED_DEB_DIR}"
  [[ ! -L "${STAGED_DEB_DIR}" && -O "${STAGED_DEB_DIR}" ]] ||
    fail_helper "split_deb_stage_failed" "Private DEB staging directory ownership failed" 1
  for source in "${server_deb}" "${client_deb}" \
                "${server_deb}.sha256" "${client_deb}.sha256" \
                "$(dirname "${server_deb}")/split-deb-packages.manifest.json"; do
    case "${source}" in
      *.deb) max_source_bytes=$((512 * 1024 * 1024)) ;;
      *.sha256) max_source_bytes=128 ;;
      *) max_source_bytes=$((1024 * 1024)) ;;
    esac
    stage_regular_source "${source}" "${STAGED_DEB_DIR}/$(basename "${source}")" "${max_source_bytes}" ||
      fail_helper "split_deb_stage_failed" "Could not stage verified DEB bytes" 1
  done
  chmod 0600 "${STAGED_DEB_DIR}"/*
  server_deb="${STAGED_DEB_DIR}/$(basename "${server_deb}")"
  client_deb="${STAGED_DEB_DIR}/$(basename "${client_deb}")"
  # The source directory may change while copying. Only the private snapshot
  # is authoritative for this lifecycle, and every install checks it again.
  verify_staged_debs

  # Validation reuses real host state, so clear any stale client-side helper
  # residue before switching the same machine back into package lifecycle roles.
  cleanup_client_network_helper_residue
  verify_staged_debs
  run_dpkg_mutation --install "${server_deb}" "${client_deb}"
  verify_install_state "${summary_json}"
  record_phase_result "install" "passed" "split packages installed cleanly"
  verify_disabled_units
  record_phase_result "preset_policy" "passed" "units remain disabled by default after package install"
  run_service_acceptance_checks "${summary_json}" "${runtime_artifacts_dir}"

  run_dpkg_mutation --remove aegis-client aegis-server
  cleanup_client_network_helper_residue
  verify_remove_state
  record_phase_result "remove" "passed" "remove preserved conffiles and removed package payload"

  cleanup_client_network_helper_residue
  verify_staged_debs
  run_dpkg_mutation --install "${server_deb}" "${client_deb}"
  verify_install_state "${summary_json}"
  record_phase_result "reinstall" "passed" "packages reinstall cleanly after remove"

  verify_staged_debs
  run_dpkg_mutation --install "${server_deb}" "${client_deb}"
  verify_install_state "${summary_json}"
  record_phase_result "upgrade_reapply" "passed" "same-version dpkg reapply kept installed payload coherent"

  run_dpkg_mutation --purge aegis-client aegis-server
  cleanup_client_network_helper_residue
  verify_purge_state
  record_phase_result "purge" "passed" "purge removed package state and default conffiles"
  write_summary_json "${summary_json}" "${OPERATOR_LOOP_SUMMARY_ARTIFACT:-}" "${PHASE_RESULTS[@]}"
  write_release_gate_handoff_json "${release_handoff_json}" "${summary_json}"
  write_release_summary_json "${release_summary_json}" "${summary_json}" "${release_handoff_json}" "${OPERATOR_LOOP_SUMMARY_ARTIFACT}"
  write_pilot_inputs_json "${pilot_inputs_json}" "${summary_json}" "${runtime_artifacts_dir}" "${release_handoff_json}" "${release_summary_json}" "${OPERATOR_LOOP_SUMMARY_ARTIFACT}"
  RELEASE_HANDOFF_ARTIFACT="${release_handoff_json}"
  RELEASE_SUMMARY_ARTIFACT="${release_summary_json}"
  PILOT_INPUTS_ARTIFACT="${pilot_inputs_json}"

  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    READY=1
    HELPER_EXIT_CODE=0
    print_json_report
  else
    echo "Debian package host lifecycle validation completed."
    echo "Artifacts:"
    echo "  ${ARTIFACT_DIR}"
  fi
}

ensure_user_cargo_path

trap restore_artifact_ownership EXIT

# Keep parser-level failures machine-readable even when `--json` comes later.
for arg in "$@"; do
  if [[ "${arg}" == "--json" ]]; then
    JSON_OUTPUT=1
    break
  fi
done

while [[ $# -gt 0 ]]; do
  case "${1}" in
    --check)
      MODE="check"
      shift
      ;;
    --run)
      MODE="run"
      shift
      ;;
    --json)
      JSON_OUTPUT=1
      shift
      ;;
    --artifact-dir)
      if [[ $# -lt 2 ]]; then
        fail_helper "missing_argument" "--artifact-dir requires a value" 1
      fi
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --server-deb)
      if [[ $# -lt 2 ]]; then
        fail_helper "missing_argument" "--server-deb requires a value" 1
      fi
      PREBUILT_SERVER_DEB="$2"
      shift 2
      ;;
    --client-deb)
      if [[ $# -lt 2 ]]; then
        fail_helper "missing_argument" "--client-deb requires a value" 1
      fi
      PREBUILT_CLIENT_DEB="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail_helper "unknown_argument" "Unknown argument: $1" 1
      ;;
  esac
done

case "${MODE}" in
  check)
    run_check_mode
    ;;
  run)
    run_lifecycle_validation
    ;;
esac
