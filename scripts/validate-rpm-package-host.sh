#!/usr/bin/env bash
# Best-effort RPM host validation for the AEGIS split .rpm lifecycle.
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
ARTIFACT_DIR="${AEGIS_RPM_HOST_VALIDATION_ARTIFACT_DIR:-}"
PREBUILT_SERVER_RPM="${AEGIS_RPM_HOST_VALIDATION_SERVER_RPM:-}"
PREBUILT_CLIENT_RPM="${AEGIS_RPM_HOST_VALIDATION_CLIENT_RPM:-}"
VALIDATION_ROOT="${AEGIS_RPM_HOST_VALIDATION_ROOT:-/}"
while [[ "${VALIDATION_ROOT}" == *"//"* ]]; do
  VALIDATION_ROOT="${VALIDATION_ROOT//\/\///}"
done

BUILD_SPLIT_RPMS_SCRIPT="${AEGIS_RPM_HOST_VALIDATION_BUILD_SPLIT_RPMS_SCRIPT:-${ROOT}/scripts/build-rpm-packages.sh}"
RPM_BIN="${AEGIS_RPM_HOST_VALIDATION_RPM_BIN:-rpm}"
RPM_QUERY_BIN="${AEGIS_RPM_HOST_VALIDATION_RPM_QUERY_BIN:-rpm}"
SYSTEMCTL_BIN="${AEGIS_RPM_HOST_VALIDATION_SYSTEMCTL_BIN:-systemctl}"
SYSTEMD_TMPFILES_BIN="${AEGIS_RPM_HOST_VALIDATION_SYSTEMD_TMPFILES_BIN:-systemd-tmpfiles}"
SYSTEMD_SYSUSERS_BIN="${AEGIS_RPM_HOST_VALIDATION_SYSTEMD_SYSUSERS_BIN:-systemd-sysusers}"
SUDO_BIN="${AEGIS_RPM_HOST_VALIDATION_SUDO_BIN:-sudo}"

REMEDIATION_COMMAND='bash scripts/validate-rpm-package-host.sh --check'
RUN_COMMAND='sudo env HOME="$HOME" PATH="$HOME/.cargo/bin:$PATH" bash scripts/validate-rpm-package-host.sh --run'
SUPPORTED_PRODUCT_CONTOUR='linux_first_split_rpm_package_validation'
SUPPORTED_OPERATOR_SCOPE='rpm_host_package_lifecycle_validation'

run_aegis_measure() {
  if [[ -x "${AEGIS_MEASURE_BIN:-}" ]]; then
    "${AEGIS_MEASURE_BIN}" "$@"
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-rpm-package-host-validation-report --help >/dev/null 2>&1
  then
    "${ROOT}/target/debug/aegis-measure" "$@"
  else
    cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- "$@"
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
  scripts/validate-rpm-package-host.sh [--check|--run] [--json] [--artifact-dir <dir>]
    [--server-rpm <path>] [--client-rpm <path>]

Modes:
  --check             Validate RPM-host prerequisites for split package lifecycle proof.
  --run               Build or consume split RPMs, then run install -> erase ->
                      reinstall -> same-version reapply -> final erase.
  --json              Emit machine-readable JSON instead of text.
  --artifact-dir DIR  Directory for built packages and validation summary.
  --server-rpm PATH   Use a prebuilt aegis-server RPM instead of rebuilding.
  --client-rpm PATH   Use a prebuilt aegis-client RPM instead of rebuilding.

This helper targets real RPM-family host validation for:
  scripts/build-rpm-packages.sh
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
  for candidate in dnf yum zypper; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      PACKAGE_MANAGER="${candidate}"
      return 0
    fi
  done
  return 1
}

classify_host_family() {
  case "${OS_ID}" in
    rhel|rocky|almalinux|centos|fedora)
      HOST_FAMILY_ID="rhel-dnf"
      HOST_FAMILY_VALIDATION_TIER="packaging_validation_target"
      ;;
    opensuse*|sles)
      HOST_FAMILY_ID="suse-zypper"
      HOST_FAMILY_VALIDATION_TIER="packaging_validation_target"
      ;;
    *)
      case "${PACKAGE_MANAGER}" in
        dnf|yum)
          HOST_FAMILY_ID="rhel-dnf"
          HOST_FAMILY_VALIDATION_TIER="packaging_validation_target"
          ;;
        zypper)
          HOST_FAMILY_ID="suse-zypper"
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
  local args=()

  if [[ "${READY}" -eq 1 ]]; then
    ready_value="true"
  fi

  args+=(
    build-rpm-package-host-validation-report
    --mode "${MODE}"
    --os-pretty-name "${OS_PRETTY_NAME}"
    --os-id "${OS_ID}"
    --supported-product-contour "${SUPPORTED_PRODUCT_CONTOUR}"
    --supported-operator-scope "${SUPPORTED_OPERATOR_SCOPE}"
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
  if [[ -n "${HELPER_EXIT_CODE}" ]]; then
    args+=(--helper-exit-code "${HELPER_EXIT_CODE}")
  fi
  if [[ -n "${ERROR_CODE}" ]]; then
    args+=(--error-code "${ERROR_CODE}")
  fi

  if (( ${#COMMAND_STATUS_ARGS[@]} != 0 )); then
    args+=("${COMMAND_STATUS_ARGS[@]}")
  fi
  if (( ${#MISSING_COMMANDS[@]} != 0 )); then
    for missing in "${MISSING_COMMANDS[@]}"; do
      args+=(--missing-command "${missing}")
    done
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

run_rpm_mutation() {
  local root_prefix=()
  if [[ -n "${AEGIS_RPM_POSTINSTALL_NONCE:-}" ]]; then
    root_prefix=(env "AEGIS_RPM_POSTINSTALL_NONCE=${AEGIS_RPM_POSTINSTALL_NONCE}")
  fi
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    # rpm writes progress to stdout. Keep --json stdout machine-readable while
    # retaining package-manager diagnostics on stderr for operator logs.
    run_as_root "${root_prefix[@]}" "${RPM_BIN}" "$@" >&2
  else
    run_as_root "${root_prefix[@]}" "${RPM_BIN}" "$@"
  fi
}

ACTIVE_RPM_RECEIPT=""
cleanup_active_rpm_receipt() {
  local receipt="${ACTIVE_RPM_RECEIPT}"
  [[ -n "${receipt}" ]] || return 0
  [[ "${receipt}" =~ ^/run/aegis-rpm-postinstall\.[a-zA-Z0-9]+$ ]] || return 1
  run_as_root rm -f -- "${receipt}/aegis-server.ok" "${receipt}/aegis-client.ok" || return 1
  run_as_root rmdir -- "${receipt}" || return 1
  ACTIVE_RPM_RECEIPT=""
}
trap 'cleanup_active_rpm_receipt' EXIT

install_rpms_checked() {
  local stage="$1"
  shift
  local pkg=""
  local receipt=""
  local nonce=""
  local run_owner=""
  local run_mode=""
  local rpm_status=0
  local server_status="missing"
  local client_status="missing"
  local status_file=""
  # The parent and receipt are root-owned; no privileged write touches a
  # caller-owned artifact path. Validate before asking root to create it.
  [[ -d /run && ! -L /run ]] ||
    fail_helper "rpm_receipt_parent_unsafe" "RPM receipt parent /run is not a real directory." 3
  run_owner="$(run_as_root stat -Lc %u -- /run)" ||
    fail_helper "rpm_receipt_parent_unsafe" "Cannot inspect RPM receipt parent." 3
  run_mode="$(run_as_root stat -Lc %a -- /run)" ||
    fail_helper "rpm_receipt_parent_unsafe" "Cannot inspect RPM receipt parent mode." 3
  [[ "${run_owner}" == 0 && "${run_mode}" =~ ^[0-7]+$ ]] ||
    fail_helper "rpm_receipt_parent_unsafe" "RPM receipt parent is not root owned." 3
  (( (8#${run_mode} & 8#22) == 0 )) ||
    fail_helper "rpm_receipt_parent_unsafe" "RPM receipt parent allows nonroot writes." 3
  receipt="$(run_as_root mktemp -d /run/aegis-rpm-postinstall.XXXXXX)" ||
    fail_helper "rpm_receipt_create_failed" "Could not create a protected RPM postinstall receipt." 3
  ACTIVE_RPM_RECEIPT="${receipt}"
  nonce="${receipt##*.}"
  [[ "${nonce}" =~ ^[a-zA-Z0-9]+$ ]] ||
    fail_helper "rpm_receipt_create_failed" "Unexpected RPM receipt name." 3
  [[ "$(run_as_root stat -Lc %u:%a -- "${receipt}")" == "0:700" ]] ||
    fail_helper "rpm_receipt_not_private" "RPM postinstall receipt is not root-owned mode 700." 3
  if AEGIS_RPM_POSTINSTALL_NONCE="${nonce}" run_rpm_mutation -Uvh "$@"; then
    rpm_status=0
  else
    rpm_status=$?
  fi
  if [[ "$(run_as_root cat -- "${receipt}/aegis-server.ok" 2>/dev/null || true)" == "${nonce}" ]]; then
    server_status="confirmed"
  fi
  if [[ "$(run_as_root cat -- "${receipt}/aegis-client.ok" 2>/dev/null || true)" == "${nonce}" ]]; then
    client_status="confirmed"
  fi
  status_file="$(mktemp "${ARTIFACT_DIR}/postinstall-${stage}.XXXXXX")" ||
    fail_helper "rpm_receipt_summary_failed" "Cannot create RPM receipt summary." 3
  printf 'stage=%s\nrpm_exit=%s\nserver_postinstall=%s\nclient_postinstall=%s\n' \
    "${stage}" "${rpm_status}" "${server_status}" "${client_status}" > "${status_file}"
  cleanup_active_rpm_receipt ||
    fail_helper "rpm_receipt_cleanup_failed" "Could not clean protected RPM receipt; inspect /run before retry." 3
  if [[ "${rpm_status}" -ne 0 ]]; then
    fail_helper "rpm_transaction_failed" "RPM transaction failed at ${stage}; package registration may be partial. Inspect and recover before retry. Status: ${status_file}" 3
  fi
  if [[ "${server_status}" != confirmed || "${client_status}" != confirmed ]]; then
    fail_helper "rpm_postinstall_unconfirmed" "RPM postinstall unconfirmed at ${stage}; package registration may be partial. Inspect and recover before retry. Status: ${status_file}" 3
  fi
}

gather_prerequisites() {
  detect_package_manager || true
  classify_host_family

  if using_prebuilt_split_rpms; then
    record_command_status "cargo" "not_required" "prebuilt split packages supplied explicitly"
    record_command_status "rpmbuild" "not_required" "prebuilt split packages supplied explicitly"
  else
    check_command "cargo" "cargo" "required to build split RPM packages"
    check_command "rpmbuild" "rpmbuild" "required to build .rpm artifacts"
  fi
  check_command "python3" "python3" "required for completed RPM pair verification"
  check_command "rpm" "${RPM_BIN}" "required for install/remove lifecycle"
  check_command "rpm-query" "${RPM_QUERY_BIN}" "required to verify package states on host"
  check_command "systemctl" "${SYSTEMCTL_BIN}" "required for service-policy validation"
  check_command "systemd-tmpfiles" "${SYSTEMD_TMPFILES_BIN}" "required for tmpfiles lifecycle validation"
  check_command "systemd-sysusers" "${SYSTEMD_SYSUSERS_BIN}" "required for sysusers lifecycle validation"

  if need_sudo; then
    check_command "sudo" "${SUDO_BIN}" "required unless validation runs as root"
  fi
}

using_prebuilt_split_rpms() {
  [[ -n "${PREBUILT_SERVER_RPM}" && -n "${PREBUILT_CLIENT_RPM}" ]]
}

validate_prebuilt_split_rpms() {
  if [[ -n "${PREBUILT_SERVER_RPM}" && -z "${PREBUILT_CLIENT_RPM}" ]]; then
    fail_helper "missing_client_rpm" "--client-rpm is required with --server-rpm" 1
  fi
  if [[ -n "${PREBUILT_CLIENT_RPM}" && -z "${PREBUILT_SERVER_RPM}" ]]; then
    fail_helper "missing_server_rpm" "--server-rpm is required with --client-rpm" 1
  fi
  if [[ -n "${PREBUILT_SERVER_RPM}" && ! -f "${PREBUILT_SERVER_RPM}" ]]; then
    fail_helper "missing_server_rpm" "Missing prebuilt server package: ${PREBUILT_SERVER_RPM}" 1
  fi
  if [[ -n "${PREBUILT_CLIENT_RPM}" && ! -f "${PREBUILT_CLIENT_RPM}" ]]; then
    fail_helper "missing_client_rpm" "Missing prebuilt client package: ${PREBUILT_CLIENT_RPM}" 1
  fi
}

print_text_report() {
  local item=""
  echo "RPM package host validation prerequisites"
  echo "---------------------------------------"
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
    echo "Host prerequisites look ready for RPM package lifecycle validation."
    echo "Run: ${RUN_COMMAND}"
  else
    echo "Host prerequisites are incomplete."
    echo "Remediation: ${REMEDIATION_COMMAND}"
  fi
}

write_summary_json() {
  local output_path="$1"
  run_aegis_measure build-rpm-package-host-run-summary \
    --validation-root "${VALIDATION_ROOT}" >"${output_path}"
}

validate_host_family() {
  case "${HOST_FAMILY_ID}" in
    rhel-dnf|suse-zypper) ;;
    *)
      fail_helper "unsupported_host_family" "This helper currently targets RPM-family hosts with dnf/yum/zypper userspace." 2
      ;;
  esac
}

run_check_mode() {
  validate_prebuilt_split_rpms
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

  "${RPM_QUERY_BIN}" -q aegis-server >/dev/null 2>&1 ||
    fail_helper "rpm_server_not_installed" "Expected aegis-server rpm to be installed." 3
  "${RPM_QUERY_BIN}" -q aegis-client >/dev/null 2>&1 ||
    fail_helper "rpm_client_not_installed" "Expected aegis-client rpm to be installed." 3

  for expected_path in \
    "/usr/local/bin/aegis-server" \
    "/usr/local/bin/aegis-client" \
    "/usr/lib/systemd/system-preset/90-aegis-server.preset" \
    "/usr/lib/systemd/system-preset/90-aegis-client.preset" \
    "/usr/share/doc/aegis/README.server.Debian" \
    "/usr/share/doc/aegis/README.client.Debian"
  do
    [[ -f "${VALIDATION_ROOT%/}/${expected_path#/}" ]] ||
      fail_helper "rpm_expected_file_missing" "Expected installed path missing: ${expected_path}" 3
  done

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

verify_erase_state() {
  if "${RPM_QUERY_BIN}" -q aegis-server >/dev/null 2>&1; then
    fail_helper "rpm_server_still_installed" "Expected aegis-server rpm to be erased." 3
  fi
  if "${RPM_QUERY_BIN}" -q aegis-client >/dev/null 2>&1; then
    fail_helper "rpm_client_still_installed" "Expected aegis-client rpm to be erased." 3
  fi

  for removed_path in \
    "/usr/local/bin/aegis-server" \
    "/usr/local/bin/aegis-client" \
    "/etc/default/aegis-server" \
    "/etc/default/aegis-client" \
    "/usr/share/doc/aegis-server" \
    "/usr/share/doc/aegis-client"
  do
    [[ ! -e "${VALIDATION_ROOT%/}/${removed_path#/}" && ! -L "${VALIDATION_ROOT%/}/${removed_path#/}" ]] ||
      fail_helper "rpm_expected_file_still_present" "Expected erased path still present: ${removed_path}" 3
  done
}

run_lifecycle_validation() {
  local output_dir=""
  local server_rpm=""
  local client_rpm=""
  local summary_json=""

  validate_prebuilt_split_rpms
  gather_prerequisites
  validate_host_family
  if (( ${#MISSING_COMMANDS[@]} != 0 )); then
    fail_helper "missing_prerequisites" "Host prerequisites are incomplete; run --check first." 1
  fi

  if [[ -z "${ARTIFACT_DIR}" ]]; then
    ARTIFACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-rpm-host-validation.XXXXXX")"
  fi
  mkdir -p "${ARTIFACT_DIR}"

  output_dir="${ARTIFACT_DIR}/packages"
  summary_json="${ARTIFACT_DIR}/validation-summary.json"
  mkdir -p "${output_dir}"

  if using_prebuilt_split_rpms; then
    server_rpm="${PREBUILT_SERVER_RPM}"
    client_rpm="${PREBUILT_CLIENT_RPM}"
  else
    "${BUILD_SPLIT_RPMS_SCRIPT}" "${output_dir}" >/dev/null
    server_rpm="$(printf '%s\n' "${output_dir}"/aegis-server-*.rpm)"
    client_rpm="$(printf '%s\n' "${output_dir}"/aegis-client-*.rpm)"
  fi

  # Refuse an incomplete RPM pair before the first host mutation. Prebuilt
  # paths must select exactly the files bound by the same completed marker.
  local package_dir="$(dirname -- "${server_rpm}")"
  [[ "$(dirname -- "${client_rpm}")" == "${package_dir}" ]] ||
    fail_helper "rpm_pair_directory_mismatch" "RPM pair must share one package directory." 1
  local package_arch=""
  package_arch="$(python3 -I -B - "${package_dir}/rpm-packages.manifest.json" "${server_rpm}" "${client_rpm}" <<'PYINNER'
import json, pathlib, sys
marker = json.loads(pathlib.Path(sys.argv[1]).read_text())
pair = marker['packages']
if pathlib.Path(sys.argv[2]).name != pair['aegis-server']['rpm_file'] or pathlib.Path(sys.argv[3]).name != pair['aegis-client']['rpm_file']:
    raise SystemExit(1)
print(marker['arch'])
PYINNER
  )" || fail_helper "rpm_pair_marker_mismatch" "RPM paths do not match the completed marker." 1
  # Pair verification diagnostics must not precede the single --json report.
  python3 -I -B "${ROOT}/scripts/verify-rpm-package-set.py" "${package_dir}" --arch "${package_arch}" >&2 ||
    fail_helper "rpm_pair_incomplete" "RPM pair or sidecars failed verification." 1

  install_rpms_checked first "${server_rpm}" "${client_rpm}"
  verify_install_state "${summary_json}"
  verify_disabled_units

  run_rpm_mutation -e aegis-client aegis-server
  verify_erase_state

  install_rpms_checked reinstall "${server_rpm}" "${client_rpm}"
  verify_install_state "${summary_json}"
  verify_disabled_units

  install_rpms_checked reapply --replacepkgs "${server_rpm}" "${client_rpm}"
  verify_install_state "${summary_json}"

  run_rpm_mutation -e aegis-client aegis-server
  verify_erase_state

  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    READY=1
    HELPER_EXIT_CODE=0
    print_json_report
  else
    echo "RPM package host lifecycle validation completed."
    echo "Artifacts:"
    echo "  ${ARTIFACT_DIR}"
  fi
}

ensure_user_cargo_path

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
    --server-rpm)
      if [[ $# -lt 2 ]]; then
        fail_helper "missing_argument" "--server-rpm requires a value" 1
      fi
      PREBUILT_SERVER_RPM="$2"
      shift 2
      ;;
    --client-rpm)
      if [[ $# -lt 2 ]]; then
        fail_helper "missing_argument" "--client-rpm requires a value" 1
      fi
      PREBUILT_CLIENT_RPM="$2"
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
