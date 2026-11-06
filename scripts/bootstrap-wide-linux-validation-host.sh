#!/usr/bin/env bash
# Prepare a Linux host for richer-host TPROXY validation.
#
# Default mode is --check: print missing prerequisites and exit non-zero when
# the host is not ready yet.
# Use --install to install OS packages via the native package manager and
# rustup/cargo for the current user when needed.
set -euo pipefail

ROOT="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)"
MODE="check"
INSTALL_RUSTUP=1
PACKAGE_MANAGER=""
OS_PRETTY_NAME="unknown-linux"
OS_ID="unknown"
OS_VERSION_ID=""
HOST_FAMILY_ID="unknown-linux"
HOST_FAMILY_VALIDATION_TIER="manual_only"
JSON_OUTPUT=0
READY=0
MISSING_COMMANDS=()
COMMAND_STATUS_ARGS=()
SUDO_STATUS="unknown"
SUDO_DETAIL=""
REMEDIATION_COMMAND='bash scripts/bootstrap-wide-linux-validation-host.sh --install'
CHECK_COMMAND='bash scripts/bootstrap-wide-linux-validation-host.sh --check'
INSTALL_COMMAND='bash scripts/bootstrap-wide-linux-validation-host.sh --install'
VALIDATION_COMMAND='sudo env HOME="$HOME" PATH="$HOME/.cargo/bin:$PATH" bash scripts/validate-wide-linux-tproxy-rich-host.sh'
UPGRADE_REAPPLY_COMMAND='bash scripts/bootstrap-wide-linux-validation-host.sh --install && sudo env HOME="$HOME" PATH="$HOME/.cargo/bin:$PATH" bash scripts/validate-wide-linux-tproxy-rich-host.sh'
SUPPORTED_PRODUCT_CONTOUR='linux_first_local_binary_operator'
SUPPORTED_OPERATOR_SCOPE='supported_linux_tproxy_operator_path'
ERROR_CODE=""
HELPER_EXIT_CODE=""

run_aegis_measure() {
  if [[ -x "${AEGIS_MEASURE_BIN:-}" ]]; then
    "${AEGIS_MEASURE_BIN}" "$@"
  elif [[ -x "${ROOT}/target/debug/aegis-measure" ]] &&
    "${ROOT}/target/debug/aegis-measure" build-wide-linux-validation-host-bootstrap-report --help >/dev/null 2>&1
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
  scripts/bootstrap-wide-linux-validation-host.sh [--check|--install] [--skip-rustup] [--json]

Modes:
  --check       Validate host prerequisites and exit non-zero if anything is missing.
  --install     Install missing OS packages and rustup/cargo for the current user.
  --skip-rustup Do not install rustup/cargo automatically in --install mode.
  --json        Emit machine-readable JSON instead of the text table.

This helper targets richer-host validation prerequisites for:
  scripts/validate-wide-linux-tproxy-rich-host.sh
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
  for candidate in apt-get dnf yum zypper; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      PACKAGE_MANAGER="${candidate}"
      return 0
    fi
  done
  return 1
}

classify_host_family() {
  case "${OS_ID}" in
    ubuntu)
      HOST_FAMILY_ID="ubuntu-apt"
      HOST_FAMILY_VALIDATION_TIER="validated_baseline"
      ;;
    debian|linuxmint|pop|neon|elementary)
      HOST_FAMILY_ID="debian-apt"
      HOST_FAMILY_VALIDATION_TIER="next_non_ubuntu_target"
      ;;
    rhel|rocky|almalinux|centos|fedora)
      HOST_FAMILY_ID="rhel-dnf"
      HOST_FAMILY_VALIDATION_TIER="planned_family"
      ;;
    opensuse*|sles)
      HOST_FAMILY_ID="suse-zypper"
      HOST_FAMILY_VALIDATION_TIER="planned_family"
      ;;
    *)
      case "${PACKAGE_MANAGER}" in
        apt-get)
          HOST_FAMILY_ID="debian-apt"
          HOST_FAMILY_VALIDATION_TIER="next_non_ubuntu_target"
          ;;
        dnf|yum)
          HOST_FAMILY_ID="rhel-dnf"
          HOST_FAMILY_VALIDATION_TIER="planned_family"
          ;;
        zypper)
          HOST_FAMILY_ID="suse-zypper"
          HOST_FAMILY_VALIDATION_TIER="planned_family"
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
  local install_rustup_value="false"
  local ready_value="false"
  local missing=""
  local args=()

  if [[ "${INSTALL_RUSTUP}" -eq 1 ]]; then
    install_rustup_value="true"
  fi
  if [[ "${READY}" -eq 1 ]]; then
    ready_value="true"
  fi

  args+=(
    build-wide-linux-validation-host-bootstrap-report
    --mode "${MODE}"
    --os-pretty-name "${OS_PRETTY_NAME}"
    --os-id "${OS_ID}"
    --supported-product-contour "${SUPPORTED_PRODUCT_CONTOUR}"
    --supported-operator-scope "${SUPPORTED_OPERATOR_SCOPE}"
    --host-family-id "${HOST_FAMILY_ID}"
    --host-family-validation-tier "${HOST_FAMILY_VALIDATION_TIER}"
    --install-rustup "${install_rustup_value}"
    --ready "${ready_value}"
    --sudo-status "${SUDO_STATUS}"
    --sudo-detail "${SUDO_DETAIL}"
    --remediation-command "${REMEDIATION_COMMAND}"
    --bootstrap-check-command "${CHECK_COMMAND}"
    --bootstrap-install-command "${INSTALL_COMMAND}"
    --validation-command "${VALIDATION_COMMAND}"
    --upgrade-reapply-command "${UPGRADE_REAPPLY_COMMAND}"
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
    if [[ "${SUDO_STATUS}" == "unknown" ]]; then
      SUDO_STATUS="unknown"
      SUDO_DETAIL="${detail}"
    fi
    print_json_report
  else
    echo "${detail}" >&2
  fi
  exit "${exit_code}"
}

# Keep parser-level failures machine-readable even when `--json` is passed
# after another argument (for example `--bogus --json`).
for arg in "$@"; do
  if [[ "${arg}" == "--json" ]]; then
    JSON_OUTPUT=1
    break
  fi
done

for arg in "$@"; do
  case "${arg}" in
    --check)
      MODE="check"
      ;;
    --install)
      MODE="install"
      ;;
    --skip-rustup)
      INSTALL_RUSTUP=0
      ;;
    --json)
      JSON_OUTPUT=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
        fail_helper "unknown_argument" "Unknown argument: ${arg}"
      fi
      echo "Unknown argument: ${arg}" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_sudo() {
  # Contracts run both as an ordinary CI user and from root-operated RT hosts.
  # The test override can only make the check stricter (pretend non-root); it
  # can never make a non-root production invocation bypass sudo.
  [[ "${EUID}" -ne 0 || "${AEGIS_BOOTSTRAP_TEST_FORCE_NONROOT:-0}" == "1" ]]
}

run_as_root() {
  if need_sudo; then
    if ! command -v sudo >/dev/null 2>&1; then
      SUDO_STATUS="missing"
      SUDO_DETAIL="required to install OS packages"
      fail_helper "sudo_missing_for_install" "sudo is required to install OS packages on ${OS_PRETTY_NAME}"
    fi
    sudo "$@"
  else
    "$@"
  fi
}

run_checked_command() {
  local error_code="$1"
  local detail="$2"
  shift 2

  local status=0
  set +e
  "$@"
  status=$?
  set -e
  if [[ "${status}" -ne 0 ]]; then
    fail_helper "${error_code}" "${detail}" "${status}"
  fi
}

apt_packages=(
  build-essential
  pkg-config
  libssl-dev
  libcap2-bin
  iproute2
  iptables
  nftables
  ca-certificates
  curl
  openssl
)

dnf_packages=(
  gcc
  gcc-c++
  make
  pkgconf-pkg-config
  openssl-devel
  libcap
  iproute
  iptables
  nftables
  ca-certificates
  curl
  openssl
)

zypper_packages=(
  gcc
  gcc-c++
  make
  pkg-config
  libopenssl-devel
  libcap-progs
  iproute2
  iptables
  nftables
  ca-certificates
  curl
  openssl
)

install_os_packages() {
  detect_package_manager || {
    fail_helper "unsupported_package_manager" "Unsupported Linux package manager on ${OS_PRETTY_NAME}. Install prerequisites manually."
  }

  if [[ "${JSON_OUTPUT}" -ne 1 ]]; then
    echo "Detected package manager: ${PACKAGE_MANAGER}"
  fi
  case "${PACKAGE_MANAGER}" in
    apt-get)
      run_checked_command "os_package_update_failed" "Failed to update OS package metadata via apt-get." \
        run_as_root apt-get update
      run_checked_command "os_package_install_failed" "Failed to install richer-host OS prerequisites via apt-get." \
        run_as_root apt-get install -y --no-install-recommends "${apt_packages[@]}"
      ;;
    dnf)
      run_checked_command "os_package_install_failed" "Failed to install richer-host OS prerequisites via dnf." \
        run_as_root dnf install -y "${dnf_packages[@]}"
      ;;
    yum)
      run_checked_command "os_package_install_failed" "Failed to install richer-host OS prerequisites via yum." \
        run_as_root yum install -y "${dnf_packages[@]}"
      ;;
    zypper)
      run_checked_command "os_package_install_failed" "Failed to install richer-host OS prerequisites via zypper." \
        run_as_root zypper --non-interactive install "${zypper_packages[@]}"
      ;;
  esac
}

install_rustup_for_user() {
  local rustup_sh=""

  ensure_user_cargo_path
  if command -v cargo >/dev/null 2>&1; then
    return 0
  fi

  if [[ "${INSTALL_RUSTUP}" -ne 1 ]]; then
    fail_helper "cargo_missing_skip_rustup" "cargo is missing; rerun without --skip-rustup or install rustup manually."
  fi

  if ! command -v curl >/dev/null 2>&1; then
    fail_helper "curl_missing_for_rustup" "curl is required to install rustup."
  fi

  if [[ "${JSON_OUTPUT}" -ne 1 ]]; then
    echo "Installing rustup/cargo for user ${USER}..."
  fi
  rustup_sh="$(mktemp "${TMPDIR:-/tmp}/rustup-init.XXXXXX.sh")"
  trap 'rm -f "${rustup_sh}"' EXIT
  run_checked_command "rustup_download_failed" "Failed to download rustup installer." \
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "${rustup_sh}"
  run_checked_command "rustup_install_failed" "Failed to install rustup/cargo." \
    sh "${rustup_sh}" -y --profile minimal
  export PATH="${HOME}/.cargo/bin:${PATH}"
}

print_status_line() {
  local name="$1"
  local status="$2"
  local detail="$3"
  printf '%-18s %-10s %s\n' "${name}" "${status}" "${detail}"
}

record_command_status() {
  local name="$1"
  local status="$2"
  local detail="$3"

  COMMAND_STATUS_ARGS+=(--command "${name}"$'\t'"${status}"$'\t'"${detail}")
  if [[ "${JSON_OUTPUT}" -ne 1 ]]; then
    print_status_line "${name}" "${status}" "${detail}"
  fi
}

check_prerequisites() {
  local missing=0
  local item=""
  local required_commands=(ip iptables ip6tables nft openssl cargo)

  ensure_user_cargo_path
  COMMAND_STATUS_ARGS=()
  MISSING_COMMANDS=()

  if [[ "${JSON_OUTPUT}" -ne 1 ]]; then
    echo "Host: ${OS_PRETTY_NAME}"
    echo "Mode: ${MODE}"
    echo
    print_status_line "command" "status" "detail"
    print_status_line "-------" "------" "------"
  fi

  for item in "${required_commands[@]}"; do
    if command -v "${item}" >/dev/null 2>&1; then
      record_command_status "${item}" "ok" "$(command -v "${item}")"
    else
      record_command_status "${item}" "missing" "required for richer-host validation"
      MISSING_COMMANDS+=("${item}")
      missing=1
    fi
  done

  if need_sudo; then
    if command -v sudo >/dev/null 2>&1; then
      if sudo -n true >/dev/null 2>&1; then
        SUDO_STATUS="ok"
        SUDO_DETAIL="passwordless sudo available"
        record_command_status "sudo -n" "${SUDO_STATUS}" "${SUDO_DETAIL}"
      else
        SUDO_STATUS="warn"
        SUDO_DETAIL="interactive sudo required; validation can still run from a root shell"
        record_command_status "sudo -n" "${SUDO_STATUS}" "${SUDO_DETAIL}"
      fi
    else
      SUDO_STATUS="missing"
      SUDO_DETAIL="required unless validation runs as root"
      record_command_status "sudo" "${SUDO_STATUS}" "${SUDO_DETAIL}"
      MISSING_COMMANDS+=("sudo")
      missing=1
    fi
  else
    SUDO_STATUS="ok"
    SUDO_DETAIL="running as root"
    record_command_status "sudo/root" "${SUDO_STATUS}" "${SUDO_DETAIL}"
  fi

  if [[ "${missing}" -ne 0 ]]; then
    READY=0
    HELPER_EXIT_CODE=1
    if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
      print_json_report
    else
      echo
      echo "Host prerequisites are incomplete."
      echo "Remediation:"
      echo "  ${REMEDIATION_COMMAND}"
    fi
    return 1
  fi

  READY=1
  HELPER_EXIT_CODE=0
  if [[ "${JSON_OUTPUT}" -eq 1 ]]; then
    print_json_report
  else
    echo
    echo "Host prerequisites look ready for richer-host validation."
  fi
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail_helper "unsupported_platform" "This helper only supports Linux hosts."
fi

detect_package_manager >/dev/null 2>&1 || true
classify_host_family

if [[ "${MODE}" == "install" ]]; then
  install_os_packages
  install_rustup_for_user
fi

check_prerequisites
