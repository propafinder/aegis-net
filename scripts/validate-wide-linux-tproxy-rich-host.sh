#!/usr/bin/env bash
# Best-effort richer-host validation lane for Linux TPROXY rollout.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
. "${ROOT}/scripts/lib/guarded-smoke-status.sh"

ARTIFACT_DIR="${AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR:-${AEGIS_EVIDENCE_DIR:-${HOME}/aegis-evidence}/wide-linux-tproxy-validation}"
STATUS_DIR="$(guarded_smoke_status_dir)"
MATRIX_TARGETS_JSON="${ARTIFACT_DIR}/matrix.targets.json"
MATRIX_RESULTS_JSON="${ARTIFACT_DIR}/matrix.results.json"
MATRIX_SUMMARY_MD="${ARTIFACT_DIR}/matrix-summary.md"
HOST_METADATA_JSON="${ARTIFACT_DIR}/host.metadata.json"
HOST_BOOTSTRAP_JSON="${ARTIFACT_DIR}/host.bootstrap.json"
VALIDATION_BUNDLE_JSON="${ARTIFACT_DIR}/bundle.manifest.json"
RERUN_ENV_SCRIPT="${ARTIFACT_DIR}/rerun-rich-host.env"
RERUN_SHELL_SCRIPT="${ARTIFACT_DIR}/rerun-rich-host-validation.sh"
SMOKE_STUB_SCRIPT="${AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT:-}"
BOOTSTRAP_HELPER_SCRIPT="${AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT:-${ROOT}/scripts/bootstrap-wide-linux-validation-host.sh}"
BOOTSTRAP_HELPER_FORCED=0
if [[ -n "${AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT:-}" ]]; then
  BOOTSTRAP_HELPER_FORCED=1
fi
JANITOR_SCRIPT="${AEGIS_WIDE_RICH_HOST_JANITOR_SCRIPT:-${ROOT}/scripts/janitor-wide-linux-tproxy.sh}"
RICH_HOST_CARGO_TARGET_DIR="${AEGIS_WIDE_RICH_HOST_CARGO_TARGET_DIR:-${ROOT}/target/wide-linux-tproxy-rich-host}"
RICH_HOST_STARTUP_WAIT_SECS="${AEGIS_WIDE_STARTUP_WAIT_SECS:-20}"
RICH_HOST_REQUEST_TIMEOUT_SECS="${AEGIS_WIDE_REQUEST_TIMEOUT_SECS:-25}"
RICH_HOST_CASE_TIMEOUT_SECS="${AEGIS_WIDE_CASE_TIMEOUT_SECS:-90}"
MATRIX_FAILED=0

if [[ -d "${HOME}/.cargo/bin" ]]; then
  case ":${PATH}:" in
    *":${HOME}/.cargo/bin:"*) ;;
    *) export PATH="${HOME}/.cargo/bin:${PATH}" ;;
  esac
fi

mkdir -p "${ARTIFACT_DIR}" "${STATUS_DIR}"
rm -f "${STATUS_DIR}"/*.txt 2>/dev/null || true

normalize_artifact_permissions() {
  local path=""
  [[ -d "${ARTIFACT_DIR}" ]] || return 0

  # Rich-host runs execute under sudo/root, but the resulting evidence bundle
  # should remain easy to inspect, archive, and commit from the invoking user.
  chmod 755 "${ARTIFACT_DIR}" 2>/dev/null || true
  while IFS= read -r path; do
    [[ -e "${path}" ]] || continue
    if [[ -d "${path}" ]]; then
      chmod 755 "${path}" 2>/dev/null || true
    else
      chmod 644 "${path}" 2>/dev/null || true
    fi
  done < <(find "${ARTIFACT_DIR}" -mindepth 1 -print 2>/dev/null || true)
  if [[ -f "${RERUN_SHELL_SCRIPT}" ]]; then
    chmod 755 "${RERUN_SHELL_SCRIPT}" 2>/dev/null || true
  fi
  if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" "${ARTIFACT_DIR}" 2>/dev/null || true
  fi
}

require_host_prerequisites() {
  if [[ -n "${SMOKE_STUB_SCRIPT}" && "${BOOTSTRAP_HELPER_FORCED}" -ne 1 ]]; then
    return 0
  fi

  local bootstrap_status=0
  set +e
  bash "${BOOTSTRAP_HELPER_SCRIPT}" --check --json > "${HOST_BOOTSTRAP_JSON}"
  bootstrap_status=$?
  set -e

  if ! cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- validate-rich-host-bootstrap --artifact "${HOST_BOOTSTRAP_JSON}" --bootstrap-status "${bootstrap_status}" >&2; then
    normalize_artifact_permissions
    exit 1
  fi
}

override_probe_result() {
  local value="${1:-}"
  if [[ -n "${value}" ]]; then
    return "${value}"
  fi
  return 255
}

smoke_class_for_protocol() {
  case "$1" in
    dns|dns_ipv6)
      echo "dns_preview"
      ;;
    generic_udp)
      echo "generic_udp"
      ;;
    *)
      echo "custom"
      ;;
  esac
}

support_tier_for_protocol() {
  case "$1" in
    generic_udp)
      echo "guarded_unstable"
      ;;
    *)
      echo "supported_preview"
      ;;
  esac
}

write_matrix_targets() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- write-rich-host-matrix-targets --output "${MATRIX_TARGETS_JSON}"
}

write_matrix_results() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- build-rich-host-matrix-summary \
    --status-dir "${STATUS_DIR}" \
    --artifact-dir "${ARTIFACT_DIR}" \
    --matrix-targets "${MATRIX_TARGETS_JSON}" \
    --matrix-results "${MATRIX_RESULTS_JSON}" \
    --matrix-summary "${MATRIX_SUMMARY_MD}" \
    --host-metadata "${HOST_METADATA_JSON}" \
    --host-bootstrap "${HOST_BOOTSTRAP_JSON}"
}

write_host_metadata() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- build-rich-host-metadata \
    --output "${HOST_METADATA_JSON}" \
    --host-bootstrap "${HOST_BOOTSTRAP_JSON}"
}

write_rerun_bundle() {
  local default_artifact_prefix="${ARTIFACT_DIR%/}"
  local bootstrap_helper_override=""
  local janitor_override=""
  local smoke_stub_override=""
  local generic_udp_port_override=""
  local forced_xtables_result=""
  local forced_nft_result=""
  local forced_ip6tables_result=""
  local forced_nft_ipv6_result=""
  local current_home="${HOME}"
  local current_path="${PATH}"

  if [[ -n "${AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT:-}" ]]; then
    bootstrap_helper_override="${AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT}"
  fi
  if [[ -n "${AEGIS_WIDE_RICH_HOST_JANITOR_SCRIPT:-}" ]]; then
    janitor_override="${AEGIS_WIDE_RICH_HOST_JANITOR_SCRIPT}"
  fi
  if [[ -n "${AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT:-}" ]]; then
    smoke_stub_override="${AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT}"
  fi
  if [[ -n "${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-}" ]]; then
    generic_udp_port_override="${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT}"
  fi
  if [[ -n "${AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT:-}" ]]; then
    forced_xtables_result="${AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT}"
  fi
  if [[ -n "${AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT:-}" ]]; then
    forced_nft_result="${AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT}"
  fi
  if [[ -n "${AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT:-}" ]]; then
    forced_ip6tables_result="${AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT}"
  fi
  if [[ -n "${AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT:-}" ]]; then
    forced_nft_ipv6_result="${AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT}"
  fi

  cat > "${RERUN_ENV_SCRIPT}" <<EOF
#!/usr/bin/env bash
export AEGIS_WIDE_RICH_HOST_CARGO_TARGET_DIR=$(printf '%q' "${RICH_HOST_CARGO_TARGET_DIR}")
export AEGIS_WIDE_STARTUP_WAIT_SECS=$(printf '%q' "${RICH_HOST_STARTUP_WAIT_SECS}")
export AEGIS_WIDE_REQUEST_TIMEOUT_SECS=$(printf '%q' "${RICH_HOST_REQUEST_TIMEOUT_SECS}")
export AEGIS_WIDE_CASE_TIMEOUT_SECS=$(printf '%q' "${RICH_HOST_CASE_TIMEOUT_SECS}")
EOF
  if [[ -n "${bootstrap_helper_override}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT=%q\n' "${bootstrap_helper_override}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${janitor_override}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_JANITOR_SCRIPT=%q\n' "${janitor_override}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${smoke_stub_override}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT=%q\n' "${smoke_stub_override}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${generic_udp_port_override}" ]]; then
    printf 'export AEGIS_WIDE_GENERIC_UDP_TARGET_PORT=%q\n' "${generic_udp_port_override}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${forced_xtables_result}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT=%q\n' "${forced_xtables_result}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${forced_nft_result}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT=%q\n' "${forced_nft_result}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${forced_ip6tables_result}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT=%q\n' "${forced_ip6tables_result}" >> "${RERUN_ENV_SCRIPT}"
  fi
  if [[ -n "${forced_nft_ipv6_result}" ]]; then
    printf 'export AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT=%q\n' "${forced_nft_ipv6_result}" >> "${RERUN_ENV_SCRIPT}"
  fi

  cat > "${RERUN_SHELL_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

ROOT=$(printf '%q' "${ROOT}")
DEFAULT_BOOTSTRAP_HELPER_SCRIPT=$(printf '%q' "${BOOTSTRAP_HELPER_SCRIPT}")
DEFAULT_ARTIFACT_PREFIX=$(printf '%q' "${default_artifact_prefix}")

export HOME=$(printf '%q' "${current_home}")
export PATH=$(printf '%q' "${current_path}")

source $(printf '%q' "${RERUN_ENV_SCRIPT}")

timestamp="\$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="\${1:-\${AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR:-\${DEFAULT_ARTIFACT_PREFIX}-rerun-\${timestamp}}}"
export AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR="\${artifact_dir}"

echo "Bootstrap helper check..."
bash "\${AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT:-\${DEFAULT_BOOTSTRAP_HELPER_SCRIPT}}" --check
echo "Running richer-host validation into \${AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR}..."
sudo env \\
  HOME="\${HOME}" \\
  PATH="\${PATH}" \\
  AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR="\${AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR}" \\
  AEGIS_WIDE_RICH_HOST_CARGO_TARGET_DIR="\${AEGIS_WIDE_RICH_HOST_CARGO_TARGET_DIR}" \\
  AEGIS_WIDE_STARTUP_WAIT_SECS="\${AEGIS_WIDE_STARTUP_WAIT_SECS}" \\
  AEGIS_WIDE_REQUEST_TIMEOUT_SECS="\${AEGIS_WIDE_REQUEST_TIMEOUT_SECS}" \\
  AEGIS_WIDE_CASE_TIMEOUT_SECS="\${AEGIS_WIDE_CASE_TIMEOUT_SECS}" \\
  AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT="\${AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT:-}" \\
  AEGIS_WIDE_RICH_HOST_JANITOR_SCRIPT="\${AEGIS_WIDE_RICH_HOST_JANITOR_SCRIPT:-}" \\
  AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT="\${AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT:-}" \\
  AEGIS_WIDE_GENERIC_UDP_TARGET_PORT="\${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-}" \\
  AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT="\${AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT:-}" \\
  AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT="\${AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT:-}" \\
  AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT="\${AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT:-}" \\
  AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT="\${AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT:-}" \\
  bash $(printf '%q' "${ROOT}/scripts/validate-wide-linux-tproxy-rich-host.sh")
EOF
  chmod 755 "${RERUN_SHELL_SCRIPT}" 2>/dev/null || true
}

write_bundle_manifest() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- build-rich-host-validation-bundle \
    --output "${VALIDATION_BUNDLE_JSON}" \
    --artifact-dir "${ARTIFACT_DIR}" \
    --matrix-targets "${MATRIX_TARGETS_JSON}" \
    --matrix-results "${MATRIX_RESULTS_JSON}" \
    --matrix-summary "${MATRIX_SUMMARY_MD}" \
    --host-metadata "${HOST_METADATA_JSON}" \
    --host-bootstrap "${HOST_BOOTSTRAP_JSON}" \
    --rerun-env "${RERUN_ENV_SCRIPT}" \
    --rerun-script "${RERUN_SHELL_SCRIPT}" \
    --bootstrap-helper "${BOOTSTRAP_HELPER_SCRIPT}" \
    --validation-script "${ROOT}/scripts/validate-wide-linux-tproxy-rich-host.sh" \
    --cargo-target-dir "${RICH_HOST_CARGO_TARGET_DIR}" \
    --startup-wait-secs "${RICH_HOST_STARTUP_WAIT_SECS}" \
    --request-timeout-secs "${RICH_HOST_REQUEST_TIMEOUT_SECS}" \
    --case-timeout-secs "${RICH_HOST_CASE_TIMEOUT_SECS}"
}

probe_xtables_tproxy() {
  if override_probe_result "${AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT:-}"; then
    return 0
  elif [[ "$?" -ne 255 ]]; then
    return 1
  fi
  sudo iptables -t mangle -N AEGIS_TPROXY_PROBE 2>/dev/null || true
  if ! sudo iptables -t mangle -A AEGIS_TPROXY_PROBE \
    -p udp -j TPROXY --on-port 1 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1 2>/dev/null
  then
    sudo iptables -t mangle -F AEGIS_TPROXY_PROBE 2>/dev/null || true
    sudo iptables -t mangle -X AEGIS_TPROXY_PROBE 2>/dev/null || true
    return 1
  fi
  sudo iptables -t mangle -F AEGIS_TPROXY_PROBE 2>/dev/null || true
  sudo iptables -t mangle -X AEGIS_TPROXY_PROBE 2>/dev/null || true
}

probe_nft_tproxy() {
  if override_probe_result "${AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT:-}"; then
    return 0
  elif [[ "$?" -ne 255 ]]; then
    return 1
  fi
  sudo nft delete table ip aegis_tproxy_probe 2>/dev/null || true
  sudo nft add table ip aegis_tproxy_probe
  sudo nft add chain ip aegis_tproxy_probe prerouting "{ type filter hook prerouting priority mangle; policy accept; }"
  if ! sudo nft add rule ip aegis_tproxy_probe prerouting \
    meta l4proto udp tproxy to :1 meta mark set 1 accept 2>/dev/null
  then
    sudo nft delete table ip aegis_tproxy_probe 2>/dev/null || true
    return 1
  fi
  sudo nft delete table ip aegis_tproxy_probe 2>/dev/null || true
}

probe_ipv6_nft_tproxy() {
  if override_probe_result "${AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT:-}"; then
    return 0
  elif [[ "$?" -ne 255 ]]; then
    return 1
  fi
  sudo nft delete table ip6 aegis_tproxy6_probe 2>/dev/null || true
  sudo nft add table ip6 aegis_tproxy6_probe
  sudo nft add chain ip6 aegis_tproxy6_probe prerouting "{ type filter hook prerouting priority mangle; policy accept; }"
  if ! sudo nft add rule ip6 aegis_tproxy6_probe prerouting \
    meta l4proto udp tproxy to :1 meta mark set 1 accept 2>/dev/null
  then
    sudo nft delete table ip6 aegis_tproxy6_probe 2>/dev/null || true
    return 1
  fi
  sudo nft delete table ip6 aegis_tproxy6_probe 2>/dev/null || true
}

probe_ipv6_loopback() {
  if override_probe_result "${AEGIS_WIDE_RICH_HOST_FORCE_IPV6_LOOPBACK_RESULT:-}"; then
    return 0
  elif [[ "$?" -ne 255 ]]; then
    return 1
  fi
  # Keep the host probe dependency-free: richer-host validation can run on
  # fresh Linux boxes that do not have ripgrep installed yet.
  local loopback_addrs=""
  loopback_addrs="$(ip -6 addr show lo 2>/dev/null || true)"
  [[ "${loopback_addrs}" == *"inet6 ::1/128"* ]]
}

probe_ip6tables_tproxy() {
  if override_probe_result "${AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT:-}"; then
    return 0
  elif [[ "$?" -ne 255 ]]; then
    return 1
  fi
  sudo ip6tables -t mangle -N AEGIS_TPROXY6_PROBE 2>/dev/null || true
  if ! sudo ip6tables -t mangle -A AEGIS_TPROXY6_PROBE \
    -p udp -j TPROXY --on-port 1 --on-ip :: --tproxy-mark 0x1/0x1 2>/dev/null
  then
    sudo ip6tables -t mangle -F AEGIS_TPROXY6_PROBE 2>/dev/null || true
    sudo ip6tables -t mangle -X AEGIS_TPROXY6_PROBE 2>/dev/null || true
    return 1
  fi
  sudo ip6tables -t mangle -F AEGIS_TPROXY6_PROBE 2>/dev/null || true
  sudo ip6tables -t mangle -X AEGIS_TPROXY6_PROBE 2>/dev/null || true
}

probe_ipv6_ip6tables_tproxy() {
  probe_ipv6_loopback && probe_ip6tables_tproxy
}

probe_ipv6_nft_stack_tproxy() {
  probe_ipv6_loopback && probe_ipv6_nft_tproxy
}

prepare_runtime_binaries() {
  if [[ -n "${SMOKE_STUB_SCRIPT}" ]]; then
    return 0
  fi
  # Build once into a shared target dir so first-run matrix cases validate runtime
  # behavior instead of timing out while cargo compiles each smoke shape.
  sudo --preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME \
    env \
      CARGO_TARGET_DIR="${RICH_HOST_CARGO_TARGET_DIR}" \
      cargo build --manifest-path "${ROOT}/Cargo.toml" --release -p aegis-client
  sudo --preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME \
    env \
      CARGO_TARGET_DIR="${RICH_HOST_CARGO_TARGET_DIR}" \
      cargo build --manifest-path "${ROOT}/Cargo.toml" -p aegis-server
}

reserve_tcp_port() {
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- reserve-tcp-port
}

run_with_case_timeout() {
  local timeout_secs="$1"
  shift
  cargo run -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure -- run-with-timeout \
    --timeout-secs "${timeout_secs}" \
    -- "$@"
}

run_host_janitor() {
  if [[ -n "${SMOKE_STUB_SCRIPT}" || ! -f "${JANITOR_SCRIPT}" ]]; then
    return 0
  fi
  # Run the janitor outside the case timeout so a stale host never poisons the
  # next richer-host run with leftover processes, netns, or helper state.
  if [[ "${EUID}" -eq 0 ]]; then
    bash "${JANITOR_SCRIPT}" >/dev/null 2>&1 || true
  elif sudo -n true >/dev/null 2>&1; then
    sudo --preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME \
      bash "${JANITOR_SCRIPT}" >/dev/null 2>&1 || true
  fi
}

run_smoke_case() {
  local case_id="$1"
  local protocol="$2"
  local backend="$3"
  local ip_family="$4"
  shift 4

  local runtime_artifact="${ARTIFACT_DIR}/${case_id}.runtime.jsonl"
  local contract_artifact="${ARTIFACT_DIR}/${case_id}.contract.json"
  local cargo_target_dir="${RICH_HOST_CARGO_TARGET_DIR}"
  local smoke_script="${ROOT}/scripts/smoke-wide-linux-tproxy.sh"
  local wide_port="${AEGIS_WIDE_PORT:-$(reserve_tcp_port)}"
  local socks_port="${AEGIS_SOCKS_PORT:-$(reserve_tcp_port)}"
  local relay_port="${AEGIS_RELAY_PORT:-$(reserve_tcp_port)}"

  if [[ -n "${SMOKE_STUB_SCRIPT}" ]]; then
    smoke_script="${SMOKE_STUB_SCRIPT}"
  fi

  run_host_janitor
  guarded_smoke_status_init "${case_id}"
  local status=0
  if [[ -n "${SMOKE_STUB_SCRIPT}" ]]; then
    set +e
    run_with_case_timeout "${RICH_HOST_CASE_TIMEOUT_SECS}" \
      env \
      CARGO_TARGET_DIR="${cargo_target_dir}" \
      AEGIS_WIDE_SMOKE_PROTOCOL="${protocol}" \
      AEGIS_WIDE_FIREWALL_BACKEND="${backend}" \
      AEGIS_WIDE_SMOKE_IP_FAMILY="${ip_family}" \
      AEGIS_WIDE_SMOKE_HOST_SHAPE=rich_linux_host \
      AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT="${runtime_artifact}" \
      AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT="${contract_artifact}" \
      AEGIS_WIDE_PORT="${wide_port}" \
      AEGIS_SOCKS_PORT="${socks_port}" \
      AEGIS_RELAY_PORT="${relay_port}" \
      AEGIS_WIDE_STARTUP_WAIT_SECS="${RICH_HOST_STARTUP_WAIT_SECS}" \
      AEGIS_WIDE_REQUEST_TIMEOUT_SECS="${RICH_HOST_REQUEST_TIMEOUT_SECS}" \
      "$@" \
      "${smoke_script}"
    status=$?
    set -e
  else
    set +e
    # Case-level timeout keeps one pathological host path from pinning the entire
    # richer-host matrix while still letting the smoke script run its own cleanup.
    run_with_case_timeout "${RICH_HOST_CASE_TIMEOUT_SECS}" \
      sudo --preserve-env=PATH,HOME,CARGO_HOME,RUSTUP_HOME \
        env \
          CARGO_TARGET_DIR="${cargo_target_dir}" \
          AEGIS_WIDE_SMOKE_PROTOCOL="${protocol}" \
          AEGIS_WIDE_FIREWALL_BACKEND="${backend}" \
          AEGIS_WIDE_SMOKE_IP_FAMILY="${ip_family}" \
          AEGIS_WIDE_SMOKE_HOST_SHAPE=rich_linux_host \
          AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT="${runtime_artifact}" \
          AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT="${contract_artifact}" \
          AEGIS_WIDE_PORT="${wide_port}" \
          AEGIS_SOCKS_PORT="${socks_port}" \
          AEGIS_RELAY_PORT="${relay_port}" \
          AEGIS_WIDE_STARTUP_WAIT_SECS="${RICH_HOST_STARTUP_WAIT_SECS}" \
          AEGIS_WIDE_REQUEST_TIMEOUT_SECS="${RICH_HOST_REQUEST_TIMEOUT_SECS}" \
          "$@" \
          bash "${smoke_script}"
    status=$?
    set -e
  fi
  run_host_janitor
  if [[ "${status}" -ne 0 ]]; then
    MATRIX_FAILED=1
    guarded_smoke_status_write "failed:${status}"
    return 0
  fi
  guarded_smoke_status_write "passed"
}

run_or_skip() {
  local case_id="$1"
  local skip_reason="$2"
  shift 2

  guarded_smoke_status_init "${case_id}"
  if "$@"; then
    return 0
  fi
  guarded_smoke_status_write "skipped: ${skip_reason}"
  return 1
}

run_documented_case() {
  local case_id="$1"
  local protocol="$2"
  local backend="$3"
  local ip_family="$4"
  local skip_reason="$5"
  local probe_fn="$6"
  shift 6

  if run_or_skip "${case_id}" "${skip_reason}" "${probe_fn}"; then
    run_smoke_case "${case_id}" "${protocol}" "${backend}" "${ip_family}" "$@"
  fi
}

write_matrix_targets
require_host_prerequisites
write_host_metadata

echo "Running richer-host Linux TPROXY validation matrix..."
echo "Documented target matrix: ${MATRIX_TARGETS_JSON}"
echo "Shared cargo target dir: ${RICH_HOST_CARGO_TARGET_DIR}"
echo "Startup wait seconds per smoke: ${RICH_HOST_STARTUP_WAIT_SECS}"
echo "Request timeout seconds per smoke: ${RICH_HOST_REQUEST_TIMEOUT_SECS}"
echo "Case timeout seconds: ${RICH_HOST_CASE_TIMEOUT_SECS}"

prepare_runtime_binaries

run_documented_case dns-xtables dns xtables ipv4 \
  "xt_TPROXY support is unavailable on this host" \
  probe_xtables_tproxy

run_documented_case dns-nft dns nft ipv4 \
  "nft TPROXY support is unavailable on this host" \
  probe_nft_tproxy

run_documented_case generic-udp-xtables generic_udp xtables ipv4 \
  "xt_TPROXY support is unavailable on this host" \
  probe_xtables_tproxy \
  AEGIS_WIDE_GENERIC_UDP_TARGET_PORT="${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-54321}"

run_documented_case generic-udp-nft generic_udp nft ipv4 \
  "nft TPROXY support is unavailable on this host" \
  probe_nft_tproxy \
  AEGIS_WIDE_GENERIC_UDP_TARGET_PORT="${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-54321}"

run_documented_case dns-ipv6 dns_ipv6 xtables ipv6 \
  "IPv6 loopback or ip6tables TPROXY support is unavailable on this host" \
  probe_ipv6_ip6tables_tproxy

run_documented_case dns-ipv6-nft dns_ipv6 nft ipv6 \
  "IPv6 loopback or nft ip6 TPROXY support is unavailable on this host" \
  probe_ipv6_nft_stack_tproxy

run_documented_case generic-udp-ipv6 generic_udp xtables ipv6 \
  "IPv6 loopback or ip6tables TPROXY support is unavailable on this host" \
  probe_ipv6_ip6tables_tproxy \
  AEGIS_WIDE_GENERIC_UDP_TARGET_PORT="${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-54321}"

run_documented_case generic-udp-ipv6-nft generic_udp nft ipv6 \
  "IPv6 loopback or nft ip6 TPROXY support is unavailable on this host" \
  probe_ipv6_nft_stack_tproxy \
  AEGIS_WIDE_GENERIC_UDP_TARGET_PORT="${AEGIS_WIDE_GENERIC_UDP_TARGET_PORT:-54321}"

write_matrix_results
write_rerun_bundle
write_bundle_manifest
normalize_artifact_permissions

echo
echo "Richer-host validation summary:"
for file in "${STATUS_DIR}"/*.txt; do
  [[ -e "${file}" ]] || continue
  printf '  %s: %s\n' "$(basename "${file}" .txt)" "$(<"${file}")"
done
echo "Documented targets: ${MATRIX_TARGETS_JSON}"
echo "Matrix results: ${MATRIX_RESULTS_JSON}"
echo "Matrix summary: ${MATRIX_SUMMARY_MD}"
echo "Bundle manifest: ${VALIDATION_BUNDLE_JSON}"
echo "Rerun helper: ${RERUN_SHELL_SCRIPT}"
echo "Artifacts: ${ARTIFACT_DIR}"

if (( MATRIX_FAILED != 0 )); then
  echo "Richer-host validation recorded one or more failed smoke cases" >&2
  exit 1
fi
