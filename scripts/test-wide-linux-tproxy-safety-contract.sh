#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
export AEGIS_MEASURE_BIN="${AEGIS_TEST_MEASURE_BINARY:-${ROOT}/target/debug/aegis-measure}"

make_stub_host() {
  local tmpdir="$1"
  mkdir -p "${tmpdir}/bin"
  mkdir -p "${tmpdir}/scripts/lib" "${tmpdir}/host/run"
  cp "${ROOT}/scripts/setup-wide-linux-tproxy.sh" "${tmpdir}/scripts/helper.sh"
  cp "${ROOT}/scripts/lib/root-state.sh" "${tmpdir}/scripts/lib/root-state.sh"
  python3 - "${tmpdir}/host" "${tmpdir}/scripts/helper.sh" "${tmpdir}/scripts/lib/root-state.sh" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[2:]:
    path = Path(name)
    text = path.read_text()
    for prefix in ("/etc/", "/var/lib/", "/var/log/", "/run/"):
        text = text.replace(prefix, sys.argv[1] + prefix)
    path.write_text(text)
PY
  for tool in nft firewall-cmd ip6tables; do
    printf '#!/usr/bin/env bash\nexit 1\n' > "${tmpdir}/bin/${tool}"
    chmod +x "${tmpdir}/bin/${tool}"
  done

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >> "${AEGIS_TPROXY_SAFETY_COMMAND_LOG}"
rule_state="${AEGIS_TPROXY_SAFETY_RULE_STATE}"
route_state="${AEGIS_TPROXY_SAFETY_ROUTE_STATE}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' "${4:-eth0}"
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "default" ]]; then
  printf 'default via 192.0.2.1 dev eth0\n'
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "add" ]]; then
  printf 'present\n' > "${rule_state}"
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "add" ]]; then
  printf 'present\n' > "${route_state}"
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  [[ -f "${rule_state}" ]] && printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  [[ -f "${route_state}" ]] && printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'iptables %s\n' "$*" >> "${AEGIS_TPROXY_SAFETY_COMMAND_LOG}"
if [[ "${1:-}" == "-t" && "${2:-}" == "mangle" && "${3:-}" == "-C" ]]; then
  exit 1
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"
}

write_client_config() {
  local path="$1"
  cat > "${path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
default_mark = 1
EOF
  chmod 0600 "${path}"
}

run_expect_fail() {
  local label="$1"
  local expected="$2"
  shift 2
  local tmpdir=""
  local output_file=""
  local command_log=""
  local status=0

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-tproxy-safety-${label}.XXXXXX")"
  tmpdir="$(cd "${tmpdir}" && pwd -P)"
  output_file="${tmpdir}/output.log"
  command_log="${tmpdir}/commands.log"
  make_stub_host "${tmpdir}"
  write_client_config "${tmpdir}/client.toml"

  set +e
  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_TPROXY_SAFETY_COMMAND_LOG="${command_log}" \
    AEGIS_TPROXY_SAFETY_RULE_STATE="${tmpdir}/rule.state" \
    AEGIS_TPROXY_SAFETY_ROUTE_STATE="${tmpdir}/route.state" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_CLIENT_CONFIG="${tmpdir}/client.toml" \
    "$@" \
    bash "${tmpdir}/scripts/helper.sh" apply >"${output_file}" 2>&1
  status=$?
  set -e

  if [[ "${status}" -eq 0 ]]; then
    echo "expected apply failure for ${label}" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,240p' "${output_file}")" in
    *"${expected}"*) ;;
    *)
      echo "missing failure detail for ${label}: ${expected}" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_expect_pass() {
  local label="$1"
  local expected_output="$2"
  local expected_log="$3"
  shift 3
  local tmpdir=""
  local output_file=""
  local command_log=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-tproxy-safety-${label}.XXXXXX")"
  tmpdir="$(cd "${tmpdir}" && pwd -P)"
  output_file="${tmpdir}/output.log"
  command_log="${tmpdir}/commands.log"
  make_stub_host "${tmpdir}"
  write_client_config "${tmpdir}/client.toml"

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_TPROXY_SAFETY_COMMAND_LOG="${command_log}" \
    AEGIS_TPROXY_SAFETY_RULE_STATE="${tmpdir}/rule.state" \
    AEGIS_TPROXY_SAFETY_ROUTE_STATE="${tmpdir}/route.state" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_CLIENT_CONFIG="${tmpdir}/client.toml" \
    "$@" \
    bash "${tmpdir}/scripts/helper.sh" apply >"${output_file}" 2>&1

  case "$(sed -n '1,240p' "${output_file}")" in
    *"${expected_output}"*) ;;
    *)
      echo "missing pass detail for ${label}: ${expected_output}" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${command_log}")" in
    *"${expected_log}"*) ;;
    *)
      echo "missing command detail for ${label}: ${expected_log}" >&2
      sed -n '1,240p' "${command_log}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_expect_fail \
  "missing-ssh-bypass" \
  "Refusing blind linux_tproxy apply on the default/public interface without SSH-safe bypass ports" \
  env AEGIS_WIDE_SSH_SAFE_PORTS=""

run_expect_fail \
  "all-interfaces-without-optin" \
  "Refusing blind linux_tproxy apply on the default/public interface with AEGIS_WIDE_ALLOW_ALL_INTERFACES=1" \
  env AEGIS_WIDE_ALLOW_ALL_INTERFACES=1

run_expect_pass \
  "ssh-bypass-present" \
  "ssh_safe_ports=22,2222" \
  "--dport 2222 -j RETURN" \
  env AEGIS_WIDE_SSH_SAFE_PORTS="22,2222"

run_expect_pass \
  "dangerous-opt-in" \
  "dangerous_public_apply_opt_in=1" \
  "--on-port 15080" \
  env AEGIS_WIDE_SSH_SAFE_PORTS="" AEGIS_WIDE_DANGEROUS_PUBLIC_APPLY=1

echo "linux_tproxy safety contract ok"
