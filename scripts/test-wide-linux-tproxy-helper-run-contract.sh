#!/usr/bin/env bash
# Contract self-test for the supervised linux_tproxy helper run path.
# This stays network-free by stubbing cargo/ip/ip6table interactions.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
export AEGIS_MEASURE_BIN="${AEGIS_TEST_MEASURE_BINARY:-${ROOT}/target/debug/aegis-measure}"

run_case() {
  local scenario="$1"
  local expected_status="$2"
  local expected_summary="$3"
  local expected_detail="$4"
  local expected_detail_2="${5:-}"
  local expected_detail_3="${6:-}"
  local expected_detail_4="${7:-}"
  local expected_detail_5="${8:-}"
  local family="${9:-ipv4}"
  local capture_contract="${10:-preview_allowlist_only}"
  local listen_value="0.0.0.0:15080"
  local expected_scope="linux_ipv4_only"
  local expected_policy="allowlist_ports"
  local expected_tier="supported_preview"
  local tmpdir=""
  local output_file=""
  local status=0

  if [[ "${family}" == "ipv6" ]]; then
    listen_value="[::]:15080"
    expected_scope="linux_ipv6_only"
  fi
  if [[ "${capture_contract}" == "generic_capture_unstable" ]]; then
    expected_tier="guarded_unstable"
    if [[ "${family}" == "ipv6" ]]; then
      expected_policy="any_target_port_linux_ipv6_unstable"
    else
      expected_policy="any_target_port_linux_ipv4_unstable"
    fi
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-run-contract.XXXXXX")"
  tmpdir="$(cd "${tmpdir}" && pwd -P)"
  output_file="${tmpdir}/output.log"
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
  for tool in nft firewall-cmd; do
    printf '#!/usr/bin/env bash\nexit 1\n' > "${tmpdir}/bin/${tool}"
    chmod +x "${tmpdir}/bin/${tool}"
  done

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${tmpdir}/bin/client-runtime-fixture" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Profile metadata, typed config and public diagnostics use the selected real
# client; only the runtime/probe is replaced by this inert fixture.
if [[ "${1:-}" == profile ]]; then
  exec "${AEGIS_TEST_REAL_STATE_CLIENT}" "$@"
fi

scenario="${AEGIS_HELPER_RUN_TEST_SCENARIO:-healthy}"
scope="${AEGIS_HELPER_RUN_TEST_SCOPE:-linux_ipv4_only}"
contract="${AEGIS_HELPER_RUN_TEST_CONTRACT:-preview_allowlist_only}"
policy="${AEGIS_HELPER_RUN_TEST_POLICY:-allowlist_ports}"
tier="${AEGIS_HELPER_RUN_TEST_TIER:-supported_preview}"

if [[ "$*" == *"--ingress-startup-probe --json"* ]]; then
  case "${scenario}" in
    probe_failure)
      printf '%s' '{"status":"error","startup":{"code":"wide_bind_failed","started_backend":null,"failure_code":"needs_cap_net_admin","hint_code":"needs_root_or_cap_net_admin_for_ip_transparent","message":"wide backend failed to start","hint":"run as root or grant CAP_NET_ADMIN","wide_dns_capture_preview_status":"disabled","wide_udp_capture_contract":"'"${contract}"'","wide_udp_capture_support_tier":"'"${tier}"'","wide_udp_capture_policy":"'"${policy}"'","wide_udp_capture_runtime_scope":"'"${scope}"'"}}'
      exit 1
      ;;
    probe_stdout_noise)
      printf '%s\n' 'warn: startup probe emitted pre-json diagnostics'
      printf '%s' '{"status":"ok","startup":{"code":"wide_primary_started","started_backend":"wide_primary","failure_code":null,"hint_code":null,"message":"wide backend started","hint":null,"wide_dns_capture_preview_status":"active","wide_udp_capture_contract":"'"${contract}"'","wide_udp_capture_support_tier":"'"${tier}"'","wide_udp_capture_policy":"'"${policy}"'","wide_udp_capture_runtime_scope":"'"${scope}"'"}}'
      exit 0
      ;;
    *)
      printf '%s' '{"status":"ok","startup":{"code":"wide_primary_started","started_backend":"wide_primary","failure_code":null,"hint_code":null,"message":"wide backend started","hint":null,"wide_dns_capture_preview_status":"active","wide_udp_capture_contract":"'"${contract}"'","wide_udp_capture_support_tier":"'"${tier}"'","wide_udp_capture_policy":"'"${policy}"'","wide_udp_capture_runtime_scope":"'"${scope}"'"}}'
      exit 0
      ;;
  esac
fi

if [[ "${scenario}" == "probe_failure" ]]; then
  echo "launch path should not execute during probe_failure scenario" >&2
  exit 99
fi

runtime=""
prev=""
for arg in "$@"; do
  if [[ "${prev}" == "--runtime-events-jsonl" ]]; then
    runtime="${arg}"
  fi
  prev="${arg}"
done

if [[ -z "${runtime}" ]]; then
  echo "missing --runtime-events-jsonl argument" >&2
  exit 98
fi

printf '%s\n' '{"ts_unix_ms":1,"level":"info","event_code":"ingress_backend_started","message":"client ingress backend started","fields":{"backend":"wide_primary","backend_runtime_id":"wide_primary_linux","wide_dns_capture_preview_status":"active","wide_udp_capture_contract":"'"${contract}"'","wide_udp_capture_support_tier":"'"${tier}"'","wide_udp_capture_policy":"'"${policy}"'","wide_udp_capture_runtime_scope":"'"${scope}"'"}}' > "${runtime}"

case "${scenario}" in
  healthy|probe_stdout_noise)
    printf '%s\n' '{"ts_unix_ms":2,"level":"info","event_code":"direct_session_succeeded","message":"direct session succeeded","fields":{}}' >> "${runtime}"
    ;;
  transport_recovered)
    printf '%s\n' '{"ts_unix_ms":2,"level":"warn","event_code":"relay_transport_failed","message":"relay transport failed","fields":{"transport":"LegacyTls","relay_server":"relay.example.org:8443","relay_error_kind":"connection_refused","error":"connect refused"}}' >> "${runtime}"
    printf '%s\n' '{"ts_unix_ms":3,"level":"info","event_code":"direct_session_succeeded","message":"direct session succeeded","fields":{}}' >> "${runtime}"
    ;;
  runtime_failover_only)
    printf '%s\n' '{"ts_unix_ms":2,"level":"info","event_code":"direct_relay_failover_triggered","message":"direct relay failover triggered","fields":{"direct_relay_failover_reason_code":"runtime_failover"}}' >> "${runtime}"
    printf '%s\n' '{"ts_unix_ms":3,"level":"info","event_code":"direct_session_succeeded","message":"direct session succeeded","fields":{}}' >> "${runtime}"
    ;;
  runtime_warning)
    printf '%s\n' '{"ts_unix_ms":2,"level":"warn","event_code":"relay_transport_failed","message":"relay transport failed","fields":{"transport":"MasqueDerived","relay_server":"relay.example.org:8443","relay_error_kind":"connection_refused","error":"connect refused"}}' >> "${runtime}"
    ;;
  *)
    echo "unknown AEGIS_HELPER_RUN_TEST_SCENARIO=${scenario}" >&2
    exit 97
    ;;
esac
EOF
  cat > "${tmpdir}/bin/aegis-client" <<'EOF'
#!/usr/bin/env bash
exec "$(dirname "$0")/client-runtime-fixture" "$@"
EOF
  chmod +x "${tmpdir}/bin/client-runtime-fixture" "${tmpdir}/bin/aegis-client"

  cat > "${tmpdir}/client.toml" <<EOF
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "${listen_value}"
capture_dns = true
udp_capture_contract = "${capture_contract}"
dns_port = 53
default_mark = 1
EOF
  chmod 0600 "${tmpdir}/client.toml"

  set +e
  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_TEST_REAL_STATE_CLIENT="${AEGIS_ROOT_STATE_CLIENT}" \
    AEGIS_CLIENT_BIN="${tmpdir}/bin/aegis-client" \
    AEGIS_HELPER_RUN_TEST_SCENARIO="${scenario}" \
    AEGIS_HELPER_RUN_TEST_SCOPE="${expected_scope}" \
    AEGIS_HELPER_RUN_TEST_CONTRACT="${capture_contract}" \
    AEGIS_HELPER_RUN_TEST_TIER="${expected_tier}" \
    AEGIS_HELPER_RUN_TEST_POLICY="${expected_policy}" \
    AEGIS_WIDE_IP_FAMILY="${family}" \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT="${capture_contract}" \
    AEGIS_CLIENT_CONFIG="${tmpdir}/client.toml" \
    AEGIS_RUNTIME_EVENTS_JSONL="${tmpdir}/runtime.jsonl" \
    bash "${tmpdir}/scripts/helper.sh" run >"${output_file}" 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne "${expected_status}" ]]; then
    echo "run helper contract mismatch for scenario=${scenario}: expected_status=${expected_status} actual_status=${status}" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,240p' "${output_file}")" in
    *"${expected_summary}"*)
      ;;
    *)
      echo "run helper summary mismatch for scenario=${scenario}: expected to find '${expected_summary}'" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${output_file}")" in
    *"${expected_detail}"*)
      ;;
    *)
      echo "run helper detail mismatch for scenario=${scenario}: expected to find '${expected_detail}'" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  if [[ -n "${expected_detail_2}" ]]; then
    case "$(sed -n '1,240p' "${output_file}")" in
      *"${expected_detail_2}"*)
        ;;
      *)
        echo "run helper detail mismatch for scenario=${scenario}: expected to find '${expected_detail_2}'" >&2
        sed -n '1,240p' "${output_file}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  fi

  if [[ -n "${expected_detail_3}" ]]; then
    case "$(sed -n '1,240p' "${output_file}")" in
      *"${expected_detail_3}"*)
        ;;
      *)
        echo "run helper detail mismatch for scenario=${scenario}: expected to find '${expected_detail_3}'" >&2
        sed -n '1,240p' "${output_file}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  fi

  if [[ -n "${expected_detail_4}" ]]; then
    case "$(sed -n '1,240p' "${output_file}")" in
      *"${expected_detail_4}"*)
        ;;
      *)
        echo "run helper detail mismatch for scenario=${scenario}: expected to find '${expected_detail_4}'" >&2
        sed -n '1,240p' "${output_file}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  fi

  if [[ -n "${expected_detail_5}" ]]; then
    case "$(sed -n '1,240p' "${output_file}")" in
      *"${expected_detail_5}"*)
        ;;
      *)
        echo "run helper detail mismatch for scenario=${scenario}: expected to find '${expected_detail_5}'" >&2
        sed -n '1,240p' "${output_file}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  fi

  rm -rf "${tmpdir}"
}

run_case healthy 0 "Run result: client exited cleanly and runtime events summary stayed healthy" "backend.wide_udp_capture_contract=preview_allowlist_only" "backend.wide_udp_capture_support_tier=supported_preview" "backend.wide_udp_capture_policy=allowlist_ports" "backend.wide_udp_capture_runtime_scope=linux_ipv4_only" "runtime_status=healthy"
run_case probe_stdout_noise 0 "Run result: client exited cleanly and runtime events summary stayed healthy" "startup.wide_udp_capture_contract=preview_allowlist_only" "startup.wide_udp_capture_support_tier=supported_preview" "startup.wide_udp_capture_policy=allowlist_ports" "startup.wide_udp_capture_runtime_scope=linux_ipv4_only" "startup_health=healthy"
run_case runtime_warning 1 "Run result: client exited cleanly, but runtime status was not healthy" "backend.wide_udp_capture_contract=preview_allowlist_only" "backend.wide_udp_capture_support_tier=supported_preview" "backend.wide_udp_capture_policy=allowlist_ports" "backend.wide_udp_capture_runtime_scope=linux_ipv4_only" "runtime_status=degraded_runtime_seen"
run_case transport_recovered 1 "Run result: client exited cleanly, but runtime status was not healthy" "backend.wide_udp_capture_contract=preview_allowlist_only" "backend.wide_udp_capture_support_tier=supported_preview" "backend.wide_udp_capture_policy=allowlist_ports" "backend.wide_udp_capture_runtime_scope=linux_ipv4_only" "runtime_status=degraded_runtime_seen"
run_case runtime_failover_only 1 "Run result: client exited cleanly, but runtime status was not healthy" "backend.wide_udp_capture_contract=preview_allowlist_only" "backend.wide_udp_capture_support_tier=supported_preview" "backend.wide_udp_capture_policy=allowlist_ports" "backend.wide_udp_capture_runtime_scope=linux_ipv4_only" "runtime_status=degraded_failover_seen"
run_case probe_failure 1 "Run result: probe did not confirm a supported linux_tproxy startup path" "startup.wide_udp_capture_contract=preview_allowlist_only" "startup.wide_udp_capture_support_tier=supported_preview" "startup.wide_udp_capture_policy=allowlist_ports" "startup.wide_udp_capture_runtime_scope=linux_ipv4_only"
run_case healthy 0 "Run result: client exited cleanly and runtime events summary stayed healthy" "backend.wide_udp_capture_contract=generic_capture_unstable" "backend.wide_udp_capture_support_tier=guarded_unstable" "backend.wide_udp_capture_policy=any_target_port_linux_ipv6_unstable" "backend.wide_udp_capture_runtime_scope=linux_ipv6_only" "dns_port=<ignored_by_generic_capture_contract>" ipv6 generic_capture_unstable

echo "linux_tproxy helper run contract ok"
