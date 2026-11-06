#!/usr/bin/env bash
# Contract self-test for smoke-wide-linux-tproxy.sh without real TPROXY.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${ROOT}/scripts/lib/smoke-preflight-exit-codes.sh"

run_lab_relay_policy_case() {
  local tproxy_smoke="${ROOT}/scripts/smoke-wide-linux-tproxy.sh"
  local redirect_smoke="${ROOT}/scripts/smoke-wide-linux-redirect.sh"

  for smoke in "${tproxy_smoke}" "${redirect_smoke}"; do
    if ! grep -Fq '[target_policy]' "${smoke}" ||
      ! grep -Fq 'profile = "full_vpn_egress"' "${smoke}"; then
      echo "lab relay must explicitly opt in to non-public test targets: ${smoke}" >&2
      exit 1
    fi
  done

  if ! grep -Fq 'allowed_ports = [${SMOKE_UDP_TARGET_PORT}]' "${tproxy_smoke}"; then
    echo "TPROXY lab relay target policy must stay limited to the selected smoke port" >&2
    exit 1
  fi
  if ! grep -Fq 'allowed_ports = [${DNS_PORT}]' "${redirect_smoke}"; then
    echo "REDIRECT lab relay target policy must stay limited to the DNS smoke port" >&2
    exit 1
  fi
}

run_process_ownership_case() {
  local smoke="${ROOT}/scripts/smoke-wide-linux-tproxy.sh"
  if grep -Fq 'cargo run -p aegis-server -- --config' "${smoke}"; then
    echo "smoke relay must run the built server directly so cleanup owns its real PID" >&2
    exit 1
  fi
  if ! grep -Fq '"${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-server" --config "${SERVER_CFG}"' "${smoke}"; then
    echo "smoke relay direct-binary PID ownership contract is missing" >&2
    exit 1
  fi
  if ! grep -Fq 'CLIENT_PID="$!"' "${smoke}" ||
    ! grep -Fq 'cleanup cannot orphan it after a failed smoke' "${smoke}"; then
    echo "smoke client cleanup must own the exec-replaced runtime PID" >&2
    exit 1
  fi
  if ! grep -Fq 'CLIENT_BIN_OVERRIDE="${SMOKE_CARGO_TARGET_DIRECTORY}/debug/aegis-client"' "${smoke}" ||
    ! grep -Fq 'helper fallback cannot start a separate' "${smoke}"; then
    echo "source-tree smoke must launch the debug client it just built instead of cargo run --release" >&2
    exit 1
  fi
}

run_preflight_case() {
  local scenario="$1"
  local expected_exit="$2"

  set +e
  AEGIS_SMOKE_PREFLIGHT_SELF_TEST_SCENARIO="${scenario}" \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null 2>&1
  local status=$?
  set -e

  if [[ "${status}" -ne "${expected_exit}" ]]; then
    echo "preflight self-test mismatch for ${scenario}: expected=${expected_exit} actual=${status}" >&2
    exit 1
  fi
}

run_client_bin_override_case() {
  local tmpdir=""
  local bindir=""
  local fake_client=""
  local client_log=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-smoke-contract.XXXXXX")"
  bindir="${tmpdir}/bin"
  fake_client="${tmpdir}/aegis-client"
  client_log="${tmpdir}/client.log"
  mkdir -p "${bindir}"

  cat > "${bindir}/cargo" <<'EOF'
#!/usr/bin/env bash
echo "cargo must not be invoked when AEGIS_CLIENT_BIN is valid" >&2
exit 99
EOF
  cat > "${fake_client}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_AEGIS_CLIENT_LOG}"
exit 0
EOF
  chmod +x "${bindir}/cargo" "${fake_client}"

  PATH="${bindir}:${PATH}" \
    AEGIS_CLIENT_BIN="${fake_client}" \
    FAKE_AEGIS_CLIENT_LOG="${client_log}" \
    AEGIS_SMOKE_CLIENT_BIN_SELF_TEST_SCENARIO=valid \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null

  if ! grep -Fq -- "--aegis-client-bin-self-test-probe" "${client_log}"; then
    echo "valid AEGIS_CLIENT_BIN was not invoked by smoke self-test" >&2
    exit 1
  fi

  set +e
  AEGIS_CLIENT_BIN="${tmpdir}/missing-aegis-client" \
    AEGIS_SMOKE_CLIENT_BIN_SELF_TEST_SCENARIO=invalid \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null 2>"${tmpdir}/invalid.err"
  local status=$?
  set -e

  if [[ "${status}" -eq 0 ]]; then
    echo "invalid AEGIS_CLIENT_BIN did not fail fast" >&2
    exit 1
  fi
  if ! grep -Fq "AEGIS_CLIENT_BIN points to a non-executable path" "${tmpdir}/invalid.err"; then
    echo "invalid AEGIS_CLIENT_BIN failure did not explain the bad path" >&2
    exit 1
  fi

  rm -rf "${tmpdir}"
}

run_loopback_idempotent_case() {
  local tmpdir=""
  local bindir=""
  local ip_log=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-smoke-contract.XXXXXX")"
  bindir="${tmpdir}/bin"
  ip_log="${tmpdir}/ip.log"
  mkdir -p "${bindir}"

  cat > "${bindir}/sudo" <<'EOF'
#!/usr/bin/env bash
"$@"
EOF
  cat > "${bindir}/ip" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "${FAKE_IP_LOG}"
exit 0
EOF
  chmod +x "${bindir}/sudo" "${bindir}/ip"

  PATH="${bindir}:${PATH}" \
    FAKE_IP_LOG="${ip_log}" \
    AEGIS_SMOKE_SELF_TEST_SCENARIO=loopback_target_idempotent \
    AEGIS_WIDE_SMOKE_PROTOCOL=dns \
    AEGIS_WIDE_SMOKE_IP_FAMILY=ipv4 \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null

  cargo run -q -p aegis-measure -- verify-tproxy-loopback-idempotent-log \
    --ip-log "${ip_log}"

  rm -rf "${tmpdir}"
}

run_case() {
  local protocol="$1"
  local family="$2"
  local backend_requested="$3"
  local expected_effective="$4"
  local expected_tier="$5"
  local expected_policy="$6"
  local expected_scope="$7"
  local target_port="${8:-0}"
  local tmpdir=""
  local contract_artifact=""
  local runtime_artifact=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-smoke-contract.XXXXXX")"
  contract_artifact="${tmpdir}/contract.json"
  runtime_artifact="${tmpdir}/runtime.jsonl"

  AEGIS_SMOKE_CONTRACT_SELF_TEST_SCENARIO=artifacts \
    AEGIS_WIDE_SMOKE_PROTOCOL="${protocol}" \
    AEGIS_WIDE_SMOKE_IP_FAMILY="${family}" \
    AEGIS_WIDE_FIREWALL_BACKEND="${backend_requested}" \
    AEGIS_WIDE_SMOKE_HOST_SHAPE=github_hosted \
    AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT="${contract_artifact}" \
    AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT="${runtime_artifact}" \
    AEGIS_WIDE_UDP_PREVIEW_PORT=5353 \
    AEGIS_WIDE_GENERIC_UDP_TARGET_PORT="${target_port}" \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null

  cargo run -q -p aegis-measure -- verify-tproxy-smoke-contract-self-test \
    --contract-artifact "${contract_artifact}" \
    --runtime-events-jsonl "${runtime_artifact}" \
    --smoke-protocol "${protocol}" \
    --ip-family "${family}" \
    --firewall-backend-requested "${backend_requested}" \
    --expected-effective "${expected_effective}" \
    --expected-tier "${expected_tier}" \
    --expected-policy "${expected_policy}" \
    --expected-scope "${expected_scope}" \
    --target-port "${target_port}"

  rm -rf "${tmpdir}"
}

run_transport_failure_case() {
  local tmpdir=""
  local contract_artifact=""
  local runtime_artifact=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-smoke-contract.XXXXXX")"
  contract_artifact="${tmpdir}/contract.json"
  runtime_artifact="${tmpdir}/runtime.jsonl"

  AEGIS_SMOKE_CONTRACT_SELF_TEST_SCENARIO=artifacts \
    AEGIS_SMOKE_CONTRACT_SELF_TEST_VARIANT=transport_failure \
    AEGIS_WIDE_SMOKE_PROTOCOL=generic_udp \
    AEGIS_WIDE_SMOKE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_FIREWALL_BACKEND=auto \
    AEGIS_WIDE_SMOKE_HOST_SHAPE=github_hosted \
    AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT="${contract_artifact}" \
    AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT="${runtime_artifact}" \
    AEGIS_WIDE_GENERIC_UDP_TARGET_PORT=54321 \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null

  cargo run -q -p aegis-measure -- verify-tproxy-transport-failure-self-test \
    --contract-artifact "${contract_artifact}" \
    --runtime-events-jsonl "${runtime_artifact}"

  rm -rf "${tmpdir}"
}

run_transport_recovered_case() {
  local tmpdir=""
  local contract_artifact=""
  local runtime_artifact=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-smoke-contract.XXXXXX")"
  contract_artifact="${tmpdir}/contract.json"
  runtime_artifact="${tmpdir}/runtime.jsonl"

  AEGIS_SMOKE_CONTRACT_SELF_TEST_SCENARIO=artifacts \
    AEGIS_SMOKE_CONTRACT_SELF_TEST_VARIANT=transport_recovered \
    AEGIS_WIDE_SMOKE_PROTOCOL=generic_udp \
    AEGIS_WIDE_SMOKE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_FIREWALL_BACKEND=auto \
    AEGIS_WIDE_SMOKE_HOST_SHAPE=github_hosted \
    AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT="${contract_artifact}" \
    AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT="${runtime_artifact}" \
    AEGIS_WIDE_GENERIC_UDP_TARGET_PORT=54321 \
    bash "${ROOT}/scripts/smoke-wide-linux-tproxy.sh" >/dev/null

  cargo run -q -p aegis-measure -- verify-tproxy-transport-recovered-self-test \
    --contract-artifact "${contract_artifact}" \
    --runtime-events-jsonl "${runtime_artifact}"

  rm -rf "${tmpdir}"
}

run_case http ipv4 auto "xtables:iptables" "supported_preview" "allowlist_ports" "linux_ipv4_only"
run_case dns ipv4 auto "xtables:iptables" "supported_preview" "allowlist_ports" "linux_ipv4_only"
run_case dns ipv4 nft "nft" "supported_preview" "allowlist_ports" "linux_ipv4_only"
run_case dns_ipv6 ipv6 auto "xtables:ip6tables" "supported_preview" "allowlist_ports" "linux_ipv6_only"
run_case generic_udp ipv4 auto "xtables:iptables" "guarded_unstable" "any_target_port_linux_ipv4_unstable" "linux_ipv4_only" 54321
run_case generic_udp ipv4 nft "nft" "guarded_unstable" "any_target_port_linux_ipv4_unstable" "linux_ipv4_only" 54321
run_case generic_udp ipv6 auto "xtables:ip6tables" "guarded_unstable" "any_target_port_linux_ipv6_unstable" "linux_ipv6_only" 54321
run_case udp_preview_drop ipv4 auto "xtables:iptables" "supported_preview" "allowlist_ports" "linux_ipv4_only" 5300
run_transport_failure_case
run_transport_recovered_case
run_loopback_idempotent_case
run_client_bin_override_case
run_lab_relay_policy_case
run_process_ownership_case
run_preflight_case needs_privilege "${EXIT_PREFLIGHT_NEEDS_CAP_NET_ADMIN}"
run_preflight_case listener_busy "${EXIT_PREFLIGHT_LISTENER_BUSY}"

echo "linux_tproxy smoke contract ok"
