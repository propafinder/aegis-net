#!/usr/bin/env bash
# Contract self-test for the richer-host validation matrix.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-rich-host-contract.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT
# Status cleanup and every artifact stay inside this fixture tree.
export RUNNER_TEMP="${tmpdir}/runner"
mkdir -p "$RUNNER_TEMP"
measure="${AEGIS_TEST_MEASURE_BINARY:-${ROOT}/target/debug/aegis-measure}"
if [[ ! -x "$measure" ]]; then
  cargo build --locked -q --manifest-path "${ROOT}/Cargo.toml" -p aegis-measure
fi
[[ -x "$measure" ]] || { echo 'Missing test aegis-measure binary.' >&2; exit 1; }
# The smoke bodies are inert and never bind these ports; reserve-tcp-port is
# outside this artifact/schema contract and has its own native unit coverage.
export AEGIS_WIDE_PORT=45180 AEGIS_SOCKS_PORT=45181 AEGIS_RELAY_PORT=45182
export AEGIS_FIXTURE_MEASURE="$measure" AEGIS_FIXTURE_PRIVILEGED_LOG="${tmpdir}/privileged.log"

stub_smoke="${tmpdir}/stub-smoke.sh"
cat > "${stub_smoke}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

contract="${AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT:?}"
runtime="${AEGIS_WIDE_SMOKE_RUNTIME_EVENTS_ARTIFACT:?}"
protocol="${AEGIS_WIDE_SMOKE_PROTOCOL:?}"
backend="${AEGIS_WIDE_FIREWALL_BACKEND:?}"
family="${AEGIS_WIDE_SMOKE_IP_FAMILY:?}"
case_id="${protocol}"
if [[ "${protocol}" == "generic_udp" ]]; then
  case_id="generic-udp"
elif [[ "${protocol}" == "dns_ipv6" ]]; then
  case_id="dns-ipv6"
fi
if [[ "${family}" == "ipv6" ]]; then
  case_id="${case_id}-ipv6"
fi
if [[ "${backend}" == "nft" ]]; then
  case_id="${case_id}-nft"
elif [[ "${backend}" == "xtables" && "${protocol}" == "generic_udp" && "${family}" == "ipv4" ]]; then
  case_id="generic-udp-xtables"
elif [[ "${backend}" == "xtables" && "${protocol}" == "dns" && "${family}" == "ipv4" ]]; then
  case_id="dns-xtables"
fi

case "${protocol}" in
  generic_udp)
    tier="guarded_unstable"
    if [[ "${family}" == "ipv6" ]]; then
      policy="any_target_port_linux_ipv6_unstable"
      scope="linux_ipv6_only"
    else
      policy="any_target_port_linux_ipv4_unstable"
      scope="linux_ipv4_only"
    fi
    ;;
  *)
    tier="supported_preview"
    policy="allowlist_ports"
    if [[ "${family}" == "ipv6" ]]; then
      scope="linux_ipv6_only"
    else
      scope="linux_ipv4_only"
    fi
    ;;
esac

mkdir -p "$(dirname "${contract}")" "$(dirname "${runtime}")"
printf '%s\n' '{"event_code":"ingress_backend_started","fields":{"backend":"wide_primary","wide_udp_capture_support_tier":"'"${tier}"'"}}' > "${runtime}"
smoke_class="dns_preview"
udp_capture_contract="preview_allowlist_only"
firewall_backend_effective="nft"
if [[ "${protocol}" == "generic_udp" ]]; then
  smoke_class="generic_udp"
  udp_capture_contract="generic_capture_unstable"
fi
if [[ "${backend}" == "xtables" ]]; then
  firewall_backend_effective="xtables:iptables"
fi
cat > "${contract}" <<JSON
{
  "smoke_class": "${smoke_class}",
  "smoke_protocol": "${protocol}",
  "ip_family": "${family}",
  "host_shape": "rich_linux_host",
  "firewall_backend_requested": "${backend}",
  "firewall_backend_effective": "${firewall_backend_effective}",
  "udp_capture_contract": "${udp_capture_contract}",
  "wide_udp_capture_support_tier": "${tier}",
  "wide_udp_capture_policy": "${policy}",
  "wide_udp_capture_runtime_scope": "${scope}"
}
JSON

if [[ "${AEGIS_RICH_HOST_STUB_FAIL_CASE:-}" == "${case_id}" ]]; then
  exit 32
fi
EOF
chmod +x "${stub_smoke}"

stub_bootstrap="${tmpdir}/stub-bootstrap.sh"
cat > "${stub_bootstrap}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--check" || "${2:-}" != "--json" ]]; then
  echo "unexpected bootstrap invocation: $*" >&2
  exit 1
fi

cat <<'JSON'
{
  "artifact_schema": "wide_linux_validation_host_bootstrap_v1",
  "mode": "check",
  "os_pretty_name": "Stub Linux",
  "os_id": "debian",
  "os_version_id": "12",
  "package_manager": "stub-pkg",
  "supported_product_contour": "linux_first_local_binary_operator",
  "supported_operator_scope": "supported_linux_tproxy_operator_path",
  "host_family_id": "debian-apt",
  "host_family_validation_tier": "next_non_ubuntu_target",
  "install_rustup": true,
  "ready": true,
  "commands": [
    {"name": "cargo", "status": "ok", "detail": "/stub/cargo"}
  ],
  "missing_commands": [],
  "sudo": {
    "status": "ok",
    "detail": "sudo available"
  },
  "remediation_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install",
  "bootstrap_check_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --check",
  "bootstrap_install_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install",
  "validation_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh",
  "upgrade_reapply_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh"
}
JSON
EOF
chmod +x "${stub_bootstrap}"

stub_bootstrap_fail="${tmpdir}/stub-bootstrap-fail.sh"
cat > "${stub_bootstrap_fail}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--check" || "${2:-}" != "--json" ]]; then
  echo "unexpected bootstrap invocation: $*" >&2
  exit 1
fi

cat <<'JSON'
{
  "artifact_schema": "wide_linux_validation_host_bootstrap_v1",
  "mode": "check",
  "os_pretty_name": "Stub Linux",
  "os_id": "debian",
  "os_version_id": "12",
  "package_manager": "stub-pkg",
  "supported_product_contour": "linux_first_local_binary_operator",
  "supported_operator_scope": "supported_linux_tproxy_operator_path",
  "host_family_id": "debian-apt",
  "host_family_validation_tier": "next_non_ubuntu_target",
  "install_rustup": true,
  "ready": false,
  "commands": [
    {"name": "cargo", "status": "missing", "detail": "required for richer-host validation"}
  ],
  "missing_commands": ["cargo"],
  "sudo": {
    "status": "ok",
    "detail": "sudo available"
  },
  "remediation_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install",
  "bootstrap_check_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --check",
  "bootstrap_install_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install",
  "validation_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh",
  "upgrade_reapply_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh"
}
JSON
exit 1
EOF
chmod +x "${stub_bootstrap_fail}"

stub_bootstrap_broken="${tmpdir}/stub-bootstrap-broken.sh"
cat > "${stub_bootstrap_broken}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--check" || "${2:-}" != "--json" ]]; then
  echo "unexpected bootstrap invocation: $*" >&2
  exit 1
fi

printf '%s\n' 'not-json-at-all'
exit 1
EOF
chmod +x "${stub_bootstrap_broken}"

fakebin="${tmpdir}/fakebin"
mkdir -p "${fakebin}"
# Avoid repeated Cargo builds inside the timeout supervisor. This shim permits
# only the real measure operations used by this fixture; it cannot build or
# run an unrelated executable. All kernel probes below remain forced/stubbed.
cat > "${fakebin}/cargo" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == run ]] || exit 97
shift
package=""
while [[ $# -gt 0 && "$1" != -- ]]; do
  case "$1" in
    -q) shift ;;
    --manifest-path) shift 2 ;;
    -p) package="$2"; shift 2 ;;
    *) exit 97 ;;
  esac
done
[[ "$package" == aegis-measure && "${1:-}" == -- ]] || exit 97
shift
case "${1:-}" in
  validate-rich-host-bootstrap|write-rich-host-matrix-targets|build-rich-host-matrix-summary|build-rich-host-metadata|build-rich-host-validation-bundle|reserve-tcp-port|run-with-timeout|check-rich-host-validation-contract-artifacts) ;;
  *) exit 97 ;;
esac
exec "$AEGIS_FIXTURE_MEASURE" "$@"
SHIM
cat > "${fakebin}/sudo" <<'SHIM'
#!/usr/bin/env bash
# Host metadata probes availability only. Never delegate to real sudo.
[[ "$*" != '-n true' ]] || exit 1
printf '%s\n' "$*" >> "$AEGIS_FIXTURE_PRIVILEGED_LOG"
exit 98
SHIM
chmod +x "${fakebin}/cargo" "${fakebin}/sudo"
export PATH="${fakebin}:${PATH}"
cat > "${fakebin}/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-Version" ]]; then
  printf '%s\n' 'ip utility, iproute2-test'
  exit 0
fi

if [[ "${1:-}" == "-6" && "${2:-}" == "addr" && "${3:-}" == "show" && "${4:-}" == "lo" ]]; then
  cat <<'OUT'
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
OUT
  exit 0
fi

echo "unexpected ip invocation: $*" >&2
exit 1
EOF
chmod +x "${fakebin}/ip"

cat > "${fakebin}/rg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 127
EOF
chmod +x "${fakebin}/rg"

artifact_dir="${tmpdir}/artifacts"

PATH="${fakebin}:${PATH}" \
AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR="${artifact_dir}" \
AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT="${stub_smoke}" \
AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT="${stub_bootstrap}" \
AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT=0 \
AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT=1 \
AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT=0 \
AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT=1 \
bash "${ROOT}/scripts/validate-wide-linux-tproxy-rich-host.sh" > "${tmpdir}/output.log"

set +e
PATH="${fakebin}:${PATH}" \
AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR="${artifact_dir}-fail" \
AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT="${stub_smoke}" \
AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT="${stub_bootstrap}" \
AEGIS_WIDE_RICH_HOST_FORCE_XTABLES_RESULT=0 \
AEGIS_WIDE_RICH_HOST_FORCE_NFT_RESULT=1 \
AEGIS_WIDE_RICH_HOST_FORCE_IP6TABLES_RESULT=0 \
AEGIS_WIDE_RICH_HOST_FORCE_NFT_IPV6_RESULT=1 \
AEGIS_RICH_HOST_STUB_FAIL_CASE=generic-udp-xtables \
bash "${ROOT}/scripts/validate-wide-linux-tproxy-rich-host.sh" > "${tmpdir}/output-fail.log"
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected richer-host matrix to fail when one smoke case fails" >&2
  exit 1
fi

set +e
PATH="${fakebin}:${PATH}" \
AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR="${artifact_dir}-bootstrap-fail" \
AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT="${stub_smoke}" \
AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT="${stub_bootstrap_fail}" \
bash "${ROOT}/scripts/validate-wide-linux-tproxy-rich-host.sh" > "${tmpdir}/output-bootstrap-fail.log" 2>&1
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected richer-host matrix to fail when bootstrap helper reports missing prerequisites" >&2
  exit 1
fi

set +e
PATH="${fakebin}:${PATH}" \
AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR="${artifact_dir}-bootstrap-broken" \
AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT="${stub_smoke}" \
AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT="${stub_bootstrap_broken}" \
bash "${ROOT}/scripts/validate-wide-linux-tproxy-rich-host.sh" > "${tmpdir}/output-bootstrap-broken.log" 2>&1
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected richer-host matrix to fail when bootstrap helper returns invalid JSON" >&2
  exit 1
fi

cargo run -q -p aegis-measure -- check-rich-host-validation-contract-artifacts \
  --artifact-dir "${artifact_dir}" \
  --repo-root "${ROOT}" \
  --failed-artifact-dir "${artifact_dir}-fail" \
  --bootstrap-fail-artifact-dir "${artifact_dir}-bootstrap-fail" \
  --bootstrap-fail-output "${tmpdir}/output-bootstrap-fail.log" \
  --bootstrap-broken-artifact-dir "${artifact_dir}-bootstrap-broken" \
  --bootstrap-broken-output "${tmpdir}/output-bootstrap-broken.log"

echo "rich-host validation matrix contract ok"

[[ ! -e "$AEGIS_FIXTURE_PRIVILEGED_LOG" ]] || { echo 'Unexpected privileged command in isolated rich-host fixture.' >&2; exit 1; }
