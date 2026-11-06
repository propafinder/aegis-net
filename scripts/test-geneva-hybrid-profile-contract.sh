#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALLER="${ROOT}/install.sh"
STRATEGY_FILE="${ROOT}/docs/GENEVA-ROADMAP.md"
CA_FILE="${ROOT}/README.md"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

validate() {
  AEGIS_INSTALL_VALIDATE_MODE_ONLY=1 bash "${INSTALLER}" client "$@" 2>/dev/null
}

out="$(validate \
  --profile full-wide-hybrid-geneva \
  --geneva-strategy-file "${STRATEGY_FILE}" \
  --masque-server masque.example.test:443 \
  --masque-ca "${CA_FILE}")"

grep -Fq 'product_mode=full-wide-hybrid-geneva' <<<"${out}" \
  || fail "hybrid product mode was not selected"
grep -Fq 'operator_mode=client-ipv6-tun-smoltcp' <<<"${out}" \
  || fail "hybrid profile did not reuse the fail-closed full-wide TUN lifecycle"
grep -Fq 'udp_carry=1' <<<"${out}" \
  || fail "hybrid profile did not force MASQUE UDP carry"

expect_rejected() {
  local label="$1"
  shift
  local rc=0
  AEGIS_INSTALL_VALIDATE_MODE_ONLY=1 bash "${INSTALLER}" client "$@" \
    >/dev/null 2>&1 || rc=$?
  [[ "${rc}" == "2" ]] || fail "${label} returned ${rc}, expected fail-fast exit 2"
}

expect_rejected "missing Geneva DSL" \
  --profile full-wide-hybrid-geneva \
  --masque-server masque.example.test:443 \
  --masque-ca "${CA_FILE}"
expect_rejected "missing MASQUE server" \
  --profile full-wide-hybrid-geneva \
  --geneva-strategy-file "${STRATEGY_FILE}" \
  --masque-ca "${CA_FILE}"
expect_rejected "missing MASQUE CA" \
  --profile full-wide-hybrid-geneva \
  --geneva-strategy-file "${STRATEGY_FILE}" \
  --masque-server masque.example.test:443
expect_rejected "route-matrix override" \
  --profile full-wide-hybrid-geneva \
  --geneva-strategy-file "${STRATEGY_FILE}" \
  --masque-server masque.example.test:443 \
  --masque-ca "${CA_FILE}" \
  --udp-policy block

for contract in \
  'set_client_config_hybrid_geneva' \
  'set_top_level_mode("auto")' \
  'set_section_value("direct", "strategies", '\''["geneva"]'\'')' \
  'set_section_value("direct", "hybrid_geneva", "true")' \
  'set_section_value("relay", "transport_priority", '\''["grpc_stream"]'\'')' \
  'set_section_value("relay", "udp_transport_priority", '\''["masque_derived", "grpc_datagram"]'\'')' \
  'AEGIS_HYBRID_DIRECT_SOCKET_MARK=44641' \
  'AEGIS_DIRECT_SOCKET_MARK="${direct_socket_mark}"' \
  'PRIVACY DISCLOSURE: the access network sees each direct IPv4 destination IP.'; do
  grep -Fq -- "${contract}" "${INSTALLER}" \
    || fail "installer lost hybrid contract: ${contract}"
done

echo "PASS: Geneva hybrid profile fails closed before install and renders explicit routes"
