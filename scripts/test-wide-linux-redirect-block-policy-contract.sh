#!/usr/bin/env bash
# Contract test for the Linux REDIRECT helper fail-closed leak-block policy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-redirect-block.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT
export AEGIS_WIDE_RESOLVER_SNAPSHOT="$TMPDIR/resolver.json"

COMMAND_LOG="${TMPDIR}/commands.log"
OUTPUT_LOG="${TMPDIR}/output.log"
mkdir -p "${TMPDIR}/bin"

cat > "${TMPDIR}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_WIDE_REDIRECT_BLOCK_COMMAND_LOG:?}"
if [[ "${3:-}" == "-C" ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "${TMPDIR}/bin/iptables"

cat > "${TMPDIR}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
printf 'ip6tables %s\n' "$*" >> "${AEGIS_WIDE_REDIRECT_BLOCK_COMMAND_LOG:?}"
if [[ "${3:-}" == "-C" ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "${TMPDIR}/bin/ip6tables"

PATH="${TMPDIR}/bin:${PATH}" \
  AEGIS_WIDE_REDIRECT_BLOCK_COMMAND_LOG="${COMMAND_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_TEST \
  AEGIS_WIDE_PORT=15080 \
  AEGIS_EXEMPT_UID=4242 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" apply >"${OUTPUT_LOG}" 2>&1

PATH="${TMPDIR}/bin:${PATH}" \
  AEGIS_WIDE_REDIRECT_BLOCK_COMMAND_LOG="${COMMAND_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_TEST \
  AEGIS_WIDE_PORT=15080 \
  AEGIS_EXEMPT_UID=4242 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" status >>"${OUTPUT_LOG}" 2>&1

PATH="${TMPDIR}/bin:${PATH}" \
  AEGIS_WIDE_REDIRECT_BLOCK_COMMAND_LOG="${COMMAND_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_TEST \
  AEGIS_WIDE_PORT=15080 \
  AEGIS_EXEMPT_UID=4242 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" teardown >>"${OUTPUT_LOG}" 2>&1

require_log() {
  local needle="$1"
  if ! grep -Fq -- "${needle}" "${COMMAND_LOG}"; then
    echo "missing command: ${needle}" >&2
    sed -n '1,260p' "${COMMAND_LOG}" >&2 || true
    exit 1
  fi
}

require_output() {
  local needle="$1"
  if ! grep -Fq -- "${needle}" "${OUTPUT_LOG}"; then
    echo "missing output: ${needle}" >&2
    sed -n '1,220p' "${OUTPUT_LOG}" >&2 || true
    exit 1
  fi
}

# Audit A: the fail-closed hooks (IPv6 REJECT / generic-UDP block) must be
# attached to OUTPUT BEFORE the IPv4 capture hook, so activation never leaves a
# window where IPv4 is captured while IPv6/UDP still egress natively.
require_order() {
  local first="$1" second="$2" fline sline
  fline=$(grep -Fn -- "${first}" "${COMMAND_LOG}" | head -1 | cut -d: -f1)
  sline=$(grep -Fn -- "${second}" "${COMMAND_LOG}" | head -1 | cut -d: -f1)
  if [[ -z "${fline}" || -z "${sline}" || "${fline}" -ge "${sline}" ]]; then
    echo "ordering violation (A): '${first}' (line ${fline:-none}) must precede '${second}' (line ${sline:-none})" >&2
    sed -n '1,260p' "${COMMAND_LOG}" >&2 || true
    exit 1
  fi
}

require_order \
  "ip6tables -t filter -I OUTPUT 1 -j AEGIS_TEST_V6" \
  "iptables -t nat -A OUTPUT -p tcp -j AEGIS_TEST_OUTPUT"

require_log "iptables -t nat -A AEGIS_TEST_OUTPUT -p tcp -j REDIRECT --to-ports 15080"
require_log "iptables -t filter -N AEGIS_TEST_FILTER"
require_log "iptables -t filter -A AEGIS_TEST_FILTER -m owner --uid-owner 4242 -j RETURN"
require_log "iptables -t filter -A AEGIS_TEST_FILTER -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable"
require_log "iptables -t filter -A AEGIS_TEST_FILTER -p tcp --dport 53 -j REJECT --reject-with tcp-reset"
require_log "iptables -t filter -A AEGIS_TEST_FILTER -p udp -j REJECT --reject-with icmp-port-unreachable"
require_log "iptables -t filter -I OUTPUT 1 -p udp -j AEGIS_TEST_FILTER"
require_log "iptables -t filter -I OUTPUT 1 -p tcp --dport 53 -j AEGIS_TEST_FILTER"
require_log "ip6tables -t filter -N AEGIS_TEST_V6"
require_log "ip6tables -t filter -A AEGIS_TEST_V6 -m owner --uid-owner 4242 -j RETURN"
require_log "ip6tables -t filter -A AEGIS_TEST_V6 -j REJECT"
require_log "ip6tables -t filter -I OUTPUT 1 -j AEGIS_TEST_V6"
require_log "iptables -t filter -D OUTPUT -p udp -j AEGIS_TEST_FILTER"
require_log "iptables -t filter -D OUTPUT -p tcp --dport 53 -j AEGIS_TEST_FILTER"
require_log "ip6tables -t filter -D OUTPUT -j AEGIS_TEST_V6"
require_log "iptables -t filter -X AEGIS_TEST_FILTER"
require_log "ip6tables -t filter -X AEGIS_TEST_V6"
require_log "iptables -t nat -D OUTPUT -p udp -j AEGIS_TEST_OUTPUT"
require_log "iptables -t nat -D PREROUTING -p udp -j AEGIS_TEST_PREROUTING"

require_output "Wide fail-closed block policy enabled: udp=1 tcp_dns=1 ipv6=1"
require_output "=== filter/AEGIS_TEST_FILTER ==="
require_output "=== ip6 filter/AEGIS_TEST_V6 ==="

# full-wide-tun runs the client as root. In capture-root mode the pinned relay
# destinations replace the uid exemption on both IPv4 and IPv6 policy chains;
# otherwise a stopped/crashed client would restore native IPv6 for root daemons.
CAPTURE_ROOT_LOG="${TMPDIR}/capture-root-commands.log"
PATH="${TMPDIR}/bin:${PATH}" \
  AEGIS_WIDE_REDIRECT_BLOCK_COMMAND_LOG="${CAPTURE_ROOT_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_ROOT \
  AEGIS_WIDE_PORT=15080 \
  AEGIS_EXEMPT_UID=0 \
  AEGIS_WIDE_CAPTURE_ROOT=1 \
  AEGIS_DIRECT_SOCKET_MARK=44641 \
  AEGIS_WIDE_RELAY_EXCLUDE_IPS=203.0.113.10 \
  AEGIS_WIDE_IPV6_TUN_DEV=aegis-tun0 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" apply >>"${OUTPUT_LOG}" 2>&1

if grep -Fq -- '--uid-owner 0 -j RETURN' "${CAPTURE_ROOT_LOG}"; then
  echo "capture-root mode leaked a uid-0 exemption" >&2
  sed -n '1,260p' "${CAPTURE_ROOT_LOG}" >&2 || true
  exit 1
fi
grep -Fq -- 'iptables -t nat -A AEGIS_ROOT_OUTPUT -d 203.0.113.10 -p tcp -j RETURN' "${CAPTURE_ROOT_LOG}"
grep -Fq -- 'iptables -t nat -A AEGIS_ROOT_OUTPUT -m mark --mark 44641 -j RETURN' "${CAPTURE_ROOT_LOG}"
grep -Fq -- 'iptables -t filter -A AEGIS_ROOT_FILTER -m mark --mark 44641 -j RETURN' "${CAPTURE_ROOT_LOG}"
grep -Fq -- 'ip6tables -t filter -A AEGIS_ROOT_V6 -o aegis-tun0 -j RETURN' "${CAPTURE_ROOT_LOG}"
grep -Fq -- 'ip6tables -t filter -A AEGIS_ROOT_V6 -j REJECT' "${CAPTURE_ROOT_LOG}"

echo "wide redirect block policy contract PASS"
