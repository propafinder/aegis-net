#!/usr/bin/env bash
# Contract self-test for the Linux TPROXY full-capture helper surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-tproxy-full.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
export AEGIS_MEASURE_BIN="${AEGIS_TEST_MEASURE_BINARY:-$ROOT/target/debug/aegis-measure}"
export AEGIS_WIDE_FIREWALLD_STATE_FILE="$TMPDIR/firewalld.state"

COMMAND_LOG="${TMPDIR}/commands.log"
OUTPUT_LOG="${TMPDIR}/output.log"
CONFIG_PATH="${TMPDIR}/client.toml"
mkdir -p "${TMPDIR}/bin"

cat > "${TMPDIR}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_WIDE_TPROXY_FULL_COMMAND_LOG:?}"
if [[ "${3:-}" == "-C" || "${3:-}" == "-D" ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "${TMPDIR}/bin/iptables"

cat > "${TMPDIR}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
printf 'ip6tables %s\n' "$*" >> "${AEGIS_WIDE_TPROXY_FULL_COMMAND_LOG:?}"
if [[ "${3:-}" == "-C" || "${3:-}" == "-D" ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "${TMPDIR}/bin/ip6tables"

cat > "${TMPDIR}/bin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >> "${AEGIS_WIDE_TPROXY_FULL_COMMAND_LOG:?}"
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' "${4:-eth0}"
  exit 0
fi
exit 0
EOF
chmod +x "${TMPDIR}/bin/ip"

cat > "${CONFIG_PATH}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
dns_port = 53
default_mark = 1
EOF
chmod 0600 "${CONFIG_PATH}"

run_helper() {
  local action="$1"
  PATH="${TMPDIR}/bin:${PATH}" \
    AEGIS_WIDE_TPROXY_FULL_COMMAND_LOG="${COMMAND_LOG}" \
    AEGIS_WIDE_CHAIN=AEGIS_FULL \
    AEGIS_WIDE_PORT=15080 \
    AEGIS_WIDE_FWMARK=1 \
    AEGIS_WIDE_ROUTE_TABLE=100 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_WIDE_IPV6_POLICY=block \
    AEGIS_CLIENT_CONFIG="${CONFIG_PATH}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" "${action}" >>"${OUTPUT_LOG}" 2>&1
}

: > "${COMMAND_LOG}"
: > "${OUTPUT_LOG}"
for action in apply status teardown; do
  if ! run_helper "${action}"; then
    echo "TPROXY full-capture helper ${action} refused" >&2
    sed -n '1,100p' "${OUTPUT_LOG}" >&2
    exit 1
  fi
done

require_log() {
  local needle="$1"
  if ! grep -Fq -- "${needle}" "${COMMAND_LOG}"; then
    echo "missing command: ${needle}" >&2
    sed -n '1,260p' "${COMMAND_LOG}" >&2 || true
    exit 1
  fi
}

reject_log() {
  local needle="$1"
  if grep -Fq -- "${needle}" "${COMMAND_LOG}"; then
    echo "unexpected command: ${needle}" >&2
    sed -n '1,260p' "${COMMAND_LOG}" >&2 || true
    exit 1
  fi
}

require_output() {
  local needle="$1"
  if ! grep -Fq -- "${needle}" "${OUTPUT_LOG}"; then
    echo "missing output: ${needle}" >&2
    sed -n '1,260p' "${OUTPUT_LOG}" >&2 || true
    exit 1
  fi
}

# Audit C2: the CHAIN's tproxy action must be installed BEFORE the prerouting
# hook that jumps to it, else packets traverse a half-built chain and leak.
require_order() {
  local first="$1" second="$2" fline sline
  fline=$(grep -Fn -- "${first}" "${COMMAND_LOG}" | head -1 | cut -d: -f1)
  sline=$(grep -Fn -- "${second}" "${COMMAND_LOG}" | head -1 | cut -d: -f1)
  if [[ -z "${fline}" || -z "${sline}" || "${fline}" -ge "${sline}" ]]; then
    echo "ordering violation (C2): '${first}' (line ${fline:-none}) must precede '${second}' (line ${sline:-none})" >&2
    sed -n '1,260p' "${COMMAND_LOG}" >&2 || true
    exit 1
  fi
}

require_log "iptables -t mangle -A PREROUTING -i eth0 -p tcp -j AEGIS_FULL"
require_log "iptables -t mangle -A PREROUTING -i eth0 -p udp -j AEGIS_FULL"
require_log "iptables -t mangle -A AEGIS_FULL -p tcp -j TPROXY --on-port 15080 --tproxy-mark 1/1"
require_log "iptables -t mangle -A AEGIS_FULL -p udp -j TPROXY --on-port 15080 --tproxy-mark 1/1"
require_log "ip rule add fwmark 1 lookup 100"
require_log "ip route add local 0.0.0.0/0 dev lo table 100"
require_log "ip6tables -t filter -N AEGIS_FULL_V6_BLOCK"
require_log "ip6tables -t filter -I OUTPUT 1 -j AEGIS_FULL_V6_BLOCK"
require_log "ip6tables -t filter -I FORWARD 1 -j AEGIS_FULL_V6_BLOCK"
require_log "ip6tables -t filter -D OUTPUT -j AEGIS_FULL_V6_BLOCK"
require_log "ip6tables -t filter -D FORWARD -j AEGIS_FULL_V6_BLOCK"
require_log "iptables -t mangle -D PREROUTING -i eth0 -p tcp -j AEGIS_FULL"
require_log "iptables -t mangle -D PREROUTING -i eth0 -p udp -j AEGIS_FULL"
require_order \
  "iptables -t mangle -A AEGIS_FULL -p tcp -j TPROXY --on-port 15080 --tproxy-mark 1/1" \
  "iptables -t mangle -A PREROUTING -i eth0 -p tcp -j AEGIS_FULL"
require_order \
  "iptables -t mangle -A AEGIS_FULL -p udp -j TPROXY --on-port 15080 --tproxy-mark 1/1" \
  "iptables -t mangle -A PREROUTING -i eth0 -p udp -j AEGIS_FULL"

reject_log "iptables -t nat"
reject_log "REDIRECT"
reject_log "iptables -t mangle -F OUTPUT"

require_output "udp_capture_contract=generic_capture_unstable"
require_output "wide_udp_capture_support_tier=guarded_unstable"
require_output "wide_udp_capture_policy=any_target_port_linux_ipv4_unstable"
require_output "ipv6_policy=block"
require_output "Generic UDP TPROXY is enabled for any target port in the selected ipv4 family"

echo "linux_tproxy full capture contract PASS"
