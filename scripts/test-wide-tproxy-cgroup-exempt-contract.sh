#!/usr/bin/env bash
# Contract: the TPROXY OUTPUT DNS-capture marking exempts the aegis-client's own
# loop traffic as NARROWLY as possible (audit H3). When AEGIS_WIDE_EXEMPT_CGROUP
# is set, the OUTPUT MARK rule must exempt only that cgroup (-m cgroup ! --path)
# so ordinary root-owned app DNS is still captured; the default keeps the uid
# match for compatibility. apply and teardown must emit the SAME match so the
# rule can be deleted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-h3-cgroup.XXXXXX")"
TMP_DIR="$(cd "${TMP_DIR}" && pwd -P)"
trap 'rm -rf "${TMP_DIR}"' EXIT
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
export AEGIS_MEASURE_BIN="${AEGIS_TEST_MEASURE_BINARY:-${ROOT}/target/debug/aegis-measure}"
mkdir -p "${TMP_DIR}/scripts/lib" "${TMP_DIR}/host/run"
cp "${ROOT}/scripts/setup-wide-linux-tproxy.sh" "${TMP_DIR}/scripts/helper.sh"
cp "${ROOT}/scripts/lib/root-state.sh" "${TMP_DIR}/scripts/lib/root-state.sh"
python3 - "${TMP_DIR}/host" "${TMP_DIR}/scripts/helper.sh" "${TMP_DIR}/scripts/lib/root-state.sh" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[2:]:
    path = Path(name)
    text = path.read_text()
    for prefix in ("/etc/", "/var/lib/", "/var/log/", "/run/"):
        text = text.replace(prefix, sys.argv[1] + prefix)
    path.write_text(text)
PY
LOG="${TMP_DIR}/cmd.log"
mkdir -p "${TMP_DIR}/bin"
CLIENT_CONFIG="${TMP_DIR}/client.toml"
cat > "${CLIENT_CONFIG}" <<'EOF'
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
udp_capture_contract = "generic_capture_unstable"
dns_port = 53
default_mark = 1
EOF
chmod 600 "${CLIENT_CONFIG}"

for tool in iptables ip6tables; do
  cat > "${TMP_DIR}/bin/${tool}" <<EOF
#!/usr/bin/env bash
printf '${tool} %s\n' "\$*" >> "\${H3_LOG:?}"
[[ "\${3:-}" == "-C" || "\${3:-}" == "-D" ]] && exit 1
exit 0
EOF
  chmod +x "${TMP_DIR}/bin/${tool}"
done
cat > "${TMP_DIR}/bin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >> "${H3_LOG:?}"
[[ "${1:-}" == "link" && "${2:-}" == "show" ]] && { printf '2: eth0: <UP>\n'; exit 0; }
[[ "$*" == 'rule show' ]] && { printf '100: from all fwmark 1 lookup 100\n'; exit 0; }
[[ "$*" == 'route show table 100' ]] && { printf 'local 0.0.0.0/0 dev lo scope host\n'; exit 0; }
exit 0
EOF
chmod +x "${TMP_DIR}/bin/ip"
for tool in nft firewall-cmd; do
  printf '#!/usr/bin/env bash\nexit 1\n' > "${TMP_DIR}/bin/${tool}"
  chmod +x "${TMP_DIR}/bin/${tool}"
done

run() {
  : > "${LOG}"
  PATH="${TMP_DIR}/bin:${PATH}" H3_LOG="${LOG}" \
    AEGIS_WIDE_CHAIN=AEGIS_H3 AEGIS_WIDE_PORT=15080 AEGIS_WIDE_FWMARK=1 \
    AEGIS_WIDE_ROUTE_TABLE=100 AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_ENABLE_DNS_PREVIEW=1 AEGIS_ENABLE_LOCAL_OUTPUT=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${H3_CLIENT_CONFIG-${CLIENT_CONFIG}}" \
    AEGIS_WIDE_EXEMPT_CGROUP="${AEGIS_WIDE_EXEMPT_CGROUP:-}" \
    bash "${TMP_DIR}/scripts/helper.sh" "$1" >"${TMP_DIR}/output.log" 2>&1 || {
      cat "${TMP_DIR}/output.log" >&2; return 1;
    }
}
has()  { grep -Fq -- "$1" "${LOG}" || { echo "FAIL: missing '$1'" >&2; exit 1; }; }
hasnt(){ grep -Fq -- "$1" "${LOG}" && { echo "FAIL: unexpected '$1'" >&2; exit 1; } || true; }

# Required configuration must refuse before any mocked firewall/route command.
printf 'not valid TOML\n' > "${TMP_DIR}/invalid.toml"
chmod 600 "${TMP_DIR}/invalid.toml"
for invalid_config in "" "${TMP_DIR}/missing.toml" "${TMP_DIR}/invalid.toml"; do
  if H3_CLIENT_CONFIG="${invalid_config}" run apply; then
    echo 'FAIL: apply accepted absent or invalid client configuration' >&2
    exit 1
  fi
  [[ ! -s "${LOG}" ]] || { echo 'FAIL: configuration refusal reached firewall/route commands' >&2; exit 1; }
done
echo "ok: absent/invalid client config refuses before firewall/route commands"

# 1. Default: broad uid match preserved (backward compatible).
run apply
has '-A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 0 -j MARK'
echo "ok: default uses uid-owner exemption"

# 2. cgroup mode: narrow cgroup match, NO broad uid-0 exemption on the OUTPUT MARK.
AEGIS_WIDE_EXEMPT_CGROUP='system.slice/aegis-client.service' run apply
has '-A OUTPUT -p udp --dport 53 -m cgroup ! --path system.slice/aegis-client.service -j MARK'
hasnt '-A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 0 -j MARK'
echo "ok: cgroup mode exempts only the client cgroup (root app DNS still captured)"

# 3. teardown emits the SAME cgroup match (so the rule is actually deletable).
AEGIS_WIDE_EXEMPT_CGROUP='system.slice/aegis-client.service' run teardown
has '-D OUTPUT -p udp --dport 53 -m cgroup ! --path system.slice/aegis-client.service -j MARK'
echo "ok: teardown deletes the same cgroup-scoped rule"

echo "wide tproxy cgroup-exempt contract PASS"
