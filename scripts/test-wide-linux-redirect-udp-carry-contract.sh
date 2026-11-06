#!/usr/bin/env bash
# Contract for the Linux full-wide bidirectional UDP/DNS redirect contour.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-udp-carry.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
export AEGIS_WIDE_RESOLVER_SNAPSHOT="$TMPDIR/resolver.json"

BIN_DIR="${TMPDIR}/bin"
mkdir -p "${BIN_DIR}"

cat > "${BIN_DIR}/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_TEST_IPTABLES_LOG:?}"
if [[ "${3:-}" == "-C" ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "${BIN_DIR}/iptables"

cat > "${BIN_DIR}/ip6tables" <<'EOF'
#!/usr/bin/env bash
printf 'ip6tables %s\n' "$*" >> "${AEGIS_TEST_IPTABLES_LOG:?}"
if [[ "${3:-}" == "-C" ]]; then
  exit 1
fi
exit 0
EOF
chmod +x "${BIN_DIR}/ip6tables"

fail() {
  echo "wide UDP carry contract FAIL: $*" >&2
  exit 1
}

require_line() {
  local file="$1" needle="$2"
  grep -Fqx -- "${needle}" "${file}" || fail "missing rule: ${needle}"
}

reject_line() {
  local file="$1" needle="$2"
  if grep -Fqx -- "${needle}" "${file}"; then
    fail "forbidden rule present: ${needle}"
  fi
}

require_order() {
  local file="$1" first="$2" second="$3" first_line second_line
  first_line="$(grep -Fnx -- "${first}" "${file}" | head -1 | cut -d: -f1 || true)"
  second_line="$(grep -Fnx -- "${second}" "${file}" | head -1 | cut -d: -f1 || true)"
  [[ -n "${first_line}" && -n "${second_line}" ]] ||
    fail "cannot verify rule order: ${first} -> ${second}"
  (( first_line < second_line )) ||
    fail "rule order is unsafe: ${first} must precede ${second}"
}

# Full-wide UDP carry: external DNS and extra preview ports must use the
# bidirectional conntrack proxy. Sending either to the one-shot wide preview
# listener loses the pre-NAT target and cannot return the response.
CARRY_LOG="${TMPDIR}/carry.log"
CARRY_OUTPUT="${TMPDIR}/carry.output"
PATH="${BIN_DIR}:${PATH}" \
  AEGIS_TEST_IPTABLES_LOG="${CARRY_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_CARRY \
  AEGIS_WIDE_PORT=15080 \
  AEGIS_WIDE_UDP_REDIRECT_PORT=15081 \
  AEGIS_EXEMPT_UID=4242 \
  AEGIS_ENABLE_DNS_PREVIEW=1 \
  AEGIS_UDP_PREVIEW_PORTS=123,5353 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" apply >"${CARRY_OUTPUT}" 2>&1

require_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -o lo -j RETURN"
require_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -m addrtype --dst-type LOCAL -p udp --dport 15081 -j RETURN"
require_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp -j REDIRECT --to-ports 15081"
reject_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp --dport 53 -j RETURN"
reject_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 15080"
reject_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp --dport 123 -j REDIRECT --to-ports 15080"
reject_line "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp --dport 5353 -j REDIRECT --to-ports 15080"
require_order "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -o lo -j RETURN" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp -j REDIRECT --to-ports 15081"
require_order "${CARRY_LOG}" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -m addrtype --dst-type LOCAL -p udp --dport 15081 -j RETURN" \
  "iptables -t nat -A AEGIS_CARRY_OUTPUT -p udp -j REDIRECT --to-ports 15081"
grep -Fq -- \
  "Bidirectional generic-UDP carry enabled: external UDP including DNS" \
  "${CARRY_OUTPUT}" || fail "apply output does not describe the DNS carry contour"

# Preview-only mode is intentionally unchanged: without a bidirectional UDP
# proxy, its narrow allowlist still redirects DNS/extra ports to the wide
# preview listener and does not install a generic UDP catch-all.
PREVIEW_LOG="${TMPDIR}/preview.log"
PATH="${BIN_DIR}:${PATH}" \
  AEGIS_TEST_IPTABLES_LOG="${PREVIEW_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_PREVIEW \
  AEGIS_WIDE_PORT=15080 \
  AEGIS_EXEMPT_UID=4242 \
  AEGIS_ENABLE_DNS_PREVIEW=1 \
  AEGIS_UDP_PREVIEW_PORTS=123,15080 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" apply >/dev/null 2>&1

require_line "${PREVIEW_LOG}" \
  "iptables -t nat -A AEGIS_PREVIEW_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 15080"
require_line "${PREVIEW_LOG}" \
  "iptables -t nat -A AEGIS_PREVIEW_OUTPUT -p udp --dport 123 -j REDIRECT --to-ports 15080"
reject_line "${PREVIEW_LOG}" \
  "iptables -t nat -A AEGIS_PREVIEW_OUTPUT -p udp -j REDIRECT --to-ports 15081"

# Evaluate the actual rendered chains with local and external destinations on
# identical ports. This catches an unconditional RETURN even if a later scoped
# rule is also present. The fixture models only matches this helper emits and
# rejects unknown predicates rather than silently treating them as matching.
python3 - "${CARRY_LOG}" "${PREVIEW_LOG}" <<'PY'
import ipaddress
import shlex
import sys


def decision(filename, chain, protocol, port, destination, interface="eth-test"):
    local = destination in {"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"}
    for line in open(filename, encoding="utf-8"):
        tokens = shlex.split(line)
        if tokens[3:5] != ["-A", chain]:
            continue
        matches = True
        i = 5
        while i < len(tokens):
            option, value = tokens[i:i + 2]
            i += 2
            if option == "-j":
                if matches:
                    return value
                break
            if option == "-m":
                assert value in {"addrtype", "owner", "mark", "conntrack"}, tokens
            elif option == "-p":
                matches &= protocol == value
            elif option == "--dport":
                matches &= port == int(value)
            elif option == "-o":
                matches &= interface == value
            elif option == "--dst-type":
                assert value == "LOCAL", tokens
                matches &= local
            elif option == "--src-type":
                assert value == "LOCAL", tokens
            elif option == "--ctstate":
                assert value in {"DNAT", "ESTABLISHED"}, tokens
                matches = False  # ordinary original, uncaptured app packet
            elif option == "--ctdir":
                assert value == "REPLY", tokens
                matches = False
            elif option == "--ctorigdstport":
                matches = False
            elif option == "--sport":
                matches &= int(value) == 40000
            elif option == "--uid-owner":
                matches &= int(value) == 1000  # ordinary application fixture
            elif option == "--mark":
                matches &= int(value) == 0
            elif option == "-d":
                matches &= ipaddress.ip_address(destination) in ipaddress.ip_network(value)
            else:
                raise AssertionError(("unmodeled match", tokens))
    return "FALLTHROUGH"


count = 0
for filename, prefix, ports in [
    (sys.argv[1], "AEGIS_CARRY", [("tcp", 15080), ("udp", 15081)]),
    (sys.argv[2], "AEGIS_PREVIEW", [("tcp", 15080), ("udp", 15080)]),
]:
    for protocol, port in ports:
        for suffix in ["OUTPUT", "PREROUTING"]:
            # Generic UDP capture is OUTPUT-only; PREROUTING has preview lanes.
            if prefix == "AEGIS_CARRY" and protocol == "udp" and suffix == "PREROUTING":
                continue
            for destination, expected in [("198.51.100.10", "REDIRECT"), ("192.0.2.1", "RETURN")]:
                actual = decision(filename, prefix + "_" + suffix, protocol, port, destination)
                assert actual == expected, (prefix, suffix, protocol, destination, actual)
                count += 1
        assert decision(filename, prefix + "_OUTPUT", protocol, port, "127.0.0.1", "lo") == "RETURN"
        count += 1
    for port in [15080, 15081]:
        assert decision(filename, prefix + "_FILTER", "udp", port, "198.51.100.10") == "REJECT"
        assert decision(filename, prefix + "_FILTER", "udp", port, "127.0.0.1", "lo") == "RETURN"
        count += 2
    for protocol in ["tcp", "udp"]:
        assert decision(filename, prefix + "_V6", protocol, 15080, "2001:db8:1::10") == "REJECT"
        assert decision(filename, prefix + "_V6", protocol, 15080, "2001:db8::1") == "RETURN"
        assert decision(filename, prefix + "_V6", protocol, 15080, "::1", "lo") == "RETURN"
        count += 3
print(f"local listener / external same-port rule decisions PASS ({count} cases)")
PY

# Teardown remains flag-independent so rollback cannot leave a live UDP hook.
TEARDOWN_LOG="${TMPDIR}/teardown.log"
PATH="${BIN_DIR}:${PATH}" \
  AEGIS_TEST_IPTABLES_LOG="${TEARDOWN_LOG}" \
  AEGIS_WIDE_CHAIN=AEGIS_CARRY \
  AEGIS_WIDE_PORT=15080 \
  bash "${ROOT}/scripts/setup-wide-linux-redirect.sh" teardown >/dev/null 2>&1

require_line "${TEARDOWN_LOG}" \
  "iptables -t nat -D OUTPUT -p udp -j AEGIS_CARRY_OUTPUT"
require_line "${TEARDOWN_LOG}" \
  "iptables -t nat -F AEGIS_CARRY_OUTPUT"
require_line "${TEARDOWN_LOG}" \
  "iptables -t nat -X AEGIS_CARRY_OUTPUT"

echo "wide Linux redirect UDP carry contract PASS"
