#!/usr/bin/env bash
# Contract test for the IPv6-capture wrapper path in
# scripts/aegis-wide-enable.sh + scripts/setup-wide-linux-tproxy.sh.
#
# Verifies that `--ipv6=capture --mode=tproxy`:
#   1. Is accepted by the wrapper's flag validator.
#   2. Re-targets the listener to [::]:WIDE_PORT.
#   3. Pins AEGIS_WIDE_IP_FAMILY=ipv6 in the underlying helper env.
#   4. Does NOT set AEGIS_WIDE_BLOCK_IPV6=1.
#   5. Passes AEGIS_WIDE_IPV6_POLICY=capture through (not "block").
#
# Also verifies the wrapper's safety rails:
#   6. `--ipv6=capture --mode=redirect` is rejected early (REDIRECT is
#      IPv4-only — NAT v6 path does not preserve original-dst).
#   7. `--ipv6=capture` is accepted by the tproxy helper's validator
#      (`setup-wide-linux-tproxy.sh apply` doesn't fail on
#      "AEGIS_WIDE_IPV6_POLICY must be ...").

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-ipv6.XXXXXX")"
TMP_DIR="$(cd "${TMP_DIR}" && pwd -P)"
trap 'rm -rf "${TMP_DIR}"' EXIT
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
export AEGIS_MEASURE_BIN="${AEGIS_TEST_MEASURE_BINARY:-${ROOT}/target/debug/aegis-measure}"

BIN="${TMP_DIR}/bin"
LOG="${TMP_DIR}/cmd.log"
ENV_DUMP="${TMP_DIR}/env.dump"
mkdir -p "${BIN}"

# Stub: aegis-wide-enable invokes setup-wide-linux-tproxy.sh apply with
# the resolved env. The fake helper dumps the relevant AEGIS_WIDE_* vars
# so the test can assert on them, then exits 0.
cat > "${BIN}/setup-wide-linux-tproxy.sh" <<EOF
#!/usr/bin/env bash
{
    printf '[fake-helper] action=%s\n' "\${1:-}"
    printf 'AEGIS_WIDE_LISTEN=%s\n' "\${AEGIS_WIDE_LISTEN:-(unset)}"
    printf 'AEGIS_WIDE_IP_FAMILY=%s\n' "\${AEGIS_WIDE_IP_FAMILY:-(unset)}"
    printf 'AEGIS_WIDE_IPV6_POLICY=%s\n' "\${AEGIS_WIDE_IPV6_POLICY:-(unset)}"
    printf 'AEGIS_WIDE_BLOCK_IPV6=%s\n' "\${AEGIS_WIDE_BLOCK_IPV6:-(unset)}"
} > '${ENV_DUMP}'
exit 0
EOF
chmod +x "${BIN}/setup-wide-linux-tproxy.sh"

cat > "${BIN}/setup-wide-linux-redirect.sh" <<EOF
#!/usr/bin/env bash
echo "[fake-redirect] $*" >> '${LOG}'
exit 0
EOF
chmod +x "${BIN}/setup-wide-linux-redirect.sh"

# Mock command/network helpers so the wrapper's preflight passes.
for cmd in iptables ip6tables systemctl logger journalctl; do
    cat > "${BIN}/${cmd}" <<EOF
#!/usr/bin/env bash
printf '${cmd} %s\n' "\$*" >> '${LOG}'
for arg in "\$@"; do
    if [[ "\$arg" == "-C" ]]; then exit 1; fi
done
exit 0
EOF
    chmod +x "${BIN}/${cmd}"
done

cat > "${BIN}/sysctl" <<EOF
#!/usr/bin/env bash
printf 'sysctl %s\n' "\$*" >> '${LOG}'
if [[ "\$1" == "-n" ]]; then echo 0; fi
exit 0
EOF
chmod +x "${BIN}/sysctl"

cat > "${BIN}/ip" <<EOF
#!/usr/bin/env bash
printf 'ip %s\n' "\$*" >> '${LOG}'
if [[ "\$1 \$2 \$3" == "-4 route show" ]]; then
    echo "default via 10.0.0.1 dev eth0"
fi
exit 0
EOF
chmod +x "${BIN}/ip"
for tool in nft firewall-cmd; do
    printf '#!/usr/bin/env bash\nexit 1\n' > "${BIN}/${tool}"
    chmod +x "${BIN}/${tool}"
done

cat > "${BIN}/id" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "-u" ]]; then
    case "\${2:-}" in aegis-client|aegis) echo 424; exit 0 ;; esac
fi
exec /usr/bin/id "\$@"
EOF
chmod +x "${BIN}/id"

# Keep production validation in a fixture copy whose administrative paths are
# entirely temporary. A symlink would still leave host /run and legacy state.
mkdir -p "${BIN}/lib" "${TMP_DIR}/host/etc" "${TMP_DIR}/host/run"
cp "${ROOT}/scripts/aegis-wide-enable.sh" "${BIN}/aegis-wide-enable.sh"
cp "${ROOT}/scripts/setup-wide-linux-tproxy.sh" "${BIN}/tproxy-validator.sh"
cp "${ROOT}/scripts/lib/root-state.sh" "${BIN}/lib/root-state.sh"
python3 - "${TMP_DIR}/host" "${BIN}/aegis-wide-enable.sh" "${BIN}/tproxy-validator.sh" "${BIN}/lib/root-state.sh" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[2:]:
    path = Path(name)
    text = path.read_text()
    for prefix in ("/etc/", "/var/lib/", "/var/log/", "/run/"):
        text = text.replace(prefix, sys.argv[1] + prefix)
    path.write_text(text)
PY

fail() { echo "FAIL: $*" >&2; sed -n '1,200p' "${LOG}" 2>/dev/null || true; cat "${ENV_DUMP}" 2>/dev/null || true; exit 1; }

# --- case 1: --ipv6=capture --mode=tproxy is accepted and propagates ----

OUT="${TMP_DIR}/capture.out"
rm -f "${ENV_DUMP}"
PATH="${BIN}:${PATH}" \
AEGIS_WIDE_SKIP_ROOT_CHECK=1 \
AEGIS_WIDE_ROLLBACK_SECS=1 \
AEGIS_WIDE_SYSCTL_FILE="${TMP_DIR}/sysctl.d.conf" \
AEGIS_WIDE_SYSCTL_SNAPSHOT="${TMP_DIR}/snap.txt" \
    bash "${BIN}/aegis-wide-enable.sh" \
        --yes --no-rollback --mode=tproxy --interface=eth0 \
        --dns=off --ipv6=capture --ssh-safe-ports=22 \
    > "${OUT}" 2>&1 || { cat "${OUT}" >&2; fail 'capture wrapper failed'; }

[[ -f "${ENV_DUMP}" ]] || fail "fake helper was not invoked (env dump missing)"
grep -Fq 'AEGIS_WIDE_LISTEN=[::]:15080' "${ENV_DUMP}" \
    || fail "AEGIS_WIDE_LISTEN not re-targeted to [::]:15080 for capture mode"
grep -Fq 'AEGIS_WIDE_IP_FAMILY=ipv6' "${ENV_DUMP}" \
    || fail "AEGIS_WIDE_IP_FAMILY not pinned to ipv6 for capture mode"
grep -Fq 'AEGIS_WIDE_IPV6_POLICY=capture' "${ENV_DUMP}" \
    || fail "AEGIS_WIDE_IPV6_POLICY not propagated as 'capture'"
grep -Fq 'AEGIS_WIDE_BLOCK_IPV6=0' "${ENV_DUMP}" \
    || fail "AEGIS_WIDE_BLOCK_IPV6 should be 0 for capture mode (was: $(grep AEGIS_WIDE_BLOCK_IPV6 "${ENV_DUMP}"))"

# --- case 2: --ipv6=capture --mode=redirect rejected ----------------------

OUT2="${TMP_DIR}/reject.out"
if PATH="${BIN}:${PATH}" \
   AEGIS_WIDE_SKIP_ROOT_CHECK=1 \
   AEGIS_WIDE_ROLLBACK_SECS=1 \
   AEGIS_WIDE_SYSCTL_FILE="${TMP_DIR}/sysctl-r.conf" \
   AEGIS_WIDE_SYSCTL_SNAPSHOT="${TMP_DIR}/snap-r.txt" \
        bash "${BIN}/aegis-wide-enable.sh" \
            --yes --mode=redirect --ipv6=capture --dns=off \
        > "${OUT2}" 2>&1; then
    fail "--ipv6=capture --mode=redirect should be rejected (REDIRECT is IPv4-only)"
fi
grep -Fq -- '--ipv6=capture requires --mode=tproxy' "${OUT2}" \
    || fail "rejection did not surface the IPv6-capture-needs-tproxy reason: $(cat "${OUT2}" | head -3)"

# --- case 3: AEGIS_WIDE_IPV6_POLICY=capture accepted by the tproxy helper -

# Run setup-wide-linux-tproxy.sh validate (the action that just exits with
# 0 after env validation) — but only with environment that should pass
# all validators. The relevant line: `case "${IPV6_POLICY}" in ... capture)`.
HELPER="${BIN}/tproxy-validator.sh"
OUT3="${TMP_DIR}/helper-validate.out"
# We invoke the validate-only path by calling `status` which performs env
# validation then exits.
PATH="${BIN}:${PATH}" AEGIS_WIDE_IPV6_POLICY=capture \
AEGIS_WIDE_CHAIN=AEGIS_TEST \
AEGIS_WIDE_PORT=15080 \
AEGIS_EXEMPT_UID=424 \
AEGIS_WIDE_FWMARK=1 \
AEGIS_WIDE_IP_FAMILY=ipv6 \
AEGIS_WIDE_INTERFACE=eth0 \
    bash "${HELPER}" status > "${OUT3}" 2>&1 || { cat "${OUT3}" >&2; fail 'valid capture helper status failed'; }
# If our IPV6_POLICY=capture had been rejected, the status invocation
# would print "AEGIS_WIDE_IPV6_POLICY must be ..." early. Assert that
# error is NOT present.
if grep -Fq 'AEGIS_WIDE_IPV6_POLICY must be' "${OUT3}"; then
    fail "tproxy helper rejected IPV6_POLICY=capture: $(grep 'AEGIS_WIDE_IPV6_POLICY must be' "${OUT3}")"
fi

# Also verify the helper rejects an obviously-bad value, so the validator
# is actually running (regression guard against accidentally bypassing it).
OUT3B="${TMP_DIR}/helper-validate-bad.out"
PATH="${BIN}:${PATH}" AEGIS_WIDE_IPV6_POLICY=banana \
AEGIS_WIDE_CHAIN=AEGIS_TEST \
AEGIS_WIDE_PORT=15080 \
AEGIS_EXEMPT_UID=424 \
AEGIS_WIDE_FWMARK=1 \
AEGIS_WIDE_IP_FAMILY=ipv6 \
AEGIS_WIDE_INTERFACE=eth0 \
    bash "${HELPER}" status > "${OUT3B}" 2>&1 || true
grep -Fq 'AEGIS_WIDE_IPV6_POLICY must be' "${OUT3B}" \
    || fail "tproxy helper validator never fires on bad value; regression guard would be silent"

echo "PASS: aegis-wide ipv6=capture wrapper + helper validator contract"
