#!/usr/bin/env bash
# Contract test for scripts/setup-wide-linux-nfqueue.sh.
#
# Verifies the apply / teardown / status actions install + remove the
# expected mangle-table iptables state, with the queue-bypass safety
# wired and the aegis exempt UID rule placed before the NFQUEUE target.
#
# Sandboxed: mocked iptables, EUID gate bypassed via env override.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/setup-wide-linux-nfqueue.sh"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-nfq-contract.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

BIN="${TMPDIR}/bin"
LOG="${TMPDIR}/iptables.log"
STATE="${TMPDIR}/state"
mkdir -p "${BIN}" "${STATE}"

# --- mocked iptables ----------------------------------------------------

# Mock state model: every call is logged. For -C checks we track which
# OUTPUT/PREROUTING-attached chains exist in $STATE/output_chains.
# Chain create/delete is tracked in $STATE/chains. Everything else returns 0.
cat > "${BIN}/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_NFQ_CONTRACT_LOG:?}"
STATE_DIR="${AEGIS_NFQ_CONTRACT_STATE:?}"
chains="${STATE_DIR}/chains"
out="${STATE_DIR}/output_chains"
touch "${chains}" "${out}"

# Locate -t TABLE and the next op.
table=""; op=""; rest=()
i=1
while [[ $i -le $# ]]; do
    v="${!i}"
    case "${v}" in
        -t) i=$((i+1)); table="${!i}" ;;
        -N|-F|-X|-L|-C|-D|-A|-I) op="${v}"; rest=("${@:i}"); break ;;
    esac
    i=$((i+1))
done

case "${op}" in
    -N)
        # -N CHAIN
        chain="${rest[1]}"
        grep -Fxq "${table}:${chain}" "${chains}" && exit 1
        echo "${table}:${chain}" >> "${chains}"; exit 0 ;;
    -F) exit 0 ;;
    -X)
        chain="${rest[1]}"
        grep -Fvx "${table}:${chain}" "${chains}" > "${chains}.tmp"
        mv "${chains}.tmp" "${chains}"
        exit 0 ;;
    -L)
        chain="${rest[1]}"
        grep -Fxq "${table}:${chain}" "${chains}" || exit 1
        exit 0 ;;
    -C)
        # -C OUTPUT -j CHAIN  → present iff CHAIN is in output_chains
        if [[ "${rest[1]}" == "OUTPUT" && "${rest[2]}" == "-j" ]]; then
            grep -Fxq "${table}:${rest[3]}" "${out}" && exit 0 || exit 1
        fi
        exit 1 ;;
    -A) exit 0 ;;
    -I)
        # -I OUTPUT 1 -j CHAIN  → attach chain to output
        if [[ "${rest[1]}" == "OUTPUT" ]]; then
            # rest = (-I OUTPUT 1 -j CHAIN ...)
            jflag_idx=-1
            for k in "${!rest[@]}"; do
                [[ "${rest[$k]}" == "-j" ]] && jflag_idx=$((k+1)) && break
            done
            [[ ${jflag_idx} -ge 0 ]] && echo "${table}:${rest[$jflag_idx]}" >> "${out}"
        fi
        exit 0 ;;
    -D)
        if [[ "${rest[1]}" == "OUTPUT" && "${rest[2]}" == "-j" ]]; then
            grep -Fvx "${table}:${rest[3]}" "${out}" > "${out}.tmp"
            mv "${out}.tmp" "${out}"
        fi
        exit 0 ;;
esac
exit 0
EOF
chmod +x "${BIN}/iptables"

# id mock so aegis-client uid resolution returns 4242.
cat > "${BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "-u" ]]; then
    case "$2" in
        aegis-client|aegis) echo 4242; exit 0 ;;
        *) exit 1 ;;
    esac
fi
EOF
chmod +x "${BIN}/id"

fail() { echo "FAIL: $*" >&2; sed -n '1,200p' "${LOG}" >&2 || true; exit 1; }

run() {
    AEGIS_WIDE_NFQ_SKIP_ROOT_CHECK=1 \
    AEGIS_NFQ_CONTRACT_LOG="${LOG}" \
    AEGIS_NFQ_CONTRACT_STATE="${STATE}" \
    AEGIS_WIDE_NFQ_CHAIN=AEGIS_NFQ_TEST \
    PATH="${BIN}:${PATH}" \
        bash "${SCRIPT}" "$@"
}

# --- case 1: apply -----------------------------------------------------

OUT="${TMPDIR}/apply.out"
run apply --queue-num=123 --dport=80,443,8443 > "${OUT}" 2>&1 \
    || fail "apply exited non-zero"

# Chain created.
grep -Fq 'iptables -t mangle -N AEGIS_NFQ_TEST' "${LOG}" \
    || fail "apply did not create chain"
# Exempt UID rule BEFORE NFQUEUE.
exempt_line=$(grep -n 'iptables -t mangle -A AEGIS_NFQ_TEST -m owner --uid-owner 4242 -j RETURN' "${LOG}" | head -1 | cut -d: -f1)
nfq_line=$(grep -n 'iptables -t mangle -A AEGIS_NFQ_TEST -p tcp --dport 80 -j NFQUEUE --queue-num 123 --queue-bypass' "${LOG}" | head -1 | cut -d: -f1)
[[ -n "${exempt_line}" ]] || fail "apply missing exempt UID RETURN rule"
[[ -n "${nfq_line}" ]] || fail "apply missing NFQUEUE rule for dport 80 queue 123"
(( exempt_line < nfq_line )) || fail "exempt UID rule must come BEFORE the NFQUEUE target"
# All 3 dports queued.
grep -Fq 'iptables -t mangle -A AEGIS_NFQ_TEST -p tcp --dport 443 -j NFQUEUE --queue-num 123 --queue-bypass' "${LOG}" \
    || fail "apply missing NFQUEUE rule for dport 443"
grep -Fq 'iptables -t mangle -A AEGIS_NFQ_TEST -p tcp --dport 8443 -j NFQUEUE --queue-num 123 --queue-bypass' "${LOG}" \
    || fail "apply missing NFQUEUE rule for dport 8443"
# Chain attached to OUTPUT.
grep -Fq 'iptables -t mangle -I OUTPUT 1 -j AEGIS_NFQ_TEST' "${LOG}" \
    || fail "apply did not attach chain to OUTPUT"
# Consumer-available status emitted, with the queue-bypass safety marker.
grep -Fq 'stage=consumer_available queue_bypass=on' "${OUT}" \
    || fail "apply output missing consumer-available/queue-bypass marker"
grep -Fq 'queue_bypass=on' "${OUT}" || fail "apply output missing queue_bypass=on safety marker"
grep -Eq 'ipv6=(on|off)' "${OUT}" || fail "apply output missing ipv6 dual-stack status"
grep -Fq 'status=ready' "${OUT}" || fail "apply output missing status=ready"

# --- case 2: status ----------------------------------------------------

OUT2="${TMPDIR}/status.out"
run status --queue-num=123 > "${OUT2}" 2>&1 || fail "status returned non-zero after apply"
grep -Fq 'status=present chain=AEGIS_NFQ_TEST' "${OUT2}" || fail "status did not report present"

# --- case 3: teardown --------------------------------------------------

OUT3="${TMPDIR}/teardown.out"
run teardown --queue-num=123 > "${OUT3}" 2>&1 || fail "teardown exited non-zero"
# Detached + flushed + deleted
grep -Fq 'iptables -t mangle -D OUTPUT -j AEGIS_NFQ_TEST' "${LOG}" || fail "teardown did not detach from OUTPUT"
grep -Fq 'iptables -t mangle -F AEGIS_NFQ_TEST' "${LOG}" || fail "teardown did not flush chain"
grep -Fq 'iptables -t mangle -X AEGIS_NFQ_TEST' "${LOG}" || fail "teardown did not delete chain"
grep -Fq 'status=removed' "${OUT3}" || fail "teardown output missing status=removed"

# --- case 4: status after teardown returns exit 1 + status=absent -----

OUT4="${TMPDIR}/status-absent.out"
if run status --queue-num=123 > "${OUT4}" 2>&1; then
    fail "status on absent chain should exit non-zero"
fi
grep -Fq 'status=absent chain=AEGIS_NFQ_TEST' "${OUT4}" || fail "status did not report absent"

# --- case 5: argument validation --------------------------------------

if run apply --queue-num=999999 >/dev/null 2>&1; then
    fail "queue-num out of range should be rejected"
fi
if run bogus-action >/dev/null 2>&1; then
    fail "unknown action should be rejected"
fi

# --- case 6: apply fails fast when no exempt UID resolvable -----------

# Override id mock to return failure for all callers.
cat > "${BIN}/id" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "${BIN}/id"
OUT6="${TMPDIR}/apply-no-uid.out"
if AEGIS_EXEMPT_UID="" run apply --queue-num=1 >"${OUT6}" 2>&1; then
    fail "apply without resolvable exempt UID should exit non-zero"
fi
grep -Fq 'cannot resolve aegis exempt UID' "${OUT6}" \
    || fail "apply did not surface the UID-resolution error"

echo "PASS: setup-wide-linux-nfqueue.sh apply/teardown/status/validation contract"
