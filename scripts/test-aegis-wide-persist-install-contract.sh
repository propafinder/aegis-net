#!/usr/bin/env bash
# Contract test for scripts/aegis-wide-persist-install.sh.
#
# Verifies the install / verify / uninstall actions produce the expected
# systemd unit on disk and report structured results. Uses env overrides
# (AEGIS_WIDE_PERSIST_UNIT_DIR / SCRIPT_PATH / SKIP_*) to sandbox the
# whole flow without touching /etc/systemd/system or systemctl.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/aegis-wide-persist-install.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-wide-persist.XXXXXX")"
TMP_DIR="$(cd "${TMP_DIR}" && pwd -P)"
trap 'rm -rf "${TMP_DIR}"' EXIT

export AEGIS_TEST_REAL_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
[[ -x "${AEGIS_TEST_REAL_CLIENT}" ]] || { echo 'Build aegis-client first.' >&2; exit 1; }
export AEGIS_TEST_STATE_ROOT="${TMP_DIR}"
export AEGIS_ROOT_STATE_CLIENT="${TMP_DIR}/state-client"
cat > "${AEGIS_ROOT_STATE_CLIENT}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == profile && "${2:-}" == metadata ]] || exit 90
[[ "${3:-}" != "${AEGIS_TEST_FAIL_METADATA:-}" ]] || exit 91
previous=""
for argument in "$@"; do
    if [[ "$previous" == --path || "$previous" == --snapshot ]]; then
        [[ "$argument" == "${AEGIS_TEST_STATE_ROOT}/"* && "$argument" != *'/../'* ]] || exit 92
    fi
    previous="$argument"
done
exec "${AEGIS_TEST_REAL_CLIENT}" "$@"
SH
chmod 0700 "${AEGIS_ROOT_STATE_CLIENT}"

UNIT_DIR="${TMP_DIR}/unit-dir"
mkdir -p "${UNIT_DIR}"
UNIT_NAME="aegis-wide-contract-test.service"
UNIT_PATH="${UNIT_DIR}/${UNIT_NAME}"

# Sandbox the "installed" wide lib dir. The persist installer now verifies the
# underlying helper is a SIBLING of aegis-wide-enable.sh (a hardcoded scripts/
# path made the unit fail on boot), so provide both siblings here.
LIB="${TMP_DIR}/lib"
mkdir -p "${LIB}"
FAKE_ENABLE="${LIB}/aegis-wide-enable.sh"
: > "${FAKE_ENABLE}"
: > "${LIB}/setup-wide-linux-redirect.sh"
: > "${LIB}/setup-wide-linux-tproxy.sh"
: > "${LIB}/aegis-wide-disable.sh"

run() {
    AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK=1 \
    AEGIS_WIDE_PERSIST_UNIT_DIR="${UNIT_DIR}" \
    AEGIS_WIDE_PERSIST_UNIT_NAME="${UNIT_NAME}" \
    AEGIS_WIDE_PERSIST_SCRIPT_PATH="${FAKE_ENABLE}" \
    AEGIS_WIDE_PERSIST_SKIP_SYSTEMCTL=1 \
        bash "${SCRIPT}" "$@"
}

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- case 1: install ------------------------------------------------------

OUT="${TMP_DIR}/install.out"
run install --mode=redirect --dns=off --ipv6=block --ssh-safe-ports=22,222 \
    > "${OUT}" 2>&1 || fail "install action exited non-zero"

[[ -f "${UNIT_PATH}" ]] || fail "unit file ${UNIT_PATH} not created"

grep -Fq 'After=network-online.target aegis-client.service' "${UNIT_PATH}" \
    || fail "unit missing After= dependencies"
grep -Fq 'Wants=network-online.target aegis-client.service' "${UNIT_PATH}" \
    || fail "unit missing soft client dependency"
if grep -Fq 'Requires=aegis-client.service' "${UNIT_PATH}"; then
    fail "unit must not use Requires=aegis-client.service (DNS preview restarts the client)"
fi
grep -Fq 'Type=oneshot' "${UNIT_PATH}" \
    || fail "unit not Type=oneshot"
grep -Fq 'RemainAfterExit=yes' "${UNIT_PATH}" \
    || fail "unit missing RemainAfterExit=yes"
grep -Fq 'Environment=AEGIS_WIDE_DISABLE_FROM_UNIT=1' "${UNIT_PATH}" \
    || fail "unit missing ExecStop recursion guard marker"
grep -Fq 'WantedBy=multi-user.target' "${UNIT_PATH}" \
    || fail "unit missing [Install] WantedBy"

grep -Fq 'ExecStartPre=/bin/sh -c ' "${UNIT_PATH}" \
    || fail "unit missing ExecStartPre sentinel-touch"
grep -Fq '/run/aegis-wide-confirmed' "${UNIT_PATH}" \
    || fail "unit missing rollback-sentinel /run/aegis-wide-confirmed"
grep -Fq "ExecStart=${FAKE_ENABLE} -y --no-rollback --mode=redirect --ssh-safe-ports=22,222 --dns=off --ipv6=block --udp=block" "${UNIT_PATH}" \
    || fail "unit ExecStart does not match expected flag set (must include --no-rollback + --udp for sticky boot)"
grep -Eq 'ExecStop=.*/aegis-wide-disable.sh' "${UNIT_PATH}" \
    || fail "unit missing ExecStop=<resolved>/aegis-wide-disable.sh"

grep -Fq "action=install unit=${UNIT_NAME}" "${OUT}" || fail "install output missing action=install line"
grep -Fq "status=ready" "${OUT}" || fail "install output missing status=ready line"

# --- case 2: install with --interface (gateway recipe) -------------------

OUT2="${TMP_DIR}/install-iface.out"
run install --mode=tproxy --dns=off --ipv6=block --interface=aegis-gre0 \
    > "${OUT2}" 2>&1 || fail "install --interface exited non-zero"
grep -Fq -- '--interface=aegis-gre0' "${UNIT_PATH}" \
    || fail "unit ExecStart missing --interface=aegis-gre0"
grep -Fq -- '--mode=tproxy' "${UNIT_PATH}" \
    || fail "unit ExecStart missing --mode=tproxy"

# --- case 3: verify --------------------------------------------------------

OUT3="${TMP_DIR}/verify-present.out"
run verify > "${OUT3}" 2>&1 || fail "verify on present unit exited non-zero"
grep -Fq "verify=present unit=${UNIT_NAME}" "${OUT3}" \
    || fail "verify did not report present"

# --- case 4: uninstall ----------------------------------------------------

OUT4="${TMP_DIR}/uninstall.out"
run uninstall > "${OUT4}" 2>&1 || fail "uninstall exited non-zero"
[[ ! -f "${UNIT_PATH}" ]] || fail "unit file should be removed by uninstall"
grep -Fq "action=uninstall unit=${UNIT_NAME} status=removed" "${OUT4}" \
    || fail "uninstall did not report status=removed"

# --- case 5: uninstall when already absent → status=already_absent ------

OUT5="${TMP_DIR}/uninstall-absent.out"
run uninstall > "${OUT5}" 2>&1 || fail "uninstall-when-absent exited non-zero"
grep -Fq "status=already_absent" "${OUT5}" \
    || fail "second uninstall did not report status=already_absent"

# --- case 6: verify on absent unit returns exit 1 ----------------------

OUT6="${TMP_DIR}/verify-absent.out"
if run verify > "${OUT6}" 2>&1; then
    fail "verify on absent unit should exit non-zero"
fi
grep -Fq "verify=absent unit=${UNIT_NAME}" "${OUT6}" \
    || fail "verify did not report absent"

# A metadata write failure must stop before systemctl and cannot report ready.
FAILED_WRITE="${TMP_DIR}/write-failed.out"
if AEGIS_TEST_FAIL_METADATA=write run install > "${FAILED_WRITE}" 2>&1; then
    fail "failed metadata writer was reported as a successful install"
fi
[[ ! -e "${UNIT_PATH}" ]] || fail "failed write unexpectedly created the unit"
! grep -q 'status=ready\|systemctl-skip:' "${FAILED_WRITE}" \
    || fail "failed write continued to systemctl or ready status"

run install > "${TMP_DIR}/reinstall.out" 2>&1 || fail "reinstall failed"
FAILED_REMOVE="${TMP_DIR}/remove-failed.out"
if AEGIS_TEST_FAIL_METADATA=remove run uninstall > "${FAILED_REMOVE}" 2>&1; then
    fail "failed metadata removal was reported as a successful uninstall"
fi
[[ -f "${UNIT_PATH}" ]] || fail "failed removal changed the unit"
! grep -q 'status=removed\|systemctl-skip: daemon-reload' "${FAILED_REMOVE}" \
    || fail "failed removal continued to daemon-reload or removed status"
run uninstall > "${TMP_DIR}/cleanup.out" 2>&1 || fail "cleanup uninstall failed"

# --- case 7: invalid flags rejected -----------------------------------

if AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK=1 \
   AEGIS_WIDE_PERSIST_UNIT_DIR="${UNIT_DIR}" \
   AEGIS_WIDE_PERSIST_UNIT_NAME="${UNIT_NAME}" \
   AEGIS_WIDE_PERSIST_SCRIPT_PATH="/tmp/fake.sh" \
   AEGIS_WIDE_PERSIST_SKIP_SYSTEMCTL=1 \
        bash "${SCRIPT}" install --mode=invalid >/dev/null 2>&1; then
    fail "invalid --mode should be rejected"
fi

if AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK=1 \
   AEGIS_WIDE_PERSIST_UNIT_DIR="${UNIT_DIR}" \
   AEGIS_WIDE_PERSIST_UNIT_NAME="${UNIT_NAME}" \
   AEGIS_WIDE_PERSIST_SCRIPT_PATH="/tmp/fake.sh" \
   AEGIS_WIDE_PERSIST_SKIP_SYSTEMCTL=1 \
        bash "${SCRIPT}" install --dns=nope >/dev/null 2>&1; then
    fail "invalid --dns should be rejected"
fi

for bad_arg in \
    $'--ssh-safe-ports=22\nExecStart=/bin/false' \
    '--ssh-safe-ports=0' \
    '--ssh-safe-ports=65536' \
    $'--interface=eth0\nExecStart=/bin/false' \
    '--interface=longer-than-fifteen'; do
    if run install "${bad_arg}" > "${TMP_DIR}/invalid-unit-arg.out" 2>&1; then
        fail "invalid unit argument was accepted"
    fi
    [[ ! -e "${UNIT_PATH}" ]] || fail "invalid unit argument created a unit"
done

# --- case 8: sibling helper missing → install fails LOUDLY (not a boot-broken
#     unit). This is the regression the reboot gate caught: the unit pointed at a
#     dir where setup-wide-linux-redirect.sh was not a sibling, so wide silently
#     did not come back after reboot.
NOHELPER="${TMP_DIR}/nohelper"
mkdir -p "${NOHELPER}"
: > "${NOHELPER}/aegis-wide-enable.sh"   # enable present, but NO sibling helper
if AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK=1 \
   AEGIS_WIDE_PERSIST_UNIT_DIR="${UNIT_DIR}" \
   AEGIS_WIDE_PERSIST_UNIT_NAME="${UNIT_NAME}" \
   AEGIS_WIDE_PERSIST_SCRIPT_PATH="${NOHELPER}/aegis-wide-enable.sh" \
   AEGIS_WIDE_PERSIST_SKIP_SYSTEMCTL=1 \
        bash "${SCRIPT}" install --mode=redirect --dns=off --ipv6=block >/dev/null 2>&1; then
    fail "install must fail when the underlying helper is not a sibling of aegis-wide-enable.sh"
fi

# A failed systemd reload or enable must not be reported as ready. The unit
# file may remain for diagnosis, but the operator must get a failing exit code.
mkdir -p "${TMP_DIR}/fake-bin"
cat > "${TMP_DIR}/fake-bin/systemctl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${AEGIS_TEST_SYSTEMCTL_LOG}"
[[ "${1:-}" != "${AEGIS_TEST_SYSTEMCTL_FAIL}" ]]
SH
chmod 0700 "${TMP_DIR}/fake-bin/systemctl"
run_systemctl_failure() {
    AEGIS_WIDE_PERSIST_SKIP_ROOT_CHECK=1 \
    AEGIS_WIDE_PERSIST_UNIT_DIR="${UNIT_DIR}" \
    AEGIS_WIDE_PERSIST_UNIT_NAME="${UNIT_NAME}" \
    AEGIS_WIDE_PERSIST_SCRIPT_PATH="${FAKE_ENABLE}" \
    AEGIS_TEST_SYSTEMCTL_LOG="${TMP_DIR}/systemctl.log" \
    AEGIS_TEST_SYSTEMCTL_FAIL="$1" \
    PATH="${TMP_DIR}/fake-bin:${PATH}" \
        bash "${SCRIPT}" install
}
for failed_action in daemon-reload enable; do
    : > "${TMP_DIR}/systemctl.log"
    if run_systemctl_failure "${failed_action}" > "${TMP_DIR}/systemctl-failed.out" 2>&1; then
        fail "failed systemctl ${failed_action} was reported as installed"
    fi
    ! grep -q 'status=ready' "${TMP_DIR}/systemctl-failed.out" \
        || fail "failed systemctl ${failed_action} reported ready"
    grep -Fq "${failed_action}" "${TMP_DIR}/systemctl.log" \
        || fail "systemctl ${failed_action} was not exercised"
    run uninstall > /dev/null
done

echo "PASS: aegis-wide-persist-install.sh install/verify/uninstall/flags contract"
