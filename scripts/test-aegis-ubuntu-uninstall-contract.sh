#!/usr/bin/env bash
# Contract test for scripts/aegis-ubuntu-uninstall.sh.
#
# Covers:
#   - detect_install_method classifies apt / bootstrap / source / none.
#   - verify_clean reports each leftover path correctly.
#   - purge action invokes the right path per detected method, then
#     verifies cleanup and only emits result=PASS when everything is gone.
#   - vacuous PASS when no install is detected and host is already clean.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${ROOT}/scripts/aegis-ubuntu-uninstall.sh"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-uninstall-contract.XXXXXX")"
TMPDIR="$(cd "${TMPDIR}" && pwd -P)"
trap 'rm -rf "${TMPDIR}"' EXIT

BIN="${TMPDIR}/bin"
mkdir -p "${BIN}" "${TMPDIR}/empty"

# --- mocks ---------------------------------------------------------------

# dpkg / apt-get / systemctl: just log; return whatever the test set up.
cat > "${BIN}/dpkg" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    -s) [[ -e "${AEGIS_FAKE_DPKG_KNOWS:-/dev/null}/$2" ]] ; exit $? ;;
esac
exit 1
EOF
chmod +x "${BIN}/dpkg"

cat > "${BIN}/apt-get" <<EOF
#!/usr/bin/env bash
echo "apt-get \$*"
EOF
chmod +x "${BIN}/apt-get"

# systemctl: pretend everything is absent unless AEGIS_FAKE_UNIT_DIR has a
# matching .service file.
cat > "${BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    list-unit-files)
        for f in "${AEGIS_FAKE_UNIT_DIR:-/nonexistent}"/*.service; do
            [[ -e "$f" ]] || continue
            printf '%s   enabled\n' "$(basename "$f")"
        done
        ;;
    is-active)
        # quiet form: exit 0 if active, 3 if not.
        unit="${@: -1}"
        [[ -e "${AEGIS_FAKE_UNIT_DIR:-/nonexistent}/${unit}.active" ]] && exit 0 || exit 3
        ;;
    stop)
        [[ -z "${AEGIS_FAKE_UNIT_DIR:-}" ]] || rm -f "${AEGIS_FAKE_UNIT_DIR}/${2}.active"
        ;;
    disable|start|restart|daemon-reload) ;;
    *) ;;
esac
exit 0
EOF
chmod +x "${BIN}/systemctl"

# --- helpers ------------------------------------------------------------

assert_grep() {
    local needle="$1" haystack="$2"
    if ! grep -Fq -- "${needle}" "${haystack}"; then
        echo "FAIL: missing line '${needle}' in ${haystack}" >&2
        sed -n '1,120p' "${haystack}" >&2
        exit 1
    fi
}

assert_no_grep() {
    local needle="$1" haystack="$2"
    if grep -Fq -- "${needle}" "${haystack}"; then
        echo "FAIL: unexpected line '${needle}' in ${haystack}" >&2
        exit 1
    fi
}

# --- case 1: no install detected, host clean → PASS_VACUOUS -------------

CASE1_ROOT="${TMPDIR}/case1"
mkdir -p "${CASE1_ROOT}"
CASE1_OUT="${TMPDIR}/case1.out"
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${CASE1_ROOT}" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
    bash "${SCRIPT}" verify > "${CASE1_OUT}" 2>&1 || true

assert_grep "detect=install_method method=none" "${CASE1_OUT}"
assert_grep "result=PASS_VACUOUS" "${CASE1_OUT}"
assert_grep "verify=clean path=/usr/local/bin/aegis-client" "${CASE1_OUT}"

# --- case 2: leftover bootstrap install — verify FAIL -------------------

CASE2_ROOT="${TMPDIR}/case2"
mkdir -p "${CASE2_ROOT}/var/lib/aegis-client"
echo '{}' > "${CASE2_ROOT}/var/lib/aegis-client/install-manifest.json"
mkdir -p "${CASE2_ROOT}/usr/local/bin"
touch "${CASE2_ROOT}/usr/local/bin/aegis-client"
CASE2_OUT="${TMPDIR}/case2.out"
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${CASE2_ROOT}" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
    bash "${SCRIPT}" verify > "${CASE2_OUT}" 2>&1 || true

assert_grep "detect=install_method method=bootstrap" "${CASE2_OUT}"
assert_grep "verify=leftover path=/usr/local/bin/aegis-client" "${CASE2_OUT}"
assert_grep "result=FAIL" "${CASE2_OUT}"
assert_no_grep "result=PASS" "${CASE2_OUT}"

# --- case 3: source install — purge with manual sweep + verify ---------

CASE3_ROOT="${TMPDIR}/case3"
mkdir -p "${CASE3_ROOT}/usr/local/bin"
touch "${CASE3_ROOT}/usr/local/bin/aegis-client"
CASE3_OUT="${TMPDIR}/case3.out"

# Execute a real file purge, isolated under the fake root and using mocked
# system commands. A clean empty fixture would not exercise the purge at all.
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${CASE3_ROOT}" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
    bash "${SCRIPT}" purge > "${CASE3_OUT}" 2>&1

assert_grep "detect=install_method method=source" "${CASE3_OUT}"
assert_grep "result=PASS" "${CASE3_OUT}"
[[ ! -e "${CASE3_ROOT}/usr/local/bin/aegis-client" ]]

# --- case 4: detection of apt install (dpkg returns 0 for aegis-client)

CASE4_OUT="${TMPDIR}/case4.out"
FAKE_DPKG_DB="${TMPDIR}/dpkg-db"
mkdir -p "${FAKE_DPKG_DB}"
touch "${FAKE_DPKG_DB}/aegis-client"
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${TMPDIR}/empty" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
AEGIS_FAKE_DPKG_KNOWS="${FAKE_DPKG_DB}" \
    bash -c '
      script_path="$1"
      set -- verify
      source "$script_path"
      ROOT_PREFIX=""
      dpkg() { [[ "$*" == "-s aegis-client" && -e "${AEGIS_FAKE_DPKG_KNOWS}/aegis-client" ]]; }
      printf "detect=install_method method=%s\n" "$(detect_install_method)"
    ' _ "${SCRIPT}" > "${CASE4_OUT}" 2>&1

assert_grep "detect=install_method method=apt" "${CASE4_OUT}"

# --- case 5: detection of source install -------------------------------

CASE5_ROOT="${TMPDIR}/case5"
mkdir -p "${CASE5_ROOT}/usr/local/bin"
touch "${CASE5_ROOT}/usr/local/bin/aegis-client"
CASE5_OUT="${TMPDIR}/case5.out"
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${CASE5_ROOT}" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
    bash "${SCRIPT}" verify > "${CASE5_OUT}" 2>&1 || true

assert_grep "detect=install_method method=source" "${CASE5_OUT}"
assert_grep "verify=leftover path=/usr/local/bin/aegis-client" "${CASE5_OUT}"

# --- case 6: a unit drop-in and env file are uninstall residue ---------

CASE6_ROOT="${TMPDIR}/case6"
mkdir -p \
  "${CASE6_ROOT}/etc/systemd/system/aegis-client.service.d" \
  "${CASE6_ROOT}/etc/default"
touch "${CASE6_ROOT}/etc/systemd/system/aegis-client.service.d/10-dedicated-uid.conf"
touch "${CASE6_ROOT}/etc/default/aegis-client"
CASE6_OUT="${TMPDIR}/case6.out"
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${CASE6_ROOT}" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
    bash "${SCRIPT}" verify > "${CASE6_OUT}" 2>&1 || true

assert_grep "verify=leftover path=/etc/systemd/system/aegis-client.service.d" "${CASE6_OUT}"
assert_grep "verify=leftover path=/etc/default/aegis-client" "${CASE6_OUT}"
assert_grep "result=FAIL" "${CASE6_OUT}"

# --- case 7: manual purge is client-scoped and removes env residue -----

CASE7_ROOT="${TMPDIR}/case7"
mkdir -p \
  "${CASE7_ROOT}/usr/local/bin" \
  "${CASE7_ROOT}/etc/default" \
  "${CASE7_ROOT}/etc/aegis/server"
touch \
  "${CASE7_ROOT}/usr/local/bin/aegis-client" \
  "${CASE7_ROOT}/usr/local/bin/aegis-server" \
  "${CASE7_ROOT}/etc/default/aegis-client" \
  "${CASE7_ROOT}/etc/default/aegis-server" \
  "${CASE7_ROOT}/etc/aegis/server/aegis-server.toml"
CASE7_OUT="${TMPDIR}/case7.out"
PATH="${BIN}:${PATH}" \
AEGIS_UNINSTALL_FAKE_ROOT="${CASE7_ROOT}" \
AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 \
    bash "${SCRIPT}" purge > "${CASE7_OUT}" 2>&1

assert_grep "method=source action=purge (manual sweep)" "${CASE7_OUT}"
assert_grep "verify=PASS leftovers=0" "${CASE7_OUT}"
[[ ! -e "${CASE7_ROOT}/etc/default/aegis-client" ]]
[[ ! -e "${CASE7_ROOT}/usr/local/bin/aegis-client" ]]
[[ -e "${CASE7_ROOT}/usr/local/bin/aegis-server" ]]
[[ -e "${CASE7_ROOT}/etc/default/aegis-server" ]]
[[ -e "${CASE7_ROOT}/etc/aegis/server/aegis-server.toml" ]]

# A server manifest alone is not a client installation.
mkdir -p "${CASE7_ROOT}/var/lib/aegis"
echo '{}' > "${CASE7_ROOT}/var/lib/aegis/install-manifest.json"
PATH="${BIN}:${PATH}" AEGIS_UNINSTALL_FAKE_ROOT="${CASE7_ROOT}" \
    bash "${SCRIPT}" verify > "${TMPDIR}/server-only.out"
assert_grep "detect=install_method method=none" "${TMPDIR}/server-only.out"
[[ -f "${CASE7_ROOT}/var/lib/aegis/install-manifest.json" ]]

# New root-owned receipts are role-scoped. A client purge removes only its
# receipt and preserves both generations of a co-located server receipt.
mkdir -p "${CASE7_ROOT}/var/lib/aegis-install/client" "${CASE7_ROOT}/var/lib/aegis-install/server"
echo '{}' > "${CASE7_ROOT}/var/lib/aegis-install/client/install-manifest.json"
echo '{}' > "${CASE7_ROOT}/var/lib/aegis-install/server/install-manifest.json"
PATH="${BIN}:${PATH}" AEGIS_UNINSTALL_FAKE_ROOT="${CASE7_ROOT}" \
    AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 bash "${SCRIPT}" purge > "${TMPDIR}/new-receipt.out"
assert_grep "detect=install_method method=bootstrap" "${TMPDIR}/new-receipt.out"
[[ ! -e "${CASE7_ROOT}/var/lib/aegis-install/client" ]]
[[ -f "${CASE7_ROOT}/var/lib/aegis-install/server/install-manifest.json" ]]
[[ -f "${CASE7_ROOT}/var/lib/aegis/install-manifest.json" ]]

# Snapshot-only residue and broken symlinks cannot yield a vacuous PASS.
printf 'net.ipv4.ip_forward=0\n' > "${CASE7_ROOT}/var/lib/aegis/wide-sysctl-original.txt"
ln -s /nonexistent-aegis-contract-target "${CASE7_ROOT}/usr/local/bin/aegis-client"
if PATH="${BIN}:${PATH}" AEGIS_UNINSTALL_FAKE_ROOT="${CASE7_ROOT}" \
    bash "${SCRIPT}" verify > "${TMPDIR}/snapshot.out"; then
    echo "FAIL: residue was certified clean" >&2; exit 1
fi
assert_grep "verify=leftover path=/var/lib/aegis/wide-sysctl-original.txt" "${TMPDIR}/snapshot.out"
assert_grep "verify=FAIL leftovers=2" "${TMPDIR}/snapshot.out"

# Fake-root V2 still refuses before any legacy purge effect. The real-root
# source route must dispatch the installed typed coordinator before method
# detection, teardown, log cleanup or apt.
CASE_V2_ROOT="${TMPDIR}/case-v2"
mkdir -p "${CASE_V2_ROOT}/var/lib/aegis-auto/control"
if PATH="${BIN}:${PATH}" AEGIS_UNINSTALL_FAKE_ROOT="${CASE_V2_ROOT}" \
    AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1 bash "${SCRIPT}" purge \
    > "${TMPDIR}/v2.out" 2>&1; then
    echo "FAIL: fake-root AUTO V2 entered legacy purge" >&2; exit 1
fi
assert_grep "AUTO V2 ownership requires its typed serial stop" "${TMPDIR}/v2.out"
[[ -d "${CASE_V2_ROOT}/var/lib/aegis-auto/control" ]]
assert_no_grep "method=auto-v2 action=purge" "${TMPDIR}/v2.out"
python3 - "${SCRIPT}" <<'PY_V2_ROUTE'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
route = source.index("method=auto-v2 action=purge")
assert route < source.index("# Refuse before install-method detection")
assert '/usr/bin/python3 -I -B "${v2_coordinator}" uninstall' in source
assert 'if [[ -n "${ROOT_PREFIX}" ]]; then' in source[:route]
PY_V2_ROUTE

# The public shell may itself be gone after dpkg removes package files. Its
# source-independent recovery command remains in the journal; while the shell
# exists, its fallback authenticates these exact bytes before execution.
RECOVERY_ROOT="${TMPDIR}/recovery-fixture"
mkdir -p "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall/recovery"
chmod 700 "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall" \
          "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall/recovery"
python3 - "${ROOT}" "${RECOVERY_ROOT}" <<'PY_V2_FIXTURE'
from pathlib import Path
import hashlib, json, sys
root, fixture = map(Path, sys.argv[1:])
journal = fixture / 'var/lib/aegis-auto-uninstall'
recovery = journal / 'recovery'
resume = (b'If the packaged public uninstall command was removed during dpkg purge, '
          b'transfer scripts/aegis-ubuntu-uninstall.sh from the exact trusted '
          b'source commit and run:\n'
          b"ssh HOST 'sudo bash -s -- purge' < "
          b'scripts/aegis-ubuntu-uninstall.sh\n'
          b'The trusted script verifies root ownership, modes and retained '
          b'source hashes before resuming. Do not execute retained Python directly.\n')
files = {
    'aegis_installer_auto_v2.py': (root / 'scripts/lib/aegis_installer_auto_v2.py').read_bytes(),
    'aegis_auto_uninstall_journal.py': (root / 'scripts/lib/aegis_auto_uninstall_journal.py').read_bytes(),
    'resume-command.txt': resume,
}
for name, raw in files.items():
    (recovery / name).write_bytes(raw)
    (recovery / name).chmod(0o600)
manifest = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
(recovery / 'recovery-manifest.json').write_bytes(
    json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode())
(recovery / 'recovery-manifest.json').chmod(0o600)
for name in ('package-handoff.json', 'generic-purged.json'):
    (journal / name).write_bytes(b'{}')
    (journal / name).chmod(0o600)
PY_V2_FIXTURE
(
    set -- verify
    source "${SCRIPT}"
    recovered="$(verified_v2_recovery_source \
        "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall/recovery" \
        "$(id -u)" "$(id -g)")"
    [[ "${recovered}" == "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall/recovery/aegis_installer_auto_v2.py" ]]
    python3 -I -B "${recovered}" --help >/dev/null
    printf 'tampered' >> "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall/recovery/aegis_installer_auto_v2.py"
    if verified_v2_recovery_source \
        "${RECOVERY_ROOT}/var/lib/aegis-auto-uninstall/recovery" \
        "$(id -u)" "$(id -g)" >/dev/null 2>&1; then
        echo 'FAIL: changed retained coordinator was executed' >&2; exit 1
    fi
)

# Argument parsing happens before every mutation, even with root bypassed.
for help in --help -h; do
    bash "${SCRIPT}" "${help}" > "${TMPDIR}/help.out"
    assert_grep "Usage:" "${TMPDIR}/help.out"
done
set +e
bash "${SCRIPT}" purge --typo > "${TMPDIR}/args.out" 2>&1
args_rc=$?
set -e
[[ "${args_rc}" -eq 2 ]]

# Execute the production manual-purge function. Simulate a persistence teardown
# that restarts the client: final stop must occur afterwards and before unlink.
(
    export PATH="${BIN}:${PATH}"
    export AEGIS_UNINSTALL_FAKE_ROOT="${CASE3_ROOT}"
    export AEGIS_UNINSTALL_SKIP_ROOT_CHECK=1
    set -- verify
    source "${SCRIPT}"
    ROOT_PREFIX=''
    running=0
    teardown_wide_before_purge() { running=1; }
    systemctl() {
        case "$1 ${2:-}" in
            'stop aegis-wide.service') running=1 ;;
            'stop aegis-client.service') running=0 ;;
            'is-active --quiet') [[ "${running}" -eq 1 ]]; return $? ;;
            'show aegis-client.service')
                printf '%s\n' 'LoadState=loaded' 'ActiveState=inactive' \
                    'SubState=dead' 'MainPID=0' 'ControlPID=0'
                ;;
        esac
        return 0
    }
    cleanup_auto_runtime_logs() { [[ "$1" == delete && "${running}" -eq 0 ]]; }
    rm() { [[ "${running}" -eq 0 ]] || exit 81; }
    purge_manual
    [[ "${running}" -eq 0 ]]
    teardown_wide_before_purge() { return 1; }
    rm() { exit 82; }
    if purge_manual; then
        echo "FAIL: ignored teardown failure" >&2; exit 1
    fi
) > "${TMPDIR}/order.out" 2>&1

# Package removal must not delete recovery helpers before teardown, and an
# APT failure must not fall through into the file sweep or be reported PASS.
(
    export AEGIS_UNINSTALL_FAKE_ROOT="${CASE3_ROOT}"
    set -- verify
    source "${SCRIPT}"
    ROOT_PREFIX=''
    phase=initial
    teardown_wide_before_purge() { phase=restored; }
    systemctl() {
        if [[ "$1" == show ]]; then
            printf '%s\n' 'LoadState=loaded' 'ActiveState=inactive' \
                'SubState=dead' 'MainPID=0' 'ControlPID=0'
        fi
        return 0
    }
    cleanup_auto_runtime_logs() {
        [[ "$1" == delete && "${phase}" == restored ]] || exit 85
        phase=logs-clean
    }
    apt-get() {
        [[ "${phase}" == logs-clean && "$*" == 'purge -y aegis-client' ]] || exit 83
        return 7
    }
    purge_manual() { exit 84; }
    if purge_via_apt; then
        echo "FAIL: ignored APT failure" >&2; exit 1
    fi
    [[ "${phase}" == logs-clean ]]
) > "${TMPDIR}/apt-order.out" 2>&1

echo "PASS: aegis-ubuntu-uninstall.sh detect/verify/purge contract"
