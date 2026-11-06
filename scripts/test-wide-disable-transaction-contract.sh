#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
TMP_DIR="$(cd "${TMP_DIR}" && pwd -P)"
trap 'rm -rf "${TMP_DIR}"' EXIT

BIN="${TMP_DIR}/bin"
LIB="${TMP_DIR}/lib"
LOG="${TMP_DIR}/calls.log"
mkdir -p "${BIN}" "${LIB}/lib" "${TMP_DIR}/host/etc" "${TMP_DIR}/host/run"
cp "${ROOT}/scripts/aegis-wide-disable.sh" "${LIB}/aegis-wide-disable.sh"
cp "${ROOT}/scripts/lib/root-state.sh" "${LIB}/lib/root-state.sh"
# Relocate every hardcoded administrative path in the fixture copy, including
# legacy migration reads and unit/sentinel removals. No host /etc, /var/lib or
# /run path reaches either shell mutation or the real Rust metadata command.
python3 - "${TMP_DIR}/host" "${LIB}/aegis-wide-disable.sh" "${LIB}/lib/root-state.sh" <<'PY'
from pathlib import Path
import sys
for name in sys.argv[2:]:
    path = Path(name)
    text = path.read_text()
    for prefix in ("/etc/", "/var/lib/", "/run/"):
        text = text.replace(prefix, sys.argv[1] + prefix)
    path.write_text(text)
PY
chmod +x "${LIB}/aegis-wide-disable.sh"

export AEGIS_TEST_REAL_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-${ROOT}/target/debug/aegis-client}"
[[ -x "${AEGIS_TEST_REAL_CLIENT}" ]] || { echo 'Build aegis-client first.' >&2; exit 1; }
export AEGIS_TEST_STATE_ROOT="${TMP_DIR}"
export AEGIS_ROOT_STATE_CLIENT="${BIN}/state-client"
cat > "${AEGIS_ROOT_STATE_CLIENT}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == profile && "${2:-}" == metadata ]] || exit 90
[[ "${3:-}" != "${AEGIS_TEST_FAIL_METADATA:-}" ]] || exit 91
if [[ "${3:-}" == read && "${AEGIS_TEST_FAIL_SNAPSHOT_RESTORE:-0}" == 1 ]]; then
    count_file="${AEGIS_TEST_STATE_ROOT}/snapshot-read-count"
    count=0
    [[ ! -f "$count_file" ]] || read -r count < "$count_file"
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    # Permit preflight validation, then model a later storage read error.
    (( count < 2 )) || exit 93
fi
previous=""
for argument in "$@"; do
    if [[ "$previous" == --path || "$previous" == --snapshot ]]; then
        [[ "$argument" == "${AEGIS_TEST_STATE_ROOT}/"* && "$argument" != *'/../'* ]] || exit 92
    fi
    previous="$argument"
done
exec "${AEGIS_TEST_REAL_CLIENT}" "$@"
SH

for helper in setup-wide-linux-redirect.sh setup-wide-linux-tproxy.sh janitor-wide-linux-tproxy.sh; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "${LIB}/${helper}"
    chmod +x "${LIB}/${helper}"
done

cat > "${BIN}/systemctl" <<'SH'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${AEGIS_TEST_CALL_LOG}"
case "${1:-}" in
    is-active|is-enabled) exit 1 ;;
    *) exit 0 ;;
esac
SH

cat > "${BIN}/iptables" <<'SH'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_TEST_CALL_LOG}"
exit 1
SH

cat > "${BIN}/ip6tables" <<'SH'
#!/usr/bin/env bash
exit 1
SH

cat > "${BIN}/iptables-save" <<'SH'
#!/usr/bin/env bash
if [[ "${AEGIS_TEST_RESIDUE:-0}" == "1" ]]; then
    printf '%s\n' ':AEGIS_WIDE_OUTPUT - [0:0]'
fi
SH

cat > "${BIN}/ip6tables-save" <<'SH'
#!/usr/bin/env bash
exit 0
SH

cat > "${BIN}/nft" <<'SH'
#!/usr/bin/env bash
if [[ "${AEGIS_TEST_NFT_RESIDUE:-0}" == "1" && "$*" == "list table ip aegis_wide_tproxy" ]]; then
    exit 0
fi
exit 1
SH

cat > "${BIN}/ip" <<'SH'
#!/usr/bin/env bash
case "$*" in
    'link show aegis-tun0') exit 1 ;;
    '-6 route show') exit 0 ;;
    *) exit 0 ;;
esac
SH

cat > "${BIN}/sysctl" <<'SH'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${AEGIS_TEST_CALL_LOG}"
exit 0
SH

chmod +x "${BIN}"/*

# CLI parsing is the first transaction boundary. Neither a help request nor a
# typo may reach systemctl/firewall/config mutation in this destructive helper.
: > "${LOG}"
PATH="${BIN}:${PATH}" \
AEGIS_TEST_CALL_LOG="${LOG}" \
AEGIS_WIDE_SKIP_ROOT_CHECK=1 \
    bash "${LIB}/aegis-wide-disable.sh" --help > "${TMP_DIR}/help.out" 2>&1
grep -q '^Usage:' "${TMP_DIR}/help.out"
[[ ! -s "${LOG}" ]]

: > "${LOG}"
set +e
PATH="${BIN}:${PATH}" \
AEGIS_TEST_CALL_LOG="${LOG}" \
AEGIS_WIDE_SKIP_ROOT_CHECK=1 \
    bash "${LIB}/aegis-wide-disable.sh" --typo > "${TMP_DIR}/unknown.out" 2>&1
unknown_status=$?
set -e
[[ "${unknown_status}" -eq 2 ]]
grep -q 'accepts no arguments' "${TMP_DIR}/unknown.out"
[[ ! -s "${LOG}" ]]

run_disable() {
    local residue="$1" output="$2" config_present="${3:-1}" nft_residue="${4:-0}"
    : > "${LOG}"
    if [[ "${config_present}" == "1" ]]; then
        cat > "${TMP_DIR}/aegis.toml" <<'TOML'
[ingress]
primary = "wide"

[ingress.wide]
enabled = true
ipv6_tun_carried = true
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
dns_preview_listen = "127.0.0.1:53"
TOML
        chmod 0640 "${TMP_DIR}/aegis.toml"
    else
        rm -f "${TMP_DIR}/aegis.toml"
    fi
    PATH="${BIN}:${PATH}" \
    AEGIS_TEST_CALL_LOG="${LOG}" \
    AEGIS_TEST_RESIDUE="${residue}" \
    AEGIS_TEST_NFT_RESIDUE="${nft_residue}" \
    AEGIS_WIDE_SKIP_ROOT_CHECK=1 \
    AEGIS_WIDE_SYSCTL_FILE="${TMP_DIR}/sysctl.conf" \
    AEGIS_WIDE_SYSCTL_SNAPSHOT="${TMP_DIR}/sysctl.snapshot" \
    AEGIS_CONFIG_FILE="${TMP_DIR}/aegis.toml" \
        bash "${LIB}/aegis-wide-disable.sh" > "${output}" 2>&1
}

line_of() {
    local literal="$1"
    grep -nF "${literal}" "${LOG}" | head -1 | cut -d: -f1
}

run_disable 0 "${TMP_DIR}/clean.out"

disable_tun="$(line_of 'systemctl disable aegis-wide-tun-firewall.service')"
disable_generic="$(line_of 'systemctl disable aegis-wide.service')"
stop_tun="$(line_of 'systemctl stop aegis-wide-tun-firewall.service')"
stop_generic="$(line_of 'systemctl stop aegis-wide.service')"
restart_client="$(line_of 'systemctl restart aegis-client')"

[[ "${disable_tun}" -lt "${stop_tun}" ]]
[[ "${disable_generic}" -lt "${stop_generic}" ]]
[[ "${disable_tun}" -lt "${restart_client}" ]]
[[ "${disable_generic}" -lt "${restart_client}" ]]
! grep -q -- '--now' "${LOG}"
grep -q 'AEGIS wide mode DISABLED' "${TMP_DIR}/clean.out"
grep -q '^primary = "socks5"$' "${TMP_DIR}/aegis.toml"
grep -q '^enabled = false$' "${TMP_DIR}/aegis.toml"
grep -q '^ipv6_tun_carried = false$' "${TMP_DIR}/aegis.toml"
! grep -q '^dns_preview_' "${TMP_DIR}/aegis.toml"
config_mode="$(python3 -c 'import os, stat, sys; print(format(stat.S_IMODE(os.stat(sys.argv[1]).st_mode), "o"))' "${TMP_DIR}/aegis.toml")"
[[ "${config_mode}" == "640" ]]

if run_disable 1 "${TMP_DIR}/residue.out"; then
    echo "expected disable to fail when AEGIS firewall residue is observable" >&2
    exit 1
fi
grep -q 'refusing a false success report' "${TMP_DIR}/residue.out"
! grep -q 'AEGIS wide mode DISABLED' "${TMP_DIR}/residue.out"

if run_disable 0 "${TMP_DIR}/nft-residue.out" 1 1; then
    echo "expected disable to fail when the native nft table remains" >&2
    exit 1
fi
grep -q 'wide nft table remains after disable' "${TMP_DIR}/nft-residue.out"
! grep -q 'AEGIS wide mode DISABLED' "${TMP_DIR}/nft-residue.out"

run_disable 0 "${TMP_DIR}/missing-config.out" 0
grep -q 'AEGIS wide mode DISABLED' "${TMP_DIR}/missing-config.out"
! grep -qF 'systemctl restart aegis-client' "${LOG}"
! grep -qF 'systemctl stop aegis-client' "${LOG}"

# A denied metadata preflight must not start any teardown or touch config.
if AEGIS_TEST_FAIL_METADATA=validate run_disable 0 "${TMP_DIR}/preflight-denied.out"; then
    echo 'expected metadata validation failure to stop disable' >&2
    exit 1
fi
[[ ! -s "${LOG}" ]]
grep -q '^primary = "wide"$' "${TMP_DIR}/aegis.toml"
! grep -q 'AEGIS wide mode DISABLED' "${TMP_DIR}/preflight-denied.out"

printf 'net.ipv4.ip_forward=0\nnet.ipv4.conf.all.route_localnet=0\nnet.ipv4.conf.eth0.route_localnet=0\n' > "${TMP_DIR}/sysctl.snapshot"
chmod 0600 "${TMP_DIR}/sysctl.snapshot"
if AEGIS_TEST_FAIL_SNAPSHOT_RESTORE=1 run_disable 0 "${TMP_DIR}/restore-read-denied.out"; then
    echo 'expected failed snapshot read to stop restore and retain recovery data' >&2
    exit 1
fi
[[ -s "${TMP_DIR}/sysctl.snapshot" ]]
[[ "$(cat "${TMP_DIR}/snapshot-read-count")" == 2 ]]
! grep -q '^sysctl \|systemctl restart aegis-client' "${LOG}"
! grep -q 'AEGIS wide mode DISABLED' "${TMP_DIR}/restore-read-denied.out"

echo "wide disable transaction contract: PASS"
