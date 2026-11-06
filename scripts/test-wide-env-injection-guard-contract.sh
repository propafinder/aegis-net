#!/usr/bin/env bash
# Contract: the wide firewall helpers reject argument/rule-injection-prone env
# vars (audit H4) BEFORE interpolating them into iptables/pf, rather than
# passing hostile values straight through to the kernel firewall tooling.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/aegis-env-guard.XXXXXX")" || exit 1
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/state"
export AEGIS_GUARD_MEASURE="${AEGIS_TEST_MEASURE_BINARY:-$ROOT/target/debug/aegis-measure}"
[[ -x "$AEGIS_GUARD_MEASURE" ]] || { echo 'Build aegis-measure before this fixture.' >&2; exit 1; }
export AEGIS_GUARD_CALLS="$fixture/privileged-calls"
cat > "$fixture/bin/cargo" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -ge 9 && "$1" == run && "$2" == -q && "$3" == --manifest-path && "$5" == -p && "$6" == aegis-measure && "$7" == -- && "$8" == macos-pf-state-basename ]] || exit 97
shift 7
exec "$AEGIS_GUARD_MEASURE" "$@"
SHIM
cat > "$fixture/bin/privileged" <<'SHIM'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "$AEGIS_GUARD_CALLS"
exit 98
SHIM
chmod +x "$fixture/bin/cargo" "$fixture/bin/privileged"
for cmd in iptables ip6tables nft ip sudo pfctl route ifconfig systemctl sysctl; do
  cp "$fixture/bin/privileged" "$fixture/bin/$cmd"
done
export PATH="$fixture/bin:$PATH"
export AEGIS_MACOS_PF_STATE_PATH="$fixture/state/pf"
export AEGIS_MACOS_PF_STATE_DIR="$fixture/state"

fail() { echo "CONTRACT FAIL: $*" >&2; exit 1; }

# Assert: running <script> with <env> aborts non-zero and prints <needle>,
# and never reaches privileged firewall calls.
reject() {
  local desc="$1" needle="$2"; shift 2
  local out rc
  out="$(env "$@" bash "${ROOT}/scripts/${SCRIPT}" apply 2>&1)"
  rc=$?
  if [[ $rc -eq 0 ]]; then
    fail "${desc}: expected non-zero exit, got 0 (injection not rejected)"
  fi
  if ! grep -Fq -- "${needle}" <<<"${out}"; then
    fail "${desc}: missing rejection message '${needle}' (got: ${out})"
  fi
  echo "ok: ${desc} rejected (rc=${rc})"
}

SCRIPT="setup-wide-linux-redirect.sh"
reject "redirect INTERFACE injection" "must be a valid interface name" \
  AEGIS_WIDE_INTERFACE='eth0 -j ACCEPT'
reject "redirect EXEMPT_UID injection" "must be numeric" \
  AEGIS_EXEMPT_UID='0; rm -rf /'

SCRIPT="setup-wide-linux-tproxy.sh"
reject "tproxy EXEMPT_UID injection" "must be numeric" \
  AEGIS_EXEMPT_UID='0 --or-injected'
reject "tproxy INTERFACE injection" "must be a valid interface name" \
  AEGIS_WIDE_INTERFACE='eth0; reboot'

SCRIPT="macos-wide-pf.sh"
reject "macos EGRESS_IF injection" "must be a valid interface name" \
  AEGIS_MACOS_PF_EGRESS_IF='en0 from any to any'
reject "macos ANCHOR_NAME injection" "invalid character" \
  AEGIS_MACOS_PF_ANCHOR_NAME='aegis
rdr pass on en0 all'

[[ ! -e "$AEGIS_GUARD_CALLS" ]] || fail 'privileged command reached before invalid environment rejection'
[[ -z "$(ls -A "$fixture/state")" ]] || fail 'invalid environment created PF state'
echo "wide env injection guard contract PASS; no privileged command or host state write"
